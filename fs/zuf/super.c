/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/magic.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <linux/backing-dev.h>
#include <linux/list.h>
#include <linux/genhd.h>
#include <linux/uuid.h>
#include <linux/posix_acl_xattr.h>

#include "zuf.h"

static struct super_operations zuf_sops;
static struct kmem_cache *zuf_inode_cachep;

enum {
	Opt_uid,
	Opt_gid,
	Opt_pedantic,
	Opt_ephemeral,
	Opt_dax,
	Opt_err
};

static const match_table_t tokens = {
	{ Opt_uid,		"uid=%u"		},
	{ Opt_gid,		"gid=%u"		},
	{ Opt_pedantic,		"pedantic"		},
	{ Opt_pedantic,		"pedantic=%d"		},
	{ Opt_ephemeral,	"ephemeral"		},
	{ Opt_dax,		"dax"			},
	{ Opt_err,		NULL			},
};

/* Output parameters from _parse_options */
struct __parse_options {
	bool clear_t2sync;
	bool pedantic_17;
};

static int _parse_options(struct zuf_sb_info *sbi, const char *data,
			  bool remount, struct __parse_options *po)
{
	char *orig_options, *options;
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	int err = 0;
	bool ephemeral = false;

	/* no options given */
	if (!data)
		return 0;

	options = orig_options = kstrdup(data, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		/* Initialize args struct so we know whether arg was found */
		args[0].to = args[0].from = NULL;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_uid:
			if (remount)
				goto bad_opt;
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->uid = KUIDT_INIT(option);
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gid = KGIDT_INIT(option);
			break;
		case Opt_pedantic:
			set_opt(sbi, PEDANTIC);
			break;
		case Opt_ephemeral:
			set_opt(sbi, EPHEMERAL);
			ephemeral = true;
			break;
		case Opt_dax:
			set_opt(sbi, DAX);
			break;
		default: {
			goto bad_opt;
		}
		}
	}

	if (remount && test_opt(sbi, EPHEMERAL) && (ephemeral == false))
		clear_opt(sbi, EPHEMERAL);
out:
	kfree(orig_options);
	return err;

bad_val:
	zuf_warn_cnd(test_opt(sbi, SILENT), "Bad value '%s' for mount option '%s'\n",
		      args[0].from, p);
	err = -EINVAL;
	goto out;
bad_opt:
	zuf_warn_cnd(test_opt(sbi, SILENT), "Bad mount option: \"%s\"\n", p);
	err = -EINVAL;
	goto out;
}

static void _print_mount_info(struct zuf_sb_info *sbi, char *mount_options)
{
	char buff[1000];
	int space = sizeof(buff);
	char *b = buff;
	uint i;
	int printed;

	for (i = 0; i < sbi->md->t1_count; ++i) {
		printed = snprintf(b, space, "%s%s", i ? "," : "",
			       _bdev_name(md_t1_dev(sbi->md, i)->bdev));

		if (unlikely(printed > space))
			goto no_space;

		b += printed;
		space -= printed;
	}

	if (sbi->md->t2_count) {
		printed = snprintf(b, space, " t2=%s",
				   _bdev_name(md_t2_dev(sbi->md, 0)->bdev));
		if (unlikely(printed > space))
			goto no_space;

		b += printed;
		space -= printed;
	}

	if (mount_options) {
		printed = snprintf(b, space, " -o %s", mount_options);
		if (unlikely(printed > space))
			goto no_space;
	}

print:
	zuf_info("mounted t1=%s (0x%lx/0x%lx)\n", buff,
		  md_t1_blocks(sbi->md), md_t2_blocks(sbi->md));
	return;

no_space:
	snprintf(buff + sizeof(buff) - 4, 4, "...");
	goto print;
}

static void _sb_mwtime_now(struct super_block *sb, struct zufs_dev_table *zdt)
{
	struct timespec now = CURRENT_TIME;

	timespec_to_mt(&zdt->s_mtime, &now);
	zdt->s_wtime = zdt->s_mtime;
	tozu_persist_md(sb, &zdt->s_mtime, 2*sizeof(zdt->s_mtime));
}

static int _setup_bdi(struct backing_dev_info *bdi, const char *device_name)
{
	char name[64] = "zuf-";
	int err;

	err = bdi_setup_and_register(bdi,
				     strncat(name, device_name, sizeof(name)));
	if (unlikely(err))
		return err;

	/* This is an HACK so to not need a dynamic allocation
	 * of bdi->name and still keep a per sb uniqueness. Hopefully
	 * bdi->name is going away
	 */
	bdi->name = (char *)dev_name(bdi->dev);

	bdi->ra_pages = ZUFS_READAHEAD_PAGES;
	bdi->capabilities = BDI_CAP_NO_ACCT_AND_WRITEBACK;
	return 0;
}

static void zuf_put_super(struct super_block *sb)
{
	struct zuf_sb_info *sbi = SBI(sb);

	if (sbi->zus_sbi) {
		zufs_dispatch_umount(ZUF_ROOT(sbi), sbi->zus_sbi);
		sbi->zus_sbi = NULL;
	}

	if (sb->s_bdi) {
		bdi_destroy(sb->s_bdi);
		sb->s_bdi = NULL;
	}

	/* NOTE!!! this is a HACK! we should not touch the s_umount
	 * lock but to make lockdep happy we do that since our devices
	 * are held exclusivly. Need to revisit every kernel version
	 * change. */
	if (sbi->md) {
		up_write(&sb->s_umount);
		md_fini(sbi->md, sb->s_bdev);
		down_write(&sb->s_umount);
	}

	sb->s_fs_info = NULL;
	if (!test_opt(sbi, FAILED))
		zuf_info("unmounted /dev/%s\n", _bdev_name(sb->s_bdev));
	kfree(sbi);
}

struct __fill_super_params {
	struct multi_devices *md;
	char *mount_options;
};

static int zuf_fill_super(struct super_block *sb, void *data, int silent)
{
	struct zuf_sb_info *sbi;
	struct __fill_super_params *fsp = data;
	struct __parse_options po = {};
	struct zufs_ioc_mount zim = {};
	struct register_fs_info *rfi;
	struct inode *root_i;
	bool exist;
	int err;

	BUILD_BUG_ON(sizeof(struct zufs_dev_table) > ZUFS_SB_SIZE);
	BUILD_BUG_ON(sizeof(struct zus_inode) != ZUFS_INODE_SIZE);

	sbi = kzalloc(sizeof(struct zuf_sb_info), GFP_KERNEL);
	if (!sbi) {
		zuf_err_cnd(silent, "Not enough memory to allocate sbi\n");
		return -ENOMEM;
	}
	sb->s_fs_info = sbi;
	sbi->sb = sb;

	/* Initialize embedded objects */
	spin_lock_init(&sbi->s_mmap_dirty_lock);
	INIT_LIST_HEAD(&sbi->s_mmap_dirty);
	if (silent)
		set_opt(sbi, SILENT);

	sbi->md = fsp->md;
	err = md_set_sb(sbi->md, sb->s_bdev, sb, silent);
	if (unlikely(err))
		goto error;

	err = _parse_options(sbi, fsp->mount_options, 0, &po);
	if (err)
		goto error;

	err = _setup_bdi(&sbi->bdi, _bdev_name(sb->s_bdev));
	if (err) {
		zuf_err_cnd(silent, "Failed to setup bdi => %d\n", err);
		goto error;
	}

	/* Tell ZUS to mount an FS for us */
	zim.pmem_kern_id = zuf_pmem_id(sbi->md);
	err = zufs_dispatch_mount(ZUF_ROOT(sbi), zuf_fst(sb)->zus_zfi, &zim);
	if (unlikely(err))
		goto error;
	sbi->zus_sbi = zim.zus_sbi;

	/* Init with default values */
	sb->s_blocksize_bits = zim.s_blocksize_bits;
	sb->s_blocksize = 1 << zim.s_blocksize_bits;

	sbi->mode = ZUFS_DEF_SBI_MODE;
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();

	rfi = &zuf_fst(sb)->rfi;

	sb->s_bdi = &sbi->bdi;
	sb->s_magic = rfi->FS_magic;
	sb->s_time_gran = rfi->s_time_gran;
	sb->s_maxbytes = rfi->s_maxbytes;
	sb->s_flags |= MS_NOSEC | (rfi->acl_on ? MS_POSIXACL : 0);

	sb->s_op = &zuf_sops;
	sb->s_xattr = tozu_xattr_handlers;

	root_i = zuf_iget(sb, zim.zus_ii, zim._zi, &exist);
	if (IS_ERR(root_i)) {
		err = PTR_ERR(root_i);
		goto error;
	}
	WARN_ON(exist);

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		zuf_err_cnd(silent, "get tozu root inode failed\n");
		iput(root_i); /* undo zuf_iget */
		err = -ENOMEM;
		goto error;
	}

	if (!zuf_rdonly(sb))
		_sb_mwtime_now(sb, md_zdt(sbi->md));

	_print_mount_info(sbi, fsp->mount_options);
	clear_opt(sbi, SILENT);
	return 0;

error:
	zuf_warn("NOT mounting => %d\n", err);
	set_opt(sbi, FAILED);
	zuf_put_super(sb);
	return err;
}

static void _zst_to_kst(const struct statfs64 *zst, struct kstatfs *kst)
{
	kst->f_type=    zst->f_type;
	kst->f_bsize=   zst->f_bsize;
	kst->f_blocks=  zst->f_blocks;
	kst->f_bfree=   zst->f_bfree;
	kst->f_bavail=  zst->f_bavail;
	kst->f_files=   zst->f_files;
	kst->f_ffree=   zst->f_ffree;
	kst->f_fsid=    zst->f_fsid;
	kst->f_namelen= zst->f_namelen;
	kst->f_frsize=  zst->f_frsize;
	kst->f_flags=   zst->f_flags;
}

static int zuf_statfs(struct dentry *d, struct kstatfs *buf)
{
	struct zuf_sb_info *sbi = SBI(d->d_sb);
	struct zufs_ioc_statfs ioc_statfs = {
		.hdr.in_len = offsetof(struct zufs_ioc_statfs, statfs_out),
		.hdr.out_len = sizeof(ioc_statfs),
		.hdr.operation = ZUS_OP_STATFS,
		.zus_sbi = sbi->zus_sbi,
	};
	int err;

	err = zufs_dispatch(ZUF_ROOT(sbi), &ioc_statfs.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_err("zufs_dispatch failed op=ZUS_OP_STATFS => %d\n", err);
		return err;
	}

	_zst_to_kst(&ioc_statfs.statfs_out, buf);
	return 0;
}

static int zuf_show_options(struct seq_file *seq, struct dentry *root)
{
	struct zuf_sb_info *sbi = SBI(root->d_sb);

	if (__kuid_val(sbi->uid) && uid_valid(sbi->uid))
		seq_printf(seq, ",uid=%u", __kuid_val(sbi->uid));
	if (__kgid_val(sbi->gid) && gid_valid(sbi->gid))
		seq_printf(seq, ",gid=%u", __kgid_val(sbi->gid));
	if (test_opt(sbi, EPHEMERAL))
		seq_printf(seq, ",ephemeral");
	if (test_opt(sbi, DAX))
		seq_printf(seq, ",dax");

	return 0;
}

static int zuf_show_devname(struct seq_file *seq, struct dentry *root)
{
	seq_printf(seq, "/dev/%s", _bdev_name(root->d_sb->s_bdev));

	return 0;
}

static int zuf_remount(struct super_block *sb, int *mntflags, char *data)
{
	unsigned long old_mount_opt;
	struct zuf_sb_info *sbi = SBI(sb);
	struct __parse_options po; /* Actually not used */
	int err;

	zuf_info("remount... -o %s\n", data);

	/* Store the old options */
	old_mount_opt = sbi->s_mount_opt;

	err = _parse_options(sbi, data, 1, &po);
	if (unlikely(err))
		goto fail;

	if ((*mntflags & MS_RDONLY) != zuf_rdonly(sb))
		_sb_mwtime_now(sb, md_zdt(sbi->md));

	return 0;

fail:
	sbi->s_mount_opt = old_mount_opt;
	zuf_dbg_err("remount failed restore option\n");
	return err;
}

static int zuf_update_s_wtime(struct super_block *sb)
{
	if (!(sb->s_flags & MS_RDONLY)) {
		struct timespec now = CURRENT_TIME;

		timespec_to_mt(&md_zdt(SBI(sb)->md)->s_wtime, &now);
	}
	return 0;
}

void tozu_add_mmap_inode(struct inode *inode)
{
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	struct zuf_inode_info *zii = ZUII(inode);

	zuf_dbg_mmap("[%ld] write_mapped=%d\n",
		      inode->i_ino, atomic_read(&zii->write_mapped));

	spin_lock(&sbi->s_mmap_dirty_lock);

	/* Because we are lazy removing the inodes, only in case of an fsync
	 * or an evict_inode. It is fine if we are call multiple times.
	 */
	if (list_empty(&zii->i_mmap_dirty))
		list_add(&zii->i_mmap_dirty, &sbi->s_mmap_dirty);

	spin_unlock(&sbi->s_mmap_dirty_lock);
}

void tozu_remove_mmap_inode(struct inode *inode)
{
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	struct zuf_inode_info *zii = ZUII(inode);

	zuf_dbg_mmap("[%ld] write_mapped=%d\n",
		      inode->i_ino, atomic_read(&zii->write_mapped));

	spin_lock(&sbi->s_mmap_dirty_lock);
	list_del_init(&zii->i_mmap_dirty);
	spin_unlock(&sbi->s_mmap_dirty_lock);
}

/*
 * We must fsync any mmap-active inodes
 */
static int tozu_sync_fs(struct super_block *sb, int wait)
{
	struct zuf_sb_info *sbi = SBI(sb);
	struct zuf_inode_info *zii, *t;
	enum {to_clean_size = 120};
	struct zuf_inode_info *zii_to_clean[to_clean_size];
	uint i, to_clean;

more_inodes:
	spin_lock(&sbi->s_mmap_dirty_lock);
	to_clean = 0;
	list_for_each_entry_safe(zii, t, &sbi->s_mmap_dirty, i_mmap_dirty) {
		list_del_init(&zii->i_mmap_dirty);
		zii_to_clean[to_clean++] = zii;
		if (to_clean >= to_clean_size)
			break;
	}
	spin_unlock(&sbi->s_mmap_dirty_lock);

	if (!to_clean)
		return 0;

	for (i = 0; i < to_clean; ++i)
		zuf_isync(&zii_to_clean[i]->vfs_inode, 0, ~0 - 1, 1);

	if (to_clean == to_clean_size)
		goto more_inodes;

	return 0;
}

static struct inode *zuf_alloc_inode(struct super_block *sb)
{
	struct zuf_inode_info *zii;

	zii = kmem_cache_alloc(zuf_inode_cachep, GFP_NOFS);
	if (!zii)
		return NULL;

	zii->vfs_inode.i_version = 1;
	return &zii->vfs_inode;
}

static void zuf_destroy_inode(struct inode *inode)
{
	kmem_cache_free(zuf_inode_cachep, ZUII(inode));
}

static void _init_once(void *foo)
{
	struct zuf_inode_info *zii = foo;

	inode_init_once(&zii->vfs_inode);
	INIT_LIST_HEAD(&zii->i_mmap_dirty);
	zii->zi = NULL;
	zii->zero_page = NULL;
	init_rwsem(&zii->in_sync);
	atomic_set(&zii->mapped, 0);
	atomic_set(&zii->vma_count, 0);
	atomic_set(&zii->write_mapped, 0);
}

int __init zuf_init_inodecache(void)
{
	zuf_inode_cachep = kmem_cache_create("zuf_inode_cache",
					       sizeof(struct zuf_inode_info),
					       0,
					       (SLAB_RECLAIM_ACCOUNT |
						SLAB_MEM_SPREAD |
						SLAB_DESTROY_BY_RCU),
					       _init_once);
	if (zuf_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void zuf_destroy_inodecache(void)
{
	kmem_cache_destroy(zuf_inode_cachep);
}

/*
 * the super block writes are all done "on the fly", so the
 * super block is never in a "dirty" state, so there's no need
 * for write_super.
 */
static struct super_operations zuf_sops = {
	.alloc_inode	= zuf_alloc_inode,
	.destroy_inode	= zuf_destroy_inode,
	.write_inode	= zuf_write_inode,
	.evict_inode	= zuf_evict_inode,
	.put_super	= zuf_put_super,
	.freeze_fs	= zuf_update_s_wtime,
	.unfreeze_fs	= zuf_update_s_wtime,
	.sync_fs	= tozu_sync_fs,
	.statfs		= zuf_statfs,
	.remount_fs	= zuf_remount,
	.show_options	= zuf_show_options,
	.show_devname	= zuf_show_devname,
};

static struct dentry *zuf_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	int silent = flags & MS_SILENT ? 1 : 0;
	struct __fill_super_params fsp = {
		.mount_options = data,
	};
	struct dentry *ret = NULL;
	const char *dev_path = NULL;
	struct zuf_fs_type *fst;
	int err;

	zuf_dbg_vfs("dev_name=%s, data=%s\n", dev_name, (const char *)data);

	fsp.md = md_alloc(sizeof(struct zuf_pmem));
	if (IS_ERR(fsp.md)) {
		err = PTR_ERR(fsp.md);
		fsp.md = NULL;
		goto out;
	}

	err = md_init(fsp.md, dev_name, fs_type, silent, &dev_path);
	if (unlikely(err)) {
		zuf_err_cnd(silent, "md_init failed! => %d\n", err);
		goto out;
	}

	fst = container_of(fs_type, struct zuf_fs_type, vfs_fst);
	zuf_add_pmem(fst->zri, fsp.md);

	zuf_dbg_vfs("mounting with dev_path=%s\n", dev_path);
	ret = mount_bdev(fs_type, flags, dev_path, &fsp, zuf_fill_super);

out:
	if (unlikely(err) && fsp.md)
		md_fini(fsp.md, NULL);
	kfree(dev_path);
	return err ? ERR_PTR(err) : ret;
}

struct zuf_fs_type g_fs_array[5];

int zuf_register_fs(struct super_block *sb, struct zufs_ioc_register_fs *rfs)
{
	struct zuf_fs_type *zft = /*kzalloc(sizeof(*zft), GFP_KERNEL)*/
				  &g_fs_array[0];

	if (unlikely(!zft))
		return -ENOMEM;

	/* Original vfs file type */
	zft->vfs_fst.owner	= THIS_MODULE;
	zft->vfs_fst.name	= kstrdup(rfs->rfi.fsname, GFP_KERNEL);
	zft->vfs_fst.mount	= zuf_mount,
	zft->vfs_fst.kill_sb	= kill_block_super,

	/* ZUS info about this FS */
	zft->rfi 		= rfs->rfi;
	zft->zus_zfi		= rfs->zus_zfi;
	INIT_LIST_HEAD(&zft->list);
	/* Back pointer to our communication channels */
	zft->zri		= ZRI(sb);

	zuf_add_fs_type(zft->zri, zft);
	zuf_info("register_filesystem [%s]\n", zft->vfs_fst.name);
	return register_filesystem(&zft->vfs_fst);
}
