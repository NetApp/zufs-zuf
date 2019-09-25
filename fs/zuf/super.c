// SPDX-License-Identifier: GPL-2.0
/*
 * Super block operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>
 */

#include <linux/types.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/backing-dev.h>

#include "zuf.h"

static struct super_operations zuf_sops;
static struct kmem_cache *zuf_inode_cachep;

enum {
	Opt_uid,
	Opt_gid,
	Opt_pedantic,
	Opt_ephemeral,
	Opt_dax,
	Opt_zpmdev,
	Opt_err
};

static const match_table_t tokens = {
	{ Opt_pedantic,		"pedantic"		},
	{ Opt_pedantic,		"pedantic=%d"		},
	{ Opt_ephemeral,	"ephemeral"		},
	{ Opt_dax,		"dax"			},
	{ Opt_zpmdev,		ZUFS_PMDEV_OPT"=%s"	},
	{ Opt_err,		NULL			},
};

static int _parse_options(struct zuf_sb_info *sbi, const char *data,
			  bool remount, struct zufs_parse_options *po)
{
	char *orig_options, *options;
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int err = 0;
	bool ephemeral = false;
	bool silent = test_opt(sbi, SILENT);
	size_t mount_options_len = 0;

	/* no options given */
	if (!data)
		return 0;

	options = orig_options = kstrdup(data, GFP_KERNEL);
	if (!options) {
		zuf_err_cnd(silent, "kstrdup => -ENOMEM\n");
		return -ENOMEM;
	}

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		/* Initialize args struct so we know whether arg was found */
		args[0].to = args[0].from = NULL;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_pedantic:
			if (!args[0].from) {
				po->mount_flags |= ZUFS_M_PEDANTIC;
				set_opt(sbi, PEDANTIC);
				continue;
			}
			if (match_int(&args[0], &po->pedantic))
				goto bad_opt;
			break;
		case Opt_ephemeral:
			po->mount_flags |= ZUFS_M_EPHEMERAL;
			set_opt(sbi, EPHEMERAL);
			ephemeral = true;
			break;
		case Opt_dax:
			set_opt(sbi, DAX);
			break;
		case Opt_zpmdev:
			if (unlikely(!test_opt(sbi, PRIVATE)))
				goto bad_opt;
			sbi->pmount_dev = match_strdup(&args[0]);
			if (sbi->pmount_dev == NULL)
				goto no_mem;
			break;
		default: {
			if (mount_options_len != 0) {
				po->mount_options[mount_options_len] = ',';
				mount_options_len++;
			}
			strcat(po->mount_options, p);
			mount_options_len += strlen(p);
		}
		}
	}

	if (remount && test_opt(sbi, EPHEMERAL) && (ephemeral == false))
		clear_opt(sbi, EPHEMERAL);
out:
	kfree(orig_options);
	return err;

bad_opt:
	zuf_warn_cnd(silent, "Bad mount option: \"%s\"\n", p);
	err = -EINVAL;
	goto out;
no_mem:
	zuf_warn_cnd(silent, "Not enough memory to parse options");
	err = -ENOMEM;
	goto out;
}

static int _print_tier_info(struct multi_devices *md, char **buff, int start,
			    int count, int *_space, char *str)
{
	int space = *_space;
	char *b = *buff;
	int printed;
	int i;

	printed = snprintf(b, space, str);
	if (unlikely(printed > space))
		return -ENOSPC;

	b += printed;
	space -= printed;

	for (i = start; i < start + count; ++i) {
		printed = snprintf(b, space, "%s%s", i == start ? "" : ",",
				   _bdev_name(md_dev_info(md, i)->bdev));

		if (unlikely(printed > space))
			return -ENOSPC;

		b += printed;
		space -= printed;
	}
	*_space = space;
	*buff = b;

	return 0;
}

static void _print_mount_info(struct zuf_sb_info *sbi, char *mount_options)
{
	struct multi_devices *md = sbi->md;
	char buff[992];
	int space = sizeof(buff);
	char *b = buff;
	int err;

	err = _print_tier_info(md, &b, 0, md->t1_count, &space, "t1=");
	if (unlikely(err))
		goto no_space;

	if (md->t2_count == 0)
		goto print_options;

	err = _print_tier_info(md, &b, md->t1_count, md->t2_count, &space,
			       " t2=");
	if (unlikely(err))
		goto no_space;

print_options:
	if (mount_options) {
		int printed = snprintf(b, space, " -o %s", mount_options);

		if (unlikely(printed > space))
			goto no_space;
	}

print:
	zuf_info("mounted %s (0x%lx/0x%lx)\n", buff,
		 md_t1_blocks(sbi->md), md_t2_blocks(sbi->md));
	return;

no_space:
	snprintf(buff + sizeof(buff) - 4, 4, "...");
	goto print;
}

static void _sb_mwtime_now(struct super_block *sb, struct md_dev_table *zdt)
{
	struct timespec64 now = current_time(sb->s_root->d_inode);

	timespec_to_mt(&zdt->s_mtime, &now);
	zdt->s_wtime = zdt->s_mtime;
	/* TOZO _persist_md(sb, &zdt->s_mtime, 2*sizeof(zdt->s_mtime)); */
}

static void _clean_bdi(struct super_block *sb)
{
	if (sb->s_bdi != &noop_backing_dev_info) {
		bdi_put(sb->s_bdi);
		sb->s_bdi = &noop_backing_dev_info;
	}
}

static int _setup_bdi(struct super_block *sb, const char *device_name)
{
	const char *n = sb->s_type->name;
	int err;

	if (sb->s_bdi)
		_clean_bdi(sb);

	err = super_setup_bdi_name(sb, "%s-%s", n, device_name);
	if (unlikely(err)) {
		zuf_err("Failed to super_setup_bdi\n");
		return err;
	}

	sb->s_bdi->ra_pages = ZUFS_READAHEAD_PAGES;
	sb->s_bdi->capabilities = BDI_CAP_NO_ACCT_AND_WRITEBACK;
	return 0;
}

static int _sb_add(struct zuf_root_info *zri, struct super_block *sb,
		   __u64 *sb_id)
{
	uint i;
	int err;

	mutex_lock(&zri->sbl_lock);

	if (zri->sbl.num == zri->sbl.max) {
		struct super_block **new_array;

		new_array = krealloc(zri->sbl.array,
				  (zri->sbl.max + SBL_INC) * sizeof(*new_array),
				  GFP_KERNEL | __GFP_ZERO);
		if (unlikely(!new_array)) {
			err = -ENOMEM;
			goto out;
		}
		zri->sbl.max += SBL_INC;
		zri->sbl.array = new_array;
	}

	for (i = 0; i < zri->sbl.max; ++i)
		if (!zri->sbl.array[i])
			break;

	if (unlikely(i == zri->sbl.max)) {
		zuf_err("!!!!! can't be! i=%d g_sbl.num=%d g_sbl.max=%d\n",
			i, zri->sbl.num, zri->sbl.max);
		err = -EFAULT;
		goto out;
	}

	++zri->sbl.num;
	zri->sbl.array[i] = sb;
	*sb_id = i + 1;
	err = 0;

	zuf_dbg_vfs("sb_id=%lld\n", *sb_id);
out:
	mutex_unlock(&zri->sbl_lock);
	return err;
}

static void _sb_remove(struct zuf_root_info *zri, struct super_block *sb)
{
	uint i;

	mutex_lock(&zri->sbl_lock);

	for (i = 0; i < zri->sbl.max; ++i)
		if (zri->sbl.array[i] == sb)
			break;
	if (unlikely(i == zri->sbl.max)) {
		zuf_err("!!!!! can't be! i=%d g_sbl.num=%d g_sbl.max=%d\n",
			i, zri->sbl.num, zri->sbl.max);
		goto out;
	}

	zri->sbl.array[i] = NULL;
	--zri->sbl.num;
out:
	mutex_unlock(&zri->sbl_lock);
}

struct super_block *zuf_sb_from_id(struct zuf_root_info *zri, __u64 sb_id,
				   struct zus_sb_info *zus_sbi)
{
	struct super_block *sb;

	--sb_id;

	if (zri->sbl.max <= sb_id) {
		zuf_err("Invalid SB_ID 0x%llx\n", sb_id);
		return NULL;
	}

	sb = zri->sbl.array[sb_id];
	if (!sb) {
		zuf_err("Stale SB_ID 0x%llx\n", sb_id);
		return NULL;
	}

	return sb;
}

static void zuf_put_super(struct super_block *sb)
{
	struct zuf_sb_info *sbi = SBI(sb);

	/* FIXME: This is because of a Kernel BUG (in v4.20) which
	 * sometimes complains in _setup_bdi() on a recycle_mount that sysfs
	 * bdi already exists. Cleaning here solves it.
	 * Calling synchronize_rcu in zuf_kill_sb() after the call to
	 * kill_block_super() does NOT solve it.
	 */
	_clean_bdi(sb);

	if (sbi->zus_sbi) {
		struct zufs_ioc_mount zim = {
			.zmi.zus_sbi = sbi->zus_sbi,
		};

		zufc_dispatch_mount(ZUF_ROOT(sbi), NULL, ZUFS_M_UMOUNT, &zim);
		sbi->zus_sbi = NULL;
	}

	/* NOTE!!! this is a HACK! we should not touch the s_umount
	 * lock but to make lockdep happy we do that since our devices
	 * are held exclusivly. Need to revisit every kernel version
	 * change.
	 */
	if (sbi->md) {
		up_write(&sb->s_umount);
		md_fini(sbi->md, false);
		down_write(&sb->s_umount);
	}

	_sb_remove(ZUF_ROOT(sbi), sb);
	sb->s_fs_info = NULL;
	if (!test_opt(sbi, FAILED))
		zuf_info("unmounted /dev/%s\n", _bdev_name(sb->s_bdev));
	kfree(sbi);
}

struct __fill_super_params {
	struct multi_devices *md;
	char *mount_options;
};

int zuf_private_mount(struct zuf_root_info *zri, struct register_fs_info *rfi,
		      struct zufs_mount_info *zmi, struct super_block **sb_out)
{
	bool silent = zmi->po.mount_flags & ZUFS_M_SILENT;
	char path[PATH_UUID];
	const char *dev_path = NULL;
	struct zuf_sb_info *sbi;
	struct super_block *sb;
	char *mount_options;
	struct mdt_check mc = {
		.alloc_mask	= ZUFS_ALLOC_MASK,
		.major_ver	= rfi->FS_ver_major,
		.minor_ver	= rfi->FS_ver_minor,
		.magic		= rfi->FS_magic,

		.silent = silent,
		.private_mnt = true,
	};
	int err;

	sb = kzalloc(sizeof(struct super_block), GFP_KERNEL);
	if (unlikely(!sb)) {
		zuf_err_cnd(silent, "Not enough memory to allocate sb\n");
		return -ENOMEM;
	}

	sbi = kzalloc(sizeof(struct zuf_sb_info), GFP_KERNEL);
	if (unlikely(!sbi)) {
		zuf_err_cnd(silent, "Not enough memory to allocate sbi\n");
		kfree(sb);
		return -ENOMEM;
	}

	sb->s_fs_info = sbi;
	sbi->sb = sb;

	zmi->po.mount_flags |= ZUFS_M_PRIVATE;
	set_opt(sbi, PRIVATE);

	mount_options = kstrndup(zmi->po.mount_options,
				 zmi->po.mount_options_len, GFP_KERNEL);
	if (unlikely(!mount_options)) {
		zuf_err_cnd(silent, "Not enough memory\n");
		err = -ENOMEM;
		goto fail;
	}

	memset(zmi->po.mount_options, 0, zmi->po.mount_options_len);

	err = _parse_options(sbi, mount_options, 0, &zmi->po);
	if (unlikely(err)) {
		zuf_err_cnd(silent, "option parsing failed => %d\n", err);
		goto fail;
	}

	if (unlikely(!sbi->pmount_dev)) {
		zuf_err_cnd(silent, "private mount missing mountdev option\n");
		err = -EINVAL;
		goto fail;
	}

	zmi->po.mount_options_len = strlen(zmi->po.mount_options);

	mc.holder = sbi;
	err = md_init(&sbi->md, sbi->pmount_dev, &mc, path, &dev_path);
	if (unlikely(err)) {
		zuf_err_cnd(silent, "md_init failed! => %d\n", err);
		goto fail;
	}

	zuf_dbg_verbose("private mount of %s\n", dev_path);

	err = _sb_add(zri, sb, &zmi->sb_id);
	if (unlikely(err)) {
		zuf_err_cnd(silent, "_sb_add failed => %d\n", err);
		goto fail;
	}

	*sb_out = sb;
	return 0;

fail:
	if (sbi->md)
		md_fini(sbi->md, true);
	kfree(mount_options);
	kfree(sbi->pmount_dev);
	kfree(sbi);
	kfree(sb);

	return err;
}

int zuf_private_umount(struct zuf_root_info *zri, struct super_block *sb)
{
	struct zuf_sb_info *sbi = SBI(sb);

	_sb_remove(zri, sb);
	md_fini(sbi->md, true);
	kfree(sbi->pmount_dev);
	kfree(sbi);
	kfree(sb);

	return 0;
}

static int zuf_fill_super(struct super_block *sb, void *data, int silent)
{
	struct zuf_sb_info *sbi = NULL;
	struct __fill_super_params *fsp = data;
	struct zufs_ioc_mount zim = {};
	struct zufs_ioc_mount *ioc_mount;
	enum big_alloc_type bat;
	struct register_fs_info *rfi;
	struct inode *root_i;
	size_t zim_size, mount_options_len;
	bool exist;
	int err;

	BUILD_BUG_ON(sizeof(struct md_dev_table) > MDT_SIZE);
	BUILD_BUG_ON(sizeof(struct zus_inode) != ZUFS_INODE_SIZE);

	mount_options_len = (fsp->mount_options ?
					strlen(fsp->mount_options) : 0) + 1;
	zim_size = sizeof(zim) + mount_options_len;
	ioc_mount = big_alloc(zim_size, sizeof(zim), &zim,
			      GFP_KERNEL | __GFP_ZERO, &bat);
	if (unlikely(!ioc_mount)) {
		zuf_err_cnd(silent, "big_alloc(%ld) => -ENOMEM\n", zim_size);
		return -ENOMEM;
	}

	ioc_mount->zmi.po.mount_options_len = mount_options_len;

	err = _sb_add(zuf_fst(sb)->zri, sb, &ioc_mount->zmi.sb_id);
	if (unlikely(err)) {
		zuf_err_cnd(silent, "_sb_add failed => %d\n", err);
		goto error;
	}

	sbi = kzalloc(sizeof(struct zuf_sb_info), GFP_KERNEL);
	if (!sbi) {
		zuf_err_cnd(silent, "Not enough memory to allocate sbi\n");
		err = -ENOMEM;
		goto error;
	}
	sb->s_fs_info = sbi;
	sbi->sb = sb;

	/* Initialize embedded objects */
	spin_lock_init(&sbi->s_mmap_dirty_lock);
	INIT_LIST_HEAD(&sbi->s_mmap_dirty);
	if (silent) {
		ioc_mount->zmi.po.mount_flags |= ZUFS_M_SILENT;
		set_opt(sbi, SILENT);
	}

	sbi->md = fsp->md;
	err = md_set_sb(sbi->md, sb->s_bdev, sb, silent);
	if (unlikely(err))
		goto error;

	err = _parse_options(sbi, fsp->mount_options, 0, &ioc_mount->zmi.po);
	if (err)
		goto error;

	err = _setup_bdi(sb, _bdev_name(sb->s_bdev));
	if (err) {
		zuf_err_cnd(silent, "Failed to setup bdi => %d\n", err);
		goto error;
	}

	/* Tell ZUS to mount an FS for us */
	err = zufc_dispatch_mount(ZUF_ROOT(sbi), zuf_fst(sb)->zus_zfi,
				  ZUFS_M_MOUNT, ioc_mount);
	if (unlikely(err)) {
		zuf_err_cnd(silent, "zufc_dispatch_mount failed => %d\n", err);
		goto error;
	}
	sbi->zus_sbi = ioc_mount->zmi.zus_sbi;

	/* Init with default values */
	sb->s_blocksize_bits = ioc_mount->zmi.s_blocksize_bits;
	sb->s_blocksize = 1 << ioc_mount->zmi.s_blocksize_bits;

	rfi = &zuf_fst(sb)->rfi;

	sb->s_magic = rfi->FS_magic;
	sb->s_time_gran = rfi->s_time_gran;
	sb->s_maxbytes = rfi->s_maxbytes;
	sb->s_flags |= SB_NOSEC;

	sbi->fs_caps = ioc_mount->zmi.fs_caps;
	if (sbi->fs_caps & ZUFS_FSC_ACL_ON)
		sb->s_flags |= SB_POSIXACL;

	sb->s_op = &zuf_sops;

	root_i = zuf_iget(sb, ioc_mount->zmi.zus_ii, ioc_mount->zmi._zi,
			  &exist);
	if (IS_ERR(root_i)) {
		err = PTR_ERR(root_i);
		zuf_err_cnd(silent, "zuf_iget failed => %d\n", err);
		goto error;
	}
	WARN_ON(exist);

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		zuf_err_cnd(silent, "d_make_root root inode failed\n");
		iput(root_i); /* undo zuf_iget */
		err = -ENOMEM;
		goto error;
	}

	if (!zuf_rdonly(sb))
		_sb_mwtime_now(sb, md_zdt(sbi->md));

	mt_to_timespec(&root_i->i_ctime, &zus_zi(root_i)->i_ctime);
	mt_to_timespec(&root_i->i_mtime, &zus_zi(root_i)->i_mtime);

	_print_mount_info(sbi, fsp->mount_options);
	clear_opt(sbi, SILENT);
	big_free(ioc_mount, bat);
	return 0;

error:
	zuf_warn("NOT mounting => %d\n", err);
	if (sbi) {
		set_opt(sbi, FAILED);
		zuf_put_super(sb);
	}
	big_free(ioc_mount, bat);
	return err;
}

static void _zst_to_kst(const struct statfs64 *zst, struct kstatfs *kst)
{
	kst->f_type	= zst->f_type;
	kst->f_bsize	= zst->f_bsize;
	kst->f_blocks	= zst->f_blocks;
	kst->f_bfree	= zst->f_bfree;
	kst->f_bavail	= zst->f_bavail;
	kst->f_files	= zst->f_files;
	kst->f_ffree	= zst->f_ffree;
	kst->f_fsid	= zst->f_fsid;
	kst->f_namelen	= zst->f_namelen;
	kst->f_frsize	= zst->f_frsize;
	kst->f_flags	= zst->f_flags;
}

static int zuf_statfs(struct dentry *d, struct kstatfs *buf)
{
	struct zuf_sb_info *sbi = SBI(d->d_sb);
	struct zufs_ioc_statfs ioc_statfs = {
		.hdr.in_len = offsetof(struct zufs_ioc_statfs, statfs_out),
		.hdr.out_len = sizeof(ioc_statfs),
		.hdr.operation = ZUFS_OP_STATFS,
		.zus_sbi = sbi->zus_sbi,
	};
	int err;

	err = zufc_dispatch(ZUF_ROOT(sbi), &ioc_statfs.hdr, NULL, 0);
	if (unlikely(err && err != -EINTR)) {
		zuf_err_dispatch(d->d_sb,
			"zufc_dispatch failed op=ZUFS_OP_STATFS => %d\n",
			err);
		return err;
	}

	_zst_to_kst(&ioc_statfs.statfs_out, buf);
	return 0;
}

struct __mount_options {
	struct zufs_ioc_mount_options imo;
	char buf[ZUFS_MO_MAX];
};

static int zuf_show_options(struct seq_file *seq, struct dentry *root)
{
	struct zuf_sb_info *sbi = SBI(root->d_sb);
	struct __mount_options mo = {
		.imo.hdr.in_len = sizeof(mo.imo),
		.imo.hdr.out_start = offsetof(typeof(mo.imo), buf),
		.imo.hdr.out_len = 0,
		.imo.hdr.out_max = sizeof(mo.buf),
		.imo.hdr.operation = ZUFS_OP_SHOW_OPTIONS,
		.imo.zus_sbi = sbi->zus_sbi,
	};
	int err;

	if (test_opt(sbi, EPHEMERAL))
		seq_puts(seq, ",ephemeral");
	if (test_opt(sbi, DAX))
		seq_puts(seq, ",dax");

	err = zufc_dispatch(ZUF_ROOT(sbi), &mo.imo.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_err_dispatch(root->d_sb,
			"zufs_dispatch failed op=ZUS_OP_SHOW_OPTIONS => %d\n",
			err);
		/* NOTE: if zusd crashed and we try to run 'umount', it will
		 * SEGFAULT because zufc_dispatch will return -EFAULT.
		 * Just return 0 as if the FS has no specific mount options.
		 */
		return 0;
	}
	seq_puts(seq, mo.buf);

	return 0;
}

static int zuf_show_devname(struct seq_file *seq, struct dentry *root)
{
	seq_printf(seq, "/dev/%s", _bdev_name(root->d_sb->s_bdev));

	return 0;
}

static int zuf_remount(struct super_block *sb, int *mntflags, char *data)
{
	struct zuf_sb_info *sbi = SBI(sb);
	struct zufs_ioc_mount zim = {};
	struct zufs_ioc_mount *ioc_mount;
	size_t remount_options_len, zim_size;
	enum big_alloc_type bat;
	ulong old_mount_opt = sbi->s_mount_opt;
	int err;

	zuf_info("remount... -o %s\n", data);

	remount_options_len = data ? (strlen(data) + 1) : 0;
	zim_size = sizeof(zim) + remount_options_len;
	ioc_mount = big_alloc(zim_size, sizeof(zim), &zim,
			      GFP_KERNEL | __GFP_ZERO, &bat);
	if (unlikely(!ioc_mount))
		return -ENOMEM;

	ioc_mount->zmi.zus_sbi = sbi->zus_sbi,
	ioc_mount->zmi.remount_flags = zuf_rdonly(sb) ? ZUFS_REM_WAS_RO : 0;
	ioc_mount->zmi.po.mount_options_len = remount_options_len;

	err = _parse_options(sbi, data, 1, &ioc_mount->zmi.po);
	if (unlikely(err))
		goto fail;

	if (*mntflags & SB_RDONLY) {
		ioc_mount->zmi.remount_flags |= ZUFS_REM_WILL_RO;

		if (!zuf_rdonly(sb))
			_sb_mwtime_now(sb, md_zdt(sbi->md));
	} else if (zuf_rdonly(sb)) {
		_sb_mwtime_now(sb, md_zdt(sbi->md));
	}

	err = zufc_dispatch_mount(ZUF_ROOT(sbi), zuf_fst(sb)->zus_zfi,
				  ZUFS_M_REMOUNT, ioc_mount);
	if (unlikely(err))
		goto fail;

	big_free(ioc_mount, bat);
	return 0;

fail:
	sbi->s_mount_opt = old_mount_opt;
	big_free(ioc_mount, bat);
	zuf_dbg_err("remount failed restore option\n");
	return err;
}

static int zuf_update_s_wtime(struct super_block *sb)
{
	if (!(zuf_rdonly(sb))) {
		struct timespec64 now = current_time(sb->s_root->d_inode);

		timespec_to_mt(&md_zdt(SBI(sb)->md)->s_wtime, &now);
	}
	return 0;
}

static void _sync_add_inode(struct inode *inode)
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

static void _sync_remove_inode(struct inode *inode)
{
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	struct zuf_inode_info *zii = ZUII(inode);

	zuf_dbg_mmap("[%ld] write_mapped=%d\n",
		      inode->i_ino, atomic_read(&zii->write_mapped));

	spin_lock(&sbi->s_mmap_dirty_lock);
	list_del_init(&zii->i_mmap_dirty);
	spin_unlock(&sbi->s_mmap_dirty_lock);
}

void zuf_sync_inc(struct inode *inode)
{
	struct zuf_inode_info *zii = ZUII(inode);

	if (1 == atomic_inc_return(&zii->write_mapped))
		_sync_add_inode(inode);
}

/* zuf_sync_dec will unmapped in batches */
void zuf_sync_dec(struct inode *inode, ulong write_unmapped)
{
	struct zuf_inode_info *zii = ZUII(inode);

	if (0 == atomic_sub_return(write_unmapped, &zii->write_mapped))
		_sync_remove_inode(inode);
}

/*
 * We must fsync any mmap-active inodes
 */
static int zuf_sync_fs(struct super_block *sb, int wait)
{
	struct zuf_sb_info *sbi = SBI(sb);
	struct zuf_inode_info *zii, *t;
	enum {to_clean_size = 120};
	struct zuf_inode_info *zii_to_clean[to_clean_size];
	uint i, to_clean;

	zuf_dbg_vfs("Syncing wait=%d\n", wait);
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

	zii->vfs_inode.i_version.counter = 1;
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
	init_rwsem(&zii->in_sync);
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
						SLAB_TYPESAFE_BY_RCU),
					       _init_once);
	if (zuf_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void zuf_destroy_inodecache(void)
{
	kmem_cache_destroy(zuf_inode_cachep);
}

static struct super_operations zuf_sops = {
	.alloc_inode	= zuf_alloc_inode,
	.destroy_inode	= zuf_destroy_inode,
	.write_inode	= zuf_write_inode,
	.evict_inode	= zuf_evict_inode,
	.put_super	= zuf_put_super,
	.freeze_fs	= zuf_update_s_wtime,
	.unfreeze_fs	= zuf_update_s_wtime,
	.sync_fs	= zuf_sync_fs,
	.statfs		= zuf_statfs,
	.remount_fs	= zuf_remount,
	.show_options	= zuf_show_options,
	.show_devname	= zuf_show_devname,
};

struct dentry *zuf_mount(struct file_system_type *fs_type, int flags,
			 const char *dev_name, void *data)
{
	int silent = flags & SB_SILENT ? 1 : 0;
	struct __fill_super_params fsp = {
		.mount_options = data,
	};
	struct zuf_fs_type *fst = ZUF_FST(fs_type);
	struct register_fs_info *rfi = &fst->rfi;
	struct mdt_check mc = {
		.alloc_mask	= ZUFS_ALLOC_MASK,
		.major_ver	= rfi->FS_ver_major,
		.minor_ver	= rfi->FS_ver_minor,
		.magic		= rfi->FS_magic,

		.holder = fs_type,
		.silent = silent,
	};
	struct dentry *ret = NULL;
	char path[PATH_UUID];
	const char *dev_path = NULL;
	int err;

	zuf_dbg_vfs("dev_name=%s, data=%s\n", dev_name, (const char *)data);

	err = md_init(&fsp.md, dev_name, &mc, path, &dev_path);
	if (unlikely(err)) {
		zuf_err_cnd(silent, "md_init failed! => %d\n", err);
		goto out;
	}

	zuf_dbg_vfs("mounting with dev_path=%s\n", dev_path);
	ret = mount_bdev(fs_type, flags, dev_path, &fsp, zuf_fill_super);

out:
	if (unlikely(err) && fsp.md)
		md_fini(fsp.md, true);

	return err ? ERR_PTR(err) : ret;
}

// ==== 8k fast_alloc ====
static struct kmem_cache *zuf_8k_cachep;

void *zuf_8k_alloc(gfp_t gfp)
{
	return kmem_cache_alloc(zuf_8k_cachep, gfp);
}

void zuf_8k_free(void *ptr)
{
	kmem_cache_free(zuf_8k_cachep, ptr);
}

int __init zuf_8k_cache_init(void)
{
	zuf_8k_cachep = kmem_cache_create("zuf_8k_cache", S_8K, 0, 0, NULL);
	if (unlikely(!zuf_8k_cachep))
		return -ENOMEM;
	return 0;
}

void zuf_8k_cache_fini(void)
{
	kmem_cache_destroy(zuf_8k_cachep);
}
