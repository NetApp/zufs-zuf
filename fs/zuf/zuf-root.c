// SPDX-License-Identifier: GPL-2.0
/*
 * ZUF Root filesystem.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * ZUF core is mounted on a small specialized FS that
 * provides the communication with the mount thread, zuf multy-channel
 * communication [ZTs], and the pmem devices.
 * Subsequently all FS super_blocks are children of this root, and point
 * to it. All using the same zuf communication multy-channel.
 *
 * [
 * TODO:
 *	Multiple servers can run on Multiple mounted roots. Each registering
 *	their own FSTYPEs. Admin should make sure that the FSTYPEs do not
 *	overlap
 * ]
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <asm-generic/mman.h>

#include "zuf.h"

/* ~~~~ Register/Unregister FS-types ~~~~ */
#ifdef CONFIG_LOCKDEP

/*
 * NOTE: When CONFIG_LOCKDEP is on the register_filesystem complains when
 * the fstype object is from a kmalloc. Because of some lockdep_keys not
 * being const_obj something.
 *
 * So in this case we have maximum of 16 fstypes system wide
 * (Total for all mounted zuf_root(s)). This way we can have them
 * in const_obj memory below at g_fs_array
 */

enum { MAX_LOCKDEP_FSs = 16 };
static uint g_fs_next;
static struct zuf_fs_type g_fs_array[MAX_LOCKDEP_FSs];

static struct zuf_fs_type *_fs_type_alloc(void)
{
	struct zuf_fs_type *ret;

	if (MAX_LOCKDEP_FSs <= g_fs_next)
		return NULL;

	ret = &g_fs_array[g_fs_next++];
	memset(ret, 0, sizeof(*ret));
	return ret;
}

static void _fs_type_free(struct zuf_fs_type *zft)
{
	if (zft == &g_fs_array[0])
		g_fs_next = 0;
}

#else /* !CONFIG_LOCKDEP*/
static struct zuf_fs_type *_fs_type_alloc(void)
{
	return kcalloc(1, sizeof(struct zuf_fs_type), GFP_KERNEL);
}

static void _fs_type_free(struct zuf_fs_type *zft)
{
	kfree(zft);
}
#endif /*CONFIG_LOCKDEP*/

int zufr_register_fs(struct super_block *sb, struct zufs_ioc_register_fs *rfs)
{
	struct zuf_fs_type *zft = _fs_type_alloc();

	if (unlikely(!zft))
		return -ENOMEM;

	/* Original vfs file type */
	zft->vfs_fst.owner	= THIS_MODULE;
	zft->vfs_fst.name	= kstrdup(rfs->rfi.fsname, GFP_KERNEL);
	zft->vfs_fst.mount	= zuf_mount;
	zft->vfs_fst.kill_sb	= kill_block_super;

	/* ZUS info about this FS */
	zft->rfi		= rfs->rfi;
	zft->zus_zfi		= rfs->zus_zfi;
	INIT_LIST_HEAD(&zft->list);
	/* Back pointer to our communication channels */
	zft->zri		= ZRI(sb);

	zuf_add_fs_type(zft->zri, zft);
	zuf_info("register_filesystem [%s]\n", zft->vfs_fst.name);
	return register_filesystem(&zft->vfs_fst);
}

static void _unregister_all_fses(struct zuf_root_info *zri)
{
	struct zuf_fs_type *zft, *n;

	list_for_each_entry_safe_reverse(zft, n, &zri->fst_list, list) {
		unregister_filesystem(&zft->vfs_fst);
		list_del_init(&zft->list);
		_fs_type_free(zft);
	}
}

static int zufr_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	drop_nlink(inode);
	return 0;
}

/* Force alignment of 2M for all vma(s)
 *
 * This belongs to t1.c and what it does for mmap. But we do not mind
 * that both our mmaps (grab_pmem or ZTs) will be 2M aligned so keep
 * it here. And zus mappings just all match perfectly with no need for
 * holes.
 * FIXME: This is copy/paste from dax-device. It can be very much simplified
 * for what we need.
 */
static unsigned long zufr_get_unmapped_area(struct file *filp,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	unsigned long off, off_end, off_align, len_align, addr_align;
	unsigned long align = PMD_SIZE;

	if (addr)
		goto out;

	off = pgoff << PAGE_SHIFT;
	off_end = off + len;
	off_align = round_up(off, align);

	if ((off_end <= off_align) || ((off_end - off_align) < align))
		goto out;

	len_align = len + align;
	if ((off + len_align) < off)
		goto out;

	addr_align = current->mm->get_unmapped_area(filp, addr, len_align,
			pgoff, flags);
	if (!IS_ERR_VALUE(addr_align)) {
		addr_align += (off - addr_align) & (align - 1);
		return addr_align;
	}
 out:
	return current->mm->get_unmapped_area(filp, addr, len, pgoff, flags);
}

static const struct inode_operations zufr_inode_operations;
static const struct file_operations zufr_file_dir_operations = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.llseek		= dcache_dir_lseek,
	.read		= generic_read_dir,
	.iterate_shared	= dcache_readdir,
	.fsync		= noop_fsync,
	.unlocked_ioctl = zufc_ioctl,
};
static const struct file_operations zufr_file_reg_operations = {
	.fsync			= noop_fsync,
	.unlocked_ioctl		= zufc_ioctl,
	.get_unmapped_area	= zufr_get_unmapped_area,
	.mmap			= zufc_mmap,
	.release		= zufc_release,
};

static int zufr_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct zuf_root_info *zri = ZRI(dir->i_sb);
	struct inode *inode;
	int err;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	/* We need to impersonate device-dax (S_DAX + S_IFCHR) in order to get
	 * the PMD (huge) page faults and allow RDMA memory access via GUP
	 * (get_user_pages_longterm).
	 */
	inode->i_flags = S_DAX;
	mode = (mode & ~S_IFREG) | S_IFCHR; /* change file type to char */

	inode->i_ino = ++zri->next_ino; /* none atomic only one mount thread */
	inode->i_blocks = inode->i_size = 0;
	inode->i_ctime = inode->i_mtime = current_time(inode);
	inode->i_atime = inode->i_ctime;
	inode_init_owner(inode, dir, mode);

	inode->i_op = &zufr_inode_operations;
	inode->i_fop = &zufr_file_reg_operations;

	err = insert_inode_locked(inode);
	if (unlikely(err)) {
		zuf_err("[%ld] insert_inode_locked => %d\n", inode->i_ino, err);
		goto fail;
	}
	d_tmpfile(dentry, inode);
	unlock_new_inode(inode);
	return 0;

fail:
	clear_nlink(inode);
	make_bad_inode(inode);
	iput(inode);
	return err;
}

static void zufr_put_super(struct super_block *sb)
{
	struct zuf_root_info *zri = ZRI(sb);

	zufc_zts_fini(zri);
	_unregister_all_fses(zri);

	zuf_info("zuf_root umount\n");
}

static void zufr_evict_inode(struct inode *inode)
{
	clear_inode(inode);
}

static const struct inode_operations zufr_inode_operations = {
	.lookup		= simple_lookup,

	.tmpfile	= zufr_tmpfile,
	.unlink		= zufr_unlink,
};
static const struct super_operations zufr_super_operations = {
	.statfs		= simple_statfs,

	.evict_inode	= zufr_evict_inode,
	.put_super	= zufr_put_super,
};

#define ZUFR_SUPER_MAGIC 0x1717

static int zufr_fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tree_descr zufr_files[] = {
		{""},
	};
	struct zuf_root_info *zri;
	struct inode *root_i;
	int err;

	zri = kzalloc(sizeof(*zri), GFP_KERNEL);
	if (!zri) {
		zuf_err_cnd(silent,
			    "Not enough memory to allocate zuf_root_info\n");
		return -ENOMEM;
	}

	err = simple_fill_super(sb, ZUFR_SUPER_MAGIC, zufr_files);
	if (unlikely(err)) {
		kfree(zri);
		return err;
	}

	sb->s_op = &zufr_super_operations;
	sb->s_fs_info = zri;
	zri->sb = sb;

	root_i = sb->s_root->d_inode;
	root_i->i_fop = &zufr_file_dir_operations;
	root_i->i_op = &zufr_inode_operations;

	spin_lock_init(&zri->mount.lock);
	mutex_init(&zri->sbl_lock);
	relay_init(&zri->mount.relay);
	INIT_LIST_HEAD(&zri->fst_list);
	INIT_LIST_HEAD(&zri->pmem_list);

	err = zufc_zts_init(zri);
	if (unlikely(err))
		return err; /* put will be called we have a root */

	return 0;
}

static struct dentry *zufr_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name,
				  void *data)
{
	struct dentry *ret = mount_single(fs_type, flags, data, zufr_fill_super);

	zuf_info("zuf_root mount [%ld]\n",
		 IS_ERR_OR_NULL(ret) ? PTR_ERR(ret) : ret->d_inode->i_ino);
	return ret;
}

static struct file_system_type zufr_type = {
	.owner =	THIS_MODULE,
	.name =		"zuf",
	.mount =	zufr_mount,
	.kill_sb	= kill_litter_super,
};

/* Create an /sys/fs/zuf/ directory. to mount on */
static struct kset *zufr_kset;

int __init zuf_root_init(void)
{
	int err = zuf_init_inodecache();

	if (unlikely(err))
		return err;

	zufr_kset = kset_create_and_add("zuf", NULL, fs_kobj);
	if (!zufr_kset) {
		err = -ENOMEM;
		goto un_inodecache;
	}

	err = register_filesystem(&zufr_type);
	if (unlikely(err))
		goto un_kset;

	return 0;

un_kset:
	kset_unregister(zufr_kset);
un_inodecache:
	zuf_destroy_inodecache();
	return err;
}

void __exit zuf_root_exit(void)
{
	unregister_filesystem(&zufr_type);
	kset_unregister(zufr_kset);
	zuf_destroy_inodecache();
}

module_init(zuf_root_init)
module_exit(zuf_root_exit)
