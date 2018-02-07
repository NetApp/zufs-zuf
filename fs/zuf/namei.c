/*
 * BRIEF DESCRIPTION
 *
 * Inode operations for directories.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */
#include <linux/fs.h>
#include "zuf.h"


static struct inode *d_parent(struct dentry *dentry)
{
	return dentry->d_parent->d_inode;
}

static void _instantiate_unlock(struct dentry *dentry, struct inode *inode)
{
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);
}

static struct dentry *zuf_lookup(struct inode *dir, struct dentry *dentry,
				 uint flags)
{
	struct super_block *sb = dir->i_sb;
	struct qstr *str = &dentry->d_name;
	uint in_len = offsetof(struct zufs_ioc_lookup, _zi);
	struct zufs_ioc_lookup ioc_lu = {
		.hdr.in_len = in_len,
		.hdr.out_start = in_len,
		.hdr.out_len = sizeof(ioc_lu) - in_len,
		.hdr.operation = ZUS_OP_LOOKUP,
		.dir_ii = ZUII(dir)->zus_ii,
		.str.len = str->len,
	};
	struct inode *inode = NULL;
	bool exist;
	int err;

	zuf_dbg_vfs("[%ld] dentry-name=%s\n", dir->i_ino, dentry->d_name.name);

	if (dentry->d_name.len > ZUFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	memcpy(&ioc_lu.str.name, str->name, str->len);

	err = zufs_dispatch(ZUF_ROOT(SBI(sb)), &ioc_lu.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_dbg_err("zufs_dispatch failed => %d\n", err);
		goto out;
	}

	inode = zuf_iget(dir->i_sb, ioc_lu.zus_ii, ioc_lu._zi, &exist);
	if (exist) {
		zuf_dbg_err("race in lookup\n");
		zuf_evict_dispatch(sb, ioc_lu.zus_ii, ZUS_OP_EVICT_INODE);
	}

out:
	return d_splice_alias(inode, dentry);
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int zuf_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		      bool excl)
{
	struct inode *inode;

	zuf_dbg_vfs("[%ld] dentry-name=%s mode=0x%x\n",
		     dir->i_ino, dentry->d_name.name, mode);

	inode = zuf_new_inode(dir, mode, &dentry->d_name, NULL, 0, false);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &tozu_file_inode_operations;
	inode->i_mapping->a_ops = &zuf_aops;
	inode->i_fop = &tozu_file_operations;

	_instantiate_unlock(dentry, inode);

	return 0;
}

static int zuf_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		     dev_t rdev)
{
	struct inode *inode;

	zuf_dbg_vfs("[%ld] mode=0x%x rdev=0x%x\n", dir->i_ino, mode, rdev);

	inode = zuf_new_inode(dir, mode, &dentry->d_name, NULL, rdev, false);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &tozu_special_inode_operations;

	_instantiate_unlock(dentry, inode);

	return 0;
}

static int tozu_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;

	inode = zuf_new_inode(dir, mode, &dentry->d_name, NULL, 0, true);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	/* TODO: See about more ephemeral operations on this file, around
	 * mmap and such.
	 * Must see about that tmpfile mode that is later link_at
	 * (probably the !O_EXCL flag)
	 */
	inode->i_op = &tozu_file_inode_operations;
	inode->i_mapping->a_ops = &zuf_aops;
	inode->i_fop = &tozu_file_operations;

	set_nlink(inode, 1); /* user_mode knows nothing */
	d_tmpfile(dentry, inode);
	/* tmpfile operate on nlink=0. Since this is a tmp file we do not care
	 * about cl_flushing. If later this file will be linked to a dir. the
	 * add_dentry will flush the zi.
	 */
	zus_zi(inode)->i_nlink = inode->i_nlink;

	unlock_new_inode(inode);
	return 0;
}

static int zuf_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
	struct inode *inode;
	ulong len;

	zuf_dbg_vfs("[%ld] de->name=%s symname=%s\n",
			dir->i_ino, dentry->d_name.name, symname);

	len = strlen(symname);
	if (len + 1 > ZUFS_MAX_SYMLINK)
		return -ENAMETOOLONG;

	inode = zuf_new_inode(dir, S_IFLNK|S_IRWXUGO, &dentry->d_name,
			       symname, len, false);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &zuf_symlink_inode_operations;
	inode->i_mapping->a_ops = &zuf_aops;

	_instantiate_unlock(dentry, inode);

	return 0;
}

static int zuf_link(struct dentry *dest_dentry, struct inode *dir,
		    struct dentry *dentry)
{
	struct inode *inode = dest_dentry->d_inode;
	int err;

	zuf_dbg_vfs("[%ld] dentry-ino=%ld dentry-name=%s dentry-parent=%ld dest_d-ino=%ld dest_d-name=%s\n",
		     dir->i_ino, inode->i_ino, dentry->d_name.name,
		     d_parent(dentry)->i_ino,
		     dest_dentry->d_inode->i_ino, dest_dentry->d_name.name);

	if (inode->i_nlink >= ZUFS_LINK_MAX)
		return -EMLINK;

	ihold(inode);

	err = zuf_add_dentry(dir, &dentry->d_name, inode, false);
	if (unlikely(err)) {
		iput(inode);
		return err;
	}

	inode->i_ctime = CURRENT_TIME;

	set_nlink(inode, le16_to_cpu(zus_zi(inode)->i_nlink));

	d_instantiate(dentry, inode);

	return 0;
}

static int zuf_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int err;

	zuf_dbg_vfs("[%ld] dentry-ino=%ld dentry-name=%s dentry-parent=%ld\n",
		     dir->i_ino, inode->i_ino, dentry->d_name.name,
		     d_parent(dentry)->i_ino);

	err = zuf_remove_dentry(dir, &dentry->d_name);
	if (unlikely(err))
		return err;

	inode->i_ctime = dir->i_ctime;

	set_nlink(inode, le16_to_cpu(ZUII(inode)->zi->i_nlink));

	return 0;
}

static int tozu_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;

	zuf_dbg_vfs("[%ld] dentry-name=%s dentry-parent=%ld mode=0x%x\n",
		     dir->i_ino, dentry->d_name.name, d_parent(dentry)->i_ino,
		     mode);

	if (dir->i_nlink >= ZUFS_LINK_MAX)
		return -EMLINK;

	inode = zuf_new_inode(dir, S_IFDIR | mode, &dentry->d_name, NULL, 0,
			      false);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &tozu_dir_inode_operations;
	inode->i_fop = &tozu_dir_operations;
	inode->i_mapping->a_ops = &zuf_aops;

	set_nlink(dir, le16_to_cpu(ZUII(inode)->zi->i_nlink));

	_instantiate_unlock(dentry, inode);

	return 0;
}

static bool _empty_dir(struct inode *dir)
{
	if (dir->i_nlink != 2) {
		zuf_warn("[%ld] directory has nlink(%d) != 2\n",
			  dir->i_ino, dir->i_nlink);
		return false;
	}
	/* NOTE: Above is not the only -ENOTEMPTY the zus-fs will need to check
	 * for the "only-files" no subdirs case. And return -ENOTEMPTY below
	 */
	return true;
}

static int zuf_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int err;

	zuf_dbg_vfs("[%ld] dentry-ino=%ld dentry-name=%s dentry-parent=%ld\n",
		     dir->i_ino, inode->i_ino, dentry->d_name.name,
		     d_parent(dentry)->i_ino);

	if (!inode)
		return -ENOENT;

	if (!_empty_dir(inode))
		return -ENOTEMPTY;

	err = zuf_remove_dentry(dir, &dentry->d_name);
	if (unlikely(err))
		return err;

	inode->i_ctime = dir->i_ctime;

	set_nlink(inode, le16_to_cpu(zus_zi(inode)->i_nlink));
	set_nlink(dir, le16_to_cpu(zus_zi(dir)->i_nlink));

	return 0;
}

/* Structure of a directory element; */
struct zuf_dir_element {
	__le64  ino;
	char name[254];
};

static int _rename_exchange(struct inode *old_inode, struct inode *new_inode,
			    struct inode *old_dir, struct inode *new_dir)
{
	/* A subdir holds a ref on parent, see if we need to exchange refs */
	if ((S_ISDIR(old_inode->i_mode) != S_ISDIR(new_inode->i_mode)) &&
	    (old_dir != new_dir)) {
		if (S_ISDIR(old_inode->i_mode)) {
			if (ZUFS_LINK_MAX <= new_dir->i_nlink)
				return -EMLINK;
		} else {
			if (ZUFS_LINK_MAX <= old_dir->i_nlink)
				return -EMLINK;
		}
	}

	set_nlink(old_dir, le16_to_cpu(zus_zi(old_dir)->i_nlink));
	set_nlink(new_dir, le16_to_cpu(zus_zi(new_dir)->i_nlink));

	/* Update Directory times */
	mt_to_timespec(&old_dir->i_mtime, &zus_zi(old_dir)->i_mtime);
	mt_to_timespec(&old_dir->i_ctime, &zus_zi(old_dir)->i_ctime);
	if (old_dir != new_dir) {
		mt_to_timespec(&new_dir->i_mtime, &zus_zi(new_dir)->i_mtime);
		mt_to_timespec(&new_dir->i_ctime, &zus_zi(new_dir)->i_ctime);
	}
	return 0;
}

static int zuf_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry,
		      uint flags)
{
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	struct zuf_sb_info *sbi = SBI(old_inode->i_sb);
	struct zufs_ioc_rename ioc_rename = {
		.hdr.in_len = sizeof(ioc_rename),
		.hdr.out_len = sizeof(ioc_rename),
		.hdr.operation = ZUS_OP_RENAME,
		.old_dir_ii = ZUII(old_dir)->zus_ii,
		.new_dir_ii = ZUII(new_dir)->zus_ii,
		.old_zus_ii = old_inode ? ZUII(old_inode)->zus_ii : NULL,
		.new_zus_ii = new_inode ? ZUII(new_inode)->zus_ii : NULL,
		.old_d_str.len = old_dentry->d_name.len,
		.new_d_str.len = new_dentry->d_name.len,
	};
	struct timespec time = CURRENT_TIME;
	int err;

	zuf_dbg_vfs("old_inode=%ld new_inode=%ld old_name=%s new_name=%s f=0x%x\n",
		     old_inode ? old_inode->i_ino : 0,
		     new_inode ? new_inode->i_ino : 0, old_dentry->d_name.name,
		     new_dentry->d_name.name, flags);

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE /*| RENAME_WHITEOUT*/))
		return -EINVAL;

	if (!(flags & RENAME_EXCHANGE) && S_ISDIR(old_inode->i_mode)) {
		if (new_inode) {
			if (!_empty_dir(new_inode))
				return -ENOTEMPTY;
		} else if (ZUFS_LINK_MAX <= new_dir->i_nlink) {
			return -EMLINK;
		}
	}

	memcpy(&ioc_rename.old_d_str.name, old_dentry->d_name.name,
		old_dentry->d_name.len);
	memcpy(&ioc_rename.new_d_str.name, new_dentry->d_name.name,
		new_dentry->d_name.len);
	timespec_to_mt(&ioc_rename.time, &time);

	err = zufs_dispatch(ZUF_ROOT(sbi), &ioc_rename.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_err("zufs_dispatch failed => %d\n", err);
		return err;
	}

	if (flags & RENAME_EXCHANGE)
		return _rename_exchange(old_inode, new_inode, old_dir, new_dir);

	mt_to_timespec(&new_dir->i_mtime, &zus_zi(new_dir)->i_mtime);
	mt_to_timespec(&new_dir->i_ctime, &zus_zi(new_dir)->i_ctime);

	if (new_inode) {
		struct zus_inode *new_zi = zus_zi(new_inode);

		set_nlink(new_inode, le16_to_cpu(new_zi->i_nlink));
		mt_to_timespec(&new_inode->i_ctime, &new_zi->i_ctime);
	} else {
		struct zus_inode *old_zi = zus_zi(old_inode);

		mt_to_timespec(&old_inode->i_ctime, &old_zi->i_ctime);
	}

	if (S_ISDIR(old_inode->i_mode)) {
		set_nlink(old_dir, le16_to_cpu(zus_zi(old_dir)->i_nlink));
		if (!new_inode)
			set_nlink(new_dir, le16_to_cpu(zus_zi(new_dir)->i_nlink));
	}

	return 0;
}

const struct inode_operations tozu_dir_inode_operations = {
	.create		= zuf_create,
	.lookup		= zuf_lookup,
	.link		= zuf_link,
	.unlink		= zuf_unlink,
	.symlink	= zuf_symlink,
	.mkdir		= tozu_mkdir,
	.rmdir		= zuf_rmdir,
	.mknod		= zuf_mknod,
	.tmpfile	= tozu_tmpfile,
	.rename		= zuf_rename,
	.setattr	= zuf_setattr,
	.update_time	= zuf_update_time,
	.get_acl	= tozu_get_acl,
	.set_acl	= tozu_set_acl,
	.listxattr	= tozu_listxattr,
#ifdef BACKPORT_NEED_I_OPT_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
#endif
};

const struct inode_operations tozu_special_inode_operations = {
	.setattr	= zuf_setattr,
	.update_time	= zuf_update_time,
	.get_acl	= tozu_get_acl,
	.set_acl	= tozu_set_acl,
	.listxattr	= tozu_listxattr,
#ifdef BACKPORT_NEED_I_OPT_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
#endif
};
