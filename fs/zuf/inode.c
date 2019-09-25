// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include <linux/posix_acl_xattr.h>
#include <linux/security.h>
#include <linux/delay.h>

#include "zuf.h"

/* Flags that should be inherited by new inodes from their parent. */
#define ZUFS_FL_INHERITED (S_SYNC | S_NOATIME | S_DIRSYNC)

/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define ZUFS_FL_REG_MASK (~S_DIRSYNC)

/* Flags that are appropriate for non-dir/non-regular files. */
#define ZUFS_FL_OTHER_MASK (S_NOATIME)

static bool _zi_valid(struct zus_inode *zi)
{
	if (!_zi_active(zi))
		return false;

	switch (le16_to_cpu(zi->i_mode) & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
	case S_IFSOCK:
		return true;
	default:
		zuf_err("unknown file type ino=%lld mode=%d\n", zi->i_ino,
			  zi->i_mode);
		return false;
	}
}

static void _set_inode_from_zi(struct inode *inode, struct zus_inode *zi)
{
	inode->i_mode = le16_to_cpu(zi->i_mode);
	inode->i_uid = KUIDT_INIT(le32_to_cpu(zi->i_uid));
	inode->i_gid = KGIDT_INIT(le32_to_cpu(zi->i_gid));
	set_nlink(inode, le16_to_cpu(zi->i_nlink));
	inode->i_size = le64_to_cpu(zi->i_size);
	inode->i_blocks = le64_to_cpu(zi->i_blocks);
	mt_to_timespec(&inode->i_atime, &zi->i_atime);
	mt_to_timespec(&inode->i_ctime, &zi->i_ctime);
	mt_to_timespec(&inode->i_mtime, &zi->i_mtime);
	inode->i_generation = le64_to_cpu(zi->i_generation);
	zuf_set_inode_flags(inode, zi);

	inode->i_blocks = le64_to_cpu(zi->i_blocks);
	inode->i_mapping->a_ops = &zuf_aops;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &zuf_file_inode_operations;
		inode->i_fop = &zuf_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &zuf_dir_inode_operations;
		inode->i_fop = &zuf_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &zuf_symlink_inode_operations;
		break;
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
	case S_IFSOCK:
		inode->i_size = 0;
		inode->i_op = &zuf_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   le32_to_cpu(zi->i_rdev));
		break;
	default:
		zuf_err("unknown file type ino=%lld mode=%d\n", zi->i_ino,
			  zi->i_mode);
		break;
	}

	inode->i_ino = le64_to_cpu(zi->i_ino);
}

/* Mask out flags that are inappropriate for the given type of inode. */
static uint _calc_flags(umode_t mode, uint dir_flags, uint flags)
{
	uint zufs_flags = dir_flags & ZUFS_FL_INHERITED;

	if (S_ISREG(mode))
		zufs_flags &= ZUFS_FL_REG_MASK;
	else if (!S_ISDIR(mode))
		zufs_flags &= ZUFS_FL_OTHER_MASK;

	return zufs_flags;
}

static int _set_zi_from_inode(struct inode *dir, struct zus_inode *zi,
			      struct inode *inode)
{
	struct zus_inode *zidir = zus_zi(dir);

	if (unlikely(!zidir))
		return -EACCES;

	zi->i_mode = cpu_to_le16(inode->i_mode);
	zi->i_uid = cpu_to_le32(__kuid_val(inode->i_uid));
	zi->i_gid = cpu_to_le32(__kgid_val(inode->i_gid));
	/* NOTE: zus is boss of i_nlink (but let it know what we think) */
	zi->i_nlink = cpu_to_le16(inode->i_nlink);
	zi->i_size = cpu_to_le64(inode->i_size);
	zi->i_blocks = cpu_to_le64(inode->i_blocks);
	timespec_to_mt(&zi->i_atime, &inode->i_atime);
	timespec_to_mt(&zi->i_mtime, &inode->i_mtime);
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
	zi->i_generation = cpu_to_le32(inode->i_generation);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		zi->i_rdev = cpu_to_le32(inode->i_rdev);

	zi->i_flags = cpu_to_le16(_calc_flags(inode->i_mode,
					      le16_to_cpu(zidir->i_flags),
					      inode->i_flags));
	return 0;
}

static bool _times_equal(struct timespec64 *t, __le64 *mt)
{
	__le64 time;

	timespec_to_mt(&time, t);
	return time == *mt;
}

/* This function checks if VFS's inode and zus_inode are in sync */
static void _warn_inode_dirty(struct inode *inode, struct zus_inode *zi)
{
#define __MISMACH_INT(inode, X, Y)	\
	if (X != Y)			\
		zuf_warn("[%ld] " #X"=0x%lx " #Y"=0x%lx""\n",	\
			  inode->i_ino, (ulong)(X), (ulong)(Y))
#define __MISMACH_TIME(inode, X, Y)	\
	if (!_times_equal(X, Y)) {	\
		struct timespec64 t;	\
		mt_to_timespec(&t, (Y));\
		zuf_warn("[%ld] " #X"=%lld:%ld " #Y"=%lld:%ld""\n",	\
			  inode->i_ino, (X)->tv_sec, (X)->tv_nsec,	\
			  t.tv_sec, t.tv_nsec);		\
	}

	if (!_times_equal(&inode->i_ctime, &zi->i_ctime) ||
	    !_times_equal(&inode->i_mtime, &zi->i_mtime) ||
	    !_times_equal(&inode->i_atime, &zi->i_atime) ||
	    inode->i_size != le64_to_cpu(zi->i_size) ||
	    inode->i_mode != le16_to_cpu(zi->i_mode) ||
	    __kuid_val(inode->i_uid) != le32_to_cpu(zi->i_uid) ||
	    __kgid_val(inode->i_gid) != le32_to_cpu(zi->i_gid) ||
	    inode->i_nlink != le16_to_cpu(zi->i_nlink) ||
	    inode->i_ino != _zi_ino(zi) ||
	    inode->i_blocks != le64_to_cpu(zi->i_blocks)) {
		__MISMACH_TIME(inode, &inode->i_ctime, &zi->i_ctime);
		__MISMACH_TIME(inode, &inode->i_mtime, &zi->i_mtime);
		__MISMACH_TIME(inode, &inode->i_atime, &zi->i_atime);
		__MISMACH_INT(inode, inode->i_size, le64_to_cpu(zi->i_size));
		__MISMACH_INT(inode, inode->i_mode, le16_to_cpu(zi->i_mode));
		__MISMACH_INT(inode, __kuid_val(inode->i_uid),
			      le32_to_cpu(zi->i_uid));
		__MISMACH_INT(inode, __kgid_val(inode->i_gid),
			      le32_to_cpu(zi->i_gid));
		__MISMACH_INT(inode, inode->i_nlink, le16_to_cpu(zi->i_nlink));
		__MISMACH_INT(inode, inode->i_ino, _zi_ino(zi));
		__MISMACH_INT(inode, inode->i_blocks,
			      le64_to_cpu(zi->i_blocks));
	}
}

static void _zii_connect(struct inode *inode, struct zus_inode *zi,
			 struct zus_inode_info *zus_ii)
{
	struct zuf_inode_info *zii = ZUII(inode);

	zii->zi = zi;
	zii->zus_ii = zus_ii;
}

struct inode *zuf_iget(struct super_block *sb, struct zus_inode_info *zus_ii,
		       zu_dpp_t _zi, bool *exist)
{
	struct zus_inode *zi = zuf_dpp_t_addr(sb, _zi);
	struct inode *inode;

	*exist = false;
	if (unlikely(!zi)) {
		/* Don't trust ZUS pointers */
		zuf_err("Bad zus_inode 0x%llx\n", _zi);
		return ERR_PTR(-EIO);
	}
	if (unlikely(!zus_ii)) {
		zuf_err("zus_ii NULL\n");
		return ERR_PTR(-EIO);
	}

	if (!_zi_valid(zi)) {
		zuf_err("inactive node ino=%lld links=%d mode=%d\n", zi->i_ino,
			  zi->i_nlink, zi->i_mode);
		return ERR_PTR(-ESTALE);
	}

	zuf_dbg_zus("[%lld] size=0x%llx, blocks=0x%llx ct=0x%llx mt=0x%llx link=0x%x mode=0x%x xattr=0x%llx\n",
		    zi->i_ino, zi->i_size, zi->i_blocks, zi->i_ctime,
		    zi->i_mtime, zi->i_nlink, zi->i_mode, zi->i_xattr);

	inode = iget_locked(sb, _zi_ino(zi));
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW)) {
		*exist = true;
		return inode;
	}

	_set_inode_from_zi(inode, zi);
	_zii_connect(inode, zi, zus_ii);

	unlock_new_inode(inode);
	return inode;
}

int zuf_evict_dispatch(struct super_block *sb, struct zus_inode_info *zus_ii,
		       int operation, uint flags)
{
	struct zufs_ioc_evict_inode ioc_evict_inode = {
		.hdr.in_len = sizeof(ioc_evict_inode),
		.hdr.out_len = sizeof(ioc_evict_inode),
		.hdr.operation = operation,
		.zus_ii = zus_ii,
		.flags = flags,
	};
	int err;

	err = zufc_dispatch(ZUF_ROOT(SBI(sb)), &ioc_evict_inode.hdr, NULL, 0);
	if (unlikely(err && err != -EINTR))
		zuf_err_dispatch(sb, "zufc_dispatch failed op=%s => %d\n",
				 zuf_op_name(operation), err);
	return err;
}

void zuf_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct zuf_inode_info *zii = ZUII(inode);

	if (!inode->i_nlink) {
		if (unlikely(!zii->zi)) {
			zuf_dbg_err("[%ld] inode without zi mode=0x%x size=0x%llx\n",
				    inode->i_ino, inode->i_mode, inode->i_size);
			goto out;
		}

		if (unlikely(is_bad_inode(inode)))
			zuf_dbg_err("[%ld] inode is bad mode=0x%x zi=%p\n",
				    inode->i_ino, inode->i_mode, zii->zi);
		else
			_warn_inode_dirty(inode, zii->zi);

		zuf_w_lock(zii);

		zufc_goose_all_zts(ZUF_ROOT(SBI(sb)), inode);

		zuf_evict_dispatch(sb, zii->zus_ii, ZUFS_OP_FREE_INODE, 0);

		inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_size = 0;

		zuf_w_unlock(zii);
	} else {
		zuf_dbg_vfs("[%ld] inode is going down?\n", inode->i_ino);

		zuf_smw_lock(zii);

		zufc_goose_all_zts(ZUF_ROOT(SBI(sb)), inode);

		zuf_evict_dispatch(sb, zii->zus_ii, ZUFS_OP_EVICT_INODE, 0);

		zuf_smw_unlock(zii);
	}

out:
	zii->zus_ii = NULL;
	zii->zi = NULL;

	clear_inode(inode);
}

/* @rdev_or_isize is i_size in the case of a symlink
 * and rdev in the case of special-files
 */
struct inode *zuf_new_inode(struct inode *dir, umode_t mode,
			    const struct qstr *qstr, const char *symname,
			    ulong rdev_or_isize, bool tmpfile)
{
	struct super_block *sb = dir->i_sb;
	struct zuf_sb_info *sbi = SBI(sb);
	struct zufs_ioc_new_inode ioc_new_inode = {
		.hdr.in_len = sizeof(ioc_new_inode),
		.hdr.out_len = sizeof(ioc_new_inode),
		.hdr.operation = ZUFS_OP_NEW_INODE,
		.dir_ii = ZUII(dir)->zus_ii,
		.flags = tmpfile ? ZI_TMPFILE : 0,
		.str.len = qstr->len,
	};
	struct inode *inode;
	struct zus_inode *zi = NULL;
	struct page *pages[2];
	uint nump = 0;
	int err;

	memcpy(&ioc_new_inode.str.name, qstr->name, qstr->len);

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_ctime = inode->i_mtime = current_time(dir);
	inode->i_atime = inode->i_ctime;

	zuf_dbg_verbose("inode=%p name=%s\n", inode, qstr->name);

	zuf_set_inode_flags(inode, &ioc_new_inode.zi);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
	    S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		init_special_inode(inode, mode, rdev_or_isize);
	} else if (symname) {
		inode->i_size = rdev_or_isize;
		nump = zuf_prepare_symname(&ioc_new_inode, symname,
					   rdev_or_isize, pages);
	}

	err = _set_zi_from_inode(dir, &ioc_new_inode.zi, inode);
	if (unlikely(err))
		goto fail;

	zus_inode_cmtime_now(dir, zus_zi(dir));

	err = zufc_dispatch(ZUF_ROOT(sbi), &ioc_new_inode.hdr, pages, nump);
	if (unlikely(err)) {
		zuf_dbg_err("zufc_dispatch failed => %d\n", err);
		goto fail;
	}
	zi = zuf_dpp_t_addr(sb, ioc_new_inode._zi);

	_zii_connect(inode, zi, ioc_new_inode.zus_ii);

	/* update inode fields from filesystem inode */
	inode->i_ino = le64_to_cpu(zi->i_ino);
	inode->i_size = le64_to_cpu(zi->i_size);
	inode->i_generation = le64_to_cpu(zi->i_generation);
	inode->i_blocks = le64_to_cpu(zi->i_blocks);
	set_nlink(inode, le16_to_cpu(zi->i_nlink));
	zuf_zii_sync(dir, false);

	zuf_dbg_zus("[%lld] size=0x%llx, blocks=0x%llx ct=0x%llx mt=0x%llx link=0x%x mode=0x%x xattr=0x%llx\n",
		    zi->i_ino, zi->i_size, zi->i_blocks, zi->i_ctime,
		    zi->i_mtime, zi->i_nlink, zi->i_mode, zi->i_xattr);

	zuf_dbg_verbose("allocating inode %ld (zi=%p)\n", _zi_ino(zi), zi);

	err = insert_inode_locked(inode);
	if (unlikely(err)) {
		zuf_dbg_err("[%ld:%s] generation=%lld insert_inode_locked => %d\n",
			    inode->i_ino, qstr->name, zi->i_generation, err);
		goto fail;
	}

	return inode;

fail:
	clear_nlink(inode);
	if (zi)
		zi->i_nlink = 0;
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}

int zuf_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	/* write_inode should never be called because we always keep our inodes
	 * clean. So let us know if write_inode ever gets called.
	 */

	/* d_tmpfile() does a mark_inode_dirty so only complain on regular files
	 * TODO: How? Every thing off for now
	 * WARN_ON(inode->i_nlink);
	 */

	return 0;
}

/*
 * Mostly supporting file_accessed() for now. Which is the only one we use.
 *
 * But also file_update_time is used by fifo code.
 */
int zuf_update_time(struct inode *inode, struct timespec64 *time, int flags)
{
	struct zus_inode *zi = zus_zi(inode);

	if (flags & S_ATIME) {
		inode->i_atime = *time;
		timespec_to_mt(&zi->i_atime, &inode->i_atime);
		/* FIXME: Set a flag that zi needs flushing
		 * for now every read needs zi-flushing.
		 */
	}

	/* File_update_time() is not used by zuf.
	 * FIXME: One exception is O_TMPFILE the vfs calls file_update_time
	 * internally bypassing FS. So just do and silent.
	 * The zus O_TMPFILE create protocol knows it needs flushing
	 */
	if ((flags & S_CTIME) || (flags & S_MTIME)) {
		if (flags & S_CTIME) {
			inode->i_ctime = *time;
			timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
		}
		if (flags & S_MTIME) {
			inode->i_mtime = *time;
			timespec_to_mt(&zi->i_mtime, &inode->i_mtime);
		}
		zuf_dbg_vfs("called for S_CTIME | S_MTIME 0x%x\n", flags);
	}

	if (flags & ~(S_CTIME | S_MTIME | S_ATIME))
		zuf_err("called for 0x%x\n", flags);

	return 0;
}

int zuf_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
		unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = d_inode(dentry);

	if (inode->i_flags & S_APPEND)
		stat->attributes |= STATX_ATTR_APPEND;
	if (inode->i_flags & S_IMMUTABLE)
		stat->attributes |= STATX_ATTR_IMMUTABLE;

	stat->attributes_mask |= (STATX_ATTR_APPEND |
				  STATX_ATTR_IMMUTABLE);
	generic_fillattr(inode, stat);
	/* stat->blocks should be the number of 512B blocks */
	stat->blocks = inode->i_blocks << (inode->i_sb->s_blocksize_bits - 9);

	return 0;
}

int zuf_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct zuf_inode_info *zii = ZUII(inode);
	struct zus_inode *zi = zii->zi;
	struct zufs_ioc_attr ioc_attr = {
		.hdr.in_len = sizeof(ioc_attr),
		.hdr.out_len = sizeof(ioc_attr),
		.hdr.operation = ZUFS_OP_SETATTR,
		.zus_ii = zii->zus_ii,
	};
	int err;

	if (!zi)
		return -EACCES;

	/* Truncate is implemented via  fallocate(punch_hole) which means we
	 * are not atomic with the other ATTRs. I think someone said that
	 * some Kernel FSs don't even support truncate to come together with
	 * other ATTRs
	 */
	if ((attr->ia_valid & ATTR_SIZE)) {
		ZUF_CHECK_I_W_LOCK(inode);
		zuf_smw_lock(zii);
		err = __zuf_fallocate(inode, ZUFS_FL_TRUNCATE, attr->ia_size,
				      ~0ULL);
		zuf_smw_unlock(zii);
		if (unlikely(err))
			return err;
		attr->ia_valid &= ~ATTR_SIZE;
	}

	err = setattr_prepare(dentry, attr);
	if (unlikely(err))
		return err;

	if (attr->ia_valid & ATTR_MODE) {
		zuf_dbg_vfs("[%ld] ATTR_MODE=0x%x\n",
			     inode->i_ino, attr->ia_mode);
		ioc_attr.zuf_attr |= STATX_MODE;
		inode->i_mode = attr->ia_mode;
		zi->i_mode = cpu_to_le16(inode->i_mode);
		if (test_opt(SBI(inode->i_sb), POSIXACL)) {
			err = posix_acl_chmod(inode, inode->i_mode);
			if (unlikely(err))
				return err;
		}
	}

	if (attr->ia_valid & ATTR_UID) {
		zuf_dbg_vfs("[%ld] ATTR_UID=0x%x\n",
			     inode->i_ino, __kuid_val(attr->ia_uid));
		ioc_attr.zuf_attr |= STATX_UID;
		inode->i_uid = attr->ia_uid;
		zi->i_uid = cpu_to_le32(__kuid_val(inode->i_uid));
	}
	if (attr->ia_valid & ATTR_GID) {
		zuf_dbg_vfs("[%ld] ATTR_GID=0x%x\n",
			     inode->i_ino, __kgid_val(attr->ia_gid));
		ioc_attr.zuf_attr |= STATX_GID;
		inode->i_gid = attr->ia_gid;
		zi->i_gid = cpu_to_le32(__kgid_val(inode->i_gid));
	}

	if (attr->ia_valid & ATTR_ATIME) {
		ioc_attr.zuf_attr |= STATX_ATIME;
		inode->i_atime = attr->ia_atime;
		timespec_to_mt(&zi->i_atime, &inode->i_atime);
		zuf_dbg_vfs("[%ld] ATTR_ATIME=0x%llx\n",
			     inode->i_ino, zi->i_atime);
	}
	if (attr->ia_valid & ATTR_CTIME) {
		ioc_attr.zuf_attr |= STATX_CTIME;
		inode->i_ctime = attr->ia_ctime;
		timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
		zuf_dbg_vfs("[%ld] ATTR_CTIME=0x%llx\n",
			     inode->i_ino, zi->i_ctime);
	}
	if (attr->ia_valid & ATTR_MTIME) {
		ioc_attr.zuf_attr |= STATX_MTIME;
		inode->i_mtime = attr->ia_mtime;
		timespec_to_mt(&zi->i_mtime, &inode->i_mtime);
		zuf_dbg_vfs("[%ld] ATTR_MTIME=0x%llx\n",
			     inode->i_ino, zi->i_mtime);
	}

	err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_attr.hdr, NULL, 0);
	if (unlikely(err))
		zuf_dbg_err("[%ld] set_attr=0x%x failed => %d\n",
			    inode->i_ino, ioc_attr.zuf_attr, err);

	return err;
}

void zuf_set_inode_flags(struct inode *inode, struct zus_inode *zi)
{
	unsigned int flags = le16_to_cpu(zi->i_flags) & ~ZUFS_S_IMMUTABLE;

	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	inode->i_flags |= flags;
	if (zi->i_flags & ZUFS_S_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE | S_NOATIME;
	if (!zi->i_xattr)
		inode_has_no_xattr(inode);
}

/* direct_IO is not called. We set an empty one so open(O_DIRECT) will be happy
 */
static ssize_t zuf_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	WARN_ON(1);
	return 0;
}

const struct address_space_operations zuf_aops = {
	.direct_IO		= zuf_direct_IO,
};
