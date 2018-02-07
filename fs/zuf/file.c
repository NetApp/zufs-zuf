/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <linux/mman.h>
#include <linux/fadvise.h>
#include "zuf.h"

static long zuf_fallocate(struct file *file, int mode, loff_t offset,
			   loff_t len)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct zuf_inode_info *zii = ZUII(inode);
	struct zufs_ioc_range ioc_range = {
		.hdr.in_len = sizeof(ioc_range),
		.hdr.operation = ZUS_OP_FALLOCATE,
		.zus_ii = ZUII(inode)->zus_ii,
		.offset = offset,
		.length = len,
		.opflags = mode,
	};
	int err;

	zuf_dbg_vfs("[%ld] mode=0x%x offset=0x%llx len=0x%llx\n",
		     inode->i_ino, mode, offset, len);

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	zuf_w_lock(zii);

	if (!(mode & FALLOC_FL_KEEP_SIZE) && i_size_read(inode) < offset + len) {
		err = inode_newsize_ok(inode, offset + len);
		if (unlikely(err))
			goto out;
	}

	zus_inode_cmtime_now(inode, zii->zi);

	err = zufs_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_range.hdr, NULL, 0);
	if (unlikely(err))
		zuf_err("zufs_dispatch failed => %d\n", err);

	i_size_write(inode, le64_to_cpu(zii->zi->i_size));
	inode->i_blocks = le64_to_cpu(zii->zi->i_blocks);

out:
	zuf_w_unlock(zii);

	return err;
}

static loff_t zuf_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct zuf_inode_info *zii = ZUII(inode);
	struct zufs_ioc_seek ioc_seek = {
		.hdr.in_len = sizeof(ioc_seek),
		.hdr.out_len = sizeof(ioc_seek),
		.hdr.operation = ZUS_OP_LLSEEK,
		.zus_ii = zii->zus_ii,
		.offset_in = offset,
		.whence = whence,
	};
	int err = 0;

	zuf_dbg_vfs("[%ld] offset=0x%llx whence=%d\n",
		     inode->i_ino, offset, whence);

	if (whence != SEEK_DATA && whence != SEEK_HOLE)
		return generic_file_llseek(file, offset, whence);

	zuf_r_lock(zii);

	if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	    offset > inode->i_sb->s_maxbytes) {
		err = -EINVAL;
		goto out;
	} else if (inode->i_size <= offset) {
		err = -ENXIO;
		goto out;
	} else if (!inode->i_blocks) {
		if (whence == SEEK_HOLE)
			ioc_seek.offset_out = i_size_read(inode);
		else
			err = -ENXIO;
		goto out;
	}

	err = zufs_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_seek.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_err("zufs_dispatch failed => %d\n", err);
		goto out;
	}

	if (ioc_seek.offset_out != file->f_pos) {
		file->f_pos = ioc_seek.offset_out;
		file->f_version = 0;
	}

out:
	zuf_r_unlock(zii);

	return err ?: ioc_seek.offset_out;
}

/* This function is called by both msync() and fsync(). */
int zuf_isync(struct inode *inode, loff_t start, loff_t end, int datasync)
{
	struct zuf_inode_info *zii = ZUII(inode);
	struct zufs_ioc_range ioc_range = {
		.hdr.in_len = sizeof(ioc_range),
		.hdr.operation = ZUS_OP_SYNC,
		.zus_ii = zii->zus_ii,
		.offset = start,
		.opflags = datasync,
	};
	loff_t isize;
	ulong uend = end + 1;
	int err = 0;

	zuf_dbg_vfs("[%ld] start=0x%llx end=0x%llx  datasync=%d write_mapped=%d\n",
		     inode->i_ino, start, end, datasync,
		     atomic_read(&zii->write_mapped));

	/* We want to serialize the syncs so they don't fight with each other
	 * and is though more efficient, but we do not want to lock out
	 * read/writes and page-faults so we have a special sync semaphore
	 */
	zuf_smw_lock(zii);

	isize = i_size_read(inode);
	if (!isize) {
		zuf_dbg_mmap("[%ld] file is empty\n", inode->i_ino);
		goto out;
	}
	if (isize < uend)
		uend = isize;
	if (uend < start) {
		zuf_dbg_mmap("[%ld] isize=0x%llx start=0x%llx end=0x%lx\n",
				 inode->i_ino, isize, start, uend);
		err = -ENODATA;
		goto out;
	}

	ioc_range.length = uend - start;
	tozu_unmap_range(inode, start, ioc_range.length, 0);

	err = zufs_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_range.hdr, NULL, 0);
	if (unlikely(err))
		zuf_err("zufs_dispatch failed => %d\n", err);

out:
	zuf_smw_unlock(zii);
	return err;
}

static int zuf_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return zuf_isync(file_inode(file), start, end, datasync);
}

/* This callback is called when a file is closed */
static int zuf_flush(struct file *file, fl_owner_t id)
{
	zuf_dbg_vfs("[%ld]\n", file->f_inode->i_ino);

	return 0;
}

static int tozu_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		       u64 offset, u64 len)
{
	int err = 0;
	ulong start_index = zuf_o2p(offset);
	ulong end_index = zuf_o2p_up(offset + len);
	struct zuf_inode_info *zii = ZUII(inode);

	zuf_dbg_vfs("[%ld] offset=0x%llx len=0x%llx i-start=0x%lx i-end=0x%lx\n",
		     inode->i_ino, offset, len, start_index, end_index);

	if (fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC))
		return -EBADR;

	zuf_r_lock(zii);

	/* TODO: ZUS fiemap (&msi)*/

	zuf_r_unlock(zii);
	return err;
}

int tozu_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	struct address_space *mapping;
	struct inode *inode;
	struct zus_inode *zi;
	struct super_block *sb;

	inode = file_inode(file);
	if (S_ISFIFO(inode->i_mode))
		return -ESPIPE;

	mapping = file->f_mapping;
	if (!mapping || len < 0)
		return -EINVAL;

	zi = zus_zi(inode);
	if (unlikely(!zi))
		return -EACCES;

	zuf_dbg_rw("[%ld] offset=0x%llx length=0x%llx advice=0x%x\n",
		       inode->i_ino, offset, len, advice);

	sb = inode->i_sb;

	/*TODO: ZUS_fadvise */

	return 0;
}

static void _lock_two_ziis(struct zuf_inode_info *zii1,
			   struct zuf_inode_info *zii2)
{
	if (zii1 > zii2)
		swap(zii2, zii2);

	zuf_w_lock(zii1);
	if (zii1 != zii2)
		zuf_w_lock_nested(zii2);
}

static void _unlock_two_ziis(struct zuf_inode_info *zii1,
		      struct zuf_inode_info *zii2)
{
	if (zii1 > zii2)
		swap(zii2, zii2);

	if (zii1 != zii2)
		zuf_w_unlock(zii2);
	zuf_w_unlock(zii1);
}

static int _clone_file_range(struct inode *src_inode, loff_t pos_in,
			     struct inode *dst_inode, loff_t pos_out,
			     u64 len, int operation)
{
	struct zuf_inode_info *src_zii = ZUII(src_inode);
	struct zuf_inode_info *dst_zii = ZUII(dst_inode);
	struct zus_inode *dst_zi = dst_zii->zi;
	struct super_block *sb = src_inode->i_sb;
	struct zufs_ioc_clone ioc_clone = {
		.hdr.in_len = sizeof(ioc_clone),
		.hdr.out_len = sizeof(ioc_clone),
		.hdr.operation = operation,
		.src_zus_ii = src_zii->zus_ii,
		.dst_zus_ii = dst_zii->zus_ii,
		.len = len,
	};
	int err;

	_lock_two_ziis(src_zii, dst_zii);

	/* NOTE: len==0 means to-end-of-file which is what we want */
	unmap_mapping_range(src_inode->i_mapping, pos_in,  len, 0);
	unmap_mapping_range(dst_inode->i_mapping, pos_out, len, 0);

	zus_inode_cmtime_now(dst_inode, dst_zi);
	err = zufs_dispatch(ZUF_ROOT(SBI(sb)), &ioc_clone.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_err("failed to clone %ld -> %ld ; err=%d\n",
			 src_inode->i_ino, dst_inode->i_ino, err);
		goto out;
	}

	dst_inode->i_blocks = le64_to_cpu(dst_zi->i_blocks);
	if (i_size_read(dst_inode) < pos_out + len)
		i_size_write(dst_inode, pos_out + len);

out:
	_unlock_two_ziis(src_zii, dst_zii);

	return err;
}

static int zuf_clone_file_range(struct file *file_in, loff_t pos_in,
				struct file *file_out, loff_t pos_out, u64 len)
{
	struct inode *src_inode = file_inode(file_in);
	struct inode *dst_inode = file_inode(file_out);
	ulong src_size = i_size_read(src_inode);
	ulong dst_size = i_size_read(dst_inode);
	struct super_block *sb = src_inode->i_sb;
	ulong len_up = len;
	int err;

	zuf_dbg_vfs("ino-in=%ld ino-out=%ld pos_in=0x%llx pos_out=0x%llx "
		     "length=0x%llx\n", src_inode->i_ino, dst_inode->i_ino,
		     pos_in, pos_out, len);

	if (src_inode == dst_inode) {
		if (pos_in == pos_out) {
			zuf_dbg_err("[%ld] Clone nothing!!\n",
				src_inode->i_ino);
			return 0;
		}
		if (pos_in < pos_out) {
			if (pos_in + len > pos_out) {
				zuf_dbg_err("[%ld] overlapping pos_in < pos_out?? => EINVAL\n",
					src_inode->i_ino);
				return -EINVAL;
			}
		} else {
			if (pos_out + len > pos_in) {
				zuf_dbg_err("[%ld] overlapping pos_out < pos_in?? => EINVAL\n",
					src_inode->i_ino);
				return -EINVAL;
			}
		}
	}

	if ((pos_in & (sb->s_blocksize - 1)) ||
	    (pos_out & (sb->s_blocksize - 1))) {
		zuf_err("[%ld] Not aligned len=0x%llx pos_in=0x%llx "
			"pos_out=0x%llx src-size=0x%llx dst-size=0x%llx\n",
			 src_inode->i_ino, len, pos_in, pos_out,
			 i_size_read(src_inode), i_size_read(dst_inode));
		return -EINVAL;
	}

	/* STD says that len==0 means up to end of SRC */
	if (!len)
		len_up = len = src_size - pos_in;

	if (!pos_in && !pos_out && (src_size <= pos_in + len) &&
	    (dst_size <= src_size)) {
		len_up = 0;
	} else if (len & (sb->s_blocksize - 1)) {
		/* un-aligned len, see if it is beyond EOF */
		if ((src_size > pos_in  + len) ||
		    (dst_size > pos_out + len)) {
			zuf_err("[%ld] Not aligned len=0x%llx pos_in=0x%llx "
				"pos_out=0x%llx src-size=0x%lx dst-size=0x%lx\n",
				src_inode->i_ino, len, pos_in, pos_out,
				src_size, dst_size);
			return -EINVAL;
		}
		len_up = zuf_p2o(zuf_o2p_up(len));
	}

	err = _clone_file_range(src_inode, pos_in, dst_inode, pos_out, len_up,
				ZUS_OP_CLONE);
	if (unlikely(err))
		zuf_err("_clone_file_range failed => %d\n", err);

	return err;
}

static ssize_t zuf_copy_file_range(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   size_t len, uint flags)
{
	struct inode *src_inode = file_inode(file_in);
	struct inode *dst_inode = file_inode(file_out);
	ssize_t ret;

	zuf_dbg_vfs("ino-in=%ld ino-out=%ld pos_in=0x%llx pos_out=0x%llx "
		     "length=0x%lx\n", src_inode->i_ino, dst_inode->i_ino,
		     pos_in, pos_out, len);

	ret = _clone_file_range(src_inode, pos_in, dst_inode, pos_out, len,
				ZUS_OP_COPY);

	return ret ?: len;
}

/* ZUFS:
 * make sure we clean up the resources consumed by zufs_init()
 */
static int zuf_file_release(struct inode *inode, struct file *filp)
{
	if (unlikely(filp->private_data))
		zuf_err("not yet\n");

	return 0;
}

const struct file_operations tozu_file_operations = {
	.llseek			= zuf_llseek,
	.read_iter		= zuf_rw_read_iter,
	.write_iter		= zuf_rw_write_iter,
	.mmap			= zuf_file_mmap,
	.open			= generic_file_open,
	.fsync			= zuf_fsync,
	.flush			= zuf_flush,
	.release		= zuf_file_release,
	.unlocked_ioctl		= tozu_ioctl,
	.fallocate		= zuf_fallocate,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= tozu_compat_ioctl,
#endif
	.copy_file_range	= zuf_copy_file_range,
	.clone_file_range	= zuf_clone_file_range,
};

const struct inode_operations tozu_file_inode_operations = {
	.setattr	= zuf_setattr,
	.getattr	= zuf_getattr,
	.update_time	= zuf_update_time,
	.fiemap		= tozu_fiemap,
	.get_acl	= tozu_get_acl,
	.set_acl	= tozu_set_acl,
	.listxattr	= tozu_listxattr,
#ifdef BACKPORT_NEED_I_OPT_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
#endif
};
