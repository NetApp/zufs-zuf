// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
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
#include <linux/uio.h>

#include "zuf.h"

long __zuf_fallocate(struct inode *inode, int mode, loff_t offset, loff_t len)
{
	return -ENOTSUPP;
}

static ssize_t zuf_read_iter(struct kiocb *kiocb, struct iov_iter *ii)
{
	struct inode *inode = file_inode(kiocb->ki_filp);
	struct zuf_inode_info *zii = ZUII(inode);
	ssize_t ret;

	zuf_dbg_rw("[%ld] ppos=0x%llx len=0x%zx\n",
		     inode->i_ino, kiocb->ki_pos, iov_iter_count(ii));

	file_accessed(kiocb->ki_filp);

	zuf_r_lock(zii);

	ret = zuf_rw_read_iter(inode->i_sb, inode, kiocb, ii);

	zuf_r_unlock(zii);

	zuf_dbg_rw("[%ld] => 0x%lx\n", inode->i_ino, ret);
	return ret;
}

static ssize_t zuf_write_iter(struct kiocb *kiocb, struct iov_iter *ii)
{
	struct inode *inode = file_inode(kiocb->ki_filp);
	struct zuf_inode_info *zii = ZUII(inode);
	ssize_t ret;
	loff_t end_offset;

	ret = generic_write_checks(kiocb, ii);
	if (unlikely(ret < 0)) {
		zuf_dbg_vfs("[%ld] generic_write_checks => 0x%lx\n",
			    inode->i_ino, ret);
		return ret;
	}

	zuf_r_lock(zii);

	ret = file_remove_privs(kiocb->ki_filp);
	if (unlikely(ret < 0))
		goto out;

	end_offset = kiocb->ki_pos + iov_iter_count(ii);
	if (inode->i_size < end_offset) {
		spin_lock(&inode->i_lock);
		if (inode->i_size < end_offset) {
			zii->zi->i_size = cpu_to_le64(end_offset);
			i_size_write(inode, end_offset);
		}
		spin_unlock(&inode->i_lock);
	}

	zus_inode_cmtime_now(inode, zii->zi);

	ret = zuf_rw_write_iter(inode->i_sb, inode, kiocb, ii);
	if (unlikely(ret < 0)) {
		/* TODO(sagi): do we want to truncate i_size? */
		goto out;
	}

	inode->i_blocks = le64_to_cpu(zii->zi->i_blocks);

out:
	zuf_r_unlock(zii);

	zuf_dbg_rw("[%ld] => 0x%lx\n", inode->i_ino, ret);
	return ret;
}

const struct file_operations zuf_file_operations = {
	.open			= generic_file_open,
	.read_iter		= zuf_read_iter,
	.write_iter		= zuf_write_iter,
};

const struct inode_operations zuf_file_inode_operations = {
	.setattr	= zuf_setattr,
	.getattr	= zuf_getattr,
	.update_time	= zuf_update_time,
};
