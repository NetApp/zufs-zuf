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

/* This function is called by both msync() and fsync(). */
int zuf_isync(struct inode *inode, loff_t start, loff_t end, int datasync)
{
	struct zuf_inode_info *zii = ZUII(inode);
	struct zufs_ioc_sync ioc_range = {
		.hdr.in_len = sizeof(ioc_range),
		.hdr.operation = ZUFS_OP_SYNC,
		.zus_ii = zii->zus_ii,
		.offset = start,
		.flags = datasync ? ZUFS_SF_DATASYNC : 0,
	};
	loff_t isize;
	ulong uend = end + 1;
	int err = 0;

	zuf_dbg_vfs(
		"[%ld] start=0x%llx end=0x%llx  datasync=%d write_mapped=%d\n",
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

	if (!atomic_read(&zii->write_mapped))
		goto out; /* Nothing to do on this inode */

	ioc_range.length = uend - start;
	unmap_mapping_range(inode->i_mapping, start, ioc_range.length, 0);
	zufc_goose_all_zts(ZUF_ROOT(SBI(inode->i_sb)), inode);

	err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_range.hdr,
			    NULL, 0);
	if (unlikely(err))
		zuf_dbg_err("zufc_dispatch failed => %d\n", err);

	zuf_sync_dec(inode, ioc_range.write_unmapped);

out:
	zuf_smw_unlock(zii);
	return err;
}

static int zuf_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return zuf_isync(file_inode(file), start, end, datasync);
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
	.mmap			= zuf_file_mmap,
	.fsync			= zuf_fsync,
};

const struct inode_operations zuf_file_inode_operations = {
	.setattr	= zuf_setattr,
	.getattr	= zuf_getattr,
	.update_time	= zuf_update_time,
};
