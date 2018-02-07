/*
 * BRIEF DESCRIPTION
 *
 * Read/Write operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include "zuf.h"

/* ~~~ Functions for read_iter ~~~ */

static int _IO_dispatch(struct zuf_sb_info *sbi, struct zus_inode_info *zus_ii,
			int operation, uint pgoffset, struct page **pages,
			uint nump, u64 filepos, uint len)
{
	struct zufs_ioc_IO IO = {
		.hdr.operation = operation,
		.hdr.in_len = sizeof(IO),
		.hdr.out_len = 0,
		.hdr.offset = pgoffset,
		.hdr.len = len,
		.zus_ii = zus_ii,
		.filepos = filepos,
	};

	return zufs_dispatch(ZUF_ROOT(sbi), &IO.hdr, pages, nump);
}

static ssize_t _zufs_IO(struct zuf_sb_info *sbi, struct inode *inode,
			int operation, struct iov_iter *ii, loff_t pos)
{
	struct zuf_inode_info *zii = ZUII(inode);
	int err = -EINVAL;
	loff_t start_pos = pos;

	while (iov_iter_count(ii)) {
		struct page *pages[ZUS_API_MAP_MAX_PAGES];
		size_t bytes;
		size_t pgoffset;
		uint nump, i;

		bytes = iov_iter_get_pages(ii, pages, ZUS_API_MAP_MAX_SIZE,
					   ZUS_API_MAP_MAX_PAGES, &pgoffset);
		if (bytes < 0) {
			err = bytes;
			break;
		}

		nump = DIV_ROUND_UP(bytes + pgoffset, PAGE_SIZE);
		err = _IO_dispatch(sbi, zii->zus_ii, operation, pgoffset, pages,
				   nump, pos, bytes);

		for (i = 0; i < nump; ++i)
			put_page(pages[i]);

		if (unlikely(err))
			break;

		iov_iter_advance(ii, bytes);
		pos += bytes;
	}

	if (unlikely(pos == start_pos))
		return err;
	return pos - start_pos;
}

static ssize_t _read_iter(struct inode *inode, struct kiocb *kiocb,
			  struct iov_iter *ii)
{
	struct super_block *sb = inode->i_sb;
	ssize_t ret;

	/* EOF protection */
	if (unlikely(kiocb->ki_pos > i_size_read(inode)))
		return 0;

	iov_iter_truncate(ii, i_size_read(inode) - kiocb->ki_pos);
	if (unlikely(!iov_iter_count(ii))) {
		/* Don't let zero len reads have any effect */
		zuf_dbg_rw("called with NULL len\n");
		return 0;
	}

	ret = _zufs_IO(SBI(sb), inode, ZUS_OP_READ, ii, kiocb->ki_pos);
	if (unlikely(ret < 0))
		return ret;

	kiocb->ki_pos += ret;
	return ret;
}

ssize_t zuf_rw_read_iter(struct kiocb *kiocb, struct iov_iter *ii)
{
	struct inode *inode = file_inode(kiocb->ki_filp);
	ssize_t ret;

	zuf_dbg_vfs("[%ld] ppos=0x%llx len=0x%zx\n",
		     inode->i_ino, kiocb->ki_pos, iov_iter_count(ii));

	ret = _read_iter(inode, kiocb, ii);

	file_accessed(kiocb->ki_filp);

	zuf_dbg_vfs("[%ld] => 0x%lx\n", inode->i_ino, ret);
	return ret;
}

/* ~~~ Functions for write_iter ~~~ */

static ssize_t _write_iter(struct inode *inode, struct kiocb *kiocb,
			  struct iov_iter *ii)
{
	ssize_t ret;

	ret = _zufs_IO(SBI(inode->i_sb), inode, ZUS_OP_WRITE, ii, kiocb->ki_pos);
	if (unlikely(ret < 0))
		return ret;

	kiocb->ki_pos += ret;
	return ret;
}

static int _remove_privs_locked(struct inode *inode, struct file *file)
{
	int ret = file_remove_privs(file);

	return ret;
}

ssize_t zuf_rw_write_iter(struct kiocb *kiocb, struct iov_iter *ii)
{
	struct inode *inode = file_inode(kiocb->ki_filp);
	struct zuf_inode_info *zii = ZUII(inode);
	ssize_t ret;

	zuf_dbg_vfs("[%ld] ppos=0x%llx len=0x%zx\n",
		     inode->i_ino, kiocb->ki_pos, iov_iter_count(ii));

	ret = generic_write_checks(kiocb, ii);
	if (unlikely(ret < 0))
		goto out;

	ret = _remove_privs_locked(inode, kiocb->ki_filp);
	if (unlikely(ret < 0))
		goto out;

// 	zus_inode_cmtime_now(inode, zi);

	ret = _write_iter(inode, kiocb, ii);

	if (kiocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, kiocb->ki_pos);
	}
	inode->i_blocks = le64_to_cpu(zii->zi->i_blocks);

out:

	zuf_dbg_vfs("[%ld] => 0x%lx\n", inode->i_ino, ret);
	return ret;
}
