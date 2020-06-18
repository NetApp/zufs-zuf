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
#include <linux/falloc.h>
#include <linux/fadvise.h>
#include <linux/sched/signal.h>

#include "zuf.h"

long __zuf_fallocate(struct inode *inode, int mode, loff_t offset, loff_t len)
{
	struct zuf_inode_info *zii = ZUII(inode);
	bool need_len_check, need_unmap;
	loff_t unmap_len = 0; /* 0 means all file */
	loff_t new_size = len + offset;
	loff_t i_size = i_size_read(inode);
	int err = 0;

	zuf_dbg_vfs("[%ld] mode=0x%x offset=0x%llx len=0x%llx\n",
		     inode->i_ino, mode, offset, len);

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;
	if (IS_SWAPFILE(inode))
		return -ETXTBSY;

	/* These are all the FL flags we know how to handle on the  kernel side
	 * a zusFS that does not support one of these can just return
	 * EOPNOTSUPP.
	 */
	if (mode & ~SBI(inode->i_sb)->falloc_sup) {
		zuf_dbg_err("Unsupported mode(0x%x)\n", mode);
		return -EOPNOTSUPP;
	}

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		if (offset >= i_size)
			return 0;
		if (offset + len > i_size)
			len = i_size - offset;
		need_len_check = false;
		need_unmap = true;
		unmap_len = len;
	} else if (mode & ZUFS_FL_TRUNCATE) {
		need_len_check = true;
		new_size = offset;
		need_unmap = true;
	} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		if (offset + len > i_size)
			return -EINVAL;
		need_len_check = false;
		need_unmap = true;
	} else if (mode & FALLOC_FL_INSERT_RANGE) {
		need_len_check = true;
		new_size = i_size + len;
		need_unmap = true;
	} else if (mode & FALLOC_FL_ZERO_RANGE) {
		need_len_check = !(mode & FALLOC_FL_KEEP_SIZE);
		need_unmap = true;
	} else {
		/* FALLOC_FL_UNSHARE_RANGE same as regular */
		need_len_check = !(mode & FALLOC_FL_KEEP_SIZE);
		need_unmap = false;
	}

	if (need_len_check && (new_size > i_size)) {
		err = inode_newsize_ok(inode, new_size);
		if (unlikely(err)) {
			zuf_dbg_err("inode_newsize_ok(0x%llx) => %d\n",
				    new_size, err);
			goto out;
		}
	}

	if (need_unmap) {
		zufc_goose_all_zts(ZUF_ROOT(SBI(inode->i_sb)), inode);
		zuf_pi_unmap(inode, offset, unmap_len, EZUF_PIU_EVEN_COWS);
	}

	zus_inode_cmtime_now(inode, zii->zi);

	err = zuf_rw_fallocate(inode, mode, offset, len);

	/* Even if we had an error these might have changed */
	i_size_write(inode, le64_to_cpu(zii->zi->i_size));
	inode->i_blocks = le64_to_cpu(zii->zi->i_blocks);

out:
	return err;
}

static long zuf_fallocate(struct file *file, int mode, loff_t offset,
			  loff_t len)
{
	struct inode *inode = file->f_inode;
	struct zuf_inode_info *zii = ZUII(inode);
	int err;

	zuf_w_lock(zii);

	err = __zuf_fallocate(inode, mode, offset, len);

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
		.hdr.operation = ZUFS_OP_LLSEEK,
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

	err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_seek.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_dbg_err("zufc_dispatch failed => %d\n", err);
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
	struct zufs_ioc_sync ioc_range = {
		.hdr.in_len = sizeof(ioc_range),
		.hdr.out_len = sizeof(ioc_range),
		.hdr.operation = ZUFS_OP_SYNC,
		.zus_ii = zii->zus_ii,
		.offset = start,
		.flags = datasync ? ZUFS_SF_DATASYNC : 0,
	};
	loff_t isize;
	ulong uend = end + 1;
	int err = 0;

	zuf_dbg_vfs("[%ld] start=0x%llx end=0x%llx  datasync=%d\n",
		    inode->i_ino, start, end, datasync);

	/* We want to serialize the syncs so they don't fight with each other
	 * and is though more efficient, but we do not want to lock out
	 * read/writes and page-faults so we have a special sync semaphore
	 */
	zuf_smw_lock(zii);

	isize = i_size_read(inode);
	if (!isize) {
		zuf_dbg_err("[%ld] file is empty\n", inode->i_ino);
		goto out;
	}
	if (isize < uend)
		uend = isize;
	if (uend < start) {
		zuf_dbg_err("[%ld] isize=0x%llx start=0x%llx end=0x%lx\n",
				 inode->i_ino, isize, start, uend);
		err = -ENODATA;
		goto out;
	}

	if (!(SBI(inode->i_sb)->fs_caps & ZUFS_FSC_SYNC_ALWAYS) &&
	    !test_bit(ZUF_II_DIRTY, &zii->flags))
		goto out; /* Nothing to do on this inode */

	ioc_range.length = uend - start;
	zuf_pi_unmap(inode, start, ioc_range.length, EZUF_PIU_SYNC);
	zufc_goose_all_zts(ZUF_ROOT(SBI(inode->i_sb)), inode);

	err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_range.hdr,
			    NULL, 0);
	if (ioc_range.hdr.flags & ZUFS_H_INODE_CLEAN) {
		zuf_dbg_rw("[%ld] got hint\n", inode->i_ino);
		zuf_sync_remove(inode);
	}
	if (unlikely(err))
		zuf_dbg_err("zufc_dispatch failed => %d\n", err);

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

noinline
static int _fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		   u64 offset, u64 length, long *on_stack, uint on_stack_size)
{
	struct super_block *sb = inode->i_sb;
	struct zuf_inode_info *zii = ZUII(inode);
	struct zufs_ioc_fiemap ioc_fiemap = {
		.hdr.operation = ZUFS_OP_FIEMAP,
		.hdr.in_len = sizeof(ioc_fiemap),
		.hdr.out_len = sizeof(ioc_fiemap),
		.zus_ii = zii->zus_ii,
		.start = offset,
		.length = length,
		.flags = fieinfo->fi_flags,
	};
	struct page **pages = NULL;
	enum big_alloc_type bat = 0;
	uint nump = 0, extents_max = 0;
	int i, err;

	zuf_dbg_vfs("[%ld] offset=0x%llx len=0x%llx extents_max=%u flags=0x%x\n",
		    inode->i_ino, offset, length, fieinfo->fi_extents_max,
		    fieinfo->fi_flags);

	/* TODO: Have support for FIEMAP_FLAG_XATTR */
	err = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (unlikely(err))
		return err;

	if (likely(fieinfo->fi_extents_max)) {
		ulong start = (ulong)fieinfo->fi_extents_start;
		ulong len = fieinfo->fi_extents_max *
						sizeof(struct fiemap_extent);
		ulong offset = start & (PAGE_SIZE - 1);
		ulong end_offset = (offset + len) & (PAGE_SIZE - 1);
		ulong __len;
		uint nump_r;

		nump = md_o2p_up(offset + len);
		if (ZUS_API_MAP_MAX_PAGES < nump)
			nump = ZUS_API_MAP_MAX_PAGES;

		__len = nump * PAGE_SIZE - offset;
		if (end_offset)
			__len -= (PAGE_SIZE - end_offset);

		extents_max = __len / sizeof(struct fiemap_extent);

		ioc_fiemap.hdr.len = extents_max * sizeof(struct fiemap_extent);
		ioc_fiemap.hdr.offset = offset;

		pages = big_alloc(nump * sizeof(*pages), on_stack_size,
				  on_stack, GFP_KERNEL, &bat);
		if (unlikely(!pages))
			return -ENOMEM;

		nump_r = get_user_pages_fast(start, nump, WRITE, pages);
		if (unlikely(nump != nump_r)) {
			err = -EFAULT;
			goto free;
		}
	}
	ioc_fiemap.extents_max = extents_max;

	zuf_r_lock(zii);

	err = zufc_dispatch(ZUF_ROOT(SBI(sb)), &ioc_fiemap.hdr, pages, nump);
	if (unlikely(err)) {
		zuf_dbg_err("zufs_dispatch failed => %d\n", err);
		goto out;
	}

	fieinfo->fi_extents_mapped = ioc_fiemap.extents_mapped;
	if (unlikely(extents_max &&
		     (extents_max < ioc_fiemap.extents_mapped))) {
		zuf_err("extents_max=%d extents_mapped=%d\n", extents_max,
			ioc_fiemap.extents_mapped);
		err = -EINVAL;
	}

out:
	zuf_r_unlock(zii);

	for (i = 0; i < nump; ++i)
		put_page(pages[i]);
free:
	big_free(pages, bat);

	return err;
}

static int zuf_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		      u64 offset, u64 length)
{
	long on_stack[ZUF_MAX_STACK(8) / sizeof(long)];

	return _fiemap(inode, fieinfo, offset, length, on_stack,
		       sizeof(on_stack));
}

/* ~~~~~ clone/copy range ~~~~~ */

/*
 * Copy/paste from Kernel mm/filemap.c::generic_remap_checks
 * FIXME: make it EXPORT_GPL
 */
static int _access_check_limits(struct file *file, loff_t pos,
				       loff_t *count)
{
	struct inode *inode = file->f_mapping->host;
	loff_t max_size = inode->i_sb->s_maxbytes;

	if (!(file->f_flags & O_LARGEFILE))
		max_size = MAX_NON_LFS;

	if (unlikely(pos >= max_size))
		return -EFBIG;
	*count = min(*count, max_size - pos);
	return 0;
}

static int _write_check_limits(struct file *file, loff_t pos,
				      loff_t *count)
{

	loff_t limit = rlimit(RLIMIT_FSIZE);

	if (limit != RLIM_INFINITY) {
		if (pos >= limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		*count = min(*count, limit - pos);
	}

	return _access_check_limits(file, pos, count);
}

static int _remap_checks(struct file *file_in, loff_t pos_in,
			 struct file *file_out, loff_t pos_out,
			 loff_t *req_count, unsigned int remap_flags)
{
	struct inode *inode_in = file_in->f_mapping->host;
	struct inode *inode_out = file_out->f_mapping->host;
	uint64_t count = *req_count;
	uint64_t bcount;
	loff_t size_in, size_out;
	loff_t bs = inode_out->i_sb->s_blocksize;
	int ret;

	/* The start of both ranges must be aligned to an fs block. */
	if (!IS_ALIGNED(pos_in, bs) || !IS_ALIGNED(pos_out, bs))
		return -EINVAL;

	/* Ensure offsets don't wrap. */
	if (pos_in + count < pos_in || pos_out + count < pos_out)
		return -EINVAL;

	size_in = i_size_read(inode_in);
	size_out = i_size_read(inode_out);

	/* Dedupe requires both ranges to be within EOF. */
	if ((remap_flags & REMAP_FILE_DEDUP) &&
	    (pos_in >= size_in || pos_in + count > size_in ||
	     pos_out >= size_out || pos_out + count > size_out))
		return -EINVAL;

	/* Ensure the infile range is within the infile. */
	if (pos_in >= size_in)
		return -EINVAL;
	count = min(count, size_in - (uint64_t)pos_in);

	ret = _access_check_limits(file_in, pos_in, &count);
	if (ret)
		return ret;

	ret = _write_check_limits(file_out, pos_out, &count);
	if (ret)
		return ret;

	/*
	 * If the user wanted us to link to the infile's EOF, round up to the
	 * next block boundary for this check.
	 *
	 * Otherwise, make sure the count is also block-aligned, having
	 * already confirmed the starting offsets' block alignment.
	 */
	if (pos_in + count == size_in) {
		bcount = ALIGN(size_in, bs) - pos_in;
	} else {
		if (!IS_ALIGNED(count, bs))
			count = ALIGN_DOWN(count, bs);
		bcount = count;
	}

	/* Don't allow overlapped cloning within the same file. */
	if (inode_in == inode_out &&
	    pos_out + bcount > pos_in &&
	    pos_out < pos_in + bcount)
		return -EINVAL;

	/*
	 * We shortened the request but the caller can't deal with that, so
	 * bounce the request back to userspace.
	 */
	if (*req_count != count && !(remap_flags & REMAP_FILE_CAN_SHORTEN))
		return -EINVAL;

	*req_count = count;
	return 0;
}

/*
 * Copy/paste from generic_remap_file_range_prep(). We cannot call
 * generic_remap_file_range_prep because it calles fsync twice and we do not
 * want to go to the Server so many times.
 * So below is just the checks.
 * FIXME: Send a patch upstream to split the generic_remap_file_range_prep
 * or receive a flag if to do the syncs
 *
 * Check that the two inodes are eligible for cloning, the ranges make
 * sense.
 *
 * If there's an error, then the usual negative error code is returned.
 * Otherwise returns 0 with *len set to the request length.
 */
static int _remap_file_range_prep(struct file *file_in, loff_t pos_in,
				  struct file *file_out, loff_t pos_out,
				  loff_t *len, unsigned int remap_flags)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	int ret;

	/* Don't touch certain kinds of inodes */
	if (IS_IMMUTABLE(inode_out))
		return -EPERM;

	if (IS_SWAPFILE(inode_in) || IS_SWAPFILE(inode_out))
		return -ETXTBSY;

	/* Don't reflink dirs, pipes, sockets... */
	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	/* Zero length dedupe exits immediately; reflink goes to EOF. */
	if (*len == 0) {
		loff_t isize = i_size_read(inode_in);

		if ((remap_flags & REMAP_FILE_DEDUP) || pos_in == isize)
			return 0;
		if (pos_in > isize)
			return -EINVAL;
		*len = isize - pos_in;
		if (*len == 0)
			return 0;
	}

	/* Check that we don't violate system file offset limits. */
	ret = _remap_checks(file_in, pos_in, file_out, pos_out, len,
			    remap_flags);
	if (ret)
		return ret;

	/*
	 * REMAP_FILE_DEDUP see if extents are the same.
	 */
	if (remap_flags & REMAP_FILE_DEDUP)
		ret = zuf_rw_file_range_compare(inode_in, pos_in,
						inode_out, pos_out, *len);

	return ret;
}

static void _lock_two_ziis(struct zuf_inode_info *zii1,
			   struct zuf_inode_info *zii2)
{
	if (zii1 > zii2)
		swap(zii1, zii2);

	zuf_w_lock(zii1);
	if (zii1 != zii2)
		zuf_w_lock_nested(zii2);
}

static void _unlock_two_ziis(struct zuf_inode_info *zii1,
		      struct zuf_inode_info *zii2)
{
	if (zii1 > zii2)
		swap(zii1, zii2);

	if (zii1 != zii2)
		zuf_w_unlock(zii2);
	zuf_w_unlock(zii1);
}

static int _clone_file_range(struct inode *src_inode, loff_t pos_in,
			     struct file *file_out,
			     struct inode *dst_inode, loff_t pos_out,
			     u64 len, u64 len_up, int operation)
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
		.pos_in = pos_in,
		.pos_out = pos_out,
		.len = len,
		.len_up = len_up,
	};
	int err;

	/* NOTE: len==0 means to-end-of-file which is what we want */
	zuf_pi_unmap(src_inode, pos_in,  len, EZUF_PIU_SYNC);
	zuf_pi_unmap(dst_inode, pos_out, len, 0);

	zufc_goose_all_zts(ZUF_ROOT(SBI(dst_inode->i_sb)), dst_inode);

	if ((len_up == 0) && (pos_in || pos_out)) {
		zuf_err("Boaz Smoking 0x%llx 0x%llx 0x%llx\n",
			pos_in, pos_out, len);
		/* Bad caller */
		return -EINVAL;
	}

	err = zufc_dispatch(ZUF_ROOT(SBI(sb)), &ioc_clone.hdr, NULL, 0);
	if (unlikely(err && err != -EINTR)) {
		zuf_dbg_err("failed to clone %ld -> %ld ; err=%d\n",
			 src_inode->i_ino, dst_inode->i_ino, err);
		return err;
	}

	dst_inode->i_blocks = le64_to_cpu(dst_zi->i_blocks);
	i_size_write(dst_inode, dst_zi->i_size);

	return err;
}

/* FIXME: Old checks are not needed. I keep them to make sure they
 * are not complaining. Will remove _zuf_old_checks SOON
 */
static int _zuf_old_checks(struct super_block *sb,
			   struct inode *src_inode, loff_t pos_in,
			   struct inode *dst_inode, loff_t pos_out, loff_t len)
{
	if (src_inode == dst_inode) {
		if (pos_in == pos_out) {
			zuf_warn("[%ld] Clone nothing!!\n",
				    src_inode->i_ino);
			return 0;
		}
		if (pos_in < pos_out) {
			if (pos_in + len > pos_out) {
				zuf_warn("[%ld] overlapping pos_in < pos_out?? => EINVAL\n",
					 src_inode->i_ino);
				return -EINVAL;
			}
		} else {
			if (pos_out + len > pos_in) {
				zuf_warn("[%ld] overlapping pos_out < pos_in?? => EINVAL\n",
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

	return 0;
}

static loff_t zuf_clone_file_range(struct file *file_in, loff_t pos_in,
				struct file *file_out, loff_t pos_out,
				loff_t len, uint remap_flags)
{
	struct inode *src_inode = file_inode(file_in);
	struct inode *dst_inode = file_inode(file_out);
	struct zuf_inode_info *src_zii = ZUII(src_inode);
	struct zuf_inode_info *dst_zii = ZUII(dst_inode);
	ulong src_size = i_size_read(src_inode);
	ulong dst_size = i_size_read(dst_inode);
	struct super_block *sb = src_inode->i_sb;
	ulong len_up;
	int err;

	zuf_dbg_vfs("IN: [%ld]{0x%llx} => [%ld]{0x%llx} length=0x%llx flags=0x%x\n",
		    src_inode->i_ino, pos_in, dst_inode->i_ino, pos_out, len,
		    remap_flags);

	if (remap_flags & ~(REMAP_FILE_CAN_SHORTEN | REMAP_FILE_DEDUP)) {
		/* New flags we do not know */
		zuf_dbg_err("[%ld] Unknown remap_flags(0x%x)\n",
			    src_inode->i_ino, remap_flags);
		return -EINVAL;
	}

	if ((pos_in + len > sb->s_maxbytes) || (pos_out + len > sb->s_maxbytes))
		return -EINVAL;

	_lock_two_ziis(src_zii, dst_zii);

	err = _remap_file_range_prep(file_in, pos_in, file_out, pos_out, &len,
				     remap_flags);
	if (err < 0 || len == 0)
		goto out;
	err = _zuf_old_checks(sb, src_inode, pos_in, dst_inode, pos_out, len);
	if (unlikely(err))
		goto out;

	err = file_remove_privs(file_out);
	if (unlikely(err))
		goto out;

	if (!(remap_flags & REMAP_FILE_DEDUP))
		zus_inode_cmtime_now(dst_inode, dst_zii->zi);

	/* See about all-file-clone optimization */
	len_up = len;
	if (!pos_in && !pos_out && (src_size <= pos_in + len) &&
	    (dst_size <= src_size)) {
		len_up = 0;
	} else if (len & (sb->s_blocksize - 1)) {
		/* un-aligned len, see if it is beyond EOF */
		if ((src_size > pos_in  + len) ||
		    (dst_size > pos_out + len)) {
			zuf_dbg_err("[%ld][%ld] Not aligned len=0x%llx pos_in=0x%llx "
				"pos_out=0x%llx src-size=0x%lx dst-size=0x%lx\n",
				src_inode->i_ino, dst_inode->i_ino, len,
				pos_in, pos_out, src_size, dst_size);
			err = -EINVAL;
			goto out;
		}
		len_up = md_p2o(md_o2p_up(len));
	}

	err = _clone_file_range(src_inode, pos_in, file_out, dst_inode, pos_out,
				len, len_up, ZUFS_OP_CLONE);
	if (unlikely(err))
		zuf_dbg_err("_clone_file_range failed => %d\n", err);

out:
	_unlock_two_ziis(src_zii, dst_zii);
	return err ? err : len;
}

static ssize_t zuf_copy_file_range(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   size_t len, uint flags)
{
	struct inode *src_inode = file_inode(file_in);
	struct inode *dst_inode = file_inode(file_out);
	ssize_t ret;

	zuf_dbg_vfs("ino-in=%ld ino-out=%ld pos_in=0x%llx pos_out=0x%llx length=0x%lx\n",
		    src_inode->i_ino, dst_inode->i_ino, pos_in, pos_out, len);

	if (src_inode->i_sb != dst_inode->i_sb)
		return generic_copy_file_range(file_in, pos_in, file_out,
					       pos_out, len, flags);

	ret = zuf_clone_file_range(file_in, pos_in, file_out, pos_out, len,
				   REMAP_FILE_ADVISORY);

	return ret ?: len;
}

static ssize_t zuf_read_iter(struct kiocb *kiocb, struct iov_iter *ii)
{
	struct inode *inode = file_inode(kiocb->ki_filp);
	struct zuf_inode_info *zii = ZUII(inode);
	ssize_t ret;

	zuf_dbg_rw("[%ld] @x%llx len=0x%zx\n",
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

	zuf_dbg_rw("[%ld] @x%llx len=0x%zx\n",
		     inode->i_ino, kiocb->ki_pos, iov_iter_count(ii));

	ret = generic_write_checks(kiocb, ii);
	if (unlikely(ret < 0)) {
		zuf_dbg_rw("[%ld] generic_write_checks => 0x%lx\n",
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

static int zuf_fadvise(struct file *file, loff_t offset, loff_t len,
		       int advise)
{
	struct inode *inode = file_inode(file);
	struct zuf_inode_info *zii = ZUII(inode);
	int err;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	zuf_r_lock(zii);

	err = zuf_rw_fadvise(inode->i_sb, file, offset, len, advise,
			     file->f_mode & FMODE_RANDOM);

	zuf_r_unlock(zii);

	return err;
}

const struct file_operations zuf_file_operations = {
	.open			= generic_file_open,
	.read_iter		= zuf_read_iter,
	.write_iter		= zuf_write_iter,
	.mmap			= zuf_file_mmap,
	.fsync			= zuf_fsync,
	.llseek			= zuf_llseek,
	.flush			= zuf_flush,
	.fallocate		= zuf_fallocate,
	.copy_file_range	= zuf_copy_file_range,
	.remap_file_range	= zuf_clone_file_range,
	.fadvise		= zuf_fadvise,
	.unlocked_ioctl		= zuf_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= zuf_compat_ioctl,
#endif
};

const struct inode_operations zuf_file_inode_operations = {
	.setattr	= zuf_setattr,
	.getattr	= zuf_getattr,
	.update_time	= zuf_update_time,
	.fiemap		= zuf_fiemap,
	.get_acl	= zuf_get_acl,
	.set_acl	= zuf_set_acl,
	.listxattr	= zuf_listxattr,
};
