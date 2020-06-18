// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Read/Write operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */
#include <linux/fadvise.h>
#include <linux/uio.h>
#include <linux/delay.h>
#include <asm/cacheflush.h>

#include "zuf.h"
#include "t2.h"

#define	rand_tag(kiocb)	\
	((kiocb->ki_filp->f_mode & FMODE_RANDOM) ? ZUFS_RW_RAND : 0)
#define	kiocb_ra(kiocb)	(&kiocb->ki_filp->f_ra)

static const char *_pr_rw(uint rw)
{
	return (rw & WRITE) ? "WRITE" : "READ";
}

static int _ioc_bounds_check(struct zufs_iomap *user_ziom, uint max_size)
{
	void *ziom_end = (void *)user_ziom + max_size;
	size_t iom_n_max = (ziom_end - (void *)&user_ziom->iom_e) /
							sizeof(__u64);

	if (unlikely(iom_n_max < user_ziom->iom_n)) {
		zuf_err("iom_n_max(0x%zx) < iom_n(0x%x)\n",
			iom_n_max, user_ziom->iom_n);
		return -EINVAL;
	}

	return 0;
}

static void _extract_gb_multy_bns(struct _io_gb_multy *io_gb,
				  struct zufs_ioc_IO *io_user, uint max_bns)
{
	uint i;

	/* Return of some T1 pages from GET_MULTY */
	/* currently we do not support any other operations other than
	 * IOM_T1_READ. (We could easily)
	 */

	io_gb->iom_n = 0;
	for (i = 0; i < max_bns; ++i) {
		ulong bn = _zufs_iom_t1_bn(io_user->iom_e[i]);

		if (unlikely(bn == -1)) {
			zuf_err("!!!! Not all decode i=%u max_bns=%u iom_e=0x%llx\n",
				i, max_bns, io_user->iom_e[i]);
			break;
		}
		io_gb->bns[io_gb->iom_n++] = bn;
	}
}

static int rw_overflow_handler(struct zuf_dispatch_op *zdo, void *arg,
			       ulong max_bytes)
{
	struct zufs_ioc_IO *io = container_of(zdo->hdr, typeof(*io), hdr);
	struct zufs_ioc_IO *io_user = arg;
	struct _io_gb_multy *io_gb = container_of(io, typeof(*io_gb), IO);
	ulong new_len;
	ulong offset;
	uint max_bns;
	int err;

	err = _ioc_bounds_check(&io_user->ziom, max_bytes);
	if (unlikely(err))
		return err;

	if (io_user->hdr.err == -EZUFS_RETRY) {
		if (!(io_user->ziom.iom_n && _zufs_iom_pop(io_user->iom_e))) {
			zuf_warn("ZUSfs violating API EZUFS_RETRY with no payload\n");
			/* Server is buggy (or memory got corrupted) let
			 * the server know
			 */
			io_user->hdr.err = -EINVAL;
			return EZUF_RETRY_DONE;
		}

		io->hdr.err = zuf_iom_execute_sync(zdo->sb, zdo->inode,
						   io_user->iom_e,
						   io_user->ziom.iom_n);

		zuf_dbg_rw(
			"[%s]zuf_iom_execute_sync(%d) max=0x%lx iom_e[%d] => %d\n",
			zuf_op_name(io->hdr.operation), io_user->ziom.iom_n,
			max_bytes, _zufs_iom_opt_type(io_user->iom_e),
			io->hdr.err);

		return EZUF_RETRY_DONE;
	}

	/* No tier ups needed */
	if (io->hdr.operation != ZUFS_OP_GET_MULTY) {
		*io = *io_user; /* copy the output to caller */
		return 0; /* We are finished */
	}

	/* ZUFS_OP_GET_MULTY Decoding at ZT context  */

	/* catch the case Server returned IO to long */
	new_len = io_user->last_pos - io->filepos;
	if (unlikely(io->hdr.len < new_len)) {
		zuf_err("Return overflow last_pos=0x%llx filepos=0x%llx len=0x%x\n",
			io_user->last_pos, io->filepos, io->hdr.len);
		/* We yell but continue because Server might have done a GET
		 * and we want to still do a PUT, even with a smoking Server.
		 */
		new_len = io->hdr.len;
		io_user->last_pos = io->filepos + new_len;
	}

	if (!io_user->ziom.iom_n) {
		if (new_len) {
			zuf_err("[%s] iom_n=0 but new_len=0x%lx\n",
				_pr_rw(io->rw), new_len);
			io_user->last_pos = io_user->filepos = io->filepos;
		}
		*io = *io_user;
		return 0;
	}

	/* extract some bns from payload */

	offset = (io->filepos & ~PAGE_MASK);
	max_bns = md_o2p_up(offset + new_len);

	/* catch the case num_blocks_of(new_len) mismatch returned iom_n.
	 * Use the minimum of the two. Also fix last_pos if needed
	 */
	if (max_bns != io_user->ziom.iom_n) {
		zuf_err("Bad Server new_len=0x%lx mismatch with iom_n=%d off=0x%lx\n",
			new_len, io_user->ziom.iom_n, offset);
		if (max_bns > io_user->ziom.iom_n) {
			max_bns = io_user->ziom.iom_n;
			io_user->last_pos = io->filepos +
						(md_p2o(max_bns) - offset);
		}
	}

	zuf_dbg_rw("[%s] _extract_bns(%d) iom_e[0x%llx]\n",
			zuf_op_name(io->hdr.operation), max_bns,
			io_user->iom_e[0]);

	*io = *io_user;
	_extract_gb_multy_bns(io_gb, io_user, max_bns);
	return 0;
}

static int _IO_dispatch(struct zuf_sb_info *sbi, struct zufs_ioc_IO *IO,
			struct zuf_inode_info *zii, int operation,
			uint pgoffset, struct page **pages, uint nump,
			u64 filepos, uint len)
{
	struct zuf_dispatch_op zdo;
	int err;

	IO->hdr.operation = operation;
	IO->hdr.in_len = sizeof(*IO);
	IO->hdr.out_len = sizeof(*IO);
	IO->hdr.offset = pgoffset;
	IO->hdr.len = len;
	IO->zus_ii = zii->zus_ii;
	IO->filepos = filepos;

	zuf_dispatch_init(&zdo, &IO->hdr, pages, nump);
	zdo.oh = rw_overflow_handler;
	zdo.sb = sbi->sb;
	zdo.inode = &zii->vfs_inode;

	zuf_dbg_verbose("[%ld][%s] fp=0x%llx nump=0x%x len=0x%x\n",
			zdo.inode ? zdo.inode->i_ino : -1,
			zuf_op_name(operation), filepos, nump, len);

	err = __zufc_dispatch(ZUF_ROOT(sbi), &zdo);
	if (unlikely(err == -EZUFS_RETRY)) {
		zuf_err("Unexpected ZUS return => %d\n", err);
		err = -EIO;
	}
	return err;
}

int zuf_rw_read_page(struct zuf_sb_info *sbi, struct inode *inode,
		     struct page *page, u64 filepos)
{
	struct zufs_ioc_IO io = {};
	struct page *pages[1];
	uint nump;
	int err;

	pages[0] = page;
	nump = 1;

	err = _IO_dispatch(sbi, &io, ZUII(inode), ZUFS_OP_READ, 0, pages, nump,
			   filepos, PAGE_SIZE);
	return err;
}


/* return < 0 - is err. 0 compairs */
int zuf_rw_file_range_compare(struct inode *i_in, loff_t pos_in,
			      struct inode *i_out, loff_t pos_out, loff_t len)
{
	struct super_block *sb = i_in->i_sb;
	ulong bs = sb->s_blocksize;
	struct page *p_in, *p_out;
	void *a_in, *a_out;
	int err = 0;

	if (unlikely((pos_in & (bs - 1)) || (pos_out & (bs - 1)) ||
		     (bs != PAGE_SIZE))) {
		zuf_err("[%ld]@0x%llx & [%ld]@0x%llx len=0x%llx bs=0x%lx\n",
			   i_in->i_ino, pos_in, i_out->i_ino, pos_out, len, bs);
		return -EINVAL;
	}

	zuf_dbg_rw("[%ld]@0x%llx & [%ld]@0x%llx len=0x%llx\n",
		   i_in->i_ino, pos_in, i_out->i_ino, pos_out, len);

	p_in = alloc_page(GFP_KERNEL);
	p_out = alloc_page(GFP_KERNEL);
	if (unlikely(!p_in || !p_out)) {
		err = -ENOMEM;
		goto out;
	}
	a_in = page_address(p_in);
	a_out = page_address(p_out);

	while (len) {
		ulong l;

		err = zuf_rw_read_page(SBI(sb), i_in, p_in, pos_in);
		if (unlikely(err))
			goto out;

		err = zuf_rw_read_page(SBI(sb), i_out, p_out, pos_out);
		if (unlikely(err))
			goto out;

		l = min_t(ulong, PAGE_SIZE, len);
		if (memcmp(a_in, a_out, l)) {
			err = -EBADE;
			goto out;
		}

		pos_in += l;
		pos_out += l;
		len -= l;
	}

out:
	__free_page(p_in);
	__free_page(p_out);

	return err;
}

int zuf_rw_fallocate(struct inode *inode, uint mode, loff_t pos, loff_t len)
{
	struct zufs_ioc_IO io = {};
	int err;

	io.last_pos = (len == ~0ULL) ? ~0ULL : pos + len;
	io.rw = mode;

	err = _IO_dispatch(SBI(inode->i_sb), &io, ZUII(inode),
			   ZUFS_OP_FALLOCATE, 0, NULL, 0, pos, 0);

	if (io.hdr.flags & ZUFS_H_INODE_CLEAN) {
		zuf_dbg_verbose("sync: [%ld] got hint\n", inode->i_ino);
		zuf_sync_remove(inode);
	}

	return err;
}

static struct page *_addr_to_page(unsigned long addr)
{
	const void *p = (const void *)addr;

	return is_vmalloc_addr(p) ? vmalloc_to_page(p) : virt_to_page(p);
}

static ssize_t _iov_iter_get_pages_kvec(struct iov_iter *ii,
		   struct page **pages, size_t maxsize, uint maxpages,
		   size_t *start)
{
	ssize_t bytes;
	size_t i, nump;
	unsigned long addr = (unsigned long)ii->kvec->iov_base;

	*start = addr & (PAGE_SIZE - 1);
	bytes = min_t(ssize_t, iov_iter_single_seg_count(ii), maxsize);
	nump = min_t(size_t, DIV_ROUND_UP(bytes + *start, PAGE_SIZE), maxpages);

	/* TODO: FUSE assumes single page for ITER_KVEC. Boaz: Remove? */
	WARN_ON(nump > 1);

	for (i = 0; i < nump; ++i) {
		pages[i] = _addr_to_page(addr + (i * PAGE_SIZE));

		get_page(pages[i]);
	}
	return bytes;
}

static ssize_t _iov_iter_get_pages_any(struct iov_iter *ii,
		   struct page **pages, size_t maxsize, uint maxpages,
		   size_t *start)
{
	ssize_t bytes;

	bytes = unlikely(ii->type & ITER_KVEC) ?
		_iov_iter_get_pages_kvec(ii, pages, maxsize, maxpages, start) :
		iov_iter_get_pages(ii, pages, maxsize, maxpages, start);

	if (unlikely(bytes < 0))
		zuf_dbg_err("[%d] bytes=%ld type=%d count=%lu",
			smp_processor_id(), bytes, ii->type, ii->count);

	return bytes;
}

static ssize_t _zufs_IO(struct zuf_sb_info *sbi, struct inode *inode,
			void *on_stack, uint max_on_stack,
			struct iov_iter *ii, struct kiocb *kiocb,
			struct file_ra_state *ra, int operation, uint rw)
{
	int err = 0;
	loff_t start_pos = kiocb->ki_pos;
	loff_t pos = start_pos;
	enum big_alloc_type bat;
	struct page **pages;
	uint max_pages = min_t(uint,
			md_o2p_up(iov_iter_count(ii) + (pos & ~PAGE_MASK)),
			ZUS_API_MAP_MAX_PAGES);

	pages = big_alloc(max_pages * sizeof(*pages), max_on_stack, on_stack,
			  GFP_NOFS, &bat);
	if (unlikely(!pages)) {
		zuf_err("Sigh on stack is best max_pages=%d\n", max_pages);
		return -ENOMEM;
	};

	while (iov_iter_count(ii)) {
		struct zufs_ioc_IO io = {};
		uint nump;
		ssize_t bytes;
		size_t pgoffset;
		uint i;

		if (ra) {
			io.ra.start	= ra->start;
			io.ra.ra_pages	= ra->ra_pages;
			io.ra.prev_pos	= ra->prev_pos;
		}
		io.rw = rw;

		bytes = _iov_iter_get_pages_any(ii, pages,
					ZUS_API_MAP_MAX_SIZE,
					ZUS_API_MAP_MAX_PAGES, &pgoffset);
		if (unlikely(bytes < 0)) {
			err = bytes;
			break;
		}

		nump = DIV_ROUND_UP(bytes + pgoffset, PAGE_SIZE);

		io.last_pos = pos;
		err = _IO_dispatch(sbi, &io, ZUII(inode), operation,
				   pgoffset, pages, nump, pos, bytes);

		bytes = io.last_pos - pos;

		zuf_dbg_rw("[%ld]	%s [0x%llx-0x%zx]\n",
			    inode->i_ino, _pr_rw(rw), pos, bytes);

		iov_iter_advance(ii, bytes);
		pos += bytes;

		if (ra) {
			ra->start	= io.ra.start;
			ra->ra_pages	= io.ra.ra_pages;
			ra->prev_pos	= io.ra.prev_pos;
		}
		if (io.wr_unmap.len)
			zuf_pi_unmap(inode, io.wr_unmap.offset,
				     io.wr_unmap.len, 0);

		for (i = 0; i < nump; ++i)
			put_page(pages[i]);

		if (unlikely(err))
			break;
	}

	big_free(pages, bat);

	if (unlikely(pos == start_pos))
		return err;

	kiocb->ki_pos = pos;
	return pos - start_pos;
}

static int _IO_get_multy(struct zuf_sb_info *sbi, struct inode *inode, uint rw,
			 struct file_ra_state *ra, loff_t pos, ulong len,
			 ulong *bns, struct _io_gb_multy *io_gb)
{
	struct zufs_ioc_IO *IO = &io_gb->IO;
	uint retry = 100;
	int err;

do_retry:
	memset(IO, 0, sizeof(*IO));

	IO->hdr.operation = ZUFS_OP_GET_MULTY;
	IO->hdr.in_len = _ioc_IO_size(0);
	IO->hdr.out_len = _ioc_IO_size(0);
	IO->hdr.len = len;
	IO->rw = rw,
	IO->zus_ii = ZUII(inode)->zus_ii;
	IO->filepos = pos;
	IO->last_pos = pos;
	if (ra) {
		IO->ra.start	= ra->start;
		IO->ra.ra_pages	= ra->ra_pages;
		IO->ra.prev_pos	= ra->prev_pos;
	}

	zuf_dispatch_init(&io_gb->zdo, &IO->hdr, NULL, 0);
	io_gb->zdo.oh = rw_overflow_handler;
	io_gb->zdo.sb = sbi->sb;
	io_gb->zdo.inode = inode;
	io_gb->zdo.bns = bns;

	err = __zufc_dispatch(ZUF_ROOT(sbi), &io_gb->zdo);
	if (unlikely(err == -EZUFS_RETRY)) {
		zuf_err("Unexpected ZUS return => %d\n", err);
		err = -EIO;
	}

	if (ra) {
		ra->start	= IO->ra.start;
		ra->ra_pages	= IO->ra.ra_pages;
		ra->prev_pos	= IO->ra.prev_pos;
	}

	if (unlikely(err)) {
		/* err from Server means no contract and NO bns locked
		 * so no puts
		 */
		if ((err != -ENOSPC) && (err != -EIO) && (err != -EINTR))
			zuf_warn("At this early stage show me %d\n", err);
		if (IO->ziom.iom_n || (IO->filepos != IO->last_pos))
			zuf_err("Server Smoking iom_n=%u err=%d\n",
				io_gb->IO.ziom.iom_n, err);
		zuf_dbg_err("_IO_dispatch => %d\n", err);
		return err;
	}
	if (unlikely(!io_gb->iom_n)) {
		/* We always go through rw_overflow_handler It already yelled
		 * about any errors and fixed what it can. If we get here it
		 * means Server returned with zero length for us to retry
		 * the operation.
		 */
		if (!--retry)
			return -EIO;
		schedule();
		goto do_retry;
	}
	/* Even if _IO_dispatch returned a theoretical error but also some
	 * pages, we do the few pages and do an OP_PUT_MULTY (error ignored)
	 */
	return 0;
}

static void _IO_put_multy(struct zuf_sb_info *sbi, struct inode *inode,
			  struct _io_gb_multy *io_gb)
{
	bool put_now;
	int err;

	put_now = io_gb->IO.ret_flags &
		  (ZUFS_RET_PUT_NOW | ZUFS_RET_NEW | ZUFS_RET_LOCKED_PUT);

	err  = zufc_pigy_put(ZUF_ROOT(sbi), &io_gb->zdo, &io_gb->IO,
			     io_gb->iom_n, io_gb->bns, put_now);
	if (unlikely(err))
		zuf_warn("zufc_pigy_put => %d\n", err);
}

static inline int _read_one(struct zuf_sb_info *sbi, struct iov_iter *ii,
			     ulong bn, uint offset, uint len, int i)
{
	uint retl;

	if (!bn) {
		retl = iov_iter_zero(len, ii);
	} else {
		void *addr = md_addr_verify(sbi->md, md_p2o(bn));

		if (unlikely(!addr)) {
			zuf_err("Server bad bn[%d]=0x%lx bytes_more=0x%lx\n",
				i, bn, iov_iter_count(ii));
			return -EIO;
		}
		retl = copy_to_iter(addr + offset, len, ii);
	}
	if (unlikely(retl != len)) {
		/* This can happen if we get a read_only Prt from App */
		zuf_dbg_err("copy_to_iter bn=0x%lx off=0x%x len=0x%x retl=0x%x\n",
			bn, offset, len, retl);
		return -EFAULT;
	}

	return 0;
}

static inline int _write_one(struct zuf_sb_info *sbi, struct iov_iter *ii,
			     ulong bn, uint offset, uint len, int i)
{
	void *addr = md_addr_verify(sbi->md, md_p2o(bn));
	uint retl;

	if (unlikely(!addr)) {
		zuf_err("Server bad page[%d] bn=0x%lx bytes_more=0x%lx\n",
			i, bn, iov_iter_count(ii));
		return -EIO;
	}

	retl = _copy_from_iter_flushcache(addr + offset, len, ii);
	if (unlikely(retl != len)) {
		/* FIXME: This can happen if we get a read_only Prt from App */
		zuf_err("copy_to_iter bn=0x%lx off=0x%x len=0x%x retl=0x%x\n",
			bn, offset, len, retl);
		return -EFAULT;
	}
	return 0;
}

int zuf_rw_cached_get(struct zuf_sb_info *sbi, struct inode *inode, uint rw,
		       struct file_ra_state *ra, loff_t pos, ulong len,
		       ulong *bns, struct _io_gb_multy *io_gb)
{
	io_gb->iom_n = 0;
	io_gb->bns = bns;

	return _IO_get_multy(sbi, inode, rw, ra, pos, len, bns, io_gb);
}

void zuf_rw_cached_put(struct zuf_sb_info *sbi, struct inode *inode,
			struct _io_gb_multy *io_gb)
{
	_IO_put_multy(sbi, inode, io_gb);
	if (io_gb->IO.wr_unmap.len)
		zuf_pi_unmap(inode, io_gb->IO.wr_unmap.offset,
			     io_gb->IO.wr_unmap.len, 0x4000);
}

static ssize_t _IO_gm_inner(struct zuf_sb_info *sbi, struct inode *inode,
			    ulong *bns, uint max_bns,
			    struct iov_iter *ii, struct file_ra_state *ra,
			    loff_t start, uint rw)
{
	loff_t pos = start;
	uint offset = pos & (PAGE_SIZE - 1);
	struct _io_gb_multy io_gb;
	ssize_t size;
	int err;
	uint i;

	size = min_t(ssize_t, ZUS_API_MAP_MAX_SIZE - offset,
		     iov_iter_count(ii));
	err = zuf_rw_cached_get(sbi, inode, rw, ra, pos, size, bns, &io_gb);
	if (unlikely(err))
		return err;

	zuf_dbg_rw("[%ld] %s [@x%llx-0x%zx] {0x%llx}\n",
		   inode->i_ino, _pr_rw(rw), pos, size,
		   io_gb.IO.last_pos - pos);

	if (unlikely(io_gb.IO.last_pos != (pos + size))) {
		size = io_gb.IO.last_pos - pos;
		zuf_dbg_rw("I see this pos=0x%llx size=0x%zx\n", pos, size);
		if (!size) {
			zuf_warn("Is this a BUG\n");
			goto out;
		}
	}

	i = 0;
	while (size) {
		uint len;
		ulong bn;

		len = min_t(uint, PAGE_SIZE - offset, size);

		bn = io_gb.bns[i];
		if (rw & WRITE)
			err = _write_one(sbi, ii, bn, offset, len, i);
		else
			err = _read_one(sbi, ii, bn, offset, len, i);
		if (unlikely(err))
			break;

		zuf_dbg_rw("[%ld]       %s [@x%04llx-0x%04x] bn=0x%04lx [%d]\n",
			    inode->i_ino, _pr_rw(rw), pos, len, bn, i);

		++i;
		pos += len;
		size -= len;
		offset = 0;
	}

	zuf_rw_cached_put(sbi, inode, &io_gb);

out:
	return unlikely(pos == start) ? err : pos - start;
}

static ssize_t _IO_gm(struct zuf_sb_info *sbi, struct inode *inode,
		      ulong *on_stack, uint max_on_stack,
		      struct iov_iter *ii, struct kiocb *kiocb,
		      struct file_ra_state *ra, uint rw)
{
	ssize_t size = 0;
	ssize_t ret = 0;
	enum big_alloc_type bat;
	ulong *bns;
	uint max_bns = min_t(uint,
		md_o2p_up(iov_iter_count(ii) + (kiocb->ki_pos & ~PAGE_MASK)),
		ZUS_API_MAP_MAX_PAGES);

	bns = big_alloc(max_bns * sizeof(ulong), max_on_stack, on_stack,
			GFP_NOFS, &bat);
	if (unlikely(!bns)) {
		zuf_err("life was more simple on the stack max_bns=%d\n",
			max_bns);
		return -ENOMEM;
	}

	while (iov_iter_count(ii)) {
		ret = _IO_gm_inner(sbi, inode, bns, max_bns, ii, ra,
				   kiocb->ki_pos, rw);
		if (unlikely(ret < 0))
			break;

		kiocb->ki_pos += ret;
		size += ret;
	}

	big_free(bns, bat);

	return size ?: ret;
}

ssize_t zuf_rw_read_iter(struct super_block *sb, struct inode *inode,
			 struct kiocb *kiocb, struct iov_iter *ii)
{
	long on_stack[ZUF_MAX_STACK(8) / sizeof(long)];
	ulong rw = READ | rand_tag(kiocb);

	/* EOF protection */
	if (unlikely(kiocb->ki_pos > i_size_read(inode)))
		return 0;

	iov_iter_truncate(ii, i_size_read(inode) - kiocb->ki_pos);
	if (unlikely(!iov_iter_count(ii))) {
		/* Don't let zero len reads have any effect */
		zuf_dbg_rw("called with NULL len\n");
		return 0;
	}

	if (zuf_is_nio_reads(inode))
		return _IO_gm(SBI(sb), inode, on_stack, sizeof(on_stack),
			      ii, kiocb, kiocb_ra(kiocb), rw);

	return _zufs_IO(SBI(sb), inode, on_stack, sizeof(on_stack), ii,
			kiocb, kiocb_ra(kiocb), ZUFS_OP_READ, rw);
}

ssize_t zuf_rw_write_iter(struct super_block *sb, struct inode *inode,
			  struct kiocb *kiocb, struct iov_iter *ii)
{
	long on_stack[ZUF_MAX_STACK(8) / sizeof(long)];
	ulong rw = WRITE;

	if (kiocb->ki_filp->f_flags & O_DSYNC ||
	    IS_SYNC(kiocb->ki_filp->f_mapping->host))
		rw |= ZUFS_RW_DSYNC;
	if (kiocb->ki_filp->f_flags & O_DIRECT)
		rw |= ZUFS_RW_DIRECT;

	if (zuf_is_nio_writes(inode))
		return _IO_gm(SBI(sb), inode, on_stack, sizeof(on_stack),
			      ii, kiocb, kiocb_ra(kiocb), rw);

	return _zufs_IO(SBI(sb), inode, on_stack, sizeof(on_stack),
			ii, kiocb, kiocb_ra(kiocb), ZUFS_OP_WRITE, rw);
}

static int _fadv_willneed(struct super_block *sb, struct inode *inode,
			  loff_t offset, loff_t len, bool rand)
{
	struct zufs_ioc_IO io = {};
	struct __zufs_ra ra = {
		.start = md_o2p(offset),
		.ra_pages = md_o2p_up(len),
		.prev_pos = offset - 1,
	};
	int err;

	io.ra.start = ra.start;
	io.ra.ra_pages = ra.ra_pages;
	io.ra.prev_pos = ra.prev_pos;
	io.rw = rand ? ZUFS_RW_RAND : 0;

	err = _IO_dispatch(SBI(sb), &io, ZUII(inode), ZUFS_OP_PRE_READ, 0,
			   NULL, 0, offset, 0);
	return err;
}

static int _fadv_dontneed(struct super_block *sb, struct inode *inode,
			  loff_t offset, loff_t len)
{
	struct zufs_ioc_sync ioc_range = {
		.hdr.in_len = sizeof(ioc_range),
		.hdr.operation = ZUFS_OP_SYNC,
		.zus_ii = ZUII(inode)->zus_ii,
		.offset = offset,
		.length = len,
		.flags = ZUFS_SF_DONTNEED,
	};

	return zufc_dispatch(ZUF_ROOT(SBI(sb)), &ioc_range.hdr, NULL, 0);
}

/* FIXME: There is a pending patch from Jan Karta to export generic_fadvise.
 * until then duplicate here what we need
 */
#include <linux/backing-dev.h>

static int _generic_fadvise(struct file *file, loff_t offset, loff_t len,
			    int advise)
{
	struct backing_dev_info *bdi = inode_to_bdi(file_inode(file));

	switch (advise) {
	case POSIX_FADV_NORMAL:
		file->f_ra.ra_pages = bdi->ra_pages;
		spin_lock(&file->f_lock);
		file->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_RANDOM:
		spin_lock(&file->f_lock);
		file->f_mode |= FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_SEQUENTIAL:
		file->f_ra.ra_pages = bdi->ra_pages * 2;
		spin_lock(&file->f_lock);
		file->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_NOREUSE:
		break;
	}

	return 0;
}

int zuf_rw_fadvise(struct super_block *sb, struct file *file,
		   loff_t offset, loff_t len, int advise, bool rand)
{
	switch (advise) {
	case POSIX_FADV_WILLNEED:
		return _fadv_willneed(sb, file_inode(file), offset, len, rand);
	case POSIX_FADV_DONTNEED:
		return _fadv_dontneed(sb, file_inode(file), offset, len);

	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_NOREUSE:
		return _generic_fadvise(file, offset, len, advise);
	default:
		zuf_warn("Unknown advise %d\n", advise);
		return -EINVAL;
	}
	return -EINVAL;
}

/* ~~~~ iom_dec.c ~~~ */
/* for now here (at rw.c) looks logical */

static int __iom_add_t2_io_len(struct super_block *sb, struct t2_io_state *tis,
			       zu_dpp_t t1, ulong t2_bn, __u64 num_pages)
{
	void *ptr;
	struct page *page;
	int i, err;

	ptr = zuf_dpp_t_addr(sb, t1);
	if (unlikely(!ptr)) {
		zuf_err("Bad t1 zu_dpp_t t1=0x%llx t2=0x%lx num_pages=0x%llx\n",
			t1, t2_bn, num_pages);
		return -EFAULT; /* zuf_dpp_t_addr already yeld */
	}

	page = virt_to_page(ptr);
	if (unlikely(!page)) {
		zuf_err("bad t1(0x%llx)\n", t1);
		return -EFAULT;
	}

	for (i = 0; i < num_pages; ++i) {
		err = t2_io_add(tis, t2_bn++, page++);
		if (unlikely(err))
			return err;
	}
	return 0;
}

static int iom_add_t2_io_len(struct super_block *sb, struct t2_io_state *tis,
			     __u64 **cur_e)
{
	struct zufs_iom_t2_io_len *t2iol = (void *)*cur_e;
	int err = __iom_add_t2_io_len(sb, tis, t2iol->iom.t1_val,
				      _zufs_iom_first_val(&t2iol->iom.t2_val),
				      t2iol->num_pages);

	*cur_e = (void *)(t2iol + 1);
	return err;
}

static int iom_add_t2_io(struct super_block *sb, struct t2_io_state *tis,
			 __u64 **cur_e)
{
	struct zufs_iom_t2_io *t2io = (void *)*cur_e;

	int err = __iom_add_t2_io_len(sb, tis, t2io->t1_val,
				      _zufs_iom_first_val(&t2io->t2_val), 1);

	*cur_e = (void *)(t2io + 1);
	return err;
}

static int iom_t2_zusmem_io(struct super_block *sb, struct t2_io_state *tis,
			    __u64 **cur_e)
{
	struct zufs_iom_t2_zusmem_io *mem_io = (void *)*cur_e;
	ulong t2_bn = _zufs_iom_first_val(&mem_io->t2_val);
	ulong user_ptr = (ulong)mem_io->zus_mem_ptr;
	int rw = _zufs_iom_opt_type(*cur_e) == IOM_T2_ZUSMEM_WRITE ?
						WRITE : READ;
	int num_p = md_o2p_up(mem_io->len);
	int num_p_r;
	struct page *pages[16];
	int i, err = 0;

	if (16 < num_p) {
		zuf_err("num_p(%d) > 16\n", num_p);
		return -EINVAL;
	}

	num_p_r = get_user_pages_fast(user_ptr, num_p, rw,
				      pages);
	if (num_p_r != num_p) {
		zuf_err("!!!! get_user_pages_fast num_p_r(%d) != num_p(%d)\n",
			num_p_r, num_p);
		err = -EFAULT;
		goto out;
	}

	for (i = 0; i < num_p_r && !err; ++i)
		err = t2_io_add(tis, t2_bn++, pages[i]);

out:
	for (i = 0; i < num_p_r; ++i)
		put_page(pages[i]);

	*cur_e = (void *)(mem_io + 1);
	return err;
}

static int iom_unmap(struct super_block *sb, struct inode *inode, __u64 **cur_e)
{
	struct zufs_iom_unmap *iom_unmap = (void *)*cur_e;
	struct inode *inode_look = NULL;
	ulong	unmap_index = _zufs_iom_first_val(&iom_unmap->unmap_index);
	ulong	unmap_n = iom_unmap->unmap_n;
	ulong	ino = iom_unmap->ino;
	int flags = EZUF_PIU_AT_iom_unmap;

	if (!inode || ino) {
		if (WARN_ON(!ino)) {
			zuf_err("[%ld] 0x%lx-0x%lx\n",
				inode ? inode->i_ino : -1, unmap_index,
				unmap_n);
			goto out;
		}
		inode_look = ilookup(sb, ino);
		if (!inode_look) {
			/* From the time we requested an unmap to now
			 * inode was evicted from cache so surely it no longer
			 * have any mappings. Cool job was already done for us.
			 * Even if a racing thread reloads the inode it will
			 * not have this mapping we wanted to clear, but only
			 * new ones.
			 * TODO: For now warn when this happen, because in
			 *    current usage it cannot happen. But before
			 *    upstream we should convert to zuf_dbg_err
			 */
			zuf_warn("[%ld] @x%lx-0x%lx\n",
				 ino, unmap_index, unmap_n);
			goto out;
		}

		inode = inode_look;
		flags = EZUF_PIU_UNLOCKED;
	} else {
		zuf_err("[%ld] unmap with inode\n", inode->i_ino);
	}

	zuf_dbg_mmap("[%ld] @x%lx-0x%lx lookup=%ld\n",
		     inode->i_ino, unmap_index, unmap_n,
		     inode_look ? inode_look->i_ino : -1);

	zuf_pi_unmap(inode, md_p2o(unmap_index), md_p2o(unmap_n), flags);

	if (inode_look)
		iput(inode_look);

out:
	*cur_e = (void *)(iom_unmap + 1);
	return 0;
}

static int iom_wbinv(__u64 **cur_e)
{
	wbinvd();

	++*cur_e;

	return 0;
}

static int iom_discard(struct super_block *sb, struct t2_io_state *tis,
		       __u64 **cur_e)
{
	struct zufs_iom_t2_io_len *t2iol = (void *)*cur_e;
	ulong t2 = _zufs_iom_first_val(&t2iol->iom.t2_val);
	ulong local_t2 = md_t2_local_bn(tis->md, t2);
	struct md_dev_info *mdi;
	int err;

	mdi = md_bn_t2_dev(tis->md, t2);

	err = blkdev_issue_discard(mdi->bdev, local_t2 << (PAGE_SHIFT - 9),
				   t2iol->num_pages << (PAGE_SHIFT - 9),
				   GFP_NOFS, 0);

	*cur_e = (void *)(t2iol + 1);

	return err;
}

struct _iom_exec_info {
	struct super_block *sb;
	struct inode *inode;
	struct t2_io_state *rd_tis;
	struct t2_io_state *wr_tis;
	__u64 *iom_e;
	uint iom_n;
	bool print;
};

static int _iom_execute_inline(struct _iom_exec_info *iei)
{
	__u64 *cur_e, *end_e;
	int err = 0;
#ifdef CONFIG_ZUF_DEBUG
	uint wrs = 0;
	uint rds = 0;
	uint uns = 0;
	uint wrmem = 0;
	uint rdmem = 0;
	uint wbinv = 0;
	uint discard = 0;
#	define	WRS()	(++wrs)
#	define	RDS()	(++rds)
#	define	UNS()	(++uns)
#	define	WRMEM()	(++wrmem)
#	define	RDMEM()	(++rdmem)
#	define	WBINV()	(++wbinv)
#	define	DISCARD()	(++discard)
#else
#	define	WRS()
#	define	RDS()
#	define	UNS()
#	define	WRMEM()
#	define	RDMEM()
#	define	WBINV()
#	define	DISCARD()
#endif /* !def CONFIG_ZUF_DEBUG */

	cur_e =  iei->iom_e;
	end_e = cur_e + iei->iom_n;
	while (cur_e && (cur_e < end_e)) {
		uint op;

		op = _zufs_iom_opt_type(cur_e);

		switch (op) {
		case IOM_NONE:
			return 0;

		case IOM_T2_WRITE:
			err = iom_add_t2_io(iei->sb, iei->wr_tis, &cur_e);
			WRS();
			break;
		case IOM_T2_READ:
			err = iom_add_t2_io(iei->sb, iei->rd_tis, &cur_e);
			RDS();
			break;

		case IOM_T2_WRITE_LEN:
			err = iom_add_t2_io_len(iei->sb, iei->wr_tis, &cur_e);
			WRS();
			break;
		case IOM_T2_READ_LEN:
			err = iom_add_t2_io_len(iei->sb, iei->rd_tis, &cur_e);
			RDS();
			break;

		case IOM_T2_ZUSMEM_WRITE:
			err = iom_t2_zusmem_io(iei->sb, iei->wr_tis, &cur_e);
			WRMEM();
			break;
		case IOM_T2_ZUSMEM_READ:
			err = iom_t2_zusmem_io(iei->sb, iei->rd_tis, &cur_e);
			RDMEM();
			break;

		case IOM_UNMAP:
			err = iom_unmap(iei->sb, iei->inode, &cur_e);
			UNS();
			break;

		case IOM_WBINV:
			err = iom_wbinv(&cur_e);
			WBINV();
			break;

		case IOM_DISCARD:
			err = iom_discard(iei->sb, iei->wr_tis, &cur_e);
			DISCARD();
			break;

		default:
			zuf_err("!!!!! Bad opt %d\n",
				_zufs_iom_opt_type(cur_e));
			err = -EIO;
			break;
		}

		if (unlikely(err))
			break;
	}

#ifdef CONFIG_ZUF_DEBUG
	zuf_dbg_rw("exec wrs=%d rds=%d uns=%d rdmem=%d wrmem=%d => %d\n",
		   wrs, rds, uns, rdmem, wrmem, err);
#endif

	return err;
}

/* inode here is the default inode if ioc_unmap->ino is zero
 * this is an optimization for the unmap done at write_iter hot path.
 */
int zuf_iom_execute_sync(struct super_block *sb, struct inode *inode,
			 __u64 *iom_e_user, uint iom_n)
{
	struct zuf_sb_info *sbi = SBI(sb);
	struct t2_io_state rd_tis = {};
	struct t2_io_state wr_tis = {};
	struct _iom_exec_info iei = {};
	int err, err_r, err_w;

	t2_io_begin(sbi->md, READ, NULL, 0, -1, &rd_tis);
	t2_io_begin(sbi->md, WRITE, NULL, 0, -1, &wr_tis);

	iei.sb = sb;
	iei.inode = inode;
	iei.rd_tis = &rd_tis;
	iei.wr_tis = &wr_tis;
	iei.iom_e = iom_e_user;
	iei.iom_n = iom_n;
	iei.print = 0;

	err = _iom_execute_inline(&iei);

	err_r = t2_io_end(&rd_tis, true);
	err_w = t2_io_end(&wr_tis, true);

	/* TODO: not sure if OK when _iom_execute return with -ENOMEM
	 * In such a case, we might be better of skiping t2_io_ends.
	 */
	return err ?: (err_r ?: err_w);
}

struct _async_iom_exec {
	struct kref kref;
	struct work_struct work;
	struct t2_io_state rd_tis;
	struct t2_io_state wr_tis;
	struct _iom_exec_info iei;
	struct zus_iomap_done *iomd;
};

void _out_of_bdev_done_thread(struct work_struct *work)
{
	struct _async_iom_exec *aie = container_of(work, typeof(*aie), work);
	struct zuf_sb_info *sbi = SBI(aie->iei.sb);
	struct zufs_ioc_iomap_done ziid = {
		.hdr.operation = ZUFS_OP_IOM_DONE,
		.hdr.in_len = sizeof(ziid),
		.hdr.err = aie->rd_tis.err ?: aie->wr_tis.err,
		.zus_sbi = sbi->zus_sbi,
		.iomd = aie->iomd,
	};
	struct zuf_dispatch_op zdo;
	int err;

	zuf_dbg_t2("0x%lx\n", (ulong)ziid.iomd);

	zuf_dispatch_init(&zdo, &ziid.hdr, NULL, 0);
	zdo.mode = EZDO_M_BACK_CHAN | EZDO_M_NONE_INTR;

	err = __zufc_dispatch(ZUF_ROOT(sbi), &zdo);
	if (unlikely(err))
		zuf_err("__zufc_dispatch => %d\n", err);

	kfree(aie);
}

void _last_async_done(struct kref *kref)
{
	struct _async_iom_exec *aie = container_of(kref, typeof(*aie), kref);

	queue_work(system_unbound_wq, &aie->work);
}

static void iom_exec_async_done(struct t2_io_state *tis, struct bio *bio,
				bool last)
{
	struct _async_iom_exec *aie = tis->priv;

	if (last) {
		kref_put(&aie->kref, _last_async_done);
		return;
	}

	t2_io_done(tis, bio, last);
}

int zuf_iom_execute_async(struct super_block *sb, struct zus_iomap_done *iomd,
			 __u64 *iom_e_user, uint iom_n)
{
	struct zuf_sb_info *sbi = SBI(sb);
	struct _async_iom_exec *aie;
	int err, err_r, err_w;

	aie = kzalloc(sizeof(*aie), GFP_KERNEL);
	if (unlikely(!aie))
		return -ENOMEM;

	aie->iei.sb = sb;
	aie->iei.rd_tis = &aie->rd_tis;
	aie->iei.wr_tis = &aie->wr_tis;
	aie->iomd = iomd;
	aie->iei.iom_e = iom_e_user;
	aie->iei.iom_n = iom_n;
	refcount_set(&aie->kref.refcount, 2);
	INIT_WORK(&aie->work, _out_of_bdev_done_thread);

	t2_io_begin(sbi->md, READ,  iom_exec_async_done, aie, -1, &aie->rd_tis);
	t2_io_begin(sbi->md, WRITE, iom_exec_async_done, aie, -1, &aie->wr_tis);

	err = _iom_execute_inline(&aie->iei);

	err_r = t2_io_end(&aie->rd_tis, false);
	err_w = t2_io_end(&aie->wr_tis, false);

	if (!err)
		err = err_r ? err_r : err_w;
	if (unlikely(err && err != -EIO))
		zuf_warn("iom_execute_async => %d %d %d\n", err, err_r, err_w);

	return err;
}
