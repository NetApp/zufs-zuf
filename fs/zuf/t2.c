/*
 * Tier-2 operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include "t2.h"

#include <linux/bitops.h>
#include <linux/bio.h>

#include "zuf.h"

#define t2_dbg(fmt, args ...) zuf_dbg_t2(fmt, ##args)

const char *_pr_rw(int rw)
{
	return (rw & WRITE) ? "WRITE" : "READ";
}
#define t2_tis_dbg(tis, fmt, args ...) \
	zuf_dbg_t2("%s: r=%d f=0x%lx " fmt, _pr_rw(tis->rw_flags),	       \
		    atomic_read(&tis->kref.refcount), tis->rw_flags, ##args)

#define t2_tis_dbg_rw(tis, fmt, args ...) \
	zuf_dbg_t2_rw("%s<%p>: r=%d f=0x%lx " fmt, _pr_rw(tis->rw_flags),     \
		    tis->priv, atomic_read(&tis->kref.refcount), tis->rw_flags,\
		    ##args)

/* ~~~~~~~~~~~~ Async read/write ~~~~~~~~~~ */
void t2_io_begin(struct md_dev_info *mdi, int rw, t2_io_done_fn done, void *priv,
		 uint n_vects, struct t2_io_state *tis)
{
	kref_init(&tis->kref);
	tis->mdi = mdi;
	tis->done = done;
	tis->priv = priv;
	tis->n_vects = min(n_vects ? n_vects : 1, (uint)BIO_MAX_PAGES);
	tis->rw_flags = rw;
	tis->last_t2 = -1;
	tis->cur_bio = NULL;
	bio_list_init(&tis->delayed_bios);
	tis->err = 0;
	blk_start_plug(&tis->plug);
	t2_tis_dbg_rw(tis, "done=%pF n_vects=%d\n", done, n_vects);
}

/*
 * wait_on_atomic_t() do nothing @action function.
 * (TODO: Do I need to check for TASK_INTERRUPTIBLE events myself)
 */
static int _tis_wait_atomic_t(atomic_t *p)
{
	schedule();
	return 0;
}

static void _tis_put(struct kref *kref)
{
	struct t2_io_state *tis = container_of(kref, typeof(*tis), kref);

	t2_tis_dbg_rw(tis, "done=%pF\n", tis->done);

	if (test_bit(B_TIS_FREE_AFTER_WAIT, &tis->rw_flags))
		wake_up_atomic_t(&kref->refcount);
	else if (tis->done)
		/* last - done may free the tis */
		tis->done(tis, NULL, true);
}

static inline bool _err_set_reported(struct md_dev_info *mdi, bool write)
{
	bool *reported = write ? &mdi->t2i.err_write_reported :
				 &mdi->t2i.err_read_reported;

	if (!(*reported)) {
		*reported = true;
		return true;
	}
	return false;
}

static void _tis_bio_done(struct bio *bio)
{
	struct t2_io_state *tis = bio->bi_private;

	t2_tis_dbg(tis, "done=%pF err=%d\n", tis->done, bio->bi_error);

	if (unlikely(bio->bi_error)) {
		zuf_dbg_err("%s: err=%d last-err=%d\n",
			     _pr_rw(tis->rw_flags), bio->bi_error, tis->err);
		if (_err_set_reported(tis->mdi, 0 != (tis->rw_flags & WRITE)))
			zuf_err("%s: err=%d\n",
				 _pr_rw(tis->rw_flags), bio->bi_error);
		tis->err = bio->bi_error; /* Store the last one */
	} else if(unlikely(tis->mdi->t2i.err_write_reported ||
		           tis->mdi->t2i.err_read_reported)) {
		if (tis->rw_flags & WRITE)
			tis->mdi->t2i.err_write_reported = false;
		else
			tis->mdi->t2i.err_read_reported = false;
	}

	if (tis->done) {
		tis->done(tis, bio, false);
	}

	bio_put(bio);
	kref_put(&tis->kref, _tis_put);
}

static bool _tis_delay(struct t2_io_state *tis)
{
	return 0 != (tis->rw_flags & TIS_DELAY_SUBMIT);
}

#define bio_list_for_each_safe(bio, btmp, bl)				\
	for (bio = (bl)->head,	btmp = bio ? bio->bi_next : NULL;	\
	     bio; bio = btmp,	btmp = bio ? bio->bi_next : NULL)

static void _tis_submit_bio(struct t2_io_state *tis, bool flush, bool done)
{
	if (flush || done) {
		if (_tis_delay(tis)) {
			struct bio *btmp, *bio;

			bio_list_for_each_safe(bio, btmp, &tis->delayed_bios) {
				bio->bi_next = NULL;
				if (bio->bi_iter.bi_sector == -1) {
					t2_warn("!!!!!!!!!!!!!\n");
					bio_put(bio);
					continue;
				}
				t2_tis_dbg(tis, "submit bio[%d] max_v=%d\n",
					    bio->bi_vcnt, tis->n_vects);
				submit_bio(bio);
			}
			bio_list_init(&tis->delayed_bios);
		}

		if (!tis->cur_bio)
			return;

		if (tis->cur_bio->bi_iter.bi_sector != -1) {
			t2_tis_dbg(tis, "submit bio[%d] max_v=%d\n",
				    tis->cur_bio->bi_vcnt, tis->n_vects);
			submit_bio(tis->cur_bio);
			tis->cur_bio = NULL;
		} else if (done) {
			t2_tis_dbg(tis, "put cur_bio=%p\n", tis->cur_bio);
			bio_put(tis->cur_bio);
			WARN_ON(kref_put(&tis->kref, _tis_put));
		}
	} else if (tis->cur_bio && (tis->cur_bio->bi_iter.bi_sector != -1)) {
		/* Not flushing regular progress */
		if (_tis_delay(tis)) {
			t2_tis_dbg(tis, "list_add cur_bio=%p\n", tis->cur_bio);
			bio_list_add(&tis->delayed_bios, tis->cur_bio);
		} else {
			t2_tis_dbg(tis, "submit bio[%d] max_v=%d\n",
				    tis->cur_bio->bi_vcnt, tis->n_vects);
			submit_bio(tis->cur_bio);
		}
		tis->cur_bio = NULL;
	}
}

/* tis->cur_bio MUST be NULL, checked by caller */
static void _tis_alloc(struct t2_io_state *tis, gfp_t gfp)
{
	struct bio *bio = bio_alloc(gfp, tis->n_vects);
	int bio_op;

	if (unlikely(!bio)) {
		if (!_tis_delay(tis))
			t2_warn("!!! failed to alloc bio");
		tis->err = -ENOMEM;
		return;
	}

	if (WARN_ON(!tis || !tis->mdi)) {
		tis->err = -ENOMEM;
		return;
	}

	/* FIXME: bio_set_op_attrs macro has a BUG which does not allow this
	 * question inline.
	 */
	bio_op = (tis->rw_flags & WRITE) ? REQ_OP_WRITE : REQ_OP_READ;
	bio_set_op_attrs(bio, bio_op, 0);

	bio->bi_bdev = tis->mdi->bdev;
	bio->bi_iter.bi_sector = -1;
	bio->bi_end_io = _tis_bio_done;
	bio->bi_private = tis;

	tis->last_t2 = -1;
	tis->cur_bio = bio;
	kref_get(&tis->kref);
	t2_tis_dbg(tis, "New bio n_vects=%d\n", tis->n_vects);
}

int t2_io_prealloc(struct t2_io_state *tis, uint n_vects)
{
	tis->err = 0; /* reset any -ENOMEM from a previous t2_io_add */

	_tis_submit_bio(tis, true, false);
	tis->n_vects = min(n_vects ? n_vects : 1, (uint)BIO_MAX_PAGES);

	t2_tis_dbg(tis, "n_vects=%d cur_bio=%p\n", tis->n_vects, tis->cur_bio);

	if (!tis->cur_bio)
		_tis_alloc(tis, GFP_NOFS);
	return tis->err;
}

int t2_io_add(struct t2_io_state *tis, ulong t2, struct page *page)
{
	int ret;

	if ((t2 != (tis->last_t2 + 1)) && (tis->last_t2 != -1))
		_tis_submit_bio(tis, false, false);

start:
	if (!tis->cur_bio) {
		_tis_alloc(tis, _tis_delay(tis) ? GFP_ATOMIC : GFP_NOFS);
		if (unlikely(tis->err))
			return tis->err;
	}

	if (tis->last_t2 == -1)
		tis->cur_bio->bi_iter.bi_sector = t2 * T2_SECTORS_PER_PAGE;

	ret = bio_add_page(tis->cur_bio, page, PAGE_SIZE, 0);
	if (unlikely(ret != PAGE_SIZE)) {
		t2_tis_dbg(tis, "bio_add_page=>%d bi_vcnt=%d n_vects=%d\n",
			   ret, tis->cur_bio->bi_vcnt, tis->n_vects);
		_tis_submit_bio(tis, false, false);
		goto start; /* device does not support tis->n_vects */
	}

	if((tis->cur_bio->bi_vcnt == tis->n_vects) && (tis->n_vects != 1))
		_tis_submit_bio(tis, false, false);

	t2_tis_dbg(tis, "t2=0x%lx last_t2=0x%lx page-i=0x%lx\n",
		   t2, tis->last_t2, page->index);

	tis->last_t2 = t2;
	return 0;
}

int t2_io_end(struct t2_io_state *tis, bool wait)
{
	int err = 0;

	if (unlikely(!tis || !tis->mdi))
		return 0; /* never initialized nothing to do */

	t2_tis_dbg_rw(tis, "wait=%d\n", wait);

	_tis_submit_bio(tis, true, true);
	blk_finish_plug(&tis->plug);

	if (wait)
		set_bit(B_TIS_FREE_AFTER_WAIT, &tis->rw_flags);
	kref_put(&tis->kref, _tis_put);

	if (wait) {
		err = wait_on_atomic_t(&tis->kref.refcount, _tis_wait_atomic_t,
					TASK_INTERRUPTIBLE);
		if (likely(!err))
			err = tis->err;
		if (tis->done)
			tis->done(tis, NULL, true);
	}

	/* In case of a ctrl-c we return an err but tis->err == 0 */
	return err;
}

/* ~~~~~~~ Sync read/write ~~~~~~~ TODO: Remove soon */
static int _sync_io_page(struct md_dev_info *mdi, int rw, ulong bn,
			 struct page *page)
{
	struct t2_io_state tis;
	int err;

	t2_io_begin(mdi, rw, NULL, NULL, 1, &tis);

	t2_tis_dbg((&tis), "bn=0x%lx p-i=0x%lx\n", bn, page->index);

	err = t2_io_add(&tis, bn, page);
	if (unlikely(err))
		return err;

	err = submit_bio_wait(tis.cur_bio);
	if (unlikely(err)) {
		SetPageError(page);
		/*
		 * We failed to write the page out to tier-2.
		 * Print a dire warning that things will go BAD (tm)
		 * very quickly.
		 */
		zuf_err("io-error bn=0x%lx => %d\n", bn, err);
	}

	/* Same as t2_io_end+_tis_bio_done but without the kref stuff */
	blk_finish_plug(&tis.plug);
	if (likely(tis.cur_bio))
		bio_put(tis.cur_bio);

	return err;
}

int t2_writepage(struct md_dev_info *mdi, ulong bn, struct page *page)
{
	return _sync_io_page(mdi, WRITE, bn, page);
}

int t2_readpage(struct md_dev_info *mdi, ulong bn, struct page *page)
{
	return _sync_io_page(mdi, READ, bn, page);
}
