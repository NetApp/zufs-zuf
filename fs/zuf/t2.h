/*
 * Tier-2 Header file.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#ifndef __T2_H__
#define __T2_H__

#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/kref.h>
#include "_pr.h"
#include "md.h"

#define T2_SECTORS_PER_PAGE	(PAGE_SIZE / 512)

#define t2_warn(fmt, args ...) zuf_warn(fmt, ##args)

/* t2.c */

/* Sync read/write */
int t2_writepage(struct md_dev_info *mdi, ulong bn, struct page *page);
int t2_readpage(struct md_dev_info *mdi, ulong bn, struct page *page);

/* Async read/write */
struct t2_io_state;
typedef void (*t2_io_done_fn)(struct t2_io_state *tis, struct bio *bio,
			      bool last);

struct t2_io_state {
	struct kref	kref; /* counts in-flight bios */
	struct blk_plug plug;

	struct md_dev_info	*mdi;
	t2_io_done_fn	done;
	void		*priv;

	uint		n_vects;
	ulong		rw_flags;
	ulong		last_t2;
	struct bio	*cur_bio;
	struct bio_list	delayed_bios;
	int		err;
};

/* For rw_flags above */
/* From Kernel: WRITE		(1U << 0) */
#define TIS_DELAY_SUBMIT	(1U << 2)
enum {B_TIS_FREE_AFTER_WAIT = 3};
#define TIS_FREE_AFTER_WAIT	(1U << B_TIS_FREE_AFTER_WAIT)
#define TIS_USER_DEF_FIRST	(1U << 8)

void t2_io_begin(struct md_dev_info *mdi, int rw, t2_io_done_fn done,
		 void *priv, uint n_vects, struct t2_io_state *tis);
int t2_io_prealloc(struct t2_io_state *tis, uint n_vects);
int t2_io_add(struct t2_io_state *tis, ulong t2, struct page *page);
int t2_io_end(struct t2_io_state *tis, bool wait);

#endif /*def __T2_H__*/
