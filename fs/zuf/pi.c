// SPDX-License-Identifier: GPL-2.0
/*
 * pi.c - Page Index facility per inode
 *
 * We can cache block-numbers that were already fetched from
 * Server in a Kernel xarray. So reads may never go to user-mode
 * after the first fetch.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include "zuf.h"

void zuf_pi_unmap(struct inode *inode, loff_t holebegin, loff_t holelen,
		  int flags)
{
	unmap_mapping_range(inode->i_mapping, holebegin, holelen,
			    flags & EZUF_PIU_EVEN_COWS);
}
