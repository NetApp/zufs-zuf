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

#include "zuf.h"

struct inode *zuf_iget(struct super_block *sb, struct zus_inode_info *zus_ii,
		       zu_dpp_t _zi, bool *exist)
{
	return ERR_PTR(-ENOTSUPP);
}

