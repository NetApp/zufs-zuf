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

#include "zuf.h"
#include "t2.h"

/* ZERO a part of a single block. len does not cross a block boundary */
int zuf_trim_edge(struct inode *inode, ulong filepos, uint len)
{
	return -EIO;
}
