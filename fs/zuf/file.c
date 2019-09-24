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

#include "zuf.h"

long __zuf_fallocate(struct inode *inode, int mode, loff_t offset, loff_t len)
{
	return -ENOTSUPP;
}

const struct file_operations zuf_file_operations = {
	.open			= generic_file_open,
};

const struct inode_operations zuf_file_inode_operations = {
	.setattr	= zuf_setattr,
	.getattr	= zuf_getattr,
	.update_time	= zuf_update_time,
};
