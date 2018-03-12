// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Ioctl operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/delay.h>
#include <linux/pfn_t.h>
#include <linux/sched/signal.h>

#include "zuf.h"

int zufc_zts_init(struct zuf_root_info *zri)
{
	return 0;
}

void zufc_zts_fini(struct zuf_root_info *zri)
{
}

long zufc_ioctl(struct file *file, unsigned int cmd, ulong arg)
{
	switch (cmd) {
	default:
		zuf_err("%d\n", cmd);
		return -ENOTTY;
	}
}

int zufc_release(struct inode *inode, struct file *file)
{
	struct zuf_special_file *zsf = file->private_data;

	if (!zsf)
		return 0;

	switch (zsf->type) {
	default:
		return 0;
	}
}

int zufc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zuf_special_file *zsf = file->private_data;

	if (unlikely(!zsf)) {
		zuf_err("Which mmap is that !!!!\n");
		return -ENOTTY;
	}

	switch (zsf->type) {
	default:
		zuf_err("type=%d\n", zsf->type);
		return -ENOTTY;
	}
}
