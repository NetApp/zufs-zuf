// SPDX-License-Identifier: GPL-2.0
/*
 * Super block operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>
 */

#include <linux/types.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/backing-dev.h>

#include "zuf.h"

static struct kmem_cache *zuf_inode_cachep;

struct super_block *zuf_sb_from_id(struct zuf_root_info *zri, __u64 sb_id,
				   struct zus_sb_info *zus_sbi)
{
	return NULL;
}

static void _init_once(void *foo)
{
	struct zuf_inode_info *zii = foo;

	inode_init_once(&zii->vfs_inode);
}

int __init zuf_init_inodecache(void)
{
	zuf_inode_cachep = kmem_cache_create("zuf_inode_cache",
					       sizeof(struct zuf_inode_info),
					       0,
					       (SLAB_RECLAIM_ACCOUNT |
						SLAB_MEM_SPREAD |
						SLAB_TYPESAFE_BY_RCU),
					       _init_once);
	if (zuf_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void zuf_destroy_inodecache(void)
{
	kmem_cache_destroy(zuf_inode_cachep);
}

struct dentry *zuf_mount(struct file_system_type *fs_type, int flags,
			 const char *dev_name, void *data)
{
	return ERR_PTR(-ENOTSUPP);
}
