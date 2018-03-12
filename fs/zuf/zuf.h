/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BRIEF DESCRIPTION
 *
 * Definitions for the ZUF filesystem.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#ifndef __ZUF_H
#define __ZUF_H

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/page_ref.h>

#include "zus_api.h"

#include "_pr.h"

enum zlfs_e_special_file {
	zlfs_e_zt = 1,
	zlfs_e_mout_thread,
	zlfs_e_pmem,
	zlfs_e_dpp_buff,
};

struct zuf_special_file {
	enum zlfs_e_special_file type;
	struct file *file;
};

/* This is the zuf-root.c mini filesystem */
struct zuf_root_info {
	struct __mount_thread_info {
		struct zuf_special_file zsf;
		struct zufs_ioc_mount *zim;
	} mount;

	#define SBL_INC 64
	struct sb_is_list {
		uint num;
		uint max;
		struct super_block **array;
	} sbl;
	struct mutex sbl_lock;

	ulong next_ino;

	struct zuf_threads_pool *_ztp;

	struct super_block *sb;
	struct list_head fst_list;

	uint next_pmem_id;
	struct list_head pmem_list;
};

static inline struct zuf_root_info *ZRI(struct super_block *sb)
{
	struct zuf_root_info *zri = sb->s_fs_info;

	WARN_ON(zri->sb != sb);
	return zri;
}

struct zuf_fs_type {
	struct file_system_type vfs_fst;
	struct zus_fs_info	*zus_zfi;
	struct register_fs_info rfi;
	struct zuf_root_info *zri;

	struct list_head list;
};

static inline void zuf_add_fs_type(struct zuf_root_info *zri,
				   struct zuf_fs_type *zft)
{
	/* Unlocked for now only one mount-thread with zus */
	list_add(&zft->list, &zri->fst_list);
}

/*
 * ZUF per-inode data in memory
 */
struct zuf_inode_info {
	struct inode		vfs_inode;
};

static inline struct zuf_inode_info *ZUII(struct inode *inode)
{
	return container_of(inode, struct zuf_inode_info, vfs_inode);
}

/* Keep this include last thing in file */
#include "_extern.h"

#endif /* __ZUF_H */
