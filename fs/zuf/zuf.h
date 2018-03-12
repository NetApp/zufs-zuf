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
#include <linux/mm.h>

#include "zus_api.h"

#include "relay.h"
#include "_pr.h"
#include "md.h"
#include "t2.h"

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

/* Our special md structure */
struct zuf_pmem {
	struct multi_devices md; /* must be first */
	struct list_head list;
	struct zuf_special_file hdr;
	uint pmem_id;
};

/* This is the zuf-root.c mini filesystem */
struct zuf_root_info {
	struct __mount_thread_info {
		struct zuf_special_file zsf;
		spinlock_t lock;
		struct relay relay;
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

static inline void zuf_add_pmem(struct zuf_root_info *zri,
				   struct multi_devices *md)
{
	struct zuf_pmem *z_pmem = (void *)md;

	z_pmem->pmem_id = ++zri->next_pmem_id; /* Avoid 0 id */

	/* Unlocked for now only one mount-thread with zus */
	INIT_LIST_HEAD(&z_pmem->list);
	list_add(&z_pmem->list, &zri->pmem_list);
}

static inline void zuf_rm_pmem(struct multi_devices *md)
{
	struct zuf_pmem *z_pmem = (void *)md;

	if (z_pmem->pmem_id) /* We avoided 0 id */
		list_del_init(&z_pmem->list);
}

static inline uint zuf_pmem_id(struct multi_devices *md)
{
	struct zuf_pmem *z_pmem = container_of(md, struct zuf_pmem, md);

	return z_pmem->pmem_id;
}

// void zuf_del_fs_type(struct zuf_root_info *zri, struct zuf_fs_type *zft);

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

static inline struct zuf_fs_type *ZUF_FST(struct file_system_type *fs_type)
{
	return container_of(fs_type, struct zuf_fs_type, vfs_fst);
}

static inline struct zuf_fs_type *zuf_fst(struct super_block *sb)
{
	return ZUF_FST(sb->s_type);
}

struct zuf_dispatch_op;
typedef int (*overflow_handler)(struct zuf_dispatch_op *zdo, void *parg,
				ulong zt_max_bytes);
struct zuf_dispatch_op {
	struct zufs_ioc_hdr *hdr;
	struct page **pages;
	uint nump;
	overflow_handler oh;
	struct super_block *sb;
	struct inode *inode;
};

static inline void
zuf_dispatch_init(struct zuf_dispatch_op *zdo, struct zufs_ioc_hdr *hdr,
		 struct page **pages, uint nump)
{
	memset(zdo, 0, sizeof(*zdo));
	zdo->hdr = hdr;
	zdo->pages = pages; zdo->nump = nump;
}

static inline int zuf_flt_to_err(vm_fault_t flt)
{
	if (likely(flt == VM_FAULT_NOPAGE))
		return 0;

	if (flt == VM_FAULT_OOM)
		return -ENOMEM;

	return -EACCES;
}

/* Keep this include last thing in file */
#include "_extern.h"

#endif /* __ZUF_H */
