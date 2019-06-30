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

#include "backport.h"

enum zlfs_e_special_file {
	zlfs_e_zt = 1,
	zlfs_e_mout_thread,
	zlfs_e_pmem,
	zlfs_e_dpp_buff,
	zlfs_e_private_mount,
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

struct zuf_private_mount_info {
	struct zuf_special_file zsf;
	struct super_block *sb;
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
 * Private Super-block flags
 */
enum {
	ZUF_MOUNT_PEDANTIC	= 0x000001,	/* Check for memory leaks */
	ZUF_MOUNT_PEDANTIC_SHADOW = 0x00002,	/* */
	ZUF_MOUNT_SILENT	= 0x000004,	/* verbosity is silent */
	ZUF_MOUNT_EPHEMERAL	= 0x000008,	/* Don't persist the data */
	ZUF_MOUNT_FAILED	= 0x000010,	/* mark a failed-mount */
	ZUF_MOUNT_DAX		= 0x000020,	/* mounted with dax option */
	ZUF_MOUNT_POSIXACL	= 0x000040,	/* mounted with posix acls */
	ZUF_MOUNT_PRIVATE	= 0x000080,	/* private mount from runner */
};

#define clear_opt(sbi, opt)       (sbi->s_mount_opt &= ~ZUF_MOUNT_ ## opt)
#define set_opt(sbi, opt)         (sbi->s_mount_opt |= ZUF_MOUNT_ ## opt)
#define test_opt(sbi, opt)      (sbi->s_mount_opt & ZUF_MOUNT_ ## opt)

/*
 * ZUF per-inode data in memory
 */
struct zuf_inode_info {
	struct inode		vfs_inode;

	/* Lock for xattr operations */
	struct rw_semaphore	xa_rwsem;
	/* Stuff for mmap write */
	struct rw_semaphore	in_sync;
	struct list_head	i_mmap_dirty;
	atomic_t		write_mapped;
	atomic_t		vma_count;
	struct rw_semaphore	rw_lock;

	/* cookies from Server */
	struct zus_inode	*zi;
	struct zus_inode_info	*zus_ii;
};

static inline struct zuf_inode_info *ZUII(struct inode *inode)
{
	return container_of(inode, struct zuf_inode_info, vfs_inode);
}

/*
 * ZUF super-block data in memory
 */
struct zuf_sb_info {
	struct super_block *sb;
	struct multi_devices *md;

	/* zus cookie*/
	struct zus_sb_info *zus_sbi;

	/* Mount options */
	unsigned long	s_mount_opt;
	char		*pmount_dev; /* for private mount */

	spinlock_t		s_mmap_dirty_lock;
	struct list_head	s_mmap_dirty;
};

static inline struct zuf_sb_info *SBI(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct zuf_fs_type *ZUF_FST(struct file_system_type *fs_type)
{
	return container_of(fs_type, struct zuf_fs_type, vfs_fst);
}

static inline struct zuf_fs_type *zuf_fst(struct super_block *sb)
{
	return ZUF_FST(sb->s_type);
}

static inline struct zuf_root_info *ZUF_ROOT(struct zuf_sb_info *sbi)
{
	return zuf_fst(sbi->sb)->zri;
}

static inline bool zuf_rdonly(struct super_block *sb)
{
	return sb->s_flags & MS_RDONLY;
}

static inline struct zus_inode *zus_zi(struct inode *inode)
{
	return ZUII(inode)->zi;
}

/* An accessor because of the frequent use in prints */
static inline ulong _zi_ino(struct zus_inode *zi)
{
	return le64_to_cpu(zi->i_ino);
}

static inline bool _zi_active(struct zus_inode *zi)
{
	return (zi->i_nlink || zi->i_mode);
}

static inline void mt_to_timespec(struct timespec *t, __le64 *mt)
{
	u32 nsec;

	t->tv_sec = div_s64_rem(le64_to_cpu(*mt), NSEC_PER_SEC, &nsec);
	t->tv_nsec = nsec;
}

static inline void timespec_to_mt(__le64 *mt, struct timespec *t)
{
	*mt = cpu_to_le64(t->tv_sec * NSEC_PER_SEC + t->tv_nsec);
}

static inline void zuf_r_lock(struct zuf_inode_info *zii)
{
	down_read_nested(&zii->rw_lock, 1);
}
static inline void zuf_r_unlock(struct zuf_inode_info *zii)
{
	up_read(&zii->rw_lock);
}

static inline void zuf_smr_lock(struct zuf_inode_info *zii)
{
	down_read_nested(&zii->in_sync, 1);
}
static inline void zuf_smr_lock_pagefault(struct zuf_inode_info *zii)
{
	down_read_nested(&zii->in_sync, 2);
}
static inline void zuf_smr_unlock(struct zuf_inode_info *zii)
{
	up_read(&zii->in_sync);
}

static inline void zuf_smw_lock(struct zuf_inode_info *zii)
{
	down_write(&zii->in_sync);
}
static inline void zuf_smw_lock_nested(struct zuf_inode_info *zii)
{
	down_write_nested(&zii->in_sync, 1);
}
static inline void zuf_smw_unlock(struct zuf_inode_info *zii)
{
	up_write(&zii->in_sync);
}

static inline void zuf_w_lock(struct zuf_inode_info *zii)
{
	down_write(&zii->rw_lock);
	zuf_smw_lock(zii);
}
static inline void zuf_w_lock_nested(struct zuf_inode_info *zii)
{
	down_write_nested(&zii->rw_lock, 2);
	zuf_smw_lock_nested(zii);
}
static inline void zuf_w_unlock(struct zuf_inode_info *zii)
{
	zuf_smw_unlock(zii);
	up_write(&zii->rw_lock);
}

static inline void ZUF_CHECK_I_W_LOCK(struct inode *inode)
{
#ifdef CONFIG_ZUF_DEBUG
	if (WARN_ON(down_write_trylock(&ZUII(inode)->rw_lock)))
		up_write(&ZUII(inode)->rw_lock);
#endif
}

static inline void zuf_xar_lock(struct zuf_inode_info *zii)
{
	down_read(&zii->xa_rwsem);
}

static inline void zuf_xar_unlock(struct zuf_inode_info *zii)
{
	up_read(&zii->xa_rwsem);
}

static inline void zuf_xaw_lock(struct zuf_inode_info *zii)
{
	down_write(&zii->xa_rwsem);
}

static inline void zuf_xaw_unlock(struct zuf_inode_info *zii)
{
	up_write(&zii->xa_rwsem);
}

/* CAREFUL: Needs an sfence eventually, after this call */
static inline
void zus_inode_cmtime_now(struct inode *inode, struct zus_inode *zi)
{
	inode->i_mtime = inode->i_ctime = current_time(inode);
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
	zi->i_mtime = zi->i_ctime;
}

static inline
void zus_inode_ctime_now(struct inode *inode, struct zus_inode *zi)
{
	inode->i_ctime = current_time(inode);
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
}

static inline void *zuf_dpp_t_addr(struct super_block *sb, zu_dpp_t v)
{
	/* TODO: Implement zufs_ioc_create_mempool already */
	if (WARN_ON(zu_dpp_t_pool(v)))
		return NULL;

	return md_addr_verify(SBI(sb)->md, zu_dpp_t_val(v));
}

/* xattr types */
enum {	ZUF_XF_SECURITY    = 1,
	ZUF_XF_SYSTEM      = 2,
	ZUF_XF_TRUSTED     = 3,
	ZUF_XF_USER        = 4,
};

struct zuf_acl {
	__le16	tag;
	__le16	perm;
	__le32	id;
} __packed;

enum big_alloc_type { ba_stack, ba_kmalloc, ba_vmalloc };

static inline
void *big_alloc(uint bytes, uint local_size, void *local, gfp_t gfp,
		enum big_alloc_type *bat)
{
	void *ptr;

	if (bytes <= local_size) {
		*bat = ba_stack;
		ptr = local;
	} else if (bytes <= PAGE_SIZE) {
		*bat = ba_kmalloc;
		ptr = kmalloc(bytes, gfp);
	} else {
		*bat = ba_vmalloc;
		ptr = vmalloc(bytes);
	}

	return ptr;
}

static inline void big_free(void *ptr, enum big_alloc_type bat)
{
	switch (bat) {
	case ba_stack:
		break;
	case ba_kmalloc:
		kfree(ptr);
		break;
	case ba_vmalloc:
		vfree(ptr);
	}
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
