/*
 * BRIEF DESCRIPTION
 *
 * Definitions for the ZUF filesystem.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#ifndef __ZUF_H
#define __ZUF_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/page_ref.h>
#include <linux/pmem.h>

#include "zus_api.h"

#include "relay.h"
#include "atomic.h"
#include "t2.h"
#include "_pr.h"
#include "md.h"

enum zlfs_e_special_file {
	zlfs_e_zt = 1,
	zlfs_e_mout_thread,
	zlfs_e_pmem,
};

struct zuf_special_file {
	enum zlfs_e_special_file type;
};

/* Our special md structure */
struct zuf_pmem {
	struct multi_devices md; /* must be first */
	struct list_head list;
	struct zuf_special_file hdr;
	uint pmem_id;
	struct file *file;
};

/* This is the zuf-root.c mini filesystem */
struct zuf_root_info {
	struct __mount_thread_info {
		struct zuf_special_file zsf;
		spinlock_t lock;
		struct relay relay;
		struct zufs_ioc_mount *zim;
		struct file *file;
	} mount;

	ulong next_ino;

	int _max_zts;
	struct zufs_thread *_all_zt;

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
	list_add(&z_pmem->list, &zri->pmem_list);
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
	ZUF_MOUNT_EPHEMERAL	= 0x000008,	/* treat this mount as ephemeral */
	ZUF_MOUNT_FAILED	= 0x000010,	/* mark a failed-mount */
	ZUF_MOUNT_DAX		= 0x000020,	/* mounted with dax option */
	ZUF_MOUNT_POSIXACL	= 0x000040,	/* mounted with posix acls */
};

#define clear_opt(sbi, opt)       (sbi->s_mount_opt &= ~ZUF_MOUNT_ ## opt)
#define set_opt(sbi, opt)         (sbi->s_mount_opt |= ZUF_MOUNT_ ## opt)
#define test_opt(sbi, opt)      (sbi->s_mount_opt & ZUF_MOUNT_ ## opt)

#define ZUFS_DEF_SBI_MODE (S_IRUGO | S_IXUGO | S_IWUSR)

/* Flags bits on zii->flags */
enum {
	ZII_UNMAP_LOCK	= 1,
};

/*
 * ZUF per-inode data in memory
 */
struct zuf_inode_info {
	struct inode		vfs_inode;
	struct list_head	i_mmap_dirty;
	struct inode		*map_list_head;
	struct zus_inode	*zi;
	struct zus_inode_info	*zus_ii;
	struct page		*zero_page;
	struct rw_semaphore	in_sync;
	atomic_t		mapped;
	atomic_t		vma_count;
	atomic_t		write_mapped;
	ulong			flags;
};

static inline struct zuf_inode_info *ZUII(struct inode *inode)
{
	return container_of(inode, struct zuf_inode_info, vfs_inode);
}

/*
 * ZUF super-block data in memory
 */
struct zuf_sb_info {
	struct backing_dev_info bdi;
	struct super_block *sb;
	struct multi_devices *md;

	/* zus cookie*/
	struct zus_sb_info *zus_sbi;

	/* Mount options */
	unsigned long	s_mount_opt;
	kuid_t		uid;    /* Mount uid for root directory */
	kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */

	spinlock_t		s_mmap_dirty_lock;
	struct list_head	s_mmap_dirty;
};

static inline struct zuf_sb_info *SBI(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct zuf_fs_type *zuf_fst(struct super_block *sb)
{
	struct zuf_fs_type *fst = container_of(sb->s_type,
						 struct zuf_fs_type, vfs_fst);

	return fst;
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

static inline bool uuid_equal(uuid_le *uuid1, uuid_le *uuid2)
{
	return (memcmp(uuid1, uuid2, sizeof(uuid_le)) == 0);
}

static inline void zuf_r_lock(struct zuf_inode_info *zii)
{
	inode_lock_shared(&zii->vfs_inode);
}
static inline void zuf_r_unlock(struct zuf_inode_info *zii)
{
	inode_unlock_shared(&zii->vfs_inode);
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
	inode_lock(&zii->vfs_inode);
	zuf_smw_lock(zii);
}
static inline void zuf_w_lock_nested(struct zuf_inode_info *zii)
{
	inode_lock_nested(&zii->vfs_inode, 2);
	zuf_smw_lock_nested(zii);
}
static inline void zuf_w_unlock(struct zuf_inode_info *zii)
{
	zuf_smw_unlock(zii);
	inode_unlock(&zii->vfs_inode);
}

static inline void ZUF_CHECK_I_W_LOCK (struct inode *inode)
{
#ifdef CONFIG_ZUF_DEBUG
	if (WARN_ON(down_write_trylock(&inode->i_rwsem)))
		up_write(&inode->i_rwsem);
#endif
}

/* CAREFUL: Needs an sfence eventually, after this call */
static inline
void zus_inode_cmtime_now(struct inode *inode, struct zus_inode *zi)
{
	inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
	zi->i_mtime = zi->i_ctime;
}

static inline void __tozu_persist_md(struct super_block *sb, void *addr,
				     uint len)
{
	if (test_opt(SBI(sb), EPHEMERAL))
		return;

	cl_flush(addr, len);
}

#define tozu_persist_md __tozu_persist_md

enum E_ZI_FLUSH {
	ZIFL_LO = 1,
	ZIFL_HI = 2,
	ZIFL_ALL = 3,

	ZIFL_SIZE = ZIFL_LO,
	ZIFL_LINK = ZIFL_LO,
	ZIFL_CMTIME = ZIFL_LO,
	ZIFL_XATTR = ZIFL_LO,

	ZIFL_ATIME = ZIFL_HI,
	ZIFL_GENERATION = ZIFL_HI,
	ZIFL_TRUNCATE = ZIFL_HI,
};

static inline
void tozu_flush_zi(struct super_block *sb, struct zus_inode *zi,
		   enum E_ZI_FLUSH what)
{
	void *start = zi;
	uint len = (what == ZIFL_ALL) ? 2 * CACHELINE_SIZE : CACHELINE_SIZE;

	if (what == ZIFL_HI)
		start += CACHELINE_SIZE;

	tozu_persist_md(sb, start, len);
}

/* Keep this include last thing in file */
#include "_extern.h"

#endif /* __ZUF_H */
