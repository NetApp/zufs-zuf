/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * zufs_api.h:
 *	ZUFS (Zero-copy User-mode File System) is:
 *		zuf (Zero-copy User-mode Feeder (Kernel)) +
 *		zus (Zero-copy User-mode Server (daemon))
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */
#ifndef _LINUX_ZUFS_API_H
#define _LINUX_ZUFS_API_H

#include <linux/types.h>
#include <linux/uuid.h>
#include <stddef.h>
#include <linux/statfs.h>

#include "md_def.h"

/*
 * Version rules:
 *   This is the zus-to-zuf API version. And not the Filesystem
 * on disk structures versions. These are left to the FS-plugging
 * to supply and check.
 * Specifically any of the API structures and constants found in this
 * file.
 * If the changes are made in a way backward compatible with old
 * user-space, MINOR is incremented. Else MAJOR is incremented.
 *
 * We believe that the zus Server application comes with the
 * Distro and should be dependent on the Kernel package.
 * (In rhel they are both in the same package)
 *
 * The more stable ABI is between the zus Server and its FS plugins.
 */
#define ZUFS_MINORS_PER_MAJOR	1024
#define ZUFS_MAJOR_VERSION 1
#define ZUFS_MINOR_VERSION 0

/* User space compatibility definitions */
#ifndef __KERNEL__

#include <string.h>

#define u8 uint8_t
#define umode_t uint16_t

#define PAGE_SHIFT     12
#define PAGE_SIZE      (1 << PAGE_SHIFT)

#ifndef __packed
#	define __packed __attribute__((packed))
#endif

#ifndef ALIGN
#define ALIGN(x, a)		ALIGN_MASK(x, (typeof(x))(a) - 1)
#define ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#endif

/* RHEL/CentOS7 specifics */
#ifndef FALLOC_FL_UNSHARE_RANGE
#define FALLOC_FL_UNSHARE_RANGE         0x40
#endif

#endif /*  ndef __KERNEL__ */

/* first available error code after include/linux/errno.h */
#define EZUFS_RETRY	531

/* The below is private to zuf Kernel only. Is not exposed to VFS nor zus
 * (defined here to allocate the constant)
 */
#define EZUF_RETRY_DONE 540


/* All device sizes offsets must align on 2M */
#define ZUFS_ALLOC_MASK		(1024 * 1024 * 2 - 1)

/**
 * zufs dual port memory
 * This is a special type of offset to either memory or persistent-memory,
 * that is designed to be used in the interface mechanism between userspace
 * and kernel, and can be accessed by both.
 * 3 first bits denote a mem-pool:
 * 0   - pmem pool
 * 1-6 - established shared pool by a call to zufs_ioc_create_mempool (below)
 * 7   - offset into app memory
 */
typedef __u64 __bitwise zu_dpp_t;

static inline uint zu_dpp_t_pool(zu_dpp_t t)
{
	return t & 0x7;
}

static inline ulong zu_dpp_t_val(zu_dpp_t t)
{
	return t & ~0x7;
}

static inline zu_dpp_t enc_zu_dpp_t(ulong v, uint pool)
{
	return v | pool;
}

/* ~~~~~ ZUFS API ioctl commands ~~~~~ */
enum {
	ZUS_API_MAP_MAX_PAGES	= 1024,
	ZUS_API_MAP_MAX_SIZE	= ZUS_API_MAP_MAX_PAGES * PAGE_SIZE,
};

struct zufs_ioc_hdr {
	__u32 err;	/* IN/OUT must be first */
	__u16 in_len;	/* How much to be copied *to* zus */
	__u16 out_max;	/* Max receive buffer at dispatch caller */
	__u16 out_start;/* Start of output parameters (to caller) */
	__u16 out_len;	/* How much to be copied *from* zus to caller */
			/* can be modified by zus */
	__u32 operation;/* One of e_zufs_operation */
	__u32 offset;	/* Start of user buffer in ZT mmap */
	__u32 len;	/* Len of user buffer in ZT mmap */
};

/* Register FS */
/* A cookie from user-mode given in register_fs_info */
struct zus_fs_info;
struct zufs_ioc_register_fs {
	struct zufs_ioc_hdr hdr;
	struct zus_fs_info *zus_zfi;
	struct register_fs_info {
		/* IN */
		char fsname[16];	/* Only 4 chars and a NUL please      */
		__u32 FS_magic;         /* This is the FS's version && magic  */
		__u32 FS_ver_major;	/* on disk, not the zuf-to-zus version*/
		__u32 FS_ver_minor;	/* (See also struct md_dev_table)   */

		__u8 notused[3];
		__u64 dt_offset;

		__u32 s_time_gran;
		__u32 def_mode;
		__u64 s_maxbytes;

	} rfi;
};
#define ZU_IOC_REGISTER_FS	_IOWR('Z', 10, struct zufs_ioc_register_fs)

/* A cookie from user-mode returned by mount */
struct zus_sb_info;

/* zus cookie per inode */
struct zus_inode_info;

enum ZUFS_M_FLAGS {
	ZUFS_M_PEDANTIC		= 0x00000001,
	ZUFS_M_EPHEMERAL	= 0x00000002,
	ZUFS_M_SILENT		= 0x00000004,
};

struct zufs_parse_options {
	__u32 mount_options_len;
	__u32 pedantic;
	__u64 mount_flags;
	char mount_options[0];
};

enum e_mount_operation {
	ZUFS_M_MOUNT	= 1,
	ZUFS_M_UMOUNT,
	ZUFS_M_REMOUNT,
	ZUFS_M_DDBG_RD,
	ZUFS_M_DDBG_WR,
};

struct zufs_mount_info {
	/* IN */
	struct zus_fs_info *zus_zfi;
	__u16	num_cpu;
	__u16	num_channels;
	__u32	pmem_kern_id;
	__u64	sb_id;

	/* OUT */
	struct zus_sb_info *zus_sbi;
	/* mount is also iget of root */
	struct zus_inode_info *zus_ii;
	zu_dpp_t _zi;
	__u64	old_mount_opt;
	__u64	remount_flags;

	/* More FS specific info */
	__u32 s_blocksize_bits;
	__u8	acl_on;
	struct zufs_parse_options po;
};

/* mount / umount */
struct  zufs_ioc_mount {
	struct zufs_ioc_hdr hdr;
	struct zufs_mount_info zmi;
};
#define ZU_IOC_MOUNT	_IOWR('Z', 11, struct zufs_ioc_mount)

/* pmem  */
struct zufs_ioc_numa_map {
	/* Set by zus */
	struct zufs_ioc_hdr hdr;

	__u32	possible_nodes;
	__u32	possible_cpus;
	__u32	online_nodes;
	__u32	online_cpus;

	__u32	max_cpu_per_node;

	/* This indicates that NOT all nodes have @max_cpu_per_node cpus */
	bool	nodes_not_symmetrical;

	/* Variable size must keep last
	 * size @online_cpus
	 */
	__u8	cpu_to_node[];
};
#define ZU_IOC_NUMA_MAP	_IOWR('Z', 12, struct zufs_ioc_numa_map)

struct zufs_ioc_pmem {
	/* Set by zus */
	struct zufs_ioc_hdr hdr;
	__u32 pmem_kern_id;

	/* Returned to zus */
	struct md_dev_table mdt;

};
/* GRAB is never ungrabed umount or file close cleans it all */
#define ZU_IOC_GRAB_PMEM	_IOWR('Z', 13, struct zufs_ioc_pmem)

/* ZT init */
enum { ZUFS_MAX_ZT_CHANNELS = 64 };

struct zufs_ioc_init {
	struct zufs_ioc_hdr hdr;
	ulong affinity;	/* IN */
	uint channel_no;
	uint max_command;
};
#define ZU_IOC_INIT_THREAD	_IOWR('Z', 14, struct zufs_ioc_init)

/* break_all (Server telling kernel to clean) */
struct zufs_ioc_break_all {
	struct zufs_ioc_hdr hdr;
};
#define ZU_IOC_BREAK_ALL	_IOWR('Z', 15, struct zufs_ioc_break_all)

/* ~~~  zufs_ioc_wait_operation ~~~ */
struct zufs_ioc_wait_operation {
	struct zufs_ioc_hdr hdr;
	/* maximum size is governed by zufs_ioc_init->max_command */
	char opt_buff[];
};
#define ZU_IOC_WAIT_OPT		_IOWR('Z', 16, struct zufs_ioc_wait_operation)

/* These are the possible operations sent from Kernel to the Server in the
 * return of the ZU_IOC_WAIT_OPT.
 */
enum e_zufs_operation {
	ZUFS_OP_NULL = 0,

	ZUFS_OP_BREAK,		/* Kernel telling Server to exit */
	ZUFS_OP_MAX_OPT,
};

/* Allocate a special_file that will be a dual-port communication buffer with
 * user mode.
 * Server will access the buffer via the mmap of this file.
 * Kernel will access the file via the valloc() pointer
 *
 * Some IOCTLs below demand use of this kind of buffer for communication
 * TODO:
 * pool_no is if we want to associate this buffer onto the 6 possible
 * mem-pools per zuf_sbi. So anywhere we have a zu_dpp_t it will mean
 * access from this pool.
 * If pool_no is zero then it is private to only this file. In this case
 * sb_id && zus_sbi are ignored / not needed.
 */
struct zufs_ioc_alloc_buffer {
	struct zufs_ioc_hdr hdr;
	/* The ID of the super block received in mount */
	__u64	sb_id;
	/* We verify the sb_id validity against zus_sbi */
	struct zus_sb_info *zus_sbi;
	/* max size of buffer allowed (size of mmap) */
	__u32 max_size;
	/* allocate this much on initial call and set into vma */
	__u32 init_size;

	/* TODO: These below are now set to ZERO. Need implementation */
	__u16 pool_no;
	__u16 flags;
	__u32 reserved;
};
#define ZU_IOC_ALLOC_BUFFER	_IOWR('Z', 17, struct zufs_ioc_init)

#endif /* _LINUX_ZUFS_API_H */
