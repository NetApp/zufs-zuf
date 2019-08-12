/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note or BSD-3-Clause */
/*
 * zufs_api.h:
 *	ZUFS (Zero-copy User-mode File System) is:
 *		zuf (Zero-copy User-mode Feeder (Kernel)) +
 *		zus (Zero-copy User-mode Server (daemon))
 *
 *	This file defines the API between the open source FS
 *	Server, and the Kernel module,
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
#include <linux/fiemap.h>
#include <stddef.h>

#ifdef __cplusplus
#define NAMELESS(X) X
#else
#define NAMELESS(X)
#endif

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
 * It is up to the Server to decides if it wants to run with this
 * Kernel or not. Version is only passively reported.
 */
#define ZUFS_MINORS_PER_MAJOR	1024
#define ZUFS_MAJOR_VERSION 1
#define ZUFS_MINOR_VERSION 0

/* Kernel versus User space compatibility definitions */
#ifdef __KERNEL__

#include <linux/statfs.h>

#else /* ! __KERNEL__ */

/* verify statfs64 definition is included */
#if !defined(__USE_LARGEFILE64) && defined(_SYS_STATFS_H)
#error "include to 'sys/statfs.h' must appear after 'zus_api.h'"
#else
#define __USE_LARGEFILE64 1
#endif

#include <sys/statfs.h>

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

#ifndef likely
#define likely(x_)	__builtin_expect(!!(x_), 1)
#define unlikely(x_)	__builtin_expect(!!(x_), 0)
#endif

#ifndef BIT
#define BIT(b)  (1UL << (b))
#endif

/* RHEL/CentOS7 are missing these */
#ifndef FALLOC_FL_UNSHARE_RANGE
#define FALLOC_FL_UNSHARE_RANGE         0x40
#endif
#ifndef FALLOC_FL_INSERT_RANGE
#define FALLOC_FL_INSERT_RANGE		0x20
#endif

#endif /*  ndef __KERNEL__ */

struct zufs_ioc_hdr {
	__s32 err;	/* IN/OUT must be first */
	__u16 in_len;	/* How much to be copied *to* zus */
	__u16 out_max;	/* Max receive buffer at dispatch caller */
	__u16 out_start;/* Start of output parameters (to caller) */
	__u16 out_len;	/* How much to be copied *from* zus to caller */
			/* can be modified by zus */
	__u16 operation;/* One of e_zufs_operation */
	__u16 flags;	/* e_zufs_hdr_flags bit flags */
	__u32 offset;	/* Start of user buffer in ZT mmap */
	__u32 len;	/* Len of user buffer in ZT mmap */
};

struct register_fs_info {
	char fsname[16];	/* Only 4 chars and a NUL please      */
	__u32 FS_magic;         /* This is the FS's version && magic  */
	__u32 FS_ver_major;	/* on disk, not the zuf-to-zus version*/
	__u32 FS_ver_minor;	/* (See also struct md_dev_table)   */
	__u32 notused;

	__u64 dt_offset;
	__u64 s_maxbytes;
	__u32 s_time_gran;
	__u32 def_mode;
};

/* Register FS */
/* A cookie from user-mode given in register_fs_info */
struct zus_fs_info;
struct zufs_ioc_register_fs {
	struct zufs_ioc_hdr hdr;
	struct zus_fs_info *zus_zfi;
	struct register_fs_info rfi;
};
#define ZU_IOC_REGISTER_FS	_IOWR('Z', 10, struct zufs_ioc_register_fs)

#endif /* _LINUX_ZUFS_API_H */
