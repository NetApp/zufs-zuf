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

#endif /* _LINUX_ZUFS_API_H */
