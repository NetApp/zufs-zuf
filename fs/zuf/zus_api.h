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

#endif /* _LINUX_ZUFS_API_H */
