/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note or BSD-3-Clause */
/*
 * Multi-Device operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */
#ifndef _LINUX_MD_DEF_H
#define _LINUX_MD_DEF_H

#include <linux/types.h>
#include <linux/uuid.h>

#ifndef __KERNEL__

#include <stdint.h>
#include <endian.h>
#include <stdbool.h>
#include <stdlib.h>

#ifndef le16_to_cpu

#define le16_to_cpu(x)	((__u16)le16toh(x))
#define le32_to_cpu(x)	((__u32)le32toh(x))
#define le64_to_cpu(x)	((__u64)le64toh(x))
#define cpu_to_le16(x)	((__le16)htole16(x))
#define cpu_to_le32(x)	((__le32)htole32(x))
#define cpu_to_le64(x)	((__le64)htole64(x))

#endif

#ifndef __aligned
#define	__aligned(x)			__attribute__((aligned(x)))
#endif

#endif /*  ndef __KERNEL__ */

#define MDT_SIZE 4096

#define MD_DEV_NUMA_SHIFT		60
#define MD_DEV_BLOCKS_MASK		0x0FFFFFFFFFFFFFFF

struct md_dev_id {
	uuid_le	uuid;
	__le64	blocks;
} __aligned(8);

static inline __u64 __dev_id_blocks(struct md_dev_id *dev)
{
	return le64_to_cpu(dev->blocks) & MD_DEV_BLOCKS_MASK;
}

static inline void __dev_id_blocks_set(struct md_dev_id *dev, __u64 blocks)
{
	dev->blocks &= ~MD_DEV_BLOCKS_MASK;
	dev->blocks |= blocks;
}

static inline int __dev_id_nid(struct md_dev_id *dev)
{
	return (int)(le64_to_cpu(dev->blocks) >> MD_DEV_NUMA_SHIFT);
}

static inline void __dev_id_nid_set(struct md_dev_id *dev, int nid)
{
	dev->blocks &= MD_DEV_BLOCKS_MASK;
	dev->blocks |= (__le64)nid << MD_DEV_NUMA_SHIFT;
}

/* 64 is the nicest number to still fit when the ZDT is 2048 and 6 bits can
 * fit in page struct for address to block translation.
 */
#define MD_DEV_MAX   64

struct md_dev_list {
	__le16		   id_index;	/* index of current dev in list */
	__le16		   t1_count;	/* # of t1 devs */
	__le16		   t2_count;	/* # of t2 devs (after t1_count) */
	__le16		   rmem_count;	/* align to 64 bit */
	struct md_dev_id dev_ids[MD_DEV_MAX];
} __aligned(64);

/*
 * Structure of the on disk multy device table
 * NOTE: md_dev_table is always of size MDT_SIZE. These below are the
 *   currently defined/used members in this version.
 *   TODO: remove the s_ from all the fields
 */
struct md_dev_table {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below
	 */
	__le16		s_sum;              /* checksum of this sb */
	__le16		s_version;          /* zdt-version */
	__le32		s_magic;            /* magic signature */
	uuid_le		s_uuid;		    /* 128-bit uuid */
	__le64		s_flags;
	__le64		s_t1_blocks;
	__le64		s_t2_blocks;

	struct md_dev_list s_dev_list;

	char		s_start_dynamic[0];

	/* all the dynamic fields should go here */
	__le64		s_mtime;		/* mount time */
	__le64		s_wtime;		/* write time */
};

/* device table s_flags */
enum enum_mdt_flags {
	MDT_F_SHADOW		= (1UL << 0),	/* simulate cpu cache */
	MDT_F_POSIXACL		= (1UL << 1),	/* enable acls */

	MDT_F_USER_START	= 8,	/* first 8 bit reserved for mdt */
};

static inline bool mdt_test_option(struct md_dev_table *mdt,
				   enum enum_mdt_flags flag)
{
	return (mdt->s_flags & flag) != 0;
}

#define MD_MINORS_PER_MAJOR	1024

static inline int mdt_major_version(struct md_dev_table *mdt)
{
	return le16_to_cpu(mdt->s_version) / MD_MINORS_PER_MAJOR;
}

static inline int mdt_minor_version(struct md_dev_table *mdt)
{
	return le16_to_cpu(mdt->s_version) % MD_MINORS_PER_MAJOR;
}

#define MDT_STATIC_SIZE(mdt) ((__u64)&mdt->s_start_dynamic - (__u64)mdt)

#endif /* _LINUX_MD_DEF_H */
