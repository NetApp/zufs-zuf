/*
 * Multi-device Header file.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#ifndef __MD_H__
#define __MD_H__

#include <linux/crc16.h>
#include <linux/fs.h>

#include "zus_api.h"

#define test_zdt_opt(zdt, opt)	(le64_to_cpu(zdt->s_flags) & opt)
#define clear_zdt_opt(zdt, opt)	(zdt->s_flags &= ~cpu_to_le64(opt))

struct md_t1_info {
	ulong phys_pfn;
	void *virt_addr;
	struct dev_pagemap *pgmap;
};

struct md_t2_info {
	bool err_read_reported;
	bool err_write_reported;
};

struct md_dev_info {
	struct block_device *bdev;
	ulong size;
	ulong offset;
	union {
		struct md_t1_info	t1i;
		struct md_t2_info	t2i;
	};
	int index;
};

struct md_dev_larray {
	ulong bn_gcd;
	struct md_dev_info **map;
};

struct multi_devices {
	int dev_index;
	int t1_count;
	int t2_count;	/* currently always 1 */
	struct md_dev_info devs[ZUFS_DEV_MAX];
	struct md_dev_larray t1a;
};

static inline u64 zuf_p2o(ulong bn)
{
	return (u64)bn << PAGE_SHIFT;
}

static inline ulong zuf_o2p(u64 offset)
{
	return offset >> PAGE_SHIFT;
}

static inline ulong zuf_o2p_up(u64 offset)
{
	return zuf_o2p(offset + PAGE_SIZE - 1);
}

static inline struct md_dev_info *md_t1_dev(struct multi_devices *md, int i)
{
	return &md->devs[i];
}

static inline struct md_dev_info *md_t2_dev(struct multi_devices *md, int i)
{
	return &md->devs[md->t1_count + i];
}

static inline struct md_dev_info *md_dev_info(struct multi_devices *md, int i)
{
	return &md->devs[i];
}

static inline void *md_t1_addr(struct multi_devices *md, int i)
{
	struct md_dev_info *mdi = md_t1_dev(md, i);

	return mdi->t1i.virt_addr;
}

static inline struct md_dev_info *md_bn_t1_dev(struct multi_devices *md,
						 ulong bn)
{
	return md->t1a.map[bn / md->t1a.bn_gcd];
}

static inline ulong md_pfn(struct multi_devices *md, ulong block)
{
	struct md_dev_info *mdi = md_bn_t1_dev(md, block);

	return mdi->t1i.phys_pfn + (block - zuf_o2p(mdi->offset));
}

static inline void *md_addr(struct multi_devices *md, ulong offset)
{
	struct md_dev_info *mdi = md_bn_t1_dev(md, zuf_o2p(offset));

	return offset ? mdi->t1i.virt_addr + (offset - mdi->offset) : NULL;
}

static inline void *md_baddr(struct multi_devices *md, ulong bn)
{
	return md_addr(md, zuf_p2o(bn));
}

static inline struct zufs_dev_table *md_zdt(struct multi_devices *md)
{
	return md_t1_addr(md, 0);
}

static inline ulong md_t1_blocks(struct multi_devices *md)
{
	return le64_to_cpu(md_zdt(md)->s_t1_blocks);
}

static inline ulong md_t2_blocks(struct multi_devices *md)
{
	return le64_to_cpu(md_zdt(md)->s_t2_blocks);
}

static inline void *md_addr_verify(struct multi_devices *md, ulong offset)
{
	if (unlikely(offset > zuf_p2o(md_t1_blocks(md)))) {
		zuf_dbg_err("offset=0x%lx > max=0x%llx\n",
			    offset, zuf_p2o(md_t1_blocks(md)));
		return NULL;
	}

	return md_addr(md, offset);
}

static inline const char *_bdev_name(struct block_device *bdev)
{
	return dev_name(&bdev->bd_part->__dev);
}

static inline short _calc_csum(struct zufs_dev_table *zdt)
{
	uint n = ZUFS_SB_STATIC_SIZE(zdt) - sizeof(zdt->s_sum);

	/* FIXME: We should skip s_version so we can change it after
	 *        mount, once we start using the new structures
	 *   So below should be &zdt->s_version => &zdt->s_magic
	 *   PXS-240.
	 */
	return crc16(~0, (__u8 *)&zdt->s_version, n);
}

static inline int md_major_version(struct zufs_dev_table *zdt)
{
	return le16_to_cpu(zdt->s_version) / ZUFS_MINORS_PER_MAJOR;
}

static inline int md_minor_version(struct zufs_dev_table *zdt)
{
	return le16_to_cpu(zdt->s_version) % ZUFS_MINORS_PER_MAJOR;
}


/* md.c */
struct zufs_dev_table *md_t2_mdt_read(struct block_device *bdev);
int md_t2_mdt_write(struct multi_devices *md, ulong flags);
bool md_mdt_check(struct zufs_dev_table *zdt, struct block_device *bdev,
		  int silent);
struct multi_devices *md_alloc(size_t size);
int md_init(struct multi_devices *md, const char *dev_name,
	    struct file_system_type *fs_type, int silent, const char **dev_path);
void md_fini(struct multi_devices *md, struct block_device *s_bdev);
int md_set_sb(struct multi_devices *md, struct block_device *s_bdev, void *sb,
	      int silent);

struct zufs_ioc_pmem;
int md_numa_info(struct multi_devices *md, struct zufs_ioc_pmem *zi_pmem);

#endif
