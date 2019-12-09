/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Multi-Device operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#ifndef __MD_H__
#define __MD_H__

#include <linux/types.h>

#include "md_def.h"

#ifndef __KERNEL__
struct page;
struct block_device;
#else
#	include <linux/blkdev.h>
#endif /* ndef __KERNEL__ */

struct md_t1_info {
	void *virt_addr;
#ifdef __KERNEL__
	ulong phys_pfn;
	struct dax_device *dax_dev;
	struct dev_pagemap *pgmap;
#endif /*def __KERNEL__*/
};

struct md_t2_info {
#ifndef __KERNEL__
	bool err_read_reported;
	bool err_write_reported;
#endif
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
	int nid;
};

struct md_dev_larray {
	ulong bn_gcd;
	struct md_dev_info **map;
};

#ifndef __KERNEL__
struct fba {
	int fd; void *ptr;
	size_t size;
	void *orig_ptr;
};
#endif /*! __KERNEL__*/

struct zus_sb_info;
struct multi_devices {
	int dev_index;
	int t1_count;
	int t2_count;
	struct md_dev_info devs[MD_DEV_MAX];
	struct md_dev_larray t1a;
	struct md_dev_larray t2a;
#ifndef __KERNEL__
	struct zufs_ioc_pmem pmem_info; /* As received from Kernel */

	void *p_pmem_addr;
	int fd;
	uint user_page_size;
	struct fba pages;
	struct zus_sb_info *sbi;
#else
	ulong t1_blocks;
	ulong t2_blocks;
#endif /*! __KERNEL__*/
};

static inline __u64 md_p2o(ulong bn)
{
	return (__u64)bn << PAGE_SHIFT;
}

static inline ulong md_o2p(__u64 offset)
{
	return offset >> PAGE_SHIFT;
}

static inline ulong md_o2p_up(__u64 offset)
{
	return md_o2p(offset + PAGE_SIZE - 1);
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

static inline ulong md_t1_blocks(struct multi_devices *md)
{
#ifdef __KERNEL__
	return md->t1_blocks;
#else
	return md->pmem_info.mdt.s_t1_blocks;
#endif
}

static inline ulong md_t2_blocks(struct multi_devices *md)
{
#ifdef __KERNEL__
	return md->t2_blocks;
#else
	return md->pmem_info.mdt.s_t2_blocks;
#endif
}

static inline struct md_dev_table *md_zdt(struct multi_devices *md)
{
	return md_t1_addr(md, 0);
}

static inline struct md_dev_info *md_bn_t1_dev(struct multi_devices *md,
						 ulong bn)
{
	return md->t1a.map[bn / md->t1a.bn_gcd];
}

static inline uuid_le *md_main_uuid(struct multi_devices *md)
{
	return &md_zdt(md)->s_dev_list.dev_ids[md->dev_index].uuid;
}

#ifdef __KERNEL__
static inline ulong md_pfn(struct multi_devices *md, ulong block)
{
	struct md_dev_info *mdi;
	bool add_pfn = false;
	ulong base_pfn;

	if (unlikely(md_t1_blocks(md) <= block)) {
		if (WARN_ON(!mdt_test_option(md_zdt(md), MDT_F_SHADOW)))
			return 0;
		block -= md_t1_blocks(md);
		add_pfn = true;
	}

	mdi = md_bn_t1_dev(md, block);
	if (add_pfn)
		base_pfn = mdi->t1i.phys_pfn + md_o2p(mdi->size);
	else
		base_pfn = mdi->t1i.phys_pfn;
	return base_pfn + (block - md_o2p(mdi->offset));
}
#endif /* def __KERNEL__ */

static inline void *md_addr(struct multi_devices *md, ulong offset)
{
#ifdef __KERNEL__
	struct md_dev_info *mdi = md_bn_t1_dev(md, md_o2p(offset));

	return offset ? mdi->t1i.virt_addr + (offset - mdi->offset) : NULL;
#else
	return offset ? md->p_pmem_addr + offset : NULL;
#endif
}

static inline void *md_baddr(struct multi_devices *md, ulong bn)
{
	return md_addr(md, md_p2o(bn));
}

static inline struct md_dev_info *md_bn_t2_dev(struct multi_devices *md,
					       ulong bn)
{
	return md->t2a.map[bn / md->t2a.bn_gcd];
}

static inline int md_t2_bn_nid(struct multi_devices *md, ulong bn)
{
	struct md_dev_info *mdi = md_bn_t2_dev(md, bn);

	return mdi->nid;
}

static inline ulong md_t2_local_bn(struct multi_devices *md, ulong bn)
{
#ifdef __KERNEL__
	struct md_dev_info *mdi = md_bn_t2_dev(md, bn);

	return bn - md_o2p(mdi->offset);
#else
	return bn; /* In zus we just let Kernel worry about it */
#endif
}

static inline ulong md_t2_gcd(struct multi_devices *md)
{
	return md->t2a.bn_gcd;
}

static inline void *md_addr_verify(struct multi_devices *md, ulong offset)
{
	if (unlikely(offset > md_p2o(md_t1_blocks(md)))) {
		md_dbg_err("offset=0x%lx > max=0x%llx\n",
			    offset, md_p2o(md_t1_blocks(md)));
		return NULL;
	}

	return md_addr(md, offset);
}

static inline struct page *md_bn_to_page(struct multi_devices *md, ulong bn)
{
#ifdef __KERNEL__
	return pfn_to_page(md_pfn(md, bn));
#else
	return md->pages.ptr + bn * md->user_page_size;
#endif
}

static inline ulong md_addr_to_offset(struct multi_devices *md, void *addr)
{
#ifdef __KERNEL__
	/* TODO: Keep the device index in page-flags we need to fix the
	 * page-ref right? for now with pages untouched we need this loop
	 */
	int dev_index;

	for (dev_index = 0; dev_index < md->t1_count; ++dev_index) {
		struct md_dev_info *mdi = md_t1_dev(md, dev_index);

		if ((mdi->t1i.virt_addr <= addr) &&
		    (addr < (mdi->t1i.virt_addr + mdi->size)))
			return mdi->offset + (addr - mdi->t1i.virt_addr);
	}

	return 0;
#else /* !__KERNEL__ */
	return addr - md->p_pmem_addr;
#endif
}

static inline ulong md_addr_to_bn(struct multi_devices *md, void *addr)
{
	return md_o2p(md_addr_to_offset(md, addr));
}

static inline ulong md_page_to_bn(struct multi_devices *md, struct page *page)
{
#ifdef __KERNEL__
	return md_addr_to_bn(md, page_address(page));
#else
	ulong bytes = (void *)page - md->pages.ptr;

	return bytes / md->user_page_size;
#endif
}

#ifdef __KERNEL__
/* TODO: Change API to take mdi and also support in um */
static inline const char *_bdev_name(struct block_device *bdev)
{
	return dev_name(&bdev->bd_part->__dev);
}
#endif /*def __KERNEL__*/

struct mdt_check {
	ulong alloc_mask;
	uint major_ver;
	uint minor_ver;
	__u32  magic;

	void *holder;
	bool silent;
	bool private_mnt;
};

/* md.c */
bool md_mdt_check(struct md_dev_table *mdt, struct md_dev_table *main_mdt,
		  struct block_device *bdev, struct mdt_check *mc);
int md_t2_mdt_read(struct multi_devices *md, int dev_index,
		   struct md_dev_table *mdt);
int md_t2_mdt_write(struct multi_devices *md, struct md_dev_table *mdt);
short md_calc_csum(struct md_dev_table *mdt);
void md_fini(struct multi_devices *md, bool put_all);

#ifdef __KERNEL__
/* length of uuid dev path /dev/disk/by-uuid/<uuid> */
#define PATH_UUID	64
int md_init(struct multi_devices **md, const char *dev_name,
	    struct mdt_check *mc, char path[PATH_UUID], const char **dp);
int md_set_sb(struct multi_devices *md, struct block_device *s_bdev, void *sb,
	      int silent);
int md_t1_info_init(struct md_dev_info *mdi, bool silent);
void md_t1_info_fini(struct md_dev_info *mdi);

#else /* libzus */
int md_init_from_pmem_info(struct multi_devices *md);
#endif

#endif
