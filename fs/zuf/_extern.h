/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#ifndef __ZUF_EXTERN_H__
#define __ZUF_EXTERN_H__
/*
 * DO NOT INCLUDE this file directly, it is included by zuf.h
 * It is here because zuf.h got to big
 */

/*
 * extern functions declarations
 */

/* zuf-core.c */
int zufc_zts_init(struct zuf_root_info *zri); /* Some private types in core */
void zufc_zts_fini(struct zuf_root_info *zri);

long zufc_ioctl(struct file *filp, unsigned int cmd, ulong arg);
int zufc_release(struct inode *inode, struct file *file);
int zufc_mmap(struct file *file, struct vm_area_struct *vma);
const char *zuf_op_name(enum e_zufs_operation op);

int zufc_dispatch_mount(struct zuf_root_info *zri, struct zus_fs_info *zus_zfi,
			enum e_mount_operation operation,
			struct zufs_ioc_mount *zim);

int __zufc_dispatch(struct zuf_root_info *zri, struct zuf_dispatch_op *zdo);
static inline
int zufc_dispatch(struct zuf_root_info *zri, struct zufs_ioc_hdr *hdr,
		  struct page **pages, uint nump)
{
	struct zuf_dispatch_op zdo;

	zuf_dispatch_init(&zdo, hdr, pages, nump);
	return __zufc_dispatch(zri, &zdo);
}

/* zuf-root.c */
int zufr_register_fs(struct super_block *sb, struct zufs_ioc_register_fs *rfs);

/* super.c */
int zuf_init_inodecache(void);
void zuf_destroy_inodecache(void);

int zuf_8k_cache_init(void);
void zuf_8k_cache_fini(void);

struct dentry *zuf_mount(struct file_system_type *fs_type, int flags,
			 const char *dev_name, void *data);
int zuf_private_mount(struct zuf_root_info *zri, struct register_fs_info *rfi,
		      struct zufs_mount_info *zmi, struct super_block **sb_out);
int zuf_private_umount(struct zuf_root_info *zri, struct super_block *sb);
struct super_block *zuf_sb_from_id(struct zuf_root_info *zri, __u64 sb_id,
				   struct zus_sb_info *zus_sbi);

/* inode.c */
struct inode *zuf_iget(struct super_block *sb, struct zus_inode_info *zus_ii,
		       zu_dpp_t _zi, bool *exist);
/* t1.c */
int zuf_pmem_mmap(struct file *file, struct vm_area_struct *vma);

#endif	/*ndef __ZUF_EXTERN_H__*/
