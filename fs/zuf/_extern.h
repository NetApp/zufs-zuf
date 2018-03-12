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

/* zuf-root.c */
int zufr_register_fs(struct super_block *sb, struct zufs_ioc_register_fs *rfs);

/* super.c */
int zuf_init_inodecache(void);
void zuf_destroy_inodecache(void);

struct dentry *zuf_mount(struct file_system_type *fs_type, int flags,
			 const char *dev_name, void *data);

#endif	/*ndef __ZUF_EXTERN_H__*/
