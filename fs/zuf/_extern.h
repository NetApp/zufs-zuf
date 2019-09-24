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

/* file.c */
long __zuf_fallocate(struct inode *inode, int mode, loff_t offset, loff_t len);

/* namei.c */
void zuf_zii_sync(struct inode *inode, bool sync_nlink);

/* inode.c */
int zuf_evict_dispatch(struct super_block *sb, struct zus_inode_info *zus_ii,
		       int operation, uint flags);
struct inode *zuf_iget(struct super_block *sb, struct zus_inode_info *zus_ii,
		       zu_dpp_t _zi, bool *exist);
void zuf_evict_inode(struct inode *inode);
struct inode *zuf_new_inode(struct inode *dir, umode_t mode,
			    const struct qstr *qstr, const char *symname,
			    ulong rdev_or_isize, bool tmpfile);
int zuf_write_inode(struct inode *inode, struct writeback_control *wbc);
int zuf_update_time(struct inode *inode, struct timespec64 *time, int flags);
int zuf_setattr(struct dentry *dentry, struct iattr *attr);
int zuf_getattr(const struct path *path, struct kstat *stat,
		 u32 request_mask, unsigned int flags);
void zuf_set_inode_flags(struct inode *inode, struct zus_inode *zi);

/* directory.c */
int zuf_add_dentry(struct inode *dir, struct qstr *str, struct inode *inode);
int zuf_remove_dentry(struct inode *dir, struct qstr *str, struct inode *inode);

/* t1.c */
int zuf_pmem_mmap(struct file *file, struct vm_area_struct *vma);

/*
 * Inode and files operations
 */

/* file.c */
extern const struct inode_operations zuf_file_inode_operations;
extern const struct file_operations zuf_file_operations;

/* inode.c */
extern const struct address_space_operations zuf_aops;

/* namei.c */
extern const struct inode_operations zuf_dir_inode_operations;
extern const struct inode_operations zuf_special_inode_operations;

/* dir.c */
extern const struct file_operations zuf_dir_operations;

#endif	/*ndef __ZUF_EXTERN_H__*/
