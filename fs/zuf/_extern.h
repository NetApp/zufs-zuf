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

/* directory.c */
int zuf_add_dentry(struct inode *dir, struct qstr *str, struct inode *inode);
int zuf_remove_dentry(struct inode *dir, struct qstr *str, struct inode *inode);

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
int zuf_update_time(struct inode *inode, struct timespec *time, int flags);
int zuf_setattr(struct dentry *dentry, struct iattr *attr);
#ifdef BACKPORT_GETATTR
int zuf_getattr(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat *stat);
#else
int zuf_getattr(const struct path *path, struct kstat *stat,
		 u32 request_mask, unsigned int flags);
#endif /* BACKPORT_GETATTR */
void zuf_set_inode_flags(struct inode *inode, struct zus_inode *zi);
bool zuf_dir_emit(struct super_block *sb, struct dir_context *ctx,
		  ulong ino, const char *name, int length);

/* symlink.c */
uint zuf_prepare_symname(struct zufs_ioc_new_inode *ioc_new_inode,
			const char *symname, ulong len, struct page *pages[2]);

/* ioctl.c */
long zuf_ioctl(struct file *filp, uint cmd, ulong arg);
#ifdef CONFIG_COMPAT
long zuf_compat_ioctl(struct file *file, uint cmd, ulong arg);
#endif

/* mmap.c */
int zuf_file_mmap(struct file *file, struct vm_area_struct *vma);

/* rw.c */
int _zuf_get_put_block(struct zuf_sb_info *sbi, struct zuf_inode_info *zii,
			  enum e_zufs_operation op, int rw, ulong index,
			  struct zufs_ioc_IO *get_block);
int zuf_rw_read_page(struct zuf_sb_info *sbi, struct inode *inode,
		     struct page *page, u64 filepos);
ssize_t zuf_rw_read_iter(struct super_block *sb, struct inode *inode,
			 struct kiocb *kiocb, struct iov_iter *ii);
ssize_t zuf_rw_write_iter(struct super_block *sb, struct inode *inode,
			  struct kiocb *kiocb, struct iov_iter *ii);
int zuf_trim_edge(struct inode *inode, ulong filepos, uint len);
int zuf_fadvise(struct super_block *sb, struct inode *inode,
		loff_t offset, loff_t len, int advise, bool rand);
int zuf_iom_execute_sync(struct super_block *sb, struct inode *inode,
			 __u64 *iom_e, uint iom_n);
int zuf_iom_execute_async(struct super_block *sb, struct zus_iomap_build *iomb,
			 __u64 *iom_e_user, uint iom_n);
/* file.c */
int zuf_isync(struct inode *inode, loff_t start, loff_t end, int datasync);

/* xattr.c */
int zuf_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		   void *fs_info);
ssize_t __zuf_getxattr(struct inode *inode, int type, const char *name,
		       void *buffer, size_t size);
int __zuf_setxattr(struct inode *inode, int type, const char *name,
		   const void *value, size_t size, int flags);
ssize_t zuf_listxattr(struct dentry *dentry, char *buffer, size_t size);
extern const struct xattr_handler *zuf_xattr_handlers[];

/* acl.c */
int zuf_set_acl(struct inode *inode, struct posix_acl *acl, int type);
struct posix_acl *zuf_get_acl(struct inode *inode, int type);
int zuf_acls_create_pre(struct inode *dir, struct inode *inode,
			struct posix_acl **user_acl);
int zuf_acls_create_post(struct inode *dir, struct inode *inode,
			 struct posix_acl *acl);
extern const struct xattr_handler zuf_acl_access_xattr_handler;
extern const struct xattr_handler zuf_acl_default_xattr_handler;

/* super.c */
int zuf_init_inodecache(void);
void zuf_destroy_inodecache(void);

void zuf_sync_inc(struct inode *inode);
void zuf_sync_dec(struct inode *inode, ulong write_unmapped);

struct dentry *zuf_mount(struct file_system_type *fs_type, int flags,
			 const char *dev_name, void *data);

struct super_block *zuf_sb_from_id(struct zuf_root_info *zri, __u64 sb_id,
				   struct zus_sb_info *zus_sbi);

int zuf_private_mount(struct zuf_root_info *zri, struct register_fs_info *rfi,
		      struct zufs_mount_info *zmi, struct super_block **sb_out);
int zuf_private_umount(struct zuf_root_info *zri, struct super_block *sb);

/* zuf-core.c */
int zufc_zts_init(struct zuf_root_info *zri); /* Some private types in core */
void zufc_zts_fini(struct zuf_root_info *zri);

long zufc_ioctl(struct file *filp, unsigned int cmd, ulong arg);
int zufc_release(struct inode *inode, struct file *file);
int zufc_mmap(struct file *file, struct vm_area_struct *vma);

int __zufc_dispatch_mount(struct zuf_root_info *zri,
			  enum e_mount_operation op,
			  struct zufs_ioc_mount *zim);
int zufc_dispatch_mount(struct zuf_root_info *zri, struct zus_fs_info *zus_zfi,
			enum e_mount_operation operation,
			struct zufs_ioc_mount *zim);

const char *zuf_op_name(enum e_zufs_operation op);
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

/* t1.c */
int zuf_pmem_mmap(struct file *file, struct vm_area_struct *vma);

/*
 * Inodes and files operations
 */

/* dir.c */
extern const struct file_operations zuf_dir_operations;

/* file.c */
extern const struct inode_operations zuf_file_inode_operations;

#ifdef BACKPORT_EXTEND_FILE_OPS
extern const struct file_operations_extend zuf_file_operations;
#else
extern const struct file_operations zuf_file_operations;
#endif /* BACKPORT_EXTEND_FILE_OPS */
extern const struct file_operations *zuf_fops(void);


/* inode.c */
extern const struct address_space_operations zuf_aops;
void zuf_zii_sync(struct inode *inode, bool sync_nlink);

/* namei.c */
#ifdef BACKPORT_INODE_OPS_WRAPPER
extern const struct inode_operations_wrapper zuf_dir_inode_operations;
#else
extern const struct inode_operations zuf_dir_inode_operations;
#endif /* BACKPORT_INODE_OPS_WRAPPER */
extern const struct inode_operations *zuf_dir_inode_ops(void);
extern const struct inode_operations zuf_special_inode_operations;

/* symlink.c */
extern const struct inode_operations zuf_symlink_inode_operations;

#endif	/*ndef __ZUF_EXTERN_H__*/
