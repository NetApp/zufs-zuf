/*
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
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

/* acl.c */
int tozu_set_acl(struct inode *inode, struct posix_acl *acl, int type);
struct posix_acl *tozu_get_acl(struct inode *inode, int type);
int tozu_acls_create(struct inode *dir, struct inode *inode);
extern const struct xattr_handler tozu_acl_access_xattr_handler;
extern const struct xattr_handler tozu_acl_default_xattr_handler;

/* directory.c */
int zuf_add_dentry(struct inode *dir, struct qstr *str,
		   struct inode *inode, bool rename);
int zuf_remove_dentry(struct inode *dir, struct qstr *str);

/* inode.c */
void tozu_unmap_range(struct inode *inode, loff_t const offset,
		      loff_t const length, int even_cows);
bool tozu_map_list_empty(struct inode *inode);
void tozu_map_list_add(struct inode *inode, struct inode *new);
void tozu_map_list_del(struct inode *inode);
struct inode *tozu_map_list_next(struct inode *inode);

int zuf_evict_dispatch(struct super_block *sb, struct zus_inode_info *zus_ii,
		       int operation);
struct inode *zuf_iget(struct super_block *sb, struct zus_inode_info *zus_ii,
		       zu_dpp_t _zi, bool *exist);
void zuf_evict_inode(struct inode *inode);
struct inode *zuf_new_inode(struct inode *dir, umode_t mode,
			    const struct qstr *qstr, const char *symname,
			    ulong rdev_or_isize, bool tmpfile);
int zuf_write_inode(struct inode *inode, struct writeback_control *wbc);
int zuf_update_time(struct inode *inode, struct timespec *time, int flags);
int zuf_setattr(struct dentry *dentry, struct iattr *attr);
int zuf_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat);
void zuf_set_inode_flags(struct inode *inode, struct zus_inode *zi);
bool zuf_dir_emit(struct super_block *sb, struct dir_context *ctx,
		  ulong ino, const char *name, int length);

/* symlink.c */
uint zuf_prepare_symname(struct zufs_ioc_new_inode *ioc_new_inode,
			const char *symname, ulong len, struct page *pages[2]);

/* ioctl.c */
long tozu_ioctl(struct file *filp, uint cmd, ulong arg);
#ifdef CONFIG_COMPAT
long tozu_compat_ioctl(struct file *file, uint cmd, ulong arg);
#endif

/* mmap.c */
int zuf_file_mmap(struct file *file, struct vm_area_struct *vma);

/* rw.c */
ssize_t zuf_rw_read_iter(struct kiocb *kiocb, struct iov_iter *ii);
ssize_t zuf_rw_write_iter(struct kiocb *kiocb, struct iov_iter *ii);

/* xattr.c */
int tozu_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		    void *fs_info);
struct tozu_xattr *tozu_new_xattr(struct super_block *sb, int type,
				  const char *name, size_t length,
				  const void *value, size_t size, ulong *xno);
ssize_t __tozu_getxattr(struct inode *inode, int type, const char *name,
			void *buffer, size_t size,
			struct tozu_xattr **xattr_out,
			struct tozu_xattr **pprev);
int __tozu_setxattr(struct inode *inode, int type, const char *name,
		    struct tozu_xattr *new_xattr, ulong new_xno, int flags);
void __tozu_removexattrs(struct super_block *sb, struct zus_inode *zi);
ssize_t tozu_listxattr(struct dentry *dentry, char *buffer, size_t size);
extern const struct xattr_handler *tozu_xattr_handlers[];

/* file.c */
int zuf_isync(struct inode *inode, loff_t start, loff_t end, int datasync);
int tozu_fadvise(struct file *file, loff_t offset, loff_t len, int advice);

/* non_gpl.c */
struct dentry *non_gpl_fh_to_dentry(struct super_block *sb, struct fid *fid,
				    int fh_len, int fh_type);
struct dentry *non_gpl_fh_to_parent(struct super_block *sb, struct fid *fid,
				    int fh_len, int fh_type);

/* super.c */
int zuf_init_inodecache(void);
void zuf_destroy_inodecache(void);

struct inode *tozu_nfs_get_inode(struct super_block *sb, u64 ino,
				 u32 generation);
void tozu_add_mmap_inode(struct inode *inode);
void tozu_remove_mmap_inode(struct inode *inode);

int zuf_register_fs(struct super_block *sb, struct zufs_ioc_register_fs *rfs);

/* zuf-core.c */
int zufs_zts_init(struct zuf_root_info *zri); /* Some private types in core */
void zufs_zts_fini(struct zuf_root_info *zri);

long zufs_ioc(struct file *filp, unsigned int cmd, ulong arg);
int zufs_dispatch_mount(struct zuf_root_info *zri, struct zus_fs_info *zus_zfi,
			struct zufs_ioc_mount *zim);
int zufs_dispatch_umount(struct zuf_root_info *zri,
			 struct zus_sb_info *zus_sbi);

int zufs_dispatch(struct zuf_root_info *zri, struct zufs_ioc_hdr *hdr,
		  struct page **pages, uint nump);

int zuf_zt_mmap(struct file *file, struct vm_area_struct *vma);

void zufs_zt_release(struct file *filp);
void zufs_mounter_release(struct file *filp);

/* zuf-root.c */

/* t1.c */
int zuf_pmem_mmap(struct file *file, struct vm_area_struct *vma);

/*
 * Inodes and files operations
 */

/* dir.c */
extern const struct file_operations tozu_dir_operations;

/* file.c */
extern const struct inode_operations tozu_file_inode_operations;
extern const struct file_operations tozu_file_operations;

/* inode.c */
extern const struct address_space_operations zuf_aops;

/* namei.c */
extern const struct inode_operations tozu_dir_inode_operations;
extern const struct inode_operations tozu_special_inode_operations;

/* symlink.c */
extern const struct inode_operations zuf_symlink_inode_operations;

#endif	/*ndef __ZUF_EXTERN_H__*/
