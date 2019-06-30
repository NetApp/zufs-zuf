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
#include <linux/fiemap.h>
#include <stddef.h>

#include "md_def.h"

#ifdef __cplusplus
#define NAMELESS(X) X
#else
#define NAMELESS(X)
#endif

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

/* Kernel versus User space compatibility definitions */
#ifdef __KERNEL__

#include <linux/statfs.h>

#else /* ! __KERNEL__ */

/* verify statfs64 definition is included */
#if !defined(__USE_LARGEFILE64) && defined(_SYS_STATFS_H)
#error "include to 'sys/statfs.h' must appear after 'zus_api.h'"
#else
#define __USE_LARGEFILE64 1
#endif

#include <sys/statfs.h>

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

#ifndef likely
#define likely(x_)	__builtin_expect(!!(x_), 1)
#define unlikely(x_)	__builtin_expect(!!(x_), 0)
#endif

/* RHEL/CentOS7 specifics */
#ifndef FALLOC_FL_UNSHARE_RANGE
#define FALLOC_FL_UNSHARE_RANGE         0x40
#endif

#endif /*  ndef __KERNEL__ */

/* first available error code after include/linux/errno.h */
#define EZUFS_RETRY	531

/* The below is private to zuf Kernel only. Is not exposed to VFS nor zus
 * (defined here to allocate the constant)
 */
#define EZUF_RETRY_DONE 540

/* TODO: Someone forgot i_flags & i_version for STATX_ attrs should send a patch
 * to add them
 */
#define ZUFS_STATX_FLAGS	0x20000000U
#define ZUFS_STATX_VERSION	0x40000000U

/*
 * Maximal count of links to a file
 */
#define ZUFS_LINK_MAX          32000
#define ZUFS_MAX_SYMLINK	PAGE_SIZE
#define ZUFS_NAME_LEN		255
#define ZUFS_READAHEAD_PAGES	8

/* All device sizes offsets must align on 2M */
#define ZUFS_ALLOC_MASK		(1024 * 1024 * 2 - 1)

/**
 * zufs dual port memory
 * This is a special type of offset to either memory or persistent-memory,
 * that is designed to be used in the interface mechanism between userspace
 * and kernel, and can be accessed by both.
 * 3 first bits denote a mem-pool:
 * 0   - pmem pool
 * 1-6 - established shared pool by a call to zufs_ioc_create_mempool (below)
 * 7   - offset into app memory
 */
typedef __u64 __bitwise zu_dpp_t;

static inline uint zu_dpp_t_pool(zu_dpp_t t)
{
	return t & 0x7;
}

static inline ulong zu_dpp_t_val(zu_dpp_t t)
{
	return t & ~0x7;
}

static inline zu_dpp_t zu_enc_dpp_t(ulong v, uint pool)
{
	return v | pool;
}

static inline ulong zu_dpp_t_bn(zu_dpp_t t)
{
	return t >> 3;
}

static inline zu_dpp_t zu_enc_dpp_t_bn(ulong v, uint pool)
{
	return zu_enc_dpp_t(v << 3, pool);
}

/*
 * Structure of a ZUS inode.
 * This is all the inode fields
 */

/* See VFS inode flags at fs.h. As ZUFS support flags up to the 7th bit, we
 * use higher bits for ZUFS specific flags
 * */
#define ZUFS_S_IMMUTABLE 04000

/* zus_inode size */
#define ZUFS_INODE_SIZE 128    /* must be power of two */
#define ZUFS_INODE_BITS   7

struct zus_inode {
	__le16	i_flags;	/* Inode flags */
	__le16	i_mode;		/* File mode */
	__le32	i_nlink;	/* Links count */
	__le64	i_size;		/* Size of data in bytes */
/* 16*/	struct __zi_on_disk_desc {
		__le64	a[2];
	}	i_on_disk;	/* FS-specific on disc placement */
/* 32*/	__le64	i_blocks;
	__le64	i_mtime;	/* Inode/data Modification time */
	__le64	i_ctime;	/* Inode/data Changed time */
	__le64	i_atime;	/* Data Access time */
/* 64 - cache-line boundary */
	__le64	i_ino;		/* Inode number */
	__le32	i_uid;		/* Owner Uid */
	__le32	i_gid;		/* Group Id */
	__le64	i_xattr;	/* FS-specific Extended attribute block */
	__le64	i_generation;	/* File version (for NFS) */
/* 96*/	union NAMELESS(_I_U) {
		__le32	i_rdev;		/* special-inode major/minor etc ...*/
		u8	i_symlink[32];	/* if i_size < sizeof(i_symlink) */
		__le64	i_sym_dpp;	/* Link location if long symlink */
		struct  _zu_dir {
			__le64	dir_root;
			__le64  parent;
		}	i_dir;
	};
	/* Total ZUFS_INODE_SIZE bytes always */
};

/* ~~~~~ vfs extension ioctl commands ~~~~~ */

/* TODO: This one needs to be an FS vector called from
 * the fadvise()  system call. (Future patch)
 */
struct zufs_ioc_fadvise {
	__u64	offset;
	__u64	length;		/* if 0 all file */
	__u64	advise;
} __packed;

#define ZUFS_IOC_FADVISE	_IOW('S', 2, struct zufs_ioc_fadvise)

/* ~~~~~ ZUFS API ioctl commands ~~~~~ */
enum {
	ZUS_API_MAP_MAX_PAGES	= 1024,
	ZUS_API_MAP_MAX_SIZE	= ZUS_API_MAP_MAX_PAGES * PAGE_SIZE,
};

struct zufs_ioc_hdr {
	__u32 err;	/* IN/OUT must be first */
	__u16 in_len;	/* How much to be copied *to* zus */
	__u16 out_max;	/* Max receive buffer at dispatch caller */
	__u16 out_start;/* Start of output parameters (to caller) */
	__u16 out_len;	/* How much to be copied *from* zus to caller */
			/* can be modified by zus */
	__u16 operation;/* One of e_zufs_operation */
	__u16 flags;	/* flags */
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

/* A cookie from user-mode returned by mount */
struct zus_sb_info;

/* zus cookie per inode */
struct zus_inode_info;

enum ZUFS_M_FLAGS {
	ZUFS_M_PEDANTIC		= 0x00000001,
	ZUFS_M_EPHEMERAL	= 0x00000002,
	ZUFS_M_SILENT		= 0x00000004,
};

struct zufs_parse_options {
	__u32 mount_options_len;
	__u32 pedantic;
	__u64 mount_flags;
	char mount_options[0];
};

enum e_mount_operation {
	ZUFS_M_MOUNT	= 1,
	ZUFS_M_UMOUNT,
	ZUFS_M_REMOUNT,
	ZUFS_M_DDBG_RD,
	ZUFS_M_DDBG_WR,
};

enum {
	ZUFS_REM_WAS_RO	= 0x00000001,
	ZUFS_REM_WILL_RO	= 0x00000002,
};

struct zufs_mount_info {
	/* IN */
	struct zus_fs_info *zus_zfi;
	__u16	num_cpu;
	__u16	num_channels;
	__u32	pmem_kern_id;
	__u64	sb_id;

	/* OUT */
	struct zus_sb_info *zus_sbi;
	/* mount is also iget of root */
	struct zus_inode_info *zus_ii;
	zu_dpp_t _zi;
	__u64	old_mount_opt;
	__u64	remount_flags;

	/* More FS specific info */
	__u32 s_blocksize_bits;
	__u8	acl_on;
	struct zufs_parse_options po;
};

struct zufs_ddbg_info {
	__u64 id; /* IN where to start from, OUT last ID */
	/* IN size of buffer, OUT size of dynamic debug message */
	__u64 len;
	char msg[0];
};

/* mount / umount */
struct  zufs_ioc_mount {
	struct zufs_ioc_hdr hdr;
	union {
		struct zufs_mount_info zmi;
		struct zufs_ddbg_info zdi;
	};
};
#define ZU_IOC_MOUNT	_IOWR('Z', 11, struct zufs_ioc_mount)

/* pmem  */
struct zufs_cpu_set {
	ulong bits[16];
};

struct zufs_ioc_numa_map {
	/* Set by zus */
	struct zufs_ioc_hdr hdr;

	__u32	possible_nodes;
	__u32	possible_cpus;
	__u32	online_nodes;
	__u32	online_cpus;

	__u32	max_cpu_per_node;

	/* This indicates that NOT all nodes have @max_cpu_per_node cpus */
	bool	nodes_not_symmetrical;
	__u8	__pad[19]; /* align cpu_set_per_node to next cache-line */

	/* Variable size must keep last
	 * size @possible_nodes
	 */
	struct zufs_cpu_set cpu_set_per_node[];
};
#define ZU_IOC_NUMA_MAP	_IOWR('Z', 12, struct zufs_ioc_numa_map)

struct zufs_ioc_pmem {
	/* Set by zus */
	struct zufs_ioc_hdr hdr;
	__u32 pmem_kern_id;

	/* Returned to zus */
	struct md_dev_table mdt;
	int dev_index;

};
/* GRAB is never ungrabed umount or file close cleans it all */
#define ZU_IOC_GRAB_PMEM	_IOWR('Z', 13, struct zufs_ioc_pmem)

/* ZT init */
enum { ZUFS_MAX_ZT_CHANNELS = 64 };

struct zufs_ioc_init {
	struct zufs_ioc_hdr hdr;
	ulong affinity;	/* IN */
	uint channel_no;
	uint max_command;
};
#define ZU_IOC_INIT_THREAD	_IOWR('Z', 14, struct zufs_ioc_init)

/* break_all (Server telling kernel to clean) */
struct zufs_ioc_break_all {
	struct zufs_ioc_hdr hdr;
};
#define ZU_IOC_BREAK_ALL	_IOWR('Z', 15, struct zufs_ioc_break_all)

/* ~~~  zufs_ioc_wait_operation ~~~ */
struct zufs_ioc_wait_operation {
	struct zufs_ioc_hdr hdr;
	/* maximum size is governed by zufs_ioc_init->max_command */
	char opt_buff[];
};
#define ZU_IOC_WAIT_OPT		_IOWR('Z', 16, struct zufs_ioc_wait_operation)

/* These are the possible operations sent from Kernel to the Server in the
 * return of the ZU_IOC_WAIT_OPT.
 */
enum e_zufs_operation {
	ZUFS_OP_NULL = 0,
	ZUFS_OP_STATFS,
	ZUFS_OP_SHOW_OPTIONS,

	ZUFS_OP_NEW_INODE,
	ZUFS_OP_FREE_INODE,
	ZUFS_OP_EVICT_INODE,

	ZUFS_OP_LOOKUP,
	ZUFS_OP_ADD_DENTRY,
	ZUFS_OP_REMOVE_DENTRY,
	ZUFS_OP_RENAME,
	ZUFS_OP_READDIR,
	ZUFS_OP_CLONE,
	ZUFS_OP_COPY,

	ZUFS_OP_READ,
	ZUFS_OP_PRE_READ,
	ZUFS_OP_WRITE,
	ZUFS_OP_GET_BLOCK,
	ZUFS_OP_PUT_BLOCK,
	ZUFS_OP_MMAP_CLOSE,
	ZUFS_OP_GET_SYMLINK,
	ZUFS_OP_SETATTR,
	ZUFS_OP_SYNC,
	ZUFS_OP_FALLOCATE,
	ZUFS_OP_LLSEEK,
	ZUFS_OP_IOCTL,
	ZUFS_OP_XATTR_GET,
	ZUFS_OP_XATTR_SET,
	ZUFS_OP_XATTR_LIST,
	ZUFS_OP_FIEMAP,

	ZUFS_OP_BREAK,		/* Kernel telling Server to exit */
	ZUFS_OP_MAX_OPT,
};

enum e_zufs_hdr_flags {
	ZUFS_H_INTR	= (1 << 0),
};

#define ZUFS_MO_MAX	512

struct zufs_ioc_mount_options {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_sb_info *zus_sbi;

	/* OUT */
	char	buf[0];
};

/* ZUFS_OP_STATFS */
struct zufs_ioc_statfs {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_sb_info *zus_sbi;

	/* OUT */
	struct statfs64 statfs_out;
};

/* zufs_ioc_new_inode flags: */
enum zi_flags {
	ZI_TMPFILE = 1,		/* for new_inode */
	ZI_LOOKUP_RACE = 1,	/* for evict */
};

struct zufs_str {
	__u8 len;
	char name[ZUFS_NAME_LEN];
};

/* ZUFS_OP_NEW_INODE */
struct zufs_ioc_new_inode {
	struct zufs_ioc_hdr hdr;
	 /* IN */
	struct zus_inode zi;
	struct zus_inode_info *dir_ii; /* If mktmp this is the root */
	struct zufs_str str;
	__u64 flags;

	 /* OUT */
	zu_dpp_t _zi;
	struct zus_inode_info *zus_ii;
};

/* ZUFS_OP_FREE_INODE, ZUFS_OP_EVICT_INODE */
struct zufs_ioc_evict_inode {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *zus_ii;
	__u64 flags;
};

/* ZUFS_OP_LOOKUP */
struct zufs_ioc_lookup {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *dir_ii;
	struct zufs_str str;

	 /* OUT */
	zu_dpp_t _zi;
	struct zus_inode_info *zus_ii;
};

/* ZUFS_OP_ADD_DENTRY, ZUFS_OP_REMOVE_DENTRY */
struct zufs_ioc_dentry {
	struct zufs_ioc_hdr hdr;
	struct zus_inode_info *zus_ii; /* IN */
	struct zus_inode_info *zus_dir_ii; /* IN */
	struct zufs_str str; /* IN */
	__u64 ino; /* OUT - only for lookup */
};

/* ZUFS_OP_RENAME */
struct zufs_ioc_rename {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *old_dir_ii;
	struct zus_inode_info *new_dir_ii;
	struct zus_inode_info *old_zus_ii;
	struct zus_inode_info *new_zus_ii;
	struct zufs_str old_d_str;
	struct zufs_str new_d_str;
	__u64 time;
	__u32 flags;
};

/* ZUFS_OP_READDIR */
struct zufs_ioc_readdir {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *dir_ii;
	loff_t pos;

	/* OUT */
	__u8	more;
};

struct zufs_dir_entry {
	__le64 ino;
	struct {
		unsigned	type	: 8;
		ulong		pos	: 56;
	};
	struct zufs_str zstr;
};

struct zufs_readdir_iter {
	void *__zde, *last;
	struct zufs_ioc_readdir *ioc_readdir;
};

enum {E_ZDE_HDR_SIZE =
	offsetof(struct zufs_dir_entry, zstr) + offsetof(struct zufs_str, name),
};

#ifndef __cplusplus
static inline void zufs_readdir_iter_init(struct zufs_readdir_iter *rdi,
					  struct zufs_ioc_readdir *ioc_readdir,
					  void *app_ptr)
{
	rdi->__zde = app_ptr;
	rdi->last = app_ptr + ioc_readdir->hdr.len;
	rdi->ioc_readdir = ioc_readdir;
	ioc_readdir->more = false;
}

static inline uint zufs_dir_entry_len(__u8 name_len)
{
	return ALIGN(E_ZDE_HDR_SIZE + name_len, sizeof(__u64));
}

static inline
struct zufs_dir_entry *zufs_next_zde(struct zufs_readdir_iter *rdi)
{
	struct zufs_dir_entry *zde = rdi->__zde;
	uint len;

	if (rdi->last <= rdi->__zde + E_ZDE_HDR_SIZE)
		return NULL;
	if (zde->zstr.len == 0)
		return NULL;
	len = zufs_dir_entry_len(zde->zstr.len);
	if (rdi->last <= rdi->__zde + len)
		return NULL;

	rdi->__zde += len;
	return zde;
}

static inline bool zufs_zde_emit(struct zufs_readdir_iter *rdi, __u64 ino,
				 __u8 type, __u64 pos, const char *name,
				 __u8 len)
{
	struct zufs_dir_entry *zde = rdi->__zde;

	if (rdi->last <= rdi->__zde + zufs_dir_entry_len(len)) {
		rdi->ioc_readdir->more = true;
		return false;
	}

	rdi->ioc_readdir->more = 0;
	zde->ino = ino;
	zde->type = type;
	/*ASSERT(0 == (pos && (1 << 56 - 1)));*/
	zde->pos = pos;
	strncpy(zde->zstr.name, name, len);
	zde->zstr.len = len;
	zufs_next_zde(rdi);

	return true;
}
#endif /* ndef __cplusplus */

struct zufs_ioc_mmap_close {
	struct zufs_ioc_hdr hdr;
	 /* IN */
	struct zus_inode_info *zus_ii;
	__u64 rw; /* Some flags + READ or WRITE */
};

/* ZUFS_OP_GET_SYMLINK */
struct zufs_ioc_get_link {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *zus_ii;

	/* OUT */
	zu_dpp_t _link;
};

/* ZUFS_OP_SETATTR */
struct zufs_ioc_attr {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *zus_ii;
	__u64 truncate_size;
	__u32 zuf_attr;
	__u32 pad;
};

enum ZUFS_RANGE_FLAGS {
	ZUFS_RF_DONTNEED		= 0x00000001,
};

/* ZUFS_OP_ISYNC, ZUFS_OP_FALLOCATE */
struct zufs_ioc_range {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *zus_ii;
	__u64 offset, length;
	__u32 opflags;
	__u32 ioc_flags;

	/* OUT */
	__u64 write_unmapped;
};

/* ZUFS_OP_CLONE */
struct zufs_ioc_clone {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *src_zus_ii;
	struct zus_inode_info *dst_zus_ii;
	__u64 pos_in, pos_out;
	__u64 len;
	__u64 len_up;
};

/* ZUFS_OP_LLSEEK */
struct zufs_ioc_seek {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *zus_ii;
	__u64 offset_in;
	__u32 whence;
	__u32 pad;

	/* OUT */
	__u64 offset_out;
};

enum e_ZUFS_IOCTL_UFLAGS {
	ZUF_REALLOC =		0x1,
	ZUF_FREEZE_REQ =	0x2,
};

enum e_ZUFS_IOCTL_KFLAGS {
	ZUF_FSFROZEN =		0x1,
	ZUF_CAP_ADMIN =		0x2,
};

/* ZUFS_OP_IOCTL */
struct zufs_ioc_ioctl {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *zus_ii;
	__u32 cmd;
	__u64 time;

	/* OUT */
	__u32 kflags; /* zuf/kernel state and flags*/
	char out_start[0];
	struct {
		__u32 uflags; /* zus state and flags */
		union {
			__u32 new_size;
			char arg[0];
		};
	};
};

/* xattr ioc_flags */
#define ZUFS_XATTR_SET_EMPTY	(1 << 0)
#define ZUFS_XATTR_TRUSTED	(1 << 1)

/* ZUFS_OP_XATTR */
struct zufs_ioc_xattr {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_inode_info *zus_ii;
	__u32	flags;
	__u32	type;
	__u16	name_len;
	__u16	ioc_flags;

	/* OUT */
	__u32	user_buf_size;
	char	buf[0];
} __packed;


/* ZUFS_OP_FIEMAP */
struct zufs_ioc_fiemap {
	struct zufs_ioc_hdr hdr;

	/* IN */
	struct zus_inode_info *zus_ii;
	__u64	start;
	__u64	length;
	__u32	flags;
	__u32	extents_max;

	/* OUT */
	__u32	extents_mapped;
	__u32	pad;

} __packed;

struct zufs_fiemap_extent_info {
	__u32 fi_flags;
	__u32 fi_extents_mapped;
	__u32 fi_extents_max;
	struct fiemap_extent *fi_extents_start;
};

static inline
int zufs_fiemap_fill_next_extent(struct zufs_fiemap_extent_info *fieinfo,
				 __u64 logical, __u64 phys,
				 __u64 len, __u32 flags)
{
	struct fiemap_extent *dest = fieinfo->fi_extents_start;

	if (fieinfo->fi_extents_max == 0) {
		fieinfo->fi_extents_mapped++;
		return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
	}

	if (fieinfo->fi_extents_mapped >= fieinfo->fi_extents_max)
		return 1;

	dest += fieinfo->fi_extents_mapped;
	dest->fe_logical = logical;
	dest->fe_physical = phys;
	dest->fe_length = len;
	dest->fe_flags = flags;

	fieinfo->fi_extents_mapped++;
	if (fieinfo->fi_extents_mapped == fieinfo->fi_extents_max)
		return 1;

	return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
}



/* ~~~~ io_map structures && IOCTL(s) ~~~~ */
/*
 * These set of structures and helpers are used in return of zufs_ioc_IO and
 * also at ZU_IOC_IOMAP_EXEC, NULL terminating list (array)
 *
 * Each iom_elemet stars with an __u64 of which the 8 hight bits carry an
 * operation_type, And the 56 bits value denotes a page offset, (md_o2p()) or a
 * length. operation_type is one of ZUFS_IOM_TYPE enum.
 * The interpreter then jumps to the next operation depending on the size
 * of the defined operation.
 */

enum ZUFS_IOM_TYPE {
	IOM_NONE	= 0,
	IOM_T1_WRITE	= 1,
	IOM_T1_READ	= 2,

	IOM_T2_WRITE	= 3,
	IOM_T2_READ	= 4,
	IOM_T2_WRITE_LEN = 5,
	IOM_T2_READ_LEN	= 6,

	IOM_T2_ZUSMEM_WRITE = 7,
	IOM_T2_ZUSMEM_READ = 8,

	IOM_UNMAP	= 9,
	IOM_WBINV	= 10,
	IOM_REPEAT	= 11,

	IOM_NUM_LEGAL_OPT,
};

#define ZUFS_IOM_VAL_BITS	56
#define ZUFS_IOM_FIRST_VAL_MASK ((1UL << ZUFS_IOM_VAL_BITS) - 1)

static inline enum ZUFS_IOM_TYPE _zufs_iom_opt_type(__u64 *iom_e)
{
	uint ret = (*iom_e) >> ZUFS_IOM_VAL_BITS;

	if (ret >= IOM_NUM_LEGAL_OPT)
		return IOM_NONE;
	return (enum ZUFS_IOM_TYPE)ret;
}

static inline bool _zufs_iom_pop(__u64 *iom_e)
{
	return _zufs_iom_opt_type(iom_e) != IOM_NONE;
}

static inline ulong _zufs_iom_first_val(__u64 *iom_elemets)
{
	return *iom_elemets & ZUFS_IOM_FIRST_VAL_MASK;
}

static inline void _zufs_iom_enc_type_val(__u64 *ptr, enum ZUFS_IOM_TYPE type,
					 ulong val)
{
	*ptr = (__u64)val | ((__u64)type << ZUFS_IOM_VAL_BITS);
}

static inline ulong _zufs_iom_t1_bn(__u64 val)
{
	if (unlikely(_zufs_iom_opt_type(&val) != IOM_T1_READ))
		return -1;

	return zu_dpp_t_bn(_zufs_iom_first_val(&val));
}

static inline void _zufs_iom_enc_bn(__u64 *ptr, ulong bn, uint pool)
{
	_zufs_iom_enc_type_val(ptr, IOM_T1_READ, zu_enc_dpp_t_bn(bn, pool));
}

/* IOM_T1_WRITE / IOM_T1_READ
 * May be followed by an IOM_REPEAT
 */
struct zufs_iom_t1_io {
	/* Special dpp_t that denote a page ie: bn << 3 | zu_dpp_t_pool  */
	__u64	t1_val;
};

/* IOM_T2_WRITE / IOM_T2_READ */
struct zufs_iom_t2_io {
	__u64	t2_val;
	zu_dpp_t t1_val;
};

/* IOM_T2_WRITE_LEN / IOM_T2_READ_LEN */
struct zufs_iom_t2_io_len {
	struct zufs_iom_t2_io iom;
	__u64 num_pages;
} __packed;

/* IOM_T2_ZUSMEM_WRITE / IOM_T2_ZUSMEM_READ */
struct zufs_iom_t2_zusmem_io {
	__u64	t2_val;
	__u64	zus_mem_ptr; /* needs an get_user_pages() */
	__u64	len;
};

/* IOM_UNMAP:
 *	Executes unmap_mapping_range & remove of zuf's block-caching
 *
 * For now iom_unmap means even_cows=0, because Kernel takes care of all
 * the cases of the even_cows=1. In future if needed it will be on the high
 * bit of unmap_n.
 */
struct zufs_iom_unmap {
	__u64	unmap_index;	/* Offset in pages of inode */
	__u64	unmap_n;	/* Num pages to unmap (0 means: to eof) */
	__u64	ino;		/* Pages of this inode */
} __packed;

#define ZUFS_WRITE_OP_SPACE						\
	((sizeof(struct zufs_iom_unmap) +				\
	  sizeof(struct zufs_iom_t2_io)) / sizeof(__u64) + sizeof(__u64))

struct zus_iomap_build;
/* For ZUFS_OP_IOM_DONE */
struct zufs_ioc_iomap_done {
	struct zufs_ioc_hdr hdr;
	/* IN */
	struct zus_sb_info *zus_sbi;

	/* The cookie received from zufs_ioc_iomap_exec */
	struct	zus_iomap_build *iomb;
};

struct zufs_iomap {
	/* A cookie from zus to return when execution is done */
	struct	zus_iomap_build *iomb;

	__u32	iom_max;	/* num of __u64 allocated	 */
	__u32	iom_n;		/* num of valid __u64 in iom_e	 */
	__u64	iom_e[0];	/* encoded operations to execute */

	/* This struct must be last */
};

/* Allocate a special_file that will be a dual-port communication buffer with
 * user mode.
 * Server will access the buffer via the mmap of this file.
 * Kernel will access the file via the valloc() pointer
 *
 * Some IOCTLs below demand use of this kind of buffer for communication
 * TODO:
 * pool_no is if we want to associate this buffer onto the 6 possible
 * mem-pools per zuf_sbi. So anywhere we have a zu_dpp_t it will mean
 * access from this pool.
 * If pool_no is zero then it is private to only this file. In this case
 * sb_id && zus_sbi are ignored / not needed.
 */
struct zufs_ioc_alloc_buffer {
	struct zufs_ioc_hdr hdr;
	/* The ID of the super block received in mount */
	__u64	sb_id;
	/* We verify the sb_id validity against zus_sbi */
	struct zus_sb_info *zus_sbi;
	/* max size of buffer allowed (size of mmap) */
	__u32 max_size;
	/* allocate this much on initial call and set into vma */
	__u32 init_size;

	/* TODO: These below are now set to ZERO. Need implementation */
	__u16 pool_no;
	__u16 flags;
	__u32 reserved;
};
#define ZU_IOC_ALLOC_BUFFER	_IOWR('Z', 17, struct zufs_ioc_init)

/*
 * Execute an iomap in behalf of the Server
 *
 * NOTE: this IOCTL must come on an above ZU_IOC_ALLOC_BUFFER type file
 * and the passed arg-buffer must be the pointer returned from an mmap
 * call preformed in the file, before the call to this IOC.
 * If this is not done the IOCTL will return EINVAL.
 */
struct zufs_ioc_iomap_exec {
	struct zufs_ioc_hdr hdr;
	/* The ID of the super block received in mount */
	__u64	sb_id;
	/* We verify the sb_id validity against zus_sbi */
	struct zus_sb_info *zus_sbi;
	/* If application buffers they are from this IO*/
	__u64	zt_iocontext;
	/* Only return from IOCTL when finished. iomap_done NOT called */
	__u32	wait_for_done;
	__u32	__pad;

	struct zufs_iomap ziom; /* must be last */
};
#define ZU_IOC_IOMAP_EXEC	_IOWR('Z', 18, struct zufs_ioc_iomap_exec)

/*
 * Mount locally with a zus-runner process
 */
#define ZUFS_PMDEV_OPT "zpmdev"
struct zufs_ioc_mount_private {
	struct zufs_ioc_hdr	hdr;
	int			mount_fd; /* kernel cookie */
	struct register_fs_info	rfi;
	struct zufs_mount_info	zmi; /* must be last */
};
#define ZU_IOC_PRIVATE_MOUNT	_IOWR('Z', 19, struct zufs_ioc_mount_private)
#define ZU_IOC_PRIVATE_UMOUNT	_IOWR('Z', 20, struct zufs_ioc_mount_private)
/*
 * ZUFS_OP_READ / ZUFS_OP_WRITE
 *       also
 * ZUFS_OP_GET_BLOCK / ZUFS_OP_PUT_BLOCK
 */
/* flags for gp_block->ret_flags */
enum {
	ZUFS_GBF_RESERVED = 1,	/* Not used */
	ZUFS_GBF_NEW = 2,	/* In write, allocated a new block need unmap */
};

/* zufs_ioc_IO extra write flags */
#define ZUFS_IO_DSYNC	(1 << 0)
#define ZUFS_IO_DIRECT	(1 << 1)
#define ZUFS_IO_RAND	(1 << 2)

struct zufs_ioc_IO {
	struct zufs_ioc_hdr hdr;

	/* IN */
	struct zus_inode_info *zus_ii;
	__u64 filepos;
	__u64 flags;		/* read/write flags IN */

	/* in / OUT */
	union NAMELESS(_IOC_IO_U) {
		/* For reads */
		struct __zufs_ra {
			ulong start;
			__u64 prev_pos;
			__u32 ra_pages;
			__u32 ra_pad; /* we need this*/
		} ra;
		/* For writes */
		struct __zufs_write_unmap {
			__u32  offset;
			__u32  len;
		} wr_unmap;
		struct __zufs_get_put_block {
			__u32 rw;	  /* rw flags also return from GB */
			__u32 ret_flags;  /* One of ZUFS_GBF_XXX */
		} gp_block;
	};

	/* The i_size I saw in this IO. If 0, than error code at .hdr.err */
	__u64 last_pos;

	struct zufs_iomap ziom;
	__u64 iom_e[ZUFS_WRITE_OP_SPACE]; /* One tier_up for WRITE or GB */
};

#endif /* _LINUX_ZUFS_API_H */
