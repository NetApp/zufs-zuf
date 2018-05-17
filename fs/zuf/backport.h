/*
 * Backport include file
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#ifndef __ZUF_BACKPORT_H__
#define __ZUF_BACKPORT_H__

/*
 * DO NOT INCLUDE this file directly, it is included by zuf.h
 */

#define BACKPORT_NEED_I_OPT_XATTR
#define BACKPORT_NO_RW_ITER
#define BACKPORT_OLD_DIRECT_IO
#define BACKPORT_EXTEND_FILE_OPS
#define BACKPORT_GETATTR
#define BACKPORT_NO_SETACL
#define BACKPORT_OLD_RENAME
#define BACKPORT_INODE_OPS_WRAPPER
#define BACKPORT_FOLLOW_LINK
#define BACKPORT_XATTR_HANDLER
#define BACKPORT_READDIR_ITERATE

#define SB_POSIXACL	MS_POSIXACL

static inline int _compat_generic_write_checks(struct kiocb *kiocb,
					       struct iov_iter *ii)
{
	return generic_write_checks(kiocb->ki_filp, &kiocb->ki_pos,
				    &ii->count, 0);
}

typedef int vm_fault_t;

static inline
int vm_fault_t_return(int err)
{
	if (err == 0 || err == -EBUSY)
		return VM_FAULT_NOPAGE;
	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	return VM_FAULT_SIGBUS;
}

static inline
vm_fault_t vmf_insert_mixed(struct vm_area_struct *vma, unsigned long addr,
			pfn_t pfn)
{
	int err;

	err = vm_insert_mixed(vma, addr, pfn);

	return vm_fault_t_return(err);
}

static inline
vm_fault_t vmf_insert_mixed_mkwrite(struct vm_area_struct *vma,
		unsigned long addr, pfn_t pfn)
{
	int err;

	err = vm_insert_mixed(vma, addr, pfn);

	return vm_fault_t_return(err);
}

#define __posix_acl_create posix_acl_create
#define posix_acl_valid(ns, acl) posix_acl_valid(acl)

#define current_time(inode) CURRENT_TIME

#endif /* ifndef __ZUF_BACKPORT_H__ */
