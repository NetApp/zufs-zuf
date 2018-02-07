/*
 * BRIEF DESCRIPTION
 *
 * Symlink operations
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#include <linux/fs.h>

#include "zuf.h"

/* Can never fail all checks already made before.
 * Returns: The number of pages stored @pages
 */
uint zuf_prepare_symname(struct zufs_ioc_new_inode *ioc_new_inode,
			 const char *symname, ulong len,
			 struct page *pages[2])
{
	uint nump;

	ioc_new_inode->zi.i_size = cpu_to_le64(len);
	if (len < sizeof(ioc_new_inode->zi.i_symlink)) {
		memcpy(&ioc_new_inode->zi.i_symlink, symname, len);
		return 0;
	}

	pages[0] = virt_to_page(symname);
	nump = 1;

	ioc_new_inode->hdr.len = len;
	ioc_new_inode->hdr.offset = (ulong)symname & (PAGE_SIZE - 1);

	if (PAGE_SIZE < ioc_new_inode->hdr.offset + len) {
		pages[1] = virt_to_page(symname + PAGE_SIZE);
		++nump;
	}

	return nump;
}

static const char *zuf_get_link(struct dentry *dentry, struct inode *inode,
				struct delayed_call *notused)
{
	struct zuf_inode_info *zii = ZUII(inode);
	struct zufs_ioc_get_link ioc_get_link = {
		.hdr.in_len = sizeof(ioc_get_link),
		.hdr.out_len = sizeof(ioc_get_link),
		.hdr.operation = ZUS_OP_GET_SYMLINK,
		.zus_ii = zii->zus_ii,
	};
	int err;

	if (inode->i_size < sizeof(zii->zi->i_symlink))
		return zii->zi->i_symlink;

	err = zufs_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_get_link.hdr,
			    NULL, 0);
	if (unlikely(err)) {
		zuf_err("zufs_dispatch failed => %d\n", err);
		return ERR_PTR(err);
	}

	return md_addr(SBI(inode->i_sb)->md, ioc_get_link._link);
}

const struct inode_operations zuf_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.get_link	= zuf_get_link,
	.update_time	= zuf_update_time,
	.setattr	= zuf_setattr,
	.listxattr	= tozu_listxattr,
#ifdef BACKPORT_NEED_I_OPT_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
#endif
};
