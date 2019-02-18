// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Symlink operations
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

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

/*
 * In case of short symlink, we serve it directly from zi; otherwise, read
 * symlink value directly from pmem using dpp mapping.
 */
static const char *zuf_get_link(struct dentry *dentry, struct inode *inode,
				struct delayed_call *notused)
{
	const char *link;
	struct zuf_inode_info *zii = ZUII(inode);

	if (inode->i_size < sizeof(zii->zi->i_symlink))
		return zii->zi->i_symlink;

	link = zuf_dpp_t_addr(inode->i_sb, le64_to_cpu(zii->zi->i_sym_dpp));
	if (!link) {
		zuf_err("bad symlink: i_sym_dpp=0x%llx\n", zii->zi->i_sym_dpp);
		return ERR_PTR(-EIO);
	}
	return link;
}

const struct inode_operations zuf_symlink_inode_operations = {
	.get_link	= zuf_get_link,
	.update_time	= zuf_update_time,
	.setattr	= zuf_setattr,
	.getattr	= zuf_getattr,
};
