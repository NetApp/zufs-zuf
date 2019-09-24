// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#include <linux/fs.h>
#include <linux/vmalloc.h>
#include "zuf.h"

static int zuf_readdir(struct file *file, struct dir_context *ctx)
{
	return -ENOTSUPP;
}

/*
 *FIXME comment to full git diff
 */

static int _dentry_dispatch(struct inode *dir, struct inode *inode,
			    struct qstr *str, int operation)
{
	struct zufs_ioc_dentry ioc_dentry = {
		.hdr.operation = operation,
		.hdr.in_len = sizeof(ioc_dentry),
		.hdr.out_len = sizeof(ioc_dentry),
		.zus_ii = inode ? ZUII(inode)->zus_ii : NULL,
		.zus_dir_ii = ZUII(dir)->zus_ii,
		.str.len = str->len,
	};
	int err;

	memcpy(&ioc_dentry.str.name, str->name, str->len);

	err = zufc_dispatch(ZUF_ROOT(SBI(dir->i_sb)), &ioc_dentry.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_dbg_err("[%ld] op=%d zufc_dispatch failed => %d\n",
			    dir->i_ino, operation, err);
		return err;
	}

	return 0;
}

/* return pointer to added de on success, err-code on failure */
int zuf_add_dentry(struct inode *dir, struct qstr *str, struct inode *inode)
{
	struct zuf_inode_info *zii = ZUII(dir);
	int err;

	if (!str->len || !zii->zi)
		return -EINVAL;

	zus_inode_cmtime_now(dir, zii->zi);
	err = _dentry_dispatch(dir, inode, str, ZUFS_OP_ADD_DENTRY);
	if (unlikely(err)) {
		zuf_dbg_err("[%ld] _dentry_dispatch failed => %d\n",
			    dir->i_ino, err);
		return err;
	}
	zuf_zii_sync(dir, false);

	return 0;
}

int zuf_remove_dentry(struct inode *dir, struct qstr *str, struct inode *inode)
{
	struct zuf_inode_info *zii = ZUII(dir);
	int err;

	if (!str->len)
		return -EINVAL;

	zus_inode_cmtime_now(dir, zii->zi);
	err = _dentry_dispatch(dir, inode, str, ZUFS_OP_REMOVE_DENTRY);
	if (unlikely(err)) {
		zuf_dbg_err("[%ld] _dentry_dispatch failed => %d\n",
			    dir->i_ino, err);
		return err;
	}
	zuf_zii_sync(dir, false);

	return 0;
}

const struct file_operations zuf_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= zuf_readdir,
	.fsync		= noop_fsync,
};
