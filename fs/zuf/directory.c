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
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	loff_t i_size = i_size_read(inode);
	struct zufs_ioc_readdir ioc_readdir = {
		.hdr.in_len = sizeof(ioc_readdir),
		.hdr.out_len = sizeof(ioc_readdir),
		.hdr.operation = ZUFS_OP_READDIR,
		.dir_ii = ZUII(inode)->zus_ii,
	};
	struct zufs_readdir_iter rdi;
	struct page **pages;
	struct zufs_dir_entry *zde;
	void *addr, *__a;
	uint nump, i;
	int err;

	if (ctx->pos && i_size <= ctx->pos)
		return 0;
	if (!i_size)
		i_size = PAGE_SIZE; /* Just for the . && .. */
	if (i_size - ctx->pos < PAGE_SIZE)
		ioc_readdir.hdr.len = PAGE_SIZE;
	else
		ioc_readdir.hdr.len = min_t(loff_t, i_size - ctx->pos,
					    ZUS_API_MAP_MAX_SIZE);
	nump = md_o2p_up(ioc_readdir.hdr.len);
	/* Allocating both readdir buffer and the pages-array.
	 * Pages array is at end
	 */
	addr = vzalloc(md_p2o(nump) + nump * sizeof(*pages));
	if (unlikely(!addr))
		return -ENOMEM;

	WARN_ON((ulong)addr & (PAGE_SIZE - 1));

	pages = addr + md_p2o(nump);
	__a = addr;
	for (i = 0; i < nump; ++i) {
		pages[i] = vmalloc_to_page(__a);
		__a += PAGE_SIZE;
	}

more:
	ioc_readdir.pos = ctx->pos;

	err = zufc_dispatch(ZUF_ROOT(SBI(sb)), &ioc_readdir.hdr, pages, nump);
	if (unlikely(err && err != -EINTR)) {
		zuf_err_dispatch(sb, "zufc_dispatch failed => %d\n", err);
		goto out;
	}

	zufs_readdir_iter_init(&rdi, &ioc_readdir, addr);
	while ((zde = zufs_next_zde(&rdi)) != NULL) {
		zuf_dbg_verbose("%s pos=0x%lx\n",
				zde->zstr.name, (ulong)zde->pos);
		ctx->pos = zde->pos;
		if (!dir_emit(ctx, zde->zstr.name, zde->zstr.len, zde->ino,
			      zde->type))
			goto out;
	}
	ctx->pos = ioc_readdir.pos;
	if (ioc_readdir.more) {
		zuf_dbg_err("more\n");
		goto more;
	}
out:
	vfree(addr);
	return err;
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
	.unlocked_ioctl = zuf_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= zuf_compat_ioctl,
#endif
};
