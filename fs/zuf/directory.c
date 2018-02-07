/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
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
		.hdr.operation = ZUS_OP_READDIR,
		.dir_ii = ZUII(inode)->zus_ii,
	};
	struct zufs_readdir_iter rdi;
	struct page *pages[ZUS_API_MAP_MAX_PAGES];
	struct zufs_dir_entry *zde;
	void *addr, *__a;
	uint nump, i;
	int err;

	if (ctx->pos && i_size <= ctx->pos)
		return 0;
	if (!i_size)
		i_size = PAGE_SIZE; /* Just for the . && .. */

	ioc_readdir.hdr.len = min_t(loff_t, i_size - ctx->pos,
				    ZUS_API_MAP_MAX_SIZE);
	nump = zuf_o2p_up(ioc_readdir.hdr.len);
	addr = vzalloc(zuf_p2o(nump));
	if (unlikely(!addr))
		return -ENOMEM;

	WARN_ON((ulong)addr & (PAGE_SIZE - 1));

	__a = addr;
	for (i = 0; i < nump; ++i) {
		pages[i] = vmalloc_to_page(__a);
		__a += PAGE_SIZE;
	}

more:
	ioc_readdir.pos = ctx->pos;

	err = zufs_dispatch(ZUF_ROOT(SBI(sb)), &ioc_readdir.hdr, pages, nump);
	if (unlikely(err)) {
		zuf_err("zufs_dispatch failed => %d\n", err);
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
zuf_err("more\n");
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

	err = zufs_dispatch(ZUF_ROOT(SBI(dir->i_sb)), &ioc_dentry.hdr, NULL, 0);
	if (unlikely(err)) {
		zuf_err("op=%d zufs_dispatch failed => %d\n", operation, err);
		return err;
	}

	return 0;
}

/* return pointer to added de on success, err-code on failure */
int zuf_add_dentry(struct inode *dir, struct qstr *str, struct inode *inode,
		   bool rename)
{
	struct zuf_inode_info *zii = ZUII(dir);
	int err;

	if (!str->len || !zii->zi)
		return -EINVAL;

	zus_inode_cmtime_now(dir, zii->zi);
	err = _dentry_dispatch(dir, inode, str, ZUS_OP_ADD_DENTRY);
	if (unlikely(err)) {
		zuf_err("_dentry_dispatch failed => %d\n", err);
		return err;
	}
	i_size_write(dir, le64_to_cpu(zii->zi->i_size));

	return 0;
}

int zuf_remove_dentry(struct inode *dir, struct qstr *str)
{
	struct zuf_inode_info *zii = ZUII(dir);
	int err;

	if (!str->len)
		return -EINVAL;

	zus_inode_cmtime_now(dir, zii->zi);
	err = _dentry_dispatch(dir, NULL, str, ZUS_OP_REMOVE_DENTRY);
	if (unlikely(err))
		return err;

	i_size_write(dir, le64_to_cpu(zii->zi->i_size));
	return 0;
}

const struct file_operations tozu_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= zuf_readdir,
	.fsync		= noop_fsync,
	.unlocked_ioctl = tozu_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= tozu_compat_ioctl,
#endif
};
