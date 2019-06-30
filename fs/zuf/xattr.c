// SPDX-License-Identifier: GPL-2.0
/*
 * Extended Attributes
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/fs.h>
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>

#include "zuf.h"

/* ~~~~~~~~~~~~~~~ xattr get ~~~~~~~~~~~~~~~ */

struct _xxxattr {
	void *user_buffer;
	union {
		struct zufs_ioc_xattr ioc_xattr;
		char buf[512];
	} d;
};

static inline uint _XXXATTR_SIZE(uint ioc_size)
{
	struct _xxxattr *_xxxattr;

	return ioc_size + (sizeof(*_xxxattr) - sizeof(_xxxattr->d));
}

static int _xattr_oh(struct zuf_dispatch_op *zdo, void *parg, ulong max_bytes)
{
	struct zufs_ioc_hdr *hdr = zdo->hdr;
	struct zufs_ioc_xattr *ioc_xattr =
			container_of(hdr, typeof(*ioc_xattr), hdr);
	struct _xxxattr *_xxattr =
			container_of(ioc_xattr, typeof(*_xxattr), d.ioc_xattr);
	struct zufs_ioc_xattr *user_ioc_xattr = parg;

	if (hdr->err)
		return 0;

	ioc_xattr->user_buf_size = user_ioc_xattr->user_buf_size;

	hdr->out_len -= sizeof(ioc_xattr->user_buf_size);
	memcpy(_xxattr->user_buffer, user_ioc_xattr->buf, hdr->out_len);
	return 0;
}

ssize_t __zuf_getxattr(struct inode *inode, int type, const char *name,
		       void *buffer, size_t size)
{
	size_t name_len = strlen(name) + 1; /* plus \NUL */
	struct _xxxattr *p_xattr;
	struct _xxxattr s_xattr;
	enum big_alloc_type bat;
	struct zufs_ioc_xattr *ioc_xattr;
	size_t ioc_size = sizeof(*ioc_xattr) + name_len;
	struct zuf_dispatch_op zdo;
	int err;
	ssize_t ret;

	zuf_dbg_vfs("[%ld] type=%d name=%s size=%lu ioc_size=%lu\n",
			inode->i_ino, type, name, size, ioc_size);

	p_xattr = big_alloc(_XXXATTR_SIZE(ioc_size), sizeof(s_xattr), &s_xattr,
			    GFP_KERNEL, &bat);
	if (unlikely(!p_xattr))
		return -ENOMEM;

	ioc_xattr = &p_xattr->d.ioc_xattr;
	memset(ioc_xattr, 0, sizeof(*ioc_xattr));
	p_xattr->user_buffer = buffer;

	ioc_xattr->hdr.in_len = ioc_size;
	ioc_xattr->hdr.out_start =
				offsetof(struct zufs_ioc_xattr, user_buf_size);
	 /* out_len updated by zus */
	ioc_xattr->hdr.out_len = sizeof(ioc_xattr->user_buf_size);
	ioc_xattr->hdr.out_max = 0;
	ioc_xattr->hdr.operation = ZUFS_OP_XATTR_GET;
	ioc_xattr->zus_ii = ZUII(inode)->zus_ii;
	ioc_xattr->type = type;
	ioc_xattr->name_len = name_len;
	ioc_xattr->user_buf_size = size;

	strcpy(ioc_xattr->buf, name);

	zuf_dispatch_init(&zdo, &ioc_xattr->hdr, NULL, 0);
	zdo.oh = _xattr_oh;
	err = __zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &zdo);
	ret = ioc_xattr->user_buf_size;

	big_free(p_xattr, bat);

	if (unlikely(err))
		return err;

	return ret;
}

/* ~~~~~~~~~~~~~~~ xattr set ~~~~~~~~~~~~~~~ */

int __zuf_setxattr(struct inode *inode, int type, const char *name,
		   const void *value, size_t size, int flags)
{
	size_t name_len = strlen(name) + 1;
	struct _xxxattr *p_xattr;
	struct _xxxattr s_xattr;
	enum big_alloc_type bat;
	struct zufs_ioc_xattr *ioc_xattr;
	size_t ioc_size = sizeof(*ioc_xattr) + name_len + size;
	int err;

	zuf_dbg_vfs("[%ld] type=%d name=%s size=%lu ioc_size=%lu\n",
			inode->i_ino, type, name, size, ioc_size);

	p_xattr = big_alloc(_XXXATTR_SIZE(ioc_size), sizeof(s_xattr), &s_xattr,
			    GFP_KERNEL, &bat);
	if (unlikely(!p_xattr))
		return -ENOMEM;

	ioc_xattr = &p_xattr->d.ioc_xattr;
	memset(ioc_xattr, 0, sizeof(*ioc_xattr));

	ioc_xattr->hdr.in_len = ioc_size;
	ioc_xattr->hdr.out_len = 0;
	ioc_xattr->hdr.operation = ZUFS_OP_XATTR_SET;
	ioc_xattr->zus_ii = ZUII(inode)->zus_ii;
	ioc_xattr->type = type;
	ioc_xattr->name_len = name_len;
	ioc_xattr->user_buf_size = size;
	ioc_xattr->flags = flags;

	if (value && !size)
		ioc_xattr->ioc_flags = ZUFS_XATTR_SET_EMPTY;

	strcpy(ioc_xattr->buf, name);
	if (value)
		memcpy(ioc_xattr->buf + name_len, value, size);

	err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_xattr->hdr,
			    NULL, 0);

	big_free(p_xattr, bat);

	return err;
}

/* ~~~~~~~~~~~~~~~ xattr list ~~~~~~~~~~~~~~~ */

static ssize_t __zuf_listxattr(struct inode *inode, char *buffer, size_t size)
{
	struct zuf_inode_info *zii = ZUII(inode);
	struct _xxxattr s_xattr;
	struct zufs_ioc_xattr *ioc_xattr;
	struct zuf_dispatch_op zdo;

	int err;

	zuf_dbg_vfs("[%ld] size=%lu\n", inode->i_ino, size);

	ioc_xattr = &s_xattr.d.ioc_xattr;
	memset(ioc_xattr, 0, sizeof(*ioc_xattr));
	s_xattr.user_buffer = buffer;

	ioc_xattr->hdr.in_len = sizeof(*ioc_xattr);
	ioc_xattr->hdr.out_start =
				offsetof(struct zufs_ioc_xattr, user_buf_size);
	 /* out_len updated by zus */
	ioc_xattr->hdr.out_len = sizeof(ioc_xattr->user_buf_size);
	ioc_xattr->hdr.out_max = 0;
	ioc_xattr->hdr.operation = ZUFS_OP_XATTR_LIST;
	ioc_xattr->zus_ii = zii->zus_ii;
	ioc_xattr->name_len = 0;
	ioc_xattr->user_buf_size = size;
	ioc_xattr->ioc_flags = capable(CAP_SYS_ADMIN) ? ZUFS_XATTR_TRUSTED : 0;

	zuf_dispatch_init(&zdo, &ioc_xattr->hdr, NULL, 0);
	zdo.oh = _xattr_oh;
	err = __zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &zdo);
	if (unlikely(err))
		return err;

	return ioc_xattr->user_buf_size;
}

ssize_t zuf_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct zuf_inode_info *zii = ZUII(inode);
	ssize_t ret;

	zuf_xar_lock(zii);

	ret = __zuf_listxattr(inode, buffer, size);

	zuf_xar_unlock(zii);

	return ret;
}

/* ~~~~~~~~~~~~~~~ xattr sb handlers ~~~~~~~~~~~~~~~ */
static bool zuf_xattr_handler_list(struct dentry *dentry)
{
	return true;
}

static
int zuf_xattr_handler_get(const struct xattr_handler *handler,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, void *value, size_t size)
{
	struct zuf_inode_info *zii = ZUII(inode);
	int ret;

	zuf_dbg_xattr("[%ld] name=%s\n", inode->i_ino, name);

	zuf_xar_lock(zii);

	ret = __zuf_getxattr(inode, handler->flags, name, value, size);

	zuf_xar_unlock(zii);

	return ret;
}

static
int zuf_xattr_handler_set(const struct xattr_handler *handler,
			  struct dentry *d_notused, struct inode *inode,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	struct zuf_inode_info *zii = ZUII(inode);
	int err;

	zuf_dbg_xattr("[%ld] name=%s size=0x%lx flags=0x%x\n",
			inode->i_ino, name, size, flags);

	zuf_xaw_lock(zii);

	err = __zuf_setxattr(inode, handler->flags, name, value, size, flags);

	zuf_xaw_unlock(zii);

	return err;
}

const struct xattr_handler zuf_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.flags = ZUF_XF_SECURITY,
	.list	= zuf_xattr_handler_list,
	.get	= zuf_xattr_handler_get,
	.set	= zuf_xattr_handler_set,
};

const struct xattr_handler zuf_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.flags = ZUF_XF_TRUSTED,
	.list	= zuf_xattr_handler_list,
	.get	= zuf_xattr_handler_get,
	.set	= zuf_xattr_handler_set,
};

const struct xattr_handler zuf_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.flags = ZUF_XF_USER,
	.list	= zuf_xattr_handler_list,
	.get	= zuf_xattr_handler_get,
	.set	= zuf_xattr_handler_set,
};

const struct xattr_handler *zuf_xattr_handlers[] = {
	&zuf_xattr_user_handler,
	&zuf_xattr_trusted_handler,
	&zuf_xattr_security_handler,
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
	NULL
};

/*
 * Callback for security_inode_init_security() for acquiring xattrs.
 */
int zuf_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		   void *fs_info)
{
	const struct xattr *xattr;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		int err;

		/* REMOVEME: We had a BUG here for a long time that never
		 * crashed, I want to see this is called, please.
		 */
		zuf_warn("Yes it is name=%s value-size=%zd\n",
			  xattr->name, xattr->value_len);

		err = zuf_xattr_handler_set(&zuf_xattr_security_handler, NULL,
					    inode, xattr->name, xattr->value,
					    xattr->value_len, 0);
		if (unlikely(err)) {
			zuf_err("[%ld] failed to init xattrs err=%d\n",
				 inode->i_ino, err);
			return err;
		}
	}
	return 0;
}
