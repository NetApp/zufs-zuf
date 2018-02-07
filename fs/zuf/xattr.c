/*
 * Extended Attributes
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/xattr.h>
#include "zuf.h"

#if 0
static struct __xattr_type {
	const char *prefix;
	size_t	prefix_len;
} xattrs[] = {
	[X_F_SECURITY]	= {XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN},
	[X_F_SYSTEM]	= {XATTR_SYSTEM_PREFIX,	  XATTR_SYSTEM_PREFIX_LEN},
	[X_F_TRUSTED]	= {XATTR_TRUSTED_PREFIX,  XATTR_TRUSTED_PREFIX_LEN},
	[X_F_USER]	= {XATTR_USER_PREFIX,	  XATTR_USER_PREFIX_LEN},
};

/* ~~~~~~~~~~~~~~~ xattr helpers ~~~~~~~~~~~~~~~ */
static void _copy_value_to_buf(void *buffer, struct tozu_xattr *xattr)
{
	memcpy(buffer, xattr->data + le16_to_cpu(xattr->name_length),
	       le16_to_cpu(xattr->value_size));
}

static bool _xattr_matches_name(struct tozu_xattr *xattr, int xtype,
				const char *name)
{
	size_t name_len = strlen(name);

	if ((xtype != xattr->type) ||
	    (name_len != le16_to_cpu(xattr->name_length)))
		return false;

	if (0 != strncmp(name, xattr->data, xattr->name_length))
		return false;

	return true;
}

static void _copy_full_name(char *buffer, struct __xattr_type *xt,
			    struct tozu_xattr *xattr)
{
	memcpy(buffer, xt->prefix, xt->prefix_len);
	memcpy(buffer + xt->prefix_len, xattr->data, xattr->name_length);
	buffer[xt->prefix_len + xattr->name_length] = '\0';
}

#endif
/* ~~~~~~~~~~~~~~~ xattr get ~~~~~~~~~~~~~~~ */

ssize_t __tozu_getxattr(struct inode *inode, int type, const char *name,
			void *buffer, size_t size,
			struct tozu_xattr **xattr_out,
			struct tozu_xattr **pprev)
{
	struct zus_inode *zi = zus_zi(inode);
	int ret = -ENODATA;

	zuf_dbg_err("[%ld] inode-%p zi-%p i_xattr=0x%llx\n",
		    inode->i_ino, inode, zi, zi ? zi->i_xattr : 0);

	/*TOZU:
	 * zus_despatch_xattr_get()
	 */
	return ret;

}

/* ~~~~~~~~~~~~~~~ xattr set ~~~~~~~~~~~~~~~ */

struct tozu_xattr *tozu_new_xattr(struct super_block *sb, int type,
				  const char *name, size_t length,
				  const void *value, size_t size, ulong *xno)
{
	struct tozu_xattr *xattr = ERR_PTR(-ENOSYS);

	/*FIXME:
	 * zus_despatch_xattr_set()
	 * Should only be used by acl (See about locking)
	 */

	return xattr;
}

/* Kernel has this funny API and this is both a set or a delete, actually more
 * like an exchange and/or delete.
 *
 * In any case we delete [type,name] if found then
 * If new_xattr/new_xno is not empty we insert it in the link list
 */
int __tozu_setxattr(struct inode *inode, int type, const char *name,
		    struct tozu_xattr *new_xattr, ulong new_xno, int flags)
{
	struct zuf_inode_info *zii = ZUII(inode);
	int err = -ENOSYS;

	zuf_dbg_xattr("[%ld] name=%s new_xattr=%p new_xno=0x%lx f=0x%x\n",
		       inode->i_ino, name, new_xattr, new_xno, flags);

	zuf_smw_lock(zii);

	/*TOZU:
	 * zus_despatch_xattr_set()
	 * We take a lock here to prevent deletes
	 */

	zuf_smw_unlock(zii);
	return err;
}

/* ~~~~~~~~~~~~~~~ xattr list ~~~~~~~~~~~~~~~ */

ssize_t tozu_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct zuf_inode_info *zii = ZUII(inode);
	struct zus_inode *zi = zus_zi(inode);
	ssize_t used = -ENOSYS;

	zuf_dbg_xattr("[%ld] i_xattr=0x%llx\n",
			inode->i_ino, zi ? zi->i_xattr: 0);

	zuf_smr_lock(zii);

	/*TOZU:
	 * zus_despatch_xattr_list()
	 * We take a lock here to prevent deletes
	 */

	zuf_smr_unlock(zii);

	return used;
}

/* ~~~~~~~~~~~~~~~ xattr sb handlers ~~~~~~~~~~~~~~~ */
static bool tozu_xattr_handler_list(struct dentry *dentry)
{
	return true;
}

static
int tozu_xattr_handler_get(const struct xattr_handler *handler,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, void *value, size_t size)
{
	struct zuf_inode_info *zii = ZUII(inode);
	int ret;

	zuf_dbg_xattr("[%ld] name=%s\n", inode->i_ino, name);

	zuf_smr_lock(zii);
	ret = __tozu_getxattr(inode, handler->flags, name, value, size,
			       NULL, NULL);
	zuf_smr_unlock(zii);
	return ret;
}

int tozu_xattr_handler_set(const struct xattr_handler *handler,
			   struct dentry *d_notused, struct inode *inode,
			   const char *name, const void *value, size_t size,
			   int flags)
{
	ulong xno = 0;
	struct tozu_xattr *xattr = NULL;

	zuf_dbg_xattr("[%ld] name=%s size=0x%lx flags=0x%x\n",
			inode->i_ino, name, size, flags);

	/*FIXME:
	 * Model need to change new_xattr + set_xattr needs to be the
	 * on zus_despatch_xattr_set call.
	 * (For now just make it compile, it is all off)
	 */

	if (value) {
		xattr = tozu_new_xattr(inode->i_sb, handler->flags, name,
				       strlen(name), value, size, &xno);
		if (unlikely(IS_ERR(xattr)))
			return PTR_ERR(xattr);

		zuf_dbg_xattr("[%ld] new_xattr=%p num=0x%lx\n",
				inode->i_ino, xattr, xno);
	}

	return __tozu_setxattr(inode, handler->flags, name, xattr, xno, flags);
}

const struct xattr_handler tozu_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.flags = X_F_SECURITY,
	.list	= tozu_xattr_handler_list,
	.get	= tozu_xattr_handler_get,
	.set	= tozu_xattr_handler_set,
};

const struct xattr_handler tozu_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.flags = X_F_TRUSTED,
	.list	= tozu_xattr_handler_list,
	.get	= tozu_xattr_handler_get,
	.set	= tozu_xattr_handler_set,
};

const struct xattr_handler tozu_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.flags = X_F_USER,
	.list	= tozu_xattr_handler_list,
	.get	= tozu_xattr_handler_get,
	.set	= tozu_xattr_handler_set,
};

const struct xattr_handler *tozu_xattr_handlers[] = {
	&tozu_xattr_user_handler,
	&tozu_xattr_trusted_handler,
	&tozu_xattr_security_handler,
	&tozu_acl_access_xattr_handler,
	&tozu_acl_default_xattr_handler,
	NULL
};

/*
 * Callback for security_inode_init_security() for acquiring xattrs.
 */
int tozu_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		    void *fs_info)
{
	const struct xattr *xattr;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		int err;

		/* REMOVEME: We had a BUG for a long time here I want to see
		 * this please
		 */
		zuf_warn("Yes it is name=%s value-size=%zd\n",
			  xattr->name, xattr->value_len);

		err = tozu_xattr_handler_set(&tozu_xattr_security_handler, NULL,
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
