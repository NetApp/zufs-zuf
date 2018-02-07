/*
 * Access Control List
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/fs.h>
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>
#include "zuf.h"

/* Originally posix_acl_release
 * The original uses kfree_rcu which is GPL, fine ... sigh
 */
static void non_gpl_acl_release(struct posix_acl *acl)
{
	if (acl && atomic_dec_and_test(&acl->a_refcount))
		kfree(acl);
}

static void _acl_to_value(const struct posix_acl *acl, void *value)
{
	int n;
	struct tozu_acl *macl = value;

	zuf_dbg_acl("acl->count=%d\n", acl->a_count);

	for (n = 0; n < acl->a_count; n++) {
		const struct posix_acl_entry *entry = &acl->a_entries[n];

		zuf_dbg_acl("aclno=%d tag=0x%x perm=0x%x\n",
			     n, entry->e_tag, entry->e_perm);

		macl->tag = cpu_to_le16(entry->e_tag);
		macl->perm = cpu_to_le16(entry->e_perm);

		switch (entry->e_tag) {
		case ACL_USER:
			macl->id = cpu_to_le32(__kuid_val(entry->e_uid));
			break;
		case ACL_GROUP:
			macl->id = cpu_to_le32(__kgid_val(entry->e_gid));
			break;
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			break;
		default:
			zuf_dbg_err("e_tag=0x%x\n", entry->e_tag);
			return;
		}
		macl++;
	}
	return;
}

int tozu_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	char *name = NULL;
	int error;
	size_t size;
	ulong xno = 0;
	struct tozu_xattr *xattr;
	struct zus_inode *zi = ZUII(inode)->zi;

	zuf_dbg_acl("[%ld] acl=%p type=0x%x\n", inode->i_ino, acl, type);

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = XATTR_POSIX_ACL_ACCESS;
		if (acl) {
			error = posix_acl_update_mode(inode, &inode->i_mode,
						      &acl);
			if (error < 0)
				return error;

			inode->i_ctime = CURRENT_TIME;
			timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
		}
		zi->i_mode = cpu_to_le16(inode->i_mode);
		break;
	case ACL_TYPE_DEFAULT:
		name = XATTR_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;
	default:
		return -EINVAL;
	}

	size = acl ? acl->a_count * sizeof(struct tozu_acl) : 0;

	xattr =	tozu_new_xattr(inode->i_sb, X_F_SYSTEM, name, strlen(name),
			       "", size, &xno);
	if (unlikely(IS_ERR(xattr)))
		return (int)PTR_ERR(xattr);

	if (acl)
		_acl_to_value(acl, xattr->data + xattr->name_length);

	error = __tozu_setxattr(inode, X_F_SYSTEM, name, xattr, xno, 0);
	if (!error)
		set_cached_acl(inode, type, acl);

	return error;
}

static struct posix_acl *_value_to_acl(void *value, size_t size)
{
	int n, count;
	struct posix_acl *acl;
	struct tozu_acl *macl = value;
	void *end = value + size;

	if (!value)
		return NULL;

	if (size < 0)
		return ERR_PTR(-EINVAL);

	count = size / sizeof(struct tozu_acl);
	if (count < 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return NULL;

	acl = posix_acl_alloc(count, GFP_NOFS);
	if (unlikely(!acl))
		return ERR_PTR(-ENOMEM);

	for (n = 0; n < count; n++) {
		if (end < (void *)macl + sizeof(struct tozu_acl))
			goto fail;

		zuf_dbg_acl("aclno=%d tag=0x%x perm=0x%x id=0x%x\n",
			     n, le16_to_cpu(macl->tag), le16_to_cpu(macl->perm),
			     le32_to_cpu(macl->id));

		acl->a_entries[n].e_tag  = le16_to_cpu(macl->tag);
		acl->a_entries[n].e_perm = le16_to_cpu(macl->perm);

		switch (acl->a_entries[n].e_tag) {
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			macl++;
			break;
		case ACL_USER:
			acl->a_entries[n].e_uid = KUIDT_INIT(le32_to_cpu(macl->id));
			macl++;
			if (end < (void *)macl)
				goto fail;
			break;
		case ACL_GROUP:
			acl->a_entries[n].e_gid = KGIDT_INIT(le32_to_cpu(macl->id));
			macl++;
			if (end < (void *)macl)
				goto fail;
			break;

		default:
			goto fail;
		}
	}
	if (macl != end)
		goto fail;
	return acl;

fail:
	non_gpl_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

struct posix_acl *tozu_get_acl(struct inode *inode, int type)
{
	struct zuf_inode_info *zii = ZUII(inode);
	char *name = NULL;
	struct posix_acl *acl = NULL;
	struct tozu_xattr *xattr;
	int ret;

	zuf_dbg_acl("[%ld] type=0x%x\n", inode->i_ino, type);

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = XATTR_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name = XATTR_POSIX_ACL_DEFAULT;
		break;
	default:
		BUG();
	}

	zuf_smr_lock(zii);

	ret = __tozu_getxattr(inode, X_F_SYSTEM, name, NULL, 0, &xattr, NULL);
	if (likely(ret > 0)) {
		acl = _value_to_acl(xattr->data + xattr->name_length, ret);
	} else if (ret != -ENODATA) {
		if (ret != 0)
			zuf_err("failed to getattr ret=%d\n", ret);
		acl = ERR_PTR(ret);
	}

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	zuf_smr_unlock(zii);
	return acl;
}

/* Used by creation of new inodes */
int tozu_acls_create(struct inode *dir, struct inode *inode)
{
	struct posix_acl *acl;
	int err;

	zuf_dbg_acl("[%ld] i_ino=%ld i_mode=o%o\n",
		     dir->i_ino, inode->i_ino, inode->i_mode);

	if (S_ISLNK(inode->i_mode))
		return 0;

	acl = tozu_get_acl(dir, ACL_TYPE_DEFAULT);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (!acl) {
		inode->i_mode &= ~current_umask();
		return 0;
	}

	if (S_ISDIR(inode->i_mode)) {
		err = tozu_set_acl(inode, acl, ACL_TYPE_DEFAULT);
		if (err)
			goto cleanup;
	}
	err = __posix_acl_create(&acl, GFP_NOFS, &inode->i_mode);
	if (unlikely(err < 0))
		return err;

	if (err > 0) /* This is an extended ACL */
		err = tozu_set_acl(inode, acl, ACL_TYPE_ACCESS);

cleanup:
	non_gpl_acl_release(acl);
	return err;
}

/* ~~~~ The ACL xattr handler ~~~~ */

/* Originaly posix_acl_xattr_get */
static int
tozu_acl_xattr_get(const struct xattr_handler *handler,
		   struct dentry *dentry, struct inode *inode,
		   const char *name, void *value, size_t size)
{
	struct super_block *sb = inode->i_sb;
	struct posix_acl *acl;
	int err;

	if (!IS_POSIXACL(inode))
		return -EOPNOTSUPP;
	if (d_is_symlink(dentry))
		return -EOPNOTSUPP;

	acl = get_acl(inode, handler->flags);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;

	err = posix_acl_to_xattr(sb->s_user_ns, acl, value, size);
	non_gpl_acl_release(acl);

	return err;
}

/* Originaly posix_acl_xattr_set */
static int
tozu_acl_xattr_set(const struct xattr_handler *handler, struct dentry *__d,
		   struct inode *inode, const char *name, const void *value,
		   size_t size, int flags)
{
	struct posix_acl *acl = NULL;
	int err;

	if (!IS_POSIXACL(inode))
		return -EOPNOTSUPP;

	if (handler->flags == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode))
		return value ? -EACCES : 0;

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (value) {
		acl = posix_acl_from_xattr(inode->i_sb->s_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);

		if (acl) {
			err = posix_acl_valid(inode->i_sb->s_user_ns, acl);
			if (unlikely(err))
				goto out;
		}
	}

	err = tozu_set_acl(inode, acl, handler->flags);
out:
	non_gpl_acl_release(acl);
	return err;
}

/* Originaly posix_acl_xattr_list */
static bool tozu_acl_xattr_list(struct dentry *dentry)
{
	return IS_POSIXACL(d_backing_inode(dentry));
}

const struct xattr_handler tozu_acl_access_xattr_handler = {
	.name	= XATTR_NAME_POSIX_ACL_ACCESS,
	.flags	= ACL_TYPE_ACCESS,
	.list	= tozu_acl_xattr_list,
	.get	= tozu_acl_xattr_get,
	.set	= tozu_acl_xattr_set,
};

const struct xattr_handler tozu_acl_default_xattr_handler = {
	.name	= XATTR_NAME_POSIX_ACL_DEFAULT,
	.flags	= ACL_TYPE_DEFAULT,
	.list	= tozu_acl_xattr_list,
	.get	= tozu_acl_xattr_get,
	.set	= tozu_acl_xattr_set,
};
