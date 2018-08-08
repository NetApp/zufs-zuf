// SPDX-License-Identifier: GPL-2.0
/*
 * Access Control List
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

static void _acl_to_value(const struct posix_acl *acl, void *value)
{
	int n;
	struct zuf_acl *macl = value;

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
}

int zuf_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	char *name = NULL;
	void *buf;
	int err;
	size_t size;

	zuf_dbg_acl("[%ld] acl=%p type=0x%x\n", inode->i_ino, acl, type);

	switch (type) {
	case ACL_TYPE_ACCESS: {
		struct zus_inode *zi = ZUII(inode)->zi;

		name = XATTR_POSIX_ACL_ACCESS;
		if (acl) {
			err = posix_acl_update_mode(inode, &inode->i_mode,
						    &acl);
			if (err < 0)
				return err;

			inode->i_ctime = current_time(inode);
			timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
		}
		zi->i_mode = cpu_to_le16(inode->i_mode);
		break;
	}
	case ACL_TYPE_DEFAULT:
		name = XATTR_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;
	default:
		return -EINVAL;
	}

	size = acl ? acl->a_count * sizeof(struct zuf_acl) : 0;
	buf = kmalloc(size, GFP_KERNEL);
	if (unlikely(!buf))
		return -ENOMEM;

	if (acl)
		_acl_to_value(acl, buf);

	err = __zuf_setxattr(inode, ZUF_XF_SYSTEM, name, buf, size, 0);
	if (!err)
		set_cached_acl(inode, type, acl);

	kfree(buf);
	return err;
}

static struct posix_acl *_value_to_acl(void *value, size_t size)
{
	int n, count;
	struct posix_acl *acl;
	struct zuf_acl *macl = value;
	void *end = value + size;

	if (!value)
		return NULL;

	count = size / sizeof(struct zuf_acl);
	if (count < 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return NULL;

	acl = posix_acl_alloc(count, GFP_NOFS);
	if (unlikely(!acl))
		return ERR_PTR(-ENOMEM);

	for (n = 0; n < count; n++) {
		if (end < (void *)macl + sizeof(struct zuf_acl))
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
			acl->a_entries[n].e_uid =
					     KUIDT_INIT(le32_to_cpu(macl->id));
			macl++;
			if (end < (void *)macl)
				goto fail;
			break;
		case ACL_GROUP:
			acl->a_entries[n].e_gid =
					     KGIDT_INIT(le32_to_cpu(macl->id));
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
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

struct posix_acl *zuf_get_acl(struct inode *inode, int type)
{
	struct zuf_inode_info *zii = ZUII(inode);
	char *name = NULL;
	void *buf;
	struct posix_acl *acl = NULL;
	int ret;

	zuf_dbg_acl("[%ld] type=0x%x\n", inode->i_ino, type);

	buf = (void *)__get_free_page(GFP_KERNEL);
	if (unlikely(!buf))
		return ERR_PTR(-ENOMEM);

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = XATTR_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name = XATTR_POSIX_ACL_DEFAULT;
		break;
	default:
		WARN_ON(1);
		return ERR_PTR(-EINVAL);
	}

	zuf_smr_lock(zii);

	ret = __zuf_getxattr(inode, ZUF_XF_SYSTEM, name, buf, PAGE_SIZE);
	if (likely(ret > 0)) {
		acl = _value_to_acl(buf, ret);
	} else if (ret != -ENODATA) {
		if (ret != 0)
			zuf_dbg_err("failed to getattr ret=%d\n", ret);
		acl = ERR_PTR(ret);
	}

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	zuf_smr_unlock(zii);

	free_page((ulong)buf);

	return acl;
}

/* Used by creation of new inodes */
int zuf_acls_create_pre(struct inode *dir, struct inode *inode,
			struct posix_acl **user_acl)
{
	struct posix_acl *acl;

	if (!IS_POSIXACL(dir))
		return 0;

	zuf_dbg_acl("[%ld] i_ino=%ld i_mode=o%o\n",
		     dir->i_ino, inode->i_ino, inode->i_mode);

	if (S_ISLNK(inode->i_mode))
		return 0;

	acl = get_acl(dir, ACL_TYPE_DEFAULT);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (!acl)
		inode->i_mode &= ~current_umask();
	else
		*user_acl = acl;

	return 0;
}

int zuf_acls_create_post(struct inode *dir, struct inode *inode,
			 struct posix_acl *acl)
{
	int err;

	zuf_dbg_acl("[%ld] i_ino=%ld i_mode=o%o\n",
		     dir->i_ino, inode->i_ino, inode->i_mode);

	if (S_ISDIR(inode->i_mode)) {
		err = zuf_set_acl(inode, acl, ACL_TYPE_DEFAULT);
		if (err)
			goto cleanup;
	}
	err = __posix_acl_create(&acl, GFP_NOFS, &inode->i_mode);
	if (unlikely(err < 0))
		return err;

	zus_zi(inode)->i_mode = cpu_to_le16(inode->i_mode);
	if (err > 0) { /* This is an extended ACL */
		err = zuf_set_acl(inode, acl, ACL_TYPE_ACCESS);
	} else {
		/* NOTE: Boaz think we will cry over this... */
		struct zufs_ioc_attr ioc_attr = {
			.hdr.in_len = sizeof(ioc_attr),
			.hdr.out_len = sizeof(ioc_attr),
			.hdr.operation = ZUFS_OP_SETATTR,
			.zus_ii = ZUII(inode)->zus_ii,
			.zuf_attr = STATX_MODE,
		};

		err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)),
				    &ioc_attr.hdr, NULL, 0);
		if (unlikely(err && err != -EINTR))
			zuf_err("zufc_dispatch failed => %d\n", err);
	}

cleanup:
	posix_acl_release(acl);
	return err;
}

#ifdef BACKPORT_XATTR_HANDLER

static size_t
zuf_acl_xattr_list_access(struct dentry *dentry, char *list, size_t list_len,
			  const char *name, size_t name_len, int type)
{
	const size_t size = sizeof(POSIX_ACL_XATTR_ACCESS);

	if (!IS_POSIXACL(dentry->d_inode))
		return 0;
	if (list && size <= list_len)
		memcpy(list, POSIX_ACL_XATTR_ACCESS, size);
	return size;
}

static size_t
zuf_acl_xattr_list_default(struct dentry *dentry, char *list, size_t list_len,
			   const char *name, size_t name_len, int type)
{
	const size_t size = sizeof(POSIX_ACL_XATTR_DEFAULT);

	if (!IS_POSIXACL(dentry->d_inode))
		return 0;
	if (list && size <= list_len)
		memcpy(list, POSIX_ACL_XATTR_DEFAULT, size);
	return size;
}

static int
zuf_acl_xattr_get(struct dentry *dentry, const char *name, void *buffer,
		  size_t size, int type)
{
	struct posix_acl *acl;
	int err;

	if (strcmp(name, "") != 0)
		return -EINVAL;
	if (!IS_POSIXACL(dentry->d_inode))
		return -EOPNOTSUPP;

	acl = zuf_get_acl(dentry->d_inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;
	err = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
	posix_acl_release(acl);

	return err;
}

static int
zuf_acl_xattr_set(struct dentry *dentry, const char *name, const void *value,
		  size_t size, int flags, int type)
{
	struct inode *inode = dentry->d_inode;
	struct posix_acl *acl;
	int err;

	if (strcmp(name, "") != 0)
		return -EINVAL;
	if (!IS_POSIXACL(dentry->d_inode))
		return -EOPNOTSUPP;
	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (value) {
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		else if (acl) {
			err = posix_acl_valid(inode->i_sb->s_user_ns, acl);
			if (err)
				goto release_and_out;
		}
	} else
		acl = NULL;

	err = zuf_set_acl(inode, acl, type);

release_and_out:
	posix_acl_release(acl);
	return err;
}

const struct xattr_handler zuf_acl_access_xattr_handler = {
	.prefix = POSIX_ACL_XATTR_ACCESS,
	.flags	= ACL_TYPE_ACCESS,
	.list	= zuf_acl_xattr_list_access,
	.get	= zuf_acl_xattr_get,
	.set	= zuf_acl_xattr_set,
};

const struct xattr_handler zuf_acl_default_xattr_handler = {
	.prefix = POSIX_ACL_XATTR_DEFAULT,
	.flags	= ACL_TYPE_DEFAULT,
	.list	= zuf_acl_xattr_list_default,
	.get	= zuf_acl_xattr_get,
	.set	= zuf_acl_xattr_set,
};

#endif /* BACKPORT_XATTR_HANDLER */
