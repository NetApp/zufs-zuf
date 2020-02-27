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
			macl->id = cpu_to_le32(
				from_kuid(&init_user_ns, entry->e_uid));
			break;
		case ACL_GROUP:
			macl->id = cpu_to_le32(
				from_kgid(&init_user_ns, entry->e_gid));
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

static int __set_acl(struct inode *inode, struct posix_acl *acl, int type,
		     bool set_mode)
{
	struct zuf_inode_info *zii = ZUII(inode);
	char *name = NULL;
	void *buf;
	int err;
	size_t size;
	umode_t old_mode = inode->i_mode;

	zuf_dbg_acl("[%ld] acl=%p type=0x%x\n", inode->i_ino, acl, type);

	switch (type) {
	case ACL_TYPE_ACCESS: {
		struct zus_inode *zi = zii->zi;

		name = XATTR_POSIX_ACL_ACCESS;
		if (acl && set_mode) {
			err = posix_acl_update_mode(inode, &inode->i_mode,
						    &acl);
			if (err)
				return err;

			zuf_dbg_acl("old=0x%x new=0x%x acl_count=%d\n",
				    old_mode, inode->i_mode,
				    acl ? acl->a_count : -1);
			inode->i_ctime = current_time(inode);
			timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
			zi->i_mode = cpu_to_le16(inode->i_mode);
		}
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

	/* NOTE: Server's zus_setxattr implementers should cl_flush the zi.
	 *  In the case it returned an error it should not cl_flush.
	 *  We will restore to old i_mode.
	 */
	zuf_xaw_lock(zii);
	err = __zuf_setxattr(inode, ZUF_XF_SYSTEM, name, buf, size, 0);
	if (likely(!err)) {
		set_cached_acl(inode, type, acl);
	} else {
		/* Error need to restore changes (xfstest/generic/449) */
		struct zus_inode *zi = zii->zi;

		inode->i_mode = old_mode;
		zi->i_mode = cpu_to_le16(inode->i_mode);
	}
	zuf_xaw_unlock(zii);

	kfree(buf);
	return err;
}

int zuf_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	return __set_acl(inode, acl, type, true);
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
			acl->a_entries[n].e_uid = make_kuid(&init_user_ns,
							le32_to_cpu(macl->id));
			macl++;
			if (end < (void *)macl)
				goto fail;
			break;
		case ACL_GROUP:
			acl->a_entries[n].e_gid = make_kgid(&init_user_ns,
							le32_to_cpu(macl->id));
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

	zuf_xar_lock(zii);

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

	zuf_xar_unlock(zii);

	free_page((ulong)buf);

	return acl;
}

/* Used by creation of new inodes */
int zuf_acls_create_pre(struct inode *dir, umode_t *mode,
			struct posix_acl **def_acl, struct posix_acl **acl)
{
	int err = posix_acl_create(dir, mode, def_acl, acl);

	return err;
}

int zuf_acls_create_post(struct inode *dir, struct inode *inode,
			 struct posix_acl *def_acl, struct posix_acl *acl)
{
	int err = 0, err2 = 0;

	zuf_dbg_acl("def_acl_count=%d acl_count=%d\n",
			def_acl ? def_acl->a_count : -1,
			acl ? acl->a_count : -1);

	if (def_acl)
		err = __set_acl(inode, def_acl, ACL_TYPE_DEFAULT, false);
	else
		inode->i_default_acl = NULL;

	if (acl)
		err2 = __set_acl(inode, acl, ACL_TYPE_ACCESS, false);
	else
		inode->i_acl = NULL;

	return err ?: err2;
}
