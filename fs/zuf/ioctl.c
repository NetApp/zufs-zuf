// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Ioctl operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#include <linux/capability.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/fadvise.h>
#include <linux/vmalloc.h>
#include <linux/capability.h>

#include "zuf.h"

#define ZUFS_SUPPORTED_FS_FLAGS (FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL | \
				 FS_NOATIME_FL | FS_DIRTY_FL)

#define ZUS_IOCTL_MAX_PAGES	8

static int _ioctl_dispatch(struct inode *inode, uint cmd, ulong arg)
{
	struct _ioctl_info {
		struct zufs_ioc_ioctl ctl;
		char buf[900];
	} ctl_alloc = {};
	enum big_alloc_type bat;
	struct zufs_ioc_ioctl *ioc_ioctl;
	size_t ioc_size = _IOC_SIZE(cmd);
	void __user *parg = (void __user *)arg;
	struct timespec64 time = current_time(inode);
	size_t size;
	bool retry = false;
	int err;
	bool freeze = false;

realloc:
	size = sizeof(*ioc_ioctl) + ioc_size;

	zuf_dbg_vfs("[%ld] cmd=0x%x arg=0x%lx size=0x%zx cap_admin=%u IOC(%d, %d, %zd)\n",
		    inode->i_ino, cmd, arg, size, capable(CAP_SYS_ADMIN), _IOC_TYPE(cmd),
		    _IOC_NR(cmd), ioc_size);

	ioc_ioctl = big_alloc(size, sizeof(ctl_alloc), &ctl_alloc, GFP_KERNEL,
			      &bat);
	if (unlikely(!ioc_ioctl))
		return -ENOMEM;

	memset(ioc_ioctl, 0, sizeof(*ioc_ioctl));
	ioc_ioctl->hdr.in_len = size;
	ioc_ioctl->hdr.out_start = offsetof(struct zufs_ioc_ioctl, out_start);
	ioc_ioctl->hdr.out_max = size;
	ioc_ioctl->hdr.out_len = 0;
	ioc_ioctl->hdr.operation = ZUFS_OP_IOCTL;
	ioc_ioctl->zus_ii = ZUII(inode)->zus_ii;
	ioc_ioctl->cmd = cmd;
	ioc_ioctl->kflags = capable(CAP_SYS_ADMIN) ? ZUF_CAP_ADMIN : 0;
	timespec_to_mt(&ioc_ioctl->time, &time);

	if (arg && ioc_size) {
		if (copy_from_user(ioc_ioctl->arg, parg, ioc_size)) {
			err = -EFAULT;
			goto out;
		}
	}

dispatch:
	err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_ioctl->hdr,
			    NULL, 0);

	if (!retry && err == -EZUFS_RETRY) {
		retry = true;
		switch (ioc_ioctl->uflags) {
		case ZUF_REALLOC:
			ioc_size = ioc_ioctl->new_size - sizeof(*ioc_ioctl);
			big_free(ioc_ioctl, bat);
			goto realloc;
		case ZUF_FREEZE_REQ:
			err = freeze_super(inode->i_sb);
			if (unlikely(err)) {
				zuf_warn("unable to freeze fs err=%d\n", err);
				goto out;
			}
			freeze = true;
			ioc_ioctl->kflags |= ZUF_FSFROZEN;
			goto dispatch;
		default:
			zuf_err("unkonwn ZUFS retry type uflags=%d\n",
				ioc_ioctl->uflags);
			err = -EINVAL;
			goto out;
		}
	}

	if (unlikely(err)) {
		zuf_dbg_err("zufc_dispatch failed => %d IOC(%d, %d, %zd)\n",
			    err, _IOC_TYPE(cmd), _IOC_NR(cmd), ioc_size);
		goto out;
	}

	if (ioc_ioctl->hdr.out_len) {
		if (copy_to_user(parg, ioc_ioctl->arg,
		    ioc_ioctl->hdr.out_len)) {
			err = -EFAULT;
			goto out;
		}
	}

out:
	if (freeze) {
		int thaw_err = thaw_super(inode->i_sb);

		if (unlikely(thaw_err))
			zuf_err("post ioctl thaw file system failure err = %d\n",
				 thaw_err);
	}

	big_free(ioc_ioctl, bat);

	return err;
}

static uint _translate_to_ioc_flags(struct zus_inode *zi)
{
	uint zi_flags = le16_to_cpu(zi->i_flags);
	uint ioc_flags = 0;

	if (zi_flags & S_SYNC)
		ioc_flags |= FS_SYNC_FL;
	if (zi_flags & S_APPEND)
		ioc_flags |= FS_APPEND_FL;
	if (zi_flags & S_IMMUTABLE)
		ioc_flags |= FS_IMMUTABLE_FL;
	if (zi_flags & S_NOATIME)
		ioc_flags |= FS_NOATIME_FL;
	if (zi_flags & S_DIRSYNC)
		ioc_flags |= FS_DIRSYNC_FL;

	return ioc_flags;
}

static int _ioc_getflags(struct inode *inode, uint __user *parg)
{
	struct zus_inode *zi = zus_zi(inode);
	uint flags = _translate_to_ioc_flags(zi);

	return put_user(flags, parg);
}

static void _translate_to_zi_flags(struct zus_inode *zi, unsigned int flags)
{
	uint zi_flags = le16_to_cpu(zi->i_flags);

	zi_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);

	if (flags & FS_SYNC_FL)
		zi_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		zi_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		zi_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		zi_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		zi_flags |= S_DIRSYNC;

	zi->i_flags = cpu_to_le16(zi_flags);
}

/* use statx ioc to flush zi changes to fs */
static int __ioc_dispatch_zi_update(struct inode *inode, uint flags)
{
	struct zufs_ioc_attr ioc_attr = {
		.hdr.in_len = sizeof(ioc_attr),
		.hdr.out_len = sizeof(ioc_attr),
		.hdr.operation = ZUFS_OP_SETATTR,
		.zus_ii = ZUII(inode)->zus_ii,
		.zuf_attr = flags,
	};
	int err;

	err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &ioc_attr.hdr, NULL, 0);
	if (unlikely(err && err != -EINTR))
		zuf_err("zufc_dispatch failed => %d\n", err);

	return err;
}

static int _ioc_setflags(struct inode *inode, uint __user *parg)
{
	struct zus_inode *zi = zus_zi(inode);
	uint flags, oldflags;
	int err;

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (get_user(flags, parg))
		return -EFAULT;

	if (flags & ~ZUFS_SUPPORTED_FS_FLAGS)
		return -EOPNOTSUPP;

	if (zi->i_flags & ZUFS_S_IMMUTABLE)
		return -EPERM;

	inode_lock(inode);

	oldflags = le32_to_cpu(zi->i_flags);

	if ((flags ^ oldflags) &
		(FS_APPEND_FL | FS_IMMUTABLE_FL)) {
		if (!capable(CAP_LINUX_IMMUTABLE)) {
			inode_unlock(inode);
			return -EPERM;
		}
	}

	if (!S_ISDIR(inode->i_mode))
		flags &= ~FS_DIRSYNC_FL;

	flags = flags & FS_FL_USER_MODIFIABLE;
	flags |= oldflags & ~FS_FL_USER_MODIFIABLE;
	inode->i_ctime = current_time(inode);
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
	_translate_to_zi_flags(zi, flags);
	zuf_set_inode_flags(inode, zi);

	err = __ioc_dispatch_zi_update(inode, ZUFS_STATX_FLAGS | STATX_CTIME);

	inode_unlock(inode);
	return err;
}

static int _ioc_setversion(struct inode *inode, uint __user *parg)
{
	struct zus_inode *zi = zus_zi(inode);
	__u32 generation;
	int err;

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (get_user(generation, parg))
		return -EFAULT;

	inode_lock(inode);

	inode->i_ctime = current_time(inode);
	inode->i_generation = generation;
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
	zi->i_generation = cpu_to_le32(inode->i_generation);

	err = __ioc_dispatch_zi_update(inode, ZUFS_STATX_VERSION | STATX_CTIME);

	inode_unlock(inode);
	return err;
}

static int _ioc_fadvise(struct file *file, ulong arg)
{
	struct inode *inode = file_inode(file);
	struct zuf_inode_info *zii = ZUII(inode);
	struct zufs_ioc_fadvise iof = {};
	int err;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (arg && copy_from_user(&iof, (void __user *)arg, sizeof(iof)))
		return -EFAULT;

	zuf_r_lock(zii);

	err = zuf_fadvise(inode->i_sb, inode, iof.offset, iof.length,
			  iof.advise, file->f_mode & FMODE_RANDOM);

	zuf_r_unlock(zii);

	return err;
}

long zuf_ioctl(struct file *filp, unsigned int cmd, ulong arg)
{
	struct inode *inode = filp->f_inode;
	void __user *parg = (void __user *)arg;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return _ioc_getflags(inode, parg);
	case FS_IOC_SETFLAGS:
		return _ioc_setflags(inode, parg);
	case FS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);
	case FS_IOC_SETVERSION:
		return _ioc_setversion(inode, parg);
	case ZUFS_IOC_FADVISE:
		return _ioc_fadvise(filp, arg);
	default:
		return _ioctl_dispatch(inode, cmd, arg);
	}
}

#ifdef CONFIG_COMPAT
long zuf_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	case FS_IOC32_SETVERSION:
		cmd = FS_IOC_SETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return zuf_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif

