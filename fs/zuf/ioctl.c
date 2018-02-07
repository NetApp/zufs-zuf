/*
 * BRIEF DESCRIPTION
 *
 * Ioctl operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
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


#include "zuf.h"

static int _ioc_getflags(struct inode *inode, uint __user *parg)
{
	struct zus_inode *zi = zus_zi(inode);
	uint flags = le32_to_cpu(zi->i_flags) & FS_FL_USER_VISIBLE;

	return put_user(flags, parg);
}

static int _ioc_setflags(struct inode *inode, uint __user *parg)
{
	struct zus_inode *zi = zus_zi(inode);
	uint flags, oldflags;

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (get_user(flags, parg))
		return -EFAULT;

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
	inode->i_ctime = CURRENT_TIME;
	zi->i_flags = cpu_to_le32(flags);
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
	zuf_set_inode_flags(inode, zi);
	tozu_flush_zi(inode->i_sb, zi, ZIFL_LO);
	inode_unlock(inode);
	return 0;
}

static int _ioc_setversion(struct inode *inode, uint __user *parg)
{
	struct zus_inode *zi = zus_zi(inode);
	__u32 generation;

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (get_user(generation, parg))
		return -EFAULT;

	inode_lock(inode);
	inode->i_ctime = CURRENT_TIME;
	inode->i_generation = generation;
	timespec_to_mt(&zi->i_ctime, &inode->i_ctime);
	zi->i_generation = cpu_to_le32(inode->i_generation);
	tozu_flush_zi(inode->i_sb, zi, ZIFL_ALL);
	inode_unlock(inode);
	return 0;
}

long tozu_ioctl(struct file *filp, unsigned int cmd, ulong arg)
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
	case ZUFS_IOC_FADVISE: {
		struct tozu_data_sync mds = {.flags = 0} ;

		if (arg && copy_from_user(&mds, parg, sizeof(mds)))
			return -EFAULT;

		/* backwards compatibility */
		return tozu_fadvise(filp, mds.offset, mds.length,
				    mds.flags ?: POSIX_FADV_WILLNEED);
	}

	case ZU_IOC_INIT_THREAD:
	case ZU_IOC_WAIT_OPT:
	case ZU_IOC_BREAK_ALL:
		return zufs_ioc(filp, cmd, arg);
	default:
		zuf_err("%x %lx\n", cmd, ZU_IOC_WAIT_OPT);
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long tozu_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
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
	return tozu_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif

