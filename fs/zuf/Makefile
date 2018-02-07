#
# ZUF: Zero-copy User-mode Feeder
#
# Copyright (c) 2018 NetApp Inc. All rights reserved.
#
# ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
#
# Makefile for the Linux zufs Kernel Feeder.
#

obj-$(CONFIG_ZUF) += zuf.o

# Infrastructure
zuf-y += md.o t2.o

# ZUF core
zuf-y += zuf-core.o zuf-root.o t1.o

# Main FS
zuf-y += xattr.o acl.o rw.o mmap.o
zuf-y += super.o directory.o file.o inode.o namei.o symlink.o ioctl.o
zuf-y += module.o
