#
# ZUF: Zero-copy User-mode Feeder
#
# Copyright (c) 2018 NetApp Inc. All rights reserved.
#
# ZUFS-License: GPL-2.0. See module.c for LICENSE details.
#
# Makefile for the Linux zufs Kernel Feeder.
#

obj-$(CONFIG_ZUFS_FS) += zuf.o

# Infrastructure
zuf-y += md.o t1.o t2.o

# ZUF core
zuf-y += zuf-core.o zuf-root.o

# Main FS
zuf-y += super.o inode.o directory.o namei.o file.o
zuf-y += module.o
