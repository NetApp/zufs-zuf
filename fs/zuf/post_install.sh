#!/bin/bash

LIB_DIR=/usr/lib/zufs
MOD=${LIB_DIR}/extra/zuf.ko
KVER=$(/bin/uname -r)
KABI_VER=$(echo ${KVER} | /bin/sed -e 's|\([0-9.]*-[0-9]*\).*|\1|')

# add zuf to modprobe DB
/bin/ln -sf ${MOD%.ko}.*${KABI_VER}*.ko /lib/modules/${KVER}/extra/zuf.ko
/sbin/depmod
