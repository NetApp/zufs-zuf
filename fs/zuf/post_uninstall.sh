#!/bin/bash

# remove zuf from modprobe DB on uninstall
if [[ ${1} -eq 0 ]] ; then
	/bin/find /lib/modules -type l -name zuf.ko -delete
	/sbin/depmod
fi
