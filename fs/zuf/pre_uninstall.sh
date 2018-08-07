#!/bin/bash

# package removal, not upgrade
if [[ ${1} -eq 0 ]] ; then
	if /bin/grep -qw zuf /proc/mounts ; then
		/bin/umount -t zuf -a
	fi
	if /bin/grep -qw zuf /proc/modules ; then
		/sbin/rmmod zuf
	fi
fi
