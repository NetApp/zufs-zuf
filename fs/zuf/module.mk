# Copyright (c) 2018 NetApp Inc. All rights reserved.
#
# ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
#
# Authors:
#	Boaz Harrosh <boazh@netapp.com>

SHELL	 := /bin/bash
LIBDIR	 ?= /usr/lib/zufs
KDIR	 ?= /lib/modules/`uname -r`/build
MDIR	 ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
O	 ?=

# Kconfig simulation (Kconfig doesn't work with out-of-tree modules)
PARAMS += CONFIG_ZUF=m

PARAMS += CFLAGS_MODULE="$(CFLAGS_MODULE)"
# end of Kconfig simulation

build:
	$(MAKE) -C $(KDIR) M=$(MDIR) $(PARAMS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean

install: build
	$(MAKE) -C $(KDIR) M=$(MDIR) modules_install

define run-fpm =
	fpm -f -s dir -t $1 -n zufs-zuf -v $(VER) -C $(TMPDIR) -p $(O)/$(MDIR) \
	    --url "netapp.com" --license "GPL" --vendor "NetApp Inc." \
	    --description "`printf "ZUF - Zero-copy User-mode Feeder\nID: $(GIT_HASH)"`" \
	    --rpm-rpmbuild-define "_build_id_links none" \
	    --iteration $(BUILD_ID) --epoch 1 \
	     --before-remove $(MDIR)/pre_uninstall.sh \
	     --after-remove $(MDIR)/post_uninstall.sh \
	     --after-install $(MDIR)/post_install.sh .
endef

rpm: build
	$(eval TMPDIR := $(shell mktemp -d))
	$(MAKE) -C $(KDIR) M=$(MDIR) DEPMOD=true MODLIB=$(TMPDIR)$(LIBDIR) modules_install
	$(eval GIT_HASH := $(shell git rev-parse HEAD))
	$(call run-fpm, rpm)
	rm -rf $(TMPDIR)

ALL_KERNS_DIR ?= /usr/src/kernels
ALL_KERNS_VERS ?= $(shell ls $(ALL_KERNS_DIR))

multi-rpm:
	$(eval TMPDIR := $(shell mktemp -d))
	@mkdir -vp $(TMPDIR)$(LIBDIR)/extra
	@for kver in $(ALL_KERNS_VERS) ; do \
		$(MAKE) -C $(ALL_KERNS_DIR)/$$kver M=$(MDIR) $(PARAMS) clean ; \
		$(MAKE) -C $(ALL_KERNS_DIR)/$$kver M=$(MDIR) $(PARAMS) modules ; \
		cp -v $(MDIR)/zuf.ko $(TMPDIR)$(LIBDIR)/extra/zuf.$$kver.ko ; \
	done
	$(eval GIT_HASH := $(shell git rev-parse HEAD))
	$(call run-fpm, rpm)
	rm -rf $(TMPDIR)

.PHONY: clean build install rpm multi-rpm
