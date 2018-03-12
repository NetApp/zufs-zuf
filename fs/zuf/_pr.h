/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#ifndef __ZUF_PR_H__
#define __ZUF_PR_H__

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/*
 * Debug code
 */
#define zuf_err(s, args ...)		pr_err("[%s:%d] " s, __func__, \
							__LINE__, ## args)
#define zuf_err_cnd(silent, s, args ...) \
	do {if (!silent) \
		pr_err("[%s:%d] " s, __func__, __LINE__, ## args); \
	} while (0)
#define zuf_warn(s, args ...)		pr_warn("[%s:%d] " s, __func__, \
							__LINE__, ## args)
#define zuf_warn_cnd(silent, s, args ...) \
	do {if (!silent) \
		pr_warn("[%s:%d] " s, __func__, __LINE__, ## args); \
	} while (0)
#define zuf_info(s, args ...)          pr_info("~info~ " s, ## args)

#define zuf_chan_debug(c, s, args...)	pr_debug(c " [%s:%d] " s, __func__, \
							__LINE__, ## args)

/* ~~~ channel prints ~~~ */
#define zuf_dbg_perf(s, args ...)	zuf_chan_debug("perfo", s, ##args)
#define zuf_dbg_err(s, args ...)	zuf_chan_debug("error", s, ##args)
#define zuf_dbg_vfs(s, args ...)	zuf_chan_debug("vfs  ", s, ##args)
#define zuf_dbg_rw(s, args ...)		zuf_chan_debug("rw   ", s, ##args)
#define zuf_dbg_t1(s, args ...)		zuf_chan_debug("t1   ", s, ##args)
#define zuf_dbg_xattr(s, args ...)	zuf_chan_debug("xattr", s, ##args)
#define zuf_dbg_acl(s, args ...)	zuf_chan_debug("acl  ", s, ##args)
#define zuf_dbg_t2(s, args ...)		zuf_chan_debug("t2dbg", s, ##args)
#define zuf_dbg_t2_rw(s, args ...)	zuf_chan_debug("t2grw", s, ##args)
#define zuf_dbg_core(s, args ...)	zuf_chan_debug("core ", s, ##args)
#define zuf_dbg_mmap(s, args ...)	zuf_chan_debug("mmap ", s, ##args)
#define zuf_dbg_zus(s, args ...)	zuf_chan_debug("zusdg", s, ##args)
#define zuf_dbg_verbose(s, args ...)	zuf_chan_debug("d-oto", s, ##args)

#define md_err		zuf_err
#define md_warn		zuf_warn
#define md_err_cnd	zuf_err_cnd
#define md_warn_cnd	zuf_warn_cnd
#define md_dbg_err	zuf_dbg_err
#define md_dbg_verbose	zuf_dbg_verbose


#endif /* define __ZUF_PR_H__ */
