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
#define zuf_dbg_err(s, args ...)	zuf_chan_debug("error", s, ##args)

#endif /* define __ZUF_PR_H__ */
