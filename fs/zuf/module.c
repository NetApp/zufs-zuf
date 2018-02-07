// SPDX-License-Identifier: GPL-2.0
/*
 * zuf - Zero-copy User-mode Feeder
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include <linux/module.h>

#include "zus_api.h"

MODULE_AUTHOR("Boaz Harrosh <boazh@netapp.com>");
MODULE_AUTHOR("Sagi Manole <sagim@netapp.com>");
MODULE_DESCRIPTION("Zero-copy User-mode Feeder");
MODULE_LICENSE("GPL");
MODULE_VERSION(__stringify(ZUFS_MAJOR_VERSION) "."
		__stringify(ZUFS_MINOR_VERSION));
