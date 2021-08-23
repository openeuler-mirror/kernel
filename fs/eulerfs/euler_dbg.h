/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef EUFS_DBG_H
#define EUFS_DBG_H

/*
 * Debug code
 */

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#define eufs_dbg(s, args...)
#define eufs_dbg_vlimit(s, args...)
#define eufs_dbg_dir(s, args...)

#define eufs_crit(s, args...) pr_crit(s, ##args)
#define eufs_err(sb, s, args...) eufs_error_mng(sb, s, ##args)
#define eufs_warn(s, args...) pr_warn(s, ##args)
#define eufs_info(s, args...)                                                 \
	pr_info("(pid=%d,cmd=%s) " s, current->pid, current->comm, ##args)

#endif /* EUFS_DBG_H */
