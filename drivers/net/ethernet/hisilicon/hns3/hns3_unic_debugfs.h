/* SPDX-License-Identifier: GPL-2.0+ */
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef __HNS3_UNIC_DEBUGFS_H
#define __HNS3_UNIC_DEBUGFS_H

enum hns3_dbg_ub_dentry_type {
	UB_DBG_DENTRY_IP,
	UB_DBG_DENTRY_GUID,
	UB_DBG_DENTRY_FASTPATH,
	UB_DBG_DENTRY_END,
};

int hns3_unic_dbg_init(struct hnae3_handle *handle, struct dentry *parent);
void hns3_unic_dbg_uninit(struct hnae3_handle *handle);

#endif
