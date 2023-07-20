/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei IP notify Protocol Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UB_NETWORK_MGMT_H
#define _UB_NETWORK_MGMT_H

#include <net/addrconf.h>
#include <linux/inetdevice.h>

struct ub_nm_sysfs_context {
	struct kobject *nm_root;
};

struct ub_nm_device {
	struct net_device *ndev;
	struct list_head nm_dev_list;
	struct ub_nm_sysfs_context sys_ctx;
};

enum ub_nm_device_op {
	UB_NM_DEVICE_ADD = 0,
	UB_NM_DEVICE_DEL
};

struct ub_um_device_op_work {
	struct work_struct work;
	struct net_device *ndev;
	enum ub_nm_device_op op;
};

void ub_nm_down_read(void);
void ub_nm_up_read(void);
void ub_nm_down_write(void);
void ub_nm_up_write(void);
struct list_head *ub_nm_get_dev_list(void);

#endif /* _UB_NETWORK_MGMT_H */
