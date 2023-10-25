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

struct ip_notify_attrs {
	struct kobj_attribute good_ipv4_notify_tx_cnt;
	struct kobj_attribute bad_ipv4_notify_tx_cnt;
	struct kobj_attribute good_ipv6_notify_tx_cnt;
	struct kobj_attribute bad_ipv6_notify_tx_cnt;
	struct kobj_attribute print_ip_notify_pkt_en;
};

struct ip_notify_stats {
	atomic64_t good_ipv4_notify_tx_cnt;
	atomic64_t bad_ipv4_notify_tx_cnt;
	atomic64_t good_ipv6_notify_tx_cnt;
	atomic64_t bad_ipv6_notify_tx_cnt;
};

struct ip_notify_ctls {
	u32 print_ip_notify_pkt_en;
};

struct ub_nm_ip_notify_ctx {
	struct kobject *ip_notify_root;
	struct ip_notify_attrs attrs;
	struct ip_notify_stats stats;
	struct ip_notify_ctls ctls;
};

struct ub_nm_sysfs_context {
	struct kobject *nm_root;
	struct ub_nm_ip_notify_ctx ip_notify_ctx;
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

int ub_ipv4_notify_event(struct notifier_block *nb, unsigned long event,
			 void *ptr);
int ub_ipv6_notify_event(struct notifier_block *nb, unsigned long event,
			 void *ptr);
int ub_ip_notify_init(struct ub_nm_device *nm_dev);
void ub_ip_notify_uninit(struct ub_nm_device *nm_dev);
void ub_nm_down_read(void);
void ub_nm_up_read(void);
void ub_nm_down_write(void);
void ub_nm_up_write(void);
struct list_head *ub_nm_get_dev_list(void);

#endif /* _UB_NETWORK_MGMT_H */
