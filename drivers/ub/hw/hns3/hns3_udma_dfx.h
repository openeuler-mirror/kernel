/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
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

#ifndef _UDMA_DFX_H
#define _UDMA_DFX_H

#include <linux/fs.h>
#include "hns3_udma_device.h"

#define DFX_DEVICE_NAME "udma_dfx"
#define MAX_UDMA_DEV	16
#define MAX_TP_CNT	256
#define MAX_JFS_CNT	256
#define MAX_JFR_CNT	256
#define MAX_JETTY_CNT	256
#define MAX_JFC_CNT	256
#define MAX_SEG_CNT	256
#define UDMA_DFX_FILE_ATTR_DEF(file_name, func_show, func_store) \
static struct udma_dfx_sys_attr g_sysfs_udma_##file_name##_attr = {\
	{\
		.name = #file_name,\
		.mode = 0644,\
	},\
	.pub_show  = (func_show),\
	.pub_store = (func_store),\
}

#define HW_ATTRS_LIST_MEMBER(file_name) (&g_sysfs_udma_##file_name##_attr.attr)
#define MAX_CHAR_NUM_DEV_NAME	12
#define UDMA_DFX_STR_LEN_MAX	20

struct udma_dfx_info;

struct udma_dfx_sys_attr {
	struct attribute attr;
	int (*pub_show)(struct udma_dfx_info *udma_dfx);
	int (*pub_store)(const char *buf, struct udma_dfx_info *udma_dfx);
};

struct udma_dfx_dev_info {
	char dev_name[MAX_CHAR_NUM_DEV_NAME];
};

struct udma_dfx_ops {
	int (*add_sysfs)(struct udma_dfx_info *info);
	void (*del_sysfs)(struct udma_dfx_info *info);
};

struct tpn_list {
	uint32_t		tpn;
	struct list_head	node;
	spinlock_t		node_lock;
};

struct jfs_list {
	uint32_t		jfs_id;
	uint8_t			state;
	uint16_t		depth;
	uint8_t			pri;
	uint32_t		jfc_id;
	struct list_head	node;
	spinlock_t		node_lock;
};

struct jfr_list {
	uint32_t		jfr_id;
	uint32_t		jfc_id;
	uint32_t		srqn;
	struct list_head	node;
	spinlock_t		node_lock;
};

struct jetty_list {
	uint32_t		jetty_id;
	uint8_t			state;
	uint32_t		jfs_depth;
	uint32_t		jfr_depth;
	uint8_t			pri;
	uint32_t		jfc_s_id;
	uint32_t		jfc_r_id;
	uint32_t		jfr_id;
	struct list_head	node;
	spinlock_t		node_lock;
};

struct jfc_list {
	uint32_t		jfc_id;
	struct list_head	node;
	spinlock_t		node_lock;
};

struct seg_list {
	uint32_t		pd;
	uint64_t		iova;
	uint32_t		len;
	uint32_t		key_id;
	struct list_head	node;
	spinlock_t		node_lock;
	union ubcore_eid	eid;
};

struct udma_dfx_info {
	struct udma_dfx_dev_info	dev;
	struct udma_dfx_ops		*ops;
	struct device			*drv_dev;
	struct kobject			kobj;
	uint32_t			tpn_cnt;
	struct tpn_list			*tpn_list;
	uint32_t			jfs_cnt;
	struct jfs_list			*jfs_list;
	uint32_t			jfr_cnt;
	struct jfr_list			*jfr_list;
	uint32_t			jetty_cnt;
	struct jetty_list		*jetty_list;
	uint32_t			jfc_cnt;
	struct jfc_list			*jfc_list;
	uint32_t			seg_cnt;
	struct seg_list			*seg_list;
	void				*priv;
};

struct udma_dfx_dev {
	struct udma_dfx_info	*dfx;
	struct udma_dev		*dev;
	rwlock_t		rwlock;
};

extern struct udma_dfx_dev g_udma_dfx_list[MAX_UDMA_DEV];

int udma_dfx_init(struct udma_dev *udma_dev);
void udma_dfx_uninit(struct udma_dev *udma_dev);
int udma_find_dfx_dev(struct udma_dev *udma_dev, int *num);
int udma_query_res(struct ubcore_device *dev, struct ubcore_res_key *key,
		   struct ubcore_res_val *val);

#endif /* _UDMA_DFX_H */
