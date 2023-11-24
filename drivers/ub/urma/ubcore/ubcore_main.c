// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Description: ubcore kernel module
 * Author: Qian Guoxin
 * Create: 2021-08-03
 * Note:
 * History: 2021-08-03: create file
 */

#include <net/addrconf.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/if_vlan.h>

#include "ubcore_cmd.h"
#include "ubcore_uvs_cmd.h"
#include "ubcore_log.h"
#include "ubcore_netlink.h"
#include <urma/ubcore_types.h>
#include <urma/ubcore_api.h>
#include <urma/ubcore_uapi.h>
#include "ubcore_priv.h"
#include "ubcore_netdev.h"
#include "ubcore_msg.h"

/* ubcore create independent cdev and ioctl channels
 * to handle public work.
 */
#define UBCORE_DEVICE_NAME "ubcore"
#define UBCORE_CLASS_NAME "ubus"
#define UBCORE_IPV4_MAP_IPV6_PREFIX 0x0000ffff
#define UBCORE_LOCAL_SHUNET (0xfe80000000000000ULL)

struct ubcore_ctx {
	dev_t ubcore_devno;
	struct cdev ubcore_cdev;
	struct class *ubcore_class;
	struct device *ubcore_dev;
};

static struct ubcore_ctx g_ubcore_ctx;

struct ubcore_net_addr_node {
	struct list_head node;
	struct ubcore_net_addr addr;
	uint32_t prefix_len;
};

int ubcore_open(struct inode *i_node, struct file *filp)
{
	return 0;
}

static int ubcore_cmd_show_utp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_res_utp_val utp_info = {0};
	struct ubcore_res_key key = {0};
	struct ubcore_res_val val = {0};
	struct ubcore_cmd_show_utp arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct ubcore_cmd_show_utp));
	if (ret != 0)
		return -EPERM;

	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL || ubcore_check_dev_name_invalid(dev, arg.in.dev_name)) {
		ubcore_log_err("find dev failed, dev:%s, arg_in: %s.\n",
			       dev == NULL ? "NULL" : dev->dev_name, arg.in.dev_name);
		return -EINVAL;
	}

	key.type = UBCORE_RES_KEY_UTP;
	key.key = arg.in.utpn;
	val.addr = (uint64_t)&utp_info;
	val.len = (uint32_t)sizeof(struct ubcore_res_utp_val);
	if (dev->ops != NULL && dev->ops->query_res != NULL &&
		dev->ops->query_res(dev, &key, &val) != 0) {
		ubcore_put_device(dev);
		ubcore_log_err("failed to query res.\n");
		return -1;
	}
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)arg.out.addr, &utp_info,
		sizeof(struct ubcore_res_utp_val));

	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_query_stats(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_query_stats arg = {0};
	struct ubcore_stats_com_val com_val;
	struct ubcore_stats_key key = {0};
	struct ubcore_stats_val val;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct ubcore_cmd_query_stats));
	if (ret != 0)
		return ret;

	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL || ubcore_check_dev_name_invalid(dev, arg.in.dev_name)) {
		ubcore_log_err("find dev failed, dev:%s, arg_in: %s.\n",
			       dev == NULL ? "NULL" : dev->dev_name, arg.in.dev_name);
		return -EINVAL;
	}

	key.type = (uint8_t)arg.in.type;
	key.key = arg.in.key;
	val.addr = (uint64_t)&com_val;
	val.len = (uint32_t)sizeof(struct ubcore_stats_com_val);

	ret = ubcore_query_stats(dev, &key, &val);
	if (ret != 0) {
		ubcore_put_device(dev);
		return ret;
	}

	ubcore_put_device(dev);
	(void)memcpy(&arg.out, &com_val, sizeof(struct ubcore_stats_com_val));
	return ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct ubcore_cmd_query_stats));
}

static int ubcore_cmd_updata_ueid(struct ubcore_cmd_hdr *hdr, enum ubcore_msg_opcode op)
{
	struct net *net = current->nsproxy->net_ns;
	struct ubcore_cmd_updata_ueid arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_updata_ueid));
	if (ret != 0)
		return -EPERM;

	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev_name: %s failed.\n", arg.in.dev_name);
		return -EPERM;
	}
	if (!dev->attr.virtualization && dev->cfg.pattern == (uint8_t)UBCORE_PATTERN_1) {
		ubcore_put_device(dev);
		ubcore_log_err("pattern1 does not support static mode\n");
		return -1;
	}
	if (dev->cfg.pattern == (uint8_t)UBCORE_PATTERN_1 || dev->dynamic_eid) {
		ubcore_log_err("The dynamic mode of pf does not support eid change\n");
		ubcore_put_device(dev);
		return -EPERM;
	}
	if (dev->attr.tp_maintainer && ubcore_get_netlink_valid() == false) {
		ubcore_put_device(dev);
		return -EPERM;
	}
	if (ubcore_msg_discover_eid(dev, arg.in.eid_index, op, net) != 0) {
		ubcore_put_device(dev);
		return -EPERM;
	}

	ubcore_put_device(dev);
	return 0;
}

static void ubcore_update_pattern1_eid(struct ubcore_device *dev,
	union ubcore_eid *eid, bool is_add)
{
	struct ubcore_ueid_cfg cfg;
	uint32_t eid_idx = 0;

	if (ubcore_update_eidtbl_by_eid(dev, eid, &eid_idx, is_add) != 0)
		return;

	cfg.eid = *eid;
	cfg.eid_index = eid_idx;
	cfg.upi = 0;
	if (is_add)
		(void)ubcore_add_ueid(dev, (uint16_t)UBCORE_NON_VIRTUALIZATION_FE_IDX, &cfg);
	else
		(void)ubcore_delete_ueid(dev, (uint16_t)UBCORE_NON_VIRTUALIZATION_FE_IDX, &cfg);
}

static void ubcore_update_pattern3_eid(struct ubcore_device *dev,
	union ubcore_eid *eid, bool is_add)
{
	uint32_t pattern3_upi = 0;
	struct ubcore_ueid_cfg cfg;
	uint32_t eid_idx = 0;

	if (ubcore_update_eidtbl_by_eid(dev, eid, &eid_idx, is_add) != 0)
		return;

	if (dev->attr.virtualization ||
		ubcore_find_upi_with_dev_name(dev->dev_name, &pattern3_upi) == NULL)
		return;

	if (pattern3_upi != (uint32_t)UCBORE_INVALID_UPI) {
		cfg.eid = *eid;
		cfg.eid_index = eid_idx;
		cfg.upi = pattern3_upi;
		if (is_add)
			(void)ubcore_add_ueid(dev,
				(uint16_t)UBCORE_NON_VIRTUALIZATION_FE_IDX, &cfg);
		else
			(void)ubcore_delete_ueid(dev,
				(uint16_t)UBCORE_NON_VIRTUALIZATION_FE_IDX, &cfg);
	} else {
		ubcore_log_err("upi not configured\n");
	}
}

static int ubcore_cmd_set_eid_mode(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_set_eid_mode arg;
	struct ubcore_event event;
	struct ubcore_device *dev;
	union ubcore_eid eid = {0};
	uint32_t i;
	int ret;

	ret = ubcore_copy_from_user(&arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_set_eid_mode));
	if (ret != 0)
		return -EPERM;

	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev_name: %s failed.\n", arg.in.dev_name);
		return -EPERM;
	}
	if (dev->dynamic_eid == arg.in.eid_mode) {
		ubcore_put_device(dev);
		return 0;
	}

	if (dev->cfg.pattern == (uint8_t)UBCORE_PATTERN_1 && arg.in.eid_mode == 0) {
		ubcore_put_device(dev);
		ubcore_log_err("pattern1 not support static mode");
		return -1;
	}

	/* change eid mode, need to flush eids */
	event.ub_dev = dev;
	event.event_type = UBCORE_EVENT_EID_CHANGE;
	for (i = 0; i < dev->attr.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == true) {
			eid = dev->eid_table.eid_entries[i].eid;
			if (dev->cfg.pattern == (uint8_t)UBCORE_PATTERN_1)
				ubcore_update_pattern1_eid(dev, &eid, false);
			else
				ubcore_update_pattern3_eid(dev, &eid, false);
			event.element.eid_idx = i;
			ubcore_dispatch_async_event(&event);
		}
	}
	dev->dynamic_eid = arg.in.eid_mode;
	ubcore_put_device(dev);
	return 0;
}

static uint32_t ubcore_get_query_res_len(uint32_t type)
{
	switch (type) {
	case UBCORE_RES_KEY_UPI:
		return (uint32_t)sizeof(struct ubcore_res_upi_val);
	case UBCORE_RES_KEY_VTP:
		return (uint32_t)sizeof(struct ubcore_res_vtp_val);
	case UBCORE_RES_KEY_TP:
		return (uint32_t)sizeof(struct ubcore_res_tp_val);
	case UBCORE_RES_KEY_TPG:
		return (uint32_t)sizeof(struct ubcore_res_tpg_val);
	case UBCORE_RES_KEY_UTP:
		return (uint32_t)sizeof(struct ubcore_res_utp_val);
	case UBCORE_RES_KEY_JFS:
		return (uint32_t)sizeof(struct ubcore_res_jfs_val);
	case UBCORE_RES_KEY_JFR:
		return (uint32_t)sizeof(struct ubcore_res_jfr_val);
	case UBCORE_RES_KEY_JETTY:
		return (uint32_t)sizeof(struct ubcore_res_jetty_val);
	case UBCORE_RES_KEY_JETTY_GROUP:
		return (uint32_t)sizeof(struct ubcore_res_jetty_group_val);
	case UBCORE_RES_KEY_JFC:
		return (uint32_t)sizeof(struct ubcore_res_jfc_val);
	case UBCORE_RES_KEY_RC:
		return (uint32_t)sizeof(struct ubcore_res_rc_val);
	case UBCORE_RES_KEY_SEG:
		return (uint32_t)sizeof(struct ubcore_res_seg_val);
	case UBCORE_RES_KEY_URMA_DEV:
		return (uint32_t)sizeof(struct ubcore_res_dev_val);
	default:
		break;
	}
	return 0;
}

static void ubcore_dealloc_res_dev(struct ubcore_res_dev_val *ubcore_addr)
{
	if (ubcore_addr->seg_list != NULL) {
		vfree(ubcore_addr->seg_list);
		ubcore_addr->seg_list = NULL;
	}
	if (ubcore_addr->jfs_list != NULL) {
		vfree(ubcore_addr->jfs_list);
		ubcore_addr->jfs_list = NULL;
	}
	if (ubcore_addr->jfr_list != NULL) {
		vfree(ubcore_addr->jfr_list);
		ubcore_addr->jfr_list = NULL;
	}
	if (ubcore_addr->jfc_list != NULL) {
		vfree(ubcore_addr->jfc_list);
		ubcore_addr->jfc_list = NULL;
	}
	if (ubcore_addr->jetty_list != NULL) {
		vfree(ubcore_addr->jetty_list);
		ubcore_addr->jetty_list = NULL;
	}
	if (ubcore_addr->jetty_group_list != NULL) {
		vfree(ubcore_addr->jetty_group_list);
		ubcore_addr->jetty_group_list = NULL;
	}
	if (ubcore_addr->rc_list != NULL) {
		vfree(ubcore_addr->rc_list);
		ubcore_addr->rc_list = NULL;
	}
	if (ubcore_addr->vtp_list != NULL) {
		vfree(ubcore_addr->vtp_list);
		ubcore_addr->vtp_list = NULL;
	}
	if (ubcore_addr->tp_list != NULL) {
		vfree(ubcore_addr->tp_list);
		ubcore_addr->tp_list = NULL;
	}
	if (ubcore_addr->tpg_list != NULL) {
		vfree(ubcore_addr->tpg_list);
		ubcore_addr->tpg_list = NULL;
	}
	if (ubcore_addr->utp_list != NULL) {
		vfree(ubcore_addr->utp_list);
		ubcore_addr->utp_list = NULL;
	}
}

static int ubcore_fill_res_addr(struct ubcore_res_dev_val *ubcore_addr)
{
	ubcore_addr->seg_list = vmalloc(sizeof(struct ubcore_seg_info) * ubcore_addr->seg_cnt);
	if (ubcore_addr->seg_list == NULL)
		return -ENOMEM;

	ubcore_addr->jfs_list = vmalloc(sizeof(uint32_t) * ubcore_addr->jfs_cnt);
	if (ubcore_addr->jfs_list == NULL)
		goto free_seg_list;

	ubcore_addr->jfr_list = vmalloc(sizeof(uint32_t) * ubcore_addr->jfr_cnt);
	if (ubcore_addr->jfr_list == NULL)
		goto free_jfs_list;

	ubcore_addr->jfc_list = vmalloc(sizeof(uint32_t) * ubcore_addr->jfc_cnt);
	if (ubcore_addr->jfc_list == NULL)
		goto free_jfr_list;

	ubcore_addr->jetty_list = vmalloc(sizeof(uint32_t) * ubcore_addr->jetty_cnt);
	if (ubcore_addr->jetty_list == NULL)
		goto free_jfc_list;

	ubcore_addr->jetty_group_list = vmalloc(sizeof(uint32_t) * ubcore_addr->jetty_group_cnt);
	if (ubcore_addr->jetty_group_list == NULL)
		goto free_jetty_list;

	ubcore_addr->rc_list = vmalloc(sizeof(uint32_t) * ubcore_addr->rc_cnt);
	if (ubcore_addr->rc_list == NULL)
		goto free_jetty_group_list;

	ubcore_addr->vtp_list = vmalloc(sizeof(uint32_t) * ubcore_addr->vtp_cnt);
	if (ubcore_addr->vtp_list == NULL)
		goto free_rc_list;

	ubcore_addr->tp_list = vmalloc(sizeof(uint32_t) * ubcore_addr->tp_cnt);
	if (ubcore_addr->tp_list == NULL)
		goto free_vtp_list;

	ubcore_addr->tpg_list = vmalloc(sizeof(uint32_t) * ubcore_addr->tpg_cnt);
	if (ubcore_addr->tpg_list == NULL)
		goto free_tp_list;

	ubcore_addr->utp_list = vmalloc(sizeof(uint32_t) * ubcore_addr->utp_cnt);
	if (ubcore_addr->utp_list == NULL)
		goto free_tpg_list;

	return 0;
free_tpg_list:
	vfree(ubcore_addr->tpg_list);
free_tp_list:
	vfree(ubcore_addr->tp_list);
free_vtp_list:
	vfree(ubcore_addr->vtp_list);
free_rc_list:
	vfree(ubcore_addr->rc_list);
free_jetty_group_list:
	vfree(ubcore_addr->jetty_group_list);
free_jetty_list:
	vfree(ubcore_addr->jetty_list);
free_jfc_list:
	vfree(ubcore_addr->jfc_list);
free_jfr_list:
	vfree(ubcore_addr->jfr_list);
free_jfs_list:
	vfree(ubcore_addr->jfs_list);
free_seg_list:
	vfree(ubcore_addr->seg_list);
	return -ENOMEM;
}

static int ubcore_fill_user_res_dev(struct ubcore_res_dev_val *dev_val,
				    struct ubcore_res_dev_val *ubcore_addr)
{
	int ret;

	dev_val->seg_cnt = ubcore_addr->seg_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->seg_list,
				  ubcore_addr->seg_list,
				  dev_val->seg_cnt * sizeof(struct ubcore_seg_info));
	if (ret != 0)
		return ret;

	dev_val->jfs_cnt = ubcore_addr->jfs_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->jfs_list,
				  ubcore_addr->jfs_list, dev_val->jfs_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->jfr_cnt = ubcore_addr->jfr_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->jfr_list,
				  ubcore_addr->jfr_list, dev_val->jfr_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->jfc_cnt = ubcore_addr->jfc_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->jfc_list,
				  ubcore_addr->jfc_list, dev_val->jfc_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->jetty_cnt = ubcore_addr->jetty_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->jetty_list,
				  ubcore_addr->jetty_list, dev_val->jetty_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->jetty_group_cnt = ubcore_addr->jetty_group_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->jetty_group_list,
				  ubcore_addr->jetty_group_list,
				  dev_val->jetty_group_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->rc_cnt = ubcore_addr->rc_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->rc_list,
		ubcore_addr->rc_list,
		dev_val->rc_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->vtp_cnt = ubcore_addr->vtp_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->vtp_list,
		ubcore_addr->vtp_list,
		dev_val->vtp_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->tp_cnt = ubcore_addr->tp_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->tp_list,
				  ubcore_addr->tp_list, dev_val->tp_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->tpg_cnt = ubcore_addr->tpg_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->tpg_list,
				  ubcore_addr->tpg_list, dev_val->tpg_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	dev_val->utp_cnt = ubcore_addr->utp_cnt;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)(uint64_t)dev_val->utp_list,
				  ubcore_addr->utp_list, dev_val->utp_cnt * sizeof(uint32_t));
	if (ret != 0)
		return ret;

	return 0;
}

static int ubcore_query_res_dev(struct ubcore_device *dev, struct ubcore_res_key *key,
				struct ubcore_res_dev_val *dev_val)
{
	struct ubcore_res_dev_val ubcore_addr = { 0 };
	struct ubcore_res_val val = { 0 };
	int ret = 0;

	(void)memcpy(&ubcore_addr, dev_val, sizeof(struct ubcore_res_dev_val));  // save

	if (ubcore_fill_res_addr(&ubcore_addr) != 0) {
		ubcore_log_err("Failed to fill dev dev_val.\n");
		return -ENOMEM;
	}

	val.addr = (uint64_t)&ubcore_addr;
	val.len = (uint32_t)sizeof(struct ubcore_res_dev_val);

	ret = ubcore_query_resource(dev, key, &val);
	if (ret != 0)
		goto ubcore_free_dev;

	ret = ubcore_fill_user_res_dev(dev_val, &ubcore_addr);
ubcore_free_dev:
	ubcore_dealloc_res_dev(&ubcore_addr);
	return ret;
}

static void ubcore_dealloc_res_tp_list(uint64_t user_tp_list, struct ubcore_res_val *val)
{
	struct ubcore_res_tpg_val *tpg = (struct ubcore_res_tpg_val *)val->addr;

	if (ubcore_copy_to_user((void __user *)(uintptr_t)user_tp_list,
		tpg->tp_list, sizeof(uint32_t) * tpg->tp_cnt) != 0)
		ubcore_log_err("ubcore_copy_to_user failed.\n");

	kfree(tpg->tp_list);
}

static int ubcore_alloc_res_tp_list(struct ubcore_res_val *val)
{
	struct ubcore_res_tpg_val *tpg;

	tpg = (struct ubcore_res_tpg_val *)val->addr;
	tpg->tp_list = kzalloc(sizeof(uint32_t) * UBCORE_MAX_TP_CNT_IN_GRP, GFP_KERNEL);
	if (tpg->tp_list == NULL)
		return -ENOMEM;

	return 0;
}

static void ubcore_dealloc_res_jetty_list(uint64_t user_jetty_list, struct ubcore_res_val *val)
{
	struct ubcore_res_jetty_group_val *tpg;

	tpg = (struct ubcore_res_jetty_group_val *)val->addr;

	if (ubcore_copy_to_user((void __user *)(uintptr_t)user_jetty_list, tpg->jetty_list,
		sizeof(uint32_t) * tpg->jetty_cnt) != 0)
		ubcore_log_err("ubcore_copy_to_user failed.\n");

	kfree(tpg->jetty_list);
}

static int ubcore_alloc_res_jetty_list(struct ubcore_device *dev, struct ubcore_res_val *val)
{
	struct ubcore_res_jetty_group_val *tpg;

	tpg = (struct ubcore_res_jetty_group_val *)val->addr;
	tpg->jetty_list = kcalloc(1, sizeof(uint32_t) * dev->attr.dev_cap.max_jetty_in_jetty_grp,
		GFP_KERNEL);
	if (tpg->jetty_list == NULL)
		return -ENOMEM;

	return 0;
}

static int ubcore_query_res_arg(struct ubcore_device *dev, struct ubcore_cmd_query_res *arg,
	uint32_t res_len)
{
	struct ubcore_res_key key = {0};
	struct ubcore_res_val val = {0};
	uint64_t user_tp_list_addr = 0;      // to saves and restores user-mode addresses
	uint64_t user_jetty_list_addr = 0;   // to saves and restores user-mode addresses
	void *k_res_val;
	int ret;

	k_res_val = kzalloc(res_len, GFP_KERNEL);
	if (k_res_val == NULL)
		return -1;

	ret = ubcore_copy_from_user(k_res_val, (void __user *)(uintptr_t)arg->out.addr, res_len);
	if (ret != 0)
		goto kfree_addr;
	if (arg->in.type == (uint32_t)UBCORE_RES_KEY_VTP && dev->attr.virtualization == true) {
		ubcore_log_warn("FE device do not support query VTP, dev: %s, type: %u.\n",
			dev->dev_name, arg->in.type);
		goto kfree_addr;
	}

	key.type = (uint8_t)arg->in.type;
	key.key = arg->in.key;
	key.key_ext = arg->in.key_ext;
	key.key_cnt = arg->in.key_cnt;
	val.addr = (uint64_t)k_res_val;
	val.len = res_len;

	if (arg->in.type == UBCORE_RES_KEY_TPG) {
		user_tp_list_addr =
			(uint64_t)(((struct ubcore_res_tpg_val *)k_res_val)->tp_list);  // save
		if (ubcore_alloc_res_tp_list(&val) != 0)
			goto kfree_addr;
	}

	if (arg->in.type == UBCORE_RES_KEY_JETTY_GROUP) {
		// save
		user_jetty_list_addr =
			(uint64_t)(((struct ubcore_res_jetty_group_val *)k_res_val)->jetty_list);
		if (ubcore_alloc_res_jetty_list(dev, &val) != 0)
			goto kfree_addr;
	}

	if (arg->in.type == UBCORE_RES_KEY_URMA_DEV)
		ret = ubcore_query_res_dev(dev, &key, (struct ubcore_res_dev_val *)k_res_val);
	else
		ret = ubcore_query_resource(dev, &key, &val);

	if (arg->in.type == UBCORE_RES_KEY_TPG) {
		ubcore_dealloc_res_tp_list(user_tp_list_addr, &val);
		/* recover after use */
		((struct ubcore_res_tpg_val *)k_res_val)->tp_list = (uint32_t *)user_tp_list_addr;
	}

	if (arg->in.type == UBCORE_RES_KEY_JETTY_GROUP) {
		ubcore_dealloc_res_jetty_list(user_jetty_list_addr, &val);
		((struct ubcore_res_jetty_group_val *)k_res_val)->jetty_list =
			(uint32_t *)user_jetty_list_addr;  // recover after use
	}

	if (ret != 0)
		goto kfree_addr;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)arg->out.addr, k_res_val, res_len);

kfree_addr:
	kfree(k_res_val);
	return ret;
}

static int ubcore_cmd_query_res(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_query_res arg = {0};
	struct ubcore_device *dev;
	uint32_t res_len;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct ubcore_cmd_query_res));
	if (ret != 0)
		return ret;

	res_len = ubcore_get_query_res_len((uint32_t)arg.in.type);
	if (res_len != arg.out.len) {
		ubcore_log_err("Failed to check res len, type: %u, res_len: %u, len: %u.\n",
			       (uint32_t)arg.in.type, res_len, arg.out.len);
		return -1;
	}
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL || ubcore_check_dev_name_invalid(dev, arg.in.dev_name)) {
		ubcore_log_err("find dev failed, dev:%s, arg_in: %s.\n",
			       dev == NULL ? "NULL" : dev->dev_name, arg.in.dev_name);
		return -EINVAL;
	}

	ret = ubcore_query_res_arg(dev, &arg, res_len);
	if (ret != 0) {
		ubcore_put_device(dev);
		ubcore_log_err("Failed to query res by arg\n");
		return -1;
	}

	ubcore_put_device(dev);
	return ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct ubcore_cmd_query_res));
}

static int ubcore_cmd_parse(struct ubcore_cmd_hdr *hdr)
{
	switch (hdr->command) {
	case UBCORE_CMD_SHOW_UTP:
		return ubcore_cmd_show_utp(hdr);
	case UBCORE_CMD_QUERY_STATS:
		return ubcore_cmd_query_stats(hdr);
	case UBCORE_CMD_QUERY_RES:
		return ubcore_cmd_query_res(hdr);
	case UBCORE_CMD_ADD_EID:
		return ubcore_cmd_updata_ueid(hdr, UBCORE_MSG_ALLOC_EID);
	case UBCORE_CMD_DEL_EID:
		return ubcore_cmd_updata_ueid(hdr, UBCORE_MSG_DEALLOC_EID);
	case UBCORE_CMD_SET_EID_MODE:
		return ubcore_cmd_set_eid_mode(hdr);
	default:
		ubcore_log_err("bad ubcore command: %d.\n", (int)hdr->command);
		return -EINVAL;
	}
}

static long ubcore_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ubcore_cmd_hdr hdr;
	int ret;

	if (cmd == UBCORE_CMD) {
		ret = ubcore_copy_from_user(&hdr, (void *)arg, sizeof(struct ubcore_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBCORE_MAX_CMD_SIZE)) {
			ubcore_log_err("length of ioctl input parameter is out of range.\n");
			return -EINVAL;
		}

		return ubcore_cmd_parse(&hdr);
	}

	if (cmd == UBCORE_UVS_CMD) {
		ret = ubcore_copy_from_user(&hdr, (void *)arg, sizeof(struct ubcore_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBCORE_MAX_CMD_SIZE)) {
			ubcore_log_err("length of ioctl input parameter is out of range.\n");
			return -EINVAL;
		}
		return ubcore_uvs_cmd_parse(&hdr);
	}

	ubcore_log_err("bad ioctl command.\n");
	return -ENOIOCTLCMD;
}

static int ubcore_close(struct inode *i_node, struct file *filp)
{
	return 0;
}

static const struct file_operations g_ubcore_ops = {
	.owner = THIS_MODULE,
	.open = ubcore_open,
	.release = ubcore_close,
	.unlocked_ioctl = ubcore_ioctl,
	.compat_ioctl = ubcore_ioctl,
};

static int ubcore_register_sysfs(void)
{
	int ret;

	ret = alloc_chrdev_region(&g_ubcore_ctx.ubcore_devno, 0, 1, UBCORE_DEVICE_NAME);
	if (ret != 0) {
		ubcore_log_err("alloc chrdev region failed, ret:%d.\n", ret);
		return ret;
	}

	cdev_init(&g_ubcore_ctx.ubcore_cdev, &g_ubcore_ops);
	ret = cdev_add(&g_ubcore_ctx.ubcore_cdev, g_ubcore_ctx.ubcore_devno, 1);
	if (ret != 0) {
		ubcore_log_err("chrdev add failed, ret:%d.\n", ret);
		goto unreg_cdev_region;
	}

	/* /sys/class/ubus/ubcore */
	g_ubcore_ctx.ubcore_class = class_create(THIS_MODULE, UBCORE_CLASS_NAME);
	if (IS_ERR(g_ubcore_ctx.ubcore_class)) {
		ret = (int)PTR_ERR(g_ubcore_ctx.ubcore_class);
		ubcore_log_err("couldn't create class %s, ret:%d.\n", UBCORE_CLASS_NAME, ret);
		goto del_cdev;
	}

	/* /dev/ubcore */
	g_ubcore_ctx.ubcore_dev =
		device_create(g_ubcore_ctx.ubcore_class, NULL, g_ubcore_ctx.ubcore_devno, NULL,
			      UBCORE_DEVICE_NAME);
	if (IS_ERR(g_ubcore_ctx.ubcore_dev)) {
		ret = (int)PTR_ERR(g_ubcore_ctx.ubcore_dev);
		ubcore_log_err("couldn't create device %s, ret:%d.\n", UBCORE_DEVICE_NAME, ret);
		goto destroy_class;
	}
	ubcore_log_info("ubcore device created success.\n");
	return 0;

destroy_class:
	class_destroy(g_ubcore_ctx.ubcore_class);
del_cdev:
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
unreg_cdev_region:
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
	return ret;
}

static void ubcore_unregister_sysfs(void)
{
	device_destroy(g_ubcore_ctx.ubcore_class, g_ubcore_ctx.ubcore_cdev.dev);
	class_destroy(g_ubcore_ctx.ubcore_class);
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
	ubcore_log_info("ubcore device destroyed success.\n");
}

static void ubcore_ipv4_to_netaddr(struct ubcore_net_addr *netaddr, __be32 ipv4)
{
	netaddr->net_addr.in4.reserved1 = 0;
	netaddr->net_addr.in4.reserved2 = htonl(UBCORE_IPV4_MAP_IPV6_PREFIX);
	netaddr->net_addr.in4.addr = ipv4;
}

static void ubcore_sip_init(struct ubcore_sip_info *sip, struct ubcore_device *pf_dev,
	const struct ubcore_net_addr *netaddr, uint8_t *port_list,
	uint8_t port_cnt, uint32_t prefix_len, uint32_t mtu)
{
	(void)memcpy(sip->dev_name, pf_dev->dev_name, UBCORE_MAX_DEV_NAME);
	(void)memcpy(&sip->addr, netaddr, sizeof(struct ubcore_net_addr));
	if (port_list != NULL)
		(void)memcpy(sip->port_id, port_list, UBCORE_MAX_PORT_CNT);
	else
		ubcore_log_warn("no one set port_list\n");

	sip->port_cnt = port_cnt;
	sip->prefix_len = prefix_len;
	sip->mtu = mtu;
}

static void ubcore_add_net_addr(struct ubcore_device *tpf_dev, struct ubcore_device *pf_dev,
	struct ubcore_net_addr *netaddr, struct net_device *netdev, uint32_t prefix_len)
{
	struct ubcore_sip_info sip = {0};
	uint8_t *port_list = NULL;
	uint8_t port_cnt = 0;
	uint32_t index;
	int ret;

	/* get driver set nedev port */
	ubcore_find_port_netdev(pf_dev, netdev, &port_list, &port_cnt);

	ubcore_sip_init(&sip, pf_dev,
		netaddr, port_list, port_cnt, prefix_len, (uint32_t)netdev->mtu);

	ret = ubcore_lookup_sip_idx(&sip, &index);
	if (ret == 0) {
		ubcore_log_err("sip already exists\n");
		return;
	}
	index = ubcore_sip_idx_alloc(0);

	if (tpf_dev->ops->add_net_addr != NULL &&
		tpf_dev->ops->add_net_addr(tpf_dev, netaddr, index) != 0)
		ubcore_log_err("Failed to set net addr");

	/* add net_addr entry, record idx -> netaddr mapping */
	(void)ubcore_add_sip_entry(&sip, index);

	/* nodify uvs add sip info */
	if (ubcore_get_netlink_valid() == true)
		(void)ubcore_notify_uvs_add_sip(tpf_dev, &sip, index);

	/* The ubcore sip table and up/down events are updated synchronously, and the uvs
	 * is abnormally disconnected. After waiting for the pull-up,
	 * the sip table in the kernel state is actively synchronized.
	 */
}

static void ubcore_delete_net_addr(struct ubcore_device *tpf_dev, struct ubcore_device *pf_dev,
	struct ubcore_net_addr *netaddr, struct net_device *netdev, uint32_t prefix_len)
{
	struct ubcore_sip_info sip = {0};
	uint8_t *port_list = NULL;
	uint8_t port_cnt = 0;
	uint32_t index;

	ubcore_find_port_netdev(pf_dev, netdev, &port_list, &port_cnt);

	ubcore_sip_init(&sip, pf_dev,
		netaddr, port_list, port_cnt, prefix_len, (uint32_t)netdev->mtu);
	if (ubcore_lookup_sip_idx(&sip, &index) != 0)
		return;

	if (tpf_dev->ops->delete_net_addr != NULL &&
		tpf_dev->ops->delete_net_addr(tpf_dev, index) != 0)
		ubcore_log_err("Failed to delete net addr");

	(void)ubcore_del_sip_entry(index);
	(void)ubcore_sip_idx_free(index);
	/* nodify uvs delete sip info */
	if (ubcore_get_netlink_valid() == true)
		(void)ubcore_notify_uvs_del_sip(tpf_dev, &sip, index);

	/* The ubcore sip table and up/down events are updated synchronously,
	 * and the uvs is abnormally disconnected. After waiting for the pull-up,
	 * the sip table in the kernel state is actively synchronized
	 */
}

static void ubcore_update_eid(struct ubcore_device *dev,
	struct ubcore_net_addr *netaddr, bool is_add)
{
	union ubcore_eid *eid;

	if (dev->transport_type <= UBCORE_TRANSPORT_INVALID ||
		dev->transport_type >= UBCORE_TRANSPORT_MAX)
		return;

	if (!dev->dynamic_eid) {
		ubcore_log_err("static mode does not allow modify of eid");
		return;
	}
	eid = (union ubcore_eid *)(void *)&netaddr->net_addr;
	if (dev->cfg.pattern == (uint8_t)UBCORE_PATTERN_1)
		ubcore_update_pattern1_eid(dev, eid, is_add);
	else
		ubcore_update_pattern3_eid(dev, eid, is_add);
}

static int ubcore_handle_inetaddr_event(struct net_device *netdev, unsigned long event,
					struct ubcore_net_addr *netaddr, uint32_t prefix_len)
{
	struct net_device *real_netdev;
	struct ubcore_net_addr real_netaddr;
	struct ubcore_device **devices;
	uint32_t num_devices = 0;
	struct ubcore_device *tpf_dev;
	struct ubcore_device *dev;

	uint32_t i;

	if (netdev == NULL || netdev->reg_state >= NETREG_UNREGISTERING)
		return NOTIFY_DONE;

	if (is_vlan_dev(netdev)) {
		real_netdev = vlan_dev_real_dev(netdev);
		(void)ubcore_fill_netaddr_macvlan(&real_netaddr, real_netdev, netaddr->type);
	} else {
		real_netdev = netdev;
		real_netaddr = *netaddr;
	}
	tpf_dev = ubcore_find_tpf_device(&real_netaddr, UBCORE_TRANSPORT_UB);
	devices = ubcore_get_devices_from_netdev(real_netdev, &num_devices);
	if (devices == NULL) {
		ubcore_put_device(tpf_dev);
		return NOTIFY_DONE;
	}
	for (i = 0; i < num_devices; i++) {
		dev = devices[i];
		switch (event) {
		case NETDEV_UP:
			if (tpf_dev)
				ubcore_add_net_addr(tpf_dev, dev, netaddr, netdev, prefix_len);
			ubcore_update_eid(dev, netaddr, true);
			break;
		case NETDEV_DOWN:
			if (tpf_dev)
				ubcore_delete_net_addr(tpf_dev, dev, netaddr, netdev, prefix_len);
			ubcore_update_eid(dev, netaddr, false);
			break;
		default:
			break;
		}
	}
	ubcore_put_device(tpf_dev);
	ubcore_put_devices(devices, num_devices);
	return NOTIFY_OK;
}

static int ubcore_ipv6_notifier_call(struct notifier_block *nb,
	unsigned long event, void *arg)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->idev == NULL || ifa->idev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->idev->dev;
	ubcore_log_info("Get a ipv6 event %s from netdev %s%s ip %pI6c prefixlen %u",
		netdev_cmd_to_name(event), netdev_name(netdev), netdev_reg_state(netdev),
		&ifa->addr, ifa->prefix_len);

	memset(&netaddr, 0, sizeof(struct ubcore_net_addr));
	(void)memcpy(&netaddr.net_addr, &ifa->addr, sizeof(struct in6_addr));
	(void)ubcore_fill_netaddr_macvlan(&netaddr, netdev, UBCORE_NET_ADDR_TYPE_IPV6);

	if (netaddr.net_addr.in6.subnet_prefix == cpu_to_be64(UBCORE_LOCAL_SHUNET))
		/* When mtu changes, intercept the ipv6 address up/down that triggers fe80 */
		return NOTIFY_DONE;
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr, ifa->prefix_len);
}

static int ubcore_ipv4_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->ifa_dev == NULL || ifa->ifa_dev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->ifa_dev->dev;
	ubcore_log_info("Get a ipv4 event %s netdev %s%s ip %pI4 prefixlen %hhu",
		netdev_cmd_to_name(event), netdev_name(netdev), netdev_reg_state(netdev),
		&ifa->ifa_address, ifa->ifa_prefixlen);

	memset(&netaddr, 0, sizeof(struct ubcore_net_addr));
	ubcore_ipv4_to_netaddr(&netaddr, ifa->ifa_address);
	(void)ubcore_fill_netaddr_macvlan(&netaddr, netdev, UBCORE_NET_ADDR_TYPE_IPV4);
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr, (uint32_t)ifa->ifa_prefixlen);
}

static void ubcore_add_ipv4_entry(struct list_head *list, __be32 ipv4, uint32_t prefix_len,
	struct net_device *netdev)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);
	if (na_entry == NULL)
		return;

	ubcore_ipv4_to_netaddr(&na_entry->addr, ipv4);
	(void)ubcore_fill_netaddr_macvlan(&na_entry->addr, netdev, UBCORE_NET_ADDR_TYPE_IPV4);
	na_entry->prefix_len = prefix_len;
	list_add_tail(&na_entry->node, list);
}

static void ubcore_add_ipv6_entry(struct list_head *list, struct in6_addr *ipv6,
	uint32_t prefix_len, struct net_device *netdev)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);
	if (na_entry == NULL)
		return;

	(void)memcpy(&na_entry->addr.net_addr, ipv6, sizeof(struct in6_addr));
	(void)ubcore_fill_netaddr_macvlan(&na_entry->addr, netdev, UBCORE_NET_ADDR_TYPE_IPV6);
	na_entry->prefix_len = prefix_len;
	list_add_tail(&na_entry->node, list);
}

static void ubcore_netdev_get_ipv4(struct net_device *netdev, struct list_head *list)
{
	struct in_ifaddr *ifa;
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(netdev);
	if (in_dev == NULL) {
		rcu_read_unlock();
		return;
	}

	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		ubcore_add_ipv4_entry(list, ifa->ifa_address, ifa->ifa_prefixlen, netdev);
	}
	rcu_read_unlock();
}

static void ubcore_netdev_get_ipv6(struct net_device *netdev, struct list_head *list)
{
	struct inet6_ifaddr *ifa;
	struct inet6_dev *in_dev;

	in_dev = in6_dev_get(netdev);
	if (in_dev == NULL)
		return;

	read_lock_bh(&in_dev->lock);
	list_for_each_entry(ifa, &in_dev->addr_list, if_list) {
		ubcore_add_ipv6_entry(list, (struct in6_addr *)&ifa->addr, ifa->prefix_len, netdev);
	}
	read_unlock_bh(&in_dev->lock);
	in6_dev_put(in_dev);
}

void ubcore_update_default_eid(struct ubcore_device *dev, bool is_add)
{
	struct net_device *netdev = dev->netdev;
	struct ubcore_net_addr_node *na_entry;
	struct ubcore_device *tpf_dev = NULL;
	struct ubcore_net_addr_node *next;
	LIST_HEAD(na_list);

	/* Do not modify eid if the driver already set default eid other than 0 */
	if (netdev == NULL || !(dev->eid_table.eid_entries[0].eid.in6.interface_id == 0 &&
		dev->eid_table.eid_entries[0].eid.in6.subnet_prefix == 0))
		return;

	ubcore_netdev_get_ipv4(netdev, &na_list);
	ubcore_netdev_get_ipv6(netdev, &na_list);
	list_for_each_entry_safe(na_entry, next, &na_list, node) {
		if (na_entry->addr.net_addr.in6.subnet_prefix == cpu_to_be64(UBCORE_LOCAL_SHUNET))
			continue;
		tpf_dev = ubcore_find_tpf_device(&na_entry->addr, UBCORE_TRANSPORT_UB);
		if (tpf_dev)
			is_add == true ?
				ubcore_add_net_addr(tpf_dev, dev, &na_entry->addr,
					netdev, na_entry->prefix_len) :
				ubcore_delete_net_addr(tpf_dev, dev, &na_entry->addr,
					netdev, na_entry->prefix_len);
		if (tpf_dev)
			ubcore_put_device(tpf_dev);
		ubcore_update_eid(dev, &na_entry->addr, is_add);
		list_del(&na_entry->node);
		kfree(na_entry);
	}
}

void ubcore_update_netaddr(struct ubcore_device *dev, struct net_device *netdev, bool add)
{
	struct ubcore_net_addr_node *na_entry;
	struct ubcore_net_addr_node *next;
	LIST_HEAD(na_list);

	/* ipv4 */
	ubcore_netdev_get_ipv4(netdev, &na_list);
	ubcore_netdev_get_ipv6(netdev, &na_list);

	list_for_each_entry_safe(na_entry, next, &na_list, node) {
		if (add) {
			if (dev->ops->add_net_addr != NULL &&
				dev->ops->add_net_addr(dev, &na_entry->addr, 0) != 0)
				ubcore_log_err("Failed to add net addr");
		} else {
			if (dev->ops->delete_net_addr != NULL &&
				dev->ops->delete_net_addr(dev, 0) != 0)
				ubcore_log_err("Failed to delete net addr");
		}
		list_del(&na_entry->node);
		kfree(na_entry);
	}
}

static int ubcore_add_netaddr(struct ubcore_device *dev, struct net_device *netdev)
{
	if (netdev->reg_state >= NETREG_UNREGISTERING)
		return NOTIFY_DONE;

	ubcore_update_netaddr(dev, netdev, true);
	return NOTIFY_OK;
}

static int ubcore_remove_netaddr(struct ubcore_device *dev, struct net_device *netdev)
{
	if (netdev->reg_state >= NETREG_UNREGISTERED)
		return NOTIFY_DONE;

	ubcore_update_netaddr(dev, netdev, false);
	return NOTIFY_OK;
}

static void ubcore_chang_mtu(struct ubcore_device *dev, struct net_device *netdev)
{
	struct ubcore_device *tpf_dev;
	struct ubcore_sip_info *old_sip;
	struct ubcore_sip_info new_sip;
	uint32_t max_cnt;
	uint32_t i;

	if (ubcore_get_netlink_valid() == false)
		return;

	tpf_dev = ubcore_find_tpf_device(NULL, UBCORE_TRANSPORT_UB);
	max_cnt = ubcore_get_sip_max_cnt();

	for (i = 0; i < max_cnt; i++) {
		if (tpf_dev) {
			old_sip = ubcore_lookup_sip_info(i);
			if (old_sip == NULL)
				continue;
			new_sip = *old_sip;
			new_sip.mtu = netdev->mtu;
			if (memcmp(old_sip->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME) == 0) {
				(void)ubcore_notify_uvs_del_sip(tpf_dev, old_sip, i);
				(void)ubcore_notify_uvs_add_sip(tpf_dev, &new_sip, i);
				ubcore_log_info("dev_name: %s, mtu: %u change mtu: %u\n",
					dev->dev_name, old_sip->mtu, new_sip.mtu);
				old_sip->mtu = netdev->mtu;
			}
		}
	}
	if (tpf_dev)
		ubcore_put_device(tpf_dev);
}

static int ubcore_netdev_event_change_upper(struct ubcore_device *dev,
	struct net_device *slave,
	struct netdev_notifier_changeupper_info *info)
{
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	struct net_device *bond = info->upper_dev;
	int ret;

	if (dev == NULL || dev->ops->bond_add == NULL ||
		dev->ops->bond_remove == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		ubcore_put_device(dev);
		return -EINVAL;
	}

	ubcore_log_info("Event with master netdev %s and slave netdev %s",
		netdev_name(bond), netdev_name(slave));

	/* dev may be unregistered so it has to be put_device here */
	ubcore_put_device(dev);

	if (info->linking) {
		lag_upper_info = info->upper_info;
		ret = dev->ops->bond_add(bond, slave, lag_upper_info);
		if (ret != 0) {
			ubcore_log_err("Failed to bond_add and ret value is %d", ret);
			return -EIO;
		}
	} else {
		ret = dev->ops->bond_remove(bond, slave);
		if (ret != 0) {
			ubcore_log_err("Failed to bond_remove and ret value is %d", ret);
			return -EIO;
		}
	}
	ubcore_log_info("Success to deal with event NETDEV_CHANGEUPPER");
	return 0;
}

static int ubcore_netdev_event_change_lower_state(struct ubcore_device *dev,
	struct net_device *slave,
	struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info = NULL;
	struct net_device *bond = NULL;
	int ret;

	if (dev == NULL || dev->ops->slave_update == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		return -EINVAL;
	}

	bond = netdev_master_upper_dev_get_rcu(slave);
	if (bond)
		ubcore_log_info("Event with master netdev %s and slave netdev %s",
			netdev_name(bond), netdev_name(slave));
	else
		ubcore_log_info("Event with master netdev NULL and slave netdev %s",
			netdev_name(slave));

	lag_lower_info = info->lower_state_info;
	ret = dev->ops->slave_update(bond, slave, lag_lower_info);
	if (ret != 0) {
		ubcore_log_err("Failed to slave_update and ret value is %d", ret);
		return -EIO;
	}
	ubcore_log_info("Success to deal with event NETDEV_CHANGELOWERSTATE");
	return 0;
}

static struct net_device *ubcore_find_master_netdev(unsigned long event,
	struct netdev_notifier_changeupper_info *info,
	struct net_device *slave)
{
	/* When we need to remove slaves from the bond device,
	 * we cannot find the ubcore dev by the netdev provided by unlink NETDEV_CHANGEUPPER.
	 * It has been unregistered. We need to find ubcore dev by the master netdev
	 */
	struct net_device *bond = NULL;

	if (event == NETDEV_CHANGEUPPER && !info->linking)
		bond = info->upper_dev;
	else if (event == NETDEV_CHANGELOWERSTATE)
		bond = netdev_master_upper_dev_get_rcu(slave);

	return bond;
}

static int ubcore_net_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);
	struct ubcore_device **devices;
	struct net_device *real_netdev;
	struct ubcore_device *dev;
	uint32_t num_devices = 0;
	uint32_t i;

	if (netdev == NULL)
		return NOTIFY_DONE;

	if (is_vlan_dev(netdev))
		real_netdev = vlan_dev_real_dev(netdev);
	else
		real_netdev = netdev;

	ubcore_log_info("Get a net event %s from ubcore_dev %s%s", netdev_cmd_to_name(event),
			netdev_name(netdev), netdev_reg_state(netdev));

	devices = ubcore_get_devices_from_netdev(real_netdev, &num_devices);
	if (devices == NULL) {
		if (event != NETDEV_CHANGEUPPER && event != NETDEV_CHANGELOWERSTATE)
			return NOTIFY_DONE;
		real_netdev = ubcore_find_master_netdev(event, arg, netdev);
		if (real_netdev == NULL) {
			ubcore_log_warn("Can not find master netdev by slave netdev %s",
				netdev_name(netdev));
			return NOTIFY_DONE;
		}
		ubcore_log_info("Success to find master netdev %s",
			netdev_name(real_netdev));
		devices = ubcore_get_devices_from_netdev(real_netdev, &num_devices);
		if (devices == NULL) {
			ubcore_log_warn("Can not find devices from master netdev %s",
				netdev_name(real_netdev));
			return NOTIFY_DONE;
		}
	}

	for (i = 0; i < num_devices; i++) {
		dev = devices[i];
		switch (event) {
		case NETDEV_REGISTER:
		case NETDEV_UP:
			if (dev->transport_type != UBCORE_TRANSPORT_UB)
				ubcore_add_netaddr(dev, netdev);
			break;
		case NETDEV_UNREGISTER:
		case NETDEV_DOWN:
			if (dev->transport_type != UBCORE_TRANSPORT_UB)
				ubcore_remove_netaddr(dev, netdev);
			break;
		case NETDEV_CHANGEADDR:
			if (dev->transport_type != UBCORE_TRANSPORT_UB) {
				ubcore_remove_netaddr(dev, netdev);
				ubcore_add_netaddr(dev, netdev);
			}
			break;
		case NETDEV_CHANGEMTU:
			if (dev->transport_type == UBCORE_TRANSPORT_UB)
				ubcore_chang_mtu(dev, netdev);
			break;
		case NETDEV_CHANGEUPPER:
			if (dev->transport_type == UBCORE_TRANSPORT_UB)
				(void)ubcore_netdev_event_change_upper(dev, netdev, arg);
			break;
		case NETDEV_CHANGELOWERSTATE:
			if (dev->transport_type == UBCORE_TRANSPORT_UB)
				(void)ubcore_netdev_event_change_lower_state(dev, netdev, arg);
			break;
		default:
			break;
		}
	}
	if (event != NETDEV_CHANGEUPPER)
		ubcore_put_devices(devices, num_devices);
	return NOTIFY_OK;
}

static struct notifier_block ubcore_ipv6_notifier = {
	.notifier_call = ubcore_ipv6_notifier_call,
};

static struct notifier_block ubcore_ipv4_notifier = {
	.notifier_call = ubcore_ipv4_notifier_call,
};

static struct notifier_block ubcore_net_notifier = {
	.notifier_call = ubcore_net_notifier_call,
};

static int ubcore_register_notifiers(void)
{
	int ret;

	ret = register_netdevice_notifier(&ubcore_net_notifier);
	if (ret != 0) {
		pr_err("Failed to register netdev notifier, ret = %d\n", ret);
		return ret;
	}
	ret = register_inetaddr_notifier(&ubcore_ipv4_notifier);
	if (ret != 0) {
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		pr_err("Failed to register inetaddr notifier, ret = %d\n", ret);
		return -1;
	}
	ret = register_inet6addr_notifier(&ubcore_ipv6_notifier);
	if (ret != 0) {
		(void)unregister_inetaddr_notifier(&ubcore_ipv4_notifier);
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		pr_err("Failed to register inet6addr notifier, ret = %d\n", ret);
		return -1;
	}
	return 0;
}

static void ubcore_unregister_notifiers(void)
{
	(void)unregister_inet6addr_notifier(&ubcore_ipv6_notifier);
	(void)unregister_inetaddr_notifier(&ubcore_ipv4_notifier);
	(void)unregister_netdevice_notifier(&ubcore_net_notifier);
}

static int __init ubcore_init(void)
{
	int ret;

	ret = ubcore_register_sysfs();
	if (ret != 0)
		return ret;

	(void)ubcore_sip_table_init();

	if (ubcore_netlink_init() != 0) {
		ubcore_sip_table_uninit();
		ubcore_unregister_sysfs();
		return -1;
	}

	ret = ubcore_register_notifiers();
	if (ret != 0) {
		pr_err("Failed to register notifiers\n");
		ubcore_netlink_exit();
		ubcore_sip_table_uninit();
		ubcore_unregister_sysfs();
		return -1;
	}

	ubcore_log_info("ubcore module init success.\n");
	return 0;
}

static void __exit ubcore_exit(void)
{
	ubcore_unregister_notifiers();
	ubcore_sip_table_uninit();
	ubcore_netlink_exit();
	ubcore_unregister_sysfs();
	ubcore_log_info("ubcore module exits.\n");
}

module_init(ubcore_init);
module_exit(ubcore_exit);

MODULE_DESCRIPTION("Kernel module for ubus");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL v2");
