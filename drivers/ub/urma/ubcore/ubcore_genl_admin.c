// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Author: Yanchao Zhao
 * Create: 2024-01-18
 * Note:
 * History: 2024-01-18: create file
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/ctype.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include "ubcore_genl_define.h"
#include "urma/ubcore_api.h"
#include "ubcore_msg.h"
#include "urma/ubcore_uapi.h"
#include "ubcore_priv.h"
#include "ubcore_cmd.h"
#include "ubcore_device.h"
#include "ubcore_genl_admin.h"

#define CB_ARGS_DEV_BUF  0
#define CB_ARGS_CMD_TYPE 1
#define CB_ARGS_SART_IDX 2
#define CB_ARGS_NEXT_TYPE 3
#define CB_ARGS_BUF_LEN 4
#define CB_ARGS_KEY_CNT 5

enum {
	UBCORE_RES_TPG_TP_CNT,
	UBCORE_RES_TPG_DSCP,
	UBCORE_RES_TPG_TP_VAL,
	UBCORE_RES_JTGRP_JETTY_CNT,
	UBCORE_RES_JTGRP_JETTY_VAL,
	UBCORE_RES_SEGVAL_SEG_CNT,
	UBCORE_RES_SEGVAL_SEG_VAL,
	UBCORE_RES_DEV_SEG_CNT,
	UBCORE_RES_DEV_SEG_VAL,
	UBCORE_RES_DEV_JFS_CNT,
	UBCORE_RES_DEV_JFS_VAL,
	UBCORE_RES_DEV_JFR_CNT,
	UBCORE_RES_DEV_JFR_VAL,
	UBCORE_RES_DEV_JFC_CNT,
	UBCORE_RES_DEV_JFC_VAL,
	UBCORE_RES_DEV_JETTY_CNT,
	UBCORE_RES_DEV_JETTY_VAL,
	UBCORE_RES_DEV_JTGRP_CNT,
	UBCORE_RES_DEV_JTGRP_VAL,
	UBCORE_RES_DEV_RC_CNT,
	UBCORE_RES_DEV_RC_VAL,
	UBCORE_RES_DEV_VTP_CNT,
	UBCORE_RES_DEV_VTP_VAL,
	UBCORE_RES_DEV_TP_CNT,
	UBCORE_RES_DEV_TP_VAL,
	UBCORE_RES_DEV_TPG_CNT,
	UBCORE_RES_DEV_TPG_VAL,
	UBCORE_RES_DEV_UTP_CNT,
	UBCORE_RES_DEV_UTP_VAL,
	UBCORE_RES_UPI_VAL,
	UBCORE_RES_VTP_VAL,
	UBCORE_RES_TP_VAL,
	UBCORE_RES_UTP_VAL,
	UBCORE_RES_JFS_VAL,
	UBCORE_RES_JFR_VAL,
	UBCORE_RES_JETTY_VAL,
	UBCORE_RES_JFC_VAL,
	UBCORE_RES_RC_VAL,
	UBCORE_ATTR_RES_LAST
};

static int ubcore_parse_admin_res_cmd(struct netlink_callback *cb, void *dst, uint32_t copy_len)
{
	struct nlattr **attrs = genl_dumpit_info(cb)->attrs;
	uint64_t args_addr;

	if (!attrs[UBCORE_HDR_ARGS_LEN] || !attrs[UBCORE_HDR_ARGS_ADDR])
		return -EINVAL;

	args_addr = nla_get_u64(attrs[UBCORE_HDR_ARGS_ADDR]);

	return ubcore_copy_from_user(dst, (void __user *)(uintptr_t)args_addr,
				    copy_len);
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
		(void)ubcore_add_ueid(dev, dev->attr.fe_idx, &cfg);
	else
		(void)ubcore_delete_ueid(dev, dev->attr.fe_idx, &cfg);
}

static void ubcore_update_pattern3_eid(struct ubcore_device *dev,
	union ubcore_eid *eid, bool is_add)
{
	struct ubcore_ueid_cfg cfg;
	uint32_t pattern3_upi = 0;
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
			(void)ubcore_add_ueid(dev, dev->attr.fe_idx, &cfg);
		else
			(void)ubcore_delete_ueid(dev, dev->attr.fe_idx, &cfg);
	} else {
		ubcore_log_err("upi not configured\n");
	}
}

int ubcore_show_utp_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_res_utp_val utp_info = {0};
	struct ubcore_res_key key = {0};
	struct ubcore_res_val val = {0};
	struct ubcore_cmd_show_utp arg;
	struct ubcore_device *dev;
	uint64_t args_addr;
	int ret = -EINVAL;

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] || !info->attrs[UBCORE_HDR_ARGS_ADDR])
		return ret;
	args_addr = nla_get_u64(info->attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)args_addr,
				    sizeof(struct ubcore_cmd_show_utp));
	if (ret != 0)
		return -EPERM;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
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

int ubcore_query_stats_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_cmd_query_stats arg = {0};
	struct ubcore_stats_com_val com_val;
	struct ubcore_stats_key key = {0};
	struct ubcore_stats_val val;
	struct ubcore_device *dev;
	uint64_t args_addr;
	int ret = -EINVAL;

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] || !info->attrs[UBCORE_HDR_ARGS_ADDR])
		return ret;
	args_addr = nla_get_u64(info->attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)args_addr,
				    sizeof(struct ubcore_cmd_query_stats));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
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
	return ubcore_copy_to_user((void __user *)(uintptr_t)args_addr, &arg,
				   sizeof(struct ubcore_cmd_query_stats));
}

static int ubcore_update_ueid(struct netlink_callback *cb, enum ubcore_msg_opcode op)
{
	struct ubcore_cmd_update_ueid arg;
	struct ubcore_update_eid_ctx *ctx;
	struct net *net = &init_net;
	struct ubcore_device *dev;
	int ret = -EINVAL;
	struct timespec64 tv;

	ret = ubcore_parse_admin_res_cmd(cb, &arg, sizeof(struct ubcore_cmd_update_ueid));
	if (ret)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev_name: %s failed.\n", arg.in.dev_name);
		return -EPERM;
	}

	if (dev->dynamic_eid) {
		ubcore_log_err("The dynamic mode of pf does not support eid change\n");
		ubcore_put_device(dev);
		return -EPERM;
	}
	if (dev->attr.tp_maintainer && ubcore_get_netlink_valid() == false) {
		ubcore_put_device(dev);
		return -EPERM;
	}

	if (arg.in.ns_fd >= 0) {
		net = get_net_ns_by_fd(arg.in.ns_fd);
		if (IS_ERR(net) || !ubcore_dev_accessible(dev, net)) {
			ubcore_put_device(dev);
			ubcore_log_err("invalid net ns.\n");
			return (int)PTR_ERR(net);
		}
	} else if (op == UBCORE_MSG_ALLOC_EID) {
		net = read_pnet(&dev->ldev.net);
	}

	ctx = kcalloc(1, sizeof(struct ubcore_update_eid_ctx), GFP_KERNEL);
	if (ctx == NULL) {
		ubcore_put_device(dev);
		if (arg.in.ns_fd >= 0)
			put_net(net);
		return -ENOMEM;
	}
	ret = ubcore_msg_discover_eid(dev, arg.in.eid_index, op, net, ctx);
	if (ret != 0) {
		ubcore_put_device(dev);
		if (arg.in.ns_fd >= 0)
			put_net(net);
		kfree(ctx);
		return -EPERM;
	}

	if (arg.in.ns_fd >= 0)
		ctx->net = net;
	ctx->dev = dev;
	ktime_get_ts64(&tv);
	ctx->start_ts = tv.tv_sec;
	cb->args[0] = (long)ctx;
	return 0;
}

int ubcore_set_eid_mode_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_cmd_set_eid_mode arg;
	struct ubcore_device *dev;
	struct ubcore_event event;
	union ubcore_eid eid;
	uint64_t args_addr;
	int ret = -EINVAL;
	uint32_t i;

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] || !info->attrs[UBCORE_HDR_ARGS_ADDR])
		return ret;
	args_addr = nla_get_u64(info->attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)args_addr,
		sizeof(struct ubcore_cmd_set_eid_mode));
	if (ret != 0)
		return -EPERM;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev_name: %s failed.\n", arg.in.dev_name);
		return -EPERM;
	}
	if (dev->dynamic_eid == arg.in.eid_mode) {
		ubcore_put_device(dev);
		return 0;
	}

	/* change eid mode, need to flush eids */
	event.ub_dev = dev;
	event.event_type = UBCORE_EVENT_EID_CHANGE;
	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == true) {
			eid = dev->eid_table.eid_entries[i].eid;
			if (dev->attr.pattern == (uint8_t)UBCORE_PATTERN_1)
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

int ubcore_set_ns_mode_ops(struct sk_buff *skb, struct genl_info *info)
{
	uint8_t ns_mode;

	if (!info->attrs[UBCORE_ATTR_NS_MODE])
		return -EINVAL;

	ns_mode = nla_get_u8(info->attrs[UBCORE_ATTR_NS_MODE]);
	return ubcore_set_ns_mode((ns_mode == 0 ? false : true));
}

int ubcore_set_dev_ns_ops(struct sk_buff *skb, struct genl_info *info)
{
	if (!info->attrs[UBCORE_ATTR_DEV_NAME] || !info->attrs[UBCORE_ATTR_NS_FD])
		return -EINVAL;

	return ubcore_set_dev_ns((char *)nla_data(info->attrs[UBCORE_ATTR_DEV_NAME]),
		nla_get_u32(info->attrs[UBCORE_ATTR_NS_FD]));
}

static void ubcore_fill_res_binary(void *res_buf, struct sk_buff *msg,
	struct netlink_callback *cb, int attrtype)
{
	if (nla_put(msg, attrtype, (int)cb->args[CB_ARGS_BUF_LEN], res_buf))
		return;

	cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
}

static void ubcore_fill_res_tpg(void *res_buf, struct sk_buff *msg, struct netlink_callback *cb)
{
	uint32_t idx = (uint32_t)cb->args[CB_ARGS_SART_IDX];
	struct ubcore_res_tpg_val *tpg_val = res_buf;

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_TPG_TP_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_TPG_TP_CNT, tpg_val->tp_cnt))
			return;
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_TPG_DSCP;
	}
	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_TPG_DSCP) {
		if (nla_put_u8(msg, UBCORE_RES_TPG_DSCP, tpg_val->dscp))
			return;
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_TPG_TP_VAL;
	}

	for (; idx < tpg_val->tp_cnt; ++idx) {
		if (nla_put_u32(msg, UBCORE_RES_TPG_TP_VAL, tpg_val->tp_list[idx]))
			return;
		cb->args[CB_ARGS_SART_IDX] = idx;
	}
	if (idx == tpg_val->tp_cnt)
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
}

static void ubcore_fill_res_jtgrp(void *res_buf, struct sk_buff *msg, struct netlink_callback *cb)
{
	struct ubcore_res_jetty_group_val *jtgrp_val = res_buf;
	uint32_t idx = (uint32_t)cb->args[CB_ARGS_SART_IDX];

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_JTGRP_JETTY_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_JTGRP_JETTY_CNT, jtgrp_val->jetty_cnt))
			return;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_JTGRP_JETTY_VAL;
	}

	for (; idx < jtgrp_val->jetty_cnt; ++idx) {
		if (nla_put_u32(msg, UBCORE_RES_JTGRP_JETTY_VAL, jtgrp_val->jetty_list[idx]))
			return;

		cb->args[CB_ARGS_SART_IDX] = idx;
	}

	if (idx == jtgrp_val->jetty_cnt)
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
}

static void ubcore_fill_res_seg(void *res_buf, struct sk_buff *msg,
	struct netlink_callback *cb)
{
	uint32_t idx = (uint32_t)cb->args[CB_ARGS_SART_IDX];
	struct ubcore_res_seg_val *seg_val = res_buf;

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_SEGVAL_SEG_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_SEGVAL_SEG_CNT, seg_val->seg_cnt))
			return;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_SEGVAL_SEG_VAL;
	}
	for (; idx < seg_val->seg_cnt; ++idx) {
		if (nla_put(msg, UBCORE_RES_SEGVAL_SEG_VAL, sizeof(struct ubcore_seg_info),
		    seg_val->seg_list + idx))
			return;

		cb->args[CB_ARGS_SART_IDX] = idx;
	}

	if (idx == seg_val->seg_cnt)
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
}

static int ubcore_fill_res_dev_ta_cnt(void *res_buf, struct sk_buff *msg,
						struct netlink_callback *cb)
{
	struct ubcore_res_dev_ta_val *dev_val = res_buf;

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_SEG_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_SEG_CNT, dev_val->seg_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_JFS_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_JFS_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_JFS_CNT, dev_val->jfs_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_JFR_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_JFR_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_JFR_CNT, dev_val->jfr_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_JFC_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_JFC_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_JFC_CNT, dev_val->jfc_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_JETTY_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_JETTY_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_JETTY_CNT, dev_val->jetty_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_JTGRP_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_JTGRP_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_JTGRP_CNT, dev_val->jetty_group_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_RC_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_RC_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_RC_CNT, dev_val->rc_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
	}

	return 0;
}

static int ubcore_fill_res_dev_tp_cnt(void *res_buf, struct sk_buff *msg,
						struct netlink_callback *cb)
{
	struct ubcore_res_dev_tp_val *dev_val = res_buf;

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_VTP_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_VTP_CNT, dev_val->vtp_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_TP_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_TP_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_TP_CNT, dev_val->tp_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_TPG_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_TPG_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_TPG_CNT, dev_val->tpg_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_UTP_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_UTP_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_UTP_CNT, dev_val->utp_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
	}

	return 0;
}

static int ubcore_fill_res(uint32_t type, void *res_buf, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	switch (type) {
	case UBCORE_RES_KEY_TPG:
		ubcore_fill_res_tpg(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_JETTY_GROUP:
		ubcore_fill_res_jtgrp(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_SEG:
		ubcore_fill_res_seg(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_DEV_TA:
		ubcore_fill_res_dev_ta_cnt(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_DEV_TP:
		ubcore_fill_res_dev_tp_cnt(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_VTP:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_VTP_VAL);
		break;
	case UBCORE_RES_KEY_TP:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_TP_VAL);
		break;
	case UBCORE_RES_KEY_UTP:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_UTP_VAL);
		break;
	case UBCORE_RES_KEY_JFS:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_JFS_VAL);
		break;
	case UBCORE_RES_KEY_JFR:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_JFR_VAL);
		break;
	case UBCORE_RES_KEY_JETTY:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_JETTY_VAL);
		break;
	case UBCORE_RES_KEY_JFC:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_JFC_VAL);
		break;
	case UBCORE_RES_KEY_RC:
		ubcore_fill_res_binary(res_buf, skb, cb, UBCORE_RES_RC_VAL);
		break;
	default:
		ubcore_log_err("key type :%u no support.\n", type);
		return -1;
	}
	return 0;
}

static void ubcore_put_list_res(void *res_buf, struct sk_buff *msg, struct netlink_callback *cb,
				int cnt_type, int val_type)
{
	struct ubcore_res_list_val *reslist = res_buf;
	uint32_t idx = (uint32_t)cb->args[CB_ARGS_SART_IDX];

	if (nla_put_u32(msg, cnt_type, reslist->cnt))
		return;

	for (; idx < reslist->cnt; ++idx) {
		if (nla_put_u32(msg, val_type, reslist->list[idx]))
			return;

		cb->args[CB_ARGS_SART_IDX] = idx;
	}
	if (idx == reslist->cnt)
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
}

static int ubcore_fill_list_res(uint32_t type, void *res_buf, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	switch (type) {
	case UBCORE_RES_KEY_JETTY_GROUP:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_JTGRP_JETTY_CNT, UBCORE_RES_JTGRP_JETTY_VAL);
		break;
	case UBCORE_RES_KEY_SEG:
		ubcore_fill_res_seg(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_JFS:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_JFS_CNT, UBCORE_RES_DEV_JFS_VAL);
		break;
	case UBCORE_RES_KEY_JFR:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_JFR_CNT, UBCORE_RES_DEV_JFR_VAL);
		break;
	case UBCORE_RES_KEY_JETTY:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_JETTY_CNT, UBCORE_RES_DEV_JETTY_VAL);
		break;
	case UBCORE_RES_KEY_JFC:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_JFC_CNT, UBCORE_RES_DEV_JFC_VAL);
		break;
	case UBCORE_RES_KEY_RC:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_RC_CNT, UBCORE_RES_DEV_RC_VAL);
		break;
	case UBCORE_RES_KEY_TPG:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_TPG_CNT, UBCORE_RES_DEV_TPG_VAL);
		break;
	case UBCORE_RES_KEY_VTP:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_VTP_CNT, UBCORE_RES_DEV_VTP_VAL);
		break;
	case UBCORE_RES_KEY_TP:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_TP_CNT, UBCORE_RES_DEV_TP_VAL);
		break;
	case UBCORE_RES_KEY_UTP:
		ubcore_put_list_res(res_buf, skb, cb,
			UBCORE_RES_DEV_UTP_CNT, UBCORE_RES_DEV_UTP_VAL);
		break;
	case UBCORE_RES_KEY_DEV_TA:
		ubcore_fill_res_dev_ta_cnt(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_DEV_TP:
		ubcore_fill_res_dev_tp_cnt(res_buf, skb, cb);
		break;
	default:
		ubcore_log_err("key type :%u no support.\n", type);
		return -1;
	}
	return 0;
}

static uint32_t ubcore_get_query_res_len(uint32_t type, struct netlink_callback *cb)
{
	switch (type) {
	case UBCORE_RES_KEY_VTP:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_VTP_VAL;
		return (uint32_t)sizeof(struct ubcore_res_vtp_val);
	case UBCORE_RES_KEY_TP:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_TP_VAL;
		return (uint32_t)sizeof(struct ubcore_res_tp_val);
	case UBCORE_RES_KEY_TPG:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_TPG_TP_CNT;
		return (uint32_t)sizeof(struct ubcore_res_tpg_val);
	case UBCORE_RES_KEY_UTP:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_UTP_VAL;
		return (uint32_t)sizeof(struct ubcore_res_utp_val);
	case UBCORE_RES_KEY_JFS:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_JFS_VAL;
		return (uint32_t)sizeof(struct ubcore_res_jfs_val);
	case UBCORE_RES_KEY_JFR:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_JFR_VAL;
		return (uint32_t)sizeof(struct ubcore_res_jfr_val);
	case UBCORE_RES_KEY_JETTY:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_JETTY_VAL;
		return (uint32_t)sizeof(struct ubcore_res_jetty_val);
	case UBCORE_RES_KEY_JETTY_GROUP:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_JTGRP_JETTY_CNT;
		return (uint32_t)sizeof(struct ubcore_res_jetty_group_val);
	case UBCORE_RES_KEY_JFC:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_JFC_VAL;
		return (uint32_t)sizeof(struct ubcore_res_jfc_val);
	case UBCORE_RES_KEY_RC:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_RC_VAL;
		return (uint32_t)sizeof(struct ubcore_res_rc_val);
	case UBCORE_RES_KEY_SEG:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_SEGVAL_SEG_CNT;
		return (uint32_t)sizeof(struct ubcore_res_seg_val);
	case UBCORE_RES_KEY_DEV_TA:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_SEG_CNT;
		return (uint32_t)sizeof(struct ubcore_res_dev_ta_val);
	case UBCORE_RES_KEY_DEV_TP:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_VTP_CNT;
		return (uint32_t)sizeof(struct ubcore_res_dev_tp_val);
	default:
		break;
	}
	return 0;
}

static uint32_t ubcore_get_list_res_len(uint32_t type, struct netlink_callback *cb)
{
	switch (type) {
	case UBCORE_RES_KEY_VTP:
	case UBCORE_RES_KEY_TP:
	case UBCORE_RES_KEY_TPG:
	case UBCORE_RES_KEY_UTP:
	case UBCORE_RES_KEY_JFS:
	case UBCORE_RES_KEY_JFR:
	case UBCORE_RES_KEY_JETTY:
	case UBCORE_RES_KEY_JETTY_GROUP:
	case UBCORE_RES_KEY_JFC:
	case UBCORE_RES_KEY_RC:
		return (uint32_t)sizeof(struct ubcore_res_list_val);
	case UBCORE_RES_KEY_SEG:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_SEGVAL_SEG_CNT;
		return (uint32_t)sizeof(struct ubcore_res_seg_val);
	case UBCORE_RES_KEY_DEV_TA:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_SEG_CNT;
		return (uint32_t)sizeof(struct ubcore_res_dev_ta_val);
	case UBCORE_RES_KEY_DEV_TP:
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_VTP_CNT;
		return (uint32_t)sizeof(struct ubcore_res_dev_tp_val);
	default:
		break;
	}
	return 0;
}

static void *ubcore_query_dev_info(struct ubcore_device *dev, struct ubcore_cmd_query_res *arg,
	uint32_t res_len)
{
	struct ubcore_res_key key = {0};
	struct ubcore_res_val val = {0};
	void *res_buf;
	int ret;

	res_buf = kzalloc(res_len, GFP_KERNEL);
	if (res_buf == NULL)
		return NULL;

	key.type = (uint8_t)arg->in.type;
	key.key = arg->in.key;
	key.key_ext = arg->in.key_ext;
	key.key_cnt = arg->in.key_cnt;
	val.addr = (uint64_t)res_buf;
	val.len = res_len;

	// urma only alloc memory for the struct
	// driver will alloc memory for the list pointer in the struct; urma need to vfree it later

	ret = ubcore_query_resource(dev, &key, &val);
	if (ret != 0) {
		kfree(res_buf);
		res_buf = NULL;
	}

	return res_buf;
}

int ubcore_query_res_start(struct netlink_callback *cb)
{
	struct ubcore_cmd_query_res arg = {0};
	struct ubcore_device *dev;
	int ret = -EINVAL;
	uint32_t res_len;
	void *res_buf;

	ret = ubcore_parse_admin_res_cmd(cb, &arg, sizeof(struct ubcore_cmd_query_res));
	if (ret)
		return ret;

	if (arg.in.key_cnt == 0)
		res_len = ubcore_get_list_res_len((uint32_t)arg.in.type, cb);
	else
		res_len = ubcore_get_query_res_len((uint32_t)arg.in.type, cb);
	if (res_len == 0) {
		ubcore_log_err("Failed to check res len, type: %u, res_len: %u.\n",
			(uint32_t)arg.in.type, res_len);
		return -EINVAL;
	}
	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev failed, arg_in: %s.\n", arg.in.dev_name);
		return -EINVAL;
	}

	if (arg.in.type == (uint32_t)UBCORE_RES_KEY_VTP && dev->attr.virtualization == true) {
		ubcore_log_warn("FE device do not support query VTP, dev: %s, type: %u.\n",
			dev->dev_name, arg.in.type);
		ubcore_put_device(dev);
		return -EINVAL;
	}

	res_buf = ubcore_query_dev_info(dev, &arg, res_len);
	if (!res_buf) {
		ubcore_put_device(dev);
		ubcore_log_err("Failed to query res by arg\n");
		return -1;
	}
	ubcore_put_device(dev);
	cb->args[CB_ARGS_DEV_BUF] = (long)res_buf;
	cb->args[CB_ARGS_CMD_TYPE] = (long)arg.in.type;
	cb->args[CB_ARGS_SART_IDX] = 0;
	cb->args[CB_ARGS_BUF_LEN] = res_len;
	cb->args[CB_ARGS_KEY_CNT] = arg.in.key_cnt;
	return 0;
}

static int ubcore_list_res_done(struct netlink_callback *cb)
{
	uint32_t type = (uint32_t)(unsigned long)cb->args[CB_ARGS_CMD_TYPE];
	void *res_buf = (void *)cb->args[CB_ARGS_DEV_BUF];
	struct ubcore_res_seg_val *seg_val;
	struct ubcore_res_dev_ta_val *ta_val;
	struct ubcore_res_dev_tp_val *tp_val;
	struct ubcore_res_list_val *list_val;

	switch (type) {
	case UBCORE_RES_KEY_JFS:
	case UBCORE_RES_KEY_JFR:
	case UBCORE_RES_KEY_JETTY:
	case UBCORE_RES_KEY_JFC:
	case UBCORE_RES_KEY_RC:
	case UBCORE_RES_KEY_JETTY_GROUP:
	case UBCORE_RES_KEY_VTP:
	case UBCORE_RES_KEY_TP:
	case UBCORE_RES_KEY_TPG:
	case UBCORE_RES_KEY_UTP:
		list_val = res_buf;
		vfree(list_val->list);
		break;
	case UBCORE_RES_KEY_SEG:
		seg_val = res_buf;
		vfree(seg_val->seg_list);
		break;
	case UBCORE_RES_KEY_DEV_TA:
		ta_val = res_buf;
		vfree(ta_val);
		break;
	case UBCORE_RES_KEY_DEV_TP:
		tp_val = res_buf;
		vfree(tp_val);
		break;
	default:
		break;
	}
	kfree(res_buf);

	return 0;
}

int ubcore_query_res_done(struct netlink_callback *cb)
{
	uint32_t type = (uint32_t)(unsigned long)cb->args[CB_ARGS_CMD_TYPE];
	void *res_buf = (void *)cb->args[CB_ARGS_DEV_BUF];
	struct ubcore_res_jetty_group_val *jtgrp_val;
	struct ubcore_res_seg_val *seg_val;
	struct ubcore_res_tpg_val *tpg_val;

	if (cb->args[CB_ARGS_KEY_CNT] == 0)
		return ubcore_list_res_done(cb);

	switch (type) {
	case UBCORE_RES_KEY_TPG:
		tpg_val = res_buf;
		vfree(tpg_val->tp_list);
		break;
	case UBCORE_RES_KEY_JETTY_GROUP:
		jtgrp_val = res_buf;
		vfree(jtgrp_val->jetty_list);
		break;
	case UBCORE_RES_KEY_SEG:
		seg_val = res_buf;
		vfree(seg_val->seg_list);
		break;
	default:
		break;
	}
	kfree(res_buf);

	return 0;
}

int ubcore_query_res_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	uint32_t type = (uint32_t)cb->args[CB_ARGS_CMD_TYPE];
	void *res_buf = (void *)cb->args[CB_ARGS_DEV_BUF];
	void *hdr;
	int ret;

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_ATTR_RES_LAST)
		return 0;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, &ubcore_genl_family,
			NLM_F_MULTI, UBCORE_CMD_QUERY_RES);
	if (!hdr)
		return 0;

	if (cb->args[CB_ARGS_KEY_CNT] == 0)
		ret = ubcore_fill_list_res(type, res_buf, skb, cb);
	else
		ret = ubcore_fill_res(type, res_buf, skb, cb);
	if (ret < 0)
		genlmsg_cancel(skb, hdr);
	else
		genlmsg_end(skb, hdr);

	return (int)skb->len;
}

static void ubcore_free_eid_ctx(struct ubcore_update_eid_ctx *ctx)
{
	if (ctx->net)
		put_net(ctx->net);
	if (ctx->dev)
		ubcore_put_device(ctx->dev);
	kfree(ctx->req_msg);
	if (ctx->s) {
		kfree(ctx->s->resp);
		ubcore_destroy_msg_session(ctx->s);
	}
	kfree(ctx);
	ubcore_log_info("updata eid done");
}

static int ubcore_dump_eid_ret(struct sk_buff *skb, struct netlink_callback *cb,
	enum ubcore_cmd cmd_type)
{
	struct ubcore_update_eid_ctx *ctx = (struct ubcore_update_eid_ctx *)cb->args[0];
	void *hdr;
	int ret;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, &ubcore_genl_family,
			NLM_F_MULTI, (uint8_t)cmd_type);
	if (!hdr)
		return -ENOMEM;
	ret = ubcore_update_uvs_eid_ret(ctx);
	if (nla_put_s32(skb, UBCORE_UPDATE_EID_RET, ret))
		genlmsg_cancel(skb, hdr);
	else
		genlmsg_end(skb, hdr);

	return ret;
}

int ubcore_add_eid_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	return ubcore_dump_eid_ret(skb, cb, UBCORE_CMD_ADD_EID);
}

int ubcore_delete_eid_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	return ubcore_dump_eid_ret(skb, cb, UBCORE_CMD_DEL_EID);
}

int ubcore_delete_eid_done(struct netlink_callback *cb)
{
	struct ubcore_update_eid_ctx *ctx = (struct ubcore_update_eid_ctx *)cb->args[0];

	ubcore_free_eid_ctx(ctx);
	return 0;
}

int ubcore_add_eid_done(struct netlink_callback *cb)
{
	struct ubcore_update_eid_ctx *ctx = (struct ubcore_update_eid_ctx *)cb->args[0];

	ubcore_free_eid_ctx(ctx);
	return 0;
}

int ubcore_delete_eid_start(struct netlink_callback *cb)
{
	return ubcore_update_ueid(cb, UBCORE_MSG_DEALLOC_EID);
}

int ubcore_add_eid_start(struct netlink_callback *cb)
{
	return ubcore_update_ueid(cb, UBCORE_MSG_ALLOC_EID);
}
