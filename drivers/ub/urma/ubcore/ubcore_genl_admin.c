// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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
#include <linux/vmalloc.h>
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_api.h>
#include <ub/urma/ubcore_uapi.h>
#include <ub/urma/ubcore_perf.h>
#include "ubcore_genl_define.h"
#include "ubcore_msg.h"
#include "ubcore_priv.h"
#include "ubcore_cmd.h"
#include "ubcore_device.h"
#include "ubcore_main.h"
#include "ubcore_main_ue_eid.h"
#include "ubcore_genl_admin.h"
#include "ubcore_topo_info.h"
#include "ubcore_tp.h"
#include "ubcore_hash_table.h"

#define CB_ARGS_DEV_BUF 0
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

enum ubcore_show_res_type {
	UBCORE_SHOW_RES_JETTY = 0,
	UBCORE_SHOW_RES_JFS,
	UBCORE_SHOW_RES_JFR,
	UBCORE_SHOW_RES_JFC,
	UBCORE_SHOW_RES_SEG,
};

struct ubagg_show_res {
	struct ubcore_jetty_id jetty_id;
	enum ubcore_show_res_type  res_type;
};

static int ubcore_parse_admin_res_cmd(struct netlink_callback *cb, void *dst,
				      uint32_t copy_len)
{
	struct nlattr **attrs = genl_dumpit_info(cb)->info.attrs;

	uint64_t args_addr;

	if (!attrs[UBCORE_HDR_ARGS_LEN] || !attrs[UBCORE_HDR_ARGS_ADDR])
		return -EINVAL;

	args_addr = nla_get_u64(attrs[UBCORE_HDR_ARGS_ADDR]);

	return ubcore_copy_from_user(dst, (void __user *)(uintptr_t)args_addr,
				     copy_len);
}

static int ubcore_admin_get_eid_attr(struct genl_info *info, int attr,
				     const union ubcore_eid **eid)
{
	if (info->attrs[attr] == NULL)
		return -EINVAL;

	if (nla_len(info->attrs[attr]) != sizeof(**eid)) {
		ubcore_log_err("invalid eid attr len: %u/%zu.\n",
			       (uint32_t)nla_len(info->attrs[attr]),
			       sizeof(**eid));
		return -EINVAL;
	}

	*eid = nla_data(info->attrs[attr]);
	return 0;
}

static int ubcore_admin_reply_main_ue_eid(struct genl_info *info,
					  const union ubcore_eid *main_ue_eid)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &ubcore_genl_family, 0,
				UBCORE_CMD_ADMIN_LOOKUP_MAIN_UE_EID);
	if (hdr == NULL) {
		nlmsg_free(msg);
		return -ENOMEM;
	}

	ret = nla_put(msg, UBCORE_ATTR_MAIN_UE_EID, sizeof(*main_ue_eid),
		      main_ue_eid);
	if (ret != 0) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

static int ubcore_admin_reply_status(struct genl_info *info, uint8_t cmd,
				     int status)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &ubcore_genl_family, 0, cmd);
	if (hdr == NULL) {
		nlmsg_free(msg);
		return -ENOMEM;
	}

	ret = nla_put_s32(msg, UBCORE_ATTR_STATUS, status);
	if (ret != 0) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

static int ubcore_admin_get_eid_batch_attrs(struct genl_info *info,
					    const union ubcore_eid **main_ue_eid,
					    const union ubcore_eid **eids,
					    uint32_t *eid_num)
{
	size_t eid_list_len;
	int ret;

	ret = ubcore_admin_get_eid_attr(info, UBCORE_ATTR_MAIN_UE_EID,
				       main_ue_eid);
	if (ret != 0)
		return ret;

	if (info->attrs[UBCORE_ATTR_EID_NUM] == NULL ||
	    info->attrs[UBCORE_ATTR_EID_LIST] == NULL)
		return -EINVAL;

	*eid_num = nla_get_u32(info->attrs[UBCORE_ATTR_EID_NUM]);
	if (*eid_num == 0 ||
	    *eid_num > UBCORE_MAIN_UE_EID_BATCH_EID_MAX) {
		ubcore_log_err("invalid main ue eid batch num: %u.\n",
			       *eid_num);
		return -EINVAL;
	}

	eid_list_len = (size_t)(*eid_num) * sizeof(**eids);
	if ((size_t)nla_len(info->attrs[UBCORE_ATTR_EID_LIST]) !=
	    eid_list_len) {
		ubcore_log_err("invalid eid list len: %u/%zu.\n",
			       (uint32_t)nla_len(info->attrs[UBCORE_ATTR_EID_LIST]),
			       eid_list_len);
		return -EINVAL;
	}

	*eids = nla_data(info->attrs[UBCORE_ATTR_EID_LIST]);
	return 0;
}

int ubcore_query_stats_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_cmd_query_stats arg = { 0 };
	struct ubcore_stats_com_val com_val;
	struct ubcore_stats_key key = { 0 };
	struct ubcore_stats_val val;
	struct ubcore_device *dev;
	uint64_t args_addr;
	int ret = -EINVAL;

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] ||
	    !info->attrs[UBCORE_HDR_ARGS_ADDR])
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
			       dev == NULL ? "NULL" : dev->dev_name,
			       arg.in.dev_name);
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

static int ubcore_update_ueid(struct netlink_callback *cb,
			      enum ubcore_msg_opcode op)
{
	struct ubcore_cmd_update_ueid arg;
	struct ubcore_update_eid_ctx *ctx;
	struct net *net = &init_net;
	struct ubcore_device *dev;
	int ret = -EINVAL;
	struct timespec64 tv;

	ret = ubcore_parse_admin_res_cmd(cb, &arg,
					 sizeof(struct ubcore_cmd_update_ueid));
	if (ret)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev_name: %s failed.\n", arg.in.dev_name);
		return -EPERM;
	}

	if (dev->dynamic_eid) {
		ubcore_log_err(
			"The dynamic mode of mue does not support eid change\n");
		ubcore_put_device(dev);
		return -EPERM;
	}
	if (dev->attr.tp_maintainer) {
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

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] ||
	    !info->attrs[UBCORE_HDR_ARGS_ADDR])
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
	if (IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
		ubcore_put_device(dev);
		return -EINVAL;
	}

	/* change eid mode, need to flush eids */
	event.ub_dev = dev;
	event.event_type = UBCORE_EVENT_EID_CHANGE;
	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == true) {
			eid = dev->eid_table.eid_entries[i].eid;
			if (dev->attr.pattern == (uint8_t)UBCORE_PATTERN_1)
				ubcore_clear_pattern1_eid(dev, &eid);
			else
				ubcore_clear_pattern3_eid(dev, &eid);
			event.element.eid_idx = i;
			ubcore_dispatch_async_event(&event);
		}
	}
	dev->dynamic_eid = arg.in.eid_mode;
	ubcore_put_device(dev);
	return 0;
}

int ubcore_set_dev_ns_mode_ops(struct sk_buff *skb, struct genl_info *info)
{
	uint8_t ns_mode;

	if (!info->attrs[UBCORE_ATTR_DEV_NS_MODE])
		return -EINVAL;

	ns_mode = nla_get_u8(info->attrs[UBCORE_ATTR_DEV_NS_MODE]);
	return ubcore_set_dev_ns_mode(ns_mode != 0);
}

int ubcore_set_eid_ns_mode_ops(struct sk_buff *skb, struct genl_info *info)
{
	uint8_t ns_mode;

	if (!info->attrs[UBCORE_ATTR_EID_NS_MODE])
		return -EINVAL;

	ns_mode = nla_get_u8(info->attrs[UBCORE_ATTR_EID_NS_MODE]);
	return ubcore_set_eid_ns_mode(ns_mode != 0);
}

int ubcore_show_system_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &ubcore_genl_family, 0,
				UBCORE_CMD_SHOW_SYSTEM);
	if (hdr == NULL) {
		nlmsg_free(msg);
		return -ENOMEM;
	}

	ret = nla_put_u8(msg, UBCORE_ATTR_DEV_NS_MODE,
			 ubcore_dev_ns_shared() ? 1 : 0);
	if (ret != 0) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	ret = nla_put_u8(msg, UBCORE_ATTR_EID_NS_MODE,
			 ubcore_eid_ns_shared() ? 1 : 0);
	if (ret != 0) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

int ubcore_set_dev_ns_ops(struct sk_buff *skb, struct genl_info *info)
{
	if (!info->attrs[UBCORE_ATTR_DEV_NAME] ||
	    !info->attrs[UBCORE_ATTR_NS_FD])
		return -EINVAL;

	return ubcore_set_dev_ns(
		(char *)nla_data(info->attrs[UBCORE_ATTR_DEV_NAME]),
		nla_get_u32(info->attrs[UBCORE_ATTR_NS_FD]));
}

int ubcore_expose_dev_ns_ops(struct sk_buff *skb, struct genl_info *info)
{
	if (!info->attrs[UBCORE_ATTR_DEV_NAME] ||
	    !info->attrs[UBCORE_ATTR_NS_FD])
		return -EINVAL;

	return ubcore_expose_dev_ns(
		(char *)nla_data(info->attrs[UBCORE_ATTR_DEV_NAME]),
		nla_get_u32(info->attrs[UBCORE_ATTR_NS_FD]));
}

int ubcore_unexpose_dev_ns_ops(struct sk_buff *skb, struct genl_info *info)
{
	if (!info->attrs[UBCORE_ATTR_DEV_NAME] ||
	    !info->attrs[UBCORE_ATTR_NS_FD])
		return -EINVAL;

	return ubcore_unexpose_dev_ns(
		(char *)nla_data(info->attrs[UBCORE_ATTR_DEV_NAME]),
		nla_get_u32(info->attrs[UBCORE_ATTR_NS_FD]));
}

int ubcore_set_dev_eid_ns_ops(struct sk_buff *skb, struct genl_info *info)
{
	if (!info->attrs[UBCORE_ATTR_DEV_NAME] ||
	    !info->attrs[UBCORE_ATTR_NS_FD] ||
		!info->attrs[UBCORE_ATTR_EID_IDX])
		return -EINVAL;

	return ubcore_set_dev_eid_ns(
		(char *)nla_data(info->attrs[UBCORE_ATTR_DEV_NAME]),
		nla_get_u16(info->attrs[UBCORE_ATTR_EID_IDX]),
		nla_get_u32(info->attrs[UBCORE_ATTR_NS_FD]));
}

int ubcore_get_topo_info(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_cmd_topo_info *arg = NULL;
	struct ubcore_topo_map *topo_map;
	uint64_t args_addr;
	int ret = -EINVAL;

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] ||
	    !info->attrs[UBCORE_HDR_ARGS_ADDR])
		return ret;
	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;
	args_addr = nla_get_u64(info->attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)args_addr,
				    sizeof(struct ubcore_cmd_topo_info));
	if (ret != 0) {
		kfree(arg);
		return -EPERM;
	}
	topo_map = ubcore_get_global_topo_map();
	if (topo_map == NULL) {
		ubcore_log_err("topo map is empty!\n");
		kfree(arg);
		return -1;
	}
	if (arg->in.node_idx >= topo_map->node_num) {
		ubcore_log_err("topo map idx > node_num!\n");
		kfree(arg);
		return -EINVAL;
	}

	arg->out.node_num = topo_map->node_num;
	(void)memcpy(&arg->out.topo_info, &topo_map->topo_infos[arg->in.node_idx],
		     sizeof(struct ubcore_topo_node));
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)args_addr, arg,
				   sizeof(struct ubcore_cmd_topo_info));
	kfree(arg);
	return ret;
}

int ubcore_set_sl(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_cmd_set_sl arg = {0};
	struct ubcore_device *dev;
	uint64_t args_addr;
	int ret = -EINVAL;

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] || !info->attrs[UBCORE_HDR_ARGS_ADDR]) {
		ubcore_log_err("info attr invalid!\n");
		return ret;
	}
	args_addr = nla_get_u64(info->attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)args_addr,
		sizeof(struct ubcore_cmd_set_sl));
	if (ret != 0) {
		ubcore_log_err("ubcore copy data from user failed, ret = %d\n", ret);
		return ret;
	}
	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev_name: %s failed.\n", arg.in.dev_name);
		return -ENODEV;
	}
	if (dev->ops == NULL || dev->ops->set_sl == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		ubcore_put_device(dev);
		return -EINVAL;
	}
	if (arg.in.priority >= UBCORE_MAX_PRIORITY_CNT) {
		ubcore_log_err("Invalid parameter.\n");
		ubcore_put_device(dev);
		return -EINVAL;
	}
	ret = dev->ops->set_sl(dev, arg.in.priority, arg.in.SL);
	ubcore_put_device(dev);
	if (ret != 0)
		ubcore_log_err("ops ubcore->set_sl failed!\n");
	return ret;
}

int ubcore_admin_insert_main_ue_eid(struct sk_buff *skb,
				    struct genl_info *info)
{
	const union ubcore_eid *main_ue_eid;
	const union ubcore_eid *eid;
	int ret;

	ret = ubcore_admin_get_eid_attr(info, UBCORE_ATTR_EID, &eid);
	if (ret != 0)
		return ret;

	ret = ubcore_admin_get_eid_attr(info, UBCORE_ATTR_MAIN_UE_EID,
					&main_ue_eid);
	if (ret != 0)
		return ret;

	return ubcore_insert_main_ue_eid(eid, main_ue_eid);
}

int ubcore_admin_delete_main_ue_eid(struct sk_buff *skb,
				    struct genl_info *info)
{
	const union ubcore_eid *eid;
	int ret;

	ret = ubcore_admin_get_eid_attr(info, UBCORE_ATTR_EID, &eid);
	if (ret != 0)
		return ret;

	return ubcore_delete_main_ue_eid(eid);
}

int ubcore_admin_lookup_main_ue_eid(struct sk_buff *skb,
				    struct genl_info *info)
{
	union ubcore_eid main_ue_eid;
	const union ubcore_eid *eid;
	int ret;

	ret = ubcore_admin_get_eid_attr(info, UBCORE_ATTR_EID, &eid);
	if (ret != 0)
		return ret;

	ret = ubcore_lookup_main_ue_eid(eid, &main_ue_eid);
	if (ret != 0)
		return ret;

	return ubcore_admin_reply_main_ue_eid(info, &main_ue_eid);
}

int ubcore_admin_flush_main_ue_eid(struct sk_buff *skb,
				   struct genl_info *info)
{
	ubcore_flush_main_ue_eid();
	return ubcore_admin_reply_status(info,
					 UBCORE_CMD_ADMIN_FLUSH_MAIN_UE_EID,
					 0);
}

int ubcore_admin_insert_main_ue_eid_batch(struct sk_buff *skb,
					  struct genl_info *info)
{
	const union ubcore_eid *main_ue_eid;
	const union ubcore_eid *eids;
	uint32_t eid_num;
	uint32_t i;
	int ret;

	ret = ubcore_admin_get_eid_batch_attrs(info, &main_ue_eid, &eids,
					       &eid_num);
	if (ret != 0)
		return ret;

	for (i = 0; i < eid_num; i++) {
		ret = ubcore_insert_main_ue_eid(&eids[i], main_ue_eid);
		if (ret != 0)
			return ret;
	}

	return 0;
}

int ubcore_get_v2p_res(struct sk_buff *skb, struct genl_info *info)
{
	struct ubagg_show_res res = {0};
	struct ubcore_cmd_show_res arg = {0};
	struct ubcore_device *bonding_dev;
	uint64_t args_addr;
	int ret = 0;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	if (!info->attrs[UBCORE_HDR_ARGS_LEN] || !info->attrs[UBCORE_HDR_ARGS_ADDR]) {
		ubcore_log_err("info attr invalid!\n");
		return -EINVAL;
	}
	args_addr = nla_get_u64(info->attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)args_addr,
		sizeof(struct ubcore_cmd_show_res));
	if (ret != 0)
		return ret;

	bonding_dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (bonding_dev == NULL) {
		ubcore_log_err("failed to get bonding_dev");
		return -EINVAL;
	}

	res.res_type = arg.in.type;
	res.jetty_id.id = arg.in.key;

	struct ubcore_user_ctl k_user_ctl = {
		.in.addr = (uint64_t)(uintptr_t)&res,
		.in.len = sizeof(res),
		.out.addr = arg.out.addr,
		.out.len = arg.out.len,
	};
	if (arg.in.key_cnt == 0)
		k_user_ctl.in.opcode = 7; /* GET_LIST_RES in ubagg */
	else
		k_user_ctl.in.opcode = 8; /* GET_SHOW_RES in ubagg */

	ret = ubcore_user_control(bonding_dev, &k_user_ctl);
	ubcore_put_device(bonding_dev);
	if (ret != 0) {
		ubcore_log_err("ubcore_user_control failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.len = k_user_ctl.out.len;
	return ubcore_copy_to_user((void __user *)(uintptr_t)args_addr, &arg,
			   sizeof(struct ubcore_cmd_show_res));
}

static void ubcore_fill_res_binary(void *res_buf, struct sk_buff *msg,
				   struct netlink_callback *cb, int attrtype)
{
	if (nla_put(msg, attrtype, (int)cb->args[CB_ARGS_BUF_LEN], res_buf))
		return;

	cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
}

static void ubcore_fill_res_tpg(void *res_buf, struct sk_buff *msg,
				struct netlink_callback *cb)
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
		if (nla_put_u32(msg, UBCORE_RES_TPG_TP_VAL,
				tpg_val->tp_list[idx]))
			return;
		cb->args[CB_ARGS_SART_IDX] = idx;
	}
	if (idx == tpg_val->tp_cnt)
		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_ATTR_RES_LAST;
}

static void ubcore_fill_res_jtgrp(void *res_buf, struct sk_buff *msg,
				  struct netlink_callback *cb)
{
	struct ubcore_res_jetty_group_val *jtgrp_val = res_buf;
	uint32_t idx = (uint32_t)cb->args[CB_ARGS_SART_IDX];

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_JTGRP_JETTY_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_JTGRP_JETTY_CNT,
				jtgrp_val->jetty_cnt))
			return;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_JTGRP_JETTY_VAL;
	}

	for (; idx < jtgrp_val->jetty_cnt; ++idx) {
		if (nla_put_u32(msg, UBCORE_RES_JTGRP_JETTY_VAL,
				jtgrp_val->jetty_list[idx]))
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
		if (nla_put_u32(msg, UBCORE_RES_SEGVAL_SEG_CNT,
				seg_val->seg_cnt))
			return;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_SEGVAL_SEG_VAL;
	}
	for (; idx < seg_val->seg_cnt; ++idx) {
		if (nla_put(msg, UBCORE_RES_SEGVAL_SEG_VAL,
			    sizeof(struct ubcore_seg_info),
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
		if (nla_put_u32(msg, UBCORE_RES_DEV_JETTY_CNT,
				dev_val->jetty_cnt))
			return -1;

		cb->args[CB_ARGS_NEXT_TYPE] = UBCORE_RES_DEV_JTGRP_CNT;
	}

	if (cb->args[CB_ARGS_NEXT_TYPE] == UBCORE_RES_DEV_JTGRP_CNT) {
		if (nla_put_u32(msg, UBCORE_RES_DEV_JTGRP_CNT,
				dev_val->jetty_group_cnt))
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

static void ubcore_put_list_res(void *res_buf, struct sk_buff *msg,
				struct netlink_callback *cb, int cnt_type,
				int val_type)
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

static int ubcore_fill_list_res(uint32_t type, void *res_buf,
				struct sk_buff *skb,
				struct netlink_callback *cb)
{
	switch (type) {
	case UBCORE_RES_KEY_JETTY_GROUP:
		ubcore_put_list_res(res_buf, skb, cb,
				    UBCORE_RES_JTGRP_JETTY_CNT,
				    UBCORE_RES_JTGRP_JETTY_VAL);
		break;
	case UBCORE_RES_KEY_SEG:
		ubcore_fill_res_seg(res_buf, skb, cb);
		break;
	case UBCORE_RES_KEY_JFS:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_JFS_CNT,
				    UBCORE_RES_DEV_JFS_VAL);
		break;
	case UBCORE_RES_KEY_JFR:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_JFR_CNT,
				    UBCORE_RES_DEV_JFR_VAL);
		break;
	case UBCORE_RES_KEY_JETTY:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_JETTY_CNT,
				    UBCORE_RES_DEV_JETTY_VAL);
		break;
	case UBCORE_RES_KEY_JFC:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_JFC_CNT,
				    UBCORE_RES_DEV_JFC_VAL);
		break;
	case UBCORE_RES_KEY_RC:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_RC_CNT,
				    UBCORE_RES_DEV_RC_VAL);
		break;
	case UBCORE_RES_KEY_TPG:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_TPG_CNT,
				    UBCORE_RES_DEV_TPG_VAL);
		break;
	case UBCORE_RES_KEY_VTP:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_VTP_CNT,
				    UBCORE_RES_DEV_VTP_VAL);
		break;
	case UBCORE_RES_KEY_TP:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_TP_CNT,
				    UBCORE_RES_DEV_TP_VAL);
		break;
	case UBCORE_RES_KEY_UTP:
		ubcore_put_list_res(res_buf, skb, cb, UBCORE_RES_DEV_UTP_CNT,
				    UBCORE_RES_DEV_UTP_VAL);
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

static uint32_t ubcore_get_query_res_len(uint32_t type,
					 struct netlink_callback *cb)
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

static uint32_t ubcore_get_list_res_len(uint32_t type,
					struct netlink_callback *cb)
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
	default:
		break;
	}
	return 0;
}

static void *ubcore_query_dev_info(struct ubcore_device *dev,
				   struct ubcore_cmd_query_res *arg,
				   uint32_t res_len)
{
	struct ubcore_res_key key = { 0 };
	struct ubcore_res_val val = { 0 };
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

#define CB_ARGS_REC_CTX 0

enum {
	UBCORE_TPID_DUMP_PHASE_HDR = 0,
	UBCORE_TPID_DUMP_PHASE_AWARE,
	UBCORE_TPID_DUMP_PHASE_UNAWARE,
};

/*
 * Incremental dumpit cursor. Only a small fixed-size context plus at most one
 * referenced tpid_list is kept in kernel memory at any time; one record is
 * produced per netlink message as the netlink core re-invokes dumpit until the
 * whole hash table has been traversed.
 */
struct ubcore_tpid_dump_ctx {
	struct ubcore_device *dev; /* referenced for the whole dump */
	uint8_t cmd;
	bool query_tpid;
	bool finished;
	uint64_t tpid;
	uint32_t bucket; /* current hash bucket */
	uint32_t lpos; /* index within the current bucket */
	uint32_t phase; /* current phase when streaming a tpid_list */
	uint32_t node_idx; /* node index within the current phase */
	uint32_t aware_cnt;
	uint32_t unaware_cnt;
	struct ubcore_tpid_list *cur_tl; /* referenced list being streamed */
};

static int ubcore_tpid_emit_rec(struct sk_buff *skb,
				struct netlink_callback *cb, uint8_t cmd,
				uint32_t type, const void *data, uint32_t len)
{
	void *hdr;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &ubcore_genl_family, NLM_F_MULTI, cmd);
	if (hdr == NULL)
		return -EMSGSIZE;

	if (nla_put_u32(skb, UBCORE_TPID_SHOW_ATTR_REC_TYPE, type) != 0 ||
	    nla_put(skb, UBCORE_TPID_SHOW_ATTR_REC_DATA, (int)len, data) != 0) {
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, hdr);
	return 0;
}

/* Find and reference the (bucket, lpos) tpid_list, advancing the cursor. */
static struct ubcore_tpid_list *ubcore_tpid_dump_find_list(
	struct ubcore_tpid_dump_ctx *ctx)
{
	struct ubcore_hash_table *ht = &ctx->dev->ht[UBCORE_HT_TPID_LIST];
	struct ubcore_tpid_list *tl;
	struct ubcore_tpid_list *found = NULL;
	uint32_t bucket = ctx->bucket;
	uint32_t pos = ctx->lpos;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return NULL;
	}
	while (bucket < ht->p.size) {
		uint32_t cnt = 0;

		hlist_for_each_entry(tl, &ht->head[bucket], hnode) {
			if (cnt == pos) {
				found = tl;
				break;
			}
			cnt++;
		}
		if (found != NULL)
			break;
		bucket++;
		pos = 0;
	}
	if (found != NULL) {
		ubcore_tpid_list_get(found);
		ctx->bucket = bucket;
		ctx->lpos = pos;
	}
	spin_unlock(&ht->lock);
	return found;
}

static void ubcore_tpid_dump_count_nodes(struct ubcore_tpid_list *tl,
					 uint32_t *aware, uint32_t *unaware)
{
	struct ubcore_tpid_list_node *e;
	uint32_t a = 0;
	uint32_t u = 0;

	mutex_lock(&tl->lock);
	list_for_each_entry(e, &tl->aware_list, node)
		a++;
	list_for_each_entry(e, &tl->unaware_list, node)
		u++;
	mutex_unlock(&tl->lock);
	*aware = a;
	*unaware = u;
}

static bool ubcore_tpid_dump_fill_node(struct ubcore_tpid_list *tl,
				       struct list_head *head, uint32_t idx,
				       struct ubcore_show_tpid_node *out)
{
	struct ubcore_tpid_list_node *e;
	uint32_t cnt = 0;
	bool ok = false;

	mutex_lock(&tl->lock);
	list_for_each_entry(e, head, node) {
		if (cnt == idx) {
			out->tp_handle = e->tp_info.tp_handle.value;
			ok = true;
			break;
		}
		cnt++;
	}
	mutex_unlock(&tl->lock);
	return ok;
}

static void ubcore_tpid_dump_fill_hdr(struct ubcore_tpid_list *tl,
				      struct ubcore_show_tpid_list_hdr *hdr)
{
	mutex_lock(&tl->lock);
	hdr->local_eid = tl->lk.local_eid;
	hdr->peer_eid = tl->lk.peer_eid;
	hdr->trans_mode = (uint32_t)tl->lk.trans_mode;
	hdr->share_mode = (uint32_t)tl->lk.share_mode;
	hdr->tp_type = tl->lk.tp_type;
	hdr->link_type = tl->lk.link_type;
	hdr->acnt = tl->acnt;
	hdr->ucnt = tl->ucnt;
	hdr->capacity = tl->capacity;
	hdr->ref_cnt = (uint32_t)kref_read(&tl->ref_cnt);
	mutex_unlock(&tl->lock);
}

/* Stream the next tpid_reuse entry, one per dumpit call. */
static int ubcore_tpid_dump_reuse(struct sk_buff *skb,
				  struct netlink_callback *cb,
				  struct ubcore_tpid_dump_ctx *ctx)
{
	struct ubcore_hash_table *ht = &ctx->dev->ht[UBCORE_HT_TPID_REUSE];
	struct ubcore_show_tpid_reuse_entry entry = { 0 };
	struct ubcore_tpid_reuse *reuse;
	bool found = false;
	uint32_t bucket = ctx->bucket;
	uint32_t pos = ctx->lpos;

	spin_lock(&ht->lock);
	if (ht->head != NULL) {
		while (bucket < ht->p.size) {
			uint32_t cnt = 0;

			hlist_for_each_entry(reuse, &ht->head[bucket], hnode) {
				if (cnt == pos) {
					entry.local_eid =
						reuse->rk.lk.local_eid;
					entry.peer_eid =
						reuse->rk.lk.peer_eid;
					entry.trans_mode = (uint32_t)
						reuse->rk.lk.trans_mode;
					entry.share_mode = (uint32_t)
						reuse->rk.lk.share_mode;
					entry.tp_type =
						reuse->rk.lk.tp_type;
					entry.link_type =
						reuse->rk.lk.link_type;
					entry.stag = reuse->rk.stag;
					entry.dtag = reuse->rk.dtag;
					entry.tp_handle =
						reuse->tp_handle.value;
					entry.reuse_state = (uint32_t)
						reuse->reuse_state;
					entry.ref_cnt = (uint32_t)kref_read(
						&reuse->ref_cnt);
					entry.use_cnt = atomic_read(
						&reuse->use_cnt);
					found = true;
					break;
				}
				cnt++;
			}
			if (found)
				break;
			bucket++;
			pos = 0;
		}
	}
	spin_unlock(&ht->lock);

	if (!found) {
		ctx->finished = true;
		return 0;
	}

	ctx->bucket = bucket;
	ctx->lpos = pos + 1;
	(void)ubcore_tpid_emit_rec(skb, cb, ctx->cmd,
				   UBCORE_TPID_SHOW_REC_REUSE_ENTRY, &entry,
				   sizeof(entry));
	return (int)skb->len;
}

/* Stream the next tpid_list record (header or one node), one per dumpit call. */
static int ubcore_tpid_dump_list(struct sk_buff *skb,
				 struct netlink_callback *cb,
				 struct ubcore_tpid_dump_ctx *ctx)
{
	struct ubcore_tpid_list *tl;

	if (ctx->query_tpid) {
		struct ubcore_show_tpid_state st = { 0 };
		struct ubcore_tpid_state *state;

		st.found = 0;
		st.status = UBCORE_TPID_MAX;
		state = ubcore_find_get_tp_id_state_entry(ctx->dev, ctx->tpid);
		if (state != NULL) {
			st.found = 1;
			mutex_lock(&state->lock);
			st.status = (uint32_t)state->tpid_status;
			st.owner_type = (uint32_t)state->tp_id_owner_type;
			st.alloced = state->alloced ? 1 : 0;
			st.ref_cnt = (uint32_t)kref_read(&state->ref_cnt);
			mutex_unlock(&state->lock);
			ubcore_tpid_state_kref_put(state);
		}
		ctx->finished = true;
		(void)ubcore_tpid_emit_rec(skb, cb, ctx->cmd,
					   UBCORE_TPID_SHOW_REC_TPID_STATE,
					   &st, sizeof(st));
		return (int)skb->len;
	}

	while (true) {
		if (ctx->cur_tl == NULL) {
			tl = ubcore_tpid_dump_find_list(ctx);
			if (tl == NULL) {
				ctx->finished = true;
				return 0;
			}
			ctx->cur_tl = tl;
			ctx->phase = UBCORE_TPID_DUMP_PHASE_HDR;
			ctx->node_idx = 0;
			ubcore_tpid_dump_count_nodes(tl, &ctx->aware_cnt,
						     &ctx->unaware_cnt);
		}
		tl = ctx->cur_tl;

		if (ctx->phase == UBCORE_TPID_DUMP_PHASE_HDR) {
			struct ubcore_show_tpid_list_hdr hdr = { 0 };

			ubcore_tpid_dump_fill_hdr(tl, &hdr);
			hdr.aware_node_cnt = ctx->aware_cnt;
			hdr.unaware_node_cnt = ctx->unaware_cnt;
			ctx->phase = UBCORE_TPID_DUMP_PHASE_AWARE;
			ctx->node_idx = 0;
			(void)ubcore_tpid_emit_rec(
				skb, cb, ctx->cmd,
				UBCORE_TPID_SHOW_REC_LIST_HDR, &hdr,
				sizeof(hdr));
			return (int)skb->len;
		}

		if (ctx->phase == UBCORE_TPID_DUMP_PHASE_AWARE) {
			struct ubcore_show_tpid_node node = { 0 };

			if (ctx->node_idx < ctx->aware_cnt &&
			    ubcore_tpid_dump_fill_node(tl,
						       &tl->aware_list,
						       ctx->node_idx,
						       &node)) {
				ctx->node_idx++;
				(void)ubcore_tpid_emit_rec(
					skb, cb, ctx->cmd,
					UBCORE_TPID_SHOW_REC_AWARE_NODE,
					&node, sizeof(node));
				return (int)skb->len;
			}
			ctx->phase = UBCORE_TPID_DUMP_PHASE_UNAWARE;
			ctx->node_idx = 0;
			continue;
		}

		/* UBCORE_TPID_DUMP_PHASE_UNAWARE */
		{
			struct ubcore_show_tpid_node node = { 0 };

			if (ctx->node_idx < ctx->unaware_cnt &&
			    ubcore_tpid_dump_fill_node(tl,
						       &tl->unaware_list,
						       ctx->node_idx,
						       &node)) {
				ctx->node_idx++;
				(void)ubcore_tpid_emit_rec(
					skb, cb, ctx->cmd,
					UBCORE_TPID_SHOW_REC_UNAWARE_NODE,
					&node, sizeof(node));
				return (int)skb->len;
			}
			ubcore_tpid_list_kref_put(tl);
			ctx->cur_tl = NULL;
			ctx->lpos++;
		}
	}
}

static int ubcore_tpid_show_common_dump(struct sk_buff *skb,
					struct netlink_callback *cb)
{
	struct ubcore_tpid_dump_ctx *ctx =
		(struct ubcore_tpid_dump_ctx *)cb->args[CB_ARGS_REC_CTX];

	if (ctx == NULL || ctx->finished)
		return 0;

	if (ctx->cmd == UBCORE_CMD_SHOW_TPID_REUSE)
		return ubcore_tpid_dump_reuse(skb, cb, ctx);

	return ubcore_tpid_dump_list(skb, cb, ctx);
}

static int ubcore_tpid_show_common_done(struct netlink_callback *cb)
{
	struct ubcore_tpid_dump_ctx *ctx =
		(struct ubcore_tpid_dump_ctx *)cb->args[CB_ARGS_REC_CTX];

	if (ctx != NULL) {
		if (ctx->cur_tl != NULL)
			ubcore_tpid_list_kref_put(ctx->cur_tl);
		if (ctx->dev != NULL)
			ubcore_put_device(ctx->dev);
		kfree(ctx);
	}
	cb->args[CB_ARGS_REC_CTX] = 0;
	return 0;
}

int ubcore_show_tpid_list_start(struct netlink_callback *cb)
{
	struct nlattr **attrs = genl_dumpit_info(cb)->info.attrs;
	struct ubcore_cmd_show_tpid_list arg = { 0 };
	struct ubcore_tpid_dump_ctx *ctx;
	struct ubcore_device *dev;
	uint64_t args_addr;
	int ret;

	if (!attrs[UBCORE_HDR_ARGS_LEN] || !attrs[UBCORE_HDR_ARGS_ADDR])
		return -EINVAL;

	args_addr = nla_get_u64(attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)args_addr,
				    sizeof(arg));
	if (ret != 0)
		return -EPERM;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev failed, dev_name: %s.\n",
			       arg.in.dev_name);
		return -EINVAL;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		ubcore_put_device(dev);
		return -ENOMEM;
	}
	ctx->dev = dev; /* released in done */
	ctx->cmd = UBCORE_CMD_SHOW_TPID_LIST;
	ctx->query_tpid = (arg.in.query_tpid != 0);
	ctx->tpid = arg.in.tpid;

	cb->args[CB_ARGS_REC_CTX] = (long)ctx;
	return 0;
}

int ubcore_show_tpid_list_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	return ubcore_tpid_show_common_dump(skb, cb);
}

int ubcore_show_tpid_list_done(struct netlink_callback *cb)
{
	return ubcore_tpid_show_common_done(cb);
}

int ubcore_show_tpid_reuse_start(struct netlink_callback *cb)
{
	struct nlattr **attrs = genl_dumpit_info(cb)->info.attrs;
	struct ubcore_cmd_show_tpid_reuse arg = { 0 };
	struct ubcore_tpid_dump_ctx *ctx;
	struct ubcore_device *dev;
	uint64_t args_addr;
	int ret;

	if (!attrs[UBCORE_HDR_ARGS_LEN] || !attrs[UBCORE_HDR_ARGS_ADDR])
		return -EINVAL;

	args_addr = nla_get_u64(attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)args_addr,
				    sizeof(arg));
	if (ret != 0)
		return -EPERM;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev failed, dev_name: %s.\n",
			       arg.in.dev_name);
		return -EINVAL;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		ubcore_put_device(dev);
		return -ENOMEM;
	}
	ctx->dev = dev; /* released in done */
	ctx->cmd = UBCORE_CMD_SHOW_TPID_REUSE;

	cb->args[CB_ARGS_REC_CTX] = (long)ctx;
	return 0;
}

int ubcore_show_tpid_reuse_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	return ubcore_tpid_show_common_dump(skb, cb);
}

int ubcore_show_tpid_reuse_done(struct netlink_callback *cb)
{
	return ubcore_tpid_show_common_done(cb);
}

int ubcore_query_res_start(struct netlink_callback *cb)
{
	struct ubcore_cmd_query_res arg = { 0 };
	struct ubcore_device *dev;
	int ret = -EINVAL;
	uint32_t res_len;
	void *res_buf;

	ret = ubcore_parse_admin_res_cmd(cb, &arg,
					 sizeof(struct ubcore_cmd_query_res));
	if (ret)
		return ret;

	if (arg.in.key_cnt == 0)
		res_len = ubcore_get_list_res_len((uint32_t)arg.in.type, cb);
	else
		res_len = ubcore_get_query_res_len((uint32_t)arg.in.type, cb);
	if (res_len == 0) {
		ubcore_log_err(
			"Failed to check res len, type: %u, res_len: %u.\n",
			(uint32_t)arg.in.type, res_len);
		return -EINVAL;
	}
	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev failed, arg_in: %s.\n",
			       arg.in.dev_name);
		return -EINVAL;
	}

	if (arg.in.type == (uint32_t)UBCORE_RES_KEY_VTP &&
	    dev->attr.virtualization == true) {
		ubcore_log_warn(
			"UE device do not support query VTP, dev: %s, type: %u.\n",
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

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &ubcore_genl_family, NLM_F_MULTI,
			  UBCORE_CMD_QUERY_RES);
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
	struct ubcore_update_eid_ctx *ctx =
		(struct ubcore_update_eid_ctx *)cb->args[0];
	void *hdr;
	int ret;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &ubcore_genl_family, NLM_F_MULTI, (uint8_t)cmd_type);
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
	struct ubcore_update_eid_ctx *ctx =
		(struct ubcore_update_eid_ctx *)cb->args[0];

	ubcore_free_eid_ctx(ctx);
	return 0;
}

int ubcore_add_eid_done(struct netlink_callback *cb)
{
	struct ubcore_update_eid_ctx *ctx =
		(struct ubcore_update_eid_ctx *)cb->args[0];

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

int ubcore_perf_start_ops(struct sk_buff *skb, struct genl_info *info)
{
	ubcore_perf_start();
	return 0;
}

int ubcore_perf_stop_ops(struct sk_buff *skb, struct genl_info *info)
{
	ubcore_perf_stop();
	return 0;
}

int ubcore_perf_show_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_cmd_perf_show *arg = NULL;
	uint64_t args_addr;
	int ret = -EINVAL;

	if (!info->attrs[UBCORE_HDR_ARGS_LEN] || !info->attrs[UBCORE_HDR_ARGS_ADDR]) {
		ubcore_log_err("Invalid argument.\n");
		return ret;
	}

	arg = vzalloc(sizeof(*arg));
	if (!arg)
		return -ENOMEM;

	args_addr = nla_get_u64(info->attrs[UBCORE_HDR_ARGS_ADDR]);
	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)args_addr,
				    sizeof(struct ubcore_cmd_perf_show));
	if (ret != 0) {
		ubcore_log_err("Failed to copy from user.\n");
		vfree(arg);
		return -EINVAL;
	}

	ubcore_perf_dump_info(&arg->out.stat);

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)args_addr, arg,
				   sizeof(struct ubcore_cmd_perf_show));
	if (ret != 0)
		ubcore_log_err("Failed to copy to user, ret = %d\n", ret);

	vfree(arg);
	return ret;
}
