// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg generic netlink support
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <net/genetlink.h>
#include <ub/urma/ubcore_uapi.h>

#include "ubagg_dfx.h"
#include "ubagg_failback.h"
#include "ubagg_log.h"
#include "ubagg_ioctl.h"
#include "ubagg_netlink.h"

#define UBAGG_MAX_NL_MSG_BUF_LEN 2048

static const struct nla_policy ubagg_genl_policy[UBAGG_ATTR_MAX] = {
	[UBAGG_ATTR_UNSPEC] = { 0 },
	[UBAGG_ATTR_PAYLOAD] = { .type = NLA_BINARY,
				 .len = UBAGG_MAX_NL_MSG_BUF_LEN },
	[UBAGG_HDR_ARGS_ADDR] = { .type = NLA_U64 },
	[UBAGG_ATTR_EID] = { .type = NLA_BINARY,
			     .len = sizeof(union ubcore_eid) },
	[UBAGG_ATTR_BONDING_PHYSICAL_DEVICE] = { .type = NLA_BINARY,
						 .len = sizeof(
							 struct ubagg_bonding_physical_device) },
};

struct ubagg_nl_topo_info {
	struct {
		int node_idx;
	} in;
	struct {
		uint32_t node_num;
		struct ubagg_topo_node topo_info;
	} out;
};

static int ubagg_nl_get_topo_ops(struct sk_buff *skb, struct genl_info *info);
static int ubagg_nl_get_physical_device_ops(struct sk_buff *skb,
					    struct genl_info *info);
static int ubagg_nl_get_v2p_res_ops(struct sk_buff *skb,
				    struct genl_info *info);

enum ubagg_genl_mcgrp {
	UBAGG_NL_MCGRP_USER_PAYLOAD,
	UBAGG_NL_MCGRP_MAX,
};

static const struct genl_multicast_group ubagg_genl_mcgrps[] = {
	[UBAGG_NL_MCGRP_USER_PAYLOAD] = { .name = "user_payload" },
};

static const struct genl_ops ubagg_genl_ops[] = {
	{
		.cmd = UBAGG_NL_CMD_GET_TOPO,
		.policy = ubagg_genl_policy,
		.maxattr = ARRAY_SIZE(ubagg_genl_policy) - 1,
		.doit = ubagg_nl_get_topo_ops,
	},
	{
		.cmd = UBAGG_NL_CMD_GET_PHYSICAL_DEVICE,
		.policy = ubagg_genl_policy,
		.maxattr = ARRAY_SIZE(ubagg_genl_policy) - 1,
		.doit = ubagg_nl_get_physical_device_ops,
	},
	{
		.cmd = UBAGG_NL_CMD_GET_V2P_RES,
		.policy = ubagg_genl_policy,
		.maxattr = ARRAY_SIZE(ubagg_genl_policy) - 1,
		.doit = ubagg_nl_get_v2p_res_ops,
	},
	{
		.cmd = UBAGG_NL_CMD_FAILBACK_START,
		.policy = ubagg_genl_policy,
		.maxattr = ARRAY_SIZE(ubagg_genl_policy) - 1,
		.doit = ubagg_fb_nl_start,
	},
	{
		.cmd = UBAGG_NL_CMD_FAILBACK_RESULT,
		.policy = ubagg_genl_policy,
		.maxattr = ARRAY_SIZE(ubagg_genl_policy) - 1,
		.doit = ubagg_fb_nl_result,
	},
};

static struct genl_family genl_family __ro_after_init = {
	.name = UBAGG_GENL_FAMILY_NAME,
	.version = UBAGG_GENL_FAMILY_VERSION,
	.maxattr = ARRAY_SIZE(ubagg_genl_policy) - 1,
	.policy = ubagg_genl_policy,
	.resv_start_op = UBAGG_NL_CMD_MAX,
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = ubagg_genl_ops,
	.n_ops = ARRAY_SIZE(ubagg_genl_ops),
	.mcgrps = ubagg_genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(ubagg_genl_mcgrps),
};

int ubagg_nl_broadcast(uint8_t cmd, uint16_t attr_type, const void *data,
		       uint16_t data_len)
{
	void *hdr = NULL;
	struct sk_buff *skb = NULL;
	int ret;

	if ((data == NULL && data_len != 0) ||
	    data_len > UBAGG_MAX_NL_MSG_BUF_LEN) {
		ubagg_log_err(
			"Invalid netlink broadcast param, cmd:%u attr:%u\n",
			cmd, attr_type);
		return -EINVAL;
	}

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		ubagg_log_err(
			"Failed to alloc skb for netlink broadcast, cmd:%u\n",
			cmd);
		return -ENOMEM;
	}

	hdr = genlmsg_put(skb, 0, 0, &genl_family, 0, cmd);
	if (hdr == NULL) {
		nlmsg_free(skb);
		ubagg_log_err("Failed to build netlink msg, cmd:%u\n", cmd);
		return -EMSGSIZE;
	}

	if (nla_put(skb, attr_type, data_len, data)) {
		genlmsg_cancel(skb, hdr);
		nlmsg_free(skb);
		ubagg_log_err("Failed to append attr:%u to cmd:%u\n", attr_type,
			      cmd);
		return -EMSGSIZE;
	}

	genlmsg_end(skb, hdr);
	rcu_read_lock();
	ret = genlmsg_multicast_allns(&genl_family, skb, 0,
				      UBAGG_NL_MCGRP_USER_PAYLOAD);
	rcu_read_unlock();
	if (ret == -ESRCH)
		return 0;
	if (ret != 0)
		ubagg_log_err("Failed to multicast cmd:%u attr:%u, ret:%d\n",
			      cmd, attr_type, ret);
	return ret;
}

int ubagg_nl_parse_attr(struct genl_info *info, uint16_t attr_type,
			void *data_out, uint32_t data_size)
{
	const void *data;
	uint32_t data_len;

	if (info == NULL || info->attrs[attr_type] == NULL ||
	    data_out == NULL) {
		ubagg_log_err("Invalid netlink attr parse param, attr:%u\n",
			      attr_type);
		return -EINVAL;
	}

	data = nla_data(info->attrs[attr_type]);
	data_len = nla_len(info->attrs[attr_type]);
	if (data == NULL || data_len != data_size) {
		ubagg_log_err("Invalid netlink attr:%u len:%u, expected:%u\n",
			      attr_type, data_len, data_size);
		return -EINVAL;
	}

	memcpy(data_out, data, data_size);
	return 0;
}

static int ubagg_nl_get_physical_device_ops(struct sk_buff *skb,
					    struct genl_info *info)
{
	size_t arg_size = 0;
	struct ubagg_cmd_physical_device *arg = NULL;
	int ret = -EINVAL;
	struct ubcore_device *dev = NULL;
	struct ubagg_physical_device_out out = { 0 };
	struct sk_buff *msg;
	void *hdr;

	if (info == NULL || info->attrs[UBAGG_ATTR_EID] == NULL ||
	    nla_len(info->attrs[UBAGG_ATTR_EID]) != sizeof(union ubcore_eid)) {
		ubagg_log_err("Invalid ubagg netlink msg\n");
		return -EINVAL;
	}

	arg_size = sizeof(struct ubagg_cmd_physical_device);
	arg = kzalloc(arg_size, GFP_KERNEL);
	if (!arg) {
		ubagg_log_err("Failed to kzalloc for arg\n");
		return -ENOMEM;
	}

	(void)memcpy(&arg->in.bonding_eid,
		     nla_data(info->attrs[UBAGG_ATTR_EID]),
		     sizeof(union ubcore_eid));

	dev = ubcore_get_device_by_eid(&arg->in.bonding_eid,
				       UBCORE_TRANSPORT_UB);
	if (IS_ERR_OR_NULL(dev)) {
		ubagg_log_err("Failed to query primary dev\n");
		kfree(arg);
		return -ENOENT;
	}
	(void)memcpy(arg->out.dev_name, dev->dev_name, UBAGG_MAX_DEV_NAME_LEN);

	ret = query_eid_idx(dev, &arg->in.bonding_eid,
			    &arg->out.bonding_eid_idx);
	ubagg_put_ubcore_device(dev);
	if (ret != 0) {
		ubagg_log_err("Failed to query eid information\n");
		kfree(arg);
		return ret;
	}

	ret = get_physical_device(NULL, &out, &arg->in.bonding_eid);
	if (ret != 0) {
		ubagg_log_err("Failed to get bonding info %d\n", ret);
		kfree(arg);
		return ret;
	}
	(void)memcpy(arg->out.physical_devs, out.physical_devs,
		     IODIE_NUM * sizeof(struct ubagg_physical_device));

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL) {
		kfree(arg);
		return -ENOMEM;
	}
	hdr = genlmsg_put_reply(msg, info, &genl_family, 0,
				UBAGG_NL_CMD_GET_PHYSICAL_DEVICE);
	if (hdr == NULL) {
		nlmsg_free(msg);
		kfree(arg);
		return -ENOMEM;
	}

	ret = nla_put(msg, UBAGG_ATTR_BONDING_PHYSICAL_DEVICE, sizeof(arg->out),
		      &arg->out);
	if (ret != 0) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		kfree(arg);
		return ret;
	}
	genlmsg_end(msg, hdr);
	kfree(arg);
	return genlmsg_reply(msg, info);
}

static int ubagg_nl_get_v2p_res_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubagg_cmd_v2p_res *arg = NULL;
	struct ubagg_device *ubagg_dev = NULL;
	uint64_t args_addr;
	int ret;

	if (info == NULL || info->attrs[UBAGG_HDR_ARGS_ADDR] == NULL) {
		ubagg_log_err("Invalid ubagg v2p res netlink msg\n");
		return -EINVAL;
	}

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	args_addr = nla_get_u64(info->attrs[UBAGG_HDR_ARGS_ADDR]);
	ret = (int)copy_from_user(arg, (void __user *)(uintptr_t)args_addr,
				  sizeof(*arg));
	if (ret != 0) {
		ubagg_log_err("Failed to copy v2p res arg from user\n");
		ret = -EFAULT;
		goto free_arg;
	}

	arg->in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	ubagg_dev = ubagg_find_dev_by_name(arg->in.dev_name);
	if (ubagg_dev == NULL) {
		ubagg_log_err("Failed to find ubagg dev %s\n",
			      arg->in.dev_name);
		ret = -ENOENT;
		goto free_arg;
	}

	ret = ubagg_query_v2p_res(ubagg_dev, arg);
	ubagg_dev_ref_put(ubagg_dev);
	if (ret != 0) {
		ubagg_log_err("Failed to query ubagg v2p res, ret:%d\n", ret);
		goto free_arg;
	}

	ret = (int)copy_to_user((void __user *)(uintptr_t)args_addr, arg,
				sizeof(*arg));
	if (ret != 0) {
		ubagg_log_err("Failed to copy v2p res arg to user\n");
		ret = -EFAULT;
		goto free_arg;
	}

	ret = 0;

free_arg:
	kfree(arg);
	return ret;
}

static int ubagg_nl_get_topo_node(uint64_t args_addr)
{
	struct ubagg_nl_topo_info *arg = NULL;
	struct ubagg_topo_map *topo_map;
	int node_num;
	int ret;

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = (int)copy_from_user(arg, (void __user *)(uintptr_t)args_addr,
				  sizeof(*arg));
	if (ret != 0) {
		ubagg_log_err("Failed to copy topo info from user, ret = %d\n",
			      ret);
		kfree(arg);
		return -EFAULT;
	}

	topo_map = get_global_ubagg_map();
	if (topo_map == NULL) {
		ubagg_log_err("topo map is empty\n");
		kfree(arg);
		return -ENXIO;
	}

	node_num = (int)topo_map->node_num;
	if (arg->in.node_idx < 0 || arg->in.node_idx >= node_num) {
		ubagg_log_err("Invalid topo node index %d, node_num:%u\n",
			      arg->in.node_idx, topo_map->node_num);
		kfree(arg);
		return -EINVAL;
	}

	arg->out.node_num = topo_map->node_num;
	(void)memcpy(&arg->out.topo_info,
		     &topo_map->topo_infos[arg->in.node_idx],
		     sizeof(arg->out.topo_info));
	ret = (int)copy_to_user((void __user *)(uintptr_t)args_addr, arg,
				sizeof(*arg));
	if (ret != 0) {
		ubagg_log_err("Failed to copy topo info to user, ret = %d\n",
			      ret);
		kfree(arg);
		return -EFAULT;
	}

	kfree(arg);
	return 0;
}

static int ubagg_nl_get_topo_ops(struct sk_buff *skb, struct genl_info *info)
{
	uint64_t args_addr;

	if (info == NULL || info->attrs[UBAGG_HDR_ARGS_ADDR] == NULL)
		return -EINVAL;

	args_addr = nla_get_u64(info->attrs[UBAGG_HDR_ARGS_ADDR]);
	return ubagg_nl_get_topo_node(args_addr);
}

int ubagg_genl_register_family(void)
{
	int ret = genl_register_family(&genl_family);

	if (ret != 0)
		ubagg_log_err("Failed to register ubagg genl family, ret=%d\n",
			      ret);
	return ret;
}

void ubagg_genl_unregister_family(void)
{
	(void)genl_unregister_family(&genl_family);
}
