// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg generic netlink support
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <net/genetlink.h>
#include <ub/urma/ubcore_uapi.h>

#include "ubagg_dfx.h"
#include "ubagg_log.h"
#include "ubagg_ioctl.h"
#include "ubagg_netlink.h"

#define UBAGG_GENL_FAMILY_NAME "UBAGG_GENL"
#define UBAGG_GENL_FAMILY_VERSION 1

enum ubagg_genl_cmd {
	UBAGG_NL_CMD_UNSPEC = 0,
	UBAGG_NL_CMD_GET_TOPO = 1,
	UBAGG_NL_CMD_GET_SLAVE_EID = 2,
	UBAGG_NL_CMD_GET_PHYSICAL_DEVICE = 4,
	UBAGG_NL_CMD_GET_V2P_RES = 5,
	UBAGG_NL_CMD_MAX,
};

enum ubagg_genl_attr {
	UBAGG_ATTR_UNSPEC = 0,
	UBAGG_HDR_ARGS_ADDR = 4,
	UBAGG_ATTR_MAX = 5,
};

static const struct nla_policy ubagg_genl_policy[UBAGG_ATTR_MAX] = {
	[UBAGG_ATTR_UNSPEC] = { 0 },
	[UBAGG_HDR_ARGS_ADDR] = { .type = NLA_U64 },
};

int ubagg_nl_get_physical_device_ops(struct sk_buff *skb, struct genl_info *info)
{
	size_t arg_size = 0;
	struct ubagg_cmd_physical_device *arg = NULL;
	int ret = -EINVAL;
	uint64_t args_addr = 0;
	struct ubcore_device *dev = NULL;
	struct ubagg_physical_device_out out = { 0 };

	if (info == NULL || info->attrs[UBAGG_HDR_ARGS_ADDR] == NULL) {
		ubagg_log_err("Invalid ubagg netlink msg\n");
		return -EINVAL;
	}

	arg_size = sizeof(struct ubagg_cmd_physical_device);
	arg = kzalloc(arg_size, GFP_KERNEL);
	if (!arg) {
		ubagg_log_err("Failed to kzalloc for arg\n");
		return -ENOMEM;
	}

	args_addr = nla_get_u64(info->attrs[UBAGG_HDR_ARGS_ADDR]);
	ret = (int)copy_from_user(arg, (void __user *)(uintptr_t)args_addr, arg_size);
	if (ret != 0) {
		ubagg_log_err("Failed to copy from user\n");
		kfree(arg);
		return -EINVAL;
	}

	dev = ubcore_get_device_by_eid(&arg->in.bonding_eid, UBCORE_TRANSPORT_UB);
	if (IS_ERR_OR_NULL(dev)) {
		ubagg_log_err("Failed to query primary dev\n");
		kfree(arg);
		return -ENOENT;
	}
	(void)memcpy(arg->out.dev_name, dev->dev_name, UBAGG_MAX_DEV_NAME_LEN);

	ret = query_eid_idx(dev, &arg->in.bonding_eid, &arg->out.bonding_eid_idx);
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

	ret = (int)copy_to_user((void __user *)(uintptr_t)args_addr, arg, arg_size);
	if (ret != 0) {
		ubagg_log_err("Failed to copy to user, ret = %d\n", ret);
		kfree(arg);
		return -EFAULT;
	}

	kfree(arg);
	return 0;
}

static int ubagg_nl_get_v2p_res_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubagg_cmd_v2p_res *arg = NULL;
	struct ubagg_device *ubagg_dev = NULL;
	uint64_t args_addr;
	int ret;

	(void)skb;

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
		ubagg_log_err("Failed to find ubagg dev %s\n", arg->in.dev_name);
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

static const struct genl_ops ubagg_genl_ops[] = {
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
	}
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
};

int ubagg_genl_register_family(void)
{
	int ret = genl_register_family(&genl_family);

	if (ret != 0)
		ubagg_log_err("Failed to register ubagg genl family, ret=%d\n", ret);
	return ret;
}

void ubagg_genl_unregister_family(void)
{
	(void)genl_unregister_family(&genl_family);
}
