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

#include "ubagg_log.h"
#include "ubagg_netlink.h"

#define UBAGG_MAX_NL_MSG_BUF_LEN 2048
#define UBAGG_GENL_FAMILY_NAME "UBAGG_GENL"
#define UBAGG_GENL_FAMILY_VERSION 1

enum ubagg_genl_cmd {
	UBAGG_NL_CMD_UNSPEC,
	UBAGG_NL_CMD_GET_TOPO,
	UBAGG_NL_CMD_GET_SLAVE_EID,
	UBAGG_NL_CMD_USER_PAYLOAD,
	UBAGG_NL_CMD_MAX,
};

enum ubagg_genl_attr {
	UBAGG_ATTR_UNSPEC,
	UBAGG_ATTR_LOCAL_EID,
	UBAGG_ATTR_PEER_EID,
	UBAGG_ATTR_PAYLOAD,
	UBAGG_ATTR_MAX,
};

static const struct nla_policy ubagg_genl_policy[UBAGG_ATTR_MAX] = {
	[UBAGG_ATTR_UNSPEC] = { 0 },
	[UBAGG_ATTR_LOCAL_EID] = { .type = NLA_BINARY, .len = UBCORE_EID_SIZE },
	[UBAGG_ATTR_PEER_EID] = { .type = NLA_BINARY, .len = UBCORE_EID_SIZE },
	[UBAGG_ATTR_PAYLOAD] = { .type = NLA_BINARY,
				 .len = UBAGG_MAX_NL_MSG_BUF_LEN },
};

enum ubagg_genl_mcgrp {
	UBAGG_NL_MCGRP_USER_PAYLOAD,
	UBAGG_NL_MCGRP_MAX,
};

static const struct genl_multicast_group ubagg_genl_mcgrps[] = {
	[UBAGG_NL_MCGRP_USER_PAYLOAD] = { .name = "user_payload" },
};

static struct genl_family genl_family __ro_after_init;

static void ubagg_nl_bonding_user_msg_handler(struct ubcore_device *dev,
					      void *payload,
					      uint16_t payload_len, void *conn)
{
	void *hdr = NULL;
	struct sk_buff *skb = NULL;
	int ret;

	if ((payload == NULL && payload_len != 0) ||
	    payload_len > UBAGG_MAX_NL_MSG_BUF_LEN) {
		ubagg_log_err("Invalid bonding user msg callback param\n");
		return;
	}

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		ubagg_log_err("Failed to alloc skb for ubagg user payload\n");
		return;
	}

	hdr = genlmsg_put(skb, 0, 0, &genl_family, 0,
			  UBAGG_NL_CMD_USER_PAYLOAD);
	if (hdr == NULL) {
		nlmsg_free(skb);
		ubagg_log_err("Failed to build ubagg user payload netlink msg\n");
		return;
	}

	if (nla_put(skb, UBAGG_ATTR_PAYLOAD, payload_len, payload)) {
		genlmsg_cancel(skb, hdr);
		nlmsg_free(skb);
		ubagg_log_err("Failed to append ubagg user payload attr\n");
		return;
	}

	genlmsg_end(skb, hdr);
	rcu_read_lock();
	ret = genlmsg_multicast_allns(&genl_family, skb, 0,
				      UBAGG_NL_MCGRP_USER_PAYLOAD);
	rcu_read_unlock();
	if (ret == -ESRCH)
		return;
	if (ret != 0)
		ubagg_log_err("Failed to multicast ubagg user payload, ret:%d\n",
			      ret);
	else
		ubagg_log_info("Broadcast ubagg user payload, payload_len:%u\n",
			       payload_len);
}

static int ubagg_nl_handle_user_msg(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_device *dev;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	const void *payload;
	uint32_t payload_len;
	int ret;

	(void)skb;

	if (info == NULL || info->attrs[UBAGG_ATTR_LOCAL_EID] == NULL ||
	    info->attrs[UBAGG_ATTR_PEER_EID] == NULL ||
	    info->attrs[UBAGG_ATTR_PAYLOAD] == NULL ||
	    nla_len(info->attrs[UBAGG_ATTR_LOCAL_EID]) != UBCORE_EID_SIZE ||
	    nla_len(info->attrs[UBAGG_ATTR_PEER_EID]) != UBCORE_EID_SIZE) {
		ubagg_log_err("Invalid ubagg user msg\n");
		return -EINVAL;
	}

	memcpy(&local_eid, nla_data(info->attrs[UBAGG_ATTR_LOCAL_EID]),
	       sizeof(local_eid));
	memcpy(&peer_eid, nla_data(info->attrs[UBAGG_ATTR_PEER_EID]),
	       sizeof(peer_eid));
	payload = nla_data(info->attrs[UBAGG_ATTR_PAYLOAD]);
	payload_len = nla_len(info->attrs[UBAGG_ATTR_PAYLOAD]);

	if (payload == NULL && payload_len != 0) {
		ubagg_log_err("Invalid ubagg user msg\n");
		return -EINVAL;
	}

	dev = ubcore_get_device_by_eid(&local_eid, UBCORE_TRANSPORT_UB);
	if (dev == NULL) {
		ubagg_log_err(
			"Failed to get ubcore device by local eid:" EID_FMT
			"\n",
			EID_ARGS(local_eid));
		return -ENODEV;
	}

	ret = ubcore_net_send_bonding_user_msg(dev, peer_eid, 0, payload,
					       payload_len);
	if (ret != 0)
		ubagg_log_err(
			"Failed to send ubagg payload by ubcore, ret:%d, local_eid:" EID_FMT
			", peer_eid:" EID_FMT "\n",
			ret, EID_ARGS(local_eid), EID_ARGS(peer_eid));
	else
		ubagg_log_info("Send ubagg payload by ubcore local_eid:" EID_FMT
			       ", peer_eid:" EID_FMT ", payload_len:%u\n",
			       EID_ARGS(local_eid), EID_ARGS(peer_eid),
			       payload_len);

	return ret;
}

static const struct genl_ops ubagg_genl_ops[] = {
	{
		.cmd = UBAGG_NL_CMD_USER_PAYLOAD,
		.doit = ubagg_nl_handle_user_msg,
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

int ubagg_netlink_init(void)
{
	int ret;

	ret = genl_register_family(&genl_family);
	if (ret != 0) {
		ubagg_log_err("Failed to register ubagg genl family, ret:%d\n",
			      ret);
		return ret;
	}

	ret = ubcore_net_register_bonding_user_msg_handler(
		ubagg_nl_bonding_user_msg_handler);
	if (ret != 0) {
		ubagg_log_err(
			"Failed to register ubagg bonding user msg handler, ret:%d\n",
			ret);
		(void)genl_unregister_family(&genl_family);
	}

	return ret;
}

void ubagg_netlink_uninit(void)
{
	ubcore_net_unregister_bonding_user_msg_handler(
		ubagg_nl_bonding_user_msg_handler);
	(void)genl_unregister_family(&genl_family);
}
