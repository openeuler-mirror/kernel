// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: ipourma netlink support
 */

#include <net/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/if_link.h>

#include "ipourma_netlink.h"

/*
 * fill info support: op_mode, transport mode, max_send_sge, urma_mtu
 * The attributes info can be changed according to the actual scenario
 */
#define IPOURMA_ATTR_SIZE 4
static const struct nla_policy ipourma_policy[IFLA_IPOURMA_MAX + 1] = {
	[IFLA_IPOURMA_OP_MODE]		= { .type = NLA_U32 },
	[IFLA_IPOURMA_TRANSPORT_MODE]	= { .type = NLA_U32 },
	[IFLA_IPOURMA_MAX_SEND_SGE]	= { .type = NLA_U32 },
	[IFLA_IPOURMA_XMTU]		= { .type = NLA_U32 },
};

static size_t ipourma_get_size(const struct net_device *dev)
{
	return nla_total_size(IPOURMA_ATTR_SIZE) + /* IFLA_IPOURMA_OP_MODE */
		nla_total_size(IPOURMA_ATTR_SIZE) + /* IFLA_IPOURMA_TRANSPORT_MODE */
		nla_total_size(IPOURMA_ATTR_SIZE) + /* IFLA_IPOURMA_MAX_SEND_SGE */
		nla_total_size(IPOURMA_ATTR_SIZE); /* IFLA_IPOURMA_XMTU */
}

static int ipourma_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	if (IS_ERR_OR_NULL(skb)) {
		pr_warn_ratelimited("fill_info: skb is NULL");
		return -EINVAL;
	}

	if (nla_put_u32(skb, IFLA_IPOURMA_OP_MODE, priv->urma_op_mode) ||
		nla_put_u32(skb, IFLA_IPOURMA_TRANSPORT_MODE, priv->urma_transport_mode) ||
		nla_put_u32(skb, IFLA_IPOURMA_MAX_SEND_SGE, priv->max_send_sge) ||
		nla_put_u32(skb, IFLA_IPOURMA_XMTU, priv->urma_mtu)) {
		netdev_dbg(dev, "fill_info: put attribute failed");
		return -EMSGSIZE;
	}

	return 0;
}

/*
 * The ipourma does not support manual adding of ipourma devices through ip commands.
 * Therefore, only the minimum device setup is performed here to comply with the
 * RTnetlink framework.
 */
static void ipourma_setup_common(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	priv->dev = dev;
	dev->type = ARPHRD_ETHER;
	dev->mtu = IPOURMA_DEFAULT_MTU;
	dev->hard_header_len = ETH_HLEN;
	dev->addr_len = ETH_ALEN;
	dev->flags = IFF_NOARP;
	dev->needs_free_netdev = false;
}

/*
 * The ipourma does not support manual adding of ipourma devices through ip commands.
 * The feedback info will be displayed if you enter command like
 * 'ip link add name ipourma3 type ipourma'.
 */
static int ipourma_newlink(struct net *src_net, struct net_device *dev,
				struct nlattr *tb[], struct nlattr *data[],
				struct netlink_ext_ack *extack)
{
	NL_SET_ERR_MSG_MOD(extack, "ipourma does not support manual device creation");
	return -EOPNOTSUPP;
}

/*
 * By default, the RTnetlink framework supports the modification of standard kernel
 * attributes using the ip command.
 * Example: ip link set dev ipourma0 up  Therefore, no additional operation in function
 * ipourma_changelink is required.
 * User-defined attributes need to be obtained by the user-mode client through the
 * interface of the RTnetlink framework.
 */
static int ipourma_changelink(struct net_device *dev, struct nlattr *tb[],
				struct nlattr *data[], struct netlink_ext_ack *extack)
{
	return 0;
}

struct rtnl_link_ops ipourma_link_ops __read_mostly = {
	.kind       = "ipourma",
	.maxtype    = IFLA_IPOURMA_MAX,
	.policy     = ipourma_policy,
	.priv_size  = sizeof(struct ipourma_dev_priv),
	.setup      = ipourma_setup_common,
	.newlink    = ipourma_newlink,
	.changelink = ipourma_changelink,
	.get_size   = ipourma_get_size,
	.fill_info  = ipourma_fill_info,
};

int ipourma_netlink_init(void)
{
	int ret = rtnl_link_register(&ipourma_link_ops);

	pr_info("netlink_init:%s\n", ret ? "failed" : "success");
	return ret;
}

void ipourma_netlink_uninit(void)
{
	rtnl_link_unregister(&ipourma_link_ops);
}

void ipourma_set_rtnl_link_ops(struct net_device *dev)
{
	dev->rtnl_link_ops = &ipourma_link_ops;
}
