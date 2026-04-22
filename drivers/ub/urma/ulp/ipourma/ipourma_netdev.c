// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: ipourma netdev operations
 */

#include <net/addrconf.h>
#include <net/pkt_sched.h>
#include <net/ip_fib.h>
#include <net/route.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/interrupt.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>

#include "ipourma_res.h"
#include "ipourma_ub.h"
#include "ipourma_main.h"
#include "ipourma_ip.h"
#include "ipourma_err.h"
#include "ipourma_utils.h"
#include "ipourma_addr_res.h"
#include "ipourma_ethtool.h"
#include "ipourma_netlink.h"
#include "ub/urma/ubcore_uapi.h"
#include "ipourma_netdev.h"

#define IN6_ADDR_BITS   (sizeof(struct in6_addr) * 8)

static u8 g_route_tbl_idx = 100;

static int prepare_route_rule(struct ipourma_dev_priv *priv, struct sk_buff *skb, int type,
							  struct in6_addr *src_ipv6)
{
	struct fib_rule_hdr *frh;
	struct nlmsghdr *nlh;

	NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	NETLINK_CB(skb).flags = NETLINK_SKB_DST;

	nlh = nlmsg_put(skb, 0, 0, type,
		sizeof(struct fib_rule_hdr), NLM_F_REQUEST | NLM_F_CREATE);
	if (IS_ERR_OR_NULL(nlh))
		return -EMSGSIZE;

	frh = nlmsg_data(nlh);
	memset(frh, 0, sizeof(*frh));
	frh->family = AF_INET6;
	frh->action = FR_ACT_TO_TBL;
	frh->src_len = (u8)IN6_ADDR_BITS;
	if (priv->route_tbl_idx)
		frh->table = priv->route_tbl_idx;
	else {
		frh->table = g_route_tbl_idx;
		priv->route_tbl_idx = g_route_tbl_idx++;
	}

	if (nla_put(skb, FRA_SRC, sizeof(struct in6_addr), src_ipv6))
		return -EMSGSIZE;

	nlmsg_end(skb, nlh);

	return 0;
}

static int ipourma_add_route_rule(struct ipourma_dev_priv *priv, union ubcore_eid *eid)
{
	struct in6_addr addr;
	struct sk_buff *skb;
	int ret;

	if (IS_ERR_OR_NULL(priv) || IS_ERR_OR_NULL(eid))
		return -EINVAL;

	ret = ipourma_resolve_ipaddr(priv->dev, ETH_P_IPV6, eid, &addr);
	if (ret != 0) {
		netdev_err(priv->dev, "Faile to resolve eid "EID_FMT"\n", EID_ARGS(*eid));
		return ret;
	}

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (IS_ERR_OR_NULL(skb)) {
		netdev_err(priv->dev, "Failed to alloc skb\n");
		return -ENOMEM;
	}

	if (prepare_route_rule(priv, skb, RTM_NEWRULE, &addr)) {
		netdev_err(priv->dev, "Failed to prepare rule\n");
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	ret = rtnl_unicast(skb, dev_net(priv->dev), 0);
	if (ret)
		netdev_err(priv->dev, "Failed to new route\n");

	return ret;
}

static int ipourma_del_route_rule(struct ipourma_dev_priv *priv, union ubcore_eid *eid)
{
	struct in6_addr addr;
	struct sk_buff *skb;
	int ret;

	if (IS_ERR_OR_NULL(priv) || IS_ERR_OR_NULL(eid))
		return -EINVAL;

	ret = ipourma_resolve_ipaddr(priv->dev, ETH_P_IPV6, eid, &addr);
	if (ret != 0)
		return ret;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (IS_ERR_OR_NULL(skb))
		return -ENOMEM;

	if (prepare_route_rule(priv, skb, RTM_DELRULE, &addr)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	ret = rtnl_unicast(skb, dev_net(priv->dev), 0);
	if (ret)
		netdev_err(priv->dev, "Failed to new route\n");

	return ret;
}

static int prepare_route_entry(struct ipourma_dev_priv *priv, struct sk_buff *skb, int type)
{
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	NETLINK_CB(skb).flags = NETLINK_SKB_DST;

	nlh = nlmsg_put(skb, 0, 0, type,
		sizeof(struct fib_rule_hdr), NLM_F_REQUEST | NLM_F_CREATE);
	if (IS_ERR_OR_NULL(nlh))
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_INET6;
	rtm->rtm_dst_len = 0;
	rtm->rtm_src_len = 0;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_table = priv->route_tbl_idx;

	if (nla_put_u32(skb, RTA_OIF, priv->dev->ifindex))
		return -EMSGSIZE;

	nlmsg_end(skb, nlh);

	return 0;
}

static void ipourma_add_route_entry(struct work_struct *work)
{
	struct ipourma_dev_priv *priv;
	struct sk_buff *skb;
	int ret;

	priv = container_of(work, struct ipourma_dev_priv, set_route_entry);

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (IS_ERR_OR_NULL(skb)) {
		netdev_err(priv->dev, "Failed to alloc skb\n");
		return;
	}

	if (prepare_route_entry(priv, skb, RTM_NEWROUTE)) {
		netdev_err(priv->dev, "Failed to prepare route entry\n");
		nlmsg_free(skb);
		return;
	}

	ret = rtnl_unicast(skb, dev_net(priv->dev), 0);
	if (ret)
		netdev_err(priv->dev, "Failed to new route\n");
}

static int ipourma_del_route_entry(struct ipourma_dev_priv *priv)
{
	struct sk_buff *skb;
	int ret;

	if (IS_ERR_OR_NULL(priv))
		return -EINVAL;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (IS_ERR_OR_NULL(skb))
		return -ENOMEM;

	if (prepare_route_entry(priv, skb, RTM_DELROUTE)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	ret = rtnl_unicast(skb, dev_net(priv->dev), 0);
	if (ret)
		netdev_err(priv->dev, "Failed to new route\n");

	return ret;
}

void ipourma_add_route(struct work_struct *work)
{
	struct ipourma_dev_priv *priv;
	int i;
	int ret = -1;
	bool flag = false;

	priv = container_of(work, struct ipourma_dev_priv, set_route);

	for (i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
		if (eid_is_empty(&priv->eid_info[i].eid))
			continue;
		ret = ipourma_add_route_rule(priv, &(priv->eid_info[i].eid));
		flag = true;
		if (ret != 0)
			goto ROUTE_ERR;
	}
	if (flag)
		queue_work(priv->net_config_wq, &(priv->set_route_entry));
	return;

ROUTE_ERR:
	for (i--; i >= 0; i--)
		ipourma_del_route_rule(priv, &(priv->eid_info[i].eid));
}

static void ipourma_del_route(struct work_struct *work)
{
	struct ipourma_dev_priv *priv;

	priv = container_of(work, struct ipourma_dev_priv, unset_route);
	ipourma_del_route_entry(priv);
	if (!IS_ERR_OR_NULL(priv->eid_info)) {
		for (int i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
			if (eid_is_empty(&priv->eid_info[i].eid))
				continue;
			ipourma_del_route_rule(priv, &priv->eid_info[i].eid);
		}
	}
}

static int ipourma_ndo_init(struct net_device *dev)
{
	int ret = 0;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;
	/* supports scatter/gather */
	dev->features |= NETIF_F_SG;
	/* HW DO NOT support TSO */
	dev->hw_features &= ~NETIF_F_FRAGLIST;

	ret = ipourma_urma_dev_init(dev);

	return ret;
}

static void ipourma_ndo_uninit(struct net_device *dev)
{
	// do uninit in ipourma_stop
}

static inline void ipourma_napi_enable(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	napi_enable(&priv->napi_send);
	napi_enable(&priv->napi_recv);
}

static inline void ipourma_rearm_jfc(struct ipourma_dev_priv *priv)
{
	if (IS_ERR_OR_NULL(priv->rx_jfc) || ubcore_rearm_jfc(priv->rx_jfc, false) != 0) {
		netdev_dbg(priv->dev, "%s\n", ipourma_err_desc(IPOURMA_REARM_JFC_FAILED));
		priv->runtime_stats.rx_stats.rearm_failed++;
	} else
		priv->runtime_stats.rx_stats.rearm_success++;
	if (IS_ERR_OR_NULL(priv->tx_jfc) || ubcore_rearm_jfc(priv->tx_jfc, false) != 0) {
		netdev_dbg(priv->dev, "%s\n", ipourma_err_desc(IPOURMA_REARM_JFC_FAILED));
		priv->runtime_stats.tx_stats.rearm_failed++;
	} else
		priv->runtime_stats.tx_stats.rearm_success++;
}

static int ipourma_open(struct net_device *dev)
{
	struct ipourma_dev_priv *priv;
	int ret = 0;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;
	priv = netdev_priv(dev);

	ret = ipourma_restart_rings(priv);
	if (ret != 0) {
		netdev_err(dev, "Device opened failed. ret = %d\n", ret);
		return ret;
	}

	ipourma_napi_enable(dev);
	netif_start_queue(dev);
	dev->flags |= IFF_RUNNING;
	netif_carrier_on(dev);
	set_bit(IPOURMA_DEV_ADMIN_UP, &priv->flags);
	ipourma_rearm_jfc(priv);
	netdev_info(dev, "Device opened.\n");

	return 0;
}

static inline void ipourma_napi_disable(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	napi_disable(&priv->napi_send);
	napi_disable(&priv->napi_recv);
}

static int ipourma_stop(struct net_device *dev)
{
	struct ipourma_dev_priv *priv;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;
	priv = netdev_priv(dev);

	ipourma_napi_disable(dev);
	clear_bit(IPOURMA_DEV_ADMIN_UP, &priv->flags);
	netif_stop_queue(dev);
	if (!IS_ERR_OR_NULL(priv->tx_wq))
		flush_workqueue(priv->tx_wq);
	if (!IS_ERR_OR_NULL(priv->rx_wq))
		flush_workqueue(priv->rx_wq);
	ipourma_reset_rings(priv);
	ipourma_lru_clear(&priv->tjetty_lru);
	netif_carrier_off(dev);
	dev->flags &= ~IFF_RUNNING;
	queue_work(priv->net_config_wq, &(priv->unset_route));

	netdev_info(dev, "Device closed.\n");

	return 0;
}

static int ipourma_change_mtu(struct net_device *dev, int mtu)
{
	bool flag;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;

	/* if device is running, then user should not change the mtu */
	if (netif_running(dev)) {
		pr_err("cannot change mtu when device is running\n");
		return -EINVAL;
	}

	/* check ranges */
	if ((mtu < IPOURMA_MIN_MTU) || (mtu > IPOURMA_MAX_MTU))
		return -EINVAL;

	flag = netif_carrier_ok(dev);
	netif_carrier_off(dev);
	dev->mtu = (uint32_t)mtu;
	if (flag)
		netif_carrier_on(dev);
	pr_info("change mtu to %d success!\n", dev->mtu);
	return 0;
}

static netdev_features_t ipourma_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;

	features &= ~(NETIF_F_GSO | NETIF_F_TSO | NETIF_F_SG);
	return features;
}

static netdev_tx_t ipourma_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	union ubcore_eid src_eid, dst_eid;
	struct ipourma_dev_priv *priv;
	u16 proto;
	int ret;

	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(skb) ||
		IS_ERR_OR_NULL(skb->head) || IS_ERR_OR_NULL(skb->data))
		return -EINVAL;

	priv  = netdev_priv(dev);
	priv->runtime_stats.tx_stats.num_recv_pkts_from_kernel++;
	proto = ntohs(skb->protocol);

	pr_skb_head_plus_linear(skb, "start xmit");
	/* only support IPv6 */
	if (proto != ETH_P_IPV6) {
		priv->runtime_stats.tx_stats.not_ipv6_proto++;
		netdev_dbg(dev, "Unsupported ether type: %u", proto);
		goto drop_out;
	}
	/* check skb */
	ret = ipourma_check_skb(dev, skb);
	if (ret != IPOURMA_OK)
		goto drop_out;

	ipourma_resolve_eids(dev, skb, proto, &src_eid, &dst_eid);

	ret = ipourma_xmit(dev, skb, &src_eid, &dst_eid);
	if (ret != IPOURMA_OK)
		goto err_out;

	return NETDEV_TX_OK;

drop_out:
	dev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
err_out:
	dev->stats.tx_errors++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static void ipourma_timeout(struct net_device *dev, unsigned int txqueue)
{
	struct ipourma_dev_priv *priv;

	if (IS_ERR_OR_NULL(dev))
		return;

	priv = netdev_priv(dev);
	netdev_err(dev, "Transmit timeout at %ld, latency %d\n",
		jiffies, jiffies_to_msecs(jiffies - dev_trans_start(dev)));
	if (IS_ERR_OR_NULL(priv->eid_info))
		return;
	for (int i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
		if (eid_is_empty(&priv->eid_info[i].eid))
			continue;
		netdev_err(dev, "queue stopped %d, tx_head %u, tx_tail %u\n",
			netif_queue_stopped(dev), priv->tx_head[i], priv->tx_tail[i]);
	}
}

/*
 * for real net device, return 0.
 */
static int ipourma_get_iflink(const struct net_device *dev)
{
	return 0;
}

static int ipourma_set_mac(struct net_device *dev, void *addr)
{
	struct sockaddr *sa = addr;

	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(addr))
		return -EINVAL;
	if (!is_valid_ether_addr(sa->sa_data))
		return -EINVAL;
	if (!(dev->priv_flags & IFF_LIVE_ADDR_CHANGE) && netif_running(dev))
		return -EBUSY;

	memcpy((void *)dev->dev_addr, sa->sa_data, dev->addr_len);

	return 0;
}

static void ipourma_get_stats(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	// fill in stats
	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(stats))
		return;
	netdev_stats_to_stats64(stats, &dev->stats);
}

static int ipourma_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	/* if ipourma has some private functions in the future, ioctl will call them here. */
	return 0;
}

static const struct net_device_ops ipourma_netdev_ops = {
	.ndo_init		 = ipourma_ndo_init,
	.ndo_uninit		 = ipourma_ndo_uninit,
	.ndo_open		 = ipourma_open,
	.ndo_stop		 = ipourma_stop,
	.ndo_change_mtu		 = ipourma_change_mtu,
	.ndo_fix_features	 = ipourma_fix_features,
	.ndo_start_xmit		 = ipourma_start_xmit,
	.ndo_tx_timeout		 = ipourma_timeout,
	.ndo_get_iflink		 = ipourma_get_iflink,
	.ndo_set_mac_address	 = ipourma_set_mac,
	.ndo_get_stats64	 = ipourma_get_stats,
	.ndo_eth_ioctl		 = ipourma_ioctl,
};

static void ipourma_netdev_setup(struct net_device *dev)
{
	dev->netdev_ops        = &ipourma_netdev_ops;

	ipourma_set_ethtool_ops(dev);
	ipourma_set_rtnl_link_ops(dev);

	dev->type              = ARPHRD_ETHER;
	dev->hard_header_len   = IPOURMA_HARD_LEN;
	dev->addr_len          = IPOURMA_ALEN;
	dev->tx_queue_len      = DEFAULT_TX_QUEUE_LEN;
	dev->needs_free_netdev = false;
	dev->mtu               = IPOURMA_DEFAULT_MTU;
	dev->flags            |= IFF_NOARP;
	dev->features         |= NETIF_F_HIGHDMA |
								NETIF_F_GRO;
	dev->features         &= ~(NETIF_F_SG | NETIF_F_TSO | NETIF_F_GSO);
	dev->num_rx_queues     = 1;
	dev->num_tx_queues     = 1;
	dev->watchdog_timeo    = HZ;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_ADDRCONF;

	netif_keep_dst(dev);
}

static inline void ipourma_open_dev(struct work_struct *work)
{
	struct ipourma_dev_priv *priv = container_of(work, struct ipourma_dev_priv, set_dev_up);
	struct net_device *dev = priv->dev;

	rtnl_lock();
	dev_change_flags(dev, dev->flags | IFF_UP, NULL);
	rtnl_unlock();
}

static inline void ipourma_init_stats(struct ipourma_dev_priv *priv)
{
	memset(&(priv->runtime_stats.tx_stats), 0, sizeof(priv->runtime_stats.tx_stats));
	memset(&(priv->runtime_stats.rx_stats), 0, sizeof(priv->runtime_stats.rx_stats));
	spin_lock_init(&(priv->runtime_stats.lock));
}

static int ipourma_priv_base_init(struct net_device *dev,
	struct ubcore_device *urma_dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	spin_lock_init(&priv->lock);
	priv->urma_dev = urma_dev;
	priv->dev = dev;
	priv->parent = NULL;
	priv->eid_info = NULL;
	priv->eid_count = 0;
	priv->tjetty_lru.count = 0;
	priv->need_restart_ring = false;
	priv->tjetty_lru.tjetty_capacity = IPOURMA_DEFAULT_TJETTY_CAP;

	ipourma_init_stats(priv);
	INIT_WORK(&(priv->set_dev_up), ipourma_open_dev);
	INIT_WORK(&(priv->set_ip), ipourma_init_ipv6_addr);
	INIT_WORK(&(priv->set_route), ipourma_add_route);
	INIT_WORK(&(priv->unset_route), ipourma_del_route);
	INIT_WORK(&(priv->set_route_entry), ipourma_add_route_entry);
	INIT_WORK(&(priv->rx_cr_event), ipourma_rx_cr_event);
	INIT_WORK(&(priv->register_netdev), ipourma_register_netdev);
	atomic_set(&priv->rx_jfr_ref, 0);
	atomic_set(&priv->tx_ring_blocked, 0);
	spin_lock_init(&priv->tjetty_lru.lock);
	INIT_LIST_HEAD(&priv->tjetty_lru.list);

	priv->register_wq = alloc_workqueue("ipourma_register_wq", WQ_MEM_RECLAIM, 0);
	if (IS_ERR_OR_NULL(priv->register_wq))
		return -1;
	return IPOURMA_OK;
}

struct net_device *ipourma_alloc_netdev(struct ubcore_device *urma_dev)
{
	struct ipourma_dev_priv *priv;
	struct net_device *dev;

	pr_debug("alloc_netdev\n");
	dev = alloc_netdev(sizeof(struct ipourma_dev_priv), "ipourma%d",
					   NET_NAME_PREDICTABLE, ipourma_netdev_setup);
	if (IS_ERR_OR_NULL(dev)) {
		pr_err("Failed to allocate net_device\n");
		return NULL;
	}
	priv = netdev_priv(dev);
	if (unlikely(ipourma_priv_base_init(dev, urma_dev) != IPOURMA_OK)) {
		free_netdev(dev);
		return NULL;
	}
	if (unlikely(ipourma_init_tjetty_hmap(dev) != IPOURMA_OK)) {
		/* free netdev which has been alloced before eid_init */
		destroy_workqueue(priv->register_wq);
		free_netdev(dev);
		return NULL;
	}
	pr_debug("alloc_netdev completed.\n");

	return dev;
}

static inline void ipourma_priv_eid_uninit(struct ipourma_dev_priv *priv)
{
	kfree(priv->eid_info);
	priv->eid_info = NULL;
	kfree(priv->tx_ring_is_full);
	priv->tx_ring_is_full = NULL;
	priv->eid_count = 0;
}

int ipourma_unalloc_netdev(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	if (priv->eid_info)
		ipourma_priv_eid_uninit(priv);
	free_netdev(dev);
	return 0;
}

static void set_ip_callback(struct work_struct *work)
{
	struct delayed_work *d_work = container_of(work, struct delayed_work, work);
	struct ipourma_set_ip_work *set_ip_work =
					container_of(d_work, struct ipourma_set_ip_work, d_work);
	struct ipourma_dev_priv *priv = set_ip_work->priv;
	int eid_idx = set_ip_work->eid_idx;
	int ret = IPOURMA_OK;

	if (!netif_running(priv->dev)) {
		schedule_delayed_work(d_work, msecs_to_jiffies(MSEC_PER_SEC));
		return;
	}
	ret = ipourma_send_ipv6_netlink(priv->dev, &(priv->eid_info[eid_idx].eid), RTM_NEWADDR);
	if (ret != 0)
		goto free_work;

	ret = ipourma_add_route_rule(priv, &(priv->eid_info[eid_idx].eid));
	if (ret != 0) {
		ret = ipourma_send_ipv6_netlink(priv->dev,
						&(priv->eid_info[eid_idx].eid),
						RTM_DELADDR);
		goto free_work;
	}

	ipourma_add_route_entry(&(priv->set_route_entry));

free_work:
	kfree(set_ip_work);
}

static void ipourma_init_set_ip_work(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	struct ipourma_set_ip_work *set_ip_work = NULL;
	struct delayed_work *d_work = NULL;

	set_ip_work = kzalloc(sizeof(struct ipourma_set_ip_work), GFP_KERNEL);
	if (IS_ERR_OR_NULL(set_ip_work)) {
		netdev_err(priv->dev, "kzalloc set_ip_work_failed, eid_idx = %u", eid_idx);
		return;
	}
	set_ip_work->priv = priv;
	set_ip_work->eid_idx = eid_idx;
	d_work = &set_ip_work->d_work;
	INIT_DELAYED_WORK(d_work, set_ip_callback);
	schedule_delayed_work(d_work, msecs_to_jiffies(MSEC_PER_SEC));
}

void ipourma_create_new_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	int ret;

	ret = ipourma_urma_init_by_eid(priv, eid_idx);
	if (ret != IPOURMA_OK) {
		memset(&priv->eid_info[eid_idx].eid, 0, UBCORE_EID_SIZE);
		return;
	}
	ipourma_init_set_ip_work(priv, eid_idx);
}
