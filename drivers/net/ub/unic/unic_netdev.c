// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include <net/addrconf.h>
#include <net/bonding.h>
#include <net/dsfield.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/time.h>
#include <linux/u64_stats_sync.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_eq.h>
#include <ub/ubase/ubase_comm_stats.h>

#include "unic_bond.h"
#include "unic_cmd.h"
#include "unic_dev.h"
#include "unic_event.h"
#include "unic_hw.h"
#include "unic_ip.h"
#include "unic_mac.h"
#include "unic_rx.h"
#include "unic_tx.h"
#include "unic_txrx.h"
#include "unic_vlan.h"
#include "unic_netdev.h"

static int unic_netdev_set_tcs(struct net_device *netdev)
{
#define UNIC_OS_DEFAULT_VL	0

	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channels *channels = &unic_dev->channels;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	struct unic_vl *vl = &channels->vl;
	int ret;
	u8 i;

	if (!caps) {
		unic_err(unic_dev, "failed to get caps info.\n");
		return -ENODATA;
	}

	netdev_reset_tc(netdev);

	if (caps->vl_num <= 1)
		return 0;

	ret = netdev_set_num_tc(netdev, channels->rss_vl_num);
	if (ret) {
		unic_err(unic_dev, "failed to set num_tc, ret = %d.\n", ret);
		return ret;
	}

	for (i = 0; i < channels->rss_vl_num; i++)
		netdev_set_tc_queue(netdev, i, vl->queue_count[i],
				    vl->queue_offset[i]);

	for (i = 0; i < UNIC_MAX_PRIO_NUM; i++) {
		if (vl->prio_vl[i] > channels->rss_vl_num)
			netdev_set_prio_tc_map(netdev, i, UNIC_OS_DEFAULT_VL);
		else
			netdev_set_prio_tc_map(netdev, i, vl->prio_vl[i]);
	}

	return 0;
}

static int unic_real_num_queue_set(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u32 queue_size = unic_dev->channels.num;
	int ret;

	if (!queue_size)
		queue_size = UNIC_DEFAULT_CHANNEL_NUM;

	ret = unic_netdev_set_tcs(netdev);
	if (ret)
		return ret;

	ret = netif_set_real_num_tx_queues(netdev, queue_size);
	if (ret) {
		unic_err(unic_dev,
			 "failed to set real num tx queues, ret = %d!\n", ret);
		return ret;
	}

	ret = netif_set_real_num_rx_queues(netdev, queue_size);
	if (ret) {
		unic_err(unic_dev,
			 "failed to set real num rx queues, ret = %d!\n", ret);
		return ret;
	}

	return 0;
}

void unic_enable_channels(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channel *c;
	u32 i;

	mutex_lock(&unic_dev->channels.mutex);
	if (!unic_dev->channels.c)
		goto out;

	for (i = 0; i < unic_dev->channels.num; i++) {
		c = &unic_dev->channels.c[i];
		napi_enable(&c->napi);
	}

	ubase_comp_register(adev, unic_comp_handler);

out:
	mutex_unlock(&unic_dev->channels.mutex);
}

void unic_disable_channels(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channel *c;
	u32 i;

	mutex_lock(&unic_dev->channels.mutex);
	if (!unic_dev->channels.c)
		goto out;

	ubase_comp_unregister(adev);

	for (i = 0; i < unic_dev->channels.num; i++) {
		c = &unic_dev->channels.c[i];
		napi_disable(&c->napi);
	}

out:
	mutex_unlock(&unic_dev->channels.mutex);
}

static int unic_net_up(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	int ret;

	unic_clear_all_queue(netdev);

	unic_enable_channels(unic_dev);

	ret = unic_mac_mode_cfg(netdev, true);
	if (ret) {
		unic_disable_channels(unic_dev);
		return ret;
	}

	unic_dev->sw_link_status = UNIC_LINK_STATUS_DOWN;

	return 0;
}

static void unic_link_status_record(struct net_device *netdev, bool linkup)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_link_stats *record = &unic_dev->stats.link_record;
	u64 idx, total;

	mutex_lock(&record->lock);

	if (linkup)
		record->link_up_cnt++;
	else
		record->link_down_cnt++;

	total = record->link_up_cnt + record->link_down_cnt;
	idx = (total - 1) % LINK_STAT_MAX_IDX;
	record->stats[idx].link_tv_sec = ktime_get_real_seconds();
	record->stats[idx].link_status = linkup;

	mutex_unlock(&record->lock);
}

static void unic_clear_fec_stats(struct unic_dev *unic_dev)
{
	struct unic_fec_stats *fec_stats = &unic_dev->stats.fec_stats;

	if (!unic_dev_ubl_supported(unic_dev))
		memset(fec_stats, 0, sizeof(*fec_stats));
}

void unic_link_status_change(struct net_device *netdev, bool linkup)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	/* stop/wake network interface by deactivate/activate event */
	if (test_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state))
		goto out;

	if (linkup) {
		if (!test_bit(UNIC_STATE_TESTING, &unic_dev->state)) {
			netif_tx_wake_all_queues(netdev);
			netif_carrier_on(netdev);
			unic_clear_fec_stats(unic_dev);
			ubase_clear_eth_port_stats(unic_dev->comdev.adev);
		}
	} else {
		netif_carrier_off(netdev);
		netif_tx_stop_all_queues(netdev);
	}

out:
	if (netif_msg_link(unic_dev))
		unic_info(unic_dev, "%s.\n", linkup ? "link up" : "link down");

	unic_link_status_record(netdev, linkup);
}

void unic_link_status_update(struct unic_dev *unic_dev)
{
	u8 link_status = UNIC_LINK_STATUS_DOWN;
	int ret;

	if (test_and_set_bit(UNIC_STATE_LINK_UPDATING, &unic_dev->state))
		return;

	if (test_bit(UNIC_STATE_DOWN, &unic_dev->state))
		goto ifdown;

	ret = unic_query_link_status(unic_dev, &link_status);
	if (ret) {
		clear_bit(UNIC_STATE_LINK_UPDATING, &unic_dev->state);
		return;
	}

	unic_dev->hw.mac.link_status = link_status;
	if (unic_dev_ubl_supported(unic_dev))
		link_status = UNIC_LINK_STATUS_UP;

ifdown:
	if (link_status != unic_dev->sw_link_status) {
		unic_dev->sw_link_status = link_status;
		unic_link_status_change(unic_dev->comdev.netdev, link_status);
	}

	clear_bit(UNIC_STATE_LINK_UPDATING, &unic_dev->state);
}

int unic_net_open(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	int ret;

	if (test_bit(UNIC_STATE_RESETTING, &unic_dev->state))
		return -EBUSY;

	if (!test_bit(UNIC_STATE_DOWN, &unic_dev->state)) {
		unic_warn(unic_dev, "net open repeatedly.\n");
		return 0;
	}

	netif_carrier_off(netdev);

	/* only cfg mac mode, wake network interface by activate event */
	if (test_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state)) {
		ret = unic_mac_mode_cfg(netdev, true);
		if (ret) {
			unic_err(unic_dev, "failed to cfg mac mode, ret = %d.\n",
				 ret);
			return ret;
		}

		clear_bit(UNIC_STATE_DOWN, &unic_dev->state);
		return 0;
	}

	ret = unic_real_num_queue_set(netdev);
	if (ret) {
		unic_err(unic_dev, "failed to set real num queue, ret = %d.\n",
			 ret);
		return ret;
	}

	ret = unic_net_up(netdev);
	if (ret) {
		unic_err(unic_dev, "failed to up net, ret = %d.\n", ret);
		return ret;
	}

	clear_bit(UNIC_STATE_DOWN, &unic_dev->state);

	if (netif_msg_ifup(unic_dev))
		unic_info(unic_dev, "net open.\n");

	return 0;
}

int unic_net_open_no_link_change(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	int ret;

	if (unic_resetting(netdev))
		return -EBUSY;

	if (test_bit(UNIC_STATE_DOWN, &unic_dev->state))
		return 0;

	netif_carrier_off(netdev);

	ret = unic_real_num_queue_set(netdev);
	if (ret) {
		unic_err(unic_dev, "failed to set real num queue, ret = %d.\n",
			 ret);
		return ret;
	}

	unic_clear_all_queue(netdev);
	unic_enable_channels(unic_dev);

	if (netif_msg_ifup(unic_dev))
		unic_info(unic_dev, "netif open.\n");

	/* ensure that network interface is awakened when linked up,
	 * otherwise, it will be handled by periodic tasks
	 */
	if (unic_dev->sw_link_status == UNIC_LINK_STATUS_UP) {
		netif_tx_wake_all_queues(netdev);
		netif_carrier_on(netdev);
		unic_clear_fec_stats(unic_dev);
		ubase_clear_eth_port_stats(unic_dev->comdev.adev);
	}

	return 0;
}

static void unic_dev_stop(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	unic_mac_mode_cfg(netdev, false);

	unic_link_status_update(unic_dev);
}

void unic_net_stop_no_link_change(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	if (test_bit(UNIC_STATE_DOWN, &unic_dev->state))
		return;

	if (netif_msg_ifdown(unic_dev))
		unic_info(unic_dev, "netif stop.\n");

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	netif_tx_stop_all_queues(netdev);

	unic_disable_channels(unic_dev);
	unic_clear_all_queue(netdev);
	unic_reset_tx_queue(netdev);
}

int unic_net_stop(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	if (test_and_set_bit(UNIC_STATE_DOWN, &unic_dev->state))
		return 0;

	/* only cfg mac mode, because stop network interface has been done
	 * by deactivate event
	 */
	if (test_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state)) {
		unic_dev_stop(netdev);
		return 0;
	}

	if (netif_msg_ifdown(unic_dev))
		unic_info(unic_dev, "net stop.\n");

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	unic_dev_stop(netdev);
	unic_disable_channels(unic_dev);
	unic_clear_all_queue(netdev);
	unic_reset_tx_queue(netdev);

	return 0;
}

static void unic_fetch_stats_tx(struct rtnl_link_stats64 *stats,
				struct unic_channel *channel)
{
	unsigned int start;

	do {
		start = u64_stats_fetch_begin(&channel->sq->syncp);

		stats->tx_bytes += channel->sq->stats.bytes;
		stats->tx_packets += channel->sq->stats.packets;
		stats->tx_errors += channel->sq->stats.pad_err;
		stats->tx_errors += channel->sq->stats.over_max_sge_num;
		stats->tx_errors += channel->sq->stats.csum_err;
		stats->tx_errors += channel->sq->stats.vlan_err;
		stats->tx_errors += channel->sq->stats.fd_cnt;
		stats->tx_errors += channel->sq->stats.drop_cnt;
		stats->tx_errors += channel->sq->stats.cfg5_drop_cnt;

		stats->tx_dropped += channel->sq->stats.pad_err;
		stats->tx_dropped += channel->sq->stats.over_max_sge_num;
		stats->tx_dropped += channel->sq->stats.csum_err;
		stats->tx_dropped += channel->sq->stats.vlan_err;
		stats->tx_dropped += channel->sq->stats.fd_cnt;
		stats->tx_dropped += channel->sq->stats.drop_cnt;
		stats->tx_dropped += channel->sq->stats.cfg5_drop_cnt;
	} while (u64_stats_fetch_retry(&channel->sq->syncp, start));
}

static void unic_fetch_stats_rx(struct rtnl_link_stats64 *stats,
				struct unic_channel *channel)
{
	unsigned int start;

	do {
		start = u64_stats_fetch_begin(&channel->rq->syncp);

		stats->rx_bytes += channel->rq->stats.bytes;
		stats->rx_packets += channel->rq->stats.packets;
		stats->rx_crc_errors += channel->rq->stats.l2_err;
		stats->rx_errors += channel->rq->stats.l3_l4_csum_err;
		stats->rx_errors += channel->rq->stats.l2_err;
		stats->rx_length_errors += channel->rq->stats.err_pkt_len_cnt;

		stats->rx_dropped += channel->rq->stats.alloc_skb_err;
		stats->rx_dropped += channel->rq->stats.l2_err;
		stats->rx_dropped += channel->rq->stats.err_pkt_len_cnt;
		stats->rx_dropped += channel->rq->stats.trunc_cnt;
		stats->rx_dropped += channel->rq->stats.doi_cnt;
		stats->multicast += channel->rq->stats.multicast;
	} while (u64_stats_fetch_retry(&channel->rq->syncp, start));
}

static void unic_get_stats64(struct net_device *netdev,
			     struct rtnl_link_stats64 *stats)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u32 channel_num = unic_dev->channels.num;
	struct rtnl_link_stats64 total_stats;
	struct unic_channel *channel;
	u32 i;

	if (test_bit(UNIC_STATE_DOWN, &unic_dev->state))
		return;

	mutex_lock(&unic_dev->channels.mutex);
	if (!unic_dev->channels.c) {
		mutex_unlock(&unic_dev->channels.mutex);
		return;
	}

	memset(&total_stats, 0, sizeof(total_stats));
	for (i = 0; i < channel_num; i++) {
		channel = &unic_dev->channels.c[i];
		unic_fetch_stats_tx(&total_stats, channel);
		unic_fetch_stats_rx(&total_stats, channel);
	}

	mutex_unlock(&unic_dev->channels.mutex);

	stats->tx_bytes = total_stats.tx_bytes;
	stats->tx_packets = total_stats.tx_packets;
	stats->tx_errors = total_stats.tx_errors;
	stats->tx_dropped = total_stats.tx_dropped;
	stats->tx_fifo_errors = netdev->stats.tx_fifo_errors;
	stats->tx_compressed = netdev->stats.tx_compressed;
	stats->tx_aborted_errors = netdev->stats.tx_aborted_errors;
	stats->tx_carrier_errors = netdev->stats.tx_carrier_errors;
	stats->tx_heartbeat_errors = netdev->stats.tx_heartbeat_errors;
	stats->tx_window_errors = netdev->stats.tx_window_errors;
	stats->collisions = netdev->stats.collisions;

	stats->rx_bytes = total_stats.rx_bytes;
	stats->rx_packets = total_stats.rx_packets;
	stats->rx_errors = total_stats.rx_errors;
	stats->rx_dropped = total_stats.rx_dropped;
	stats->rx_length_errors = total_stats.rx_length_errors;
	stats->rx_crc_errors = total_stats.rx_crc_errors;
	stats->multicast = total_stats.multicast;
	stats->rx_missed_errors = netdev->stats.rx_missed_errors;
	stats->rx_over_errors = netdev->stats.rx_over_errors;
	stats->rx_frame_errors = netdev->stats.rx_frame_errors;
	stats->rx_fifo_errors = netdev->stats.rx_fifo_errors;
	stats->rx_compressed = netdev->stats.rx_compressed;
}

static int unic_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct unic_dev *unic_dev = (struct unic_dev *)netdev_priv(netdev);
	int ret;

	if (netif_running(netdev)) {
		unic_err(unic_dev,
			 "failed to change MTU, due to network interface is up, please down it first and try again.\n");
		return -EBUSY;
	}

	if (unic_resetting(netdev))
		return -EBUSY;

	if (netif_msg_ifdown(unic_dev))
		unic_info(unic_dev, "change mtu from %u to %d.\n",
			  netdev->mtu, new_mtu);

	ret = unic_set_mtu(unic_dev, new_mtu);
	if (ret) {
		unic_err(unic_dev, "failed to change MTU in hardware, ret = %d.\n",
			 ret);
		return ret;
	}

	netdev->mtu = (u32)new_mtu;

	return 0;
}

static int unic_set_mac_address(struct net_device *netdev, void *addr)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	char format_mac[UNIC_FORMAT_MAC_LEN];
	u8 unic_addr[UNIC_ADDR_LEN] = {0};
	struct sockaddr *mac_addr = addr;
	int ret;

	if (!unic_dev_cfg_mac_supported(unic_dev))
		return -EOPNOTSUPP;

	if (!mac_addr || !is_valid_ether_addr((const u8 *)mac_addr->sa_data)) {
		unic_err(unic_dev, "invalid user mac.\n");
		return -EADDRNOTAVAIL;
	}

	if (ether_addr_equal(netdev->dev_addr, mac_addr->sa_data)) {
		unic_comm_format_mac_addr(format_mac, mac_addr->sa_data);
		unic_info(unic_dev, "already using mac(%s).\n", format_mac);
		return 0;
	}

	ether_addr_copy(unic_addr, mac_addr->sa_data);
	ret = unic_cfg_mac_address(unic_dev, unic_addr);
	if (ret) {
		unic_err(unic_dev, "failed to set mac address, ret = %d.\n", ret);
		return ret;
	}

	dev_addr_set(netdev, unic_addr);
	ubase_set_dev_mac(unic_dev->comdev.adev, netdev->dev_addr,
			  netdev->addr_len);

	return ret;
}

static u8 unic_get_netdev_flags(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u8 flags = 0;

	if (netdev->flags & IFF_PROMISC) {
		if (unic_dev_ubl_supported(unic_dev))
			flags = UNIC_USER_UPE | UNIC_USER_MPE;
		else
			flags = UNIC_USER_UPE | UNIC_USER_MPE | UNIC_USER_BPE;
	} else if (netdev->flags & IFF_ALLMULTI) {
		flags = UNIC_USER_MPE;
	}

	return flags;
}

static void unic_set_rx_mode(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_vport *vport = &unic_dev->vport;
	u8 promisc_changed;
	u8 new_flags;

	new_flags = unic_get_netdev_flags(netdev);
	if (unic_dev_eth_mac_supported(unic_dev)) {
		__dev_uc_sync(netdev, unic_add_uc_mac, unic_del_uc_mac);
		__dev_mc_sync(netdev, unic_add_mc_mac, unic_del_mc_mac);
		promisc_changed = unic_dev->netdev_flags ^ new_flags;
		if (promisc_changed & UNIC_USER_UPE)
			set_bit(UNIC_VPORT_STATE_VLAN_FILTER_CHANGE,
				&vport->state);
	}

	unic_dev->netdev_flags = new_flags;

	set_bit(UNIC_VPORT_STATE_PROMISC_CHANGE, &vport->state);
}

static void unic_tx_timeout(struct net_device *netdev, u32 queue_idx)
{
	unic_dump_sq_stats(netdev, queue_idx);
}

static u8 unic_get_skb_dscp(struct sk_buff *skb)
{
#define UNIC_INVALID_DSCP	0xff
#define UNIC_DSCP_SHIFT		2

	__be16 protocol = skb->protocol;
	u8 dscp = UNIC_INVALID_DSCP;

	if (protocol == htons(ETH_P_8021Q))
		protocol = vlan_get_protocol(skb);

	if (protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> UNIC_DSCP_SHIFT;
	else if (protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> UNIC_DSCP_SHIFT;

	return dscp;
}

static u16 unic_select_queue(struct net_device *netdev, struct sk_buff *skb,
			     struct net_device *sb_dev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_vl *vl = &unic_dev->channels.vl;
	u8 dscp;

	if (!vl->dscp_app_cnt)
		goto out;

	dscp = unic_get_skb_dscp(skb);
	if (unlikely(dscp >= UBASE_MAX_DSCP))
		goto out;

	if (vl->dscp_prio[dscp] == UNIC_INVALID_PRIORITY)
		skb->priority = 0;
	else
		skb->priority = vl->dscp_prio[dscp];

out:
	return netdev_pick_tx(netdev, skb, sb_dev);
}

static int unic_vlan_rx_add_vid(struct net_device *netdev, __be16 proto,
				u16 vlan_id)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	return unic_set_vlan_table(unic_dev, proto, vlan_id, true);
}

static int unic_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto,
				 u16 vlan_id)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	return unic_set_vlan_table(unic_dev, proto, vlan_id, false);
}

static int unic_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	netdev_features_t changed = netdev->features ^ features;
	struct unic_dev *unic_dev = netdev_priv(netdev);
	bool enable;
	int ret;

	if (unic_dev_ubl_supported(unic_dev) ||
	    !unic_dev_cfg_vlan_filter_supported(unic_dev))
		return 0;

	if (changed & NETIF_F_HW_VLAN_CTAG_FILTER) {
		enable = !!(features & NETIF_F_HW_VLAN_CTAG_FILTER);
		ret = unic_set_vlan_filter(unic_dev, enable);
		if (ret)
			return ret;
	}

	return 0;
}

static const struct net_device_ops unic_netdev_ops = {
	.ndo_get_stats64 = unic_get_stats64,
	.ndo_start_xmit = unic_start_xmit,
	.ndo_tx_timeout = unic_tx_timeout,
	.ndo_change_mtu = unic_change_mtu,
	.ndo_open = unic_net_open,
	.ndo_stop = unic_net_stop,
	.ndo_set_mac_address = unic_set_mac_address,
	.ndo_set_rx_mode = unic_set_rx_mode,
	.ndo_select_queue = unic_select_queue,
	.ndo_vlan_rx_add_vid = unic_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = unic_vlan_rx_kill_vid,
	.ndo_set_features = unic_set_features,
};

void unic_set_netdev_ops(struct net_device *netdev)
{
	netdev->netdev_ops = &unic_netdev_ops;
}

static bool unic_port_dev_check(const struct net_device *dev)
{
	return dev->netdev_ops == &unic_netdev_ops;
}

static struct unic_dev *unic_get_bond_slave(struct net_device *ndev)
{
	struct slave *first_slave;
	struct unic_dev *unic_dev;
	struct bonding *bond;

	if (!netif_is_bond_master(ndev))
		return NULL;

	rcu_read_lock();
	bond = netdev_priv(ndev);
	first_slave = bond_first_slave_rcu(bond);
	if (!first_slave || !unic_port_dev_check(first_slave->dev)) {
		rcu_read_unlock();
		return NULL;
	}

	unic_dev = netdev_priv(first_slave->dev);
	rcu_read_unlock();

	return unic_dev;
}

static int unic_eth_ip_event(struct sockaddr *sa, struct net_device *ndev,
			     u16 ip_mask, unsigned long event)
{
	enum UNIC_COMM_ADDR_STATE state;
	struct unic_dev *unic_dev;
	int ret = NOTIFY_OK;

	unic_dev = unic_get_bond_slave(ndev);
	if (!unic_dev)
		return NOTIFY_DONE;

	if (!unic_bond_ip_sync_supported(unic_dev))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		state = UNIC_COMM_ADDR_TO_ADD;
		break;
	case NETDEV_DOWN:
		state = UNIC_COMM_ADDR_TO_DEL;
		break;
	default:
		return NOTIFY_DONE;
	}

	if (unic_update_bond_ipaddr(unic_dev, sa, ip_mask, state))
		ret = NOTIFY_BAD;

	return ret;
}

static int unic_ub_ip_event(struct sockaddr *sa, struct net_device *ndev,
			    u16 ip_mask, unsigned long event)
{
	struct unic_dev *unic_dev;
	int ret;

	if (!unic_port_dev_check(ndev))
		return NOTIFY_DONE;

	unic_dev = netdev_priv(ndev);
	if (__unic_removing(unic_dev))
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_UP:
		ret = unic_add_ip_addr(unic_dev, sa, ip_mask);
		if (ret)
			return NOTIFY_BAD;
		break;
	case NETDEV_DOWN:
		ret = unic_rm_ip_addr(unic_dev, sa, ip_mask);
		if (ret)
			return NOTIFY_BAD;
		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static int unic_ipaddr_event(struct notifier_block *nb, unsigned long event,
			     struct sockaddr *sa, struct net_device *ndev,
			     u16 ip_mask)
{
	if (ndev->type == ARPHRD_ETHER)
		return unic_eth_ip_event(sa, ndev, ip_mask, event);
	else if (ndev->type == ARPHRD_UB)
		return unic_ub_ip_event(sa, ndev, ip_mask, event);
	else
		return NOTIFY_DONE;
}

static int unic_inetaddr_event(struct notifier_block *nb, unsigned long event,
			       void *ptr)
{
	struct in_ifaddr *ifa4 = (struct in_ifaddr *)ptr;
	struct net_device *ndev = (struct net_device *)ifa4->ifa_dev->dev;
	u16 ip4_mask = (u16)ifa4->ifa_prefixlen;
	struct sockaddr_in in;

	in.sin_family = AF_INET;
	in.sin_addr.s_addr = ifa4->ifa_address;

	return unic_ipaddr_event(nb, event, (struct sockaddr *)&in, ndev,
				 ip4_mask);
}

static int unic_inet6addr_event(struct notifier_block *nb, unsigned long event,
				void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net_device *ndev = (struct net_device *)ifa6->idev->dev;
	u16 ip6_mask = (u16)ifa6->prefix_len;
	struct sockaddr_in6 in6;

	in6.sin6_family = AF_INET6;
	in6.sin6_addr = ifa6->addr;

	return unic_ipaddr_event(nb, event, (struct sockaddr *)&in6, ndev,
				 ip6_mask);
}

static struct notifier_block unic_inetaddr_notifier = {
	.notifier_call = unic_inetaddr_event
};

static struct notifier_block unic_inet6addr_notifier = {
	.notifier_call = unic_inet6addr_event
};

int unic_register_ipaddr_notifier(void)
{
	int ret;

	ret = register_inetaddr_notifier(&unic_inetaddr_notifier);
	if (ret)
		return ret;

	ret = register_inet6addr_notifier(&unic_inet6addr_notifier);
	if (ret)
		unregister_inetaddr_notifier(&unic_inetaddr_notifier);

	return ret;
}

void unic_unregister_ipaddr_notifier(void)
{
	unregister_inetaddr_notifier(&unic_inetaddr_notifier);
	unregister_inet6addr_notifier(&unic_inet6addr_notifier);
}

static int unic_netdev_event(struct notifier_block *nb,
			     unsigned long event, void *ptr)
{
	struct net_device *netdev;
	struct unic_dev *unic_dev;

	netdev = netdev_notifier_info_to_dev(ptr);
	if (!netdev || !unic_port_dev_check(netdev))
		return NOTIFY_DONE;

	unic_dev = netdev_priv(netdev);

	if (!unic_dev_eth_mac_supported(unic_dev) || event != NETDEV_CHANGEUPPER)
		return NOTIFY_DONE;

	set_bit(UNIC_STATE_SYNC_BOND_PORT, &unic_dev->state);

	return NOTIFY_OK;
}

static struct notifier_block unic_netdev_notifier = {
	.notifier_call = unic_netdev_event,
};

int unic_register_netdevice_notifier(void)
{
	return register_netdevice_notifier(&unic_netdev_notifier);
}

void unic_unregister_netdevice_notifier(void)
{
	unregister_netdevice_notifier(&unic_netdev_notifier);
}

int unic_query_link_status(struct unic_dev *unic_dev, u8 *link_status)
{
	struct unic_link_status_cmd_resp resp = {0};
	struct ubase_cmd_buf out;
	struct ubase_cmd_buf in;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_LINK_STATUS, true, 0, NULL);

	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_LINK_STATUS, false,
			     sizeof(resp), &resp);

	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret) {
		unic_err(unic_dev,
			 "failed to get mac link status, ret = %d.\n", ret);
		return ret;
	}

	*link_status = (resp.status & UNIC_LINK_STATUS_UP_M) > 0 ?
		       UNIC_LINK_STATUS_UP : UNIC_LINK_STATUS_DOWN;

	return 0;
}
