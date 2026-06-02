// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/phy.h>
#include <ub/ubase/ubase_comm_cmd.h>

#include "unic.h"
#include "unic_cmd.h"
#include "unic_dev.h"
#include "unic_hw.h"
#include "unic_netdev.h"
#include "unic_lb.h"

#define UNIC_LB_TEST_CHANNEL_ID		0
#define UNIC_LB_TEST_PKT_NUM		1
#define UNIC_LB_TEST_UNEXECUTED		1
#define UNIC_LB_TEST_PACKET_SIZE	128

#define UNIC_SW_TYPE_LEN		1
#define UNIC_HEX			16
#define UNIC_DHCPV4_PROTO		0x0100

static void unic_set_selftest_param(struct unic_dev *unic_dev, bool *st_param)
{
	st_param[UNIC_LB_APP] = unic_dev_app_lb_supported(unic_dev);
	st_param[UNIC_LB_SERIAL_SERDES] =
			unic_dev_serial_serdes_lb_supported(unic_dev);
	st_param[UNIC_LB_PARALLEL_SERDES] =
			unic_dev_parallel_serdes_lb_supported(unic_dev);
	st_param[UNIC_LB_EXTERNAL] =
			unic_dev_external_lb_supported(unic_dev);
}

static int unic_set_lb_mode(struct unic_dev *unic_dev, bool en, int loop_type)
{
	struct unic_lb_en_cfg req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.lb_en = en ? 1 : 0;
	req.sub_cmd = loop_type;

	ubase_fill_inout_buf(&in, UBASE_OPC_DL_CONFIG_LB, false, sizeof(req),
			     &req);

	ret = ubase_cmd_send_in(unic_dev->comdev.adev, &in);
	if (ret)
		unic_err(unic_dev,
			 "failed to config loopback mode, ret = %d, loop_type = %d.\n",
			 ret, loop_type);

	return ret;
}

static int unic_lb_link_status_wait(struct unic_dev *unic_dev, bool en)
{
#define UNIC_LINK_STATUS_MS		100
#define UNIC_MAC_LINK_STATUS_NUM	100

	u8 link_status = UNIC_LINK_STATUS_DOWN;
	u8 link_ret;
	int i = 0;
	int ret;

	link_ret = en ? UNIC_LINK_STATUS_UP : UNIC_LINK_STATUS_DOWN;

	do {
		ret = unic_query_link_status(unic_dev, &link_status);
		if (ret)
			return ret;
		if (link_status == link_ret)
			return 0;

		msleep(UNIC_LINK_STATUS_MS);
	} while (++i < UNIC_MAC_LINK_STATUS_NUM);

	unic_warn(unic_dev, "query mac link status timeout, en = %d.\n", en);
	return -EBUSY;
}

static int unic_enable_serdes_lb(struct unic_dev *unic_dev, int loop_type)
{
	int ret;

	ret = unic_mac_cfg(unic_dev, true);
	if (ret)
		return ret;

	ret = unic_set_lb_mode(unic_dev, true, loop_type);
	if (ret)
		return ret;

	return unic_lb_link_status_wait(unic_dev, true);
}

static int unic_disable_serdes_lb(struct unic_dev *unic_dev, int loop_type)
{
	int ret;

	ret = unic_set_lb_mode(unic_dev, false, loop_type);
	if (ret)
		return ret;

	ret = unic_mac_cfg(unic_dev, false);
	if (ret)
		return ret;

	return unic_lb_link_status_wait(unic_dev, false);
}

static int unic_set_serdes_lb(struct unic_dev *unic_dev, bool en, int loop_type)
{
	if (!unic_dev_parallel_serdes_lb_supported(unic_dev))
		return -EOPNOTSUPP;

	return en ? unic_enable_serdes_lb(unic_dev, loop_type) :
		    unic_disable_serdes_lb(unic_dev, loop_type);
}

static int unic_set_app_lb(struct unic_dev *unic_dev, bool en)
{
	int ret;

	if (!unic_dev_app_lb_supported(unic_dev))
		return -EOPNOTSUPP;

	ret = unic_mac_cfg(unic_dev, en);
	if (ret)
		return ret;

	return unic_lb_link_status_wait(unic_dev, en);
}

static int unic_lb_config(struct net_device *ndev, int loop_type, bool en)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct unic_vport *vport = &unic_dev->vport;
	struct unic_promisc_en promisc_all_en = {0};
	struct unic_promisc_en promisc_en = {0};
	int ret = 0;

	unic_fill_promisc_en(&promisc_en,
			     unic_dev->netdev_flags | vport->last_promisc_flags);
	memset(&promisc_all_en, 1, sizeof(promisc_all_en));

	switch (loop_type) {
	case UNIC_LB_APP:
		ret = unic_set_app_lb(unic_dev, en);
		break;
	case UNIC_LB_SERIAL_SERDES:
	case UNIC_LB_PARALLEL_SERDES:
		ret = unic_set_serdes_lb(unic_dev, en, loop_type);
		break;
	case UNIC_LB_EXTERNAL:
		break;
	default:
		unic_info(unic_dev,
			  "loop_type is not supported, loop_type = %d.\n",
			  loop_type);
		return -EOPNOTSUPP;
	}

	if (ret && ret != -EOPNOTSUPP)
		unic_err(unic_dev,
			 "loopback_config return error, ret = %d, enable = %d.\n",
			 ret, en);

	unic_set_promisc_mode(unic_dev, en ? &promisc_all_en : &promisc_en);

	return ret;
}

static int unic_selftest_prepare(struct net_device *ndev, bool if_running,
				 u8 autoneg)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	int ret;

	ret = if_running ? unic_net_stop(ndev) : 0;
	if (ret) {
		unic_err(unic_dev, "failed to stop net, ret = %d.\n", ret);
		return ret;
	}

	ret = autoneg ? unic_set_mac_autoneg(unic_dev, false) : 0;
	if (ret) {
		unic_err(unic_dev, "failed to set mac autoneg, ret = %d.\n", ret);
		goto restore_net;
	}

	set_bit(UNIC_STATE_TESTING, &unic_dev->state);

	return 0;

restore_net:
	ret = if_running ? unic_net_open(ndev) : 0;
	if (ret)
		unic_err(unic_dev, "failed to restore net, ret = %d.\n", ret);

	return ret;
}

static void unic_eth_lb_check_skb_data(struct unic_channel *c,
				       struct sk_buff *skb)
{
	struct unic_dev *unic_dev = netdev_priv(skb->dev);
	struct net_device *ndev = skb->dev;
	struct unic_rq *rq = c->rq;
	u32 len = skb_headlen(skb);
	u8 *packet = skb->data;
	struct ethhdr *ethh;
	u32 i;

	if (ZERO_OR_NULL_PTR(packet)) {
		unic_err(unic_dev, "eth packet content is null.\n");
		goto out;
	}

	if (len != UNIC_LB_TEST_PACKET_SIZE) {
		unic_err(unic_dev,
			 "eth test packet size error, len = %u.\n", len);
		goto out;
	}

	ethh = (struct ethhdr *)(skb->data - ETH_HLEN);
	if (memcmp(ethh->h_dest, ndev->dev_addr, ETH_ALEN) ||
	    memcmp(ethh->h_source, ndev->dev_addr, ETH_ALEN) ||
	    ethh->h_proto != htons(ETH_P_ARP)) {
		unic_err(unic_dev, "eth segment error.\n");
		goto out;
	}

	for (i = 0; i < len; i++) {
		if (packet[i] != i) {
			unic_err(unic_dev,
				 "eth packet content error, i = %u.\n", i);
			goto out;
		}
	}

	dev_kfree_skb_any(skb);
	return;
out:
	/* Due to the fact that incorrect packet content in the poll rx process
	 * can also increase packet and byte counts, the statistics should be
	 * subtracted when counting if the packets are incorrect.
	 */
	u64_stats_update_begin(&rq->syncp);
	rq->stats.packets--;
	rq->stats.bytes -= skb->len;
	u64_stats_update_end(&rq->syncp);
	print_hex_dump(KERN_ERR, "eth selftest:", DUMP_PREFIX_OFFSET,
		       UNIC_HEX, 1, skb->data, len, true);
	dev_kfree_skb_any(skb);
}

static u32 unic_lb_check_rx(struct unic_dev *unic_dev, u32 budget,
			    struct sk_buff *skb)
{
	struct unic_channel *c;
	u64 pre_pkt, pre_byte;
	u32 pkt_total = 0;
	u32 i;

	for (i = 0; i < unic_dev->channels.num; i++) {
		c = &unic_dev->channels.c[i];
		pre_pkt = c->rq->stats.packets;
		pre_byte = c->rq->stats.bytes;

		preempt_disable();
		unic_poll_rx(c, budget, unic_eth_lb_check_skb_data);
		preempt_enable();

		pkt_total += (c->rq->stats.packets - pre_pkt);
		c->rq->stats.packets = pre_pkt;
		c->rq->stats.bytes = pre_byte;
	}
	return pkt_total;
}

static void unic_eth_lb_setup_skb(struct sk_buff *skb)
{
	struct net_device *ndev = skb->dev;
	struct ethhdr *ethh;
	u8 *packet;
	u8 i;

	skb_reserve(skb, NET_IP_ALIGN);
	ethh = skb_put(skb, sizeof(struct ethhdr));
	packet = skb_put(skb, UNIC_LB_TEST_PACKET_SIZE);

	ether_addr_copy(ethh->h_dest, ndev->dev_addr);
	ether_addr_copy(ethh->h_source, ndev->dev_addr);

	ethh->h_proto = htons(ETH_P_ARP);

	for (i = 0; i < UNIC_LB_TEST_PACKET_SIZE; i++)
		packet[i] = i;
}

static struct sk_buff *unic_lb_skb_prepare(struct net_device *ndev)
{
	u32 size = UNIC_LB_TEST_PACKET_SIZE + ETH_HLEN + NET_IP_ALIGN;
	struct sk_buff *skb;

	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb)
		return NULL;

	skb->dev = ndev;
	skb->queue_mapping = UNIC_LB_TEST_CHANNEL_ID;

	unic_eth_lb_setup_skb(skb);

	return skb;
}

static void unic_lb_poll_tx(struct unic_dev *unic_dev, struct sk_buff *skb)
{
	u64 pre_pkt, pre_byte;
	struct unic_sq *sq;

	sq = unic_dev->channels.c[skb->queue_mapping].sq;

	pre_pkt = sq->stats.packets;
	pre_byte = sq->stats.bytes;

	unic_poll_tx(sq, 0);
	if (sq->pi != sq->ci) {
		unic_err(unic_dev, "cqe error, sp pi doesn't match sp ci.\n");
		kfree_skb(skb);
	}

	sq->stats.packets = pre_pkt;
	sq->stats.bytes = pre_byte;
}

static int unic_lb_run_test(struct net_device *ndev, int loop_mode)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct sk_buff *skb;
	netdev_tx_t tx_ret;
	int ret_val = 0;
	u32 i, cnt = 0;

	/* Avoid loopback failure caused by receiving packets after mac_en
	 * takes effect but before loopback_en takes effect.
	 */
	for (i = 0; i < unic_dev->channels.num; i++)
		unic_clear_rq(unic_dev->channels.c[i].rq);

	skb = unic_lb_skb_prepare(ndev);
	if (!skb) {
		unic_err(unic_dev, "failed to alloc skb.\n");
		return -ENOMEM;
	}

	/* Used to handle the release of skb in different situations of xmit.
	 * 1. When the chip reports cqe normally, skb is released through
	 *    kfree_skb and napi_consume_skb in success situation.
	 * 2. When the chip reports cqe abnormally, pi and ci are not equal,
	 *    skb is released through kfree_skb twice in success situation.
	 * 3. In dropped situation, pi and ci are equal, skb is released through
	 *    kfree_skb and dev_kfree_skb_any.
	 * 4. In busy situation, skb is released through kfree_skb twice.
	 */
	skb_get(skb);

	tx_ret = unic_start_xmit(skb, ndev);
	if (tx_ret == NETDEV_TX_OK) {
		cnt++;
	} else {
		kfree_skb(skb);
		unic_err(unic_dev, "failed to xmit loopback skb, ret = %d.\n",
			 tx_ret);
	}

	if (cnt != UNIC_LB_TEST_PKT_NUM) {
		ret_val = -EBUSY;
		unic_err(unic_dev, "mode %d sent fail, cnt = %u, budget = %d.\n",
			 loop_mode, cnt, UNIC_LB_TEST_PKT_NUM);
		goto out;
	}

	/* Allow 200 milliseconds for packets to go from Tx to Rx */
	msleep(200);

	cnt = unic_lb_check_rx(unic_dev, UNIC_LB_TEST_PKT_NUM, skb);
	if (cnt != UNIC_LB_TEST_PKT_NUM) {
		ret_val = -EINVAL;
		unic_err(unic_dev, "mode %d recv fail, cnt = %u, budget = %d.\n",
			 loop_mode, cnt, UNIC_LB_TEST_PKT_NUM);
	}

out:
	unic_lb_poll_tx(unic_dev, skb);
	kfree_skb(skb);
	return ret_val;
}

static void unic_external_selftest_prepare(struct net_device *ndev)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (test_and_set_bit(UNIC_STATE_DOWN, &unic_dev->state))
		return;

	netif_carrier_off(ndev);
	netif_tx_disable(ndev);

	unic_disable_channels(unic_dev);

	unic_clear_all_queue(ndev);

	unic_reset_tx_queue(ndev);
}

static void unic_do_external_selftest(struct net_device *ndev,
				      struct ethtool_test *eth_test, u64 *data)
{
	data[UNIC_LB_EXTERNAL] = unic_lb_config(ndev, UNIC_LB_EXTERNAL, true);
	if (!data[UNIC_LB_EXTERNAL])
		data[UNIC_LB_EXTERNAL] = unic_lb_run_test(ndev, UNIC_LB_EXTERNAL);

	unic_lb_config(ndev, UNIC_LB_EXTERNAL, false);

	if (data[UNIC_LB_EXTERNAL])
		eth_test->flags |= ETH_TEST_FL_FAILED;

	eth_test->flags |= ETH_TEST_FL_EXTERNAL_LB_DONE;
}

static void unic_external_selftest_restore(struct net_device *ndev)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (unic_is_initing_or_resetting(unic_dev))
		return;

	if (!test_bit(UNIC_STATE_DOWN, &unic_dev->state))
		return;

	unic_clear_all_queue(ndev);

	unic_enable_channels(unic_dev);

	netif_tx_wake_all_queues(ndev);

	clear_bit(UNIC_STATE_DOWN, &unic_dev->state);
}

static void unic_do_selftest(struct net_device *ndev, bool *st_param,
			     struct ethtool_test *eth_test, u64 *data)
{
	int lb_type;

	for (lb_type = UNIC_LB_APP; lb_type < UNIC_LB_EXTERNAL; lb_type++) {
		if (!st_param[lb_type])
			continue;

		data[lb_type] = unic_lb_config(ndev, lb_type, true);
		if (!data[lb_type])
			data[lb_type] = unic_lb_run_test(ndev, lb_type);

		unic_lb_config(ndev, lb_type, false);

		if (data[lb_type])
			eth_test->flags |= ETH_TEST_FL_FAILED;
	}
}

static void unic_selftest_restore(struct net_device *ndev, bool if_running,
				  u8 autoneg)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	int ret;

	clear_bit(UNIC_STATE_TESTING, &unic_dev->state);

	ret = autoneg ? unic_set_mac_autoneg(unic_dev, true) : 0;
	if (ret)
		unic_err(unic_dev, "failed to restore mac autoneg, ret = %d.\n",
			 ret);

	ret = if_running ? unic_net_open(ndev) : 0;
	if (ret)
		unic_err(unic_dev, "failed to restore unic ndev, ret = %d.\n",
			 ret);
}

static bool unic_self_test_is_unexecuted(struct net_device *ndev,
					 struct ethtool_test *eth_test,
					 u64 *data)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (test_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state)) {
		unic_err(unic_dev,
			 "failed to self test, due to dev deactivate.\n");
		return true;
	}

	if (unic_is_initing_or_resetting(unic_dev) || !unic_dev->channels.c) {
		unic_err(unic_dev,
			 "failed to self test, due to dev initing or resetting.\n");
		return true;
	}

	if (!(eth_test->flags & ETH_TEST_FL_OFFLINE)) {
		unic_err(unic_dev,
			 "failed to self test, due to disable test flags.\n");
		return true;
	}

	if (unic_dev_external_lb_supported(unic_dev))
		data[UNIC_LB_EXTERNAL] = UNIC_LB_TEST_UNEXECUTED;

	return false;
}

int unic_get_selftest_count(struct unic_dev *unic_dev)
{
	int count = 0;

	if (unic_dev_app_lb_supported(unic_dev))
		count++;

	if (unic_dev_serial_serdes_lb_supported(unic_dev))
		count++;

	if (unic_dev_parallel_serdes_lb_supported(unic_dev))
		count++;

	if (unic_dev_external_lb_supported(unic_dev))
		count++;

	return count == 0 ? -EOPNOTSUPP : UNIC_LB_MAX;
}

static bool unic_external_selftest_is_executed(struct net_device *ndev, bool *st_param,
					       struct ethtool_test *eth_test, bool if_running)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (!(eth_test->flags & ETH_TEST_FL_EXTERNAL_LB))
		return false;

	if (!if_running || !netif_carrier_ok(ndev)) {
		unic_warn(unic_dev,
			  "not to run external selftest, due to link down.\n");
		return false;
	}

	if (!st_param[UNIC_LB_EXTERNAL]) {
		unic_warn(unic_dev,
			  "not to run external selftest, due to not support.\n");
		return false;
	}

	return true;
}

void unic_self_test(struct net_device *ndev,
		    struct ethtool_test *eth_test, u64 *data)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct unic_mac *mac = &unic_dev->hw.mac;
	bool if_running = netif_running(ndev);
	bool st_param[UNIC_LB_MAX];
	int ret, i;

	ret = unic_get_selftest_count(unic_dev);
	if (ret == -EOPNOTSUPP) {
		eth_test->flags |= ETH_TEST_FL_FAILED;
		return;
	}

	/* initialize the loopback test result, avoiding mark not support loopback
	 * test as PASS.
	 */
	for (i = 0; i < UNIC_LB_MAX; i++)
		data[i] = -EOPNOTSUPP;

	if (unic_self_test_is_unexecuted(ndev, eth_test, data)) {
		eth_test->flags |= ETH_TEST_FL_FAILED;
		return;
	}

	unic_set_selftest_param(unic_dev, st_param);

	if (unic_external_selftest_is_executed(ndev, st_param, eth_test, if_running)) {
		unic_external_selftest_prepare(ndev);
		unic_do_external_selftest(ndev, eth_test, data);
		unic_external_selftest_restore(ndev);
	}

	ret = unic_selftest_prepare(ndev, if_running, mac->autoneg);
	if (ret)
		return;

	unic_do_selftest(ndev, st_param, eth_test, data);
	unic_selftest_restore(ndev, if_running, mac->autoneg);
}
