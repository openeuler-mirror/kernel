/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_port_stats.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/if_vlan.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#include "ossl_knl.h"
#include "nic_pub_cmd.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_mag_cfg.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_xdp.h"
#include "hinic5_ethtool_port_stats.h"

#define HINIC5_NETDEV_STAT(_stat_item) { \
	.name = #_stat_item, \
	.size = FIELD_SIZEOF(struct rtnl_link_stats64, _stat_item), \
	.offset = offsetof(struct rtnl_link_stats64, _stat_item) \
}

static struct hinic5_stats hinic5_netdev_stats[] = {
	HINIC5_NETDEV_STAT(rx_packets),
	HINIC5_NETDEV_STAT(tx_packets),
	HINIC5_NETDEV_STAT(rx_bytes),
	HINIC5_NETDEV_STAT(tx_bytes),
	HINIC5_NETDEV_STAT(rx_errors),
	HINIC5_NETDEV_STAT(tx_errors),
	HINIC5_NETDEV_STAT(rx_dropped),
	HINIC5_NETDEV_STAT(tx_dropped),
	HINIC5_NETDEV_STAT(multicast),
	HINIC5_NETDEV_STAT(collisions),
	HINIC5_NETDEV_STAT(rx_length_errors),
	HINIC5_NETDEV_STAT(rx_over_errors),
	HINIC5_NETDEV_STAT(rx_crc_errors),
	HINIC5_NETDEV_STAT(rx_frame_errors),
	HINIC5_NETDEV_STAT(rx_fifo_errors),
	HINIC5_NETDEV_STAT(rx_missed_errors),
	HINIC5_NETDEV_STAT(tx_aborted_errors),
	HINIC5_NETDEV_STAT(tx_carrier_errors),
	HINIC5_NETDEV_STAT(tx_fifo_errors),
	HINIC5_NETDEV_STAT(tx_heartbeat_errors),
};

static struct hinic5_stats hinic5_port_link_stat[] = {
	HINIC5_PORT_LINK_STAT(link_down_events_phy),
};

static struct hinic5_stats hinic5_nic_dev_stats[] = {
	HINIC5_NIC_STAT(netdev_tx_timeout),
};

static struct hinic5_stats hinic5_nic_dev_stats_extern[] = {
	HINIC5_NIC_STAT(tx_carrier_off_drop),
	HINIC5_NIC_STAT(tx_invalid_qid),
	HINIC5_NIC_STAT(rsvd1),
	HINIC5_NIC_STAT(rsvd2),
};

static struct hinic5_stats hinic5_rx_queue_stats[] = {
	HINIC5_RXQ_STAT(packets),
	HINIC5_RXQ_STAT(bytes),
	HINIC5_RXQ_STAT(errors),
	HINIC5_RXQ_STAT(csum_errors),
	HINIC5_RXQ_STAT(other_errors),
	HINIC5_RXQ_STAT(dropped),
#ifdef HAVE_XDP_SUPPORT
	HINIC5_RXQ_STAT(xdp_dropped),
	HINIC5_RXQ_STAT(xdp_redirected),
#endif
	HINIC5_RXQ_STAT(rx_buf_empty),
};

static struct hinic5_stats hinic5_rx_queue_stats_extern[] = {
	HINIC5_RXQ_STAT(alloc_skb_err),
	HINIC5_RXQ_STAT(alloc_rx_buf_err),
#ifdef HAVE_XDP_SUPPORT
	HINIC5_RXQ_STAT(xdp_large_pkt),
#endif
	HINIC5_RXQ_STAT(restore_drop_sge),
	HINIC5_RXQ_STAT(pkt_mc),
};

static struct hinic5_stats hinic5_tx_queue_stats[] = {
	HINIC5_TXQ_STAT(packets),
	HINIC5_TXQ_STAT(bytes),
	HINIC5_TXQ_STAT(busy),
	HINIC5_TXQ_STAT(wake),
	HINIC5_TXQ_STAT(dropped),
	HINIC5_TXQ_STAT(unfinished),
};

#ifdef HAVE_XDP_SUPPORT
static struct hinic5_stats hinic5_xdp_tx_queue_stats[] = {
	HINIC5_XDPTXQ_STAT(xdp_dropped),
	HINIC5_XDPTXQ_STAT(xdp_xmits),
};
#endif

static struct hinic5_stats hinic5_tx_queue_stats_extern[] = {
	HINIC5_TXQ_STAT(skb_pad_err),
	HINIC5_TXQ_STAT(frag_len_overflow),
	HINIC5_TXQ_STAT(offload_cow_skb_err),
	HINIC5_TXQ_STAT(map_frag_err),
	HINIC5_TXQ_STAT(unknown_tunnel_pkt),
	HINIC5_TXQ_STAT(frag_size_err),
	HINIC5_TXQ_STAT(rsvd1),
	HINIC5_TXQ_STAT(rsvd2),
};

static struct hinic5_stats hinic5_function_stats[] = {
	HINIC5_FUNC_STAT(tx_unicast_pkts_vport),
	HINIC5_FUNC_STAT(tx_unicast_bytes_vport),
	HINIC5_FUNC_STAT(tx_multicast_pkts_vport),
	HINIC5_FUNC_STAT(tx_multicast_bytes_vport),
	HINIC5_FUNC_STAT(tx_broadcast_pkts_vport),
	HINIC5_FUNC_STAT(tx_broadcast_bytes_vport),

	HINIC5_FUNC_STAT(rx_unicast_pkts_vport),
	HINIC5_FUNC_STAT(rx_unicast_bytes_vport),
	HINIC5_FUNC_STAT(rx_multicast_pkts_vport),
	HINIC5_FUNC_STAT(rx_multicast_bytes_vport),
	HINIC5_FUNC_STAT(rx_broadcast_pkts_vport),
	HINIC5_FUNC_STAT(rx_broadcast_bytes_vport),

	HINIC5_FUNC_STAT(tx_discard_vport),
	HINIC5_FUNC_STAT(rx_discard_vport),
	HINIC5_FUNC_STAT(tx_err_vport),
	HINIC5_FUNC_STAT(rx_err_vport),
};

static struct hinic5_stats hinic5_port_stats[] = {
	HINIC5_PORT_STAT(mac_tx_fragment_pkt_num),
	HINIC5_PORT_STAT(mac_tx_undersize_pkt_num),
	HINIC5_PORT_STAT(mac_tx_undermin_pkt_num),
	HINIC5_PORT_STAT(mac_tx_64_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_65_127_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_128_255_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_256_511_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_512_1023_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_1024_1518_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_1519_2047_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_2048_4095_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_4096_8191_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_8192_9216_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_9217_12287_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_12288_16383_oct_pkt_num),
	HINIC5_PORT_STAT(mac_tx_1519_max_bad_pkt_num),
	HINIC5_PORT_STAT(mac_tx_1519_max_good_pkt_num),
	HINIC5_PORT_STAT(mac_tx_oversize_pkt_num),
	HINIC5_PORT_STAT(mac_tx_jabber_pkt_num),
	HINIC5_PORT_STAT(mac_tx_bad_pkt_num),
	HINIC5_PORT_STAT(mac_tx_bad_oct_num),
	HINIC5_PORT_STAT(mac_tx_good_pkt_num),
	HINIC5_PORT_STAT(mac_tx_good_oct_num),
	HINIC5_PORT_STAT(mac_tx_total_pkt_num),
	HINIC5_PORT_STAT(mac_tx_total_oct_num),
	HINIC5_PORT_STAT(mac_tx_uni_pkt_num),
	HINIC5_PORT_STAT(mac_tx_multi_pkt_num),
	HINIC5_PORT_STAT(mac_tx_broad_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pause_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri0_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri1_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri2_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri3_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri4_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri5_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri6_pkt_num),
	HINIC5_PORT_STAT(mac_tx_pfc_pri7_pkt_num),
	HINIC5_PORT_STAT(mac_tx_control_pkt_num),
	HINIC5_PORT_STAT(mac_tx_err_all_pkt_num),
	HINIC5_PORT_STAT(mac_tx_from_app_good_pkt_num),
	HINIC5_PORT_STAT(mac_tx_from_app_bad_pkt_num),

	HINIC5_PORT_STAT(mac_rx_fragment_pkt_num),
	HINIC5_PORT_STAT(mac_rx_undersize_pkt_num),
	HINIC5_PORT_STAT(mac_rx_undermin_pkt_num),
	HINIC5_PORT_STAT(mac_rx_64_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_65_127_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_128_255_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_256_511_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_512_1023_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_1024_1518_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_1519_2047_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_2048_4095_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_4096_8191_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_8192_9216_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_9217_12287_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_12288_16383_oct_pkt_num),
	HINIC5_PORT_STAT(mac_rx_1519_max_bad_pkt_num),
	HINIC5_PORT_STAT(mac_rx_1519_max_good_pkt_num),
	HINIC5_PORT_STAT(mac_rx_oversize_pkt_num),
	HINIC5_PORT_STAT(mac_rx_jabber_pkt_num),
	HINIC5_PORT_STAT(mac_rx_bad_pkt_num),
	HINIC5_PORT_STAT(mac_rx_bad_oct_num),
	HINIC5_PORT_STAT(mac_rx_good_pkt_num),
	HINIC5_PORT_STAT(mac_rx_good_oct_num),
	HINIC5_PORT_STAT(mac_rx_total_pkt_num),
	HINIC5_PORT_STAT(mac_rx_total_oct_num),
	HINIC5_PORT_STAT(mac_rx_uni_pkt_num),
	HINIC5_PORT_STAT(mac_rx_multi_pkt_num),
	HINIC5_PORT_STAT(mac_rx_broad_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pause_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri0_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri1_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri2_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri3_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri4_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri5_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri6_pkt_num),
	HINIC5_PORT_STAT(mac_rx_pfc_pri7_pkt_num),
	HINIC5_PORT_STAT(mac_rx_control_pkt_num),
	HINIC5_PORT_STAT(mac_rx_sym_err_pkt_num),
	HINIC5_PORT_STAT(mac_rx_fcs_err_pkt_num),
	HINIC5_PORT_STAT(mac_rx_send_app_good_pkt_num),
	HINIC5_PORT_STAT(mac_rx_send_app_bad_pkt_num),
	HINIC5_PORT_STAT(mac_rx_unfilter_pkt_num),
};

static char g_hinic_priv_flags_strings[][ETH_GSTRING_LEN] = {
	"Symmetric-RSS",
	"Force-Link-up",
	"Rxq_Recovery",
};

u32 hinic5_get_io_stats_size(const struct hinic5_nic_dev *nic_dev)
{
	u32 count;

	count = (u32)(ARRAY_LEN(hinic5_nic_dev_stats) +
		ARRAY_LEN(hinic5_nic_dev_stats_extern) +
		(ARRAY_LEN(hinic5_tx_queue_stats) +
		ARRAY_LEN(hinic5_tx_queue_stats_extern) +
		ARRAY_LEN(hinic5_rx_queue_stats) +
		ARRAY_LEN(hinic5_rx_queue_stats_extern)) * nic_dev->max_qps);

	return count;
}

#define GET_VALUE_OF_PTR(size, ptr) (				\
	(size) == sizeof(u64) ? *(u64 *)(ptr) :			\
	(size) == sizeof(u32) ? *(u32 *)(ptr) :			\
	(size) == sizeof(u16) ? *(u16 *)(ptr) : *(u8 *)(ptr)	\
)

#define DEV_STATS_PACK(items, item_idx, array, stats_ptr) do {		\
	int j;								\
	for (j = 0; j < ARRAY_LEN(array); j++) {			\
		memcpy((items)[item_idx].name, (array)[j].name,		\
		       HINIC5_SHOW_ITEM_LEN);				\
		(items)[item_idx].hexadecimal = 0;			\
		(items)[item_idx].value =				\
			GET_VALUE_OF_PTR((array)[j].size,		\
			(char *)(stats_ptr) + (array)[j].offset);	\
		(item_idx)++;						\
	}								\
} while (0)

int hinic5_rx_queue_stat_pack(struct hinic5_show_item *item,
			      struct hinic5_stats *stat,
			      const struct hinic5_rxq_stats *rxq_stats, u16 qid)
{
	int ret;

	ret = snprintf(item->name, HINIC5_SHOW_ITEM_LEN, stat->name, qid);
	if (ret < 0)
		return -EINVAL;

	item->hexadecimal = 0;
	item->value = GET_VALUE_OF_PTR(stat->size, (char *)(rxq_stats) + stat->offset);

	return 0;
}

int hinic5_tx_queue_stat_pack(struct hinic5_show_item *item,
			      struct hinic5_stats *stat,
			      const struct hinic5_txq_stats *txq_stats, u16 qid)
{
	int ret;

	ret = snprintf(item->name, HINIC5_SHOW_ITEM_LEN, stat->name, qid);
	if (ret < 0)
		return -EINVAL;

	item->hexadecimal = 0;
	item->value = GET_VALUE_OF_PTR(stat->size, (char *)(txq_stats) + stat->offset);

	return 0;
}

int hinic5_get_io_stats(const struct hinic5_nic_dev *nic_dev, void *stats)
{
	struct hinic5_show_item *items = stats;
	int item_idx = 0;
	u16 qid;
	int idx;
	int ret;

	DEV_STATS_PACK(items, item_idx, hinic5_nic_dev_stats, &nic_dev->stats);
	DEV_STATS_PACK(items, item_idx, hinic5_nic_dev_stats_extern, &nic_dev->stats);

	for (qid = 0; qid < nic_dev->max_qps; qid++) {
		for (idx = 0; idx < ARRAY_LEN(hinic5_tx_queue_stats); idx++) {
			ret = hinic5_tx_queue_stat_pack(&items[item_idx++],
							&hinic5_tx_queue_stats[idx],
							&nic_dev->txqs[qid].txq_stats, qid);
			if (ret != 0)
				return -EINVAL;
	}

	for (idx = 0; idx < ARRAY_LEN(hinic5_tx_queue_stats_extern); idx++) {
		ret = hinic5_tx_queue_stat_pack(&items[item_idx++],
						&hinic5_tx_queue_stats_extern[idx],
						&nic_dev->txqs[qid].txq_stats, qid);
		if (ret != 0)
			return -EINVAL;
		}
	}

	for (qid = 0; qid < nic_dev->max_qps; qid++) {
		for (idx = 0; idx < ARRAY_LEN(hinic5_rx_queue_stats); idx++) {
			ret = hinic5_rx_queue_stat_pack(&items[item_idx++],
							&hinic5_rx_queue_stats[idx],
							&nic_dev->rxqs[qid].rxq_stats, qid);
			if (ret != 0)
				return -EINVAL;
		}

		for (idx = 0; idx < ARRAY_LEN(hinic5_rx_queue_stats_extern); idx++) {
			ret = hinic5_rx_queue_stat_pack(&items[item_idx++],
							&hinic5_rx_queue_stats_extern[idx],
							&nic_dev->rxqs[qid].rxq_stats, qid);
			if (ret != 0)
				return -EINVAL;
		}
	}

	return 0;
}

static char g_hinic5_test_strings[][ETH_GSTRING_LEN] = {
	"Internal lb test  (on/offline)",
	"External lb test (external_lb)",
};

int hinic5_get_sset_count(struct net_device *netdev, int sset)
{
	int count = 0, q_num = 0, xdp_num = 0;
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	switch (sset) {
	case ETH_SS_TEST:
		return ARRAY_LEN(g_hinic5_test_strings);
	case ETH_SS_STATS:
		q_num = nic_dev->q_params.num_qps;
		xdp_num = nic_dev->q_params.xdp_qps;
		count = ARRAY_LEN(hinic5_netdev_stats) +
		    ARRAY_LEN(hinic5_nic_dev_stats) +
			ARRAY_LEN(hinic5_port_link_stat) +
			ARRAY_LEN(hinic5_function_stats) +
			ARRAY_LEN(hinic5_tx_queue_stats) * q_num +
			ARRAY_LEN(hinic5_rx_queue_stats) * q_num;

#ifdef HAVE_XDP_SUPPORT
		count += ARRAY_LEN(hinic5_xdp_tx_queue_stats) * xdp_num;
#endif

		if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
			count += ARRAY_LEN(hinic5_port_stats);
		return count;

	case ETH_SS_PRIV_FLAGS:
		return ARRAY_LEN(g_hinic_priv_flags_strings);
	default:
		return -EOPNOTSUPP;
	}
}

static void get_drv_queue_stats(struct hinic5_nic_dev *nic_dev, u64 *data)
{
	struct hinic5_txq_stats txq_stats;
#ifdef HAVE_XDP_SUPPORT
	struct hinic5_xdptxq_stats xdptxq_stats;
#endif
	struct hinic5_rxq_stats rxq_stats;
	u16 i = 0, j = 0, qid = 0;
	char *p = NULL;

	/* 1. Count kernel TX queues (num_qps), display regular statistic fields */
	for (qid = 0; qid < nic_dev->q_params.num_qps; qid++) {
		if (!nic_dev->txqs)
			break;

		hinic5_txq_get_stats(&nic_dev->txqs[qid], &txq_stats);
		for (j = 0; j < ARRAY_LEN(hinic5_tx_queue_stats); j++, i++) {
			p = (char *)(&txq_stats) +
				hinic5_tx_queue_stats[j].offset;
			data[i] = (hinic5_tx_queue_stats[j].size ==
					sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
		}
	}

	/* 3. Count RX queues (num_qps) (kernel queues only) */
	for (qid = 0; qid < nic_dev->q_params.num_qps; qid++) {
		if (!nic_dev->rxqs)
			break;

		hinic5_rxq_get_stats(&nic_dev->rxqs[qid], &rxq_stats);
		for (j = 0; j < ARRAY_LEN(hinic5_rx_queue_stats); j++, i++) {
			p = (char *)(&rxq_stats) +
				hinic5_rx_queue_stats[j].offset;
			data[i] = (hinic5_rx_queue_stats[j].size ==
					sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
		}
	}

	/* 2. Count XDP TX queues (xdp_qps), display XDP-related statistic fields only */
#ifdef HAVE_XDP_SUPPORT
	for (qid = nic_dev->q_params.num_qps;
	     qid < nic_dev->q_params.num_qps + nic_dev->q_params.xdp_qps; qid++) {
		if (!nic_dev->txqs)
			break;

		hinic5_xdptxq_get_stats(&nic_dev->txqs[qid], &xdptxq_stats);
		/* Only display xdp_dropped and xdp_xmits */
		for (j = 0; j < ARRAY_LEN(hinic5_xdp_tx_queue_stats); j++, i++) {
			p = (char *)(&xdptxq_stats) +
				hinic5_xdp_tx_queue_stats[j].offset;
			data[i] = (hinic5_xdp_tx_queue_stats[j].size ==
					sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
		}
	}
#endif
}

static u16 get_ethtool_port_stats(struct hinic5_nic_dev *nic_dev, u64 *data)
{
	struct mag_cmd_port_stats *port_stats = NULL;
	char *p = NULL;
	u16 i = 0, j = 0;
	int err;

	port_stats = kzalloc(sizeof(*port_stats), GFP_KERNEL);
	if (!port_stats) {
		memset(&data[i], 0,
		       ARRAY_LEN(hinic5_port_stats) * sizeof(*data));
		i += ARRAY_LEN(hinic5_port_stats);
		return i;
	}

	err = hinic5_get_phy_port_stats(nic_dev->hwdev, port_stats);
	if (err != 0)
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to get port stats from fw\n");

	for (j = 0; j < ARRAY_LEN(hinic5_port_stats); j++, i++) {
		p = (char *)(port_stats) + hinic5_port_stats[j].offset;
		data[i] = (hinic5_port_stats[j].size ==
				sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}

	kfree(port_stats);

	return i;
}

void hinic5_get_ethtool_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
#ifdef HAVE_NDO_GET_STATS64
	struct rtnl_link_stats64 temp;
	const struct rtnl_link_stats64 *net_stats = NULL;
#else
	const struct net_device_stats *net_stats = NULL;
#endif
	struct hinic5_nic_stats *nic_stats = NULL;

	struct hinic5_vport_stats vport_stats = {0};
	u16 i = 0, j = 0;
	char *p = NULL;
	int err;
	struct hinic5_port_link_stats link_count = {0};

#ifdef HAVE_NDO_GET_STATS64
	net_stats = dev_get_stats(netdev, &temp);
#else
	net_stats = dev_get_stats(netdev);
#endif
	for (j = 0; j < ARRAY_LEN(hinic5_netdev_stats); j++, i++) {
		p = (char *)(net_stats) + hinic5_netdev_stats[j].offset;
		data[i] = GET_VALUE_OF_PTR(hinic5_netdev_stats[j].size, p);
	}

	nic_stats = &nic_dev->stats;
	for (j = 0; j < ARRAY_LEN(hinic5_nic_dev_stats); j++, i++) {
		p = (char *)(nic_stats) + hinic5_nic_dev_stats[j].offset;
		data[i] = GET_VALUE_OF_PTR(hinic5_nic_dev_stats[j].size, p);
	}

	err = hinic5_get_link_down_cnt(nic_dev->hwdev, (int *)&link_count.link_down_events_phy);
	if (err != 0)
		nicif_err(nic_dev, drv, netdev,
			  "Failed to get link down counter from fw\n");

	for (j = 0; j < ARRAY_LEN(hinic5_port_link_stat); j++) {
		p = (char *)(&link_count) + hinic5_port_link_stat[j].offset;
		data[i++] = GET_VALUE_OF_PTR(hinic5_port_link_stat[j].size, p);
	}

	err = hinic5_get_vport_stats(nic_dev->hwdev, hinic5_global_func_id(nic_dev->hwdev),
				     &vport_stats);
	if (err != 0)
		nicif_err(nic_dev, drv, netdev,
			  "Failed to get function stats from fw\n");

	for (j = 0; j < ARRAY_LEN(hinic5_function_stats); j++, i++) {
		p = (char *)(&vport_stats) + hinic5_function_stats[j].offset;
		data[i] = GET_VALUE_OF_PTR(hinic5_function_stats[j].size, p);
	}

	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
		i += get_ethtool_port_stats(nic_dev, data + i);

	get_drv_queue_stats(nic_dev, data + i);
}

static u16 get_drv_dev_strings(struct hinic5_nic_dev *nic_dev, char *p)
{
	u16 i, cnt = 0;

	for (i = 0; i < ARRAY_LEN(hinic5_netdev_stats); i++) {
		memcpy(p, hinic5_netdev_stats[i].name, ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
		cnt++;
	}

	for (i = 0; i < ARRAY_LEN(hinic5_nic_dev_stats); i++) {
		memcpy(p, hinic5_nic_dev_stats[i].name, ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
		cnt++;
	}

	for (i = 0; i < ARRAY_LEN(hinic5_port_link_stat); i++) {
		memcpy(p, hinic5_port_link_stat[i].name, ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
		cnt++;
	}

	return cnt;
}

static u16 get_hw_stats_strings(struct hinic5_nic_dev *nic_dev, char *p)
{
	u16 i, cnt = 0;

	for (i = 0; i < ARRAY_LEN(hinic5_function_stats); i++) {
		memcpy(p, hinic5_function_stats[i].name, ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
		cnt++;
	}

	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev)) {
		for (i = 0; i < ARRAY_LEN(hinic5_port_stats); i++) {
			memcpy(p, hinic5_port_stats[i].name, ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
			cnt++;
		}
	}

	return cnt;
}

static u16 get_qp_stats_strings(const struct hinic5_nic_dev *nic_dev, char *p)
{
	u16 i = 0, j = 0, cnt = 0;
	int err;

	/* 1. Kernel TX queue statistic names (num_qps) */
	for (i = 0; i < nic_dev->q_params.num_qps; i++) {
		for (j = 0; j < ARRAY_LEN(hinic5_tx_queue_stats); j++) {
			err = sprintf(p, hinic5_tx_queue_stats[j].name, i);
			if (err < 0)
				nicif_err(nic_dev, drv, nic_dev->netdev,
					  "Failed to sprintf tx queue stats name, idx_qps: %u, idx_stats: %u\n",
					  i, j);
			p += ETH_GSTRING_LEN;
			cnt++;
		}
	}

	/* 2 RX queue statistic names (kernel queues only) */
	for (i = 0; i < nic_dev->q_params.num_qps; i++) {
		for (j = 0; j < ARRAY_LEN(hinic5_rx_queue_stats); j++) {
			err = sprintf(p, hinic5_rx_queue_stats[j].name, i);
			if (err < 0)
				nicif_err(nic_dev, drv, nic_dev->netdev,
					  "Failed to sprintf rx queue stats name, idx_qps: %u, idx_stats: %u\n",
					  i, j);
			p += ETH_GSTRING_LEN;
			cnt++;
		}
	}

	/* 3 XDP TX queue statistic names (xdp_qps) */
#ifdef HAVE_XDP_SUPPORT
	for (i = 0; i < nic_dev->q_params.xdp_qps; i++) {
		for (j = 0; j < ARRAY_LEN(hinic5_xdp_tx_queue_stats); j++) {
			err = sprintf(p, hinic5_xdp_tx_queue_stats[j].name, i);
			if (err < 0)
				nicif_err(nic_dev, drv, nic_dev->netdev,
					  "Failed to sprintf xdp tx queue stats name, idx_qps: %u, idx_stats: %u\n",
					  i, j);
			p += ETH_GSTRING_LEN;
			cnt++;
		}
	}
#endif

	return cnt;
}

void hinic5_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	char *p = (char *)data;
	u16 offset = 0;

	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(data, *g_hinic5_test_strings, sizeof(g_hinic5_test_strings));
		return;
	case ETH_SS_STATS:
		offset = get_drv_dev_strings(nic_dev, p);
		offset += get_hw_stats_strings(nic_dev,
					       p + (u32)(offset * ETH_GSTRING_LEN));
		get_qp_stats_strings(nic_dev, p + (u32)(offset * ETH_GSTRING_LEN));

		return;
	case ETH_SS_PRIV_FLAGS:
		memcpy(data, g_hinic_priv_flags_strings, sizeof(g_hinic_priv_flags_strings));
		return;
	default:
		nicif_err(nic_dev, drv, netdev,
			  "Invalid string set %u.", stringset);
		return;
	}
}

#if defined(ETHTOOL_GFECPARAM) && defined(ETHTOOL_SFECPARAM)
struct fecparam_value_map {
	u8 hinic5_fec_offset;
	u8 hinic5_fec_value;
	u8 ethtool_fec_value;
};

static void fecparam_convert(u32 opcode, u8 in_fec_param, u8 *out_fec_param)
{
	u8 i;
	u8 fec_value_table_lenth;
	struct fecparam_value_map fec_value_table[] = {
		{PORT_FEC_NOT_SET,  BIT(PORT_FEC_NOT_SET),  ETHTOOL_FEC_NONE},
		{PORT_FEC_RSFEC,    BIT(PORT_FEC_RSFEC),    ETHTOOL_FEC_RS},
		{PORT_FEC_BASEFEC,  BIT(PORT_FEC_BASEFEC),  ETHTOOL_FEC_BASER},
		{PORT_FEC_NOFEC,    BIT(PORT_FEC_NOFEC),    ETHTOOL_FEC_OFF},
#ifdef ETHTOOL_FEC_LLRS
		{PORT_FEC_LLRSFEC,  BIT(PORT_FEC_LLRSFEC),  ETHTOOL_FEC_LLRS},
#endif
		{PORT_FEC_AUTO,     BIT(PORT_FEC_AUTO),     ETHTOOL_FEC_AUTO}
	};

	*out_fec_param = 0;
	fec_value_table_lenth = (u8)(sizeof(fec_value_table) / sizeof(struct fecparam_value_map));

	if (opcode == MAG_CMD_OPCODE_SET) {
		for (i = 0; i < fec_value_table_lenth; i++) {
			if ((in_fec_param & fec_value_table[i].ethtool_fec_value) != 0)
				/* The MPU uses the offset to determine the FEC mode. */
				*out_fec_param = fec_value_table[i].hinic5_fec_offset;
		}
	}

	if (opcode == MAG_CMD_OPCODE_GET) {
		for (i = 0; i < fec_value_table_lenth; i++) {
			if ((in_fec_param & fec_value_table[i].hinic5_fec_value) != 0)
				*out_fec_param |= fec_value_table[i].ethtool_fec_value;
		}
	}
}

/* When the ethtool is used to set the FEC mode */
static bool check_fecparam_is_valid(u8 fec_param)
{
	if (fec_param == ETHTOOL_FEC_RS ||
	    fec_param == ETHTOOL_FEC_BASER ||
#ifdef ETHTOOL_FEC_LLRS
	    fec_param == ETHTOOL_FEC_LLRS ||
#endif
	    fec_param == ETHTOOL_FEC_OFF)
		return true;
	return false;
}

int hinic5_get_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u8 advertised_fec = 0;
	u8 supported_fec = 0;
	int err;

	err = hinic5_get_fec(nic_dev->hwdev, &advertised_fec, &supported_fec);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Get fec param failed\n");
		return err;
	}

	fecparam_convert(MAG_CMD_OPCODE_GET, BIT(advertised_fec),
			 (u8 *)(&fecparam->active_fec));
	fecparam_convert(MAG_CMD_OPCODE_GET, supported_fec, (u8 *)(&fecparam->fec));

	nicif_info(nic_dev, drv, netdev, "Get fec param success\n");
	return 0;
}

int hinic5_set_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	int err;
	u8 advertised_fec = 0;

	if (check_fecparam_is_valid((u8)(fecparam->fec)) == false) {
		nicif_err(nic_dev, drv, netdev, "fec param is invalid, failed to set fec param\n");
		return -EINVAL;
	}

	fecparam_convert(MAG_CMD_OPCODE_SET, (u8)(fecparam->fec), &advertised_fec);

	err = hinic5_set_fec(nic_dev->hwdev, advertised_fec);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Set fec param failed\n");
		return err;
	}

	nicif_info(nic_dev, drv, netdev, "Set fec param success\n");
	return 0;
}
#endif

