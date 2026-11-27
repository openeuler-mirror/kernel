// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: ipourma ethtool support
 */

#include <linux/kernel.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/version.h>

#include "ub/urma/ubcore_uapi.h"
#include "ipourma_ethtool.h"

#define IPOURMA_DRIVER_VERSION	"0.1.0"
#define IPOURMA_FW_VERSION	"0.1.0"

struct ipourma_stats {
	char stat_string[ETH_GSTRING_LEN];
	int stat_offset;
};

#define IPOURMA_NETDEV_STAT(m) { \
		.stat_string = #m, \
		.stat_offset = offsetof(struct rtnl_link_stats64, m) }

static const struct ipourma_stats ipourma_gstrings_stats[] = {
	IPOURMA_NETDEV_STAT(rx_packets),
	IPOURMA_NETDEV_STAT(tx_packets),
	IPOURMA_NETDEV_STAT(rx_bytes),
	IPOURMA_NETDEV_STAT(tx_bytes),
	IPOURMA_NETDEV_STAT(tx_errors),
	IPOURMA_NETDEV_STAT(rx_dropped),
	IPOURMA_NETDEV_STAT(tx_dropped),
};

#define IPOURMA_GLOBAL_STATS_LEN	ARRAY_SIZE(ipourma_gstrings_stats)

/*
 * Runtime statistics mirrored from sysfs query_ipourma_stats. Each entry maps
 * a flat ethtool counter name to a byte offset within struct
 * ipourma_runtime_stats. The tx_/rx_ prefixes keep names unique in the flat
 * ethtool -S namespace (sysfs groups them under ==tx_stats==/==rx_stats==).
 */
struct ipourma_rt_stat {
	char name[ETH_GSTRING_LEN];
	size_t offset; /* byte offset within struct ipourma_runtime_stats */
};

#define IPOURMA_RT_STAT_TX(f) { \
		.name = "tx_" #f, \
		.offset = offsetof(struct ipourma_runtime_stats, tx_stats.f) }
#define IPOURMA_RT_STAT_RX(f) { \
		.name = "rx_" #f, \
		.offset = offsetof(struct ipourma_runtime_stats, rx_stats.f) }

/* tx_stats scalar fields (cqe_stats[] expanded separately below) */
static const struct ipourma_rt_stat ipourma_rt_tx_stats[] = {
	IPOURMA_RT_STAT_TX(num_recv_pkts_from_kernel),
	IPOURMA_RT_STAT_TX(post_send_enque),
	IPOURMA_RT_STAT_TX(post_send_bypass),
	IPOURMA_RT_STAT_TX(gso_not_support),
	IPOURMA_RT_STAT_TX(packet_size_error),
	IPOURMA_RT_STAT_TX(frag_error),
	IPOURMA_RT_STAT_TX(not_ipv6_proto),
	IPOURMA_RT_STAT_TX(not_ipv6_addr),
	IPOURMA_RT_STAT_TX(ip_eid_not_equal),
	IPOURMA_RT_STAT_TX(ring_full),
	IPOURMA_RT_STAT_TX(ring_invalid),
	IPOURMA_RT_STAT_TX(post_send_start),
	IPOURMA_RT_STAT_TX(num_import_jetty_real),
	IPOURMA_RT_STAT_TX(num_import_jetty_bypass),
	IPOURMA_RT_STAT_TX(num_tjetty_hash_hit),
	IPOURMA_RT_STAT_TX(num_pending_flush),
	IPOURMA_RT_STAT_TX(linear_len_oversize),
	IPOURMA_RT_STAT_TX(import_jetty_failed),
	IPOURMA_RT_STAT_TX(send_wr_failed),
	IPOURMA_RT_STAT_TX(pending_drop),
	IPOURMA_RT_STAT_TX(pending_create_drop),
	IPOURMA_RT_STAT_TX(pass_to_ub),
	IPOURMA_RT_STAT_TX(cqe_notify),
	IPOURMA_RT_STAT_TX(num_napi_tx),
	IPOURMA_RT_STAT_TX(cqe_recved),
	IPOURMA_RT_STAT_TX(cqe_success),
	IPOURMA_RT_STAT_TX(cqe_err),
	IPOURMA_RT_STAT_TX(poll_jfc_success),
	IPOURMA_RT_STAT_TX(poll_jfc_failed),
	IPOURMA_RT_STAT_TX(rearm_success),
	IPOURMA_RT_STAT_TX(rearm_failed),
	IPOURMA_RT_STAT_TX(flush_jetty_success),
};

/* rx_stats scalar fields (cqe_stats[] expanded separately below) */
static const struct ipourma_rt_stat ipourma_rt_rx_stats[] = {
	IPOURMA_RT_STAT_RX(cqe_notify),
	IPOURMA_RT_STAT_RX(num_napi_rx),
	IPOURMA_RT_STAT_RX(enque),
	IPOURMA_RT_STAT_RX(deque),
	IPOURMA_RT_STAT_RX(cqe_recved),
	IPOURMA_RT_STAT_RX(cqe_success),
	IPOURMA_RT_STAT_RX(cqe_err),
	IPOURMA_RT_STAT_RX(poll_jfc_success),
	IPOURMA_RT_STAT_RX(poll_jfc_failed),
	IPOURMA_RT_STAT_RX(rearm_success),
	IPOURMA_RT_STAT_RX(rearm_failed),
	IPOURMA_RT_STAT_RX(cr_len_err),
	IPOURMA_RT_STAT_RX(replenish_enque),
	IPOURMA_RT_STAT_RX(pass_to_kernel),
	IPOURMA_RT_STAT_RX(replenish_deque),
	IPOURMA_RT_STAT_RX(num_post_wr),
	IPOURMA_RT_STAT_RX(alloc_skb_failed),
	IPOURMA_RT_STAT_RX(register_seg_failed),
	IPOURMA_RT_STAT_RX(post_wr_failed),
	IPOURMA_RT_STAT_RX(alloc_skb_retry),
};

#define IPOURMA_RT_TX_STATS_LEN		ARRAY_SIZE(ipourma_rt_tx_stats)
#define IPOURMA_RT_RX_STATS_LEN		ARRAY_SIZE(ipourma_rt_rx_stats)
/* per-direction CQE-status breakdown: tx_cqes_<name> / rx_cqes_<name>.
 * Short "cqes" (cqe-status) prefix keeps names within ETH_GSTRING_LEN (31).
 */
#define IPOURMA_CQE_STATUS_LEN		IPOURMA_MAX_CR_STATUS

/* Order MUST be: base netdev stats, tx scalars, tx cqe_status, rx scalars, rx cqe_status */
#define IPOURMA_RT_STATS_LEN		(IPOURMA_RT_TX_STATS_LEN + IPOURMA_CQE_STATUS_LEN + \
					 IPOURMA_RT_RX_STATS_LEN + IPOURMA_CQE_STATUS_LEN)
#define IPOURMA_TOTAL_STATS_LEN		(IPOURMA_GLOBAL_STATS_LEN + IPOURMA_RT_STATS_LEN)

/* Byte offset of cqe_stats[i] within struct ipourma_runtime_stats */
#define IPOURMA_CQE_STAT_OFFSET(dir, i) \
	(offsetof(struct ipourma_runtime_stats, dir##_stats.cqe_stats) + \
	 (i) * sizeof(uint64_t))

static int ub_speed_enum_to_int(enum ubcore_speed speed)
{
	switch (speed) {
	case UBCORE_SP_10M:
		return SPEED_10;
	case UBCORE_SP_100M:
		return SPEED_100;
	case UBCORE_SP_1G:
		return SPEED_1000;
	case UBCORE_SP_2_5G:
		return SPEED_2500;
	case UBCORE_SP_5G:
		return SPEED_5000;
	case UBCORE_SP_10G:
		return SPEED_10000;
	case UBCORE_SP_14G:
		return SPEED_14000;
	case UBCORE_SP_25G:
		return SPEED_25000;
	case UBCORE_SP_40G:
		return SPEED_40000;
	case UBCORE_SP_50G:
		return SPEED_50000;
	case UBCORE_SP_100G:
		return SPEED_100000;
	case UBCORE_SP_200G:
		return SPEED_200000;
	case UBCORE_SP_400G:
		return SPEED_400000;
	case UBCORE_SP_800G:
		return SPEED_800000;
	}

	return SPEED_UNKNOWN;
}

static int ipourma_get_link_ksettings(struct net_device *netdev,
					struct ethtool_link_ksettings *cmd)
{
	struct ipourma_dev_priv *priv;
	struct ubcore_device *dev;
	struct ubcore_device_status status;
	int ret, speed;

	if (IS_ERR_OR_NULL(netdev) || IS_ERR_OR_NULL(cmd))
		return -EINVAL;
	priv = netdev_priv(netdev);
	dev = priv->urma_dev;

	if (!netif_carrier_ok(netdev)) {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
		return 0;
	}

	if (IS_ERR_OR_NULL(priv->urma_dev->ops) ||
		IS_ERR_OR_NULL(priv->urma_dev->ops->query_device_status))
		return -EINVAL;

	ret = priv->urma_dev->ops->query_device_status(dev, &status);
	if (ret)
		return ret;

	/* For IP over URMA, each port corresponds to a ubcore_device */
	speed = ub_speed_enum_to_int(status.port_status[0].active_speed);
	if (speed < 0)
		return -EINVAL;

	cmd->base.speed		 = (uint32_t)speed;
	cmd->base.duplex	 = DUPLEX_FULL;
	cmd->base.phy_address	 = 0xFF;
	cmd->base.autoneg	 = AUTONEG_DISABLE;
	cmd->base.port		 = PORT_FIBRE;

	return 0;
}

static void ipourma_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct ipourma_dev_priv *priv;

	if (IS_ERR_OR_NULL(netdev) || IS_ERR_OR_NULL(drvinfo))
		return;

	priv = netdev_priv(netdev);

	strscpy(drvinfo->version, IPOURMA_DRIVER_VERSION,
		sizeof(drvinfo->version));
	strscpy(drvinfo->fw_version, IPOURMA_FW_VERSION,
		sizeof(drvinfo->fw_version));

	if (priv->urma_dev->dev.parent) {
		strscpy(drvinfo->bus_info, dev_name(priv->urma_dev->dev.parent),
			sizeof(drvinfo->bus_info));
	}

	strscpy(drvinfo->driver, "ub_ipourma", sizeof(drvinfo->driver));
}

static void ipourma_get_strings(struct net_device __always_unused *dev,
			      u32 stringset, u8 *data)
{
	u8 *p = data;
	int i;

	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(data))
		return;
	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < IPOURMA_GLOBAL_STATS_LEN; i++) {
			memcpy(p, ipourma_gstrings_stats[i].stat_string,
				ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < IPOURMA_RT_TX_STATS_LEN; i++) {
			memcpy(p, ipourma_rt_tx_stats[i].name, ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < IPOURMA_CQE_STATUS_LEN; i++) {
			snprintf((char *)p, ETH_GSTRING_LEN, "tx_cqes_%s",
				 ipourma_cr_status_names[i]);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < IPOURMA_RT_RX_STATS_LEN; i++) {
			memcpy(p, ipourma_rt_rx_stats[i].name, ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < IPOURMA_CQE_STATUS_LEN; i++) {
			snprintf((char *)p, ETH_GSTRING_LEN, "rx_cqes_%s",
				 ipourma_cr_status_names[i]);
			p += ETH_GSTRING_LEN;
		}
		break;
	default:
		break;
	}
}

static void ipourma_get_ethtool_stats(struct net_device *dev,
				    struct ethtool_stats __always_unused *stats,
				    u64 *data)
{
	int i, idx = 0;
	struct net_device_stats *net_stats;
	struct ipourma_dev_priv *priv;
	struct ipourma_runtime_stats *rt;
	u8 *p, *base;

	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(data))
		return;

	/* standard netdev counters from dev->stats */
	net_stats = &dev->stats;
	p = (u8 *)net_stats;
	for (i = 0; i < IPOURMA_GLOBAL_STATS_LEN; i++)
		data[idx++] = *(u64 *)(p + ipourma_gstrings_stats[i].stat_offset);

	/* runtime tx/rx counters, snapshot under the same lock as sysfs */
	priv = netdev_priv(dev);
	rt = &priv->runtime_stats;
	base = (u8 *)rt;
	spin_lock(&rt->lock);
	for (i = 0; i < IPOURMA_RT_TX_STATS_LEN; i++)
		data[idx++] = *(u64 *)(base + ipourma_rt_tx_stats[i].offset);
	for (i = 0; i < IPOURMA_CQE_STATUS_LEN; i++)
		data[idx++] = *(u64 *)(base + IPOURMA_CQE_STAT_OFFSET(tx, i));
	for (i = 0; i < IPOURMA_RT_RX_STATS_LEN; i++)
		data[idx++] = *(u64 *)(base + ipourma_rt_rx_stats[i].offset);
	for (i = 0; i < IPOURMA_CQE_STATUS_LEN; i++)
		data[idx++] = *(u64 *)(base + IPOURMA_CQE_STAT_OFFSET(rx, i));
	spin_unlock(&rt->lock);
}

static int ipourma_get_sset_count(struct net_device __always_unused *dev,
				 int sset)
{
	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;
	switch (sset) {
	case ETH_SS_STATS:
		return IPOURMA_TOTAL_STATS_LEN;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

static const struct ethtool_ops ipourma_ethtool_ops = {
	.get_link_ksettings	= ipourma_get_link_ksettings,
	.get_drvinfo		= ipourma_get_drvinfo,
	.get_strings		= ipourma_get_strings,
	.get_ethtool_stats	= ipourma_get_ethtool_stats,
	.get_sset_count		= ipourma_get_sset_count,
	.get_link		= ethtool_op_get_link,
};

void ipourma_set_ethtool_ops(struct net_device *dev)
{
	dev->ethtool_ops = &ipourma_ethtool_ops;
}
