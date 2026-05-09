// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_eswitch.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/ethtool.h>
#include <net/dst_metadata.h>

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_irq.h"
#include "sxe2_vsi.h"
#include "sxe2_log.h"
#include "sxe2_netdev.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_tx.h"
#include "sxe2_eswitch.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_ethtool.h"
#include "sxe2_tc.h"
#include "sxe2_rx.h"

#ifdef NEED_DEFINE_METADATA_DST_FREE
void metadata_dst_free(struct metadata_dst *md_dst)
{
	kfree((void *)md_dst);
}
#endif

STATIC void sxe2_eswitch_vsi_destroy(struct sxe2_adapter *adapter)
{
	sxe2_vsi_destroy(adapter->eswitch_ctxt.esw_vsi);
	adapter->eswitch_ctxt.esw_vsi = NULL;

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_KERNEL) {
		sxe2_vsi_destroy(adapter->eswitch_ctxt.user_esw_vsi);
		adapter->eswitch_ctxt.user_esw_vsi = NULL;
	}
}

static s32 sxe2_uplink_vsi_cfg_to_switchdev(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *uplink_vsi;
	struct net_device *uplink_netdev;
	s32 ret = 0;

	uplink_vsi = adapter->vsi_ctxt.main_vsi;

	adapter->eswitch_ctxt.uplink_vsi = uplink_vsi;

	sxe2_vsi_l2_fltr_remove(adapter, uplink_vsi->idx_in_dev);

	if (uplink_vsi->type == SXE2_VSI_T_PF) {
		uplink_netdev = uplink_vsi->netdev;
		netif_addr_lock_bh(uplink_netdev);
		__dev_uc_unsync(uplink_netdev, NULL);
		__dev_mc_unsync(uplink_netdev, NULL);
		netif_addr_unlock_bh(uplink_netdev);
	}

	ret = sxe2_promisc_rule_add(uplink_vsi);
	if (ret && ret != -EEXIST)
		return ret;

	ret = sxe2_vlan_filter_control(adapter, uplink_vsi->idx_in_dev, false);

	return ret;
}

static s32 sxe2_mac_rule_restore(struct sxe2_vsi *vsi, const u8 *mac)
{
	s32 ret;
	u8 broadcast[ETH_ALEN];

	eth_broadcast_addr(broadcast);
	ret = sxe2_mac_rule_add(vsi, broadcast);
	if (ret) {
		LOG_ERROR("vsi[%u][%u] broadcast mac addr add failed.(err:%d).\n",
			  vsi->id_in_pf, vsi->idx_in_dev, ret);
		return ret;
	}

	ret = sxe2_mac_rule_add(vsi, mac);
	if (ret) {
		LOG_ERROR("vsi[%u][%u] dev mac addr add failed.(err:%d).\n",
			  vsi->id_in_pf, vsi->idx_in_dev, ret);
		return ret;
	}

	return ret;
}

static void sxe2_uplink_vsi_cfg_to_legacy(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct net_device *netdev = vsi->netdev;

	(void)sxe2_promisc_rule_del(adapter, vsi->idx_in_dev);

	(void)sxe2_mac_rule_restore(vsi, vsi->netdev->dev_addr);

	(void)sxe2_vsi_vlan_zero_add(vsi);

	rtnl_lock();
	if (netdev->features &
	    (NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER)) {
		(void)sxe2_vlan_filter_control(adapter, vsi->idx_in_dev, true);
	}
	rtnl_unlock();

	sxe2_set_rx_mode(vsi->netdev);

	(void)sxe2_etype_fltr_init(vsi);
	(void)sxe2_src_vsi_prune_control(adapter, vsi->idx_in_dev, true);
	(void)sxe2_srcvsi_rule_add(vsi);
}

static struct net_device *sxe2_repr_netdev_alloc(struct sxe2_vf_node *vf)
{
	struct sxe2_netdev_priv *priv;
	struct net_device *netdev;
	struct sxe2_adapter *adapter = vf->adapter;

	netdev = alloc_etherdev_mq(sizeof(*priv), SXE2_ESWITCH_QUEUE_CNT);
	if (!netdev) {
		LOG_DEV_ERR("vf:%u repr netdev alloc failed. priv size %zu\n",
			    vf->vf_idx, sizeof(*priv));
		return NULL;
	}

	vf->repr->netdev = netdev;
	vf->repr->vf_node = vf;
	vf->repr->src_vsi = NULL;
	priv = netdev_priv(netdev);
	priv->repr = vf->repr;
	priv->vsi = adapter->eswitch_ctxt.esw_vsi;

	SET_NETDEV_DEV(netdev, &adapter->pdev->dev);

	return netdev;
}

static s32 sxe2_repr_open(struct net_device *netdev)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vf_repr *repr = np->repr;
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_vf_node *vf_node = repr->vf_node;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, adapter->vsi_ctxt.main_vsi->state)) {
		ret = -EBUSY;
		goto unlock;
	}

	vf_node->prop.link_forced = true;
	vf_node->prop.link_up = true;
	sxe2_notify_vf_link_state(repr->vf_node);

	netif_carrier_on(netdev);

	netif_tx_start_all_queues(netdev);

	LOG_INFO_BDF("vf:%u src_vsi:%u repr:%pK esw_vsi:%u start.\n",
		     repr->vf_node->vf_idx, repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH],
		     repr, np->vsi->idx_in_dev);

unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static int sxe2_repr_stop(struct net_device *netdev)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vf_repr *repr = np->repr;
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_vf_node *vf_node = repr->vf_node;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, adapter->vsi_ctxt.main_vsi->state))
		goto unlock;

	vf_node->prop.link_forced = true;
	vf_node->prop.link_up = false;
	sxe2_notify_vf_link_state(repr->vf_node);

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	LOG_INFO_BDF("vf:%u src_vsi:%u repr:%pK esw_vsi:%u stopped.\n",
		     repr->vf_node->vf_idx, repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH],
		     repr, np->vsi->idx_in_dev);

unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return 0;
}

static int sxe2_repr_get_phys_port_name(struct net_device *netdev, char *buf,
					size_t len)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vf_repr *repr = np->repr;
	struct sxe2_vf_node *vf = repr->vf_node;
	int res;

	res = snprintf(buf, len, "r%d", vf->vf_idx);
	if (res <= 0)
		return -EOPNOTSUPP;
	return 0;
}

STATIC netdev_tx_t sxe2_repr_start_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vf_repr *repr = np->repr;

	skb_dst_drop(skb);
	dst_hold((struct dst_entry *)repr->dst);
	skb_dst_set(skb, (struct dst_entry *)repr->dst);
	skb->queue_mapping = repr->vf_node->vf_idx;

	return sxe2_xmit(skb, netdev);
}

#ifdef HAVE_VOID_NDO_GET_STATS64
static struct rtnl_link_stats64 *
sxe2_repr_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
#else
static void sxe2_repr_get_stats64(struct net_device *netdev,
				  struct rtnl_link_stats64 *stats)
#endif
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct rtnl_link_stats64 *repr_vf_stats;
	u16 vf_idx;

	vf_idx = np->repr->vf_idx;
	repr_vf_stats = &adapter->repr_vf_stats.repr_link_stats64[vf_idx];
	memcpy(stats, repr_vf_stats, sizeof(*stats));

#ifdef HAVE_VOID_NDO_GET_STATS64
	return stats;
#endif
}

#ifdef HAVE_NDO_OFFLOAD_STATS
static bool sxe2_repr_ndo_has_offload_stats(const struct net_device *dev,
					    int attr_id)
{
	return attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT;
}

static int sxe2_repr_slow_path_stats64(const struct net_device *netdev,
				       struct rtnl_link_stats64 *stats)
{
	int ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	u64 pkts, bytes;
	struct sxe2_vsi *esw_vsi = np->vsi;
	struct sxe2_adapter *adapter = np->vsi->adapter;
	int vf_id = np->repr->vf_node->vf_idx;
	struct sxe2_queue *txq = NULL;
	struct sxe2_queue *rxq = NULL;
	struct sxe2_vsi_qs_stats *qs_stats_last = &esw_vsi->vsi_qs_stats;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, esw_vsi->state)) {
		stats->rx_packets = qs_stats_last->txqs_stats[vf_id].packets;
		stats->rx_bytes = qs_stats_last->txqs_stats[vf_id].bytes;
		stats->tx_packets = qs_stats_last->rxqs_stats[vf_id].packets;
		stats->tx_bytes = qs_stats_last->rxqs_stats[vf_id].bytes;
		stats->tx_dropped = qs_stats_last->rxqs_stats[vf_id]
						    .rx_stats.rx_pg_alloc_fail +
				    qs_stats_last->rxqs_stats[vf_id]
						    .rx_stats.rx_buff_alloc_err;
		LOG_DEBUG_BDF("esw vsi[%u][%u] vf_id[%u]dev is busy now(err:%d).\n",
			      esw_vsi->id_in_pf, esw_vsi->idx_in_dev, vf_id, ret);
		goto l_unlock;
	}

	txq = esw_vsi->txqs.q[vf_id];
	rxq = esw_vsi->rxqs.q[vf_id];

	sxe2_fetch_u64_data_per_ring(&txq->syncp, txq->stats, &pkts, &bytes);
	stats->rx_packets = pkts;
	stats->rx_bytes = bytes;

	sxe2_fetch_u64_data_per_ring(&rxq->syncp, rxq->stats, &pkts, &bytes);
	stats->tx_packets = pkts;
	stats->tx_bytes = bytes;
	stats->tx_dropped = rxq->stats->rx_stats.rx_pg_alloc_fail +
			    rxq->stats->rx_stats.rx_buff_alloc_err;
	LOG_DEBUG_BDF("esw stats vf_id:[%u] rx_pack:[%llu] tx_pack:[%llu]\n", vf_id,
		      stats->rx_packets, stats->tx_packets);
l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static int sxe2_repr_ndo_get_offload_stats(int attr_id, const struct net_device *dev,
					   void *sp)
{
	if (attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT)
		return sxe2_repr_slow_path_stats64(dev,
						   (struct rtnl_link_stats64 *)sp);

	return -EINVAL;
}
#endif

static LIST_HEAD(sxe2_repr_block_cb_list);

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
static s32 sxe2_repr_setup_tc(struct net_device *netdev, enum tc_setup_type type,
			      void *type_data)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);

	if (type == TC_SETUP_BLOCK)
		return flow_block_cb_setup_simple(type_data, &sxe2_repr_block_cb_list,
						  sxe2_repr_setup_tc_block_cb, np, np, true);
	return -EOPNOTSUPP;
}
#else
static s32 sxe2_repr_setup_tc(struct net_device *netdev, u32 __always_unused handle,
			      __be16 __always_unused proto, struct tc_to_netdev *tc)
{
	if (tc->type == TC_SETUP_CLSFLOWER)
		return sxe2_repr_setup_tc_cls_flower(np->repr, tc->cls_flower);
	return -EOPNOTSUPP;
}
#endif

STATIC const struct net_device_ops sxe2_repr_netdev_ops = {
		.ndo_get_stats64 = sxe2_repr_get_stats64,

		.ndo_get_phys_port_name = sxe2_repr_get_phys_port_name,
		.ndo_start_xmit = sxe2_repr_start_xmit,
		.ndo_open = sxe2_repr_open,
		.ndo_stop = sxe2_repr_stop,

#ifdef HAVE_NDO_OFFLOAD_STATS
		.ndo_has_offload_stats = sxe2_repr_ndo_has_offload_stats,
		.ndo_get_offload_stats = sxe2_repr_ndo_get_offload_stats,
#endif
		.ndo_setup_tc = sxe2_repr_setup_tc,
};

static void sxe2_repr_netdev_ops_init(struct net_device *netdev)
{
	netdev->netdev_ops = &sxe2_repr_netdev_ops;
}

#ifdef HAVE_NETDEV_MIN_MAX_MTU
static void sxe2_repr_netdev_mtu_init(struct net_device *netdev)
{
	sxe2_netdev_mtu_init(netdev);
}
#endif

STATIC void sxe2_repr_get_drvinfo(struct net_device *netdev,
				  struct ethtool_drvinfo *drvinfo)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);

	__sxe2_get_drvinfo(netdev, drvinfo, priv->repr->vf_node->adapter);
}

STATIC int sxe2_repr_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return SXE2_VSI_HW_STATS_LEN;

	default:
		return -EOPNOTSUPP;
	}
}

STATIC void sxe2_repr_get_ethtool_stats(struct net_device *netdev,
					struct ethtool_stats __always_unused *stats,
					u64 *data)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);

	if (priv->repr->src_vsi) {
		struct sxe2_vsi *vsi = priv->repr->src_vsi;

		__sxe2_repr_get_ethtool_stats(netdev, stats, data, vsi);
	}
}

STATIC void sxe2_repr_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	__sxe2_repr_get_strings(netdev, stringset, data);
}

static bool sxe2_repr_is_coalesce_param_invalid(struct ethtool_coalesce *ec)
{
	if (ec->rx_coalesce_usecs || ec->rx_max_coalesced_frames ||
	    ec->rx_coalesce_usecs_irq || ec->rx_max_coalesced_frames_irq ||
	    ec->tx_coalesce_usecs || ec->tx_max_coalesced_frames ||
	    ec->tx_coalesce_usecs_irq || ec->tx_max_coalesced_frames_irq ||
	    ec->stats_block_coalesce_usecs || ec->use_adaptive_rx_coalesce ||
	    ec->use_adaptive_tx_coalesce || ec->pkt_rate_low ||
	    ec->rx_coalesce_usecs_low || ec->rx_max_coalesced_frames_low ||
	    ec->tx_coalesce_usecs_low || ec->tx_max_coalesced_frames_low ||
	    ec->pkt_rate_high || ec->rx_max_coalesced_frames_high ||
	    ec->tx_coalesce_usecs_high || ec->tx_max_coalesced_frames_high ||
	    ec->rate_sample_interval)
		return true;

	return false;
}

#ifdef SET_COALESCE_NEED_2_PARAMS
STATIC int sxe2_repr_set_coalesce(struct net_device *netdev,
				  struct ethtool_coalesce *ec)
#else
STATIC int sxe2_repr_set_coalesce(struct net_device *netdev,
				  struct ethtool_coalesce *ec,
				  struct kernel_ethtool_coalesce *kernel_coal,
				  struct netlink_ext_ack *extack)
#endif
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	u16 vf_idx;
	struct sxe2_vf_node *vf;
	struct sxe2_vsi *vsi = adapter->eswitch_ctxt.esw_vsi;
	struct sxe2_irq_data *irq_data;
	s32 ret = 0;

	if (sxe2_repr_is_coalesce_param_invalid(ec))
		return -EOPNOTSUPP;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, adapter->vsi_ctxt.main_vsi->state)) {
		ret = -EBUSY;
		goto unlock;
	}

	irq_data = vsi->irqs.irq_data[0];
	if (!irq_data) {
		ret = -EINVAL;
		goto unlock;
	}

	if (ec->rx_coalesce_usecs_high >
			    SXE2_PF_INT_RATE_CREDIT_INTERVAL_MAX *
					    hw->hw_cfg.credit_interval_gran ||
	    (ec->rx_coalesce_usecs_high &&
	     ec->rx_coalesce_usecs_high < hw->hw_cfg.credit_interval_gran)) {
		LOG_NETDEV_INFO("invalid value, rx_coalesce_usecs_high valid values\t"
				"are 0(disabled), value:%d ,valid range:[%d-%d]\n",
				ec->rx_coalesce_usecs_high,
				hw->hw_cfg.credit_interval_gran,
				SXE2_PF_INT_RATE_CREDIT_INTERVAL_MAX *
						hw->hw_cfg.credit_interval_gran);
		ret = -EINVAL;
		goto unlock;
	}

	sxe2_for_each_vf(adapter, vf_idx)
	{
		vf = SXE2_VF_NODE(adapter, vf_idx);
		if (ec->rx_coalesce_usecs_high != vf->repr->irq_data->rate_limit)
			vf->repr->irq_data->rate_limit =
					(u16)ec->rx_coalesce_usecs_high;
	}

	irq_data->rate_limit = (u16)ec->rx_coalesce_usecs_high;

	sxe2_hw_irq_rate_limit_set(hw, irq_data->idx_in_pf, irq_data->rate_limit);

unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef GET_COALESCE_NEED_2_PARAMS
STATIC int sxe2_repr_get_coalesce(struct net_device *netdev,
				  struct ethtool_coalesce *ec)
#else
STATIC int sxe2_repr_get_coalesce(struct net_device *netdev,
				  struct ethtool_coalesce *ec,
				  struct kernel_ethtool_coalesce *kernel_coal,
				  struct netlink_ext_ack *extack)
#endif
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	struct sxe2_vsi *vsi = adapter->eswitch_ctxt.esw_vsi;
	struct sxe2_irq_data *irq_data;
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, adapter->vsi_ctxt.main_vsi->state)) {
		ret = -EBUSY;
		goto unlock;
	}

	irq_data = vsi->irqs.irq_data[0];
	if (!irq_data) {
		ret = -EINVAL;
		goto unlock;
	}

	ec->rx_coalesce_usecs_high = irq_data->rate_limit;

unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static const struct ethtool_ops sxe2_repr_ethtool_ops = {
#ifdef SUPPORTED_COALESCE_PARAMS
		.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS_HIGH,
#endif
		.get_drvinfo = sxe2_repr_get_drvinfo,
		.get_link = ethtool_op_get_link,
		.get_strings = sxe2_repr_get_strings,
		.get_ethtool_stats = sxe2_repr_get_ethtool_stats,
		.get_sset_count = sxe2_repr_get_sset_count,
		.set_coalesce = sxe2_repr_set_coalesce,
		.get_coalesce = sxe2_repr_get_coalesce,

};

static void sxe2_repr_ethtool_ops_set(struct net_device *netdev)
{
	netdev->ethtool_ops = &sxe2_repr_ethtool_ops;
}

STATIC s32 sxe2_repr_netdev_init(struct sxe2_vf_node *vf)
{
	struct net_device *netdev;

	netdev = sxe2_repr_netdev_alloc(vf);
	if (!netdev)
		return -ENOMEM;

	sxe2_repr_netdev_ops_init(netdev);

#ifdef HAVE_NETDEV_MIN_MAX_MTU
	sxe2_repr_netdev_mtu_init(netdev);
#endif

	sxe2_repr_ethtool_ops_set(netdev);

	return 0;
}

STATIC s32 sxe2_repr_netdev_register(struct sxe2_vf_node *vf)
{
	struct net_device *netdev = vf->repr->netdev;

	eth_hw_addr_random(netdev);

	netdev->hw_features |= NETIF_F_HW_TC;

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	return register_netdev(netdev);
}

STATIC s32 __sxe2_vf_repr_create(struct sxe2_vf_node *vf)
{
	s32 ret;
	struct sxe2_vf_repr *repr;
	struct sxe2_adapter *adapter = vf->adapter;

	repr = kzalloc(sizeof(*repr), GFP_KERNEL);
	if (!repr) {
		LOG_ERROR_BDF("vf:%u repr malloc failed.\n", vf->vf_idx);
		return -ENOMEM;
	}
	vf->repr = repr;

	repr->irq_data = kzalloc(sizeof(*repr->irq_data), GFP_KERNEL);
	if (!repr->irq_data) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("vf:%u repr irq data alloc failed.\n", vf->vf_idx);
		goto l_repr_free;
	}

	ret = sxe2_repr_netdev_init(vf);
	if (ret)
		goto l_irq_free;

	ret = sxe2_repr_netdev_register(vf);
	if (ret) {
		LOG_ERROR_BDF("vf:%u representor netdev register failed.(err:%d)\n",
			      vf->vf_idx, ret);
		goto l_netdev_free;
	}

	vf->msg_table = sxe2_esw_mbx_msg_table_get();

	LOG_INFO_BDF("vf:%u repr:%pK netdev:%pK name:%s.\n", vf->vf_idx, repr,
		     repr->netdev, repr->netdev->name);

	return ret;

l_netdev_free:
	free_netdev(repr->netdev);
	repr->netdev = NULL;

l_irq_free:
	kfree(repr->irq_data);
	repr->irq_data = NULL;

l_repr_free:
	kfree(repr);
	vf->repr = NULL;
	return ret;
}

STATIC void __sxe2_vf_repr_destroy(struct sxe2_vf_node *vf)
{
	struct sxe2_vf_repr *repr = vf->repr;
	struct net_device *netdev = repr->netdev;

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	unregister_netdev(netdev);

	free_netdev(netdev);
	kfree(repr->irq_data);
	repr->irq_data = NULL;
	kfree(repr);
	vf->repr = NULL;
}

STATIC void sxe2_vf_repr_destroy(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf_node;
	u16 idx;

	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	sxe2_for_each_vf(adapter, idx)
	{
		vf_node = SXE2_VF_NODE(adapter, idx);
		if (vf_node->repr)
			__sxe2_vf_repr_destroy(vf_node);
	}
}

static s32 sxe2_vf_repr_create(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf_node;
	u16 idx;
	s32 ret;

	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	sxe2_for_each_vf(adapter, idx)
	{
		vf_node = SXE2_VF_NODE(adapter, idx);
		ret = __sxe2_vf_repr_create(vf_node);
		if (ret) {
			LOG_ERROR_BDF("vf:%u repr create failed.\n", idx);
			goto l_err;
		}
	}

	return 0;

l_err:
	sxe2_vf_repr_destroy(adapter);
	return ret;
}

s32 sxe2_vf_sp_rule_add(struct sxe2_vf_node *vf_node, bool is_user)
{
	return sxe2_eswitch_vf_slow_path_rule_setup(vf_node, is_user, true);
}

s32 sxe2_vf_sp_rule_del(struct sxe2_vf_node *vf_node, bool is_user)
{
	return sxe2_eswitch_vf_slow_path_rule_setup(vf_node, is_user, false);
}

void sxe2_vf_repr_decfg(struct sxe2_vf_node *vf_node)
{
	struct sxe2_vf_repr *repr;

	repr = vf_node->repr;

	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, vf_node->adapter->flags))
		return;

	if (!repr->dst)
		return;

	(void)sxe2_vf_sp_rule_del(vf_node, false);
	netif_napi_del(&repr->irq_data->napi);
	metadata_dst_free(repr->dst);
	repr->dst = NULL;
}

void sxe2_vfs_repr_decfg(struct sxe2_adapter *adapter)
{
	u16 idx;
	struct sxe2_vf_node *vf_node;

	sxe2_for_each_vf(adapter, idx)
	{
		(void)mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
		vf_node = sxe2_vf_node_get(adapter, idx);
		sxe2_vf_repr_decfg(vf_node);
		(void)mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
	}
}

#ifdef HAVE_METADATA_PORT_INFO
static s32 sxe2_vf_repr_cfg(struct sxe2_vf_node *vf_node)
{
	s32 ret;
	struct sxe2_vf_repr *repr;
	struct sxe2_adapter *adapter;

	adapter = vf_node->adapter;

	repr = vf_node->repr;
	repr->dst = metadata_dst_alloc(0, METADATA_HW_PORT_MUX, GFP_KERNEL);
	if (!repr->dst) {
		ret = -ENOMEM;
		LOG_DEV_ERR("metadata dst alloc failed.\n");
		goto l_err;
	}

	ret = sxe2_vf_sp_rule_add(vf_node, false);
	if (ret && (ret != -EEXIST)) {
		metadata_dst_free(repr->dst);
		repr->dst = NULL;
		LOG_DEV_ERR("slow path rule add failed.(err:%d)\n", ret);
		goto l_err;
	}

	vf_node->prop.spoofchk = false;

	netif_napi_add(repr->netdev, &repr->irq_data->napi, sxe2_esw_napi_poll,
		       NAPI_POLL_WEIGHT);
	netif_keep_dst(repr->netdev);

	repr->dst->u.port_info.port_id = repr->vf_node->vsi_id[SXE2_VF_TYPE_ETH];
	repr->dst->u.port_info.lower_dev = repr->netdev;

	return 0;

l_err:
	sxe2_vf_repr_decfg(vf_node);
	return ret;
}

static s32 sxe2_vfs_repr_cfg(struct sxe2_adapter *adapter)
{
	u16 idx;
	struct sxe2_vf_node *vf_node;
	s32 ret = 0;

	sxe2_for_each_vf(adapter, idx)
	{
		(void)mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
		vf_node = sxe2_vf_node_get(adapter, idx);
		ret = sxe2_vf_repr_cfg(vf_node);
		if (ret) {
			(void)mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
			goto l_end;
		}
		(void)mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
	}

	return ret;

l_end:
	sxe2_vfs_repr_decfg(adapter);

	return ret;
}
#else
static s32 sxe2_vfs_repr_cfg(struct sxe2_adapter *adapter)
{
	return -ENODEV;
}
#endif

static void sxe2_eswitch_irq_queues_map(struct sxe2_adapter *adapter)
{
	u16 i;
	struct sxe2_irq_data *irq_data;
	struct sxe2_queue *txq;
	struct sxe2_queue *rxq;
	struct sxe2_vf_node *vf;
	struct sxe2_vsi *esw_vsi = adapter->eswitch_ctxt.esw_vsi;

	sxe2_for_each_vsi_txq(esw_vsi, i)
	{
		vf = SXE2_VF_NODE(adapter, i);
		if (!vf) {
			LOG_WARN_BDF("vf:%u has freed.\n", i);
			continue;
		}

		irq_data = vf->repr->irq_data;
		irq_data->vsi = esw_vsi;
		irq_data->idx_in_pf = esw_vsi->irqs.irq_data[0]->idx_in_pf;
		irq_data->tx.list.next = esw_vsi->txqs.q[i];
		irq_data->tx.list.next->next = NULL;
		irq_data->tx.itr_idx = esw_vsi->irqs.irq_data[0]->tx.itr_idx;

		txq = esw_vsi->txqs.q[i];
		txq->idx_in_vsi = 0;
		txq->irq_data = irq_data;
		txq->netdev = vf->repr->netdev;

		LOG_DEBUG_BDF("eswitch irq map, vf %d, irq in pf %d, txq in pf %d\n",
			      i, irq_data->idx_in_pf, txq->idx_in_pf);
	}

	sxe2_for_each_vsi_rxq(esw_vsi, i)
	{
		vf = SXE2_VF_NODE(adapter, i);
		if (!vf) {
			LOG_WARN_BDF("vf:%u has freed.\n", i);
			continue;
		}

		irq_data = vf->repr->irq_data;
		irq_data->vsi = esw_vsi;
		irq_data->idx_in_pf = esw_vsi->irqs.irq_data[0]->idx_in_pf;
		irq_data->rx.list.next = esw_vsi->rxqs.q[i];
		irq_data->rx.list.next->next = NULL;
		irq_data->rx.itr_idx = esw_vsi->irqs.irq_data[0]->rx.itr_idx;

		rxq = esw_vsi->rxqs.q[i];
		rxq->idx_in_vsi = 0;
		rxq->irq_data = irq_data;
		rxq->netdev = vf->repr->netdev;

		LOG_DEBUG_BDF("eswitch irq map, vf %d, irq in pf %d, rxq in pf %d\n",
			      i, irq_data->idx_in_pf, rxq->idx_in_pf);
	}
}

static s32 sxe2_eswitch_offload_enable(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_eswitch_context *eswitch = &adapter->eswitch_ctxt;

	eswitch->adapter = adapter;

	set_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags);

	ret = sxe2_eswitch_vsi_create(adapter);
	if (ret) {
		LOG_ERROR_BDF("eswitch vsi create failed.(err:%d)\n", ret);
		clear_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags);
		return ret;
	}

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK) {
		ret = sxe2_uplink_vsi_cfg_to_switchdev(adapter);
		if (ret)
			goto l_uplink_setup;
	}

	ret = sxe2_vf_repr_create(adapter);
	if (ret)
		goto l_uplink_setup;

	ret = sxe2_vfs_repr_cfg(adapter);
	if (ret)
		goto l_repr_destroy;

	sxe2_eswitch_irq_queues_map(adapter);

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2_vsi_open(eswitch->esw_vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (ret) {
		LOG_ERROR_BDF("eswitch vsi[%u][%u] open failed.(err:%d)\n",
			      eswitch->esw_vsi->id_in_pf,
			      eswitch->esw_vsi->idx_in_dev, ret);
		goto l_vsi_open_fail;
	}

	return ret;

l_vsi_open_fail:
	sxe2_vfs_repr_decfg(adapter);

l_repr_destroy:
	sxe2_vf_repr_destroy(adapter);

l_uplink_setup:
	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK)
		sxe2_uplink_vsi_cfg_to_legacy(adapter);

	sxe2_eswitch_vsi_destroy(adapter);

	clear_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags);

	return -ENODEV;
}

static s32 sxe2_eswitch_offload_disable(struct sxe2_adapter *adapter)
{
	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags))
		return 0;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (!test_bit(SXE2_VSI_S_CLOSE, adapter->eswitch_ctxt.esw_vsi->state))
		(void)sxe2_vsi_close(adapter->eswitch_ctxt.esw_vsi);

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_KERNEL &&
	    !test_bit(SXE2_VSI_S_CLOSE, adapter->eswitch_ctxt.user_esw_vsi->state)) {
		(void)sxe2_vsi_close(adapter->eswitch_ctxt.user_esw_vsi);
	}

	mutex_unlock(&adapter->vsi_ctxt.lock);

	sxe2_vfs_repr_decfg(adapter);

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK) {
		sxe2_vsi_complex_fltr_remove(adapter,
					     adapter->vsi_ctxt.main_vsi->idx_in_dev,
					     false);
	}

	sxe2_vf_repr_destroy(adapter);

	clear_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags);

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK)
		sxe2_uplink_vsi_cfg_to_legacy(adapter);

	sxe2_eswitch_vsi_destroy(adapter);

	return 0;
}

s32 sxe2_eswitch_configure(struct sxe2_adapter *adapter, bool enable)
{
	s32 ret = 0;

	if (enable)
		ret = sxe2_eswitch_offload_enable(adapter);
	else
		ret = sxe2_eswitch_offload_disable(adapter);

	if (ret)
		LOG_ERROR_BDF("eswitch offload %s failed.(err:%d)\n",
			      enable ? "enable" : "disable", ret);
	return ret;
}

irqreturn_t sxe2_eswitch_msix_ring_irq_handler(int __always_unused irq, void *data)
{
	struct sxe2_irq_data *irq_data = (struct sxe2_irq_data *)data;
	struct sxe2_adapter *adapter = irq_data->vsi->adapter;
	struct sxe2_vf_node *vf;
	u16 vf_idx;

	if (!SXE2_IRQ_HAS_TXQ(irq_data) && !SXE2_IRQ_HAS_RXQ(irq_data))
		return IRQ_HANDLED;

	sxe2_for_each_vf(adapter, vf_idx)
	{
		vf = SXE2_VF_NODE(adapter, vf_idx);
		napi_schedule(&vf->repr->irq_data->napi);
	}

	return IRQ_HANDLED;
}

bool sxe2_is_repr_netdev(struct net_device *netdev)
{
	return netdev && (netdev->netdev_ops == &sxe2_repr_netdev_ops);
}

void sxe2_eswitch_txqs_stop(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf;
	u16 idx;

	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	sxe2_for_each_vf(adapter, idx)
	{
		vf = SXE2_VF_NODE(adapter, idx);
		if (vf->repr) {
			netif_carrier_off(vf->repr->netdev);
			netif_tx_disable(vf->repr->netdev);
		}
	}
}

bool sxe2_eswitch_is_offload(struct sxe2_adapter *adapter)
{
	return adapter->eswitch_ctxt.mode == DEVLINK_ESWITCH_MODE_SWITCHDEV;
}

void sxe2_vf_repr_rebuild(struct sxe2_vsi *vsi, bool is_vfr_vflr)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vf_repr *repr;
	struct sxe2_vf_node *vf_node;

	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags))
		return;

	if (!is_vfr_vflr) {
		LOG_INFO_BDF("vsi[%u][%u] pfr/pflr skip.\n", vsi->id_in_pf,
			     vsi->idx_in_dev);
		return;
	}

	vf_node = vsi->vf_node;
	repr = vf_node->repr;
	repr->src_vsi = vsi;
#ifdef HAVE_METADATA_PORT_INFO
	repr->dst->u.port_info.port_id = vsi->idx_in_dev;
#endif
}

static void sxe2_eswitch_txqs_start(struct sxe2_adapter *adapter)
{
	u16 vf_idx;
	struct sxe2_vf_node *vf;

	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	sxe2_for_each_vf(adapter, vf_idx)
	{
		vf = SXE2_VF_NODE(adapter, vf_idx);
		if (vf->repr && netif_running(vf->repr->netdev)) {
			netif_carrier_on(vf->repr->netdev);
			netif_tx_start_all_queues(vf->repr->netdev);
		}
	}
}

void sxe2_eswitch_stop(struct sxe2_adapter *adapter)
{
	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags))
		return;

	if (sxe2_vsi_close(adapter->eswitch_ctxt.esw_vsi))
		LOG_ERROR_BDF("eswitch vsi close failed.\n");
}

s32 sxe2_eswitch_rebuild(struct sxe2_adapter *adapter)
{
	struct sxe2_eswitch_context *esw_ctxt = &adapter->eswitch_ctxt;
	s32 ret;

	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags))
		return 0;

	ret = sxe2_sriov_vsi_rebuild(esw_ctxt->esw_vsi, false);
	if (ret) {
		LOG_ERROR_BDF("eswitch vsi rebuild failed.(err:%d)\n", ret);
		goto l_end;
	}

	ret = sxe2_uplink_vsi_cfg_to_switchdev(adapter);
	if (ret) {
		LOG_ERROR_BDF("uplink vsi promisc enable failed.\n");
		goto l_end;
	}

	ret = sxe2_vfs_repr_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("vf repr cfg failed.\n");
		goto l_end;
	}

	ret = sxe2_vfs_complex_fltr_restore(adapter);
	if (ret) {
		LOG_ERROR_BDF("vfs complex fltr restore failed.\n");
		goto l_end;
	}

	ret = sxe2_pf_complex_fltr_restore(adapter);
	if (ret) {
		LOG_ERROR_BDF("pf complex fltr restore failed.\n");
		goto l_end;
	}

	sxe2_eswitch_irq_queues_map(adapter);

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2_vsi_open(esw_ctxt->esw_vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (ret) {
		LOG_ERROR_BDF("eswitch vsi[%u][%u] open failed.(err:%d)\n",
			      esw_ctxt->esw_vsi->id_in_pf,
			      esw_ctxt->esw_vsi->idx_in_dev, ret);
		goto l_end;
	}

	sxe2_eswitch_txqs_start(adapter);

l_end:
	return ret;
}

s32 sxe2_eswitch_mode_write_try_lock(struct sxe2_adapter *adapter)
{
	set_bit(SXE2_ESWITCH_MODE_CHANGING, &adapter->eswitch_ctxt.flag);
	if (atomic64_read(&adapter->eswitch_ctxt.mode_ref_cnt) > 0)
		return -EBUSY;

	return 0;
}

void sxe2_eswitch_mode_rwlock_init(struct sxe2_adapter *adapter)
{
	atomic64_set(&adapter->eswitch_ctxt.mode_ref_cnt, 0);
}

void sxe2_eswitch_mode_write_unlock(struct sxe2_adapter *adapter)
{
	clear_bit(SXE2_ESWITCH_MODE_CHANGING, &adapter->eswitch_ctxt.flag);
}

s32 sxe2_eswitch_mode_read_lock(struct sxe2_adapter *adapter)
{
	s32 retry = SXE2_ESWITCH_MODE_TIMEOUT;

	atomic64_inc(&adapter->eswitch_ctxt.mode_ref_cnt);

	while (retry--) {
		if (!test_bit(SXE2_ESWITCH_MODE_CHANGING,
			      &adapter->eswitch_ctxt.flag))
			break;
		usleep_range(1000, 1200);
	}
	if (retry <= 0)
		return -EBUSY;

	return 0;
}

void sxe2_eswitch_mode_read_unlock(struct sxe2_adapter *adapter)
{
	atomic64_dec(&adapter->eswitch_ctxt.mode_ref_cnt);
}

s32 sxe2_eswitch_ucmd_uplink_set(struct sxe2_adapter *adapter, bool to_user)
{
	s32 ret = 0;
	struct sxe2_eswitch_context *eswitch = &adapter->eswitch_ctxt;
	struct sxe2_vsi *user_pf_vsi;
	struct sxe2_vsi *ker_pf_vsi;

	if (sxe2_eswitch_mode_read_lock(adapter)) {
		ret = -EBUSY;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);

	ker_pf_vsi = adapter->vsi_ctxt.main_vsi;
	user_pf_vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_PF);
	if (!user_pf_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_vsi_unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, ker_pf_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, user_pf_vsi->state)) {
		ret = -EBUSY;
		goto l_vsi_unlock;
	}

	if (to_user && eswitch->uplink_vsi->type == SXE2_VSI_T_DPDK_PF) {
		LOG_WARN_BDF("current uplink vsi is user, no neet to set.\n");
		goto l_vsi_unlock;
	} else if (!to_user && eswitch->uplink_vsi->type == SXE2_VSI_T_PF) {
		LOG_WARN_BDF("current uplink vsi is kernel, no neet to set.\n");
		goto l_vsi_unlock;
	} else if (!sxe2_eswitch_is_offload(adapter)) {
		LOG_ERROR_BDF("eswitch mode is not switchdev, not support.\n");
		ret = -EOPNOTSUPP;
		goto l_vsi_unlock;
	} else if (!sxe2_vf_is_exist(adapter)) {
		LOG_ERROR_BDF("VF count is 0, not support.\n");
		ret = -EOPNOTSUPP;
		goto l_vsi_unlock;
	}

	if (to_user) {
		ret = sxe2_promisc_rule_del(adapter, ker_pf_vsi->idx_in_dev);
		if (ret && ret != -ENOENT)
			goto l_vsi_unlock;

		ret = sxe2_promisc_rule_add(user_pf_vsi);
		if (ret && ret != -EEXIST)
			goto l_to_uesr_failed;

		adapter->eswitch_ctxt.uplink_vsi = user_pf_vsi;
		goto l_vsi_unlock;
	} else {
		ret = sxe2_promisc_rule_del(adapter, user_pf_vsi->idx_in_dev);
		if (ret && ret != -ENOENT)
			goto l_vsi_unlock;

		ret = sxe2_promisc_rule_add(ker_pf_vsi);
		if (ret && ret != -EEXIST)
			goto l_to_kernel_failed;

		adapter->eswitch_ctxt.uplink_vsi = ker_pf_vsi;
		goto l_vsi_unlock;
	}

l_to_uesr_failed:
	(void)sxe2_promisc_rule_add(ker_pf_vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	sxe2_eswitch_mode_read_unlock(adapter);
	return ret;

l_to_kernel_failed:
	(void)sxe2_promisc_rule_add(user_pf_vsi);

l_vsi_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
l_end:
	sxe2_eswitch_mode_read_unlock(adapter);
	return ret;
}

s32 sxe2_eswitch_ucmd_uplink_resetto_ker(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_eswitch_context *eswitch = &adapter->eswitch_ctxt;
	struct sxe2_vsi *user_pf_vsi;
	struct sxe2_vsi *ker_pf_vsi;

	ker_pf_vsi = adapter->vsi_ctxt.main_vsi;
	user_pf_vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_PF);
	if (!user_pf_vsi) {
		LOG_ERROR_BDF("user PF vsi is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, ker_pf_vsi->state) ||
	    test_bit(SXE2_VSI_S_DISABLE, user_pf_vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (eswitch->uplink_vsi->type == SXE2_VSI_T_PF) {
		LOG_WARN_BDF("current uplink vsi is kernel, no neet to set.\n");
		goto l_end;
	}

	ret = sxe2_promisc_rule_del(adapter, user_pf_vsi->idx_in_dev);
	if (ret && ret != -ENOENT)
		goto l_end;

	ret = sxe2_promisc_rule_add(ker_pf_vsi);
	if (ret && ret != -EEXIST)
		goto l_to_kernel_failed;

	adapter->eswitch_ctxt.uplink_vsi = ker_pf_vsi;
	return ret;

l_to_kernel_failed:
	(void)sxe2_promisc_rule_add(user_pf_vsi);

l_end:
	return ret;
}

s32 sxe2_eswitch_ucmd_mode_get(struct sxe2_adapter *adapter, bool *is_switchdev)
{
	s32 ret = 0;

	if (sxe2_eswitch_mode_read_lock(adapter)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (sxe2_eswitch_is_offload(adapter) && sxe2_vf_is_exist(adapter))
		*is_switchdev = true;
	else
		*is_switchdev = false;

l_end:
	sxe2_eswitch_mode_read_unlock(adapter);
	return ret;
}

s32 sxe2_eswitch_ucmd_eswvsi_get(struct sxe2_adapter *adapter, u16 *user_esw_vsi_id)
{
	s32 ret = 0;

	if (sxe2_eswitch_mode_read_lock(adapter)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (adapter->eswitch_ctxt.user_esw_vsi)
		*user_esw_vsi_id = adapter->eswitch_ctxt.user_esw_vsi->idx_in_dev;

l_end:
	sxe2_eswitch_mode_read_unlock(adapter);
	return ret;
}

s32 sxe2_eswitch_ucmd_repr_cfg(struct sxe2_vf_node *vf_node, bool is_to_user)
{
	s32 ret = 0;
	u16 vf_vsi_id;
	u16 vf_vsi_id_u;
	struct sxe2_vsi *esw_vsi;
	struct sxe2_vsi *esw_vsi_u;
	u16 qid_in_vsi;
	struct sxe2_vf_repr_cfg repr_cfg = {0};
	struct sxe2_adapter *adapter = vf_node->adapter;

	vf_vsi_id = vf_node->vsi_id[SXE2_VF_TYPE_ETH];
	vf_vsi_id_u = vf_node->vsi_id[SXE2_VF_TYPE_DPDK];

	mutex_lock(&vf_node->repr_cfg_lock);

	if (is_to_user && vf_node->user_repr_valid) {
		LOG_WARN_BDF("current repr is user, no neet to set,\t"
			     "user_vf_vsi_id[%u], ker_vf_vsi_id[%u]\n",
			     vf_vsi_id, vf_vsi_id_u);
		goto l_end;
	} else if (!is_to_user && !vf_node->user_repr_valid) {
		LOG_WARN_BDF("current repr is kernel, no neet to set,\t"
			     "user_vf_vsi_id[%u], ker_vf_vsi_id[%u]\n",
			     vf_vsi_id, vf_vsi_id_u);
		goto l_end;
	}

	esw_vsi_u = vf_node->adapter->eswitch_ctxt.user_esw_vsi;
	esw_vsi = vf_node->adapter->eswitch_ctxt.esw_vsi;

	qid_in_vsi = vf_node->vf_idx;
	repr_cfg.queue_in_dev = esw_vsi->rxqs.q[qid_in_vsi]->idx_in_pf +
				vf_node->adapter->q_ctxt.rxq_base_idx_in_dev;
	repr_cfg.queue_in_dev_u = esw_vsi_u->rxqs.q[qid_in_vsi]->idx_in_pf +
				  vf_node->adapter->q_ctxt.rxq_base_idx_in_dev;
	repr_cfg.cfg_to_user = is_to_user;

	LOG_DEBUG_BDF("vf_idx:%u, queue_in_dev:%u, queue_in_dev_u:%u,\t"
		      "cfg_to_user:%u\n",
		      vf_node->vf_idx, repr_cfg.queue_in_dev,
		      repr_cfg.queue_in_dev_u, repr_cfg.cfg_to_user);

	ret = sxe2_eswitch_vf_slow_path_rule_update(vf_node->adapter, vf_vsi_id,
						    &repr_cfg);
	if (ret) {
		LOG_ERROR_BDF("kernel vf slow path update failed,\t"
			      "ker_vf_vsi_id[%u]\n",
			      vf_vsi_id);
		goto l_end;
	}

	ret = sxe2_eswitch_vf_slow_path_rule_update(vf_node->adapter, vf_vsi_id_u,
						    &repr_cfg);
	if (ret) {
		LOG_ERROR_BDF("user vf slow path update failed,\t"
			      "user_vf_vsi_id[%u]\n",
			      vf_vsi_id_u);
		goto l_reback;
	}
	vf_node->user_repr_valid = is_to_user;
	goto l_end;

l_reback:
	repr_cfg.cfg_to_user = !is_to_user;
	(void)sxe2_eswitch_vf_slow_path_rule_update(vf_node->adapter, vf_vsi_id,
						    &repr_cfg);
l_end:
	mutex_unlock(&vf_node->repr_cfg_lock);
	return ret;
}
