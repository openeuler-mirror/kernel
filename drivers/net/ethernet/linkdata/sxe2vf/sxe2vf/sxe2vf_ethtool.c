// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_ethtool.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#ifdef HAVE_SCTP
#include <linux/sctp.h>
#endif
#include <linux/ip.h>
#ifndef SXE2_KERNEL_TEST
#include <linux/ipv6.h>
#endif

#include "sxe2_compat.h"
#include "sxe2vf.h"
#include "sxe2vf_ethtool.h"
#include "sxe2_log.h"
#include "sxe2_version.h"
#include "sxe2vf_vsi.h"
#include "sxe2vf_rxft.h"
#include "sxe2_cmd.h"

#define SXE2VF_COALESCE_QIDX_INVAL 0xFFFFFFFF
#define SXE2VF_VSI_TX_QC(vsi, q_idx) (&(vsi)->txqs.q[(q_idx)]->irq_data->tx)
#define SXE2VF_VSI_RX_QC(vsi, q_idx) (&(vsi)->rxqs.q[(q_idx)]->irq_data->rx)
#define SXE2VF_VSI_TX_IRQ(vsi, q_idx) (&(vsi)->txqs.q[(q_idx)]->irq_data)
#define SXE2VF_VSI_RX_IRQ(vsi, q_idx) (&(vsi)->rxqs.q[(q_idx)]->irq_data)

#define ETHTOOL_GRXRINGS 0x0000002d
#define SXE2VF_Q_TYPE_STR_RX "rx"
#define SXE2VF_Q_TYPE_STR_TX "tx"

static void sxe2_vf_vsi_hw_stats_update(struct sxe2vf_adapter *adapter)
{
	(void)sxe2vf_stats_get_msg_send(adapter);
}

s32 sxe2vf_stats_push_sync(struct sxe2vf_adapter *adapter)
{
	return sxe2vf_stats_push_msg_send(adapter);
}

STATIC void sxe2vf_fetch_u64_data_per_ring(struct u64_stats_sync *syncp,
					   struct sxe2vf_queue_stats *stats,
					   u64 *pkts, u64 *bytes)
{
	u32 start;

	do {
		start = u64_stats_fetch_begin(syncp);
		*pkts = stats->packets;
		*bytes = stats->bytes;
	} while (u64_stats_fetch_retry(syncp, start));
}

void sxe2vf_vsi_sw_stats_update(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_vsi_sw_stats cur_stats;
	struct sxe2vf_vsi_qs_stats *vsi_qs_stats = &vsi->vsi_qs_stats;
	struct sxe2vf_queue_stats *txq_stats, *rxq_stats;
	u64 pkts, bytes;
	u8 j;

	memset(&cur_stats, 0, sizeof(cur_stats));

	sxe2vf_for_each_vsi_txq(vsi, j)
	{
		txq_stats = &vsi_qs_stats->txqs_stats[j];
		sxe2vf_fetch_u64_data_per_ring(&txq_stats->syncp, txq_stats, &pkts,
					       &bytes);
		cur_stats.tx_packets += pkts;
		cur_stats.tx_bytes += bytes;
		cur_stats.tx_restart += txq_stats->tx_stats.tx_restart;
		cur_stats.tx_busy += txq_stats->tx_stats.tx_busy;
		cur_stats.tx_linearize += txq_stats->tx_stats.tx_linearize;
		cur_stats.tx_vlan_insert += txq_stats->tx_stats.tx_vlan_insert;
		cur_stats.tx_tso_packets += txq_stats->tx_stats.tx_tso_packets;
		cur_stats.tx_tso_bytes += txq_stats->tx_stats.tx_tso_bytes;
		cur_stats.tx_csum_none += txq_stats->tx_stats.tx_csum_none;
		cur_stats.tx_csum_partial += txq_stats->tx_stats.tx_csum_partial;
		cur_stats.tx_csum_partial_inner +=
				txq_stats->tx_stats.tx_csum_partial_inner;
		cur_stats.tx_queue_dropped += txq_stats->tx_stats.tx_queue_dropped;
		cur_stats.tx_xmit_more += txq_stats->tx_stats.tx_xmit_more;
		cur_stats.tx_tso_linearize_chk +=
				txq_stats->tx_stats.tx_tso_linearize_chk;
	}

	sxe2vf_for_each_vsi_rxq(vsi, j)
	{
		rxq_stats = &vsi_qs_stats->rxqs_stats[j];
		sxe2vf_fetch_u64_data_per_ring(&rxq_stats->syncp, rxq_stats, &pkts,
					       &bytes);
		cur_stats.rx_packets += pkts;
		cur_stats.rx_bytes += bytes;
		cur_stats.rx_buff_alloc_err += rxq_stats->rx_stats.rx_buff_alloc_err;
		cur_stats.rx_pg_alloc_fail += rxq_stats->rx_stats.rx_pg_alloc_fail;
		cur_stats.rx_lro_count += rxq_stats->rx_stats.rx_lro_count;
		cur_stats.rx_lro_packets += rxq_stats->rx_stats.rx_lro_packets;
		cur_stats.rx_vlan_strip += rxq_stats->rx_stats.rx_vlan_strip;
		cur_stats.rx_csum_err += rxq_stats->rx_stats.rx_csum_err;
		cur_stats.rx_csum_unnecessary +=
				rxq_stats->rx_stats.rx_csum_unnecessary;
		cur_stats.rx_csum_none += rxq_stats->rx_stats.rx_csum_none;
		cur_stats.rx_csum_complete += rxq_stats->rx_stats.rx_csum_complete;
		cur_stats.rx_csum_unnecessary_inner +=
				rxq_stats->rx_stats.rx_csum_unnecessary_inner;
		cur_stats.rx_lro_bytes += rxq_stats->rx_stats.rx_lro_bytes;
		cur_stats.rx_pkts_sw_drop += rxq_stats->rx_stats.rx_pkts_sw_drop;
		cur_stats.rx_page_alloc += rxq_stats->rx_stats.rx_page_alloc;
		cur_stats.rx_non_eop_descs += rxq_stats->rx_stats.rx_non_eop_descs;
		cur_stats.rx_pa_err += rxq_stats->rx_stats.rx_pa_err;
	}

	memcpy(&vsi->vsi_stats.vsi_sw_stats, &cur_stats, sizeof(cur_stats));
}

static void sxe2vf_get_ethtool_stats(struct net_device *netdev,
				     struct ethtool_stats *stats, u64 *data)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	u32 i = 0;
	struct sxe2vf_queue *tx_q, *rx_q;
	u64 pkts, bytes;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	u8 j;

	struct sxe2_vf_vsi_hw_stats *hw_stats = &vsi->vsi_stats.vsi_hw_stats;
	struct sxe2vf_vsi_sw_stats *sw_stats = &vsi->vsi_stats.vsi_sw_stats;

	u64 rx_offload_success = 0;
	u64 rx_error_decrypt_fail = 0;
	u64 rx_error_invalid_state = 0;
	u64 rx_error_invalid_sp = 0;
	u64 tx_offload_success = 0;
	u64 tx_error_invalid_state = 0;
	u64 tx_error_invalid_sp = 0;

	char *p;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state))
		goto l_unlock;

	sxe2vf_vsi_sw_stats_update(vsi);
	sxe2_vf_vsi_hw_stats_update(adapter);

	for (j = 0; j < SXE2VF_VSI_SW_STATS_LEN; j++) {
		p = (char *)sw_stats + sxe2vf_gstrings_vsi_sw_stats[j].stats_offset;
		data[i++] = *(u64 *)p;
	}

	for (j = 0; j < SXE2VF_VSI_HW_STATS_LEN; j++) {
		p = (char *)hw_stats + sxe2vf_gstrings_vsi_hw_stats[j].stats_offset;
		data[i++] = *(u64 *)p;
	}

	sxe2vf_for_each_vsi_txq(vsi, j)
	{
		tx_q = READ_ONCE(vsi->txqs.q[j]);
		sxe2vf_fetch_u64_data_per_ring(&tx_q->syncp, tx_q->stats, &pkts,
					       &bytes);
		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = tx_q->stats->tx_stats.tx_tso_packets;
		data[i++] = tx_q->stats->tx_stats.tx_tso_bytes;
		data[i++] = tx_q->stats->tx_stats.tx_tso_linearize_chk;
		data[i++] = tx_q->stats->tx_stats.tx_vlan_insert;
		data[i++] = tx_q->stats->tx_stats.tx_csum_none;
		data[i++] = tx_q->stats->tx_stats.tx_csum_partial;
		data[i++] = tx_q->stats->tx_stats.tx_csum_partial_inner;
		data[i++] = tx_q->stats->tx_stats.tx_busy;
		data[i++] = tx_q->stats->tx_stats.tx_queue_dropped;
		data[i++] = tx_q->stats->tx_stats.tx_xmit_more;
		data[i++] = tx_q->stats->tx_stats.tx_restart;
		data[i++] = tx_q->stats->tx_stats.tx_linearize;
	}

	sxe2vf_for_each_vsi_rxq(vsi, j)
	{
		rx_q = READ_ONCE(vsi->rxqs.q[j]);
		sxe2vf_fetch_u64_data_per_ring(&rx_q->syncp, rx_q->stats, &pkts,
					       &bytes);
		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = rx_q->stats->rx_stats.rx_csum_unnecessary;
		data[i++] = rx_q->stats->rx_stats.rx_csum_none;
		data[i++] = rx_q->stats->rx_stats.rx_csum_complete;
		data[i++] = rx_q->stats->rx_stats.rx_csum_unnecessary_inner;
		data[i++] = rx_q->stats->rx_stats.rx_csum_err;
		data[i++] = rx_q->stats->rx_stats.rx_lro_packets;
		data[i++] = rx_q->stats->rx_stats.rx_lro_bytes;
		data[i++] = rx_q->stats->rx_stats.rx_lro_count;
		data[i++] = rx_q->stats->rx_stats.rx_vlan_strip;
		data[i++] = rx_q->stats->rx_stats.rx_pkts_sw_drop;
		data[i++] = rx_q->stats->rx_stats.rx_buff_alloc_err;
		data[i++] = rx_q->stats->rx_stats.rx_pg_alloc_fail;
		data[i++] = rx_q->stats->rx_stats.rx_page_alloc;
		data[i++] = rx_q->stats->rx_stats.rx_non_eop_descs;
		data[i++] = rx_q->stats->rx_stats.rx_pa_err;
	}

	sxe2vf_for_each_vsi_rxq(vsi, j)
	{
		rx_q = READ_ONCE(vsi->rxqs.q[j]);
		rx_offload_success += rx_q->stats->ipsec_stats.rx_offload_success;
		rx_error_decrypt_fail +=
				rx_q->stats->ipsec_stats.rx_error_decrypt_fail;
		rx_error_invalid_state +=
				rx_q->stats->ipsec_stats.rx_error_invalid_state;
		rx_error_invalid_sp += rx_q->stats->ipsec_stats.rx_error_invalid_sp;
	}
	data[i++] = rx_offload_success;
	data[i++] = rx_error_decrypt_fail;
	data[i++] = rx_error_invalid_state;
	data[i++] = rx_error_invalid_sp;

	sxe2vf_for_each_vsi_txq(vsi, j)
	{
		tx_q = READ_ONCE(vsi->txqs.q[j]);
		tx_offload_success += tx_q->stats->ipsec_stats.tx_offload_success;
		tx_error_invalid_state +=
				tx_q->stats->ipsec_stats.tx_error_invalid_state;
		tx_error_invalid_sp += tx_q->stats->ipsec_stats.tx_error_invalid_sp;
	}
	data[i++] = tx_offload_success;
	data[i++] = tx_error_invalid_state;
	data[i++] = tx_error_invalid_sp;

	data[i++] = adapter->fnav_ctxt.fnav_match;

l_unlock:
	(void)i;
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

STATIC int sxe2vf_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return (int)SXE2VF_ALL_STATS_LEN(netdev);
	case ETH_SS_PRIV_FLAGS:
		return SXE2VF_PRIV_FLAG_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

STATIC void sxe2vf_get_ipsec_strings(struct sxe2vf_adapter *adapter, u8 **data)
{
	u8 *p;

	if (!data)
		return;

	p = *data;

	ethtool_sprintf(&p, "ipsec_rx_offload_ok");
	ethtool_sprintf(&p, "ipsec_rx_decrypt_fail");
	ethtool_sprintf(&p, "ipsec_rx_invalid_state");
	ethtool_sprintf(&p, "ipsec_rx_invalid_sp");

	ethtool_sprintf(&p, "ipsec_tx_offload_ok");
	ethtool_sprintf(&p, "ipsec_tx_invalid_state");
	ethtool_sprintf(&p, "ipsec_tx_invalid_sp");

	*data = p;
}

STATIC void sxe2vf_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	u32 i;
	u8 *p = data;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < SXE2VF_VSI_SW_STATS_LEN; i++)
			ethtool_sprintf(&p, sxe2vf_gstrings_vsi_sw_stats[i]
							    .stats_string);
		for (i = 0; i < SXE2VF_VSI_HW_STATS_LEN; i++)
			ethtool_sprintf(&p, sxe2vf_gstrings_vsi_hw_stats[i]
							    .stats_string);

		sxe2vf_for_each_vsi_txq(vsi, i)
		{
			ethtool_sprintf(&p, "tx%u_packets", i);
			ethtool_sprintf(&p, "tx%u_bytes", i);
			ethtool_sprintf(&p, "tx%u_tso_packets", i);
			ethtool_sprintf(&p, "tx%u_tso_bytes", i);
			ethtool_sprintf(&p, "tx%u_tso_linearize_chk", i);
			ethtool_sprintf(&p, "tx%u_added_vlan_packets", i);
			ethtool_sprintf(&p, "tx%u_csum_none", i);
			ethtool_sprintf(&p, "tx%u_csum_partial", i);
			ethtool_sprintf(&p, "tx%u_csum_partial_inner", i);
			ethtool_sprintf(&p, "tx%u_stopped", i);
			ethtool_sprintf(&p, "tx%u_dropped", i);
			ethtool_sprintf(&p, "tx%u_xmit_more", i);
			ethtool_sprintf(&p, "tx%u_wake", i);
			ethtool_sprintf(&p, "tx%u_linearize", i);
		}

		sxe2vf_for_each_vsi_rxq(vsi, i)
		{
			ethtool_sprintf(&p, "rx%u_packets", i);
			ethtool_sprintf(&p, "rx%u_bytes", i);
			ethtool_sprintf(&p, "rx%u_csum_unnecessary", i);
			ethtool_sprintf(&p, "rx%u_csum_none", i);
			ethtool_sprintf(&p, "rx%u_csum_complete", i);
			ethtool_sprintf(&p, "rx%u_csum_unnecessary_inner", i);
			ethtool_sprintf(&p, "rx%u_csum_err", i);
			ethtool_sprintf(&p, "rx%u_lro_packets", i);
			ethtool_sprintf(&p, "rx%u_lro_bytes", i);
			ethtool_sprintf(&p, "rx%u_lro_count", i);
			ethtool_sprintf(&p, "rx%u_removed_vlan_packets", i);
			ethtool_sprintf(&p, "rx%u_pkts_sw_drop", i);
			ethtool_sprintf(&p, "rx%u_buff_alloc_err", i);
			ethtool_sprintf(&p, "rx%u_pg_alloc_fail", i);
			ethtool_sprintf(&p, "rx%u_page_alloc", i);
			ethtool_sprintf(&p, "rx%u_non_eop_descs", i);
			ethtool_sprintf(&p, "rx%u_pa_err", i);
		}
		sxe2vf_get_ipsec_strings(adapter, &p);
		ethtool_sprintf(&p, "fnav_match");
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < SXE2VF_PRIV_FLAG_LEN; i++)
			ethtool_sprintf(&p, sxe2vf_gstrings_priv_flags[i].name);
		break;
	default:
		break;
	}
}

static u32 sxe2vf_get_priv_flags(struct net_device *netdev)
{
	u32 i, flags = 0;
	const struct sxe2vf_priv_flag *priv_flag;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	for (i = 0; i < SXE2VF_PRIV_FLAG_LEN; i++) {
		priv_flag = &sxe2vf_gstrings_priv_flags[i];
		if (test_bit((int)priv_flag->adapter_flag_bitno, adapter->flags))
			flags |= (u32)BIT(i);
	}
	return flags;
}

STATIC void sxe2vf_fnav_tunnel_flag_set(struct sxe2vf_adapter *adapter, u32 flags)
{
	if ((flags & BIT(SXE2VF_PRIV_FLAGS_FNAV_TUNNEL)) &&
	    !test_bit(SXE2VF_FLAG_FNAV_TUNNEL, adapter->flags)) {
		set_bit(SXE2VF_FLAG_FNAV_TUNNEL, adapter->flags);
	}

	if (!(flags & BIT(SXE2VF_PRIV_FLAGS_FNAV_TUNNEL)) &&
	    test_bit(SXE2VF_FLAG_FNAV_TUNNEL, adapter->flags)) {
		clear_bit(SXE2VF_FLAG_FNAV_TUNNEL, adapter->flags);
	}
}

static s32 sxe2vf_legacy_rx_flag_set(struct sxe2vf_adapter *adapter, u32 flags)
{
	s32 ret = 0;
	bool need_downup = false;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct net_device *netdev = vsi->netdev;
	bool old_legacy_rx =
			(bool)test_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE, adapter->flags);

	if ((flags & BIT(SXE2VF_PRIV_FLAGS_LEGACY_RX)) &&
	    !test_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE, adapter->flags)) {
		need_downup = true;
		set_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE, adapter->flags);
	} else if (!(flags & BIT(SXE2VF_PRIV_FLAGS_LEGACY_RX)) &&
		   test_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE, adapter->flags)) {
		need_downup = true;
		clear_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE, adapter->flags);
	}

	if (need_downup) {
		ret = sxe2vf_vsi_reopen_locked(adapter->vsi_ctxt.vf_vsi);
		if (ret) {
			if (old_legacy_rx) {
				set_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE,
					adapter->flags);
			} else {
				clear_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE,
					  adapter->flags);
			}
			LOG_NETDEV_ERR("set legacy rx priv flag err %d\n", ret);
		}
	} else {
		LOG_INFO_BDF("legacy rx priv flag not changed.\n");
	}

	return ret;
}

static int sxe2vf_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 ret = 0;
	bool part_failed = false;

	ret = sxe2vf_legacy_rx_flag_set(adapter, flags);
	if (ret)
		part_failed = true;

	sxe2vf_fnav_tunnel_flag_set(adapter, flags);

	if (part_failed)
		ret = -EINVAL;

	return ret;
}

#ifdef GET_RINGPARAM_NEED_2_PARAMS
static void sxe2vf_get_ringparam(struct net_device *netdev,
				 struct ethtool_ringparam *ring)
#else
static void sxe2vf_get_ringparam(struct net_device *netdev,
				 struct ethtool_ringparam *ring,
				 struct kernel_ethtool_ringparam *kernel_ring,
				 struct netlink_ext_ack *extack)
#endif
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	ring->rx_max_pending = SXE2VF_MAX_NUM_DESC;
	ring->tx_max_pending = SXE2VF_MAX_NUM_DESC;
	ring->rx_pending = adapter->vsi_ctxt.vf_vsi->rxqs.depth;
	ring->tx_pending = adapter->vsi_ctxt.vf_vsi->txqs.depth;
}

static bool sxe2vf_ringparam_changed(struct sxe2vf_adapter *adapter,
				     struct ethtool_ringparam *ring, u32 *tx_cnt,
				     u32 *rx_cnt)
{
	bool changed = true;

	*tx_cnt = clamp_t(u32, ring->tx_pending, SXE2VF_MIN_NUM_DESC,
			  SXE2VF_MAX_NUM_DESC);
	*tx_cnt = ALIGN(*tx_cnt, SXE2VF_DESC_ALIGN_32);

	*rx_cnt = clamp_t(u32, ring->rx_pending, SXE2VF_MIN_NUM_DESC,
			  SXE2VF_MAX_NUM_DESC);
	*rx_cnt = ALIGN(*rx_cnt, SXE2VF_DESC_ALIGN_32);

	if ((*tx_cnt == adapter->vsi_ctxt.vf_vsi->txqs.depth) &&
	    (*rx_cnt == adapter->vsi_ctxt.vf_vsi->rxqs.depth)) {
		changed = false;
	}

	return changed;
}

static void sxe2vf_ringparam_set_offline(struct sxe2vf_vsi *vsi, u32 tx_size,
					 u32 rx_size)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct net_device *netdev = vsi->netdev;

	u32 i;

	if (vsi->txqs.depth == tx_size) {
		LOG_NETDEV_DEBUG("tx desc depth[%d] not changed.\n", tx_size);
	} else {
		LOG_NETDEV_DEBUG("link is down, tx desc depth chang from [%d] to \t"
				 "[%d] happens\t"
				 " when link is brought up.\n",
				 vsi->txqs.depth, tx_size);
		sxe2vf_for_each_vsi_txq(vsi, i)
		{
			vsi->txqs.q[i]->depth = (u16)tx_size;
		}

		vsi->txqs.depth = (u16)tx_size;
	}

	if (vsi->rxqs.depth == rx_size) {
		LOG_NETDEV_DEBUG("rx desc depth[%d] not changed.\n", rx_size);
	} else {
		LOG_NETDEV_DEBUG("link is down, rx desc depth chang from [%d] to \t"
				 "[%d] happens\t"
				 "when link is brought up.\n",
				 vsi->rxqs.depth, rx_size);
		sxe2vf_for_each_vsi_rxq(vsi, i)
		{
			vsi->rxqs.q[i]->depth = (u16)rx_size;
		}
		vsi->rxqs.depth = (u16)rx_size;
	}
}

#ifdef SET_RINGPARAM_NEED_2_PARAMS
static int sxe2vf_set_ringparam(struct net_device *netdev,
				struct ethtool_ringparam *user_param)
#else
static int
sxe2vf_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *user_param,
		     struct kernel_ethtool_ringparam __always_unused *kernel_ring,
		     struct netlink_ext_ack __always_unused *extack)
#endif
{
	s32 ret = 0;
	u32 new_rx_count, new_tx_count;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	u32 old_tx_depth;
	u32 old_rx_depth;

	if (user_param->rx_mini_pending || user_param->rx_jumbo_pending) {
		LOG_ERROR_BDF("do not support set rx_mini_pending=%u or \t"
			      "rx_jumbo_pending=%u\n",
			      user_param->rx_mini_pending,
			      user_param->rx_jumbo_pending);
		return -EINVAL;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try later\n");
		ret = -EBUSY;
		goto l_end;
	}
	if (!sxe2vf_ringparam_changed(adapter, user_param, &new_tx_count,
				      &new_rx_count)) {
		LOG_DEBUG_BDF("ring depth not changed, tx_depth=%u, rx_depth=%u\n",
			      new_tx_count, new_rx_count);
		goto l_end;
	}

	old_tx_depth = vsi->txqs.depth;
	old_rx_depth = vsi->rxqs.depth;

	if (netif_running(netdev)) {
		ret = sxe2vf_vsi_close(vsi);
		if (ret) {
			LOG_DEBUG_BDF("vsi close failed, vsi %d error %d\n",
				      vsi->vsi_id, ret);
			goto l_end;
		}
	}

	sxe2vf_ringparam_set_offline(vsi, new_tx_count, new_rx_count);

	if (netif_running(netdev)) {
		ret = sxe2vf_vsi_open(vsi);
		if (ret) {
			LOG_ERROR_BDF("vf change tx_depth:%u rx_depth:%u \t"
				      "failed.(err:%d)\n",
				      new_tx_count, new_rx_count, ret);
			vsi->txqs.depth = (u16)old_tx_depth;
			vsi->rxqs.depth = (u16)old_rx_depth;
			sxe2vf_queues_depth_update(vsi);
		}
	}

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static void sxe2vf_get_channels(struct net_device *netdev,
				struct ethtool_channels *ch)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	ch->other_count = SXE2VF_EVENT_MSIX_CNT;
	ch->max_other = SXE2VF_EVENT_MSIX_CNT;

	ch->combined_count = adapter->vsi_ctxt.vf_vsi->txqs.q_cnt;
	ch->max_combined = adapter->q_ctxt.eth_q_cnt;
}

static int sxe2vf_set_channels(struct net_device *netdev,
			       struct ethtool_channels *ch)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	u32 num_new = ch->combined_count;
	s32 ret = 0;
#ifndef SXE2_CFG_RELEASE
	u32 old_cnt = adapter->q_ctxt.q_cnt_req;
#endif
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

	if (num_new == 0 || num_new > adapter->q_ctxt.eth_q_cnt)
		return -EINVAL;

	if (num_new == adapter->vsi_ctxt.vf_vsi->txqs.q_cnt)
		return 0;

	if (ch->rx_count || ch->tx_count ||
	    (ch->other_count != SXE2VF_EVENT_MSIX_CNT && ch->other_count != 0))
		return -EINVAL;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try later\n");
		ret = -EBUSY;
		goto l_unlock;
	}
	ret = sxe2vf_set_channels_fnav_check(adapter, num_new);
	if (ret)
		goto l_unlock;

	adapter->q_ctxt.q_cnt_req = (u16)num_new;

	if (netif_running(netdev))
		(void)sxe2vf_vsi_close(vsi);

	ret = sxe2vf_set_channels_rss_reset(netdev, adapter, num_new);
	if (ret) {
		(void)sxe2vf_vsi_disable(vsi);
		LOG_ERROR_BDF("change channel from %u to %u rss lut reset failed. \t"
			      "%d\n",
			      old_cnt, num_new, ret);
		goto l_unlock;
	}

	ret = sxe2vf_vsi_rebuild(vsi);
	if (ret) {
		(void)sxe2vf_vsi_disable(vsi);
		LOG_ERROR_BDF("change channel from %u to %u rebuild failed. %d\n",
			      old_cnt, num_new, ret);
		goto l_unlock;
	}

	if (netif_running(vsi->netdev)) {
		ret = sxe2vf_vsi_open(vsi);
		goto l_unlock;
	}

	LOG_INFO_BDF("change channel from %u to %u.\n", old_cnt, num_new);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

static void sxe2_vf_get_hw_autoneg_info(struct ethtool_link_ksettings *ks,
					struct flm_ethtool_get_link_resp *link_cfg,
					u32 advertising)
{
	ks->base.autoneg = link_cfg->current_an_en.current_an;
	if (link_cfg->configed_pause_result.tx_en &&
	    link_cfg->configed_pause_result.rx_en) {
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising, Asym_Pause);
	} else if (link_cfg->configed_pause_result.tx_en) {
		ethtool_link_ksettings_add_link_mode(ks, advertising, Asym_Pause);
	} else if (link_cfg->configed_pause_result.rx_en) {
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising, Asym_Pause);
	} else {
		ethtool_link_ksettings_add_link_mode(ks, advertising, Pause);
		ethtool_link_ksettings_add_link_mode(ks, advertising, Asym_Pause);
	}
}

static void
sxe2_vf_get_advertise_fec_info(struct ethtool_link_ksettings *ks,
			       struct flm_ethtool_get_link_resp *link_cfg,
			       u32 advertising, u32 supported, u32 linkstate)
{
	if (linkstate) {
		ethtool_link_ksettings_add_link_mode(ks, advertising, FEC_NONE);
		if (link_cfg->advertis_fec.fec_br) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     FEC_BASER);
		}

		if (link_cfg->advertis_fec.fec_528 ||
		    link_cfg->advertis_fec.fec_544) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     FEC_RS);
		}
	}
}

static void sxe2_vf_get_an_info(struct ethtool_link_ksettings *ks,
				struct flm_ethtool_get_link_resp *link_cfg,
				u32 advertising, u32 supported, u32 speed)
{
	if (link_cfg->local_an_en.suppert_an)
		ethtool_link_ksettings_add_link_mode(ks, supported, Autoneg);

	if (link_cfg->local_an_en.advertis_an)
		ethtool_link_ksettings_add_link_mode(ks, advertising, Autoneg);
}

static void sxe2_vf_get_hw_connect_info(struct ethtool_link_ksettings *ks,
					struct flm_ethtool_get_link_resp *link_cfg,
					u32 advertising, u32 supported)
{
	switch (link_cfg->optical_module.current_connection) {
	case SXE2_FW_CONNECT_MODE_TRANSCEIVER:
		ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
		ks->base.port = PORT_FIBRE;
		break;
	case SXE2_FW_CONNECT_MODE_BACKPLANE:
		ethtool_link_ksettings_add_link_mode(ks, supported, Backplane);
		ethtool_link_ksettings_add_link_mode(ks, advertising, Backplane);
		ks->base.port = PORT_NONE;
		break;
	case SXE2_FW_CONNECT_MODE_DAC:
		ethtool_link_ksettings_add_link_mode(ks, supported, TP);
		ethtool_link_ksettings_add_link_mode(ks, advertising, TP);
		ks->base.port = PORT_DA;
		break;
	case SXE2_FW_CONNECT_MODE_AOC:
		ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
		ethtool_link_ksettings_add_link_mode(ks, advertising, FIBRE);
		ks->base.port = PORT_FIBRE;
		break;
	default:
		ks->base.port = PORT_OTHER;
		break;
	}
}

static void
sxe2_vf_get_hw_part_adver_info(struct ethtool_link_ksettings *ks,
			       struct flm_ethtool_get_link_resp *link_cfg,
			       u32 lp_advertising, u32 supported)
{
	ethtool_link_ksettings_add_link_mode(ks, supported, Pause);
	if (link_cfg->sxe2_ana_fsm == SXE2_AN_GOOD) {
		if (link_cfg->partner_pause_result.tx_en &&
		    link_cfg->partner_pause_result.rx_en) {
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Pause);
		} else if (link_cfg->partner_pause_result.tx_en) {
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Pause);
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Asym_Pause);
		} else if (link_cfg->partner_pause_result.rx_en) {
			ethtool_link_ksettings_add_link_mode(ks, lp_advertising,
							     Asym_Pause);
		} else {
			ethtool_link_ksettings_del_link_mode(ks, lp_advertising,
							     Pause);
			ethtool_link_ksettings_del_link_mode(ks, lp_advertising,
							     Asym_Pause);
		}
	}
}

static void
sxe2_vf_ethtool_support_fec_get(struct support_speed_ability_mode *speed_ability,
				struct ethtool_link_ksettings *ks)
{
	ethtool_link_ksettings_add_link_mode(ks, supported, FEC_NONE);
	if (speed_ability->ability_speed_100Gcr4 ||
	    speed_ability->ability_speed_100Gkr4)
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);

	if (speed_ability->ability_speed_50Gcr2 ||
	    speed_ability->ability_speed_50Gkr2)
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);

	if (speed_ability->ability_speed_25Gcr ||
	    speed_ability->ability_speed_25Gkr ||
	    speed_ability->ability_speed_25Gkrcr ||
	    speed_ability->ability_speed_25Gkrcr_s) {
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_BASER);
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);
	}

	if (speed_ability->ability_speed_10Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_BASER);
		ethtool_link_ksettings_add_link_mode(ks, supported, FEC_RS);
	}
}

static void sxe2_vf_get_speed_ability(struct ethtool_link_ksettings *ks,
				      struct flm_ethtool_get_link_resp *link_cfg,
				      struct support_speed_ability_mode *ability,
				      u8 usr_link_speed)
{
	ethtool_link_ksettings_zero_link_mode(ks, supported);
	ethtool_link_ksettings_zero_link_mode(ks, advertising);

	if (ability->ability_speed_10Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     10000baseKR_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_10G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     10000baseKR_Full);
		}
	}

	if (ability->ability_speed_25Gcr || ability->ability_speed_25Gkrcr_s) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     25000baseCR_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_25G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseCR_Full);
		}
	}

	if (ability->ability_speed_25Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     25000baseKR_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_25G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseKR_Full);
		}
	}

	if (ability->ability_speed_50Gcr2) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     50000baseCR2_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_50G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseCR2_Full);
		}
	}

	if (ability->ability_speed_50Gkr2) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     50000baseKR2_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_50G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseKR2_Full);
		}
	}

	if (ability->ability_speed_100Gcr4) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     100000baseCR4_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_100G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseCR4_Full);
		}
	}

	if (ability->ability_speed_100Gkr4) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     100000baseKR4_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_100G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseKR4_Full);
		}
	}

	if (ability->ability_speed_100Gsr4) {
		ethtool_link_ksettings_add_link_mode(ks, supported,
						     100000baseSR4_Full);
		if (link_cfg->current_an_en.current_an &&
		    (usr_link_speed == FLM_FW_SPEED_100G ||
		     usr_link_speed == FLM_FW_SPEED_AUTO)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseSR4_Full);
		}
	}

	if (link_cfg->an_publicity.an_mode.speed_ability_10Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     10000baseKR_Full);
	}

	if (link_cfg->an_publicity.an_mode.speed_ability_25Gkrcr ||
	    link_cfg->an_publicity.an_mode.speed_ability_25Gkrcr_s) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseKR_Full);
	}

	if (link_cfg->an_publicity.an_np_mode.speed_ability_25Gkr) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseKR_Full);
	}

	if (link_cfg->an_publicity.an_np_mode.speed_ability_25Gcr) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseCR_Full);
	}

	if (link_cfg->an_publicity.an_np_mode.speed_ability_50Gcr2) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     50000baseCR2_Full);
	}

	if (link_cfg->an_publicity.an_np_mode.speed_ability_50Gkr2) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     50000baseKR2_Full);
	}

	if (link_cfg->an_publicity.an_mode.fec_rs528_25g) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseKR_Full);
	}

	if (link_cfg->an_publicity.an_mode.fec_ability_10g) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     10000baseKR_Full);
	}

	if (link_cfg->an_publicity.an_mode.fec_bsfec_25g) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseKR_Full);
	}

	if (link_cfg->an_publicity.an_mode.fec_en_10g) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     10000baseKR_Full);
	}

	if (link_cfg->an_publicity.an_mode.Consortium_25g_50g_en) {
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     25000baseKR_Full);
		ethtool_link_ksettings_add_link_mode(ks, advertising,
						     50000baseKR2_Full);
	}

	sxe2_vf_ethtool_support_fec_get(ability, ks);
}

static void
sxe2_vf_get_advertise_link_mode_info(struct ethtool_link_ksettings *ks,
				     struct flm_ethtool_get_link_resp *link_cfg,
				     u32 speed)
{
	if (!link_cfg->current_an_en.current_an) {
		if (speed == SXE2_LINK_SPEED_VF_10G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  10000baseKR_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     10000baseKR_Full);
		}

		if (speed == SXE2_LINK_SPEED_VF_25G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  25000baseCR_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseCR_Full);
		}

		if (speed == SXE2_LINK_SPEED_VF_25G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  25000baseKR_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     25000baseKR_Full);
		}

		if (speed == SXE2_LINK_SPEED_VF_50G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  50000baseCR2_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseCR2_Full);
		}

		if (speed == SXE2_LINK_SPEED_VF_50G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  50000baseKR2_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     50000baseKR2_Full);
		}

		if (speed == SXE2_LINK_SPEED_VF_100G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  100000baseCR4_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseCR4_Full);
		}

		if (speed == SXE2_LINK_SPEED_VF_100G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  100000baseKR4_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseKR4_Full);
		}

		if (speed == SXE2_LINK_SPEED_VF_100G &&
		    ethtool_link_ksettings_test_link_mode(ks, supported,
							  100000baseSR4_Full)) {
			ethtool_link_ksettings_add_link_mode(ks, advertising,
							     100000baseSR4_Full);
		}
	}
}

static void sxe2_vf_get_adpter_base_info(struct net_device *netdev,
					 struct ethtool_link_ksettings *ks,
					 u32 speed)
{
	u32 supported;
	u32 advertising;
	u32 lp_advertising;
	struct sxe2_msg_ethtool_info link_cfg;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 ret;

	(void)ethtool_convert_link_mode_to_legacy_u32(&supported,
						      ks->link_modes.supported);
	(void)ethtool_convert_link_mode_to_legacy_u32(&advertising,
						      ks->link_modes.advertising);
	(void)ethtool_convert_link_mode_to_legacy_u32(&lp_advertising,
						      ks->link_modes.lp_advertising);

	link_cfg.usr_link_speed = FLM_FW_SPEED_AUTO;
	ret = sxe2vf_ethtool_info_request(adapter, &link_cfg);
	if (ret)
		goto end;

	sxe2_vf_get_speed_ability(ks, &link_cfg.cfg, &link_cfg.ability,
				  link_cfg.usr_link_speed);

	sxe2_vf_get_hw_autoneg_info(ks, &link_cfg.cfg, advertising);

	sxe2_vf_get_advertise_link_mode_info(ks, &link_cfg.cfg, speed);

	sxe2_vf_get_advertise_fec_info(ks, &link_cfg.cfg, advertising, supported,
				       adapter->link_ctxt.link_up);

	sxe2_vf_get_an_info(ks, &link_cfg.cfg, advertising, supported, speed);

	sxe2_vf_get_hw_connect_info(ks, &link_cfg.cfg, advertising, supported);

	sxe2_vf_get_hw_part_adver_info(ks, &link_cfg.cfg, lp_advertising, supported);

end:
	return;
}

STATIC int sxe2vf_get_link_ksettings(struct net_device *netdev,
				     struct ethtool_link_ksettings *link_settings)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 ret = 0;

	ethtool_link_ksettings_zero_link_mode(link_settings, supported);
	link_settings->base.autoneg = AUTONEG_DISABLE;
	link_settings->base.port = PORT_NONE;
	link_settings->base.duplex = DUPLEX_FULL;

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2vf_link_status_request(adapter);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_vf_get_adpter_base_info(netdev, link_settings,
				     adapter->link_ctxt.speed);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	if ((!(adapter->link_ctxt.speed)) || (ret)) {
		link_settings->base.speed = SPEED_UNKNOWN;
		link_settings->base.duplex = DUPLEX_UNKNOWN;
		return 0;
	}

	switch (adapter->link_ctxt.speed) {
	case SXE2_LINK_SPEED_VF_10G:
		link_settings->base.speed = SPEED_10000;
		break;
	case SXE2_LINK_SPEED_VF_25G:
		link_settings->base.speed = SPEED_25000;
		break;
	case SXE2_LINK_SPEED_VF_50G:
		link_settings->base.speed = SPEED_50000;
		break;
	case SXE2_LINK_SPEED_VF_100G:
		link_settings->base.speed = SPEED_100000;
		break;
	default:
		break;
	}

	return 0;
}

STATIC void sxe2vf_get_drvinfo(struct net_device *netdev,
			       struct ethtool_drvinfo *drvinfo)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2_fw_ver_msg *fw_ver = &adapter->hw.fw_ver;

	strscpy(drvinfo->driver, SXE2VF_DRV_NAME, sizeof(drvinfo->driver));
	strscpy(drvinfo->version, SXE2_VERSION, sizeof(drvinfo->version));
	(void)snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		       "%u.%u.%u.%u", fw_ver->main_version_id,
		       fw_ver->sub_version_id, fw_ver->fix_version_id,
		       fw_ver->build_id);
	strscpy(drvinfo->bus_info, pci_name(adapter->pdev),
		sizeof(drvinfo->bus_info));
	drvinfo->n_priv_flags = SXE2VF_PRIV_FLAG_LEN;
}

static u32 sxe2vf_get_msglevel(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	return adapter->log_level_ctxt.msg_enable;
}

static void sxe2vf_set_msglevel(struct net_device *netdev, u32 data)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	adapter->log_level_ctxt.msg_enable = data;
}

static s32 sxe2vf_get_tx_qc_coalesce(struct ethtool_coalesce *ec,
				     struct sxe2vf_q_container *qc)
{
	if (!qc->list.cnt)
		return -EINVAL;

	ec->use_adaptive_tx_coalesce = SXE2VF_IS_ITR_DYNAMIC(qc);
	ec->tx_coalesce_usecs = qc->itr_setting;

	return 0;
}

static s32 sxe2vf_get_rx_qc_coalesce(struct ethtool_coalesce *ec,
				     struct sxe2vf_q_container *qc)
{
	if (!qc->list.cnt)
		return -EINVAL;

	ec->use_adaptive_rx_coalesce = SXE2VF_IS_ITR_DYNAMIC(qc);
	ec->rx_coalesce_usecs = qc->itr_setting;

	return 0;
}

static s32 sxe2vf_get_queue_coalesce(struct sxe2vf_vsi *vsi,
				     struct ethtool_coalesce *ec, u32 q_idx)
{
	if (q_idx < vsi->txqs.q_cnt && q_idx < vsi->rxqs.q_cnt) {
		if (sxe2vf_get_tx_qc_coalesce(ec, SXE2VF_VSI_TX_QC(vsi, q_idx)))
			return -EINVAL;
		if (sxe2vf_get_rx_qc_coalesce(ec, SXE2VF_VSI_RX_QC(vsi, q_idx)))
			return -EINVAL;
	} else if (q_idx < vsi->txqs.q_cnt) {
		if (sxe2vf_get_tx_qc_coalesce(ec, SXE2VF_VSI_TX_QC(vsi, q_idx)))
			return -EINVAL;
	} else if (q_idx < vsi->rxqs.q_cnt) {
		if (sxe2vf_get_rx_qc_coalesce(ec, SXE2VF_VSI_RX_QC(vsi, q_idx)))
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	return 0;
}

STATIC s32 sxe2vf_irq_coalesce_get(struct net_device *netdev,
				   struct ethtool_coalesce *user, u32 q_idx)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, adapter->vsi_ctxt.vf_vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try later\n");
		ret = -EBUSY;
		goto end;
	}

	if (q_idx == SXE2VF_COALESCE_QIDX_INVAL)
		q_idx = 0;
	if (sxe2vf_get_queue_coalesce(vsi, user, q_idx))
		ret = -EINVAL;

end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC void sxe2vf_invalid_itr_print(struct net_device *netdev,
				     u32 use_adaptive_coalesce, u32 coalesce_usecs,
				     const s8 *q_type_str)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	if (use_adaptive_coalesce)
		return;

	if (coalesce_usecs % adapter->irq_ctxt.itr_gran)
		LOG_NETDEV_INFO("User set %s-usecs to invalid value %d, device only \t"
				"support\t"
				"values that multiple of %d. Rounding down and \t"
				"attempting\t"
				"to set %s-usecs to %d\n",
				q_type_str, coalesce_usecs,
				adapter->irq_ctxt.itr_gran, q_type_str,
				rounddown(coalesce_usecs,
					  adapter->irq_ctxt.itr_gran));
}

STATIC void sxe2vf_invalid_coalesce_print(struct net_device *netdev,
					  struct ethtool_coalesce *ec)
{
	sxe2vf_invalid_itr_print(netdev, ec->use_adaptive_tx_coalesce,
				 ec->tx_coalesce_usecs, SXE2VF_Q_TYPE_STR_TX);
	sxe2vf_invalid_itr_print(netdev, ec->use_adaptive_rx_coalesce,
				 ec->rx_coalesce_usecs, SXE2VF_Q_TYPE_STR_RX);
}

static s32 sxe2vf_set_qc_itr(struct sxe2vf_q_container *qc, const s8 *q_type_str,
			     u32 use_adaptive_coalesce, u32 coalesce_usecs)
{
	struct sxe2vf_irq_data *irq_data = qc->list.next->irq_data;
	struct sxe2vf_vsi *vsi = irq_data->vsi;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_hw *hw = &adapter->hw;
	struct net_device *netdev = vsi->netdev;

	if (use_adaptive_coalesce) {
		if (coalesce_usecs != qc->itr_setting) {
			LOG_NETDEV_INFO("%s interrupt throttling cannot be changed\t"
					"if adaptive-%s is enabled\n",
					q_type_str, q_type_str);
			return -EINVAL;
		}
		qc->itr_mode = SXE2VF_ITR_DYNAMIC;

	} else {
		if (coalesce_usecs >
		    SXE2VF_VF_INT_ITR_INTERVAL_MAX * adapter->irq_ctxt.itr_gran) {
			LOG_NETDEV_INFO("Invalid value, %s-usecs range is 0-%d\n",
					q_type_str,
					SXE2VF_VF_INT_ITR_INTERVAL_MAX *
							adapter->irq_ctxt.itr_gran);
			return -EINVAL;
		}
		qc->itr_mode = SXE2VF_ITR_STATIC;
		qc->itr_setting = rounddown(coalesce_usecs,
					    adapter->irq_ctxt.itr_gran);
		sxe2vf_hw_int_itr_set(hw, qc->itr_idx, irq_data->irq_idx,
				      qc->itr_setting / adapter->irq_ctxt.itr_gran);
	}

	return 0;
}

static s32 sxe2vf_set_queue_coalesce(struct net_device *netdev,
				     struct ethtool_coalesce *ec, u32 q_idx)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	s32 ret;

	if (q_idx < vsi->txqs.q_cnt && q_idx < vsi->rxqs.q_cnt) {
		ret = sxe2vf_set_qc_itr(SXE2VF_VSI_TX_QC(vsi, q_idx), SXE2VF_Q_TYPE_STR_TX,
					ec->use_adaptive_tx_coalesce, ec->tx_coalesce_usecs);
		if (ret)
			return ret;

		ret = sxe2vf_set_qc_itr(SXE2VF_VSI_RX_QC(vsi, q_idx), SXE2VF_Q_TYPE_STR_RX,
					ec->use_adaptive_rx_coalesce, ec->rx_coalesce_usecs);
		if (ret)
			return ret;
	} else if (q_idx < vsi->txqs.q_cnt) {
		ret = sxe2vf_set_qc_itr(SXE2VF_VSI_TX_QC(vsi, q_idx), SXE2VF_Q_TYPE_STR_TX,
					ec->use_adaptive_tx_coalesce, ec->tx_coalesce_usecs);
		if (ret)
			return ret;
	} else if (q_idx < vsi->rxqs.q_cnt) {
		ret = sxe2vf_set_qc_itr(SXE2VF_VSI_RX_QC(vsi, q_idx), SXE2VF_Q_TYPE_STR_RX,
					ec->use_adaptive_rx_coalesce, ec->rx_coalesce_usecs);
		if (ret)
			return ret;
	} else {
		return -EINVAL;
	}

	return 0;
}

static s32 sxe2vf_set_all_queue_coalesce(struct net_device *netdev,
					 struct ethtool_coalesce *ec)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	u16 irq_idx;
	s32 ret;
	struct sxe2vf_irq_data *irq_data;

	sxe2vf_for_each_vsi_irq(vsi, irq_idx)
	{
		irq_data = vsi->irqs.irq_data[irq_idx];
		if (SXE2VF_IRQ_HAS_TXQ(irq_data)) {
			ret = sxe2vf_set_qc_itr(&irq_data->tx, SXE2VF_Q_TYPE_STR_TX,
						ec->use_adaptive_tx_coalesce,
						ec->tx_coalesce_usecs);
			if (ret)
				return ret;
		}
		if (SXE2VF_IRQ_HAS_RXQ(irq_data)) {
			ret = sxe2vf_set_qc_itr(&irq_data->rx, SXE2VF_Q_TYPE_STR_RX,
						ec->use_adaptive_rx_coalesce,
						ec->rx_coalesce_usecs);
			if (ret)
				return ret;
		}
	}
	return 0;
}

STATIC s32 sxe2vf_irq_coalesce_set(struct net_device *netdev,
				   struct ethtool_coalesce *user, u32 q_idx)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (q_idx == SXE2VF_COALESCE_QIDX_INVAL) {
		ret = sxe2vf_set_all_queue_coalesce(netdev, user);

	} else if (q_idx < vsi->txqs.q_cnt) {
		ret = sxe2vf_set_queue_coalesce(netdev, user, q_idx);

	} else {
		LOG_NETDEV_INFO("Invalid queue idx, q_idx range is 0 - %d\n",
				vsi->txqs.q_cnt - 1);
		ret = -EINVAL;
	}

	if (ret)
		goto l_unlock;

	sxe2vf_invalid_coalesce_print(netdev, user);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef GET_COALESCE_NEED_2_PARAMS
static int sxe2vf_get_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *ec)
#else
static int sxe2vf_get_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *ec,
			       struct kernel_ethtool_coalesce *kernel_coal,
			       struct netlink_ext_ack *extack)
#endif
{
	return sxe2vf_irq_coalesce_get(netdev, ec, SXE2VF_COALESCE_QIDX_INVAL);
}

#ifdef SET_COALESCE_NEED_2_PARAMS
static int sxe2vf_set_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *ec)
#else
static int sxe2vf_set_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *ec,
			       struct kernel_ethtool_coalesce *kernel_coal,
			       struct netlink_ext_ack *extack)
#endif
{
	return sxe2vf_irq_coalesce_set(netdev, ec, SXE2VF_COALESCE_QIDX_INVAL);
}

static int sxe2vf_get_per_queue_coalesce(struct net_device *netdev, u32 queue,
					 struct ethtool_coalesce *ec)
{
	return sxe2vf_irq_coalesce_get(netdev, ec, queue);
}

static int sxe2vf_set_per_queue_coalesce(struct net_device *netdev, u32 queue,
					 struct ethtool_coalesce *ec)
{
	return sxe2vf_irq_coalesce_set(netdev, ec, queue);
}

static int sxe2vf_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd,
			    u32 *rule_locs)
{
	int ret = -EOPNOTSUPP;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = adapter->vsi_ctxt.vf_vsi->rxqs.q_cnt;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = adapter->fnav_ctxt.filter_cnt;
		cmd->data = SXE2VF_MAX_FNAV_FILTERS;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = sxe2vf_ethtool_fnav_filter_get_by_loc(adapter, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		ret = sxe2vf_ethtool_ntuple_filter_locs_get(adapter, cmd,
							    (u32 *)rule_locs);
		break;
	case ETHTOOL_GRXFH:
		sxe2vf_get_rss_flow(adapter, cmd);
		ret = 0;
		break;
	default:
		LOG_DEBUG_BDF("command parameters not supported\n, cmd=%u",
			      cmd->cmd);
		break;
	}

	return ret;
}

#ifdef HAVE_ETHTOOL_RXFH_PARAM
STATIC int sxe2vf_get_rxfh(struct net_device *netdev,
			   struct ethtool_rxfh_param *rxfh)
#else
STATIC int sxe2vf_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
#endif
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	int ret = 0;
	u32 i = 0;
#ifdef HAVE_ETHTOOL_RXFH_PARAM
	u32 *indir = rxfh->indir;
	u8 *key = rxfh->key;
#endif

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		LOG_ERROR_BDF("sxe2 vf rss (id: %u)ethtool get rxfh state is \t"
			      "disable.\n",
			      vsi->vsi_id);
		ret = -EBUSY;
		goto l_unlock;
	}

#ifdef HAVE_ETHTOOL_RXFH_PARAM
	rxfh->hfunc = ETH_RSS_HASH_TOP;
#else

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;
#endif

	if (indir) {
		if (adapter->rss_ctxt.lut) {
			for (i = 0; i < adapter->rss_ctxt.rss_lut_size; i++)
				indir[i] = (u32)(adapter->rss_ctxt.lut[i]);
		}
	}

	if (key) {
		if (adapter->rss_ctxt.key)
			memcpy(key, adapter->rss_ctxt.key,
			       adapter->rss_ctxt.rss_key_size);
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef HAVE_ETHTOOL_RXFH_PARAM
STATIC int sxe2vf_set_rxfh(struct net_device *netdev,
			   struct ethtool_rxfh_param *rxfh,
			   struct netlink_ext_ack *extack)
#else
STATIC int sxe2vf_set_rxfh(struct net_device *netdev, const u32 *indir,
			   const u8 *key, const u8 hfunc)
#endif
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_msg_params params = {0};
	int ret = 0;
	u32 i = 0;
	u8 *user_key = NULL;
	u8 *user_lut = NULL;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
#ifdef HAVE_ETHTOOL_RXFH_PARAM
	const u32 *indir = rxfh->indir;
	const u8 *key = rxfh->key;
	const u8 hfunc = rxfh->hfunc;
#endif

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		LOG_ERROR_BDF("sxe2 vf rss (id: %u)ethtool set rxfh state is \t"
			      "disable.\n",
			      vsi->vsi_id);
		ret = -EBUSY;
		goto l_unlock;
	}

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP) {
		ret = -EOPNOTSUPP;
		goto l_unlock;
	}

	if (key) {
		user_key = devm_kzalloc(dev, adapter->rss_ctxt.rss_key_size,
					GFP_KERNEL);
		if (!user_key) {
			LOG_ERROR_BDF("no memory for user hash key.\n");
			ret = -ENOMEM;
			goto l_unlock;
		}
		memcpy(user_key, key, adapter->rss_ctxt.rss_key_size);
	}

	if (indir) {
		user_lut = devm_kzalloc(dev, adapter->rss_ctxt.rss_lut_size,
					GFP_KERNEL);
		if (!user_lut) {
			LOG_ERROR_BDF("no memory for user lut.\n");
			ret = -ENOMEM;
			goto l_unlock;
		}
		for (i = 0; i < adapter->rss_ctxt.rss_lut_size; i++)
			user_lut[i] = (u8)(indir[i]);
	}

	if (key) {
		sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
						SXE2_VF_SET_RSS_KEY, user_key,
						adapter->rss_ctxt.rss_key_size, NULL,
						0);
		ret = sxe2vf_mbx_msg_send(adapter, &params);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf rss (id: %u) mbx msg send set rss \t"
				      "key fail.\n",
				      vsi->vsi_id);
			goto l_unlock;
		}
		if (adapter->rss_ctxt.key) {
			memcpy(adapter->rss_ctxt.key, user_key,
			       adapter->rss_ctxt.rss_key_size);
		}
	}

	if (indir) {
		sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
						SXE2_VF_SET_RSS_LUT, user_lut,
						adapter->rss_ctxt.rss_lut_size, NULL,
						0);
		ret = sxe2vf_mbx_msg_send(adapter, &params);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf rss (id: %u) mbx msg send set rss \t"
				      "lut fail.\n",
				      vsi->vsi_id);
			goto l_unlock;
		}
		if (adapter->rss_ctxt.lut) {
			memcpy(adapter->rss_ctxt.lut, user_lut,
			       adapter->rss_ctxt.rss_lut_size);
		}
	}

l_unlock:
	if (user_key)
		devm_kfree(dev, user_key);
	if (user_lut)
		devm_kfree(dev, user_lut);

	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC u32 sxe2vf_get_rxft_key_size(struct net_device __always_unused *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	return (u32)adapter->rss_ctxt.rss_key_size;
}

STATIC u32 sxe2vf_get_rxft_indir_size(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	return (u32)adapter->rss_ctxt.rss_lut_size;
}

static const u8 eth_addr_full_mask[SXE2_FNAV_ETH_ADDR_LEN] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const u8 eth_addr_zero_mask[SXE2_FNAV_ETH_ADDR_LEN] = {
		0, 0, 0, 0, 0, 0,
};

static const struct in6_addr ipv6_addr_full_mask = {.in6_u = {.u6_addr8 = {
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
									      0xFF,
							      }}};

static const struct in6_addr ipv6_addr_zero_mask = {.in6_u = {.u6_addr8 = {
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
									      0,
							      }}};

STATIC void sxe2vf_fnav_fld_convert_msg(unsigned long *flds,
					struct sxe2_fnav_comm_proto_hdr *proto_hdr)
{
	u32 tmp_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	u32 i = 0;

	bitmap_to_arr32(tmp_flds, flds, SXE2_FLOW_FLD_ID_MAX);

	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX); i++)
		proto_hdr->flds[i] = cpu_to_le32(tmp_flds[i]);
}

STATIC void sxe2vf_fill_fnav_ip4_hdr(struct sxe2vf_fnav_filter_full_key *full_key,
				     struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *proto_hdr =
			&full_msg->proto_hdr[full_msg->proto_cnt];
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
	proto_hdr->type = cpu_to_le32(SXE2_FLOW_HDR_IPV4);

	if (full_key->ip_mask.tos == U8_MAX) {
		proto_hdr->ipv4.tos = full_key->ip_data.tos;
		set_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, flds);
	}

	if (full_key->ip_mask.proto == U8_MAX) {
		proto_hdr->ipv4.proto = full_key->ip_data.proto;
		set_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, flds);
	}

	if (full_key->ip_mask.v4_addrs.src_ip == htonl(U32_MAX)) {
		proto_hdr->ipv4.saddr = full_key->ip_data.v4_addrs.src_ip;
		set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, flds);
	}

	if (full_key->ip_mask.v4_addrs.dst_ip == htonl(U32_MAX)) {
		proto_hdr->ipv4.daddr = full_key->ip_data.v4_addrs.dst_ip;
		set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, flds);
	}

	sxe2vf_fnav_fld_convert_msg(flds, proto_hdr);
	full_msg->proto_cnt++;
}

STATIC void sxe2vf_fill_fnav_ip6_hdr(struct sxe2vf_fnav_filter_full_key *full_key,
				     struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *proto_hdr =
			&full_msg->proto_hdr[full_msg->proto_cnt];
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
	proto_hdr->type = cpu_to_le32(SXE2_FLOW_HDR_IPV6);

	if (full_key->ip_mask.tclass == U8_MAX) {
		proto_hdr->ipv6.tc = full_key->ip_data.tclass;
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DSCP, flds);
	}

	if (full_key->ip_mask.proto == U8_MAX) {
		proto_hdr->ipv6.proto = full_key->ip_data.proto;
		set_bit(SXE2_FLOW_FLD_ID_IPV6_PROT, flds);
	}

	if (!memcmp(&full_key->ip_mask.v6_addrs.src_ip, &ipv6_addr_full_mask,
		    sizeof(struct in6_addr))) {
		memcpy(&proto_hdr->ipv6.src_ip, &full_key->ip_data.v6_addrs.src_ip,
		       sizeof(struct in6_addr));
		set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, flds);
	}

	if (!memcmp(&full_key->ip_mask.v6_addrs.dst_ip, &ipv6_addr_full_mask,
		    sizeof(struct in6_addr))) {
		memcpy(&proto_hdr->ipv6.dst_ip, &full_key->ip_data.v6_addrs.dst_ip,
		       sizeof(struct in6_addr));
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, flds);
	}

	sxe2vf_fnav_fld_convert_msg(flds, proto_hdr);
	full_msg->proto_cnt++;
}

STATIC void sxe2vf_fill_fnav_tcp_hdr(struct sxe2vf_fnav_filter_full_key *full_key,
				     struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *proto_hdr =
			&full_msg->proto_hdr[full_msg->proto_cnt];
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
	proto_hdr->type = cpu_to_le32(SXE2_FLOW_HDR_TCP);

	if (full_key->ip_mask.src_port == htons(U16_MAX)) {
		proto_hdr->l4.src_port = full_key->ip_data.src_port;
		set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, flds);
	}

	if (full_key->ip_mask.dst_port == htons(U16_MAX)) {
		proto_hdr->l4.dst_port = full_key->ip_data.dst_port;
		set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, flds);
	}

	sxe2vf_fnav_fld_convert_msg(flds, proto_hdr);
	full_msg->proto_cnt++;
}

STATIC void sxe2vf_fill_fnav_udp_hdr(struct sxe2vf_fnav_filter_full_key *full_key,
				     struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *proto_hdr =
			&full_msg->proto_hdr[full_msg->proto_cnt];
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
	proto_hdr->type = cpu_to_le32(SXE2_FLOW_HDR_UDP);

	if (full_key->ip_mask.src_port == htons(U16_MAX)) {
		proto_hdr->l4.src_port = full_key->ip_data.src_port;
		set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, flds);
	}

	if (full_key->ip_mask.dst_port == htons(U16_MAX)) {
		proto_hdr->l4.dst_port = full_key->ip_data.dst_port;
		set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, flds);
	}

	sxe2vf_fnav_fld_convert_msg(flds, proto_hdr);
	full_msg->proto_cnt++;
}

STATIC void sxe2vf_fill_fnav_sctp_hdr(struct sxe2vf_fnav_filter_full_key *full_key,
				      struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *proto_hdr =
			&full_msg->proto_hdr[full_msg->proto_cnt];
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
	proto_hdr->type = cpu_to_le32(SXE2_FLOW_HDR_SCTP);

	if (full_key->ip_mask.src_port == htons(U16_MAX)) {
		proto_hdr->l4.src_port = full_key->ip_data.src_port;
		set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, flds);
	}

	if (full_key->ip_mask.dst_port == htons(U16_MAX)) {
		proto_hdr->l4.dst_port = full_key->ip_data.dst_port;
		set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, flds);
	}

	sxe2vf_fnav_fld_convert_msg(flds, proto_hdr);
	full_msg->proto_cnt++;
}

STATIC void sxe2vf_fill_fnav_eth_hdr(struct sxe2vf_fnav_filter_full_key *full_key,
				     struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *proto_hdr =
			&full_msg->proto_hdr[full_msg->proto_cnt];
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
	proto_hdr->type = cpu_to_le32(SXE2_FLOW_HDR_ETH);

	if (full_key->eth_mask.etype == htons(U16_MAX)) {
		proto_hdr->eth.etype = full_key->eth_data.etype;
		set_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, flds);
	}

	if (!memcmp(&full_key->eth_mask.src, &eth_addr_full_mask,
		    sizeof(full_key->eth_mask.src))) {
		memcpy(&proto_hdr->eth.src, &full_key->eth_data.src,
		       sizeof(proto_hdr->eth.src));
		set_bit(SXE2_FLOW_FLD_ID_ETH_SA, flds);
	}

	if (!memcmp(&full_key->eth_mask.dst, &eth_addr_full_mask,
		    sizeof(full_key->eth_mask.dst))) {
		memcpy(&proto_hdr->eth.dst, &full_key->eth_data.dst,
		       sizeof(proto_hdr->eth.dst));
		set_bit(SXE2_FLOW_FLD_ID_ETH_DA, flds);
	}

	sxe2vf_fnav_fld_convert_msg(flds, proto_hdr);
	full_msg->proto_cnt++;
}

STATIC bool sxe2vf_ethtool_vlan_seg_valid(struct ethtool_rx_flow_spec *fsp)
{
	bool ret = fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci;

	if (!ret)
		return true;

	if (fsp->m_ext.vlan_etype &&
	    !(fsp->h_ext.vlan_etype == cpu_to_be16(ETH_P_8021Q) ||
	      fsp->h_ext.vlan_etype == cpu_to_be16(ETH_P_8021AD))) {
		ret = false;
		goto l_end;
	}

	if (fsp->m_ext.vlan_tci && ntohs(fsp->h_ext.vlan_tci) >= VLAN_N_VID) {
		ret = false;
		goto l_end;
	}

	if (fsp->m_u.ether_spec.h_proto && fsp->m_ext.vlan_tci &&
	    !fsp->m_ext.vlan_etype) {
		LOG_WARN("Filter with proto and vlan require also vlan-etype.\n");
		ret = false;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC void sxe2vf_fill_fnav_vlan_hdr(struct sxe2vf_fnav_filter_full_key *full_key,
				      struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *proto_hdr =
			&full_msg->proto_hdr[full_msg->proto_cnt];
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
	proto_hdr->type = cpu_to_le32(SXE2_FLOW_HDR_VLAN);

	if (full_key->ext_mask.vlan_type == htons(U16_MAX)) {
		proto_hdr->vlan.vlan_type = full_key->ext_data.vlan_type;
		set_bit(SXE2_FLOW_FLD_ID_S_TPID, flds);
	}

	if (full_key->ext_mask.s_vlan_tag == htons(U16_MAX)) {
		proto_hdr->vlan.vlan_tci = full_key->ext_data.s_vlan_tag;
		set_bit(SXE2_FLOW_FLD_ID_S_TCI, flds);
	}

	sxe2vf_fnav_fld_convert_msg(flds, proto_hdr);
	full_msg->proto_cnt++;
}

STATIC s32 sxe2vf_validate_fnav_filter_masks(struct sxe2vf_adapter *adapter,
					     struct sxe2vf_fnav_filter *filter)
{
	if (filter->full_key.eth_mask.etype &&
	    filter->full_key.eth_mask.etype != htons(U16_MAX))
		goto partial_mask;
	if (memcmp(filter->full_key.eth_mask.src, &eth_addr_full_mask,
		   SXE2_FNAV_ETH_ADDR_LEN) &&
	    memcmp(filter->full_key.eth_mask.src, &eth_addr_zero_mask,
		   SXE2_FNAV_ETH_ADDR_LEN))
		goto partial_mask;
	if (memcmp(filter->full_key.eth_mask.dst, &eth_addr_full_mask,
		   SXE2_FNAV_ETH_ADDR_LEN) &&
	    memcmp(filter->full_key.eth_mask.dst, &eth_addr_zero_mask,
		   SXE2_FNAV_ETH_ADDR_LEN))
		goto partial_mask;

	if (filter->full_key.ext_mask.s_vlan_tag &&
	    filter->full_key.ext_mask.s_vlan_tag != htons(U16_MAX))
		goto partial_mask;
	if (filter->full_key.ext_mask.vlan_type &&
	    filter->full_key.ext_mask.vlan_type != htons(U16_MAX))
		goto partial_mask;

	if (filter->full_key.ip_ver == 4) {
		if (filter->full_key.ip_mask.v4_addrs.src_ip &&
		    filter->full_key.ip_mask.v4_addrs.src_ip != htonl(U32_MAX))
			goto partial_mask;

		if (filter->full_key.ip_mask.v4_addrs.dst_ip &&
		    filter->full_key.ip_mask.v4_addrs.dst_ip != htonl(U32_MAX))
			goto partial_mask;

		if (filter->full_key.ip_mask.tos &&
		    filter->full_key.ip_mask.tos != U8_MAX)
			goto partial_mask;
	} else if (filter->full_key.ip_ver == 6) {
		if (memcmp(&filter->full_key.ip_mask.v6_addrs.src_ip,
			   &ipv6_addr_zero_mask, sizeof(struct in6_addr)) &&
		    memcmp(&filter->full_key.ip_mask.v6_addrs.src_ip,
			   &ipv6_addr_full_mask, sizeof(struct in6_addr)))
			goto partial_mask;

		if (memcmp(&filter->full_key.ip_mask.v6_addrs.dst_ip,
			   &ipv6_addr_zero_mask, sizeof(struct in6_addr)) &&
		    memcmp(&filter->full_key.ip_mask.v6_addrs.dst_ip,
			   &ipv6_addr_full_mask, sizeof(struct in6_addr)))
			goto partial_mask;

		if (filter->full_key.ip_mask.tclass &&
		    filter->full_key.ip_mask.tclass != U8_MAX)
			goto partial_mask;
	}

	if (filter->full_key.ip_mask.proto &&
	    filter->full_key.ip_mask.proto != U8_MAX)
		goto partial_mask;

	if (filter->full_key.ip_mask.src_port &&
	    filter->full_key.ip_mask.src_port != htons(U16_MAX))
		goto partial_mask;

	if (filter->full_key.ip_mask.dst_port &&
	    filter->full_key.ip_mask.dst_port != htons(U16_MAX))
		goto partial_mask;

	if (filter->full_key.ip_mask.spi &&
	    filter->full_key.ip_mask.spi != htonl(U32_MAX))
		goto partial_mask;

	if (filter->full_key.ip_mask.l4_header &&
	    filter->full_key.ip_mask.l4_header != htonl(U32_MAX))
		goto partial_mask;

	return 0;

partial_mask:
	return -EOPNOTSUPP;
}

STATIC s32 sxe2vf_ethtool_fnav_full_key_fill(struct ethtool_rx_flow_spec *fsp,
					     struct sxe2vf_fnav_filter *filter)
{
	int ret = 0;
	struct sxe2vf_fnav_filter_full_key *full_key = &filter->full_key;

	if (fsp->flow_type & FLOW_EXT) {
		memcpy(full_key->ext_data.usr_def, fsp->h_ext.data,
		       sizeof(full_key->ext_data.usr_def));
		full_key->ext_data.vlan_type = fsp->h_ext.vlan_etype;
		full_key->ext_data.s_vlan_tag = fsp->h_ext.vlan_tci;
		memcpy(full_key->ext_mask.usr_def, fsp->m_ext.data,
		       sizeof(full_key->ext_mask.usr_def));
		full_key->ext_mask.vlan_type = fsp->m_ext.vlan_etype;
		full_key->ext_mask.s_vlan_tag = fsp->m_ext.vlan_tci;
		filter->has_flex_filed = SXE2VF_FNAV_HAS_FLEX_FIELD;
	} else {
		filter->has_flex_filed = SXE2VF_FNAV_NO_FLEX_FIELD;
	}

	switch (filter->flow_type) {
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		full_key->ip_data.v4_addrs.src_ip = fsp->h_u.tcp_ip4_spec.ip4src;
		full_key->ip_data.v4_addrs.dst_ip = fsp->h_u.tcp_ip4_spec.ip4dst;
		full_key->ip_data.src_port = fsp->h_u.tcp_ip4_spec.psrc;
		full_key->ip_data.dst_port = fsp->h_u.tcp_ip4_spec.pdst;
		full_key->ip_data.tos = fsp->h_u.tcp_ip4_spec.tos;
		full_key->ip_mask.v4_addrs.src_ip = fsp->m_u.tcp_ip4_spec.ip4src;
		full_key->ip_mask.v4_addrs.dst_ip = fsp->m_u.tcp_ip4_spec.ip4dst;
		full_key->ip_mask.src_port = fsp->m_u.tcp_ip4_spec.psrc;
		full_key->ip_mask.dst_port = fsp->m_u.tcp_ip4_spec.pdst;
		full_key->ip_mask.tos = fsp->m_u.tcp_ip4_spec.tos;
		full_key->ip_ver = 4;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		full_key->ip_data.v4_addrs.src_ip = fsp->h_u.usr_ip4_spec.ip4src;
		full_key->ip_data.v4_addrs.dst_ip = fsp->h_u.usr_ip4_spec.ip4dst;
		full_key->ip_data.l4_header = fsp->h_u.usr_ip4_spec.l4_4_bytes;
		full_key->ip_data.tos = fsp->h_u.usr_ip4_spec.tos;
		full_key->ip_data.proto = fsp->h_u.usr_ip4_spec.proto;
		full_key->ip_mask.v4_addrs.src_ip = fsp->m_u.usr_ip4_spec.ip4src;
		full_key->ip_mask.v4_addrs.dst_ip = fsp->m_u.usr_ip4_spec.ip4dst;
		full_key->ip_mask.l4_header = fsp->m_u.usr_ip4_spec.l4_4_bytes;
		full_key->ip_mask.tos = fsp->m_u.usr_ip4_spec.tos;
		full_key->ip_mask.proto = fsp->m_u.usr_ip4_spec.proto;
		full_key->ip_ver = 4;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		memcpy(&full_key->ip_data.v6_addrs.src_ip,
		       fsp->h_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&full_key->ip_data.v6_addrs.dst_ip,
		       fsp->h_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		full_key->ip_data.src_port = fsp->h_u.tcp_ip6_spec.psrc;
		full_key->ip_data.dst_port = fsp->h_u.tcp_ip6_spec.pdst;
		full_key->ip_data.tclass = fsp->h_u.tcp_ip6_spec.tclass;
		memcpy(&full_key->ip_mask.v6_addrs.src_ip,
		       fsp->m_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&full_key->ip_mask.v6_addrs.dst_ip,
		       fsp->m_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		full_key->ip_mask.src_port = fsp->m_u.tcp_ip6_spec.psrc;
		full_key->ip_mask.dst_port = fsp->m_u.tcp_ip6_spec.pdst;
		full_key->ip_mask.tclass = fsp->m_u.tcp_ip6_spec.tclass;
		full_key->ip_ver = 6;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		memcpy(&full_key->ip_data.v6_addrs.src_ip,
		       fsp->h_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&full_key->ip_data.v6_addrs.dst_ip,
		       fsp->h_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		full_key->ip_data.l4_header = fsp->h_u.usr_ip6_spec.l4_4_bytes;
		full_key->ip_data.tclass = fsp->h_u.usr_ip6_spec.tclass;
		if (!fsp->m_u.usr_ip6_spec.l4_proto)
			full_key->ip_data.proto = IPPROTO_NONE;
		else
			full_key->ip_data.proto = fsp->h_u.usr_ip6_spec.l4_proto;
		memcpy(&full_key->ip_mask.v6_addrs.src_ip,
		       fsp->m_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&full_key->ip_mask.v6_addrs.dst_ip,
		       fsp->m_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		full_key->ip_mask.l4_header = fsp->m_u.usr_ip6_spec.l4_4_bytes;
		full_key->ip_mask.tclass = fsp->m_u.usr_ip6_spec.tclass;
		full_key->ip_mask.proto = fsp->m_u.usr_ip6_spec.l4_proto;
		full_key->ip_ver = 6;
		break;
	case SXE2_FNAV_FLOW_TYPE_ETH:
		memcpy(full_key->eth_data.src, fsp->h_u.ether_spec.h_source,
		       sizeof(full_key->eth_data.src));
		memcpy(full_key->eth_data.dst, fsp->h_u.ether_spec.h_dest,
		       sizeof(full_key->eth_data.src));
		full_key->eth_data.etype = fsp->h_u.ether_spec.h_proto;
		memcpy(full_key->eth_mask.src, fsp->m_u.ether_spec.h_source,
		       sizeof(full_key->eth_mask.src));
		memcpy(full_key->eth_mask.dst, fsp->m_u.ether_spec.h_dest,
		       sizeof(full_key->eth_mask.src));
		full_key->eth_mask.etype = fsp->m_u.ether_spec.h_proto;
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

STATIC s32 sxe2vf_ethtool_fnav_valid_param_check(enum sxe2_fnav_flow_type flow_type,
						 struct ethtool_rx_flow_spec *fsp)
{
	s32 ret = 0;
	struct ethtool_tcpip4_spec *l4_ip4_spec = &fsp->m_u.tcp_ip4_spec;
	struct ethtool_tcpip6_spec *l4_ip6_spec = &fsp->m_u.tcp_ip6_spec;
	struct ethtool_usrip4_spec *usr_ip4_spec = &fsp->m_u.usr_ip4_spec;
	struct ethtool_usrip6_spec *usr_ip6_spec = &fsp->m_u.usr_ip6_spec;
	struct ethhdr *eth_spec = &fsp->m_u.ether_spec;

	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		if (is_zero_ether_addr(eth_spec->h_source) &&
		    is_zero_ether_addr(eth_spec->h_dest) && !eth_spec->h_proto &&
		    !fsp->m_ext.vlan_etype && !fsp->m_ext.vlan_tci) {
			return -EINVAL;
		}
		if (!sxe2vf_ethtool_vlan_seg_valid(fsp))
			return -EINVAL;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		if (!l4_ip4_spec->psrc && !l4_ip4_spec->ip4src &&
		    !l4_ip4_spec->pdst && !l4_ip4_spec->ip4dst &&
		    !l4_ip4_spec->tos) {
			return -EINVAL;
		}
		if ((!is_zero_ether_addr(fsp->m_ext.h_dest)) ||
		    fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci) {
			return -EOPNOTSUPP;
		}
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		if (ipv6_addr_any((struct in6_addr *)l4_ip6_spec->ip6src) &&
		    ipv6_addr_any((struct in6_addr *)l4_ip6_spec->ip6dst) &&
		    !l4_ip6_spec->psrc && !l4_ip6_spec->pdst &&
		    !l4_ip6_spec->tclass) {
			return -EINVAL;
		}
		if ((!is_zero_ether_addr(fsp->m_ext.h_dest)) ||
		    fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci) {
			return -EOPNOTSUPP;
		}
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		if (!usr_ip4_spec->ip4src && !usr_ip4_spec->ip4dst &&
		    !usr_ip4_spec->tos && !usr_ip4_spec->proto) {
			return -EINVAL;
		}
		if (fsp->m_u.usr_ip4_spec.l4_4_bytes ||
		    fsp->m_u.usr_ip4_spec.ip_ver ||
		    (!is_zero_ether_addr(fsp->m_ext.h_dest)) ||
		    fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci) {
			return -EOPNOTSUPP;
		}
		if (usr_ip4_spec->proto == 0xFF &&
		    (fsp->h_u.usr_ip4_spec.proto == SXE2VF_FNAV_L4_PROT_TCP ||
		     fsp->h_u.usr_ip4_spec.proto == SXE2VF_FNAV_L4_PROT_UDP ||
		     fsp->h_u.usr_ip4_spec.proto == SXE2VF_FNAV_L4_PROT_SCTP)) {
			return -EOPNOTSUPP;
		}
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		if (ipv6_addr_any((struct in6_addr *)usr_ip6_spec->ip6src) &&
		    ipv6_addr_any((struct in6_addr *)usr_ip6_spec->ip6dst) &&
		    !usr_ip6_spec->l4_proto && !usr_ip6_spec->tclass) {
			return -EINVAL;
		}
		if (fsp->m_u.usr_ip6_spec.l4_4_bytes ||
		    (!is_zero_ether_addr(fsp->m_ext.h_dest)) ||
		    fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci) {
			return -EOPNOTSUPP;
		}
		if (usr_ip6_spec->l4_proto == 0xFF &&
		    (fsp->h_u.usr_ip6_spec.l4_proto == SXE2VF_FNAV_L4_PROT_TCP ||
		     fsp->h_u.usr_ip6_spec.l4_proto == SXE2VF_FNAV_L4_PROT_UDP ||
		     fsp->h_u.usr_ip6_spec.l4_proto == SXE2VF_FNAV_L4_PROT_SCTP)) {
			return -EOPNOTSUPP;
		}
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

STATIC s32 sxe2vf_ethtool_fnav_filter_fill(struct sxe2vf_adapter *adapter,
					   struct ethtool_rx_flow_spec *fsp,
					   struct sxe2vf_fnav_filter *filter)
{
	int ret = 0;
	u32 ring = 0;
	u8 vf = 0;
	enum sxe2_fnav_flow_type flow_type;

#ifdef HAVE_ETHTOOL_FLOW_RSS
	flow_type = fsp->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);
#else
	flow_type = fsp->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT);
#endif
	flow_type = sxe2vf_ethtool_flow_to_type(flow_type);
	if (flow_type == SXE2_FNAV_FLOW_TYPE_NONE) {
#ifdef HAVE_ETHTOOL_FLOW_RSS
		LOG_DEV_ERR("unsupport flow type, fsp->flow_type:%d\n",
			    fsp->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS));
#else
		LOG_DEV_ERR("unsupport flow type, fsp->flow_type:%d\n",
			    fsp->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT));
#endif
		ret = -EINVAL;
		goto l_end;
	}
	filter->flow_type = flow_type;

	filter->filter_loc = fsp->location;

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		filter->act_type = SXE2_FNAV_ACTION_DROP;
		filter->q_index = 0;
	} else if ((~(ETHTOOL_RX_FLOW_SPEC_RING | ETHTOOL_RX_FLOW_SPEC_RING_VF)) &
		   fsp->ring_cookie) {
		LOG_DEV_ERR("failed to add filter. unsupported action %lld.\n",
			    fsp->ring_cookie);
		ret = -EOPNOTSUPP;
		goto l_end;
	} else {
		ring = (u32)ethtool_get_flow_spec_ring(fsp->ring_cookie);
		vf = (u8)ethtool_get_flow_spec_ring_vf(fsp->ring_cookie);
		if (vf) {
			LOG_DEV_ERR("failed to add filter. vf fnav\t"
				    "not supported on VF queues.\n");
			ret = -EINVAL;
			goto l_end;
		}
		if (ring >= adapter->vsi_ctxt.vf_vsi->rxqs.q_cnt) {
			LOG_DEV_ERR("failed to add filter. unsupported q_index \t"
				    "%u.\n",
				    ring);
			ret = -EINVAL;
			goto l_end;
		}
		filter->act_type = SXE2_FNAV_ACTION_QUEUE;
		filter->q_index = (u16)ring;
	}

	ret = sxe2vf_ethtool_fnav_valid_param_check(flow_type, fsp);
	if (ret) {
		LOG_ERROR_BDF("ethtool cmd has not support param, ret: %d\n", ret);
		goto l_end;
	}

	ret = sxe2vf_ethtool_fnav_full_key_fill(fsp, filter);
	if (ret) {
		LOG_ERROR_BDF("failed to add full key, ret: %d\n", ret);
		goto l_end;
	}
	ret = sxe2vf_validate_fnav_filter_masks(adapter, filter);
	if (ret)
		LOG_ERROR_BDF("failed to add full key, ret: %d\n", ret);

l_end:
	return ret;
}

STATIC int
sxe2vf_ethtool_parse_ntuple_userdef(struct sxe2vf_adapter *adapter,
				    struct sxe2vf_fnav_filter *filter,
				    struct sxe2_fnav_comm_user_data *user_data)
{
	u64 value, mask;
	u16 flex_offset;

	if (!filter->has_flex_filed)
		return 0;

	value = be64_to_cpu(*((__force __be64 *)filter->full_key.ext_data.usr_def));
	mask = be64_to_cpu(*((__force __be64 *)filter->full_key.ext_mask.usr_def));

	if (!mask)
		return 0;

	LOG_DEBUG_BDF("user-def param:0x%llx.\n", value);

	if (!((mask & SXE2VF_USERDEF_FLEX_FLTR_M) == SXE2VF_USERDEF_FLEX_FLTR_M) ||
	    value > SXE2VF_USERDEF_FLEX_FLTR_M) {
		LOG_ERROR_BDF("sxe2 vf fnav flex mask=%llu value=%llu is invalid.\n",
			      mask, value);
		return -EINVAL;
	}

	flex_offset = (u16)FIELD_GET(SXE2VF_USERDEF_FLEX_OFFS_M, value);
	if (flex_offset > SXE2VF_USERDEF_FLEX_MAX_OFFS_VAL) {
		LOG_ERROR_BDF("sxe2 vf fnav flex offset = %u is invalid.\n",
			      flex_offset);
		return -EINVAL;
	}

	user_data->flex_word =
			cpu_to_be16((u16)(value & SXE2VF_USERDEF_FLEX_WORD_M));
	user_data->flex_offset = cpu_to_le16(flex_offset);
	user_data->has_flex_filed = filter->has_flex_filed;

	return 0;
}

s32 sxe2vf_fill_fnav_filter_full_msg(struct sxe2vf_adapter *adapter,
				     struct sxe2vf_fnav_filter *filter)
{
	struct sxe2vf_fnav_filter_full_key *full_key = &filter->full_key;
	struct sxe2_fnav_comm_full_msg *full_msg = &filter->full_msg;
	int ret = 0;
	u32 i = 0;
	u8 act_count = 2;

	full_msg->filter_loc = cpu_to_le32(filter->filter_loc);
	full_msg->flow_type = cpu_to_le32(filter->flow_type);

	full_msg->action_cnt = act_count;
	full_msg->action[0].act_queue.q_index = cpu_to_le16(filter->q_index);
	full_msg->action[0].type = cpu_to_le32(filter->act_type);
	full_msg->action[1].act_count.stat_ctrl =
			cpu_to_le32(SXE2_FNAV_STAT_ENA_PKTS);
	full_msg->action[1].act_count.stat_index =
			cpu_to_le32(adapter->fnav_ctxt.stat_idx);
	full_msg->action[1].type = cpu_to_le32(SXE2_FNAV_ACTION_COUNT);

	full_msg->proto_cnt = 0;

	switch (full_msg->flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		sxe2vf_fill_fnav_eth_hdr(full_key, full_msg);
		if (full_key->ext_mask.vlan_type || full_key->ext_mask.s_vlan_tag)
			sxe2vf_fill_fnav_vlan_hdr(full_key, full_msg);

		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		sxe2vf_fill_fnav_ip4_hdr(full_key, full_msg);
		sxe2vf_fill_fnav_tcp_hdr(full_key, full_msg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		sxe2vf_fill_fnav_ip4_hdr(full_key, full_msg);
		sxe2vf_fill_fnav_udp_hdr(full_key, full_msg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		sxe2vf_fill_fnav_ip4_hdr(full_key, full_msg);
		sxe2vf_fill_fnav_sctp_hdr(full_key, full_msg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		sxe2vf_fill_fnav_ip4_hdr(full_key, full_msg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		sxe2vf_fill_fnav_ip6_hdr(full_key, full_msg);
		sxe2vf_fill_fnav_tcp_hdr(full_key, full_msg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		sxe2vf_fill_fnav_ip6_hdr(full_key, full_msg);
		sxe2vf_fill_fnav_udp_hdr(full_key, full_msg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		sxe2vf_fill_fnav_ip6_hdr(full_key, full_msg);
		sxe2vf_fill_fnav_sctp_hdr(full_key, full_msg);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		sxe2vf_fill_fnav_ip6_hdr(full_key, full_msg);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret || full_msg->proto_cnt == 0) {
		LOG_ERROR_BDF("ethtool fnav parse proto failed, ret:%d, \t"
			      "proto_cnt:%u.\n",
			      ret, full_msg->proto_cnt);
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2vf_ethtool_parse_ntuple_userdef(adapter, filter,
						  &full_msg->usr_data);
	if (ret) {
		LOG_ERROR_BDF("ethtool fnav parse user data failed, ret:%d\n", ret);
		goto l_end;
	}

	for (i = 0; i < full_msg->proto_cnt; i++)
		full_msg->proto_hdr[i].tunnel_level = SXE2_FNAV_TUN_FLAG_ANY;

	if (test_bit(SXE2VF_FLAG_FNAV_TUNNEL, adapter->flags))
		full_msg->tunn_flag = cpu_to_le32(SXE2_FNAV_TUN_FLAG_ANY);
	else
		full_msg->tunn_flag = cpu_to_le32(SXE2_FNAV_TUN_FLAG_NO_TUNNEL);

l_end:
	return ret;
}

STATIC s32 sxe2vf_fnav_check_and_remove_filter_at_loc(struct sxe2vf_adapter *adapter,
						      u32 loc)
{
	struct sxe2vf_fnav_filter *filter_old = NULL;
	s32 ret = 0;

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);

	filter_old = sxe2vf_fnav_find_filter_by_loc_unlock(adapter, loc);
	if (filter_old) {
		ret = sxe2vf_fnav_del_filter(adapter, filter_old);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf fnav delete filter failed, ret:%d\n",
				      ret);
		}
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);
	return ret;
}

s32 sxe2vf_fnav_add_filter_with_packet(struct sxe2vf_adapter *adapter,
				       struct sxe2vf_fnav_filter *filter)
{
	struct sxe2_fnav_comm_full_msg *filter_msg = NULL;
	struct sxe2vf_msg_params params = {0};
	s32 ret = 0;
	struct sxe2_vf_fnav_add_filter_resp filter_resp;

	filter_msg = kzalloc(sizeof(*filter_msg), GFP_KERNEL);
	if (!filter_msg) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("No memory!\n");
		goto l_end;
	}

	memcpy(filter_msg, &filter->full_msg,
	       sizeof(*filter_msg));
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_FNAV_FILTER_ADD, filter_msg,
					sizeof(*filter_msg),
					&filter_resp, sizeof(filter_resp));

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav add filter fail, ret = %d !\n", ret);
	} else {
		filter->flow_id = filter_resp.flow_id;
		LOG_INFO_BDF("sxe2 vf fnav add filter success, flow_id = %u !\n",
			     filter_resp.flow_id);
	}

l_end:
	kfree(filter_msg);

	return ret;
}

#ifdef SXE2_SUPPORT_ACL
STATIC bool sxevf_is_acl_filter(struct ethtool_rx_flow_spec *fsp)
{
	struct ethtool_tcpip4_spec *tcp_ip4_spec;
	struct ethtool_usrip4_spec *usr_ip4_spec;
	struct ethhdr *eth_spec;

	switch (fsp->flow_type & ~FLOW_EXT) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		tcp_ip4_spec = &fsp->m_u.tcp_ip4_spec;

		if (tcp_ip4_spec->ip4src &&
		    tcp_ip4_spec->ip4src != htonl(0xFFFFFFFF))
			return true;

		if (tcp_ip4_spec->ip4dst &&
		    tcp_ip4_spec->ip4dst != htonl(0xFFFFFFFF))
			return true;

		if (!tcp_ip4_spec->ip4src && !tcp_ip4_spec->ip4dst &&
		    !tcp_ip4_spec->psrc && !tcp_ip4_spec->pdst && !tcp_ip4_spec->tos)
			return true;

		if (tcp_ip4_spec->psrc && tcp_ip4_spec->psrc != htons(0xFFFF))
			return true;

		if (tcp_ip4_spec->pdst && tcp_ip4_spec->pdst != htons(0xFFFF))
			return true;

		break;
	case IPV4_USER_FLOW:
		usr_ip4_spec = &fsp->m_u.usr_ip4_spec;

		if (usr_ip4_spec->ip4src &&
		    usr_ip4_spec->ip4src != htonl(0xFFFFFFFF))
			return true;

		if (usr_ip4_spec->ip4dst &&
		    usr_ip4_spec->ip4dst != htonl(0xFFFFFFFF))
			return true;

		if (!usr_ip4_spec->ip4src && !usr_ip4_spec->ip4dst)
			return true;

		break;
	case ETHER_FLOW:
		eth_spec = &fsp->m_u.ether_spec;

		if (fsp->m_ext.vlan_tci || fsp->m_ext.vlan_etype)
			return false;

		if (!is_broadcast_ether_addr(eth_spec->h_dest) &&
		    !is_zero_ether_addr(eth_spec->h_dest))
			return true;

		if (!is_broadcast_ether_addr(eth_spec->h_source) &&
		    !is_zero_ether_addr(eth_spec->h_source))
			return true;

		if (eth_spec->h_proto && eth_spec->h_proto != htons(0xFFFF))
			return true;

		if (!eth_spec->h_proto && is_zero_ether_addr(eth_spec->h_source) &&
		    is_zero_ether_addr(eth_spec->h_dest))
			return true;

		break;
	}

	return false;
}

STATIC int sxe2vf_ethtool_acl_filter_add(struct sxe2vf_adapter *adapter,
					 struct ethtool_rx_flow_spec *fsp)
{
	struct sxe2vf_msg_params params = {};
	s32 ret = 0;

	sxe2vf_mbx_msg_dflt_params_fill(&params,
					SXE2VF_MSG_RESP_WAIT_NOTIFY, SXE2_VF_ACL_FILTER_ADD,
					fsp, sizeof(struct ethtool_rx_flow_spec), NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf acl add filter fail, ret = %d !\n", ret);
	else
		LOG_INFO_BDF("sxe2 vf acl add filter success\n");

	return ret;
}
#endif
STATIC int sxe2vf_ethtool_ntuple_filter_add(struct sxe2vf_adapter *adapter,
					    struct ethtool_rxnfc *cmd)
{
	int ret = 0;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct ethtool_rx_flow_spec *fsp = NULL;
	struct sxe2vf_fnav_filter *filter = NULL;
	struct sxe2vf_fnav_filter *filter_tmp = NULL;
	struct sxe2vf_fnav_filter *pre = NULL;

	if (!test_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags)) {
		LOG_DEV_ERR("ntuple feature is not enabled, please type in\t"
			    " \"ethtool -K {dev} ntuple on\" to enable ntuple \t"
			    "firstly.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
	if (fsp->flow_type & FLOW_MAC_EXT) {
		LOG_DEV_ERR("unsupport flow type \"FLOW_MAC_EXT\".\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}
#ifdef SXE2_SUPPORT_ACL
	if (sxevf_is_acl_filter(fsp)) {
		ret = sxe2vf_ethtool_acl_filter_add(adapter, fsp);
		if (ret)
			LOG_DEV_ERR("add acl filter failed, ret:%d.\n", ret);

		goto l_end;
	}
#endif
	if (adapter->fnav_ctxt.filter_cnt >= SXE2VF_MAX_FNAV_FILTERS ||
	    fsp->location >= SXE2VF_MAX_FNAV_FILTERS) {
		LOG_ERROR_BDF("location overflow, filter_cnt:%u, max_cnt:%u, \t"
			      "location:%u\n",
			      adapter->fnav_ctxt.filter_cnt, SXE2VF_MAX_FNAV_FILTERS,
			      fsp->location);
		ret = -ENOSPC;
		goto l_end;
	}

	filter = devm_kzalloc(dev, sizeof(*filter), GFP_KERNEL);
	if (!filter) {
		LOG_ERROR_BDF("no memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	ret = sxe2vf_ethtool_fnav_filter_fill(adapter, fsp, filter);
	if (ret) {
		LOG_ERROR_BDF("ethtool fnav filter fill failed, ret:%d\n", ret);
		goto l_end;
	}

	if (sxe2vf_fnav_is_dup_filter(adapter, filter)) {
		LOG_DEV_ERR("duplicate rule is detected\n");
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2vf_fnav_check_and_remove_filter_at_loc(adapter, fsp->location);
	if (ret) {
		LOG_ERROR_BDF("ethtool fnav filter del same loc=%d failed, ret:%d\n",
			      fsp->location, ret);
		goto l_end;
	}

	ret = sxe2vf_fill_fnav_filter_full_msg(adapter, filter);
	if (ret) {
		LOG_ERROR_BDF("ethtool fnav fill fdir flow cfg failed, ret:%d\n",
			      ret);
		goto l_end;
	}

	ret = sxe2vf_fnav_add_filter_with_packet(adapter, filter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav add filter fail, ret = %d !\n", ret);
	} else {
		list_for_each_entry(filter_tmp, &adapter->fnav_ctxt.filter_list,
				    l_node) {
			if (filter_tmp->filter_loc >= filter->filter_loc)
				break;

			pre = filter_tmp;
		}
		if (pre)
			list_add(&filter->l_node, &pre->l_node);
		else
			list_add(&filter->l_node, &adapter->fnav_ctxt.filter_list);

		adapter->fnav_ctxt.filter_cnt++;
	}

l_end:
	if (filter && ret)
		devm_kfree(dev, filter);

	return ret;
}

#ifdef SXE2_SUPPORT_ACL
static s32 sxe2vf_acl_del_filter(struct sxe2vf_adapter *adapter, u32 loc)
{
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};
	struct sxe2vf_acl_filter_del_req del_msg;

	del_msg.filter_id = cpu_to_le32(loc);

	sxe2vf_mbx_msg_dflt_params_fill(&params,
					SXE2VF_MSG_RESP_WAIT_NOTIFY, SXE2_VF_ACL_FILTER_DEL,
					&del_msg,
					sizeof(struct sxe2vf_acl_filter_del_req), NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav del filter fail!\n");
	else
		LOG_INFO_BDF("sxe2 vf acl del filter success!\n");

	return ret;
}
#endif
STATIC s32 sxe2vf_ethtool_ntuple_filter_del(struct sxe2vf_adapter *adapter,
					    struct ethtool_rxnfc *cmd)
{
	s32 ret = -ENOENT;
	struct sxe2vf_fnav_filter *filter;
	struct ethtool_rx_flow_spec *fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	if (!test_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags)) {
		LOG_DEV_ERR("ntuple feature is not enabled, please type \t"
			    "in \"ethtool -K {dev} ntuple on\" to enable ntuple \t"
			    "firstly.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);
	filter = sxe2vf_fnav_find_filter_by_loc_unlock(adapter, fsp->location);
	if (filter) {
		ret = sxe2vf_fnav_del_filter(adapter, filter);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf fnav delete filter failed, ret:%d\n",
				      ret);
		}
#ifdef SXE2_SUPPORT_ACL
	} else {
		ret = sxe2vf_acl_del_filter(adapter, fsp->location);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf acl delete filter failed, ret:%d\n",
				      ret);
		}
	}
#else
	}
#endif
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);

l_end:
	return ret;
}

STATIC int sxe2vf_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	int ret = -EOPNOTSUPP;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		LOG_ERROR_BDF("sxe2 vf rss (id: %u)ethtool set rxnfc state is \t"
			      "disable.\n",
			      vsi->vsi_id);
		ret = -EBUSY;
		goto l_unlock;
	}

	LOG_DEBUG_BDF("set rxnfc, cmd: %u\n", cmd->cmd);

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		ret = sxe2vf_set_rss_flow(adapter, cmd);
		break;
	case ETHTOOL_SRXCLSRLINS:
		ret = sxe2vf_ethtool_ntuple_filter_add(adapter, cmd);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		ret = sxe2vf_ethtool_ntuple_filter_del(adapter, cmd);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static const struct ethtool_ops sxe2vf_ethtool_ops = {
#ifdef SUPPORTED_COALESCE_PARAMS
		.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
					     ETHTOOL_COALESCE_USE_ADAPTIVE,
#endif
		.get_sset_count = sxe2vf_get_sset_count,
		.get_strings = sxe2vf_get_strings,
		.get_ethtool_stats = sxe2vf_get_ethtool_stats,

		.get_priv_flags = sxe2vf_get_priv_flags,
		.set_priv_flags = sxe2vf_set_priv_flags,

		.get_ringparam = sxe2vf_get_ringparam,
		.set_ringparam = sxe2vf_set_ringparam,

		.get_channels = sxe2vf_get_channels,
		.set_channels = sxe2vf_set_channels,

		.get_link = ethtool_op_get_link,
		.get_link_ksettings = sxe2vf_get_link_ksettings,
		.get_drvinfo = sxe2vf_get_drvinfo,

		.get_msglevel = sxe2vf_get_msglevel,
		.set_msglevel = sxe2vf_set_msglevel,

		.get_per_queue_coalesce = sxe2vf_get_per_queue_coalesce,
		.set_per_queue_coalesce = sxe2vf_set_per_queue_coalesce,
		.set_coalesce = sxe2vf_set_coalesce,
		.get_coalesce = sxe2vf_get_coalesce,

		.get_rxnfc = sxe2vf_get_rxnfc,
		.set_rxnfc = sxe2vf_set_rxnfc,
		.get_rxfh_key_size = sxe2vf_get_rxft_key_size,
		.get_rxfh_indir_size = sxe2vf_get_rxft_indir_size,
		.get_rxfh = sxe2vf_get_rxfh,
		.set_rxfh = sxe2vf_set_rxfh,
};

void sxe2vf_ethtool_ops_init(struct net_device *netdev)
{
	netdev->ethtool_ops = &sxe2vf_ethtool_ops;
}
