// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_netdev.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/netdevice.h>
#include <net/dsfield.h>
#include <linux/if_macvlan.h>

#include "sxe2_compat.h"
#include "sxe2_tx.h"
#include "sxe2_rx.h"
#include "sxe2_log.h"
#include "sxe2_netdev.h"
#include "sxe2_common.h"
#include "sxe2_dcb_nl.h"
#include "sxe2_ethtool.h"
#include "sxe2_txsched.h"
#include "sxe2_macvlan.h"
#include "sxe2_tc.h"
#include "sxe2_sriov.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_ipsec.h"
#include "sxe2_fnav.h"
#include "sxe2_dev_ctrl.h"
#include "sxe2_xsk.h"
#include "sxe2_monitor.h"
#include "sxe2_linkchg.h"
#include "sxe2_cmd.h"

#define SXE2_SET_FEATURE(features, feature, enable)                                 \
	do {                                                                        \
		typeof(feature) _feature = (feature);                               \
		typeof(features) _features = (features);                               \
		if (enable)                                                         \
			*_features |= _feature;                                      \
		else                                                                \
			*_features &= ~_feature;                                     \
	} while (0)

static inline int sxe2_conflict_features_chk(u64 changed_features, u64 features,
					     u64 con1, u64 con2)
{
	if ((changed_features & con1 && features & con1) &&
	    (changed_features & con2 && features & con2))
		return -EINVAL;

	return 0;
}

static int sxe2_eth_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct sxe2_netdev_priv *netpriv = netdev_priv(dev);
	struct sxe2_adapter *adapter = netpriv->vsi->adapter;

	switch (cmd) {
	case SIOCSHWTSTAMP:
		return sxe2_ptp_hwts_set(adapter, ifr);
	case SIOCGHWTSTAMP:
		return sxe2_ptp_hwts_get(adapter, ifr);
	default:
		break;
	}
	return -EOPNOTSUPP;
}

void sxe2_fetch_u64_data_per_ring(struct u64_stats_sync *syncp,
				  struct sxe2_queue_stats *stats, u64 *pkts,
				  u64 *bytes)
{
	u32 start;

	do {
		start = u64_stats_fetch_begin(syncp);
		*pkts = stats->packets;
		*bytes = stats->bytes;
	} while (u64_stats_fetch_retry(syncp, start));
}

#ifdef HAVE_RTNL_LINK_NDO_GET_STATS64
STATIC struct rtnl_link_stats64 *sxe2_get_stats64(struct net_device *netdev,
						  struct rtnl_link_stats64 *stats)
#else
STATIC void sxe2_get_stats64(struct net_device *netdev,
			     struct rtnl_link_stats64 *stats)
#endif
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	sxe2_sw_vsi_stats_update(vsi);

	stats->tx_packets = vsi->vsi_stats.vsi_sw_stats.tx_packets;
	stats->rx_packets = vsi->vsi_stats.vsi_sw_stats.rx_packets;
	stats->tx_bytes = vsi->vsi_stats.vsi_sw_stats.tx_bytes;
	stats->rx_bytes = vsi->vsi_stats.vsi_sw_stats.rx_bytes;

	stats->multicast = vsi->vsi_stats.vsi_hw_stats.rx_vsi_multicast_packets;
	stats->rx_crc_errors = adapter->pf_stats.pf_hw_stats.rx_crc_errors;

	if (vsi->type == SXE2_VSI_T_PF) {
		stats->rx_errors = adapter->pf_stats.pf_hw_stats.rx_crc_errors +
				   adapter->pf_stats.pf_hw_stats.rx_illegal_bytes +
				   adapter->pf_stats.pf_hw_stats.rx_len_errors +
				   adapter->pf_stats.pf_hw_stats.rx_undersize_good +
				   vsi->vsi_stats.vsi_sw_stats.rx_csum_err +
				   adapter->pf_stats.pf_hw_stats.rx_oversize_good +
				   vsi->vsi_stats.vsi_sw_stats.rx_pkts_sw_drop;
		stats->rx_length_errors =
				adapter->pf_stats.pf_hw_stats.rx_len_errors;
		stats->rx_missed_errors =
				adapter->pf_stats.pf_hw_stats.rx_out_of_buffer;
	}

#ifdef HAVE_RTNL_LINK_NDO_GET_STATS64
	return stats;
#endif
}

#ifdef HAVE_XDP_SUPPORT
STATIC s32 sxe2_max_xdp_frame_size(struct sxe2_vsi *vsi)
{
	if (PAGE_SIZE >= 8192 ||
	    test_bit(SXE2_FLAG_LEGACY_RX_ENABLE, vsi->adapter->flags))
		return SXE2_RXBUF_2048 - XDP_PACKET_HEADROOM;
	else
		return SXE2_RXBUF_3072;
}
#endif

s32 sxe2_set_mtu_cfg(struct sxe2_adapter *adapter, u32 set_mtu)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_fw_mtu_info mtu = {0};

	mtu.is_set_hw = false;
	mtu.mtu = set_mtu;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MAC_MTU_SET, &mtu,
				  sizeof(struct sxe2_fw_mtu_info), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("failed to mtu, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

out:
	return ret;
}

static int sxe2_change_mtu(struct net_device *netdev, int new_mtu)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	u32 old_mtu = netdev->mtu;

	if (new_mtu < ETH_MIN_MTU || new_mtu > SXE2_MAX_MTU) {
		LOG_NETDEV_ERR("new MTU invalid. mtu range is %d-%d", ETH_MIN_MTU,
			       SXE2_MAX_MTU);
		return -EINVAL;
	}

	if (new_mtu == (int)netdev->mtu) {
		LOG_NETDEV_WARN("MTU is already %u\n", netdev->mtu);
		return 0;
	}

#ifdef HAVE_XDP_SUPPORT
	if (sxe2_xdp_is_enable(vsi)) {
		int frame_size = sxe2_max_xdp_frame_size(vsi);

		if (new_mtu + SXE2_PACKET_HDR_PAD > frame_size) {
			LOG_NETDEV_ERR("max MTU for XDP usage is %d\n",
				       frame_size - SXE2_PACKET_HDR_PAD);
			return -EINVAL;
		}
	}
#endif

	netdev->mtu = (unsigned int)new_mtu;
	ret = sxe2_set_mtu_cfg(adapter, netdev->mtu);
	if (ret) {
		LOG_NETDEV_ERR("max set failed is mtu:%d, ret: %d\n", netdev->mtu,
			       ret);
	}
	ret = sxe2_vsi_down_up(vsi);
	if (ret) {
		netdev->mtu = old_mtu;
		LOG_NETDEV_ERR("changing MTU from %u to %d failed.\n", old_mtu,
			       new_mtu);
		goto l_end;
	}

	LOG_NETDEV_DEBUG("changed MTU to %d suc\n", new_mtu);

	if (new_mtu > SXE2_IPSEC_PAYLOAD_LIMIT &&
	    sxe2_is_ipsec_offload_enable(netdev)) {
		LOG_NETDEV_WARN("SXE2:the maximum encryption length of IPsec is\n"
				"2k.\n"
				"If the packet length is greater than 2k,\n"
				"the hardware ipsec offloading may fail.\n");
	}

	set_bit(SXE2_FLAG_MTU_CHANGED, adapter->flags);

l_end:
	return ret;
}

void sxe2_set_vlan_offload_features(struct sxe2_vsi *vsi,
				    netdev_features_t current_features,
				    netdev_features_t requested_features)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;

	netdev_features_t current_stag_strip;
	netdev_features_t requested_stag_strip;
	netdev_features_t current_ctag_strip;
	netdev_features_t requested_ctag_strip;
	netdev_features_t current_stag_insert;
	netdev_features_t requested_stag_insert;
	netdev_features_t current_ctag_insert;
	netdev_features_t requested_ctag_insert;

	current_stag_strip = current_features & NETIF_F_HW_VLAN_STAG_RX;
	requested_stag_strip = requested_features & NETIF_F_HW_VLAN_STAG_RX;
	current_ctag_strip = current_features & NETIF_F_HW_VLAN_CTAG_RX;
	requested_ctag_strip = requested_features & NETIF_F_HW_VLAN_CTAG_RX;
	current_stag_insert = current_features & NETIF_F_HW_VLAN_STAG_TX;
	requested_stag_insert = requested_features & NETIF_F_HW_VLAN_STAG_TX;
	current_ctag_insert = current_features & NETIF_F_HW_VLAN_CTAG_TX;
	requested_ctag_insert = requested_features & NETIF_F_HW_VLAN_CTAG_TX;

	if (current_ctag_strip != requested_ctag_strip && !requested_ctag_strip)
		(void)sxe2_hw_desc_vlan_strip_switch(hw, vsi->idx_in_dev,
						     ETH_P_8021Q, false, false);
	else if ((current_stag_strip != requested_stag_strip) &&
		 !requested_stag_strip)
		(void)sxe2_hw_desc_vlan_strip_switch(hw, vsi->idx_in_dev,
						     ETH_P_8021AD, false, false);

	if (current_ctag_strip != requested_ctag_strip && requested_ctag_strip)
		(void)sxe2_hw_desc_vlan_strip_switch(hw, vsi->idx_in_dev,
						     ETH_P_8021Q, false, true);
	else if ((current_stag_strip != requested_stag_strip) &&
		 requested_stag_strip)
		(void)sxe2_hw_desc_vlan_strip_switch(hw, vsi->idx_in_dev,
						     ETH_P_8021AD, false, true);

	if (current_ctag_insert != requested_ctag_insert && !requested_ctag_insert)
		(void)sxe2_hw_desc_vlan_insert_switch(hw, vsi->idx_in_dev,
						      ETH_P_8021Q, false, false);
	else if ((current_stag_insert != requested_stag_insert) &&
		 !requested_stag_insert)
		(void)sxe2_hw_desc_vlan_insert_switch(hw, vsi->idx_in_dev,
						      ETH_P_8021AD, false, false);

	if (current_ctag_insert != requested_ctag_insert && requested_ctag_insert)
		(void)sxe2_hw_desc_vlan_insert_switch(hw, vsi->idx_in_dev,
						      ETH_P_8021Q, false, true);
	else if ((current_stag_insert != requested_stag_insert) &&
		 requested_stag_insert)
		(void)sxe2_hw_desc_vlan_insert_switch(hw, vsi->idx_in_dev,
						      ETH_P_8021AD, false, true);
}

s32 sxe2_set_vlan_filter_features(struct sxe2_vsi *vsi, netdev_features_t features)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags))
		return ret;

	if (features & (NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER)) {
		if (vsi->netdev && !(vsi->netdev->flags & IFF_PROMISC))
			ret = sxe2_vlan_filter_control(adapter, vsi->idx_in_dev,
						       true);
	} else {
		ret = sxe2_vlan_filter_control(adapter, vsi->idx_in_dev, false);
	}
	return ret;
}

static s32 sxe2_set_vlan_features(struct net_device *netdev,
				  netdev_features_t features,
				  netdev_features_t *oper_features)
{
	netdev_features_t current_features, requested_features;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = np->vsi->adapter;
	s32 ret = 0;

	current_features = netdev->features & NETIF_VLAN_OFFLOAD_FEATURES;
	requested_features = features & NETIF_VLAN_OFFLOAD_FEATURES;
	if (current_features ^ requested_features) {
		sxe2_set_vlan_offload_features(vsi, current_features,
					       requested_features);
		SXE2_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_CTAG_RX,
				 (features & NETIF_F_HW_VLAN_CTAG_RX));
		SXE2_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_CTAG_TX,
				 (features & NETIF_F_HW_VLAN_CTAG_TX));
		SXE2_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_STAG_RX,
				 (features & NETIF_F_HW_VLAN_STAG_RX));
		SXE2_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_STAG_TX,
				 (features & NETIF_F_HW_VLAN_STAG_TX));
	}

	current_features = netdev->features & NETIF_VLAN_FILTERING_FEATURES;
	requested_features = features & NETIF_VLAN_FILTERING_FEATURES;
	if (current_features ^ requested_features) {
		ret = sxe2_set_vlan_filter_features(vsi, features);
		if (!ret) {
			SXE2_SET_FEATURE(oper_features,
					 NETIF_VLAN_FILTERING_FEATURES,
					 (features & NETIF_VLAN_FILTERING_FEATURES));
		}
	}

	LOG_DEBUG_BDF("current features %llx, request features %llx\n",
		      netdev->features, features);
	return ret;
}

static s32 sxe2_set_lro_features(struct net_device *netdev,
				 netdev_features_t features,
				 netdev_features_t *oper_features)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	bool need_reinit = false;
	s32 ret = 0;
	bool lro_ena = !!(features & NETIF_F_LRO);
	bool old_lro_feature = (bool)test_bit(SXE2_VSI_FLAG_LRO_ENABLE, vsi->flags);

	if (!(features & NETIF_F_LRO)) {
		if (test_bit(SXE2_VSI_FLAG_LRO_ENABLE, vsi->flags)) {
			need_reinit = true;
			clear_bit(SXE2_VSI_FLAG_LRO_ENABLE, vsi->flags);
			LOG_DEBUG_BDF("lro disabled and need reinit\n");
		}
	} else {
		if (!(features & NETIF_F_RXCSUM)) {
			LOG_NETDEV_ERR("Cannot simultaneously enable lro and \t"
				       "disable rx csum.\n");
			return -EOPNOTSUPP;
		}

		if (!(test_bit(SXE2_VSI_FLAG_LRO_ENABLE, vsi->flags))) {
			need_reinit = true;
			set_bit(SXE2_VSI_FLAG_LRO_ENABLE, vsi->flags);
			LOG_DEBUG_BDF("lro enabled and need reinit\n");
		}
	}

	if (need_reinit) {
		if (!test_and_set_bit(SXE2_VSI_S_DOWN, vsi->state)) {
			ret = sxe2_vsi_down(vsi);
			if (ret) {
				LOG_NETDEV_ERR("set_features if_down err %d\n", ret);
				goto l_end;
			}

			ret = sxe2_vsi_up(vsi);
			if (ret) {
				LOG_NETDEV_ERR("set_features if_up err %d\n", ret);
			} else {
				SXE2_SET_FEATURE(oper_features, NETIF_F_LRO,
						 lro_ena);
			}
		}
	}

l_end:
	if (ret) {
		if (old_lro_feature)
			set_bit(SXE2_VSI_FLAG_LRO_ENABLE, vsi->flags);
		else
			clear_bit(SXE2_VSI_FLAG_LRO_ENABLE, vsi->flags);
	}

	return ret;
}

static s32 sxe2_set_macvlan_features(struct net_device *netdev,
				     netdev_features_t features,
				     netdev_features_t *oper_features)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;

	if ((features & NETIF_F_HW_L2FW_DOFFLOAD) &&
	    !(netdev->features & NETIF_F_HW_L2FW_DOFFLOAD)) {
		ret = sxe2_macvlan_init(vsi, true);
		if (!ret) {
			SXE2_SET_FEATURE(oper_features, NETIF_F_HW_L2FW_DOFFLOAD,
					 (features & NETIF_F_HW_L2FW_DOFFLOAD));
		}
	} else if (!(features & NETIF_F_HW_L2FW_DOFFLOAD) &&
		   (netdev->features & NETIF_F_HW_L2FW_DOFFLOAD)) {
		ret = sxe2_macvlan_deinit(vsi, true);
		if (!ret) {
			SXE2_SET_FEATURE(oper_features, NETIF_F_HW_L2FW_DOFFLOAD,
					 (features & NETIF_F_HW_L2FW_DOFFLOAD));
		}
	}

	return ret;
}

static s32 sxe2_set_fnav_features(struct net_device *netdev,
				  netdev_features_t features,
				  netdev_features_t *oper_features)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	netdev_features_t changed_features = netdev->features ^ features;
	bool fnav_ena = !!(features & NETIF_F_NTUPLE);

	if (changed_features & NETIF_F_NTUPLE) {
		ret = sxe2_fnav_switch(adapter, fnav_ena);
		if (!ret) {
			SXE2_SET_FEATURE(oper_features, NETIF_F_NTUPLE, fnav_ena);
		} else {
			LOG_DEV_ERR("%s feature %llx failed, ret %d\n",
				    fnav_ena ? "enable" : "disable",
				    (u64)NETIF_F_NTUPLE, ret);
		}
	}

	return ret;
}

static s32 sxe2_set_rxcsum_features(struct net_device *netdev,
				    netdev_features_t features,
				    netdev_features_t *oper_features)
{
	s32 ret = 0;
	bool rxcsum_ena = !!(features & NETIF_F_RXCSUM);

	SXE2_SET_FEATURE(oper_features, NETIF_F_RXCSUM, rxcsum_ena);

	return ret;
}

static s32 sxe2_set_rxfcs_features(struct net_device *netdev,
				   netdev_features_t features,
				   netdev_features_t *oper_features)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	bool need_reinit = false;
	s32 ret = 0;
	bool rxfcs_ena = !!(features & NETIF_F_RXFCS);
	bool old_rxfcs_feature =
			(bool)test_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, vsi->flags);

	if (!(features & NETIF_F_RXFCS)) {
		if (test_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, vsi->flags)) {
			need_reinit = true;
			clear_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, vsi->flags);
			LOG_DEBUG_BDF("rxfcs disabled and need reinit\n");
		}
	} else {
		if (!(test_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, vsi->flags))) {
			need_reinit = true;
			set_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, vsi->flags);
			LOG_DEBUG_BDF("rxfcs enabled and need reinit\n");
		}
	}

	if (need_reinit) {
		if (!test_and_set_bit(SXE2_VSI_S_DOWN, vsi->state)) {
			ret = sxe2_vsi_down(vsi);
			if (ret) {
				LOG_NETDEV_ERR("set_features if_down err %d\n", ret);
				goto l_end;
			}

			ret = sxe2_vsi_up(vsi);
			if (ret) {
				LOG_NETDEV_ERR("set_features if_up err %d\n", ret);
			} else {
				SXE2_SET_FEATURE(oper_features, NETIF_F_RXFCS,
						 rxfcs_ena);
			}
		}
	}

l_end:
	if (ret) {
		if (old_rxfcs_feature)
			set_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, vsi->flags);
		else
			clear_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, vsi->flags);
	}

	return ret;
}

#ifdef HAVE_MACSEC_SUPPORT
static s32 sxe2_set_macsec_features(struct net_device *netdev,
				    netdev_features_t features,
				    netdev_features_t *oper_features)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	netdev_features_t changed_features = netdev->features ^ features;
	bool macsec_ena = !!(features & NETIF_F_HW_MACSEC);

	if (changed_features & NETIF_F_HW_MACSEC) {
		if (macsec_ena) {
			LOG_DEBUG_BDF("enable macsec offload(off to on).\n");
			if (sxe2_macsec_conflict_features_check(netdev)) {
				LOG_DEV_ERR("failed to enable macsec offload,\t"
					    "please disable ipsec offload \t"
					    "feature.\n");
				ret = -EINVAL;
			}
		}
		{
			LOG_DEBUG_BDF("disable macsec offload switch(on to off).\n");
			if (sxe2_is_macsec_can_not_disable(adapter)) {
				LOG_DEV_ERR("can not disable macsec offload,\t"
					    "please delete the secy first.\n");
				ret = -EINVAL;
			}
		}
		if (!ret) {
			SXE2_SET_FEATURE(oper_features, NETIF_F_HW_MACSEC,
					 macsec_ena);
		}
	}

	return ret;
}
#endif

STATIC s32 sxe2_set_ipsec_features(struct net_device *netdev,
				   netdev_features_t features,
				   netdev_features_t *oper_features)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	netdev_features_t changed_features = netdev->features ^ features;
	bool ipsec_ena = !!(features & NETIF_F_HW_ESP);

	if (changed_features & NETIF_F_HW_ESP) {
		mutex_lock(&adapter->ipsec_ctxt.context_lock);
		if (ipsec_ena) {
			LOG_DEBUG_BDF("enable ipsec offload(off to on).\n");
			if (sxe2_ipsec_conflict_features_check(adapter, netdev)) {
				LOG_DEV_ERR("failed to enable ipsec offload, please \t"
					    "disable tx segmentation offload \t"
					    "features,tx vlan offload feature and \t"
					    "LRO offload feature.\n");
				ret = -EINVAL;
			}
		} else {
			LOG_DEBUG_BDF("disable ipsec offload switch(on to off).\n");
			if (sxe2_is_ipsec_can_not_disable(adapter)) {
				LOG_DEV_ERR("can not disable ipsec offload, please \t"
					    "delete all xfrm state before disable \t"
					    "ipsec offload\n");
				ret = -EINVAL;
			}
		}
		if (!ret)
			SXE2_SET_FEATURE(oper_features, NETIF_F_HW_ESP, ipsec_ena);

		mutex_unlock(&adapter->ipsec_ctxt.context_lock);
	}

	return ret;
}

static s32 sxe2_conflict_features_check(struct net_device *netdev,
					netdev_features_t features)
{
	netdev_features_t changed_features = netdev->features ^ features;
	netdev_features_t conflict1, conflict2;

	(void)changed_features;
	(void)conflict1;
	(void)conflict2;

	conflict1 = NETIF_F_HW_ESP;
	conflict2 = 0 | NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6 |
		    NETIF_F_GSO_GRE | NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_GRE_CSUM |
		    NETIF_F_GSO_UDP_TUNNEL_CSUM | NETIF_F_GSO_PARTIAL
#ifdef NETIF_F_GSO_UDP_L4
		    | NETIF_F_GSO_UDP_L4
#endif
		    | NETIF_F_GSO_IPXIP4 | NETIF_F_GSO_IPXIP6 | NETIF_F_LRO |
		    NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX |
		    NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC | NETIF_F_IPV6_CSUM
#ifdef HAVE_MACSEC_SUPPORT
		    | NETIF_F_HW_MACSEC
#endif
			;

	(void)sxe2_conflict_features_chk(changed_features, features, conflict1,
					 conflict2);

#ifdef HAVE_MACSEC_SUPPORT
	conflict1 = NETIF_F_HW_MACSEC;
	conflict2 = NETIF_F_HW_ESP;
	(void)sxe2_conflict_features_chk(changed_features, features, conflict1,
					 conflict2);
#endif

	return 0;
}

static int sxe2_set_features(struct net_device *netdev, netdev_features_t features)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	netdev_features_t oper_features;
	bool part_failed = false;

	s32 ret = 0;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("device is in safe mode - not enabling advanced netdev \t"
			    "features");
		return 0;
	}

	ret = sxe2_conflict_features_check(netdev, features);
	if (ret) {
		LOG_DEV_ERR("some features are conflict\n");
		return ret;
	}

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		(void)mutex_unlock(&adapter->vsi_ctxt.lock);
		return ret;
	}

	oper_features = netdev->features;

	ret = sxe2_set_rxfcs_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	ret = sxe2_set_lro_features(netdev, features, &oper_features);
	if (ret) {
		part_failed = true;
		goto skip_rxcsum;
	}

	ret = sxe2_set_rxcsum_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

skip_rxcsum:
#ifdef HAVE_MACSEC_SUPPORT
	ret = sxe2_set_macsec_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;
#endif
	ret = sxe2_set_ipsec_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	ret = sxe2_set_vlan_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	ret = sxe2_set_fnav_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	(void)mutex_unlock(&adapter->vsi_ctxt.lock);

	ret = sxe2_set_macvlan_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	if (part_failed) {
		netdev->features = oper_features;
		ret = -EINVAL;
	}

	return ret;
}

static netdev_features_t
sxe2_features_check(struct sk_buff *skb, struct net_device __always_unused *netdev,
		    netdev_features_t features)
{
	size_t len;
	bool gso = skb_is_gso(skb);
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	if (gso && (skb_shinfo(skb)->gso_size < SXE2_TXCD_QW1_MSS_MIN)) {
		LOG_WARN_BDF("gso size < 88, not support\n");
		features &= ~NETIF_F_GSO_MASK;
	}

	if (skb_network_offset(skb) < 0) {
		goto out_rm_features;
	} else {
		len = (size_t)skb_network_offset(skb);
		if (len > SXE2_TXDD_MACLEN_MAX || len & 0x1) {
			LOG_WARN_BDF("The mac header exceeds the max length,\t"
				     "not support tso/csum, maclen = %zu\n",
				     len);
			goto out_rm_features;
		}
	}

	len = skb_network_header_len(skb);
	if (len > SXE2_TXDD_IPLEN_MAX || len & 0x1) {
		LOG_WARN_BDF("The ip header exceeds the max length,\t"
			     "not support tso/csum, iplen = %zu\n",
			     len);
		goto out_rm_features;
	}

	if (skb->encapsulation) {
		if (gso && (skb_shinfo(skb)->gso_type &
			    (SKB_GSO_GRE | SKB_GSO_UDP_TUNNEL))) {
			len = (size_t)skb_inner_network_header(skb) -
			      (size_t)skb_transport_header(skb);
			if (len > SXE2_TXDD_L4LEN_MAX || len & 0x1) {
				LOG_WARN_BDF("tunnel:The inner L4 header exceeds \t"
					     "the max length, not support tso/csum, \t"
					     "l4 len = %zu\n",
					     len);
				goto out_rm_features;
			}
		}

		len = skb_inner_network_header_len(skb);
		if (len > SXE2_TXDD_IPLEN_MAX || len & 0x1) {
			LOG_WARN_BDF("tunnel:The inner ip header exceeds the max \t"
				     "length, not support tso/csum, ip len = %zu\n",
				     len);
			goto out_rm_features;
		}
	}

	return features;

out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

static netdev_features_t sxe2_fix_ipsec_features(struct sxe2_adapter *adapter,
						 struct net_device *netdev,
						 netdev_features_t features)
{
	netdev_features_t tso_features;

	if (netdev->features & NETIF_F_HW_ESP) {
		tso_features = NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6 |
			       NETIF_F_GSO_GRE | NETIF_F_GSO_UDP_TUNNEL |
			       NETIF_F_GSO_GRE_CSUM | NETIF_F_GSO_UDP_TUNNEL_CSUM |
			       NETIF_F_GSO_PARTIAL | NETIF_F_GSO_IPXIP4 |
#ifdef NETIF_F_GSO_UDP_L4
			       NETIF_F_GSO_UDP_L4 |
#endif
			       NETIF_F_GSO_IPXIP6;
		if (features & (tso_features)) {
			LOG_DEV_WARN("ipsec is conflicted with tx segmentation \t"
				     "offload.\n");
			features &= ~(tso_features);
		}
		if (features &
		    (NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC | NETIF_F_IPV6_CSUM)) {
			LOG_DEV_WARN("ipsec is conflicted with tx Checksum \t"
				     "offload.\n");
			features &= ~(NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC |
				      NETIF_F_IPV6_CSUM);
		}
		if (features & (NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX)) {
			LOG_DEV_WARN("ipsec is conflicted with tx VLAN offload.\n");
			features &= ~(NETIF_F_HW_VLAN_CTAG_TX |
				      NETIF_F_HW_VLAN_STAG_TX);
		}
		if (features & NETIF_F_LRO) {
			LOG_DEV_WARN("ipsec is conflicted with LRO.\n");
			features &= ~(NETIF_F_LRO);
		}
#ifdef HAVE_MACSEC_SUPPORT
		if (features & NETIF_F_HW_MACSEC) {
			LOG_DEV_WARN("ipsec is conflicted with macsec offload.\n");
			features &= ~(NETIF_F_HW_MACSEC);
		}
#endif
	}
	return features;
}

static netdev_features_t sxe2_fix_features(struct net_device *netdev,
					   netdev_features_t features)
{
	netdev_features_t req_vlan_fltr, cur_vlan_fltr;
	bool cur_ctag, cur_stag, req_ctag, req_stag;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	netdev_features_t request_features;

	request_features = features;

	LOG_DEBUG_BDF("fix features:0x%llx netdev features:0x%llx.\n", features,
		      netdev->features);

	cur_vlan_fltr = netdev->features & NETIF_VLAN_FILTERING_FEATURES;
	cur_ctag = cur_vlan_fltr & NETIF_F_HW_VLAN_CTAG_FILTER;
	cur_stag = cur_vlan_fltr & NETIF_F_HW_VLAN_STAG_FILTER;

	req_vlan_fltr = features & NETIF_VLAN_FILTERING_FEATURES;
	req_ctag = req_vlan_fltr & NETIF_F_HW_VLAN_CTAG_FILTER;
	req_stag = req_vlan_fltr & NETIF_F_HW_VLAN_STAG_FILTER;

	if (req_vlan_fltr != cur_vlan_fltr) {
		if (req_ctag && req_stag) {
			features |= NETIF_VLAN_FILTERING_FEATURES;
		} else if (!req_ctag && !req_stag) {
			features &= ~NETIF_VLAN_FILTERING_FEATURES;
		} else {
			LOG_DEV_WARN("802.1Q and 802.1ad VLAN filtering must be \t"
				     "either both on or both off.\n"
				     "VLAN filtering has been enabled for both \t"
				     "types.\n");
			if (!cur_ctag && !cur_stag)
				features |= NETIF_VLAN_FILTERING_FEATURES;
			else
				features &= ~NETIF_VLAN_FILTERING_FEATURES;
		}
	}

	if ((features & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX)) &&
	    (features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX))) {
		LOG_DEV_WARN("cannot support CTAG and STAG VLAN stripping and/or \t"
			     "insertion simultaneously since CTAG and STAG offloads \t"
			     "are mutually exclusive, clearing STAG offload \t"
			     "settings\n");
		features &= ~(NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX);
	}
	features = sxe2_fix_ipsec_features(adapter, netdev, features);

#ifdef HAVE_MACSEC_SUPPORT
	if (netdev->features & NETIF_F_HW_MACSEC) {
		if (features & NETIF_F_HW_ESP) {
			features &= ~NETIF_F_HW_ESP;
			LOG_DEV_WARN("cannot turn on ipsec offload when macsec \t"
				     "offload is on.\n");
		}
	}
#endif

	LOG_DEV_DEBUG("request features %llx, fix features %llx\n", request_features,
		      features);

	return features;
}

s32 sxe2_open(struct net_device *netdev)
{
	u16 old_txq_cnt = (u16)netdev->real_num_tx_queues;
	u16 old_rxq_cnt = (u16)netdev->real_num_rx_queues;
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	bool link_status = true;

#if defined CONFIG_LOCKDEP && defined LOCK_STATE_HELD
	WARN_ON(lockdep_is_held(&adapter->vsi_ctxt.lock) == LOCK_STATE_HELD);
#endif
	ret = sxe2_netdev_q_cnt_set(netdev, vsi->txqs.q_cnt, vsi->rxqs.q_cnt, true);
	if (ret)
		goto l_end;

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		LOG_NETDEV_ERR("can't open net device while vsi is disabled");
		ret = -EBUSY;
		goto unlock;
	}

	netif_carrier_off(netdev);

	if (vsi->type == SXE2_VSI_T_PF) {
		mutex_lock(&adapter->link_ctxt.link_status_lock);
		link_status = sxe2_get_pf_link_status(adapter);
		mutex_unlock(&adapter->link_ctxt.link_status_lock);
		if (!link_status)
			(void)sxe2_link_up(adapter);
	}

	ret = sxe2_vsi_open(vsi);

unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	if (ret)
		(void)sxe2_netdev_q_cnt_set(netdev, old_txq_cnt, old_rxq_cnt, true);

	return ret;
}

s32 sxe2_net_link_down(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};
	enum flm_link_status link_status = FLM_PORT_DOWN;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FLM_LINK_UP_DOWN_SET, &link_status,
				  sizeof(enum flm_link_status), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

out:
	return ret;
}

s32 sxe2_link_up(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};
	struct flm_link_info req = {0};
	struct flm_link_info_pasist persist_cfg = {0};

	ret = sxe2_link_get_pasist_info(adapter, &persist_cfg);
	if (ret) {
		LOG_ERROR_BDF("Failed to get persist cfg, ret=%d\n", ret);
		goto out;
	}

	req.is_link_up = persist_cfg.link_status;
	req.fec = persist_cfg.fec_mode;
	req.fc_mode = persist_cfg.fc_mode;
	req.speed = persist_cfg.speed;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FLM_LINK_UP, &req,
				  sizeof(struct flm_link_info), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to link cfg, ret=%d\n", ret);
		ret = -EIO;
	}

out:
	return ret;
}

s32 sxe2_stop(struct net_device *netdev)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_mac_filter *mac_filter = &vsi->mac_filter;
	struct sxe2_mac_sync_entry *list_itr = NULL;
	struct sxe2_mac_sync_entry *tmp = NULL;

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		goto unlock;

	if (test_bit(SXE2_FLAG_LINK_DOWN_ON_CLOSE, adapter->flags)) {
		ret = sxe2_net_link_down(adapter);
		if (ret)
			goto unlock;
	}

	ret = sxe2_vsi_close(vsi);

	(void)mutex_lock(&mac_filter->sync_lock);
	INIT_LIST_HEAD(&mac_filter->tmp_unsync_list);

	netif_addr_lock_bh(netdev);
	__dev_uc_unsync(netdev, sxe2_unsync_mac_add);
	__dev_mc_unsync(netdev, sxe2_unsync_mac_add);
	netif_addr_unlock_bh(netdev);

	list_for_each_entry_safe(list_itr, tmp, &mac_filter->tmp_unsync_list,
				 list_entry) {
		(void)sxe2_mac_addr_del(vsi, list_itr->mac_addr,
					SXE2_MAC_OWNER_UC_MC);
		list_del(&list_itr->list_entry);
		kfree(list_itr);
	}
	(void)mutex_unlock(&mac_filter->sync_lock);

unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static int sxe2_set_mac_address(struct net_device *netdev, void *pi)
{
	int ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sockaddr *addr = pi;
	u8 *mac;
	u8 old_mac[ETH_ALEN];

	mac = (u8 *)addr->sa_data;
	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, mac))
		return 0;

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		LOG_ERROR("can't set mac %pM. device not ready\n", mac);
		ret = -EBUSY;
		goto l_unlock;
	}

	netif_addr_lock_bh(netdev);
	ether_addr_copy(old_mac, netdev->dev_addr);
	netif_addr_unlock_bh(netdev);

	ret = sxe2_cur_mac_addr_set(vsi, mac);
	if (ret) {
		LOG_DEV_ERR("set mac addr failed, mac %pM, ret %d\n", mac, ret);
		ret = -EADDRNOTAVAIL;
		goto l_unlock;
	}

	ret = sxe2_mac_addr_del(vsi, old_mac, SXE2_MAC_OWNER_NETDEV);
	if (ret) {
		LOG_DEV_ERR("delete mac filter failed, mac %pM, ret %d\n", old_mac,
			    ret);
	}

	ret = sxe2_mac_addr_add(vsi, mac, SXE2_MAC_OWNER_NETDEV);
	if (ret) {
		LOG_DEV_ERR("add mac filter failed, mac %pM, ret %d\n", mac, ret);
		goto l_add_new_mac_fail;
	}

	netif_addr_lock_bh(netdev);
	eth_hw_addr_set(netdev, mac);
	netif_addr_unlock_bh(netdev);

	goto l_unlock;

l_add_new_mac_fail:
	ret = sxe2_mac_addr_add(vsi, old_mac, SXE2_MAC_OWNER_NETDEV);
	if (ret) {
		LOG_DEV_ERR("add pre mac filter failed, mac %pM, ret %d\n", old_mac,
			    ret);
	}

	ret = sxe2_cur_mac_addr_set(vsi, old_mac);
	if (ret)
		LOG_DEV_ERR("set mac addr failed, mac %pM, ret %d\n", old_mac, ret);

	ret = -EADDRNOTAVAIL;

l_unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static struct net_device *sxe2_netdev_alloc(struct sxe2_vsi *vsi)
{
	struct sxe2_netdev_priv *priv;
	struct net_device *netdev;
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 txq_cnt = adapter->irq_ctxt.irq_layout.lan;
	u16 rxq_cnt = adapter->irq_ctxt.irq_layout.lan;

	if (test_bit(SXE2_FLAG_VMDQ_CAPABLE, vsi->adapter->flags)) {
		txq_cnt += SXE2_MAX_MACVLANS;
		rxq_cnt += SXE2_MAX_MACVLANS;
	}
	netdev = alloc_etherdev_mqs(sizeof(*priv), txq_cnt, rxq_cnt);
	if (!netdev) {
		LOG_DEV_ERR("alloc netdev failed, priv size %zu, txqs %u, rxqs %u\n",
			    sizeof(*priv), txq_cnt, rxq_cnt);
		goto l_end;
	}

	vsi->netdev = netdev;
	priv = netdev_priv(netdev);
	priv->vsi = vsi;
	SET_NETDEV_DEV(netdev, &adapter->pdev->dev);

	LOG_INFO_BDF("vsi[%u][%u] type:%u netdev:%pK vsi:%pK.\n", vsi->id_in_pf,
		     vsi->idx_in_dev, vsi->type, netdev, vsi);

l_end:
	return netdev;
}

static void sxe2_netdev_lro_feature_init(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);

	if (netdev->features & NETIF_F_LRO)
		set_bit(SXE2_VSI_FLAG_LRO_ENABLE, priv->vsi->flags);
	else
		clear_bit(SXE2_VSI_FLAG_LRO_ENABLE, priv->vsi->flags);
}

static void sxe2_netdev_rxfcs_feature_init(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);

	if (netdev->features & NETIF_F_RXFCS)
		set_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, priv->vsi->flags);
	else
		clear_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, priv->vsi->flags);
}

void sxe2_netdev_feature_init(struct net_device *netdev)
{
	netdev_features_t defaults;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	netdev_features_t csum_features;
	netdev_features_t tso_features;
	netdev_features_t vlan_features;

	if (sxe2_is_safe_mode(adapter)) {
		netdev->features = NETIF_F_SG | NETIF_F_HIGHDMA;
		netdev->hw_features = netdev->features;
		return;
	}

	defaults = NETIF_F_SG | NETIF_F_RXHASH |
		   NETIF_F_NTUPLE |
		   NETIF_F_HIGHDMA;

	csum_features = NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC |
			NETIF_F_IPV6_CSUM;

	vlan_features = NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX |
			NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER;

	tso_features = NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6 |
		       NETIF_F_GSO_GRE | NETIF_F_GSO_UDP_TUNNEL |
		       NETIF_F_GSO_GRE_CSUM | NETIF_F_GSO_UDP_TUNNEL_CSUM |
		       NETIF_F_GSO_PARTIAL | NETIF_F_GSO_IPXIP4 |
#ifdef NETIF_F_GSO_UDP_L4
		       NETIF_F_GSO_UDP_L4 |
#endif
		       NETIF_F_GSO_IPXIP6;

	netdev->gso_partial_features |=
			NETIF_F_GSO_UDP_TUNNEL_CSUM | NETIF_F_GSO_GRE_CSUM;

	netdev->hw_features =
			defaults | csum_features | tso_features | vlan_features;
	netdev->features = netdev->hw_features;

	netdev->hw_features |= NETIF_F_LRO | NETIF_F_RXFCS;

	netdev->mpls_features = NETIF_F_HW_CSUM;

	netdev->hw_enc_features |= defaults | csum_features | tso_features;

	netdev->vlan_features |=
			defaults | csum_features | tso_features | NETIF_F_LRO;

	netdev->hw_features |= NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX;

	netdev->hw_features |= NETIF_F_HW_TC;

#ifdef HAVE_MACSEC_SUPPORT
	netdev->hw_features |= NETIF_F_HW_MACSEC;
#endif
	netdev->hw_features |= NETIF_F_HW_ESP;
	netdev->hw_enc_features |= NETIF_F_HW_ESP;

	sxe2_netdev_lro_feature_init(netdev);

	sxe2_netdev_rxfcs_feature_init(netdev);

	if (test_bit(SXE2_FLAG_VMDQ_CAPABLE, adapter->flags))
		netdev->hw_features |= NETIF_F_HW_L2FW_DOFFLOAD;

	LOG_DEBUG_BDF("netdev init features:0x%llx hw_features:0x%llx.\n",
		      netdev->features, netdev->hw_features);
}

static int sxe2_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
			       struct net_device *dev, u32 filter_mask, int nlflags)
{
	struct sxe2_netdev_priv *np = netdev_priv(dev);
	struct sxe2_vsi *vsi = np->vsi;
	u16 bmode = vsi->adapter->switch_ctxt.evb_mode;

	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, bmode, 0, 0, nlflags,
				       filter_mask, NULL);
}

#ifdef NETDEV_NO_NEED_EXTACK_PRAM
static int sxe2_bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
			       u16 __always_unused flags)
#else
static int sxe2_bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
			       u16 __always_unused flags,
			       struct netlink_ext_ack __always_unused *extack)
#endif
{
	struct sxe2_netdev_priv *np = netdev_priv(dev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_switch_context *switch_ctxt;
	struct nlattr *attr, *br_spec;
	int rem = 0;
	struct sxe2_vsi *vsi;
	u16 i;
	__u16 mode;
	u16 old_mode;
	int ret = 0;

	switch_ctxt = &adapter->switch_ctxt;
	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	(void)mutex_lock(&switch_ctxt->evb_mode_lock);

	if (test_bit(SXE2_VSI_S_DISABLE, np->vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	switch_ctxt = &adapter->switch_ctxt;
	br_spec = nlmsg_find_attr(nlh, sizeof(struct ifinfomsg), IFLA_AF_SPEC);

	nla_for_each_nested(attr, br_spec, rem) {
		if (nla_type(attr) != IFLA_BRIDGE_MODE)
			continue;
		mode = nla_get_u16(attr);
		if (mode != BRIDGE_MODE_VEPA && mode != BRIDGE_MODE_VEB) {
			ret = -EINVAL;
			goto l_unlock;
		}

		if (switch_ctxt->evb_mode == mode)
			continue;
		old_mode = switch_ctxt->evb_mode;
		switch_ctxt->evb_mode = mode;

		sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
		{
			vsi = adapter->vsi_ctxt.vsi[i];
			if (!vsi)
				continue;
			ret =
			 sxe2_vsi_loopback_control(adapter, vsi->idx_in_dev,
						   (mode == BRIDGE_MODE_VEB ? true : false));
			if (ret) {
				switch_ctxt->evb_mode = old_mode;
				goto l_unlock;
			}
		}

		ret = sxe2_rule_bridge_mode_update(adapter);
		if (ret) {
			switch_ctxt->evb_mode = old_mode;
			goto l_unlock;
		}
	}

l_unlock:
	(void)mutex_unlock(&switch_ctxt->evb_mode_lock);
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef NETDEV_NO_NEED_EXTACK_PRAM
static int sxe2_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr, u16 vid,
			u16 flags)
{
	return ndo_dflt_fdb_add(ndm, tb, dev, addr, vid, flags);
}
#else
static int sxe2_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr, u16 vid,
			u16 flags, struct netlink_ext_ack __always_unused *extack)
{
	return ndo_dflt_fdb_add(ndm, tb, dev, addr, vid, flags);
}
#endif

static int sxe2_set_tx_maxrate(struct net_device *netdev, int queue_index,
			       u32 maxrate)
{
	int ret;
	struct sxe2_queue *txq;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (maxrate && (maxrate > (SXE2_TXSCHED_MAX_BW / 1000))) {
		LOG_NETDEV_ERR("invalid max rate %u specified for the queue %d\n",
			       maxrate, queue_index);
		return -EINVAL;
	}

	if (maxrate && maxrate > adapter->link_ctxt.current_link_speed) {
		LOG_NETDEV_ERR("invalid max rate %u specified for the queue %d in\t"
			       "port %d\n",
			       maxrate, queue_index, adapter->port_idx);
		return -EINVAL;
	}

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, np->vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}

	txq = vsi->txqs.q[queue_index];

	if (!maxrate)
		ret = sxe2_txsched_q_bw_lmt_cfg(vsi, txq, SXE2_NODE_RL_TYPE_EIR,
						SXE2_TXSCHED_DFLT_BW);
	else
		ret = sxe2_txsched_q_bw_lmt_cfg(vsi, txq, SXE2_NODE_RL_TYPE_EIR,
						maxrate * 1000);
	if (ret) {
		LOG_NETDEV_ERR("unable to set tx max rate, ret=%d, txq_idx=%u, \t"
			       "maxrate=%u\n",
			       ret, queue_index, maxrate);
	}

l_unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

#ifdef NDO_FDB_DEL_API_NEED_5_PARAMS
static int sxe2_fdb_del(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr, u16 vid)
#else
static int sxe2_fdb_del(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr, u16 vid,
			struct netlink_ext_ack *xtack)
#endif
{
	return ndo_dflt_fdb_del(ndm, tb, dev, addr, vid);
}

static int sxe2_vlan_rx_add_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vlan vlan;
	u16 proto_u16;
	int ret;

	if (!vid && be16_to_cpu(proto) == ETH_P_8021Q)
		return 0;

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}
	proto_u16 = be16_to_cpu(proto);
	vlan = SXE2_VLAN(proto_u16, vid, 0);
	ret = sxe2_vlan_rule_add(vsi, &vlan);
	if (ret == -EEXIST)
		ret = 0;

l_unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static int sxe2_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vlan vlan;
	u16 proto_u16;
	int ret;

	if (!vid && be16_to_cpu(proto) == ETH_P_8021Q)
		return 0;

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_unlock;
	}
	proto_u16 = be16_to_cpu(proto);
	vlan = SXE2_VLAN(proto_u16, vid, 0);
	ret = sxe2_vlan_rule_del(adapter, vsi->idx_in_dev, &vlan);
	if (ret == -ENOENT)
		ret = 0;

l_unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static LIST_HEAD(sxe2_block_cb_list);

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
static s32 sxe2_setup_tc(struct net_device *netdev, enum tc_setup_type type,
			 void *type_data)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);

	if (type == TC_SETUP_BLOCK)
		return flow_block_cb_setup_simple(type_data, &sxe2_block_cb_list,
						  sxe2_setup_tc_block_cb, np, np,
						  true);
	return -EOPNOTSUPP;
}
#else
static s32 sxe2_setup_tc(struct net_device *netdev, u32 __always_unused handle,
			 __be16 __always_unused proto, struct tc_to_netdev *tc)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);

	if (tc->type == TC_SETUP_CLSFLOWER)
		return sxe2_setup_tc_cls_flower(np, np->vsi->netdev, tc->cls_flower);
	return -EOPNOTSUPP;
}
#endif

static u8 sxe2_get_dscp_up(struct sxe2_dcbx_cfg *dcbcfg, struct sk_buff *skb)
{
	u8 dscp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return dcbcfg->dscp_map[dscp];
}

#ifdef HAVE_NDO_SELECT_QUEUE_SB_DEV
#ifdef NDO_SELECT_QUEUE_NEED_4_PARAMS
STATIC u16 sxe2_select_queue(struct net_device *netdev, struct sk_buff *skb,
			     struct net_device *sb_dev,
			     select_queue_fallback_t fallback)
#else
STATIC u16 sxe2_select_queue(struct net_device *netdev, struct sk_buff *skb,
			     struct net_device *sb_dev)
#endif
#else
#ifdef NDO_SELECT_QUEUE_NEED_4_PARAMS
STATIC u16 sxe2_select_queue(struct net_device *netdev, struct sk_buff *skb,
			     void __always_unused *accel_priv,
			     select_queue_fallback_t fallback)
#else
STATIC u16 sxe2_select_queue(struct net_device *netdev, struct sk_buff *skb,
			     void __always_unused *accel_priv)
#endif
#endif

{
	struct sxe2_dcbx_cfg *dcbcfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	dcbcfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	if (dcbcfg->qos_mode == SXE2_QOS_MODE_DSCP)
		skb->priority = sxe2_get_dscp_up(dcbcfg, skb);

#ifdef NDO_SELECT_QUEUE_NEED_4_PARAMS
#ifdef HAVE_NDO_SELECT_QUEUE_SB_DEV
	return fallback(netdev, skb, sb_dev);
#else
	return fallback(netdev, skb);
#endif
#else
	return netdev_pick_tx(netdev, skb, sb_dev);
#endif
}

s32 sxe2_check_vf_ready_for_cfg(struct sxe2_vf_node *vf)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vf->adapter;

	if (test_bit(SXE2_VF_STATE_DIS, vf->states)) {
		ret = -EBUSY;
		LOG_ERROR_BDF("vf:%u pf status:0x%lx vf states:0x%lx.\n", vf->vf_idx,
			      *adapter->flags, *vf->states);
	}

	return ret;
}

STATIC s32 sxe2_set_vf_spoofchk(struct net_device *netdev, s32 vf_idx, bool ena)
{
	s32 ret;
	struct sxe2_vf_node *vf_node;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_vsi *user_vsi;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (sxe2_eswitch_is_offload(adapter)) {
		LOG_DEV_INFO("switchdev mode not support change spoofchk status.\n");
		return -EOPNOTSUPP;
	}

	if (sxe2_vf_id_check(adapter, (u16)vf_idx))
		return -EINVAL;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	vf_node = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf_node) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf_node);
	if (ret)
		goto l_end;

	if (ena == vf_node->prop.spoofchk) {
		LOG_DEV_DEBUG("vf spoofchk already %s\n", ena ? "on" : "off");
		ret = 0;
		goto l_end;
	}

	eth_vsi = vf_node->vsi;
	user_vsi = vf_node->dpdk_vf_vsi;
	if (!eth_vsi && !user_vsi) {
		vf_node->prop.spoofchk = (u8)ena;
		goto l_end;
	} else if (!eth_vsi && user_vsi) {
		ret = sxe2_vsi_spoofchk_control(adapter, user_vsi->idx_in_dev, ena);
		if (ret) {
			LOG_DEV_ERR("failed to set spoofchk %s for vf %d vsi %d\n"
				    "error %d\n",
				    ena ? "on" : "off", vf_idx, user_vsi->idx_in_dev,
				    ret);
		}
	} else if (eth_vsi && !user_vsi) {
		ret = sxe2_vsi_spoofchk_control(adapter, eth_vsi->idx_in_dev, ena);
		if (ret) {
			LOG_DEV_ERR("failed to set spoofchk %s for vf %d vsi %d\n"
				    "error %d\n",
				    ena ? "on" : "off", vf_idx, eth_vsi->idx_in_dev,
				    ret);
		}
	} else {
		ret = sxe2_vsi_spoofchk_control(adapter, eth_vsi->idx_in_dev, ena);
		if (ret) {
			LOG_DEV_ERR("failed to set spoofchk %s for vf %d vsi %d\n"
				    "error %d\n",
				    ena ? "on" : "off", vf_idx, eth_vsi->idx_in_dev,
				    ret);
			goto l_end;
		}
		ret = sxe2_vsi_spoofchk_control(adapter, user_vsi->idx_in_dev, ena);
		if (ret) {
			LOG_DEV_ERR("failed to set spoofchk %s for vf %d vsi %d\n"
				    "error %d\n",
				    ena ? "on" : "off", vf_idx, user_vsi->idx_in_dev,
				    ret);
			(void)sxe2_vsi_spoofchk_control(adapter, eth_vsi->idx_in_dev,
							!ena);
		}
	}

	if (!ret)
		vf_node->prop.spoofchk = (u8)ena;

l_end:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	return ret;
}

STATIC s32 sxe2_set_vf_mac(struct net_device *netdev, s32 vf_idx, u8 *mac_addr)
{
	s32 ret = 0;
	struct sxe2_vf_node *vf_node;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (is_multicast_ether_addr(mac_addr)) {
		LOG_NETDEV_ERR("%pM not a valid unicast address\n", mac_addr);
		return -EINVAL;
	}

	if (sxe2_vf_id_check(adapter, (u16)vf_idx))
		return -EINVAL;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));

	vf_node = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf_node) {
		ret = -EINVAL;
		goto l_unlock;
	}

	if (ether_addr_equal(vf_node->mac_addr.addr, mac_addr)) {
		LOG_INFO_BDF("vf:%u no need dup set mac addr:%pM.\n", vf_idx,
			     mac_addr);
		goto l_unlock;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf_node);
	if (ret) {
		LOG_ERROR_BDF("vf:%u pf flags:0x%lx vf states:0x%lx not ready.\n",
			      vf_idx, *adapter->flags, *vf_node->states);
		goto l_unlock;
	}

	ether_addr_copy(vf_node->mac_addr.addr, mac_addr);
	if (is_zero_ether_addr(mac_addr)) {
		vf_node->prop.mac_from_pf = false;
		LOG_NETDEV_INFO("mac on vf %d. vf driver will be reinitialized\n",
				vf_idx);
	} else {
		vf_node->prop.mac_from_pf = true;
		LOG_NETDEV_INFO("setting mac %pM on vf %d. vf driver will be \t"
				"reinitialized\n",
				mac_addr, vf_idx);
	}
	ret = sxe2_reset_vf(adapter, (u16)vf_idx, SXE2_VF_RESET_FLAG_NOTIFY);
	if (ret)
		LOG_ERROR_BDF("vf:%u set mac:%pM failed.\n", vf_idx, mac_addr);

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));

	return ret;
}

STATIC s32 sxe2_get_vf_cfg(struct net_device *netdev, s32 vf_idx,
			   struct ifla_vf_info *info)
{
	s32 ret;
	struct sxe2_vf_node *vf_node;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (sxe2_vf_id_check(adapter, (u16)vf_idx))
		return -EINVAL;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	vf_node = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf_node) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf_node);
	if (ret)
		goto l_end;

	info->vf = (u32)vf_idx;
	ether_addr_copy(info->mac, vf_node->mac_addr.addr);

	info->vlan = sxe2_vf_port_vid_get(vf_node);
	info->qos = sxe2_vf_port_vprio_get(vf_node);

	info->trusted = vf_node->prop.trusted;
	info->spoofchk = vf_node->prop.spoofchk;
	if (!vf_node->prop.link_forced)
		info->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vf_node->prop.link_up)
		info->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		info->linkstate = IFLA_VF_LINK_STATE_DISABLE;
	info->max_tx_rate = vf_node->prop.max_tx_rate;
	info->min_tx_rate = vf_node->prop.min_tx_rate;

l_end:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	return ret;
}

STATIC s32 sxe2_set_vf_trust(struct net_device *netdev, s32 vf_idx, bool status)
{
	s32 ret = 0;
	struct sxe2_vf_node *vf_node;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (sxe2_eswitch_is_offload(adapter)) {
		LOG_DEV_INFO("switchdev mode not support change vf trust status.\n");
		return -EOPNOTSUPP;
	}

	if (sxe2_vf_id_check(adapter, (u16)vf_idx))
		return -EINVAL;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	vf_node = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf_node) {
		ret = -EINVAL;
		goto l_unlock;
	}

	if (status == vf_node->prop.trusted)
		goto l_unlock;

	ret = sxe2_check_vf_ready_for_cfg(vf_node);
	if (ret)
		goto l_unlock;

	vf_node->prop.trusted = (u8)status;
	LOG_DEV_INFO("vf %u is now %strusted\n", vf_idx, status ? "" : "un");

	ret = sxe2_reset_vf(adapter, (u16)vf_idx, SXE2_VF_RESET_FLAG_NOTIFY);
	if (ret)
		LOG_ERROR_BDF("vf:%u set trust failed.\n", vf_idx);

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	return ret;
}

STATIC s32 sxe2_set_vf_link_state(struct net_device *netdev, s32 vf_idx, s32 state)
{
	s32 ret;
	struct sxe2_vf_node *vf_node;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (sxe2_vf_id_check(adapter, (u16)vf_idx))
		return -EINVAL;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	vf_node = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf_node) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf_node);
	if (ret)
		goto l_end;

	switch (state) {
	case IFLA_VF_LINK_STATE_AUTO:
		vf_node->prop.link_forced = false;
		break;
	case IFLA_VF_LINK_STATE_ENABLE:
		vf_node->prop.link_forced = true;
		vf_node->prop.link_up = true;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		vf_node->prop.link_forced = true;
		vf_node->prop.link_up = false;
		break;
	default:
		ret = -EINVAL;
		goto l_end;
	}

	sxe2_notify_vf_link_state(vf_node);

l_end:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));
	return ret;
}

#ifdef HAVE_XDP_SUPPORT
STATIC void sxe2_vsi_assign_bpf_prog(struct sxe2_vsi *vsi, struct bpf_prog *prog)
{
	struct bpf_prog *old_prog;
	int i;

	old_prog = xchg(&vsi->xdp_prog, prog);

	sxe2_for_each_vsi_rxq(vsi, i)
			WRITE_ONCE(vsi->rxqs.q[i]->xdp_prog, vsi->xdp_prog);

	if (old_prog && old_prog != prog)
		bpf_prog_put(old_prog);
}

STATIC s32 sxe2_xdp_alloc_and_setup_rings(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 i;

	for (i = 0; i < (s32)vsi->num_xdp_txq; i++) {
		u16 xdp_q_idx = vsi->txqs.q_cnt + (u16)i;
		struct sxe2_queue *xdp_ring;

		xdp_ring = kzalloc(sizeof(*xdp_ring), GFP_KERNEL);

		if (!xdp_ring)
			goto free_xdp_rings;

		xdp_ring->idx_in_pf = SXE2_Q_IDX_INVAL;
		xdp_ring->idx_in_vsi = xdp_q_idx;
		xdp_ring->vsi = vsi;
		xdp_ring->dev = dev;
		xdp_ring->depth = vsi->txqs.depth;
		WRITE_ONCE(vsi->xdp_rings.q[i], xdp_ring);
		if (sxe2_tx_ring_alloc(vsi->xdp_rings.q[i], vsi))
			goto free_xdp_rings;
		sxe2_set_ring_xdp(xdp_ring);
		xdp_ring->netdev = NULL;
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_AF_XDP_ZC_SUPPORT
		xdp_ring->xsk_pool = sxe2_xsk_pool(xdp_ring);
#endif
#endif
	}
	vsi->xdp_rings.q_cnt = (u16)vsi->num_xdp_txq;
	vsi->xdp_rings.q_alloc = (u16)vsi->num_xdp_txq;

	return 0;

free_xdp_rings:
	for (; i >= 0; i--)
		if (vsi->xdp_rings.q[i])
			sxe2_tx_ring_free(vsi->xdp_rings.q[i]);
	return -ENOMEM;
}

void sxe2_vsi_xdp_qs_stats_deinit(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_qs_stats *vsi_qs_stat = &vsi->vsi_qs_stats;
	u16 i;

	if (vsi_qs_stat->xdp_stats) {
		for (i = 0; i < vsi->num_xdp_txq; i++) {
			kfree(vsi_qs_stat->xdp_stats[i]);
			WRITE_ONCE(vsi_qs_stat->xdp_stats[i], NULL);
		}
		kfree(vsi_qs_stat->xdp_stats);
		vsi_qs_stat->xdp_stats = NULL;
	}
}

STATIC s32 sxe2_vsi_xdp_qs_stats_init(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_qs_stats *vsi_qs_stats;
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 i;

	vsi_qs_stats = &vsi->vsi_qs_stats;

	if (!vsi_qs_stats->xdp_stats) {
		vsi_qs_stats->xdp_stats = kcalloc(vsi->num_xdp_txq,
						  sizeof(*vsi_qs_stats->xdp_stats),
						  GFP_KERNEL);
		if (!vsi_qs_stats->xdp_stats) {
			LOG_ERROR_BDF("alloc txqs stats failed, count: %d, size: \t"
				      "%zu.\n",
				      vsi->xdp_rings.q_cnt,
				      sizeof(*vsi_qs_stats->xdp_stats));
			goto err_out;
		}
	}

	for (i = 0; i < vsi->num_xdp_txq; i++) {
		struct sxe2_queue_stats *txq_stats;
		struct sxe2_queue *txq = vsi->xdp_rings.q[i];

		txq_stats = vsi_qs_stats->xdp_stats[i];
		if (!txq_stats) {
			txq_stats = kzalloc(sizeof(*txq_stats), GFP_KERNEL);
			if (!txq_stats)
				goto err_out;

			WRITE_ONCE(vsi_qs_stats->xdp_stats[i], txq_stats);
		}

		txq->stats = txq_stats;
	}

	return 0;

err_out:
	sxe2_vsi_xdp_qs_stats_deinit(vsi);
	return -ENOMEM;
}

s32 sxe2_prepare_xdp_rings(struct sxe2_vsi *vsi, struct bpf_prog *prog)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_irq_data *irq_data;
	s32 xdp_rings_rem = (s32)vsi->num_xdp_txq;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 i;
	s32 ret;
	s32 xdp_rings_per_v, q_id, q_base;

	vsi->xdp_rings.q = devm_kcalloc(dev, vsi->num_xdp_txq,
					sizeof(*vsi->xdp_rings.q), GFP_KERNEL);
	if (!vsi->xdp_rings.q)
		return -ENOMEM;

	if (sxe2_xdp_alloc_and_setup_rings(vsi))
		goto clear_xdp_rings;

	ret = sxe2_vsi_queues_get(vsi, SXE2_DATA_XDP_TQ);
	if (ret) {
		LOG_DEV_ERR("get txqs %d failed(%d).\n", vsi->xdp_rings.q_cnt, ret);
		goto err_map_xdp;
	}
	adapter->q_ctxt.txq_layout.xdp += vsi->xdp_rings.q_cnt;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		irq_data = vsi->irqs.irq_data[i];
		xdp_rings_per_v =
				(s32)DIV_ROUND_UP(xdp_rings_rem, vsi->irqs.cnt - i);
		q_base = (s32)(vsi->num_xdp_txq) - xdp_rings_rem;

		for (q_id = q_base; q_id < (q_base + xdp_rings_per_v); q_id++) {
			struct sxe2_queue *xdp_ring = vsi->xdp_rings.q[q_id];

			xdp_ring->irq_data = irq_data;
			sxe2_queue_add(xdp_ring, &irq_data->tx.list);
		}
		xdp_rings_rem -= xdp_rings_per_v;
	}

	ret = sxe2_vsi_xdp_qs_stats_init(vsi);
	if (ret) {
		LOG_DEV_ERR("failed qs stats config for xdp, error(%d)\n", ret);
		goto err_map_xdp;
	}

	ret = sxe2_txsched_lan_vsi_cfg(vsi);
	if (ret) {
		LOG_DEV_ERR("failed vsi lan queue config for xdp, error(%d)\n", ret);
		goto clear_xdp_stats;
	}

	sxe2_vsi_assign_bpf_prog(vsi, prog);

	return 0;

clear_xdp_stats:
	sxe2_vsi_xdp_qs_stats_deinit(vsi);

err_map_xdp:
	(void)mutex_lock(&adapter->q_ctxt.lock);
	for (i = 0; i < (s32)vsi->num_xdp_txq; i++) {
		if (vsi->xdp_rings.q[i]->idx_in_pf != SXE2_Q_IDX_INVAL) {
			clear_bit(vsi->xdp_rings.q[i]->idx_in_pf,
				  adapter->q_ctxt.txq_layout.txq_map);
			vsi->xdp_rings.q[i]->idx_in_pf = SXE2_Q_IDX_INVAL;
		}
	}
	(void)mutex_unlock(&adapter->q_ctxt.lock);

clear_xdp_rings:
	for (i = 0; i < (s32)vsi->num_xdp_txq; i++)
		if (vsi->xdp_rings.q[i]) {
			kfree_rcu(vsi->xdp_rings.q[i], rcu);
			vsi->xdp_rings.q[i] = NULL;
		}
	devm_kfree(dev, vsi->xdp_rings.q);
	vsi->xdp_rings.q = NULL;

	return -ENOMEM;
}

s32 sxe2_destroy_xdp_rings(struct sxe2_vsi *vsi, bool is_rebuild)
{
	s32 ret;
	u32 i;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_irq_data *irq_data;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_queue *queue;

	if (!vsi->irqs.irq_data || !vsi->irqs.irq_data[0])
		goto free_qmap;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		struct sxe2_list list;

		irq_data = vsi->irqs.irq_data[i];
		list.next = NULL;
		list.cnt = 0;
		sxe2_for_each_queue(queue, irq_data->tx.list)
		{
			if (!sxe2_queue_is_xdp(queue))
				sxe2_queue_add(queue, &list);
		}
		irq_data->tx.list.cnt = list.cnt;
		irq_data->tx.list.next = list.next;
	}

free_qmap:
	(void)mutex_lock(&adapter->q_ctxt.lock);
	for (i = 0; i < vsi->num_xdp_txq; i++) {
		clear_bit(vsi->xdp_rings.q[i]->idx_in_pf,
			  adapter->q_ctxt.txq_layout.txq_map);
		vsi->xdp_rings.q[i]->idx_in_pf = SXE2_Q_IDX_INVAL;
	}
	adapter->q_ctxt.txq_layout.xdp = 0;
	(void)mutex_unlock(&adapter->q_ctxt.lock);

	for (i = 0; i < vsi->num_xdp_txq; i++)
		if (vsi->xdp_rings.q[i]) {
			if (vsi->xdp_rings.q[i]->desc.base_addr) {
				synchronize_rcu();
				sxe2_tx_ring_free(vsi->xdp_rings.q[i]);
			}
			kfree_rcu(vsi->xdp_rings.q[i], rcu);
			WRITE_ONCE(vsi->xdp_rings.q[i], NULL);
		}

	devm_kfree(dev, vsi->xdp_rings.q);
	vsi->xdp_rings.q = NULL;

	if (is_rebuild)
		return 0;

	sxe2_vsi_assign_bpf_prog(vsi, NULL);

	ret = sxe2_txsched_lan_vsi_cfg(vsi);
	if (ret)
		LOG_DEV_ERR("Failed VSI LAN queue config for XDP, error(%d)\n", ret);

	sxe2_vsi_xdp_qs_stats_deinit(vsi);
	return ret;
}
#endif

#ifdef HAVE_AF_XDP_ZC_SUPPORT
STATIC void sxe2_vsi_rx_napi_schedule(struct sxe2_vsi *vsi)
{
	s32 i;

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		struct sxe2_queue *rx_ring = vsi->rxqs.q[i];

		if (rx_ring->xsk_pool)
			napi_schedule(&rx_ring->irq_data->napi);
	}
}
#endif

#ifdef HAVE_XDP_SUPPORT
STATIC void sxe2_clear_xdp_stats(struct sxe2_vsi *vsi)
{
	s32 i;
	struct sxe2_queue *rx_ring;

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		rx_ring = READ_ONCE(vsi->rxqs.q[i]);
		if (rx_ring)
			memset(&rx_ring->stats->rx_stats.xdp_stats, 0,
			       sizeof(rx_ring->stats->rx_stats.xdp_stats));
	}
}

STATIC s32 sxe2_xdp_setup_prog(struct sxe2_vsi *vsi, struct bpf_prog *prog,
			       struct netlink_ext_ack *extack)
{
	u32 frame_size = vsi->netdev->mtu + SXE2_PACKET_HDR_PAD;
	bool if_running = netif_running(vsi->netdev);
	s32 ret = 0, xdp_ring_err = 0;

	if (frame_size > vsi->rxqs.rx_buf_len) {
		NL_SET_ERR_MSG_MOD(extack, "MTU too large for loading XDP");
		return -EOPNOTSUPP;
	}

	if (sxe2_xdp_is_enable(vsi) == !!prog) {
		sxe2_vsi_assign_bpf_prog(vsi, prog);
		return 0;
	}

	if (if_running && !test_and_set_bit(SXE2_VSI_S_DOWN, vsi->state)) {
		ret = sxe2_vsi_down(vsi);
		if (ret) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Preparing device for XDP attach failed");
			return ret;
		}
	}

#ifdef HAVE_XDP_SUPPORT
	if (!sxe2_xdp_is_enable(vsi) && prog) {
		sxe2_xdp_queue_cnt_set(vsi, vsi->rxqs.q_cnt);

		xdp_ring_err = sxe2_prepare_xdp_rings(vsi, prog);
		if (xdp_ring_err)
			NL_SET_ERR_MSG_MOD(extack,
					   "Setting up XDP Tx resources failed");
		sxe2_clear_xdp_stats(vsi);
	} else if (sxe2_xdp_is_enable(vsi) && !prog) {
		xdp_ring_err = sxe2_destroy_xdp_rings(vsi, false);
		if (xdp_ring_err)
			NL_SET_ERR_MSG_MOD(extack,
					   "Freeing XDP Tx resources failed");
	}
#endif

	if (if_running)
		ret = sxe2_vsi_up(vsi);

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifdef HAVE_AF_XDP_NETDEV_UMEM
	if (!ret && prog)
		sxe2_vsi_rx_napi_schedule(vsi);
#else
	if (!ret && prog && vsi->xsk_umems)
		sxe2_vsi_rx_napi_schedule(vsi);
#endif
#endif

	return (ret || xdp_ring_err) ? -ENOMEM : 0;
}

STATIC s32 sxe2_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct sxe2_netdev_priv *priv = netdev_priv(dev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	s32 ret = 0;

	if (sxe2_is_safe_mode(adapter)) {
#ifdef HAVE_XDP_QUERY_PROG
		if (xdp->command == XDP_QUERY_PROG) {
			xdp->prog_id = 0;
			return 0;
		}
#endif
		LOG_DEV_ERR("safe mode not support xdp config.\n");
		return -EOPNOTSUPP;
	}

	if (vsi->type != SXE2_VSI_T_PF) {
		LOG_DEV_ERR("device type(%d) not support xdp setting.\n", vsi->type);
		return -EINVAL;
	}

	(void)mutex_lock(&adapter->vsi_ctxt.lock);

#ifdef HAVE_XDP_QUERY_PROG
	if (xdp->command == XDP_QUERY_PROG) {
		xdp->prog_id = vsi->xdp_prog ? vsi->xdp_prog->aux->id : 0;
		ret = 0;
		goto unlock;
	}
#endif

	if (test_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags)) {
		LOG_DEV_ERR("MACVLAN is enabled, can not set xdp.\n");
		ret = -EPERM;
		goto unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		if (!!xdp->prog) {
			ret = -EBUSY;
			goto unlock;
		}
	}

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		ret = sxe2_xdp_setup_prog(vsi, xdp->prog, xdp->extack);
		break;

#ifdef HAVE_AF_XDP_ZC_SUPPORT
	case XDP_SETUP_XSK_POOL:
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		ret = sxe2_xsk_pool_setup(vsi, xdp->xsk.pool, xdp->xsk.queue_id);
#else
		ret = sxe2_xsk_umem_setup(vsi, xdp->xsk.umem, xdp->xsk.queue_id);
#endif
		break;
#endif
	default:
		ret = -EINVAL;
		break;
	}

unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}
#endif

#ifdef HAVE_XDP_SUPPORT
STATIC s32 sxe2_xdp_xmit(struct net_device *dev, s32 frame_cnt,
			 struct xdp_frame **frames, u32 flags)
{
	struct sxe2_netdev_priv *np = netdev_priv(dev);
	struct sxe2_vsi *vsi = np->vsi;
	u32 queue_index;
	struct sxe2_queue *xdp_ring;
	s32 nxmit = 0, i;

	preempt_disable();
	queue_index = smp_processor_id();
	preempt_enable();
	queue_index = (queue_index % vsi->num_xdp_txq);

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	if (test_bit(SXE2_VSI_S_DOWN, vsi->state)) {
		nxmit = -ENETDOWN;
		goto l_end;
	}

	if (!sxe2_xdp_is_enable(vsi) || queue_index >= vsi->num_xdp_txq) {
		nxmit = -ENXIO;
		goto l_end;
	}

	xdp_ring = vsi->xdp_rings.q[queue_index];
	for (i = 0; i < frame_cnt; i++) {
		struct xdp_frame *xdpf = frames[i];
		s32 err;

		err = sxe2_xmit_xdp_ring(xdpf->data, xdpf->len, xdp_ring);
		if (err != SXE2_XDP_TX)
			break;
		nxmit++;
	}

	if (unlikely(flags & XDP_XMIT_FLUSH))
		sxe2_xdp_ring_update_tail(xdp_ring);

l_end:
	return nxmit;
}
#endif

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifdef HAVE_NDO_XSK_WAKEUP
s32 sxe2_xsk_wakeup(struct net_device *netdev, u32 queue_id, u32 flags)
#else
s32 sxe2_xsk_async_xmit(struct net_device *netdev, u32 queue_id)
#endif
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_irq_data *q_vector;
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_queue *ring;
	s32 ret = 0;

	if (test_bit(SXE2_VSI_S_DOWN, vsi->state)) {
		ret = -ENETDOWN;
		goto l_end;
	}

	if (!sxe2_xdp_is_enable(vsi)) {
		ret = -ENXIO;
		goto l_end;
	}

	if (queue_id >= vsi->num_xdp_txq) {
		ret = -ENXIO;
		goto l_end;
	}

	if (!vsi->xdp_rings.q[queue_id]->xsk_pool) {
		ret = -ENXIO;
		goto l_end;
	}

	ring = vsi->xdp_rings.q[queue_id];

	q_vector = ring->irq_data;
	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		sxe2_trigger_soft_intr(&vsi->adapter->hw, q_vector);

l_end:
	return ret;
}
#endif

STATIC s32 sxe2_set_vf_bw_check_param(struct net_device *netdev, s32 vf_idx,
				      s32 min_tx_rate, s32 max_tx_rate)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (sxe2_min_tx_rate_oversubscribed(adapter, vf_idx, min_tx_rate)) {
		ret = -EINVAL;
		goto l_end;
	}

	if (min_tx_rate && ((u32)min_tx_rate > (SXE2_TXSCHED_MAX_BW / 1000))) {
		LOG_NETDEV_ERR("invalid min rate %u specified for the vf %d\n",
			       (u32)min_tx_rate, vf_idx);
		ret = -EINVAL;
		goto l_end;
	}

	if (max_tx_rate && ((u32)max_tx_rate > (SXE2_TXSCHED_MAX_BW / 1000))) {
		LOG_NETDEV_ERR("invalid max rate %u specified for the vf %d\n",
			       (u32)max_tx_rate, vf_idx);
		ret = -EINVAL;
		goto l_end;
	}

	if (max_tx_rate &&
	    ((u32)max_tx_rate > adapter->link_ctxt.current_link_speed)) {
		LOG_NETDEV_ERR("invalid max rate %u specified for the vf %d in port \t"
			       "%d\n",
			       (u32)max_tx_rate, vf_idx, adapter->port_idx);
		ret = -EINVAL;
		goto l_end;
	}

	if (min_tx_rate && max_tx_rate && min_tx_rate > max_tx_rate) {
		LOG_NETDEV_ERR("invalid vf[%d] min rate %u > max rate %u\n", vf_idx,
			       min_tx_rate, max_tx_rate);
		ret = -EINVAL;
		goto l_end;
	}
l_end:
	return ret;
}

STATIC s32 sxe2_set_vf_bw_check(struct net_device *netdev, s32 vf_idx,
				s32 min_tx_rate, s32 max_tx_rate)
{
	s32 ret;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (test_bit(SXE2_VSI_S_DISABLE, np->vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

	if (sxe2_vf_id_check(adapter, (u16)vf_idx)) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_set_vf_bw_check_param(netdev, vf_idx, min_tx_rate, max_tx_rate);

l_end:
	return ret;
}

s32 sxe2_cfg_vf_bw(struct sxe2_adapter *adapter, s32 vf_idx, s32 min_tx_rate,
		   s32 max_tx_rate)
{
	s32 ret;
	struct sxe2_vf_node *vf_node;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));

	vf_node = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf_node) {
		ret = -EINVAL;
		goto l_unlock;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf_node);
	if (ret)
		goto l_unlock;

	if (vf_node->prop.min_tx_rate != (u32)min_tx_rate) {
		if (!min_tx_rate)
			ret = sxe2_txsched_vf_bw_lmt_cfg(adapter, vf_node,
							 SXE2_NODE_RL_TYPE_CIR,
							 SXE2_TXSCHED_DFLT_BW);
		else
			ret = sxe2_txsched_vf_bw_lmt_cfg(adapter, vf_node,
							 SXE2_NODE_RL_TYPE_CIR,
							 (u32)min_tx_rate * 1000);
		if (ret) {
			LOG_ERROR_BDF("unable to set vf min rate, ret=%d, \t"
				      "vf_idx=%u, minrate=%u\n",
				      ret, vf_idx, min_tx_rate);
			goto l_unlock;
		}
		vf_node->prop.min_tx_rate = (u32)min_tx_rate;
	}

	if (vf_node->prop.max_tx_rate != (u32)max_tx_rate) {
		if (!max_tx_rate)
			ret = sxe2_txsched_vf_bw_lmt_cfg(adapter, vf_node,
							 SXE2_NODE_RL_TYPE_EIR,
							 SXE2_TXSCHED_DFLT_BW);
		else
			ret = sxe2_txsched_vf_bw_lmt_cfg(adapter, vf_node,
							 SXE2_NODE_RL_TYPE_EIR,
							 (u32)max_tx_rate * 1000);
		if (ret) {
			LOG_ERROR_BDF("unable to set vf max rate, ret=%d, \t"
				      "vf_idx=%u, maxrate=%u\n",
				      ret, vf_idx, max_tx_rate);
			goto l_unlock;
		}
		vf_node->prop.max_tx_rate = (u32)max_tx_rate;
	}

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, (u16)vf_idx));

	return ret;
}

STATIC s32 sxe2_set_vf_bw(struct net_device *netdev, s32 vf_idx, s32 min_tx_rate,
			  s32 max_tx_rate)
{
	s32 ret;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	ret = sxe2_set_vf_bw_check(netdev, vf_idx, min_tx_rate, max_tx_rate);
	if (ret) {
		LOG_NETDEV_ERR("vf bw check failed\n");
		goto l_end;
	}

	ret = sxe2_cfg_vf_bw(adapter, vf_idx, min_tx_rate, max_tx_rate);
	if (ret)
		LOG_NETDEV_ERR("cfg vf bw failed\n");

l_end:
	return ret;
}

STATIC const struct net_device_ops sxe2_netdev_ops = {
		.ndo_open = sxe2_open,
		.ndo_stop = sxe2_stop,

		.ndo_select_queue = sxe2_select_queue,
		.ndo_start_xmit = sxe2_xmit,
		.ndo_get_stats64 = sxe2_get_stats64,
		.ndo_change_mtu = sxe2_change_mtu,
		.ndo_validate_addr = eth_validate_addr,
		.ndo_set_features = sxe2_set_features,
		.ndo_features_check = sxe2_features_check,
		.ndo_fix_features = sxe2_fix_features,
		.ndo_set_mac_address = sxe2_set_mac_address,
#ifdef HAVE_NDO_ETH_IOCTL
		.ndo_eth_ioctl = sxe2_eth_ioctl,
#else
		.ndo_do_ioctl = sxe2_eth_ioctl,
#endif

		.ndo_bridge_getlink = sxe2_bridge_getlink,
		.ndo_bridge_setlink = sxe2_bridge_setlink,
		.ndo_dfwd_add_station = sxe2_fwd_add_macvlan,
		.ndo_dfwd_del_station = sxe2_fwd_del_macvlan,
		.ndo_fdb_add = sxe2_fdb_add,
		.ndo_fdb_del = sxe2_fdb_del,
		.ndo_set_rx_mode = sxe2_set_rx_mode,

		.ndo_vlan_rx_add_vid = sxe2_vlan_rx_add_vid,
		.ndo_vlan_rx_kill_vid = sxe2_vlan_rx_kill_vid,

		.ndo_setup_tc = sxe2_setup_tc,
		.ndo_set_tx_maxrate = sxe2_set_tx_maxrate,
		.ndo_set_vf_vlan = sxe2_set_vf_port_vlan,
		.ndo_set_vf_spoofchk = sxe2_set_vf_spoofchk,
		.ndo_set_vf_mac = sxe2_set_vf_mac,
		.ndo_get_vf_config = sxe2_get_vf_cfg,
		.ndo_set_vf_trust = sxe2_set_vf_trust,
		.ndo_set_vf_link_state = sxe2_set_vf_link_state,
		.ndo_set_vf_rate = sxe2_set_vf_bw,
#ifdef CONFIG_RFS_ACCEL
		.ndo_rx_flow_steer = sxe2_rx_flow_steer,
#endif

#ifdef HAVE_XDP_SUPPORT
		.ndo_bpf = sxe2_xdp,
		.ndo_xdp_xmit = sxe2_xdp_xmit,
#endif
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifdef HAVE_NDO_XSK_WAKEUP
		.ndo_xsk_wakeup = sxe2_xsk_wakeup,
#else
		.ndo_xsk_async_xmit = sxe2_xsk_async_xmit,
#endif

#endif
};

STATIC const struct net_device_ops sxe2_netdev_ops_for_safe_mode = {
		.ndo_open = sxe2_open,
		.ndo_stop = sxe2_stop,
		.ndo_start_xmit = sxe2_xmit,
		.ndo_get_stats64 = sxe2_get_stats64,
		.ndo_change_mtu = sxe2_change_mtu,
		.ndo_validate_addr = eth_validate_addr,
		.ndo_set_mac_address = sxe2_set_mac_address,
#ifdef HAVE_XDP_SUPPORT
		.ndo_bpf = sxe2_xdp,
#endif
};

STATIC void sxe2_netdev_ops_init(struct net_device *netdev)
{
	netdev->netdev_ops = &sxe2_netdev_ops;
}

STATIC void sxe2_netdev_ops_init_for_safe_mode(struct net_device *netdev)
{
	netdev->netdev_ops = &sxe2_netdev_ops_for_safe_mode;
}

static void sxe2_netdev_priv_flags_init(struct net_device *netdev)
{
	netdev->priv_flags |= IFF_UNICAST_FLT;
}

#ifdef HAVE_NETDEV_MIN_MAX_MTU
void sxe2_netdev_mtu_init(struct net_device *netdev)
{
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = SXE2_MAX_MTU;
}
#endif

s32 sxe2_netdev_init(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	struct net_device *netdev;

	netdev = sxe2_netdev_alloc(vsi);
	if (!netdev) {
		ret = -ENOMEM;
		goto l_end;
	}

	sxe2_netdev_feature_init(netdev);

	if (!sxe2_is_safe_mode(adapter))
		sxe2_netdev_ops_init(netdev);
	else
		sxe2_netdev_ops_init_for_safe_mode(netdev);
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	netdev->udp_tunnel_nic_info = adapter->udp_tunnel_nic;
#endif
	sxe2_netdev_priv_flags_init(netdev);

#ifdef HAVE_NETDEV_MIN_MAX_MTU
	sxe2_netdev_mtu_init(netdev);
#endif
	if (!sxe2_is_safe_mode(adapter))
		sxe2_ethtool_ops_set(netdev);
	else
		sxe2_ethtool_ops_set_for_safe_mode(netdev);

	sxe2_dcbnl_setup(vsi);

l_end:
	return ret;
}

void sxe2_netdev_deinit(struct sxe2_vsi *vsi)
{
	free_netdev(vsi->netdev);
	vsi->netdev = NULL;
}

s32 sxe2_netdev_register(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	netif_tx_stop_all_queues(vsi->netdev);
	netif_carrier_off(vsi->netdev);
	LOG_INFO_BDF("net dev carrier off link down.\n");

	ret = register_netdev(vsi->netdev);
	if (ret) {
		LOG_DEV_ERR("netdev register failed, ret=%d.\n", ret);
		goto l_end;
	}

	ret = sxe2_hw_mtu_init(adapter, vsi->netdev->mtu, false);
	if (ret) {
		unregister_netdev(vsi->netdev);
		LOG_DEV_ERR("net dev init mtu set failed, ret=%d.\n", ret);
	}

l_end:
	return ret;
}

bool netif_is_sxe2(struct net_device *netdev)
{
	return netdev && (netdev->netdev_ops == &sxe2_netdev_ops);
}

#ifdef HAVE_FLOW_BLOCK_API
#ifdef HAVE_TC_INDIR_BLOCK
static void sxe2_rep_indr_tc_block_unbind(void *cb_priv)
{
	struct sxe2_indr_block_priv *indr_priv = cb_priv;

	list_del(&indr_priv->list);
	kfree(indr_priv);
}
#endif
#endif

#ifdef HAVE_TC_INDIR_BLOCK
static struct sxe2_indr_block_priv *
sxe2_indr_block_priv_find(struct sxe2_netdev_priv *np, struct net_device *netdev)
{
	struct sxe2_indr_block_priv *cb_priv;

	list_for_each_entry(cb_priv, &np->tc_indr_block_priv_list, list) {
		if (!cb_priv->netdev)
			return NULL;
		if (cb_priv->netdev == netdev)
			return cb_priv;
	}
	return NULL;
}

#ifdef SXE2_INDR_SETUP_TC_BLOCK_NEED_3_PARAMS
STATIC s32 sxe2_indr_setup_tc_block(struct net_device *netdev,
				    struct sxe2_netdev_priv *np,
				    struct flow_block_offload *f)
#else
STATIC s32 sxe2_indr_setup_tc_block(struct net_device *netdev, struct Qdisc *sch,
				    struct sxe2_netdev_priv *np,
				    struct flow_block_offload *f, void *data,
				    void (*cleanup)(struct flow_block_cb *block_cb))
#endif
{
#ifndef HAVE_FLOW_BLOCK_API
	s32 ret;
#endif
	struct sxe2_indr_block_priv *indr_priv;
#ifdef HAVE_FLOW_BLOCK_API
	struct flow_block_cb *block_cb;
#endif

	if ((sxe2_tc_tun_type_get(netdev) == SXE2_TNL_NONE) &&
	    !(is_vlan_dev(netdev) && vlan_dev_real_dev(netdev) == np->vsi->netdev))
		return -EOPNOTSUPP;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	if (f->command == FLOW_BLOCK_BIND) {
		indr_priv = sxe2_indr_block_priv_find(np, netdev);
		if (indr_priv)
			return -EEXIST;

		indr_priv = kzalloc(sizeof(*indr_priv), GFP_KERNEL);
		if (!indr_priv)
			return -ENOMEM;

		indr_priv->netdev = netdev;
		indr_priv->np = np;

		list_add(&indr_priv->list, &np->tc_indr_block_priv_list);

#ifdef HAVE_FLOW_BLOCK_API
#ifdef HAVE_FLOW_INDR_BLOCK_API
		block_cb = flow_indr_block_cb_alloc(sxe2_indr_setup_block_cb,
						    indr_priv, indr_priv,
						    sxe2_rep_indr_tc_block_unbind, f,
						    netdev, sch, data, np, cleanup);
#else
		block_cb = flow_block_cb_alloc(sxe2_indr_setup_block_cb, indr_priv,
					       indr_priv,
					       sxe2_rep_indr_tc_block_unbind);
#endif
		if (IS_ERR(block_cb)) {
			list_del(&indr_priv->list);
			kfree(indr_priv);
			return (s32)PTR_ERR(block_cb);
		}

		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &sxe2_block_cb_list);
#else
		ret = tcf_block_cb_register(f->block, sxe2_indr_setup_block_cb,
					    indr_priv, indr_priv, f->extack);
		if (ret) {
			list_del(&indr_priv->list);
			kfree(indr_priv);
		}
		return ret;
#endif
	} else if (f->command == FLOW_BLOCK_UNBIND) {
		indr_priv = sxe2_indr_block_priv_find(np, netdev);
		if (!indr_priv)
			return -ENOENT;

#ifdef HAVE_FLOW_BLOCK_API
		block_cb = flow_block_cb_lookup(f->block, sxe2_indr_setup_block_cb,
						indr_priv);
		if (!block_cb)
			return -ENOENT;

#ifdef HAVE_FLOW_INDR_BLOCK_API
		flow_indr_block_cb_remove(block_cb, f);
#else
		flow_block_cb_remove(block_cb, f);
#endif
		list_del(&block_cb->driver_list);
#else
		tcf_block_cb_unregister(f->block, sxe2_indr_setup_block_cb,
					indr_priv);
		list_del(&indr_priv->list);
		kfree(indr_priv);
#endif
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}

#ifdef SXE2_INDR_SETUP_TC_BLOCK_CB_NEED_4_PARAMS
STATIC s32 sxe2_indr_setup_tc_block_cb(struct net_device *netdev, void *cb_priv,
				       enum tc_setup_type type, void *type_data)
{
	if (type == TC_SETUP_BLOCK)
		return sxe2_indr_setup_tc_block(netdev, cb_priv, type_data);
	else
		return -EOPNOTSUPP;
}
#else
STATIC s32 sxe2_indr_setup_tc_block_cb(struct net_device *netdev,
				       struct Qdisc *sch, void *cb_priv,
				       enum tc_setup_type type, void *type_data,
				       void *data,
				       void (*cleanup)(struct flow_block_cb *block_cb))
{
	if (type == TC_SETUP_BLOCK)
		return sxe2_indr_setup_tc_block(netdev, sch, cb_priv, type_data,
						data, cleanup);
	else
		return -EOPNOTSUPP;
}
#endif

#ifndef HAVE_TC_FLOW_INDIR_DEV
static int sxe2_indr_register_block(struct sxe2_netdev_priv *np,
				    struct net_device *netdev)
{
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	int err;

	err = __flow_indr_block_cb_register(netdev, np, sxe2_indr_setup_tc_block_cb,
					    np);
	if (err) {
		LOG_NETDEV_ERR("Failed to register remote block notifier for %s, \t"
			       "err %d\n",
			       netdev_name(netdev), err);
	}
	return err;
}

static void sxe2_indr_unregister_block(struct sxe2_netdev_priv *np,
				       struct net_device *netdev)
{
	__flow_indr_block_cb_unregister(netdev, sxe2_indr_setup_tc_block_cb, np);
}

static void sxe2_indr_clean_block_privs(struct sxe2_netdev_priv *np)
{
	struct sxe2_indr_block_priv *cb_priv, *temp;
	struct list_head *head = &np->tc_indr_block_priv_list;

	list_for_each_entry_safe(cb_priv, temp, head, list) {
		sxe2_indr_unregister_block(np, cb_priv->netdev);
		devm_kfree(&cb_priv->netdev->dev, cb_priv);
	}
}

static int sxe2_netdevice_event(struct notifier_block *nb, unsigned long event,
				void *ptr)
{
	struct sxe2_netdev_priv *np =
			container_of(nb, struct sxe2_netdev_priv, netdevice_nb);
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	int tunnel_type = sxe2_tc_tun_type_get(netdev);

	if (tunnel_type != SXE2_TNL_VXLAN && tunnel_type != SXE2_TNL_GENEVE &&
	    !(is_vlan_dev(netdev) && vlan_dev_real_dev(netdev) == np->vsi->netdev))
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_REGISTER:
		sxe2_indr_register_block(np, netdev);
		break;
	case NETDEV_UNREGISTER:
		sxe2_indr_unregister_block(np, netdev);
		break;
	}
	return NOTIFY_OK;
}
#endif
#endif

#ifdef HAVE_TC_INDIR_BLOCK
s32 sxe2_tc_indir_block_register(struct sxe2_vsi *vsi)
{
	struct sxe2_netdev_priv *np;

	if (!vsi || !vsi->netdev)
		return -EINVAL;

	np = netdev_priv(vsi->netdev);

	INIT_LIST_HEAD(&np->tc_indr_block_priv_list);
#ifdef HAVE_TC_FLOW_INDIR_DEV
	return flow_indr_dev_register(sxe2_indr_setup_tc_block_cb, np);
#else
	np->netdevice_nb.notifier_call = sxe2_netdevice_event;
	return register_netdevice_notifier(&np->netdevice_nb);
#endif
}

void sxe2_tc_indir_block_unregister(struct sxe2_vsi *vsi)
{
	struct sxe2_netdev_priv *np = netdev_priv(vsi->netdev);

#ifdef HAVE_TC_FLOW_INDIR_DEV
#ifdef UNREGISTER_NEED_SETUP_BLOCK
	flow_indr_dev_unregister(sxe2_indr_setup_tc_block_cb, np,
				 sxe2_indr_setup_block_cb);
#else
	flow_indr_dev_unregister(sxe2_indr_setup_tc_block_cb, np,
				 sxe2_rep_indr_tc_block_unbind);
#endif
#else
	unregister_netdevice_notifier(&np->netdevice_nb);
	sxe2_indr_clean_block_privs(np);
#endif
}
#endif

bool sxe2_netdev_is(struct net_device *dev)
{
	return dev && (dev->netdev_ops == &sxe2_netdev_ops ||
		       dev->netdev_ops == &sxe2_netdev_ops_for_safe_mode);
}

s32 sxe2_netdev_q_cnt_set(struct net_device *netdev, u16 txq_cnt, u16 rxq_cnt,
			  bool is_locked)
{
	s32 ret;
	struct sxe2_netdev_priv *np;
	struct sxe2_adapter *adapter;
	u16 old_txq_cnt;
	u16 total_txq_cnt;

	if (!is_locked)
		rtnl_lock();

	old_txq_cnt = (u16)netdev->real_num_tx_queues;
	total_txq_cnt = txq_cnt;

	if (!netif_is_macvlan(netdev)) {
		np = netdev_priv(netdev);
		adapter = np->vsi->adapter;
		if (test_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags))
			total_txq_cnt += adapter->macvlan_ctxt.max_num_macvlan;
	}

	ret = netif_set_real_num_tx_queues(netdev, total_txq_cnt);
	if (ret) {
		LOG_ERROR("set real txq cnt from %u to %u failed %d.\n", old_txq_cnt,
			  total_txq_cnt, ret);
		goto l_out;
	}

	ret = netif_set_real_num_rx_queues(netdev, rxq_cnt);
	if (ret) {
		LOG_ERROR("set real rxq cnt to %u failed.\n", rxq_cnt);
		(void)netif_set_real_num_tx_queues(netdev, old_txq_cnt);
	}

l_out:
	if (!is_locked)
		rtnl_unlock();
	return ret;
}
