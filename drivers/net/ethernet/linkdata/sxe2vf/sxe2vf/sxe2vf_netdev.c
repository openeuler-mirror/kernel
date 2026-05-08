// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_netdev.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>

#include "sxe2_log.h"
#include "sxe2vf_ethtool.h"
#include "sxe2vf_netdev.h"
#include "sxe2vf.h"
#include "sxe2vf_rx.h"
#include "sxe2vf_l2_filter.h"
#include "sxe2vf_tx.h"
#include "sxe2vf_vsi.h"
#include "sxe2vf_rxft.h"
#include "sxe2vf_ipsec.h"

#define SXE2VF_TSO_MIN_MTU 576
#define SXE2VF_WAIT_POST_COMPLETE_COUNT 2000
#define SXE2VF_WAIT_POST_10MS 10

#define SXE2VF_SET_FEATURE(features, feature, enable)                               \
	do {                                                                        \
		typeof(features) __features = (features);                           \
		typeof(feature) __feature = (feature);                              \
		if (enable)                                                         \
			*(__features) |= __feature;                                 \
		else                                                                \
			*(__features) &= ~__feature;                                \
	} while (0)

static inline int sxe2vf_conflict_features_chk(u64 changed_features, u64 features,
					       u64 con1, u64 con2)
{
	if ((changed_features & con1 && features & con1) &&
	    (changed_features & con2 && features & con2))
		return -EINVAL;

	return 0;
}

STATIC s32 sxe2vf_open(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi;
	s32 i;
	s32 ret;

	for (i = 0; i < SXE2VF_WAIT_POST_COMPLETE_COUNT; i++) {
		msleep(SXE2VF_WAIT_POST_10MS);
		if (test_bit(SXE2VF_FLAG_DRV_PROBE_DONE, adapter->flags))
			break;
	}

	if (i == SXE2VF_WAIT_POST_COMPLETE_COUNT) {
		LOG_DEV_ERR("probe post not complete, try later.\n");
		return -EIO;
	}

	vsi = adapter->vsi_ctxt.vf_vsi;
	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try open later flag:0x%lx.\n",
			     *adapter->flags);
		ret = -EBUSY;
		goto unlock;
	}

	if (!test_bit(SXE2VF_VSI_CLOSE, vsi->state)) {
		LOG_DEV_INFO("vf already open flag:0x%lx.\n", *adapter->flags);
		ret = 0;
		goto l_set_bit;
	}

	ret = sxe2vf_vsi_open(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi open failed %d.\n", ret);
		goto unlock;
	}

	LOG_INFO_BDF("netdev opened.\n");

l_set_bit:
	set_bit(SXE2VF_FLAG_DRV_UP, adapter->flags);

unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

STATIC s32 sxe2vf_stop(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	struct sxe2vf_sync_addr_node *list_itr = NULL;
	struct sxe2vf_sync_addr_node *tmp = NULL;
	s32 ret = 0;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	vsi = adapter->vsi_ctxt.vf_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);

	clear_bit(SXE2VF_FLAG_DRV_UP, adapter->flags);

	if (test_bit(SXE2VF_VSI_DISABLE, vsi->state))
		goto unlock;

	ret = sxe2vf_vsi_close(vsi);
	if (!ret)
		LOG_INFO_BDF("netdev stopped.\n");

	mutex_lock(&switch_ctxt->mac_addr_lock);
	INIT_LIST_HEAD(&filter->tmp_unsync_list);

	netif_addr_lock_bh(netdev);
	__dev_uc_unsync(netdev, sxe2vf_addr_unsync);
	__dev_mc_unsync(netdev, sxe2vf_addr_unsync);
	netif_addr_unlock_bh(netdev);

	list_for_each_entry_safe(list_itr, tmp, &filter->tmp_unsync_list, list) {
		(void)sxe2vf_mac_addr_del(adapter, list_itr->macaddr,
					  SXE2VF_MAC_OWNER_UC_MC);
		list_del(&list_itr->list);
		kfree(list_itr);
	}

	mutex_unlock(&switch_ctxt->mac_addr_lock);

unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static int sxe2vf_set_vlan_features(struct net_device *netdev,
				    netdev_features_t features,
				    netdev_features_t *oper_features)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 status = 0;
	s32 ret = 0;

	if (adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist &&
	    (features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX))) {
		LOG_DEV_ERR("port vlan exist, stag offload not support.\n");
		ret = -EOPNOTSUPP;
		return ret;
	}

	if (adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist &&
	    (features & SXE2VF_VLAN_FILTER_FEATURES)) {
		LOG_DEV_ERR("port vlan exist, vlan filter not support.\n");
		ret = -EOPNOTSUPP;
		return ret;
	}

	status = sxe2vf_vlan_offload_cfg(netdev,
					 features & SXE2VF_VLAN_OFFLOAD_FEATURES);
	if (!status) {
		SXE2VF_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_CTAG_RX,
				   (features & NETIF_F_HW_VLAN_CTAG_RX));
		SXE2VF_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_CTAG_TX,
				   (features & NETIF_F_HW_VLAN_CTAG_TX));
		SXE2VF_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_STAG_RX,
				   (features & NETIF_F_HW_VLAN_STAG_RX));
		SXE2VF_SET_FEATURE(oper_features, NETIF_F_HW_VLAN_STAG_TX,
				   (features & NETIF_F_HW_VLAN_STAG_TX));
	} else {
		ret = status;
	}

	status = sxe2vf_vlan_filter_cfg(netdev,
					features & SXE2VF_VLAN_FILTER_FEATURES);
	if (!status) {
		SXE2VF_SET_FEATURE(oper_features, SXE2VF_VLAN_FILTER_FEATURES,
				   (features & SXE2VF_VLAN_FILTER_FEATURES));
	} else {
		ret = status;
	}

	LOG_INFO_BDF("current features 0x%llx, request features 0x%llx\n",
		     netdev->features, features);
	return ret;
}

static s32 sxe2vf_set_lro_features(struct net_device *netdev,
				   netdev_features_t features,
				   netdev_features_t *oper_features)
{
	bool need_reset = false;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 ret = 0;
	bool lro_ena = !!(features & NETIF_F_LRO);
	bool old_lro_feature =
			(bool)test_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags);

	if (!(features & NETIF_F_LRO)) {
		if (test_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags)) {
			clear_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags);
			need_reset = true;
			LOG_DEBUG_BDF("lro disabled and need reset\n");
		}
	} else {
		if (!(features & NETIF_F_RXCSUM)) {
			LOG_NETDEV_ERR("Cannot simultaneously enable lro and\t"
				       "disable rx csum.\n");
			return -EOPNOTSUPP;
		}

		if (!(test_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags))) {
			set_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags);
			need_reset = true;
			LOG_DEBUG_BDF("lro enabled and need reset\n");
		}
	}

	if (need_reset) {
		ret = sxe2vf_vsi_reopen(adapter->vsi_ctxt.vf_vsi);
		if (ret) {
			LOG_NETDEV_ERR("set_features down_up err %d\n", ret);
			if (old_lro_feature)
				set_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags);
			else
				clear_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags);
		} else {
			SXE2VF_SET_FEATURE(oper_features, NETIF_F_LRO, lro_ena);
		}
	}

	return ret;
}

static s32 sxe2vf_set_rxfcs_features(struct net_device *netdev,
				     netdev_features_t features,
				     netdev_features_t *oper_features)
{
	bool need_reset = false;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 ret = 0;
	bool rxfcs_ena = !!(features & NETIF_F_RXFCS);
	bool old_rxfcs_feature =
			(bool)test_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags);

	if (!(features & NETIF_F_RXFCS)) {
		if (test_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags)) {
			clear_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags);
			need_reset = true;
			LOG_DEBUG_BDF("rxfcs disabled and need reset\n");
		}
	} else {
		if (!(test_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags))) {
			set_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags);
			need_reset = true;
			LOG_DEBUG_BDF("rxfcs enabled and need reset\n");
		}
	}

	if (need_reset) {
		ret = sxe2vf_vsi_reopen(adapter->vsi_ctxt.vf_vsi);
		if (ret) {
			LOG_NETDEV_ERR("set_features down_up err %d\n", ret);
			if (old_rxfcs_feature)
				set_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags);
			else
				clear_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags);
		} else {
			SXE2VF_SET_FEATURE(oper_features, NETIF_F_RXFCS, rxfcs_ena);
		}
	}

	return ret;
}

STATIC int sxe2vf_set_fnav_features(struct net_device *netdev,
				    netdev_features_t features,
				    netdev_features_t *oper_features)
{
	s32 ret = 0;
	netdev_features_t changed_features = netdev->features ^ features;
	bool fnav_ena = !!(features & NETIF_F_NTUPLE);
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	if (!(changed_features & NETIF_F_NTUPLE))
		goto l_end;

	if (fnav_ena) {
		if (!test_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags))
			set_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags);

		SXE2VF_SET_FEATURE(oper_features, NETIF_F_NTUPLE, fnav_ena);
		goto l_end;
	}

	if (!test_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags)) {
		SXE2VF_SET_FEATURE(oper_features, NETIF_F_NTUPLE, fnav_ena);
		goto l_end;
	}

	ret = sxe2vf_fnav_all_filter_del(adapter);
	if (!ret) {
		SXE2VF_SET_FEATURE(oper_features, NETIF_F_NTUPLE, fnav_ena);
	} else {
		LOG_ERROR_BDF("delete all filter failed, ret:%d", ret);
		goto l_end;
	}
#ifdef SXE2_SUPPORT_ACL
	ret = sxe2vf_acl_filter_clear_msg_send(adapter);
	if (ret) {
		LOG_ERROR_BDF("send acl filter clear msg failed, ret:%d", ret);
		goto l_end;
	}
#endif
	clear_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags);
l_end:
	LOG_INFO_BDF("sxe2 vf fnav set feature done, fnav_ena:%d ret:%d\n", fnav_ena,
		     ret);
	return ret;
}

static s32 sxe2vf_set_rxcsum_features(struct net_device *netdev,
				      netdev_features_t features,
				      netdev_features_t *oper_features)
{
	s32 ret = 0;
	bool rxcsum_ena = !!(features & NETIF_F_RXCSUM);

	SXE2VF_SET_FEATURE(oper_features, NETIF_F_RXCSUM, rxcsum_ena);

	return ret;
}

STATIC s32 sxe2vf_set_ipsec_features(struct net_device *netdev,
				     netdev_features_t features,
				     netdev_features_t *oper_features)
{
	s32 ret = 0;
	netdev_features_t changed_features = netdev->features ^ features;
	bool ipsec_ena = !!(features & NETIF_F_HW_ESP);
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	if (changed_features & NETIF_F_HW_ESP) {
		mutex_lock(&adapter->ipsec_ctxt.context_lock);
		if (ipsec_ena) {
			LOG_DEBUG_BDF("Enable ipsec offload(off to on).\n");
			if (sxe2vf_ipsec_conflict_features_check(netdev)) {
				LOG_DEV_ERR("failed to enable ipsec offload,\t"
					    "please disable tx segmentation offload\t"
					    "features,\t"
					    "tx vlan offload feature and LRO\t"
					    "offload feature.\n");
				ret = -EINVAL;
			} else {
				if (netdev->mtu >= SXE2VF_IPSEC_PAYLOAD_LIMIT) {
					LOG_NETDEV_WARN("SXE2:Current mtu is %d.\t"
							"The maximum encryption\t"
							"length of IPsec is 2k.\t"
							"If the packet length is\t"
							"greater than 2k,\t"
							"the hardware ipsec\t"
							"offloading may fail.\n",
							netdev->mtu);
				}
			}
		} else {
			LOG_DEBUG_BDF("Disable ipsec offload switch(on to off).\n");
			if (sxe2vf_is_ipsec_can_not_disable(adapter)) {
				LOG_DEV_ERR("Can not disable ipsec offload,\t"
					    "please delete all xfrm state before\t"
					    "disable ipsec offload\n");
				ret = -EINVAL;
			}
		}
		if (!ret)
			SXE2VF_SET_FEATURE(oper_features, NETIF_F_HW_ESP, ipsec_ena);

		mutex_unlock(&adapter->ipsec_ctxt.context_lock);
	}

	return ret;
}

static s32 sxe2vf_conflict_features_check(struct net_device *netdev,
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
		    NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC | NETIF_F_IPV6_CSUM;

	(void)sxe2vf_conflict_features_chk(changed_features, features, conflict1,
					   conflict2);

	return 0;
}

static s32 sxe2vf_set_features(struct net_device *netdev, netdev_features_t features)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	netdev_features_t oper_features;
	bool part_failed = false;

	ret = sxe2vf_conflict_features_check(netdev, features);
	if (ret) {
		LOG_DEV_ERR("some features are conflict\n");
		return ret;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, adapter->vsi_ctxt.vf_vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try later\n");
		mutex_unlock(&adapter->vsi_ctxt.lock);
		return -EBUSY;
	}

	oper_features = netdev->features;
	ret = sxe2vf_set_rxfcs_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	ret = sxe2vf_set_lro_features(netdev, features, &oper_features);
	if (ret) {
		part_failed = true;
		goto skip_rxcsum;
	}

	ret = sxe2vf_set_rxcsum_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

skip_rxcsum:
	ret = sxe2vf_set_ipsec_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	ret = sxe2vf_set_vlan_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	ret = sxe2vf_set_fnav_features(netdev, features, &oper_features);
	if (ret)
		part_failed = true;

	if (part_failed) {
		netdev->features = oper_features;
		ret = -EINVAL;
	}

	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static netdev_features_t sxe2vf_fix_ipsec_features(struct sxe2vf_adapter *adapter,
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
			LOG_DEV_ERR("ipsec is conflicted with tx segmentation\t"
				    "offload.\n");
			features &= ~(tso_features);
		}
		if (features &
		    (NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC | NETIF_F_IPV6_CSUM)) {
			LOG_DEV_ERR("ipsec is conflicted with tx Checksum\t"
				    "offload.\n");
			features &= ~(NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC |
				      NETIF_F_IPV6_CSUM);
		}
		if (features & (NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX)) {
			LOG_DEV_ERR("ipsec is conflicted with tx VLAN offload.\n");
			features &= ~(NETIF_F_HW_VLAN_CTAG_TX |
				      NETIF_F_HW_VLAN_STAG_TX);
		}
		if (features & NETIF_F_LRO) {
			LOG_DEV_ERR("ipsec is conflicted with LRO.\n");
			features &= ~(NETIF_F_LRO);
		}
	}
	return features;
}

static netdev_features_t sxe2vf_fix_features(struct net_device *netdev,
					     netdev_features_t features)
{
	netdev_features_t req_vlan_fltr, cur_vlan_fltr;
	bool cur_ctag, cur_stag, req_ctag, req_stag;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	u8 port_vlan_exist = vlan_info->port_vlan_exist;
	u8 is_switchdev = vlan_info->is_switchdev;
	netdev_features_t request_features;

	request_features = features;

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
			LOG_DEV_WARN("802.1Q and 802.1ad VLAN filtering must be\t"
				     "either both on or both off.\n"
				     "VLAN filtering has been enabled for both\t"
				     "types.\n");
			if (!cur_ctag && !cur_stag)
				features |= NETIF_VLAN_FILTERING_FEATURES;
			else
				features &= ~NETIF_VLAN_FILTERING_FEATURES;
		}
	}

	if ((features & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX)) &&
	    (features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX))) {
		LOG_DEV_WARN("cannot support CTAG and STAG VLAN stripping and/or\t"
			     "insertion simultaneously.\n"
			     "since CTAG and STAG offloads are mutually exclusive,\t"
			     "clearing STAG offload settings\n");
		features &= ~(NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX);
	}

	if (port_vlan_exist) {
		features &= ~(SXE2VF_VLAN_FILTER_FEATURES | NETIF_F_HW_VLAN_STAG_RX |
			      NETIF_F_HW_VLAN_STAG_TX);
	}

	if (is_switchdev) {
		features &= ~(SXE2VF_VLAN_FILTER_FEATURES | NETIF_F_HW_VLAN_STAG_RX |
			      NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_CTAG_RX |
			      NETIF_F_HW_VLAN_CTAG_TX);
	}

	features = sxe2vf_fix_ipsec_features(adapter, netdev, features);

	LOG_DEBUG_BDF("request features %llx, fix features %llx\n", request_features,
		      features);
	return features;
}

static netdev_features_t
sxe2vf_features_check(struct sk_buff *skb, struct net_device __always_unused *netdev,
		      netdev_features_t features)
{
	size_t len;
	bool gso = skb_is_gso(skb);
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	if (gso && (skb_shinfo(skb)->gso_size < SXE2VF_TXCD_QW1_MSS_MIN)) {
		LOG_WARN_BDF("gso size < 88, not support\n");
		features &= ~NETIF_F_GSO_MASK;
	}

	len = (size_t)skb_network_offset(skb);
	if (len > SXE2VF_TXDD_MACLEN_MAX || len & 0x1) {
		LOG_WARN_BDF("The mac header exceeds the max length,\t"
			     "not support tso/csum, maclen = %zu\n",
			     len);
		goto out_rm_features;
	}

	len = skb_network_header_len(skb);
	if (len > SXE2VF_TXDD_IPLEN_MAX || len & 0x1) {
		LOG_WARN_BDF("The ip header exceeds the max length,\t"
			     "not support tso/csum, iplen = %zu\n",
			     len);
		goto out_rm_features;
	}

	if (skb->encapsulation) {
		if (gso && (skb_shinfo(skb)->gso_type &
			    (SKB_GSO_GRE | SKB_GSO_UDP_TUNNEL))) {
			len = (size_t)(skb_inner_network_header(skb) -
				       skb_transport_header(skb));
			if (len > SXE2VF_TXDD_L4LEN_MAX || len & 0x1) {
				LOG_WARN_BDF("tunnel:The inner L4 header exceeds\t"
					     "the max length,\t"
					     "not support tso/csum, l4 len = %zu\n",
					     len);
				goto out_rm_features;
			}
		}

		len = skb_inner_network_header_len(skb);
		if (len > SXE2VF_TXDD_IPLEN_MAX || len & 0x1) {
			LOG_WARN_BDF("tunnel:The inner ip header exceeds the max\t"
				     "length,\t"
				     "not support tso/csum, ip len = %zu\n",
				     len);
			goto out_rm_features;
		}
	}

	return features;

out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

static int sxe2vf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 ret;
	u32 old_mtu = netdev->mtu;

	if (new_mtu == (int)netdev->mtu) {
		LOG_NETDEV_WARN("MTU is already %u\n", netdev->mtu);
		return 0;
	}

	netdev->mtu = (unsigned int)new_mtu;

	ret = sxe2vf_vsi_reopen_locked(adapter->vsi_ctxt.vf_vsi);
	if (ret) {
		netdev->mtu = old_mtu;
		LOG_NETDEV_ERR("changing MTU from %u to %d failed.\n", old_mtu,
			       new_mtu);
		return ret;
	}

	if (new_mtu > SXE2VF_IPSEC_PAYLOAD_LIMIT &&
	    sxe2vf_is_ipsec_offload_enable(netdev)) {
		LOG_NETDEV_WARN("SXE2:the maximum encryption length of IPsec is\t"
				"2k.\n"
				"If the packet length is greater than 2k, the\t"
				"hardware ipsec offloading may fail.\n");
	}

	LOG_NETDEV_INFO("changing MTU from %u to %d\n", old_mtu, new_mtu);

	set_bit(SXE2VF_FLAG_MTU_CHANGED, adapter->flags);

	return ret;
}

#ifdef HAVE_RTNL_LINK_NDO_GET_STATS64
STATIC struct rtnl_link_stats64 *sxe2vf_get_stats64(struct net_device *netdev,
						    struct rtnl_link_stats64 *stats)
#else
STATIC void sxe2vf_get_stats64(struct net_device *netdev,
			       struct rtnl_link_stats64 *stats)
#endif
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2vf_vsi_sw_stats *cur_stats = &vsi->vsi_stats.vsi_sw_stats;

	(void)sxe2vf_vsi_sw_stats_update(vsi);

	stats->tx_packets = cur_stats->tx_packets;
	stats->rx_packets = cur_stats->rx_packets;
	stats->tx_bytes = cur_stats->tx_bytes;
	stats->rx_bytes = cur_stats->rx_bytes;
#ifdef HAVE_RTNL_LINK_NDO_GET_STATS64
	return stats;
#endif
}

STATIC const struct net_device_ops sxe2vf_netdev_ops = {
		.ndo_open = sxe2vf_open,
		.ndo_stop = sxe2vf_stop,
		.ndo_start_xmit = sxe2vf_xmit,
		.ndo_set_mac_address = sxe2vf_set_mac_address,
		.ndo_set_rx_mode = sxe2vf_set_rx_mode,
		.ndo_validate_addr = eth_validate_addr,
		.ndo_change_mtu = sxe2vf_change_mtu,
		.ndo_vlan_rx_add_vid = sxe2vf_vlan_rx_add_vid,
		.ndo_vlan_rx_kill_vid = sxe2vf_vlan_rx_kill_vid,
		.ndo_features_check = sxe2vf_features_check,
		.ndo_fix_features = sxe2vf_fix_features,
		.ndo_set_features = sxe2vf_set_features,
		.ndo_setup_tc = NULL,
		.ndo_get_stats64 = sxe2vf_get_stats64,
};

STATIC void sxe2vf_netdev_feature_init(struct net_device *netdev)
{
	netdev_features_t defaults;
	netdev_features_t lro_features = 0;
	netdev_features_t csum_features;
	netdev_features_t tso_features;
	netdev_features_t vlan_features;

	netdev->priv_flags |= IFF_UNICAST_FLT;

	defaults = NETIF_F_SG | NETIF_F_HIGHDMA | NETIF_F_NTUPLE | NETIF_F_RXHASH;

	csum_features = NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC |
			NETIF_F_IPV6_CSUM;

	tso_features = NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6 |
		       NETIF_F_GSO_GRE | NETIF_F_GSO_UDP_TUNNEL |
		       NETIF_F_GSO_GRE_CSUM | NETIF_F_GSO_UDP_TUNNEL_CSUM |
		       NETIF_F_GSO_PARTIAL | NETIF_F_GSO_IPXIP4 |
#ifdef NETIF_F_GSO_UDP_L4
		       NETIF_F_GSO_UDP_L4 |
#endif
		       NETIF_F_GSO_IPXIP6;

	vlan_features = NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX;

	netdev->gso_partial_features |=
			NETIF_F_GSO_UDP_TUNNEL_CSUM | NETIF_F_GSO_GRE_CSUM;
	netdev->hw_features |= defaults | csum_features | tso_features |
			       NETIF_F_HW_TC | NETIF_F_LRO | vlan_features |
			       NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX |
			       NETIF_F_RXFCS;

	netdev->features |= defaults | csum_features | tso_features | lro_features |
			    vlan_features | NETIF_F_HW_VLAN_CTAG_FILTER |
			    NETIF_F_HW_VLAN_STAG_FILTER;

	netdev->hw_enc_features |= defaults | csum_features | tso_features;

	netdev->vlan_features |= defaults | csum_features | tso_features;

	if (netdev->wanted_features) {
		if (!(netdev->wanted_features & NETIF_F_TSO) ||
		    netdev->mtu < SXE2VF_TSO_MIN_MTU)
			netdev->features &= ~NETIF_F_TSO;
		if (!(netdev->wanted_features & NETIF_F_TSO6) ||
		    netdev->mtu < SXE2VF_TSO_MIN_MTU)
			netdev->features &= ~NETIF_F_TSO6;
		if (!(netdev->wanted_features & NETIF_F_TSO_ECN))
			netdev->features &= ~NETIF_F_TSO_ECN;
		if (!(netdev->wanted_features & NETIF_F_GRO))
			netdev->features &= ~NETIF_F_GRO;
		if (!(netdev->wanted_features & NETIF_F_GSO))
			netdev->features &= ~NETIF_F_GSO;
	}

	netdev->hw_features |= NETIF_F_HW_ESP;
	netdev->hw_enc_features |= NETIF_F_HW_ESP;
}

#ifdef HAVE_NETDEV_MIN_MAX_MTU
STATIC void sxe2vf_mtu_range_init(struct net_device *netdev)
{
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = SXE2VF_FRAME_SIZE_MAX - SXE2VF_PACKET_HDR_PAD;
}
#endif

STATIC void sxe2vf_netdev_ops_init(struct net_device *netdev)
{
	netdev->netdev_ops = &sxe2vf_netdev_ops;
	netdev->watchdog_timeo = SXE2VF_NETDEV_WATCHDOG_TIMEOUT;
}

void sxe2vf_netdev_init(struct sxe2vf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	sxe2vf_netdev_feature_init(netdev);

	sxe2vf_netdev_ops_init(netdev);

	sxe2vf_ethtool_ops_init(netdev);

#ifdef HAVE_NETDEV_MIN_MAX_MTU
	sxe2vf_mtu_range_init(netdev);
#endif
}

s32 sxe2vf_netdev_register(struct sxe2vf_adapter *adapter)
{
	s32 ret;
	struct net_device *netdev = adapter->netdev;

	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	LOG_INFO_BDF("net dev carrier off link down.\n");

	ret = register_netdev(netdev);
	if (ret) {
		LOG_ERROR_BDF("netdev register failed.(err:%d).\n", ret);
		return ret;
	}

	set_bit(SXE2VF_FLAG_NETDEV_REGISTERED, adapter->flags);

	return ret;
}

void sxe2vf_netdev_unregister(struct sxe2vf_adapter *adapter)
{
	if (test_and_clear_bit(SXE2VF_FLAG_NETDEV_REGISTERED, adapter->flags))
		unregister_netdev(adapter->netdev);
}
