/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_l2_filter.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_L2_FILTER_H__
#define __SXE2VF_L2_FILTER_H__
#include <linux/netdevice.h>
#include <linux/netdev_features.h>

#define SXE2VF_VLAN_OFFLOAD_FEATURES                                           \
	(NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX |                   \
	 NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX)

#define SXE2VF_VLAN_FILTER_FEATURES                                            \
	(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER)

#define SXE2VF_VLAN(tpid, vid, prio) ((struct sxe2vf_vlan){ tpid, vid, prio })

struct sxe2vf_mac_attr {
	u8 is_vf_mac : 1;
	u8 reserve : 7;
};

struct sxe2vf_mac {
	u8 macaddr[ETH_ALEN];
	struct sxe2vf_mac_attr attr;
};

enum sxe2vf_mac_owner {
	SXE2VF_MAC_OWNER_NETDEV = 0,
	SXE2VF_MAC_OWNER_UC_MC,
	SXE2VF_MAC_OWNER_ROCE,
};

struct sxe2vf_addr_node {
	struct list_head list;
	struct sxe2vf_mac mac;
	unsigned long usage;
};

struct sxe2vf_sync_addr_node {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
};

struct sxe2vf_vlan {
	u16 tpid;
	u16 vid;
	u8 prio;
};

struct sxe2vf_vlan_node {
	struct list_head list;
	struct sxe2vf_vlan vlan;
};

struct sxe2vf_vlan_offload {
	u8 stag_strip_enable;
	u8 ctag_strip_enable;
	u8 stag_insert_enable;
	u8 ctag_insert_enable;
};

struct sxe2vf_vlan_filter {
	u8 ctag_filter_enable;
	u8 stag_filter_enable;
};

struct sxe2vf_vlan_info {
	struct list_head vlan_list;
	/* in order to protect the data */
	struct mutex vlan_lock;
	u8 port_vlan_exist;
	u8 is_switchdev;
	u16 max_cnt;
	u16 cnt;
	struct sxe2vf_vlan_offload vlan_offload;
	struct sxe2vf_vlan_filter filter_offload;
	netdev_features_t dev_features;
};

s32 sxe2vf_addr_sync(struct net_device *netdev, const u8 *addr);

s32 sxe2vf_addr_unsync(struct net_device *netdev, const u8 *addr);

int sxe2vf_set_mac_address(struct net_device *netdev, void *p);

void sxe2vf_set_rx_mode(struct net_device *netdev);

s32 sxe2vf_l2_filter_cfg_sync(struct sxe2vf_adapter *adapter);

void sxe2vf_l2_filter_clear(struct sxe2vf_adapter *adapter);

bool sxe2vf_promisc_mode_changed(struct sxe2vf_adapter *adapter);

void sxe2vf_filter_list_destroy(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vlan_cfg(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vlan_cfg_rebuild(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vlan_offload_cfg(struct net_device *netdev,
			    netdev_features_t request);

s32 sxe2vf_vlan_filter_cfg(struct net_device *netdev,
			   netdev_features_t request);

int sxe2vf_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto, u16 vid);

int sxe2vf_vlan_rx_add_vid(struct net_device *netdev, __be16 proto, u16 vid);

bool sxe2vf_vlan_cnt_is_valid(struct sxe2vf_adapter *adapter);

void sxe2vf_vlan_feature_update(struct sxe2vf_adapter *adapter);

int sxe2vf_mac_addr_add(struct sxe2vf_adapter *adapter, const u8 *addr,
			enum sxe2vf_mac_owner owner);

int sxe2vf_mac_addr_del(struct sxe2vf_adapter *adapter, const u8 *addr,
			enum sxe2vf_mac_owner owner);

s32 sxe2vf_dev_mac_add(struct sxe2vf_adapter *adapter);

void sxe2vf_l2_filter_rules_restore(struct sxe2vf_adapter *adapter);

s32 sxe2vf_addr_node_del(struct sxe2vf_adapter *adapter, const u8 *macaddr);
struct sxe2vf_addr_node *sxe2vf_addr_find(struct sxe2vf_adapter *adapter,
					  const u8 *macaddr);

s32 sxe2vf_ucmd_unicast_mac_add(struct sxe2vf_adapter *adapter, u16 vsi_id, const u8 *addr);

s32 sxe2vf_ucmd_multi_broad_mac_add(struct sxe2vf_adapter *adapter, u16 vsi_id, const u8 *addr);

s32 sxe2vf_ucmd_unicast_mac_del(struct sxe2vf_adapter *adapter, u16 vsi_id, const u8 *addr);

s32 sxe2vf_ucmd_multi_broad_mac_del(struct sxe2vf_adapter *adapter, u16 vsi_id, const u8 *addr);

s32 sxe2vf_ucmd_promisc_rule_add(struct sxe2vf_adapter *adapter, u16 vsi_id);

s32 sxe2vf_ucmd_promisc_rule_del(struct sxe2vf_adapter *adapter, u16 vsi_id);

s32 sxe2vf_ucmd_allmulti_rule_add(struct sxe2vf_adapter *adapter, u16 vsi_id);

s32 sxe2vf_ucmd_allmulti_rule_del(struct sxe2vf_adapter *adapter, u16 vsi_id);
s32 sxe2vf_ucmd_vlan_filter_cfg(struct sxe2vf_adapter *adapter,
				u16 vsi_id, bool is_open);
s32 sxe2vf_ucmd_vlan_rule_process(struct sxe2vf_adapter *adapter,
				  u16 vsi_id, struct sxe2vf_vlan *vlan,
				  bool add);

s32 sxe2vf_user_l2_feature_clean(struct sxe2vf_adapter *adapter, u16 vsi_id);

#endif
