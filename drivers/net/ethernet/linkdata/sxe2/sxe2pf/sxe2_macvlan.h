/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_macvlan.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_MACVLAN_H__
#define __SXE2_MACVLAN_H__

#define SXE2_DFLT_TXQ_VMDQ_VSI (1)
#define SXE2_DFLT_RXQ_VMDQ_VSI (1)
#define SXE2_DFLT_VEC_VMDQ_VSI (1)
#define SXE2_MAX_NUM_VMDQ_VSI (16)
#define SXE2_MAX_TXQ_VMDQ_VSI (4)
#define SXE2_MAX_RXQ_VMDQ_VSI (4)

struct sxe2_adapter;
struct sxe2_vsi;

struct sxe2_macvlan {
	struct list_head list;
	s32 id;
	struct net_device *vdev;
	struct sxe2_vsi *parent_vsi;
	struct sxe2_vsi *vsi;
	u8 mac[ETH_ALEN];
};

struct sxe2_macvlan_context {
	DECLARE_BITMAP(avail_macvlan, SXE2_MAX_MACVLANS);
	struct list_head macvlan_list;
	u16 num_macvlan;
	u16 max_num_macvlan;
};

s32 sxe2_vsi_cfg_netdev_tc0(struct sxe2_vsi *vsi);

bool sxe2_macvlan_is_enabled(struct sxe2_adapter *adapter);

s32 sxe2_macvlan_init(struct sxe2_vsi *vsi, bool init);

s32 sxe2_macvlan_deinit(struct sxe2_vsi *vsi, bool locked);

s32 sxe2_macvlan_rebuild(struct sxe2_adapter *adapter);

void sxe2_fwd_del_macvlan(struct net_device *netdev, void *accel_priv);

void *sxe2_fwd_add_macvlan(struct net_device *netdev, struct net_device *vdev);

void sxe2_fwd_del_macvlan_deay(struct sxe2_adapter *adapter);

#ifdef SXE2_MACVLAN_STATS
struct sxe2_macvlan *sxe2_get_macvlan(int id, struct sxe2_adapter *adapter);
#endif
#endif
