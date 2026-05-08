/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_eswitch.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_ESWITCH_H__
#define __SXE2_ESWITCH_H__

#include <linux/devlink.h>

#include "sxe2_vsi.h"

#define SXE2_ESWITCH_QUEUE_CNT	   1
#define SXE2_ESWITCH_MODE_CHANGING 1
#define SXE2_ESWITCH_MODE_TIMEOUT  2000

enum sxe2_eswtich_mode {
	SXE2_EWSITCH_MODE_LEGACY,
	SXE2_ESWITCH_MODE_OFFLOAD,
};

struct sxe2_eswitch_context {
	struct sxe2_adapter *adapter;
	struct sxe2_vsi *uplink_vsi;
	struct sxe2_vsi *esw_vsi;
	struct sxe2_vsi *user_esw_vsi;
	enum devlink_eswitch_mode mode;
	atomic64_t mode_ref_cnt;
	unsigned long flag;
};

struct sxe2_vf_repr {
	struct sxe2_vsi *src_vsi;
	struct sxe2_vsi *dpdk_vf_vsi;
	struct sxe2_vf_node *vf_node;
	struct sxe2_irq_data *irq_data;
	struct net_device *netdev;
	struct metadata_dst *dst;
	u16 vf_idx;
	u8 rule_added;
};

struct sxe2_vf_repr_cfg {
	u16 queue_in_dev;
	u16 queue_in_dev_u;
	bool cfg_to_user;
};

s32 sxe2_eswitch_configure(struct sxe2_adapter *adapter, bool enable);

irqreturn_t sxe2_eswitch_msix_ring_irq_handler(int __always_unused irq,
					       void *data);

bool sxe2_is_repr_netdev(struct net_device *netdev);

void sxe2_eswitch_txqs_stop(struct sxe2_adapter *adapter);

bool sxe2_eswitch_is_offload(struct sxe2_adapter *adapter);

void sxe2_vf_repr_rebuild(struct sxe2_vsi *vsi, bool is_vfr_vflr);

void sxe2_eswitch_stop(struct sxe2_adapter *adapter);

s32 sxe2_eswitch_rebuild(struct sxe2_adapter *adapter);

s32 sxe2_vf_sp_rule_add(struct sxe2_vf_node *vf_node, bool is_user);

s32 sxe2_vf_sp_rule_del(struct sxe2_vf_node *vf_node, bool is_user);

void sxe2_vf_repr_decfg(struct sxe2_vf_node *vf_node);

void sxe2_vfs_repr_decfg(struct sxe2_adapter *adapter);

void sxe2_eswitch_mode_rwlock_init(struct sxe2_adapter *adapter);

s32 sxe2_eswitch_mode_write_try_lock(struct sxe2_adapter *adapter);

void sxe2_eswitch_mode_write_unlock(struct sxe2_adapter *adapter);

s32 sxe2_eswitch_mode_read_lock(struct sxe2_adapter *adapter);

void sxe2_eswitch_mode_read_unlock(struct sxe2_adapter *adapter);

s32 sxe2_eswitch_ucmd_uplink_set(struct sxe2_adapter *adapter, bool to_user);

s32 sxe2_eswitch_ucmd_uplink_resetto_ker(struct sxe2_adapter *adapter);

s32 sxe2_eswitch_ucmd_mode_get(struct sxe2_adapter *adapter, bool *is_switchdev);

s32 sxe2_eswitch_ucmd_eswvsi_get(struct sxe2_adapter *adapter, u16 *user_esw_vsi_id);
s32 sxe2_eswitch_ucmd_repr_cfg(struct sxe2_vf_node *vf_node, bool is_to_user);
#endif
