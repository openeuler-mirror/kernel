/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_tc.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_TC_H__
#define __SXE2_TC_H__

#include <linux/types.h>
#include "sxe2_eswitch.h"

enum sxe2_tunnel_type sxe2_tc_tun_type_get(struct net_device *tunnel_dev);

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
s32 sxe2_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv);

s32 sxe2_indr_setup_block_cb(enum tc_setup_type type, void *type_data, void *indr_priv);

s32 sxe2_repr_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv);
#endif

s32 sxe2_setup_tc_cls_flower(struct sxe2_netdev_priv *np,
			     struct net_device *filter_dev,
			     struct flow_cls_offload *cls_flower);

s32 sxe2_repr_setup_tc_cls_flower(struct sxe2_vf_repr *repr,
				  struct flow_cls_offload *cls_flower);

s32 sxe2_eswitch_vf_slow_path_rule_setup(struct sxe2_vf_node *vf_node,
					 bool is_user, bool is_add);

s32 sxe2_bond_single_rule_setup(struct sxe2_adapter *adapter, bool is_add);

s32 sxe2_rdma_dump_pcap_setup(struct sxe2_vsi *vsi, u8 *mac, bool is_add);

s32 sxe2_tcf_word_cnt_calc(struct sxe2_tcf_fltr *fltr);

s32 sxe2_eswitch_vf_slow_path_rule_update(struct sxe2_adapter *adapter,
					  u16 vsi_id, struct sxe2_vf_repr_cfg *repr_cfg);

#endif
