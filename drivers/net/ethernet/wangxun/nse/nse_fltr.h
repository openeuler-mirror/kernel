/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_FLTR_H_
#define _NSE_FLTR_H_

#include "nse_vlan.h"

void
nse_fltr_free_list(struct device *dev, struct list_head *h);

enum nse_status
nse_fltr_add_mac(struct nse_vsi *vsi, const u8 *mac,
		 enum nse_sw_fwd_act_type act_type);
enum nse_status
nse_fltr_add_bmc_mac(struct nse_vsi *vsi, const u8 *mac,
		 enum nse_sw_fwd_act_type act_type);
enum nse_status nse_fltr_add_roce_mac(struct nse_vsi *vsi, const u8 *mac,
				 struct nse_vsi *dst_vsi, enum nse_sw_fwd_act_type act_type);
enum nse_status
nse_fltr_add_mac_and_broadcast(struct nse_vsi *vsi, const u8 *mac,
			       enum nse_sw_fwd_act_type act_type);
enum nse_status nse_fltr_add_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan);
enum nse_status
nse_fltr_add_mac_vlan(struct nse_vsi *vsi, const u8 *mac, u16 vlan_id,
		      enum nse_sw_fwd_act_type act_type);
enum nse_status
nse_fltr_add_eth(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		 enum nse_sw_fwd_act_type act_type);
enum nse_status
nse_fltr_remove_mac(struct nse_vsi *vsi, const u8 *mac,
		    enum nse_sw_fwd_act_type act_type);
enum nse_status
nse_fltr_remove_bmc_mac(struct nse_vsi *vsi, const u8 *mac,
		    enum nse_sw_fwd_act_type act_type);
enum nse_status nse_fltr_remove_roce_mac(struct nse_vsi *vsi, const u8 *mac,
				 struct nse_vsi *dst_vsi, enum nse_sw_fwd_act_type act_type);
enum nse_status nse_fltr_remove_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan);

enum nse_status
nse_fltr_remove_mac_vlan(struct nse_vsi *vsi, const u8 *mac, u16 vlan_id,
			 enum nse_sw_fwd_act_type act_type);
enum nse_status
nse_fltr_remove_eth(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		    enum nse_sw_fwd_act_type act_type);
void nse_fltr_remove_all(struct nse_vsi *vsi);

enum nse_status
nse_fltr_set_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
			 u16 vid);
enum nse_status
nse_fltr_set_vlan_vsi_promisc(struct nse_hw *hw, struct nse_vsi *vsi,
			      u8 promisc_mask);
enum nse_status
nse_fltr_clear_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
			   u16 vid);
enum nse_status
nse_fltr_clear_vlan_vsi_promisc(struct nse_hw *hw, struct nse_vsi *vsi,
				u8 promisc_mask);

enum nse_status
nse_fltr_add_mac_to_list(struct nse_vsi *vsi, struct list_head *list,
			 const u8 *mac, enum nse_sw_fwd_act_type act_type);

enum nse_status
nse_fltr_add_mac_list(struct nse_vsi *vsi,
			 struct list_head *list);

enum nse_status
nse_fltr_remove_mac_list(struct nse_vsi *vsi,
			 struct list_head *list);

void
nse_fltr_set_bmc_mac_event(struct nse_hw *hw,
			struct nse_rq_event_info *event);

#endif
