/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_LEGACY_SWITCH_H_
#define _NSE_LEGACY_SWITCH_H_

#define NSE_FLTR_STATE_MODIFIED        0x1
#define NSE_FLTR_STATE_IN_USE          0x2

struct nse_legacy_sw_fltr_info {
	union {
		struct {
			u8 mac_addr[ETH_ALEN];
		};
		struct {
			u16 vlan_id;
		};
		struct {
			u16 ethtype;
		};
	};
};

struct nse_legacy_sw_fltr_list_entry {
	struct list_head list_entry;
	struct nse_legacy_sw_fltr_info fltr_info;
};

enum nse_status
nse_legacy_sw_add_mac(struct nse_hw *hw, const u8 *mac, u16 vsi_handle);

enum nse_status
nse_legacy_sw_remove_mac(struct nse_hw *hw, const u8 *mac, u16 vsi_handle);

enum nse_status
nse_legacy_sw_add_vlan(struct nse_hw *hw, u16 vid, u16 vsi_handle);

enum nse_status
nse_legacy_sw_remove_vlan(struct nse_hw *hw, u16 vid, u16 vsi_handle);

enum nse_status
nse_legacy_sw_add_ethtype(struct nse_hw *hw, u16 ethtype, u16 vsi_handle);

enum nse_status
nse_legacy_sw_remove_ethtype(struct nse_hw *hw, u16 ethtype, u16 vsi_handle);

void nse_legacy_sw_remove_vsi_fltr(struct nse_hw *hw, u16 vsi_handle);

enum nse_status
nse_replay_vsi_all_fltr_legacy(struct nse_hw *hw, u16 vsi_handle);

void nse_drain_sw_replay_list_legacy(struct nse_hw *hw);

void nse_replace_sw_replay_list_legacy(struct nse_hw *hw);

#endif /* _NSE_SWITCH_H_ */

