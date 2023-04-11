/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_MACVLAN_H_
#define _NBL_MACVLAN_H_

#define NBL_MACVLAN_TRY_GET_STATUS_TIMES 10

int nbl_macvlan_add(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id,
		    u8 vsi_id, int index);

int nbl_macvlan_delete(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id);

int nbl_af_configure_mac_addr(struct nbl_hw *hw, u16 func_id, u8 eth_port_id,
			      u8 *mac_addr, u8 vsi_id);
int nbl_configure_mac_addr(struct nbl_hw *hw, u8 *mac_addr);

int nbl_af_clear_mac_addr(struct nbl_hw *hw, u16 func_id);
int nbl_clear_mac_addr(struct nbl_hw *hw);

int nbl_af_change_mac_addr(struct nbl_hw *hw, u16 func_id, u8 *mac_addr, u8 vsi_id);
int nbl_change_mac_addr(struct nbl_hw *hw, u8 *mac_addr);

int nbl_af_operate_vlan_id(struct nbl_hw *hw, u16 func_id, u16 vlan_id,
			   u8 vsi_id, bool add);
int nbl_add_vlan_id(struct nbl_hw *hw, u16 vlan_id);
int nbl_delete_vlan_id(struct nbl_hw *hw, u16 vlan_id);

#endif
