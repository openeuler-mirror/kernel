/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_FLTR_H_
#define _MCE_FLTR_H_

int mce_add_uc_filter(struct net_device *netdev, const u8 *addr);
int mce_del_uc_filter(struct net_device *netdev, const u8 *addr);
int mce_add_mc_filter(struct net_device *netdev, const u8 *addr);
int mce_del_mc_filter(struct net_device *netdev, const u8 *addr);
int mce_update_mac_list(struct mce_hw *hw, enum mce_mac_node_state state,
			enum mce_mac_addr_type mac_type, const u8 *addr);
int mce_sync_mac_uc_hash_list(struct mce_hw *hw);
int mce_sync_mac_mc_hash_list(struct mce_hw *hw);
void mce_clear_mac_hash_list(struct mce_hw *hw,
			     enum mce_mac_addr_type mac_type);

#endif /* _MCE_FLTR_H_ */
