// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_fltr.h"
#include "mce_lib.h"

static struct mce_mac_hnode *mce_find_mac_hnode(struct mce_hw *hw,
						struct hlist_head *hash_tb,
						u16 idx, const u8 *addr)
{
	struct mce_mac_hnode *entry;

	hlist_for_each_entry(entry, &hash_tb[idx], node)
		if (ether_addr_equal(addr, entry->mac_addr))
			return entry;
	return NULL;
}

static struct mce_mac_hnode *mce_add_mac_hnode(struct mce_hw *hw,
					       struct hlist_head *hash_tb,
					       u16 idx, const u8 *addr)
{
	struct mce_mac_hnode *mac_hnode;

	mac_hnode = mce_find_mac_hnode(hw, hash_tb, idx, addr);
	if (mac_hnode)
		return mac_hnode;

	mac_hnode = kmalloc(sizeof(*mac_hnode), GFP_ATOMIC);
	if (!mac_hnode)
		return NULL;

	ether_addr_copy(mac_hnode->mac_addr, addr);
	INIT_HLIST_NODE(&mac_hnode->node);
	hlist_add_head(&mac_hnode->node, &hash_tb[idx]);

	return mac_hnode;
}

static bool mce_del_mac_hnode(struct mce_hw *hw,
			      struct hlist_head *hash_tb, u16 idx,
			      const u8 *addr)
{
	struct mce_mac_hnode *entry;
	struct hlist_node *tmp;

	hlist_for_each_entry_safe(entry, tmp, &hash_tb[idx], node) {
		if (ether_addr_equal(addr, entry->mac_addr)) {
			hlist_del(&entry->node);
			kfree(entry);
			return true;
		}
	}
	return false;
}

int mce_update_mac_list(struct mce_hw *hw, enum mce_mac_node_state state,
			enum mce_mac_addr_type mac_type, const u8 *addr)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct hlist_head *hash_tb;
	u16 hash_v;
	bool s_low;

	if (mac_type == MCE_MAC_ADDR_UC) {
		hash_tb = hw->uc_hash_tb;
		s_low = hw->uc_mc_hash_ctl.uc_s_low;
	} else {
		hash_tb = hw->mc_hash_tb;
		s_low = hw->uc_mc_hash_ctl.mc_s_low;
	}

	spin_lock_bh(&hw->mac_hash_lock);
	hash_v = mce_calc_mac_hash_val(hw, addr, s_low);
	if (state == MCE_MAC_TO_ADD)
		mce_add_mac_hnode(hw, hash_tb, hash_v, addr);
	else
		mce_del_mac_hnode(hw, hash_tb, hash_v, addr);
	/* each bit of uc_hash_bm indicates that this bucket of hash has changed */
	if (mac_type == MCE_MAC_ADDR_UC) {
		set_bit(hash_v, hw->uc_hash_bm);
		set_bit(MCE_FLAG_PF_UC_HASH_SYNC_ENA, pf->flags);
	} else {
		set_bit(hash_v, hw->mc_hash_bm);
		set_bit(MCE_FLAG_PF_MC_HASH_SYNC_ENA, pf->flags);
	}
	spin_unlock_bh(&hw->mac_hash_lock);

	dev_dbg(hw->dev,
		"%s %s hash_v:0x%04x addr:%02x:%02x:%02x:%02x:%02x:%02x\n",
		(state == MCE_MAC_TO_ADD) ? "add" : "del",
		(mac_type == MCE_MAC_ADDR_UC) ? "uc" : "mc", hash_v, addr[0],
		addr[1], addr[2], addr[3], addr[4], addr[5]);

	return 0;
}

int mce_sync_mac_uc_hash_list(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	unsigned int hash_v;

	if (!test_bit(MCE_FLAG_PF_UC_HASH_SYNC_ENA, pf->flags))
		return 0;
	clear_bit(MCE_FLAG_PF_UC_HASH_SYNC_ENA, pf->flags);

	spin_lock_bh(&hw->mac_hash_lock);

	for_each_set_bit(hash_v, hw->uc_hash_bm, MCE_FILTER_HASH_TB_SIZE) {
		clear_bit(hash_v, hw->uc_hash_bm);
		if (hlist_empty(&hw->uc_hash_tb[hash_v]))
			hw->ops->del_uc_filter(hw, hash_v);
		else
			hw->ops->add_uc_filter(hw, hash_v);
	}

	spin_unlock_bh(&hw->mac_hash_lock);

	return 0;
}

int mce_sync_mac_mc_hash_list(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	unsigned int hash_v;

	if (!test_bit(MCE_FLAG_PF_MC_HASH_SYNC_ENA, pf->flags))
		return 0;
	clear_bit(MCE_FLAG_PF_MC_HASH_SYNC_ENA, pf->flags);

	spin_lock_bh(&hw->mac_hash_lock);

	for_each_set_bit(hash_v, hw->mc_hash_bm, MCE_FILTER_HASH_TB_SIZE) {
		clear_bit(hash_v, hw->mc_hash_bm);
		if (hlist_empty(&hw->mc_hash_tb[hash_v]))
			hw->ops->del_mc_filter(hw, hash_v);
		else
			hw->ops->add_mc_filter(hw, hash_v);
	}

	spin_unlock_bh(&hw->mac_hash_lock);

	return 0;
}

void mce_clear_mac_hash_list(struct mce_hw *hw,
			     enum mce_mac_addr_type mac_type)
{
	struct mce_mac_hnode *entry;
	struct hlist_head *hash_tb;
	struct hlist_node *tmp;
	int i;

	hash_tb = (mac_type == MCE_MAC_ADDR_UC) ? hw->uc_hash_tb :
						  hw->mc_hash_tb;

	spin_lock_bh(&hw->mac_hash_lock);

	for (i = 0; i < MCE_FILTER_HASH_TB_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp, &hash_tb[i], node) {
			hlist_del(&entry->node);
			kfree(entry);
		}
	}

	spin_unlock_bh(&hw->mac_hash_lock);
}

/**
 * mce_add_uc_filter - Add an address for unicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 * Returns: The result of the operation.
 */
int mce_add_uc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;

	mce_update_mac_list(hw, MCE_MAC_TO_ADD, MCE_MAC_ADDR_UC, addr);
	return 0;
}

/**
 * mce_del_uc_filter - Del an address for unicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 * Returns: The result of the operation.
 */
int mce_del_uc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;

	mce_update_mac_list(hw, MCE_MAC_TO_DEL, MCE_MAC_ADDR_UC, addr);
	return 0;
}

/**
 * mce_add_mc_filter - Add an address for multicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 * Returns: The result of the operation.
 */
int mce_add_mc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		hw->vf.ops->set_vf_add_mc_fliter(hw, addr);
	else
		mce_update_mac_list(hw, MCE_MAC_TO_ADD, MCE_MAC_ADDR_MC,
				    addr);
	return 0;
}

/**
 * mce_del_mc_filter - Del an address for multicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 * Returns: The result of the operation.
 */
int mce_del_mc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		hw->vf.ops->set_vf_del_mc_filter(hw, addr);
	else
		mce_update_mac_list(hw, MCE_MAC_TO_DEL, MCE_MAC_ADDR_MC,
				    addr);
	return 0;
}
