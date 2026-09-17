// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_fltr.h"

/**
 * mcevf_add_uc_filter - Add an address for unicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mcevf_add_uc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;
	struct mcevf_pf *pf = hw->back;

	if (test_bit(MCEVF_FLAG_SPOOF_ON, pf->flags))
		dev_err(hw->dev, "mac vlan cannot used until pf set spoof off for you\n");

	if (hw->ops->add_uc_filter(hw, addr)) {
		dev_err(hw->dev, "hw add uc addr %02x:%02x:%02x:%02x:%02x:%02x error\n",
			(u32)addr[0], (u32)addr[1], (u32)addr[2], (u32)addr[3],
				(u32)addr[4], (u32)addr[5]);
		dev_err(hw->dev, "it can not used\n");

	} else {
		dev_dbg(hw->dev, "hw add uc addr %02x:%02x:%02x:%02x:%02x:%02x\n",
			(u32)addr[0], (u32)addr[1], (u32)addr[2], (u32)addr[3],
				(u32)addr[4], (u32)addr[5]);
	}
	return 0;
}

/**
 * mcevf_del_uc_filter - Del an address for unicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mcevf_del_uc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;

	hw->ops->del_uc_filter(hw, addr);
	return 0;
}

/**
 * mcevf_add_mc_filter - Add an address for multicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mcevf_add_mc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;

	hw->ops->add_mc_filter(hw, addr);

	return 0;
}

/**
 * mcevf_del_mc_filter - Del an address for multicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mcevf_del_mc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;

	hw->ops->del_mc_filter(hw, addr);
	return 0;
}
