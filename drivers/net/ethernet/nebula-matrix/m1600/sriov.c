// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/netdevice.h>

#include "common.h"
#include "mailbox.h"
#include "sriov.h"

#ifdef CONFIG_PCI_IOV
void nbl_af_enter_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	u8 forward_ring_index = af_res->forward_ring_index;
	struct nbl_ingress_eth_port_fwd port_fwd_config;
	struct nbl_src_vsi_port src_vsi_port_config;

	rd32_for_each(hw, NBL_PRO_INGRESS_ETH_PORT_FWD_REG_ARR(eth_port_id),
		      (u32 *)&port_fwd_config, sizeof(port_fwd_config));
	port_fwd_config.forward_queue_id_en = 1;
	port_fwd_config.forward_queue_id = forward_ring_index;
	wr32_for_each(hw, NBL_PRO_INGRESS_ETH_PORT_FWD_REG_ARR(eth_port_id),
		      (u32 *)&port_fwd_config, sizeof(port_fwd_config));

	rd32_for_each(hw, NBL_PRO_SRC_VSI_PORT_REG_ARR(vsi_id),
		      (u32 *)&src_vsi_port_config, sizeof(src_vsi_port_config));
	src_vsi_port_config.mac_lut_en = 1;
	src_vsi_port_config.forward_queue_id_en = 1;
	src_vsi_port_config.forward_queue_id = forward_ring_index;
	wr32_for_each(hw, NBL_PRO_SRC_VSI_PORT_REG_ARR(vsi_id),
		      (u32 *)&src_vsi_port_config, sizeof(src_vsi_port_config));
}

void nbl_af_leave_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_ingress_eth_port_fwd port_fwd_config;
	struct nbl_src_vsi_port src_vsi_port_config;

	rd32_for_each(hw, NBL_PRO_INGRESS_ETH_PORT_FWD_REG_ARR(eth_port_id),
		      (u32 *)&port_fwd_config, sizeof(port_fwd_config));
	port_fwd_config.forward_queue_id_en = 0;
	port_fwd_config.forward_queue_id = 0;
	wr32_for_each(hw, NBL_PRO_INGRESS_ETH_PORT_FWD_REG_ARR(eth_port_id),
		      (u32 *)&port_fwd_config, sizeof(port_fwd_config));

	rd32_for_each(hw, NBL_PRO_SRC_VSI_PORT_REG_ARR(vsi_id),
		      (u32 *)&src_vsi_port_config, sizeof(src_vsi_port_config));
	src_vsi_port_config.mac_lut_en = 0;
	src_vsi_port_config.forward_queue_id_en = 0;
	src_vsi_port_config.forward_queue_id = 0;
	wr32_for_each(hw, NBL_PRO_SRC_VSI_PORT_REG_ARR(vsi_id),
		      (u32 *)&src_vsi_port_config, sizeof(src_vsi_port_config));
}

static void nbl_enter_forward_ring_mode(struct nbl_hw *hw)
{
	u8 eth_port_id;
	u8 vsi_id;

	eth_port_id = hw->eth_port_id;
	vsi_id = hw->vsi_id;
	if (is_af(hw))
		nbl_af_enter_forward_ring_mode(hw, eth_port_id, vsi_id);
	else
		nbl_mailbox_req_enter_forward_ring_mode(hw, eth_port_id, vsi_id);
}

static void nbl_leave_forward_ring_mode(struct nbl_hw *hw)
{
	u8 eth_port_id;
	u8 vsi_id;

	eth_port_id = hw->eth_port_id;
	vsi_id = hw->vsi_id;
	if (is_af(hw))
		nbl_af_leave_forward_ring_mode(hw, eth_port_id, vsi_id);
	else
		nbl_mailbox_req_leave_forward_ring_mode(hw, eth_port_id, vsi_id);
}
#endif

static int nbl_sriov_disable(struct pci_dev *pdev)
{
#ifdef CONFIG_PCI_IOV
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	if (pci_vfs_assigned(pdev)) {
		pr_warn("Unloading driver while VFs are assigned\n");
		return -EPERM;
	}

	nbl_leave_forward_ring_mode(hw);

	pci_disable_sriov(pdev);
#endif
	return 0;
}

static int nbl_sriov_enable(struct pci_dev *pdev, int num_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	int existing_vfs = pci_num_vf(pdev);
	int err;

	if (existing_vfs) {
		pr_err("VFs is created already\n");
		return -EINVAL;
	}

	nbl_enter_forward_ring_mode(hw);

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		pr_warn("Failed to enable SR-IOV with error %d\n", err);
		return err;
	}

	return num_vfs;
#else
	return 0;
#endif
}

int nbl_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return nbl_sriov_disable(pdev);
	else
		return nbl_sriov_enable(pdev, num_vfs);
}
