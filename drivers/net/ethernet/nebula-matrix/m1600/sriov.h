/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_SRIOV_H_
#define _NBL_SRIOV_H_

#ifdef CONFIG_PCI_IOV
void nbl_af_enter_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
void nbl_af_leave_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
#endif

int nbl_sriov_configure(struct pci_dev *pdev, int num_vfs);

#endif
