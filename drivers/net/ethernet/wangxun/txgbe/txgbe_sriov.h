/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_SRIOV_H_
#define _TXGBE_SRIOV_H_

/* txgbe driver limit the max number of VFs could be enabled to
 * 63 (TXGBE_MAX_VF_FUNCTIONS - 1)
 */
#define TXGBE_MAX_VFS_DRV_LIMIT  (TXGBE_MAX_VF_FUNCTIONS - 1)

#define TXGBE_VF_LINK_STATE_DISABLE 0
#define TXGBE_VF_LINK_STATE_AUTO 1
#define TXGBE_VF_LINK_STATE_ENABLE 2

void txgbe_restore_vf_multicasts(struct txgbe_adapter *adapter);
void txgbe_msg_task(struct txgbe_adapter *adapter);
void txgbe_ping_all_vfs_with_link_status(struct txgbe_adapter *adapter, bool link_up);
void txgbe_set_all_vfs(struct txgbe_adapter *adapter);

int txgbe_ndo_set_vf_mac(struct net_device *netdev, int queue, u8 *mac);
int txgbe_ndo_set_vf_vlan(struct net_device *netdev, int queue, u16 vlan,
			  u8 qos, __be16 vlan_proto);

int txgbe_ndo_set_vf_bw(struct net_device *netdev,
			int vf,
			int min_tx_rate,
			int max_tx_rate);

int txgbe_ndo_set_vf_spoofchk(struct net_device *netdev, int vf, bool setting);
int txgbe_ndo_set_vf_link_state(struct net_device *netdev, int vf, int state);
int txgbe_ndo_set_vf_trust(struct net_device *netdev, int vf, bool setting);

int txgbe_ndo_get_vf_config(struct net_device *netdev,
			    int vf, struct ifla_vf_info *ivi);

int txgbe_disable_sriov(struct txgbe_adapter *adapter);
#ifdef CONFIG_PCI_IOV
int txgbe_vf_configuration(struct pci_dev *pdev, unsigned int event_mask);
void txgbe_enable_sriov(struct txgbe_adapter *adapter);
#endif
int txgbe_pci_sriov_configure(struct pci_dev *dev, int num_vfs);
void txgbe_check_vf_rate_limit(struct txgbe_adapter *adapter);
#endif /* _TXGBE_SRIOV_H_ */

