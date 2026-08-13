/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_SRIOV_H_
#define _MCE_SRIOV_H_
#include "mce_netdev.h"
#include "mce.h"
#include "mce_vf_lib.h"

#ifdef CONFIG_PCI_IOV
int mce_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac);
int mce_get_vf_cfg(struct net_device *netdev, int vf_id,
		   struct ifla_vf_info *ivi);
int mce_set_vf_port_vlan(struct net_device *netdev, int vf_id,
			 u16 vlan_id, u8 qos, __be16 vlan_proto);
int mce_set_vf_bw(struct net_device *netdev, int vf_id, int tx_rate);

int mce_reset_vf(struct net_device *netdev);
int mce_set_vf_dscp_prio(struct net_device *netdev, u8 dscp, u8 prio);
int mce_set_vf_dscp(struct net_device *netdev, bool ena);
int mce_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena);
int mce_sriov_init_hw(struct mce_pf *pf);
int mce_sriov_deinit_hw(struct mce_pf *pf);
int mce_sriov_configure(struct pci_dev *dev, int num_vfs);
int mce_disable_sriov(struct mce_pf *pf);
#else
static inline int mce_reset_vf(struct net_device *netdev)
{
	return 0;
}

static inline int mce_set_vf_dscp_prio(struct net_device *netdev, u8 dscp,
				       u8 prio)
{
	return 0;
}

static inline int mce_set_vf_dscp(struct net_device *netdev, bool ena)
{
	return 0;
}

static inline int
mce_set_vf_mac(struct net_device __always_unused *netdev,
	       int __always_unused vf_id, u8 __always_unused *mac)
{
	return -EOPNOTSUPP;
}

static inline int
mce_get_vf_cfg(struct net_device __always_unused *netdev,
	       int __always_unused vf_id,
		 struct ifla_vf_info __always_unused *ivi)
{
	return -EOPNOTSUPP;
}

static inline int
mce_set_vf_port_vlan(struct net_device __always_unused *netdev,
		     int __always_unused vf_id, u16 __always_unused vid,
		       u8 __always_unused qos,
		       __be16 __always_unused v_proto)
{
	return -EOPNOTSUPP;
}

static inline int mce_set_vf_bw(struct net_device __always_unused *netdev,
				int __always_unused vf_id,
				int __always_unused max_tx_rate)
{
	return -EOPNOTSUPP;
}

static inline int
mce_set_vf_spoofchk(struct net_device __always_unused *netdev,
		    int __always_unused vf_id, bool __always_unused ena)
{
	return -EOPNOTSUPP;
}

static inline int mce_sriov_init_hw(struct mce_pf *pf)
{
	return 0;
}

static inline int mce_sriov_deinit_hw(struct mce_pf *pf)
{
	return 0;
}

static inline int mce_set_vf_link_state(struct net_device *netdev, int vf_id,
					int state)
{
	return 0;
}

static inline int mce_sriov_configure(struct pci_dev *dev, int num_vfs)
{
	return 0;
}

static inline int mce_disable_sriov(struct mce_pf *pf)
{
	return 0;
}
#endif

#endif /* _MCE_SRIOV_H_ */
