/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_SRIOV_H_
#define _NSE_SRIOV_H_
#include "nse_vf_lib.h"
#include "nse_virtchnl.h"

/* Static VF transaction/status register def */
#define VF_DEVICE_STATUS		0xAA
#define VF_TRANS_PENDING_M		0x20

/* wait defines for polling PF_PCI_CIAD register status */
#define NSE_PCI_CIAD_WAIT_COUNT		100
#define NSE_PCI_CIAD_WAIT_DELAY_US	1

#define NSE_MIN_QS_PER_VF		1
#define NSE_NONQ_VECS_VF		1

#define NSE_NUM_VF_MSIX_MAX		64
#define NSE_NUM_VF_MSIX_LARGE		33
#define NSE_NUM_VF_MSIX_MED		17
#define NSE_NUM_VF_MSIX_MED_SMALL	9
#define NSE_NUM_VF_MSIX_SMALL		5
#define NSE_NUM_VF_MSIX_MULTIQ_MIN	3
#define NSE_MIN_INTR_PER_VF		(NSE_MIN_QS_PER_VF + 1)

#define NSE_MAX_VF_RESET_TRIES		40
#define NSE_MAX_VF_RESET_SLEEP_MS	20
#define NSE_MAX_VF_PORT			NSE_MAX_PORT_PER_PCI_DEV

#ifdef CONFIG_PCI_IOV
int
nse_get_vf_port_info(struct nse_pf *pf, u16 vf_id,
		     struct iidc_vf_port_info *vf_port_info);
void nse_dump_all_vfs(struct nse_pf *pf);
void nse_process_vflr_event(struct nse_pf *pf, struct nse_rq_event_info *event);
void nse_process_vflr_event_mini(struct nse_pf *pf, struct nse_rq_event_info *event);
int nse_sriov_configure(struct pci_dev *pdev, int num_vfs);
int nse_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac);
int
nse_get_vf_cfg(struct net_device *netdev, int vf_id, struct ifla_vf_info *ivi);
void nse_free_vfs(struct nse_pf *pf);
void nse_vc_process_vf_msg(struct nse_pf *pf, struct nse_rq_event_info *event);

/* VF configuration related iplink handlers */
void nse_restore_all_vfs_msi_state(struct pci_dev *pdev);
bool
nse_is_malicious_vf(struct nse_pf *pf, struct nse_rq_event_info *event,
		    u16 num_msg_proc, u16 num_msg_pending);

#ifdef IFLA_VF_VLAN_INFO_MAX
int
nse_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos,
		     __be16 vlan_proto);
#else
int
nse_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos);
#endif

int
nse_set_vf_bw(struct net_device *netdev, int vf_id, int min_tx_rate,
	      int max_tx_rate);

int nse_set_vf_trust(struct net_device *netdev, int vf_id, bool trusted);

int nse_set_vf_link_state(struct net_device *netdev, int vf_id, int link_state);

int nse_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena);

int nse_calc_vf_reg_idx(struct nse_vf *vf, struct nse_q_vector *q_vector,
			u8 tc);

int
nse_get_vf_stats(struct net_device *netdev, int vf_id,
		 struct ifla_vf_stats *vf_stats);
void
nse_vf_lan_overflow_event(struct nse_pf *pf, struct nse_rq_event_info *event);
void nse_print_vfs_mdd_events(struct nse_pf *pf);
void nse_print_vf_rx_mdd_event(struct nse_vf *vf);
bool nse_vc_isvalid_vsi_abs_id(struct nse_vf *vf, u16 vsi_abs_id);
bool nse_vc_isvalid_vsi_rel_id(struct nse_vf *vf, u16 vsi_rel_id);
#else /* CONFIG_PCI_IOV */
static inline void nse_dump_all_vfs(struct nse_pf *pf) { }
static inline void nse_process_vflr_event(struct nse_pf *pf, struct nse_rq_event_info *event) { }
static inline void nse_process_vflr_event_mini(struct nse_pf *pf,
					       struct nse_rq_event_info *event) { }
static inline void nse_free_vfs(struct nse_pf *pf) { }
static inline void
nse_vc_process_vf_msg(struct nse_pf *pf, struct nse_rq_event_info *event) { }
static inline void
nse_vf_lan_overflow_event(struct nse_pf *pf,
			  struct nse_rq_event_info *event) { }
static inline void nse_print_vfs_mdd_events(struct nse_pf *pf) { }
static inline void nse_print_vf_rx_mdd_event(struct nse_vf *vf) { }
static inline void nse_restore_all_vfs_msi_state(struct pci_dev *pdev) { }
static inline int
nse_get_vf_port_info(struct nse_pf __always_unused *pf,
		     u16 __always_unused vf_id,
		     struct iidc_vf_port_info __always_unused *vf_port_info)
{
	return -EOPNOTSUPP;
}

static inline bool
nse_is_malicious_vf(struct nse_pf __always_unused *pf,
		    struct nse_rq_event_info __always_unused *event,
		    u16 __always_unused num_msg_proc,
		    u16 __always_unused num_msg_pending)
{
	return false;
}

static inline int
nse_sriov_configure(struct pci_dev __always_unused *pdev,
		    int __always_unused num_vfs)
{
	return -EOPNOTSUPP;
}

static inline int
nse_set_vf_mac(struct net_device __always_unused *netdev,
	       int __always_unused vf_id, u8 __always_unused *mac)
{
	return -EOPNOTSUPP;
}

static inline int
nse_get_vf_cfg(struct net_device __always_unused *netdev,
	       int __always_unused vf_id,
	       struct ifla_vf_info __always_unused *ivi)
{
	return -EOPNOTSUPP;
}

static inline int
nse_set_vf_trust(struct net_device __always_unused *netdev,
		 int __always_unused vf_id, bool __always_unused trusted)
{
	return -EOPNOTSUPP;
}

#ifdef IFLA_VF_VLAN_INFO_MAX
static inline int
nse_set_vf_port_vlan(struct net_device __always_unused *netdev,
		     int __always_unused vf_id, u16 __always_unused vid,
		     u8 __always_unused qos, __be16 __always_unused v_proto)
{
	return -EOPNOTSUPP;
}
#else
static inline int
nse_set_vf_port_vlan(struct net_device __always_unused *netdev,
		     int __always_unused vf_id, u16 __always_unused vid,
		     u8 __always_unused qos)
{
	return -EOPNOTSUPP;
}
#endif /* IFLA_VF_VLAN_INFO_MAX */

static inline int
nse_set_vf_spoofchk(struct net_device __always_unused *netdev,
		    int __always_unused vf_id, bool __always_unused ena)
{
	return -EOPNOTSUPP;
}

static inline int
nse_set_vf_link_state(struct net_device __always_unused *netdev,
		      int __always_unused vf_id, int __always_unused link_state)
{
	return -EOPNOTSUPP;
}

static inline int
nse_set_vf_bw(struct net_device __always_unused *netdev,
	      int __always_unused vf_id, int __always_unused min_tx_rate,
	      int __always_unused max_tx_rate)
{
	return -EOPNOTSUPP;
}

static inline int
nse_calc_vf_reg_idx(struct nse_vf __always_unused *vf,
		    struct nse_q_vector __always_unused *q_vector,
		    u8 __always_unused tc)
{
	return 0;
}

static inline int
nse_get_vf_stats(struct net_device __always_unused *netdev,
		 int __always_unused vf_id,
		 struct ifla_vf_stats __always_unused *vf_stats)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_PCI_IOV */

static inline u16 nse_abs_vf_id(struct nse_hw *hw, u16 rel_vf_id)
{
	return rel_vf_id + hw->func_caps.first_vf;
}

static inline u16 nse_rel_vf_id(struct nse_hw *hw, u16 abs_vf_id)
{
	return abs_vf_id - hw->func_caps.first_vf;
}

bool nse_is_sriov_enabled(struct nse_pf *pf);

#endif /* _NSE_SRIOV_H_ */

