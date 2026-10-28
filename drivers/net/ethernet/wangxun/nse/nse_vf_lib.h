/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VF_LIB_H_
#define _NSE_VF_LIB_H_

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/bitmap.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/pci.h>
#include <linux/if_ether.h>
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include <net/devlink.h>
#endif /* CONFIG_NET_DEVLINK */
#include "virtchnl.h"
#include "nse_type.h"
#include "nse_flow.h"
#include "nse_vsi_vlan_ops.h"
#include "nse_vf_meter.h"

#define NSE_MAX_SRIOV_VFS		252

/* VF resource constraints */
#define NSE_MAX_QS_PER_VF			256

/* Maximum number of queue pairs to configure by default for a VF */
#define NSE_MAX_DFLT_QS_PER_VF		16

struct nse_pf;
struct nse_vf;
struct nse_virtchnl_ops;

/* VF capabilities */
enum nse_virtchnl_cap {
	NSE_VIRTCHNL_VF_CAP_PRIVILEGE = 0,
};

/* Specific VF states */
enum nse_vf_states {
	NSE_VF_STATE_INIT = 0,		/* PF is initializing VF */
	NSE_VF_STATE_ACTIVE,		/* VF resources are allocated for use */
	NSE_VF_STATE_QS_ENA,		/* VF queue(s) enabled */
	NSE_VF_STATE_DIS,
	NSE_VF_STATE_MC_PROMISC,
	NSE_VF_STATE_UC_PROMISC,
	NSE_VF_STATES_NBITS
};

struct nse_time_mac {
	unsigned long time_modified;
	u8 addr[ETH_ALEN];
};

/* VF MDD events print structure */
struct nse_mdd_vf_events {
	u16 count;			/* total count of Rx|Tx events */
	/* count number of the last printed event */
	u16 last_printed;
};

/* VF operations */
struct nse_vf_ops {
	void (*free)(struct nse_vf *vf);
	void (*clear_reset_state)(struct nse_vf *vf);
	void (*clear_mbx_register)(struct nse_vf *vf);
	void (*trigger_reset_register)(struct nse_vf *vf);
	bool (*poll_reset_status)(struct nse_vf *vf);
	void (*clear_reset_trigger)(struct nse_vf *vf);
	void (*irq_close)(struct nse_vf *vf);

	int (*reinit_vsi)(struct nse_vf *vf);
	void (*post_vsi_rebuild)(struct nse_vf *vf);
	struct nse_q_vector* (*get_q_vector)(struct nse_vf *vf,
					     struct nse_vsi *vsi,
					     u16 vector_id);
	void (*cfg_rdma_irq_map)(struct nse_vf *vf,
				 struct virtchnl_rdma_qv_info *qv_info);
	void (*clear_rdma_irq_map)(struct nse_vf *vf);
};

/* Virtchnl/SR-IOV config info */
struct nse_vfs {
	DECLARE_HASHTABLE(table, 8);	/* table of VF entries */
	struct mutex table_lock;	/* Lock for protecting the hash table */
	u16 num_supported;		/* max supported VFs on this PF */
	/* current enabled VF number, should be equal to pci_num_vf(pf->pdev) */
	u16 num_enabled;
	u16 num_qps_per;		/* number of queue pairs per VF */
	u16 num_txcq_per;
	u16 num_msix_per;		/* number of MSI-X vectors per VF */

	/* if lan_tx_use_cq, then = num_txcq_per, and VF driver should use no more than this */
	u16 max_lan_msix_per;

	struct kobject		*config; /*directory of sriov config*/
	struct nse_vf_sysfs *sysfs_vfs;

	u16 vf_vsialloc_firstvsi;
	u16 vf_rx_qbase_firstq;
	u16 vf_rx_qbase_numq;
	u16 vf_tx_qbase_firstq;
	u16 vf_tx_qbase_numq;
	u16 vfint_alloc_first;
	u16 vfint_alloc_vecnum;

	/* CQ base not set to HW AGR & PWRP, but still keep it here */
	u16 vf_txcq_qbase_firstq;
};

struct nse_vf_qs_bw {
	u16 queue_id;
	u32 committed;
	u32 peak;
	u8 tc;
};

/* VF information structure */
struct nse_vf {
	struct hlist_node entry;
	struct rcu_head rcu;
	struct kref refcnt;
	struct nse_pf *pf;

	/* Used during virtchnl message handling and NDO ops against the VF
	 * that will trigger a VFR
	 */
	struct mutex cfg_lock;

	u16 vf_id;			/* VF ID in the PF space */
	u16 lan_vsi_idx;		/* index into PF struct */

	struct nse_vf_qs_bw qs_bw[NSE_MAX_QS_PER_VF];
	/* first vector index of this VF in the PF space */
	int first_vector_idx;
	struct nse_sw *vf_sw_id;	/* switch ID the VF VSIs connect to */
	struct virtchnl_version_info vf_ver;
	u64 driver_req_caps;	/* reported by VF driver */
	u64 driver_caps;		/* reported by VF driver */
	u16 stag;			/* VF Port Extender (PE) stag if used */
	struct virtchnl_ether_addr dev_lan_addr;
	struct virtchnl_ether_addr hw_lan_addr;
	struct nse_time_mac legacy_last_added_umac;
	DECLARE_BITMAP(txq_ena, NSE_MAX_QS_PER_VF);
	DECLARE_BITMAP(rxq_ena, NSE_MAX_QS_PER_VF);
	struct nse_vlan port_vlan_info;	/* Port VLAN ID, QoS, and TPID */
	struct virtchnl_vlan_caps vlan_v2_caps;
	u8 pf_set_mac:1;		/* VF MAC address set by VMM admin */
	u8 trusted:1;
	u8 spoofchk:1;
	u8 link_forced:1;
	u8 link_up:1;			/* only valid if VF link is forced */
	u8 use_pv_msgbox: 1;		/* this VF use PV msgbox instead of mailboxq */

	/* VSI indices - actual VSI pointers are maintained in the PF structure
	 * When assigned, these will be non-zero, because VSI 0 is always
	 * the main LAN VSI for the PF.
	 */
	u16 vf_vsi_abs_id;
	u16 vf_vsi_rel_id;
	unsigned int min_tx_rate;	/* Minimum Tx bandwidth limit in Mbps */
	unsigned int max_tx_rate;	/* Maximum Tx bandwidth limit in Mbps */
	DECLARE_BITMAP(vf_states, NSE_VF_STATES_NBITS);	/* VF runtime states */

	unsigned long vf_caps;		/* VF's adv. capabilities */

	u16 num_mac;
	u16 num_vf_qs;			/* num of queue configured per VF */
	u8 vlan_strip_ena;		/* Outer and Inner VLAN strip enable */
#define NSE_INNER_VLAN_STRIP_ENA	BIT(0)
#define NSE_OUTER_VLAN_STRIP_ENA	BIT(1)

	struct nse_mdd_vf_events mdd_rx_events;
	struct nse_mdd_vf_events mdd_tx_events;
	DECLARE_BITMAP(opcodes_allowlist, VIRTCHNL_OP_MAX);

	struct nse_repr *repr;
	const struct nse_virtchnl_ops *virtchnl_ops;
	const struct nse_vf_ops *vf_ops;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	/* devlink port data */
	struct devlink_port devlink_port;
#endif /* CONFIG_NET_DEVLINK */

#ifdef CONFIG_DEBUG_FS
	struct dentry *vf_dbgfs_dir;
#endif

	struct nse_vf_meter rx_vf_meter;
	struct nse_vf_meter tx_vf_meter;

	u16 vf_reset_count;
	u16 vfr_count;
	u16 vflr_count;
};

/* Flags for controlling behavior of nse_reset_vf */
enum nse_vf_reset_flags {
	NSE_VF_RESET_VFLR = BIT(0), /* Indicate a VFLR reset */
	NSE_VF_RESET_NOTIFY = BIT(1), /* Notify VF prior to reset */
	NSE_VF_RESET_LOCK = BIT(2), /* Acquire the VF cfg_lock */
};

static inline u16 nse_vf_get_port_vlan_id(struct nse_vf *vf)
{
	return vf->port_vlan_info.vid;
}

static inline u8 nse_vf_get_port_vlan_prio(struct nse_vf *vf)
{
	return vf->port_vlan_info.prio;
}

static inline bool nse_vf_is_port_vlan_ena(struct nse_vf *vf)
{
	return (nse_vf_get_port_vlan_id(vf) || nse_vf_get_port_vlan_prio(vf));
}

static inline u16 nse_vf_get_port_vlan_tpid(struct nse_vf *vf)
{
	return vf->port_vlan_info.tpid;
}

/* VF Hash Table access functions
 *
 * These functions provide abstraction for interacting with the VF hash table.
 * In general, direct access to the hash table should be avoided outside of
 * these functions where possible.
 *
 * The VF entries in the hash table are protected by reference counting to
 * track lifetime of accesses from the table. The nse_get_vf_by_id() function
 * obtains a reference to the VF structure which must be dropped by using
 * nse_put_vf().
 */

/**
 * nse_for_each_vf - Iterate over each VF entry
 * @pf: pointer to the PF private structure
 * @bkt: bucket index used for iteration
 * @vf: pointer to the VF entry currently being processed in the loop
 *
 * The bkt variable is an unsigned integer iterator used to traverse the VF
 * entries. It is *not* guaranteed to be the VF's vf_id. Do not assume it is.
 * Use vf->vf_id to get the id number if needed.
 *
 * The caller is expected to be under the table_lock mutex for the entire
 * loop. Use this iterator if your loop is long or if it might sleep.
 */
#define nse_for_each_vf(pf, bkt, vf) \
	hash_for_each((pf)->vfs.table, (bkt), (vf), entry)

/**
 * nse_for_each_vf_rcu - Iterate over each VF entry protected by RCU
 * @pf: pointer to the PF private structure
 * @bkt: bucket index used for iteration
 * @vf: pointer to the VF entry currently being processed in the loop
 *
 * The bkt variable is an unsigned integer iterator used to traverse the VF
 * entries. It is *not* guaranteed to be the VF's vf_id. Do not assume it is.
 * Use vf->vf_id to get the id number if needed.
 *
 * The caller is expected to be under rcu_read_lock() for the entire loop.
 * Only use this iterator if your loop is short and you can guarantee it does
 * not sleep.
 */
#define nse_for_each_vf_rcu(pf, bkt, vf) \
	hash_for_each_rcu((pf)->vfs.table, (bkt), (vf), entry)

#ifdef CONFIG_PCI_IOV
/* The vf_id parameter is a u32 in order to handle IDs stored as u32 values
 * without implicit truncation.
 */
struct nse_vf *nse_get_vf_by_id(struct nse_pf *pf, u32 vf_id);
struct nse_vf *nse_get_vf_by_vsi_abs_id(struct nse_pf *pf, u16 vsi_abs_id);
void nse_put_vf(struct nse_vf *vf);
bool nse_is_valid_vf_id(struct nse_pf *pf, u32 vf_id);
bool nse_has_vfs(struct nse_pf *pf);
u16 nse_get_num_vfs(struct nse_pf *pf);
struct nse_vsi *nse_get_vf_vsi(struct nse_vf *vf);
bool nse_is_vf_disabled(struct nse_vf *vf);
int nse_check_vf_ready_for_cfg(struct nse_vf *vf);
void nse_set_vf_state_qs_dis(struct nse_vf *vf);
bool nse_is_any_vf_in_unicast_promisc(struct nse_pf *pf);
void nse_vf_get_promisc_masks(struct nse_vf *vf, struct nse_vsi *vsi,
			      u8 *ucast_m, u8 *mcast_m);
int
nse_vf_set_vsi_promisc(struct nse_vf *vf, struct nse_vsi *vsi, u8 promisc_m);
int
nse_vf_clear_vsi_promisc(struct nse_vf *vf, struct nse_vsi *vsi, u8 promisc_m);
int nse_reset_vf(struct nse_vf *vf, u32 flags);
void nse_reset_all_vfs(struct nse_pf *pf, enum nse_reset_req reset_type);
#else /* CONFIG_PCI_IOV */
static inline struct nse_vf *nse_get_vf_by_id(struct nse_pf *pf, u32 vf_id)
{
	return NULL;
}

static inline struct nse_vf *nse_get_vf_by_vsi_abs_id(struct nse_pf *pf, u16 vsi_abs_id)
{
	return NULL;
}

static inline void nse_put_vf(struct nse_vf *vf)
{
}

static inline bool nse_is_valid_vf_id(struct nse_pf *pf, u32 vf_id)
{
	return false;
}

static inline bool nse_has_vfs(struct nse_pf *pf)
{
	return false;
}

static inline u16 nse_get_num_vfs(struct nse_pf *pf)
{
	return 0;
}

static inline struct nse_vsi *nse_get_vf_vsi(struct nse_vf *vf)
{
	return NULL;
}

static inline bool nse_is_vf_disabled(struct nse_vf *vf)
{
	return true;
}

static inline int nse_check_vf_ready_for_cfg(struct nse_vf *vf)
{
	return -EOPNOTSUPP;
}

static inline void nse_set_vf_state_qs_dis(struct nse_vf *vf)
{
}

static inline bool nse_is_any_vf_in_unicast_promisc(struct nse_pf *pf)
{
	return false;
}

static inline int
nse_vf_set_vsi_promisc(struct nse_vf *vf, struct nse_vsi *vsi, u8 promisc_m)
{
	return -EOPNOTSUPP;
}

static inline int
nse_vf_clear_vsi_promisc(struct nse_vf *vf, struct nse_vsi *vsi, u8 promisc_m)
{
	return -EOPNOTSUPP;
}

static inline int nse_reset_vf(struct nse_vf *vf, u32 flags)
{
	return 0;
}

static inline void nse_reset_all_vfs(struct nse_pf *pf, enum nse_reset_req reset_type)
{
}
#endif /* !CONFIG_PCI_IOV */

#endif /* _NSE_VF_LIB_H_ */
