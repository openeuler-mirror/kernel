/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VIRTCHNL_H_
#define _NSE_VIRTCHNL_H_

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/if_ether.h>
#include "virtchnl.h"
#include "nse_vf_lib.h"

/* Restrict number of MAC Addr and VLAN that non-trusted VF can programmed */
#define NSE_MAX_VLAN_PER_VF		8

/* MAC filters: 1 is reserved for the VF's default/perm_addr/LAA MAC, 1 for
 * broadcast, and 16 for additional unicast/multicast filters
 */
#define NSE_MAX_MACADDR_PER_VF		18

#define NSE_VF_UCAST_PROMISC_BITS NSE_PROMISC_UCAST_RX
#define NSE_VF_UCAST_VLAN_PROMISC_BITS	(NSE_PROMISC_UCAST_RX | \
					 NSE_PROMISC_VLAN_RX)

struct nse_virtchnl_ops {
	int (*get_ver_msg)(struct nse_vf *vf, u8 *msg);

	int (*get_vf_res_msg)(struct nse_vf *vf, u8 *msg);

	void (*reset_vf)(struct nse_vf *vf);
	void (*reset_vf_rdma)(struct nse_vf *vf);

	int (*add_mac_addr_msg)(struct nse_vf *vf, u8 *msg);
	int (*del_mac_addr_msg)(struct nse_vf *vf, u8 *msg);

	int (*cfg_qs_msg)(struct nse_vf *vf, u8 *msg);
	int (*ena_qs_msg)(struct nse_vf *vf, u8 *msg);
	int (*dis_qs_msg)(struct nse_vf *vf, u8 *msg);
	int (*get_qp_info)(struct nse_vf *vf, u8 *msg);
	int (*cfg_irq_map_msg)(struct nse_vf *vf, u8 *msg);

	int (*config_rss_key)(struct nse_vf *vf, u8 *msg);
	int (*config_rss_lut)(struct nse_vf *vf, u8 *msg);
	int (*config_rss_alg)(struct nse_vf *vf, u8 *msg);

	int (*set_fdir_input_mask)(struct nse_vf *vf, u8 *msg);

	int (*set_logall_bitmap)(struct nse_vf *vf, u8 *msg);

	int (*get_stats_msg)(struct nse_vf *vf, u8 *msg);

	int (*cfg_promiscuous_mode_msg)(struct nse_vf *vf, u8 *msg);

	int (*query_rxdid)(struct nse_vf *vf);

	int (*rdma_msg)(struct nse_vf *vf, u8 *msg, u16 msglen);
	int (*cfg_rdma_irq_map_msg)(struct nse_vf *vf, u8 *msg);
	int (*clear_rdma_irq_map)(struct nse_vf *vf);

	int (*get_qos_caps)(struct nse_vf *vf);
	int (*cfg_q_tc_map)(struct nse_vf *vf, u8 *msg);
	int (*cfg_q_bw)(struct nse_vf *vf, u8 *msg);
	int (*cfg_q_quanta)(struct nse_vf *vf, u8 *msg);

	int (*get_offload_vlan_v2_caps)(struct nse_vf *vf);
	int (*add_vlan_v2_msg)(struct nse_vf *vf, u8 *msg);
	int (*remove_vlan_v2_msg)(struct nse_vf *vf, u8 *msg);
	int (*ena_vlan_stripping_v2_msg)(struct nse_vf *vf, u8 *msg);
	int (*dis_vlan_stripping_v2_msg)(struct nse_vf *vf, u8 *msg);
	int (*ena_vlan_insertion_v2_msg)(struct nse_vf *vf, u8 *msg);
	int (*dis_vlan_insertion_v2_msg)(struct nse_vf *vf, u8 *msg);
};

#ifdef CONFIG_PCI_IOV
void nse_virtchnl_set_dflt_ops(struct nse_vf *vf);
void nse_virtchnl_set_repr_ops(struct nse_vf *vf);
void
nse_vc_vf_broadcast(struct nse_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen);
void nse_vc_notify_vf_link_state(struct nse_vf *vf, bool force);
void nse_vc_notify_link_state(struct nse_pf *pf, bool force);
void nse_vc_notify_reset(struct nse_pf *pf, enum nse_reset_req reset_type);
int
nse_vc_send_msg_to_vf(struct nse_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen);
bool nse_vc_isvalid_vsi_abs_id(struct nse_vf *vf, u16 vsi_abs_id);
bool nse_vc_isvalid_vsi_rel_id(struct nse_vf *vf, u16 vsi_rel_id);

#else /* CONFIG_PCI_IOV */
static inline void nse_virtchnl_set_dflt_ops(struct nse_vf *vf) { }
static inline void nse_virtchnl_set_repr_ops(struct nse_vf *vf) { }
static inline void
nse_vc_vf_broadcast(struct nse_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
}

static inline void nse_vc_notify_vf_link_state(struct nse_vf *vf, bool force) { }
static inline void nse_vc_notify_link_state(struct nse_pf *pf, bool force) { }
static inline void nse_vc_notify_reset(struct nse_pf *pf, enum nse_reset_req reset_type) { }

static inline int
nse_vc_send_msg_to_vf(struct nse_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	return -EOPNOTSUPP;
}

static inline bool nse_vc_isvalid_vsi_abs_id(struct nse_vf *vf, u16 vsi_abs_id)
{
	return 0;
}

static inline bool nse_vc_isvalid_vsi_rel_id(struct nse_vf *vf, u16 vsi_rel_id)
{
	return 0;
}

#endif /* !CONFIG_PCI_IOV */

#endif /* _NSE_VIRTCHNL_H_ */

