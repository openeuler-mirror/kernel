/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NBL_TC_PEDIT_H__
#define __NBL_TC_PEDIT_H__

#include "nbl_include.h"
#include "nbl_core.h"
#include "nbl_resource.h"

#define NBL_TC_PEDIT_MAC_LEN	6
#define NBL_TC_PEDIT_IP6_LEN	16
#define NBL_TC_PEDIT_KEY_LEN	16
#define NBL_TC_PEDIT_TAB_LEN	8

#define NBL_TC_PEDIT_HW_END_PED_TYPE NBL_FLOW_PED_UMAC_D_TYPE
#define NBL_TC_PEDIT_IS_DEFAULT_TYPE(p_type) ((p_type) < NBL_TC_PEDIT_HW_END_PED_TYPE)
#define NBL_TC_PEDIT_SET_D_TYPE(p_type) ((p_type) += NBL_TC_PEDIT_HW_END_PED_TYPE)
#define NBL_TC_PEDIT_UNSET_D_TYPE(p_type) ((p_type) -= NBL_TC_PEDIT_HW_END_PED_TYPE)

#define NBL_TC_PEDIT_IP6_PHY_TYPE_GAP (NBL_FLOW_PED_UIP6_TYPE - NBL_FLOW_PED_UIP_TYPE)
#define NBL_TC_PEDIT_GET_IP6_PHY_TYPE(p_type) ((p_type) + NBL_TC_PEDIT_IP6_PHY_TYPE_GAP)

struct nbl_tc_pedit_node {
	u32 ref_cnt:31;
	u32 normal_in_h:1;
	u32 node_idx:15;
	u32 node_base:15;
	u32 node_h:1;
	u32 node_val:1;
	void *entry;
	u8 key[];
};

struct nbl_tc_pedit_entry {
	struct nbl_tc_pedit_node hnode;
	union {
		u8 mac[NBL_TC_PEDIT_MAC_LEN];
		u32 ip[2];
		u8 ip6[NBL_TC_PEDIT_IP6_LEN];
		u8 key[NBL_TC_PEDIT_KEY_LEN];
	};
};

#define NBL_TC_PEDIT_SET_NODE_RES_VAL(node) ((node).pedit_val = 1)
#define NBL_TC_PEDIT_SET_NODE_RES_ENTRY(node, idx, e) ((node).pedit_node[idx] = e)

#define NBL_TC_PEDIT_GET_NODE_RES_VAL(node) ((node).pedit_val)
#define NBL_TC_PEDIT_GET_NODE_RES_ENTRY(node, idx) \
				((struct nbl_tc_pedit_entry *)(node).pedit_node[idx])

#define NBL_TC_PEDIT_GET_KEY(ped_node) ((ped_node)->hnode.key)
#define NBL_TC_PEDIT_GET_NODE_REF(ped_node) ((ped_node)->hnode.ref_cnt)
#define NBL_TC_PEDIT_GET_NODE_H(ped_node) ((ped_node)->hnode.node_h)
#define NBL_TC_PEDIT_GET_NORMAL_IN_H(ped_node) ((ped_node)->hnode.normal_in_h)
#define NBL_TC_PEDIT_GET_NODE_IDX(ped_node) ((ped_node)->hnode.node_idx)
#define NBL_TC_PEDIT_GET_NODE_VAL(ped_node) ((ped_node)->hnode.node_val)

#define NBL_TC_PEDIT_INC_NODE_REF(ped_node) ((ped_node)->hnode.ref_cnt++)
#define NBL_TC_PEDIT_DEC_NODE_REF(ped_node) ((ped_node)->hnode.ref_cnt--)

#define NBL_TC_PEDIT_SET_NODE_IDX(ped_node, idx) ((ped_node)->hnode.node_idx = idx)
#define NBL_TC_PEDIT_SET_NODE_BASE_ID(ped_node, idx) ((ped_node)->hnode.node_base = idx)
#define NBL_TC_PEDIT_SET_NODE_VAL(ped_node) ((ped_node)->hnode.node_val = 1)
#define NBL_TC_PEDIT_SET_NODE_INVAL(ped_node) ((ped_node)->hnode.node_val = 0)
#define NBL_TC_PEDIT_SET_NORMAL_IN_H(ped_node) ((ped_node)->hnode.normal_in_h = 1)
#define NBL_TC_PEDIT_SET_NODE_H(ped_node) ((ped_node)->hnode.node_h = 1)
#define NBL_TC_PEDIT_SET_NODE_ENTRY(ped_node, e) ((ped_node)->hnode.entry = e)

#define NBL_TC_PEDIT_COPY_NODE(src_node, dst_node) ((dst_node)->hnode = (src_node)->hnode)

u16 nbl_tc_pedit_get_hw_id(struct nbl_tc_pedit_entry *ped_node);
int nbl_tc_pedit_init(struct nbl_common_info *common,
		      struct nbl_tc_pedit_res_info *pedit_res, u32 max_cnt);
int nbl_tc_pedit_uninit(struct nbl_tc_pedit_res_info *pedit_res, u32 max_cnt);
int nbl_tc_pedit_del_node(struct nbl_tc_pedit_mgt *pedit_mgt,
			  struct nbl_tc_pedit_node_res *ped_node);
int nbl_tc_pedit_add_node(struct nbl_tc_pedit_mgt *pedit_mgt,
			  struct nbl_tc_pedit_entry *e,
			  void **e_out, enum nbl_flow_ped_type pedit_type);
#endif
