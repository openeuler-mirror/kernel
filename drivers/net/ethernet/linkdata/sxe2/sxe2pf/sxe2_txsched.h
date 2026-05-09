/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_txsched.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_TXSCHED_H__
#define __SXE2_TXSCHED_H__
#include "sxe2_cmd.h"

struct sxe2_adapter;
struct sxe2_vsi;

#define SXE2_TX_SCHED_NODE_PER_VSI_MAX 5

#define SXE2_TXSCHED_SW_PORT_LAYER	0
#define SXE2_TXSCHED_SW_TC_LAYER	1
#define SXE2_TXSCHED_SW_VEB_LAYER	2
#define SXE2_TXSCHED_SW_VSIG_LAYER	3
#define SXE2_TXSCHED_SW_VSI_LAYER	4
#define SXE2_TXSCHED_SW_QG_LAYER	5
#define SXE2_TXSCHED_SW_Q_LAYER		6

#define SXE2_TX_SCHED_STATE_INIT  0x0
#define SXE2_TX_SCHED_STATE_READY 0x1

#define SXE2_TX_SCHED_VSI_MAX_TXQ_NUM 256

#define SXE2_TXSCH_VF_VSIG_AGG_MAX (48)

#define SXE2_TXSCH_NODE_PRIO_DLFT 0
#define SXE2_TXSCH_NODE_PRIO_HIGH 7

#define SXE2_TXSCH_NODE_ADJ_LVL_DFLT 3
#define SXE2_TXSCH_NODE_ADJ_LVL_MAX  3

enum sxe2_node_type {
	SXE2_TXSCHD_NODE_TYPE_UNKNOWN = 0,

	SXE2_TXSCHD_NODE_TYPE_PORT,

	SXE2_TXSCHD_NODE_TYPE_TC,

	SXE2_TXSCHD_VEB_TYPE_PF,
	SXE2_TXSCHD_VEB_TYPE_MACVLAN_ESW,
	SXE2_TXSCHD_VEB_TYPE_VF,

	SXE2_TXSCHD_VSIG_TYPE_PF_AGG,
	SXE2_TXSCHD_VSIG_TYPE_AGG,
	SXE2_TXSCHD_VSIG_TYPE_GEN,
	SXE2_TXSCHD_VSIG_TYPE_VF_AGG,
	SXE2_TXSCHED_VSIG_TYPE_USER_PF,

	SXE2_TXSCHD_VSI_TYPE_PF,
	SXE2_TXSCHD_VSI_TYPE_PF_RDMA,
	SXE2_TXSCHD_VSI_TYPE_PF_CHANNEL,
	SXE2_TXSCHD_VSI_TYPE_PF_LOOPBACK,
	SXE2_TXSCHD_VSI_TYPE_PF_CTRL,
	SXE2_TXSCHD_VSI_TYPE_MACVLAN_ESW,
	SXE2_TXSCHD_VSI_TYPE_VF,
	SXE2_TXSCHD_VSI_TYPE_USER_PF,
	SXE2_TXSCHD_VSI_TYPE_USER_VF,

	SXE2_TXSCHD_QS_TYPE_RDMA,
	SXE2_TXSCHD_QS_TYPE_LAN,
};

enum sxe2_txsch_vsi_type {
	FUSION_VF2VSI_NODE_VF_KVSI = 0,
	FUSION_VF2VSI_MODE_VF_UVSI,
	FUSION_VF2VSIG_MODE_VF_KVSI,
	FUSION_VF2VSIG_MODE_VF_UVSI,
	OTHER_MODE_KVSI,
	OTHER_MODE_UVSI,
	OTHER_MODE_UNKNOWN,
};

struct sxe2_txsch_add_nodes_req {
	u8 tc;
	u8 prio;
	u8 sw_layer;
	u8 adj_lvl;
	u16 num;
	u16 weight;
	u16 parent_teid;
	enum sxe2_txsched_node_owner owner;
};

struct sxe2_txsched_vf_tm_info {
	u32 committed;
	u32 peak;
	u8 priority;
	u16 weight;
};

struct sxe2_txsched_add_node_info {
	u8 num;
	enum sxe2_node_type type;
	struct sxe2_txsched_node *node;
};

struct sxe2_txsched_node {
	struct sxe2_txsched_node *parent;
	struct sxe2_txsched_node *group;
	struct sxe2_txsched_node *sibling;
	struct sxe2_txsched_node *
		*child;
	struct sxe2_txsched_node_info info;
	enum sxe2_node_type node_type;
	u16 vf_idx_in_pf;
	u16 vsi_idx_in_dev;
	u16 txq_idx_in_vsi;
	u16 txq_idx_in_dev;
	u8 in_use;
	u8 child_cnt;
	u8 tc;
	u8 owner;
	u8 same_node_num_pre_tc;
};

struct sxe2_txsched_context {
	struct sxe2_txsched_node *root;
	struct sxe2_fwc_txsched_cap_resp cap;
	/* in order to protect the data */
	struct mutex lock;
	u8 state;
	u8 sw_entry_point_layer;
	u16 user_root_teid;
	struct sxe2_txsched_node *sib_head[SXE2_MAX_TRAFFIC_CLASS][SXE2_TXSCHED_LAYER_MAX];
};

struct sxe2_txsched_node_param {
	u32 tc;
	u32 owner;
	u16 vsi_idx_in_dev;
	u16 parent_teid;
	u16 node_teid;
	u16 txq_idx_in_dev;
	u16 txq_idx_in_vsi;
	u8 sw_layer;
	u8 node_silbing_idx;
};

bool sxe2_txsch_is_vf_vsi_agg_mode(struct sxe2_adapter *adapter);

bool sxe2_txsched_support_chk(struct sxe2_adapter *adapter);

s32 sxe2_txsched_txq_node_add(struct sxe2_adapter *adapter,
			      struct sxe2_vsi *vsi, struct sxe2_queue *txq,
			      enum sxe2_txsched_node_owner owner,
			      struct sxe2_fwc_cfg_txq_req *req);

s32 sxe2_txsched_txq_node_del(struct sxe2_adapter *adapter,
			      struct sxe2_queue *txq);

void sxe2_txsched_dflt_topo_deinit(struct sxe2_adapter *adapter);

s32 sxe2_txsched_dflt_topo_init(struct sxe2_adapter *adapter);

s32 sxe2_txsched_init(struct sxe2_adapter *adapter);

void sxe2_txsched_deinit(struct sxe2_adapter *adapter);

s32 sxe2_txsched_q_bw_lmt_cfg(struct sxe2_vsi *vsi, struct sxe2_queue *txq,
			      u8 rl_type, u32 bw);

void sxe2_txsched_vsi_q_ctxt_free(struct sxe2_vsi *vsi);

s32 sxe2_txsched_lan_vsi_rm(struct sxe2_vsi *vsi);

s32 sxe2_txsched_rdma_vsi_rm(struct sxe2_vsi *vsi);

bool sxe2_txsched_qset_left(struct sxe2_adapter *adapter, u16 vsi_idx);

s32 sxe2_txsched_lan_vsi_cfg(struct sxe2_vsi *vsi);

void sxe2_txsched_tree_clean(struct sxe2_adapter *adapter);

void sxe2_txsched_tree_dump(struct sxe2_adapter *adapter);

void sxe2_txsched_sw_tree_dump(struct sxe2_adapter *adapter);

s32 sxe2_txsched_vf_bw_lmt_cfg(struct sxe2_adapter *adapter,
			       struct sxe2_vf_node *vf_node, u8 rl_type, u32 bw);

s32 sxe2_txsched_ets_update(struct sxe2_adapter *adapter, u8 tc_cnt);

s32 sxe2_txsched_dflt_tc_node_add(struct sxe2_adapter *adapter,
				  struct sxe2_txsched_node_info *tc0_info);

s32 sxe2_txsched_qset_node_add(struct sxe2_adapter *adapter,
			       struct sxe2_vsi *vsi,
			       struct aux_rdma_qset_params *qset, u8 tc);
s32 sxe2_txsched_qset_node_del(struct sxe2_adapter *adapter,
			       struct aux_rdma_qset_params *qset, u8 tc);
s32 sxe2_txsched_rdma_vsi_cfg(struct sxe2_vsi *vsi, u8 is_aa);

struct sxe2_txsched_node *
sxe2_txsched_find_node_by_teid(struct sxe2_txsched_node *start_node, u16 teid);

s32 sxe2_txsched_qset_node_move(struct sxe2_adapter *adapter,
				struct sxe2_adapter *new_adapter,
				struct aux_rdma_qset_params *dqset,
				u16 *new_teid, u8 is_aa);

s32 sxe2_txsched_node_bw_lmt_cfg(struct sxe2_vsi *vsi,
				 struct sxe2_txsched_node *node, u8 rl_type,
				 u32 bw);

s32 sxe2_txsched_nodes_add_tm(struct sxe2_adapter *adapter,
			      struct sxe2_txsched_node *parent, u8 tc,
			      u8 sw_layer, u16 sibling_num,
			      struct sxe2_txsched_node **first_node,
			      u16 *num_nodes_added,
			      struct sxe2_txsched_vf_tm_info *tm_info,
			      u16 *node_teid);

void sxe2_txsched_sw_subtree_dump(struct sxe2_adapter *adapter,
				  struct sxe2_txsched_node *node);

void sxe2_txsched_hw_subtree_dump(struct sxe2_adapter *adapter,
				  struct sxe2_txsched_node *node);

void sxe2_txsched_vf_tree_clean(struct sxe2_adapter *adapter);

struct sxe2_txsched_node *
sxe2_txsched_vsi_first_node_get(struct sxe2_txsched_context *ctxt, u8 tc,
				u16 vsi_idx, u8 owner);

s32 sxe2_txsch_ucmd_root_vsi_cfg(struct sxe2_vsi *vsi, u16 *vsi_teid);

s32 sxe2_txsched_tc_max_bw_lmt_cfg(struct sxe2_vsi *vsi, u8 tc, u32 max_tx_rate);

s32 sxe2_txsched_ucmd_vsig_node_del(struct sxe2_vsi *vsi);

s32 sxe2_txsched_ucmd_vsi_node_del(struct sxe2_vsi *vsi);

s32 sxe2_txsch_ucmd_subtree_del(struct sxe2_adapter *adapter,
				u16 vsi_idx, u16 node_teid,
				bool del_root);

struct sxe2_txsched_ucmd_node_params {
	u16 parent_teid;
	u16 node_teid;
	u32 committed;
	u32 peak;
	u8 priority;
	u8 reserve;
	u16 weight;
	u8 adj_lvl;
};

struct sxe2_txsch_ucmd_qnode_params {
	u16 parent_teid;
	u16 node_teid;
	u32 committed;
	u32 peak;
	u8 priority;
	u8 reserve;
	u16 weight;
	u32 queue_id;
	u8 adj_lvl;
};

s32 sxe2_txsched_ucmd_node_add(struct sxe2_vsi *vsi,
			       struct sxe2_txsched_ucmd_node_params *node_params);

s32 sxe2_txsched_ucmd_qnode_add(struct sxe2_vsi *vsi,
				struct sxe2_txsch_ucmd_qnode_params *node_params);

#endif
