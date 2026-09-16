/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_SCHED_H_
#define _NSE_SCHED_H_

#include "nse_common.h"

extern unsigned int nse_sch_tree_scheme;

enum nse_sched_layer_id {
	NSE_SCHED_LAYER_ID_ROOT		=	0x0,
	NSE_SCHED_LAYER_ID_PORT,
	NSE_SCHED_LAYER_ID_TC,

	NSE_SCHED_LAYER_ID_INITIAL_LAYER_MAX,

	NSE_SCHED_LAYER_ID_MAX		=	NSE_SCH_TREE_MAX_LAYERS_NUM,
};

struct nse_sched_rl_factor {
	u16 factor_idx;
	u16 factor_int;
	u16 factor_df_int;
	u16 factor_df_df;
};

struct nse_sched_node *nse_sched_get_node(struct nse_port_info *pi, u32 tnid);
struct nse_sched_node *nse_sched_find_node_by_tnid(struct nse_sched_node *start_node, u32 tnid);

struct nse_sched_node *nse_sched_get_tc_node(struct nse_port_info *pi, u8 tc);

struct nse_sched_node *
nse_sched_get_vsi_node(struct nse_port_info *pi, struct nse_sched_node *tc_node,
		       u16 vsi_handle);

struct nse_sched_node *
nse_sched_get_free_qparent(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
			   u8 owner);

void nse_sched_fill_cmd_data_add_node_one(struct nse_port_info *pi,
				struct nse_aqc_qos_sch_add_node_one *cmd_data,
				struct nse_sched_node *parent,
				struct nse_sched_node **prev_sibling_pptr,
				struct nse_sched_node **next_sibling_pptr,
				bool is_leaf, u16 qid, u16 qid_type);

enum nse_status nse_sched_fill_cmd_data_del_node_one_and_unlink_sw_node(struct nse_port_info *pi,
				struct nse_aqc_qos_sch_del_node_one *cmd_data,
				struct nse_sched_node *parent,
				u32 tnid,
				struct nse_sched_node **node_pptr,
				struct nse_sched_node **prev_sibling_pptr,
				struct nse_sched_node **next_sibling_pptr,
				bool is_leaf);

enum nse_status
nse_sched_add_one_sw_node(struct nse_port_info *pi, struct nse_sched_node *tc_node,
			struct nse_sched_node *parent, u8 layer,
			struct nse_sched_node *prev_sibling, struct nse_sched_node *next_sibling,
			u32 new_node_tnid,
			struct nse_aqc_qos_sch_add_node_one *cmd_data,
			struct nse_sched_node **new_node_pptr);

void
nse_sched_del_one_sw_node(struct nse_hw *hw, struct nse_sched_node *parent,
						struct nse_sched_node *node,
						bool already_unlinked);

void nse_free_sched_node(struct nse_port_info *pi, struct nse_sched_node *node,
			 struct nse_aqc_qos_sch_del_node_one *cmd_data);

bool nse_sched_no_need_to_del_hw_node(struct nse_hw *hw);

enum nse_status
nse_sched_cfg_vsi(struct nse_port_info *pi, u16 vsi_handle, u8 tc, u16 maxqs,
		  u8 owner, bool enable);

enum nse_status nse_rm_vsi_lan_cfg(struct nse_port_info *pi, u16 vsi_handle);
enum nse_status nse_rm_vsi_rdma_cfg(struct nse_port_info *pi, u16 vsi_handle);

enum nse_status
nse_sched_get_node_sch_param(struct nse_hw *hw,
							u32 tnid, struct nse_sch_node_param *param);

enum nse_status
nse_sched_conf_node_sch_param_pir(struct nse_hw *hw,
									struct nse_sched_node *node,
									u16 op,
				  struct nse_sched_rl_factor *rlf);

#define NSE_SCHED_CONF_CIR_RETRY_CNT	3	/* only used when conf port-node */

enum nse_status
nse_sched_conf_node_sch_param_cir(struct nse_hw *hw,
									struct nse_sched_node *node,
									u16 op,
				  struct nse_sched_rl_factor *rlf,
									u8 *conf_status);

void
nse_sched_node_sch_param_compute_pir_cir(struct nse_port_info __always_unused *pi,
				u32 rate_kbps, struct nse_sched_rl_factor *rl_factor);

void
nse_sched_node_sch_param_compute_pir_cir_by_idx(struct nse_port_info *pi,
				struct nse_sched_rl_factor *rl_factor);

enum nse_status
nse_sched_set_q_pir(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		 u16 q_handle, u32 user_bw);

enum nse_status
nse_sched_set_q_cir(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		 u16 q_handle, u32 user_bw);

enum nse_status
nse_sched_set_vsi_pir_per_tc(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u32 user_bw);

enum nse_status
nse_sched_set_vsi_cir_per_tc(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u32 user_bw);

enum nse_status
nse_sched_set_tc_cir(struct nse_port_info *pi, u8 tc, u32 tc_bw);

void
nse_sched_set_tc_cir_by_dcbxcfg(struct nse_hw *hw, struct nse_dcbx_cfg *local_dcbx_cfg);

enum nse_status
nse_sched_unset_node_cir(struct nse_port_info *pi, struct nse_sched_node *node, bool locked);

enum nse_status
nse_sched_set_port_node_pir(struct nse_port_info *pi, bool full);

enum nse_status
nse_sched_replay_q_bw(struct nse_port_info *pi, struct nse_q_ctx *q_ctx);

enum nse_status
nse_sched_replay_vsi_bw(struct nse_hw *hw, u16 vsi_handle,
			unsigned long *tc_bitmap);

void nse_sched_dump_layer_infos(struct nse_hw *hw);
void nse_sched_dump_node(struct nse_sched_node *n);
void nse_sched_dump_node_branch_to_root(struct nse_sched_node *n);
void nse_sched_dump_node_subtree(struct nse_sched_node *n, unsigned int ident_cnt, char *linebuf);

void nse_sched_clear_port(struct nse_port_info *pi);	/* used in reset */
void nse_sched_cleanup_all(struct nse_hw *hw);			/* as deinit */
enum nse_status nse_sched_init(struct nse_hw *hw);

#endif

