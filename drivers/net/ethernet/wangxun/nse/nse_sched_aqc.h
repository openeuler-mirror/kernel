/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_SCHED_AQC_H_
#define _NSE_SCHED_AQC_H_

#include "nse_type.h"
#include "nse_adminq_cmd.h"

void nse_sched_aqc_fill_node_default_sch_param(struct nse_hw *hw,
						struct nse_sch_node_param *param,
							bool is_leaf, u8 tc);

enum nse_status
nse_sched_aqc_rw_ctl(struct nse_hw *hw, u32 rw_flag, u32 *sch_ctl_val);

enum nse_status
nse_sched_set_bypass(struct nse_hw *hw, bool bypass);

enum nse_status
nse_sched_aqc_pf_init(struct nse_hw *hw);

enum nse_status
nse_sched_aqc_add_node_one(struct nse_hw *hw, struct nse_aqc_qos_sch_add_node_one *cmd_data);

enum nse_status
nse_sched_aqc_del_node_one(struct nse_hw *hw, struct nse_aqc_qos_sch_del_node_one *cmd_data);

enum nse_status
nse_sched_aqc_suspend_resume_node_one(struct nse_hw *hw,
				      struct nse_aqc_qos_sch_suspend_resume_node_one *cmd_data);

enum nse_status
nse_sched_suspend_node_one(struct nse_hw *hw, u32 tnid);

enum nse_status
nse_sched_resume_node_one(struct nse_hw *hw, u32 tnid);

enum nse_status
nse_sched_aqc_set_unset_qid2lnid(struct nse_hw *hw,
				 struct nse_aqc_qos_sch_set_unset_qid2lnid *cmd_data);

enum nse_status
nse_sched_set_leaf_qid2lnid(struct nse_hw *hw, u16 qid, u16 qid_type,
							u16 leaf_tnid, u32 leaf_suid,
								u32 leaf_logic_idx_in_su);

enum nse_status
nse_sched_unset_leaf_qid2lnid(struct nse_hw *hw, u16 qid, u16 qid_type);

enum nse_status
nse_sched_aqc_get_or_set_node_param_one(struct nse_hw *hw,
					struct nse_aqc_qos_sch_get_set_node_param_one *cmd_data,
							bool get_or_set);

enum nse_status
nse_sched_aqc_rw_port_ctl(struct nse_hw *hw,
			  struct nse_aqc_qos_sch_rw_port_ctl *cmd_data,
							bool rw);

enum nse_status
nse_sched_aqc_conf_cir(struct nse_hw *hw,
							struct nse_aqc_qos_sch_conf_cir *cmd_data);

enum nse_status
nse_sched_aqc_conf_pir(struct nse_hw *hw,
							struct nse_aqc_qos_sch_conf_pir *cmd_data);

enum nse_status
nse_sched_aqc_dbg_dump_free_se_list(struct nse_hw *hw,
				    struct nse_aqc_qos_sch_dbg_dump_free_se_list *cmd_data);

enum nse_status
nse_sched_aqc_dbg_dump_se(struct nse_hw *hw, struct nse_aqc_qos_sch_dbg_dump_se *cmd_buf);

enum nse_status
nse_sched_aqc_dbg_dump_qid2lnid(struct nse_hw *hw,
				struct nse_aqc_qos_sch_dbg_dump_qid2lnid *cmd_buf);

#endif

