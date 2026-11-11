/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_FDIR_H_
#define _NSE_FDIR_H_

#include "nse_type.h"
#include "nse.h"
#include "nse_adminq_cmd.h"
#include "nse_controlq.h"

#define NSE_FDIR_MAX_NUM_PFILTER_VF_VSI		64
#define NSE_FDIR_MAX_NUM_SFILTER_VF_VSI		512

enum nse_status
nse_aq_fdir_force_reinit(struct nse_hw *hw);

enum nse_status
nse_aq_fdir_query_setting(struct nse_hw *hw, struct nse_aqc_fdir_query_setting *setting);

enum nse_status
nse_aq_fdir_query_stats(struct nse_hw *hw, struct nse_aqc_fdir_query_stats *stats);

enum nse_status
nse_aq_fdir_get_vsi_space(struct nse_hw *hw, u16 vsi_abs_id, u32 *gs_size);

enum nse_status
nse_aq_fdir_set_vsi_space(struct nse_hw *hw, u16 vsi_abs_id, u32 gs_size);

enum nse_status
nse_aq_fdir_get_drop_q(struct nse_hw *hw, u32 *drp_vsi_q);

enum nse_status
nse_aq_fdir_set_drop_q(struct nse_hw *hw, u16 drp_vsi, u16 q_abs_id);

enum nse_status
nse_aq_fdir_get_vsi_input_mask(struct nse_hw *hw, u16 vsi_abs_id,
			       struct nse_aqc_fdir_get_set_vsi_input_mask *input_mask);

enum nse_status
nse_aq_fdir_set_vsi_input_mask(struct nse_hw *hw, u16 vsi_abs_id,
			       struct nse_aqc_fdir_get_set_vsi_input_mask *input_mask);

enum nse_status
nse_aq_fdir_add_perfect_filter(struct nse_hw *hw,
			       struct nse_aqc_fdir_conf_perfect_filter *cmd_data);

enum nse_status
nse_aq_fdir_del_perfect_filter(struct nse_hw *hw,
			       struct nse_aqc_fdir_conf_perfect_filter *cmd_data);

enum nse_status
nse_aq_fdir_query_perfect_filter(struct nse_hw *hw,
				 struct nse_aqc_fdir_conf_perfect_filter *cmd_data);

enum nse_status
nse_aq_fdir_get_vsi_qtbl(struct nse_hw *hw, u16 vsi_abs_id, u32 *val);

enum nse_status
nse_aq_fdir_set_vsi_qtbl(struct nse_hw *hw, u16 vsi_abs_id, u32 val);

void
nse_fdir_dump_setting(struct nse_hw *hw, struct nse_aqc_fdir_query_setting *setting);

void
nse_fdir_dump_stats(struct nse_hw *hw, struct nse_aqc_fdir_query_stats *stats);

void nse_fdir_dump_cb(struct nse_hw *hw);

void nse_fdir_dump_filter(struct nse_hw *hw, struct nse_fdir_filter *f, bool verbose);

void
nse_fdir_process_reinit_event(struct nse_hw *hw, struct nse_rq_event_info *event);

void nse_fdir_compute_hash(struct nse_fdir_input_stream *stream, u32 key, u16 *hash_p);

int nse_add_ethtool_ntuple(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd);
int nse_del_ethtool_ntuple(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd);
int nse_get_ethtool_ntuple(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd);
int nse_get_ethtool_ntuple_ids(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd, u32 *rule_locs);

void nse_del_ethool_ntuple_all(struct nse_hw *hw);

int nse_fdir_flush_vsi_perfect_filter(struct nse_hw *hw, struct nse_vsi *vsi);

void nse_fdir_prepare_for_reset(struct nse_hw *hw);
void nse_fdir_rebuild(struct nse_hw *hw, enum nse_reset_req reset_type);
#endif

