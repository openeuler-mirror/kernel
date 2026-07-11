/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/**************************************************************
 * FQ
 *fq_num:  1280 : 0, 1, 2 ... 0x4ff
 *fq2_num: 1024 : 0x500, 0x502, 0x504 ... 0xcfe
 *fq4_num: 1024 : 0xd00, 0xd04, 0xd08 ... 0x1cfc
 *fq8_num: 1120 : 0x1d00, 0x1d08, 0x1d10 ... 0x3ff8
 * SP-WFQ
 *sp_num: 128 : 0x4000, 0x4001, 0x4002 ... 0x407f
 *wfq_num: 2048 : 0x4080, 0x4081, 0x4082 ... 0x487f
 *wfq2_num: 256 : 0x4880, 0x4882, 0x4884 ... 0x4a7e
 *wfq4_num: 256 : 0x4a80, 0x4a84, 0x4a88 ... 0x4e7c
 *wfq8_num: 688 : 0x4e80, 0x4e88, 0x4e90 ... 0x63f8
 *
 *
 *flow id 0~0xf  0MR 0x10~0xfff
 *
 * flowid:32K, profileid:512
 *
 * flowid:4K, profileid:128
 *
 * flowid:1K, profileid:32
 ***************************************************************
 */
#ifndef _DPP_DRV_QOS_H_
#define _DPP_DRV_QOS_H_

#include "zxic_common.h"
#include "dpp_tm.h"
#include "dpp_tm_api.h"
#include "dpp_stat_car.h"
#include "dpp_stat_api.h"
#include "dpp_agent_channel.h"

#define DPP_VPORT_NUM_MAX (0x7fff)
#define DPP_CRDT_LEVEL_MAX (7)
#define DPP_SCHE_TYPE_MAX (10)

#define DPP_TM_PORT_WIDTH (56)
#define DPP_TM_VPORT_WIDTH (32)
#define DPP_TM_LEVEL_WIDTH (28)
#define DPP_TM_TYPE_WIDTH (24)

#define G_SCH_ID_LEN (8)

#define CAR_TYPE_MAX (4)

#define G_PROFILE_ID_LEN (8)

/* Get Real port */
#define DPP_TM_CRDT_PP_PORT_GET(_gsch_id, _pp_port) \
	((_pp_port) = ((_gsch_id >> DPP_TM_PORT_WIDTH) & 0xffff))

/* Get Real vport */
#define DPP_TM_CRDT_VPORT_GET(_gsch_id, _vport) \
	((_vport) = ((_gsch_id >> DPP_TM_VPORT_WIDTH) & 0xffff))

/* Get Real level */
#define DPP_TM_CRDT_LEVEL_GET(_gsch_id, _sche_level) \
	((_sche_level) = ((_gsch_id >> DPP_TM_LEVEL_WIDTH) & 0xf))

/* Get Real type */
#define DPP_TM_CRDT_TYPE_GET(_gsch_id, _sche_type) \
	((_sche_type) = ((_gsch_id >> DPP_TM_TYPE_WIDTH) & 0xf))

/* Get Real se_id */
#define DPP_TM_CRDT_SE_ID_GET(_gsch_id, _se_id) ((_se_id) = ((_gsch_id & 0xffff)))

/* Get Real profile */
#define DPP_CAR_PROFILE_ID_GET(_profile_id, _profileid) ((_profileid) = ((_profile_id & 0xffff)))
DPP_STATUS dpp_cosq_gsch_id_add(struct dpp_pf_info_t *pf_info, u32 pp_port, u32 numq, u32 level,
				u32 flags, u64 *p_gsch_id);
DPP_STATUS dpp_cosq_gsch_id_delete(struct dpp_pf_info_t *pf_info, u32 pp_port, u64 gsch_id);
DPP_STATUS dpp_sch_base_node_get(struct dpp_pf_info_t *pf_info, u32 pp_port, u64 *gsch_id);
DPP_STATUS dpp_crdt_se_pp_link_set(struct dpp_pf_info_t *pf_info, u32 se_id, u32 pp_id, u32 weight,
				   u32 sp_mapping);
DPP_STATUS dpp_crdt_se_link_set(struct dpp_pf_info_t *pf_info, u32 se_id, u32 se_linkid,
				u32 se_weight, u32 se_sp);
DPP_STATUS dpp_crdt_flow_link_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 c_linkid,
				  u32 c_weight, u32 c_sp, u32 mode, u32 e_linkid, u32 e_weight,
				  u32 e_sp);
DPP_STATUS dpp_crdt_del_flow_link_set(struct dpp_pf_info_t *pf_info, u32 id_s, u32 id_e);
DPP_STATUS dpp_crdt_del_se_link_set(struct dpp_pf_info_t *pf_info, u32 id_s, u32 id_e);
DPP_STATUS dpp_port_shape_set(struct dpp_pf_info_t *pf_info, u32 pp_port, u32 cir, u32 cbs,
			      u32 c_en);
DPP_STATUS dpp_port_shape_get(struct dpp_pf_info_t *pf_info, u32 pp_port,
			      struct dpp_tm_shape_pp_para_t *p_para);
DPP_STATUS dpp_se_shape_set(struct dpp_pf_info_t *pf_info, u32 se_id, u32 pir, u32 pbs, u32 db_en,
			    u32 cir, u32 cbs);
DPP_STATUS dpp_flow_shape_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 cir, u32 cbs,
			      u32 db_en, u32 eir, u32 ebs);
DPP_STATUS dpp_flow_map_port_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 port);
DPP_STATUS dpp_flow_map_port_get(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 *p_port);
DPP_STATUS dpp_flow_td_th_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 td_th);
DPP_STATUS dpp_flow_td_th_get(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 *p_td_th);
DPP_STATUS dpp_blk_size_set(struct dpp_pf_info_t *pf_info, u32 size);
DPP_STATUS dpp_qmu_pfc_en_set(struct dpp_pf_info_t *pf_info, u32 pfc_en);
DPP_STATUS dpp_qmu_pfc_en_get(struct dpp_pf_info_t *pf_info, u32 *p_pfc_en);
DPP_STATUS dpp_qmu_port_pfc_set(struct dpp_pf_info_t *pf_info, u32 port_id, u32 port_en);
DPP_STATUS dpp_qmu_port_pfc_get(struct dpp_pf_info_t *pf_info, u32 port_id, u32 *p_port_en);
DPP_STATUS dpp_car_profile_id_add(struct dpp_pf_info_t *pf_info, u32 flags, u64 *profile_id);
DPP_STATUS dpp_car_profile_id_delete(struct dpp_pf_info_t *pf_info, u32 flags, u64 profile_id);
DPP_STATUS dpp_car_queue_cfg_set(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 drop_flag, u32 plcr_en, u32 profile_id);
DPP_STATUS dpp_car_queue_cfg_get(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 *p_drop_flag, u32 *p_plcr_en, u32 *p_profile_id);
DPP_STATUS dpp_car_profile_cfg_set(struct dpp_pf_info_t *pf_info, u32 car_type, u32 pkt_sign,
				   u32 profile_id, void *p_car_profile_cfg);
DPP_STATUS dpp_car_profile_cfg_get(struct dpp_pf_info_t *pf_info, u32 car_type, u32 pkt_sign,
				   u32 profile_id, void *p_car_profile_cfg);
DPP_STATUS dpp_car_queue_map_set(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 map_flow_id, u32 map_sp);
DPP_STATUS dpp_car_queue_map_get(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 *p_map_flow_id, u32 *p_map_sp);

#endif
