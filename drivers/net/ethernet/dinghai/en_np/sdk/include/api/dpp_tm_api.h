/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_TM_API_H_
#define _DPP_TM_API_H_

#if ZXIC_REAL("header file")
#include "dpp_module.h"
#endif

#if ZXIC_REAL("macro")
#define DPP_TM_SA_NUM (128)
#define DPP_TM_PP_NUM (64)
#define DPP_ETM_Q_NUM (9216)
#define DPP_FTM_Q_NUM (2048)
#define DPP_ETM_CRDT_NUM (0x47FF)
#define DPP_FTM_CRDT_NUM (0xFFF)
#define DPP_ETM_MID_SE_NUM (6144)
#define DPP_FTM_MID_SE_NUM (512)
#define DPP_ETM_MID_WFQFQ_NUM (8 * 6144)
#define DPP_FTM_MID_WFQFQ_NUM (8 * 512)

#define DPP_ETM_WFQSP_OFFSET (0x4000)
#define DPP_ETM_FQ_NUM (16 * 1024)
#define DPP_ETM_WFQSP_NUM (9 * 1024)
#define DPP_ETM_FQSPWFQ_NUM (25 * 1024)
#define DPP_FTM_WFQSP_NUM (1920 + 64)
#define DPP_ETM_SCH_DEL_NUM (0xABFF)
#define DPP_FTM_SCH_DEL_NUM (0x177F)

#define DPP_TM_INVALID_PORT (0xFFFF)
#define DPP_FTM_DELETED_LINK_ID (0x7FF)
#define DPP_ETM_DELETED_LINK_ID (0x7FFF)

#define DPP_FTM_PORT_LINKID_BASE (0x780)
#define DPP_ETM_PORT_LINKID_BASE (0x7F80)

#define DPP_FTM_SHAP_SEID_BASE (0x1000)
#define DPP_ETM_SHAP_SEID_BASE (0x4800)

/**< @brief TD */
#define DPP_TM_Q_TD_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_PP_TD_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_SYS_TD_TH_MAX (8192) /**< @brief Kbyte */

#define DPP_TM_Q_AVG_Q_LEN_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_PP_AVG_Q_LEN_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_SYS_AVG_Q_LEN_MAX (8192) /**< @brief Kbyte */

/**< @brief WRED */
#define DPP_TM_Q_WRED_NUM (32)
#define DPP_TM_Q_WRED_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_Q_WRED_MAX_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_Q_WRED_MIN_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_Q_WRED_MAX_CFG_PARA (0xffffffff)

#define DPP_TM_PP_WRED_NUM (8)
#define DPP_TM_PP_WRED_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_PP_WRED_MAX_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_PP_WRED_MIN_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_PP_WRED_MAX_CFG_PARA (0xffffffff)

/**< @brief GRED */
#define DPP_TM_SYS_GRED_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_SYS_GRED_MAX_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_SYS_GRED_MIN_TH_MAX (8192) /**< @brief Kbyte */
#define DPP_TM_SYS_GRED_MID_TH_MAX (8192) /**< @brief Kbyte */

#define DPP_TM_DP_NUM (8)
#define DPP_TM_RED_P_MIN (1)
#define DPP_TM_RED_P_MAX (100)
#define DPP_TM_CGAVD_WEIGHT_MAX (15)
#define DPP_TM_CGAVD_MOVE_PROFILE_NUM (16)

#define DPP_TM_SCH_WEIGHT_INVALID (0)
#define DPP_TM_SCH_WEIGHT_MIN (1)
#define DPP_TM_SCH_WEIGHT_MAX (511)
#define DPP_TM_SCH_SP_NUM (8)

#define DPP_ETM_MID_SHAPE_PROFILE_NUM (512)
#define DPP_FTM_MID_SHAPE_PROFILE_NUM (64)
#define DPP_ETM_FLOW_SHAPE_PROFILE_NUM (512)
#define DPP_FTM_FLOW_SHAPE_PROFILE_NUM (128)

#define DPP_TM_SHAPE_CIR_MIN (0) /**< @brief kbps */
#define DPP_TM_SHAPE_CIR_MAX (800 * 1000 * 1000)
#define DPP_TM_SHAPE_CBS_MIN (0) /**< @brief kbyte */
#define DPP_TM_SHAPE_CBS_MAX (128 * 1024)

#define DPP_TM_SHAPE_CBS_REG_MIN (0) /**< @brief kbyte */
#define DPP_TM_SHAPE_CBS_REG_MAX (0x7FF) /**< @brief kbyte */

#define DPP_TM_SYS_HZ (1000 * 1000 * 1000)

#define DPP_TM_TC_NUM (8)

#endif

#if ZXIC_REAL("data struct define")

enum dpp_tm_work_mode_e { DPP_TM_WORK_MODE_TM = 0, DPP_TM_WORK_MODE_SA, DPP_TM_WORK_MODE_INVALID };

enum dpp_tm_qmu_work_mode_e {
	DPP_TM_QMU_WORK_MODE_2M = 0,
	DPP_TM_QMU_WORK_MODE_4M,
	DPP_TM_QMU_WORK_MODE_INVALID
};

enum dpp_tm_qmu_ddr_random_mode_e {
	DPP_TM_QMU_DDR_NOT_RANDOM = 0,
	DPP_TM_QMU_DDR_RANDOM,
	DPP_TM_QMU_DDR_RANDOM_MODE_INVALID
};

struct dpp_tm_cnt_mode_t {
	u32 fc_count_mode;
	u32 count_rd_mode;
	u32 count_overflow_mode;
};

struct dpp_tm_int_t {
	u32 shap_int;
	u32 crdt_int;
	u32 mmu_int;
	u32 qmu_int;
	u32 cgavd_int;
	u32 olif_int;
	u32 cfgmt_int;
};

enum dpp_tm_cgavd_level_e { QUEUE_LEVEL = 0, PP_LEVEL, SYS_LEVEL, SA_LEVEL, INVALID_LEVEL };

enum dpp_tm_cgavd_dp_sel_e { DP_SEL_DP = 0, DP_SEL_TC, DP_SEL_PKT_LEN, INVALID_DP };

enum dpp_tm_cgavd_method_e { TD_METHOD = 0, WRED_GRED_METHOD, INVALID_METHOD };

struct dpp_tm_wred_dp_line_para_t {
	u32 max_th;
	u32 min_th;
	u32 max_p;
	u32 weight;
	u32 q_len_th;
};

struct dpp_tm_gred_dp_line_para_t {
	u32 max_th;
	u32 mid_th;
	u32 min_th;
	u32 max_p;
	u32 weight;
	u32 q_len_th;
};

enum dpp_tm_sch_level_e {
	DPP_TM_SCH_LEVEL_Q = 1,
	DPP_TM_SCH_LEVEL_VC = 2,
	DPP_TM_SCH_LEVEL_VCG = 3,
	DPP_TM_SCH_LEVEL_VP = 4,
	DPP_TM_SCH_LEVEL_PP = 5,
	DPP_TM_SCH_LEVEL_INVALID
};

/**< @brief SP_ID */
enum dpp_tm_sch_sp_e {
	DPP_TM_SCH_SP_0 = 0,
	DPP_TM_SCH_SP_1 = 1,
	DPP_TM_SCH_SP_2 = 2,
	DPP_TM_SCH_SP_3 = 3,
	DPP_TM_SCH_SP_4 = 4,
	DPP_TM_SCH_SP_5 = 5,
	DPP_TM_SCH_SP_6 = 6,
	DPP_TM_SCH_SP_7 = 7,
	DPP_TM_SCH_SP_8 = 8,
	DPP_TM_SCH_SP_INVALID
};

struct dpp_tm_sch_para_t {
	u32 level_id;
	enum dpp_tm_sch_level_e se_last_level;
	u32 se_id;
	enum dpp_tm_sch_sp_e c_sp_id;
	enum dpp_tm_sch_sp_e e_sp_id;
	u32 sp_relay;
	u32 c_sp_weight;
	u32 e_sp_weight;
};

struct dpp_tm_wfqfq_t {
	u32 wfqfq_id[8];
};

struct dpp_tm_sch_flow_para_t {
	u32 c_linkid;
	u32 c_weight;
	u32 c_sp;
	u32 mode;
	u32 e_linkid;
	u32 e_weight;
	u32 e_sp;
};

struct dpp_tm_sch_se_para_t {
	u32 se_linkid;
	u32 cp_token_en;
	u32 se_weight;
	u32 se_sp;
};

struct dpp_tm_sch_se_para_insw_t {
	u32 se_linkid;
	u32 cp_token_en;
	u32 se_sp;
	u32 se_weight[8];
};

enum dpp_tm_sch_port_linkid_t {
	DPP_TM_PP_LINKID_PORT0 = 0x7F80,
	DPP_TM_PP_LINKID_PORT1 = 0x7F81,
	DPP_TM_PP_LINKID_PORT2 = 0x7F82,
	DPP_TM_PP_LINKID_PORT3 = 0x7F83,
	DPP_TM_PP_LINKID_PORT4 = 0x7F84,
	DPP_TM_PP_LINKID_PORT5 = 0x7F85,
	DPP_TM_PP_LINKID_PORT6 = 0x7F86,
	DPP_TM_PP_LINKID_PORT7 = 0x7F87,
	DPP_TM_PP_LINKID_PORT8 = 0x7F88,
	DPP_TM_PP_LINKID_PORT9 = 0x7F89,
	DPP_TM_PP_LINKID_PORT10 = 0x7F8A,
	DPP_TM_PP_LINKID_PORT11 = 0x7F8B,
	DPP_TM_PP_LINKID_PORT12 = 0x7F8C,
	DPP_TM_PP_LINKID_PORT13 = 0x7F8D,
	DPP_TM_PP_LINKID_PORT14 = 0x7F8E,
	DPP_TM_PP_LINKID_PORT15 = 0x7F8F,
	DPP_TM_PP_LINKID_PORT16 = 0x7F90,
	DPP_TM_PP_LINKID_PORT17 = 0x7F91,
	DPP_TM_PP_LINKID_PORT18 = 0x7F92,
	DPP_TM_PP_LINKID_PORT19 = 0x7F93,
	DPP_TM_PP_LINKID_PORT20 = 0x7F94,
	DPP_TM_PP_LINKID_PORT21 = 0x7F95,
	DPP_TM_PP_LINKID_PORT22 = 0x7F96,
	DPP_TM_PP_LINKID_PORT23 = 0x7F97,
	DPP_TM_PP_LINKID_PORT24 = 0x7F98,
	DPP_TM_PP_LINKID_PORT25 = 0x7F99,
	DPP_TM_PP_LINKID_PORT26 = 0x7F9A,
	DPP_TM_PP_LINKID_PORT27 = 0x7F9B,
	DPP_TM_PP_LINKID_PORT28 = 0x7F9C,
	DPP_TM_PP_LINKID_PORT29 = 0x7F9D,
	DPP_TM_PP_LINKID_PORT30 = 0x7F9E,
	DPP_TM_PP_LINKID_PORT31 = 0x7F9F,
	DPP_TM_PP_LINKID_PORT32 = 0x7FA0,
	DPP_TM_PP_LINKID_PORT33 = 0x7FA1,
	DPP_TM_PP_LINKID_PORT34 = 0x7FA2,
	DPP_TM_PP_LINKID_PORT35 = 0x7FA3,
	DPP_TM_PP_LINKID_PORT36 = 0x7FA4,
	DPP_TM_PP_LINKID_PORT37 = 0x7FA5,
	DPP_TM_PP_LINKID_PORT38 = 0x7FA6,
	DPP_TM_PP_LINKID_PORT39 = 0x7FA7,
	DPP_TM_PP_LINKID_PORT40 = 0x7FA8,
	DPP_TM_PP_LINKID_PORT41 = 0x7FA9,
	DPP_TM_PP_LINKID_PORT42 = 0x7FAA,
	DPP_TM_PP_LINKID_PORT43 = 0x7FAB,
	DPP_TM_PP_LINKID_PORT44 = 0x7FAC,
	DPP_TM_PP_LINKID_PORT45 = 0x7FAD,
	DPP_TM_PP_LINKID_PORT46 = 0x7FAE,
	DPP_TM_PP_LINKID_PORT47 = 0x7FAF,
	DPP_TM_PP_LINKID_PORT48 = 0x7FB0,
	DPP_TM_PP_LINKID_PORT49 = 0x7FB1,
	DPP_TM_PP_LINKID_PORT50 = 0x7FB2,
	DPP_TM_PP_LINKID_PORT51 = 0x7FB3,
	DPP_TM_PP_LINKID_PORT52 = 0x7FB4,
	DPP_TM_PP_LINKID_PORT53 = 0x7FB5,
	DPP_TM_PP_LINKID_PORT54 = 0x7FB6,
	DPP_TM_PP_LINKID_PORT55 = 0x7FB7,
	DPP_TM_PP_LINKID_PORT56 = 0x7FB8,
	DPP_TM_PP_LINKID_PORT57 = 0x7FB9,
	DPP_TM_PP_LINKID_PORT58 = 0x7FBA,
	DPP_TM_PP_LINKID_PORT59 = 0x7FBB,
	DPP_TM_PP_LINKID_PORT60 = 0x7FBC,
	DPP_TM_PP_LINKID_PORT61 = 0x7FBD,
	DPP_TM_PP_LINKID_PORT62 = 0x7FBE,
	DPP_TM_PP_LINKID_PORT63 = 0x7FBF,
	DPP_TM_PP_LINKID_INVALID
};
enum dpp_tm_shape_flag_e {
	DPP_TM_SHAPE_FLAG_CIR = 0,
	DPP_TM_SHAPE_FLAG_EIR = 1,
	DPP_TM_SHAPE_FLAG_INVALID
};

enum dpp_tm_shape_mode_e {
	DPP_TM_SINGLE_MIX_BUCKET = 0,
	DPP_TM_DUAL_BUCKET = 1,
	DPP_TM_DUAL_PIPE = 2,
	DPP_TM_SHAPE_MODE_INVALID
};

struct dpp_tm_shape_profile_t {
	u32 cir;
	u32 cbs;
	u32 eir;
	u32 ebs;
};

struct dpp_tm_shape_pp_para_t {
	u32 cir;
	u32 cbs;
	u32 c_en;
};

struct dpp_tm_shape_para_t {
	u32 class_id;
	u32 profile_id;
	u32 c_en;
	u32 e_en;
	enum dpp_tm_shape_mode_e mode;
};

struct dpp_tm_shape_t {
	u32 mid_level;
	u32 cir;
	u32 cbs;
	u32 eir;
	u32 ebs;
	u32 c_en;
	u32 e_en;
	u32 mode;
};

struct dpp_tm_shape_para {
	u32 shape_cir;
	u32 shape_cbs;
	u32 shape_num;
};

struct dpp_tm_init_para_t {
	enum dpp_tm_work_mode_e tm_sa_mode;
	enum dpp_tm_qmu_work_mode_e qmu_mode;
	u32 case_num;
	enum dpp_tm_qmu_ddr_random_mode_e ddr_random_mode;
	u32 block_size;
	u32 local_sa_id;
};

struct dpp_tm_asic_init_info_t {
	u32 blk_size;
	u32 case_num;
	u32 imem_omem;
	u32 mode;
};

#endif

#if ZXIC_REAL("function declaration")

DPP_STATUS dpp_tm_cfgmt_blk_size_get(struct dpp_dev_t *dev, u32 *p_size);

DPP_STATUS dpp_tm_cfgmt_sa_work_mode_set(struct dpp_dev_t *dev, enum dpp_tm_work_mode_e mode);

#ifdef ETM_REAL
DPP_STATUS dpp_tm_cgavd_move_en_set(u32 dev_id, enum dpp_tm_cgavd_level_e level, u32 en);

DPP_STATUS dpp_tm_cgavd_move_th_set(u32 dev_id, enum dpp_tm_cgavd_level_e level, u32 id, u32 value);

DPP_STATUS dpp_tm_cgavd_flow_move_profile_set(u32 dev_id, u32 move_profile, u32 th);
#endif

DPP_STATUS dpp_tm_cgavd_port_share_th_set(u32 dev_id, u32 th);

DPP_STATUS dpp_tm_cgavd_en_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 en);

DPP_STATUS dpp_tm_cgavd_method_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				   enum dpp_tm_cgavd_method_e method);

DPP_STATUS dpp_tm_cgavd_td_th_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				  u32 td_th);

DPP_STATUS dpp_tm_cgavd_wred_id_set(u32 dev_id, enum dpp_tm_cgavd_level_e level, u32 id,
				    u32 wred_id);

DPP_STATUS dpp_tm_cgavd_q_map_pp_set(struct dpp_dev_t *dev, u32 q_id, u32 pp_id);

DPP_STATUS dpp_tm_tc_map_flow_set(struct dpp_dev_t *dev, u32 tc_id, u32 flow_id);

DPP_STATUS dpp_tm_cgavd_dyn_th_en_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				      u32 id, u32 en);

DPP_STATUS dpp_tm_cgavd_imem_omem_set(u32 dev_id, u32 en, u32 mode);

DPP_STATUS dpp_tm_qmu_credit_value_get(struct dpp_dev_t *dev, u32 *p_credit_value);

DPP_STATUS dpp_tm_qmu_pkt_aging_set(struct dpp_dev_t *dev, u32 aging_en, u32 aging_interval,
				    u32 aging_step_interval, u32 aging_start_qnum,
				    u32 aging_end_qnum, u32 aging_pkt_num, u32 aging_req_aful_th);
DPP_STATUS dpp_tm_qmu_pkt_age_time_set(struct dpp_dev_t *dev, u32 aging_en, u32 aging_time,
				       u32 aging_que_start, u32 aging_que_end);
DPP_STATUS dpp_etm_crdt_fq_set(struct dpp_dev_t *dev, u32 fq_num, u32 fq2_num, u32 fq4_num,
			       u32 fq8_num);
DPP_STATUS dpp_tm_crdt_wfqsp_set(struct dpp_dev_t *dev, u32 sp_num, u32 wfq_num, u32 wfq2_num,
				 u32 wfq4_num, u32 wfq8_num);
DPP_STATUS dpp_tm_crdt_flow_link_set(struct dpp_dev_t *dev, u32 flow_id, u32 c_linkid, u32 c_weight,
				     u32 c_sp, u32 mode, u32 e_linkid, u32 e_weight, u32 e_sp);
DPP_STATUS dpp_tm_crdt_se_link_set(struct dpp_dev_t *dev, u32 se_id, u32 se_linkid, u32 se_weight,
				   u32 se_sp);
DPP_STATUS dpp_tm_crdt_se_link_insw_set(struct dpp_dev_t *dev, u32 se_id, u32 se_linkid,
					u32 se_weight, u32 se_sp);
DPP_STATUS dpp_tm_crdt_se_link_insw_single_set(struct dpp_dev_t *dev, u32 se_id, u32 se_linkid,
					       u32 se_weight, u32 se_sp);
DPP_STATUS dpp_tm_crdt_del_flow_link_set(struct dpp_dev_t *dev, u32 id_s, u32 id_e);
DPP_STATUS dpp_tm_crdt_del_se_link_set(struct dpp_dev_t *dev, u32 id_s, u32 id_e);
DPP_STATUS dpp_tm_crdt_se_pp_link_set(struct dpp_dev_t *dev, u32 se_id, u32 pp_id, u32 weight,
				      u32 sp_mapping);
DPP_STATUS dpp_tm_crdt_eir_crs_filter_en_set(struct dpp_dev_t *dev, u32 que_id, u32 en);
DPP_STATUS dpp_tm_clr_shape_para(struct dpp_dev_t *dev);
DPP_STATUS dpp_tm_shape_flow_db_en_set(struct dpp_dev_t *dev, u32 db_en, u32 mode);
DPP_STATUS dpp_tm_shape_flow_para_set(struct dpp_dev_t *dev, u32 flow_id, u32 cir, u32 cbs,
				      u32 db_en, u32 eir, u32 ebs);
DPP_STATUS dpp_tm_shape_se_para_set(struct dpp_dev_t *dev, u32 se_id, u32 pir, u32 pbs, u32 db_en,
				    u32 cir, u32 cbs);
DPP_STATUS dpp_tm_shape_pp_para_wr(struct dpp_dev_t *dev, u32 port_id, u32 cir, u32 cbs, u32 c_en);
DPP_STATUS dpp_tm_shape_pp_para_set(struct dpp_dev_t *dev, u32 port_id,
				    const struct dpp_tm_shape_pp_para_t *p_para);
DPP_STATUS dpp_tm_qmu_scan_rate_set(u32 dev_id, u32 scan_en, u32 scan_rate);
DPP_STATUS dpp_tm_qmu_egress_shape_set(u32 dev_id, u32 port_id, u32 shape_cir, u32 shape_cbs,
				       u32 shape_en);
DPP_STATUS dpp_tm_cgavd_wred_dp_line_para_set(u32 dev_id, enum dpp_tm_cgavd_level_e level,
					      u32 wred_id, u32 dp,
					      struct dpp_tm_wred_dp_line_para_t *p_para);
DPP_STATUS
dpp_tm_wred_dp_line_para_flag_wr(u32 dev_id, u32 level, u32 wred_id, u32 dp, u32 max_th, u32 min_th,
				 u32 max_p, u32 weight, u32 q_len_th, u32 flag);
DPP_STATUS dpp_tm_cgavd_wred_pke_len_calc_sign_set(u32 dev_id, u32 flag);
DPP_STATUS dpp_tm_tmmu_imem_en_set(u32 dev_id, u32 imem_en);
DPP_STATUS dpp_tm_tmmu_ddr_force_rdy_set(u32 dev_id, u32 ddr_force_rdy);
DPP_STATUS dpp_tm_wr_more_reg(u32 dev_id, u32 module_id, u32 first_addr, u32 first_data,
			      u32 data_step, u32 reg_num);
DPP_STATUS dpp_tm_help(u32 dev_id);

#endif /***function declaration***/

#endif /****_DPP_TM_H_****/
