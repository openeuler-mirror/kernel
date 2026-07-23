/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_ETM_H_
#define _DPP_ETM_H_

#include "dpp_tm_api.h"
#include "dpp_etm_reg.h"
#if ZXIC_REAL("ETM_MACRO")

#define ETM_WRITE_CHECK (1)
#define DPP_TM_CGAVD_KILO_UL (1024) /* Kbytebyte */
#define DPP_TM_CGAVD_TD_MAX (16 * 512)
/* CIR: bps */
#define DPP_TM_SHAPE_CIR_STEP ((400L * 1000 * 1000 * 1000 / 0x3FFFFFE))
//#define DPP_TM_SHAPE_CIR_STEP  (160069565217 / 0x3FFFFFE)
/* EIR: bps */
//define DPP_TM_SHAPE_EIR_STEP  ((int) 160 * 1000 * 1000 * 1000 / 0x3FFFFFE)
#define DPP_TM_SHAPE_EIR_STEP (160 * 1000 * 1000 * 1000 / 0x3FFFFFE)
#define DPP_TM_SHAPE_DEFAULT_CBS (20)
#define DPP_TM_KILO_UL (1024)
#define DPP_TM_KILO_ULL (1000)
#define DPP_TM_QMU_PORT_SHAP_MAG (1.03)
#define DPP_ETM_SA_EGRS_MAX_PORTID (66)
/*cfgmt_byte_mode:0:block mode 1:byte mode*/
#define DPP_TM_CGAVD_BLOCK_MODE (0)
#define DPP_TM_CGAVD_ZXIC_UINT8_MODE (1)

/*shap:2K,0-127*/
/*ETM 0xABFF/2K = 21 */
#define DPP_ETM_SHAP_TABEL_ID_MAX (22)
/*FTM 0x17FF/2K = 2 */
#define DPP_FTM_SHAP_TABEL_ID_MAX (3)
#define DPP_TM_SHAP_MAP_ID_MAX (128)

/******************************************************************************
 *                                END:                                  *
 *****************************************************************************/
#endif /* ETM_MACRO */

#if ZXIC_REAL("ETM_STRUCT")
/******************************************************************************
 *                              START:                                *
 *****************************************************************************/
/* block */
enum dpp_tm_blk_size_e {
	DPP_ETM_BLK_SIZE_128_B = 0,
	DPP_ETM_BLK_SIZE_256_B,
	DPP_ETM_BLK_SIZE_512_B,
	DPP_ETM_BLK_SIZE_1024_B,
	DPP_ETM_BLK_SIZE_INVALID
};

struct dpp_tm_amplify_gene_para_t {
	u32 amplify_gene[16];
};

struct dpp_tm_equal_pkt_len_th_para_t {
	u32 equal_pkt_len_th[7];
};

struct dpp_tm_equal_pkt_len_para_t {
	u32 equal_pkt_len[8];
};

/*ETM_STRUCT_STAT */
enum dpp_tm_cgavd_stat_qnum_e {
	DPP_ETM_CGAVD_STAT_QNUM1 = 0,
	DPP_ETM_CGAVD_STAT_QNUM2 = 1,
	DPP_ETM_CGAVD_STAT_QNUM_INVALID
};

enum dpp_tm_cgavd_stat_mode_e {
	DPP_ETM_CGAVD_STAT_ALL_QUEUE = 0,
	DPP_ETM_CGAVD_STAT_ONE_QUEUE = 1,
	DPP_ETM_CGAVD_STAT_MODE_INVALID
};

struct dpp_tm_cgavd_stat_para_t {
	enum dpp_tm_cgavd_stat_mode_e mode;
	u32 q_id;
};

struct dpp_tm_cgavd_stat_info_t {
	enum dpp_tm_cgavd_stat_mode_e mode;
	u32 q_id;
	u32 lif_in_pkt_num;
	u32 enqueue_pkt_num;
	u32 dequeue_pkt_num;
	u32 td_drop_pkt_num;
	u32 wred_drop_pkt_num;
	u32 wred_dpi_pkt_num[8];
	u32 gred_drop_pkt_num;
	u32 gred_dpi_pkt_num[8];
};

struct dpp_tm_qmu_stat_info_t {
	u32 fc_cnt_mode;
	u32 mmu_qmu_wr_fc_cnt;
	u32 mmu_qmu_rd_fc_cnt;
	u32 qmu_cgavd_fc_cnt;
	u32 cgavd_qmu_pkt_cnt;
	u32 cgavd_qmu_pktlen_all;
	u32 cgavd_qmu_drop_tap;
	u32 last_drop_qnum;
	u32 crdt_qmu_credit_cnt;
	u32 qmu_to_qsch_report_cnt;
	u32 qmu_to_cgavd_report_cnt;
	u32 qmu_crdt_crs_normal_cnt;
	u32 qmu_crdt_crs_off_cnt;
	u32 qsch_qlist_shedule_cnt;
	u32 qsch_qlist_sch_ept_cnt;
	u32 qmu_to_mmu_blk_wr_cnt;
	u32 qmu_to_csw_blk_rd_cnt;
	u32 qmu_to_mmu_sop_wr_cnt;
	u32 qmu_to_mmu_eop_wr_cnt;
	u32 qmu_to_mmu_drop_wr_cnt;
	u32 qmu_to_csw_sop_rd_cnt;
	u32 qmu_to_csw_eop_rd_cnt;
	u32 qmu_to_csw_drop_rd_cnt;
	u32 mmu_to_qmu_wr_release_cnt;
	u32 mmu_to_qmu_rd_release_cnt;
};

struct dpp_tm_qmu_spec_q_stat_info_t {
	u32 observe_portfc_spec;
	u32 spec_lif_portfc_count;
	u32 observe_qnum_set;
	u32 spec_q_pkt_received;
	u32 spec_q_pkt_dropped;
	u32 spec_q_pkt_scheduled;
	u32 spec_q_wr_cmd_sent;
	u32 spec_q_rd_cmd_sent;
	u32 spec_q_pkt_enq;
	u32 spec_q_pkt_deq;
	u32 spec_q_crdt_uncon_received;
	u32 spec_q_crdt_cong_received;
	u32 spec_q_crs_normal_cnt;
	u32 spec_q_crs_off_cnt;
};

struct dpp_tm_qmu_spec_bat_stat_info_t {
	u32 observe_batch_set;
	u32 spec_bat_pkt_received;
	u32 spec_bat_pkt_dropped;
	u32 spec_bat_blk_scheduled;
	u32 spec_bat_wr_cmd_sent;
	u32 spec_bat_rd_cmd_sent;
	u32 spec_bat_pkt_enq;
	u32 spec_bat_pkt_deq;
	u32 spec_bat_crdt_uncon_received;
	u32 spec_bat_crdt_cong_received;
	u32 spec_bat_crs_normal_cnt;
	u32 spec_bat_crs_off_cnt;
};

struct qmu_port_shape_para {
	u32 shape_value_amplified;
	u32 token_add_num;
	u32 token_gap;
};

/*etm ddr_attach、bank_num、depth(mmu)*/
struct dpp_etm_qmu_init_para {
	u32 etm_mmu_ddr_attach;
	u32 etm_mmu_bank_num;
	u32 etm_mmu_depth;
};

/*ftm ddr_attach、bank_num、depth(mmu)*/
struct dpp_ftm_qmu_init_para {
	u32 ftm_mmu_ddr_attach;
	u32 ftm_mmu_bank_num;
	u32 ftm_mmu_depth;
};

struct dpp_tm_crdt_spwfq_start_num_t {
	u32 start_num_fq;
	u32 start_num_fq2;
	u32 start_num_fq4;
	u32 start_num_fq8;
	u32 start_num_sp;
	u32 start_num_wfq;
	u32 start_num_wfq2;
	u32 start_num_wfq4;
	u32 start_num_wfq8;
};

#endif

#if ZXIC_REAL("ETM_FUNCTION")
DPP_STATUS dpp_tm_shape_para_array_prt(u32 dev_id, u32 para_x, u32 para_y, u32 clear_flag);

DPP_STATUS dpp_tm_qmu_qlist_set(u32 dev_id, u32 ddr_num, u32 bank_num_para, u32 bank_vld,
				u32 gene_para);

DPP_STATUS dpp_tm_cgavd_td_th_together_wr(struct dpp_dev_t *dev, u32 level, u32 id, u32 td_th,
					  u32 num);

DPP_STATUS dpp_tm_cgavd_td_th_together_get(struct dpp_dev_t *dev, u32 level, u32 id, u32 num);

DPP_STATUS dpp_tm_cgavd_dyn_th_en_set_more(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					   u32 id, u32 en, u32 num);

DPP_STATUS dpp_tm_cgavd_move_drop_sp_th_set(u32 dev_id, u32 sp, u32 th);

DPP_STATUS dpp_tm_wred_dp_line_para_wr(u32 dev_id, u32 level, u32 wred_id, u32 dp, u32 max_th,
				       u32 min_th, u32 max_p, u32 weight, u32 q_len_th);

DPP_STATUS dpp_tm_gred_dp_line_para_wr(u32 dev_id, u32 dp, u32 max_th, u32 mid_th, u32 min_th,
				       u32 max_p, u32 weight, u32 q_len_th);

DPP_STATUS dpp_tm_crdt_idle_check(struct dpp_dev_t *dev);

DPP_STATUS
dpp_tm_crdt_wfqsp_get(struct dpp_dev_t *dev,
		      struct dpp_tm_crdt_spwfq_start_num_t *p_spwfq_start_num);

DPP_STATUS dpp_tm_crdt_se_para_get(struct dpp_dev_t *dev, u32 se_id,
				   struct dpp_etm_crdt_se_para_tbl_t *p_se_para_tbl);

DPP_STATUS dpp_tm_cfgmt_qmu_work_mode_set(struct dpp_dev_t *dev, enum dpp_tm_qmu_work_mode_e mode);

DPP_STATUS dpp_tm_cfgmt_qmu_work_mode_get(struct dpp_dev_t *dev,
					  enum dpp_tm_qmu_work_mode_e *p_mode);

DPP_STATUS dpp_tm_cfgmt_local_sa_id_set(u32 dev_id, u32 sa_id);

DPP_STATUS dpp_tm_cfgmt_local_sa_id_get(u32 dev_id, u32 *p_sa_id);

DPP_STATUS dpp_tm_q_len_use_cpu_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				    u32 q_len_use_cpu_set_en, u32 q_len_cpu_set);

DPP_STATUS dpp_tm_q_avg_len_use_cpu_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					u32 q_avg_len_use_cpu_set_en, u32 q_avg_len_cpu_set);

DPP_STATUS dpp_tm_qmu_qos_sign_set(struct dpp_dev_t *dev, u32 q_id, u32 qos_sign);

DPP_STATUS dpp_tm_crdt_credit_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_crdt_credit_en_get(u32 dev_id, u32 *p_en);

DPP_STATUS dpp_tm_crdt_space_choose_set(u32 dev_id, u32 crdt_space_choose);

DPP_STATUS dpp_tm_crdt_space_choose_get(u32 dev_id, u32 *p_crdt_space_choose);

DPP_STATUS dpp_tm_crdt_port_congest_en_set(struct dpp_dev_t *dev, u32 port_id, u32 port_en);

DPP_STATUS dpp_tm_crdt_port_congest_en_get(struct dpp_dev_t *dev, u32 port_id, u32 *p_port_en);

DPP_STATUS dpp_tm_crdt_renew_scan_set(u32 dev_id, u32 renew_scan_flow, u32 renew_scan_mid);

DPP_STATUS dpp_tm_crdt_renew_scan_get(u32 dev_id, u32 *renew_scan_flow, u32 *renew_scan_mid);

DPP_STATUS dpp_tm_crdt_crs_sheild_set(u32 dev_id, u32 flow_id, u32 en, u32 crs_value);

DPP_STATUS dpp_tm_crdt_crs_sheild_get(u32 dev_id, u32 *p_flow_id, u32 *p_en, u32 *p_crs_value);

DPP_STATUS dpp_tm_crdt_rci_grade_th_set(u32 dev_id, u32 index, u32 rci_grade_th_0_data);

DPP_STATUS dpp_tm_crdt_rci_grade_th_get(u32 dev_id, u32 index, u32 *p_rci_grade_th_0_data);

DPP_STATUS dpp_tm_crdt_asm_interval_set(u32 dev_id, u32 index, u32 asm_interval_0_data);

DPP_STATUS dpp_tm_crdt_asm_interval_get(u32 dev_id, u32 index, u32 *p_asm_interval_0_data);

DPP_STATUS dpp_tm_crdt_rci_grade_get(u32 dev_id, u32 *p_rci_grade_data);

DPP_STATUS dpp_tm_crdt_rci_value_r_get(u32 dev_id, u32 *p_crdt_rci_value_r_data);

DPP_STATUS dpp_tm_crdt_interval_now_get(u32 dev_id, u32 *p_crdt_interval_now_data);

DPP_STATUS
dpp_tm_crdt_interval_en_cfg_set(u32 dev_id, u32 crdt_interval_en_cfg_data);

DPP_STATUS dpp_tm_crdt_cfgmt_interval_set(u32 dev_id, u32 valid_serdes_num, u32 ucn_level,
					  u32 cr_clk);

DPP_STATUS
dpp_tm_crdt_interval_en_cfg_get(u32 dev_id, u32 *p_crdt_interval_en_cfg_data);

DPP_STATUS dpp_tm_crdt_ucn_asm_rdy_shield_en_set(u32 dev_id, u32 ucn_rdy_shield_en,
						 u32 asm_rdy_shield_en);

DPP_STATUS
dpp_tm_crdt_ucn_asm_rdy_shield_en_get(u32 dev_id, u32 *p_ucn_rdy_shield_en,
				      u32 *p_asm_rdy_shield_en);

DPP_STATUS dpp_tm_qmu_credit_value_set(u32 dev_id, u32 credit_value);

DPP_STATUS dpp_tm_qmu_ddr_rand_grp_set(u32 dev_id, u32 ddr_num);

DPP_STATUS dpp_tm_qmu_ddr_random_set(u32 dev_id, u32 ddr_random);

DPP_STATUS dpp_tm_qmu_cfg_done_set(u32 dev_id);

DPP_STATUS dpp_tm_qmu_crs_eir_th_set(u32 dev_id, u32 index, u32 crs_th);

DPP_STATUS dpp_tm_qmu_crs_th_set(u32 dev_id, u32 index, u32 crs_th);

DPP_STATUS dpp_tm_qmu_crs_th2_set(u32 dev_id, u32 que_type, u32 empty_que_ack_th);

DPP_STATUS dpp_tm_qmu_pkt_blk_mode_set(u32 dev_id, u32 pkt_blk_mode);

DPP_STATUS dpp_tm_qmu_pkt_blk_mode_get(u32 dev_id, u32 *p_pkt_blk_mode);

DPP_STATUS dpp_tm_qmu_wr_aged_en_set(struct dpp_dev_t *dev, u32 aged_en);

DPP_STATUS dpp_tm_qmu_wr_aged_scan_time_set(struct dpp_dev_t *dev, u32 scan_time);

DPP_STATUS dpp_tm_qmu_wr_aged_scan_time_get(struct dpp_dev_t *dev, u32 *p_scan_time);

DPP_STATUS dpp_tm_qmu_qcfg_dest_id_set(u32 dev_id, u32 que_id, u32 dest_said);

DPP_STATUS dpp_tm_qmu_qcfg_dest_id_get(u32 dev_id, u32 que_id, u32 *p_dest_said);

DPP_STATUS dpp_tm_qmu_pid_use_set(u32 dev_id, u32 used_inall);

DPP_STATUS dpp_tm_qmu_pid_use_get(u32 dev_id, u32 *p_used_inall);

DPP_STATUS dpp_tm_qmu_pid_round_th_set(u32 dev_id, u32 round_th);

DPP_STATUS dpp_tm_qmu_pid_round_th_get(u32 dev_id, u32 *p_round_th);

DPP_STATUS dpp_tm_qmu_crs_force_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_qmu_crs_force_q_set(u32 dev_id, u32 q_id);

DPP_STATUS dpp_tm_qmu_crs_force_state_set(u32 dev_id, u32 crs_state);

DPP_STATUS dpp_tm_qmu_qnum_crs_force(u32 dev_id, u32 qnum, u32 qcfg_qsch_crs_force_crs,
				     u32 qcfg_qsch_crs_force_en);

DPP_STATUS dpp_tm_qmu_crs_state_set(u32 dev_id, u32 qnum, u32 state);

DPP_STATUS dpp_tm_qmu_crs_state_get(u32 dev_id, u32 qnum, u32 *p_state);

DPP_STATUS dpp_tm_qmu_auto_credit_que_set(struct dpp_dev_t *dev, u32 first_que, u32 last_que);

DPP_STATUS dpp_tm_qmu_auto_credit_que_get(struct dpp_dev_t *dev, u32 *p_first_que, u32 *p_last_que);

DPP_STATUS dpp_tm_qmu_auto_credit_rate_set(struct dpp_dev_t *dev, u32 auto_crdt_en,
					   u32 auto_crdt_rate);

DPP_STATUS dpp_tm_qmu_auto_credit_rate_get(struct dpp_dev_t *dev, u32 *p_auto_crdt_en,
					   u32 *p_auto_crdt_rate);

DPP_STATUS dpp_tm_qmu_crbal_drop_en_set(u32 dev_id, u32 all_drop_en, u32 drop_en);

DPP_STATUS dpp_tm_qmu_crbal_drop_en_get(u32 dev_id, u32 *p_all_drop_en, u32 *p_drop_en);

DPP_STATUS dpp_tm_qmu_qcfg_csch_congest_th_set(struct dpp_dev_t *dev, u32 port_id,
					       u32 qmu_congest_th);

DPP_STATUS dpp_tm_qmu_qcfg_csch_congest_th_get(struct dpp_dev_t *dev, u32 port_id,
					       u32 *p_qmu_congest_th);

DPP_STATUS dpp_tm_qmu_qcfg_csch_sp_fc_th_set(struct dpp_dev_t *dev, u32 port_id, u32 q_pri,
					     u32 qmu_sp_fc_th);

DPP_STATUS dpp_tm_qmu_qcfg_csch_sp_fc_th_get(struct dpp_dev_t *dev, u32 port_id, u32 q_pri,
					     u32 *p_qmu_sp_fc_th);

DPP_STATUS dpp_tm_qmu_observe_portfc_set(struct dpp_dev_t *dev, u32 port_id);

DPP_STATUS dpp_tm_qmu_pfc_en_set(struct dpp_dev_t *dev, u32 pfc_en);

DPP_STATUS dpp_tm_qmu_pfc_en_get(struct dpp_dev_t *dev, u32 *pfc_en);

DPP_STATUS dpp_tm_qmu_port_pfc_make_set(struct dpp_dev_t *dev, u32 port_id, u32 port_en);

DPP_STATUS dpp_tm_qmu_port_pfc_make_get(struct dpp_dev_t *dev, u32 port_id, u32 *p_port_en);

DPP_STATUS dpp_etm_qmu_init_set_1(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_1(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_1(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_2(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_2(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_2(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_pd16k_2(u32 dev_id, u32 depth);

DPP_STATUS dpp_etm_qmu_init_set_chuk32(u32 dev_id, u32 depth);

DPP_STATUS dpp_ftm_qmu_init_set_pd16k_2(u32 dev_id, u32 depth);

DPP_STATUS dpp_tm_qmu_init_set_pd16k_2(u32 dev_id, u32 depth);

DPP_STATUS dpp_tm_qmu_init_set_chuk32(u32 dev_id, u32 depth);

DPP_STATUS dpp_etm_qmu_init_set_3(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_3(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_3(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_4(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_4(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_4(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_5(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_5(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_5(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_6(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_6(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_6(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_7(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_7(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_7(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_8(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_8(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_8(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_9(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_9(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_9(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_10(u32 dev_id);

DPP_STATUS dpp_ftm_qmu_init_set_10(u32 dev_id);

DPP_STATUS dpp_tm_qmu_init_set_10(u32 dev_id);

DPP_STATUS dpp_etm_qmu_init_set_11(u32 dev_id, u32 ddr_no1, u32 ddr_no2);

DPP_STATUS dpp_ftm_qmu_init_set_11(u32 dev_id, u32 ddr_no1, u32 ddr_no2);

DPP_STATUS dpp_tm_qmu_init_set_11(u32 dev_id, u32 ddr_no1, u32 ddr_no2);

DPP_STATUS dpp_ftm_qmu_init_set_12(u32 dev_id, u32 ftm_ddr_no);

DPP_STATUS dpp_tm_qmu_init_set_12(u32 dev_id, u32 ddr_no);

DPP_STATUS dpp_etm_qmu_init_set_13(u32 dev_id, u32 ddr_no);

DPP_STATUS dpp_ftm_qmu_init_set_13(u32 dev_id, u32 ddr_no);

DPP_STATUS dpp_tm_qmu_init_set_13(u32 dev_id, u32 ddr_no);
DPP_STATUS dpp_tm_qmu_init_set_14(u32 dev_id, u32 etm_ddr_no, u32 ftm_ddr_no);
DPP_STATUS dpp_etm_qmu_init_set_14(u32 dev_id, u32 etm_ddr_no);
DPP_STATUS dpp_ftm_qmu_init_set_14(u32 dev_id, u32 ftm_ddr_no);
DPP_STATUS dpp_tm_qmu_init_set_15(u32 dev_id, u32 etm_ddr_no, u32 ftm_ddr_no);
DPP_STATUS dpp_etm_qmu_init_set_15(u32 dev_id, u32 etm_ddr_no);
DPP_STATUS dpp_ftm_qmu_init_set_15(u32 dev_id, u32 ftm_ddr_no);

DPP_STATUS dpp_tm_qmu_init_set_16(u32 dev_id, u32 etm_ddr_no, u32 ftm_ddr_no);

DPP_STATUS dpp_etm_qmu_init_set_16(u32 dev_id, u32 ftm_ddr_no);

DPP_STATUS dpp_ftm_qmu_init_set_16(u32 dev_id, u32 etm_ddr_no);

DPP_STATUS dpp_tm_crdt_sch_64k_test(u32 dev_id, u32 port_id);

DPP_STATUS dpp_tm_rem_and_exp_translate(u32 data, u32 rembitsum, u32 *p_remdata, u32 *p_exp);

DPP_STATUS dpp_tm_cgavd_stat_q_set(u32 dev_id, enum dpp_tm_cgavd_stat_qnum_e qnum,
				   enum dpp_tm_cgavd_stat_mode_e mode, u32 q_id);

DPP_STATUS dpp_tm_cgavd_stat_q_get(u32 dev_id, enum dpp_tm_cgavd_stat_qnum_e qnum,
				   struct dpp_tm_cgavd_stat_info_t *p_para);

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_para_set(struct dpp_dev_t *dev,
					       struct dpp_tm_equal_pkt_len_para_t *p_equal_pkt_len);

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_para_get(struct dpp_dev_t *dev,
					       struct dpp_tm_equal_pkt_len_para_t *p_equal_pkt_len);

DPP_STATUS
dpp_tm_cgavd_amplify_gene_para_set(struct dpp_dev_t *dev,
				   struct dpp_tm_amplify_gene_para_t *p_amplify_gene_para);

DPP_STATUS
dpp_tm_cgavd_amplify_gene_para_get(struct dpp_dev_t *dev,
				   struct dpp_tm_amplify_gene_para_t *p_amplify_gene_para);

DPP_STATUS
dpp_tm_cgavd_equal_pkt_len_th_para_set(struct dpp_dev_t *dev,
				       struct dpp_tm_equal_pkt_len_th_para_t *p_equal_pkt_len_th);

DPP_STATUS dpp_tm_qmu_ddr_random_get(u32 dev_id, u32 *p_ddr_random);

DPP_STATUS
dpp_tm_cgavd_equal_pkt_len_th_para_get(struct dpp_dev_t *dev,
				       struct dpp_tm_equal_pkt_len_th_para_t *p_equal_pkt_len_th);

DPP_STATUS dpp_tm_cgavd_stat_q_all_get_diag(u32 dev_id);

DPP_STATUS dpp_tm_cgavd_stat_q_single_get_diag(u32 dev_id);

DPP_STATUS dpp_tm_cgavd_default_queue_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_cgavd_default_queue_en_get(u32 dev_id, u32 *p_en);

DPP_STATUS dpp_tm_cgavd_default_queue_set(u32 dev_id, u32 def_start_queue, u32 def_finish_queue);

DPP_STATUS dpp_tm_cgavd_default_queue_get(u32 dev_id, u32 *p_def_start_queue,
					  u32 *p_def_finish_queue);

DPP_STATUS dpp_tm_cgavd_protocol_queue_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_cgavd_protocol_queue_en_get(u32 dev_id, u32 *p_en);

DPP_STATUS dpp_tm_cgavd_protocol_queue_set(u32 dev_id, u32 protocol_start_que,
					   u32 protocol_finish_que);

DPP_STATUS dpp_tm_cgavd_protocol_queue_get(u32 dev_id, u32 *p_protocol_start_que,
					   u32 *p_protocol_finish_que);

DPP_STATUS dpp_tm_qmu_observe_batch_set(struct dpp_dev_t *dev, u32 batch_id);

DPP_STATUS dpp_tm_qmu_observe_qnum_set(struct dpp_dev_t *dev, u32 q_id);

DPP_STATUS dpp_tm_qmu_crbal_initial_value_set(u32 dev_id, u32 crbal_initial_value);

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_en_set(struct dpp_dev_t *dev, u32 en);

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_en_get(struct dpp_dev_t *dev, u32 *p_en);

DPP_STATUS dpp_etm_crdt_traffic_diag(u32 dev_id, u32 ackflow_start, u32 ackflow_end,
				     u32 sleep_time_ms);

DPP_STATUS dpp_ftm_crdt_traffic_diag(u32 dev_id, u32 ackflow_start, u32 ackflow_end,
				     u32 sleep_time_ms);

DPP_STATUS diag_dpp_tm_crdt_traffic_diag(u32 dev_id, u32 ackflow_start, u32 ackflow_end,
					 u32 sleep_time_ms);

DPP_STATUS dpp_tm_olif_stat_set_mul(u32 dev_id, u32 i_or_e_sel, u32 port_or_dest_id_sel,
				    u32 start_id, u32 start_port_dest_id, u32 num);

/******************************************************************************
 *                               END:                                 *
 *****************************************************************************/
#endif

#if ZXIC_REAL("ETM_STAT")

DPP_STATUS diag_dpp_tm_int(u32 dev_id);

DPP_STATUS dpp_tm_case_no_get(u32 dev_id, u32 *case_no);

DPP_STATUS dpp_tm_int_mask_set(u32 dev_id, u32 int_mask_flag);

DPP_STATUS dpp_tm_cgavd_move_drop_sp_th_get(u32 dev_id, u32 sp, u32 *p_th);

DPP_STATUS dpp_tm_cgavd_cfg_mode_get_diag(u32 dev_id);

DPP_STATUS dpp_tm_cgavd_td_byte_block_th_get_diag(u32 dev_id, enum dpp_tm_cgavd_level_e level,
						  u32 id);

DPP_STATUS dpp_tm_qmu_mmu_cfg_clr(u32 dev_id);

DPP_STATUS dpp_tm_qmu_stat_get(u32 dev_id, struct dpp_tm_qmu_stat_info_t *p_para);

DPP_STATUS dpp_tm_qmu_spec_q_stat_get(u32 dev_id, struct dpp_tm_qmu_spec_q_stat_info_t *p_para);

DPP_STATUS
dpp_tm_qmu_spec_bat_stat_get(u32 dev_id, struct dpp_tm_qmu_spec_bat_stat_info_t *p_para);

DPP_STATUS dpp_tm_qmu_fc_cnt_mode_set(struct dpp_dev_t *dev, u32 mode);

DPP_STATUS dpp_tm_qmu_fc_cnt_mode_get(struct dpp_dev_t *dev, u32 *p_mode);

DPP_STATUS dpp_tm_cfgmt_blk_size_get_diag(u32 dev_id);

DPP_STATUS dpp_tm_qlist_ept_flag_get_diag(u32 dev_id, u32 qnum);

DPP_STATUS dpp_tm_qlist_ept_flag_get(u32 dev_id, u32 qnum, u32 *p_value);

DPP_STATUS dpp_tm_qlist_r_bcnt_get(u32 dev_id, u32 qnum, u32 *p_value);

DPP_STATUS dpp_tm_qlist_r_bcnt_get_diag(u32 dev_id, u32 qnum);

DPP_STATUS dpp_tm_csch_r_block_cnt_get(u32 dev_id, u32 pri, u32 *p_value);

DPP_STATUS dpp_tm_csch_r_block_cnt_diag(u32 dev_id, u32 port);

DPP_STATUS dpp_tm_crdt_flow_link_state_get_diag(u32 dev_id, u32 flow_id);

DPP_STATUS dpp_tm_crdt_se_link_state_get_diag(u32 dev_id, u32 se_id);

DPP_STATUS dpp_tm_olif_fifo_empty_state_get_diag(u32 dev_id);

DPP_STATUS dpp_tm_crdt_clr_diag(u32 dev_id);

DPP_STATUS dpp_tm_crdt_crs_sheild_set(u32 dev_id, u32 flow_id, u32 en, u32 crs_value);

DPP_STATUS dpp_tm_crdt_crs_sheild_get(u32 dev_id, u32 *p_flow_id, u32 *p_en, u32 *p_crs_value);

DPP_STATUS dpp_tm_crdt_cfgmt_interval_get(u32 dev_id, u32 valid_serdes_num, u32 ucn_level,
					  u32 *p_cr_clk);

DPP_STATUS dpp_tm_crs_statics(u32 dev_id, u32 que_id);

DPP_STATUS dpp_tm_crs_cnt_prt(u32 dev_id, u32 que_id, u32 ackflow_id, u32 valid_flag);

DPP_STATUS dpp_tm_crs_cnt_prt_1(u32 dev_id, u32 que_id, u32 ackflow_id, u32 valid_flag,
				u32 sleep_time);

DPP_STATUS dpp_tm_qmu_qlist_state_query(u32 dev_id);

DPP_STATUS dpp_tm_shape_token_dec_cnt_diag(u32 dev_id);

DPP_STATUS dpp_tm_shape_token_dist_cnt_diag(u32 dev_id);

DPP_STATUS dpp_tm_olif_stat_set(u32 dev_id, u32 id, u32 all_or_by_port, u32 i_or_e_sel,
				u32 port_or_dest_id_sel, u32 port_dest_id);

DPP_STATUS diag_dpp_tm_crdt_port_congest_credit_cnt(u32 dev_id, u32 pp_id);

#endif /*ETM_STAT */

#if ZXIC_REAL("TM_REG")
DPP_STATUS dpp_tm_wr_reg(u32 dev_id, u32 module_id, u32 addr, u32 data);

DPP_STATUS dpp_tm_rd_reg(u32 dev_id, u32 module_id, u32 addr);

DPP_STATUS dpp_tm_rd_more_reg(u32 dev_id, u32 module_id, u32 first_addr, u32 reg_num);

DPP_STATUS dpp_tm_ind_wr_reg(u32 dev_id, u32 module_id, u32 addr, u64 data);

DPP_STATUS dpp_tm_ind_rd_reg(u32 dev_id, u32 module_id, u32 addr);
#endif /*TM_REG */

#if ZXIC_REAL("TM_CFGMT")
DPP_STATUS dpp_tm_cfgmt_subsystem_rdy_check(u32 dev_id);

DPP_STATUS dpp_tm_cfgmt_cpu_check(struct dpp_dev_t *dev);

DPP_STATUS dpp_tm_cfgmt_sa_work_mode_get(struct dpp_dev_t *dev, enum dpp_tm_work_mode_e *p_mode);

DPP_STATUS dpp_tm_cfgmt_ddr_attach_set(struct dpp_dev_t *dev, u32 ddr_num);

DPP_STATUS dpp_tm_cfgmt_ddr_attach_get(struct dpp_dev_t *dev, u32 *p_ddr_num);

DPP_STATUS dpp_qmu_init_info(u32 dev_id);

DPP_STATUS dpp_tm_cfgmt_crc_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_cfgmt_port_transfer_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_cfgmt_port_transfer_en_get(u32 dev_id, u32 *p_en);

DPP_STATUS dpp_tm_cfgmt_crc_en_get(u32 dev_id, u32 *p_en);

DPP_STATUS dpp_tm_cfgmt_blk_size_set(struct dpp_dev_t *dev, u32 size);

DPP_STATUS dpp_tm_cfgmt_cnt_mode_set(u32 dev_id, struct dpp_tm_cnt_mode_t *p_mode);

DPP_STATUS dpp_tm_cfgmt_cnt_mode_get(u32 dev_id, struct dpp_tm_cnt_mode_t *p_mode);

DPP_STATUS dpp_tm_cfgmt_int_mask_set(u32 dev_id, struct dpp_tm_int_t *p_para);

DPP_STATUS dpp_tm_cfgmt_int_mask_get(u32 dev_id, struct dpp_tm_int_t *p_para);

DPP_STATUS dpp_tm_cfgmt_int_state_get(u32 dev_id, struct dpp_tm_int_t *p_para);

DPP_STATUS dpp_tm_cfgmt_clkgate_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_cfgmt_clkgate_en_get(u32 dev_id, u32 *p_en);

DPP_STATUS dpp_tm_cfgmt_softrst_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_cfgmt_softrst_en_get(u32 dev_id, u32 *p_en);

#endif /*TM_CFGMT */

#if ZXIC_REAL("TM_CGAVD")
#ifdef ETM_REAL
DPP_STATUS dpp_tm_cgavd_move_en_get(u32 dev_id, enum dpp_tm_cgavd_level_e level, u32 *p_en);

DPP_STATUS dpp_tm_cgavd_move_th_set(u32 dev_id, enum dpp_tm_cgavd_level_e level, u32 id, u32 value);

DPP_STATUS dpp_tm_cgavd_move_th_get(u32 dev_id, enum dpp_tm_cgavd_level_e level, u32 id,
				    u32 *p_value);

DPP_STATUS dpp_tm_cgavd_flow_move_profile_get(u32 dev_id, u32 move_profile, u32 *p_th);
#endif
DPP_STATUS dpp_tm_cgavd_port_share_th_get(u32 dev_id, u32 *p_th);

DPP_STATUS dpp_tm_cgavd_en_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 *p_en);

DPP_STATUS dpp_tm_cgavd_dp_sel_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				   enum dpp_tm_cgavd_dp_sel_e dp_sel);

DPP_STATUS dpp_tm_cgavd_method_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				   enum dpp_tm_cgavd_method_e *p_method);

DPP_STATUS dpp_tm_flow_que_len_get(struct dpp_dev_t *dev, u32 que_id, u32 *p_len);

DPP_STATUS dpp_tm_port_que_len_get(u32 dev_id, u32 pp_id, u32 *pp_len);

DPP_STATUS dpp_tm_sys_que_len_get(u32 dev_id, u32 *sys_len, u32 *sys_protocol_len);

DPP_STATUS dpp_tm_cgavd_td_th_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				  u32 *p_td_th);

DPP_STATUS dpp_tm_cgavd_wred_id_get(u32 dev_id, enum dpp_tm_cgavd_level_e level, u32 id,
				    u32 *p_wred_id);

DPP_STATUS dpp_tm_cgavd_wred_dp_line_para_get(u32 dev_id, enum dpp_tm_cgavd_level_e level,
					      u32 wred_id, u32 dp,
					      struct dpp_tm_wred_dp_line_para_t *p_para);

DPP_STATUS
dpp_tm_cgavd_gred_dp_line_para_set(u32 dev_id, u32 dp, struct dpp_tm_gred_dp_line_para_t *p_para);

DPP_STATUS dpp_tm_cgavd_ladtd_dp_line_para_set(u32 dev_id, u32 dp, u32 td_th);

DPP_STATUS
dpp_tm_cgavd_gred_dp_line_para_get(u32 dev_id, u32 dp, struct dpp_tm_gred_dp_line_para_t *p_para);

DPP_STATUS dpp_tm_cgavd_dyn_th_en_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				      u32 id, u32 *p_en);

DPP_STATUS dpp_tm_cgavd_uniform_th_en_set(struct dpp_dev_t *dev, u32 en);

DPP_STATUS dpp_tm_cgavd_uniform_th_en_get(struct dpp_dev_t *dev, u32 *p_en);

DPP_STATUS dpp_tm_cgavd_uniform_th_set(struct dpp_dev_t *dev, u32 th);

DPP_STATUS dpp_tm_cgavd_uniform_th_get(struct dpp_dev_t *dev, u32 *p_th);

DPP_STATUS dpp_tm_cgavd_q_pri_set(struct dpp_dev_t *dev, u32 q_id, u32 pri);

DPP_STATUS dpp_tm_cgavd_q_map_pp_get(struct dpp_dev_t *dev, u32 q_id, u32 *p_pp_id);

DPP_STATUS dpp_tm_tc_map_flow_get(struct dpp_dev_t *dev, u32 tc_id, u32 *flow_id);

DPP_STATUS dpp_tm_cgavd_imem_omem_get(u32 dev_id, u32 *p_en, u32 *p_mode);

#ifdef ETM_REAL
DPP_STATUS dpp_tm_cgavd_move_th_together_wr(u32 dev_id, enum dpp_tm_cgavd_level_e level,
					    u32 start_id, u32 value, u32 num);
#endif
DPP_STATUS dpp_tm_sys_window_th_set(u32 dev_id, u32 th_h, u32 th_l);

DPP_STATUS dpp_tm_cgavd_cfg_fc_set(u32 dev_id, u32 cgavd_fc);

DPP_STATUS dpp_tm_cgavd_cfg_fc_get(u32 dev_id, u32 *cgavd_fc);

DPP_STATUS dpp_tm_cgavd_cfg_no_fc_set(u32 dev_id, u32 cgavd_no_fc);

DPP_STATUS dpp_tm_cgavd_cfg_no_fc_get(u32 dev_id, u32 *cgavd_no_fc);

DPP_STATUS dpp_tm_cgavd_avg_qlen_return_zero_en_set(u32 dev_id, u32 en);
#endif /*TM_CGAVD */
DPP_STATUS dpp_tm_crdt_ram_init(u32 dev_id);

DPP_STATUS dpp_tm_crdt_sch_type_get(struct dpp_dev_t *dev, u32 se_id, u32 *item_num,
				    u32 *sch_type_num);

DPP_STATUS dpp_tm_crdt_flow_link_wr(struct dpp_dev_t *dev, u32 flow_id,
				    struct dpp_tm_sch_flow_para_t *p_flow_para);

DPP_STATUS
dpp_tm_crdt_flow_link_more_set(struct dpp_dev_t *dev, u32 flow_id_s, u32 flow_id_e, u32 c_linkid,
			       u32 c_weight, u32 c_sp, u32 mode, u32 e_linkid, u32 e_weight,
			       u32 e_sp);

DPP_STATUS dpp_tm_crdt_se_link_wr(struct dpp_dev_t *dev, u32 se_id,
				  struct dpp_tm_sch_se_para_t *p_sch_se_para);

DPP_STATUS
dpp_tm_crdt_se_link_insw_wr(struct dpp_dev_t *dev, u32 se_id,
			    struct dpp_tm_sch_se_para_insw_t *p_sch_se_para_insw);

DPP_STATUS dpp_tm_crdt_flow_link_state_get(struct dpp_dev_t *dev, u32 flow_id, u32 *link_state);

DPP_STATUS dpp_tm_crdt_se_link_state_get(struct dpp_dev_t *dev, u32 se_id, u32 *link_state);

DPP_STATUS dpp_tm_crdt_del_cmd_idle(struct dpp_dev_t *dev);

DPP_STATUS dpp_tm_crdt_del_link_set(struct dpp_dev_t *dev, u32 id);

DPP_STATUS dpp_tm_crdt_pp_para_get(struct dpp_dev_t *dev, u32 pp_id, u32 *p_weight,
				   u32 *p_sp_mapping);

DPP_STATUS dpp_tm_crdt_eir_crs_filter_en_more_set(u32 dev_id, u32 que_id_s, u32 que_id_e, u32 en);

DPP_STATUS dpp_tm_crdt_eir_crs_filter_en_get(u32 dev_id, u32 que_id, u32 *p_en);

DPP_STATUS dpp_tm_crdt_eir_crs_filter_en_get_diag(u32 dev_id, u32 que_id);

DPP_STATUS dpp_tm_shape_para_array_prt(u32 dev_id, u32 para_x, u32 para_y, u32 clear_flag);

DPP_STATUS dpp_tm_shap_crd_grain_set(u32 dev_id, u32 credit_value);

DPP_STATUS dpp_tm_shap_ram_init(u32 dev_id);

DPP_STATUS dpp_tm_shape_flow_db_en_get(struct dpp_dev_t *dev, u32 *db_en, u32 *mode);

DPP_STATUS dpp_tm_shape_token_grain_set(u32 dev_id, u32 token_grain);

DPP_STATUS dpp_tm_shape_token_grain_get(struct dpp_dev_t *dev, u32 *token_grain);

DPP_STATUS dpp_tm_shape_map_table_set(struct dpp_dev_t *dev, u32 id, u32 profile_id);

DPP_STATUS dpp_tm_shape_map_table_get(struct dpp_dev_t *dev, u32 id, u32 *profile_id);

DPP_STATUS dpp_tm_shape_flow_para_get(struct dpp_dev_t *dev, u32 flow_id, u32 mode, u32 *p_para_id,
				      struct dpp_tm_shape_para *p_flow_para_tbl);

DPP_STATUS dpp_etm_shape_flow_para_set(struct dpp_dev_t *dev, u32 flow_id, u32 cir, u32 cbs,
				       u32 db_en, u32 eir, u32 ebs);

DPP_STATUS dpp_tm_shape_se_para_get(struct dpp_dev_t *dev, u32 se_id, u32 mode, u32 *p_para_id,
				    struct dpp_tm_shape_para *p_se_para_tbl);

DPP_STATUS dpp_ftm_shape_se_para_set(u32 dev_id, u32 se_id, u32 pir, u32 pbs, u32 db_en, u32 cir,
				     u32 cbs);

DPP_STATUS dpp_etm_shape_se_para_set(struct dpp_dev_t *dev, u32 se_id, u32 pir, u32 pbs, u32 db_en,
				     u32 cir, u32 cbs);

DPP_STATUS dpp_tm_shape_para_set(struct dpp_dev_t *dev, u32 total_para_id, u32 cir, u32 cbs);

DPP_STATUS dpp_tm_shape_para_get(struct dpp_dev_t *dev, u32 total_para_id,
				 struct dpp_tm_shape_para *p_shap_para_tbl);

DPP_STATUS dpp_tm_shape_token_pp_cfg(u32 dev_id, u32 port_id);

DPP_STATUS dpp_tm_crdt_ackcnt_diag(u32 dev_id, u32 delay_ms);

DPP_STATUS dpp_tm_shape_pp_para_get(struct dpp_dev_t *dev, u32 port_id,
				    struct dpp_tm_shape_pp_para_t *p_para);

DPP_STATUS dpp_tm_qmu_sa_credit_value_set(u32 dev_id, u32 sa_ver_id, u32 sa_credit_value);

DPP_STATUS dpp_tm_qmu_sa_credit_value_get(u32 dev_id, u32 sa_ver_id, u32 *p_sa_credit_value);

DPP_STATUS dpp_tm_qmu_crs_sent_rate_set(u32 dev_id, u32 sent_cyc);

DPP_STATUS dpp_tm_qmu_crs_sent_rate_get(u32 dev_id, u32 *p_sent_cyc);

DPP_STATUS dpp_tm_qmu_crs_filter_en_set(u32 dev_id, u32 en);

DPP_STATUS dpp_tm_qmu_mul_token_gen_num_set(u32 dev_id, u32 token_add_num);

DPP_STATUS dpp_tm_qmu_mul_ack_lb_set(u32 dev_id, u32 q3_lb_control_en, u32 q012_lb_control_en,
				     u32 q3_lb_max_cnt, u32 q012_lb_max_cnt, u32 q3_lb_add_rate,
				     u32 q012_lb_add_rate);

DPP_STATUS dpp_tm_qmu_mcn_lb_sel_set(u32 dev_id, u32 mcn_lb_sel);

DPP_STATUS dpp_tm_qmu_mul_sp_dwrr_set(u32 dev_id, u32 sp_or_dwrr, u32 dwrr_w0, u32 dwrr_w1,
				      u32 dwrr_w2);

DPP_STATUS dpp_tm_qmu_dest_sa_shap_en_set(u32 dev_id, u32 shap_en);

DPP_STATUS dpp_tm_qmu_scan_rate_get(u32 dev_id, u32 *p_scan_en, u32 *p_scan_rate);

DPP_STATUS dpp_tm_qmu_scan_que_range_set(u32 dev_id, u32 first_que, u32 last_que);

DPP_STATUS dpp_tm_qmu_scan_que_range_get(u32 dev_id, u32 *first_que, u32 *last_que);

DPP_STATUS dpp_tm_qmu_qlist_qcfg_clr_done_get(struct dpp_dev_t *dev, u32 *p_clr_done_flag);

DPP_STATUS dpp_tm_qmu_qsch_port_shape_set(struct dpp_dev_t *dev, u32 port_id, u32 token_add_num,
					  u32 token_gap, u32 token_depth, u32 shape_en);

DPP_STATUS dpp_tm_qmu_port_shape_set(struct dpp_dev_t *dev, u32 port_id, u32 token_add_num,
				     u32 token_gap, u32 token_depth, u32 shape_en);

DPP_STATUS dpp_tm_qmu_port_shape_get(struct dpp_dev_t *dev, u32 port_id, u32 *p_token_add_num,
				     u32 *p_token_gap, u32 *p_token_depth, u32 *p_shape_en);

DPP_STATUS dpp_tm_qmu_egress_shape_get(u32 dev_id, u32 port_id, u32 *shape_value, u32 *shape_en);

DPP_STATUS dpp_tm_qmu_spec_qnum_set(struct dpp_dev_t *dev, u32 qnum);

DPP_STATUS dpp_tm_qmu_spec_qnum_get(struct dpp_dev_t *dev, u32 *p_qnum);

DPP_STATUS dpp_tm_qmu_spec_group_set(struct dpp_dev_t *dev, u32 group_num);

DPP_STATUS dpp_tm_qmu_spec_group_get(struct dpp_dev_t *dev, u32 *p_group_num);

DPP_STATUS dpp_tm_qmu_crbal_value_set(u32 dev_id, u32 qnum, u32 value);

DPP_STATUS dpp_tm_qmu_crbal_value_get(u32 dev_id, u32 qnum, u32 *p_value);

DPP_STATUS dpp_tm_qmu_dest_sa_shape_para_set(u32 dev_id, s32 max_value, s32 min_value);

DPP_STATUS dpp_tm_qmu_dest_sa_shape_para_get(u32 dev_id, u32 *p_max_value, u32 *p_min_value);

DPP_STATUS dpp_tm_qmu_spec_q_crs_normal_cnt(u32 dev_id, u32 *p_que_crs_normal_cnt);

DPP_STATUS dpp_tm_qmu_spec_q_crs_off_cnt(u32 dev_id, u32 *p_que_crs_off_cnt);

DPP_STATUS dpp_tm_qmu_init_set(u32 dev_id, u32 case_no);

DPP_STATUS dpp_tm_tmmu_imem_en_get(u32 dev_id, u32 *p_imem_en);

DPP_STATUS dpp_tm_tmmu_ddr_force_rdy_get(u32 dev_id, u32 *p_ddr_force_rdy);

DPP_STATUS dpp_tm_mr_init(u32 dev_id);
DPP_STATUS dpp_tm_asic_init(u32 dev_id, struct dpp_tm_asic_init_info_t *p_tm_asic_init_info);

DPP_STATUS dpp_tm_asic_init_diag(u32 dev_id, u32 blk_size, u32 case_num, u32 imem_omem, u32 mode);

/****************************************************************************
 * : dpp_tm_avg_que_len_get
 * :
 * : dev_id:
 * @param   tm_type   0-ETM,1-FTM
 *           cgavd_level: ，0:，1:，2:
 *           que_id: 。
 * : p_avg_len: ，BLOCK。
 *   : DPP_OK-，DPP_ERR-
 * :
 * author  cy      @date  2015/06/29
 *****************************************************************************
 */
DPP_STATUS dpp_tm_avg_que_len_get(u32 dev_id, enum dpp_tm_cgavd_level_e cgavd_level, u32 que_id,
				  u32 *p_avg_len);

DPP_STATUS dpp_tm_cgavd_wred_pke_len_calc_sign_get(u32 dev_id, u32 *p_flag);

DPP_STATUS dpp_tm_cgavd_cfg_mode_set(struct dpp_dev_t *dev, u32 mode);

DPP_STATUS dpp_tm_cgavd_cfg_mode_get(struct dpp_dev_t *dev, u32 *p_mode);

DPP_STATUS dpp_tm_cgavd_td_byte_block_th_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					     u32 id, u32 byte_block_th);

DPP_STATUS dpp_tm_cgavd_td_byte_block_th_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					     u32 id, u32 *p_byte_block_th);

DPP_STATUS
dpp_tm_cgavd_uniform_byte_block_th_set(struct dpp_dev_t *dev, u32 byte_block_uni_th);

DPP_STATUS
dpp_tm_cgavd_uniform_byte_block_th_get(struct dpp_dev_t *dev, u32 *p_byte_block_uni_th);

/***********TM CPU Begin*************/
DPP_STATUS dpp_tm_glb_mgr_set(u32 dev_id, u32 size, u8 *p_data_buff);

DPP_STATUS dpp_tm_glb_mgr_get(u32 dev_id, u32 *p_flag, u32 *p_size, u8 **pp_data_buff);

DPP_STATUS dpp_tm_glb_size_get(u32 dev_id, u32 *p_size);

DPP_STATUS dpp_tm_credit_value_set(u32 dev_id, u32 credit_value);

DPP_STATUS
dpp_tm_shape_flow_para_array_get(struct dpp_dev_t *dev, u32 flow_id, u32 mode,
				 struct dpp_tm_shape_para *p_flow_para_tbl);

#endif
