/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_ETM_REG_H_
#define _DPP_ETM_REG_H_
struct dpp_etm_cfgmt_cpu_check_reg_t {
	u32 cpu_check_reg;
};

struct dpp_etm_cfgmt_cfgmt_blksize_t {
	u32 cfgmt_blksize;
};

struct dpp_etm_cfgmt_reg_int_state_reg_t {
	u32 shap_int;
	u32 crdt_int;
	u32 mmu_int;
	u32 qmu_int;
	u32 cgavd_int;
	u32 olif_int;
	u32 cfgmt_int_buf;
};

struct dpp_etm_cfgmt_reg_int_mask_reg_t {
	u32 shap_int_mask;
	u32 crdt_int_mask;
	u32 tmmu_int_mask;
	u32 qmu_int_mask;
	u32 cgavd_int_mask;
	u32 olif_int_mask;
	u32 cfgmt_int_buf_mask;
};

struct dpp_etm_cfgmt_timeout_limit_t {
	u32 timeout_limit;
};

struct dpp_etm_cfgmt_subsystem_rdy_reg_t {
	u32 olif_rdy;
	u32 qmu_rdy;
	u32 cgavd_rdy;
	u32 tmmu_rdy;
	u32 shap_rdy;
	u32 crdt_rdy;
};

struct dpp_etm_cfgmt_subsystem_en_reg_t {
	u32 subsystem_en_buf_31_28;
	u32 subsystem_en_buf_25_0;
};

struct dpp_etm_cfgmt_cfgmt_int_reg_t {
	u32 cfgmt_int_buf;
};

struct dpp_etm_cfgmt_qmu_work_mode_t {
	u32 qmu_work_mode;
};

struct dpp_etm_cfgmt_cfgmt_ddr_attach_t {
	u32 cfgmt_ddr_attach;
};

struct dpp_etm_cfgmt_cnt_mode_reg_t {
	u32 cfgmt_fc_count_mode;
	u32 cfgmt_count_rd_mode;
	u32 cfgmt_count_overflow_mode;
};

struct dpp_etm_cfgmt_clkgate_en_t {
	u32 clkgate_en;
};

struct dpp_etm_cfgmt_softrst_en_t {
	u32 softrst_en;
};

struct dpp_etm_olif_imem_prog_full_t {
	u32 imem_prog_full_assert;
	u32 imem_prog_full_negate;
};

struct dpp_etm_olif_qmu_para_prog_full_t {
	u32 qmu_para_prog_full_assert;
	u32 qmu_para_prog_full_negate;
};

struct dpp_etm_olif_olif_int_mask_t {
	u32 emem_dat_sop_err_mask;
	u32 emem_dat_eop_err_mask;
	u32 imem_dat_sop_err_mask;
	u32 imem_dat_eop_err_mask;
	u32 crcram_parity_err_mask;
	u32 emem_fifo_ecc_mask;
	u32 imem_fifo_ecc_mask;
	u32 emem_fifo_ovf_mask;
	u32 emem_fifo_udf_mask;
	u32 imem_fifo_ovf_mask;
	u32 imem_fifo_udf_mask;
	u32 para_fifo_ecc_mask;
	u32 para_fifo_ovf_mask;
	u32 para_fifo_udf_mask;
	u32 itmh_ecc_single_err_mask;
	u32 itmh_ecc_double_err_mask;
	u32 order_fifo_parity_err_mask;
	u32 order_fifo_ovf_mask;
	u32 order_fifo_udf_mask;
};

struct dpp_etm_olif_itmhram_parity_err_2_int_t {
	u32 emem_dat_sop_err;
	u32 emem_dat_eop_err;
	u32 imem_dat_sop_err;
	u32 imem_dat_eop_err;
	u32 crcram_parity_err_1_int;
	u32 emem_fifo_ecc_single_err_int;
	u32 emem_fifo_ecc_double_err_int;
	u32 imem_fifo_ecc_single_err_int;
	u32 imem_fifo_ecc_double_err_int;
	u32 emem_fifo_ovf_int;
	u32 emem_fifo_udf_int;
	u32 imem_fifo_ovf_int;
	u32 imem_fifo_udf_int;
	u32 para_fifo_ecc_single_err_int;
	u32 para_fifo_ecc_double_err_int;
	u32 para_fifo_ovf_int;
	u32 para_fifo_udf_int;
	u32 itmh_ecc_single_err_int;
	u32 itmh_ecc_double_err_int;
	u32 order_fifo_parity_err_int;
	u32 order_fifo_ovf_int;
	u32 order_fifo_udf_int;
};

struct dpp_etm_olif_lif0_port_rdy_mask_h_t {
	u32 lif0_port_rdy_mask_h;
};

struct dpp_etm_olif_lif0_port_rdy_mask_l_t {
	u32 lif0_port_rdy_mask_l;
};

struct dpp_etm_olif_lif0_port_rdy_cfg_h_t {
	u32 lif0_port_rdy_cfg_h;
};

struct dpp_etm_olif_lif0_port_rdy_cfg_l_t {
	u32 lif0_port_rdy_cfg_l;
};

struct dpp_etm_olif_lif0_link_rdy_mask_cfg_t {
	u32 lif0_link_rdy_mask;
	u32 lif0_link_rdy_cfg;
};

struct dpp_etm_olif_tm_lif_stat_cfg_t {
	u32 all_or_by_port;
	u32 i_or_e_sel;
	u32 port_or_dest_id_sel;
	u32 port_dest_id;
};

struct dpp_etm_olif_tm_lif_sop_stat_t {
	u32 tm_lif_sop_stat;
};

struct dpp_etm_olif_tm_lif_eop_stat_t {
	u32 tm_lif_eop_stat;
};

struct dpp_etm_olif_tm_lif_vld_stat_t {
	u32 tm_lif_vld_stat;
};

struct dpp_etm_cgavd_prog_full_assert_cfg_t {
	u32 prog_full_assert_cfg;
	u32 prog_full_negate_cfg;
};

struct dpp_etm_cgavd_cgavd_int_t {
	u32 cgavd_int;
};

struct dpp_etm_cgavd_cgavd_ram_err_t {
	u32 flow_qnum_intb;
	u32 flow_qnum_inta;
	u32 pp_qlen_inta;
	u32 pp_qlen_intb;
	u32 pp_tdth_int;
	u32 flow_tdth_inta;
	u32 flow_tdth_intb;
	u32 flow_qlen_inta;
	u32 flow_qlen_intb;
	u32 qmu_cgavd_fifo_uv_int;
	u32 qmu_cgavd_fifo_ov_int;
	u32 pds_deal_fifo_ov_int;
	u32 pds_deal_fifo_uv_int;
};

struct dpp_etm_cgavd_cgavd_int_mask_t {
	u32 cgavd_int_mask;
};

struct dpp_etm_cgavd_cgavd_ram_err_int_mask_t {
	u32 flow_qnum_inta_mask;
	u32 flow_qnum_intb_mask;
	u32 pp_qlen_inta_mask;
	u32 pp_qlen_intb_mask;
	u32 pp_tdth_int_mask;
	u32 flow_tdth_inta_mask;
	u32 flow_tdth_intb_mask;
	u32 flow_qlen_inta_mask;
	u32 flow_qlen_intb_mask;
	u32 qmu_cgavd_fifo_uv_int_mask;
	u32 qmu_cgavd_fifo_ov_int_mask;
	u32 pds_deal_fifo_ov_int_mask;
	u32 pds_deal_fifo_uv_int_mask;
};

struct dpp_etm_cgavd_cfgmt_byte_mode_t {
	u32 cfgmt_byte_mode;
};

struct dpp_etm_cgavd_avg_qlen_return_zero_en_t {
	u32 avg_qlen_return_zero_en;
};

struct dpp_etm_cgavd_flow_wred_q_len_th_t {
	u32 flow_wred_q_len_th;
};

struct dpp_etm_cgavd_flow_wq_t {
	u32 wq_flow;
};

struct dpp_etm_cgavd_flow_wred_max_th_t {
	u32 flow_wred_max_th;
};

struct dpp_etm_cgavd_flow_wred_min_th_t {
	u32 flow_wred_min_th;
};

struct dpp_etm_cgavd_flow_wred_cfg_para_t {
	u32 flow_wred_cfg_para;
};

struct dpp_etm_cgavd_pp_avg_q_len_t {
	u32 pp_avg_q_len;
};

struct dpp_etm_cgavd_pp_td_th_t {
	u32 pp_td_th;
};

struct dpp_etm_cgavd_pp_ca_mtd_t {
	u32 pp_ca_mtd;
};

struct dpp_etm_cgavd_pp_wred_grp_th_en_t {
	u32 pp_wred_grp;
	u32 pp_wred_grp_th_en;
};

struct dpp_etm_cgavd_pp_wred_q_len_th_t {
	u32 pp_wred_q_len_th;
};

struct dpp_etm_cgavd_pp_wq_t {
	u32 wq_pp;
};

struct dpp_etm_cgavd_pp_wred_max_th_t {
	u32 pp_wred_max_th;
};

struct dpp_etm_cgavd_pp_wred_min_th_t {
	u32 pp_wred_min_th;
};

struct dpp_etm_cgavd_pp_cfg_para_t {
	u32 pp_cfg_para;
};

struct dpp_etm_cgavd_sys_avg_q_len_t {
	u32 sys_avg_q_len;
};

struct dpp_etm_cgavd_sys_td_th_t {
	u32 sys_td_th;
};

struct dpp_etm_cgavd_sys_cgavd_metd_t {
	u32 sys_cgavd_metd;
};

struct dpp_etm_cgavd_sys_cfg_q_grp_para_t {
	u32 gred_q_len_th_sys;
};

struct dpp_etm_cgavd_sys_wq_t {
	u32 wq_sys;
};

struct dpp_etm_cgavd_gred_max_th_t {
	u32 gred_max_th;
};

struct dpp_etm_cgavd_gred_mid_th_t {
	u32 gred_mid_th;
};

struct dpp_etm_cgavd_gred_min_th_t {
	u32 gred_min_th;
};

struct dpp_etm_cgavd_gred_cfg_para0_t {
	u32 gred_cfg_para0;
};

struct dpp_etm_cgavd_gred_cfg_para1_t {
	u32 gred_cfg_para1;
};

struct dpp_etm_cgavd_gred_cfg_para2_t {
	u32 gred_cfg_para2;
};

struct dpp_etm_cgavd_sys_window_th_h_t {
	u32 sys_window_th_h;
};

struct dpp_etm_cgavd_sys_window_th_l_t {
	u32 sys_window_th_l;
};

struct dpp_etm_cgavd_amplify_gene0_t {
	u32 amplify_gene0;
};

struct dpp_etm_cgavd_amplify_gene1_t {
	u32 amplify_gene1;
};

struct dpp_etm_cgavd_amplify_gene2_t {
	u32 amplify_gene2;
};

struct dpp_etm_cgavd_amplify_gene3_t {
	u32 amplify_gene3;
};

struct dpp_etm_cgavd_amplify_gene4_t {
	u32 amplify_gene4;
};

struct dpp_etm_cgavd_amplify_gene5_t {
	u32 amplify_gene5;
};

struct dpp_etm_cgavd_amplify_gene6_t {
	u32 amplify_gene6;
};

struct dpp_etm_cgavd_amplify_gene7_t {
	u32 amplify_gene7;
};

struct dpp_etm_cgavd_amplify_gene8_t {
	u32 amplify_gene8;
};

struct dpp_etm_cgavd_amplify_gene9_t {
	u32 amplify_gene9;
};

struct dpp_etm_cgavd_amplify_gene10_t {
	u32 amplify_gene10;
};

struct dpp_etm_cgavd_amplify_gene11_t {
	u32 amplify_gene11;
};

struct dpp_etm_cgavd_amplify_gene12_t {
	u32 amplify_gene12;
};

struct dpp_etm_cgavd_amplify_gene13_t {
	u32 amplify_gene13;
};

struct dpp_etm_cgavd_amplify_gene14_t {
	u32 amplify_gene14;
};

struct dpp_etm_cgavd_amplify_gene15_t {
	u32 amplify_gene15;
};

struct dpp_etm_cgavd_equal_pkt_len_en_t {
	u32 equal_pkt_len_en;
};

struct dpp_etm_cgavd_equal_pkt_len_th0_t {
	u32 equal_pkt_len_th0;
};

struct dpp_etm_cgavd_equal_pkt_len_th1_t {
	u32 equal_pkt_len_th1;
};

struct dpp_etm_cgavd_equal_pkt_len_th2_t {
	u32 equal_pkt_len_th2;
};

struct dpp_etm_cgavd_equal_pkt_len_th3_t {
	u32 equal_pkt_len_th3;
};

struct dpp_etm_cgavd_equal_pkt_len_th4_t {
	u32 equal_pkt_len_th4;
};

struct dpp_etm_cgavd_equal_pkt_len_th5_t {
	u32 equal_pkt_len_th5;
};

struct dpp_etm_cgavd_equal_pkt_len_th6_t {
	u32 equal_pkt_len_th6;
};

struct dpp_etm_cgavd_equal_pkt_len0_t {
	u32 equal_pkt_len0;
};

struct dpp_etm_cgavd_equal_pkt_len1_t {
	u32 equal_pkt_len1;
};

struct dpp_etm_cgavd_equal_pkt_len2_t {
	u32 equal_pkt_len2;
};

struct dpp_etm_cgavd_equal_pkt_len3_t {
	u32 equal_pkt_len3;
};

struct dpp_etm_cgavd_equal_pkt_len4_t {
	u32 equal_pkt_len4;
};

struct dpp_etm_cgavd_equal_pkt_len5_t {
	u32 equal_pkt_len5;
};

struct dpp_etm_cgavd_equal_pkt_len6_t {
	u32 equal_pkt_len6;
};

struct dpp_etm_cgavd_equal_pkt_len7_t {
	u32 equal_pkt_len7;
};

struct dpp_etm_cgavd_flow_cpu_set_avg_len_t {
	u32 flow_cpu_set_avg_len;
};

struct dpp_etm_cgavd_flow_cpu_set_q_len_t {
	u32 flow_cpu_set_q_len;
};

struct dpp_etm_cgavd_pp_cpu_set_avg_q_len_t {
	u32 pp_cpu_set_avg_q_len;
};

struct dpp_etm_cgavd_pp_cpu_set_q_len_t {
	u32 pp_cpu_set_q_len;
};

struct dpp_etm_cgavd_sys_cpu_set_avg_len_t {
	u32 sys_cpu_set_avg_len;
};

struct dpp_etm_cgavd_sys_cpu_set_q_len_t {
	u32 sys_cpu_set_q_len;
};

struct dpp_etm_cgavd_pke_len_calc_sign_t {
	u32 pke_len_calc_sign;
};

struct dpp_etm_cgavd_rd_cpu_or_ram_t {
	u32 cpu_sel_sys_q_len_en;
	u32 cpu_sel_sys_avg_q_len_en;
	u32 cpu_sel_pp_q_len_en;
	u32 cpu_sel_pp_avg_q_len_en;
	u32 cpu_sel_flow_q_len_en;
	u32 cpu_sel_flow_avg_q_len_en;
};

struct dpp_etm_cgavd_q_len_update_disable_t {
	u32 q_len_sys_update_en;
	u32 q_len_pp_update_en;
	u32 q_len_flow_update_en;
};

struct dpp_etm_cgavd_cgavd_dp_sel_t {
	u32 flow_dp_sel_high;
	u32 flow_dp_sel_mid;
	u32 flow_dp_sel_low;
	u32 pp_dp_sel_high;
	u32 pp_dp_sel_mid;
	u32 pp_dp_sel_low;
	u32 sys_dp_sel_high;
	u32 sys_dp_sel_mid;
	u32 sys_dp_sel_low;
};

struct dpp_etm_cgavd_cgavd_sub_en_t {
	u32 cgavd_sa_sub_en;
	u32 cgavd_sys_sub_en;
	u32 cgavd_pp_sub_en;
	u32 cgavd_flow_sub_en;
};

struct dpp_etm_cgavd_default_start_queue_t {
	u32 default_start_queue;
};

struct dpp_etm_cgavd_default_finish_queue_t {
	u32 default_finish_queue;
};

struct dpp_etm_cgavd_protocol_start_queue_t {
	u32 protocol_start_queue;
};

struct dpp_etm_cgavd_protocol_finish_queue_t {
	u32 protocol_finish_queue;
};

struct dpp_etm_cgavd_uniform_td_th_t {
	u32 uniform_td_th;
};

struct dpp_etm_cgavd_uniform_td_th_en_t {
	u32 uniform_td_th_en;
};

struct dpp_etm_cgavd_cgavd_cfg_fc_t {
	u32 cgavd_cfg_fc;
};

struct dpp_etm_cgavd_cgavd_cfg_no_fc_t {
	u32 cgavd_cfg_no_fc;
};

struct dpp_etm_cgavd_cgavd_force_imem_omem_t {
	u32 imem_omem_force_en;
	u32 choose_imem_omem;
};

struct dpp_etm_cgavd_cgavd_sys_q_len_l_t {
	u32 cgavd_sys_q_len_l;
};

struct dpp_etm_cgavd_default_queue_en_t {
	u32 default_queue_en;
};

struct dpp_etm_cgavd_protocol_queue_en_t {
	u32 protocol_queue_en;
};

struct dpp_etm_cgavd_cfg_tc_flowid_dat_t {
	u32 cfg_tc_flowid_dat;
};

struct dpp_etm_cgavd_flow_td_th_t {
	u32 flow_td_th;
};

struct dpp_etm_cgavd_flow_ca_mtd_t {
	u32 flow_ca_mtd;
};

struct dpp_etm_cgavd_flow_dynamic_th_en_t {
	u32 flow_dynamic_th_en;
};

struct dpp_etm_cgavd_pp_num_t {
	u32 pp_num;
};

struct dpp_etm_cgavd_flow_q_len_t {
	u32 flow_q_len;
};

struct dpp_etm_cgavd_flow_wred_grp_t {
	u32 flow_wred_grp;
};

struct dpp_etm_cgavd_flow_avg_q_len_t {
	u32 flow_avg_q_len;
};

struct dpp_etm_cgavd_qos_sign_t {
	u32 qos_sign_flow_cfg_din;
};

struct dpp_etm_cgavd_q_pri_t {
	u32 qpri_flow_cfg_din;
};

struct dpp_etm_cgavd_odma_tm_itmd_rd_low_t {
	u32 odma_tm_itmd_low;
};

struct dpp_etm_cgavd_odma_tm_itmd_rd_mid_t {
	u32 odma_tm_itmd_mid;
};

struct dpp_etm_cgavd_odma_tm_itmd_rd_high_t {
	u32 odma_tm_itmd_high;
};

struct dpp_etm_cgavd_cgavd_stat_pkt_len_t {
	u32 expect_deq_pkt_len;
	u32 expect_enq_pkt_len;
};

struct dpp_etm_cgavd_cgavd_stat_qnum_t {
	u32 cgavd_unexcept_qnum;
	u32 cgavd_except_qnum;
};

struct dpp_etm_cgavd_cgavd_stat_dp_t {
	u32 cgavd_stat_dp;
};

struct dpp_etm_cgavd_flow_num0_t {
	u32 flow_num0;
};

struct dpp_etm_cgavd_flow_num1_t {
	u32 flow_num1;
};

struct dpp_etm_cgavd_flow_num2_t {
	u32 flow_num2;
};

struct dpp_etm_cgavd_flow_num3_t {
	u32 flow_num3;
};

struct dpp_etm_cgavd_flow_num4_t {
	u32 flow_num4;
};

struct dpp_etm_cgavd_flow0_imem_cnt_t {
	u32 flow0_imem_cnt;
};

struct dpp_etm_cgavd_flow1_imem_cnt_t {
	u32 flow1_imem_cnt;
};

struct dpp_etm_cgavd_flow2_imem_cnt_t {
	u32 flow2_imem_cnt;
};

struct dpp_etm_cgavd_flow3_imem_cnt_t {
	u32 flow3_imem_cnt;
};

struct dpp_etm_cgavd_flow4_imem_cnt_t {
	u32 flow4_imem_cnt;
};

struct dpp_etm_cgavd_flow0_drop_cnt_t {
	u32 flow0_drop_cnt;
};

struct dpp_etm_cgavd_flow1_drop_cnt_t {
	u32 flow1_drop_cnt;
};

struct dpp_etm_cgavd_flow2_drop_cnt_t {
	u32 flow2_drop_cnt;
};

struct dpp_etm_cgavd_flow3_drop_cnt_t {
	u32 flow3_drop_cnt;
};

struct dpp_etm_cgavd_flow4_drop_cnt_t {
	u32 flow4_drop_cnt;
};

struct dpp_etm_cgavd_fc_count_mode_t {
	u32 fc_count_mode;
};

struct dpp_etm_cgavd_qmu_cgavd_fc_num_t {
	u32 qmu_cgavd_fc_state;
	u32 qmu_cgavd_fc_num;
};

struct dpp_etm_cgavd_cgavd_odma_fc_num_t {
	u32 cgavd_lif_fc_state;
	u32 cgavd_lif_fc_num;
};

struct dpp_etm_cgavd_cfg_offset_t {
	u32 cfg_offset;
};

struct dpp_etm_tmmu_tmmu_init_done_t {
	u32 tmmu_init_done;
};

struct dpp_etm_tmmu_tmmu_int_mask_1_t {
	u32 imem_enq_rd_fifo_full_mask;
	u32 imem_enq_rd_fifo_overflow_mask;
	u32 imem_enq_rd_fifo_underflow_mask;
	u32 imem_enq_drop_fifo_full_mask;
	u32 imem_enq_drop_fifo_overflow_mask;
	u32 imem_enq_drop_fifo_underflow_mask;
	u32 imem_deq_rd_fifo_full_mask;
	u32 imem_deq_rd_fifo_overflow_mask;
	u32 imem_deq_rd_fifo_underflow_mask;
	u32 imem_deq_drop_fifo_full_mask;
	u32 imem_deq_drop_fifo_overflow_mask;
	u32 imem_deq_drop_fifo_underflow_mask;
	u32 dma_data_fifo_full_mask;
	u32 dma_data_fifo_overflow_mask;
	u32 dma_data_fifo_underflow_mask;
	u32 wr_cmd_fifo_full_mask;
	u32 wr_cmd_fifo_overflow_mask;
	u32 wr_cmd_fifo_underflow_mask;
	u32 cached_pd_fifo_full_mask;
	u32 cached_pd_fifo_overflow_mask;
	u32 cached_pd_fifo_underflow_mask;
	u32 emem_pd_fifo_full_mask;
	u32 emem_pd_fifo_overflow_mask;
	u32 emem_pd_fifo_underflow_mask;
	u32 pd_order_fifo_full_mask;
	u32 pd_order_fifo_overflow_mask;
	u32 pd_order_fifo_underflow_mask;
};

struct dpp_etm_tmmu_tmmu_int_mask_2_t {
	u32 dma_data_fifo_parity_err_mask;
	u32 imem_enq_rd_fifo_ecc_single_err_mask;
	u32 imem_enq_rd_fifo_ecc_double_err_mask;
	u32 imem_enq_drop_fifo_ecc_single_err_mask;
	u32 imem_enq_drop_fifo_ecc_double_err_mask;
	u32 imem_deq_rd_fifo_ecc_single_err_mask;
	u32 imem_deq_rd_fifo_ecc_double_err_mask;
	u32 imem_deq_drop_fifo_ecc_single_err_mask;
	u32 imem_deq_drop_fifo_ecc_double_err_mask;
	u32 wr_cmd_fifo_ecc_single_err_mask;
	u32 wr_cmd_fifo_ecc_double_err_mask;
	u32 pd_cache_ram_ecc_single_err_mask;
	u32 pd_cache_ram_ecc_double_err_mask;
	u32 cached_pd_fifo_ecc_single_err_mask;
	u32 cached_pd_fifo_ecc_double_err_mask;
	u32 emem_pd_fifo_ecc_single_err_mask;
	u32 emem_pd_fifo_ecc_double_err_mask;
};

struct dpp_etm_tmmu_cfgmt_tm_pure_imem_en_t {
	u32 cfgmt_tm_pure_imem_en;
};

struct dpp_etm_tmmu_cfgmt_force_ddr_rdy_cfg_t {
	u32 cfgmt_force_ddr_rdy_cfg;
};

struct dpp_etm_tmmu_pd_order_fifo_aful_th_t {
	u32 pd_order_fifo_aful_th;
};

struct dpp_etm_tmmu_cached_pd_fifo_aful_th_t {
	u32 cached_pd_fifo_aful_th;
};

struct dpp_etm_tmmu_wr_cmd_fifo_aful_th_t {
	u32 wr_cmd_fifo_aful_th;
};

struct dpp_etm_tmmu_imem_enq_rd_fifo_aful_th_t {
	u32 imem_enq_rd_fifo_aful_th;
};

struct dpp_etm_tmmu_imem_enq_drop_fifo_aful_th_t {
	u32 imem_enq_drop_fifo_aful_th;
};

struct dpp_etm_tmmu_imem_deq_drop_fifo_aful_th_t {
	u32 imem_deq_drop_fifo_aful_th;
};

struct dpp_etm_tmmu_imem_deq_rd_fifo_aful_th_t {
	u32 imem_deq_rd_fifo_aful_th;
};

struct dpp_etm_tmmu_tmmu_states_1_t {
	u32 imem_enq_rd_fifo_full;
	u32 imem_enq_rd_fifo_overflow;
	u32 imem_enq_rd_fifo_underflow;
	u32 imem_enq_drop_fifo_full;
	u32 imem_enq_drop_fifo_overflow;
	u32 imem_enq_drop_fifo_underflow;
	u32 imem_deq_rd_fifo_full;
	u32 imem_deq_rd_fifo_overflow;
	u32 imem_deq_rd_fifo_underflow;
	u32 imem_deq_drop_fifo_full;
	u32 imem_deq_drop_fifo_overflow;
	u32 imem_deq_drop_fifo_underflow;
	u32 dma_data_fifo_full;
	u32 dma_data_fifo_overflow;
	u32 dma_data_fifo_underflow;
	u32 wr_cmd_fifo_full;
	u32 wr_cmd_fifo_overflow;
	u32 wr_cmd_fifo_underflow;
	u32 cached_pd_fifo_full;
	u32 cached_pd_fifo_overflow;
	u32 cached_pd_fifo_underflow;
	u32 emem_pd_fifo_full;
	u32 emem_pd_fifo_overflow;
	u32 emem_pd_fifo_underflow;
	u32 pd_order_fifo_full;
	u32 pd_order_fifo_overflow;
	u32 pd_order_fifo_underflow;
};

struct dpp_etm_tmmu_tmmu_states_2_t {
	u32 dma_data_fifo_parity_err;
	u32 imem_enq_rd_fifo_ecc_single_err;
	u32 imem_enq_rd_fifo_ecc_double_err;
	u32 imem_enq_drop_fifo_ecc_single_err;
	u32 imem_enq_drop_fifo_ecc_double_err;
	u32 imem_deq_rd_fifo_ecc_single_err;
	u32 imem_deq_rd_fifo_ecc_double_err;
	u32 imem_deq_drop_fifo_ecc_single_err;
	u32 imem_deq_drop_fifo_ecc_double_err;
	u32 wr_cmd_fifo_ecc_single_err;
	u32 wr_cmd_fifo_ecc_double_err;
	u32 pd_cache_ram_ecc_single_err;
	u32 pd_cache_ram_ecc_double_err;
	u32 cached_pd_fifo_ecc_single_err;
	u32 cached_pd_fifo_ecc_double_err;
	u32 emem_pd_fifo_ecc_single_err;
	u32 emem_pd_fifo_ecc_double_err;
};

struct dpp_etm_shap_shap_ind_cmd_t {
	u32 rd;
	u32 mem_id;
	u32 addr;
};

struct dpp_etm_shap_shap_ind_sta_t {
	u32 indirectaccessdone;
};

struct dpp_etm_shap_shap_ind_data0_t {
	u32 indirectdata0;
};

struct dpp_etm_shap_shap_ind_data1_t {
	u32 indirectdata1;
};

struct dpp_etm_shap_full_threshold_t {
	u32 full_threshold;
};

struct dpp_etm_shap_empty_threshold_t {
	u32 empty_threshold;
};

struct dpp_etm_shap_shap_sta_init_cfg_t {
	u32 sta_ram_init_done;
	u32 sta_ram_init_en;
};

struct dpp_etm_shap_shap_cfg_init_cfg_t {
	u32 cfg_ram_init_done;
	u32 cfg_ram_init_en;
};

struct dpp_etm_shap_token_mode_switch_t {
	u32 token_mode_switch;
};

struct dpp_etm_shap_token_grain_t {
	u32 token_grain;
};

struct dpp_etm_shap_crd_grain_t {
	u32 crd_grain;
};

struct dpp_etm_shap_shap_stat_ctrl_t {
	u32 shap_stat_ctrl;
};

struct dpp_etm_shap_token_stat_id_t {
	u32 token_stat_id;
};

struct dpp_etm_shap_token_stat_t {
	u32 token_stat;
};

struct dpp_etm_shap_shap_stat_clk_cnt_t {
	u32 shap_stat_clk_cnt;
};

struct dpp_etm_shap_shap_bucket_map_tbl_t {
	u32 shap_map;
};

struct dpp_etm_shap_bkt_para_tbl_t {
	u32 bucket_depth;
	u32 bucket_rate;
};

struct dpp_etm_crdt_credit_en_t {
	u32 credit_en;
};

struct dpp_etm_crdt_crt_inter1_t {
	u32 crd_inter1;
};

struct dpp_etm_crdt_db_token_t {
	u32 db_token;
};

struct dpp_etm_crdt_crs_flt_cfg_t {
	u32 crs_flt_cfg;
};

struct dpp_etm_crdt_th_sp_t {
	u32 th_sp;
};

struct dpp_etm_crdt_th_wfq_fq_t {
	u32 th_fq;
	u32 th_wfq;
};

struct dpp_etm_crdt_th_wfq2_fq2_t {
	u32 th_fq2;
	u32 th_wfq2;
};

struct dpp_etm_crdt_th_wfq4_fq4_t {
	u32 th_fq4;
	u32 th_wfq4;
};

struct dpp_etm_crdt_cfg_state_t {
	u32 cfg_state;
};

struct dpp_etm_crdt_crdt_ind_cmd_t {
	u32 rd;
	u32 mem_id;
	u32 addr;
};

struct dpp_etm_crdt_crdt_ind_sta_t {
	u32 indirectaccessdone;
};

struct dpp_etm_crdt_crdt_ind_data0_t {
	u32 indirectdata0;
};

struct dpp_etm_crdt_crdt_ind_data1_t {
	u32 indirectdata1;
};

struct dpp_etm_crdt_crdt_state_t {
	u32 crdt_int;
	u32 crdt_rdy;
};

struct dpp_etm_crdt_stat_que_id_0_t {
	u32 stat_que_id_0;
};

struct dpp_etm_crdt_stat_que_id_1_t {
	u32 stat_que_id_1;
};

struct dpp_etm_crdt_stat_que_id_2_t {
	u32 stat_que_id_2;
};

struct dpp_etm_crdt_stat_que_id_3_t {
	u32 stat_que_id_3;
};

struct dpp_etm_crdt_stat_que_id_4_t {
	u32 stat_que_id_4;
};

struct dpp_etm_crdt_stat_que_id_5_t {
	u32 stat_que_id_5;
};

struct dpp_etm_crdt_stat_que_id_6_t {
	u32 stat_que_id_6;
};

struct dpp_etm_crdt_stat_que_id_7_t {
	u32 stat_que_id_7;
};

struct dpp_etm_crdt_stat_que_id_8_t {
	u32 stat_que_id_8;
};

struct dpp_etm_crdt_stat_que_id_9_t {
	u32 stat_que_id_9;
};

struct dpp_etm_crdt_stat_que_id_10_t {
	u32 stat_que_id_10;
};

struct dpp_etm_crdt_stat_que_id_11_t {
	u32 stat_que_id_11;
};

struct dpp_etm_crdt_stat_que_id_12_t {
	u32 stat_que_id_12;
};

struct dpp_etm_crdt_stat_que_id_13_t {
	u32 stat_que_id_13;
};

struct dpp_etm_crdt_stat_que_id_14_t {
	u32 stat_que_id_14;
};

struct dpp_etm_crdt_stat_que_id_15_t {
	u32 stat_que_id_15;
};

struct dpp_etm_crdt_stat_que_credit_t {
	u32 stat_que_credit_cnt;
};

struct dpp_etm_crdt_crdt_cfg_ram_init_t {
	u32 cfg_ram_init_done;
	u32 cfg_ram_init_en;
};

struct dpp_etm_crdt_crdt_sta_ram_init_t {
	u32 sta_ram_init_done;
	u32 sta_ram_init_en;
};

struct dpp_etm_crdt_crs_que_id_t {
	u32 crs_que_id;
};

struct dpp_etm_crdt_qmu_crs_end_state_t {
	u32 qmu_crs_end_state;
};

struct dpp_etm_crdt_shap_rdy_t {
	u32 shap_rdy;
};

struct dpp_etm_crdt_shap_int_reg_t {
	u32 pp_c_token_min_int;
};

struct dpp_etm_crdt_shap_int_mask_reg_t {
	u32 pp_c_token_min_int_mask;
};

struct dpp_etm_crdt_token_state_almost_empty_th_t {
	u32 token_state_almost_empty_th;
};

struct dpp_etm_crdt_token_state_empty_th_t {
	u32 token_state_empty_th;
};

struct dpp_etm_crdt_full_th_t {
	u32 token_state_full_th;
};

struct dpp_etm_crdt_pp_c_level_shap_en_t {
	u32 pp_c_level_shap_en;
};

struct dpp_etm_crdt_enq_token_th_t {
	u32 enq_token_th;
};

struct dpp_etm_crdt_pp_tokenq_level1_qstate_weight_cir_t {
	u32 pp_pp_q_state_cir;
	u32 pp_pp_q_weight_wfq_l1_cir;
};

struct dpp_etm_crdt_pp_idle_weight_level1_cir_t {
	u32 pp_idle_q_weight_wfq_l1_cir;
};

struct dpp_etm_crdt_rci_grade_th_0_cfg_t {
	u32 rci_grade_th_0_cfg;
};

struct dpp_etm_crdt_rci_grade_th_1_cfg_t {
	u32 rci_grade_th_1_cfg;
};

struct dpp_etm_crdt_rci_grade_th_2_cfg_t {
	u32 rci_grade_th_2_cfg;
};

struct dpp_etm_crdt_rci_grade_th_3_cfg_t {
	u32 rci_grade_th_3_cfg;
};

struct dpp_etm_crdt_rci_grade_th_4_cfg_t {
	u32 rci_grade_th_4_cfg;
};

struct dpp_etm_crdt_rci_grade_th_5_cfg_t {
	u32 rci_grade_th_5_cfg;
};

struct dpp_etm_crdt_rci_grade_th_6_cfg_t {
	u32 rci_grade_th_6_cfg;
};

struct dpp_etm_crdt_flow_del_cmd_t {
	u32 flow_del_busy;
	u32 flow_alt_cmd;
	u32 flow_alt_ind;
};

struct dpp_etm_crdt_cnt_clr_t {
	u32 cnt_clr;
};

struct dpp_etm_crdt_crdt_int_bus_t {
	u32 ldstr_fifo15_ovf_int;
	u32 ldstr_fifo14_ovf_int;
	u32 ldstr_fifo13_ovf_int;
	u32 ldstr_fifo12_ovf_int;
	u32 ldstr_fifo11_ovf_int;
	u32 ldstr_fifo10_ovf_int;
	u32 ldstr_fifo9_ovf_int;
	u32 ldstr_fifo8_ovf_int;
	u32 ldstr_fifo7_ovf_int;
	u32 ldstr_fifo6_ovf_int;
	u32 ldstr_fifo5_ovf_int;
	u32 ldstr_fifo4_ovf_int;
	u32 ldstr_fifo3_ovf_int;
	u32 ldstr_fifo2_ovf_int;
	u32 ldstr_fifo1_ovf_int;
	u32 ldstr_fifo0_ovf_int;
	u32 cfg_del_err_int;
	u32 flwin_secrs_fifo_ovf_int;
	u32 flwin_voqcrs_fifo_ovf_int;
};

struct dpp_etm_crdt_crdt_int_mask_t {
	u32 crdt_int_mask;
};

struct dpp_etm_crdt_cfg_weight_together_t {
	u32 cfg_weight_together;
};

struct dpp_etm_crdt_weight_t {
	u32 c_weight;
	u32 e_weight;
};

struct dpp_etm_crdt_dev_sp_state_t {
	u32 dev_sp_state;
};

struct dpp_etm_crdt_dev_crs_t {
	u32 dev_crs;
};

struct dpp_etm_crdt_congest_token_disable_31_0_t {
	u32 congest_token_disable_31_0;
};

struct dpp_etm_crdt_congest_token_disable_63_32_t {
	u32 congest_token_disable_63_32;
};

struct dpp_etm_crdt_crdt_interval_en_cfg_t {
	u32 crdt_interval_en;
};

struct dpp_etm_crdt_q_token_staue_cfg_t {
	u32 test_token_q_id;
};

struct dpp_etm_crdt_q_token_dist_cnt_t {
	u32 q_token_dist_counter;
};

struct dpp_etm_crdt_q_token_dec_cnt_t {
	u32 q_token_dec_counter;
};

struct dpp_etm_crdt_pp_weight_ram_t {
	u32 pp_c_weight;
};

struct dpp_etm_crdt_pp_cbs_shape_en_ram_t {
	u32 pp_cbs;
	u32 pp_c_shap_en;
};

struct dpp_etm_crdt_pp_next_pc_q_state_ram_t {
	u32 pp_next_pc;
	u32 pp_token_num;
	u32 pp_q_state;
};

struct dpp_etm_crdt_dev_interval_t {
	u32 dev_interval;
};

struct dpp_etm_crdt_dev_wfq_cnt_t {
	u32 dev_wfq_cnt;
};

struct dpp_etm_crdt_dev_wfq_state_t {
	u32 dev_wfq_state;
};

struct dpp_etm_crdt_dev_active_head_ptr_t {
	u32 dev_active_head_ptr;
};

struct dpp_etm_crdt_dev_active_tail_ptr_t {
	u32 dev_active_tail_ptr;
};

struct dpp_etm_crdt_dev_unactive_head_ptr_t {
	u32 dev_unactive_head_ptr;
};

struct dpp_etm_crdt_dev_unactive_tail_ptr_t {
	u32 dev_unactive_tail_ptr;
};

struct dpp_etm_crdt_pp_weight_t {
	u32 pp_weight;
};

struct dpp_etm_crdt_pp_que_state_t {
	u32 pp_enque_flag;
	u32 pp_cir;
	u32 pp_congest_cir;
	u32 pp_crs;
	u32 dev_sp;
};

struct dpp_etm_crdt_pp_next_ptr_t {
	u32 pp_next_ptr;
};

struct dpp_etm_crdt_pp_cfg_t {
	u32 pp_cfg;
};

struct dpp_etm_crdt_pp_up_ptr_t {
	u32 pp_up_ptr;
};

struct dpp_etm_crdt_credit_drop_num_t {
	u32 credit_drop_num;
};

struct dpp_etm_crdt_se_id_lv0_t {
	u32 se_id_out_lv0;
};

struct dpp_etm_crdt_se_id_lv1_t {
	u32 se_id_out_lv1;
};

struct dpp_etm_crdt_se_id_lv2_t {
	u32 se_id_out_lv2;
};

struct dpp_etm_crdt_se_id_lv3_t {
	u32 se_id_out_lv3;
};

struct dpp_etm_crdt_se_id_lv4_t {
	u32 se_id_out_lv4;
};

struct dpp_etm_crdt_que_id_t {
	u32 que_id_out;
};

struct dpp_etm_crdt_se_info_lv0_t {
	u32 se_shape_lv0;
	u32 se_ins_out_lv0;
	u32 se_state_out_lv0;
	u32 se_new_state_out_lv0;
};

struct dpp_etm_crdt_se_info_lv1_t {
	u32 se_shape_lv1;
	u32 se_ins_out_lv1;
	u32 se_state_out_lv1;
	u32 se_new_state_out_lv1;
};

struct dpp_etm_crdt_se_info_lv2_t {
	u32 se_shape_lv2;
	u32 se_ins_out_lv2;
	u32 se_state_out_lv2;
	u32 se_new_state_out_lv2;
};

struct dpp_etm_crdt_se_info_lv3_t {
	u32 se_shape_lv3;
	u32 se_ins_out_lv3;
	u32 se_state_out_lv3;
	u32 se_new_state_out_lv3;
};

struct dpp_etm_crdt_se_info_lv4_t {
	u32 se_shape_lv4;
	u32 se_ins_out_lv4;
	u32 se_state_out_lv4;
	u32 se_new_state_out_lv4;
};

struct dpp_etm_crdt_que_state_t {
	u32 que_state_out;
};

struct dpp_etm_crdt_eir_off_in_advance_t {
	u32 eir_crs_filter;
};

struct dpp_etm_crdt_double_level_shap_prevent_t {
	u32 double_level_shap_prevent;
};

struct dpp_etm_crdt_add_store_cycle_t {
	u32 add_store_cycle;
};

struct dpp_etm_crdt_tflag2_wr_flag_sum_t {
	u32 tflag2_wr_flag_sum;
};

struct dpp_etm_crdt_flowque_para_tbl_t {
	u32 flowque_link;
	u32 flowque_w;
	u32 flowque_pri;
};

struct dpp_etm_crdt_se_para_tbl_t {
	u32 se_insw;
	u32 se_link;
	u32 cp_token_en;
	u32 se_w;
	u32 se_pri;
};

struct dpp_etm_crdt_flowque_ins_tbl_t {
	u32 flowque_ins;
};

struct dpp_etm_crdt_se_ins_tbl_t {
	u32 se_ins_flag;
	u32 se_ins_priority;
};

struct dpp_etm_crdt_eir_crs_filter_tbl_t {
	u32 eir_crs_filter;
};

struct dpp_etm_qmu_qcfg_qlist_cfg_done_t {
	u32 qcfg_qlist_cfg_done;
};

struct dpp_etm_qmu_qcfg_qsch_credit_value_t {
	u32 qcfg_qsch_credit_value;
};

struct dpp_etm_qmu_qcfg_qsch_crbal_init_value_t {
	u32 qcfg_qsch_crbal_init_value;
};

struct dpp_etm_qmu_qcfg_qsch_crbal_init_mask_t {
	u32 qcfg_qsch_crbal_init_mask;
};

struct dpp_etm_qmu_cmdsch_rd_cmd_aful_th_t {
	u32 cmdsch_rd_cmd_aful_th;
};

struct dpp_etm_qmu_cfg_port_fc_interval_t {
	u32 cfg_port_fc_interval;
};

struct dpp_etm_qmu_qcfg_csch_aged_cfg_t {
	u32 qcfg_csch_aged_cfg;
};

struct dpp_etm_qmu_qcfg_csch_aged_scan_time_t {
	u32 qcfg_csch_aged_scan_time;
};

struct dpp_etm_qmu_qcfg_qmu_qlist_state_query_t {
	u32 pkt_age_req_fifo_afull;
	u32 rd_release_fwft_afull;
	u32 drop_imem_fwft_afull;
	u32 pkt_age_req_fifo_empty;
	u32 rd_release_fwft_empty;
	u32 drop_imem_fwft_empty;
	u32 mmu_qmu_sop_rd_rdy;
	u32 big_fifo_empty;
	u32 qmu_mmu_rd_release_rdy;
	u32 xsw_qmu_crs_rdy;
	u32 mmu_qmu_rdy;
	u32 mmu_ql_wr_rdy;
	u32 mmu_ql_rd_rdy;
	u32 csw_ql_rdy;
	u32 ql_init_done;
	u32 free_addr_ready;
	u32 bank_group_afull;
	u32 pds_fwft_empty;
	u32 enq_rpt_fwft_afull;
};

struct dpp_etm_qmu_cfgmt_qsch_crbal_drop_en_t {
	u32 cfgmt_qsch_all_crbal_drop_en;
	u32 cfgmt_qsch_crbal_drop_en;
};

struct dpp_etm_qmu_cfgmt_wlist_qnum_fifo_aful_th_t {
	u32 cfgmt_wlist_qnum_fifo_aful_th;
};

struct dpp_etm_qmu_qcfg_csw_pkt_blk_mode_t {
	u32 qcfg_csw_pkt_blk_mode;
};

struct dpp_etm_qmu_qcfg_qlist_ram_init_cancel_t {
	u32 qcfg_qlist_ram_init_cancel;
};

struct dpp_etm_qmu_qcfg_qsch_crbal_transfer_mode_t {
	u32 qcfg_qsch_crbal_transfer_mode;
	u32 qcfg_qsch_crbal_transfer_value;
};

struct dpp_etm_qmu_qcfg_qlist_qclr_interval_t {
	u32 qcfg_qlist_qclr_interval;
};

struct dpp_etm_qmu_qcfg_qsch_qclr_rate_t {
	u32 qcfg_qsch_qclr_rate;
};

struct dpp_etm_qmu_qcfg_qlist_ddr_random_t {
	u32 qcfg_qlist_ddr_random;
};

struct dpp_etm_qmu_cfgmt_qlist_pds_fifo_afull_th_t {
	u32 cfgmt_qlist_pds_fifo_afull_th;
};

struct dpp_etm_qmu_cfgmt_sop_cmd_fifo_afull_th_t {
	u32 cfgmt_sop_cmd_fifo_afull_th;
};

struct dpp_etm_qmu_cfgmt_non_sop_cmd_fifo_afull_th_t {
	u32 cfgmt_non_sop_cmd_fifo_afull_th;
};

struct dpp_etm_qmu_cfgmt_mmu_data_fifo_afull_th_t {
	u32 cfgmt_mmu_data_fifo_afull_th;
};

struct dpp_etm_qmu_qcfg_qlist_bank_ept_th_t {
	u32 qcfg_qlist_bank_ept_th;
};

struct dpp_etm_qmu_random_bypass_en_t {
	u32 random_bypass_en;
};

struct dpp_etm_qmu_cfgmt_crs_spd_bypass_t {
	u32 cfgmt_crs_spd_bypass;
};

struct dpp_etm_qmu_cfgmt_crs_interval_t {
	u32 cfgmt_crs_interval;
};

struct dpp_etm_qmu_cfg_qsch_auto_credit_control_en_t {
	u32 cfg_qsch_auto_credit_control_en;
};

struct dpp_etm_qmu_cfg_qsch_autocrfrstque_t {
	u32 cfg_qsch_autocrfrstque;
};

struct dpp_etm_qmu_cfg_qsch_autocrlastque_t {
	u32 cfg_qsch_autocrlastque;
};

struct dpp_etm_qmu_cfg_qsch_autocreditrate_t {
	u32 cfg_qsch_autocreditrate;
};

struct dpp_etm_qmu_cfg_qsch_scanfrstque_t {
	u32 cfg_qsch_scanfrstque;
};

struct dpp_etm_qmu_cfg_qsch_scanlastque_t {
	u32 cfg_qsch_scanlastque;
};

struct dpp_etm_qmu_cfg_qsch_scanrate_t {
	u32 cfg_qsch_scanrate;
};

struct dpp_etm_qmu_cfg_qsch_scan_en_t {
	u32 cfg_qsch_scan_en;
};

struct dpp_etm_qmu_cfgmt_qsch_rd_credit_fifo_rate_t {
	u32 cfgmt_qsch_rd_credit_fifo_rate;
};

struct dpp_etm_qmu_qcfg_qlist_bdep_t {
	u32 qcfg_qlist_bdep;
};

struct dpp_etm_qmu_qcfg_qlist_bhead_t {
	u32 bank_vld;
	u32 qcfg_qlist_bhead;
};

struct dpp_etm_qmu_qcfg_qlist_btail_t {
	u32 qcfg_qlist_btail;
};

struct dpp_etm_qmu_qcfg_qsch_shap_param_t {
	u32 qcfg_qsch_shap_en;
	u32 qcfg_qsch_shap_param1;
	u32 qcfg_qsch_shap_param2;
};

struct dpp_etm_qmu_qcfg_qsch_shap_token_t {
	u32 qcfg_qsch_shap_token;
};

struct dpp_etm_qmu_qcfg_qsch_shap_offset_t {
	u32 qcfg_qsch_shap_offset;
};

struct dpp_etm_qmu_qcfg_qsch_crs_eir_th_t {
	u32 qcfg_qsch_crs_eir_th;
};

struct dpp_etm_qmu_qcfg_qsch_crs_th1_t {
	u32 qcfg_qsch_crs_th1;
};

struct dpp_etm_qmu_qcfg_qsch_crs_th2_t {
	u32 qcfg_qsch_crs_th2;
};

struct dpp_etm_qmu_qcfg_csch_congest_th_t {
	u32 qcfg_csch_congest_th;
};

struct dpp_etm_qmu_qcfg_csch_sp_fc_th_t {
	u32 qcfg_csch_sp_fc_th;
};

struct dpp_etm_qmu_qcfg_csw_shap_parameter_t {
	u32 qcfg_csw_shap_en;
	u32 qcfg_csw_shap_parameter;
};

struct dpp_etm_qmu_cfgmt_rd_release_aful_th_t {
	u32 cfgmt_rd_release_aful_th;
};

struct dpp_etm_qmu_cfgmt_drop_imem_release_fifo_aful_th_t {
	u32 cfgmt_drop_imem_release_fifo_aful_th;
};

struct dpp_etm_qmu_cfgmt_nnh_rd_buf_aful_th_t {
	u32 cfgmt_nnh_rd_buf_aful_th;
};

struct dpp_etm_qmu_cfg_pid_use_inall_t {
	u32 cfgmt_nod_rd_buf_0_aful_th;
};

struct dpp_etm_qmu_cfg_pid_round_th_t {
	u32 cfgmt_nod_rd_buf_1_aful_th;
};

struct dpp_etm_qmu_cfgmt_credit_fifo_afull_th_t {
	u32 cfgmt_credit_fifo_afull_th;
};

struct dpp_etm_qmu_cfgmt_scan_fifo_afull_th_t {
	u32 cfgmt_scan_fifo_afull_th;
};

struct dpp_etm_qmu_cfgmt_small_fifo_aful_th_t {
	u32 cfgmt_small_fifo_aful_th;
};

struct dpp_etm_qmu_cfgmt_free_addr_fifo_aful_th_t {
	u32 cfgmt_free_addr_fifo_aful_th;
};

struct dpp_etm_qmu_cfgmt_enq_rpt_fifo_aful_th_t {
	u32 cfgmt_enq_rpt_fifo_aful_th;
};

struct dpp_etm_qmu_qcfg_csw_shap_token_depth_t {
	u32 qcfg_csw_shap_token_depth;
};

struct dpp_etm_qmu_qcfg_csw_shap_offset_value_t {
	u32 qcfg_csw_shap_offset_value;
};

struct dpp_etm_qmu_qcfg_csw_fc_offset_value_t {
	u32 qcfg_csw_fc_offset_value;
};

struct dpp_etm_qmu_qmu_init_done_state_t {
	u32 csch_qcfg_init_done;
	u32 qsch_qcfg_init_done;
	u32 qlist_qcfg_init_done;
	u32 qcsr_ram_init_done;
};

struct dpp_etm_qmu_csw_qcfg_port_shap_rdy_0_t {
	u32 csw_qcfg_port_shap_rdy_0;
};

struct dpp_etm_qmu_csw_qcfg_port_shap_rdy_1_t {
	u32 csw_qcfg_port_shap_rdy_1;
};

struct dpp_etm_qmu_qlist_cfgmt_ram_init_done_t {
	u32 qlist_qcfg_qds_ram_init_done;
	u32 qlist_qcfg_chk_ram_init_done;
	u32 qlist_qcfg_ept_ram_init_done;
	u32 qlist_qcfg_cti_ram_init_done;
	u32 qlist_qcfg_cto_ram_init_done;
	u32 qlist_qcfg_bcnt_ram_init_done;
	u32 qlist_qcfg_biu_ram_init_done;
	u32 qlist_qcfg_baram_init_done;
};

struct dpp_etm_qmu_qlist_cfgmt_ram_ecc_err_t {
	u32 qds_ram_parity_err;
	u32 qcsr_qnum_fifo_parity_err;
	u32 sa_id_ram_parity_err;
	u32 enq_rpt_fifo_parity_err;
	u32 bcnts_parity_err;
	u32 baram_parity_err_a;
	u32 baram_parity_err_b;
	u32 bcntm_ram_parity_err;
	u32 biu_ram_single_ecc_err;
	u32 chk_ram_single_ecc_err;
	u32 cmd_sch_cmd_ram_single_ecc_err;
	u32 cmd_sch_list_ram_single_ecc_err;
	u32 cmd_sch_hp_ram_single_ecc_err;
	u32 cmd_sch_tp_ram_single_ecc_err;
	u32 cmd_sch_enq_active_ram_single_ecc_err;
	u32 cmd_sch_deq_active_ram_single_ecc_err;
	u32 cmd_sch_empty_ram_single_ecc_err;
	u32 cmd_sch_eop_ram_single_ecc_err;
	u32 cmd_sch_blkcnt_ram_single_ecc_err;
	u32 biu_ram_double_ecc_err;
	u32 chk_ram_double_ecc_err;
	u32 cmd_sch_cmd_ram_double_ecc_err;
	u32 cmd_sch_list_ram_double_ecc_err;
	u32 cmd_sch_hp_ram_double_ecc_err;
	u32 cmd_sch_tp_ram_double_ecc_err;
	u32 cmd_sch_enq_active_ram_double_ecc_err;
	u32 cmd_sch_deq_active_ram_double_ecc_err;
	u32 cmd_sch_empty_ram_double_ecc_err;
	u32 cmd_sch_eop_ram_double_ecc_err;
	u32 cmd_sch_blkcnt_ram_double_ecc_err;
};

struct dpp_etm_qmu_qlist_cfgmt_ram_slot_err_t {
	u32 qds_ram_enq_rd_slot_err;
	u32 qds_ram_deq_rd_slot_err;
	u32 qds_ram_enq_wr_slot_err;
	u32 qds_ram_deq_wr_slot_err;
	u32 chk_ram_enq_rd_slot_err;
	u32 chk_ram_deq_rd_slot_err;
	u32 chk_ram_enq_wr_slot_err;
	u32 chk_ram_deq_wr_slot_err;
	u32 ept_ram_enq_rd_slot_err;
	u32 ept_ram_deq_rd_slot_err;
	u32 ept_ram_enq_wr_slot_err;
	u32 ept_ram_deq_wr_slot_err;
	u32 cti_ram_enq_rd_slot_err;
	u32 cti_ram_deq_rd_slot_err;
	u32 cti_ram_enq_wr_slot_err;
	u32 cti_ram_deq_wr_slot_err;
	u32 cto_ram_enq_rd_slot_err;
	u32 cto_ram_deq_rd_slot_err;
	u32 cto_ram_enq_wr_slot_err;
	u32 cto_ram_deq_wr_slot_err;
};

struct dpp_etm_qmu_qsch_cfgmt_ram_ecc_t {
	u32 crbal_rama_parity_error;
	u32 crbal_ramb_parity_error;
	u32 crs_ram_parity_error;
	u32 wlist_flag_ram_single_ecc_err;
	u32 wlist_next_single_ecc_err;
	u32 wlist_wactive_ram_single_ecc_err;
	u32 wlist_ractive_ram_single_ecc_err;
	u32 wlist_tp1_ram_single_ecc_err;
	u32 wlist_tp2_ram_single_ecc_err;
	u32 wlist_empty1_ram_single_ecc_err_a;
	u32 wlist_empty1_ram_single_ecc_err_b;
	u32 wlist_empty2_ram_single_ecc_err_a;
	u32 wlist_empty2_ram_single_ecc_err_b;
	u32 wlist_hp_ram_single_ecc_err_a;
	u32 wlist_hp_ram_single_ecc_err_b;
	u32 wlist_flag_ram_double_ecc_err;
	u32 wlist_next_double_ecc_err;
	u32 wlist_wactive_ram_double_ecc_err;
	u32 wlist_ractive_ram_double_ecc_err;
	u32 wlist_tp1_ram_double_ecc_err;
	u32 wlist_tp2_ram_double_ecc_err;
	u32 wlist_empty1_ram_double_ecc_err_a;
	u32 wlist_empty1_ram_double_ecc_err_b;
	u32 wlist_empty2_ram_double_ecc_err_a;
	u32 wlist_empty2_ram_double_ecc_err_b;
	u32 wlist_hp_ram_double_ecc_err_a;
	u32 wlist_hp_ram_double_ecc_err_b;
};

struct dpp_etm_qmu_qlist_cfgmt_fifo_state_t {
	u32 pkt_age_req_fifo_overflow;
	u32 pkt_age_req_fifo_underflow;
	u32 qcsr_big_fifo_ovfl;
	u32 qcsr_small_fifo_overflow;
	u32 enq_rpt_fifo_overflow;
	u32 enq_rpt_fifo_underflow;
	u32 pds_fwft_overflow;
	u32 pds_fwft_underflow;
	u32 free_addr_fifo_overflow;
	u32 free_addr_fifo_underflow;
	u32 rd_release_fwft_overflow;
	u32 rd_release_fwft_underflow;
	u32 pid_free_list_overflow;
	u32 pid_free_list_underflow;
	u32 pid_prp_list_overflow;
	u32 pid_prp_list_underflow;
	u32 pid_rdy_list_overflow;
	u32 pid_rdy_list_underflow;
	u32 drop_imem_release_fwft_overflow;
	u32 drop_imem_release_fwft_underflow;
	u32 nnh_rd_buf_fifo_overflow;
	u32 nnh_rd_buf_fifo_underflow;
	u32 nod_rd_buf_0_fifo_overflow;
	u32 nod_rd_buf_0_fifo_underflow;
	u32 nod_rd_buf_1_fifo_overflow;
	u32 nod_rd_buf_1_fifo_underflow;
};

struct dpp_etm_qmu_qlist_qcfg_clr_done_t {
	u32 qlist_qcfg_clr_done;
};

struct dpp_etm_qmu_qmu_int_mask1_t {
	u32 qmu_int_mask1;
};

struct dpp_etm_qmu_qmu_int_mask2_t {
	u32 qmu_int_mask2;
};

struct dpp_etm_qmu_qmu_int_mask3_t {
	u32 qmu_int_mask3;
};

struct dpp_etm_qmu_qmu_int_mask4_t {
	u32 qmu_int_mask4;
};

struct dpp_etm_qmu_qmu_int_mask5_t {
	u32 qmu_int_mask5;
};

struct dpp_etm_qmu_qmu_int_mask6_t {
	u32 qmu_int_mask6;
};

struct dpp_etm_qmu_cmd_sch_cfgmt_fifo_state_t {
	u32 nsop_fifo_parity_err;
	u32 cmdsch_rd_cmd_fifo_parity_err;
	u32 sop_fifo_afull;
	u32 sop_fifo_empty;
	u32 sop_fifo_overflow;
	u32 sop_fifo_underflow;
	u32 mmu_data_fifo_afull;
	u32 mmu_data_fifo_empty;
	u32 mmudat_fifo_overflow;
	u32 mmudat_fifo_underflow;
	u32 non_sop_fifo_afull;
	u32 non_sop_fifo_empty;
	u32 nsop_fifo_overflow;
	u32 nsop_fifo_underflow;
	u32 cmdsch_rd_cmd_fifo_afull;
	u32 cmdsch_rd_cmd_fifo_empty;
	u32 cmdsch_rd_cmd_fifo_overflow;
	u32 cmdsch_rd_cmd_fifo_underflow;
	u32 wlist_qnum_fifo_overflow;
	u32 wlist_qnum_fifo_underflow;
	u32 qsch_scan_fifo_overflow;
	u32 qsch_scan_fifo_underflow;
	u32 qsch_credit_fifo_overflow;
	u32 qsch_credit_fifo_underflow;
	u32 qsch_credit_fifo2_overflow;
	u32 qsch_credit_fifo2_underflow;
};

struct dpp_etm_qmu_qlist_r_bcnt_t {
	u32 qlist_r_bcnt;
};

struct dpp_etm_qmu_qsch_rw_crbal_t {
	u32 qsch_rw_crbal;
};

struct dpp_etm_qmu_qsch_rw_crs_t {
	u32 qsch_rw_crs;
};

struct dpp_etm_qmu_qsch_r_wlist_empty_t {
	u32 qsch_r_wlist_empty;
};

struct dpp_etm_qmu_qcfg_qlist_baram_rd_t {
	u32 qcfg_qlist_baram_rd;
};

struct dpp_etm_qmu_qcfg_qsch_crbal_fb_rw_t {
	u32 qcfg_qlist_crbal_fb_rw;
};

struct dpp_etm_qmu_qcfg_qlist_grp0_bank_t {
	u32 qcfg_qlist_grp0_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp1_bank_t {
	u32 qcfg_qlist_grp1_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp2_bank_t {
	u32 qcfg_qlist_grp2_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp3_bank_t {
	u32 qcfg_qlist_grp3_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp4_bank_t {
	u32 qcfg_qlist_grp4_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp5_bank_t {
	u32 qcfg_qlist_grp5_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp6_bank_t {
	u32 qcfg_qlist_grp6_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp7_bank_t {
	u32 qcfg_qlist_grp7_bank_wr;
};

struct dpp_etm_qmu_qcfg_qlist_grp_t {
	u32 qcfg_qlist_grp_wr;
};

struct dpp_etm_qmu_cfgmt_active_to_bank_cfg_t {
	u32 cfgmt_active_to_bank_cfg;
};

struct dpp_etm_qmu_cfgmt_ddr_in_mmu_cfg_t {
	u32 cfgmt_ddr_in_mmu_cfg;
};

struct dpp_etm_qmu_cfgmt_ddr_in_qmu_cfg_t {
	u32 cfgmt_ddr_in_qmu_cfg;
};

struct dpp_etm_qmu_cfgmt_bank_to_mmu_cfg_t {
	u32 cfgmt_bank_in_mmu_cfg;
};

struct dpp_etm_qmu_cfgmt_bank_to_qmu_cfg_t {
	u32 cfgmt_bank_in_qmu_cfg;
};

struct dpp_etm_qmu_cfgmt_grp_ram_n_clr_thd_t {
	u32 cfgmt_grp_ram_n_clr_thd;
};

struct dpp_etm_qmu_cfgmt_age_pkt_num_t {
	u32 cfgmt_age_pkt_num;
};

struct dpp_etm_qmu_cfgmt_age_multi_interval_t {
	u32 cfgmt_age_multi_interval;
};

struct dpp_etm_qmu_cfgmt_qmu_pkt_age_en_t {
	u32 cfgmt_qmu_pkt_age_en;
};

struct dpp_etm_qmu_cfgmt_qmu_pkt_age_interval_t {
	u32 cfgmt_qmu_pkt_age_interval;
};

struct dpp_etm_qmu_cfgmt_qmu_pkt_age_start_end_t {
	u32 cfgmt_qmu_pkt_age_end;
	u32 cfgmt_qmu_pkt_age_start;
};

struct dpp_etm_qmu_cfgmt_pkt_age_req_aful_th_t {
	u32 cfgmt_pkt_age_req_aful_th;
};

struct dpp_etm_qmu_cfgmt_pkt_age_step_interval_t {
	u32 cfgmt_pkt_age_step_interval;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_age_mode_t {
	u32 cfgmt_qmu_imem_age_en;
	u32 cfgmt_qmu_imem_age_qlen_en;
	u32 cfgmt_qmu_imem_age_time_en;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_qlen_age_interval_t {
	u32 cfgmt_qmu_imem_qlen_age_interval;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_time_age_interval_t {
	u32 cfgmt_qmu_imem_time_age_interval;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_qlen_age_thd_t {
	u32 cfgmt_qmu_imem_qlen_age_thd;
};

struct dpp_etm_qmu_cfgmt_imem_age_step_interval_t {
	u32 cfgmt_imem_age_step_interval;
};

struct dpp_etm_qmu_cfgmt_qmu_ecc_bypass_read_t {
	u32 cfgmt_qmu_ecc_bypass_read;
};

struct dpp_etm_qmu_cfgmt_qmu_resp_stat_fc_en_t {
	u32 cfgmt_qmu_resp_stat_fc_en;
};

struct dpp_etm_qmu_cfgmt_qmu_bank_xoff_pds_mode_t {
	u32 cfgmt_qmu_bank_xoff_pds_mode;
};

struct dpp_etm_qmu_cfgmt_qmu_stat_offset_t {
	u32 cfgmt_qmu_stat_offset;
};

struct dpp_etm_qmu_fc_cnt_mode_t {
	u32 fc_cnt_mode;
};

struct dpp_etm_qmu_mmu_qmu_wr_fc_cnt_t {
	u32 mmu_qmu_wr_fc_cnt;
};

struct dpp_etm_qmu_mmu_qmu_rd_fc_cnt_t {
	u32 mmu_qmu_rd_fc_cnt;
};

struct dpp_etm_qmu_qmu_cgavd_fc_cnt_t {
	u32 qmu_cgavd_fc_cnt;
};

struct dpp_etm_qmu_cgavd_qmu_pkt_cnt_t {
	u32 cgavd_qmu_pkt_cnt;
};

struct dpp_etm_qmu_cgavd_qmu_pktlen_all_t {
	u32 cgavd_qmu_pktlen_all;
};

struct dpp_etm_qmu_observe_portfc_spec_t {
	u32 observe_portfc_spec;
};

struct dpp_etm_qmu_spec_lif_portfc_count_t {
	u32 spec_lif_portfc_count;
};

struct dpp_etm_qmu_cfgmt_qmu_pfc_en_t {
	u32 cfgmt_qmu_pfc_en;
};

struct dpp_etm_qmu_cfgmt_qmu_pfc_mask_1_t {
	u32 cfgmt_qmu_pfc_mask_1;
};

struct dpp_etm_qmu_cfgmt_qmu_pfc_mask_2_t {
	u32 cfgmt_qmu_pfc_mask_2;
};

struct dpp_etm_cfgmt_chip_version_reg_t {
	u32 chip_version_reg;
	u32 chip_sub_reg;
	u32 chip_type_reg;
};

struct dpp_etm_cfgmt_chip_date_reg_t {
	u32 chip_date_reg;
};

struct dpp_etm_cfgmt_cfgmt_crc_en_t {
	u32 cfgmt_crc_en;
};

struct dpp_etm_cfgmt_cfg_port_transfer_en_t {
	u32 cfg_port_transfer_en;
};

struct dpp_etm_cfgmt_tm_sa_work_mode_t {
	u32 tm_sa_work_mode;
};

struct dpp_etm_cfgmt_local_sa_id_t {
	u32 local_sa_id;
};

struct dpp_etm_olif_olif_rdy_t {
	u32 cfgmt_block_mode;
	u32 cfgmt_count_overflow_mode;
	u32 cfgmt_count_rd_mode;
	u32 olif_rdy;
};

struct dpp_etm_olif_emem_prog_full_t {
	u32 emem_prog_full_assert;
	u32 emem_prog_full_negate;
};

struct dpp_etm_olif_port_order_fifo_full_t {
	u32 port_order_fifo_full_assert;
	u32 port_order_fifo_full_negate;
};

struct dpp_etm_olif_olif_release_last_t {
	u32 olif_release_last_addr;
	u32 olif_release_last_bank;
};

struct dpp_etm_olif_olif_fifo_empty_state_t {
	u32 qmu_para_fifo_empty;
	u32 emem_empty;
	u32 imem_empty;
};

struct dpp_etm_olif_qmu_olif_release_fc_cnt_t {
	u32 qmu_olif_release_fc_cnt;
};

struct dpp_etm_olif_olif_qmu_link_fc_cnt_t {
	u32 olif_qmu_link_fc_cnt;
};

struct dpp_etm_olif_lif0_link_fc_cnt_t {
	u32 lif0_link_fc_cnt;
};

struct dpp_etm_olif_olif_tmmu_fc_cnt_t {
	u32 olif_tmmu_fc_cnt;
};

struct dpp_etm_olif_olif_mmu_fc_cnt_t {
	u32 olif_mmu_fc_cnt;
};

struct dpp_etm_olif_olif_qmu_port_rdy_h_t {
	u32 olif_qmu_port_rdy_h;
};

struct dpp_etm_olif_olif_qmu_port_rdy_l_t {
	u32 olif_qmu_port_rdy_l;
};

struct dpp_etm_olif_lif0_port_rdy_h_t {
	u32 lif0_port_rdy_h;
};

struct dpp_etm_olif_lif0_port_rdy_l_t {
	u32 lif0_port_rdy_l;
};

struct dpp_etm_olif_qmu_olif_rd_sop_cnt_t {
	u32 qmu_olif_rd_sop_cnt;
};

struct dpp_etm_olif_qmu_olif_rd_eop_cnt_t {
	u32 qmu_olif_rd_eop_cnt;
};

struct dpp_etm_olif_qmu_olif_rd_vld_cnt_t {
	u32 qmu_olif_rd_vld_cnt;
};

struct dpp_etm_olif_qmu_olif_rd_blk_cnt_t {
	u32 qmu_olif_rd_blk_cnt;
};

struct dpp_etm_olif_mmu_tm_data_sop_cnt_t {
	u32 mmu_tm_data_sop_cnt;
};

struct dpp_etm_olif_mmu_tm_data_eop_cnt_t {
	u32 mmu_tm_data_eop_cnt;
};

struct dpp_etm_olif_mmu_tm_data_vld_cnt_t {
	u32 mmu_tm_data_vld_cnt;
};

struct dpp_etm_olif_odma_tm_data_sop_cnt_t {
	u32 odma_tm_data_sop_cnt;
};

struct dpp_etm_olif_odma_tm_data_eop_cnt_t {
	u32 odma_tm_data_eop_cnt;
};

struct dpp_etm_olif_odma_tm_deq_vld_cnt_t {
	u32 odma_tm_deq_vld_cnt;
};

struct dpp_etm_olif_olif_qmu_release_vld_cnt_t {
	u32 olif_qmu_release_vld_cnt;
};

struct dpp_etm_olif_emem_dat_vld_cnt_t {
	u32 emem_dat_vld_cnt;
};

struct dpp_etm_olif_imem_dat_vld_cnt_t {
	u32 imem_dat_vld_cnt;
};

struct dpp_etm_olif_emem_dat_rd_cnt_t {
	u32 emem_dat_rd_cnt;
};

struct dpp_etm_olif_imem_dat_rd_cnt_t {
	u32 imem_dat_rd_cnt;
};

struct dpp_etm_olif_qmu_olif_rd_sop_emem_cnt_t {
	u32 qmu_olif_rd_sop_emem_cnt;
};

struct dpp_etm_olif_qmu_olif_rd_vld_emem_cnt_t {
	u32 qmu_olif_rd_vld_emem_cnt;
};

struct dpp_etm_olif_cpu_last_wr_addr_t {
	u32 cpu_last_wr_addr;
};

struct dpp_etm_olif_cpu_last_wr_data_t {
	u32 cpu_last_wr_data;
};

struct dpp_etm_olif_cpu_last_rd_addr_t {
	u32 cpu_last_rd_addr;
};

struct dpp_etm_olif_qmu_olif_last_port_t {
	u32 qmu_olif_last_port;
};

struct dpp_etm_olif_qmu_olif_last_addr_t {
	u32 qmu_olif_last_addr;
};

struct dpp_etm_olif_qmu_olif_last_bank_t {
	u32 qmu_olif_last_bank;
};

struct dpp_etm_olif_tm_lif_byte_stat_t {
	u32 tm_lif_byte_stat;
};

struct dpp_etm_olif_tm_lif_err_stat_t {
	u32 tm_lif_err_stat;
};

struct dpp_etm_cgavd_port_share_cnt_t {
	u32 port_share_cnt;
};

struct dpp_etm_cgavd_total_imem_cnt_t {
	u32 total_imem_cnt;
};

struct dpp_etm_cgavd_pp_q_len_t {
	u32 pp_q_len;
};

struct dpp_etm_cgavd_sys_q_len_t {
	u32 sys_q_len;
};

struct dpp_etm_cgavd_cgavd_cfg_error_warning_t {
	u32 error_correction_11;
	u32 error_correction_10;
	u32 error_correction_9;
	u32 error_correction_8;
	u32 error_correction_7;
	u32 error_correction_6;
	u32 error_correction5;
	u32 error_correction_4;
	u32 error_correction_3;
	u32 error_correction_2;
	u32 error_correction_1;
	u32 error_correction_0;
};

struct dpp_etm_cgavd_mult_qlen_th_en_t {
	u32 mult_qlen_th;
};

struct dpp_etm_cgavd_mult_qlen_th_t {
	u32 mult_qlen_th;
};

struct dpp_etm_cgavd_cgavd_cfg_move_t {
	u32 cfgmt_sys_move_en;
	u32 cfgmt_port_move_en;
	u32 cfgmt_flow_move_en;
};

struct dpp_etm_cgavd_cfgmt_total_th_t {
	u32 cfgmt_total_th;
};

struct dpp_etm_cgavd_cfgmt_port_share_th_t {
	u32 cfgmt_port_share_th;
};

struct dpp_etm_cgavd_sa_unreach_state_t {
	u32 sa_unreach_state;
};

struct dpp_etm_cgavd_mv_port_th_t {
	u32 port_th;
};

struct dpp_etm_cgavd_mv_drop_sp_th_t {
	u32 mvdrop_sp_th;
};

struct dpp_etm_cgavd_cgavd_state_warning_t {
	u32 deq_q_num_warning;
	u32 deq_pkt_len_warning;
	u32 enq_pkt_dp_warning;
	u32 unenq_q_num_warning;
	u32 enq_q_num_warning;
	u32 enq_pkt_len_warning;
};

struct dpp_etm_cgavd_tmmu_cgavd_dma_fifo_cnt_t {
	u32 tmmu_cgavd_dma_fifo_cnt;
};

struct dpp_etm_cgavd_tmmu_cgavd_dma_fifo_cnt_max_t {
	u32 tmmu_cgavd_dma_fifo_cnt_max;
};

struct dpp_etm_cgavd_imem_total_cnt_t {
	u32 imem_total_cnt;
};

struct dpp_etm_cgavd_imem_total_cnt_max_t {
	u32 imem_total_cnt_max;
};

struct dpp_etm_cgavd_flow0_omem_cnt_t {
	u32 flow0_omem_cnt;
};

struct dpp_etm_cgavd_flow1_omem_cnt_t {
	u32 flow1_omem_cnt;
};

struct dpp_etm_cgavd_flow2_omem_cnt_t {
	u32 flow2_omem_cnt;
};

struct dpp_etm_cgavd_flow3_omem_cnt_t {
	u32 flow3_omem_cnt;
};

struct dpp_etm_cgavd_flow4_omem_cnt_t {
	u32 flow4_omem_cnt;
};

struct dpp_etm_cgavd_appoint_flow_num_message_1_t {
	u32 appoint_flow_num_en_1;
	u32 appoint_flow_num_1;
};

struct dpp_etm_cgavd_appoint_flow_num_message_2_t {
	u32 appoint_flow_num_en_2;
	u32 appoint_flow_num_2;
};

struct dpp_etm_cgavd_odma_cgavd_pkt_num_1_t {
	u32 odma_cgavd_pkt_num_1;
};

struct dpp_etm_cgavd_odma_cgavd_byte_num_1_t {
	u32 odma_cgavd_byte_num_1;
};

struct dpp_etm_cgavd_cgavd_enqueue_pkt_num_1_t {
	u32 cgavd_enqueue_pkt_num_1;
};

struct dpp_etm_cgavd_cgavd_dequeue_pkt_num_1_t {
	u32 cgavd_dequeue_pkt_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_pkt_imem_num_1_t {
	u32 cgavd_qmu_pkt_imem_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_pkt_omem_num_1_t {
	u32 cgavd_qmu_pkt_omem_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_byte_imem_num_1_t {
	u32 cgavd_qmu_byte_imem_1;
};

struct dpp_etm_cgavd_cgavd_qmu_byte_omem_num_1_t {
	u32 cgavd_qmu_byte_omem_1;
};

struct dpp_etm_cgavd_cgavd_qmu_pkt_drop_num_1_t {
	u32 cgavd_qmu_pkt_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_byte_drop_num_1_t {
	u32 cgavd_qmu_byte_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_forbid_drop_num_1_t {
	u32 cgavd_qmu_forbid_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_flow_td_drop_num_1_t {
	u32 cgavd_qmu_flow_td_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_flow_wred_drop_num_1_t {
	u32 cgavd_qmu_flow_wred_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_flow_wred_dp_drop_num_1_t {
	u32 cgavd_qmu_flow_wred_dp_drop_num1;
};

struct dpp_etm_cgavd_cgavd_qmu_pp_td_num_1_t {
	u32 cgavd_qmu_pp_td_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_pp_wred_drop_num_1_t {
	u32 cgavd_qmu_pp_wred_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_pp_wred_dp_drop_num_1_t {
	u32 cgavd_qmu_pp_wred_dp_drop_num1;
};

struct dpp_etm_cgavd_cgavd_qmu_sys_td_drop_num_1_t {
	u32 cgavd_qmu_sys_td_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_sys_gred_drop_num_1_t {
	u32 cgavd_qmu_sys_gred_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_sys_gred_dp_drop_num1_t {
	u32 cgavd_qmu_sys_gred_dp_drop_num1;
};

struct dpp_etm_cgavd_cgavd_qmu_sa_drop_num_1_t {
	u32 cgavd_qmu_sa_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_move_drop_num_1_t {
	u32 cgavd_qmu_move_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_tm_mult_drop_num_1_t {
	u32 cgavd_qmu_tm_mult_drop_num_1;
};

struct dpp_etm_cgavd_cgavd_qmu_tm_error_drop_num_1_t {
	u32 cgavd_qmu_tm_error_drop_num_1;
};

struct dpp_etm_cgavd_odma_cgavd_pkt_num_2_t {
	u32 odma_cgavd_pkt_num_2;
};

struct dpp_etm_cgavd_odma_cgavd_byte_num_2_t {
	u32 odma_cgavd_byte_num_2;
};

struct dpp_etm_cgavd_cgavd_enqueue_pkt_num_2_t {
	u32 cgavd_enqueue_pkt_num_2;
};

struct dpp_etm_cgavd_cgavd_dequeue_pkt_num_2_t {
	u32 cgavd_dequeue_pkt_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_pkt_imem_num_2_t {
	u32 cgavd_qmu_pkt_imem_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_pkt_omem_num_2_t {
	u32 cgavd_qmu_pkt_omem_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_byte_imem_num_2_t {
	u32 cgavd_qmu_byte_imem_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_byte_omem_num_2_t {
	u32 cgavd_qmu_byte_omem_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_pkt_drop_num_2_t {
	u32 cgavd_qmu_pkt_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_byte_drop_num_2_t {
	u32 cgavd_qmu_byte_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_forbid_drop_num_2_t {
	u32 cgavd_qmu_forbid_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_flow_td_drop_num_2_t {
	u32 cgavd_qmu_flow_td_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_flow_wred_drop_num_2_t {
	u32 cgavd_qmu_flow_wred_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_flow_wred_dp_drop_num_2_t {
	u32 cgavd_qmu_flow_wred_dp_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_pp_td_num_2_t {
	u32 cgavd_qmu_pp_td_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_pp_wred_drop_num_2_t {
	u32 cgavd_qmu_pp_wred_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_pp_wred_dp_drop_num_2_t {
	u32 cgavd_qmu_pp_wred_dp_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_sys_td_drop_num_2_t {
	u32 cgavd_qmu_sys_td_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_sys_gred_drop_num_2_t {
	u32 cgavd_qmu_sys_gred_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_sys_gred_dp_drop_num_2_t {
	u32 cgavd_qmu_sys_gred_dp_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_sa_drop_num_2_t {
	u32 cgavd_qmu_sa_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_move_drop_num_2_t {
	u32 cgavd_qmu_move_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_tm_mult_drop_num_2_t {
	u32 cgavd_qmu_tm_mult_drop_num_2;
};

struct dpp_etm_cgavd_cgavd_qmu_tm_error_drop_num_2_t {
	u32 cgavd_qmu_tm_error_drop_num_2;
};

struct dpp_etm_cgavd_move_flow_th_profile_t {
	u32 move_drop_profile;
};

struct dpp_etm_cgavd_move_flow_th_t {
	u32 move_drop_flow_th;
};

struct dpp_etm_tmmu_emem_pd_fifo_aful_th_t {
	u32 emem_pd_fifo_aful_th;
};

struct dpp_etm_tmmu_dma_data_fifo_aful_th_t {
	u32 dma_data_fifo_aful_th;
};

struct dpp_etm_tmmu_tmmu_states_0_t {
	u32 tm_odma_pkt_rdy;
	u32 dma_data_fifo_empty;
	u32 imem_enq_rd_fifo_empty;
	u32 imem_enq_drop_fifo_empty;
	u32 imem_deq_rd_fifo_empty;
	u32 imem_deq_drop_fifo_empty;
	u32 wr_cmd_fifo_empty;
	u32 cached_pd_fifo_empty;
	u32 emem_pd_fifo_empty;
	u32 pd_order_fifo_empty;
	u32 odma_tm_data_rdy;
	u32 odma_tm_discard_rdy;
	u32 olif_tmmu_rdy;
	u32 mmu_tm_cmd_wr_rdy;
	u32 mmu_tm_data_wr_rdy;
	u32 mmu_tm_rd_rdy;
	u32 mmu_tm_sop_rd_rdy;
	u32 qmu_tmmu_sop_data_rdy;
	u32 tmmu_cmdsw_imem_release_rdy;
	u32 imem_age_release_rdy;
	u32 tmmu_qmu_wr_rdy;
	u32 tmmu_qmu_rdy_7;
	u32 tmmu_qmu_rdy_6;
	u32 tmmu_qmu_rdy_5;
	u32 tmmu_qmu_rdy_4;
	u32 tmmu_qmu_rdy_3;
	u32 tmmu_qmu_rdy_2;
	u32 tmmu_qmu_rdy_1;
	u32 tmmu_qmu_rdy_0;
	u32 tmmu_qmu_rd_rdy;
	u32 tmmu_qmu_sop_rd_rdy;
};

struct dpp_etm_tmmu_qmu_tmmu_wr_sop_cnt_t {
	u32 qmu_tmmu_wr_sop_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_wr_eop_cnt_t {
	u32 qmu_tmmu_wr_eop_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_wr_drop_cnt_t {
	u32 qmu_tmmu_wr_drop_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_wr_emem_cnt_t {
	u32 qmu_tmmu_wr_emem_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_wr_imem_cnt_t {
	u32 qmu_tmmu_wr_imem_cnt;
};

struct dpp_etm_tmmu_tmmu_mmu_wr_sop_cnt_t {
	u32 tmmu_mmu_wr_sop_cnt;
};

struct dpp_etm_tmmu_tmmu_mmu_wr_eop_cnt_t {
	u32 tmmu_mmu_wr_eop_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_rd_sop_cnt_t {
	u32 qmu_tmmu_rd_sop_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_rd_eop_cnt_t {
	u32 qmu_tmmu_rd_eop_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_rd_drop_cnt_t {
	u32 qmu_tmmu_rd_drop_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_rd_emem_cnt_t {
	u32 qmu_tmmu_rd_emem_cnt;
};

struct dpp_etm_tmmu_qmu_tmmu_rd_imem_cnt_t {
	u32 qmu_tmmu_rd_imem_cnt;
};

struct dpp_etm_tmmu_tmmu_mmu_rd_sop_cnt_t {
	u32 tmmu_mmu_rd_sop_cnt;
};

struct dpp_etm_tmmu_tmmu_mmu_rd_eop_cnt_t {
	u32 tmmu_mmu_rd_eop_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_in_sop_cnt_t {
	u32 tmmu_odma_in_sop_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_in_eop_cnt_t {
	u32 tmmu_odma_in_eop_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_vld_cnt_t {
	u32 tmmu_odma_vld_cnt;
};

struct dpp_etm_tmmu_qmu_pd_in_cnt_t {
	u32 qmu_pd_in_cnt;
};

struct dpp_etm_tmmu_tmmu_pd_hit_cnt_t {
	u32 tmmu_pd_hit_cnt;
};

struct dpp_etm_tmmu_tmmu_pd_out_cnt_t {
	u32 tmmu_pd_out_cnt;
};

struct dpp_etm_tmmu_tmmu_wr_cmd_fifo_wr_cnt_t {
	u32 tmmu_wr_cmd_fifo_wr_cnt;
};

struct dpp_etm_tmmu_tmmu_imem_age_cnt_t {
	u32 tmmu_imem_age_cnt;
};

struct dpp_etm_tmmu_tmmu_cmdsch_rd_cnt_t {
	u32 tmmu_cmdsch_rd_cnt;
};

struct dpp_etm_tmmu_tmmu_cmdsch_drop_cnt_t {
	u32 tmmu_cmdsch_drop_cnt;
};

struct dpp_etm_tmmu_tmmu_cmdsw_drop_cnt_t {
	u32 tmmu_cmdsw_drop_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_enq_rd_cnt_t {
	u32 tmmu_odma_enq_rd_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_enq_drop_cnt_t {
	u32 tmmu_odma_enq_drop_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_imem_age_cnt_t {
	u32 tmmu_odma_imem_age_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_deq_rd_cnt_t {
	u32 tmmu_odma_deq_rd_cnt;
};

struct dpp_etm_tmmu_tmmu_odma_deq_drop_cnt_t {
	u32 tmmu_odma_deq_drop_cnt;
};

struct dpp_etm_tmmu_olif_tmmu_xoff_cnt_t {
	u32 olif_tmmu_xoff_cnt;
};

struct dpp_etm_tmmu_odma_tm_data_xoff_cnt_t {
	u32 odma_tm_data_xoff_cnt;
};

struct dpp_etm_tmmu_tm_odma_pkt_xoff_cnt_t {
	u32 tm_odma_pkt_xoff_cnt;
};

struct dpp_etm_tmmu_tm_state_3_t {
	u32 tmmu_qmu_rdy_9;
	u32 tmmu_qmu_rdy_8;
};

struct dpp_etm_tmmu_cfgmt_pd_cache_cmd_t {
	u32 cfgmt_pd_cache_addr;
};

struct dpp_etm_tmmu_cfgmt_pd_cache_rd_done_t {
	u32 cfgmt_pd_cache_rd_done;
};

struct dpp_etm_tmmu_cfgmt_pd_cache_rd_data_0_t {
	u32 cfgmt_pd_cache_rd_data_0;
};

struct dpp_etm_tmmu_cfgmt_pd_cache_rd_data_1_t {
	u32 cfgmt_pd_cache_rd_data_1;
};

struct dpp_etm_tmmu_cfgmt_pd_cache_rd_data_2_t {
	u32 cfgmt_pd_cache_rd_data_2;
};

struct dpp_etm_tmmu_cfgmt_pd_cache_rd_data_3_t {
	u32 cfgmt_pd_cache_rd_data_3;
};

struct dpp_etm_tmmu_cfgmt_tmmu_to_odma_para_t {
	u32 cfgmt_tmmu_to_odma_para;
};

struct dpp_etm_tmmu_cfgmt_dma_data_fifo_cnt_t {
	u32 cfgmt_dma_data_fifo_cnt;
};

struct dpp_etm_tmmu_cfgmt_cache_tag_bit0_offset_t {
	u32 cfgmt_cache_tag_bit0_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_tag_bit1_offset_t {
	u32 cfgmt_cache_tag_bit1_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_tag_bit2_offset_t {
	u32 cfgmt_cache_tag_bit2_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_tag_bit3_offset_t {
	u32 cfgmt_cache_tag_bit3_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_tag_bit4_offset_t {
	u32 cfgmt_cache_tag_bit4_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_tag_bit5_offset_t {
	u32 cfgmt_cache_tag_bit5_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit0_offset_t {
	u32 cfgmt_cache_index_bit0_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit1_offset_t {
	u32 cfgmt_cache_index_bit1_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit2_offset_t {
	u32 cfgmt_cache_index_bit2_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit3_offset_t {
	u32 cfgmt_cache_index_bit3_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit4_offset_t {
	u32 cfgmt_cache_index_bit4_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit5_offset_t {
	u32 cfgmt_cache_index_bit5_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit6_offset_t {
	u32 cfgmt_cache_index_bit6_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit7_offset_t {
	u32 cfgmt_cache_index_bit7_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit8_offset_t {
	u32 cfgmt_cache_index_bit8_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit9_offset_t {
	u32 cfgmt_cache_index_bit9_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit10_offset_t {
	u32 cfgmt_cache_index_bit10_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit11_offset_t {
	u32 cfgmt_cache_index_bit11_offset;
};

struct dpp_etm_tmmu_cfgmt_cache_index_bit12_offset_t {
	u32 cfgmt_cache_index_bit12_offset;
};

struct dpp_etm_shap_bktfull_fifo_full_flagregister_t {
	u32 bktfull_fifo_full_flag_core;
};

struct dpp_etm_shap_fifo_full_regregister_t {
	u32 fifo_full_reg;
};

struct dpp_etm_shap_fifo_empty_regregister_t {
	u32 fifo_empty_reg;
};

struct dpp_etm_shap_fifo_almost_full_regregister_t {
	u32 fifo_almost_full_reg;
};

struct dpp_etm_shap_fifo_almost_empty_regregister_t {
	u32 fifo_almost_empty_reg;
};

struct dpp_etm_crdt_credit_space_select_t {
	u32 credit_space_select;
};

struct dpp_etm_crdt_stat_space_max_t {
	u32 stat_space_max;
};

struct dpp_etm_crdt_stat_space_min_t {
	u32 stat_space_min;
};

struct dpp_etm_crdt_stat_space_credit_t {
	u32 stat_space_credit;
};

struct dpp_etm_crdt_stat_que_step8_credit_t {
	u32 stat_que_step8_credit;
};

struct dpp_etm_crdt_special_que_t {
	u32 special_que_id;
};

struct dpp_etm_crdt_special_que_credit_t {
	u32 special_que_credit;
};

struct dpp_etm_crdt_lif_congest_credit_cnt_t {
	u32 lif_congest_credit_cnt;
};

struct dpp_etm_crdt_lif_port_congest_credit_cnt_t {
	u32 lif_port_congest_credit_cnt;
};

struct dpp_etm_crdt_crdt_congest_credit_cnt_t {
	u32 crdt_congest_credit_cnt;
};

struct dpp_etm_crdt_crdt_port_congest_credit_cnt_t {
	u32 crdt_port_congest_credit_cnt;
};

struct dpp_etm_crdt_congest_port_id_t {
	u32 congest_port_id;
};

struct dpp_etm_crdt_dev_link_control_t {
	u32 dev_link_control;
};

struct dpp_etm_crdt_crdt_sa_port_rdy_t {
	u32 crdt_sa_port_rdy;
};

struct dpp_etm_crdt_crdt_congest_mode_select_t {
	u32 crdt_congest_mode_selectr;
};

struct dpp_etm_crdt_fifo_out_all_crs_normal_cnt_t {
	u32 fifo_out_all_crs_normal_cnt;
};

struct dpp_etm_crdt_fifo_out_all_crs_off_cnt_t {
	u32 fifo_out_all_crs_off_cnt;
};

struct dpp_etm_crdt_fifo_out_que_crs_normal_cnt_t {
	u32 fifo_out_que_crs_normal_cnt;
};

struct dpp_etm_crdt_fifo_out_que_crs_off_cnt_t {
	u32 fifo_out_que_crs_off_cnt;
};

struct dpp_etm_crdt_mode_add_60g_t {
	u32 mode_add_60g;
};

struct dpp_etm_crdt_pp_token_add_t {
	u32 pp_token_add_cir;
};

struct dpp_etm_crdt_pp_cir_token_total_dist_cnt_t {
	u32 pp_cir_token_total_dist_counter;
};

struct dpp_etm_crdt_pp_cir_token_total_dec_cnt_t {
	u32 pp_cir_token_total_dec_counter;
};

struct dpp_etm_crdt_dev_credit_cnt_t {
	u32 dev_credit_cnt;
};

struct dpp_etm_crdt_no_credit_cnt1_t {
	u32 no_credit_cnt1;
};

struct dpp_etm_crdt_no_credit_cnt2_t {
	u32 no_credit_cnt2;
};

struct dpp_etm_crdt_asm_interval_0_cfg_t {
	u32 asm_interval_0_cfg;
};

struct dpp_etm_crdt_asm_interval_1_cfg_t {
	u32 asm_interval_1_cfg;
};

struct dpp_etm_crdt_asm_interval_2_cfg_t {
	u32 asm_interval_2_cfg;
};

struct dpp_etm_crdt_asm_interval_3_cfg_t {
	u32 asm_interval_3_cfg;
};

struct dpp_etm_crdt_asm_interval_4_cfg_t {
	u32 asm_interval_4_cfg;
};

struct dpp_etm_crdt_asm_interval_5cfg_t {
	u32 asm_interval_5_cfg;
};

struct dpp_etm_crdt_asm_interval_6_cfg_t {
	u32 asm_interval_6_cfg;
};

struct dpp_etm_crdt_asm_interval_7_cfg_t {
	u32 asm_interval_7_cfg;
};

struct dpp_etm_crdt_crdt_total_congest_mode_cfg_t {
	u32 crdt_total_congest_mode_cfg;
};

struct dpp_etm_crdt_rci_fifo_ini_deep_cfg_t {
	u32 rci_fifo_ini_deep_cfg;
};

struct dpp_etm_crdt_crdt_ecc_t {
	u32 seinfo_wfq_single_ecc_err;
	u32 seinfo_wfq_double_ecc_err;
	u32 seinfo_fq_single_ecc_err;
	u32 seinfo_fq_double_ecc_err;
	u32 ecc_bypass;
};

struct dpp_etm_crdt_ucn_asm_rdy_shield_en_t {
	u32 ucn_rdy_shield_en;
	u32 asm_rdy_shield_en;
};

struct dpp_etm_crdt_ucn_asm_rdy_t {
	u32 ucn_rdy;
	u32 asm_rdy;
};

struct dpp_etm_crdt_rci_grade_t {
	u32 rci_grade;
};

struct dpp_etm_crdt_crdt_rci_value_r_t {
	u32 crdt_rci_value_r;
};

struct dpp_etm_crdt_crdt_interval_now_t {
	u32 crdt_interval_now;
};

struct dpp_etm_crdt_crs_sheild_flow_id_cfg_t {
	u32 crs_sheild_flow_id_cfg;
};

struct dpp_etm_crdt_crs_sheild_en_cfg_t {
	u32 crs_sheild_en_cfg;
};

struct dpp_etm_crdt_crs_sheild_value_cfg_t {
	u32 crs_sheild_value_cfg;
};

struct dpp_etm_crdt_test_token_calc_ctrl_t {
	u32 test_token_calc_state;
	u32 test_token_calc_trigger;
};

struct dpp_etm_crdt_test_token_sample_cycle_num_t {
	u32 sample_cycle_num;
};

struct dpp_etm_crdt_q_state_0_7_t {
	u32 q_token_state_7;
	u32 q_token_state_6;
	u32 q_token_state_5;
	u32 q_token_state_4;
	u32 q_token_state_3;
	u32 q_token_state_2;
	u32 q_token_state_1;
	u32 q_token_state_0;
};

struct dpp_etm_crdt_q_state_8_15_t {
	u32 q_token_state_15;
	u32 q_token_state_14;
	u32 q_token_state_13;
	u32 q_token_state_12;
	u32 q_token_state_11;
	u32 q_token_state_10;
	u32 q_token_state_9;
	u32 q_token_state_8;
};

struct dpp_etm_qmu_csw_csch_rd_cmd_cnt_t {
	u32 csw_csch_rd_cmd_cnt;
};

struct dpp_etm_qmu_csw_csch_rd_sop_cnt_t {
	u32 csw_csch_rd_sop_cnt;
};

struct dpp_etm_qmu_csw_csch_rd_eop_cnt_t {
	u32 csw_csch_rd_eop_cnt;
};

struct dpp_etm_qmu_csw_csch_rd_drop_cnt_t {
	u32 csw_csch_rd_drop_cnt;
};

struct dpp_etm_qmu_csch_mmu_rd_cmd_cnt_t {
	u32 csch_mmu_rd_cmd_cnt;
};

struct dpp_etm_qmu_csch_mmu_rd_sop_cnt_t {
	u32 csch_mmu_rd_sop_cnt;
};

struct dpp_etm_qmu_csch_mmu_rd_eop_cnt_t {
	u32 csch_mmu_rd_eop_cnt;
};

struct dpp_etm_qmu_csch_mmu_rd_drop_cnt_t {
	u32 csch_mmu_rd_drop_cnt;
};

struct dpp_etm_qmu_qcfg_qsch_crs_filter_t {
	u32 qcfg_qsch_crs_filter;
};

struct dpp_etm_qmu_qcfg_qsch_crs_force_en_t {
	u32 qcfg_qsch_crs_force_en;
};

struct dpp_etm_qmu_qcfg_qsch_crs_force_qnum_t {
	u32 qcfg_qsch_crs_force_qnum;
};

struct dpp_etm_qmu_qcfg_qsch_crs_force_crs_t {
	u32 qcfg_qsch_crs_force_crs;
};

struct dpp_etm_qmu_cfgmt_oshp_sgmii_shap_mode_t {
	u32 cfgmt_oshp_sgmii_shap_mode;
};

struct dpp_etm_qmu_cfgmt_qmu_sashap_en_t {
	u32 cfgmt_qmu_sashap_en;
};

struct dpp_etm_qmu_cfgmt_sashap_token_max_t {
	u32 cfgmt_sashap_token_max;
};

struct dpp_etm_qmu_cfgmt_sashap_token_min_t {
	u32 cfgmt_sashap_token_min;
};

struct dpp_etm_qmu_cfg_qsch_q3lbaddrate_t {
	u32 cfg_qsch_q3lbaddrate;
};

struct dpp_etm_qmu_cfg_qsch_q012lbaddrate_t {
	u32 cfg_qsch_q012lbaddrate;
};

struct dpp_etm_qmu_cfg_qsch_q3creditlbmaxcnt_t {
	u32 cfg_qsch_q3creditlbmaxcnt;
};

struct dpp_etm_qmu_cfg_qsch_q012creditlbmaxcnt_t {
	u32 cfg_qsch_q012creditlbmaxcnt;
};

struct dpp_etm_qmu_cfg_qsch_mul_token_gen_num_t {
	u32 cfg_qsch_mul_token_gen_num;
};

struct dpp_etm_qmu_cfg_qsch_q3_credit_lb_control_en_t {
	u32 cfg_qsch_q3_credit_lb_control_en;
};

struct dpp_etm_qmu_cfg_qsch_q012_credit_lb_control_en_t {
	u32 cfg_qsch_q012_credit_lb_control_en;
};

struct dpp_etm_qmu_cfg_qsch_sp_dwrr_en_t {
	u32 cfg_qsch_sp_dwrr_en;
};

struct dpp_etm_qmu_cfg_qsch_q01_attach_en_t {
	u32 cfg_qsch_q01_attach_en;
};

struct dpp_etm_qmu_cfg_qsch_w0_t {
	u32 cfg_qsch_w0;
};

struct dpp_etm_qmu_cfg_qsch_w1_t {
	u32 cfg_qsch_w1;
};

struct dpp_etm_qmu_cfg_qsch_w2_t {
	u32 cfg_qsch_w2;
};

struct dpp_etm_qmu_cfg_qsch_lkybktmaxcnt1_t {
	u32 cfg_qsch_lkybktmaxcnt1;
};

struct dpp_etm_qmu_cfg_qsch_lkybktmaxcnt2_t {
	u32 cfg_qsch_lkybktmaxcnt2;
};

struct dpp_etm_qmu_cfg_qsch_lkybktdcrrate1_t {
	u32 cfg_qsch_lkybktdcrrate1;
};

struct dpp_etm_qmu_cfg_qsch_lkybktdcrrate2_t {
	u32 cfg_qsch_lkybktdcrrate2;
};

struct dpp_etm_qmu_cfg_qsch_lkybktdcrrate3_t {
	u32 cfg_qsch_lkybktdcrrate3;
};

struct dpp_etm_qmu_cfg_qsch_lkybktmaxcnt3_t {
	u32 cfg_qsch_lkybktmaxcnt3;
};

struct dpp_etm_qmu_cfg_qsch_qmu_mul_auto_sa_version_t {
	u32 cfg_qsch_qmu_mul_auto_sa_version;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_0_t {
	u32 cfg_qsch_sa_credit_value_0;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_1_t {
	u32 cfg_qsch_sa_credit_value_1;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_2_t {
	u32 cfg_qsch_sa_credit_value_2;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_3_t {
	u32 cfg_qsch_sa_credit_value_3;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_4_t {
	u32 cfg_qsch_sa_credit_value_4;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_5_t {
	u32 cfg_qsch_sa_credit_value_5;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_6_t {
	u32 cfg_qsch_sa_credit_value_6;
};

struct dpp_etm_qmu_cfg_qsch_sa_credit_value_7_t {
	u32 cfg_qsch_sa_credit_value_7;
};

struct dpp_etm_qmu_cfg_qsch_remote_credit_fifo_almost_full_th_t {
	u32 cfg_qsch_remote_credit_fifo_almost_full_th;
};

struct dpp_etm_qmu_cfg_qsch_auto_credit_fifo_almost_full_th_t {
	u32 cfg_qsch_auto_credit_fifo_almost_full_th;
};

struct dpp_etm_qmu_cfg_qsch_q3_credit_fifo_almost_full_th_t {
	u32 cfg_qsch_q3_credit_fifo_almost_full_th;
};

struct dpp_etm_qmu_cfg_qsch_q012_credit_fifo_almost_full_th_t {
	u32 cfg_qsch_q012_credit_fifo_almost_full_th;
};

struct dpp_etm_qmu_cfg_qsch_mul_fc_res_en_t {
	u32 cfg_qsch_mul_fc_res_en;
};

struct dpp_etm_qmu_cfgmt_mul_ovf_udf_flg_query_t {
	u32 qsch_cfg_remote_credit_fifo_full;
	u32 qsch_cfg_remote_credit_fifo_empty;
	u32 qsch_cfg_remote_credit_fifo_overflow;
	u32 qsch_cfg_remote_credit_fifo_underflow;
	u32 qsch_cfg_auto_credit_fifo_full;
	u32 qsch_cfg_auto_credit_fifo_empty;
	u32 qsch_cfg_auto_credit_fifo_overflow;
	u32 qsch_cfg_auto_credit_fifo_underflow;
	u32 qsch_cfg_q3_credit_fifo_full;
	u32 qsch_cfg_q3_credit_fifo_empty;
	u32 qsch_cfg_q3_credit_fifo_overflow;
	u32 qsch_cfg_q3_credit_fifo_underflow;
	u32 qsch_cfg_q012_credit_fifo_full;
	u32 qsch_cfg_q012_credit_fifo_empty;
	u32 qsch_cfg_q012_credit_fifo_overflow;
	u32 qsch_cfg_q012_credit_fifo_underflow;
	u32 qsch_cfg_lkybktoverflow1;
	u32 qsch_cfg_lkybktoverflow2;
	u32 qsch_cfg_lkybktoverflow3;
};

struct dpp_etm_qmu_cfgmt_mul_cng_flg_query_t {
	u32 qsch_cfg_q3cngflag;
	u32 qsch_cfg_q012cngflag;
	u32 qsch_cfg_cngflag1;
	u32 qsch_cfg_cngflag2;
	u32 qsch_cfg_cngflag3;
};

struct dpp_etm_qmu_qsch_cfg_lkybktval1_t {
	u32 qsch_cfg_lkybktval1;
};

struct dpp_etm_qmu_qsch_cfg_lkybktval2_t {
	u32 qsch_cfg_lkybktval2;
};

struct dpp_etm_qmu_qsch_cfg_lkybktval3_t {
	u32 qsch_cfg_lkybktval3;
};

struct dpp_etm_qmu_qsch_cfg_q3lbval_t {
	u32 qsch_cfg_q3lbval;
};

struct dpp_etm_qmu_qsch_cfg_q012lbval_t {
	u32 qsch_cfg_q012lbval;
};

struct dpp_etm_qmu_qlist_cfgmt_ram_ecc_err2_t {
	u32 qlist_imem_pd_ram_single_ecc_err;
	u32 qlist_imem_pd_ram_double_ecc_err;
	u32 qlist_imem_up_ptr_ram_single_ecc_err;
	u32 qlist_imem_up_ptr_ram_double_ecc_err;
	u32 qlist_imem_down_ptr_ram_single_ecc_err;
	u32 qlist_imem_down_ptr_ram_double_ecc_err;
	u32 cmdsw_sop_fifo_single_ecc_err;
	u32 cmdsw_sop_fifo_double_ecc_err;
	u32 cmdsw_nsop_fifo_single_ecc_err;
	u32 cmdsw_nsop_fifo_double_ecc_err;
	u32 cmdsw_mmudat_fifo_single_ecc_err;
	u32 cmdsw_mmudat_fifo_double_ecc_err;
	u32 qlist_rd_release_fwft_single_ecc_err;
	u32 qlist_rd_release_fwft_double_ecc_err;
	u32 qlist_drop_imem_fwft_single_ecc_err;
	u32 qlist_drop_imem_fwft_double_ecc_err;
};

struct dpp_etm_qmu_csch_aged_cmd_cnt_t {
	u32 csch_aged_cmd_cnt;
};

struct dpp_etm_qmu_csch_qcfg_csch_congest_cnt_t {
	u32 csch_qcfg_csch_congest_cnt;
};

struct dpp_etm_qmu_csch_qcfg_qlist_csch_sop_cnt_t {
	u32 csch_qcfg_qlist_csch_sop_cnt;
};

struct dpp_etm_qmu_csch_qcfg_qlist_csch_eop_cnt_t {
	u32 csch_qcfg_qlist_csch_eop_cnt;
};

struct dpp_etm_qmu_csch_qcfg_csch_csw_sop_cnt_t {
	u32 csch_qcfg_csch_csw_sop_cnt;
};

struct dpp_etm_qmu_csch_qcfg_csch_csw_eop_cnt_t {
	u32 csch_qcfg_csch_csw_eop_cnt;
};

struct dpp_etm_qmu_csch_qcfg_qlist_csch_drop_cnt_t {
	u32 csch_qcfg_qlist_csch_drop_cnt;
};

struct dpp_etm_qmu_csch_qcfg_csch_csw_drop_cnt_t {
	u32 csch_qcfg_csch_csw_drop_cnt;
};

struct dpp_etm_qmu_csw_mmu_sop_cmd_cnt_t {
	u32 csw_mmu_sop_cmd_cnt;
};

struct dpp_etm_qmu_mmu_csw_sop_data_cnt_t {
	u32 mmu_csw_sop_data_cnt;
};

struct dpp_etm_qmu_csw_qsch_feedb_cnt_t {
	u32 csw_qsch_feedb_cnt;
};

struct dpp_etm_qmu_qmu_crdt_port_fc_cnt_t {
	u32 qmu_crdt_port_fc_cnt;
};

struct dpp_etm_qmu_csch_r_block_cnt_t {
	u32 csch_r_block_cnt;
};

struct dpp_etm_qmu_qcfg_qlist_qds_head_rd_t {
	u32 qcfg_qlist_qds_head_rd;
};

struct dpp_etm_qmu_qcfg_qlist_qds_tail_rd_t {
	u32 qcfg_qlist_qds_tail_rd;
};

struct dpp_etm_qmu_qcfg_qlist_ept_rd_t {
	u32 qcfg_qlist_ept_rd;
};

struct dpp_etm_qmu_qcfg_qlist_age_flag_rd_t {
	u32 qcfg_qlist_age_flag_rd;
};

struct dpp_etm_qmu_qcfg_qlist_cti_rd_t {
	u32 qcfg_qlist_cti_rd;
};

struct dpp_etm_qmu_qcfg_qlist_cto_rd_t {
	u32 qcfg_qlist_cto_rd;
};

struct dpp_etm_qmu_qcfg_qlist_chk_rd_t {
	u32 qcfg_qlist_chk_rd;
};

struct dpp_etm_qmu_qcfg_qlist_nod_rd_t {
	u32 qcfg_qlist_nod_rd;
};

struct dpp_etm_qmu_qcfg_qlist_biu_rd_t {
	u32 qcfg_qlist_biu_rd;
};

struct dpp_etm_qmu_qsch_r_wlist_flag_t {
	u32 qsch_r_wlist_flag;
};

struct dpp_etm_qmu_qcfg_crs_flg_rd_t {
	u32 qcfg_crs_flg_rd;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_age_qds_t {
	u32 cfgmt_qmu_imem_tp;
	u32 cfgmt_qmu_imem_hp;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_age_qlen_t {
	u32 cfgmt_qmu_imem_no_empty;
	u32 cfgmt_qmu_imem_qlen;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_pd_ram_low_t {
	u32 cfgmt_qmu_imem_pd_ram_low;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_pd_ram_high_t {
	u32 cfgmt_qmu_imem_pd_ram_high;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_up_ptr_t {
	u32 cfgmt_qmu_imem_up_ptr;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_down_ptr_t {
	u32 cfgmt_qmu_imem_down_ptr;
};

struct dpp_etm_qmu_cfgmt_qmu_imem_age_flag_t {
	u32 cfgmt_qmu_imem_age_flag;
};

struct dpp_etm_qmu_cfg_qsch_lkybkt2cngth_t {
	u32 cfg_qsch_lkybkt2cngth;
};

struct dpp_etm_qmu_cfg_qsch_lkybkt1cngth_t {
	u32 cfg_qsch_lkybkt1cngth;
};

struct dpp_etm_qmu_cfg_qsch_lkybkt3cngth_t {
	u32 cfg_qsch_lkybkt3cngth;
};

struct dpp_etm_qmu_cfg_qsch_rm_mul_mcn1_credit_value_t {
	u32 cfg_qsch_rm_mul_mcn1_credit_value;
};

struct dpp_etm_qmu_cfg_qsch_rm_mul_mcn2_credit_value_t {
	u32 cfg_qsch_rm_mul_mcn2_credit_value;
};

struct dpp_etm_qmu_cfg_qsch_rm_mul_mcn3_credit_value_t {
	u32 cfg_qsch_rm_mul_mcn3_credit_value;
};

struct dpp_etm_qmu_rm_mul_mcn1_rand_ansr_seed_t {
	u32 cfg_qsch_rm_mul_mcn1_rand_mchsm_en;
	u32 cfg_qsch_rm_mul_mcn1_rand_ansr_seed;
};

struct dpp_etm_qmu_rm_mul_mcn2_rand_ansr_seed_t {
	u32 cfg_qsch_rm_mul_mcn2_rand_mchsm_en;
	u32 cfg_qsch_rm_mul_mcn2_rand_ansr_seed;
};

struct dpp_etm_qmu_rm_mul_mcn3_rand_ansr_seed_t {
	u32 cfg_qsch_rm_mul_mcn3_rand_mchsm_en;
	u32 cfg_qsch_rm_mul_mcn3_rand_ansr_seed;
};

struct dpp_etm_qmu_rm_mul_mcn1_rand_ansr_th_t {
	u32 cfg_qsch_rm_mul_mcn1_rand_ansr_th;
};

struct dpp_etm_qmu_rm_mul_mcn2_rand_ansr_th_t {
	u32 cfg_qsch_rm_mul_mcn2_rand_ansr_th;
};

struct dpp_etm_qmu_rm_mul_mcn3_rand_ansr_th_t {
	u32 cfg_qsch_rm_mul_mcn3_rand_ansr_th;
};

struct dpp_etm_qmu_rm_mul_mcn1_rand_hold_base_t {
	u32 cfg_qsch_rm_mul_mcn1_rand_mchsm_en;
	u32 cfg_qsch_rm_mul_mcn1_rand_hold_base;
};

struct dpp_etm_qmu_rm_mul_mcn2_rand_hold_base_t {
	u32 cfg_qsch_rm_mul_mcn2_rand_mchsm_en;
	u32 cfg_qsch_rm_mul_mcn2_rand_hold_base;
};

struct dpp_etm_qmu_rm_mul_mcn3_rand_hold_base_t {
	u32 cfg_qsch_rm_mul_mcn3_rand_mchsm_en;
	u32 cfg_qsch_rm_mul_mcn3_rand_hold_base;
};

struct dpp_etm_qmu_rm_mul_mcn1_rand_sel_mask_t {
	u32 cfg_qsch_rm_mul_mcn1_rand_sel_mask;
};

struct dpp_etm_qmu_rm_mul_mcn2_rand_sel_mask_t {
	u32 cfg_qsch_rm_mul_mcn2_rand_sel_mask;
};

struct dpp_etm_qmu_rm_mul_mcn3_rand_sel_mask_t {
	u32 cfg_qsch_rm_mul_mcn3_rand_sel_mask;
};

struct dpp_etm_qmu_rm_mul_mcn1_rand_sel_seed_reg0_t {
	u32 rm_mul_mcn1_rand_sel_seed7;
	u32 rm_mul_mcn1_rand_sel_seed6;
	u32 rm_mul_mcn1_rand_sel_seed5;
	u32 rm_mul_mcn1_rand_sel_seed4;
	u32 rm_mul_mcn1_rand_sel_seed3;
	u32 rm_mul_mcn1_rand_sel_seed2;
	u32 rm_mul_mcn1_rand_sel_seed1;
	u32 rm_mul_mcn1_rand_sel_seed0;
};

struct dpp_etm_qmu_rm_mul_mcn1_rand_sel_seed_reg1_t {
	u32 rm_mul_mcn1_rand_sel_seed8;
};

struct dpp_etm_qmu_rm_mul_mcn2_rand_sel_seed_reg0_t {
	u32 rm_mul_mcn2_rand_sel_seed7;
	u32 rm_mul_mcn2_rand_sel_seed6;
	u32 rm_mul_mcn2_rand_sel_seed5;
	u32 rm_mul_mcn2_rand_sel_seed4;
	u32 rm_mul_mcn2_rand_sel_seed3;
	u32 rm_mul_mcn2_rand_sel_seed2;
	u32 rm_mul_mcn2_rand_sel_seed1;
	u32 rm_mul_mcn2_rand_sel_seed0;
};

struct dpp_etm_qmu_rm_mul_mcn2_rand_sel_seed_reg1_t {
	u32 rm_mul_mcn2_rand_sel_seed8;
};

struct dpp_etm_qmu_rm_mul_mcn3_rand_sel_seed_reg0_t {
	u32 rm_mul_mcn3_rand_sel_seed7;
	u32 rm_mul_mcn3_rand_sel_seed6;
	u32 rm_mul_mcn3_rand_sel_seed5;
	u32 rm_mul_mcn3_rand_sel_seed4;
	u32 rm_mul_mcn3_rand_sel_seed3;
	u32 rm_mul_mcn3_rand_sel_seed2;
	u32 rm_mul_mcn3_rand_sel_seed1;
	u32 rm_mul_mcn3_rand_sel_seed0;
};

struct dpp_etm_qmu_rm_mul_mcn3_rand_sel_seed_reg1_t {
	u32 rm_mul_mcn3_rand_sel_seed8;
};

struct dpp_etm_qmu_rm_mul_mcn1_step_wait_th1_t {
	u32 cfg_qsch_rm_mul_mcn1_step_wait_th1;
};

struct dpp_etm_qmu_rm_mul_mcn1_step_wait_th2_t {
	u32 cfg_qsch_rm_mul_mcn1_step_wait_th2;
};

struct dpp_etm_qmu_rm_mul_mcn1_step_wait_th3_t {
	u32 cfg_qsch_rm_mul_mcn1_step_wait_th3;
};

struct dpp_etm_qmu_rm_mul_mcn1_step_wait_th4_t {
	u32 cfg_qsch_rm_mul_mcn1_step_wait_th4;
};

struct dpp_etm_qmu_rm_mul_mcn1_step_wait_th5_t {
	u32 cfg_qsch_rm_mul_mcn1_step_wait_th5;
};

struct dpp_etm_qmu_rm_mul_mcn1_step_wait_th6_t {
	u32 cfg_qsch_rm_mul_mcn1_step_wait_th6;
};

struct dpp_etm_qmu_rm_mul_mcn1_step_wait_th7_t {
	u32 cfg_qsch_rm_mul_mcn1_step_wait_th7;
};

struct dpp_etm_qmu_rm_mul_mcn2_step_wait_th1_t {
	u32 cfg_qsch_rm_mul_mcn2_step_wait_th1;
};

struct dpp_etm_qmu_rm_mul_mcn2_step_wait_th2_t {
	u32 cfg_qsch_rm_mul_mcn2_step_wait_th2;
};

struct dpp_etm_qmu_rm_mul_mcn2_step_wait_th3_t {
	u32 cfg_qsch_rm_mul_mcn2_step_wait_th3;
};

struct dpp_etm_qmu_rm_mul_mcn2_step_wait_th4_t {
	u32 cfg_qsch_rm_mul_mcn2_step_wait_th4;
};

struct dpp_etm_qmu_rm_mul_mcn2_step_wait_th5_t {
	u32 cfg_qsch_rm_mul_mcn2_step_wait_th5;
};

struct dpp_etm_qmu_rm_mul_mcn2_step_wait_th6_t {
	u32 cfg_qsch_rm_mul_mcn2_step_wait_th6;
};

struct dpp_etm_qmu_rm_mul_mcn2_step_wait_th7_t {
	u32 cfg_qsch_rm_mul_mcn2_step_wait_th7;
};

struct dpp_etm_qmu_rm_mul_mcn3_step_wait_th1_t {
	u32 cfg_qsch_rm_mul_mcn3_step_wait_th1;
};

struct dpp_etm_qmu_rm_mul_mcn3_step_wait_th2_t {
	u32 cfg_qsch_rm_mul_mcn3_step_wait_th2;
};

struct dpp_etm_qmu_rm_mul_mcn3_step_wait_th3_t {
	u32 cfg_qsch_rm_mul_mcn3_step_wait_th3;
};

struct dpp_etm_qmu_rm_mul_mcn3_step_wait_th4_t {
	u32 cfg_qsch_rm_mul_mcn3_step_wait_th4;
};

struct dpp_etm_qmu_rm_mul_mcn3_step_wait_th5_t {
	u32 cfg_qsch_rm_mul_mcn3_step_wait_th5;
};

struct dpp_etm_qmu_rm_mul_mcn3_step_wait_th6_t {
	u32 cfg_qsch_rm_mul_mcn3_step_wait_th6;
};

struct dpp_etm_qmu_rm_mul_mcn3step_wait_th7_t {
	u32 cfg_qsch_rm_mul_mcn3_step_wait_th7;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate0_t {
	u32 cfg_qsch_mulcrdcntrate0;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate1_t {
	u32 cfg_qsch_mulcrdcntrate1;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate2_t {
	u32 cfg_qsch_mulcrdcntrate2;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate3_t {
	u32 cfg_qsch_mulcrdcntrate3;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate4_t {
	u32 cfg_qsch_mulcrdcntrate4;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate5_t {
	u32 cfg_qsch_mulcrdcntrate5;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate6_t {
	u32 cfg_qsch_mulcrdcntrate6;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate7_t {
	u32 cfg_qsch_mulcrdcntrate7;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate8_t {
	u32 cfg_qsch_mulcrdcntrate8;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate9_t {
	u32 cfg_qsch_mulcrdcntrate9;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate10_t {
	u32 cfg_qsch_mulcrdcntrate10;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate11_t {
	u32 cfg_qsch_mulcrdcntrate11;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate12_t {
	u32 cfg_qsch_mulcrdcntrate12;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate13_t {
	u32 cfg_qsch_mulcrdcntrate13;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate14_t {
	u32 cfg_qsch_mulcrdcntrate14;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate15_t {
	u32 cfg_qsch_mulcrdcntrate15;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate16_t {
	u32 cfg_qsch_mulcrdcntrate16;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate17_t {
	u32 cfg_qsch_mulcrdcntrate17;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate18_t {
	u32 cfg_qsch_mulcrdcntrate18;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate19_t {
	u32 cfg_qsch_mulcrdcntrate19;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate20_t {
	u32 cfg_qsch_mulcrdcntrate20;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate21_t {
	u32 cfg_qsch_mulcrdcntrate21;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate22_t {
	u32 cfg_qsch_mulcrdcntrate22;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate23_t {
	u32 cfg_qsch_mulcrdcntrate23;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate24_t {
	u32 cfg_qsch_mulcrdcntrate24;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate25_t {
	u32 cfg_qsch_mulcrdcntrate25;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate26_t {
	u32 cfg_qsch_mulcrdcntrate26;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate27_t {
	u32 cfg_qsch_mulcrdcntrate27;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate28_t {
	u32 cfg_qsch_mulcrdcntrate28;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate29_t {
	u32 cfg_qsch_mulcrdcntrate29;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate30_t {
	u32 cfg_qsch_mulcrdcntrate30;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate31_t {
	u32 cfg_qsch_mulcrdcntrate31;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate32_t {
	u32 cfg_qsch_mulcrdcntrate32;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate33_t {
	u32 cfg_qsch_mulcrdcntrate33;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate34_t {
	u32 cfg_qsch_mulcrdcntrate34;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate35_t {
	u32 cfg_qsch_mulcrdcntrate35;
};

struct dpp_etm_qmu_cfg_qsch_mulcrdcntrate36_t {
	u32 cfg_qsch_mulcrdcntrate36;
};

struct dpp_etm_qmu_cfg_qsch_rm_mul_mcn1_rand_hold_shift_t {
	u32 cfg_qsch_rm_mul_mcn1_rand_hold_shift;
};

struct dpp_etm_qmu_cfg_qsch_rm_mul_mcn2_rand_hold_shift_t {
	u32 cfg_qsch_rm_mul_mcn2_rand_hold_shift;
};

struct dpp_etm_qmu_cfg_qsch_rm_mul_mcn3_rand_hold_shift_t {
	u32 cfg_qsch_rm_mul_mcn3_rand_hold_shift;
};

struct dpp_etm_qmu_last_drop_qnum_get_t {
	u32 cgavd_qmu_drop_tap;
	u32 last_drop_qnum;
};

struct dpp_etm_qmu_crdt_qmu_credit_cnt_t {
	u32 crdt_qmu_credit_cnt;
};

struct dpp_etm_qmu_qmu_to_qsch_report_cnt_t {
	u32 qmu_to_qsch_report_cnt;
};

struct dpp_etm_qmu_qmu_to_cgavd_report_cnt_t {
	u32 qmu_to_cgavd_report_cnt;
};

struct dpp_etm_qmu_qmu_crdt_crs_normal_cnt_t {
	u32 qmu_crdt_crs_normal_cnt;
};

struct dpp_etm_qmu_qmu_crdt_crs_off_cnt_t {
	u32 qmu_crdt_crs_off_cnt;
};

struct dpp_etm_qmu_qsch_qlist_shedule_cnt_t {
	u32 qsch_qlist_shedule_cnt;
};

struct dpp_etm_qmu_qsch_qlist_sch_ept_cnt_t {
	u32 qsch_qlist_sch_ept_cnt;
};

struct dpp_etm_qmu_qmu_to_mmu_blk_wr_cnt_t {
	u32 qmu_to_mmu_blk_wr_cnt;
};

struct dpp_etm_qmu_qmu_to_csw_blk_rd_cnt_t {
	u32 qmu_to_csw_blk_rd_cnt;
};

struct dpp_etm_qmu_qmu_to_mmu_sop_wr_cnt_t {
	u32 qmu_to_mmu_sop_wr_cnt;
};

struct dpp_etm_qmu_qmu_to_mmu_eop_wr_cnt_t {
	u32 qmu_to_mmu_eop_wr_cnt;
};

struct dpp_etm_qmu_qmu_to_mmu_drop_wr_cnt_t {
	u32 qmu_to_mmu_drop_wr_cnt;
};

struct dpp_etm_qmu_qmu_to_csw_sop_rd_cnt_t {
	u32 qmu_to_csw_sop_rd_cnt;
};

struct dpp_etm_qmu_qmu_to_csw_eop_rd_cnt_t {
	u32 qmu_to_csw_eop_rd_cnt;
};

struct dpp_etm_qmu_qmu_to_csw_drop_rd_cnt_t {
	u32 qmu_to_csw_drop_rd_cnt;
};

struct dpp_etm_qmu_mmu_to_qmu_wr_release_cnt_t {
	u32 mmu_to_qmu_wr_release_cnt;
};

struct dpp_etm_qmu_mmu_to_qmu_rd_release_cnt_t {
	u32 mmu_to_qmu_rd_release_cnt;
};

struct dpp_etm_qmu_observe_qnum_set_t {
	u32 observe_qnum_set;
};

struct dpp_etm_qmu_spec_q_pkt_received_t {
	u32 spec_q_pkt_received;
};

struct dpp_etm_qmu_spec_q_pkt_dropped_t {
	u32 spec_q_pkt_dropped;
};

struct dpp_etm_qmu_spec_q_pkt_scheduled_t {
	u32 spec_q_pkt_scheduled;
};

struct dpp_etm_qmu_spec_q_wr_cmd_sent_t {
	u32 spec_q_wr_cmd_sent;
};

struct dpp_etm_qmu_spec_q_rd_cmd_sent_t {
	u32 spec_q_rd_cmd_sent;
};

struct dpp_etm_qmu_spec_q_pkt_enq_t {
	u32 spec_q_pkt_enq;
};

struct dpp_etm_qmu_spec_q_pkt_deq_t {
	u32 spec_q_pkt_deq;
};

struct dpp_etm_qmu_spec_q_crdt_uncon_received_t {
	u32 spec_q_crdt_uncon_received;
};

struct dpp_etm_qmu_spec_q_crdt_cong_received_t {
	u32 spec_q_crdt_cong_received;
};

struct dpp_etm_qmu_spec_q_crs_normal_cnt_t {
	u32 spec_q_crs_normal_cnt;
};

struct dpp_etm_qmu_spec_q_crs_off_cnt_t {
	u32 spec_q_crs_off_cnt;
};

struct dpp_etm_qmu_observe_batch_set_t {
	u32 observe_batch_set;
};

struct dpp_etm_qmu_spec_bat_pkt_received_t {
	u32 spec_bat_pkt_received;
};

struct dpp_etm_qmu_spec_bat_pkt_dropped_t {
	u32 spec_bat_pkt_dropped;
};

struct dpp_etm_qmu_spec_bat_blk_scheduled_t {
	u32 spec_bat_blk_scheduled;
};

struct dpp_etm_qmu_spec_bat_wr_cmd_sent_t {
	u32 spec_bat_wr_cmd_sent;
};

struct dpp_etm_qmu_spec_bat_rd_cmd_sent_t {
	u32 spec_bat_rd_cmd_sent;
};

struct dpp_etm_qmu_spec_bat_pkt_enq_t {
	u32 spec_bat_pkt_enq;
};

struct dpp_etm_qmu_spec_bat_pkt_deq_t {
	u32 spec_bat_pkt_deq;
};

struct dpp_etm_qmu_spec_bat_crdt_uncon_received_t {
	u32 spec_bat_crdt_uncon_received;
};

struct dpp_etm_qmu_spec_bat_crdt_cong_received_t {
	u32 spec_bat_crdt_cong_received;
};

struct dpp_etm_qmu_spec_bat_crs_normal_cnt_t {
	u32 spec_bat_crs_normal_cnt;
};

struct dpp_etm_qmu_spec_bat_crs_off_cnt_t {
	u32 spec_bat_crs_off_cnt;
};

struct dpp_etm_qmu_bcntm_ovfl_qnum_get_t {
	u32 bcntm_ovfl_qnum_get;
};

struct dpp_etm_qmu_crbal_a_ovf_qnum_get_t {
	u32 crbal_a_ovf_qnum_get;
};

struct dpp_etm_qmu_crbal_b_ovf_qnum_get_t {
	u32 crbal_b_ovf_qnum_get;
};

struct dpp_etm_qmu_crbal_drop_qnum_get_t {
	u32 crbal_drop_qnum_get;
};

struct dpp_etm_qmu_deq_flg_report_cnt_t {
	u32 deq_flg_report_cnt;
};

struct dpp_etm_qmu_spec_q_crs_get_t {
	u32 spec_q_crs_get;
};

struct dpp_etm_qmu_spec_q_crs_in_get_t {
	u32 spec_q_crs_in_get;
};

struct dpp_etm_qmu_spec_q_crs_flg_csol_get_t {
	u32 spec_q_crs_flg_csol_get;
};

struct dpp_etm_qmu_ept_sch_qnum_get_t {
	u32 ept_sch_qnum_get;
};

#endif
