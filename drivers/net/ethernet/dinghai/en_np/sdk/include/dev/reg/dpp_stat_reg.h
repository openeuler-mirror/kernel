/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_STAT_REG_H_
#define _DPP_STAT_REG_H_
struct dpp_stat_stat_cfg_cpu_ind_eram_wdat0_t {
	u32 cpu_ind_eram_wdat0;
};

struct dpp_stat_stat_cfg_etm_port_sel_cfg_t {
	u32 etm_port0_sel_cfg;
	u32 etm_port1_sel_cfg;
	u32 etm_port2_sel_cfg;
	u32 etm_port3_sel_cfg;
};

struct dpp_stat_stat_cfg_tm_stat_cfg_t {
	u32 stat_overflow_mode;
	u32 tm_stat_mode_cfg;
	u32 tm_flow_control_cfg;
};

struct dpp_stat_stat_cfg_ppu_eram_depth_t {
	u32 ppu_eram_depth;
};

struct dpp_stat_stat_cfg_ppu_eram_base_addr_t {
	u32 ppu_eram_base_addr;
};

struct dpp_stat_stat_cfg_ppu_ddr_base_addr_t {
	u32 ppu_ddr_base_addr;
};

struct dpp_stat_stat_cfg_plcr0_base_addr_t {
	u32 plcr0_base_addr;
};

struct dpp_stat_stat_cfg_etm_stat_start_addr_cfg_t {
	u32 etm_stat_start_addr_cfg;
};

struct dpp_stat_stat_cfg_etm_stat_depth_cfg_t {
	u32 etm_stat_depth_cfg;
};

struct dpp_stat_stat_cfg_cycle_mov_en_cfg_t {
	u32 cycle_mov_en_cfg;
};

struct dpp_stat_etcam_cpu_ind_wdat0_t {
	u32 wdat0;
};

struct dpp_stat_etcam_cpu_ind_ctrl_tmp0_t {
	u32 reg_tcam_flag;
	u32 flush;
	u32 rd_wr;
	u32 wr_mode;
	u32 dat_or_mask;
	u32 ram_sel;
	u32 addr;
};

struct dpp_stat_etcam_cpu_ind_ctrl_tmp1_t {
	u32 row_or_col_msk;
	u32 vben;
	u32 vbit;
};

struct dpp_stat_etcam_cpu_ind_rd_done_t {
	u32 cpu_ind_rd_done;
};

struct dpp_stat_etcam_cpu_rdat0_t {
	u32 cpu_rdat0;
};

struct dpp_stat_etcam_cpu_rdat1_t {
	u32 cpu_rdat1;
};

struct dpp_stat_etcam_cpu_rdat2_t {
	u32 cpu_rdat2;
};

struct dpp_stat_etcam_cpu_rdat3_t {
	u32 cpu_rdat3;
};

struct dpp_stat_etcam_cpu_rdat4_t {
	u32 cpu_rdat4;
};

struct dpp_stat_etcam_cpu_rdat5_t {
	u32 cpu_rdat5;
};

struct dpp_stat_etcam_cpu_rdat6_t {
	u32 cpu_rdat6;
};

struct dpp_stat_etcam_cpu_rdat7_t {
	u32 cpu_rdat7;
};

struct dpp_stat_etcam_cpu_rdat8_t {
	u32 cpu_rdat8;
};

struct dpp_stat_etcam_cpu_rdat9_t {
	u32 cpu_rdat9;
};

struct dpp_stat_etcam_cpu_rdat10_t {
	u32 cpu_rdat10;
};

struct dpp_stat_etcam_cpu_rdat11_t {
	u32 cpu_rdat11;
};

struct dpp_stat_etcam_cpu_rdat12_t {
	u32 cpu_rdat12;
};

struct dpp_stat_etcam_cpu_rdat13_t {
	u32 cpu_rdat13;
};

struct dpp_stat_etcam_cpu_rdat14_t {
	u32 cpu_rdat14;
};

struct dpp_stat_etcam_cpu_rdat15_t {
	u32 cpu_rdat15;
};

struct dpp_stat_etcam_cpu_rdat16_t {
	u32 cpu_rdat16;
};

struct dpp_stat_etcam_cpu_rdat17_t {
	u32 cpu_rdat17;
};

struct dpp_stat_etcam_cpu_rdat18_t {
	u32 cpu_rdat18;
};

struct dpp_stat_etcam_cpu_rdat19_t {
	u32 cpu_rdat19;
};

struct dpp_stat_etcam_qvbo_t {
	u32 qvbo;
};

struct dpp_stat_etcam_cnt_overflow_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_stat_car0_cara_queue_ram0_159_0_t {
	u32 cara_drop;
	u32 cara_plcr_en;
	u32 cara_profile_id;
	u32 cara_tq_h;
	u32 cara_tq_l;
	u32 cara_ted;
	u32 cara_tcd;
	u32 cara_tei;
	u32 cara_tci;
};

struct dpp_stat_car0_cara_profile_ram1_255_0_t {
	u32 cara_profile_wr;
	u32 cara_pkt_sign;
	u32 cara_cd;
	u32 cara_cf;
	u32 cara_cm;
	u32 cara_eir;
	u32 cara_cir;
	u32 cara_ebs_pbs;
	u32 cara_cbs;
	u32 cara_c_pri1;
	u32 cara_c_pri2;
	u32 cara_c_pri3;
	u32 cara_c_pri4;
	u32 cara_c_pri5;
	u32 cara_c_pri6;
	u32 cara_c_pri7;
	u32 cara_e_g_pri1;
	u32 cara_e_g_pri2;
	u32 cara_e_g_pri3;
	u32 cara_e_g_pri4;
	u32 cara_e_g_pri5;
	u32 cara_e_g_pri6;
	u32 cara_e_g_pri7;
	u32 cara_e_y_pri0;
	u32 cara_e_y_pri1;
	u32 cara_e_y_pri2;
	u32 cara_e_y_pri3;
	u32 cara_e_y_pri4;
	u32 cara_e_y_pri5;
	u32 cara_e_y_pri6;
	u32 cara_e_y_pri7;
};

struct dpp_stat_car0_cara_qovs_ram_ram2_t {
	u32 cara_qovs;
};

struct dpp_stat_car0_look_up_table1_t {
	u32 cara_flow_id;
	u32 cara_sp;
};

struct dpp_stat_car0_cara_pkt_des_i_cnt_t {
	u32 cara_pkt_des_i_cnt;
};

struct dpp_stat_car0_cara_green_pkt_i_cnt_t {
	u32 cara_green_pkt_i_cnt;
};

struct dpp_stat_car0_cara_yellow_pkt_i_cnt_t {
	u32 cara_yellow_pkt_i_cnt;
};

struct dpp_stat_car0_cara_red_pkt_i_cnt_t {
	u32 cara_red_pkt_i_cnt;
};

struct dpp_stat_car0_cara_pkt_des_o_cnt_t {
	u32 cara_pkt_des_o_cnt;
};

struct dpp_stat_car0_cara_green_pkt_o_cnt_t {
	u32 cara_green_pkt_o_cnt;
};

struct dpp_stat_car0_cara_yellow_pkt_o_cnt_t {
	u32 cara_yellow_pkt_o_cnt;
};

struct dpp_stat_car0_cara_red_pkt_o_cnt_t {
	u32 cara_red_pkt_o_cnt;
};

struct dpp_stat_car0_cara_pkt_des_fc_for_cfg_cnt_t {
	u32 cara_pkt_des_fc_for_cfg_cnt;
};

struct dpp_stat_car0_cara_appoint_qnum_or_sp_t {
	u32 cara_appoint_qnum_or_not;
	u32 cara_appoint_sp_or_not;
	u32 cara_plcr_stat_sp;
	u32 cara_plcr_stat_qnum;
};

struct dpp_stat_car0_cara_cfgmt_count_mode_t {
	u32 cara_cfgmt_count_overflow_mode;
	u32 cara_cfgmt_count_rd_mode;
};

struct dpp_stat_car0_cara_pkt_size_cnt_t {
	u32 cara_pkt_size_cnt;
};

struct dpp_stat_car0_cara_plcr_init_dont_t {
	u32 cara_plcr_init_done;
};

struct dpp_stat_car0_carb_queue_ram0_159_0_t {
	u32 carb_drop;
	u32 carb_plcr_en;
	u32 carb_profile_id;
	u32 carb_tq_h;
	u32 carb_tq_l;
	u32 carb_ted;
	u32 carb_tcd;
	u32 carb_tei;
	u32 carb_tci;
};

struct dpp_stat_car0_carb_profile_ram1_255_0_t {
	u32 carb_profile_wr;
	u32 carb_random_discard_en_e;
	u32 carb_random_discard_en_c;
	u32 carb_pkt_sign;
	u32 carb_cd;
	u32 carb_cf;
	u32 carb_cm;
	u32 carb_eir;
	u32 carb_cir;
	u32 carb_ebs_pbs;
	u32 carb_cbs;
	u32 carb_c_pri1;
	u32 carb_c_pri2;
	u32 carb_c_pri3;
	u32 carb_c_pri4;
	u32 carb_c_pri5;
	u32 carb_c_pri6;
	u32 carb_c_pri7;
	u32 carb_e_g_pri1;
	u32 carb_e_g_pri2;
	u32 carb_e_g_pri3;
	u32 carb_e_g_pri4;
	u32 carb_e_g_pri5;
	u32 carb_e_g_pri6;
	u32 carb_e_g_pri7;
	u32 carb_e_y_pri0;
	u32 carb_e_y_pri1;
	u32 carb_e_y_pri2;
	u32 carb_e_y_pri3;
	u32 carb_e_y_pri4;
	u32 carb_e_y_pri5;
	u32 carb_e_y_pri6;
	u32 carb_e_y_pri7;
};

struct dpp_stat_car0_carb_qovs_ram_ram2_t {
	u32 carb_qovs;
};

struct dpp_stat_car0_look_up_table2_t {
	u32 carb_flow_id;
	u32 carb_sp;
};

struct dpp_stat_car0_carb_pkt_des_i_cnt_t {
	u32 carb_pkt_des_i_cnt;
};

struct dpp_stat_car0_carb_green_pkt_i_cnt_t {
	u32 carb_green_pkt_i_cnt;
};

struct dpp_stat_car0_carb_yellow_pkt_i_cnt_t {
	u32 carb_yellow_pkt_i_cnt;
};

struct dpp_stat_car0_carb_red_pkt_i_cnt_t {
	u32 carb_red_pkt_i_cnt;
};

struct dpp_stat_car0_carb_pkt_des_o_cnt_t {
	u32 carb_pkt_des_o_cnt;
};

struct dpp_stat_car0_carb_green_pkt_o_cnt_t {
	u32 carb_green_pkt_o_cnt;
};

struct dpp_stat_car0_carb_yellow_pkt_o_cnt_t {
	u32 carb_yellow_pkt_o_cnt;
};

struct dpp_stat_car0_carb_red_pkt_o_cnt_t {
	u32 carb_red_pkt_o_cnt;
};

struct dpp_stat_car0_carb_pkt_des_fc_for_cfg_cnt_t {
	u32 carb_pkt_des_fc_for_cfg_cnt;
};

struct dpp_stat_car0_carb_appoint_qnum_or_sp_t {
	u32 carb_appoint_qnum_or_not;
	u32 carb_appoint_sp_or_not;
	u32 carb_plcr_stat_sp;
	u32 carb_plcr_stat_qnum;
};

struct dpp_stat_car0_carb_cfgmt_count_mode_t {
	u32 carb_cfgmt_count_overflow_mode;
	u32 carb_cfgmt_count_rd_mode;
};

struct dpp_stat_car0_carb_pkt_size_cnt_t {
	u32 carb_pkt_size_cnt;
};

struct dpp_stat_car0_carb_plcr_init_dont_t {
	u32 carb_plcr_init_done;
};

struct dpp_stat_car0_carc_queue_ram0_159_0_t {
	u32 carc_drop;
	u32 carc_plcr_en;
	u32 carc_profile_id;
	u32 carc_tq_h;
	u32 carc_tq_l;
	u32 carc_ted;
	u32 carc_tcd;
	u32 carc_tei;
	u32 carc_tci;
};

struct dpp_stat_car0_carc_profile_ram1_255_0_t {
	u32 carc_profile_wr;
	u32 carc_random_discard_en_e;
	u32 carc_random_discard_en_c;
	u32 carc_pkt_sign;
	u32 carc_cd;
	u32 carc_cf;
	u32 carc_cm;
	u32 carc_eir;
	u32 carc_cir;
	u32 carc_ebs_pbs;
	u32 carc_cbs;
	u32 carc_c_pri1;
	u32 carc_c_pri2;
	u32 carc_c_pri3;
	u32 carc_c_pri4;
	u32 carc_c_pri5;
	u32 carc_c_pri6;
	u32 carc_c_pri7;
	u32 carc_e_g_pri1;
	u32 carc_e_g_pri2;
	u32 carc_e_g_pri3;
	u32 carc_e_g_pri4;
	u32 carc_e_g_pri5;
	u32 carc_e_g_pri6;
	u32 carc_e_g_pri7;
	u32 carc_e_y_pri0;
	u32 carc_e_y_pri1;
	u32 carc_e_y_pri2;
	u32 carc_e_y_pri3;
	u32 carc_e_y_pri4;
	u32 carc_e_y_pri5;
	u32 carc_e_y_pri6;
	u32 carc_e_y_pri7;
};

struct dpp_stat_car0_carc_qovs_ram_ram2_t {
	u32 carc_qovs;
};

struct dpp_stat_car0_carc_pkt_des_i_cnt_t {
	u32 carc_pkt_des_i_cnt;
};

struct dpp_stat_car0_carc_green_pkt_i_cnt_t {
	u32 carc_green_pkt_i_cnt;
};

struct dpp_stat_car0_carc_yellow_pkt_i_cnt_t {
	u32 carc_yellow_pkt_i_cnt;
};

struct dpp_stat_car0_carc_red_pkt_i_cnt_t {
	u32 carc_red_pkt_i_cnt;
};

struct dpp_stat_car0_carc_pkt_des_o_cnt_t {
	u32 carc_pkt_des_o_cnt;
};

struct dpp_stat_car0_carc_green_pkt_o_cnt_t {
	u32 carc_green_pkt_o_cnt;
};

struct dpp_stat_car0_carc_yellow_pkt_o_cnt_t {
	u32 carc_yellow_pkt_o_cnt;
};

struct dpp_stat_car0_carc_red_pkt_o_cnt_t {
	u32 carc_red_pkt_o_cnt;
};

struct dpp_stat_car0_carc_pkt_des_fc_for_cfg_cnt_t {
	u32 carc_pkt_des_fc_for_cfg_cnt;
};

struct dpp_stat_car0_carc_appoint_qnum_or_sp_t {
	u32 carc_appoint_qnum_or_not;
	u32 carc_appoint_sp_or_not;
	u32 carc_plcr_stat_sp;
	u32 carc_plcr_stat_qnum;
};

struct dpp_stat_car0_carc_cfgmt_count_mode_t {
	u32 carc_cfgmt_count_overflow_mode;
	u32 carc_cfgmt_count_rd_mode;
};

struct dpp_stat_car0_carc_pkt_size_cnt_t {
	u32 carc_pkt_size_cnt;
};

struct dpp_stat_car0_carc_plcr_init_dont_t {
	u32 carc_plcr_init_done;
};

struct dpp_stat_car0_carb_random_ram_t {
	u32 para8_e;
	u32 para7_e;
	u32 para6_e;
	u32 para5_e;
	u32 para4_h_e;
	u32 para4_l_e;
	u32 para3_e;
	u32 para2_h_e;
	u32 para2_l_e;
	u32 para1_e;
	u32 para0_h_e;
	u32 para0_l_e;
	u32 para8_c;
	u32 para7_c;
	u32 para6_c;
	u32 para5_c;
	u32 para4_h_c;
	u32 para4_l_c;
	u32 para3_c;
	u32 para2_h_c;
	u32 para2_l_c;
	u32 para1_c;
	u32 para0_h_c;
	u32 para0_l_c;
};

struct dpp_stat_car0_carc_random_ram_t {
	u32 para8_e;
	u32 para7_e;
	u32 para6_e;
	u32 para5_e;
	u32 para4_h_e;
	u32 para4_l_e;
	u32 para3_e;
	u32 para2_h_e;
	u32 para2_l_e;
	u32 para1_e;
	u32 para0_h_e;
	u32 para0_l_e;
	u32 para8_c;
	u32 para7_c;
	u32 para6_c;
	u32 para5_c;
	u32 para4_h_c;
	u32 para4_l_c;
	u32 para3_c;
	u32 para2_h_c;
	u32 para2_l_c;
	u32 para1_c;
	u32 para0_h_c;
	u32 para0_l_c;
};

struct dpp_stat_car0_cara_begin_flow_id_t {
	u32 cara_begin_flow_id;
};

struct dpp_stat_car0_carb_begin_flow_id_t {
	u32 carb_begin_flow_id;
};

struct dpp_stat_car0_carc_begin_flow_id_t {
	u32 carc_begin_flow_id;
};

struct dpp_stat_car0_prog_full_assert_cfg_w_t {
	u32 prog_full_assert_cfg_w;
};

struct dpp_stat_car0_prog_full_negate_cfg_w_t {
	u32 prog_full_negate_cfg_w;
};

struct dpp_stat_car0_timeout_limit_t {
	u32 timeout_limit;
};

struct dpp_stat_car0_pkt_des_fifo_overflow_t {
	u32 pkt_des_fifo_overflow;
};

struct dpp_stat_car0_pkt_des_fifo_underflow_t {
	u32 pkt_des_fifo_underflow;
};

struct dpp_stat_car0_pkt_des_fifo_prog_full_t {
	u32 pkt_des_fifo_prog_full;
};

struct dpp_stat_car0_pkt_des_fifo_prog_empty_t {
	u32 pkt_des_fifo_prog_empty;
};

struct dpp_stat_car0_pkt_des_fifo_full_t {
	u32 pkt_des_fifo_full;
};

struct dpp_stat_car0_pkt_des_fifo_empty_t {
	u32 pkt_des_fifo_empty;
};

struct dpp_stat_car0_pkt_size_offset_t {
	u32 pkt_size_offset;
};

struct dpp_stat_car0_car_plcr_init_dont_t {
	u32 plcr_init_done;
};

struct dpp_stat_car0_max_pkt_size_a_t {
	u32 max_pkt_size_a;
};

struct dpp_stat_car0_max_pkt_size_b_t {
	u32 max_pkt_size_b;
};

struct dpp_stat_car0_max_pkt_size_c_t {
	u32 max_pkt_size_c;
};

struct dpp_stat_car0_car_hierarchy_mode_t {
	u32 car_hierarchy_mode;
};

struct dpp_stat_car0_prog_empty_assert_cfg_w_t {
	u32 prog_empty_assert_cfg_w;
};

struct dpp_stat_car0_prog_empty_negate_cfg_w_t {
	u32 prog_empty_negate_cfg_w;
};

struct dpp_stat_car0_pkt_des_fifo_ovf_int_t {
	u32 pkt_des_fifo_ovf_int;
};

struct dpp_stat_car0_pkt_des_fifo_data_count_t {
	u32 pkt_des_fifo_data_count;
};

struct dpp_stat_car0_pkt_des_fifo_udf_int_t {
	u32 pkt_des_fifo_udf_int;
};

struct dpp_stat_car0_cara_queue_ram0_159_0_pkt_t {
	u32 cara_drop;
	u32 cara_plcr_en;
	u32 cara_profile_id;
	u32 cara_tq_h;
	u32 cara_tq_l;
	u32 cara_dc_high;
	u32 cara_dc_low;
	u32 cara_tc;
};

struct dpp_stat_car0_cara_profile_ram1_255_0_pkt_t {
	u32 cara_profile_wr;
	u32 cara_pkt_sign;
	u32 cara_pkt_cir;
	u32 cara_pkt_cbs;
	u32 cara_pri0;
	u32 cara_pri1;
	u32 cara_pri2;
	u32 cara_pri3;
	u32 cara_pri4;
	u32 cara_pri5;
	u32 cara_pri6;
	u32 cara_pri7;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_wdat1_t {
	u32 cpu_ind_eram_wdat1;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_wdat2_t {
	u32 cpu_ind_eram_wdat2;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_wdat3_t {
	u32 cpu_ind_eram_wdat3;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_req_info_t {
	u32 rw_mode;
	u32 read_mode;
	u32 tm_cs;
	u32 queue_cs;
	u32 rw_addr;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_rd_done_t {
	u32 cpu_ind_eram_rd_done;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_rdat0_t {
	u32 cpu_ind_eram_rdat0;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_rdat1_t {
	u32 cpu_ind_eram_rdat1;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_rdat2_t {
	u32 cpu_ind_eram_rdat2;
};

struct dpp_stat_stat_cfg_cpu_ind_eram_rdat3_t {
	u32 cpu_ind_eram_rdat3;
};

struct dpp_stat_stat_cfg_tm_alu_eram_cpu_rdy_t {
	u32 tm_alu_eram_cpu_rdy;
};

struct dpp_stat_stat_cfg_oam_stat_cfg_t {
	u32 oam_flow_control_cfg;
	u32 oam_lm_flow_control_cfg;
	u32 oam_in_eram_cfg;
};

struct dpp_stat_stat_cfg_ftm_port_sel_cfg_t {
	u32 ftm_port0_sel_cfg;
	u32 ftm_port1_sel_cfg;
	u32 ftm_port2_sel_cfg;
	u32 ftm_port3_sel_cfg;
};

struct dpp_stat_stat_cfg_oam_eram_base_addr_t {
	u32 oam_eram_base_addr;
};

struct dpp_stat_stat_cfg_oam_lm_eram_base_addr_t {
	u32 oam_lm_eram_base_addr;
};

struct dpp_stat_stat_cfg_oam_ddr_base_addr_t {
	u32 oam_ddr_base_addr;
};

struct dpp_stat_stat_cfg_plcr0_schd_pful_cfg_t {
	u32 plcr0_schd_pful_assert;
	u32 plcr0_schd_pful_negate;
};

struct dpp_stat_stat_cfg_oam_lm_ord_pful_cfg_t {
	u32 oam_lm_ord_pful_assert;
	u32 oam_lm_ord_pful_negate;
};

struct dpp_stat_stat_cfg_ddr_schd_pful_cfg_t {
	u32 ddr_schd_pful_assert;
	u32 ddr_schd_pful_negate;
};

struct dpp_stat_stat_cfg_eram_schd_pful_cfg_t {
	u32 eram_schd_pful_assert;
	u32 eram_schd_pful_negate;
};

struct dpp_stat_stat_cfg_eram_schd_pept_cfg_t {
	u32 eram_schd_pept_assert;
	u32 eram_schd_pept_negate;
};

struct dpp_stat_stat_cfg_eram_schd_oam_pful_cfg_t {
	u32 eram_schd_oam_pful_assert;
	u32 eram_schd_oam_pful_negate;
};

struct dpp_stat_stat_cfg_eram_schd_oam_pept_cfg_t {
	u32 eram_schd_oam_pept_assert;
	u32 eram_schd_oam_pept_negate;
};

struct dpp_stat_stat_cfg_eram_schd_oam_lm_pful_cfg_t {
	u32 eram_schd_oam_lm_pful_assert;
	u32 eram_schd_oam_lm_pful_negate;
};

struct dpp_stat_stat_cfg_eram_schd_oam_lm_pept_cfg_t {
	u32 eram_schd_oam_lm_pept_assert;
	u32 eram_schd_oam_lm_pept_negate;
};

struct dpp_stat_stat_cfg_rschd_pful_cfg_t {
	u32 rschd_pful_assert;
	u32 rschd_pful_negate;
};

struct dpp_stat_stat_cfg_rschd_pept_cfg_t {
	u32 rschd_pept_assert;
	u32 rschd_pept_negate;
};

struct dpp_stat_stat_cfg_rschd_plcr_pful_cfg_t {
	u32 rschd_plcr_pful_assert;
	u32 rschd_plcr_pful_negate;
};

struct dpp_stat_stat_cfg_rschd_plcr_pept_cfg_t {
	u32 rschd_plcr_pept_assert;
	u32 rschd_plcr_pept_negate;
};

struct dpp_stat_stat_cfg_rschd_plcr_info_pful_cfg_t {
	u32 rschd_plcr_info_pful_assert;
	u32 rschd_plcr_info_pful_negate;
};

struct dpp_stat_stat_cfg_alu_arb_cpu_pful_cfg_t {
	u32 alu_arb_cpu_pful_assert;
	u32 alu_arb_cpu_pful_negate;
};

struct dpp_stat_stat_cfg_alu_arb_user_pful_cfg_t {
	u32 alu_arb_user_pful_assert;
	u32 alu_arb_user_pful_negate;
};

struct dpp_stat_stat_cfg_alu_arb_stat_pful_cfg_t {
	u32 alu_arb_stat_pful_assert;
	u32 alu_arb_stat_pful_negate;
};

struct dpp_stat_stat_cfg_cycmov_dat_pful_cfg_t {
	u32 cycmov_dat_pful_assert;
	u32 cycmov_dat_pful_negate;
};

struct dpp_stat_stat_cfg_ddr_opr_pful_cfg_t {
	u32 ddr_opr_pful_assert;
	u32 ddr_opr_pful_negate;
};

struct dpp_stat_stat_cfg_cycle_mov_pful_cfg_t {
	u32 cycle_mov_pful_assert;
	u32 cycle_mov_pful_negate;
};

struct dpp_stat_stat_cfg_cntovf_pful_cfg_t {
	u32 cntovf_pful_assert;
	u32 cntovf_pful_negate;
};

struct dpp_stat_stat_cfg_eram_schd_plcr_pful_cfg_t {
	u32 eram_schd_plcr_pful_assert;
	u32 eram_schd_plcr_pful_negate;
};

struct dpp_stat_stat_cfg_eram_schd_plcr_pept_cfg_t {
	u32 eram_schd_plcr_pept_assert;
	u32 eram_schd_plcr_pept_negate;
};

struct dpp_stat_stat_cfg_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_stat_stat_cfg_tm_mov_period_cfg_t {
	u32 etm_mov_period_cfg;
	u32 ftm_mov_period_cfg;
};

struct dpp_stat_stat_cfg_alu_ddr_cpu_req_pful_cfg_t {
	u32 alu_ddr_cpu_req_pful_assert;
	u32 alu_ddr_cpu_req_pful_negate;
};

struct dpp_stat_stat_cfg_cycmov_addr_pful_cfg_t {
	u32 cycmov_addr_pful_assert;
	u32 cycmov_addr_pful_negate;
};

struct dpp_stat_stat_cfg_ord_ddr_plcr_fifo_empty_t {
	u32 ord_oam_lm_empty;
	u32 ddr_schd_fifo_empty;
	u32 plcr0_schd_fifo_empty;
};

struct dpp_stat_stat_cfg_tm_stat_fifo_empty_t {
	u32 tm_stat_fifo_empty;
};

struct dpp_stat_stat_cfg_eram_schd_fifo_empty_0_1_t {
	u32 eram_schd_fifo_empty1;
	u32 eram_schd_fifo_empty0;
};

struct dpp_stat_stat_cfg_eram_schd_fifo_empty_2_3_t {
	u32 eram_schd_fifo_empty3;
	u32 eram_schd_fifo_empty2;
};

struct dpp_stat_stat_cfg_eram_schd_fifo_empty_4_5_t {
	u32 eram_schd_fifo_empty5;
	u32 eram_schd_fifo_empty4;
};

struct dpp_stat_stat_cfg_eram_schd_fifo_empty_6_7_t {
	u32 eram_schd_fifo_empty7;
	u32 eram_schd_fifo_empty6;
};

struct dpp_stat_stat_cfg_eram_schd_fifo_empty_free_8_t {
	u32 eram_schd_free_fifo_empty8;
	u32 eram_schd_free_fifo_empty7;
	u32 eram_schd_free_fifo_empty6;
	u32 eram_schd_free_fifo_empty5;
	u32 eram_schd_free_fifo_empty4;
	u32 eram_schd_free_fifo_empty3;
	u32 eram_schd_free_fifo_empty2;
	u32 eram_schd_free_fifo_empty1;
	u32 eram_schd_free_fifo_empty0;
	u32 eram_schd_fifo_empty8;
};

struct dpp_stat_stat_cfg_rschd_fifo_empty_0_3_t {
	u32 rschd_fifo_empty3;
	u32 rschd_fifo_empty2;
	u32 rschd_fifo_empty1;
	u32 rschd_fifo_empty0;
};

struct dpp_stat_stat_cfg_rschd_fifo_empty_4_7_t {
	u32 rschd_fifo_empty7;
	u32 rschd_fifo_empty6;
	u32 rschd_fifo_empty5;
	u32 rschd_fifo_empty4;
};

struct dpp_stat_stat_cfg_rschd_fifo_empty_8_11_t {
	u32 rschd_fifo_empty11;
	u32 rschd_fifo_empty10;
	u32 rschd_fifo_empty9;
	u32 rschd_fifo_empty8;
};

struct dpp_stat_stat_cfg_rschd_fifo_empty_12_15_t {
	u32 rschd_fifo_empty15;
	u32 rschd_fifo_empty14;
	u32 rschd_fifo_empty13;
	u32 rschd_fifo_empty12;
};

struct dpp_stat_stat_cfg_rschd_fifo_empty_plcr_16_17_t {
	u32 rschd_fifo_empty_plcr;
	u32 rschd_fifo_empty17;
	u32 rschd_fifo_empty16;
};

struct dpp_stat_stat_cfg_stat_int_unmask_flag_t {
	u32 stat_int5_unmask_flag;
	u32 stat_int4_unmask_flag;
	u32 stat_int3_unmask_flag;
	u32 stat_int2_unmask_flag;
	u32 stat_int1_unmask_flag;
	u32 stat_int0_unmask_flag;
};

struct dpp_stat_stat_cfg_stat_int0_en_t {
	u32 stat_int0_en31;
	u32 stat_int0_en30;
	u32 stat_int0_en29;
	u32 stat_int0_en28;
	u32 stat_int0_en27;
	u32 stat_int0_en26;
	u32 stat_int0_en25;
	u32 stat_int0_en24;
	u32 stat_int0_en23;
	u32 stat_int0_en22;
	u32 stat_int0_en21;
	u32 stat_int0_en20;
	u32 stat_int0_en19;
	u32 stat_int0_en18;
	u32 stat_int0_en17;
	u32 stat_int0_en16;
	u32 stat_int0_en15;
	u32 stat_int0_en14;
	u32 stat_int0_en13;
	u32 stat_int0_en12;
	u32 stat_int0_en11;
	u32 stat_int0_en10;
	u32 stat_int0_en9;
	u32 stat_int0_en8;
	u32 stat_int0_en7;
	u32 stat_int0_en6;
	u32 stat_int0_en5;
	u32 stat_int0_en4;
	u32 stat_int0_en3;
	u32 stat_int0_en2;
	u32 stat_int0_en1;
	u32 stat_int0_en0;
};

struct dpp_stat_stat_cfg_stat_int0_mask_t {
	u32 stat_int0_mask31;
	u32 stat_int0_mask30;
	u32 stat_int0_mask29;
	u32 stat_int0_mask28;
	u32 stat_int0_mask27;
	u32 stat_int0_mask26;
	u32 stat_int0_mask25;
	u32 stat_int0_mask24;
	u32 stat_int0_mask23;
	u32 stat_int0_mask22;
	u32 stat_int0_mask21;
	u32 stat_int0_mask20;
	u32 stat_int0_mask19;
	u32 stat_int0_mask18;
	u32 stat_int0_mask17;
	u32 stat_int0_mask16;
	u32 stat_int0_mask15;
	u32 stat_int0_mask14;
	u32 stat_int0_mask13;
	u32 stat_int0_mask12;
	u32 stat_int0_mask11;
	u32 stat_int0_mask10;
	u32 stat_int0_mask9;
	u32 stat_int0_mask8;
	u32 stat_int0_mask7;
	u32 stat_int0_mask6;
	u32 stat_int0_mask5;
	u32 stat_int0_mask4;
	u32 stat_int0_mask3;
	u32 stat_int0_mask2;
	u32 stat_int0_mask1;
	u32 stat_int0_mask0;
};

struct dpp_stat_stat_cfg_stat_int0_status_t {
	u32 stat_int0_status31;
	u32 stat_int0_status30;
	u32 stat_int0_status29;
	u32 stat_int0_status28;
	u32 stat_int0_status27;
	u32 stat_int0_status26;
	u32 stat_int0_status25;
	u32 stat_int0_status24;
	u32 stat_int0_status23;
	u32 stat_int0_status22;
	u32 stat_int0_status21;
	u32 stat_int0_status20;
	u32 stat_int0_status19;
	u32 stat_int0_status18;
	u32 stat_int0_status17;
	u32 stat_int0_status16;
	u32 stat_int0_status15;
	u32 stat_int0_status14;
	u32 stat_int0_status13;
	u32 stat_int0_status12;
	u32 stat_int0_status11;
	u32 stat_int0_status10;
	u32 stat_int0_status9;
	u32 stat_int0_status8;
	u32 stat_int0_status7;
	u32 stat_int0_status6;
	u32 stat_int0_status5;
	u32 stat_int0_status4;
	u32 stat_int0_status3;
	u32 stat_int0_status2;
	u32 stat_int0_status1;
	u32 stat_int0_status0;
};

struct dpp_stat_stat_cfg_stat_int1_en_t {
	u32 stat_int1_en31;
	u32 stat_int1_en30;
	u32 stat_int1_en29;
	u32 stat_int1_en28;
	u32 stat_int1_en27;
	u32 stat_int1_en26;
	u32 stat_int1_en25;
	u32 stat_int1_en24;
	u32 stat_int1_en23;
	u32 stat_int1_en22;
	u32 stat_int1_en21;
	u32 stat_int1_en20;
	u32 stat_int1_en19;
	u32 stat_int1_en18;
	u32 stat_int1_en17;
	u32 stat_int1_en16;
	u32 stat_int1_en15;
	u32 stat_int1_en14;
	u32 stat_int1_en13;
	u32 stat_int1_en12;
	u32 stat_int1_en11;
	u32 stat_int1_en10;
	u32 stat_int1_en9;
	u32 stat_int1_en8;
	u32 stat_int1_en7;
	u32 stat_int1_en6;
	u32 stat_int1_en5;
	u32 stat_int1_en4;
	u32 stat_int1_en3;
	u32 stat_int1_en2;
	u32 stat_int1_en1;
	u32 stat_int1_en0;
};

struct dpp_stat_stat_cfg_stat_int1_mask_t {
	u32 stat_int1_mask31;
	u32 stat_int1_mask30;
	u32 stat_int1_mask29;
	u32 stat_int1_mask28;
	u32 stat_int1_mask27;
	u32 stat_int1_mask26;
	u32 stat_int1_mask25;
	u32 stat_int1_mask24;
	u32 stat_int1_mask23;
	u32 stat_int1_mask22;
	u32 stat_int1_mask21;
	u32 stat_int1_mask20;
	u32 stat_int1_mask19;
	u32 stat_int1_mask18;
	u32 stat_int1_mask17;
	u32 stat_int1_mask16;
	u32 stat_int1_mask15;
	u32 stat_int1_mask14;
	u32 stat_int1_mask13;
	u32 stat_int1_mask12;
	u32 stat_int1_mask11;
	u32 stat_int1_mask10;
	u32 stat_int1_mask9;
	u32 stat_int1_mask8;
	u32 stat_int1_mask7;
	u32 stat_int1_mask6;
	u32 stat_int1_mask5;
	u32 stat_int1_mask4;
	u32 stat_int1_mask3;
	u32 stat_int1_mask2;
	u32 stat_int1_mask1;
	u32 stat_int1_mask0;
};

struct dpp_stat_stat_cfg_stat_int1_status_t {
	u32 stat_int1_status31;
	u32 stat_int1_status30;
	u32 stat_int1_status29;
	u32 stat_int1_status28;
	u32 stat_int1_status27;
	u32 stat_int1_status26;
	u32 stat_int1_status25;
	u32 stat_int1_status24;
	u32 stat_int1_status23;
	u32 stat_int1_status22;
	u32 stat_int1_status21;
	u32 stat_int1_status20;
	u32 stat_int1_status19;
	u32 stat_int1_status18;
	u32 stat_int1_status17;
	u32 stat_int1_status16;
	u32 stat_int1_status15;
	u32 stat_int1_status14;
	u32 stat_int1_status13;
	u32 stat_int1_status12;
	u32 stat_int1_status11;
	u32 stat_int1_status10;
	u32 stat_int1_status9;
	u32 stat_int1_status8;
	u32 stat_int1_status7;
	u32 stat_int1_status6;
	u32 stat_int1_status5;
	u32 stat_int1_status4;
	u32 stat_int1_status3;
	u32 stat_int1_status2;
	u32 stat_int1_status1;
	u32 stat_int1_status0;
};

struct dpp_stat_stat_cfg_stat_int2_en_t {
	u32 stat_int2_en31;
	u32 stat_int2_en30;
	u32 stat_int2_en29;
	u32 stat_int2_en28;
	u32 stat_int2_en27;
	u32 stat_int2_en26;
	u32 stat_int2_en25;
	u32 stat_int2_en24;
	u32 stat_int2_en23;
	u32 stat_int2_en22;
	u32 stat_int2_en21;
	u32 stat_int2_en20;
	u32 stat_int2_en19;
	u32 stat_int2_en18;
	u32 stat_int2_en17;
	u32 stat_int2_en16;
	u32 stat_int2_en15;
	u32 stat_int2_en14;
	u32 stat_int2_en13;
	u32 stat_int2_en12;
	u32 stat_int2_en11;
	u32 stat_int2_en10;
	u32 stat_int2_en9;
	u32 stat_int2_en8;
	u32 stat_int2_en7;
	u32 stat_int2_en6;
	u32 stat_int2_en5;
	u32 stat_int2_en4;
	u32 stat_int2_en3;
	u32 stat_int2_en2;
	u32 stat_int2_en1;
	u32 stat_int2_en0;
};

struct dpp_stat_stat_cfg_stat_int2_mask_t {
	u32 stat_int2_mask31;
	u32 stat_int2_mask30;
	u32 stat_int2_mask29;
	u32 stat_int2_mask28;
	u32 stat_int2_mask27;
	u32 stat_int2_mask26;
	u32 stat_int2_mask25;
	u32 stat_int2_mask24;
	u32 stat_int2_mask23;
	u32 stat_int2_mask22;
	u32 stat_int2_mask21;
	u32 stat_int2_mask20;
	u32 stat_int2_mask19;
	u32 stat_int2_mask18;
	u32 stat_int2_mask17;
	u32 stat_int2_mask16;
	u32 stat_int2_mask15;
	u32 stat_int2_mask14;
	u32 stat_int2_mask13;
	u32 stat_int2_mask12;
	u32 stat_int2_mask11;
	u32 stat_int2_mask10;
	u32 stat_int2_mask9;
	u32 stat_int2_mask8;
	u32 stat_int2_mask7;
	u32 stat_int2_mask6;
	u32 stat_int2_mask5;
	u32 stat_int2_mask4;
	u32 stat_int2_mask3;
	u32 stat_int2_mask2;
	u32 stat_int2_mask1;
	u32 stat_int2_mask0;
};

struct dpp_stat_stat_cfg_stat_int2_status_t {
	u32 stat_int2_status31;
	u32 stat_int2_status30;
	u32 stat_int2_status29;
	u32 stat_int2_status28;
	u32 stat_int2_status27;
	u32 stat_int2_status26;
	u32 stat_int2_status25;
	u32 stat_int2_status24;
	u32 stat_int2_status23;
	u32 stat_int2_status22;
	u32 stat_int2_status21;
	u32 stat_int2_status20;
	u32 stat_int2_status19;
	u32 stat_int2_status18;
	u32 stat_int2_status17;
	u32 stat_int2_status16;
	u32 stat_int2_status15;
	u32 stat_int2_status14;
	u32 stat_int2_status13;
	u32 stat_int2_status12;
	u32 stat_int2_status11;
	u32 stat_int2_status10;
	u32 stat_int2_status9;
	u32 stat_int2_status8;
	u32 stat_int2_status7;
	u32 stat_int2_status6;
	u32 stat_int2_status5;
	u32 stat_int2_status4;
	u32 stat_int2_status3;
	u32 stat_int2_status2;
	u32 stat_int2_status1;
	u32 stat_int2_status0;
};

struct dpp_stat_stat_cfg_stat_int3_en_t {
	u32 stat_int3_en31;
	u32 stat_int3_en30;
	u32 stat_int3_en29;
	u32 stat_int3_en28;
	u32 stat_int3_en27;
	u32 stat_int3_en26;
	u32 stat_int3_en25;
	u32 stat_int3_en24;
	u32 stat_int3_en23;
	u32 stat_int3_en22;
	u32 stat_int3_en21;
	u32 stat_int3_en20;
	u32 stat_int3_en19;
	u32 stat_int3_en18;
	u32 stat_int3_en17;
	u32 stat_int3_en16;
	u32 stat_int3_en15;
	u32 stat_int3_en14;
	u32 stat_int3_en13;
	u32 stat_int3_en12;
	u32 stat_int3_en11;
	u32 stat_int3_en10;
	u32 stat_int3_en9;
	u32 stat_int3_en8;
	u32 stat_int3_en7;
	u32 stat_int3_en6;
	u32 stat_int3_en5;
	u32 stat_int3_en4;
	u32 stat_int3_en3;
	u32 stat_int3_en2;
	u32 stat_int3_en1;
	u32 stat_int3_en0;
};

struct dpp_stat_stat_cfg_stat_int3_mask_t {
	u32 stat_int3_mask31;
	u32 stat_int3_mask30;
	u32 stat_int3_mask29;
	u32 stat_int3_mask28;
	u32 stat_int3_mask27;
	u32 stat_int3_mask26;
	u32 stat_int3_mask25;
	u32 stat_int3_mask24;
	u32 stat_int3_mask23;
	u32 stat_int3_mask22;
	u32 stat_int3_mask21;
	u32 stat_int3_mask20;
	u32 stat_int3_mask19;
	u32 stat_int3_mask18;
	u32 stat_int3_mask17;
	u32 stat_int3_mask16;
	u32 stat_int3_mask15;
	u32 stat_int3_mask14;
	u32 stat_int3_mask13;
	u32 stat_int3_mask12;
	u32 stat_int3_mask11;
	u32 stat_int3_mask10;
	u32 stat_int3_mask9;
	u32 stat_int3_mask8;
	u32 stat_int3_mask7;
	u32 stat_int3_mask6;
	u32 stat_int3_mask5;
	u32 stat_int3_mask4;
	u32 stat_int3_mask3;
	u32 stat_int3_mask2;
	u32 stat_int3_mask1;
	u32 stat_int3_mask0;
};

struct dpp_stat_stat_cfg_stat_int3_status_t {
	u32 stat_int3_status31;
	u32 stat_int3_status30;
	u32 stat_int3_status29;
	u32 stat_int3_status28;
	u32 stat_int3_status27;
	u32 stat_int3_status26;
	u32 stat_int3_status25;
	u32 stat_int3_status24;
	u32 stat_int3_status23;
	u32 stat_int3_status22;
	u32 stat_int3_status21;
	u32 stat_int3_status20;
	u32 stat_int3_status19;
	u32 stat_int3_status18;
	u32 stat_int3_status17;
	u32 stat_int3_status16;
	u32 stat_int3_status15;
	u32 stat_int3_status14;
	u32 stat_int3_status13;
	u32 stat_int3_status12;
	u32 stat_int3_status11;
	u32 stat_int3_status10;
	u32 stat_int3_status9;
	u32 stat_int3_status8;
	u32 stat_int3_status7;
	u32 stat_int3_status6;
	u32 stat_int3_status5;
	u32 stat_int3_status4;
	u32 stat_int3_status3;
	u32 stat_int3_status2;
	u32 stat_int3_status1;
	u32 stat_int3_status0;
};

struct dpp_stat_stat_cfg_stat_int4_en_t {
	u32 stat_int4_en_18;
	u32 stat_int4_en_17;
	u32 stat_int4_en_16;
	u32 stat_int4_en_15;
	u32 stat_int4_en_14;
	u32 stat_int4_en_13;
	u32 stat_int4_en_12;
	u32 stat_int4_en_11;
	u32 stat_int4_en_10;
	u32 stat_int4_en_9;
	u32 stat_int4_en_8;
	u32 stat_int4_en_7;
	u32 stat_int4_en_6;
	u32 stat_int4_en_5;
	u32 stat_int4_en_4;
	u32 stat_int4_en_3;
	u32 stat_int4_en_2;
	u32 stat_int4_en_1;
	u32 stat_int4_en_0;
};

struct dpp_stat_stat_cfg_stat_int4_mask_t {
	u32 stat_int4_mask_18;
	u32 stat_int4_mask_17;
	u32 stat_int4_mask_16;
	u32 stat_int4_mask_15;
	u32 stat_int4_mask_14;
	u32 stat_int4_mask_13;
	u32 stat_int4_mask_12;
	u32 stat_int4_mask_11;
	u32 stat_int4_mask_10;
	u32 stat_int4_mask_9;
	u32 stat_int4_mask_8;
	u32 stat_int4_mask_7;
	u32 stat_int4_mask_6;
	u32 stat_int4_mask_5;
	u32 stat_int4_mask_4;
	u32 stat_int4_mask_3;
	u32 stat_int4_mask_2;
	u32 stat_int4_mask_1;
	u32 stat_int4_mask_0;
};

struct dpp_stat_stat_cfg_stat_int4_status_t {
	u32 stat_int4_mask_18;
	u32 stat_int4_mask_17;
	u32 stat_int4_mask_16;
	u32 stat_int4_mask_15;
	u32 stat_int4_mask_14;
	u32 stat_int4_mask_13;
	u32 stat_int4_mask_12;
	u32 stat_int4_mask_11;
	u32 stat_int4_mask_10;
	u32 stat_int4_mask_9;
	u32 stat_int4_mask_8;
	u32 stat_int4_mask_7;
	u32 stat_int4_mask_6;
	u32 stat_int4_mask_5;
	u32 stat_int4_mask_4;
	u32 stat_int4_mask_3;
	u32 stat_int4_mask_2;
	u32 stat_int4_mask_1;
	u32 stat_int4_mask_0;
};

struct dpp_stat_stat_cfg_stat_int5_en_t {
	u32 stat_int5_en_18;
	u32 stat_int5_en_17;
	u32 stat_int5_en_16;
	u32 stat_int5_en_15;
	u32 stat_int5_en_14;
	u32 stat_int5_en_13;
	u32 stat_int5_en_12;
	u32 stat_int5_en_11;
	u32 stat_int5_en_10;
	u32 stat_int5_en_9;
	u32 stat_int5_en_8;
	u32 stat_int5_en_7;
	u32 stat_int5_en_6;
	u32 stat_int5_en_5;
	u32 stat_int5_en_4;
	u32 stat_int5_en_3;
	u32 stat_int5_en_2;
	u32 stat_int5_en_1;
	u32 stat_int5_en_0;
};

struct dpp_stat_stat_cfg_stat_int5_mask_t {
	u32 stat_int5_mask_18;
	u32 stat_int5_mask_17;
	u32 stat_int5_mask_16;
	u32 stat_int5_mask_15;
	u32 stat_int5_mask_14;
	u32 stat_int5_mask_13;
	u32 stat_int5_mask_12;
	u32 stat_int5_mask_11;
	u32 stat_int5_mask_10;
	u32 stat_int5_mask_9;
	u32 stat_int5_mask_8;
	u32 stat_int5_mask_7;
	u32 stat_int5_mask_6;
	u32 stat_int5_mask_5;
	u32 stat_int5_mask_4;
	u32 stat_int5_mask_3;
	u32 stat_int5_mask_2;
	u32 stat_int5_mask_1;
	u32 stat_int5_mask_0;
};

struct dpp_stat_stat_cfg_stat_int5_status_t {
	u32 stat_int5_mask_18;
	u32 stat_int5_mask_17;
	u32 stat_int5_mask_16;
	u32 stat_int5_mask_15;
	u32 stat_int5_mask_14;
	u32 stat_int5_mask_13;
	u32 stat_int5_mask_12;
	u32 stat_int5_mask_11;
	u32 stat_int5_mask_10;
	u32 stat_int5_mask_9;
	u32 stat_int5_mask_8;
	u32 stat_int5_mask_7;
	u32 stat_int5_mask_6;
	u32 stat_int5_mask_5;
	u32 stat_int5_mask_4;
	u32 stat_int5_mask_3;
	u32 stat_int5_mask_2;
	u32 stat_int5_mask_1;
	u32 stat_int5_mask_0;
};

struct dpp_stat_stat_cfg_rschd_ecc_bypass_t {
	u32 rschd_ecc_bypass_18;
	u32 rschd_ecc_bypass_17;
	u32 rschd_ecc_bypass_16;
	u32 rschd_ecc_bypass_15;
	u32 rschd_ecc_bypass_14;
	u32 rschd_ecc_bypass_13;
	u32 rschd_ecc_bypass_12;
	u32 rschd_ecc_bypass_11;
	u32 rschd_ecc_bypass_10;
	u32 rschd_ecc_bypass_9;
	u32 rschd_ecc_bypass_8;
	u32 rschd_ecc_bypass_7;
	u32 rschd_ecc_bypass_6;
	u32 rschd_ecc_bypass_5;
	u32 rschd_ecc_bypass_4;
	u32 rschd_ecc_bypass_3;
	u32 rschd_ecc_bypass_2;
	u32 rschd_ecc_bypass_1;
	u32 rschd_ecc_bypass_0;
};

struct dpp_stat_stat_cfg_rschd_ecc_single_err_t {
	u32 rschd_ecc_single_err_18;
	u32 rschd_ecc_single_err_17;
	u32 rschd_ecc_single_err_16;
	u32 rschd_ecc_single_err_15;
	u32 rschd_ecc_single_err_14;
	u32 rschd_ecc_single_err_13;
	u32 rschd_ecc_single_err_12;
	u32 rschd_ecc_single_err_11;
	u32 rschd_ecc_single_err_10;
	u32 rschd_ecc_single_err_9;
	u32 rschd_ecc_single_err_8;
	u32 rschd_ecc_single_err_7;
	u32 rschd_ecc_single_err_6;
	u32 rschd_ecc_single_err_5;
	u32 rschd_ecc_single_err_4;
	u32 rschd_ecc_single_err_3;
	u32 rschd_ecc_single_err_2;
	u32 rschd_ecc_single_err_1;
	u32 rschd_ecc_single_err_0;
};

struct dpp_stat_stat_cfg_rschd_ecc_double_err_t {
	u32 rschd_ecc_double_err_18;
	u32 rschd_ecc_double_err_17;
	u32 rschd_ecc_double_err_16;
	u32 rschd_ecc_double_err_15;
	u32 rschd_ecc_double_err_14;
	u32 rschd_ecc_double_err_13;
	u32 rschd_ecc_double_err_12;
	u32 rschd_ecc_double_err_11;
	u32 rschd_ecc_double_err_10;
	u32 rschd_ecc_double_err_9;
	u32 rschd_ecc_double_err_8;
	u32 rschd_ecc_double_err_7;
	u32 rschd_ecc_double_err_6;
	u32 rschd_ecc_double_err_5;
	u32 rschd_ecc_double_err_4;
	u32 rschd_ecc_double_err_3;
	u32 rschd_ecc_double_err_2;
	u32 rschd_ecc_double_err_1;
	u32 rschd_ecc_double_err_0;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat0_t {
	u32 cpu_ind_ddr_wdat0;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat1_t {
	u32 cpu_ind_ddr_wdat1;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat2_t {
	u32 cpu_ind_ddr_wdat2;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat3_t {
	u32 cpu_ind_ddr_wdat3;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat4_t {
	u32 cpu_ind_ddr_wdat4;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat5_t {
	u32 cpu_ind_ddr_wdat5;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat6_t {
	u32 cpu_ind_ddr_wdat6;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat7_t {
	u32 cpu_ind_ddr_wdat7;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat8_t {
	u32 cpu_ind_ddr_wdat8;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat9_t {
	u32 cpu_ind_ddr_wdat9;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat10_t {
	u32 cpu_ind_ddr_wdat10;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat11_t {
	u32 cpu_ind_ddr_wdat11;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat12_t {
	u32 cpu_ind_ddr_wdat12;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat13_t {
	u32 cpu_ind_ddr_wdat13;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat14_t {
	u32 cpu_ind_ddr_wdat14;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_wdat15_t {
	u32 cpu_ind_ddr_wdat15;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_req_info_t {
	u32 rw_mode;
	u32 read_mode;
	u32 tm_cs;
	u32 rw_addr;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rd_done_t {
	u32 cpu_ind_ddr_rd_done;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat0_t {
	u32 cpu_ind_ddr_rdat0;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat1_t {
	u32 cpu_ind_ddr_rdat1;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat2_t {
	u32 cpu_ind_ddr_rdat2;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat3_t {
	u32 cpu_ind_ddr_rdat3;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat4_t {
	u32 cpu_ind_ddr_rdat4;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat5_t {
	u32 cpu_ind_ddr_rdat5;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat6_t {
	u32 cpu_ind_ddr_rdat6;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat7_t {
	u32 cpu_ind_ddr_rdat7;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat8_t {
	u32 cpu_ind_ddr_rdat8;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat9_t {
	u32 cpu_ind_ddr_rdat9;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat10_t {
	u32 cpu_ind_ddr_rdat10;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat11_t {
	u32 cpu_ind_ddr_rdat11;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat12_t {
	u32 cpu_ind_ddr_rdat12;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat13_t {
	u32 cpu_ind_ddr_rdat13;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat14_t {
	u32 cpu_ind_ddr_rdat14;
};

struct dpp_stat_stat_cfg_cpu_ind_ddr_rdat15_t {
	u32 cpu_ind_ddr_rdat15;
};

struct dpp_stat_stat_cfg_tm_alu_ddr_cpu_rdy_t {
	u32 tm_alu_ddr_cpu_rdy;
};

struct dpp_stat_stat_cfg_ept_flag_t {
	u32 ept_flag;
};

struct dpp_stat_stat_cfg_ppu_soft_rst_t {
	u32 ppu_soft_rst;
};

struct dpp_stat_stat_cfg_stat_smmu0_fc15_0_cnt_t {
	u32 stat_smmu0_fc15_0_cnt;
};

struct dpp_stat_stat_cfg_smmu0_stat_fc15_0_cnt_t {
	u32 smmu0_stat_fc15_0_cnt;
};

struct dpp_stat_stat_cfg_smmu0_stat_rsp15_0_cnt_t {
	u32 smmu0_stat_rsp15_0_cnt;
};

struct dpp_stat_stat_cfg_stat_smmu0_req15_0_cnt_t {
	u32 stat_smmu0_req15_0_cnt;
};

struct dpp_stat_stat_cfg_ppu_stat_mec5_0_rsp_fc_cnt_t {
	u32 ppu_stat_mec5_0_rsp_fc_cnt;
};

struct dpp_stat_stat_cfg_stat_ppu_mec5_0_key_fc_cnt_t {
	u32 stat_ppu_mec5_0_key_fc_cnt;
};

struct dpp_stat_stat_cfg_stat_ppu_mec5_0_rsp_cnt_t {
	u32 stat_ppu_mec5_0_rsp_cnt;
};

struct dpp_stat_stat_cfg_ppu_stat_mec5_0_key_cnt_t {
	u32 ppu_stat_mec5_0_key_cnt;
};

struct dpp_stat_stat_cfg_ppu5_0_no_exist_opcd_ex_cnt_t {
	u32 ppu5_0_no_exist_opcd_ex_cnt;
};

struct dpp_stat_stat_cfg_se_etm_stat_wr_fc_cnt_t {
	u32 se_etm_stat_wr_fc_cnt;
};

struct dpp_stat_stat_cfg_se_etm_stat_rd_fc_cnt_t {
	u32 se_etm_stat_rd_fc_cnt;
};

struct dpp_stat_stat_cfg_stat_etm_deq_fc_cnt_t {
	u32 stat_etm_deq_fc_cnt;
};

struct dpp_stat_stat_cfg_stat_etm_enq_fc_cnt_t {
	u32 stat_etm_enq_fc_cnt;
};

struct dpp_stat_stat_cfg_stat_oam_lm_fc_cnt_t {
	u32 stat_oam_lm_fc_cnt;
};

struct dpp_stat_stat_cfg_oam_stat_lm_fc_cnt_t {
	u32 oam_stat_lm_fc_cnt;
};

struct dpp_stat_stat_cfg_stat_oam_fc_cnt_t {
	u32 stat_oam_fc_cnt;
};

struct dpp_stat_stat_cfg_cmmu_stat_fc_cnt_t {
	u32 cmmu_stat_fc_cnt;
};

struct dpp_stat_stat_cfg_stat_cmmu_req_cnt_t {
	u32 stat_cmmu_req_cnt;
};

struct dpp_stat_stat_cfg_smmu0_plcr_rsp0_cnt_t {
	u32 smmu0_plcr_rsp0_cnt;
};

struct dpp_stat_stat_cfg_plcr_smmu0_req0_cnt_t {
	u32 plcr_smmu0_req0_cnt;
};

struct dpp_stat_stat_cfg_stat_oam_lm_rsp_cnt_t {
	u32 stat_oam_lm_rsp_cnt;
};

struct dpp_stat_stat_cfg_oam_stat_lm_req_cnt_t {
	u32 oam_stat_lm_req_cnt;
};

struct dpp_stat_stat_cfg_oam_stat_req_cnt_t {
	u32 oam_stat_req_cnt;
};

struct dpp_stat_stat_cfg_se_etm_stat_rsp_cnt_t {
	u32 se_etm_stat_rsp_cnt;
};

struct dpp_stat_stat_cfg_etm_stat_se_wr_req_cnt_t {
	u32 etm_stat_se_wr_req_cnt;
};

struct dpp_stat_stat_cfg_etm_stat_se_rd_req_cnt_t {
	u32 etm_stat_se_rd_req_cnt;
};

struct dpp_stat_stat_cfg_etm_stat_smmu0_req_cnt0_t {
	u32 etm_stat_smmu0_req_cnt0;
};

struct dpp_stat_stat_cfg_etm_stat_smmu0_req_cnt1_t {
	u32 etm_stat_smmu0_req_cnt1;
};

struct dpp_stat_stat_cfg_tm_stat_eram_cpu_rsp_cnt_t {
	u32 tm_stat_eram_cpu_rsp_cnt;
};

struct dpp_stat_stat_cfg_cpu_rd_eram_req_cnt_t {
	u32 cpu_rd_eram_req_cnt;
};

struct dpp_stat_stat_cfg_cpu_wr_eram_req_cnt_t {
	u32 cpu_wr_eram_req_cnt;
};

struct dpp_stat_stat_cfg_tm_stat_ddr_cpu_rsp_cnt_t {
	u32 tm_stat_ddr_cpu_rsp_cnt;
};

struct dpp_stat_stat_cfg_cpu_rd_ddr_req_cnt_t {
	u32 cpu_rd_ddr_req_cnt;
};

struct dpp_stat_stat_cfg_cpu_wr_ddr_req_cnt_t {
	u32 cpu_wr_ddr_req_cnt;
};

struct dpp_stat_etcam_cpu_ind_wdat1_t {
	u32 wdat1;
};

struct dpp_stat_etcam_cpu_ind_wdat2_t {
	u32 wdat2;
};

struct dpp_stat_etcam_cpu_ind_wdat3_t {
	u32 wdat3;
};

struct dpp_stat_etcam_cpu_ind_wdat4_t {
	u32 wdat4;
};

struct dpp_stat_etcam_cpu_ind_wdat5_t {
	u32 wdat5;
};

struct dpp_stat_etcam_cpu_ind_wdat6_t {
	u32 wdat6;
};

struct dpp_stat_etcam_cpu_ind_wdat7_t {
	u32 wdat7;
};

struct dpp_stat_etcam_cpu_ind_wdat8_t {
	u32 wdat8;
};

struct dpp_stat_etcam_cpu_ind_wdat9_t {
	u32 wdat9;
};

struct dpp_stat_etcam_cpu_ind_wdat10_t {
	u32 wdat10;
};

struct dpp_stat_etcam_cpu_ind_wdat11_t {
	u32 wdat11;
};

struct dpp_stat_etcam_cpu_ind_wdat12_t {
	u32 wdat12;
};

struct dpp_stat_etcam_cpu_ind_wdat13_t {
	u32 wdat13;
};

struct dpp_stat_etcam_cpu_ind_wdat14_t {
	u32 wdat14;
};

struct dpp_stat_etcam_cpu_ind_wdat15_t {
	u32 wdat15;
};

struct dpp_stat_etcam_cpu_ind_wdat16_t {
	u32 wdat16;
};

struct dpp_stat_etcam_cpu_ind_wdat17_t {
	u32 wdat17;
};

struct dpp_stat_etcam_cpu_ind_wdat18_t {
	u32 wdat18;
};

struct dpp_stat_etcam_cpu_ind_wdat19_t {
	u32 wdat19;
};

struct dpp_stat_etcam_t_strwc_cfg_t {
	u32 t_strwc_cfg;
};

struct dpp_stat_etcam_etcam_int_unmask_flag_t {
	u32 etcam_int_unmask_flag;
};

struct dpp_stat_etcam_etcam_int_en0_t {
	u32 etcam_int_en17;
	u32 etcam_int_en16;
	u32 etcam_int_en15;
	u32 etcam_int_en14;
	u32 etcam_int_en13;
	u32 etcam_int_en12;
	u32 etcam_int_en11;
	u32 etcam_int_en10;
	u32 etcam_int_en9;
	u32 etcam_int_en8;
	u32 etcam_int_en7;
	u32 etcam_int_en6;
	u32 etcam_int_en5;
	u32 etcam_int_en4;
	u32 etcam_int_en3;
	u32 etcam_int_en2;
	u32 etcam_int_en1;
	u32 etcam_int_en0;
};

struct dpp_stat_etcam_etcam_int_mask0_t {
	u32 etcam_int_mask17;
	u32 etcam_int_mask16;
	u32 etcam_int_mask15;
	u32 etcam_int_mask14;
	u32 etcam_int_mask13;
	u32 etcam_int_mask12;
	u32 etcam_int_mask11;
	u32 etcam_int_mask10;
	u32 etcam_int_mask9;
	u32 etcam_int_mask8;
	u32 etcam_int_mask7;
	u32 etcam_int_mask6;
	u32 etcam_int_mask5;
	u32 etcam_int_mask4;
	u32 etcam_int_mask3;
	u32 etcam_int_mask2;
	u32 etcam_int_mask1;
	u32 etcam_int_mask0;
};

struct dpp_stat_etcam_etcam_int_status_t {
	u32 etcam_int_status17;
	u32 etcam_int_status16;
	u32 etcam_int_status15;
	u32 etcam_int_status14;
	u32 etcam_int_status13;
	u32 etcam_int_status12;
	u32 etcam_int_status11;
	u32 etcam_int_status10;
	u32 etcam_int_status9;
	u32 etcam_int_status8;
	u32 etcam_int_status7;
	u32 etcam_int_status6;
	u32 etcam_int_status5;
	u32 etcam_int_status4;
	u32 etcam_int_status3;
	u32 etcam_int_status2;
	u32 etcam_int_status1;
	u32 etcam_int_status0;
};

struct dpp_stat_etcam_int_tb_ini_ok_t {
	u32 int_tb_ini_ok;
};

struct dpp_stat_etcam_etcam_clk_en_t {
	u32 etcam_clk_en;
};

struct dpp_stat_etcam_as_etcam_req0_cnt_t {
	u32 as_etcam_req0_cnt;
};

struct dpp_stat_etcam_as_etcam_req1_cnt_t {
	u32 as_etcam_req1_cnt;
};

struct dpp_stat_etcam_etcam_as_index0_cnt_t {
	u32 etcam_as_index0_cnt;
};

struct dpp_stat_etcam_etcam_as_index1_cnt_t {
	u32 etcam_as_index1_cnt;
};

struct dpp_stat_etcam_etcam_not_hit0_cnt_t {
	u32 etcam_not_hit0_cnt;
};

struct dpp_stat_etcam_etcam_not_hit1_cnt_t {
	u32 etcam_not_hit1_cnt;
};

struct dpp_stat_etcam_table_id_not_match_cnt_t {
	u32 table_id_not_match_cnt;
};

struct dpp_stat_etcam_table_id_clash01_cnt_t {
	u32 table_id_clash01_cnt;
};

struct dpp_stat_etcam_etcam_cpu_fl_t {
	u32 etcam_cpu_fl;
};

struct dpp_stat_etcam_etcam_arb_empty_t {
	u32 etcam_arb_empty;
};

#endif
