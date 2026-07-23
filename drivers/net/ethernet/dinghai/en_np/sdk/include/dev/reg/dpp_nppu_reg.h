/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_NPPU_REG_H_
#define _DPP_NPPU_REG_H_
struct dpp_nppu_mr_cfg_cfg_shap_param_t {
	u32 shap_en;
	u32 shap_rate;
};

struct dpp_nppu_mr_cfg_cfg_shap_token_t {
	u32 cfg_shap_plen_offset;
	u32 cfg_shap_token;
};

struct dpp_nppu_mr_cfg_idle_ptr_fifo_aful_th_t {
	u32 idle_ptr3_fifo_aful_th;
	u32 idle_ptr2_fifo_aful_th;
	u32 idle_ptr1_fifo_aful_th;
	u32 idle_ptr0_fifo_aful_th;
};

struct dpp_nppu_mr_cfg_mr_cos_port_cfg_t {
	u32 cos3_port_cfg;
	u32 cos2_port_cfg;
	u32 cos1_port_cfg;
	u32 cos0_port_cfg;
};

struct dpp_nppu_pktrx_cfg_ind_status_t {
	u32 ind_access_done;
};

struct dpp_nppu_pktrx_cfg_ind_cmd_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_pktrx_cfg_ind_data0_t {
	u32 ind_dat0;
};

struct dpp_nppu_pktrx_cfg_ind_data1_t {
	u32 ind_dat1;
};

struct dpp_nppu_pktrx_cfg_ind_data2_t {
	u32 ind_dat2;
};

struct dpp_nppu_pktrx_cfg_ind_data3_t {
	u32 ind_dat3;
};

struct dpp_nppu_pktrx_cfg_ind_data4_t {
	u32 ind_dat4;
};

struct dpp_nppu_pktrx_cfg_ind_data5_t {
	u32 ind_dat5;
};

struct dpp_nppu_pktrx_cfg_ind_data6_t {
	u32 ind_dat6;
};

struct dpp_nppu_pktrx_cfg_ind_data7_t {
	u32 ind_dat7;
};

struct dpp_nppu_pktrx_cfg_tcam_0_cmd_t {
	u32 cfg_vben;
	u32 cfg_vbi;
	u32 cfg_t_strwc;
	u32 tcam0_sm;
	u32 tcam0_smen;
	u32 tcam0_rm;
	u32 tcam0_rmen;
	u32 tcam0_enable;
	u32 tcam0_flush;
	u32 tcam0_unload;
	u32 tcam0_unload_addr;
};

struct dpp_nppu_pktrx_cfg_tcam_1_cmd_t {
	u32 tcam1_sm;
	u32 tcam1_smen;
	u32 tcam1_rm;
	u32 tcam1_rmen;
	u32 tcam1_enable;
	u32 tcam1_flush;
	u32 tcam1_unload;
	u32 tcam1_unload_addr;
};

struct dpp_nppu_pktrx_cfg_port_en_0_t {
	u32 cfg_isch_port_en_0;
};

struct dpp_nppu_pktrx_cfg_port_en_1_t {
	u32 cfg_isch_port_en_1;
};

struct dpp_nppu_pktrx_cfg_port_en_2_t {
	u32 cfg_isch_port_en_2;
};

struct dpp_nppu_pktrx_cfg_port_en_3_t {
	u32 cfg_port_change_en_0;
	u32 cfg_port_change_en_1;
	u32 cfg_isch_port_en_3;
};

struct dpp_nppu_pktrx_cfg_cfg_port_l2_offset_mode_0_t {
	u32 cfg_port_l2_offset_mode_0;
};

struct dpp_nppu_pktrx_cfg_cfg_port_l2_offset_mode_1_t {
	u32 cfg_port_l2_offset_mode_1;
};

struct dpp_nppu_pktrx_cfg_cfg_port_l2_offset_mode_2_t {
	u32 cfg_port_l2_offset_mode_2;
};

struct dpp_nppu_pktrx_cfg_cfg_port_l2_offset_mode_3_t {
	u32 cfg_port_l2_offset_mode_3;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_0_t {
	u32 cfg_isch_fc_mode_0;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_1_t {
	u32 cfg_isch_fc_mode_1;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_2_t {
	u32 cfg_isch_fc_mode_2;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_3_t {
	u32 cfg_isch_fc_mode_3;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_4_t {
	u32 cfg_isch_fc_mode_4;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_5_t {
	u32 cfg_isch_fc_mode_5;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_6_t {
	u32 cfg_isch_fc_mode_6;
};

struct dpp_nppu_pktrx_cfg_port_fc_mode_7_t {
	u32 cfg_pfu_aging_en;
	u32 cfg_isch_aging_en;
	u32 cfg_isch_fc_mode_7;
};

struct dpp_nppu_pktrx_cfg_cfg_isch_aging_th_t {
	u32 cfg_pfu_delay_cycle;
	u32 cfg_isch_aging_th;
};

struct dpp_nppu_pktrx_cfg_isch_fifo_th_0_t {
	u32 cfg_sch_fifo3_fc_th;
	u32 cfg_sch_fifo2_fc_th;
	u32 cfg_sch_fifo1_fc_th;
	u32 cfg_sch_fifo0_fc_th;
};

struct dpp_nppu_pktrx_cfg_isch_cfg_1_t {
	u32 cfg_parser_max_len_en;
	u32 cfg_parser_max_len;
	u32 cfg_parser_min_len_en;
	u32 cfg_parser_min_len;
	u32 sp_sch_sel;
};

struct dpp_nppu_pktrx_cfg_tcam_0_vld_t {
	u32 cfg_tcam0_vld;
};

struct dpp_nppu_pktrx_cfg_tcam_1_vld_t {
	u32 cfg_tcam1_vld;
};

struct dpp_nppu_pktrx_cfg_cpu_port_en_mask_t {
	u32 cpu_port_en_mask;
};

struct dpp_nppu_pktrx_cfg_pktrx_glbal_cfg_0_t {
	u32 pktrx_glbal_cfg_0;
};

struct dpp_nppu_pktrx_cfg_pktrx_glbal_cfg_1_t {
	u32 pktrx_glbal_cfg_1;
};

struct dpp_nppu_pktrx_cfg_pktrx_glbal_cfg_2_t {
	u32 pktrx_glbal_cfg_2;
};

struct dpp_nppu_pktrx_cfg_pktrx_glbal_cfg_3_t {
	u32 pktrx_glbal_cfg_3;
};

struct dpp_nppu_pktrx_cfg_nppu_start_t {
	u32 nppu_start;
};

struct dpp_nppu_pktrx_stat_ind_status_t {
	u32 ind_access_done;
};

struct dpp_nppu_pktrx_stat_ind_cmd_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_pktrx_stat_ind_data0_t {
	u32 ind_dat0;
};

struct dpp_nppu_idma_cfg_debug_cnt_ovfl_mode_t {
	u32 debug_cnt_ovfl_mode;
};

struct dpp_nppu_idma_stat_ind_status_t {
	u32 ind_access_done;
};

struct dpp_nppu_idma_stat_ind_cmd_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_idma_stat_ind_data0_t {
	u32 ind_data0;
};

struct dpp_nppu_pbu_cfg_ind_status_t {
	u32 ind_access_done;
};

struct dpp_nppu_pbu_cfg_ind_cmd_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_pbu_cfg_ind_data0_t {
	u32 ind_data0;
};

struct dpp_nppu_pbu_cfg_ind_data1_t {
	u32 ind_data1;
};

struct dpp_nppu_pbu_cfg_ind_data2_t {
	u32 ind_data2;
};

struct dpp_nppu_pbu_cfg_ind_data3_t {
	u32 ind_data3;
};

struct dpp_nppu_pbu_cfg_ind_data4_t {
	u32 ind_data4;
};

struct dpp_nppu_pbu_cfg_ind_data5_t {
	u32 ind_data5;
};

struct dpp_nppu_pbu_cfg_ind_data6_t {
	u32 ind_data6;
};

struct dpp_nppu_pbu_cfg_ind_data7_t {
	u32 ind_data7;
};

struct dpp_nppu_pbu_cfg_idma_public_th_t {
	u32 idma_public_th;
};

struct dpp_nppu_pbu_cfg_lif_public_th_t {
	u32 lif_public_th;
};

struct dpp_nppu_pbu_cfg_idma_total_th_t {
	u32 idma_total_th;
};

struct dpp_nppu_pbu_cfg_lif_total_th_t {
	u32 lif_total_th;
};

struct dpp_nppu_pbu_cfg_mc_total_th_t {
	u32 mc_total_th;
};

struct dpp_nppu_pbu_cfg_mc_cos10_th_t {
	u32 mc_cos1_mode;
	u32 mc_cos0_mode;
	u32 mc_cos1_th;
	u32 mc_cos0_th;
};

struct dpp_nppu_pbu_cfg_mc_cos32_th_t {
	u32 mc_cos3_mode;
	u32 mc_cos2_mode;
	u32 mc_cos3_th;
	u32 mc_cos2_th;
};

struct dpp_nppu_pbu_cfg_mc_cos54_th_t {
	u32 mc_cos5_mode;
	u32 mc_cos4_mode;
	u32 mc_cos5_th;
	u32 mc_cos4_th;
};

struct dpp_nppu_pbu_cfg_mc_cos76_th_t {
	u32 mc_cos7_mode;
	u32 mc_cos6_mode;
	u32 mc_cos7_th;
	u32 mc_cos6_th;
};

struct dpp_nppu_pbu_cfg_debug_cnt_ovfl_mode_t {
	u32 debug_cnt_ovfl_mode;
};

struct dpp_nppu_pbu_cfg_se_key_aful_negate_cfg_t {
	u32 se_key_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_sa_flag_t {
	u32 sa_flag;
};

struct dpp_nppu_pbu_stat_ind_data_t {
	u32 ind_data;
};

struct dpp_nppu_pbu_stat_ind_status_t {
	u32 ind_access_done;
};

struct dpp_nppu_pbu_stat_ind_cmd_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_pbu_stat_total_cnt_t {
	u32 total_cnt;
};

struct dpp_nppu_pbu_stat_idma_pub_cnt_t {
	u32 idma_pub_cnt;
};

struct dpp_nppu_pbu_stat_lif_pub_cnt_t {
	u32 lif_pub_cnt;
};

struct dpp_nppu_pbu_stat_mc_total_cnt_t {
	u32 mc_total_cnt;
};

struct dpp_nppu_pbu_stat_pbu_thram_init_done_t {
	u32 pbu_thram_init_done;
};

struct dpp_nppu_pbu_stat_ifb_fptr_init_done_t {
	u32 ifb_fptr_init_done;
};

struct dpp_nppu_isu_cfg_weight_normal_uc_t {
	u32 weight_normal_uc;
};

struct dpp_nppu_isu_cfg_fabric_or_saip_t {
	u32 fabric_or_saip;
};

struct dpp_nppu_isu_stat_ind_status_t {
	u32 ind_access_done;
};

struct dpp_nppu_isu_stat_ind_cmd_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_isu_stat_ind_dat0_t {
	u32 ind_dat0;
};

struct dpp_nppu_odma_cfg_ind_access_done_t {
	u32 ind_access_done;
};

struct dpp_nppu_odma_cfg_ind_command_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_odma_cfg_ind_dat0_t {
	u32 ind_dat0;
};

struct dpp_nppu_odma_cfg_ind_dat1_t {
	u32 ind_dat1;
};

struct dpp_nppu_odma_cfg_fabric_or_saip_t {
	u32 fabric_or_saip;
};

struct dpp_nppu_odma_cfg_max_pkt_len_t {
	u32 max_pkt_len;
};

struct dpp_nppu_odma_cfg_age_en_t {
	u32 age_en;
};

struct dpp_nppu_odma_cfg_age_mode_t {
	u32 age_mode;
};

struct dpp_nppu_odma_cfg_age_value_time_t {
	u32 age_value_time;
};

struct dpp_nppu_odma_cfg_age_value_room_t {
	u32 age_value_room;
};

struct dpp_nppu_odma_cfg_age_out_cnt_t {
	u32 age_out_cnt;
};

struct dpp_nppu_odma_cfg_token_value_a_t {
	u32 token_value_a;
};

struct dpp_nppu_odma_cfg_token_value_b_t {
	u32 token_value_b;
};

struct dpp_nppu_odma_cfg_cfg_shap_en_p0_t {
	u32 cfg_shap_en_p0;
};

struct dpp_nppu_odma_cfg_cfg_shap_en_p1_t {
	u32 cfg_shap_en_p1;
};

struct dpp_nppu_odma_cfg_cfg_shap_en_tm_t {
	u32 cfg_shap_en_tm;
};

struct dpp_nppu_odma_stat_ind_status_t {
	u32 ind_access_done;
};

struct dpp_nppu_odma_stat_ind_cmd_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_odma_stat_ind_data0_t {
	u32 ind_dat0;
};

struct dpp_nppu_odma_stat_debug_cnt_cfg_t {
	u32 debug_cnt_ovf_mode;
	u32 debug_cnt_rdclr_mode;
	u32 user_cnt_value;
};

struct dpp_nppu_oam_cfg_bfd_firstchk_th_t {
	u32 bfd_firstchk_th;
};

struct dpp_nppu_pbu_cfg_memid_0_pbu_fc_idmath_ram_t {
	u32 lif_th_15;
	u32 lif_prv_15;
	u32 idma_prv_15;
	u32 idma_th_cos0_15;
	u32 idma_th_cos1_15;
	u32 idma_th_cos2_15;
	u32 idma_th_cos3_15;
	u32 idma_th_cos4_15;
	u32 idma_th_cos5_15;
	u32 idma_th_cos6_15;
	u32 idma_th_cos7_15;
};

struct dpp_nppu_pbu_cfg_memid_1_pbu_fc_macth_ram_t {
	u32 cos7_th;
	u32 cos6_th;
	u32 cos5_th;
	u32 cos4_th;
	u32 cos3_th;
	u32 cos2_th;
	u32 cos1_th;
	u32 cos0_th;
};

struct dpp_nppu_pbu_stat_memid_1_all_kind_port_cnt_t {
	u32 peak_port_cnt;
	u32 current_port_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_ppu_pbu_ifb_req_vld_cnt_t {
	u32 ppu_pbu_ifb_req_vld_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_pbu_ppu_ifb_rsp_vld_cnt_t {
	u32 pbu_ppu_ifb_rsp_vld_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_odma_pbu_recy_ptr_vld_cnt_t {
	u32 odma_pbu_recy_ptr_vld_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_ppu_pbu_mcode_pf_req_cnt_t {
	u32 ppu_pbu_mcode_pf_req_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_pbu_ppu_mcode_pf_rsp_cnt_t {
	u32 pbu_ppu_mcode_pf_rsp_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_ppu_pbu_logic_pf_req_cnt_t {
	u32 ppu_pbu_logic_pf_req_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_pbu_ppu_logic_pf_rsp_cnt_t {
	u32 pbu_ppu_logic_pf_rsp_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_ppu_use_ptr_pulse_cnt_t {
	u32 ppu_use_ptr_pulse_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_ppu_pbu_wb_vld_cnt_t {
	u32 ppu_pbu_wb_vld_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_pbu_ppu_reorder_para_vld_cnt_t {
	u32 pbu_ppu_reorder_para_vld_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_se_pbu_dpi_key_vld_cnt_t {
	u32 se_pbu_dpi_key_vld_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_pbu_se_dpi_rsp_datvld_cnt_t {
	u32 pbu_se_dpi_rsp_datvld_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_odma_pbu_ifb_rd1_cnt_t {
	u32 odma_pbu_ifb_rd1_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_odma_pbu_ifb_rd2_cnt_t {
	u32 odma_pbu_ifb_rd2_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_pbu_ppu_mcode_pf_no_rsp_cnt_t {
	u32 pbu_ppu_mcode_pf_no_rsp_cnt;
};

struct dpp_nppu_pbu_stat_memid_2_pbu_ppu_logic_pf_no_rsp_cnt_t {
	u32 pbu_ppu_logic_pf_no_rsp_cnt;
};

struct dpp_nppu_pbu_stat_memid_3_cpu_rd_ifb_data_t {
	u32 cpu_rd_ifb_data;
};

struct dpp_nppu_pbu_stat_memid_4_mux_sel_rgt_t {
	u32 current_port_cnt;
};

struct dpp_nppu_pbu_stat_memid_5_port_pub_cnt_t {
	u32 port_pub_cnt;
};

struct dpp_nppu_idma_stat_memid_1_idma_o_isu_pkt_pulse_total_cnt_t {
	u32 idma_o_isu_pkt_pulse_total_cnt;
};

struct dpp_nppu_idma_stat_memid_1_idma_o_isu_epkt_pulse_total_cnt_t {
	u32 idma_o_isu_epkt_pulse_total_cnt;
};

struct dpp_nppu_idma_stat_memid_1_idma_dispkt_pulse_total_cnt_t {
	u32 idma_dispkt_pulse_total_cnt;
};

struct dpp_nppu_idma_stat_memid_0_idma_o_isu_pkt_pulse_cnt_t {
	u32 idma_o_isu_pkt_pulse_cnt;
};

struct dpp_nppu_idma_stat_memid_0_idma_o_isu_epkt_pulse_cnt_t {
	u32 idma_o_isu_epkt_pulse_cnt;
};

struct dpp_nppu_idma_stat_memid_0_idma_dispkt_pulse_cnt_t {
	u32 idma_dispkt_pulse_cnt;
};

struct dpp_nppu_mr_cfg_ind_access_states_t {
	u32 ind_access_done;
};

struct dpp_nppu_mr_cfg_ind_access_cmd0_t {
	u32 wr_mode;
	u32 rd_or_wr;
	u32 ind_access_addr0;
};

struct dpp_nppu_mr_cfg_ind_access_data0_t {
	u32 ind_access_data0;
};

struct dpp_nppu_mr_cfg_ind_access_data1_t {
	u32 ind_access_data1;
};

struct dpp_nppu_mr_cfg_ind_access_cmd1_t {
	u32 ind_access_addr1;
};

struct dpp_nppu_mr_cfg_mr_init_done_t {
	u32 mr_init_done;
};

struct dpp_nppu_mr_cfg_cnt_mode_reg_t {
	u32 cfgmt_count_rd_mode;
	u32 cfgmt_count_overflow_mode;
};

struct dpp_nppu_mr_cfg_cfg_ecc_bypass_read_t {
	u32 cfg_ecc_bypass_read;
};

struct dpp_nppu_mr_cfg_cfg_rep_mod_t {
	u32 cfg_rep_mod;
};

struct dpp_nppu_mr_cfg_block_ptr_fifo_aful_th_t {
	u32 block_ptr3_fifo_aful_th;
	u32 block_ptr2_fifo_aful_th;
	u32 block_ptr1_fifo_aful_th;
	u32 block_ptr0_fifo_aful_th;
};

struct dpp_nppu_mr_cfg_pre_rcv_ptr_fifo_aful_th_t {
	u32 pre_rcv_ptr3_fifo_aful_th;
	u32 pre_rcv_ptr2_fifo_aful_th;
	u32 pre_rcv_ptr1_fifo_aful_th;
	u32 pre_rcv_ptr0_fifo_aful_th;
};

struct dpp_nppu_mr_cfg_mgid_fifo_aful_th_t {
	u32 mgid3_fifo_aful_th;
	u32 mgid2_fifo_aful_th;
	u32 mgid1_fifo_aful_th;
	u32 mgid0_fifo_aful_th;
};

struct dpp_nppu_mr_cfg_rep_cmd_fifo_aful_th_t {
	u32 rep_cmd3_fifo_aful_th;
	u32 rep_cmd2_fifo_aful_th;
	u32 rep_cmd1_fifo_aful_th;
	u32 rep_cmd0_fifo_aful_th;
};

struct dpp_nppu_mr_cfg_mr_int_mask_1_t {
	u32 free_ptr0_fifo_full_mask;
	u32 free_ptr1_fifo_full_mask;
	u32 free_ptr2_fifo_full_mask;
	u32 free_ptr3_fifo_full_mask;
	u32 block_ptr0_fifo_full_mask;
	u32 block_ptr1_fifo_full_mask;
	u32 block_ptr2_fifo_full_mask;
	u32 block_ptr3_fifo_full_mask;
	u32 mgid0_fifo_full_mask;
	u32 mgid1_fifo_full_mask;
	u32 mgid2_fifo_full_mask;
	u32 mgid3_fifo_full_mask;
	u32 pre_rcv_ptr0_fifo_full_mask;
	u32 pre_rcv_ptr1_fifo_full_mask;
	u32 pre_rcv_ptr2_fifo_full_mask;
	u32 pre_rcv_ptr3_fifo_full_mask;
	u32 rep_cmd0_fifo_full_mask;
	u32 rep_cmd1_fifo_full_mask;
	u32 rep_cmd2_fifo_full_mask;
	u32 rep_cmd3_fifo_full_mask;
};

struct dpp_nppu_mr_cfg_mr_int_mask_2_t {
	u32 free_ptr0_fifo_udf_mask;
	u32 free_ptr1_fifo_udf_mask;
	u32 free_ptr2_fifo_udf_mask;
	u32 free_ptr3_fifo_udf_mask;
	u32 block_ptr0_fifo_udf_mask;
	u32 block_ptr1_fifo_udf_mask;
	u32 block_ptr2_fifo_udf_mask;
	u32 block_ptr3_fifo_udf_mask;
	u32 mgid0_fifo_udf_mask;
	u32 mgid1_fifo_udf_mask;
	u32 mgid2_fifo_udf_mask;
	u32 mgid3_fifo_udf_mask;
	u32 pre_rcv_ptr0_fifo_udf_mask;
	u32 pre_rcv_ptr1_fifo_udf_mask;
	u32 pre_rcv_ptr2_fifo_udf_mask;
	u32 pre_rcv_ptr3_fifo_udf_mask;
	u32 rep_cmd0_fifo_udf_mask;
	u32 rep_cmd1_fifo_udf_mask;
	u32 rep_cmd2_fifo_udf_mask;
	u32 rep_cmd3_fifo_udf_mask;
};

struct dpp_nppu_mr_cfg_mr_int_mask_3_t {
	u32 free_ptr0_fifo_ovf_mask;
	u32 free_ptr1_fifo_ovf_mask;
	u32 free_ptr2_fifo_ovf_mask;
	u32 free_ptr3_fifo_ovf_mask;
	u32 block_ptr0_fifo_ovf_mask;
	u32 block_ptr1_fifo_ovf_mask;
	u32 block_ptr2_fifo_ovf_mask;
	u32 block_ptr3_fifo_ovf_mask;
	u32 mgid0_fifo_ovf_mask;
	u32 mgid1_fifo_ovf_mask;
	u32 mgid2_fifo_ovf_mask;
	u32 mgid3_fifo_ovf_mask;
	u32 pre_rcv_ptr0_fifo_ovf_mask;
	u32 pre_rcv_ptr1_fifo_ovf_mask;
	u32 pre_rcv_ptr2_fifo_ovf_mask;
	u32 pre_rcv_ptr3_fifo_ovf_mask;
	u32 rep_cmd0_fifo_ovf_mask;
	u32 rep_cmd1_fifo_ovf_mask;
	u32 rep_cmd2_fifo_ovf_mask;
	u32 rep_cmd3_fifo_ovf_mask;
};

struct dpp_nppu_mr_cfg_mr_int_mask_4_t {
	u32 data_buf0_ram_parity_err_mask;
	u32 data_buf1_ram_parity_err_mask;
	u32 data_buf2_ram_parity_err_mask;
	u32 data_buf3_ram_parity_err_mask;
	u32 mlt_ecc_single_err_mask;
	u32 free_ptr0_fifo_ecc_single_err_mask;
	u32 free_ptr1_fifo_ecc_single_err_mask;
	u32 free_ptr2_fifo_ecc_single_err_mask;
	u32 free_ptr3_fifo_ecc_single_err_mask;
	u32 block_ptr0_fifo_ecc_single_err_mask;
	u32 block_ptr1_fifo_ecc_single_err_mask;
	u32 block_ptr2_fifo_ecc_single_err_mask;
	u32 block_ptr3_fifo_ecc_single_err_mask;
	u32 mgid0_fifo_ecc_single_err_mask;
	u32 mgid1_fifo_ecc_single_err_mask;
	u32 mgid2_fifo_ecc_single_err_mask;
	u32 mgid3_fifo_ecc_single_err_mask;
	u32 pre_rcv_ptr0_fifo_ecc_single_err_mask;
	u32 pre_rcv_ptr1_fifo_ecc_single_err_mask;
	u32 pre_rcv_ptr2_fifo_ecc_single_err_mask;
	u32 pre_rcv_ptr3_fifo_ecc_single_err_mask;
	u32 rep_cmd0_fifo_ecc_single_err_mask;
	u32 rep_cmd1_fifo_ecc_single_err_mask;
	u32 rep_cmd2_fifo_ecc_single_err_mask;
	u32 rep_cmd3_fifo_ecc_single_err_mask;
};

struct dpp_nppu_mr_cfg_mr_states_1_t {
	u32 free_ptr0_fifo_full;
	u32 free_ptr1_fifo_full;
	u32 free_ptr2_fifo_full;
	u32 free_ptr3_fifo_full;
	u32 block_ptr0_fifo_full;
	u32 block_ptr1_fifo_full;
	u32 block_ptr2_fifo_full;
	u32 block_ptr3_fifo_full;
	u32 mgid0_fifo_full;
	u32 mgid1_fifo_full;
	u32 mgid2_fifo_full;
	u32 mgid3_fifo_full;
	u32 pre_rcv_ptr0_fifo_full;
	u32 pre_rcv_ptr1_fifo_full;
	u32 pre_rcv_ptr2_fifo_full;
	u32 pre_rcv_ptr3_fifo_full;
	u32 rep_cmd0_fifo_full;
	u32 rep_cmd1_fifo_full;
	u32 rep_cmd2_fifo_full;
	u32 rep_cmd3_fifo_full;
};

struct dpp_nppu_mr_cfg_mr_states_2_t {
	u32 free_ptr0_fifo_udf;
	u32 free_ptr1_fifo_udf;
	u32 free_ptr2_fifo_udf;
	u32 free_ptr3_fifo_udf;
	u32 block_ptr0_fifo_udf;
	u32 block_ptr1_fifo_udf;
	u32 block_ptr2_fifo_udf;
	u32 block_ptr3_fifo_udf;
	u32 mgid0_fifo_udf;
	u32 mgid1_fifo_udf;
	u32 mgid2_fifo_udf;
	u32 mgid3_fifo_udf;
	u32 pre_rcv_ptr0_fifo_udf;
	u32 pre_rcv_ptr1_fifo_udf;
	u32 pre_rcv_ptr2_fifo_udf;
	u32 pre_rcv_ptr3_fifo_udf;
	u32 rep_cmd0_fifo_udf;
	u32 rep_cmd1_fifo_udf;
	u32 rep_cmd2_fifo_udf;
	u32 rep_cmd3_fifo_udf;
};

struct dpp_nppu_mr_cfg_mr_states_3_t {
	u32 free_ptr0_fifo_ovf;
	u32 free_ptr1_fifo_ovf;
	u32 free_ptr2_fifo_ovf;
	u32 free_ptr3_fifo_ovf;
	u32 block_ptr0_fifo_ovf;
	u32 block_ptr1_fifo_ovf;
	u32 block_ptr2_fifo_ovf;
	u32 block_ptr3_fifo_ovf;
	u32 mgid0_fifo_ovf;
	u32 mgid1_fifo_ovf;
	u32 mgid2_fifo_ovf;
	u32 mgid3_fifo_ovf;
	u32 pre_rcv_ptr0_fifo_ovf;
	u32 pre_rcv_ptr1_fifo_ovf;
	u32 pre_rcv_ptr2_fifo_ovf;
	u32 pre_rcv_ptr3_fifo_ovf;
	u32 rep_cmd0_fifo_ovf;
	u32 rep_cmd1_fifo_ovf;
	u32 rep_cmd2_fifo_ovf;
	u32 rep_cmd3_fifo_ovf;
};

struct dpp_nppu_mr_cfg_mr_states_4_t {
	u32 data_buf0_ram_parity_err;
	u32 data_buf1_ram_parity_err;
	u32 data_buf2_ram_parity_err;
	u32 data_buf3_ram_parity_err;
	u32 mlt_ecc_single_err;
	u32 free_ptr0_fifo_ecc_single_err;
	u32 free_ptr1_fifo_ecc_single_err;
	u32 free_ptr2_fifo_ecc_single_err;
	u32 free_ptr3_fifo_ecc_single_err;
	u32 block_ptr0_fifo_ecc_single_err;
	u32 block_ptr1_fifo_ecc_single_err;
	u32 block_ptr2_fifo_ecc_single_err;
	u32 block_ptr3_fifo_ecc_single_err;
	u32 mgid0_fifo_ecc_single_err;
	u32 mgid1_fifo_ecc_single_err;
	u32 mgid2_fifo_ecc_single_err;
	u32 mgid3_fifo_ecc_single_err;
	u32 pre_rcv_ptr0_fifo_ecc_single_err;
	u32 pre_rcv_ptr1_fifo_ecc_single_err;
	u32 pre_rcv_ptr2_fifo_ecc_single_err;
	u32 pre_rcv_ptr3_fifo_ecc_single_err;
	u32 rep_cmd0_fifo_ecc_single_err;
	u32 rep_cmd1_fifo_ecc_single_err;
	u32 rep_cmd2_fifo_ecc_single_err;
	u32 rep_cmd3_fifo_ecc_single_err;
};

struct dpp_nppu_mr_cfg_mr_states_5_t {
	u32 mlt_ecc_double_err;
	u32 free_ptr0_fifo_ecc_double_err;
	u32 free_ptr1_fifo_ecc_double_err;
	u32 free_ptr2_fifo_ecc_double_err;
	u32 free_ptr3_fifo_ecc_double_err;
	u32 block_ptr0_fifo_ecc_double_err;
	u32 block_ptr1_fifo_ecc_double_err;
	u32 block_ptr2_fifo_ecc_double_err;
	u32 block_ptr3_fifo_ecc_double_err;
	u32 mgid0_fifo_ecc_double_err;
	u32 mgid1_fifo_ecc_double_err;
	u32 mgid2_fifo_ecc_double_err;
	u32 mgid3_fifo_ecc_double_err;
	u32 pre_rcv_ptr0_fifo_ecc_double_err;
	u32 pre_rcv_ptr1_fifo_ecc_double_err;
	u32 pre_rcv_ptr2_fifo_ecc_double_err;
	u32 pre_rcv_ptr3_fifo_ecc_double_err;
	u32 rep_cmd0_fifo_ecc_double_err;
	u32 rep_cmd1_fifo_ecc_double_err;
	u32 rep_cmd2_fifo_ecc_double_err;
	u32 rep_cmd3_fifo_ecc_double_err;
};

struct dpp_nppu_mr_cfg_mr_states_6_t {
	u32 free_ptr0_fifo_empty;
	u32 free_ptr1_fifo_empty;
	u32 free_ptr2_fifo_empty;
	u32 free_ptr3_fifo_empty;
	u32 block_ptr0_fifo_empty;
	u32 block_ptr1_fifo_empty;
	u32 block_ptr2_fifo_empty;
	u32 block_ptr3_fifo_empty;
	u32 mgid0_fifo_empty;
	u32 mgid1_fifo_empty;
	u32 mgid2_fifo_empty;
	u32 mgid3_fifo_empty;
	u32 pre_rcv_ptr0_fifo_empty;
	u32 pre_rcv_ptr1_fifo_empty;
	u32 pre_rcv_ptr2_fifo_empty;
	u32 pre_rcv_ptr3_fifo_empty;
	u32 rep_cmd0_fifo_empty;
	u32 rep_cmd1_fifo_empty;
	u32 rep_cmd2_fifo_empty;
	u32 rep_cmd3_fifo_empty;
};

struct dpp_nppu_mr_cfg_mr_states_7_t {
	u32 cos0_is_rep_busy;
	u32 cos1_is_rep_busy;
	u32 cos2_is_rep_busy;
	u32 cos3_is_rep_busy;
	u32 block_ptr0_fifo_non_sop_ren_rdy;
	u32 block_ptr1_fifo_non_sop_ren_rdy;
	u32 block_ptr2_fifo_non_sop_ren_rdy;
	u32 block_ptr3_fifo_non_sop_ren_rdy;
	u32 pre_rcv_ptr0_fifo_non_sop_ren_rdy;
	u32 pre_rcv_ptr1_fifo_non_sop_ren_rdy;
	u32 pre_rcv_ptr2_fifo_non_sop_ren_rdy;
	u32 pre_rcv_ptr3_fifo_non_sop_ren_rdy;
	u32 port_shap_rdy;
	u32 mr_lif_group0_rdy_3;
	u32 mr_lif_group0_rdy_2;
	u32 mr_lif_group0_rdy_1;
	u32 mr_lif_group0_rdy_0;
	u32 pktrx_pfc_rdy_3;
	u32 pktrx_pfc_rdy_2;
	u32 pktrx_pfc_rdy_1;
	u32 pktrx_pfc_rdy_0;
	u32 pktrx_link_rdy;
};

struct dpp_nppu_mr_cfg_mr_states_8_t {
	u32 mr_head;
};

struct dpp_nppu_mr_cfg_mr_sop_in_cnt_t {
	u32 mr_sop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_eop_in_cnt_t {
	u32 mr_eop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_sop_out_cnt_t {
	u32 mr_sop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_eop_out_cnt_t {
	u32 mr_eop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos0_in_cnt_t {
	u32 mr_cos0_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos1_in_cnt_t {
	u32 mr_cos1_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos2_in_cnt_t {
	u32 mr_cos2_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos3_in_cnt_t {
	u32 mr_cos3_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos0_out_cnt_t {
	u32 mr_cos0_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos1_out_cnt_t {
	u32 mr_cos1_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos2_out_cnt_t {
	u32 mr_cos2_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos3_out_cnt_t {
	u32 mr_cos3_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_err_in_cnt_t {
	u32 mr_err_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos0_sop_in_cnt_t {
	u32 mr_cos0_sop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos0_eop_in_cnt_t {
	u32 mr_cos0_eop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos1_sop_in_cnt_t {
	u32 mr_cos1_sop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos1_eop_in_cnt_t {
	u32 mr_cos1_eop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos2_sop_in_cnt_t {
	u32 mr_cos2_sop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos2_eop_in_cnt_t {
	u32 mr_cos2_eop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos3_sop_in_cnt_t {
	u32 mr_cos3_sop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos3_eop_in_cnt_t {
	u32 mr_cos3_eop_in_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos0_in_err_cnt_t {
	u32 mr_cos0_in_err_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos1_in_err_cnt_t {
	u32 mr_cos1_in_err_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos2_in_err_cnt_t {
	u32 mr_cos2_in_err_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos3_in_err_cnt_t {
	u32 mr_cos3_in_err_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos0_sop_out_cnt_t {
	u32 mr_cos0_sop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos0_eop_out_cnt_t {
	u32 mr_cos0_eop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos1_sop_out_cnt_t {
	u32 mr_cos1_sop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos1_eop_out_cnt_t {
	u32 mr_cos1_eop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos2_sop_out_cnt_t {
	u32 mr_cos2_sop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos2_eop_out_cnt_t {
	u32 mr_cos2_eop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos3_sop_out_cnt_t {
	u32 mr_cos3_sop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_cos3_eop_out_cnt_t {
	u32 mr_cos3_eop_out_cnt;
};

struct dpp_nppu_mr_cfg_mr_mlt_unvld_cnt_t {
	u32 mr_mlt_unvld_cnt;
};

struct dpp_nppu_mr_cfg_mr_sop_eop_match_cfg_t {
	u32 mr_sop_eop_macth_en;
	u32 mr_sop_eop_macth_dicard_th;
};

struct dpp_nppu_mr_cfg_mr_mlt_unvld_mgid_t {
	u32 mr_mlt_unvld_mgid;
};

struct dpp_nppu_pktrx_cfg_isch_fifo_th_1_t {
	u32 cfg_sch_fifo7_fc_th;
	u32 cfg_sch_fifo6_fc_th;
	u32 cfg_sch_fifo5_fc_th;
	u32 cfg_sch_fifo4_fc_th;
};

struct dpp_nppu_pktrx_cfg_isch_fifo_th_2_t {
	u32 cfg_sch_fifo3_drop_th;
	u32 cfg_sch_fifo1_drop_th;
	u32 cfg_sch_fifo0_drop_th;
	u32 cfg_sch_fifo8_fc_th;
};

struct dpp_nppu_pktrx_cfg_isch_fifo_th_3_t {
	u32 cfg_sch_fifo6_drop_th;
	u32 cfg_sch_fifo5_drop_th;
	u32 cfg_sch_fifo4_drop_th;
	u32 cfg_sch_fifo2_drop_th;
};

struct dpp_nppu_pktrx_cfg_isch_fifo_th_4_t {
	u32 cfg_sch_fifo9_fc_th;
	u32 cfg_sch_fifo9_drop_th;
	u32 cfg_sch_fifo8_drop_th;
	u32 cfg_sch_fifo7_drop_th;
};

struct dpp_nppu_pktrx_cfg_isch_cfg_0_t {
	u32 cfg_sch_wrr1_weight1;
};

struct dpp_nppu_pktrx_cfg_hdu_ex_tpid_0_t {
	u32 cfg_type0;
	u32 cfg_type1;
};

struct dpp_nppu_pktrx_cfg_hdu_ex_tpid_1_t {
	u32 cfg_type2;
	u32 cfg_type3;
};

struct dpp_nppu_pktrx_cfg_hdu_int_tpid_0_t {
	u32 cfg_inner_type0;
	u32 cfg_inner_type1;
};

struct dpp_nppu_pktrx_cfg_hdu_int_tpid_1_t {
	u32 cfg_inner_type2;
	u32 cfg_inner_type3;
};

struct dpp_nppu_pktrx_cfg_hdu_hdlc_0_t {
	u32 hdlc_cfg0_type;
	u32 hdlc_cfg1_type;
};

struct dpp_nppu_pktrx_cfg_hdu_hdlc_1_t {
	u32 hdlc_cfg2_type;
	u32 hdlc_cfg3_type;
};

struct dpp_nppu_pktrx_cfg_hdu_udf_l3type_0_t {
	u32 cfg_l3_type0;
	u32 cfg_l3_type1;
};

struct dpp_nppu_pktrx_cfg_hdu_udf_l3type_1_t {
	u32 cfg_l3_type2;
	u32 cfg_l3_type3;
};

struct dpp_nppu_pktrx_cfg_hdu_udf_l3type_2_t {
	u32 cfg_l3_type4;
	u32 cfg_l3_type5;
};

struct dpp_nppu_pktrx_cfg_hdu_udf_l3type_3_t {
	u32 cfg_l3_type6;
	u32 cfg_l3_type7;
};

struct dpp_nppu_pktrx_cfg_hdu_udf_l4type_0_t {
	u32 cfg_l4_type0;
	u32 cfg_l4_type1;
	u32 cfg_l4_type2;
	u32 cfg_l4_type3;
};

struct dpp_nppu_pktrx_cfg_hdu_udf_l4type_1_t {
	u32 cfg_l4_type4;
	u32 cfg_l4_type5;
	u32 cfg_l4_type6;
	u32 cfg_l4_type7;
};

struct dpp_nppu_pktrx_cfg_hdu_udf_l4type_2_t {
	u32 cfg_l4_type8;
	u32 cfg_l4_type9;
	u32 cfg_l4_type10;
};

struct dpp_nppu_pktrx_cfg_slot_no_cfg_t {
	u32 cfg_parser_slot_no;
};

struct dpp_nppu_pktrx_cfg_pktrx_int_en_0_t {
	u32 pktrx_int_en_31;
	u32 pktrx_int_en_30;
	u32 pktrx_int_en_29;
	u32 pktrx_int_en_28;
	u32 pktrx_int_en_27;
	u32 pktrx_int_en_26;
	u32 pktrx_int_en_25;
	u32 pktrx_int_en_24;
	u32 pktrx_int_en_23;
	u32 pktrx_int_en_22;
	u32 pktrx_int_en_21;
	u32 pktrx_int_en_20;
	u32 pktrx_int_en_19;
	u32 pktrx_int_en_18;
	u32 pktrx_int_en_17;
	u32 pktrx_int_en_16;
	u32 pktrx_int_en_15;
	u32 pktrx_int_en_14;
	u32 pktrx_int_en_13;
	u32 pktrx_int_en_12;
	u32 pktrx_int_en_11;
	u32 pktrx_int_en_10;
	u32 pktrx_int_en_9;
	u32 pktrx_int_en_8;
	u32 pktrx_int_en_7;
	u32 pktrx_int_en_6;
	u32 pktrx_int_en_5;
	u32 pktrx_int_en_4;
	u32 pktrx_int_en_3;
	u32 pktrx_int_en_2;
	u32 pktrx_int_en_1;
	u32 pktrx_int_en_0;
};

struct dpp_nppu_pktrx_cfg_pktrx_int_en_1_t {
	u32 pktrx_int_en_35;
	u32 pktrx_int_en_34;
	u32 pktrx_int_en_33;
	u32 pktrx_int_en_32;
};

struct dpp_nppu_pktrx_cfg_pktrx_int_mask_0_t {
	u32 pktrx_int_mask_31;
	u32 pktrx_int_mask_30;
	u32 pktrx_int_mask_29;
	u32 pktrx_int_mask_28;
	u32 pktrx_int_mask_27;
	u32 pktrx_int_mask_26;
	u32 pktrx_int_mask_25;
	u32 pktrx_int_mask_24;
	u32 pktrx_int_mask_23;
	u32 pktrx_int_mask_22;
	u32 pktrx_int_mask_21;
	u32 pktrx_int_mask_20;
	u32 pktrx_int_mask_19;
	u32 pktrx_int_mask_18;
	u32 pktrx_int_mask_17;
	u32 pktrx_int_mask_16;
	u32 pktrx_int_mask_15;
	u32 pktrx_int_mask_14;
	u32 pktrx_int_mask_13;
	u32 pktrx_int_mask_12;
	u32 pktrx_int_mask_11;
	u32 pktrx_int_mask_10;
	u32 pktrx_int_mask_9;
	u32 pktrx_int_mask_8;
	u32 pktrx_int_mask_7;
	u32 pktrx_int_mask_6;
	u32 pktrx_int_mask_5;
	u32 pktrx_int_mask_4;
	u32 pktrx_int_mask_3;
	u32 pktrx_int_mask_2;
	u32 pktrx_int_mask_1;
	u32 pktrx_int_mask_0;
};

struct dpp_nppu_pktrx_cfg_pktrx_int_mask_1_t {
	u32 pktrx_int_mask_35;
	u32 pktrx_int_mask_34;
	u32 pktrx_int_mask_33;
	u32 pktrx_int_mask_32;
};

struct dpp_nppu_pktrx_cfg_pktrx_int_status_t {
	u32 int_status;
};

struct dpp_nppu_pktrx_cfg_pktrx_port_rdy0_t {
	u32 pktrx_trpgrx_r1_rdy;
	u32 pktrx_trpgrx_r2_rdy;
};

struct dpp_nppu_pktrx_cfg_pktrx_lif0_pfc_rdy0_t {
	u32 pktrx_trpgrx_r1_pfc_rdy_0;
};

struct dpp_nppu_pktrx_cfg_pktrx_lif0_pfc_rdy1_t {
	u32 pktrx_trpgrx_r1_pfc_rdy_1;
};

struct dpp_nppu_pktrx_cfg_pktrx_lif0_pfc_rdy2_t {
	u32 pktrx_trpgrx_r1_pfc_rdy_2;
};

struct dpp_nppu_pktrx_cfg_pktrx_lif0_pfc_rdy3_t {
	u32 pktrx_trpgrx_r2_pfc_rdy_3;
};

struct dpp_nppu_pktrx_cfg_pktrx_lif0_pfc_rdy4_t {
	u32 pktrx_trpgrx_r2_pfc_rdy_4;
};

struct dpp_nppu_pktrx_cfg_pktrx_lif0_pfc_rdy5_t {
	u32 pktrx_trpgrx_r2_pfc_rdy_5;
};

struct dpp_nppu_pktrx_cfg_pktrx_lif0_pfc_rdy6_t {
	u32 pktrx_trpgrx_r2_pfc_rdy_6;
};

struct dpp_nppu_pktrx_cfg_cfg_port_l2_offset_mode_t {
	u32 cfg_port_l2_offset_mode;
};

struct dpp_nppu_idma_cfg_int_ram_en_t {
	u32 phy_sts_parity_err;
	u32 ptr_buf_parity_err;
};

struct dpp_nppu_idma_cfg_int_ram_mask_t {
	u32 phy_sts_parity_err;
	u32 ptr_buf_parity_err;
};

struct dpp_nppu_idma_cfg_int_ram_status_t {
	u32 phy_sts_parity_err;
	u32 ptr_buf_parity_err;
};

struct dpp_nppu_idma_cfg_subsys_int_mask_flag_t {
	u32 subsys_int_mask_flag;
};

struct dpp_nppu_idma_cfg_subsys_int_unmask_flag_t {
	u32 subsys_int_unmask_flag;
};

struct dpp_nppu_idma_cfg_debug_cnt_rdclr_mode_t {
	u32 debug_cnt_rdclr_mode;
};

struct dpp_nppu_pbu_cfg_int_ram_en0_t {
	u32 int_ram_en_31;
	u32 int_ram_en_30;
	u32 int_ram_en_29;
	u32 int_ram_en_28;
	u32 int_ram_en_27;
	u32 int_ram_en_26;
	u32 int_ram_en_25;
	u32 int_ram_en_24;
	u32 int_ram_en_23;
	u32 int_ram_en_22;
	u32 int_ram_en_21;
	u32 int_ram_en_20;
	u32 int_ram_en_19;
	u32 int_ram_en_18;
	u32 int_ram_en_17;
	u32 int_ram_en_16;
	u32 int_ram_en_15;
	u32 int_ram_en_14;
	u32 int_ram_en_13;
	u32 int_ram_en_12;
	u32 int_ram_en_11;
	u32 int_ram_en_10;
	u32 int_ram_en_9;
	u32 int_ram_en_8;
	u32 int_ram_en_7;
	u32 int_ram_en_6;
	u32 int_ram_en_5;
	u32 int_ram_en_4;
	u32 int_ram_en_3;
	u32 int_ram_en_2;
	u32 int_ram_en_1;
	u32 int_ram_en_0;
};

struct dpp_nppu_pbu_cfg_int_ram_mask0_t {
	u32 int_ram_mask_31;
	u32 int_ram_mask_30;
	u32 int_ram_mask_29;
	u32 int_ram_mask_28;
	u32 int_ram_mask_27;
	u32 int_ram_mask_26;
	u32 int_ram_mask_25;
	u32 int_ram_mask_24;
	u32 int_ram_mask_23;
	u32 int_ram_mask_22;
	u32 int_ram_mask_21;
	u32 int_ram_mask_20;
	u32 int_ram_mask_19;
	u32 int_ram_mask_18;
	u32 int_ram_mask_17;
	u32 int_ram_mask_16;
	u32 int_ram_mask_15;
	u32 int_ram_mask_14;
	u32 int_ram_mask_13;
	u32 int_ram_mask_12;
	u32 int_ram_mask_11;
	u32 int_ram_mask_10;
	u32 int_ram_mask_9;
	u32 int_ram_mask_8;
	u32 int_ram_mask_7;
	u32 int_ram_mask_6;
	u32 int_ram_mask_5;
	u32 int_ram_mask_4;
	u32 int_ram_mask_3;
	u32 int_ram_mask_2;
	u32 int_ram_mask_1;
	u32 int_ram_mask_0;
};

struct dpp_nppu_pbu_cfg_int_ram_status0_t {
	u32 int_ram_status_31;
	u32 int_ram_status_30;
	u32 int_ram_status_29;
	u32 int_ram_status_28;
	u32 int_ram_status_27;
	u32 int_ram_status_26;
	u32 int_ram_status_25;
	u32 int_ram_status_24;
	u32 int_ram_status_23;
	u32 int_ram_status_22;
	u32 int_ram_status_21;
	u32 int_ram_status_20;
	u32 int_ram_status_19;
	u32 int_ram_status_18;
	u32 int_ram_status_17;
	u32 int_ram_status_16;
	u32 int_ram_status_15;
	u32 int_ram_status_14;
	u32 int_ram_status_13;
	u32 int_ram_status_12;
	u32 int_ram_status_11;
	u32 int_ram_status_10;
	u32 int_ram_status_9;
	u32 int_ram_status_8;
	u32 int_ram_status_7;
	u32 int_ram_status_6;
	u32 int_ram_status_5;
	u32 int_ram_status_4;
	u32 int_ram_status_3;
	u32 int_ram_status_2;
	u32 int_ram_status_1;
	u32 int_ram_status_0;
};

struct dpp_nppu_pbu_cfg_int_fifo_en0_t {
	u32 int_fifo_en_31;
	u32 int_fifo_en_30;
	u32 int_fifo_en_29;
	u32 int_fifo_en_28;
	u32 int_fifo_en_27;
	u32 int_fifo_en_26;
	u32 int_fifo_en_25;
	u32 int_fifo_en_24;
	u32 int_fifo_en_23;
	u32 int_fifo_en_22;
	u32 int_fifo_en_21;
	u32 int_fifo_en_20;
	u32 int_fifo_en_19;
	u32 int_fifo_en_18;
	u32 int_fifo_en_17;
	u32 int_fifo_en_16;
	u32 int_fifo_en_15;
	u32 int_fifo_en_14;
	u32 int_fifo_en_13;
	u32 int_fifo_en_12;
	u32 int_fifo_en_11;
	u32 int_fifo_en_10;
	u32 int_fifo_en_9;
	u32 int_fifo_en_8;
	u32 int_fifo_en_7;
	u32 int_fifo_en_6;
	u32 int_fifo_en_5;
	u32 int_fifo_en_4;
	u32 int_fifo_en_3;
	u32 int_fifo_en_2;
	u32 int_fifo_en_1;
	u32 int_fifo_en_0;
};

struct dpp_nppu_pbu_cfg_int_fifo_en1_t {
	u32 int_fifo_en_35;
	u32 int_fifo_en_34;
	u32 int_fifo_en_33;
	u32 int_fifo_en_32;
};

struct dpp_nppu_pbu_cfg_int_fifo_mask0_t {
	u32 int_fifo_mask_31;
	u32 int_fifo_mask_30;
	u32 int_fifo_mask_29;
	u32 int_fifo_mask_28;
	u32 int_fifo_mask_27;
	u32 int_fifo_mask_26;
	u32 int_fifo_mask_25;
	u32 int_fifo_mask_24;
	u32 int_fifo_mask_23;
	u32 int_fifo_mask_22;
	u32 int_fifo_mask_21;
	u32 int_fifo_mask_20;
	u32 int_fifo_mask_19;
	u32 int_fifo_mask_18;
	u32 int_fifo_mask_17;
	u32 int_fifo_mask_16;
	u32 int_fifo_mask_15;
	u32 int_fifo_mask_14;
	u32 int_fifo_mask_13;
	u32 int_fifo_mask_12;
	u32 int_fifo_mask_11;
	u32 int_fifo_mask_10;
	u32 int_fifo_mask_9;
	u32 int_fifo_mask_8;
	u32 int_fifo_mask_7;
	u32 int_fifo_mask_6;
	u32 int_fifo_mask_5;
	u32 int_fifo_mask_4;
	u32 int_fifo_mask_3;
	u32 int_fifo_mask_2;
	u32 int_fifo_mask_1;
	u32 int_fifo_mask_0;
};

struct dpp_nppu_pbu_cfg_int_fifo_mask1_t {
	u32 int_fifo_mask_35;
	u32 int_fifo_mask_34;
	u32 int_fifo_mask_33;
	u32 int_fifo_mask_32;
};

struct dpp_nppu_pbu_cfg_int_fifo_status0_t {
	u32 int_fifo_status_31;
	u32 int_fifo_status_30;
	u32 int_fifo_status_29;
	u32 int_fifo_status_28;
	u32 int_fifo_status_27;
	u32 int_fifo_status_26;
	u32 int_fifo_status_25;
	u32 int_fifo_status_24;
	u32 int_fifo_status_23;
	u32 int_fifo_status_22;
	u32 int_fifo_status_21;
	u32 int_fifo_status_20;
	u32 int_fifo_status_19;
	u32 int_fifo_status_18;
	u32 int_fifo_status_17;
	u32 int_fifo_status_16;
	u32 int_fifo_status_15;
	u32 int_fifo_status_14;
	u32 int_fifo_status_13;
	u32 int_fifo_status_12;
	u32 int_fifo_status_11;
	u32 int_fifo_status_10;
	u32 int_fifo_status_9;
	u32 int_fifo_status_8;
	u32 int_fifo_status_7;
	u32 int_fifo_status_6;
	u32 int_fifo_status_5;
	u32 int_fifo_status_4;
	u32 int_fifo_status_3;
	u32 int_fifo_status_2;
	u32 int_fifo_status_1;
	u32 int_fifo_status_0;
};

struct dpp_nppu_pbu_cfg_int_fifo_status1_t {
	u32 int_fifo_status_35;
	u32 int_fifo_status_34;
	u32 int_fifo_status_33;
	u32 int_fifo_status_32;
};

struct dpp_nppu_pbu_cfg_subsys_int_mask_flag_t {
	u32 subsys_int_mask_flag;
};

struct dpp_nppu_pbu_cfg_subsys_int_unmask_flag_t {
	u32 subsys_int_unmask_flag;
};

struct dpp_nppu_pbu_cfg_sa_ip_en_t {
	u32 sa_ip_en;
};

struct dpp_nppu_pbu_cfg_debug_cnt_rdclr_mode_t {
	u32 debug_cnt_rdclr_mode;
};

struct dpp_nppu_pbu_cfg_fptr_fifo_aful_assert_cfg_t {
	u32 fptr_fifo_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_fptr_fifo_aful_negate_cfg_t {
	u32 fptr_fifo_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_pf_fifo_aful_assert_cfg_t {
	u32 pf_fifo_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_pf_fifo_aful_negate_cfg_t {
	u32 pf_fifo_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_pf_fifo_aept_assert_cfg_t {
	u32 pf_fifo_aept_assert_cfg;
};

struct dpp_nppu_pbu_cfg_pf_fifo_aept_negate_cfg_t {
	u32 pf_fifo_aept_negate_cfg;
};

struct dpp_nppu_pbu_cfg_wb_aful_assert_cfg_t {
	u32 wb_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_wb_aful_negate_cfg_t {
	u32 wb_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_se_key_aful_assert_cfg_t {
	u32 se_key_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_ifbrd_se_aful_assert_cfg_t {
	u32 ifbrd_se_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_ifbrd_se_aful_negate_cfg_t {
	u32 ifbrd_se_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_ifbrd_odma_aful_assert_cfg_t {
	u32 ifbrd_odma_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_ifbrd_odma_aful_negate_cfg_t {
	u32 ifbrd_odma_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_ifbrd_ppu_aful_assert_cfg_t {
	u32 ifbrd_ppu_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_ifbrd_ppu_aful_negate_cfg_t {
	u32 ifbrd_ppu_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_mc_logic_aful_assert_cfg_t {
	u32 mc_logic_aful_assert_cfg;
};

struct dpp_nppu_pbu_cfg_mc_logic_aful_negate_cfg_t {
	u32 mc_logic_aful_negate_cfg;
};

struct dpp_nppu_pbu_cfg_mc_logic_diff_t {
	u32 mc_logic_diff;
};

struct dpp_nppu_pbu_cfg_cfg_peak_port_cnt_clr_t {
	u32 cfg_peak_port_cnt_clr;
};

struct dpp_nppu_pbu_cfg_all_ftm_crdt_th_t {
	u32 ftm_crdt_port_cng_th;
	u32 ftm_crdt_port_th;
};

struct dpp_nppu_pbu_cfg_all_ftm_link_th_01_t {
	u32 total_congest_th1;
	u32 total_congest_th0;
};

struct dpp_nppu_pbu_cfg_all_ftm_link_th_23_t {
	u32 total_congest_th3;
	u32 total_congest_th2;
};

struct dpp_nppu_pbu_cfg_all_ftm_link_th_45_t {
	u32 total_congest_th5;
	u32 total_congest_th4;
};

struct dpp_nppu_pbu_cfg_all_ftm_link_th_6_t {
	u32 total_congest_th6;
};

struct dpp_nppu_pbu_cfg_all_ftm_total_congest_th_t {
	u32 all_ftm_total_congest_th;
};

struct dpp_nppu_pbu_cfg_cfg_crdt_mode_t {
	u32 cfg_crdt_mode;
};

struct dpp_nppu_pbu_cfg_cfg_pfc_rdy_high_time_t {
	u32 cfg_pfc_rdy_high_time;
};

struct dpp_nppu_pbu_cfg_cfg_pfc_rdy_low_time_t {
	u32 cfg_pfc_rdy_low_time;
};

struct dpp_nppu_pbu_stat_pbu_fc_rdy_t {
	u32 pbu_oam_send_fc_rdy;
	u32 pbu_odma_fc_rdy;
	u32 pbu_tm_fc_rdy;
	u32 pbu_idma_cos_rdy;
};

struct dpp_nppu_pbu_stat_pbu_lif_group0_rdy0_t {
	u32 pbu_ipg1_rdy;
	u32 pbu_ipg0_rdy;
	u32 pbu_trpgrx_xge_rdy;
	u32 pbu_trpgrx_cge1_rdy;
	u32 pbu_trpgrx_cge0_rdy;
};

struct dpp_nppu_pbu_stat_pbu_lif_group0_rdy1_t {
	u32 pbu_lif_group0_rdy1;
};

struct dpp_nppu_pbu_stat_pbu_lif_group1_rdy_t {
	u32 pbu_lif_group1_rdy1;
};

struct dpp_nppu_pbu_stat_pbu_lif_group0_pfc_rdy_t {
	u32 pbu_lif_group0_pfc_rdy;
};

struct dpp_nppu_pbu_stat_pbu_lif_group1_pfc_rdy_t {
	u32 pbu_lif_group1_pfc_rdy;
};

struct dpp_nppu_pbu_stat_pbu_sa_port_rdy_0_31_t {
	u32 pbu_sa_port_rdy_0_31;
};

struct dpp_nppu_pbu_stat_pbu_sa_port_rdy_32_50_t {
	u32 pbu_sa_port_rdy_32_50;
};

struct dpp_nppu_pbu_stat_pbu_pktrx_mr_pfc_rdy_t {
	u32 pbu_pktrx_mr_pfc_rdy;
};

struct dpp_nppu_pbu_stat_pbu_ftm_crdt_port_rdy_0_31_t {
	u32 pbu_ftm_crdt_port_rdy_0_31;
};

struct dpp_nppu_pbu_stat_pbu_ftm_crdt_port_rdy_32_47_t {
	u32 pbu_ftm_crdt_port_rdy_32_47;
};

struct dpp_nppu_pbu_stat_pbu_ftm_crdt_port_cng_rdy_0_31_t {
	u32 pbu_ftm_crdt_port_cng_rdy_0_31;
};

struct dpp_nppu_pbu_stat_pbu_ftm_crdt_port_cng_rdy_32_47_t {
	u32 pbu_ftm_crdt_port_cng_rdy_32_47;
};

struct dpp_nppu_pbu_stat_pbu_ftm_crdt_sys_info_t {
	u32 pbu_ftm_crdt_sys_info;
};

struct dpp_nppu_isu_cfg_weight_normal_mc_t {
	u32 weight_normal_mc;
};

struct dpp_nppu_isu_cfg_weight_sa_mc_t {
	u32 weight_sa_mc;
};

struct dpp_nppu_isu_cfg_weight_etm_t {
	u32 weight_etm;
};

struct dpp_nppu_isu_cfg_weight_lp_mc_t {
	u32 weight_lp_mc;
};

struct dpp_nppu_isu_cfg_weight_oam_t {
	u32 weight_oam;
};

struct dpp_nppu_isu_cfg_weight_lif_ctrl1_t {
	u32 weight_lif_ctrl1;
};

struct dpp_nppu_isu_cfg_weight_lif_ctrl2_t {
	u32 weight_lif_ctrl2;
};

struct dpp_nppu_isu_cfg_ecc_bypass_read_t {
	u32 eccbypass;
};

struct dpp_nppu_isu_cfg_isu_int_mask_t {
	u32 isu_int_mask;
};

struct dpp_nppu_isu_cfg_cfg_crdt_cycle_t {
	u32 cfg_cycle;
};

struct dpp_nppu_isu_cfg_cfg_crdt_value_t {
	u32 cfg_value;
};

struct dpp_nppu_isu_cfg_isu_int_en_t {
	u32 isu_int_en;
};

struct dpp_nppu_isu_cfg_isu_ppu_fifo_fc_t {
	u32 isu_ppu_fifo_fc;
};

struct dpp_nppu_isu_cfg_isu_int_status_t {
	u32 isu_int_status_26;
	u32 isu_int_status_25;
	u32 isu_int_status_24;
	u32 isu_int_status_23;
	u32 isu_int_status_22;
	u32 isu_int_status_21;
	u32 isu_int_status_20;
	u32 isu_int_status_19;
	u32 isu_int_status_18;
	u32 isu_int_status_17;
	u32 isu_int_status_16;
	u32 isu_int_status_15;
	u32 isu_int_status_14;
	u32 isu_int_status_13;
	u32 isu_int_status_12;
	u32 isu_int_status_11;
	u32 isu_int_status_10;
	u32 isu_int_status_9;
	u32 isu_int_status_8;
	u32 isu_int_status_7;
	u32 isu_int_status_6;
	u32 isu_int_status_5;
	u32 isu_int_status_4;
	u32 isu_int_status_3;
	u32 isu_int_status_2;
	u32 isu_int_status_1;
	u32 isu_int_status_0;
};

struct dpp_nppu_isu_cfg_fd_prog_full_assert_cfg_t {
	u32 fd_prog_full_assert_cfg;
};

struct dpp_nppu_isu_cfg_fd_prog_full_negate_cfg_t {
	u32 fd_prog_full_negate_cfg;
};

struct dpp_nppu_isu_cfg_lp_prog_full_assert_cfg_t {
	u32 lp_prog_ept_assert_cfg;
};

struct dpp_nppu_isu_cfg_lp_prog_full_negate_cfg_t {
	u32 lp_prog_ept_negate_cfg;
};

struct dpp_nppu_isu_stat_debug_cnt_dat0_t {
	u32 debug_cnt_dat0;
};

struct dpp_nppu_isu_stat_debug_cnt_dat1_t {
	u32 debug_cnt_dat1;
};

struct dpp_nppu_isu_stat_debug_cnt_dat2_t {
	u32 debug_cnt_dat2;
};

struct dpp_nppu_isu_stat_debug_cnt_dat3_t {
	u32 debug_cnt_dat3;
};

struct dpp_nppu_isu_stat_debug_cnt_dat4_t {
	u32 debug_cnt_dat4;
};

struct dpp_nppu_isu_stat_debug_cnt_dat5_t {
	u32 debug_cnt_dat5;
};

struct dpp_nppu_isu_stat_debug_cnt_dat6_t {
	u32 debug_cnt_dat6;
};

struct dpp_nppu_isu_stat_debug_cnt_dat7_t {
	u32 debug_cnt_dat7;
};

struct dpp_nppu_isu_stat_debug_cnt_dat8_t {
	u32 debug_cnt_dat8;
};

struct dpp_nppu_isu_stat_debug_cnt_dat9_t {
	u32 debug_cnt_dat9;
};

struct dpp_nppu_isu_stat_debug_cnt_dat10_t {
	u32 debug_cnt_dat10;
};

struct dpp_nppu_isu_stat_debug_cnt_dat11_t {
	u32 debug_cnt_dat11;
};

struct dpp_nppu_isu_stat_debug_cnt_dat12_t {
	u32 debug_cnt_dat12;
};

struct dpp_nppu_isu_stat_debug_cnt_dat13_t {
	u32 debug_cnt_dat13;
};

struct dpp_nppu_isu_stat_debug_cnt_dat14_t {
	u32 debug_cnt_dat14;
};

struct dpp_nppu_isu_stat_debug_cnt_dat15_t {
	u32 debug_cnt_dat15;
};

struct dpp_nppu_isu_stat_debug_cnt_dat16_t {
	u32 debug_cnt_dat16;
};

struct dpp_nppu_isu_stat_debug_cnt_dat17_t {
	u32 debug_cnt_dat17;
};

struct dpp_nppu_isu_stat_debug_cnt_dat18_t {
	u32 debug_cnt_dat18;
};

struct dpp_nppu_isu_stat_debug_cnt_dat19_t {
	u32 debug_cnt_dat18;
};

struct dpp_nppu_isu_stat_debug_cnt_cfg_t {
	u32 debug_cnt_ovf_mode;
	u32 debug_cnt_rdclr_mode;
	u32 user_cnt_value;
};

struct dpp_nppu_odma_cfg_exsa_tdm_offset_t {
	u32 exsa_tdm_offset;
};

struct dpp_nppu_odma_cfg_ecc_bypass_readt_t {
	u32 ecc_bypass_read;
};

struct dpp_nppu_odma_cfg_odma_int_en_0_t {
	u32 odma_int_en_31;
	u32 odma_int_en_30;
	u32 odma_int_en_29;
	u32 odma_int_en_28;
	u32 odma_int_en_27;
	u32 odma_int_en_26;
	u32 odma_int_en_25;
	u32 odma_int_en_24;
	u32 odma_int_en_22;
	u32 odma_int_en_21;
	u32 odma_int_en_18;
};

struct dpp_nppu_odma_cfg_odma_int_en_1_t {
	u32 odma_int_en_63;
	u32 odma_int_en_62;
	u32 odma_int_en_61;
	u32 odma_int_en_59;
	u32 odma_int_en_58;
	u32 odma_int_en_57;
	u32 odma_int_en_56;
	u32 odma_int_en_55;
	u32 odma_int_en_54;
	u32 odma_int_en_53;
	u32 odma_int_en_52;
	u32 odma_int_en_51;
	u32 odma_int_en_49;
	u32 odma_int_en_47;
	u32 odma_int_en_45;
	u32 odma_int_en_39;
	u32 odma_int_en_38;
	u32 odma_int_en_37;
	u32 odma_int_en_36;
	u32 odma_int_en_35;
	u32 odma_int_en_34;
	u32 odma_int_en_33;
	u32 odma_int_en_32;
};

struct dpp_nppu_odma_cfg_odma_int_en_2_t {
	u32 odma_int_en_91;
	u32 odma_int_en_88;
	u32 odma_int_en_85;
	u32 odma_int_en_82;
	u32 odma_int_en_79;
	u32 odma_int_en_75;
	u32 odma_int_en_74;
	u32 odma_int_en_71;
	u32 odma_int_en_65;
	u32 odma_int_en_64;
};

struct dpp_nppu_odma_cfg_odma_int_en_3_t {
	u32 odma_int_en_115;
	u32 odma_int_en_114;
	u32 odma_int_en_112;
	u32 odma_int_en_110;
	u32 odma_int_en_109;
	u32 odma_int_en_108;
	u32 odma_int_en_107;
	u32 odma_int_en_106;
	u32 odma_int_en_102;
	u32 odma_int_en_101;
	u32 odma_int_en_100;
	u32 odma_int_en_98;
	u32 odma_int_en_96;
};

struct dpp_nppu_odma_cfg_odma_int_mask_0_t {
	u32 odma_int_mask_31;
	u32 odma_int_mask_30;
	u32 odma_int_mask_29;
	u32 odma_int_mask_28;
	u32 odma_int_mask_27;
	u32 odma_int_mask_26;
	u32 odma_int_mask_25;
	u32 odma_int_mask_24;
	u32 odma_int_mask_22;
	u32 odma_int_mask_21;
	u32 odma_int_mask_18;
};

struct dpp_nppu_odma_cfg_odma_int_mask_1_t {
	u32 odma_int_mask_63;
	u32 odma_int_mask_62;
	u32 odma_int_mask_61;
	u32 odma_int_mask_59;
	u32 odma_int_mask_58;
	u32 odma_int_mask_57;
	u32 odma_int_mask_56;
	u32 odma_int_mask_55;
	u32 odma_int_mask_54;
	u32 odma_int_mask_53;
	u32 odma_int_mask_52;
	u32 odma_int_mask_51;
	u32 odma_int_mask_50;
	u32 odma_int_mask_49;
	u32 odma_int_mask_47;
	u32 odma_int_mask_45;
	u32 odma_int_mask_39;
	u32 odma_int_mask_38;
	u32 odma_int_mask_37;
	u32 odma_int_mask_36;
	u32 odma_int_mask_35;
	u32 odma_int_mask_34;
	u32 odma_int_mask_33;
	u32 odma_int_mask_32;
};

struct dpp_nppu_odma_cfg_odma_int_mask_2_t {
	u32 odma_int_mask_91;
	u32 odma_int_mask_88;
	u32 odma_int_mask_85;
	u32 odma_int_mask_82;
	u32 odma_int_mask_79;
	u32 odma_int_mask_75;
	u32 odma_int_mask_74;
	u32 odma_int_mask_71;
	u32 odma_int_mask_65;
	u32 odma_int_mask_64;
};

struct dpp_nppu_odma_cfg_odma_int_mask_3_t {
	u32 odma_int_mask_115;
	u32 odma_int_mask_114;
	u32 odma_int_mask_112;
	u32 odma_int_mask_110;
	u32 odma_int_mask_109;
	u32 odma_int_mask_108;
	u32 odma_int_mask_107;
	u32 odma_int_mask_106;
	u32 odma_int_mask_102;
	u32 odma_int_mask_101;
	u32 odma_int_mask_100;
	u32 odma_int_mask_98;
	u32 odma_int_mask_96;
};

struct dpp_nppu_odma_cfg_odma_int_status_0_t {
	u32 odma_int_status_31;
	u32 odma_int_status_30;
	u32 odma_int_status_29;
	u32 odma_int_status_28;
	u32 odma_int_status_27;
	u32 odma_int_status_26;
	u32 odma_int_status_25;
	u32 odma_int_status_24;
	u32 odma_int_status_22;
	u32 odma_int_status_21;
	u32 odma_int_status_18;
};

struct dpp_nppu_odma_cfg_odma_int_status_1_t {
	u32 odma_int_status_63;
	u32 odma_int_status_62;
	u32 odma_int_status_61;
	u32 odma_int_status_59;
	u32 odma_int_status_58;
	u32 odma_int_status_57;
	u32 odma_int_status_56;
	u32 odma_int_status_55;
	u32 odma_int_status_54;
	u32 odma_int_status_53;
	u32 odma_int_status_52;
	u32 odma_int_status_51;
	u32 odma_int_status_49;
	u32 odma_int_status_47;
	u32 odma_int_status_45;
	u32 odma_int_status_39;
	u32 odma_int_status_38;
	u32 odma_int_status_37;
	u32 odma_int_status_36;
	u32 odma_int_status_35;
	u32 odma_int_status_34;
	u32 odma_int_status_33;
	u32 odma_int_status_32;
};

struct dpp_nppu_odma_cfg_odma_int_status_2_t {
	u32 odma_int_status_91;
	u32 odma_int_status_88;
	u32 odma_int_status_85;
	u32 odma_int_status_82;
	u32 odma_int_status_79;
	u32 odma_int_status_75;
	u32 odma_int_status_74;
	u32 odma_int_status_71;
	u32 odma_int_status_65;
	u32 odma_int_status_64;
};

struct dpp_nppu_odma_cfg_odma_int_status_3_t {
	u32 odma_int_status_117;
	u32 odma_int_status_116;
	u32 odma_int_status_115;
	u32 odma_int_status_114;
	u32 odma_int_status_112;
	u32 odma_int_status_110;
	u32 odma_int_status_109;
	u32 odma_int_status_108;
	u32 odma_int_status_107;
	u32 odma_int_status_106;
	u32 odma_int_status_102;
	u32 odma_int_status_101;
	u32 odma_int_status_100;
	u32 odma_int_status_98;
	u32 odma_int_status_96;
};

struct dpp_nppu_odma_cfg_sp_tdm_err_nor_cfg_t {
	u32 sp_tdm_err_nor_cfg;
};

struct dpp_nppu_odma_cfg_etm_dis_ptr_prog_full_cfg_a_t {
	u32 etm_dis_ptr_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_etm_dis_ptr_prog_full_cfg_n_t {
	u32 etm_dis_ptr_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_ftm_dis_ptr_prog_full_cfg_a_t {
	u32 ftm_dis_ptr_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_ftm_dis_ptr_prog_full_cfg_n_t {
	u32 ftm_dis_ptr_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_tm_dis_fifo_prog_full_cfg_a_t {
	u32 tm_dis_fifo_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_tm_dis_fifo_prog_full_cfg_n_t {
	u32 tm_dis_fifo_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_err_prog_full_cfg_a_t {
	u32 err_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_err_prog_full_cfg_n_t {
	u32 err_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_tdmuc_prog_full_cfg_a_t {
	u32 tdmuc_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_tdmuc_prog_full_cfg_n_t {
	u32 tdmuc_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_tdmmc_groupid_prog_full_cfg_a_t {
	u32 tdmmc_groupid_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_tdmmc_groupid_prog_full_cfg_n_t {
	u32 tdmmc_groupid_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_tdmmc_no_bitmap_prog_full_cfg_a_t {
	u32 tdmmc_no_bitmap_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_tdmmc_no_bitmap_prog_full_cfg_n_t {
	u32 tdmmc_no_bitmap_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_tdmmc_prog_full_cfg_a_t {
	u32 tdmmc_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_tdmmc_prog_full_cfg_n_t {
	u32 tdmmc_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_desc_prog_full_cfg_a_t {
	u32 desc_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_desc_prog_full_cfg_n_t {
	u32 desc_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_dly_prog_full_cfg_a_t {
	u32 dly_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_dly_prog_full_cfg_n_t {
	u32 dly_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_rsp_prog_full_cfg_a_t {
	u32 rsp_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_rsp_prog_full_cfg_n_t {
	u32 rsp_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_nor_prog_full_cfg_a_t {
	u32 nor_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_nor_prog_full_cfg_n_t {
	u32 nor_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_etm_nor_prog_full_cfg_a_t {
	u32 etm_nor_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_etm_nor_prog_full_cfg_n_t {
	u32 etm_nor_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_ftm_nor_prog_full_cfg_a_t {
	u32 ftm_nor_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_ftm_nor_prog_full_cfg_n_t {
	u32 ftm_nor_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_etm_prog_full_cfg_a_t {
	u32 etm_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_etm_prog_full_cfg_n_t {
	u32 etm_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_ftm_prog_full_cfg_a_t {
	u32 ftm_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_ftm_prog_full_cfg_n_t {
	u32 ftm_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_etm_nrdcnt_prog_full_cfg_a_t {
	u32 etm_nrdcnt_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_etm_nrdcnt_prog_full_cfg_n_t {
	u32 etm_nrdcnt_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_ftm_nrdcnt_prog_full_cfg_a_t {
	u32 ftm_nrdcnt_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_ftm_nrdcnt_prog_full_cfg_n_t {
	u32 ftm_nrdcnt_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_pp_prog_full_cfg_a_t {
	u32 pp_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_pp_prog_full_cfg_n_t {
	u32 pp_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_tm_weight_t {
	u32 tm_weight;
};

struct dpp_nppu_odma_cfg_pp_weight_t {
	u32 pp_weight;
};

struct dpp_nppu_odma_cfg_ifbcmd_prog_full_cfg_a_t {
	u32 ifbcmd_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_ifbcmd_prog_full_cfg_n_t {
	u32 ifbcmd_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_mccnt_prog_full_cfg_a_t {
	u32 mccnt_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_mccnt_prog_full_cfg_n_t {
	u32 mccnt_prog_full_cfg_n;
};

struct dpp_nppu_odma_cfg_int_or_pon_t {
	u32 int_or_pon;
};

struct dpp_nppu_odma_cfg_quemng_cnt_in_err_cnt_t {
	u32 quemng_cnt_in_err_cnt;
};

struct dpp_nppu_odma_cfg_lif0_port_eop_cnt_t {
	u32 lif0_port_eop_cnt;
};

struct dpp_nppu_odma_cfg_lif1_port_eop_cnt_t {
	u32 lif1_port_eop_cnt;
};

struct dpp_nppu_odma_cfg_lifc_port0_eop_cnt_t {
	u32 lifc_port0_eop_cnt;
};

struct dpp_nppu_odma_cfg_lifc_port1_eop_cnt_t {
	u32 lifc_port1_eop_cnt;
};

struct dpp_nppu_odma_cfg_fptr_fifo_prog_ept_cfg_n_t {
	u32 fptr_fifo_prog_ept_cfg_n;
};

struct dpp_nppu_odma_cfg_isu_fifo_prog_full_cfg_a_t {
	u32 isu_fifo_prog_full_cfg_a;
};

struct dpp_nppu_odma_cfg_isu_fifo_prog_full_cfg_n_t {
	u32 isu_fifo_prog_full_cfg_n;
};

struct dpp_nppu_oam_cfg_ind_access_done_t {
	u32 ind_access_done;
};

struct dpp_nppu_oam_cfg_ind_access_command_t {
	u32 ind_rd_or_wr;
	u32 ind_mem_mask;
	u32 ind_mem_id;
	u32 ind_mem_addr;
};

struct dpp_nppu_oam_cfg_ind_dat0_t {
	u32 ind_dat0;
};

struct dpp_nppu_oam_cfg_ind_dat1_t {
	u32 ind_dat1;
};

struct dpp_nppu_oam_cfg_ind_dat2_t {
	u32 ind_dat2;
};

struct dpp_nppu_oam_cfg_ind_dat3_t {
	u32 ind_dat3;
};

struct dpp_nppu_oam_cfg_oam_tx_main_en_t {
	u32 oam_tx_main_en;
};

struct dpp_nppu_oam_cfg_tx_total_num_t {
	u32 tx_total_num;
};

struct dpp_nppu_oam_cfg_oam_chk_main_en_t {
	u32 oam_chk_main_en;
};

struct dpp_nppu_oam_cfg_chk_total_num0_t {
	u32 chk_total_num0;
};

struct dpp_nppu_oam_cfg_ma_chk_main_en_t {
	u32 oam_chk_main_en;
};

struct dpp_nppu_oam_cfg_chk_total_num1_t {
	u32 chk_total_num0;
};

struct dpp_nppu_oam_cfg_tx_stat_en_t {
	u32 tx_stat_en;
};

struct dpp_nppu_oam_cfg_rec_stat_en_t {
	u32 rec_stat_en;
};

struct dpp_nppu_oam_cfg_stat_oam_rdy_mask_t {
	u32 stat_oam_rdy_mask;
};

struct dpp_nppu_oam_cfg_session_grading0_t {
	u32 session_grading0;
};

struct dpp_nppu_oam_cfg_session_grading1_t {
	u32 session_grading1;
};

struct dpp_nppu_oam_cfg_session_grading2_t {
	u32 session_grading2;
};

struct dpp_nppu_oam_cfg_session_grading3_t {
	u32 session_grading3;
};

struct dpp_nppu_oam_cfg_bfd_chk_haddr_t {
	u32 bfd_chk_haddr;
};

struct dpp_nppu_oam_cfg_ethccm_chk_haddr_t {
	u32 ethccm_chk_haddr;
};

struct dpp_nppu_oam_cfg_tpbfd_chk_haddr_t {
	u32 tpbfd_chk_haddr;
};

struct dpp_nppu_oam_cfg_tpoam_ccm_chk_haddr_t {
	u32 tpoam_ccm_chk_haddr;
};

struct dpp_nppu_oam_cfg_bfd_tx_haddr_t {
	u32 bfd_tx_haddr;
};

struct dpp_nppu_oam_cfg_ethccm_tx_haddr_t {
	u32 ethccm_tx_haddr;
};

struct dpp_nppu_oam_cfg_tpbfd_tx_haddr_t {
	u32 tpbfd_tx_haddr;
};

struct dpp_nppu_oam_cfg_tpoam_ccm_tx_haddr_t {
	u32 tpoam_ccm_tx_haddr;
};

struct dpp_nppu_oam_cfg_ethccm_ma_chk_haddr_t {
	u32 ethccm_ma_chk_haddr;
};

struct dpp_nppu_oam_cfg_tpccm_ma_chk_haddr_t {
	u32 tpccm_ma_chk_haddr;
};

struct dpp_nppu_oam_cfg_groupnum_ram_clr_t {
	u32 groupnum_ram_clr;
};

struct dpp_nppu_oam_cfg_index_ram0_clr_t {
	u32 index_ram0_clr;
};

struct dpp_nppu_oam_cfg_index_ram1_clr_t {
	u32 index_ram1_clr;
};

struct dpp_nppu_oam_cfg_rmep_ram_clr_t {
	u32 rmep_ram_clr;
};

struct dpp_nppu_oam_cfg_ma_ram_clr_t {
	u32 ma_ram_clr;
};

struct dpp_nppu_oam_cfg_ram_init_done_t {
	u32 ram_init_done;
};

struct dpp_nppu_oam_cfg_rec_bfd_debug_en_t {
	u32 rec_bfd_debug_en;
};

struct dpp_nppu_oam_cfg_oam_session_int_t {
	u32 tpma_int;
	u32 ethma_int;
	u32 bfd_int;
	u32 ethoam_int;
	u32 tpbfd_int;
	u32 tpoam_int;
};

struct dpp_nppu_oam_cfg_pon_int_t {
	u32 fifo_int;
	u32 pon_protect_int;
};

struct dpp_nppu_oam_cfg_oam_int_clr_t {
	u32 oam_int_clr;
};

struct dpp_nppu_oam_cfg_type_int_clr0_t {
	u32 tpma_int_clr;
	u32 ethma_int_clr;
	u32 bfd_int_clr;
	u32 ethoam_int_clr;
	u32 tpbfd_int_clr;
	u32 tpoam_int_clr;
};

struct dpp_nppu_oam_cfg_type_int_clr1_t {
	u32 fifo_int_clr;
	u32 pon_protect_int_clr;
};

struct dpp_nppu_oam_cfg_interrupt_mask_t {
	u32 fifo_interrupt_mask;
	u32 pon_protect_interruptmask;
	u32 tpma_interrupt_mask;
	u32 ethma_interrupt_mask;
	u32 bfd_interrupt_mask;
	u32 ethoam_interrupt_mask;
	u32 tpbfd_interrupt_mask;
	u32 tpoam_interrupt_mask;
};

struct dpp_nppu_oam_cfg_int0_index_t {
	u32 int0_index0;
};

struct dpp_nppu_oam_cfg_int1_index_t {
	u32 int1_index0;
};

struct dpp_nppu_oam_cfg_int0_index_region_t {
	u32 int0_index_region;
};

struct dpp_nppu_oam_cfg_int1_index_region_t {
	u32 int1_index_region;
};

struct dpp_nppu_oam_cfg_bdiinfo_fwft_fifo_th_t {
	u32 bdiinfo_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_recsec_fwft_fifo_th_t {
	u32 recsec_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_timing_chk_info0_fwft_fifo_th_t {
	u32 timing_chk_info0_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_recma_fwft_fifo_th_t {
	u32 recma_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_timing_chk_info1_fwft_fifo_th_t {
	u32 timing_chk_info1_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_oam_txinst_fifo_th_t {
	u32 oam_txinst_fifo_th;
};

struct dpp_nppu_oam_cfg_oam_rdinfo_fwft_fifo_th_t {
	u32 oam_rdinfo_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_lm_cnt_fwft_fifo_th_t {
	u32 lm_cnt_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_oam_pkt_fifo_th_t {
	u32 oam_pkt_fifo_th;
};

struct dpp_nppu_oam_cfg_reclm_stat_fifo_th_t {
	u32 reclm_stat_fifo_th;
};

struct dpp_nppu_oam_cfg_txlm_stat_fifo_th_t {
	u32 txlm_stat_fifo_th;
};

struct dpp_nppu_oam_cfg_oam_chk_fwft_fifo_th_t {
	u32 oam_chk_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_txoam_stat_fifo_th_t {
	u32 txoam_stat_fifo_th;
};

struct dpp_nppu_oam_cfg_recoam_stat_fifo_th_t {
	u32 recoam_stat_fifo_th;
};

struct dpp_nppu_oam_cfg_txpkt_data_fwft_fifo_th_t {
	u32 txpkt_data_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_tstpkt_fwft_fifo_th_t {
	u32 tstpkt_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_tst_txinst_fwft_fifo_th_t {
	u32 tst_txinst_fwft_fifo_th;
};

struct dpp_nppu_oam_cfg_tstrx_main_en_t {
	u32 tstrx_main_en;
};

struct dpp_nppu_oam_cfg_tsttx_cfg_para_tbl2_t {
	u32 ddr_self_test_tx_en;
	u32 tm_self_test_tx_en;
	u32 fast_aging_tx_en;
	u32 timing_aging_tx_en;
	u32 backgroud_flow_tx_en;
	u32 tsttx_tx_en;
	u32 tx_freq;
	u32 tx_offset;
};

struct dpp_nppu_oam_cfg_tsttx_cfg_para_tbl1_t {
	u32 tx_count;
};

struct dpp_nppu_oam_cfg_tsttx_cfg_para_tbl0_t {
	u32 fast_tx_mode_en;
	u32 tsttx_tx_head_len;
	u32 tsttx_tx_interval;
};

struct dpp_nppu_oam_cfg_tstrx_cfg_para_t {
	u32 tstrx_session_num;
	u32 tstrx_session_en;
};

struct dpp_nppu_oam_cfg_fifo_status_int_en_0_t {
	u32 fifo_status_int_en_31;
	u32 fifo_status_int_en_30;
	u32 fifo_status_int_en_29;
	u32 fifo_status_int_en_28;
	u32 fifo_status_int_en_27;
	u32 fifo_status_int_en_26;
	u32 fifo_status_int_en_25;
	u32 fifo_status_int_en_24;
	u32 fifo_status_int_en_23;
	u32 fifo_status_int_en_22;
	u32 fifo_status_int_en_21;
	u32 fifo_status_int_en_20;
	u32 fifo_status_int_en_19;
	u32 fifo_status_int_en_18;
	u32 fifo_status_int_en_17;
	u32 fifo_status_int_en_16;
	u32 fifo_status_int_en_15;
	u32 fifo_status_int_en_14;
	u32 fifo_status_int_en_13;
	u32 fifo_status_int_en_12;
	u32 fifo_status_int_en_11;
	u32 fifo_status_int_en_10;
	u32 fifo_status_int_en_9;
	u32 fifo_status_int_en_8;
	u32 fifo_status_int_en_7;
	u32 fifo_status_int_en_6;
	u32 fifo_status_int_en_5;
	u32 fifo_status_int_en_4;
	u32 fifo_status_int_en_3;
	u32 fifo_status_int_en_2;
	u32 fifo_status_int_en_1;
	u32 fifo_status_int_en_0;
};

struct dpp_nppu_oam_cfg_fifo_status_int_en_1_t {
	u32 fifo_status_int_en_41;
	u32 fifo_status_int_en_40;
	u32 fifo_status_int_en_39;
	u32 fifo_status_int_en_38;
	u32 fifo_status_int_en_37;
	u32 fifo_status_int_en_36;
	u32 fifo_status_int_en_35;
	u32 fifo_status_int_en_34;
	u32 fifo_status_int_en_33;
	u32 fifo_status_int_en_32;
};

struct dpp_nppu_oam_cfg_fifo_status_int_mask_0_t {
	u32 fifo_status_int_mask_31;
	u32 fifo_status_int_mask_30;
	u32 fifo_status_int_mask_29;
	u32 fifo_status_int_mask_28;
	u32 fifo_status_int_mask_27;
	u32 fifo_status_int_mask_26;
	u32 fifo_status_int_mask_25;
	u32 fifo_status_int_mask_24;
	u32 fifo_status_int_mask_23;
	u32 fifo_status_int_mask_22;
	u32 fifo_status_int_mask_21;
	u32 fifo_status_int_mask_20;
	u32 fifo_status_int_mask_19;
	u32 fifo_status_int_mask_18;
	u32 fifo_status_int_mask_17;
	u32 fifo_status_int_mask_16;
	u32 fifo_status_int_mask_15;
	u32 fifo_status_int_mask_14;
	u32 fifo_status_int_mask_13;
	u32 fifo_status_int_mask_12;
	u32 fifo_status_int_mask_11;
	u32 fifo_status_int_mask_10;
	u32 fifo_status_int_mask_9;
	u32 fifo_status_int_mask_8;
	u32 fifo_status_int_mask_7;
	u32 fifo_status_int_mask_6;
	u32 fifo_status_int_mask_5;
	u32 fifo_status_int_mask_4;
	u32 fifo_status_int_mask_3;
	u32 fifo_status_int_mask_2;
	u32 fifo_status_int_mask_1;
	u32 fifo_status_int_mask_0;
};

struct dpp_nppu_oam_cfg_fifo_status_int_mask_1_t {
	u32 fifo_status_int_mask_41;
	u32 fifo_status_int_mask_40;
	u32 fifo_status_int_mask_39;
	u32 fifo_status_int_mask_38;
	u32 fifo_status_int_mask_37;
	u32 fifo_status_int_mask_36;
	u32 fifo_status_int_mask_35;
	u32 fifo_status_int_mask_34;
	u32 fifo_status_int_mask_33;
	u32 fifo_status_int_mask_32;
};

struct dpp_nppu_oam_cfg_fifo_status_int_status_t {
	u32 fifo_status_int_status;
};

struct dpp_nppu_oam_cfg_main_frequency_t {
	u32 main_frequency;
};

struct dpp_nppu_oam_cfg_oam_cfg_type_t {
	u32 oam_cfg_type;
};

struct dpp_nppu_oam_cfg_fst_swch_eth_head0_t {
	u32 fst_swch_eth_head;
};

struct dpp_nppu_oam_cfg_fst_swch_eth_head1_t {
	u32 fst_swch_eth_head1;
};

struct dpp_nppu_oam_cfg_fst_swch_eth_head2_t {
	u32 fst_swch_eth_head2;
};

struct dpp_nppu_oam_cfg_fst_swch_eth_head3_t {
	u32 fst_swch_eth_head3;
};

struct dpp_nppu_oam_cfg_oam_fs_txinst_fifo_th_t {
	u32 oam_fs_txinst_fifo_th;
};

struct dpp_nppu_oam_cfg_oam_ma_fs_txinst_fifo_th_t {
	u32 oam_ma_fs_txinst_fifo_th;
};

struct dpp_nppu_oam_cfg_pon_int_ram_clr_t {
	u32 pon_int_ram_clr;
};

struct dpp_nppu_oam_cfg_pon_p_int_index_t {
	u32 pon_p_int_index;
};

struct dpp_nppu_oam_cfg_pon_protect_pkt_fifo_th_t {
	u32 pon_protect_pkt_fifo_th;
};

struct dpp_nppu_oam_cfg_pon_laser_off_en_t {
	u32 pon_laser_off_en;
};

struct dpp_nppu_oam_cfg_pon_prtct_pkt_tx_en_t {
	u32 pon_prtct_pkt_tx_en;
};

struct dpp_nppu_oam_cfg_cfg_pon_master_t {
	u32 cfg_pon_master;
};

struct dpp_nppu_oam_cfg_level_mode_t {
	u32 level_mode;
};

struct dpp_nppu_oam_cfg_interrupt_en_t {
	u32 interrupt_en;
};

struct dpp_nppu_oam_cfg_pon_laser_on_en_t {
	u32 pon_laser_on_en;
};

struct dpp_nppu_oam_cfg_ti_pon_sd_t {
	u32 ti_pon_sd;
};

struct dpp_nppu_oam_cfg_ti_pon_los_t {
	u32 ti_pon_los;
};

struct dpp_nppu_oam_cfg_ind_dat4_t {
	u32 ind_dat4;
};

struct dpp_nppu_oam_cfg_ind_dat5_t {
	u32 ind_dat5;
};

struct dpp_nppu_oam_cfg_ind_dat6_t {
	u32 ind_dat6;
};

struct dpp_nppu_oam_cfg_ind_dat7_t {
	u32 ind_dat7;
};

struct dpp_nppu_oam_cfg_ind_dat8_t {
	u32 ind_dat8;
};

struct dpp_nppu_oam_cfg_ind_dat9_t {
	u32 ind_dat9;
};

struct dpp_nppu_oam_cfg_ind_dat10_t {
	u32 ind_dat10;
};

struct dpp_nppu_oam_cfg_ind_dat11_t {
	u32 ind_dat11;
};

struct dpp_nppu_oam_cfg_ind_dat12_t {
	u32 ind_dat12;
};

struct dpp_nppu_oam_cfg_ind_dat13_t {
	u32 ind_dat13;
};

struct dpp_nppu_oam_cfg_ind_dat14_t {
	u32 ind_dat14;
};

struct dpp_nppu_oam_cfg_ind_dat15_t {
	u32 ind_dat15;
};

struct dpp_nppu_oam_cfg_oam_2544_pkt_fifo_th_t {
	u32 oam_2544_pkt_fifo_th;
};

struct dpp_nppu_oam_cfg_txinfo_ram_clr_t {
	u32 txinfo_ram_clr;
};

struct dpp_nppu_oam_cfg_txinfo_ram_init_done_t {
	u32 txinfo_ram_init_done;
};

struct dpp_nppu_oam_cfg_fifo_status_int_status40_t {
	u32 fifo_status_int_status40;
};

struct dpp_nppu_oam_cfg_fifo_status_int_status41_t {
	u32 fifo_status_int_status41;
};

struct dpp_nppu_oam_cfg_oam_2544_fun_en_t {
	u32 oam_2544_fun_en;
};

struct dpp_nppu_oam_cfg_oam_2544_stat_clr_t {
	u32 oam_2544_stat_clr;
};

struct dpp_nppu_oam_cfg_txdis_default_t {
	u32 txdis_default;
};

struct dpp_nppu_oam_cfg_txdis_default_en_t {
	u32 txdis_default_en;
};

struct dpp_nppu_oam_cfg_tpbfd_firstchk_th_t {
	u32 tpbfd_firstchk_th;
};

struct dpp_nppu_oam_cfg_ethccm_firstchk_th_t {
	u32 ethccm_firstchk_th;
};

struct dpp_nppu_oam_cfg_tpccm_firstchk_th_t {
	u32 tpccm_firstchk_th;
};

struct dpp_nppu_oam_stat_txstat_req_cnt_t {
	u32 txstat_req_cnt;
};

struct dpp_nppu_oam_stat_chkstat_req_cnt_t {
	u32 chkstat_req_cnt;
};

struct dpp_nppu_oam_stat_stat_oam_fc_cnt_t {
	u32 stat1_oam_fc_cnt;
};

struct dpp_nppu_oam_stat_bfdseq_req_cnt_t {
	u32 bfdseq_req_cnt;
};

struct dpp_nppu_oam_stat_lmcnt_req_cnt_t {
	u32 lmcnt_req_cnt;
};

struct dpp_nppu_oam_stat_stat_oam_lm_rsp_cnt_t {
	u32 stat2_rsp_cnt;
};

struct dpp_nppu_oam_stat_stat_oam_lm_fc_cnt_t {
	u32 stat2_oam_fc_cnt;
};

struct dpp_nppu_oam_stat_se_req_cnt_t {
	u32 se_req_cnt;
};

struct dpp_nppu_oam_stat_se_rsp_cnt_t {
	u32 se_rsp_cnt;
};

struct dpp_nppu_oam_stat_se_oam_fc_cnt_t {
	u32 se_oam_fc_cnt;
};

struct dpp_nppu_oam_stat_oam_se_fc_cnt_t {
	u32 oam_se_fc_cnt;
};

struct dpp_nppu_oam_stat_oam_pktrx_sop_cnt_t {
	u32 oam_pktrx_sop_cnt;
};

struct dpp_nppu_oam_stat_oam_pktrx_eop_cnt_t {
	u32 oam_pktrx_eop_cnt;
};

struct dpp_nppu_oam_stat_pktrx_oam_fc_cnt_t {
	u32 pktrx_oam_fc_cnt;
};

struct dpp_nppu_oam_stat_pktrx_oam_tst_fc_cnt_t {
	u32 pktrx_oam_tst_fc_cnt;
};

struct dpp_nppu_oam_stat_odma_oam_sop_cnt_t {
	u32 odma_oam_sop_cnt;
};

struct dpp_nppu_oam_stat_odma_oam_eop_cnt_t {
	u32 odma_oam_eop_cnt;
};

struct dpp_nppu_oam_stat_oam_odma_fc_cnt_t {
	u32 oam_odma_fc_cnt;
};

struct dpp_nppu_oam_stat_rec_ma_pkt_illegal_cnt_t {
	u32 rec_ma_pkt_illegal_cnt;
};

struct dpp_nppu_oam_stat_rec_rmep_pkt_illegal_cnt_t {
	u32 rec_rmep_pkt_illegal_cnt;
};

struct dpp_nppu_oam_stat_rec_eth_ais_pkt_cnt_t {
	u32 rec_eth_ais_pkt_cnt;
};

struct dpp_nppu_oam_stat_rec_tp_ais_pkt_cnt_t {
	u32 rec_tp_ais_pkt_cnt;
};

struct dpp_nppu_oam_stat_rec_tp_csf_pkt_cnt_t {
	u32 rec_tp_csf_pkt_cnt;
};

struct dpp_nppu_oam_stat_rec_eth_level_defect_cnt_t {
	u32 rec_eth_level_defect_cnt;
};

struct dpp_nppu_oam_stat_rec_eth_megid_defect_cnt_t {
	u32 rec_eth_megid_defect_cnt;
};

struct dpp_nppu_oam_stat_rec_eth_mepid_defect_cnt_t {
	u32 rec_eth_mepid_defect_cnt;
};

struct dpp_nppu_oam_stat_rec_eth_interval_defect_cnt_t {
	u32 rec_eth_interval_defect_cnt;
};

struct dpp_nppu_oam_stat_rec_sess_unenable_cnt_t {
	u32 rec_sess_unenable_cnt;
};

struct dpp_nppu_oam_stat_oam_2544_rd_pkt_cnt_t {
	u32 oam_2544_rd_pkt_cnt;
};

struct dpp_nppu_oam_stat_debug_cnt_clr_t {
	u32 debug_cnt_clr;
};

struct dpp_nppu_oam_stat_oam_pktrx_catch_data_t {
	u32 oam_pktrx_catch_data;
};

struct dpp_nppu_oam_stat_odma_oam_catch_data_t {
	u32 odma_oam_catch_data;
};

struct dpp_nppu_oam_stat_tst_session_tx_cnt_t {
	u32 tst_session_tx_cnt;
};

struct dpp_nppu_oam_stat_tst_session_rx_cnt_t {
	u32 tst_session_rx_cnt;
};

struct dpp_nppu_oam_stat_tstrx_lost_cnt_t {
	u32 tstrx_lost_cnt;
};

struct dpp_nppu_oam_stat_bfdseq_wr_cnt_t {
	u32 bfdseq_wr_cnt;
};

struct dpp_nppu_oam_stat_bfdtime_wr_cnt_t {
	u32 bfdtime_wr_cnt;
};

struct dpp_nppu_oam_stat_lmcnt_wr_cnt_t {
	u32 lmcnt_wr_cnt;
};

struct dpp_nppu_oam_stat_oam_fs_pkt_cnt_t {
	u32 oam_fs_pkt_cnt;
};

struct dpp_nppu_oam_stat_oam_ma_fs_pkt_cnt_t {
	u32 lmcnt_wr_cnt;
};

struct dpp_nppu_oam_stat_rec_tp_level_defect_cnt_t {
	u32 rec_tp_level_defect_cnt;
};

struct dpp_nppu_oam_stat_rec_tp_megid_defect_cnt_t {
	u32 rec_tp_megid_defect_cnt;
};

struct dpp_nppu_oam_stat_rec_tp_mepid_defect_cnt_t {
	u32 rec_tp_mepid_defect_cnt;
};

struct dpp_nppu_oam_stat_rec_tp_interval_defect_cnt_t {
	u32 rec_tp_interval_defect_cnt;
};

struct dpp_nppu_oam_stat_rd_reg_clear_mode_t {
	u32 rd_clear_mode_cfg;
};

struct dpp_nppu_oam_stat_rd_data_reg_clear_mode_t {
	u32 rd_data_reg_clear_mode_cfg;
};

struct dpp_nppu_oam_cfg_indir_oam_int_status_ram_0_t {
	u32 bfd_diag_value_bit4;
	u32 bfd_diag_value_bit3;
	u32 bfd_diag_value_bit2;
	u32 bfd_diag_value_bit1;
	u32 bfd_diag_value_bit0;
	u32 dloc_int;
	u32 drdi_int;
};

struct dpp_nppu_oam_cfg_indir_oam_int_status_ram1_t {
	u32 sticky_error_level_defect;
	u32 sticky_error_megid_defect;
	u32 sticky_error_mepid_defect;
	u32 sticky_error_inter_defect;
	u32 sticky_ais_defect;
	u32 sticky_csf_defect;
	u32 current_error_level_defect;
	u32 current_error_megid_defect;
	u32 current_error_mepid_defect;
	u32 current_error_inter_defect;
	u32 current_ais_defect;
	u32 current_csf_defect;
};

struct dpp_nppu_oam_cfg_indir_tst_pkt_tx_para_ram_t {
	u32 ddr_self_test_tx_en;
	u32 tm_self_test_tx_en;
	u32 fast_aging_tx_en;
	u32 timing_aging_tx_en;
	u32 backgroud_flow_tx_en;
	u32 tsttx_session_en;
	u32 tx_freq;
	u32 tx_offset;
	u32 tx_count;
	u32 fast_tx_mode_en;
	u32 tsttx_pkthead_len;
	u32 tsttx_interval;
};

struct dpp_nppu_oam_cfg_indir_groupnumram_t {
	u32 mep_down_num;
};

struct dpp_nppu_oam_cfg_indir_oam_tx_tbl_ram_t {
	u32 oam_tx_en;
	u32 oam_tx_type;
	u32 oam_fetch_len;
	u32 bfd_seq_tx_en;
	u32 tx_para;
	u32 oam_tx_interval;
	u32 hd_ena_flag;
	u32 last_tx_time;
};

struct dpp_nppu_oam_cfg_indir_oam_chk_tbl_ram_t {
	u32 fast_switch_en;
	u32 oam_chk_en;
	u32 oam_chk_type;
	u32 ccm_predel_flag;
	u32 lm_chk_en;
	u32 ccm_group_id;
	u32 oam_chk_internal;
	u32 fist_chk_flag;
	u32 last_chk_time;
};

struct dpp_nppu_oam_cfg_indir_oam_ma_chk_tbl_ram_t {
	u32 ma_fast_switch_en;
	u32 ma_chk_en;
	u32 ma_type;
	u32 error_level_defect_en;
	u32 error_megid_defect_en;
	u32 error_mepid_defect_en;
	u32 error_inter_defect_en;
	u32 ais_defect_en;
	u32 csf_defect_en;
	u32 error_level_defect_ccm;
	u32 error_megid_defect_ccm;
	u32 error_mepid_defect_ccm;
	u32 error_inter_defect_ccm;
	u32 ais_defect_ccm;
	u32 csf_defect_ccm;
	u32 ma_predel_en;
	u32 error_level_defect_ts;
	u32 error_megid_defect_ts;
	u32 error_mepid_defect_ts;
	u32 error_inter_defect_ts;
	u32 ais_defect_ts;
	u32 csf_defect_ts;
};

struct dpp_nppu_oam_cfg_indir_oam_2544_tx_ram_t {
	u32 tx_en_2544;
	u32 tx_cfg_times_2544;
	u32 current_times;
	u32 slice_num;
	u32 pkt_mty;
};

#endif
