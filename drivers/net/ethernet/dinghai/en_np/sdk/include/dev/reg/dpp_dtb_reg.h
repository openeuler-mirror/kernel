/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DTB_REG_H_
#define _DPP_DTB_REG_H_
struct dpp_dtb_dtb_cfg_cfg_eram_wr_interval_cnt_t {
	u32 cfg_eram_wr_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_zcam_wr_interval_cnt_t {
	u32 cfg_zcam_wr_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_tcam_wr_interval_cnt_t {
	u32 cfg_zcam_wr_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_ddr_wr_interval_cnt_t {
	u32 cfg_ddr_wr_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_hash_wr_interval_cnt_t {
	u32 cfg_hash_wr_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_eram_rd_interval_cnt_t {
	u32 cfg_eram_rd_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_zcam_rd_interval_cnt_t {
	u32 cfg_zcam_rd_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_tcam_rd_interval_cnt_t {
	u32 cfg_tcam_rd_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_ddr_rd_interval_cnt_t {
	u32 cfg_ddr_rd_interval_cnt;
};

struct dpp_dtb_dtb_cfg_cfg_dtb_queue_lock_state_0_3_t {
	u32 cfg_dtb_queue_lock_state;
};

struct dpp_dtb_dtb_axim0_w_convert_0_mode_t {
	u32 w_convert_mode;
};

struct dpp_dtb_dtb_axim0_r_convert_0_mode_t {
	u32 r_convert_mode;
};

struct dpp_dtb_dtb_axim0_aximr_os_t {
	u32 aximr_os;
};

struct dpp_dtb_dtb_axim1_w_convert_1_mode_t {
	u32 w_convert_mode;
};

struct dpp_dtb_dtb_axim1_r_convert_1_mode_t {
	u32 r_convert_mode;
};

struct dpp_dtb_dtb_axis_axis_convert_mode_t {
	u32 w_r_convert_mode;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_event0_t {
	u32 cfg_finish_int_event0;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_event1_t {
	u32 cfg_finish_int_event1;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_event2_t {
	u32 cfg_finish_int_event2;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_event3_t {
	u32 cfg_finish_int_event3;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_maks0_t {
	u32 cfg_finish_int_mask0;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_maks1_t {
	u32 cfg_finish_int_mask1;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_maks2_t {
	u32 cfg_finish_int_mask2;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_maks3_t {
	u32 cfg_finish_int_mask3;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_test0_t {
	u32 cfg_finish_int_test0;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_test1_t {
	u32 cfg_finish_int_test1;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_test2_t {
	u32 cfg_finish_int_test2;
};

struct dpp_dtb_dtb_cfg_cfg_finish_int_test3_t {
	u32 cfg_finish_int_test3;
};

struct dpp_dtb_dtb_cfg_cfg_dtb_int_to_riscv_sel_t {
	u32 cfg_dtb_int_to_riscv_sel0;
};

struct dpp_dtb_dtb_cfg_cfg_dtb_ep_int_msix_enable_t {
	u32 cfg_dtb_ep_int_msix_enable;
};

struct dpp_dtb_dtb_cfg_cfg_dtb_ep_doorbell_addr_h_0_15_t {
	u32 cfg_dtb_ep_doorbell_addr_h_0_15;
};

struct dpp_dtb_dtb_cfg_cfg_dtb_ep_doorbell_addr_l_0_15_t {
	u32 cfg_dtb_ep_doorbell_addr_l_0_15;
};

struct dpp_dtb_dtb_cfg_cfg_dtb_debug_mode_en_t {
	u32 cfg_dtb_debug_mode_en;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_addr_high_t {
	u32 info_axi_last_rd_table_addr_high;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_addr_low_t {
	u32 info_axi_last_rd_table_addr_low;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_len_t {
	u32 info_axi_last_rd_table_len;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t {
	u32 info_rd_table_user_en;
	u32 info_rd_table_epid;
	u32 info_rd_table_vfunc_num;
	u32 info_rd_table_func_num;
	u32 info_rd_table_vfunc_active;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_onload_cnt_t {
	u32 info_axi_last_rd_table_onload_cnt;
};

struct dpp_dtb_dtb_cfg_cnt_axi_rd_table_resp_err_t {
	u32 cnt_axi_rd_table_resp_err;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_addr_high_t {
	u32 info_axi_last_rd_pd_addr_high;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_addr_low_t {
	u32 info_axi_last_rd_pd_addr_low;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_len_t {
	u32 info_axi_last_rd_pd_len;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t {
	u32 info_rd_pd_user_en;
	u32 info_rd_pd_epid;
	u32 info_rd_pd_vfunc_num;
	u32 info_rd_pd_func_num;
	u32 info_rd_pd_vfunc_active;
};

struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_onload_cnt_t {
	u32 info_axi_last_rd_pd_onload_cnt;
};

struct dpp_dtb_dtb_cfg_cnt_axi_rd_pd_resp_err_t {
	u32 cnt_axi_rd_pd_resp_err;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_addr_high_t {
	u32 info_axi_last_wr_ctrl_addr_high;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_addr_low_t {
	u32 info_axi_last_wr_ctrl_addr_low;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_len_t {
	u32 info_axi_last_wr_ctrl_len;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t {
	u32 info_wr_ctrl_user_en;
	u32 info_wr_ctrl_epid;
	u32 info_wr_ctrl_vfunc_num;
	u32 info_wr_ctrl_func_num;
	u32 info_wr_ctrl_vfunc_active;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_onload_cnt_t {
	u32 info_axi_last_wr_ctrl_onload_cnt;
};

struct dpp_dtb_dtb_cfg_cnt_axi_wr_ctrl_resp_err_t {
	u32 cnt_axi_wr_ctrl_resp_err;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_addr_high_t {
	u32 info_axi_last_wr_ddr_addr_high;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_addr_low_t {
	u32 info_axi_last_wr_ddr_addr_low;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_len_t {
	u32 info_axi_last_wr_ddr_len;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t {
	u32 info_wr_ddr_user_en;
	u32 info_wr_ddr_epid;
	u32 info_wr_ddr_vfunc_num;
	u32 info_wr_ddr_func_num;
	u32 info_wr_ddr_vfunc_active;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_onload_cnt_t {
	u32 info_axi_last_wr_ddr_onload_cnt;
};

struct dpp_dtb_dtb_cfg_cnt_axi_wr_ddr_resp_err_t {
	u32 cnt_axi_wr_ddr_resp_err;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_addr_high_t {
	u32 info_axi_last_wr_fin_addr_high;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_addr_low_t {
	u32 info_axi_last_wr_fin_addr_low;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_len_t {
	u32 info_axi_last_wr_fin_len;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t {
	u32 info_wr_fin_user_en;
	u32 info_wr_fin_epid;
	u32 info_wr_fin_vfunc_num;
	u32 info_wr_fin_func_num;
	u32 info_wr_fin_vfunc_active;
};

struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_onload_cnt_t {
	u32 info_axi_last_wr_fin_onload_cnt;
};

struct dpp_dtb_dtb_cfg_cnt_axi_wr_fin_resp_err_t {
	u32 cnt_axi_wr_fin_resp_err;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_smmu0_table_high_t {
	u32 cnt_dtb_wr_smmu0_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_smmu0_table_low_t {
	u32 cnt_dtb_wr_smmu0_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_smmu1_table_high_t {
	u32 cnt_dtb_wr_smmu1_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_smmu1_table_low_t {
	u32 cnt_dtb_wr_smmu1_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_zcam_table_high_t {
	u32 cnt_dtb_wr_zcam_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_zcam_table_low_t {
	u32 cnt_dtb_wr_zcam_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_etcam_table_high_t {
	u32 cnt_dtb_wr_etcam_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_etcam_table_low_t {
	u32 cnt_dtb_wr_etcam_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_hash_table_high_t {
	u32 cnt_dtb_wr_hash_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_wr_hash_table_low_t {
	u32 cnt_dtb_wr_hash_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_smmu0_table_high_t {
	u32 cnt_dtb_rd_smmu0_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_smmu0_table_low_t {
	u32 cnt_dtb_rd_smmu0_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_smmu1_table_high_t {
	u32 cnt_dtb_rd_smmu1_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_smmu1_table_low_t {
	u32 cnt_dtb_rd_smmu1_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_zcam_table_high_t {
	u32 cnt_dtb_rd_zcam_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_zcam_table_low_t {
	u32 cnt_dtb_rd_zcam_table_low;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_etcam_table_high_t {
	u32 cnt_dtb_rd_etcam_table_high;
};

struct dpp_dtb_dtb_cfg_cnt_dtb_rd_etcam_table_low_t {
	u32 cnt_dtb_rd_etcam_table_low;
};

struct dpp_dtb_dtb_cfg_info_wr_ctrl_state_t {
	u32 info_wr_ctrl_state;
};

struct dpp_dtb_dtb_cfg_info_rd_table_state_t {
	u32 info_rd_table_state;
};

struct dpp_dtb_dtb_cfg_info_rd_pd_state_t {
	u32 info_rd_pd_state;
};

struct dpp_dtb_dtb_cfg_info_dump_cmd_state_t {
	u32 info_dump_cmd_state;
};

struct dpp_dtb_dtb_cfg_info_wr_ddr_state_t {
	u32 info_wr_ddr_state;
};

struct dpp_dtb_dtb_cfg_cfg_dtb_debug_info_clr_t {
	u32 cfg_dtb_debug_info_clr;
};

struct dpp_dtb_ddos_cfg_ddos_stat_dump_thrd_0_15_t {
	u32 cfg_ddos_stat_dump_thrd;
};

struct dpp_dtb_ddos_cfg_ddos_stat_dump_thrd_comp_en_t {
	u32 cfg_ddos_stat_dump_thrd_comp_en;
};

struct dpp_dtb_ddos_cfg_ddos_dump_stat_num_t {
	u32 cfg_ddos_dump_stat_num;
};

struct dpp_dtb_ddos_cfg_ddos_even_hash_table_baddr_t {
	u32 cfg_ddos_even_hash_table_baddr;
};

struct dpp_dtb_ddos_cfg_ddos_odd_hash_table_baddr_t {
	u32 cfg_ddos_odd_hash_table_baddr;
};

struct dpp_dtb_ddos_cfg_ddos_stat_index_offset_t {
	u32 cfg_ddos_stat_index_offset;
};

struct dpp_dtb_ddos_cfg_ddos_ns_flag_cnt_t {
	u32 cfg_ddos_ns_flag_cnt;
};

struct dpp_dtb_ddos_cfg_ddos_even_stat_table_baddr_t {
	u32 cfg_ddos_even_stat_table_baddr;
};

struct dpp_dtb_ddos_cfg_ddos_odd_stat_table_baddr_t {
	u32 cfg_ddos_odd_stat_table_baddr;
};

struct dpp_dtb_ddos_cfg_ddos_even_stat_dump_daddr_h_t {
	u32 cfg_ddos_even_stat_dump_daddr_h;
};

struct dpp_dtb_ddos_cfg_ddos_even_stat_dump_daddr_l_t {
	u32 cfg_ddos_even_stat_dump_daddr_l;
};

struct dpp_dtb_ddos_cfg_ddos_odd_stat_dump_daddr_h_t {
	u32 cfg_ddos_odd_stat_dump_daddr_h;
};

struct dpp_dtb_ddos_cfg_ddos_odd_stat_dump_daddr_l_t {
	u32 cfg_ddos_odd_stat_dump_daddr_l;
};

struct dpp_dtb_ddos_cfg_ddos_work_mode_enable_t {
	u32 cfg_ddos_mode_work_enable;
};

struct dpp_dtb_ddos_cfg_ddos_stat_table_len_t {
	u32 cfg_ddos_stat_table_len;
};

struct dpp_dtb_ddos_cfg_ddos_hash_table_len_t {
	u32 cfg_ddos_hash_table_len;
};

struct dpp_dtb_dtb_ram_traf_ctrl_ram0_0_255_t {
	u32 traf_ctrl_ram0_0_255;
};

struct dpp_dtb_dtb_ram_traf_ctrl_ram1_0_255_t {
	u32 traf_ctrl_ram1_0_255;
};

struct dpp_dtb_dtb_ram_traf_ctrl_ram2_0_255_t {
	u32 traf_ctrl_ram2_0_255;
};

struct dpp_dtb_dtb_ram_traf_ctrl_ram3_0_255_t {
	u32 traf_ctrl_ram3_0_255;
};

struct dpp_dtb_dtb_ram_traf_ctrl_ram4_0_255_t {
	u32 traf_ctrl_ram4_0_255;
};

struct dpp_dtb_dtb_ram_traf_ctrl_ram5_0_63_t {
	u32 traf_ctrl_ram5_0_63;
};

struct dpp_dtb_dtb_ram_dump_pd_ram_0_2047_t {
	u32 dump_pd_ram_0_2047;
};

struct dpp_dtb_dtb_ram_rd_ctrl_ram_0_4095_t {
	u32 rd_ctrl_ram_0_4095;
};

struct dpp_dtb_dtb_ram_rd_table_ram_0_8191_t {
	u32 rd_table_ram_0_8191;
};

struct dpp_dtb_dtb_ram_dtb_cmd_man_ram_0_16383_t {
	u32 dtb_cmd_man_ram_0_16383;
};

#endif
