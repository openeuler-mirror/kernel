/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_SMMU1_REG_H_
#define _DPP_SMMU1_REG_H_
struct dpp_se_smmu1_ddr_wdat0_t {
	u32 ddr_wdat0;
};

struct dpp_se_smmu1_dir_arbi_ser_rpful_t {
	u32 dir_arbi_ser_rpful;
};

struct dpp_se_smmu1_cfg_wr_arbi_pful2_t {
	u32 hash_wr_pful;
	u32 dir_wr_pful;
};

struct dpp_se_smmu1_etm_tbl_cfg_t {
	u32 etm_baddr;
};

struct dpp_se_smmu1_cfg_cash_addr_pful_t {
	u32 cfg_cash_addr_pful;
};

struct dpp_se_smmu1_ctrl_rfifo_cfg_t {
	u32 brst_fwft_fifo_prog_empty_assert;
	u32 brst_fwft_fifo_prog_empty_negate;
	u32 brst_fwft_fifo_prog_full_assert;
	u32 brst_fwft_fifo_prog_full_negate;
};

struct dpp_se_smmu1_cache_req_fifo_cfg_t {
	u32 srch_fifo_pfull_assert;
	u32 srch_fifo_pfull_negate;
};

struct dpp_se_smmu1_ddr_wdat1_t {
	u32 ddr_wdat1;
};

struct dpp_se_smmu1_ddr_wdat2_t {
	u32 ddr_wdat2;
};

struct dpp_se_smmu1_ddr_wdat3_t {
	u32 ddr_wdat3;
};

struct dpp_se_smmu1_ddr_wdat4_t {
	u32 ddr_wdat4;
};

struct dpp_se_smmu1_ddr_wdat5_t {
	u32 ddr_wdat5;
};

struct dpp_se_smmu1_ddr_wdat6_t {
	u32 ddr_wdat6;
};

struct dpp_se_smmu1_ddr_wdat7_t {
	u32 ddr_wdat7;
};

struct dpp_se_smmu1_ddr_wdat8_t {
	u32 ddr_wdat8;
};

struct dpp_se_smmu1_ddr_wdat9_t {
	u32 ddr_wdat9;
};

struct dpp_se_smmu1_ddr_wdat10_t {
	u32 ddr_wdat10;
};

struct dpp_se_smmu1_ddr_wdat11_t {
	u32 ddr_wdat11;
};

struct dpp_se_smmu1_ddr_wdat12_t {
	u32 ddr_wdat12;
};

struct dpp_se_smmu1_ddr_wdat13_t {
	u32 ddr_wdat13;
};

struct dpp_se_smmu1_ddr_wdat14_t {
	u32 ddr_wdat14;
};

struct dpp_se_smmu1_ddr_wdat15_t {
	u32 ddr_wdat15;
};

struct dpp_se_smmu1_cnt_stat_cache_en_t {
	u32 cnt_stat_cache_en;
};

struct dpp_se_smmu1_cnt_stat_cache_clr_t {
	u32 cnt_stat_cache_clr;
};

struct dpp_se_smmu1_cnt_stat_cache_req_63_32_t {
	u32 cnt_stat_cache_req_63_32;
};

struct dpp_se_smmu1_cnt_stat_cache_req_31_0_t {
	u32 cnt_stat_cache_req_31_0;
};

struct dpp_se_smmu1_cnt_stat_cache_hit_63_32_t {
	u32 cnt_stat_cache_hit_63_32;
};

struct dpp_se_smmu1_cnt_stat_cache_hit_31_0_t {
	u32 cnt_stat_cache_hit_31_0;
};

struct dpp_se_smmu1_ddr_cmd0_t {
	u32 ecc_en;
	u32 rw_len;
	u32 baddr;
};

struct dpp_se_smmu1_info_addr_t {
	u32 info_addr;
};

struct dpp_se_smmu1_ddr_cmd1_t {
	u32 rw_flag;
	u32 rw_addr;
};

struct dpp_se_smmu1_clr_start_addr_t {
	u32 clr_start_addr;
};

struct dpp_se_smmu1_clr_end_addr_t {
	u32 clr_end_addr;
};

struct dpp_se_smmu1_clr_tbl_en_t {
	u32 cfg_init_en;
	u32 clr_tbl_en;
};

struct dpp_se_smmu1_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_se_smmu1_init_done_t {
	u32 cache_init_done;
	u32 clr_done;
	u32 init_ok;
};

struct dpp_se_smmu1_cpu_rsp_rd_done_t {
	u32 cpu_rsp_rd_done;
};

struct dpp_se_smmu1_ksch_oam_sp_en_t {
	u32 ksch_oam_sp_en;
};

struct dpp_se_smmu1_cfg_cache_en_t {
	u32 cfg_cache_en;
};

struct dpp_se_smmu1_cache_age_en_t {
	u32 cache_age_en;
};

struct dpp_se_smmu1_cpu_rdat0_t {
	u32 cpu_rdat0;
};

struct dpp_se_smmu1_cpu_rdat1_t {
	u32 cpu_rdat1;
};

struct dpp_se_smmu1_cpu_rdat2_t {
	u32 cpu_rdat2;
};

struct dpp_se_smmu1_cpu_rdat3_t {
	u32 cpu_rdat3;
};

struct dpp_se_smmu1_cpu_rdat4_t {
	u32 cpu_rdat4;
};

struct dpp_se_smmu1_cpu_rdat5_t {
	u32 cpu_rdat5;
};

struct dpp_se_smmu1_cpu_rdat6_t {
	u32 cpu_rdat6;
};

struct dpp_se_smmu1_cpu_rdat7_t {
	u32 cpu_rdat7;
};

struct dpp_se_smmu1_cpu_rdat8_t {
	u32 cpu_rdat8;
};

struct dpp_se_smmu1_cpu_rdat9_t {
	u32 cpu_rdat9;
};

struct dpp_se_smmu1_cpu_rdat10_t {
	u32 cpu_rdat10;
};

struct dpp_se_smmu1_cpu_rdat11_t {
	u32 cpu_rdat11;
};

struct dpp_se_smmu1_cpu_rdat12_t {
	u32 cpu_rdat12;
};

struct dpp_se_smmu1_cpu_rdat13_t {
	u32 cpu_rdat13;
};

struct dpp_se_smmu1_cpu_rdat14_t {
	u32 cpu_rdat14;
};

struct dpp_se_smmu1_cpu_rdat15_t {
	u32 cpu_rdat15;
};

struct dpp_se_smmu1_ctrl_cpu_rd_rdy_t {
	u32 ctrl_cpu_rd_rdy;
};

struct dpp_se_smmu1_cpu_warbi_rdy_cfg_t {
	u32 cpu_warbi_rdy_cfg;
};

struct dpp_se_smmu1_dir_arbi_cpu_rpful_t {
	u32 smmu1_cfg_rpful;
	u32 smmu1_cfg_wpful;
};

struct dpp_se_smmu1_dir_arbi_wpful_t {
	u32 smmu1_ser_wdir_pful;
	u32 smmu1_cfg_wdir_pful;
};

struct dpp_se_smmu1_cfg_wr_arbi_pful0_t {
	u32 arbi_out_pful;
	u32 cpu_wr_pful;
};

struct dpp_se_smmu1_cfg_wr_arbi_pful1_t {
	u32 tm_wr_pful;
	u32 stat_wr_pful;
};

struct dpp_se_smmu1_smmu1_wdone_pful_cfg_t {
	u32 smmu1_wdone_pful_cfg;
};

struct dpp_se_smmu1_stat_rate_cfg_cnt_t {
	u32 stat_rate_cfg_cnt;
};

struct dpp_se_smmu1_ftm_rate_cfg_cnt_t {
	u32 ftm_rate_cfg_cnt;
};

struct dpp_se_smmu1_etm_rate_cfg_cnt_t {
	u32 etm_rate_cfg_cnt;
};

struct dpp_se_smmu1_dir_rate_cfg_cnt_t {
	u32 dir_rate_cfg_cnt;
};

struct dpp_se_smmu1_hash_rate_cfg_cnt_t {
	u32 hash_rate_cfg_cnt;
};

struct dpp_se_smmu1_ftm_tbl_cfg_t {
	u32 ftm_baddr;
};

struct dpp_se_smmu1_lpm_v4_as_tbl_cfg_t {
	u32 lpm_v4_as_rsp_len;
	u32 lpm_v4_as_ecc_en;
	u32 lpm_v4_as_baddr;
};

struct dpp_se_smmu1_lpm_v4_tbl_cfg_t {
	u32 lpm_v4_len;
	u32 lpm_v4_ecc_en;
	u32 lpm_v4_baddr;
};

struct dpp_se_smmu1_lpm_v6_tbl_cfg_t {
	u32 lpm_v6_len;
	u32 lpm_v6_ecc_en;
	u32 lpm_v6_baddr;
};

struct dpp_se_smmu1_lpm_v6_as_tbl_cfg_t {
	u32 lpm_v6_as_rsp_len;
	u32 lpm_v6_as_ecc_en;
	u32 lpm_v6_as_baddr;
};

struct dpp_se_smmu1_dma_tbl_cfg_t {
	u32 dma_baddr;
};

struct dpp_se_smmu1_stat_mode_cfg_t {
	u32 stat_mode;
};

struct dpp_se_smmu1_ctrl_rpar_cpu_pful_t {
	u32 ctrl_rpar_cpu_pful;
};

struct dpp_se_smmu1_cfg_ksch_dir_pful_t {
	u32 cfg_ksch_dir_pful;
};

struct dpp_se_smmu1_cfg_ksch_hash_pful_t {
	u32 cfg_ksch_hash_pful;
};

struct dpp_se_smmu1_cfg_ksch_lpm_pful_t {
	u32 cfg_ksch_lpm_pful;
};

struct dpp_se_smmu1_cfg_ksch_lpm_as_pful_t {
	u32 cfg_ksch_lpm_as_pful;
};

struct dpp_se_smmu1_cfg_ksch_stat_pful_t {
	u32 cfg_ksch_stat_pful;
};

struct dpp_se_smmu1_cfg_ksch_tm_pful_t {
	u32 cfg_ksch_tm_pful;
};

struct dpp_se_smmu1_cfg_ksch_oam_pful_t {
	u32 cfg_ksch_oam_pful;
};

struct dpp_se_smmu1_cfg_ksch_dma_pful_t {
	u32 cfg_ksch_dma_pful;
};

struct dpp_se_smmu1_ctrl_wfifo_cfg_t {
	u32 ctrl_wfifo_cfg;
};

struct dpp_se_smmu1_rsch_hash_ptr_cfg_t {
	u32 rsch_hash_ptr_cfg;
};

struct dpp_se_smmu1_rsch_lpm_ptr_cfg_t {
	u32 rsch_lpm_ptr_cfg;
};

struct dpp_se_smmu1_rsch_lpm_as_ptr_cfg_t {
	u32 rsch_lpm_as_ptr_cfg;
};

struct dpp_se_smmu1_rsch_stat_ptr_cfg_t {
	u32 rsch_stat_ptr_cfg;
};

struct dpp_se_smmu1_rsch_oam_ptr_cfg_t {
	u32 rsch_oam_ptr_cfg;
};

struct dpp_se_smmu1_rschd_fifo_pept_cfg_t {
	u32 rschd_fifo_pept_cfg;
};

struct dpp_se_smmu1_dir_fifo_pful_cfg_t {
	u32 dir_fifo_pful_cfg;
};

struct dpp_se_smmu1_hash_fifo_pful_cfg_t {
	u32 hash_fifo_pful_cfg;
};

struct dpp_se_smmu1_lpm_fifo_pful_cfg_t {
	u32 lpm_fifo_pful_cfg;
};

struct dpp_se_smmu1_lpm_as_fifo_pful_cfg_t {
	u32 lpm_as_fifo_pful_cfg;
};

struct dpp_se_smmu1_stat_fifo_pful_cfg_t {
	u32 stat_fifo_pful_cfg;
};

struct dpp_se_smmu1_ftm_fifo_pful_cfg_t {
	u32 ftm_fifo_pful_cfg;
};

struct dpp_se_smmu1_etm_fifo_pful_cfg_t {
	u32 etm_fifo_pful_cfg;
};

struct dpp_se_smmu1_oam_fifo_pful_cfg_t {
	u32 oam_fifo_pful_cfg;
};

struct dpp_se_smmu1_dma_fifo_pful_cfg_t {
	u32 dma_fifo_pful_cfg;
};

struct dpp_se_smmu1_cache_rsp_rr_fifo_cfg_t {
	u32 rr_pfull_assert0;
	u32 rr_pfull_negate0;
};

struct dpp_se_smmu1_ddr_rsp_rr_fifo_cfg_t {
	u32 rr_pfull_assert1;
	u32 rr_pfull_negate1;
};

struct dpp_se_smmu1_cpu_cahce_fifo_cfg_t {
	u32 smmu1_cahce_fwft_fifo_pfull_assert;
	u32 smmu1_cahce_fwft_fifo_pfull_negate;
};

struct dpp_se_smmu1_cache_rsp_fifo_cfg_t {
	u32 rschd_fifo_pfull_assert;
	u32 rschd_fifo_pfull_negate;
};

struct dpp_se_smmu1_test_state_t {
	u32 test_state;
};

struct dpp_se_smmu1_cache_fifo_ept_t {
	u32 cache_fifo_ept;
};

struct dpp_se_smmu1_rr_fifo_ept_t {
	u32 rr_fifo_ept;
};

struct dpp_se_smmu1_wr_fifo_ept_t {
	u32 dir_arbi_ept;
};

struct dpp_se_smmu1_wdone_fifo_ept_t {
	u32 wdone_fifo_ept;
};

struct dpp_se_smmu1_kschd_fifo_ept0_t {
	u32 kschd_fifo_ept0;
};

struct dpp_se_smmu1_cash_fifo_ept_t {
	u32 cash_fifo_ept;
};

struct dpp_se_smmu1_ctrl_fifo_ept_t {
	u32 ctrl_fifo_ept;
};

struct dpp_se_smmu1_smmu1_rschd_ept3_t {
	u32 rschd_fifo_ept3;
};

struct dpp_se_smmu1_smmu1_rschd_ept2_t {
	u32 rschd_fifo_ept2;
};

struct dpp_se_smmu1_smmu1_rschd_ept1_t {
	u32 rschd_fifo_ept1;
};

struct dpp_se_smmu1_smmu1_rschd_ept0_t {
	u32 rschd_fifo_ept0;
};

struct dpp_se_smmu1_cash0_ecc_err_addr_t {
	u32 cash0_ecc_err_addr;
};

struct dpp_se_smmu1_arbi_cpu_wr_rdy_t {
	u32 arbi_cpu_wr_rdy;
};

struct dpp_se_smmu1_smmu1_int_0_en_t {
	u32 smmu1_int_0_en;
};

struct dpp_se_smmu1_smmu1_int_0_mask_t {
	u32 smmu1_int_0_mask;
};

struct dpp_se_smmu1_smmu1_int_1_en_t {
	u32 smmu1_int_1_en;
};

struct dpp_se_smmu1_smmu1_int_1_mask_t {
	u32 smmu1_int_1_mask;
};

struct dpp_se_smmu1_smmu1_int_2_en_t {
	u32 smmu1_int_2_en;
};

struct dpp_se_smmu1_smmu1_int_2_mask_t {
	u32 smmu1_int_2_mask;
};

struct dpp_se_smmu1_smmu1_int_3_en_t {
	u32 smmu1_int_3_en;
};

struct dpp_se_smmu1_smmu1_int_3_mask_t {
	u32 smmu1_int_3_mask;
};

struct dpp_se_smmu1_smmu1_int_0_status_t {
	u32 smmu1_int_0_status;
};

struct dpp_se_smmu1_smmu1_int_1_status_t {
	u32 smmu1_int_1_status;
};

struct dpp_se_smmu1_smmu1_int_2_status_t {
	u32 smmu1_int_2_status;
};

struct dpp_se_smmu1_smmu1_int_3_status_t {
	u32 smmu1_int_3_status;
};

struct dpp_se_smmu1_smmu1_int_status_t {
	u32 smmu1_int_status;
};

struct dpp_se_smmu1_ctrl_to_cash7_0_fc_cnt_t {
	u32 ctrl_to_cash7_0_fc_cnt;
};

struct dpp_se_smmu1_cash7_0_to_ctrl_req_cnt_t {
	u32 cash7_0_to_ctrl_req_cnt;
};

struct dpp_se_smmu1_rschd_to_cache7_fc_cnt_t {
	u32 rschd_to_cache7_fc_cnt;
};

struct dpp_se_smmu1_cash7_to_cache_rsp_cnt_t {
	u32 cash7_to_cache_rsp_cnt;
};

struct dpp_se_smmu1_cash7_to_ctrl_fc_cnt_t {
	u32 cash7_to_ctrl_fc_cnt;
};

struct dpp_se_smmu1_ctrl_to_cash7_0_rsp_cnt_t {
	u32 ctrl_to_cash7_0_rsp_cnt;
};

struct dpp_se_smmu1_kschd_to_cache7_0_req_cnt_t {
	u32 kschd_to_cache7_0_req_cnt;
};

struct dpp_se_smmu1_cache7_0_to_kschd_fc_cnt_t {
	u32 cache7_0_to_kschd_fc_cnt;
};

struct dpp_se_smmu1_dma_to_smmu1_rd_req_cnt_t {
	u32 dma_to_smmu1_rd_req_cnt;
};

struct dpp_se_smmu1_oam_to_kschd_req_cnt_t {
	u32 oam_to_kschd_req_cnt;
};

struct dpp_se_smmu1_oam_rr_state_rsp_cnt_t {
	u32 oam_rr_state_rsp_cnt;
};

struct dpp_se_smmu1_oam_clash_info_cnt_t {
	u32 oam_clash_info_cnt;
};

struct dpp_se_smmu1_oam_to_rr_req_cnt_t {
	u32 oam_to_rr_req_cnt;
};

struct dpp_se_smmu1_lpm_as_to_kschd_req_cnt_t {
	u32 lpm_as_to_kschd_req_cnt;
};

struct dpp_se_smmu1_lpm_as_rr_state_rsp_cnt_t {
	u32 lpm_as_rr_state_rsp_cnt;
};

struct dpp_se_smmu1_lpm_as_clash_info_cnt_t {
	u32 lpm_as_clash_info_cnt;
};

struct dpp_se_smmu1_lpm_as_to_rr_req_cnt_t {
	u32 lpm_as_to_rr_req_cnt;
};

struct dpp_se_smmu1_lpm_to_kschd_req_cnt_t {
	u32 lpm_to_kschd_req_cnt;
};

struct dpp_se_smmu1_lpm_rr_state_rsp_cnt_t {
	u32 lpm_rr_state_rsp_cnt;
};

struct dpp_se_smmu1_lpm_clash_info_cnt_t {
	u32 lpm_clash_info_cnt;
};

struct dpp_se_smmu1_lpm_to_rr_req_cnt_t {
	u32 lpm_to_rr_req_cnt;
};

struct dpp_se_smmu1_hash3_0_to_kschd_req_cnt_t {
	u32 hash3_0_to_kschd_req_cnt;
};

struct dpp_se_smmu1_hash3_0_rr_state_rsp_cnt_t {
	u32 hash3_0_rr_state_rsp_cnt;
};

struct dpp_se_smmu1_hash3_0_clash_info_cnt_t {
	u32 hash3_0_clash_info_cnt;
};

struct dpp_se_smmu1_hash3_0_to_rr_req_cnt_t {
	u32 hash3_0_to_rr_req_cnt;
};

struct dpp_se_smmu1_dir3_0_to_kschd_req_cnt_t {
	u32 dir3_0_to_kschd_req_cnt;
};

struct dpp_se_smmu1_dir3_0_clash_info_cnt_t {
	u32 dir3_0_clash_info_cnt;
};

struct dpp_se_smmu1_dir_tbl_wr_req_cnt_t {
	u32 dir_tbl_wr_req_cnt;
};

struct dpp_se_smmu1_warbi_to_dir_tbl_warbi_fc_cnt_t {
	u32 warbi_to_dir_tbl_warbi_fc_cnt;
};

struct dpp_se_smmu1_dir3_0_to_bank_rr_req_cnt_t {
	u32 dir3_0_to_bank_rr_req_cnt;
};

struct dpp_se_smmu1_kschd_to_dir3_0_fc_cnt_t {
	u32 kschd_to_dir3_0_fc_cnt;
};

struct dpp_se_smmu1_dir3_0_rr_state_rsp_cnt_t {
	u32 dir3_0_rr_state_rsp_cnt;
};

struct dpp_se_smmu1_wr_done_to_warbi_fc_cnt_t {
	u32 wr_done_to_warbi_fc_cnt;
};

struct dpp_se_smmu1_wr_done_ptr_req_cnt_t {
	u32 wr_done_ptr_req_cnt;
};

struct dpp_se_smmu1_ctrl7_0_to_warbi_fc_cnt_t {
	u32 ctrl7_0_to_warbi_fc_cnt;
};

struct dpp_se_smmu1_warbi_to_ctrl7_0_wr_req_cnt_t {
	u32 warbi_to_ctrl7_0_wr_req_cnt;
};

struct dpp_se_smmu1_warbi_to_cash7_0_wr_req_cnt_t {
	u32 warbi_to_cash7_0_wr_req_cnt;
};

struct dpp_se_smmu1_warbi_to_cpu_wr_fc_cnt_t {
	u32 warbi_to_cpu_wr_fc_cnt;
};

struct dpp_se_smmu1_cpu_wr_req_cnt_t {
	u32 cpu_wr_req_cnt;
};

struct dpp_se_smmu1_ctrl7_0_to_cpu_rd_rsp_cnt_t {
	u32 ctrl7_0_to_cpu_rd_rsp_cnt;
};

struct dpp_se_smmu1_cpu_to_ctrl7_0_rd_req_cnt_t {
	u32 cpu_to_ctrl7_0_rd_req_cnt;
};

struct dpp_se_smmu1_cpu_rd_dir_tbl_rsp_cnt_t {
	u32 cpu_rd_dir_tbl_rsp_cnt;
};

struct dpp_se_smmu1_cpu_to_dir_tbl_rd_wr_req_cnt_t {
	u32 cpu_to_dir_tbl_rd_wr_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_mmu_7_0_rsp_fc_cnt_t {
	u32 smmu1_to_mmu_7_0_rsp_fc_cnt;
};

struct dpp_se_smmu1_mmu_7_0_to_smmu1_rd_rsp_cnt_t {
	u32 mmu_7_0_to_smmu1_rd_rsp_cnt;
};

struct dpp_se_smmu1_mmu_7_0_to_smmu1_rd_fc_cnt_t {
	u32 mmu_7_0_to_smmu1_rd_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_mmu_7_rd_req_cnt_t {
	u32 smmu1_to_mmu_7_rd_req_cnt;
};

struct dpp_se_smmu1_mmu_7_to_smmu1_wr_fc_cnt_t {
	u32 mmu_7_to_smmu1_wr_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_mmu_7_0_wr_req_cnt_t {
	u32 smmu1_to_mmu_7_0_wr_req_cnt;
};

struct dpp_se_smmu1_se_to_smmu1_wr_rsp_fc_cnt_t {
	u32 se_to_smmu1_wr_rsp_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_se_wr_rsp_cnt_t {
	u32 smmu1_to_se_wr_rsp_cnt;
};

struct dpp_se_smmu1_ddr7_0_wr_rsp_cnt_t {
	u32 ddr7_0_wr_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_as_fc_cnt_t {
	u32 smmu1_to_as_fc_cnt;
};

struct dpp_se_smmu1_as_to_smmu1_wr_req_cnt_t {
	u32 as_to_smmu1_wr_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_se_parser_fc_cnt_t {
	u32 smmu1_to_se_parser_fc_cnt;
};

struct dpp_se_smmu1_se_parser_to_smmu1_req_cnt_t {
	u32 se_parser_to_smmu1_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_etm_wr_fc_cnt_t {
	u32 smmu1_to_etm_wr_fc_cnt;
};

struct dpp_se_smmu1_etm_wr_req_cnt_t {
	u32 etm_wr_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_ftm_wr_fc_cnt_t {
	u32 smmu1_to_ftm_wr_fc_cnt;
};

struct dpp_se_smmu1_ftm_wr_req_cnt_t {
	u32 ftm_wr_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_state_wr_fc_cnt_t {
	u32 smmu1_to_state_wr_fc_cnt;
};

struct dpp_se_smmu1_state_wr_req_cnt_t {
	u32 state_wr_req_cnt;
};

struct dpp_se_smmu1_se_to_dma_rsp_cnt_t {
	u32 se_to_dma_rsp_cnt;
};

struct dpp_se_smmu1_se_to_dma_fc_cnt_t {
	u32 se_to_dma_fc_cnt;
};

struct dpp_se_smmu1_oam_to_smmu1_fc_cnt_t {
	u32 oam_to_smmu1_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_oam_rsp_cnt_t {
	u32 smmu1_to_oam_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_oam_fc_cnt_t {
	u32 smmu1_to_oam_fc_cnt;
};

struct dpp_se_smmu1_oam_to_smmu1_req_cnt_t {
	u32 oam_to_smmu1_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_etm_rsp_cnt_t {
	u32 smmu1_to_etm_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_ftm_rsp_cnt_t {
	u32 smmu1_to_ftm_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_etm_fc_cnt_t {
	u32 smmu1_to_etm_fc_cnt;
};

struct dpp_se_smmu1_etm_to_smmu1_req_cnt_t {
	u32 etm_to_smmu1_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_ftm_fc_cnt_t {
	u32 smmu1_to_ftm_fc_cnt;
};

struct dpp_se_smmu1_ftm_to_smmu1_req_cnt_t {
	u32 ftm_to_smmu1_req_cnt;
};

struct dpp_se_smmu1_smmu1_to_stat_rsp_cnt_t {
	u32 smmu1_to_stat_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_stat_fc_cnt_t {
	u32 smmu1_to_stat_fc_cnt;
};

struct dpp_se_smmu1_stat_to_smmu1_req_cnt_t {
	u32 stat_to_smmu1_req_cnt;
};

struct dpp_se_smmu1_lpm_as_to_smmu1_fc_cnt_t {
	u32 lpm_as_to_smmu1_fc_cnt;
};

struct dpp_se_smmu1_lpm_to_smmu1_fc_cnt_t {
	u32 lpm_to_smmu1_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_lpm_as_rsp_cnt_t {
	u32 smmu1_to_lpm_as_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_lpm_rsp_cnt_t {
	u32 smmu1_to_lpm_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_lpm_as_fc_cnt_t {
	u32 smmu1_to_lpm_as_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_lpm_fc_cnt_t {
	u32 smmu1_to_lpm_fc_cnt;
};

struct dpp_se_smmu1_lpm_as_to_smmu1_req_cnt_t {
	u32 lpm_as_to_smmu1_req_cnt;
};

struct dpp_se_smmu1_lpm_to_smmu1_req_cnt_t {
	u32 lpm_to_smmu1_req_cnt;
};

struct dpp_se_smmu1_hash3_0_to_smmu1_fc_cnt_t {
	u32 hash3_0_to_smmu1_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_hash3_0_rsp_cnt_t {
	u32 smmu1_to_hash3_0_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_hash3_0_fc_cnt_t {
	u32 smmu1_to_hash3_0_fc_cnt;
};

struct dpp_se_smmu1_hash3_0_to_smmu1_cnt_t {
	u32 hash3_0_to_smmu1_cnt;
};

struct dpp_se_smmu1_se_to_smmu1_dir3_0_rsp_fc_cnt_t {
	u32 se_to_smmu1_dir3_0_rsp_fc_cnt;
};

struct dpp_se_smmu1_smmu1_to_se_dir3_0_rsp_cnt_t {
	u32 smmu1_to_se_dir3_0_rsp_cnt;
};

struct dpp_se_smmu1_smmu1_to_se_dir3_0_fc_cnt_t {
	u32 smmu1_to_se_dir3_0_fc_cnt;
};

struct dpp_se_smmu1_se_to_smmu1_dir3_0_cnt_t {
	u32 se_to_smmu1_dir3_0_cnt;
};

struct dpp_se_smmu1_cache7_0_to_rschd_rsp_cnt_t {
	u32 cache7_0_to_rschd_rsp_cnt;
};

struct dpp_se_cmmu_ddr_rw_addr_t {
	u32 ddr_wr;
};

struct dpp_se_cmmu_ddr_rw_mode_t {
	u32 ddr_rw_flag;
	u32 ddr_rw_mode;
};

struct dpp_se_cmmu_cp_cmd_t {
	u32 stat_tbl_baddr;
};

struct dpp_se_cmmu_cpu_ind_rd_done_t {
	u32 cpu_ind_rd_done;
};

struct dpp_se_cmmu_cpu_ind_rdat0_t {
	u32 cpu_ind_rdat0;
};

struct dpp_se_cmmu_cpu_ind_rdat1_t {
	u32 cpu_ind_rdat1;
};

struct dpp_se_cmmu_cpu_ind_rdat2_t {
	u32 cpu_ind_rdat2;
};

struct dpp_se_cmmu_cpu_ind_rdat3_t {
	u32 cpu_ind_rdat3;
};

struct dpp_se_cmmu_cpu_ddr_fifo_almful_t {
	u32 cpu_ddr_fifo_almful;
};

struct dpp_se_cmmu_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_se_cmmu_cmmu_pful_cfg_t {
	u32 alu_cmd_pful_negate;
	u32 alu_cmd_pful_assert;
};

struct dpp_se_cmmu_cmmu_stat_pful_cfg_t {
	u32 cmmu_stat_pful_negate;
	u32 cmmu_stat_pful_assert;
};

struct dpp_se_cmmu_stat_overflow_mode_t {
	u32 stat_overflow_mode;
};

struct dpp_se_cmmu_cmmu_cp_fifo_pful_t {
	u32 cmmu_cp_fifo_pful;
};

struct dpp_se_cmmu_ddr_wr_dat0_t {
	u32 ddr_wr_dat0;
};

struct dpp_se_cmmu_ddr_wr_dat1_t {
	u32 ddr_wr_dat1;
};

struct dpp_se_cmmu_cmmu_int_unmask_flag_t {
	u32 cmmu_int_unmask_flag;
};

struct dpp_se_cmmu_cmmu_int_en_t {
	u32 cmmu_int_en12;
	u32 cmmu_int_en11;
	u32 cmmu_int_en10;
	u32 cmmu_int_en9;
	u32 cmmu_int_en8;
	u32 cmmu_int_en7;
	u32 cmmu_int_en6;
	u32 cmmu_int_en5;
	u32 cmmu_int_en4;
	u32 cmmu_int_en3;
	u32 cmmu_int_en2;
	u32 cmmu_int_en1;
	u32 cmmu_int_en0;
};

struct dpp_se_cmmu_cmmu_int_mask_t {
	u32 cmmu_int_mask12;
	u32 cmmu_int_mask11;
	u32 cmmu_int_mask10;
	u32 cmmu_int_mask9;
	u32 cmmu_int_mask8;
	u32 cmmu_int_mask7;
	u32 cmmu_int_mask6;
	u32 cmmu_int_mask5;
	u32 cmmu_int_mask4;
	u32 cmmu_int_mask3;
	u32 cmmu_int_mask2;
	u32 cmmu_int_mask1;
	u32 cmmu_int_mask0;
};

struct dpp_se_cmmu_cmmu_int_status_t {
	u32 cmmu_int_status12;
	u32 cmmu_int_status11;
	u32 cmmu_int_status10;
	u32 cmmu_int_status9;
	u32 cmmu_int_status8;
	u32 cmmu_int_status7;
	u32 cmmu_int_status6;
	u32 cmmu_int_status5;
	u32 cmmu_int_status4;
	u32 cmmu_int_status3;
	u32 cmmu_int_status2;
	u32 cmmu_int_status1;
	u32 cmmu_int_status0;
};

struct dpp_se_cmmu_stat_cmmu_req_cnt_t {
	u32 stat_cmmu_req_cnt;
};

struct dpp_se_cmmu_cmmu_fc0_cnt_t {
	u32 cmmu_stat_rdy;
};

struct dpp_se_cmmu_cmmu_fc1_cnt_t {
	u32 smmu1_cmmu_wr_rdy;
};

struct dpp_se_cmmu_cmmu_fc2_cnt_t {
	u32 smmu1_cmmu_rd_rdy;
};

#endif
