/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_SE_REG_H_
#define _DPP_SE_REG_H_
struct dpp_se_alg_init_ok_t {
	u32 init_ok;
};

struct dpp_se_alg_cpu_rd_rdy_t {
	u32 cpu_rd_rdy;
};

struct dpp_se_alg_cpu_rd_data_tmp0_t {
	u32 cpu_rd_data_tmp0;
};

struct dpp_se_alg_cpu_rd_data_tmp1_t {
	u32 cpu_rd_data_tmp1;
};

struct dpp_se_alg_cpu_rd_data_tmp2_t {
	u32 cpu_rd_data_tmp2;
};

struct dpp_se_alg_cpu_rd_data_tmp3_t {
	u32 cpu_rd_data_tmp3;
};

struct dpp_se_alg_cpu_rd_data_tmp4_t {
	u32 cpu_rd_data_tmp4;
};

struct dpp_se_alg_cpu_rd_data_tmp5_t {
	u32 cpu_rd_data_tmp5;
};

struct dpp_se_alg_cpu_rd_data_tmp6_t {
	u32 cpu_rd_data_tmp6;
};

struct dpp_se_alg_cpu_rd_data_tmp7_t {
	u32 cpu_rd_data_tmp7;
};

struct dpp_se_alg_cpu_rd_data_tmp8_t {
	u32 cpu_rd_data_tmp8;
};

struct dpp_se_alg_cpu_rd_data_tmp9_t {
	u32 cpu_rd_data_tmp9;
};

struct dpp_se_alg_cpu_rd_data_tmp10_t {
	u32 cpu_rd_data_tmp10;
};

struct dpp_se_alg_cpu_rd_data_tmp11_t {
	u32 cpu_rd_data_tmp11;
};

struct dpp_se_alg_cpu_rd_data_tmp12_t {
	u32 cpu_rd_data_tmp12;
};

struct dpp_se_alg_cpu_rd_data_tmp13_t {
	u32 cpu_rd_data_tmp13;
};

struct dpp_se_alg_cpu_rd_data_tmp14_t {
	u32 cpu_rd_data_tmp14;
};

struct dpp_se_alg_cpu_rd_data_tmp15_t {
	u32 cpu_rd_data_tmp15;
};

struct dpp_se_alg_lpm_v4_config_rgt_t {
	u32 lpm_v4_shift_sel;
	u32 lpm_v4_sram_cmp_flag;
	u32 lpm_v4_ddr3_addr_sel;
};

struct dpp_se_alg_lpm_v6_config_rgt_t {
	u32 lpm_v6_shift_sel;
	u32 lpm_v6_sram_cmp_flag;
	u32 lpm_v6_ddr3_addr_sel;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u0_pfull_ast_t {
	u32 lpm_ext_rsp_fifo_u0_pfull_ast;
};

struct dpp_se_as_hash_age_pat_cfg_t {
	u32 hash_age_pat_cfg;
};

struct dpp_se_as_learn_rdy_cfg_t {
	u32 learn_rdy_cfg;
};

struct dpp_se_kschd_kschd_as_pful_cfg_t {
	u32 kschd_as_pful_cfg;
};

struct dpp_se_kschd_kschd_dir_pful_cfg_t {
	u32 kschd_dir_pful_cfg;
};

struct dpp_se_kschd_kschd_as_ept_cfg_t {
	u32 kschd_as_ept_cfg;
};

struct dpp_se_kschd_cpu_arbi_pful_cfg_t {
	u32 cpu_arbi_pful_cfg;
};

struct dpp_se_kschd_kschd_pbu_pful_cfg_t {
	u32 kschd_pbu_pful_cfg;
};

struct dpp_se_rschd_rschd_dir_pful_cfg_t {
	u32 rschd_dir_pful_cfg;
};

struct dpp_se_rschd_rschd_dir_ept_cfg_t {
	u32 rschd_dir_ept_cfg;
};

struct dpp_se_cfg_ppu_soft_rst_t {
	u32 ppu_soft_rst;
};

struct dpp_se_cfg_ept_flag_t {
	u32 ept_flag;
};

struct dpp_se_cfg_ddr_key_lk0_3_t {
	u32 ddr_key_lk0_3;
};

struct dpp_se_cfg_ddr_key_lk0_2_t {
	u32 ddr_key_lk0_2;
};

struct dpp_se_cfg_ddr_key_lk0_1_t {
	u32 ddr_key_lk0_1;
};

struct dpp_se_cfg_ddr_key_lk0_0_t {
	u32 ddr_key_lk0_0;
};

struct dpp_se_cfg_ddr_key_lk1_3_t {
	u32 ddr_key_lk1_3;
};

struct dpp_se_cfg_ddr_key_lk1_2_t {
	u32 ddr_key_lk1_2;
};

struct dpp_se_cfg_ddr_key_lk1_1_t {
	u32 ddr_key_lk1_1;
};

struct dpp_se_cfg_ddr_key_lk1_0_t {
	u32 ddr_key_lk1_0;
};

struct dpp_se_cfg_hash_key_lk0_18_t {
	u32 hash_key_lk0_18;
};

struct dpp_se_cfg_hash_key_lk0_17_t {
	u32 hash_key_lk0_17;
};

struct dpp_se_cfg_hash_key_lk0_16_t {
	u32 hash_key_lk0_16;
};

struct dpp_se_cfg_hash_key_lk0_15_t {
	u32 hash_key_lk0_15;
};

struct dpp_se_cfg_hash_key_lk0_14_t {
	u32 hash_key_lk0_14;
};

struct dpp_se_cfg_hash_key_lk0_13_t {
	u32 hash_key_lk0_13;
};

struct dpp_se_cfg_hash_key_lk0_12_t {
	u32 hash_key_lk0_12;
};

struct dpp_se_cfg_hash_key_lk0_11_t {
	u32 hash_key_lk0_11;
};

struct dpp_se_cfg_hash_key_lk0_10_t {
	u32 hash_key_lk0_10;
};

struct dpp_se_cfg_hash_key_lk0_9_t {
	u32 hash_key_lk0_9;
};

struct dpp_se_cfg_hash_key_lk0_8_t {
	u32 hash_key_lk0_8;
};

struct dpp_se_cfg_hash_key_lk0_7_t {
	u32 hash_key_lk0_7;
};

struct dpp_se_cfg_hash_key_lk0_6_t {
	u32 hash_key_lk0_6;
};

struct dpp_se_cfg_hash_key_lk0_5_t {
	u32 hash_key_lk0_5;
};

struct dpp_se_cfg_hash_key_lk0_4_t {
	u32 hash_key_lk0_4;
};

struct dpp_se_cfg_hash_key_lk0_3_t {
	u32 hash_key_lk0_3;
};

struct dpp_se_cfg_hash_key_lk0_2_t {
	u32 hash_key_lk0_2;
};

struct dpp_se_cfg_hash_key_lk0_1_t {
	u32 hash_key_lk0_1;
};

struct dpp_se_cfg_hash_key_lk0_0_t {
	u32 hash_key_lk0_0;
};

struct dpp_se_cfg_hash_key_lk1_18_t {
	u32 hash_key_lk1_18;
};

struct dpp_se_cfg_hash_key_lk1_17_t {
	u32 hash_key_lk1_17;
};

struct dpp_se_cfg_hash_key_lk1_16_t {
	u32 hash_key_lk1_16;
};

struct dpp_se_cfg_hash_key_lk1_15_t {
	u32 hash_key_lk1_15;
};

struct dpp_se_cfg_hash_key_lk1_14_t {
	u32 hash_key_lk1_14;
};

struct dpp_se_cfg_hash_key_lk1_13_t {
	u32 hash_key_lk1_13;
};

struct dpp_se_cfg_hash_key_lk1_12_t {
	u32 hash_key_lk1_12;
};

struct dpp_se_cfg_hash_key_lk1_11_t {
	u32 hash_key_lk1_11;
};

struct dpp_se_cfg_hash_key_lk1_10_t {
	u32 hash_key_lk1_10;
};

struct dpp_se_cfg_hash_key_lk1_9_t {
	u32 hash_key_lk1_9;
};

struct dpp_se_cfg_hash_key_lk1_8_t {
	u32 hash_key_lk1_8;
};

struct dpp_se_cfg_hash_key_lk1_7_t {
	u32 hash_key_lk1_7;
};

struct dpp_se_cfg_hash_key_lk1_6_t {
	u32 hash_key_lk1_6;
};

struct dpp_se_cfg_hash_key_lk1_5_t {
	u32 hash_key_lk1_5;
};

struct dpp_se_cfg_hash_key_lk1_4_t {
	u32 hash_key_lk1_4;
};

struct dpp_se_cfg_hash_key_lk1_3_t {
	u32 hash_key_lk1_3;
};

struct dpp_se_cfg_hash_key_lk1_2_t {
	u32 hash_key_lk1_2;
};

struct dpp_se_cfg_hash_key_lk1_1_t {
	u32 hash_key_lk1_1;
};

struct dpp_se_cfg_hash_key_lk1_0_t {
	u32 hash_key_lk1_0;
};

struct dpp_se_cfg_hash_key_lk2_18_t {
	u32 hash_key_lk2_18;
};

struct dpp_se_cfg_hash_key_lk2_17_t {
	u32 hash_key_lk2_17;
};

struct dpp_se_cfg_hash_key_lk2_16_t {
	u32 hash_key_lk2_16;
};

struct dpp_se_cfg_hash_key_lk2_15_t {
	u32 hash_key_lk2_15;
};

struct dpp_se_cfg_hash_key_lk2_14_t {
	u32 hash_key_lk2_14;
};

struct dpp_se_cfg_hash_key_lk2_13_t {
	u32 hash_key_lk2_13;
};

struct dpp_se_cfg_hash_key_lk2_12_t {
	u32 hash_key_lk2_12;
};

struct dpp_se_cfg_hash_key_lk2_11_t {
	u32 hash_key_lk2_11;
};

struct dpp_se_cfg_hash_key_lk2_10_t {
	u32 hash_key_lk2_10;
};

struct dpp_se_cfg_hash_key_lk2_9_t {
	u32 hash_key_lk2_9;
};

struct dpp_se_cfg_hash_key_lk2_8_t {
	u32 hash_key_lk2_8;
};

struct dpp_se_cfg_hash_key_lk2_7_t {
	u32 hash_key_lk2_7;
};

struct dpp_se_cfg_hash_key_lk2_6_t {
	u32 hash_key_lk2_6;
};

struct dpp_se_cfg_hash_key_lk2_5_t {
	u32 hash_key_lk2_5;
};

struct dpp_se_cfg_hash_key_lk2_4_t {
	u32 hash_key_lk2_4;
};

struct dpp_se_cfg_hash_key_lk2_3_t {
	u32 hash_key_lk2_3;
};

struct dpp_se_cfg_hash_key_lk2_2_t {
	u32 hash_key_lk2_2;
};

struct dpp_se_cfg_hash_key_lk2_1_t {
	u32 hash_key_lk2_1;
};

struct dpp_se_cfg_hash_key_lk2_0_t {
	u32 hash_key_lk2_0;
};

struct dpp_se_cfg_hash_key_lk3_18_t {
	u32 hash_key_lk3_18;
};

struct dpp_se_cfg_hash_key_lk3_17_t {
	u32 hash_key_lk3_17;
};

struct dpp_se_cfg_hash_key_lk3_16_t {
	u32 hash_key_lk3_16;
};

struct dpp_se_cfg_hash_key_lk3_15_t {
	u32 hash_key_lk3_15;
};

struct dpp_se_cfg_hash_key_lk3_14_t {
	u32 hash_key_lk3_14;
};

struct dpp_se_cfg_hash_key_lk3_13_t {
	u32 hash_key_lk3_13;
};

struct dpp_se_cfg_hash_key_lk3_12_t {
	u32 hash_key_lk3_12;
};

struct dpp_se_cfg_hash_key_lk3_11_t {
	u32 hash_key_lk3_11;
};

struct dpp_se_cfg_hash_key_lk3_10_t {
	u32 hash_key_lk3_10;
};

struct dpp_se_cfg_hash_key_lk3_9_t {
	u32 hash_key_lk3_9;
};

struct dpp_se_cfg_hash_key_lk3_8_t {
	u32 hash_key_lk3_8;
};

struct dpp_se_cfg_hash_key_lk3_7_t {
	u32 hash_key_lk3_7;
};

struct dpp_se_cfg_hash_key_lk3_6_t {
	u32 hash_key_lk3_6;
};

struct dpp_se_cfg_hash_key_lk3_5_t {
	u32 hash_key_lk3_5;
};

struct dpp_se_cfg_hash_key_lk3_4_t {
	u32 hash_key_lk3_4;
};

struct dpp_se_cfg_hash_key_lk3_3_t {
	u32 hash_key_lk3_3;
};

struct dpp_se_cfg_hash_key_lk3_2_t {
	u32 hash_key_lk3_2;
};

struct dpp_se_cfg_hash_key_lk3_1_t {
	u32 hash_key_lk3_1;
};

struct dpp_se_cfg_hash_key_lk3_0_t {
	u32 hash_key_lk3_0;
};

struct dpp_se_cfg_lpm_key_lk0_6_t {
	u32 lpm_key_lk0_6;
};

struct dpp_se_cfg_lpm_key_lk0_5_t {
	u32 lpm_key_lk0_5;
};

struct dpp_se_cfg_lpm_key_lk0_4_t {
	u32 lpm_key_lk0_4;
};

struct dpp_se_cfg_lpm_key_lk0_3_t {
	u32 lpm_key_lk0_3;
};

struct dpp_se_cfg_lpm_key_lk0_2_t {
	u32 lpm_key_lk0_2;
};

struct dpp_se_cfg_lpm_key_lk0_1_t {
	u32 lpm_key_lk0_1;
};

struct dpp_se_cfg_lpm_key_lk0_0_t {
	u32 lpm_key_lk0_0;
};

struct dpp_se_cfg_lpm_key_lk1_6_t {
	u32 lpm_key_lk1_6;
};

struct dpp_se_cfg_lpm_key_lk1_5_t {
	u32 lpm_key_lk1_5;
};

struct dpp_se_cfg_lpm_key_lk1_4_t {
	u32 lpm_key_lk1_4;
};

struct dpp_se_cfg_lpm_key_lk1_3_t {
	u32 lpm_key_lk1_3;
};

struct dpp_se_cfg_lpm_key_lk1_2_t {
	u32 lpm_key_lk1_2;
};

struct dpp_se_cfg_lpm_key_lk1_1_t {
	u32 lpm_key_lk1_1;
};

struct dpp_se_cfg_lpm_key_lk1_0_t {
	u32 lpm_key_lk1_0;
};

struct dpp_se_cfg_lpm_key_lk2_6_t {
	u32 lpm_key_lk2_6;
};

struct dpp_se_cfg_lpm_key_lk2_5_t {
	u32 lpm_key_lk2_5;
};

struct dpp_se_cfg_lpm_key_lk2_4_t {
	u32 lpm_key_lk2_4;
};

struct dpp_se_cfg_lpm_key_lk2_3_t {
	u32 lpm_key_lk2_3;
};

struct dpp_se_cfg_lpm_key_lk2_2_t {
	u32 lpm_key_lk2_2;
};

struct dpp_se_cfg_lpm_key_lk2_1_t {
	u32 lpm_key_lk2_1;
};

struct dpp_se_cfg_lpm_key_lk2_0_t {
	u32 lpm_key_lk2_0;
};

struct dpp_se_cfg_lpm_key_lk3_6_t {
	u32 lpm_key_lk3_6;
};

struct dpp_se_cfg_lpm_key_lk3_5_t {
	u32 lpm_key_lk3_5;
};

struct dpp_se_cfg_lpm_key_lk3_4_t {
	u32 lpm_key_lk3_4;
};

struct dpp_se_cfg_lpm_key_lk3_3_t {
	u32 lpm_key_lk3_3;
};

struct dpp_se_cfg_lpm_key_lk3_2_t {
	u32 lpm_key_lk3_2;
};

struct dpp_se_cfg_lpm_key_lk3_1_t {
	u32 lpm_key_lk3_1;
};

struct dpp_se_cfg_lpm_key_lk3_0_t {
	u32 lpm_key_lk3_0;
};

struct dpp_se_cfg_etcam_key_lk0_22_t {
	u32 etcam_key_lk0_22;
};

struct dpp_se_cfg_etcam_key_lk0_21_t {
	u32 etcam_key_lk0_21;
};

struct dpp_se_cfg_etcam_key_lk0_20_t {
	u32 etcam_key_lk0_20;
};

struct dpp_se_cfg_etcam_key_lk0_19_t {
	u32 etcam_key_lk0_19;
};

struct dpp_se_cfg_etcam_key_lk0_18_t {
	u32 etcam_key_lk0_18;
};

struct dpp_se_cfg_etcam_key_lk0_17_t {
	u32 etcam_key_lk0_17;
};

struct dpp_se_cfg_etcam_key_lk0_16_t {
	u32 etcam_key_lk0_16;
};

struct dpp_se_cfg_etcam_key_lk0_15_t {
	u32 etcam_key_lk0_15;
};

struct dpp_se_cfg_etcam_key_lk0_14_t {
	u32 etcam_key_lk0_14;
};

struct dpp_se_cfg_etcam_key_lk0_13_t {
	u32 etcam_key_lk0_13;
};

struct dpp_se_cfg_etcam_key_lk0_12_t {
	u32 etcam_key_lk0_12;
};

struct dpp_se_cfg_etcam_key_lk0_11_t {
	u32 etcam_key_lk0_11;
};

struct dpp_se_cfg_etcam_key_lk0_10_t {
	u32 etcam_key_lk0_10;
};

struct dpp_se_cfg_etcam_key_lk0_9_t {
	u32 etcam_key_lk0_9;
};

struct dpp_se_cfg_etcam_key_lk0_8_t {
	u32 etcam_key_lk0_8;
};

struct dpp_se_cfg_etcam_key_lk0_7_t {
	u32 etcam_key_lk0_7;
};

struct dpp_se_cfg_etcam_key_lk0_6_t {
	u32 etcam_key_lk0_6;
};

struct dpp_se_cfg_etcam_key_lk0_5_t {
	u32 etcam_key_lk0_5;
};

struct dpp_se_cfg_etcam_key_lk0_4_t {
	u32 etcam_key_lk0_4;
};

struct dpp_se_cfg_etcam_key_lk0_3_t {
	u32 etcam_key_lk0_3;
};

struct dpp_se_cfg_etcam_key_lk0_2_t {
	u32 etcam_key_lk0_2;
};

struct dpp_se_cfg_etcam_key_lk0_1_t {
	u32 etcam_key_lk0_1;
};

struct dpp_se_cfg_etcam_key_lk0_0_t {
	u32 etcam_key_lk0_0;
};

struct dpp_se_cfg_etcam_key_lk1_22_t {
	u32 etcam_key_lk1_22;
};

struct dpp_se_cfg_etcam_key_lk1_21_t {
	u32 etcam_key_lk1_21;
};

struct dpp_se_cfg_etcam_key_lk1_20_t {
	u32 etcam_key_lk1_20;
};

struct dpp_se_cfg_etcam_key_lk1_19_t {
	u32 etcam_key_lk1_19;
};

struct dpp_se_cfg_etcam_key_lk1_18_t {
	u32 etcam_key_lk1_18;
};

struct dpp_se_cfg_etcam_key_lk1_17_t {
	u32 etcam_key_lk1_17;
};

struct dpp_se_cfg_etcam_key_lk1_16_t {
	u32 etcam_key_lk1_16;
};

struct dpp_se_cfg_etcam_key_lk1_15_t {
	u32 etcam_key_lk1_15;
};

struct dpp_se_cfg_etcam_key_lk1_14_t {
	u32 etcam_key_lk1_14;
};

struct dpp_se_cfg_etcam_key_lk1_13_t {
	u32 etcam_key_lk1_13;
};

struct dpp_se_cfg_etcam_key_lk1_12_t {
	u32 etcam_key_lk1_12;
};

struct dpp_se_cfg_etcam_key_lk1_11_t {
	u32 etcam_key_lk1_11;
};

struct dpp_se_cfg_etcam_key_lk1_10_t {
	u32 etcam_key_lk1_10;
};

struct dpp_se_cfg_etcam_key_lk1_9_t {
	u32 etcam_key_lk1_9;
};

struct dpp_se_cfg_etcam_key_lk1_8_t {
	u32 etcam_key_lk1_8;
};

struct dpp_se_cfg_etcam_key_lk1_7_t {
	u32 etcam_key_lk1_7;
};

struct dpp_se_cfg_etcam_key_lk1_6_t {
	u32 etcam_key_lk1_6;
};

struct dpp_se_cfg_etcam_key_lk1_5_t {
	u32 etcam_key_lk1_5;
};

struct dpp_se_cfg_etcam_key_lk1_4_t {
	u32 etcam_key_lk1_4;
};

struct dpp_se_cfg_etcam_key_lk1_3_t {
	u32 etcam_key_lk1_3;
};

struct dpp_se_cfg_etcam_key_lk1_2_t {
	u32 etcam_key_lk1_2;
};

struct dpp_se_cfg_etcam_key_lk1_1_t {
	u32 etcam_key_lk1_1;
};

struct dpp_se_cfg_etcam_key_lk1_0_t {
	u32 etcam_key_lk1_0;
};

struct dpp_se_cfg_etcam_key_lk2_22_t {
	u32 etcam_key_lk2_22;
};

struct dpp_se_cfg_etcam_key_lk2_21_t {
	u32 etcam_key_lk2_21;
};

struct dpp_se_cfg_etcam_key_lk2_20_t {
	u32 etcam_key_lk2_20;
};

struct dpp_se_cfg_etcam_key_lk2_19_t {
	u32 etcam_key_lk2_19;
};

struct dpp_se_cfg_etcam_key_lk2_18_t {
	u32 etcam_key_lk2_18;
};

struct dpp_se_cfg_etcam_key_lk2_17_t {
	u32 etcam_key_lk2_17;
};

struct dpp_se_cfg_etcam_key_lk2_16_t {
	u32 etcam_key_lk2_16;
};

struct dpp_se_cfg_etcam_key_lk2_15_t {
	u32 etcam_key_lk2_15;
};

struct dpp_se_cfg_etcam_key_lk2_14_t {
	u32 etcam_key_lk2_14;
};

struct dpp_se_cfg_etcam_key_lk2_13_t {
	u32 etcam_key_lk2_13;
};

struct dpp_se_cfg_etcam_key_lk2_12_t {
	u32 etcam_key_lk2_12;
};

struct dpp_se_cfg_etcam_key_lk2_11_t {
	u32 etcam_key_lk2_11;
};

struct dpp_se_cfg_etcam_key_lk2_10_t {
	u32 etcam_key_lk2_10;
};

struct dpp_se_cfg_etcam_key_lk2_9_t {
	u32 etcam_key_lk2_9;
};

struct dpp_se_cfg_etcam_key_lk2_8_t {
	u32 etcam_key_lk2_8;
};

struct dpp_se_cfg_etcam_key_lk2_7_t {
	u32 etcam_key_lk2_7;
};

struct dpp_se_cfg_etcam_key_lk2_6_t {
	u32 etcam_key_lk2_6;
};

struct dpp_se_cfg_etcam_key_lk2_5_t {
	u32 etcam_key_lk2_5;
};

struct dpp_se_cfg_etcam_key_lk2_4_t {
	u32 etcam_key_lk2_4;
};

struct dpp_se_cfg_etcam_key_lk2_3_t {
	u32 etcam_key_lk2_3;
};

struct dpp_se_cfg_etcam_key_lk2_2_t {
	u32 etcam_key_lk2_2;
};

struct dpp_se_cfg_etcam_key_lk2_1_t {
	u32 etcam_key_lk2_1;
};

struct dpp_se_cfg_etcam_key_lk2_0_t {
	u32 etcam_key_lk2_0;
};

struct dpp_se_cfg_etcam_key_lk3_22_t {
	u32 etcam_key_lk3_22;
};

struct dpp_se_cfg_etcam_key_lk3_21_t {
	u32 etcam_key_lk3_21;
};

struct dpp_se_cfg_etcam_key_lk3_20_t {
	u32 etcam_key_lk3_20;
};

struct dpp_se_cfg_etcam_key_lk3_19_t {
	u32 etcam_key_lk3_19;
};

struct dpp_se_cfg_etcam_key_lk3_18_t {
	u32 etcam_key_lk3_18;
};

struct dpp_se_cfg_etcam_key_lk3_17_t {
	u32 etcam_key_lk3_17;
};

struct dpp_se_cfg_etcam_key_lk3_16_t {
	u32 etcam_key_lk3_16;
};

struct dpp_se_cfg_etcam_key_lk3_15_t {
	u32 etcam_key_lk3_15;
};

struct dpp_se_cfg_etcam_key_lk3_14_t {
	u32 etcam_key_lk3_14;
};

struct dpp_se_cfg_etcam_key_lk3_13_t {
	u32 etcam_key_lk3_13;
};

struct dpp_se_cfg_etcam_key_lk3_12_t {
	u32 etcam_key_lk3_12;
};

struct dpp_se_cfg_etcam_key_lk3_11_t {
	u32 etcam_key_lk3_11;
};

struct dpp_se_cfg_etcam_key_lk3_10_t {
	u32 etcam_key_lk3_10;
};

struct dpp_se_cfg_etcam_key_lk3_9_t {
	u32 etcam_key_lk3_9;
};

struct dpp_se_cfg_etcam_key_lk3_8_t {
	u32 etcam_key_lk3_8;
};

struct dpp_se_cfg_etcam_key_lk3_7_t {
	u32 etcam_key_lk3_7;
};

struct dpp_se_cfg_etcam_key_lk3_6_t {
	u32 etcam_key_lk3_6;
};

struct dpp_se_cfg_etcam_key_lk3_5_t {
	u32 etcam_key_lk3_5;
};

struct dpp_se_cfg_etcam_key_lk3_4_t {
	u32 etcam_key_lk3_4;
};

struct dpp_se_cfg_etcam_key_lk3_3_t {
	u32 etcam_key_lk3_3;
};

struct dpp_se_cfg_etcam_key_lk3_2_t {
	u32 etcam_key_lk3_2;
};

struct dpp_se_cfg_etcam_key_lk3_1_t {
	u32 etcam_key_lk3_1;
};

struct dpp_se_cfg_etcam_key_lk3_0_t {
	u32 etcam_key_lk3_0;
};

struct dpp_se_cfg_pbu_key_lk0_3_t {
	u32 pbu_key_lk0_3;
};

struct dpp_se_cfg_pbu_key_lk0_2_t {
	u32 pbu_key_lk0_2;
};

struct dpp_se_cfg_pbu_key_lk0_1_t {
	u32 pbu_key_lk0_1;
};

struct dpp_se_cfg_pbu_key_lk0_0_t {
	u32 pbu_key_lk0_0;
};

struct dpp_se_cfg_pbu_key_lk1_3_t {
	u32 pbu_key_lk1_3;
};

struct dpp_se_cfg_pbu_key_lk1_2_t {
	u32 pbu_key_lk1_2;
};

struct dpp_se_cfg_pbu_key_lk1_1_t {
	u32 pbu_key_lk1_1;
};

struct dpp_se_cfg_pbu_key_lk1_0_t {
	u32 pbu_key_lk1_0;
};

struct dpp_se_cfg_pbu_key_lk2_3_t {
	u32 pbu_key_lk2_3;
};

struct dpp_se_cfg_pbu_key_lk2_2_t {
	u32 pbu_key_lk2_2;
};

struct dpp_se_cfg_pbu_key_lk2_1_t {
	u32 pbu_key_lk2_1;
};

struct dpp_se_cfg_pbu_key_lk2_0_t {
	u32 pbu_key_lk2_0;
};

struct dpp_se_cfg_pbu_key_lk3_3_t {
	u32 pbu_key_lk3_3;
};

struct dpp_se_cfg_pbu_key_lk3_2_t {
	u32 pbu_key_lk3_2;
};

struct dpp_se_cfg_pbu_key_lk3_1_t {
	u32 pbu_key_lk3_1;
};

struct dpp_se_cfg_pbu_key_lk3_0_t {
	u32 pbu_key_lk3_0;
};

struct dpp_se_alg_schd_learn_fifo_pfull_ast_t {
	u32 schd_learn_fifo_pfull_ast;
};

struct dpp_se_alg_schd_learn_fifo_pfull_neg_t {
	u32 schd_learn_fifo_pfull_neg;
};

struct dpp_se_alg_schd_hash0_fifo_pfull_ast_t {
	u32 schd_hash0_fifo_pfull_ast;
};

struct dpp_se_alg_schd_hash0_fifo_pfull_neg_t {
	u32 schd_hash0_fifo_pfull_neg;
};

struct dpp_se_alg_schd_hash1_fifo_pfull_ast_t {
	u32 schd_hash1_fifo_pfull_ast;
};

struct dpp_se_alg_schd_hash1_fifo_pfull_neg_t {
	u32 schd_hash1_fifo_pfull_neg;
};

struct dpp_se_alg_schd_hash2_fifo_pfull_ast_t {
	u32 schd_hash2_fifo_pfull_ast;
};

struct dpp_se_alg_schd_hash2_fifo_pfull_neg_t {
	u32 schd_hash2_fifo_pfull_neg;
};

struct dpp_se_alg_schd_hash3_fifo_pfull_ast_t {
	u32 schd_hash3_fifo_pfull_ast;
};

struct dpp_se_alg_schd_hash3_fifo_pfull_neg_t {
	u32 schd_hash3_fifo_pfull_neg;
};

struct dpp_se_alg_schd_lpm_fifo_pfull_ast_t {
	u32 schd_lpm_fifo_pfull_ast;
};

struct dpp_se_alg_schd_lpm_fifo_pfull_neg_t {
	u32 schd_lpm_fifo_pfull_neg;
};

struct dpp_se_alg_hash0_key_fifo_pfull_ast_t {
	u32 hash0_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash0_key_fifo_pfull_neg_t {
	u32 hash0_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash0_sreq_fifo_pfull_ast_t {
	u32 hash0_sreq_fifo_pfull_ast;
};

struct dpp_se_alg_hash0_sreq_fifo_pfull_neg_t {
	u32 hash0_sreq_fifo_pfull_neg;
};

struct dpp_se_alg_hash0_int_rsp_fifo_pfull_ast_t {
	u32 hash0_int_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash0_int_rsp_fifo_pfull_neg_t {
	u32 hash0_int_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_hash0_ext_rsp_fifo_pfull_ast_t {
	u32 hash0_ext_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash0_ext_rsp_fifo_pfull_neg_t {
	u32 hash0_ext_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_hash1_key_fifo_pfull_ast_t {
	u32 hash1_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash1_key_fifo_pfull_neg_t {
	u32 hash1_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash1_sreq_fifo_pfull_ast_t {
	u32 hash1_sreq_fifo_pfull_ast;
};

struct dpp_se_alg_hash1_sreq_fifo_pfull_neg_t {
	u32 hash1_sreq_fifo_pfull_neg;
};

struct dpp_se_alg_hash1_int_rsp_fifo_pfull_ast_t {
	u32 hash1_int_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash1_int_rsp_fifo_pfull_neg_t {
	u32 hash1_int_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_hash1_ext_rsp_fifo_pfull_ast_t {
	u32 hash1_ext_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash1_ext_rsp_fifo_pfull_neg_t {
	u32 hash1_ext_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_hash2_key_fifo_pfull_ast_t {
	u32 hash2_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash2_key_fifo_pfull_neg_t {
	u32 hash2_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash2_sreq_fifo_pfull_ast_t {
	u32 hash2_sreq_fifo_pfull_ast;
};

struct dpp_se_alg_hash2_sreq_fifo_pfull_neg_t {
	u32 hash2_sreq_fifo_pfull_neg;
};

struct dpp_se_alg_hash2_int_rsp_fifo_pfull_ast_t {
	u32 hash2_int_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash2_int_rsp_fifo_pfull_neg_t {
	u32 hash2_int_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_hash2_ext_rsp_fifo_pfull_ast_t {
	u32 hash2_ext_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash2_ext_rsp_fifo_pfull_neg_t {
	u32 hash2_ext_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_hash3_key_fifo_pfull_ast_t {
	u32 hash3_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash3_key_fifo_pfull_neg_t {
	u32 hash3_key_fifo_pfull_ast;
};

struct dpp_se_alg_hash3_sreq_fifo_pfull_ast_t {
	u32 hash3_sreq_fifo_pfull_ast;
};

struct dpp_se_alg_hash3_sreq_fifo_pfull_neg_t {
	u32 hash3_sreq_fifo_pfull_neg;
};

struct dpp_se_alg_hash3_int_rsp_fifo_pfull_ast_t {
	u32 hash3_int_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash3_int_rsp_fifo_pfull_neg_t {
	u32 hash3_int_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_hash3_ext_rsp_fifo_pfull_ast_t {
	u32 hash3_ext_rsp_fifo_pfull_ast;
};

struct dpp_se_alg_hash3_ext_rsp_fifo_pfull_neg_t {
	u32 hash3_ext_rsp_fifo_pfull_neg;
};

struct dpp_se_alg_lpm_as_info_t {
	u32 lpm_as_type;
	u32 lpm_as_en;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u0_pfull_neg_t {
	u32 lpm_ext_rsp_fifo_u0_pfull_neg;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u2_pfull_ast_t {
	u32 lpm_ext_rsp_fifo_u2_pfull_ast;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u2_pfull_neg_t {
	u32 lpm_ext_rsp_fifo_u2_pfull_neg;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u3_pfull_ast_t {
	u32 lpm_ext_rsp_fifo_u3_pfull_ast;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u3_pfull_neg_t {
	u32 lpm_ext_rsp_fifo_u3_pfull_neg;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u4_pfull_ast_t {
	u32 lpm_ext_rsp_fifo_u4_pfull_ast;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_u4_pfull_neg_t {
	u32 lpm_ext_rsp_fifo_u4_pfull_neg;
};

struct dpp_se_alg_lpm_as_rsp_fifo_u0_pfull_ast_t {
	u32 lpm_as_rsp_fifo_u0_pfull_ast;
};

struct dpp_se_alg_lpm_as_rsp_fifo_u0_pfull_neg_t {
	u32 lpm_as_rsp_fifo_u0_pfull_neg;
};

struct dpp_se_alg_lpm_as_rsp_fifo_u1_pfull_ast_t {
	u32 lpm_as_rsp_fifo_u1_pfull_ast;
};

struct dpp_se_alg_lpm_as_rsp_fifo_u1_pfull_neg_t {
	u32 lpm_as_rsp_fifo_u1_pfull_neg;
};

struct dpp_se_alg_lpm_v4_ddr3_base_addr_t {
	u32 lpm_v4_ddr3_base_addr;
};

struct dpp_se_alg_lpm_v6_ddr3_base_addr_t {
	u32 lpm_v6_ddr3_base_addr;
};

struct dpp_se_alg_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_se_alg_hash_p0_key_vld_cnt_t {
	u32 hash_p0_key_vld_cnt;
};

struct dpp_se_alg_hash_p1_key_vld_cnt_t {
	u32 hash_p1_key_vld_cnt;
};

struct dpp_se_alg_hash_p2_key_vld_cnt_t {
	u32 hash_p2_key_vld_cnt;
};

struct dpp_se_alg_hash_p3_key_vld_cnt_t {
	u32 hash_p3_key_vld_cnt;
};

struct dpp_se_alg_lpm_p0_key_vld_cnt_t {
	u32 lpm_p0_key_vld_cnt;
};

struct dpp_se_alg_hash_p0_rsp_vld_cnt_t {
	u32 hash_p0_rsp_vld_cnt;
};

struct dpp_se_alg_hash_p1_rsp_vld_cnt_t {
	u32 hash_p1_rsp_vld_cnt;
};

struct dpp_se_alg_hash_p2_rsp_vld_cnt_t {
	u32 hash_p2_rsp_vld_cnt;
};

struct dpp_se_alg_hash_p3_rsp_vld_cnt_t {
	u32 hash_p3_rsp_vld_cnt;
};

struct dpp_se_alg_lpm_p0_rsp_vld_cnt_t {
	u32 lpm_p0_rsp_vld_cnt;
};

struct dpp_se_alg_hash_p0_smf_cnt_t {
	u32 hash_p0_smf_cnt;
};

struct dpp_se_alg_hash_p1_smf_cnt_t {
	u32 hash_p1_smf_cnt;
};

struct dpp_se_alg_hash_p2_smf_cnt_t {
	u32 hash_p2_smf_cnt;
};

struct dpp_se_alg_hash_p3_smf_cnt_t {
	u32 hash_p3_smf_cnt;
};

struct dpp_se_alg_lpm_p0_smf_cnt_t {
	u32 lpm_p0_smf_cnt;
};

struct dpp_se_alg_hash_p0_spacevld_cnt_t {
	u32 hash_p0_spacevld_cnt;
};

struct dpp_se_alg_hash_p1_spacevld_cnt_t {
	u32 hash_p1_spacevld_cnt;
};

struct dpp_se_alg_hash_p2_spacevld_cnt_t {
	u32 hash_p2_spacevld_cnt;
};

struct dpp_se_alg_hash_p3_spacevld_cnt_t {
	u32 hash_p3_spacevld_cnt;
};

struct dpp_se_alg_smmu1_p0_req_vld_cnt_t {
	u32 smmu1_p0_req_vld_cnt;
};

struct dpp_se_alg_smmu1_p1_req_vld_cnt_t {
	u32 smmu1_p1_req_vld_cnt;
};

struct dpp_se_alg_smmu1_p2_req_vld_cnt_t {
	u32 smmu1_p2_req_vld_cnt;
};

struct dpp_se_alg_smmu1_p3_req_vld_cnt_t {
	u32 smmu1_p3_req_vld_cnt;
};

struct dpp_se_alg_smmu1_p4_req_vld_cnt_t {
	u32 smmu1_p4_req_vld_cnt;
};

struct dpp_se_alg_smmu1_p5_req_vld_cnt_t {
	u32 smmu1_p5_req_vld_cnt;
};

struct dpp_se_alg_smmu1_p0_rsp_vld_cnt_t {
	u32 smmu1_p0_rsp_vld_cnt;
};

struct dpp_se_alg_smmu1_p1_rsp_vld_cnt_t {
	u32 smmu1_p1_rsp_vld_cnt;
};

struct dpp_se_alg_smmu1_p2_rsp_vld_cnt_t {
	u32 smmu1_p2_rsp_vld_cnt;
};

struct dpp_se_alg_smmu1_p3_rsp_vld_cnt_t {
	u32 smmu1_p3_rsp_vld_cnt;
};

struct dpp_se_alg_smmu1_p4_rsp_vld_cnt_t {
	u32 smmu1_p4_rsp_vld_cnt;
};

struct dpp_se_alg_smmu1_p5_rsp_vld_cnt_t {
	u32 smmu1_p5_rsp_vld_cnt;
};

struct dpp_se_alg_schd_learn_fifo_int_cnt_t {
	u32 schd_learn_fifo_int_cnt;
};

struct dpp_se_alg_schd_hash0_fifo_int_cnt_t {
	u32 schd_hash0_fifo_int_cnt;
};

struct dpp_se_alg_schd_hash1_fifo_int_cnt_t {
	u32 schd_hash1_fifo_int_cnt;
};

struct dpp_se_alg_schd_hash2_fifo_int_cnt_t {
	u32 schd_hash2_fifo_int_cnt;
};

struct dpp_se_alg_schd_hash3_fifo_int_cnt_t {
	u32 schd_hash3_fifo_int_cnt;
};

struct dpp_se_alg_schd_lpm_fifo_int_cnt_t {
	u32 schd_lpm_fifo_int_cnt;
};

struct dpp_se_alg_schd_learn_fifo_parity_err_cnt_t {
	u32 schd_learn_fifo_parity_err_cnt;
};

struct dpp_se_alg_schd_hash0_fifo_parity_err_cnt_t {
	u32 schd_hash0_fifo_parity_err_cnt;
};

struct dpp_se_alg_schd_hash1_fifo_parity_err_cnt_t {
	u32 schd_hash1_fifo_parity_err_cnt;
};

struct dpp_se_alg_schd_hash2_fifo_parity_err_cnt_t {
	u32 schd_hash2_fifo_parity_err_cnt;
};

struct dpp_se_alg_schd_hash3_fifo_parity_err_cnt_t {
	u32 schd_hash3_fifo_parity_err_cnt;
};

struct dpp_se_alg_schd_lpm_fifo_parity_err_cnt_t {
	u32 schd_lpm_fifo_parity_err_cnt;
};

struct dpp_se_alg_rd_init_cft_cnt_t {
	u32 rd_init_cft_cnt;
};

struct dpp_se_alg_zgp0_zblk0_ecc_err_cnt_t {
	u32 zgp0_zblk0_ecc_err_cnt;
};

struct dpp_se_alg_zgp0_zblk1_ecc_err_cnt_t {
	u32 zgp0_zblk1_ecc_err_cnt;
};

struct dpp_se_alg_zgp0_zblk2_ecc_err_cnt_t {
	u32 zgp0_zblk2_ecc_err_cnt;
};

struct dpp_se_alg_zgp0_zblk3_ecc_err_cnt_t {
	u32 zgp0_zblk3_ecc_err_cnt;
};

struct dpp_se_alg_zgp0_zblk4_ecc_err_cnt_t {
	u32 zgp0_zblk4_ecc_err_cnt;
};

struct dpp_se_alg_zgp0_zblk5_ecc_err_cnt_t {
	u32 zgp0_zblk5_ecc_err_cnt;
};

struct dpp_se_alg_zgp0_zblk6_ecc_err_cnt_t {
	u32 zgp0_zblk6_ecc_err_cnt;
};

struct dpp_se_alg_zgp0_zblk7_ecc_err_cnt_t {
	u32 zgp0_zblk7_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk0_ecc_err_cnt_t {
	u32 zgp1_zblk0_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk1_ecc_err_cnt_t {
	u32 zgp1_zblk1_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk2_ecc_err_cnt_t {
	u32 zgp1_zblk2_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk3_ecc_err_cnt_t {
	u32 zgp1_zblk3_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk4_ecc_err_cnt_t {
	u32 zgp1_zblk4_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk5_ecc_err_cnt_t {
	u32 zgp1_zblk5_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk6_ecc_err_cnt_t {
	u32 zgp1_zblk6_ecc_err_cnt;
};

struct dpp_se_alg_zgp1_zblk7_ecc_err_cnt_t {
	u32 zgp1_zblk7_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk0_ecc_err_cnt_t {
	u32 zgp2_zblk0_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk1_ecc_err_cnt_t {
	u32 zgp2_zblk1_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk2_ecc_err_cnt_t {
	u32 zgp2_zblk2_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk3_ecc_err_cnt_t {
	u32 zgp2_zblk3_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk4_ecc_err_cnt_t {
	u32 zgp2_zblk4_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk5_ecc_err_cnt_t {
	u32 zgp2_zblk5_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk6_ecc_err_cnt_t {
	u32 zgp2_zblk6_ecc_err_cnt;
};

struct dpp_se_alg_zgp2_zblk7_ecc_err_cnt_t {
	u32 zgp2_zblk7_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk0_ecc_err_cnt_t {
	u32 zgp3_zblk0_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk1_ecc_err_cnt_t {
	u32 zgp3_zblk1_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk2_ecc_err_cnt_t {
	u32 zgp3_zblk2_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk3_ecc_err_cnt_t {
	u32 zgp3_zblk3_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk4_ecc_err_cnt_t {
	u32 zgp3_zblk4_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk5_ecc_err_cnt_t {
	u32 zgp3_zblk5_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk6_ecc_err_cnt_t {
	u32 zgp3_zblk6_ecc_err_cnt;
};

struct dpp_se_alg_zgp3_zblk7_ecc_err_cnt_t {
	u32 zgp3_zblk7_ecc_err_cnt;
};

struct dpp_se_alg_zcam_hash_p0_err_cnt_t {
	u32 zcam_hash_p0_err_cnt;
};

struct dpp_se_alg_zcam_hash_p1_err_cnt_t {
	u32 zcam_hash_p1_err_cnt;
};

struct dpp_se_alg_zcam_hash_p2_err_cnt_t {
	u32 zcam_hash_p2_err_cnt;
};

struct dpp_se_alg_zcam_hash_p3_err_cnt_t {
	u32 zcam_hash_p3_err_cnt;
};

struct dpp_se_alg_zcam_lpm_err_cnt_t {
	u32 zcam_lpm_err_cnt;
};

struct dpp_se_alg_hash0_sreq_fifo_parity_err_cnt_t {
	u32 hash0_sreq_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash0_sreq_fifo_int_cnt_t {
	u32 hash0_sreq_fifo_int_cnt;
};

struct dpp_se_alg_hash0_key_fifo_int_cnt_t {
	u32 hash0_key_fifo_int_cnt;
};

struct dpp_se_alg_hash0_int_rsp_fifo_parity_err_cnt_t {
	u32 hash0_int_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash0_ext_rsp_fifo_parity_err_cnt_t {
	u32 hash0_ext_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash0_ext_rsp_fifo_int_cnt_t {
	u32 hash0_ext_rsp_fifo_int_cnt;
};

struct dpp_se_alg_hash0_int_rsp_fifo_int_cnt_t {
	u32 hash0_int_rsp_fifo_int_cnt;
};

struct dpp_se_alg_hash1_sreq_fifo_parity_err_cnt_t {
	u32 hash1_sreq_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash1_sreq_fifo_int_cnt_t {
	u32 hash1_sreq_fifo_int_cnt;
};

struct dpp_se_alg_hash1_key_fifo_int_cnt_t {
	u32 hash1_key_fifo_int_cnt;
};

struct dpp_se_alg_hash1_int_rsp_fifo_parity_err_cnt_t {
	u32 hash1_int_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash1_ext_rsp_fifo_parity_err_cnt_t {
	u32 hash1_ext_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash1_ext_rsp_fifo_int_cnt_t {
	u32 hash1_ext_rsp_fifo_int_cnt;
};

struct dpp_se_alg_hash1_int_rsp_fifo_int_cnt_t {
	u32 hash1_int_rsp_fifo_int_cnt;
};

struct dpp_se_alg_hash2_sreq_fifo_parity_err_cnt_t {
	u32 hash2_sreq_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash2_sreq_fifo_int_cnt_t {
	u32 hash2_sreq_fifo_int_cnt;
};

struct dpp_se_alg_hash2_key_fifo_int_cnt_t {
	u32 hash2_key_fifo_int_cnt;
};

struct dpp_se_alg_hash2_int_rsp_fifo_parity_err_cnt_t {
	u32 hash2_int_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash2_ext_rsp_fifo_parity_err_cnt_t {
	u32 hash2_ext_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash2_ext_rsp_fifo_int_cnt_t {
	u32 hash2_ext_rsp_fifo_int_cnt;
};

struct dpp_se_alg_hash2_int_rsp_fifo_int_cnt_t {
	u32 hash2_int_rsp_fifo_int_cnt;
};

struct dpp_se_alg_hash3_sreq_fifo_parity_err_cnt_t {
	u32 hash3_sreq_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash3_sreq_fifo_int_cnt_t {
	u32 hash3_sreq_fifo_int_cnt;
};

struct dpp_se_alg_hash3_key_fifo_int_cnt_t {
	u32 hash3_key_fifo_int_cnt;
};

struct dpp_se_alg_hash3_int_rsp_fifo_parity_err_cnt_t {
	u32 hash3_int_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash3_ext_rsp_fifo_parity_err_cnt_t {
	u32 hash3_ext_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_hash3_ext_rsp_fifo_int_cnt_t {
	u32 hash3_ext_rsp_fifo_int_cnt;
};

struct dpp_se_alg_hash3_int_rsp_fifo_int_cnt_t {
	u32 hash3_int_rsp_fifo_int_cnt;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_int_cnt_t {
	u32 lpm_ext_rsp_fifo_int_cnt;
};

struct dpp_se_alg_lpm_ext_v6_fifo_int_cnt_t {
	u32 lpm_ext_v6_fifo_int_cnt;
};

struct dpp_se_alg_lpm_ext_v4_fifo_int_cnt_t {
	u32 lpm_ext_v4_fifo_int_cnt;
};

struct dpp_se_alg_lpm_ext_addr_fifo_int_cnt_t {
	u32 lpm_ext_addr_fifo_int_cnt;
};

struct dpp_se_alg_lpm_ext_v4_fifo_parity_err_cnt_t {
	u32 lpm_ext_v4_fifo_parity_err_cnt;
};

struct dpp_se_alg_lpm_ext_v6_fifo_parity_err_cnt_t {
	u32 lpm_ext_v6_fifo_parity_err_cnt;
};

struct dpp_se_alg_lpm_ext_rsp_fifo_parity_err_cnt_t {
	u32 lpm_ext_rsp_fifo_parity_err_cnt;
};

struct dpp_se_alg_lpm_as_req_fifo_int_cnt_t {
	u32 lpm_as_req_fifo_int_cnt;
};

struct dpp_se_alg_lpm_as_int_rsp_fifo_int_cnt_t {
	u32 lpm_as_int_rsp_fifo_int_cnt;
};

struct dpp_se_alg_se_alg_int_status_t {
	u32 schd_int_unmask_flag;
	u32 zblk_ecc_int_unmask_flag;
	u32 hash0_int_unmask_flag;
	u32 hash1_int_unmask_flag;
	u32 hash2_int_unmask_flag;
	u32 hash3_int_unmask_flag;
	u32 lpm_int_unmask_flag;
};

struct dpp_se_alg_schd_int_en_t {
	u32 wr_rsp_fifo_ovfl;
	u32 init_rd_cft_en;
	u32 schd_lpm_fifo_parity_errl;
	u32 schd_hash3_fifo_parity_err;
	u32 schd_hash2_fifo_parity_err;
	u32 schd_hash1_fifo_parity_err;
	u32 schd_hash0_fifo_parity_err;
	u32 schd_learn_fifo_parity_err;
	u32 schd_lpm_fifo_ovfl;
	u32 schd_hash3_fifo_ovfl;
	u32 schd_hash2_fifo_unfl;
	u32 schd_hash1_fifo_ovfl;
	u32 schd_hash0_fifo_ovfl;
	u32 schd_learn_fifo_ovfl;
};

struct dpp_se_alg_schd_int_mask_t {
	u32 schd_int_mask;
};

struct dpp_se_alg_schd_int_status_t {
	u32 schd_int_status;
};

struct dpp_se_alg_zblk_ecc_int_en_t {
	u32 zblk_ecc_int_en;
};

struct dpp_se_alg_zblk_ecc_int_mask_t {
	u32 zblk_ecc_int_mask;
};

struct dpp_se_alg_zblk_ecc_int_status_t {
	u32 zblk_ecc_int_status;
};

struct dpp_se_alg_hash0_int_en_t {
	u32 zcam_hash_p0_err_en;
	u32 hash0_agree_int_fifo_ovf_en;
	u32 hash0_agree_ext_fifo_ovf_en;
	u32 hash0_agree_ext_fifo_parity_err_en;
	u32 hash0_agree_int_fifo_parity_err_en;
	u32 hash0_key_fifo_ovfl_en;
	u32 hash0_sreq_fifo_ovfl_en;
	u32 hash0_key_fifo_parity_err_en;
};

struct dpp_se_alg_hash0_int_mask_t {
	u32 hash0_int_mask;
};

struct dpp_se_alg_hash0_int_status_t {
	u32 hash0_int_status;
};

struct dpp_se_alg_hash1_int_en_t {
	u32 zcam_hash_p1_err_en;
	u32 hash1_agree_int_fifo_ovf_en;
	u32 hash1_agree_ext_fifo_ovf_en;
	u32 hash1_agree_ext_fifo_parity_err_en;
	u32 hash1_agree_int_fifo_parity_err_en;
	u32 hash1_key_fifo_ovfl_en;
	u32 hash1_sreq_fifo_ovfl_en;
	u32 hash1_key_fifo_parity_err_en;
};

struct dpp_se_alg_hash1_int_mask_t {
	u32 hash1_int_mask;
};

struct dpp_se_alg_hash1_int_status_t {
	u32 hash1_int_status;
};

struct dpp_se_alg_hash2_int_en_t {
	u32 zcam_hash_p2_err_en;
	u32 hash2_agree_int_fifo_ovf_en;
	u32 hash2_agree_ext_fifo_ovf_en;
	u32 hash2_agree_ext_fifo_parity_err_en;
	u32 hash2_agree_int_fifo_parity_err_en;
	u32 hash2_key_fifo_ovfl_en;
	u32 hash2_sreq_fifo_ovfl_en;
	u32 hash2_key_fifo_parity_err_en;
};

struct dpp_se_alg_hash2_int_mask_t {
	u32 hash2_int_mask;
};

struct dpp_se_alg_hash2_int_status_t {
	u32 hash2_int_status;
};

struct dpp_se_alg_hash3_int_en_t {
	u32 zcam_hash_p3_err_en;
	u32 hash3_agree_int_fifo_ovf_en;
	u32 hash3_agree_ext_fifo_ovf_en;
	u32 hash3_agree_ext_fifo_parity_err_en;
	u32 hash3_agree_int_fifo_parity_err_en;
	u32 hash3_key_fifo_ovfl_en;
	u32 hash3_sreq_fifo_ovfl_en;
	u32 hash3_key_fifo_parity_err_en;
};

struct dpp_se_alg_hash3_int_mask_t {
	u32 hash3_int_mask;
};

struct dpp_se_alg_hash3_int_status_t {
	u32 hash3_int_status;
};

struct dpp_se_alg_lpm_int_en_t {
	u32 zcam_lpm_err_en;
	u32 lpm_as_int_rsp_fifo_ovfl_en;
	u32 lpm_as_req_fifo_ovfl_en;
	u32 lpm_ext_ddr_rsp_fifo_parity_en;
	u32 lpm_ext_v6_key_parity_en;
	u32 lpm_ext_v4_key_parity_en;
	u32 lpm_ext_addr_fifo_ovfl_en;
	u32 lpm_ext_v4_fifo_ovfl_en;
	u32 lpm_ext_v6_fifo_ovfl_en;
	u32 lpm_ext_ddr_rsp_ovf_en;
};

struct dpp_se_alg_lpm_int_mask_t {
	u32 lpm_int_mask;
};

struct dpp_se_alg_lpm_int_status_t {
	u32 lpm_int_status;
};

struct dpp_se_alg_zblock_lpm_mask0_t {
	u32 vpn_id_mask;
	u32 prefix0_mask;
	u32 prefix1_mask;
	u32 prefix2_mask;
	u32 prefix3_mask;
};

struct dpp_se_alg_zblock_lpm_mask1_t {
	u32 vpn_id_mask;
	u32 prefix0_mask;
	u32 prefix1_mask;
	u32 prefix2_mask;
	u32 prefix3_mask;
};

struct dpp_se_alg_zblock_lpm_mask2_t {
	u32 vpn_id_mask;
	u32 prefix0_mask;
	u32 prefix1_mask;
	u32 prefix2_mask;
	u32 prefix3_mask;
};

struct dpp_se_alg_zblock_lpm_mask3_t {
	u32 vpn_id_mask;
	u32 prefix0_mask;
	u32 prefix1_mask;
	u32 prefix2_mask;
	u32 prefix3_mask;
};

struct dpp_se_alg_zblock_default_route0_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_default_route1_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_default_route2_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_default_route3_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_default_route4_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_default_route5_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_default_route6_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_default_route7_t {
	u32 vpn_id;
	u32 vpn_dresult;
	u32 vpn_flag;
	u32 vpn_vld;
};

struct dpp_se_alg_zblock_hash_listtable_item0_t {
	u32 hash_item;
};

struct dpp_se_alg_zblock_hash_listtable_item1_t {
	u32 hash_item;
};

struct dpp_se_alg_zblock_hash_listtable_item2_t {
	u32 hash_item;
};

struct dpp_se_alg_zblock_hash_listtable_item3_t {
	u32 hash_item;
};

struct dpp_se_alg_zblock_ecc_err_status_t {
	u32 sram3_ecc_err;
	u32 sram2_ecc_err;
	u32 sram1_ecc_err;
	u32 sram0_ecc_err;
};

struct dpp_se_alg_zblock_lpm_v6_sram_cmp_t {
	u32 sram_cmp_flag;
};

struct dpp_se_alg_zblock_lpm_v4_sram_cmp_t {
	u32 sram_cmp_flag;
};

struct dpp_se_parser_kschd_pful_cfg_t {
	u32 kschd_pful_assert;
	u32 kschd_pful_negate;
};

struct dpp_se_parser_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_se_parser_parser_int_en_t {
	u32 parser_int_en;
};

struct dpp_se_parser_parser_int_mask_t {
	u32 parser_int_mask;
};

struct dpp_se_parser_parser_int_status_t {
	u32 parser_int_status;
};

struct dpp_se_parser_parser_int_unmask_flag_t {
	u32 parser_int_unmask_flag;
};

struct dpp_se_parser_ecc_bypass_read_t {
	u32 ecc_bypass_read;
};

struct dpp_se_parser_mex0_5_req_cnt_t {
	u32 mex0_5_req_cnt;
};

struct dpp_se_parser_kschd_req0_5_cnt_t {
	u32 kschd_req0_5_cnt;
};

struct dpp_se_parser_kschd_parser_fc0_5_cnt_t {
	u32 kschd_parser_fc0_5_cnt;
};

struct dpp_se_parser_se_ppu_mex0_5_fc_cnt_t {
	u32 se_ppu_mex0_5_fc_cnt;
};

struct dpp_se_parser_smmu0_marc_fc_cnt_t {
	u32 smmu0_marc_fc_cnt;
};

struct dpp_se_parser_smmu0_marc_key_cnt_t {
	u32 smmu0_marc_key_cnt;
};

struct dpp_se_parser_cmmu_key_cnt_t {
	u32 cmmu_key_cnt;
};

struct dpp_se_parser_cmmu_parser_fc_cnt_t {
	u32 cmmu_parser_fc_cnt;
};

struct dpp_se_parser_marc_tab_type_err_mex0_5_cnt_t {
	u32 marc_tab_type_err_mex0_5_cnt;
};

struct dpp_se_parser_eram_fulladdr_drop_cnt_t {
	u32 eram_fulladdr_drop_cnt;
};

struct dpp_se_as_hash0_pful_cfg_t {
	u32 hash0_pful_cfg;
};

struct dpp_se_as_hash1_pful_cfg_t {
	u32 hash1_pful_cfg;
};

struct dpp_se_as_hash2_pful_cfg_t {
	u32 hash2_pful_cfg;
};

struct dpp_se_as_hash3_pful_cfg_t {
	u32 hash3_pful_cfg;
};

struct dpp_se_as_pbu_pful_cfg_t {
	u32 pbu_pful_cfg;
};

struct dpp_se_as_lpm_pful_cfg_t {
	u32 lpm_pful_cfg;
};

struct dpp_se_as_etcam_pful_cfg_t {
	u32 etcam_pful_cfg;
};

struct dpp_se_as_as_learn0_fifo_cfg_t {
	u32 as_learn1_pful_negate;
	u32 as_learn1_pful_asert;
	u32 as_learn0_pful_negate;
	u32 as_learn0_pful_asert;
};

struct dpp_se_as_as_learn1_fifo_cfg_t {
	u32 as_learn3_pful_negate;
	u32 as_learn3_pful_asert;
	u32 as_learn2_pful_negate;
	u32 as_learn2_pful_asert;
};

struct dpp_se_as_as_dma_fifo_cfg_t {
	u32 as_dma_fifo_cfg;
};

struct dpp_se_as_age_pful_cfg_t {
	u32 age_pful_cfg;
};

struct dpp_se_as_etcam_rsp_cfg_t {
	u32 eram_rsp_pful_negate;
	u32 eram_rsp_pful_assert;
	u32 etcam_rsp_pful_negate;
	u32 etcam_rsp_pful_assert;
};

struct dpp_se_as_pbu_ecc_bypass_read_t {
	u32 pbu_ecc_bypass_read;
};

struct dpp_se_as_etcam0_ecc_bypass_read_t {
	u32 etcam0_ecc_bypass_read;
};

struct dpp_se_as_etcam1_ecc_bypass_read_t {
	u32 etcam1_ecc_bypass_read;
};

struct dpp_se_as_lpm_ecc_bypass_read_t {
	u32 lpm_ecc_bypass_read;
};

struct dpp_se_as_hash_ecc_bypass_read_t {
	u32 hash3_ecc_bypass_read;
	u32 hash2_ecc_bypass_read;
	u32 hash1_ecc_bypass_read;
	u32 hash0_ecc_bypass_read;
};

struct dpp_se_as_hash_learn_ecc_bypass_read_t {
	u32 hash_learn_ecc_bypass_read;
};

struct dpp_se_as_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_se_as_as_int_0_en_t {
	u32 as_int_0_en;
};

struct dpp_se_as_as_int_0_mask_t {
	u32 as_int_0_mask;
};

struct dpp_se_as_as_int_1_en_t {
	u32 as_int_1_en;
};

struct dpp_se_as_as_int_1_mask_t {
	u32 as_int_1_mask;
};

struct dpp_se_as_as_int_2_en_t {
	u32 as_int_2_en;
};

struct dpp_se_as_as_int_2_mask_t {
	u32 as_int_2_mask;
};

struct dpp_se_as_as_int_0_status_t {
	u32 port0_int_status;
};

struct dpp_se_as_as_int_1_status_t {
	u32 port1_int_status;
};

struct dpp_se_as_as_int_2_status_t {
	u32 port2_int_status;
};

struct dpp_se_as_se_as_int_status_t {
	u32 as_int_2_unmask_flag;
	u32 as_int_1_unmask_flag;
	u32 as_int_0_unmask_flag;
};

struct dpp_se_as_hash0_3_wr_req_cnt_t {
	u32 hash0_3_wr_req_cnt;
};

struct dpp_se_as_smmu0_etcam0_1_fc_cnt_t {
	u32 smmu0_etcam0_1_fc_cnt;
};

struct dpp_se_as_etcam0_1_smmu0_req_cnt_t {
	u32 etcam0_1_smmu0_req_cnt;
};

struct dpp_se_as_smmu0_etcam0_1_rsp_cnt_t {
	u32 smmu0_etcam0_1_rsp_cnt;
};

struct dpp_se_as_as_hla_hash_p0_3_key_cnt_t {
	u32 as_hla_hash_p0_3_key_cnt;
};

struct dpp_se_as_as_hla_lpm_p0_key_cnt_t {
	u32 as_hla_lpm_p0_key_cnt;
};

struct dpp_se_as_alg_as_hash_p0_3_rsp_cnt_t {
	u32 alg_as_hash_p0_3_rsp_cnt;
};

struct dpp_se_as_alg_as_hash_p0_3_smf_rsp_cnt_t {
	u32 alg_as_hash_p0_3_smf_rsp_cnt;
};

struct dpp_se_as_alg_as_lpm_p0_rsp_cnt_t {
	u32 alg_as_lpm_p0_rsp_cnt;
};

struct dpp_se_as_alg_as_lpm_p0_3_smf_rsp_cnt_t {
	u32 alg_as_lpm_p0_3_smf_rsp_cnt;
};

struct dpp_se_as_as_pbu_key_cnt_t {
	u32 as_pbu_key_cnt;
};

struct dpp_se_as_pbu_se_dpi_rsp_dat_cnt_t {
	u32 pbu_se_dpi_rsp_dat_cnt;
};

struct dpp_se_as_as_etcam_ctrl_req0_cnt_t {
	u32 as_etcam_ctrl_req0_cnt;
};

struct dpp_se_as_etcam_ctrl_as_index0_1_cnt_t {
	u32 etcam_ctrl_as_index0_1_cnt;
};

struct dpp_se_as_etcam_ctrl_as_hit0_1_cnt_t {
	u32 etcam_ctrl_as_hit0_1_cnt;
};

struct dpp_se_as_as_smmu0_req_cnt_t {
	u32 as_smmu0_req_cnt;
};

struct dpp_se_as_learn_hla_wr_cnt_t {
	u32 learn_hla_wr_cnt;
};

struct dpp_se_as_as_smmu1_req_cnt_t {
	u32 as_smmu1_req_cnt;
};

struct dpp_se_as_se_cfg_mac_dat_cnt_t {
	u32 se_cfg_mac_dat_cnt;
};

struct dpp_se_as_alg_as_hash_p0_3_fc_cnt_t {
	u32 alg_as_hash_p0_3_fc_cnt;
};

struct dpp_se_as_alg_as_lpm_p0_fc_cnt_t {
	u32 alg_as_lpm_p0_fc_cnt;
};

struct dpp_se_as_as_alg_hash_p0_3_fc_cnt_t {
	u32 as_alg_hash_p0_3_fc_cnt;
};

struct dpp_se_as_as_alg_lpm_p0_fc_cnt_t {
	u32 as_alg_lpm_p0_fc_cnt;
};

struct dpp_se_as_as_pbu_fc_cnt_t {
	u32 as_pbu_fc_cnt;
};

struct dpp_se_as_pbu_se_dpi_key_fc_cnt_t {
	u32 pbu_se_dpi_key_fc_cnt;
};

struct dpp_se_as_as_etcam_ctrl_fc0_1_cnt_t {
	u32 as_etcam_ctrl_fc0_1_cnt;
};

struct dpp_se_as_etcam_ctrl_as_fc0_1_cnt_t {
	u32 etcam_ctrl_as_fc0_1_cnt;
};

struct dpp_se_as_smmu0_as_mac_age_fc_cnt_t {
	u32 smmu0_as_mac_age_fc_cnt;
};

struct dpp_se_as_alg_learn_fc_cnt_t {
	u32 alg_learn_fc_cnt;
};

struct dpp_se_as_smmu1_as_fc_cnt_t {
	u32 smmu1_as_fc_cnt;
};

struct dpp_se_as_cfg_se_mac_fc_cnt_t {
	u32 cfg_se_mac_fc_cnt;
};

struct dpp_se_kschd_kschd_cpu_rdy_t {
	u32 kschd_cpu_rdy;
};

struct dpp_se_kschd_ppu0_ecc_bypass_read_t {
	u32 ppu0_ecc_bypass_read;
};

struct dpp_se_kschd_pbu_ecc_bypass_read_t {
	u32 pbu_ecc_bypass_read;
};

struct dpp_se_kschd_smmu1_ecc_bypass_read_t {
	u32 u3_smmu1_ecc_bypass_read;
	u32 u2_smmu1_ecc_bypass_read;
	u32 u1_smmu1_ecc_bypass_read;
	u32 u0_smmu1_ecc_bypass_read;
};

struct dpp_se_kschd_ass_ecc_bypass_read_t {
	u32 ass_ecc_bypass_read;
};

struct dpp_se_kschd_sdt_h_t {
	u32 sdt_h;
};

struct dpp_se_kschd_sdt_l_t {
	u32 sdt_l;
};

struct dpp_se_kschd_hash_key15_t {
	u32 dma_en;
	u32 delete_en;
	u32 hash_key15;
};

struct dpp_se_kschd_hash_key14_t {
	u32 hash_key14;
};

struct dpp_se_kschd_hash_key13_t {
	u32 hash_key13;
};

struct dpp_se_kschd_hash_key12_t {
	u32 hash_key12;
};

struct dpp_se_kschd_hash_key11_t {
	u32 hash_key11;
};

struct dpp_se_kschd_hash_key10_t {
	u32 hash_key10;
};

struct dpp_se_kschd_hash_key9_t {
	u32 hash_key9;
};

struct dpp_se_kschd_hash_key8_t {
	u32 hash_key8;
};

struct dpp_se_kschd_hash_key7_t {
	u32 hash_key7;
};

struct dpp_se_kschd_hash_key6_t {
	u32 hash_key6;
};

struct dpp_se_kschd_hash_key5_t {
	u32 hash_key5;
};

struct dpp_se_kschd_hash_key4_t {
	u32 hash_key4;
};

struct dpp_se_kschd_hash_key3_t {
	u32 hash_key3;
};

struct dpp_se_kschd_hash_key2_t {
	u32 hash_key2;
};

struct dpp_se_kschd_hash_key1_t {
	u32 hash_key1;
};

struct dpp_se_kschd_hash_key0_t {
	u32 hash_key0;
};

struct dpp_se_kschd_schd_int_0_en_t {
	u32 port0_int_en;
};

struct dpp_se_kschd_schd_int_0_mask_t {
	u32 port0_int_mask;
};

struct dpp_se_kschd_schd_int_1_en_t {
	u32 port1_int_en;
};

struct dpp_se_kschd_schd_int_1_mask_t {
	u32 port1_int_mask;
};

struct dpp_se_kschd_schd_int_2_en_t {
	u32 port2_int_en;
};

struct dpp_se_kschd_schd_int_2_mask_t {
	u32 port2_int_mask;
};

struct dpp_se_kschd_schd_int_3_en_t {
	u32 port3_int_en;
};

struct dpp_se_kschd_schd_int_3_mask_t {
	u32 port3_int_mask;
};

struct dpp_se_kschd_schd_int_4_en_t {
	u32 port4_int_en;
};

struct dpp_se_kschd_schd_int_4_mask_t {
	u32 port4_int_mask;
};

struct dpp_se_kschd_schd_int_0_status_t {
	u32 port0_int_status;
};

struct dpp_se_kschd_schd_int_1_status_t {
	u32 port1_int_status;
};

struct dpp_se_kschd_schd_int_2_status_t {
	u32 port2_int_status;
};

struct dpp_se_kschd_schd_int_3_status_t {
	u32 port3_int_status;
};

struct dpp_se_kschd_schd_int_4_status_t {
	u32 port4_int_status;
};

struct dpp_se_kschd_se_kschd_int_status_t {
	u32 schd_int4_unmask_flag;
	u32 schd_int3_unmask_flag;
	u32 schd_int2_unmask_flag;
	u32 schd_int1_unmask_flag;
	u32 schd_int0_unmask_flag;
};

struct dpp_se_kschd_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_se_kschd_se_parser_kschd_key0_3_cnt_t {
	u32 se_parser_kschd_key0_3_cnt;
};

struct dpp_se_kschd_se_smmu1_key0_3_cnt_t {
	u32 se_smmu1_key0_3_cnt;
};

struct dpp_se_kschd_kschd_as_key0_cnt_t {
	u32 kschd_as_key0_cnt;
};

struct dpp_se_kschd_kschd_as_key1_cnt_t {
	u32 kschd_as_key1_cnt;
};

struct dpp_se_kschd_kschd_as_key2_cnt_t {
	u32 kschd_as_key2_cnt;
};

struct dpp_se_kschd_kschd_as_key3_cnt_t {
	u32 kschd_as_key3_cnt;
};

struct dpp_se_kschd_kschd_as_key4_cnt_t {
	u32 kschd_as_key4_cnt;
};

struct dpp_se_kschd_kschd_as_key5_cnt_t {
	u32 kschd_as_key5_cnt;
};

struct dpp_se_kschd_kschd_as_key6_cnt_t {
	u32 kschd_as_key6_cnt;
};

struct dpp_se_kschd_kschd_as_key9_cnt_t {
	u32 kschd_as_key9_cnt;
};

struct dpp_se_kschd_kschd_se_parser_fc0_3_cnt_t {
	u32 kschd_se_parser_fc0_3_cnt;
};

struct dpp_se_kschd_smmu1_se_fc0_3_cnt_t {
	u32 smmu1_se_fc0_3_cnt;
};

struct dpp_se_kschd_as_kschd_fc_cnt0_t {
	u32 as_kschd_fc_cnt0;
};

struct dpp_se_kschd_as_kschd_fc_cnt1_t {
	u32 as_kschd_fc_cnt1;
};

struct dpp_se_kschd_as_kschd_fc_cnt2_t {
	u32 as_kschd_fc_cnt2;
};

struct dpp_se_kschd_as_kschd_fc_cnt3_t {
	u32 as_kschd_fc_cnt3;
};

struct dpp_se_kschd_as_kschd_fc_cnt4_t {
	u32 as_kschd_fc_cnt4;
};

struct dpp_se_kschd_as_kschd_fc_cnt5_t {
	u32 as_kschd_fc_cnt5;
};

struct dpp_se_kschd_as_kschd_fc_cnt6_t {
	u32 as_kschd_fc_cnt6;
};

struct dpp_se_kschd_as_kschd_fc_cnt9_t {
	u32 as_kschd_fc_cnt9;
};

struct dpp_se_rschd_rschd_hash_pful_cfg_t {
	u32 rschd_hash_pful_cfg;
};

struct dpp_se_rschd_rschd_hash_ept_cfg_t {
	u32 rschd_hash_ept_cfg;
};

struct dpp_se_rschd_rschd_pbu_pful_cfg_t {
	u32 rschd_pbu_pful_cfg;
};

struct dpp_se_rschd_rschd_pbu_ept_cfg_t {
	u32 rschd_pbu_ept_cfg;
};

struct dpp_se_rschd_rschd_lpm_pful_cfg_t {
	u32 rschd_lpm_pful_cfg;
};

struct dpp_se_rschd_rschd_lpm_ept_cfg_t {
	u32 rschd_lpm_ept_cfg;
};

struct dpp_se_rschd_rschd_etcam_pful_cfg_t {
	u32 rschd_etcam_pful_cfg;
};

struct dpp_se_rschd_rschd_etcam_ept_cfg_t {
	u32 rschd_etcam_ept_cfg;
};

struct dpp_se_rschd_smmu0_wb_pful_cfg_t {
	u32 smmu0_wb_pful_cfg;
};

struct dpp_se_rschd_smmu0_wb_ept_cfg_t {
	u32 smmu0_wb_ept_cfg;
};

struct dpp_se_rschd_smmu1_wb_pful_cfg_t {
	u32 smmu1_wb_pful_cfg;
};

struct dpp_se_rschd_smmu1_wb_ept_cfg_t {
	u32 smmu1_wb_ept_cfg;
};

struct dpp_se_rschd_alg_wb_pful_cfg_t {
	u32 alg_wb_pful_cfg;
};

struct dpp_se_rschd_alg_wb_ept_cfg_t {
	u32 alg_wb_ept_cfg;
};

struct dpp_se_rschd_wr_rsp_vld_en_t {
	u32 wr_rsp_vld_en;
};

struct dpp_se_rschd_nppu_wb_pful_cfg_t {
	u32 nppu_wb_pful_cfg;
};

struct dpp_se_rschd_nppu_wb_ept_cfg_t {
	u32 nppu_wb_ept_cfg;
};

struct dpp_se_rschd_port0_int_en_t {
	u32 port0_int_en;
};

struct dpp_se_rschd_port0_int_mask_t {
	u32 port0_int_mask;
};

struct dpp_se_rschd_port1_int_en_t {
	u32 port1_int_en;
};

struct dpp_se_rschd_port1_int_mask_t {
	u32 port1_int_mask;
};

struct dpp_se_rschd_port0_int_status_t {
	u32 port0_int_status;
};

struct dpp_se_rschd_port1_int_status_t {
	u32 port1_int_status;
};

struct dpp_se_rschd_se_rschd_int_status_t {
	u32 port1_int_unmask_flag;
	u32 port0_int_unmask_flag;
};

struct dpp_se_rschd_debug_cnt_mode_t {
	u32 cnt_rd_mode;
	u32 cnt_overflow_mode;
};

struct dpp_se_rschd_se_ppu_mex0_5_rsp1_cnt_t {
	u32 se_ppu_mex0_5_rsp1_cnt;
};

struct dpp_se_rschd_as_rschd_rsp0_cnt_t {
	u32 as_rschd_rsp0_cnt;
};

struct dpp_se_rschd_as_rschd_rsp1_cnt_t {
	u32 as_rschd_rsp1_cnt;
};

struct dpp_se_rschd_as_rschd_rsp2_cnt_t {
	u32 as_rschd_rsp2_cnt;
};

struct dpp_se_rschd_as_rschd_rsp3_cnt_t {
	u32 as_rschd_rsp3_cnt;
};

struct dpp_se_rschd_as_rschd_rsp4_cnt_t {
	u32 as_rschd_rsp4_cnt;
};

struct dpp_se_rschd_as_rschd_rsp5_cnt_t {
	u32 as_rschd_rsp5_cnt;
};

struct dpp_se_rschd_as_rschd_rsp6_cnt_t {
	u32 as_rschd_rsp6_cnt;
};

struct dpp_se_rschd_as_rschd_rsp9_cnt_t {
	u32 as_rschd_rsp9_cnt;
};

struct dpp_se_rschd_smmu1_se_rsp0_3_cnt_t {
	u32 smmu1_se_rsp0_3_cnt;
};

struct dpp_se_rschd_ppu_se_mex0_3_fc_cnt_t {
	u32 ppu_se_mex0_3_fc_cnt;
};

struct dpp_se_rschd_rschd_as_fc_cnt0_t {
	u32 rschd_as_fc_cnt0;
};

struct dpp_se_rschd_rschd_as_fc_cnt1_t {
	u32 rschd_as_fc_cnt1;
};

struct dpp_se_rschd_rschd_as_fc_cnt2_t {
	u32 rschd_as_fc_cnt2;
};

struct dpp_se_rschd_rschd_as_fc_cnt3_t {
	u32 rschd_as_fc_cnt3;
};

struct dpp_se_rschd_rschd_as_fc_cnt4_t {
	u32 rschd_as_fc_cnt4;
};

struct dpp_se_rschd_rschd_as_fc_cnt5_t {
	u32 rschd_as_fc_cnt5;
};

struct dpp_se_rschd_rschd_as_fc_cnt6_t {
	u32 rschd_as_fc_cnt6;
};

struct dpp_se_rschd_rschd_as_fc_cnt9_t {
	u32 rschd_as_fc_cnt9;
};

struct dpp_se_rschd_se_smmu1_fc0_3_cnt_t {
	u32 se_smmu1_fc0_3_cnt;
};

struct dpp_se_rschd_smmu0_se_wr_done_cnt_t {
	u32 smmu0_se_wr_done_cnt;
};

struct dpp_se_rschd_se_smmu0_wr_done_fc_cnt_t {
	u32 se_smmu0_wr_done_fc_cnt;
};

struct dpp_se_rschd_smmu1_se_wr_rsp_cnt_t {
	u32 smmu1_se_wr_rsp_cnt;
};

struct dpp_se_rschd_se_smmu1_wr_rsp_fc_cnt_t {
	u32 se_smmu1_wr_rsp_fc_cnt;
};

struct dpp_se_rschd_alg_se_wr_rsp_cnt_t {
	u32 alg_se_wr_rsp_cnt;
};

struct dpp_se_rschd_se_alg_wr_rsp_fc_cnt_t {
	u32 se_alg_wr_rsp_fc_cnt;
};

#endif
