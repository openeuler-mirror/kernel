/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_SE4K_REG_H_
#define _DPP_SE4K_REG_H_
struct dpp_se4k_se_alg_cpu_cmd_rgt_t {
	u32 rd_flag;
	u32 mask;
	u32 reg_sram_flag;
	u32 zgroup_id;
	u32 zblock_id;
	u32 zcell_id;
	u32 addr;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp0_t {
	u32 cpu_wr_data_tmp0;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp1_t {
	u32 cpu_wr_data_tmp1;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp2_t {
	u32 cpu_wr_data_tmp2;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp3_t {
	u32 cpu_wr_data_tmp3;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp4_t {
	u32 cpu_wr_data_tmp4;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp5_t {
	u32 cpu_wr_data_tmp5;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp6_t {
	u32 cpu_wr_data_tmp6;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp7_t {
	u32 cpu_wr_data_tmp7;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp8_t {
	u32 cpu_wr_data_tmp8;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp9_t {
	u32 cpu_wr_data_tmp9;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp10_t {
	u32 cpu_wr_data_tmp10;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp11_t {
	u32 cpu_wr_data_tmp11;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp12_t {
	u32 cpu_wr_data_tmp12;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp13_t {
	u32 cpu_wr_data_tmp13;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp14_t {
	u32 cpu_wr_data_tmp14;
};

struct dpp_se4k_se_alg_cpu_wr_data_tmp15_t {
	u32 cpu_wr_data_tmp15;
};

struct dpp_se4k_se_alg_cpu_rd_rdy_t {
	u32 cpu_rd_rdy;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp0_t {
	u32 cpu_rd_data_tmp0;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp1_t {
	u32 cpu_rd_data_tmp1;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp2_t {
	u32 cpu_rd_data_tmp2;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp3_t {
	u32 cpu_rd_data_tmp3;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp4_t {
	u32 cpu_rd_data_tmp4;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp5_t {
	u32 cpu_rd_data_tmp5;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp6_t {
	u32 cpu_rd_data_tmp6;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp7_t {
	u32 cpu_rd_data_tmp7;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp8_t {
	u32 cpu_rd_data_tmp8;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp9_t {
	u32 cpu_rd_data_tmp9;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp10_t {
	u32 cpu_rd_data_tmp10;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp11_t {
	u32 cpu_rd_data_tmp11;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp12_t {
	u32 cpu_rd_data_tmp12;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp13_t {
	u32 cpu_rd_data_tmp13;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp14_t {
	u32 cpu_rd_data_tmp14;
};

struct dpp_se4k_se_alg_cpu_rd_data_tmp15_t {
	u32 cpu_rd_data_tmp15;
};

struct dpp_se4k_se_alg_hash0_ext_cfg_rgt_t {
	u32 hash0_ext_mode;
	u32 hash0_ext_flag;
};

struct dpp_se4k_se_alg_hash1_ext_cfg_rgt_t {
	u32 hash1_ext_mode;
	u32 hash1_ext_flag;
};

struct dpp_se4k_se_alg_hash2_ext_cfg_rgt_t {
	u32 hash2_ext_mode;
	u32 hash2_ext_flag;
};

struct dpp_se4k_se_alg_hash3_ext_cfg_rgt_t {
	u32 hash3_ext_mode;
	u32 hash3_ext_flag;
};

struct dpp_se4k_se_alg_hash0_tbl30_depth_t {
	u32 hash0_tbl3_depth;
	u32 hash0_tbl2_depth;
	u32 hash0_tbl1_depth;
	u32 hash0_tbl0_depth;
};

struct dpp_se4k_se_alg_hash0_tbl74_depth_t {
	u32 hash0_tbl7_depth;
	u32 hash0_tbl6_depth;
	u32 hash0_tbl5_depth;
	u32 hash0_tbl4_depth;
};

struct dpp_se4k_se_alg_hash1_tbl30_depth_t {
	u32 hash1_tbl3_depth;
	u32 hash1_tbl2_depth;
	u32 hash1_tbl1_depth;
	u32 hash1_tbl0_depth;
};

struct dpp_se4k_se_alg_hash1_tbl74_depth_t {
	u32 hash1_tbl7_depth;
	u32 hash1_tbl6_depth;
	u32 hash1_tbl5_depth;
	u32 hash1_tbl4_depth;
};

struct dpp_se4k_se_alg_hash2_tbl30_depth_t {
	u32 hash2_tbl3_depth;
	u32 hash2_tbl2_depth;
	u32 hash2_tbl1_depth;
	u32 hash2_tbl0_depth;
};

struct dpp_se4k_se_alg_hash2_tbl74_depth_t {
	u32 hash2_tbl7_depth;
	u32 hash2_tbl6_depth;
	u32 hash2_tbl5_depth;
	u32 hash2_tbl4_depth;
};

struct dpp_se4k_se_alg_hash3_tbl30_depth_t {
	u32 hash3_tbl3_depth;
	u32 hash3_tbl2_depth;
	u32 hash3_tbl1_depth;
	u32 hash3_tbl0_depth;
};

struct dpp_se4k_se_alg_hash3_tbl74_depth_t {
	u32 hash3_tbl7_depth;
	u32 hash3_tbl6_depth;
	u32 hash3_tbl5_depth;
	u32 hash3_tbl4_depth;
};

struct dpp_se4k_se_alg_wr_rsp_cfg_t {
	u32 wr_rsp_fifo_cfg;
};

struct dpp_se4k_se_alg_hash_mono_flag_t {
	u32 hash3_mono_flag;
	u32 hash2_mono_flag;
	u32 hash1_mono_flag;
	u32 hash0_mono_flag;
};

struct dpp_se4k_se_alg_hash10_ext_crc_cfg_t {
	u32 hash1_crc_cfg;
	u32 hash0_crc_cfg;
};

struct dpp_se4k_se_alg_hash32_ext_crc_cfg_t {
	u32 hash3_crc_cfg;
	u32 hash2_crc_cfg;
};

struct dpp_se4k_se_alg_zblock_service_configure_t {
	u32 service_sel;
	u32 hash_channel_sel;
	u32 st_en;
};

struct dpp_se4k_se_alg_zblock_hash_zcell_mono_t {
	u32 ha_zcell3_mono_flag;
	u32 ha_zcell3_tbl_id;
	u32 ha_zcell2_mono_flag;
	u32 ha_zcell2_tbl_id;
	u32 ha_zcell1_mono_flag;
	u32 ha_zcell1_tbl_id;
	u32 ha_zcell0_mono_flag;
	u32 ha_zcell0_tbl_id;
};

struct dpp_se4k_se_alg_zlock_hash_zreg_mono_t {
	u32 ha_zreg3_mono_flag;
	u32 ha_zreg3_tbl_id;
	u32 ha_zreg2_mono_flag;
	u32 ha_zreg2_tbl_id;
	u32 ha_zreg1_mono_flag;
	u32 ha_zreg1_tbl_id;
	u32 ha_zreg0_mono_flag;
	u32 ha_zreg0_tbl_id;
};

#endif
