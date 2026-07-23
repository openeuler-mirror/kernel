/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PPU4K_REG_H_
#define _DPP_PPU4K_REG_H_
struct dpp_ppu4k_cluster_wr_high_data_r_mex_t {
	u32 wr_high_data_r_mex;
};

struct dpp_ppu4k_cluster_wr_low_data_r_mex_t {
	u32 wr_low_data_r_mex;
};

struct dpp_ppu4k_cluster_addr_r_mex_t {
	u32 operate_type;
	u32 addr_r_mex;
};

struct dpp_ppu4k_cluster_sdt_tbl_ind_access_done_t {
	u32 rd_addr_r_mex;
};

struct dpp_ppu4k_cluster_rd_high_data_r_mex_t {
	u32 rd_high_data_r_mex;
};

struct dpp_ppu4k_cluster_rd_low_data_r_mex_t {
	u32 rd_low_data_r_mex;
};

#endif
