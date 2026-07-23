/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_AXI_REG_H_
#define _DPP_AXI_REG_H_
struct dpp_axi_axi_conv_cfg_epid_v_func_num_t {
	u32 user_en;
	u32 cfg_epid;
	u32 cfg_vfunc_num;
	u32 cfg_func_num;
	u32 cfg_vfunc_active;
};

struct dpp_axi_axi_conv_info_axim_rw_hsk_cnt_t {
	u32 axim_rd_handshake_cnt;
	u32 axim_wr_handshake_cnt;
};

struct dpp_axi_axi_conv_info_axim_last_wr_id_t {
	u32 axim_rd_id;
	u32 axim_wr_id;
};

struct dpp_axi_axi_conv_info_axim_last_wr_addr_h_t {
	u32 aximlastwraddrhigh;
};

struct dpp_axi_axi_conv_info_axim_last_wr_addr_l_t {
	u32 aximlastrdaddrlow;
};

struct dpp_axi_axi_conv_cfg_debug_info_clr_en_t {
	u32 cfg_global_clr_en;
};

#endif
