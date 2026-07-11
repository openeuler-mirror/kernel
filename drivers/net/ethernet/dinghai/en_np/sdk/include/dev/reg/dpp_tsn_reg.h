/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_TSN_REG_H_
#define _DPP_TSN_REG_H_
struct dpp_tsn_tsn_port_cfg_tsn_test_reg_t {
	u32 cfg_tsn_test_reg;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_qbv_enable_t {
	u32 cfg_tsn_port_qbv_enable;
};

struct dpp_tsn_tsn_port_cfg_tsn_phy_port_sel_t {
	u32 cfg_tsn_phy_port_sel;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_time_sel_t {
	u32 cfg_tsn_port_time_sel;
};

struct dpp_tsn_tsn_port_cfg_tsn_clk_freq_t {
	u32 en;
	u32 cfg_tsn_clk_freq;
};

struct dpp_tsn_tsn_port_cfg_tsn_read_ram_n_t {
	u32 cfg_tsn_data;
	u32 cfg_tsn_read_status;
	u32 cfg_tsn_read_ram_n;
};

struct dpp_tsn_tsn_port_cfg_tsn_exe_time_t {
	u32 cfg_tsn_exe_time;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_itr_shift_t {
	u32 cfg_tsn_port_itr_shift;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_base_time_h_t {
	u32 cfg_tsn_port_base_time_h;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_base_time_l_t {
	u32 cfg_tsn_port_base_time_l;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_cycle_time_h_t {
	u32 cfg_tsn_port_cycle_time_h;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_cycle_time_l_t {
	u32 cfg_tsn_port_cycle_time_l;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_guard_band_time_t {
	u32 cfg_tsn_port_guard_band_time;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_default_gate_en_t {
	u32 cfg_tsn_port_default_gate_en;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_change_gate_en_t {
	u32 cfg_tsn_port_change_gate_en;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_init_finish_t {
	u32 cfg_tsn_port_init_finish;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_change_en_t {
	u32 cfg_tsn_port_change_en;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_gcl_num0_t {
	u32 cfg_tsn_port_gcl_num0;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_gcl_num1_t {
	u32 cfg_tsn_port_gcl_num1;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_gcl_value0_t {
	u32 cfg_tsn_port_gcl_gate_control0;
	u32 cfg_tsn_port_gcl_interval_time0;
};

struct dpp_tsn_tsn_port_cfg_tsn_port_gcl_value1_t {
	u32 cfg_tsn_port_gcl_gate_control1;
	u32 cfg_tsn_port_gcl_interval_time1;
};

#endif
