/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_TRPG_REG_H_
#define _DPP_TRPG_REG_H_
struct dpp_trpg_trpg_rx_port_cpu_trpg_ms_en_t {
	u32 cpu_trpgrx_ms_en;
};

struct dpp_trpg_trpg_rx_port_cpu_trpg_port_en_t {
	u32 cpu_trpgrx_port_en;
};

struct dpp_trpg_trpg_rx_port_cpu_trpg_look_en_t {
	u32 cpu_trpgrx_look_en;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_ram_almost_full_t {
	u32 cpu_trpgrx_ram_almost_full;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_ram_test_en_t {
	u32 cpu_trpgrx_ram_test_en;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_inmod_pfc_rdy_en_t {
	u32 cpu_trpgrx_inmod_pfc_rdy_en;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_num_h_t {
	u32 cpu_trpgrx_pkt_num_h;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_num_l_t {
	u32 cpu_trpgrx_pkt_num_l;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_byte_num_h_t {
	u32 cpu_trpgrx_pkt_byte_num_h;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_byte_num_l_t {
	u32 cpu_trpgrx_pkt_byte_num_l;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_cnt_clr_t {
	u32 cpu_trpgrx_pkt_cnt_clr;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_fc_clk_freq_t {
	u32 cpu_trpgrx_fc_clk_freq;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_fc_en_t {
	u32 cpu_trpgrx_fc_en;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_fc_token_add_num_t {
	u32 cpu_trpgrx_fc_token_add_num;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_fc_token_max_num_t {
	u32 cpu_trpgrx_fc_token_max_num;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_port_state_info_t {
	u32 cpu_trpgrx_port_state_info;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_ram_past_max_dep_t {
	u32 cpu_trpgrx_ram_past_max_dep;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_ram_past_max_dep_clr_t {
	u32 cpu_trpgrx_ram_past_max_dep_clr;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_past_max_len_t {
	u32 cpu_trpgrx_pkt_past_max_len;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_past_max_len_clr_t {
	u32 cpu_trpgrx_pkt_past_max_len_clr;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_past_min_len_t {
	u32 cpu_trpgrx_pkt_past_min_len;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_pkt_past_min_len_clr_t {
	u32 cpu_trpgrx_pkt_past_min_len_clr;
};

struct dpp_trpg_trpg_rx_ram_trpg_rx_data_ram_t {
	u32 trpg_rx_data_ram;
};

struct dpp_trpg_trpg_rx_ram_trpg_rx_info_ram_t {
	u32 trpg_rx_info_ram;
};

struct dpp_trpg_trpg_tx_port_cpu_trpg_ms_en_t {
	u32 cpu_trpgtx_ms_en;
};

struct dpp_trpg_trpg_tx_port_cpu_trpg_port_en_t {
	u32 cpu_trpgtx_port_en;
};

struct dpp_trpg_trpg_tx_port_cpu_trpg_look_en_t {
	u32 cpu_trpgtx_look_en;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_ram_almost_full_t {
	u32 cpu_trpgtx_ram_almost_full;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_ram_test_en_t {
	u32 cpu_trpgtx_ram_test_en;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_num_h_t {
	u32 cpu_trpgtx_pkt_num_h;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_num_l_t {
	u32 cpu_trpgtx_pkt_num_l;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_byte_num_h_t {
	u32 cpu_trpgtx_pkt_byte_num_h;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_byte_num_l_t {
	u32 cpu_trpgtx_pkt_byte_num_l;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_cnt_clr_t {
	u32 cpu_trpgtx_pkt_cnt_clr;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_fc_clk_freq_t {
	u32 cpu_trpgtx_fc_clk_freq;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_fc_en_t {
	u32 cpu_trpgtx_fc_en;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_fc_token_add_num_t {
	u32 cpu_trpgtx_fc_token_add_num;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_fc_token_max_num_t {
	u32 cpu_trpgtx_fc_token_max_num;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_port_state_info_t {
	u32 cpu_trpgtx_port_state_info;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_ram_past_max_dep_t {
	u32 cpu_trpgtx_ram_past_max_dep;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_ram_past_max_dep_clr_t {
	u32 cpu_trpgtx_ram_past_max_dep_clr;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_past_max_len_t {
	u32 cpu_trpgtx_pkt_past_max_len;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_past_max_len_clr_t {
	u32 cpu_trpgtx_pkt_past_max_len_clr;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_past_min_len_t {
	u32 cpu_trpgtx_pkt_past_min_len;
};

struct dpp_trpg_trpg_tx_port_cpu_trpgtx_pkt_past_min_len_clr_t {
	u32 cpu_trpgtx_pkt_past_min_len_clr;
};

struct dpp_trpg_trpg_tx_etm_port_cpu_trpgtx_etm_ram_almost_full_t {
	u32 cpu_trpgtx_etm_ram_almost_full;
};

struct dpp_trpg_trpg_tx_etm_port_cpu_trpgtx_etm_ram_test_en_t {
	u32 cpu_trpgtx_etm_ram_test_en;
};

struct dpp_trpg_trpg_tx_glb_cpu_todtime_update_int_mask_t {
	u32 cpu_todtime_update_int_mask;
};

struct dpp_trpg_trpg_tx_glb_cpu_todtime_update_int_clr_t {
	u32 cpu_todtime_update_int_clr;
};

struct dpp_trpg_trpg_tx_glb_cpu_todtime_ram_test_en_t {
	u32 cpu_todtime_ram_test_en;
};

struct dpp_trpg_trpg_tx_ram_trpg_tx_data_ram_t {
	u32 trpg_tx_data_ram;
};

struct dpp_trpg_trpg_tx_ram_trpg_tx_info_ram_t {
	u32 trpg_tx_info_ram;
};

struct dpp_trpg_trpg_tx_etm_ram_trpg_tx_etm_data_ram_t {
	u32 trpg_tx_etm_data_ram;
};

struct dpp_trpg_trpg_tx_etm_ram_trpg_tx_etm_info_ram_t {
	u32 trpg_tx_etm_info_ram;
};

struct dpp_trpg_trpg_rx_port_cpu_trpg_ms_st_t {
	u32 cpu_trpgrx_ms_st;
};

struct dpp_trpg_trpg_rx_port_cpu_trpg_ms_ind_t {
	u32 cpu_trpgrx_ms_ind;
};

struct dpp_trpg_trpg_rx_port_cpu_trpg_ms_slave_ind_t {
	u32 cpu_trpgrx_ms_slave_ind;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_up_water_level_t {
	u32 cpu_trpgrx_up_water_level;
};

struct dpp_trpg_trpg_rx_port_cpu_trpgrx_low_water_level_t {
	u32 cpu_trpgrx_low_water_level;
};

struct dpp_trpg_trpg_tx_port_cpu_trpg_ms_st_t {
	u32 cpu_trpgtx_ms_st;
};

struct dpp_trpg_trpg_tx_port_cpu_trpg_ms_ind_t {
	u32 cpu_trpgtx_ms_ind;
};

struct dpp_trpg_trpg_tx_port_cpu_trpg_ms_slave_ind_t {
	u32 cpu_trpgtx_ms_slave_ind;
};

struct dpp_trpg_trpg_tx_glb_cpu_todtime_update_int_event_t {
	u32 cpu_todtime_update_int_event;
};

struct dpp_trpg_trpg_tx_glb_cpu_todtime_update_int_test_t {
	u32 cpu_todtime_update_int_test;
};

struct dpp_trpg_trpg_tx_glb_cpu_todtime_update_int_addr_t {
	u32 cpu_todtime_update_int_addr;
};

struct dpp_trpg_trpg_tx_todtime_ram_trpg_tx_todtime_ram_t {
	u32 trpg_tx_todtime_ram;
};

#endif
