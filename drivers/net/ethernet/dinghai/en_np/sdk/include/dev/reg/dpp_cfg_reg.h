/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_CFG_REG_H_
#define _DPP_CFG_REG_H_
struct dpp_cfg_pcie_int_repeat_t {
	u32 int_repeat;
};

struct dpp_cfg_dma_dma_up_size_t {
	u32 dma_up_size;
};

struct dpp_cfg_csr_soc_wr_time_out_thresh_t {
	u32 soc_wr_time_out_thresh;
};

struct dpp_cfg_pcie_pcie_ddr_switch_t {
	u32 pcie_ddr_switch;
};

struct dpp_cfg_pcie_user0_int_en_t {
	u32 user_int_en;
};

struct dpp_cfg_pcie_user0_int_mask_t {
	u32 user_int_mask;
};

struct dpp_cfg_pcie_user0_int_status_t {
	u32 user_int_status;
};

struct dpp_cfg_pcie_user1_int_en_t {
	u32 user_int_en;
};

struct dpp_cfg_pcie_user1_int_mask_t {
	u32 user_int_mask;
};

struct dpp_cfg_pcie_user1_int_status_t {
	u32 user_int_status;
};

struct dpp_cfg_pcie_user2_int_en_t {
	u32 user_int_en;
};

struct dpp_cfg_pcie_user2_int_mask_t {
	u32 user_int_mask;
};

struct dpp_cfg_pcie_user2_int_status_t {
	u32 user_int_status;
};

struct dpp_cfg_pcie_ecc_1b_int_en_t {
	u32 ecc_1b_int_en;
};

struct dpp_cfg_pcie_ecc_1b_int_mask_t {
	u32 ecc_1b_int_mask;
};

struct dpp_cfg_pcie_ecc_1b_int_status_t {
	u32 ecc_1b_int_status;
};

struct dpp_cfg_pcie_ecc_2b_int_en_t {
	u32 ecc_2b_int_en;
};

struct dpp_cfg_pcie_ecc_2b_int_mask_t {
	u32 ecc_2b_int_mask;
};

struct dpp_cfg_pcie_ecc_2b_int_status_t {
	u32 ecc_2b_int_status;
};

struct dpp_cfg_pcie_cfg_int_status_t {
	u32 cfg_int_status;
};

struct dpp_cfg_pcie_i_core_to_cntl_t {
	u32 i_core_to_cntl;
};

struct dpp_cfg_pcie_test_in_low_t {
	u32 test_in_low;
};

struct dpp_cfg_pcie_test_in_high_t {
	u32 test_in_high;
};

struct dpp_cfg_pcie_local_interrupt_out_t {
	u32 local_interrupt_out;
};

struct dpp_cfg_pcie_pl_ltssm_t {
	u32 pl_ltssm;
};

struct dpp_cfg_pcie_test_out0_t {
	u32 test_out0;
};

struct dpp_cfg_pcie_test_out1_t {
	u32 test_out1;
};

struct dpp_cfg_pcie_test_out2_t {
	u32 test_out2;
};

struct dpp_cfg_pcie_test_out3_t {
	u32 test_out3;
};

struct dpp_cfg_pcie_test_out4_t {
	u32 test_out4;
};

struct dpp_cfg_pcie_test_out5_t {
	u32 test_out5;
};

struct dpp_cfg_pcie_test_out6_t {
	u32 test_out6;
};

struct dpp_cfg_pcie_test_out7_t {
	u32 test_out7;
};

struct dpp_cfg_pcie_sync_o_core_status_t {
	u32 sync_o_core_status;
};

struct dpp_cfg_pcie_sync_o_alert_dbe_t {
	u32 sync_o_alert_dbe;
};

struct dpp_cfg_pcie_sync_o_alert_sbe_t {
	u32 sync_o_alert_sbe;
};

struct dpp_cfg_pcie_sync_o_link_loopback_en_t {
	u32 sync_o_link_loopback_en;
};

struct dpp_cfg_pcie_sync_o_local_fs_lf_valid_t {
	u32 sync_o_local_fs_lf_valid;
};

struct dpp_cfg_pcie_sync_o_rx_idle_detect_t {
	u32 sync_o_rx_idle_detect;
};

struct dpp_cfg_pcie_sync_o_rx_rdy_t {
	u32 sync_o_rx_rdy;
};

struct dpp_cfg_pcie_sync_o_tx_rdy_t {
	u32 sync_o_tx_rdy;
};

struct dpp_cfg_pcie_pcie_link_up_cnt_t {
	u32 pcie_link_up_cnt;
};

struct dpp_cfg_pcie_test_out_pcie0_t {
	u32 test_out_pcie0;
};

struct dpp_cfg_pcie_test_out_pcie1_t {
	u32 test_out_pcie1;
};

struct dpp_cfg_pcie_test_out_pcie2_t {
	u32 test_out_pcie2;
};

struct dpp_cfg_pcie_test_out_pcie3_t {
	u32 test_out_pcie3;
};

struct dpp_cfg_pcie_test_out_pcie4_t {
	u32 test_out_pcie4;
};

struct dpp_cfg_pcie_test_out_pcie5_t {
	u32 test_out_pcie5;
};

struct dpp_cfg_pcie_test_out_pcie6_t {
	u32 test_out_pcie6;
};

struct dpp_cfg_pcie_test_out_pcie7_t {
	u32 test_out_pcie7;
};

struct dpp_cfg_pcie_test_out_pcie8_t {
	u32 test_out_pcie8;
};

struct dpp_cfg_pcie_test_out_pcie9_t {
	u32 test_out_pcie9;
};

struct dpp_cfg_pcie_test_out_pcie10_t {
	u32 test_out_pcie10;
};

struct dpp_cfg_pcie_test_out_pcie11_t {
	u32 test_out_pcie11;
};

struct dpp_cfg_pcie_test_out_pcie12_t {
	u32 test_out_pcie12;
};

struct dpp_cfg_pcie_test_out_pcie13_t {
	u32 test_out_pcie13;
};

struct dpp_cfg_pcie_test_out_pcie14_t {
	u32 test_out_pcie14;
};

struct dpp_cfg_pcie_test_out_pcie15_t {
	u32 test_out_pcie15;
};

struct dpp_cfg_pcie_int_repeat_en_t {
	u32 int_repeat_en;
};

struct dpp_cfg_pcie_dbg_awid_axi_mst_t {
	u32 dbg_awid_axi_mst;
};

struct dpp_cfg_pcie_dbg_awaddr_axi_mst0_t {
	u32 dbg_awaddr_axi_mst0;
};

struct dpp_cfg_pcie_dbg_awaddr_axi_mst1_t {
	u32 dbg_awaddr_axi_mst1;
};

struct dpp_cfg_pcie_dbg_awlen_axi_mst_t {
	u32 dbg_awlen_axi_mst;
};

struct dpp_cfg_pcie_dbg_awsize_axi_mst_t {
	u32 dbg_awid_axi_mst;
};

struct dpp_cfg_pcie_dbg_awburst_axi_mst_t {
	u32 dbg_awburst_axi_mst;
};

struct dpp_cfg_pcie_dbg_awlock_axi_mst_t {
	u32 dbg_awlock_axi_mst;
};

struct dpp_cfg_pcie_dbg_awcache_axi_mst_t {
	u32 dbg_awcache_axi_mst;
};

struct dpp_cfg_pcie_dbg_awprot_axi_mst_t {
	u32 dbg_awprot_axi_mst;
};

struct dpp_cfg_pcie_dbg_wid_axi_mst_t {
	u32 dbg_wid_axi_mst;
};

struct dpp_cfg_pcie_dbg_wdata_axi_mst0_t {
	u32 dbg_wdata_axi_mst0;
};

struct dpp_cfg_pcie_dbg_wdata_axi_mst1_t {
	u32 dbg_wdata_axi_mst1;
};

struct dpp_cfg_pcie_dbg_wdata_axi_mst2_t {
	u32 dbg_wdata_axi_mst2;
};

struct dpp_cfg_pcie_dbg_wdata_axi_mst3_t {
	u32 dbg_wdata_axi_mst3;
};

struct dpp_cfg_pcie_dbg_wstrb_axi_mst_t {
	u32 dbg_wstrb_axi_mst;
};

struct dpp_cfg_pcie_dbg_wlast_axi_mst_t {
	u32 dbg_wlast_axi_mst;
};

struct dpp_cfg_pcie_dbg_arid_axi_mst_t {
	u32 dbg_arid_axi_mst;
};

struct dpp_cfg_pcie_dbg_araddr_axi_mst0_t {
	u32 dbg_araddr_axi_mst0;
};

struct dpp_cfg_pcie_dbg_araddr_axi_mst1_t {
	u32 dbg_araddr_axi_mst1;
};

struct dpp_cfg_pcie_dbg_arlen_axi_mst_t {
	u32 dbg_arlen_axi_mst;
};

struct dpp_cfg_pcie_dbg_arsize_axi_mst_t {
	u32 dbg_arsize_axi_mst;
};

struct dpp_cfg_pcie_dbg_arburst_axi_mst_t {
	u32 dbg_arburst_axi_mst;
};

struct dpp_cfg_pcie_dbg_arlock_axi_mst_t {
	u32 dbg_arlock_axi_mst;
};

struct dpp_cfg_pcie_dbg_arcache_axi_mst_t {
	u32 dbg_arcache_axi_mst;
};

struct dpp_cfg_pcie_dbg_arprot_axi_mst_t {
	u32 dbg_arprot_axi_mst;
};

struct dpp_cfg_pcie_dbg_rdata_axi_mst0_t {
	u32 dbg_rdata_axi_mst0;
};

struct dpp_cfg_pcie_dbg_rdata_axi_mst1_t {
	u32 dbg_rdata_axi_mst1;
};

struct dpp_cfg_pcie_dbg_rdata_axi_mst2_t {
	u32 dbg_rdata_axi_mst2;
};

struct dpp_cfg_pcie_dbg_rdata_axi_mst3_t {
	u32 dbg_rdata_axi_mst3;
};

struct dpp_cfg_pcie_axi_mst_state_t {
	u32 axi_mst_state;
};

struct dpp_cfg_pcie_axi_cfg_state_t {
	u32 axi_cfg_state;
};

struct dpp_cfg_pcie_axi_slv_rd_state_t {
	u32 axi_slv_rd_state;
};

struct dpp_cfg_pcie_axi_slv_wr_state_t {
	u32 axi_slv_wr_state;
};

struct dpp_cfg_pcie_axim_delay_en_t {
	u32 axim_delay_en;
};

struct dpp_cfg_pcie_axim_delay_t {
	u32 axim_delay;
};

struct dpp_cfg_pcie_axim_speed_wr_t {
	u32 axim_speed_wr;
};

struct dpp_cfg_pcie_axim_speed_rd_t {
	u32 axim_speed_rd;
};

struct dpp_cfg_pcie_dbg_awaddr_axi_slv0_t {
	u32 dbg_awaddr_axi_slv0;
};

struct dpp_cfg_pcie_dbg_awaddr_axi_slv1_t {
	u32 dbg_awaddr_axi_slv1;
};

struct dpp_cfg_pcie_dbg0_wdata_axi_slv0_t {
	u32 dbg0_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg0_wdata_axi_slv1_t {
	u32 dbg0_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg0_wdata_axi_slv2_t {
	u32 dbg0_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg0_wdata_axi_slv3_t {
	u32 dbg0_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg1_wdata_axi_slv0_t {
	u32 dbg1_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg1_wdata_axi_slv1_t {
	u32 dbg1_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg1_wdata_axi_slv2_t {
	u32 dbg1_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg1_wdata_axi_slv3_t {
	u32 dbg1_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg2_wdata_axi_slv0_t {
	u32 dbg2_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg2_wdata_axi_slv1_t {
	u32 dbg2_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg2_wdata_axi_slv2_t {
	u32 dbg2_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg2_wdata_axi_slv3_t {
	u32 dbg2_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg3_wdata_axi_slv0_t {
	u32 dbg3_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg3_wdata_axi_slv1_t {
	u32 dbg3_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg3_wdata_axi_slv2_t {
	u32 dbg3_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg3_wdata_axi_slv3_t {
	u32 dbg3_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg4_wdata_axi_slv0_t {
	u32 dbg4_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg4_wdata_axi_slv1_t {
	u32 dbg4_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg4_wdata_axi_slv2_t {
	u32 dbg4_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg4_wdata_axi_slv3_t {
	u32 dbg4_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg5_wdata_axi_slv0_t {
	u32 dbg5_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg5_wdata_axi_slv1_t {
	u32 dbg5_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg5_wdata_axi_slv2_t {
	u32 dbg5_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg5_wdata_axi_slv3_t {
	u32 dbg5_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg6_wdata_axi_slv0_t {
	u32 dbg6_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg6_wdata_axi_slv1_t {
	u32 dbg6_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg6_wdata_axi_slv2_t {
	u32 dbg6_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg6_wdata_axi_slv3_t {
	u32 dbg6_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg7_wdata_axi_slv0_t {
	u32 dbg7_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg7_wdata_axi_slv1_t {
	u32 dbg7_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg7_wdata_axi_slv2_t {
	u32 dbg7_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg7_wdata_axi_slv3_t {
	u32 dbg7_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg8_wdata_axi_slv0_t {
	u32 dbg8_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg8_wdata_axi_slv1_t {
	u32 dbg8_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg8_wdata_axi_slv2_t {
	u32 dbg8_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg8_wdata_axi_slv3_t {
	u32 dbg8_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg9_wdata_axi_slv0_t {
	u32 dbg9_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg9_wdata_axi_slv1_t {
	u32 dbg9_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg9_wdata_axi_slv2_t {
	u32 dbg9_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg9_wdata_axi_slv3_t {
	u32 dbg9_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg_awlen_axi_slv_t {
	u32 dbg_awlen_axi_slv;
};

struct dpp_cfg_pcie_dbg_wlast_axi_slv_t {
	u32 dbg_wlast_axi_slv;
};

struct dpp_cfg_pcie_dbg_araddr_axi_slv0_t {
	u32 dbg5_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg_araddr_axi_slv1_t {
	u32 dbg5_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg0_rdata_axi_slv0_t {
	u32 dbg5_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg0_rdata_axi_slv1_t {
	u32 dbg6_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg0_rdata_axi_slv2_t {
	u32 dbg6_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg0_rdata_axi_slv3_t {
	u32 dbg6_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg1_rdata_axi_slv0_t {
	u32 dbg6_wdata_axi_slv3;
};

struct dpp_cfg_pcie_dbg1_rdata_axi_slv1_t {
	u32 dbg7_wdata_axi_slv0;
};

struct dpp_cfg_pcie_dbg1_rdata_axi_slv2_t {
	u32 dbg7_wdata_axi_slv1;
};

struct dpp_cfg_pcie_dbg1_rdata_axi_slv3_t {
	u32 dbg7_wdata_axi_slv2;
};

struct dpp_cfg_pcie_dbg_rlast_axi_slv_t {
	u32 dbg_rlast_axi_slv;
};

struct dpp_cfg_dma_dma_enable_t {
	u32 dma_enable;
};

struct dpp_cfg_dma_up_req_t {
	u32 up_req;
};

struct dpp_cfg_dma_dma_up_current_state_t {
	u32 dma_up_current_state;
};

struct dpp_cfg_dma_dma_up_req_ack_t {
	u32 dma_up_req_ack;
};

struct dpp_cfg_dma_dma_done_latch_t {
	u32 done_latch;
};

struct dpp_cfg_dma_dma_up_cpu_addr_low32_t {
	u32 dma_up_cpu_addr_low;
};

struct dpp_cfg_dma_dma_up_cpu_addr_high32_t {
	u32 dma_up_cpu_addr_high;
};

struct dpp_cfg_dma_dma_up_se_addr_t {
	u32 dma_up_se_addr;
};

struct dpp_cfg_dma_dma_done_int_t {
	u32 dma_done_int;
};

struct dpp_cfg_dma_sp_cfg_t {
	u32 sp_cfg;
};

struct dpp_cfg_dma_dma_ing_t {
	u32 dma_ing;
};

struct dpp_cfg_dma_rd_timeout_thresh_t {
	u32 rd_timeout_thresh;
};

struct dpp_cfg_dma_dma_tab_sta_up_fifo_gap_t {
	u32 dma_tab_sta_up_fifo_gap;
};

struct dpp_cfg_dma_cfg_mac_tim_t {
	u32 cfg_mac_tim;
};

struct dpp_cfg_dma_cfg_mac_num_t {
	u32 cfg_mac_num;
};

struct dpp_cfg_dma_init_bd_addr_t {
	u32 init_bd_addr;
};

struct dpp_cfg_dma_mac_up_bd_addr1_low32_t {
	u32 mac_up_bd_addr1_low32;
};

struct dpp_cfg_dma_mac_up_bd_addr1_high32_t {
	u32 mac_up_bd_addr1_high32;
};

struct dpp_cfg_dma_mac_up_bd_addr2_low32_t {
	u32 mac_up_bd_addr2_low32;
};

struct dpp_cfg_dma_mac_up_bd_addr2_high32_t {
	u32 mac_up_bd_addr2_high32;
};

struct dpp_cfg_dma_cfg_mac_max_num_t {
	u32 cfg_mac_max_num;
};

struct dpp_cfg_dma_dma_wbuf_ff_empty_t {
	u32 dma_wbuf_ff_empty;
};

struct dpp_cfg_dma_dma_wbuf_state_t {
	u32 dma_wbuf_state;
};

struct dpp_cfg_dma_dma_mac_bd_addr_low32_t {
	u32 dma_mac_bd_addr_low32;
};

struct dpp_cfg_dma_dma_mac_bd_addr_high32_t {
	u32 dma_mac_bd_addr_high32;
};

struct dpp_cfg_dma_mac_up_enable_t {
	u32 mac_up_enable;
};

struct dpp_cfg_dma_mac_endian_t {
	u32 mac_endian;
};

struct dpp_cfg_dma_up_endian_t {
	u32 up_endian;
};

struct dpp_cfg_dma_dma_up_rd_cnt_latch_t {
	u32 dma_up_rd_cnt_latch;
};

struct dpp_cfg_dma_dma_up_rcv_cnt_latch_t {
	u32 dma_up_rcv_cnt_latch;
};

struct dpp_cfg_dma_dma_up_cnt_latch_t {
	u32 dma_up_cnt_latch;
};

struct dpp_cfg_dma_cpu_rd_bd_pulse_t {
	u32 cpu_rd_bd_pulse;
};

struct dpp_cfg_dma_cpu_bd_threshold_t {
	u32 cpu_bd_threshold;
};

struct dpp_cfg_dma_cpu_bd_used_cnt_t {
	u32 cpu_bd_used_cnt;
};

struct dpp_cfg_dma_dma_up_rcv_status_t {
	u32 dma_up_rcv_status;
};

struct dpp_cfg_dma_slv_rid_err_en_t {
	u32 slv_rid_err_en;
};

struct dpp_cfg_dma_slv_rresp_err_en_t {
	u32 slv_rresp_err_en;
};

struct dpp_cfg_dma_se_rdbk_ff_full_t {
	u32 se_rdbk_ff_full;
};

struct dpp_cfg_dma_dma_up_data_count_t {
	u32 dma_up_data_count;
};

struct dpp_cfg_dma_dma_mwr_fifo_afull_gap_t {
	u32 dma_mwr_fifo_afull_gap;
};

struct dpp_cfg_dma_dma_info_fifo_afull_gap_t {
	u32 dma_mwr_fifo_afull_gap;
};

struct dpp_cfg_dma_dma_rd_timeout_set_t {
	u32 dma_rd_timeout_set;
};

struct dpp_cfg_dma_dma_bd_dat_err_en_t {
	u32 dma_bd_dat_err_en;
};

struct dpp_cfg_dma_dma_repeat_cnt_t {
	u32 dma_repeat_cnt;
};

struct dpp_cfg_dma_dma_rd_timeout_en_t {
	u32 dma_rd_timeout_en;
};

struct dpp_cfg_dma_dma_repeat_read_t {
	u32 dma_repeat_read;
};

struct dpp_cfg_dma_dma_repeat_read_en_t {
	u32 dma_repeat_read_en;
};

struct dpp_cfg_dma_bd_ctl_state_t {
	u32 bd_ctl_state;
};

struct dpp_cfg_dma_dma_done_int_cnt_wr_t {
	u32 dma_done_int_cnt_wr;
};

struct dpp_cfg_dma_dma_done_int_cnt_mac_t {
	u32 dma_done_int_cnt_mac;
};

struct dpp_cfg_dma_current_mac_num_t {
	u32 current_mac_num;
};

struct dpp_cfg_dma_cfg_mac_afifo_afull_t {
	u32 cfg_mac_afifo_afull;
};

struct dpp_cfg_dma_dma_mac_ff_full_t {
	u32 dma_mac_ff_full;
};

struct dpp_cfg_dma_user_axi_mst_t {
	u32 user_en;
	u32 cfg_epid;
	u32 cfg_vfunc_num;
	u32 cfg_func_num;
	u32 cfg_vfunc_active;
};

struct dpp_cfg_csr_sbus_state_t {
	u32 sbus_state;
};

struct dpp_cfg_csr_mst_debug_en_t {
	u32 mst_debug_en;
};

struct dpp_cfg_csr_sbus_command_sel_t {
	u32 sbus_command_sel;
};

struct dpp_cfg_csr_soc_rd_time_out_thresh_t {
	u32 soc_rd_time_out_thresh;
};

struct dpp_cfg_csr_big_little_byte_order_t {
	u32 big_little_byte_order;
};

struct dpp_cfg_csr_ecc_bypass_read_t {
	u32 ecc_bypass_read;
};

struct dpp_cfg_csr_ahb_async_wr_fifo_afull_gap_t {
	u32 ahb_async_wr_fifo_afull_gap;
};

struct dpp_cfg_csr_ahb_async_rd_fifo_afull_gap_t {
	u32 ahb_async_rd_fifo_afull_gap;
};

struct dpp_cfg_csr_ahb_async_cpl_fifo_afull_gap_t {
	u32 ahb_async_cpl_fifo_afull_gap;
};

struct dpp_cfg_csr_mst_debug_data0_high26_t {
	u32 mst_debug_data0_high26;
};

struct dpp_cfg_csr_mst_debug_data0_low32_t {
	u32 mst_debug_data0_low32;
};

struct dpp_cfg_csr_mst_debug_data1_high26_t {
	u32 mst_debug_data1_high26;
};

struct dpp_cfg_csr_mst_debug_data1_low32_t {
	u32 mst_debug_data1_low32;
};

struct dpp_cfg_csr_mst_debug_data2_high26_t {
	u32 mst_debug_data2_high26;
};

struct dpp_cfg_csr_mst_debug_data2_low32_t {
	u32 mst_debug_data2_low32;
};

struct dpp_cfg_csr_mst_debug_data3_high26_t {
	u32 mst_debug_data3_high26;
};

struct dpp_cfg_csr_mst_debug_data3_low32_t {
	u32 mst_debug_data3_low32;
};

struct dpp_cfg_csr_mst_debug_data4_high26_t {
	u32 mst_debug_data4_high26;
};

struct dpp_cfg_csr_mst_debug_data4_low32_t {
	u32 mst_debug_data4_low32;
};

struct dpp_cfg_csr_mst_debug_data5_high26_t {
	u32 mst_debug_data5_high26;
};

struct dpp_cfg_csr_mst_debug_data5_low32_t {
	u32 mst_debug_data5_low32;
};

struct dpp_cfg_csr_mst_debug_data6_high26_t {
	u32 mst_debug_data6_high26;
};

struct dpp_cfg_csr_mst_debug_data6_low32_t {
	u32 mst_debug_data6_low32;
};

struct dpp_cfg_csr_mst_debug_data7_high26_t {
	u32 mst_debug_data7_high26;
};

struct dpp_cfg_csr_mst_debug_data7_low32_t {
	u32 mst_debug_data7_low32;
};

struct dpp_cfg_csr_mst_debug_data8_high26_t {
	u32 mst_debug_data8_high26;
};

struct dpp_cfg_csr_mst_debug_data8_low32_t {
	u32 mst_debug_data8_low32;
};

struct dpp_cfg_csr_mst_debug_data9_high26_t {
	u32 mst_debug_data9_high26;
};

struct dpp_cfg_csr_mst_debug_data9_low32_t {
	u32 mst_debug_data9_low32;
};

struct dpp_cfg_csr_mst_debug_data10_high26_t {
	u32 mst_debug_data10_high26;
};

struct dpp_cfg_csr_mst_debug_data10_low32_t {
	u32 mst_debug_data10_low32;
};

struct dpp_cfg_csr_mst_debug_data11_high26_t {
	u32 mst_debug_data11_high26;
};

struct dpp_cfg_csr_mst_debug_data11_low32_t {
	u32 mst_debug_data11_low32;
};

struct dpp_cfg_csr_mst_debug_data12_high26_t {
	u32 mst_debug_data12_high26;
};

struct dpp_cfg_csr_mst_debug_data12_low32_t {
	u32 mst_debug_data12_low32;
};

struct dpp_cfg_csr_mst_debug_data13_high26_t {
	u32 mst_debug_data13_high26;
};

struct dpp_cfg_csr_mst_debug_data13_low32_t {
	u32 mst_debug_data13_low32;
};

struct dpp_cfg_csr_mst_debug_data14_high26_t {
	u32 mst_debug_data14_high26;
};

struct dpp_cfg_csr_mst_debug_data14_low32_t {
	u32 mst_debug_data14_low32;
};

struct dpp_cfg_csr_mst_debug_data15_high26_t {
	u32 mst_debug_data15_high26;
};

struct dpp_cfg_csr_mst_debug_data15_low32_t {
	u32 mst_debug_data15_low32;
};

#endif
