/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_PHY_H_
#define _NBL_DEF_PHY_H_

#include "nbl_hw.h"

#define NBL_PHY_OPS_TBL_TO_OPS(phy_ops_tbl)		((phy_ops_tbl)->ops)
#define NBL_PHY_OPS_TBL_TO_PRIV(phy_ops_tbl)		((phy_ops_tbl)->priv)

struct nbl_phy_ops {
	int (*init_chip_module)(void *priv, u8 eth_speed, u8 eth_num);
	void (*set_driver_status)(void *priv, bool active);
	int (*get_firmware_version)(void *priv, char *firmware_version);
	enum nbl_board_type_enum (*get_board_type)(void *priv);
	int (*flow_init)(void *priv);
	int (*set_qid_map_table)(void *priv, void *data, int qid_map_select);
	int (*set_qid_map_ready)(void *priv, bool ready);
	int (*cfg_ipro_queue_tbl)(void *priv, u16 queue_id, u16 vsi_id, u8 enable);
	int (*cfg_ipro_dn_sport_tbl)(void *priv, u16 vsi_id, u16 dst_eth_id, u16 bmode, bool binit);
	int (*set_vnet_queue_info)(void *priv, struct nbl_vnet_queue_info_param *param,
				   u16 queue_id);
	int (*clear_vnet_queue_info)(void *priv, u16 queue_id);
	int (*cfg_vnet_qinfo_log)(void *priv, u16 queue_id, bool vld);
	int (*reset_dvn_cfg)(void *priv, u16 queue_id);
	int (*reset_uvn_cfg)(void *priv, u16 queue_id);
	int (*restore_dvn_context)(void *priv, u16 queue_id, u16 split, u16 last_avail_index);
	int (*restore_uvn_context)(void *priv, u16 queue_id, u16 split, u16 last_avail_index);
	int (*get_tx_queue_cfg)(void *priv, void *data, u16 queue_id);
	int (*get_rx_queue_cfg)(void *priv, void *data, u16 queue_id);
	int (*cfg_tx_queue)(void *priv, void *data, u16 queue_id);
	int (*cfg_rx_queue)(void *priv, void *data, u16 queue_id);
	bool (*check_q2tc)(void *priv, u16 queue_id);
	int (*cfg_q2tc_netid)(void *priv, u16 queue_id, u16 netid, u16 vld);
	int (*cfg_q2tc_tcid)(void *priv, u16 queue_id, u16 tcid);
	int (*set_tc_wgt)(void *priv, u16 func_id, u8 *weight, u16 num_tc);
	int (*set_tc_spwrr)(void *priv, u16 func_id, u8 spwrr);
	int (*set_shaping)(void *priv, u16 func_id, u64 total_tx_rate, u64 burst,
			   u8 vld, bool active);
	void (*active_shaping)(void *priv, u16 func_id);
	void (*deactive_shaping)(void *priv, u16 func_id);
	int (*set_ucar)(void *priv, u16 func_id, u64 total_tx_rate, u64 burst,
			u8 vld);
	int (*cfg_dsch_net_to_group)(void *priv, u16 func_id, u16 group_id, u16 vld);
	int (*cfg_dsch_group_to_port)(void *priv, u16 group_id, u16 class_id, u16 dport, u16 vld);
	int (*init_epro_rss_key)(void *priv, u16 table_id);
	void (*get_vsi_rss_key)(void *priv, u16 vsi_id, u8 *rss_key);
	int (*get_rss_key)(void *priv, u8 *rss_key, u16 table_id);
	int (*set_rss_key)(void *priv, const u8 *rss_key, u16 table_id);
	void (*get_rss_hash_key_sel)(void *priv, u16 vsi_id, u8 *rss_hash_key_sel);
	int (*set_rss_hash_key_sel)(void *priv, u16 vsi_id, u8 rss_hash_key_sel);
	void (*read_rss_indir)(void *priv, u16 vsi_id, u32 *rss_indir,
			       u16 rss_ret_base, u16 rss_entry_size);
	void (*get_rss_alg_sel)(void *priv, u16 vsi_id, u8 eth_id, u8 *rss_alg_sel);
	int (*set_rss_alg_sel)(void *priv, u16 vsi_id, u8 alg_sel);
	int (*get_rss_hash_tmpt_sel)(void *priv, u16 vsi_id, int flow_type, u64 *tempt_sel);
	int (*set_rss_hash_tmpt_sel)(void *priv, u16 vsi_id, int flow_type, u64 tempt_sel);
	int (*init_epro_vpt_tbl)(void *priv, u16 vsi_id, u16 bmode, bool binit,
				 u16 rss_key_range_oft);
	int (*set_epro_rss_default)(void *priv, u16 vsi_id, u16 rss_key_range_oft);
	int (*cfg_epro_rss_ret)(void *priv, u32 index, u16 size_unit, u8 size_type,
				u32 q_num, u16 *queue_list, const u32 *indir);
	int (*set_epro_rss_ret)(void *priv, u32 index, u16 global_queue_id);
	int (*get_epro_rss_ret)(void *priv, u32 index, u16 size_unit, u8 size_type, u32 *indir);
	int (*set_epro_rss_pt)(void *priv, u16 vsi_id, u16 rss_ret_base, u16 rss_entry_size);
	int (*clear_epro_rss_pt)(void *priv, u16 vsi_id);
	int (*disable_dvn)(void *priv, u16 queue_id);
	int (*disable_uvn)(void *priv, u16 queue_id);
	int (*lso_dsch_drain)(void *priv, u16 queue_id);
	int (*rsc_cache_drain)(void *priv, u16 queue_id);
	u64 (*save_dvn_ctx)(void *priv, u16 queue_id, u16 split);
	u64 (*save_uvn_ctx)(void *priv, u16 queue_id, u16 split, u16 queue_size);
	void (*get_rx_queue_err_stats)(void *priv, u16 queue_id,
				       struct nbl_queue_err_stats *queue_err_stats);
	void (*get_tx_queue_err_stats)(void *priv, u16 queue_id,
				       struct nbl_queue_err_stats *queue_err_stats);
	void (*setup_queue_switch)(void *priv, u16 eth_id);
	void (*init_pfc)(void *priv, u8 eth_id, u8 ether_ports, u8 pfc_mode, u8 bp_mode);
	int (*cfg_phy_flow)(void *priv, u16 vsi_id, u16 count, u8 eth_id,
			    bool status, u16 rss_key_range_oft);
	int (*cfg_eth_port_priority_replace)(void *priv, u8 eth_id, bool status);
	int (*get_chip_temperature)(void *priv, enum nbl_hwmon_type type, u32 senser_id);
	int (*get_module_temperature)(void *priv, u8 eth_id, enum nbl_hwmon_type type);
	void (*cfg_lacp_lldp)(void *priv, bool lldp_or_lacp, bool enable, u16 vsi_id);

	int (*cfg_epro_vpt_tbl)(void *priv, u16 vsi_id);
	void (*set_promisc_mode)(void *priv, u16 vsi_id, u16 eth_id, u16 mode);
	void (*configure_msix_map)(void *priv, u16 func_id, bool valid, dma_addr_t dma_addr,
				   u8 bus, u8 devid, u8 function);
	void (*configure_msix_info)(void *priv, u16 func_id, bool valid, u16 interrupt_id,
				    u8 bus, u8 devid, u8 function, bool net_msix_mask_en);
	void (*get_msix_resource)(void *priv, u16 func_id, u16 *msix_base);
	void (*get_coalesce)(void *priv, u16 interrupt_id, u16 *pnum, u16 *rate);
	void (*set_coalesce)(void *priv, u16 interrupt_id, u16 pnum, u16 rate);
	void (*set_msix_fast_restrain)(void *priv, u16 interrupt_id, u16 pnum, u16 rate);
	void (*write_ped_tbl)(void *priv, u8 *data, u16 idx, u32 ped_type);
	void (*dump_mailbox_dbg)(void *priv);
	void (*update_mailbox_queue_tail_ptr)(void *priv, u16 tail_ptr, u8 txrx);
	void (*config_mailbox_rxq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*config_mailbox_txq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*config_mailbox_txq_rst)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*stop_mailbox_rxq)(void *priv);
	void (*stop_mailbox_txq)(void *priv);
	u16 (*get_mailbox_rx_tail_ptr)(void *priv);
	bool (*check_mailbox_dma_err)(void *priv, bool tx);
	u32 (*get_host_pf_mask)(void *priv, u8 func_id);
	u32 (*get_host_pf_fid)(void *priv, u8 func_id);
	u32 (*get_real_bus)(void *priv);
	u64 (*get_pf_bar_addr)(void *priv, u16 func_id);
	u64 (*get_vf_bar_addr)(void *priv, u16 func_id);
	void (*cfg_mailbox_qinfo)(void *priv, u16 func_id, u16 bus, u16 devid, u16 function);
	void (*enable_mailbox_irq)(void *priv, u16 func_id, bool enable_msix, u16 global_vector_id);
	void (*enable_abnormal_irq)(void *priv, bool enable_msix, u16 global_vector_id);
	void (*enable_sfp_plug_irq)(void *priv, bool enable_msix, u16 global_vector_id);
	void (*enable_msix_irq)(void *priv, u16 global_vector_id);
	u8 *(*get_msix_irq_enable_info)(void *priv, u16 global_vector_id,
					u32 *irq_data, u32 *irq_mask_data);
	void (*config_adminq_rxq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*config_adminq_txq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*stop_adminq_rxq)(void *priv);
	void (*stop_adminq_txq)(void *priv);
	void (*cfg_adminq_qinfo)(void *priv, u16 bus, u16 devid, u16 function);
	void (*enable_adminq_irq)(void *priv, bool enable_msix, u16 global_vector_id);
	void (*update_adminq_queue_tail_ptr)(void *priv, u16 tail_ptr, u8 txrx);
	u16 (*get_adminq_rx_tail_ptr)(void *priv);
	bool (*check_adminq_dma_err)(void *priv, bool tx);
	void (*update_tail_ptr)(void *priv, struct nbl_notify_param *param);
	u8* (*get_tail_ptr)(void *priv);
	int (*set_spoof_check_addr)(void *priv, u16 vsi_id, u8 *mac);
	int (*set_spoof_check_enable)(void *priv, u16 vsi_id, u8 enable);
	int (*set_vsi_mtu)(void *priv, u16 vsi_id, u16 mtu_sel);
	u8 __iomem * (*get_hw_addr)(void *priv, size_t *size);
	u8 __iomem * (*get_rdma_hw_addr)(void *priv);
	int (*set_lag_status)(void *priv, bool lag_en);
	int (*enable_lldp_protocol)(void *priv, u16 eth_id, void *data);
	int (*enable_lag_protocol)(void *priv, u16 eth_id, void *data);
	int (*cfg_lag_hash_algorithm)(void *priv, u16 eth_id, u16 lag_id,
				      enum netdev_lag_hash hash_type);
	int (*cfg_lag_member_fwd)(void *priv, u16 eth_id, u16 lag_id, u8 fwd);
	int (*set_sfp_state)(void *priv, u8 eth_id, u8 state);
	int (*cfg_lag_member_list)(void *priv, struct nbl_lag_member_list_param *param);
	int (*cfg_lag_member_up_attr)(void *priv, u16 eth_id, u16 lag_id, bool enable);
	int (*cfg_lag_mcc)(void *priv, u16 mcc_id, u16 action);
	bool (*get_lag_fwd)(void *priv, u16 eth_id);

	int (*cfg_bond_shaping)(void *priv, u8 eth_id, u8 speed, bool enable);
	void (*cfg_bgid_back_pressure)(void *priv, u8 main_eth_id, u8 other_eth_id,
				       bool enable, u8 speed);
	void (*clear_acl)(void *priv, u16 tcam_start_idx, u16 tcam_end_idx);
	void (*clear_acl_rdma)(void *priv, u16 tcam_start_idx, u16 tcam_end_idx);
	void (*cfg_eth_shaping)(void *priv, u8 eth_id, u32 speed);
	int (*set_fd_udf)(void *priv, u8 lxmode, u8 offset);
	int (*clear_fd_udf)(void *priv);
	int (*set_fd_tcam_cfg_default)(void *priv);
	int (*set_rdma_tcam_cfg_default)(void *priv, u8 profile_id, u8 tcam_id);
	int (*set_fd_tcam_cfg_lite)(void *priv);
	int (*set_fd_tcam_cfg_full)(void *priv);
	int (*set_fd_tcam_ram)(void *priv, struct nbl_acl_tcam_param *data,
			       struct nbl_acl_tcam_param *mask, u16 ram_index, u32 depth_index);
	int (*set_rdma_tcam_ram)(void *priv, struct nbl_acl_tcam_param *data,
				 struct nbl_acl_tcam_param *mask, u16 ram_index, u32 depth_index);
	int (*set_fd_action_ram)(void *priv, u32 *action, u16 ram_index, u32 depth_index);
	void (*set_hw_status)(void *priv, enum nbl_hw_status hw_status);
	void (*check_hw_status)(void *priv);
	enum nbl_hw_status (*get_hw_status)(void *priv);
	int (*set_mtu)(void *priv, u16 vsi_id, u16 mtu);
	u16 (*get_mtu_index)(void *priv, u16 vsi_id);
	void (*cfg_vlan_filtering)(void *priv, bool filter);

	/* For leonis */
	int (*lookup_key)(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			  u8 *resp_head, u8 *resp_data);
	int (*alloc_kt)(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			u8 *resp_head, u8 *resp_data);
	int (*free_kt)(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
		       u8 *resp_head, u8 *resp_data);
	int (*add_kt)(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
		      u8 *resp_head, u8 *resp_data);
	int (*del_ht_oft)(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			  u8 *resp_head, u8 *resp_data);
	int (*init_mcc)(void *priv, u16 mcc_id);
	void (*clear_mcc)(void *priv, u16 mcc_id);

	int (*set_ht)(void *priv, u16 hash, u16 hash_other, u8 ht_table,
		      u8 bucket, u32 key_index, u8 valid);
	int (*set_kt)(void *priv, u8 *key, u32 key_index, u8 key_type);
	int (*search_key)(void *priv, u8 *key, u8 key_type);
	int (*add_tcam)(void *priv, u32 index, u8 *key, u32 *action, u8 key_type, u8 pp_type);
	void (*del_tcam)(void *priv, u32 index, u8 key_type, u8 pp_type);
	int (*add_mcc)(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id,
		       u16 action, u8 eth_id, u16 vsi_id);
	void (*del_mcc)(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id,
			u8 eth_id, u16 vsi_id);
	void (*update_mcc_next_node)(void *priv, u16 mcc_id, u16 next_mcc_id);
	int (*add_tnl_encap)(void *priv, const u8 encap_buf[], u16 encap_idx,
			     union nbl_flow_encap_offset_tbl_u encap_idx_info);
	void (*del_tnl_encap)(void *priv, u16 encap_idx);
	void (*set_decap_set)(void *priv, u8 *mac, u16 vlan_0, u16 vlan_1,
			      u8 vlan_layer, u8 idx, u8 is_add, u16 vsi_id);
	int (*init_fem)(void *priv);
	void (*init_acl)(void *priv);
	void (*uninit_acl)(void *priv);
	int (*set_upcall_rule)(void *priv, u8 idx, u16 vsi_id);
	int (*unset_upcall_rule)(void *priv, u8 idx);
	void (*set_shaping_dport_vld)(void *priv, u8 eth_id, bool vld);
	void (*set_dport_fc_th_vld)(void *priv, u8 eth_id, bool vld);
	void (*cfg_ktls_tx_keymat)(void *priv, u32 index, u8 mode, u8 *salt, u8 *key, u8 key_len);
	void (*cfg_ktls_rx_keymat)(void *priv, u32 index, u8 mode, u8 *salt, u8 *key, u8 key_len);
	void (*cfg_ktls_rx_record)(void *priv, u32 index, u32 tcp_sn, u64 rec_num, bool init);
	int (*init_acl_stats)(void *priv);

	void (*cfg_dipsec_nat)(void *priv, u16 sport);
	void (*cfg_dipsec_sad_iv)(void *priv, u32 index, u64 iv);
	void (*cfg_dipsec_sad_esn)(void *priv, u32 index, u32 sn, u32 esn, u8 wrap_en, u8 enable);
	void (*cfg_dipsec_sad_lifetime)(void *priv, u32 index, u32 lft_cnt,
					u32 lft_diff, u8 limit_enable, u8 limit_type);
	void (*cfg_dipsec_sad_crypto)(void *priv, u32 index, u32 *key, u32 salt,
				      u32 crypto_type, u8 tunnel_mode, u8 icv_len);
	void (*cfg_dipsec_sad_encap)(void *priv, u32 index, u8 nat_flag,
				     u16 dport, u32 spi, u32 *ip_data);
	u32 (*read_dipsec_status)(void *priv);
	u32 (*reset_dipsec_status)(void *priv);
	u32 (*read_dipsec_lft_info)(void *priv);
	void (*cfg_dipsec_lft_info)(void *priv, u32 index, u32 lifetime_diff,
				    u32 flag_wen, u32 msb_wen);
	void (*init_dprbac)(void *priv);
	void (*cfg_uipsec_nat)(void *priv, u8 nat_flag, u16 dport);
	void (*cfg_uipsec_sad_esn)(void *priv, u32 index, u32 sn, u32 esn, u8 overlap, u8 enable);
	void (*cfg_uipsec_sad_lifetime)(void *priv, u32 index, u32 lft_cnt,
					u32 lft_diff, u8 limit_enable, u8 limit_type);
	void (*cfg_uipsec_sad_crypto)(void *priv, u32 index, u32 *key, u32 salt,
				      u32 crypto_type, u8 tunnel_mode, u8 icv_len);
	void (*cfg_uipsec_sad_window)(void *priv, u32 index, u8 window_en, u8 option);
	void (*cfg_uipsec_em_tcam)(void *priv, u16 tcam_index, u32 *data);
	void (*cfg_uipsec_em_ad)(void *priv, u16 tcam_index, u32 index);
	void (*clear_uipsec_tcam_ad)(void *priv, u16 tcam_index);
	void (*cfg_uipsec_em_ht)(void *priv, u32 index, u16 ht_table, u16 ht_index,
				 u16 ht_other_index, u16 ht_bucket);
	void (*cfg_uipsec_em_kt)(void *priv, u32 index, u32 *data);
	void (*clear_uipsec_ht_kt)(void *priv, u32 index, u16 ht_table,
				   u16 ht_index, u16 ht_bucket);
	void (*cfg_uipsec_em_cmd)(void *priv, u8 *data);
	u32 (*read_uipsec_status)(void *priv);
	u32 (*reset_uipsec_status)(void *priv);
	u32 (*read_uipsec_lft_info)(void *priv);
	void (*cfg_uipsec_lft_info)(void *priv, u32 index, u32 lifetime_diff,
				    u32 flag_wen, u32 msb_wen);
	void (*init_uprbac)(void *priv);

	u32 (*get_fw_ping)(void *priv);
	void (*set_fw_ping)(void *priv, u32 ping);
	u32 (*get_fw_pong)(void *priv);
	void (*set_fw_pong)(void *priv, u32 pong);

	int (*init_vdpaq)(void *priv, u16 func_id, u16 bdf, u64 pa, u32 size);
	void (*destroy_vdpaq)(void *priv, u16 func_id);

	void (*get_reg_dump)(void *priv, u32 *data, u32 len);
	int (*get_reg_dump_len)(void *priv);
	int (*process_abnormal_event)(void *priv,
				      struct nbl_abnormal_event_info *abnomal_info);
	int (*process_sfp_plug_event)(void *priv, u8 eth_id);
	u32 (*get_uvn_desc_entry_stats)(void *priv);
	void (*set_uvn_desc_wr_timeout)(void *priv, u16 timeout);
	void (*set_tc_kgen_cvlan_zero)(void *priv);
	void (*unset_tc_kgen_cvlan)(void *priv);
	void (*set_ped_tab_vsi_type)(void *priv, u32 port_id, u16 eth_proto);
	void (*load_p4)(void *priv, u32 addr, u32 size, u8 *data);
	void (*configure_qos)(void *priv, u8 eth_id, u8 *pfc, u8 trust, u8 *dscp2prio_map);
	void (*configure_rdma_bw)(void *priv, u8 eth_id, int rdma_bw);
	void (*get_pfc_buffer_size)(void *priv, u8 eth_id, u8 prio, int *xoff, int *xon);
	int (*set_pfc_buffer_size)(void *priv, u8 eth_id, u8 prio, int xoff, int xon);
	void (*set_rate_limit)(void *priv, u16 func_id, enum nbl_traffic_type type, u32 rate);
	int (*get_dstat_vsi_stat)(void *priv, u16 vsi_id, u64 *fwd_pkt, u64 *fwd_byte);
	int (*get_ustat_vsi_stat)(void *priv, u16 vsi_id, u64 *fwd_pkt, u64 *fwd_byte);
	int (*get_uvn_pkt_drop_stats)(void *priv, u16 global_queue_id, u32 *uvn_stat_pkt_drop);
	int (*get_uvn_drop_queue_disable)(void *priv, u32 *uvn_drop_queue_disable);
	int (*get_ustore_pkt_drop_stats)(void *priv, u8 eth_id,
					 struct nbl_chan_param_drop_stats_resp *drop_stats);
	u32 (*get_fake_drop_stats)(void *priv);
	void (*set_qinfo_tx)(void *priv, u16 func_id, dma_addr_t dma_addr, u32 size_bwid);
	void (*get_qinfo_tx)(void *priv, u16 func_id, dma_addr_t *dma_addr, u32 *size_bwid);
	/* For bootis */
	int (*add_mv_tbl)(void *priv, u16 vsi, const void *key, const void *act, u16 result_idx);
	int (*del_mv_tbl)(void *priv, const void *key);
	int (*search_mv_tbl)(void *priv, const void *key, u8 *act);
	int (*modify_mv_tbl)(void *priv, const void *key, const void *act);
	int (*cfg_rss_alg)(void *priv, u16 vsi, const void *param);
	void (*cfg_padpt_txrx_enable)(void *priv, bool tx_enable, bool rx_enable);
	int (*enable_port)(void *priv, bool enable);
	int (*setup_loopback)(void *priv, u32 eth_id, u32 enable, bool set_all_lane);
	int (*init_port)(void *priv);
	int (*init_fec)(void *priv);
	bool (*sfp_is_present)(void *priv, u32 eth_id);
	int (*read_i2c_begin)(void *priv, u32 eth_id);
	int (*read_i2c_end)(void *priv, u32 eth_id);
	int (*read_i2c)(void *priv, u32 eth_id, u32 addr, u32 *rdata, bool turn_page);
	int (*read_i2c_by_page)(void *priv, u32 eth_id, struct nbl_ethtool_module_eeprom *eeprom,
				u32 offset, u32 length, u8 *rdata);
	int (*get_eth_mac_address)(void *priv, u32 eth_id, u8 *mac_addr);
	int (*get_part_number)(void *priv, char *part_number);
	int (*get_serial_number)(void *priv, char *serial_number);
	int (*ctrl_port_led)(void *priv, u8 eth_id, enum nbl_led_reg_ctrl led_ctrl, u32 *led_reg);
	int (*get_port_info)(void *priv, u8 eth_id, struct nbl_port_state *port_state);
	int (*set_eth_mac_addr)(void *priv, u8 *mac, u8 eth_id);
	int (*set_eth_pause_enable)(void *priv, u8 eth_id, u8 is_tx, bool enable);
	int (*nway_reset)(void *priv, u8 eth_id);
	int (*get_sfp_type)(void *priv, u16 eth_id, enum nbl_sfp_type *sfp_type);
	int (*get_eth_serdes_type)(void *priv);
	int (*reset_eth_rx_adaption)(void *priv, u8 eth_id);

	/* for board cfg */
	u32 (*get_fw_eth_num)(void *priv);
	u32 (*get_fw_eth_map)(void *priv);
	void (*get_board_info)(void *priv, struct nbl_board_port_info *board);
	u32 (*get_quirks)(void *priv);

	/* for userspace */
	int (*init_offload_fwd)(void *priv, u16 vsi_id);
	int (*init_cmdq)(void *priv, void *data, u16 func_id);
	int (*reset_cmdq)(void *priv, void *param);
	int (*destroy_cmdq)(void *priv);
	void (*update_cmdq_tail)(void *priv, u32 doorbell);
	int (*init_rep)(void *priv, u16 vsi_id, u8 inner_type,
			u8 outer_type, u8 rep_type, u16 rss_key_range_oft);
	int (*init_flow)(void *priv, void *data);
	int (*deinit_flow)(void *priv);
	int (*offload_flow_rule)(void *priv, void *data);
	int (*get_flow_acl_switch)(void *priv, u8 *acl_enable);
	void (*get_line_rate_info)(void *priv, void *data, void *result);
	void (*set_eth_stats_snapshot)(void *priv, u32 eth_id, u8 snapshot);
	void (*get_eth_ip_reg)(void *priv, u32 eth_id, u64 addr_off, u32 *data);
	int (*set_eth_fec_mode)(void *priv, u32 eth_id, enum nbl_port_mode mode);
	void (*get_eth_statistics)(void *priv, u32 eth_id,
				   enum nbl_get_eth_statistics_type type, void *data);
	int (*cfg_eth_mode)(void *priv, u8 eth_id, enum nbl_port_mode mode);
	int (*get_link_state)(void *priv, u8 eth_id, u8 *link_state);
	void (*clear_profile_table_action)(void *priv);
	void (*ipro_chksum_err_ctrl)(void *priv, u8 status);
	void (*ipro_chksum_err_select)(void *priv, u8 status, u8 dir);
	void (*pa_chksum_err_report)(void *priv, u8 status, u8 dir);
	void (*set_slave_swd_id)(void *priv, u16 vf_start, u16 vf_cnt,
				 u16 swd_id, u16 pf_id);
	void (*clear_ipro_decap)(void *priv);
	void (*cfg_tnl_offload_profile)(void *priv, u8 mode);
	void (*cfg_nodport_upcall)(void *priv, u16 vsi_id, bool enable);

	/* For virtio */
	void (*get_common_cfg)(void *priv, u32 offset, void *buf, u32 len);
	void (*set_common_cfg)(void *priv, u32 offset, void *buf, u32 len);
	void (*get_device_cfg)(void *priv, u32 offset, void *buf, u32 len);
	void (*set_device_cfg)(void *priv, u32 offset, void *buf, u32 len);
	bool (*get_rdma_capability)(void *priv);

	/* For Draco */
	int (*capture_bdf)(void *priv, u16 *func_id, u8 *mgt_pf, u16 *bdf);
	int (*get_table_range)(void *priv, u8 pf_id, u8 addr_id, u8 eth_num,
			       u32 *range_oft, u32 *range_size);
	void (*set_net_qid_table)(void *priv, u16 func_id,
				  u16 global_queue_id, u16 local_queue_id, u8 is_vf);
	int (*cfg_rx_vlan_parse)(void *priv, u16 vsi_id, u16 enable, u16 rx_vlan_mode);
	int (*cfg_rss_hash)(void *priv, u16 vsi_id, u16 rss_hash_mode);
	void (*get_rx_prio_stats)(void *priv, u16 eth_id, u16 prio,
				  struct nbl_prio_stats *prio_stats);
	void (*get_tx_prio_stats)(void *priv, u16 eth_id, u16 prio,
				  struct nbl_prio_stats *prio_stats);
	int (*read_fem_tbl)(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			    u8 *resp_head, u8 *resp_data);
	int (*write_fem_tbl)(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			     u8 *resp_head, u8 *resp_data);
	int (*clear_em)(void *priv, u8 pf_id);

	void (*cfg_macsec_fs)(void *priv, u32 index, struct nbl_macsec_fs *macsec_fs);
	void (*cfg_macsec_txsc)(void *priv, u32 index, struct nbl_macsec_tx_sc *tx_sc);
	void (*cfg_macsec_rxsc)(void *priv, u32 index, struct nbl_macsec_rx_sc *rx_sc);
	void (*cfg_macsec_sa)(void *priv, u32 index, struct nbl_macsec_sa *sa, bool is_tx);

	u32 (*get_perf_dump_length)(void *priv);
	u32 (*get_perf_dump_data)(void *priv, u8 *buffer, u32 size);

	int (*get_mirror_table_id)(void *priv, u16 vsi_id, int dir,
				   bool mirror_en, u8 *mt_id);
	int (*configure_mirror)(void *priv, u16 vsi_id, bool mirror_en, int dir,
				u8 mt_id);
	int (*configure_mirror_table)(void *priv, bool mirror_en,
				      u16 mirror_vsi_id, u16 mirror_queue_id, u8 mt_id);
	int (*clear_mirror_cfg)(void *priv, u16 vsi_id);
	u32 (*get_dvn_desc_req)(void *priv);
	void (*set_dvn_desc_req)(void *priv, u32 desc_req);
	void (*set_dvn_desc_req_dpdk)(void *priv, u8 eth_speed, bool is_dpdk);
	void (*set_dpa_chksum_errcode)(void *priv, bool flag);
	void (*dump_abnormal_intr)(void *priv, struct seq_file *m);
	void (*get_prio_stat_data)(void *priv, u32 eth_id, u64 *data, u32 *data_len);
	int (*get_acl_flow_stat_width)(void *priv);
	void (*set_pp_udf)(void *priv, u8 udi_id, u32 offset);
	void (*set_acl_udf)(void *priv, u8 udi_id, u32 offset);
	void (*set_epro_udf)(void *priv, u8 udi_id, u32 offset);
	int (*init_hol)(void *priv);
};

struct nbl_phy_ops_tbl {
	struct nbl_phy_ops *ops;
	void *priv;
};

int nbl_phy_init_leonis(void *p, struct nbl_init_param *param);
void nbl_phy_remove_leonis(void *p);

int nbl_phy_init_draco(void *p, struct nbl_init_param *param);
void nbl_phy_remove_draco(void *p);

#endif
