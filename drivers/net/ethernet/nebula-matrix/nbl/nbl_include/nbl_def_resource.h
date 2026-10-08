/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_RESOURCE_H_
#define _NBL_DEF_RESOURCE_H_

#include "nbl_include.h"

#define NBL_RES_OPS_TBL_TO_OPS(res_ops_tbl)		((res_ops_tbl)->ops)
#define NBL_RES_OPS_TBL_TO_PRIV(res_ops_tbl)		((res_ops_tbl)->priv)

struct nbl_resource_pt_ops {
	netdev_tx_t (*start_xmit)(struct sk_buff *skb, struct net_device *netdev);
	netdev_tx_t (*start_xmit_draco)(struct sk_buff *skb, struct net_device *netdev);
	netdev_tx_t (*rep_xmit)(struct sk_buff *skb, struct net_device *netdev);
	netdev_tx_t (*self_test_xmit)(struct sk_buff *skb, struct net_device *netdev);
	int (*napi_poll)(struct napi_struct *napi, int budget);
	netdev_features_t (*features_check)(struct sk_buff *skb, struct net_device *dev,
					    netdev_features_t features);
	int (*xdp_xmit)(struct net_device *netdev, int n, struct xdp_frame **frame, u32 flags);
};

struct nbl_resource_pt_tbl {
	struct nbl_resource_pt_ops pt_ops;
	void *txrx_mgt;
};

struct nbl_resource_ops {
	int (*init_chip_module)(void *priv);
	void (*set_driver_status)(void *priv, bool active);
	void (*get_res_pt_tbl)(void *priv, struct nbl_resource_pt_tbl *pt_tbl);
	int (*init_queue)(void *priv);
	int (*init_vsi)(void *priv);
	int (*init_vf_msix_map)(void *priv, struct nbl_ch_prm_init_vf_msix_map *param);
	int (*configure_msix_map)(void *priv, struct nbl_ch_prm_cfg_msix_map *param);
	int (*destroy_msix_map)(void *priv, u16 *func_id);
	int (*enable_mailbox_irq)(void *priv, struct nbl_ch_prm_enable_irq *param);
	int (*enable_abnormal_irq)(void *p, struct nbl_ch_prm_enable_irq *param);
	int (*enable_sfp_plug_irq)(void *priv, struct nbl_ch_prm_enable_irq *param);
	int (*enable_adminq_irq)(void *p, struct nbl_ch_prm_enable_irq *param);
	u16 (*get_global_vector)(void *priv, struct nbl_ch_prm_get_global_vec *param);
	u16 (*get_msix_entry_id)(void *priv, u16 vsi_id, u16 local_vector_id);
	int (*get_chip_temperature)(void *priv, struct nbl_ch_prm_get_hwmon *param);
	int (*get_module_temperature)(void *priv, struct nbl_ch_prm_get_hwmon *param);
	int (*get_mbx_irq_num)(void *priv);
	int (*get_adminq_irq_num)(void *priv);
	int (*get_abnormal_irq_num)(void *priv);
	int (*get_sfp_plug_irq_num)(void *priv);

	int (*alloc_rings)(void *priv, struct nbl_ring_param *param);
	void (*remove_rings)(void *priv);
	dma_addr_t (*start_tx_ring)(void *priv, struct nbl_tx_ring_start_param *param);
	void (*stop_tx_ring)(void *priv, u8 ring_index);
	dma_addr_t (*start_rx_ring)(void *priv, struct nbl_rx_ring_start_param *param);
	void (*stop_rx_ring)(void *priv, u8 ring_index);
	void (*update_rx_ring)(void *priv, u16 index);
	void (*kick_rx_ring)(void *priv, u16 index);
	int (*dump_ring)(void *priv, struct nbl_dump_ring_param *param);
	int (*dump_ring_stats)(void *priv, struct nbl_dump_ring_param *param);
	void (*set_rings_xdp_prog)(void *priv, void *prog);
	int (*register_xdp_rxq)(void *priv, u8 ring_index);
	void (*unregister_xdp_rxq)(void *priv, u8 ring_index);
	struct nbl_napi_struct *(*get_vector_napi)(void *priv, u16 index);
	void (*set_vector_info)(void *priv, struct nbl_vec_info_param *param);
	void (*register_vsi_ring)(void *priv, struct nbl_vsi_ring_param *param);
	int (*register_net)(void *priv, struct nbl_ch_prm_register_net_info *param,
			    struct nbl_register_net_result *output);
	int (*unregister_net)(void *priv, u16 *func_id);
	int (*alloc_txrx_queues)(void *priv, struct nbl_ch_prm_alloc_txrx_queues *param);
	int (*free_txrx_queues)(void *priv, u16 *vsi_id);
	int (*register_vsi2q)(void *priv, u16 vsi_index, u16 vsi_id,
			      u16 queue_offset, u16 queue_num);
	int (*setup_q2vsi)(void *priv, u16 vsi_id);
	void (*remove_q2vsi)(void *priv, u16 vsi_id);
	int (*setup_rss)(void *priv, u16 vsi_id);
	void (*remove_rss)(void *priv, u16 vsi_id);
	int (*setup_queue)(void *priv, struct nbl_ch_prm_setup_queue *param);
	int (*remove_queue)(void *priv, struct nbl_ch_prm_setup_queue *param);
	void (*remove_all_queues)(void *priv, u16 vsi_id);
	int (*cfg_dsch)(void *priv, u16 vsi_id, bool vld);
	int (*setup_cqs)(void *priv, u16 vsi_id, u16 real_qps, bool rss_indir_set);
	void (*remove_cqs)(void *priv, u16 vsi_id);
	int (*cfg_qdisc_mqprio)(void *priv, struct nbl_tc_qidsc_param *param);
	int (*clear_queues)(void *priv, u16 *vsi_id);
	int (*check_offload_status)(void *priv, bool *is_down);
	u16 (*get_local_queue_id)(void *priv,
				  struct nbl_get_local_queue_id_param *param);
	u16 (*get_global_queue_id)(void *priv, u16 vsi_id, u16 local_queue_id);

	u8* (*get_msix_irq_enable_info)(void *priv, u16 global_vector_id,
					u32 *irq_data, u32 *irq_mask_data);

	int (*set_spoof_check_addr)(void *priv, struct nbl_ch_prm_set_spoof_check_addr *param);
	int (*set_vf_spoof_check)(void *priv, struct nbl_ch_prm_set_vf_spoof_check *param);
	void (*get_base_mac_addr)(void *priv, u8 *mac);

	int (*add_macvlan)(void *priv, u8 *mac, u16 vlan, u16 vsi);
	void (*del_macvlan)(void *priv, u8 *mac, u16 vlan, u16 vsi);
	int (*set_decap_set)(void *priv, struct nbl_ch_prm_set_decap_set *param);
	int (*add_lag_flow)(void *priv, u16 *vsi);
	int (*del_lag_flow)(void *priv, u16 *vsi);
	int (*add_lldp_flow)(void *priv, u16 *vsi);
	int (*del_lldp_flow)(void *priv, u16 *vsi);
	int (*add_multi_rule)(void *priv, u16 *vsi);
	int (*del_multi_rule)(void *priv, u16 *vsi);
	int (*add_multi_mcast)(void *priv, u16 vsi);
	void (*del_multi_mcast)(void *priv, u16 vsi);
	int (*setup_multi_group)(void *priv);
	void (*remove_multi_group)(void *priv);
	int (*setup_ecn_stats)(void *priv);
	void (*remove_ecn_stats)(void *priv);
	int (*clear_accel_flow)(void *priv, u16 *vsi_id);
	int (*clear_flow)(void *priv, u16 *vsi_id);
	void (*dump_flow)(void *priv, struct seq_file *m);
	int (*alloc_kt)(void *priv);
	int (*free_kt)(void *priv);
	void (*clear_fem_tcam)(void *priv);

	void (*dump_func_info)(void *priv, struct seq_file *m);
	u16 (*get_vsi_id)(void *priv, struct nbl_ch_prm_get_vsi *param);
	int (*get_my_pf)(void *priv, u16 *sfid, u8 *my_pf);
	int (*get_eth_id)(void *priv, struct nbl_ch_prm_get_eth_id *param,
			  struct nbl_ch_prm_get_eth_id *output);
	int (*set_promisc_mode)(void *priv, struct nbl_ch_prm_set_promisc_mode *param);
	u32 (*get_tx_headroom)(void *priv);
	void (*get_rep_feature)(void *priv, struct nbl_register_net_result *register_result);
	int (*get_rep_queue_info)(void *priv, struct nbl_ch_prm_get_queue_info *output);
	int (*get_user_queue_info)(void *priv, u16 *vsi_id,
				   struct nbl_ch_prm_get_queue_info *output);
	int (*set_mtu)(void *priv, u16 vsi_id, u16 mtu);
	int (*check_mtu)(void *priv, bool force_xdp, int new_mtu, int *max_mtu);

	int (*set_eswitch_mode)(void *priv, u16 *switch_mode);
	u16 (*get_eswitch_mode)(void *priv);
	int (*alloc_rep_data)(void *priv, struct nbl_alloc_rep_data_param *param);
	void (*free_rep_data)(void *priv);
	void (*set_rep_netdev_info)(void *priv, void *rep_data);
	void (*unset_rep_netdev_info)(void *priv);
	struct net_device *(*get_rep_netdev_info)(void *priv, u16 rep_data_index);
	int (*disable_phy_flow)(void *priv, u8 *eth_id);
	int (*enable_phy_flow)(void *priv, u8 *eth_id);
	void (*init_acl)(void *priv);
	void (*uninit_acl)(void *priv);
	int (*set_upcall_rule)(void *priv, struct nbl_ch_prm_set_upcall *param);
	int (*unset_upcall_rule)(void *priv, u8 *eth_id);
	int (*set_shaping_dport_vld)(void *priv, struct nbl_ch_prm_set_func_vld *param);
	int (*set_dport_fc_th_vld)(void *priv, struct nbl_ch_prm_set_func_vld *param);
	void (*get_rep_stats)(void *priv, struct nbl_get_rep_stats_param *param,
			      struct nbl_rep_stats *output);
	u16 (*get_rep_index)(void *priv, u16 *rep_vsi_id);
	void (*get_queue_stats)(void *priv, struct nbl_get_queue_stats_param *param,
				struct nbl_queue_stats *output);
	int (*get_queue_err_stats)(void *priv,
				   struct nbl_ch_prm_get_queue_err_stats *param,
				   struct nbl_queue_err_stats *output);
	void (*get_net_stats)(void *priv, struct nbl_stats *queue_stats);
	int (*get_eth_ctrl_stats)(void *priv, u32 *eth_id,
				  struct nbl_eth_ctrl_stats *output);
	void (*get_private_stat_len)(void *priv, u32 *len);
	void (*get_private_stat_data)(void *priv, u32 eth_id, u64 *data, u32 data_len);
	int (*get_pause_stats)(void *priv, u32 *eth_id, struct nbl_pause_stats *output);
	int (*get_eth_mac_stats)(void *priv, u32 *eth_id,
				 struct nbl_eth_mac_stats *output);
	int (*get_rmon_stats)(void *priv, u32 *eth_id, struct nbl_rmon_stats *output);
	void (*get_rmon_hist_range)(void *priv, const struct ethtool_rmon_hist_range **range);
	void (*fill_private_stat_strings)(void *priv, u8 *strings);
	int (*get_eth_abnormal_stats)(void *priv, u8 *eth_id,
				      struct nbl_eth_abnormal_stats *output);
	u16 (*get_max_desc_num)(void);
	u16 (*get_min_desc_num)(void);
	int (*get_coalesce)(void *priv, struct nbl_ch_prm_get_coalesce_req *param,
			    struct nbl_ch_prm_get_coalesce *ec);
	int (*set_coalesce)(void *priv, struct nbl_ch_prm_set_coalesce *param);
	int (*set_msix_fast_restrain)(void *priv,
				      struct nbl_set_msix_fast_restrain_param *param);
	u16 (*get_intr_suppress_level)(void *priv,
				       struct nbl_get_intr_suppress_level_param *param);
	int (*set_intr_suppress_level)(void *priv,
				       struct nbl_ch_prm_set_intr_suppress_level *param);
	int (*set_intr_suppress_level_fast)(void *priv,
					    struct nbl_set_intr_suppress_level_fast_param *param);
	int (*get_rxfh_indir_size)(void *priv, u16 *vsi_id, u32 *rxfh_indir_size);
	void (*get_rxfh_indir)(void *priv, u16 vsi_id, u32 *indir);
	int (*set_rxfh_indir)(void *priv, u16 vsi_id, const u32 *indir, u32 indir_size);
	void (*get_rxfh_rss_key_size)(void *priv, u32 *rxfh_rss_key_size);
	int (*get_rxfh_rss_key)(void *priv, struct nbl_ch_prm_get_rxfh_rss_key *prm,
				struct nbl_ch_prm_get_rxfh_key *output);
	int (*set_rxfh_rss_key)(void *priv, struct nbl_ch_prm_set_rxfh_rss_key *prm);
	int (*get_rss_alg_sel)(void *priv, u16 *vsi_id, u8 *alg_sel);
	int (*set_rss_alg_sel)(void *priv, struct nbl_ch_prm_set_rxfh_rss_alg_sel *prm);
	int (*get_hash_fields)(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields);
	int (*set_hash_fields)(void *priv, u16 vsi_id, int flow_type, u64 hash_fields);
	int (*get_firmware_version)(void *priv, struct nbl_ch_prm_get_firmware_version *output);
	int (*nway_reset)(void *priv, u8 eth_id);
	int (*cfg_rx_half_offload)(void *priv, struct nbl_cfg_rx_half_offload_param *prm);
	int (*cfg_rx_vlan_parse)(void *priv, struct nbl_ch_prm_cfg_rx_vlan_parse *prm);
	int (*cfg_rss_hash)(void *priv, struct nbl_ch_prm_cfg_rss_hash *prm);
	int (*cfg_txrx_vlan)(void *priv, struct nbl_cfg_txrx_vlan_param *prm);

	void (*setup_rdma_id)(void *priv, struct ida *adev_ida,
			      struct ida *grc_adev_ida, struct mutex *lock);
	void (*remove_rdma_id)(void *priv, struct ida *adev_ida,
			       struct ida *grc_adev_ida, struct mutex *lock);
	int (*register_rdma_grc_id)(void *priv, u16 *vsi_id, int *grc_id);
	int (*unregister_rdma_grc_id)(void *priv, u16 *vsi_id);
	int (*register_rdma)(void *priv, u16 *vsi_id, struct nbl_rdma_register_param *param);
	int (*unregister_rdma)(void *priv, u16 *vsi_id);
	int (*enable_up_rdma_bypass)(void *priv, struct nbl_enable_up_rdma_bypass_param *prm);
	u8 __iomem * (*get_hw_addr)(void *priv, size_t *size);
	u8 __iomem * (*get_rdma_hw_addr)(void *priv);
	u64 (*get_real_hw_addr)(void *priv, u16 *vsi_id);
	u16 (*get_function_id)(void *priv, u16 *vsi_id);
	int (*get_real_bdf)(void *priv, u16 *vsi_id, struct nbl_ch_prm_get_real_bdf *output);

	int (*set_lag_status)(void *priv, bool *lag_en);
	int (*enable_lag_protocol)(void *priv, struct nbl_ch_prm_enable_lag_protocol *param);
	int (*cfg_lag_hash_algorithm)(void *priv, struct nbl_ch_prm_cfg_lag_hash_algorithm *param);
	int (*cfg_lag_member_fwd)(void *priv, struct nbl_ch_prm_cfg_lag_member_fwd *param);
	int (*cfg_lag_member_list)(void *priv, struct nbl_lag_member_list_param *param);
	int (*cfg_lag_member_up_attr)(void *priv, struct nbl_ch_prm_cfg_lag_member_up_attr *param);
	int (*cfg_duppkt_info)(void *priv, struct nbl_lag_member_list_param *param);
	int (*cfg_duppkt_mcc)(void *priv, struct nbl_lag_member_list_param *param);
	int (*cfg_lag_mcc)(void *priv, struct nbl_ch_prm_cfg_lag_mcc *param);
	int (*cfg_bond_shaping)(void *priv, struct nbl_ch_prm_cfg_bond_shaping *param);
	int (*cfg_bgid_back_pressure)(void *priv, struct nbl_ch_prm_cfg_bgid_back_pressure *param);

	int (*init_port)(void *priv);
	int (*get_port_attributes)(void *priv);
	int (*update_ring_num)(void *priv);
	int (*update_rdma_cap)(void *priv);
	int (*update_rdma_mem_type)(void *priv);
	int (*update_internal_cfg)(void *priv);
	void (*get_rdma_cap_num)(void *priv, u16 *cap_num, u16 *my_cap_num);

	int (*get_part_number)(void *priv, char *part_number);
	int (*get_serial_number)(void *priv, char *serial_number);
	int (*enable_port)(void *priv, bool enable);
	int (*cfg_eth_bond_info)(void *priv, struct nbl_lag_member_list_param *param);
	int (*get_eth_bond_info)(void *priv, struct nbl_bond_param *param);
	void (*cfg_eth_bond_event)(void *priv, bool enable);
	void (*recv_port_notify)(void *priv, void *data);
	int (*get_port_state)(void *priv, u8 eth_id, struct nbl_port_state *port_state);
	int (*get_fec_stats)(void *priv, u32 eth_id, struct nbl_fec_stats *fec_stats);
	int (*set_port_advertising)(void *priv, struct nbl_port_advertising *port_advertising);
	int (*get_module_info)(void *priv, u8 eth_id, struct ethtool_modinfo *info);
	int (*get_module_eeprom)(void *priv, u8 eth_id, struct ethtool_eeprom *eeprom, u8 *data);
	int (*get_module_eeprom_by_page)(void *priv, u8 eth_id,
					 struct nbl_ethtool_module_eeprom *eeprom, u8 *data);
	int (*get_link_state)(void *priv, u8 eth_id, struct nbl_eth_link_info *eth_link_info);
	int (*get_link_down_count)(void *priv, u8 eth_id, u64 *link_down_count);
	int (*get_link_status_opcode)(void *priv, u8 eth_id, u32 *link_status_opcode);
	int (*set_eth_mac_addr)(void *priv, u8 *mac, u8 eth_id);
	int (*process_abnormal_event)(void *priv,
				      struct nbl_abnormal_event_info *abnomal_info);
	int (*process_sfp_plug_event)(void *priv);
	int (*get_owned_pf_bitmap)(void *priv,
				   unsigned long **owned_pf_bitmap, u8 *max_pf, u16 *bdf);
	int (*ctrl_port_led)(void *priv, u8 eth_id, enum nbl_led_reg_ctrl led_ctrl, u32 *led_reg);
	int (*set_wol)(void *priv, u8 eth_id, bool enable);
	void (*adapt_desc_gother)(void *priv);
	void (*set_desc_high_throughput)(void *priv);
	void (*flr_clear_net)(void *priv, u16 vfid);
	void (*flr_clear_queues)(void *priv, u16 vfid);
	void (*flr_qinfo_cfg)(void *priv, u16 vfid);
	void (*flr_clear_accel_flow)(void *priv, u16 vfid);
	void (*flr_clear_flows)(void *priv, u16 vfid);
	void (*flr_clear_interrupt)(void *priv, u16 vfid);
	void (*flr_clear_accel)(void *priv, u16 vfid);
	void (*flr_clear_rdma)(void *priv, u16 vfid);
	u16 (*covert_vfid_to_vsi_id)(void *priv, u16 vfid);
	int (*set_bridge_mode)(void *priv, u16 func_id, u16 bmode);
	u16 (*get_vf_function_id)(void *priv, u16 vsi_id, int vf_id);
	u16 (*get_vf_vsi_id)(void *priv, u16 vsi_id, int vf_id);
	bool (*check_vf_is_active)(void *priv, u16 func_id);
	int (*check_vf_is_vdpa)(void *priv, u16 func_id, u8 *is_vdpa);
	int (*get_vdpa_vf_stats)(void *priv, u16 func_id, struct nbl_vf_stats *vf_stats);
	int (*get_uvn_pkt_drop_stats)(void *priv, u16 vsi_id,
				      u16 num_queues, u32 *uvn_stat_pkt_drop);
	int (*get_pkt_drop_stats)(void *priv);
	int (*get_total_pkt_drop_stats)(void *priv, struct nbl_chan_param_get_total_drop *param,
					struct nbl_chan_param_drop_stats_resp *drop_stats);

	bool (*check_fw_heartbeat)(void *priv);
	bool (*check_fw_reset)(void *priv);
	int (*flash_lock)(void *priv);
	int (*flash_unlock)(void *priv);
	int (*flash_prepare)(void *priv);
	int (*flash_image)(void *priv, struct nbl_flash_image_param *param);
	int (*flash_activate)(void *priv);
	int (*get_phy_caps)(void *priv, u8 *eth_id, struct nbl_phy_caps *phy_caps);
	int (*set_sfp_state)(void *priv, struct nbl_ch_prm_set_sfp_state *param);
	int (*set_eth_loopback)(void *priv, struct nbl_ch_prm_set_eth_loopback *param);
	struct sk_buff *(*clean_rx_lb_test)(void *priv, u32 *ring_index);
	int (*passthrough_fw_cmd)(void *priv, struct nbl_passthrough_fw_cmd_param *param,
				  struct nbl_passthrough_fw_cmd_param *result);

	u32 (*check_active_vf)(void *priv, u16 *func_id);
	int (*get_board_id)(void *priv);

	void (*get_reg_dump)(void *priv, u32 *data, u32 len);
	int (*get_reg_dump_len)(void *priv);

	bool (*get_product_flex_cap)(void *priv, enum nbl_flex_cap_type *cap_type);
	bool (*get_product_fix_cap)(void *priv, enum nbl_fix_cap_type *cap_type);
	int (*alloc_ktls_tx_index)(void *priv, u16 *vsi);
	int (*free_ktls_tx_index)(void *priv, u32 *index);
	int (*cfg_ktls_tx_keymat)(void *priv, struct nbl_ch_prm_cfg_ktls_keymat *param);
	int (*alloc_ktls_rx_index)(void *priv, u16 *vsi);
	int (*free_ktls_rx_index)(void *priv, u32 *index);
	int (*cfg_ktls_rx_keymat)(void *priv, struct nbl_ch_prm_cfg_ktls_keymat *param);
	int (*cfg_ktls_rx_record)(void *priv, struct nbl_ch_prm_cfg_ktls_record *param);
	int (*add_ktls_rx_flow)(void *priv, struct nbl_ch_prm_cfg_ktls_flow *param);
	int (*del_ktls_rx_flow)(void *priv, struct nbl_ch_prm_cfg_ktls_flow *param);

	int (*alloc_ipsec_tx_index)(void *priv, struct nbl_ch_prm_ipsec_index *param);
	int (*free_ipsec_tx_index)(void *priv, struct nbl_ch_prm_ipsec_index *param);
	int (*alloc_ipsec_rx_index)(void *priv, struct nbl_ch_prm_ipsec_index *param);
	int (*free_ipsec_rx_index)(void *priv, struct nbl_ch_prm_ipsec_index *param);
	int (*cfg_ipsec_tx_sad)(void *priv, struct nbl_ch_prm_cfg_ipsec_sad *param);
	int (*cfg_ipsec_rx_sad)(void *priv, struct nbl_ch_prm_cfg_ipsec_sad *param);
	int (*add_ipsec_tx_flow)(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param);
	int (*del_ipsec_tx_flow)(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param);
	int (*add_ipsec_rx_flow)(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param);
	int (*del_ipsec_rx_flow)(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param);
	bool (*check_ipsec_status)(void *priv);
	u32 (*get_dipsec_lft_info)(void *priv);
	int (*handle_dipsec_soft_expire)(void *priv, u32 *index);
	int (*handle_dipsec_hard_expire)(void *priv, u32 *index);
	u32 (*get_uipsec_lft_info)(void *priv);
	int (*handle_uipsec_soft_expire)(void *priv, u32 *index);
	int (*handle_uipsec_hard_expire)(void *priv, u32 *index);

	dma_addr_t (*restore_abnormal_ring)(void *priv,
					    struct nbl_abnormal_ring_param *param);
	int (*restart_abnormal_ring)(void *priv,
				     struct nbl_abnormal_ring_param *param);
	int (*restore_hw_queue)(void *priv, struct nbl_ch_prm_restore_hw_queue *param);
	int (*stop_abnormal_sw_queue)(void *priv,
				      struct nbl_stop_abnormal_sw_queue_param *param);
	int (*stop_abnormal_hw_queue)(void *priv,
				      struct nbl_ch_prm_stop_abnormal_hw_queue *param);

	void (*register_func_mac)(void *priv, u8 *mac, u16 func_id);
	int (*register_func_link_forced)(void *priv, u16 func_id, u8 link_forced,
					 bool *should_notify);
	int (*register_func_trust)(void *priv, u16 func_id,
				   bool trust, bool *should_notify);
	int (*register_func_vlan)(void *priv, u16 func_id,
				  u16 vlan_tci, u16 vlan_proto, bool *should_notify);
	int (*register_func_rate)(void *priv, u16 func_id, int rate);
	int (*get_link_forced)(void *priv, u16 vsi_id);
	int (*set_tx_rate)(void *priv, u16 func_id, int tx_rate, int burst);
	int (*set_rx_rate)(void *priv, u16 func_id, int rx_rate, int burst);

	int (*get_fd_flow)(void *priv, u16 vsi_id, u32 location,
			   enum nbl_chan_fdir_rule_type rule_type,
			   struct nbl_chan_param_fdir_replace *cmd);
	int (*get_fd_flow_cnt)(void *priv, enum nbl_chan_fdir_rule_type rule_type, u16 vsi_id);
	int (*config_fd_flow_state)(void *priv, enum nbl_chan_fdir_rule_type rule_type,
				    u16 vsi_id, u16 state);
	int (*get_fd_flow_all)(void *priv, struct nbl_chan_param_get_fd_flow_all *param,
			       u32 *rule_locs);
	int (*get_fd_flow_max)(void *priv);

	int (*replace_fd_flow)(void *priv, struct nbl_chan_param_fdir_replace *info);
	int (*remove_fd_flow)(void *priv, enum nbl_chan_fdir_rule_type rule_type,
			      u32 loc, u16 vsi_id);
	void (*dump_fd_flow)(void *priv, struct seq_file *m);
	void (*cfg_fd_update_event)(void *priv, bool enable);
	int (*set_rdma_rx_vsi_remap)(void *priv, bool init);

	/* for vdpa driver */
	int (*cfg_queue_log)(void *priv, u16 vsi_id, u16 qps, bool vld);
	u64 (*get_queue_ctx)(void *priv, u16 vsi_id, u16 qid);
	int (*init_vdpaq)(void *priv, u16 func_id, u64 pa, u32 size);
	void (*destroy_vdpaq)(void *priv, u16 func_id);
	int (*get_upcall_port)(void *priv, u16 *bdf);

	/* for pmd driver */
	void (*register_net_rep)(void *priv, u16 pf_id, u16 vf_id,
				 struct nbl_register_net_rep_result *result);
	void (*unregister_net_rep)(void *priv, u16 vsi_id);
	void (*register_eth_rep)(void *priv, u8 eth_id);
	void (*unregister_eth_rep)(void *priv, u8 eth_id);
	u16 (*get_vsi_global_qid)(void *priv,
				  struct nbl_ch_prm_get_vsi_global_qid *param);
	void (*get_line_rate_info)(void *priv, void *data, void *result);
	int (*register_upcall_port)(void *priv, u16 func_id);
	void (*unregister_upcall_port)(void *priv, u16 func_id);
	void (*set_offload_status)(void *priv, u16 func_id);
	void (*init_offload_fwd)(void *priv, u16 vsi_id);
	int (*add_nd_upcall_flow)(void *priv, u16 vsi_id, bool mode);
	void (*del_nd_upcall_flow)(void *priv);
	void (*init_cmdq)(void *priv, void *data, u16 func_id);
	void (*reset_cmdq)(void *priv);
	void (*destroy_cmdq)(void *priv);
	void (*init_rep)(void *priv, u16 vsi_id, u8 inner_type,
			 u8 outer_type, u8 rep_type);
	void (*init_flow)(void *priv, void *param);
	void (*deinit_flow)(void *priv);
	void (*offload_flow_rule)(void *priv, void *data);
	void (*get_flow_acl_switch)(void *priv, u8 *acl_enable);
	void (*cfg_tnl_offload_profile)(void *priv, u8 mode);
	void (*get_board_info)(void *priv, struct nbl_board_port_info *board_info);
	void (*set_slave_swd_id)(void *priv, u16 swd_id, u16 pf_id);

	/* For virtio */
	void (*configure_virtio_dev_msix)(void *priv, u16 vector);
	void (*configure_rdma_msix_off)(void *priv, u16 vector);
	void (*configure_virtio_dev_ready)(void *priv);
	void (*reset_virtio_dev)(void *priv);
	bool (*get_ecpu_bond_status)(void *priv);

	int (*switchdev_init_cmdq)(void *priv);
	int (*switchdev_deinit_cmdq)(void *priv, u8 index);
	void (*get_tc_flow_parse_info)(void *priv, struct nbl_tc_parse_info **parse_info);
	int (*add_tc_flow)(void *priv, struct nbl_tc_flow_param *param);
	int (*del_tc_flow)(void *priv, struct nbl_tc_flow_param *param);
	int (*flow_index_lookup)(void *priv, struct nbl_flow_index_key key);

	bool (*tc_tun_encap_lookup)(void *priv, struct nbl_rule_action *rule_act,
				    struct nbl_tc_flow_param *param);
	int (*tc_tun_encap_del)(void *priv, struct nbl_encap_key *key);
	int (*tc_tun_encap_add)(void *priv, struct nbl_rule_action *action);
	int (*tc_tun_create_header)(void *priv, struct nbl_tc_tun_create_header_param *param);

	int (*set_tc_flow_info)(void *priv);
	int (*unset_tc_flow_info)(void *priv);
	int (*get_tc_flow_info)(void *priv);
	int (*query_tc_stats)(void *priv, struct nbl_stats_param *param);

	u32 (*get_p4_version)(void *priv);
	int (*get_p4_info)(void *priv, char *verify_code);
	int (*load_p4)(void *priv, struct nbl_load_p4_param *param);
	int (*get_p4_used)(void *priv);
	int (*set_p4_used)(void *priv, int *p4_type);

	u16 (*get_vf_base_vsi_id)(void *priv, u16 pf_id);

	int (*set_pmd_debug)(void *priv, bool pmd_debug);

	int (*alloc_macsec_txsc_index)(void *priv);
	void (*free_macsec_txsc_index)(void *priv, u8 index);
	int (*alloc_macsec_rxsc_index)(void *priv);
	void (*free_macsec_rxsc_index)(void *priv, u8 index);
	void (*cfg_macsec_fs)(void *priv, u32 index, struct nbl_macsec_fs *macsec_fs);
	void (*cfg_macsec_txsc)(void *priv, u32 index, struct nbl_macsec_tx_sc *tx_sc);
	void (*cfg_macsec_rxsc)(void *priv, u32 index, struct nbl_macsec_rx_sc *rx_sc);
	void (*cfg_macsec_sa)(void *priv, u32 index, struct nbl_macsec_sa *sa, bool is_tx);
	int (*get_xdp_queue_info)(void *priv, u16 *param,
				  struct nbl_ch_prm_get_queue_info *output);
	void (*set_hw_status)(void *priv, enum nbl_hw_status hw_status);
	void (*check_hw_status)(void *priv);
	enum nbl_hw_status (*get_hw_status)(void *priv);
	void (*get_active_func_bitmaps)(void *priv, unsigned long *bitmap, int max_func);
	int (*configure_qos)(void *priv, struct nbl_ch_prm_configure_qos *param);
	int (*configure_rdma_bw)(void *priv, struct nbl_ch_prm_configure_rdma_bw *param);
	int (*get_pfc_buffer_size)(void *priv, struct nbl_ch_prm_get_pfc_buffer_size *param,
				   struct nbl_ch_prm_get_pfc_buffer_size_resp *output);
	int (*set_pfc_buffer_size)(void *priv, struct nbl_ch_prm_set_pfc_buffer_size *param);
	int (*set_rate_limit)(void *priv, struct nbl_ch_prm_set_rate_limit *param);
	int (*set_tc_wgt)(void *priv, struct nbl_ch_prm_set_tc_wgt *param);

	u32 (*get_perf_dump_length)(void *priv);
	u32 (*get_perf_dump_data)(void *priv, struct nbl_ch_prm_get_perf_dump_data *param);

	int (*register_dev_name)(void *priv, struct nbl_ch_prm_pf_name *param);
	int (*get_dev_name)(void *priv, struct nbl_ch_prm_pf_name *param,
			    struct nbl_ch_prm_pf_name *output);

	int (*get_mirror_table_id)(void *priv, struct nbl_ch_prm_get_mirror_table_id *param,
				   struct nbl_ch_prm_get_mirror_table_id *output);
	int (*configure_mirror)(void *priv, struct nbl_ch_prm_mirror *param);
	int (*configure_tx_mirror_to_rdma)(void *priv,
					   struct nbl_ch_prm_tx_mirror_to_rdma *param);
	int (*configure_mirror_table)(void *priv, struct nbl_ch_prm_mirror_table *param);
	int (*clear_mirror_cfg)(void *priv, u16 *func_id);

	void (*cfg_mirror_outputport_event)(void *priv, bool enable);
	int (*check_flow_table_spec)(void *priv, struct nbl_ch_prm_flow_table_spec *param);
	u32 (*get_dvn_desc_req)(void *priv);
	void (*set_dvn_desc_req)(void *priv, u32 desc_req);
	void (*set_rx_csum_drop)(void *priv, bool enable);
	void (*cfg_vlan_filtering)(void *priv, bool filter);
	void (*set_xdp_enhance)(void *priv, bool enable);
	void (*dump_abnormal_intr)(void *priv, struct seq_file *m);
	int (*get_lag_ports_max)(void *priv);
	bool (*check_lag_nosupport)(void *priv);
};

struct nbl_resource_ops_tbl {
	struct nbl_resource_ops *ops;
	void *priv;
};

int nbl_res_init_leonis(void *p, struct nbl_init_param *param);
void nbl_res_remove_leonis(void *p);
int nbl_res_init_draco(void *p, struct nbl_init_param *param);
void nbl_res_remove_draco(void *p);

#endif
