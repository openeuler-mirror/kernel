/* SPDX-License-Identifier: GPL-2.0*/
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
	netdev_tx_t (*rep_xmit)(struct sk_buff *skb, struct net_device *netdev);
	netdev_tx_t (*self_test_xmit)(struct sk_buff *skb, struct net_device *netdev);
	int (*napi_poll)(struct napi_struct *napi, int budget);
};

struct nbl_resource_ops {
	int (*init_chip_module)(void *priv);
	void (*get_resource_pt_ops)(void *priv, struct nbl_resource_pt_ops *pt_ops);
	int (*queue_init)(void *priv);
	int (*vsi_init)(void *priv);
	int (*configure_msix_map)(void *priv, u16 func_id, u16 num_net_msix, u16 num_others_msix,
				  bool net_msix_mask_en);
	int (*destroy_msix_map)(void *priv, u16 func_id);
	int (*enable_mailbox_irq)(void *priv, u16 func_id, u16 vector_id, bool enable_msix);
	int (*enable_abnormal_irq)(void *p, u16 vector_id, bool enable_msix);
	int (*enable_adminq_irq)(void *p, u16 vector_id, bool enable_msix);
	u16 (*get_global_vector)(void *priv, u16 vsi_id, u16 local_vector_id);
	u16 (*get_msix_entry_id)(void *priv, u16 vsi_id, u16 local_vector_id);
	u32 (*get_chip_temperature)(void *priv);
	u32 (*get_chip_temperature_max)(void *priv);
	u32 (*get_chip_temperature_crit)(void *priv);
	int (*get_module_temperature)(void *priv, u8 eth_id, enum nbl_module_temp_type type);
	int (*get_mbx_irq_num)(void *priv);
	int (*get_adminq_irq_num)(void *priv);
	int (*get_abnormal_irq_num)(void *priv);

	int (*alloc_rings)(void *priv, struct net_device *netdev, u16 tx_num,
			   u16 rx_num, u16 tx_desc_num, u16 rx_desc_num);
	void (*remove_rings)(void *priv);
	dma_addr_t (*start_tx_ring)(void *priv, u8 ring_index);
	void (*stop_tx_ring)(void *priv, u8 ring_index);
	dma_addr_t (*start_rx_ring)(void *priv, u8 ring_index, bool use_napi);
	void (*stop_rx_ring)(void *priv, u8 ring_index);
	void (*update_rx_ring)(void *priv, u16 index);
	void (*kick_rx_ring)(void *priv, u16 index);
	int (*dump_ring)(void *priv, struct seq_file *m, bool is_tx, int index);
	int (*dump_ring_stats)(void *priv, struct seq_file *m, bool is_tx, int index);
	struct napi_struct *(*get_vector_napi)(void *priv, u16 index);
	void (*set_vector_info)(void *priv, u8 *irq_enable_base, u32 irq_data,
				u16 index, bool mask_en);
	void (*register_vsi_ring)(void *priv, u16 vsi_index, u16 ring_offset, u16 ring_num);
	int (*register_net)(void *priv, u16 func_id,
			    struct nbl_register_net_param *register_param,
			    struct nbl_register_net_result *register_result);
	int (*unregister_net)(void *priv, u16 func_id);
	int (*alloc_txrx_queues)(void *priv, u16 vsi_id, u16 queue_num);
	void (*free_txrx_queues)(void *priv, u16 vsi_id);
	int (*register_vsi2q)(void *priv, u16 vsi_index, u16 vsi_id,
			      u16 queue_offset, u16 queue_num);
	int (*setup_q2vsi)(void *priv, u16 vsi_id);
	void (*remove_q2vsi)(void *priv, u16 vsi_id);
	int (*setup_rss)(void *priv, u16 vsi_id);
	void (*remove_rss)(void *priv, u16 vsi_id);
	int (*setup_queue)(void *priv, struct nbl_txrx_queue_param *param, bool is_tx);
	void (*remove_all_queues)(void *priv, u16 vsi_id);
	int (*cfg_dsch)(void *priv, u16 vsi_id, bool vld);
	int (*setup_cqs)(void *priv, u16 vsi_id, u16 real_qps);
	void (*remove_cqs)(void *priv, u16 vsi_id);
	void (*clear_queues)(void *priv, u16 vsi_id);
	u16 (*get_local_queue_id)(void *priv, u16 vsi_id, u16 global_queue_id);

	int (*enable_msix_irq)(void *priv, u16 global_vector_id);
	u8* (*get_msix_irq_enable_info)(void *priv, u16 global_vector_id, u32 *irq_data);

	int (*set_spoof_check_addr)(void *priv, u16 vsi_id, u8 *mac);
	int (*set_vf_spoof_check)(void *priv, u16 vsi_id, int vfid, u8 enable);
	void (*get_base_mac_addr)(void *priv, u8 *mac);

	int (*add_macvlan)(void *priv, u8 *mac, u16 vlan, u16 vsi);
	void (*del_macvlan)(void *priv, u8 *mac, u16 vlan, u16 vsi);
	int (*add_lag_flow)(void *priv, u16 vsi);
	void (*del_lag_flow)(void *priv, u16 vsi);
	int (*add_lldp_flow)(void *priv, u16 vsi);
	void (*del_lldp_flow)(void *priv, u16 vsi);
	int (*add_multi_rule)(void *priv, u16 vsi);
	void (*del_multi_rule)(void *priv, u16 vsi);
	int (*setup_multi_group)(void *priv);
	void (*remove_multi_group)(void *priv);
	void (*clear_flow)(void *priv, u16 vsi_id);
	void (*dump_flow)(void *priv, struct seq_file *m);

	u16 (*get_vsi_id)(void *priv, u16 func_id, u16 type);
	void (*get_eth_id)(void *priv, u16 vsi_id, u8 *eth_mode, u8 *eth_id);
	int (*set_promisc_mode)(void *priv, u16 vsi_id, u16 mode);
	u32 (*get_tx_headroom)(void *priv);
	void (*get_user_queue_info)(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id);

	void (*get_queue_stats)(void *priv, u8 queue_id,
				struct nbl_queue_stats *queue_stats, bool is_tx);
	int (*get_queue_err_stats)(void *priv, u16 func_id, u8 queue_id,
				   struct nbl_queue_err_stats *queue_err_stats, bool is_tx);
	void (*get_net_stats)(void *priv, struct nbl_stats *queue_stats);
	void (*get_private_stat_len)(void *priv, u32 *len);
	void (*get_private_stat_data)(void *priv, u32 eth_id, u64 *data);
	void (*fill_private_stat_strings)(void *priv, u8 *strings);
	u16 (*get_max_desc_num)(void);
	u16 (*get_min_desc_num)(void);
	u16 (*get_tx_desc_num)(void *priv, u32 ring_index);
	u16 (*get_rx_desc_num)(void *priv, u32 ring_index);
	void (*set_tx_desc_num)(void *priv, u32 ring_index, u16 desc_num);
	void (*set_rx_desc_num)(void *priv, u32 ring_index, u16 desc_num);
	void (*get_coalesce)(void *priv, u16 func_id, u16 vector_id,
			     struct ethtool_coalesce *ec);
	void (*set_coalesce)(void *priv, u16 func_id, u16 vector_id,
			     u16 num_net_msix, u16 pnum, u16 rate);
	u16 (*get_intr_suppress_level)(void *priv, u64 rate,  u16 last_level);
	void (*set_intr_suppress_level)(void *priv, u16 func_id, u16 vector_id,
					u16 num_net_msix, u16 level);
	void (*get_rxfh_indir_size)(void *priv, u16 vsi_id, u32 *rxfh_indir_size);
	void (*get_rxfh_indir)(void *priv, u16 vsi_id, u32 *indir);
	void (*get_rxfh_rss_key_size)(void *priv, u32 *rxfh_rss_key_size);
	void (*get_rxfh_rss_key)(void *priv, u8 *rss_key);
	void (*get_rss_alg_sel)(void *priv, u8 *alg_sel, u8 eth_id);
	int (*get_firmware_version)(void *priv, char *firmware_verion);
	int (*get_driver_info)(void *priv, struct nbl_driver_info *driver_info);
	int (*nway_reset)(void *priv, u8 eth_id);

	u8 __iomem * (*get_hw_addr)(void *priv, size_t *size);
	u64 (*get_real_hw_addr)(void *priv, u16 vsi_id);
	u16 (*get_function_id)(void *priv, u16 vsi_id);
	void (*get_real_bdf)(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function);

	int (*get_port_attributes)(void *priv);
	int (*update_ring_num)(void *priv);
	int (*set_ring_num)(void *priv, struct nbl_fw_cmd_ring_num_param *param);
	int (*enable_port)(void *priv, bool enable);
	void (*recv_port_notify)(void *priv, void *data);
	int (*get_port_state)(void *priv, u8 eth_id, struct nbl_port_state *port_state);
	int (*set_port_advertising)(void *priv, struct nbl_port_advertising *port_advertising);
	int (*get_module_info)(void *priv, u8 eth_id, struct ethtool_modinfo *info);
	int (*get_module_eeprom)(void *priv, u8 eth_id, struct ethtool_eeprom *eeprom, u8 *data);
	int (*get_link_state)(void *priv, u8 eth_id, struct nbl_eth_link_info *eth_link_info);
	int (*set_eth_mac_addr)(void *priv, u8 *mac, u8 eth_id);
	int (*process_abnormal_event)(void *priv, struct nbl_abnormal_event_info *abnomal_info);
	int (*ctrl_port_led)(void *priv, u8 eth_id, enum nbl_led_reg_ctrl led_ctrl, u32 *led_reg);
	void (*adapt_desc_gother)(void *priv);
	void (*flr_clear_net)(void *priv, u16 vfid);
	void (*flr_clear_queues)(void *priv, u16 vfid);
	void (*flr_clear_flows)(void *priv, u16 vfid);
	void (*flr_clear_interrupt)(void *priv, u16 vfid);
	void (*unmask_all_interrupts)(void *priv);
	int (*set_bridge_mode)(void *priv, u16 func_id, u16 bmode);
	u16 (*get_vf_function_id)(void *priv, u16 vsi_id, int vf_id);

	bool (*check_fw_heartbeat)(void *priv);
	bool (*check_fw_reset)(void *priv);
	int (*flash_lock)(void *priv);
	int (*flash_unlock)(void *priv);
	int (*flash_prepare)(void *priv);
	int (*flash_image)(void *priv, u32 module, const u8 *data, size_t len);
	int (*flash_activate)(void *priv);
	void (*get_phy_caps)(void *priv, u8 eth_id, struct nbl_phy_caps *phy_caps);
	void (*get_phy_state)(void *priv, u8 eth_id, struct nbl_phy_state *phy_state);
	int (*set_sfp_state)(void *priv, u8 eth_id, u8 state);
	int (*setup_loopback)(void *priv, u32 eth_id, u32 enable);
	struct sk_buff *(*clean_rx_lb_test)(void *priv, u32 ring_index);
	int (*passthrough_fw_cmd)(void *priv, struct nbl_passthrough_fw_cmd_param *param,
				  struct nbl_passthrough_fw_cmd_param *result);

	u32 (*check_active_vf)(void *priv, u16 func_id);
	int (*get_board_id)(void *priv);

	void (*get_reg_dump)(void *priv, u32 *data, u32 len);
	int (*get_reg_dump_len)(void *priv);

	bool (*get_product_flex_cap)(void *priv, enum nbl_flex_cap_type cap_type);
	bool (*get_product_fix_cap)(void *priv, enum nbl_fix_cap_type cap_type);

	dma_addr_t (*restore_abnormal_ring)(void *priv, int ring_index, int type);
	int (*restart_abnormal_ring)(void *priv, int ring_index, int type);
	int (*restore_hw_queue)(void *priv, u16 vsi_id, u16 local_queue_id,
				dma_addr_t dma, int type);

	void (*get_board_info)(void *priv, struct nbl_board_port_info *board_info);

	int (*get_p4_info)(void *priv, char *verify_code);
	int (*load_p4)(void *priv, struct nbl_load_p4_param *param);
	int (*load_p4_default)(void *priv);
	int (*get_p4_used)(void *priv);
	int (*set_p4_used)(void *priv, int p4_type);

	u16 (*get_vf_base_vsi_id)(void *priv, u16 pf_id);
	u16 (*get_vsi_global_queue_id)(void *priv, u16 vsi_id, u16 local_qid);
};

struct nbl_resource_ops_tbl {
	struct nbl_resource_ops *ops;
	void *priv;
};

int nbl_res_init_leonis(void *p, struct nbl_init_param *param);
void nbl_res_remove_leonis(void *p);
#endif
