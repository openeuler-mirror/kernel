/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_SERVICE_H_
#define _NBL_DEF_SERVICE_H_

#include "nbl_include.h"

#define NBL_SERV_OPS_TBL_TO_OPS(serv_ops_tbl) ((serv_ops_tbl)->ops)
#define NBL_SERV_OPS_TBL_TO_PRIV(serv_ops_tbl) ((serv_ops_tbl)->priv)

struct nbl_service_ops {
	int (*init_chip)(void *p);
	int (*destroy_chip)(void *p);
	int (*init_p4)(void *priv);
	int (*configure_msix_map)(void *p, u16 num_net_msix, u16 num_others_msix,
				  bool net_msix_mask_en);
	int (*destroy_msix_map)(void *priv);
	int (*enable_mailbox_irq)(void *p, u16 vector_id, bool enable_msix);
	int (*enable_abnormal_irq)(void *p, u16 vector_id, bool enable_msix);
	int (*enable_adminq_irq)(void *p, u16 vector_id, bool enable_msix);
	int (*request_net_irq)(void *priv, struct nbl_msix_info_param *msix_info);
	void (*free_net_irq)(void *priv, struct nbl_msix_info_param *msix_info);
	u16 (*get_global_vector)(void *priv, u16 local_vector_id);
	u16 (*get_msix_entry_id)(void *priv, u16 local_vector_id);
	void (*get_common_irq_num)(void *priv, struct nbl_common_irq_num *irq_num);
	void (*get_ctrl_irq_num)(void *priv, struct nbl_ctrl_irq_num *irq_num);
	int (*get_port_attributes)(void *p);
	int (*update_ring_num)(void *priv);
	int (*enable_port)(void *p, bool enable);
	void (*set_netdev_carrier_state)(void *p, struct net_device *netdev, u8 link_state);

	int (*vsi_open)(void *priv, struct net_device *netdev, u16 vsi_index,
			u16 real_qps, bool use_napi);
	int (*vsi_stop)(void *priv, u16 vsi_index);
	int (*switch_traffic_default_dest)(void *priv, u16 from_vsi, u16 to_vsi);

	int (*netdev_open)(struct net_device *netdev);
	int (*netdev_stop)(struct net_device *netdev);
	netdev_tx_t (*start_xmit)(struct sk_buff *skb, struct net_device *netdev);
	int (*change_mtu)(struct net_device *netdev, int new_mtu);
	void (*get_stats64)(struct net_device *netdev, struct rtnl_link_stats64 *stats);
	void (*set_rx_mode)(struct net_device *dev);
	void (*change_rx_flags)(struct net_device *dev, int flag);
	int (*set_mac)(struct net_device *dev, void *p);
	int (*rx_add_vid)(struct net_device *dev, __be16 proto, u16 vid);
	int (*rx_kill_vid)(struct net_device *dev, __be16 proto, u16 vid);
	netdev_features_t (*features_check)(struct sk_buff *skb, struct net_device *dev,
					    netdev_features_t features);
	void (*tx_timeout)(struct net_device *netdev, u32 txqueue);

	int (*get_phys_port_name)(struct net_device *dev, char *name, size_t len);
	int (*get_port_parent_id)(struct net_device *dev, struct netdev_phys_item_id *ppid);

	int (*register_net)(void *priv, struct nbl_register_net_param *register_param,
			    struct nbl_register_net_result *register_result);
	int (*unregister_net)(void *priv);
	int (*setup_txrx_queues)(void *priv, u16 vsi_id, u16 queue_num, u16 net_vector_id);
	void (*remove_txrx_queues)(void *priv, u16 vsi_id);
	int (*register_vsi_info)(void *priv, u16 vsi_index, u16 vsi_id,
				 u16 queue_offset, u16 queue_num);
	int (*setup_q2vsi)(void *priv, u16 vsi_id);
	void (*remove_q2vsi)(void *priv, u16 vsi_id);
	int (*setup_rss)(void *priv, u16 vsi_id);
	void (*remove_rss)(void *priv, u16 vsi_id);
	u32 (*get_chip_temperature)(void *priv);
	u32 (*get_chip_temperature_max)(void *priv);
	u32 (*get_chip_temperature_crit)(void *priv);
	int (*get_module_temperature)(void *priv, u8 eth_id, enum nbl_module_temp_type type);

	int (*alloc_rings)(void *priv, struct net_device *dev,
			   u16 tx_num, u16 rx_num, u16 desc_num);
	void (*free_rings)(void *priv);
	int (*enable_napis)(void *priv, u16 vsi_index);
	void (*disable_napis)(void *priv, u16 vsi_index);
	void (*set_mask_en)(void *priv, bool enable);
	int (*start_net_flow)(void *priv, struct net_device *dev, u16 vsi_id);
	void (*stop_net_flow)(void *priv, u16 vsi_id);
	int (*set_lldp_flow)(void *priv, u16 vsi_id);
	void (*remove_lldp_flow)(void *priv, u16 vsi_id);
	int (*start_mgt_flow)(void *priv);
	void (*stop_mgt_flow)(void *priv);
	u32 (*get_tx_headroom)(void *priv);
	int (*set_spoof_check_addr)(void *priv, u8 *mac);

	u16 (*get_vsi_id)(void *priv, u16 func_id, u16 type);
	void (*get_eth_id)(void *priv, u16 vsi_id, u8 *eth_mode, u8 *eth_id);
	void (*debugfs_init)(void *priv);
	void (*debugfs_netops_create)(void *priv, u16 tx_queue_num, u16 rx_queue_num);
	void (*debugfs_ctrlops_create)(void *priv);
	void (*debugfs_exit)(void *priv);
	int (*setup_net_resource_mgt)(void *priv, struct net_device *dev);
	void (*remove_net_resource_mgt)(void *priv);
	int (*enable_lag_protocol)(void *priv, u16 vsi_id, bool lag_en);
	void (*set_sfp_state)(void *priv, struct net_device *netdev, u8 eth_id,
			      bool open, bool is_force);
	int (*get_board_id)(void *priv);
	void (*get_user_queue_info)(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id);

	/* ethtool */
	void (*get_drvinfo)(struct net_device *netdev, struct ethtool_drvinfo *drvinfo);
	int (*get_module_eeprom)(struct net_device *netdev,
				 struct ethtool_eeprom *eeprom, u8 *data);
	int (*get_module_info)(struct net_device *netdev, struct ethtool_modinfo *info);
	int (*get_eeprom_length)(struct net_device *netdev);
	int (*get_eeprom)(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes);
	void (*get_strings)(struct net_device *netdev, u32 stringset, u8 *data);
	int (*get_sset_count)(struct net_device *netdev, int sset);
	void (*get_ethtool_stats)(struct net_device *netdev,
				  struct ethtool_stats *stats, u64 *data);
	void (*get_channels)(struct net_device *netdev, struct ethtool_channels *channels);
	int (*set_channels)(struct net_device *netdev, struct ethtool_channels *channels);
	u32 (*get_link)(struct net_device *netdev);
	int (*get_ksettings)(struct net_device *netdev, struct ethtool_link_ksettings *cmd);
	int (*set_ksettings)(struct net_device *netdev, const struct ethtool_link_ksettings *cmd);
	void (*get_ringparam)(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			      struct kernel_ethtool_ringparam *k_ringparam,
			      struct netlink_ext_ack *extack);
	int (*set_ringparam)(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			     struct kernel_ethtool_ringparam *k_ringparam,
			     struct netlink_ext_ack *extack);

	int (*get_coalesce)(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce *kernel_ec,
			    struct netlink_ext_ack *extack);
	int (*set_coalesce)(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce *kernel_ec,
			    struct netlink_ext_ack *extack);

	int (*get_rxnfc)(struct net_device *netdev, struct ethtool_rxnfc *cmd, u32 *rule_locs);
	u32 (*get_rxfh_indir_size)(struct net_device *netdev);
	u32 (*get_rxfh_key_size)(struct net_device *netdev);
	int (*get_rxfh)(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc);
	u32 (*get_msglevel)(struct net_device *netdev);
	void (*set_msglevel)(struct net_device *netdev, u32 msglevel);
	int (*get_regs_len)(struct net_device *netdev);
	void (*get_ethtool_dump_regs)(struct net_device *netdev,
				      struct ethtool_regs *regs, void *p);
	int (*get_per_queue_coalesce)(struct net_device *netdev,
				      u32 q_num, struct ethtool_coalesce *ec);
	int (*set_per_queue_coalesce)(struct net_device *netdev,
				      u32 q_num, struct ethtool_coalesce *ec);
	void (*self_test)(struct net_device *netdev, struct ethtool_test *eth_test, u64 *data);
	u32 (*get_priv_flags)(struct net_device *netdev);
	int (*set_priv_flags)(struct net_device *netdev, u32 priv_flags);
	int (*set_pause_param)(struct net_device *netdev, struct ethtool_pauseparam *param);
	void (*get_pause_param)(struct net_device *netdev, struct ethtool_pauseparam *param);
	int (*set_fec_param)(struct net_device *netdev, struct ethtool_fecparam *fec);
	int (*get_fec_param)(struct net_device *netdev, struct ethtool_fecparam *fec);
	int (*get_ts_info)(struct net_device *netdev, struct ethtool_ts_info *ts_info);
	int (*set_phys_id)(struct net_device *netdev, enum ethtool_phys_id_state state);
	int (*nway_reset)(struct net_device *netdev);

	u8 __iomem * (*get_hw_addr)(void *priv, size_t *size);
	u64 (*get_real_hw_addr)(void *priv, u16 vsi_id);
	u16 (*get_function_id)(void *priv, u16 vsi_id);
	void (*get_real_bdf)(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function);
	int (*set_eth_mac_addr)(void *priv, u8 *mac, u8 eth_id);
	int (*process_abnormal_event)(void *priv);
	void (*adapt_desc_gother)(void *priv);
	void (*process_flr)(void *priv, u16 vfid);
	void (*recovery_abnormal)(void *priv);
	void (*keep_alive)(void *priv);

	int (*get_devlink_info)(struct devlink *devlink, struct devlink_info_req *req,
				struct netlink_ext_ack *extack);
	int (*update_devlink_flash)(struct devlink *devlink,
				    struct devlink_flash_update_params *params,
				    struct netlink_ext_ack *extack);

	u32 (*get_adminq_tx_buf_size)(void *priv);
	bool (*check_fw_heartbeat)(void *priv);
	bool (*check_fw_reset)(void *priv);

	bool (*get_product_flex_cap)(void *priv, enum nbl_flex_cap_type cap_type);
	bool (*get_product_fix_cap)(void *priv, enum nbl_fix_cap_type cap_type);

	int (*setup_st)(void *priv, void *st_table_param);
	void (*remove_st)(void *priv, void *st_table_param);
	u16 (*get_vf_base_vsi_id)(void *priv, u16 func_id);
};

struct nbl_service_ops_tbl {
	struct nbl_resource_pt_ops pt_ops;
	struct nbl_service_ops *ops;
	void *priv;
};

int nbl_serv_init(void *priv, struct nbl_init_param *param);
void nbl_serv_remove(void *priv);

#endif
