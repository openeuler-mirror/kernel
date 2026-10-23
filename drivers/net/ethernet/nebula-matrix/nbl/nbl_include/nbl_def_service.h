/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_SERVICE_H_
#define _NBL_DEF_SERVICE_H_

#include "nbl_include.h"

#define NBL_SERV_OPS_TBL_TO_OPS(serv_ops_tbl)	((serv_ops_tbl)->ops)
#define NBL_SERV_OPS_TBL_TO_PRIV(serv_ops_tbl)	((serv_ops_tbl)->priv)

struct nbl_service_traffic_switch {
	u16 normal_vsi;
	u16 sync_other_vsi;
	u16 async_other_vsi;
	bool promisc;
	bool has_lacp;
	bool has_lldp;
};

struct nbl_service_ops {
	int (*init_chip_factory)(void *priv);
	int (*destroy_chip_factory)(void *p);
	int (*clear_mirrior_table)(void *p);
	int (*init_chip)(void *p);
	int (*destroy_chip)(void *p);
	int (*enable_driver)(void *p);
	int (*init_p4)(void *priv);
	int (*configure_msix_map)(void *p, u16 func_id, u16 num_net_msix, u16 num_others_msix,
				  bool net_msix_mask_en);
	int (*destroy_msix_map)(void *priv, u16 func_id);
	int (*enable_mailbox_irq)(void *p, u16 func_id, u16 vector_id, bool enable_msix);
	int (*enable_abnormal_irq)(void *p, u16 func_id, u16 vector_id, bool enable_msix);
	int (*enable_sfp_plug_irq)(void *priv, u16 vector_id, bool enable_msix);
	int (*enable_adminq_irq)(void *p, u16 vector_id, bool enable_msix);
	int (*request_net_irq)(void *priv, struct nbl_msix_info_param *msix_info);
	void (*free_net_irq)(void *priv, struct nbl_msix_info_param *msix_info);
	u16 (*get_global_vector)(void *priv, u16 local_vector_id);
	void (*get_common_irq_num)(void *priv, struct nbl_common_irq_num *irq_num);
	void (*get_ctrl_irq_num)(void *priv, struct nbl_ctrl_irq_num *irq_num);
	int (*get_port_attributes)(void *p);
	int (*update_template_config)(void *priv);
	int (*get_part_number)(void *priv, char *part_number);
	int (*get_serial_number)(void *priv, char *serial_number);
	int (*enable_port)(void *p, bool enable);
	void (*init_port)(void *priv);
	void (*set_netdev_carrier_state)(void *p, struct net_device *netdev, u8 link_state);
	void (*set_port_state_update)(void *priv, u8 port_state_update);
	int (*get_firmware_version)(void *priv, struct nbl_ch_prm_get_firmware_version *output);

	int (*vsi_open)(void *priv, struct net_device *netdev, u16 vsi_index,
			u16 real_qps, bool use_napi);
	int (*vsi_stop)(void *priv, u16 vsi_index);
	int (*vsi_hw_stop)(void *priv, u16 vsi_id);
	int (*switch_traffic_default_dest)(void *priv, int op);
	int (*config_fd_flow_state)(void *priv, enum nbl_chan_fdir_rule_type type, u32 state);

	/* For netdev ops */
	int (*netdev_open)(struct net_device *netdev);
	int (*netdev_stop)(struct net_device *netdev);
	int (*change_mtu)(struct net_device *netdev, int new_mtu);
	int (*change_rep_mtu)(struct net_device *netdev, int new_mtu);
	void (*get_stats64)(struct net_device *netdev, struct rtnl_link_stats64 *stats);
	void (*set_rx_mode)(struct net_device *dev);
	void (*change_rx_flags)(struct net_device *dev, int flag);
	int (*set_mac)(struct net_device *dev, void *p);
	int (*rx_add_vid)(struct net_device *dev, __be16 proto, u16 vid);
	int (*rx_kill_vid)(struct net_device *dev, __be16 proto, u16 vid);
	int (*set_features)(struct net_device *dev, netdev_features_t features);
	int (*setup_tc)(struct net_device *dev, enum tc_setup_type type, void *type_data);
	void (*reset_tc_mqprio)(struct net_device *dev);
	int (*get_phys_port_name)(struct net_device *dev, char *name, size_t len);
	int (*get_port_parent_id)(struct net_device *dev, struct netdev_phys_item_id *ppid);
	int (*set_vf_spoofchk)(struct net_device *netdev, int vf_id, bool ena);
	int (*set_vf_link_state)(struct net_device *dev, int vf_id, int link_state);
	int (*set_vf_mac)(struct net_device *netdev, int vf_id, u8 *mac);
	int (*set_vf_rate)(struct net_device *netdev, int vf_id, int min_rate, int max_rate);
	int (*set_vf_vlan)(struct net_device *dev, int vf_id, u16 vlan, u8 pri, __be16 proto);
	int (*get_vf_config)(struct net_device *dev, int vf_id, struct ifla_vf_info *ivi);
	int (*get_vf_stats)(struct net_device *dev, int vf_id, struct ifla_vf_stats *vf_stats);
	void (*tx_timeout)(struct net_device *netdev, u32 txqueue);
	int (*bridge_setlink)(struct net_device *netdev, struct nlmsghdr *nlh,
			      u16 flags, struct netlink_ext_ack *extack);
	int (*bridge_getlink)(struct sk_buff *skb, u32 pid, u32 seq,
			      struct net_device *dev, u32 filter_mask, int nlflags);
u16 (*select_queue)(struct net_device *netdev, struct sk_buff *skb,
		    struct net_device *sb_dev);
	void (*get_eth_ctrl_stats)(struct net_device *netdev,
				   struct ethtool_eth_ctrl_stats *eth_ctrl_stats);
	void (*get_eth_mac_stats)(struct net_device *netdev,
				  struct ethtool_eth_mac_stats *eth_mac_stats);
	void (*get_fec_stats)(struct net_device *netdev, struct ethtool_fec_stats *fec_stats);
	int (*set_vf_trust)(struct net_device *netdev, int vf_id, bool trusted);
	int (*register_net)(void *priv, struct nbl_ch_prm_register_net_info *param,
			    struct nbl_register_net_result *output);
	int (*unregister_net)(void *priv, u16 func_id);
	int (*setup_txrx_queues)(void *priv, u16 vsi_id, u16 queue_num, u16 net_vector_id);
	void (*remove_txrx_queues)(void *priv, u16 vsi_id);
	int (*register_vsi_info)(void *priv, struct nbl_vsi_param *vsi_param);
	int (*init_tx_rate)(void *priv, u16 vsi_id);
	int (*setup_q2vsi)(void *priv, u16 vsi_id);
	void (*remove_q2vsi)(void *priv, u16 vsi_id);
	int (*setup_rss)(void *priv, u16 vsi_id);
	void (*remove_rss)(void *priv, u16 vsi_id);
	int (*setup_rss_indir)(void *priv, u16 vsi_index);
	int (*check_offload_status)(void *priv);
	int (*get_chip_temperature)(void *priv, enum nbl_hwmon_type type, u32 senser_id);
	int (*get_module_temperature)(void *priv, u8 eth_id, enum nbl_hwmon_type type);

	void (*cpu_affinity_init)(void *priv, u16 ring_num);
	int (*alloc_rings)(void *priv, struct nbl_ring_param *param);
	void (*free_rings)(void *priv);
	void (*set_mask_en)(void *priv, bool enable);
	int (*start_net_flow)(void *priv, struct net_device *dev, u16 vsi_id, u16 vid,
			      bool trusted);
	void (*stop_net_flow)(void *priv, u16 vsi_id);
	void (*unregister_upcall_port)(void *priv);
	void (*clear_flow)(void *priv, u16 vsi_id);
	int (*set_promisc_mode)(void *priv, struct nbl_ch_prm_set_promisc_mode *param);
	int (*cfg_multi_mcast)(void *priv, struct nbl_ch_prm_cfg_multi_mcast *param);
	int (*set_lldp_flow)(void *priv, u16 vsi_id);
	int (*remove_lldp_flow)(void *priv, u16 vsi_id);
	int (*start_mgt_flow)(void *priv);
	void (*stop_mgt_flow)(void *priv);
	u32 (*get_tx_headroom)(void *priv);
	int (*set_spoof_check_addr)(void *priv, u8 *mac);

	u16 (*get_vsi_id)(void *priv, u16 func_id, u16 type);
	int (*get_my_pf)(void *priv, u16 *sfid, u8 *my_pf);
	int (*get_eth_id)(void *priv, struct nbl_ch_prm_get_eth_id *param,
			  struct nbl_ch_prm_get_eth_id *output);
	void (*debugfs_init)(void *priv);
	void (*debugfs_netops_create)(void *priv, u16 tx_queue_num, u16 rx_queue_num);
	void (*debugfs_ctrlops_create)(void *priv);
	void (*debugfs_exit)(void *priv);
	int (*setup_net_resource_mgt)(void *priv, struct net_device *dev,
				      u16 vlan_proto, u16 vlan_tci, u32 rate);
	void (*remove_net_resource_mgt)(void *priv);
	void (*start_net_resource_mgt)(void *priv);
	void (*stop_net_resource_mgt)(void *priv);
	void (*stop_net_dev_timer)(void *priv);
	void (*start_net_dev_timer)(void *priv);
	int (*init_hw_stats)(void *priv, const struct nbl_init_param *param);
	int (*remove_hw_stats)(void *priv);
	int (*get_rx_dropped)(void *priv, u64 *rx_dropped, u64 *rx_dropped_queue_disable);
	int (*set_lag_status)(void *priv, bool *lag_en);
	int (*enable_lag_protocol)(void *priv, struct nbl_ch_prm_enable_lag_protocol *param);
	int (*cfg_lag_hash_algorithm)(void *priv, struct nbl_ch_prm_cfg_lag_hash_algorithm *param);
	int (*cfg_lag_member_fwd)(void *priv, struct nbl_ch_prm_cfg_lag_member_fwd *param);
	int (*cfg_lag_member_list)(void *priv, struct nbl_lag_member_list_param *param);
	int (*cfg_lag_member_up_attr)(void *priv, struct nbl_ch_prm_cfg_lag_member_up_attr *param);
	int (*cfg_bond_shaping)(void *priv, struct nbl_ch_prm_cfg_bond_shaping *param);
	int (*cfg_bgid_back_pressure)(void *priv, struct nbl_ch_prm_cfg_bgid_back_pressure *param);
	void (*set_sfp_state)(void *priv, u8 eth_id,
			      bool open, bool is_force);
	int (*get_board_id)(void *priv);
	void (*cfg_eth_bond_event)(void *priv, bool enable);
	void (*get_board_info)(void *priv, struct nbl_board_port_info *board_info);

	/* rep associated */
	int (*rep_netdev_open)(struct net_device *netdev);
	int (*rep_netdev_stop)(struct net_device *netdev);
	netdev_tx_t (*rep_start_xmit)(struct sk_buff *skb, struct net_device *netdev);
	void (*rep_get_stats64)(struct net_device *netdev, struct rtnl_link_stats64 *stats);
	void (*rep_set_rx_mode)(struct net_device *dev);
	int (*rep_set_mac)(struct net_device *dev, void *p);
	int (*rep_rx_add_vid)(struct net_device *dev, __be16 proto, u16 vid);
	int (*rep_rx_kill_vid)(struct net_device *dev, __be16 proto, u16 vid);
	int (*rep_setup_tc)(struct net_device *dev, enum tc_setup_type type, void *type_data);
	int (*rep_get_phys_port_name)(struct net_device *dev, char *name, size_t len);
	int (*rep_get_port_parent_id)(struct net_device *dev, struct netdev_phys_item_id *ppid);
	void (*get_rep_feature)(void *priv, struct nbl_register_net_result *register_result);
	void (*get_rep_queue_num)(void *priv, u8 *base_queue_id, u8 *rep_queue_num);
	int (*alloc_rep_queue_mgt)(void *priv, struct net_device *netdev);
	void (*get_rep_queue_info)(void *priv, u16 *queue_num, u16 *queue_size);
	void (*get_user_queue_info)(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id);
	int (*free_rep_queue_mgt)(void *priv);
	int (*set_eswitch_mode)(void *priv, u16 switch_mode);
	u16 (*get_eswitch_mode)(void *priv);
	int (*alloc_rep_data)(void *priv, struct nbl_alloc_rep_data_param *param);
	void (*free_rep_data)(void *priv);
	void (*set_rep_netdev_info)(void *priv, void *rep_data);
	void (*unset_rep_netdev_info)(void *priv);
	int (*disable_phy_flow)(void *priv, u8 eth_id);
	int (*enable_phy_flow)(void *priv, u8 eth_id);
	void (*init_acl)(void *priv);
	void (*uninit_acl)(void *priv);
	int (*set_upcall_rule)(void *priv, u8 eth_id, u16 vsi_id);
	int (*unset_upcall_rule)(void *priv, u8 eth_id);
	int (*switchdev_init_cmdq)(void *priv);
	int (*switchdev_deinit_cmdq)(void *priv);
	int (*set_tc_flow_info)(void *priv);
	int (*unset_tc_flow_info)(void *priv);
	int (*get_tc_flow_info)(void *priv);
	int (*register_indr_dev_tc_offload)(void *priv, struct net_device *netdev);
	void (*unregister_indr_dev_tc_offload)(void *priv, struct net_device *netdev);
	void (*set_lag_info)(void *priv, u8 lag_id, u16 lag_num);
	void (*unset_lag_info)(void *priv);
	void (*set_netdev_ops)(void *priv, const struct net_device_ops *net_device_ops, bool is_pf);

	/* ethtool */
	void (*get_drvinfo)(struct net_device *netdev, struct ethtool_drvinfo *drvinfo);
	int (*get_module_eeprom_by_page)(struct net_device *netdev,
					 const struct ethtool_module_eeprom *page_data,
					 struct netlink_ext_ack *extack);
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
	int (*get_link_ext_state)(struct net_device *netdev,
				  struct ethtool_link_ext_state_info *link_ext_state_info);
	void (*get_link_ext_stats)(struct net_device *netdev, struct ethtool_link_ext_stats *stats);
	int (*get_ksettings)(struct net_device *netdev, struct ethtool_link_ksettings *cmd);
	int (*set_ksettings)(struct net_device *netdev, const struct ethtool_link_ksettings *cmd);
	void (*get_ringparam)(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			      struct kernel_ethtool_ringparam *k_ringparam,
			      struct netlink_ext_ack *extack);
	int (*set_ringparam)(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			     struct kernel_ethtool_ringparam *k_ringparam,
			     struct netlink_ext_ack *extack);
	int (*flash_device)(struct net_device *netdev, struct ethtool_flash *flash);
	int (*get_dump_flag)(struct net_device *netdev, struct ethtool_dump *dump);
	int (*get_dump_data)(struct net_device *netdev, struct ethtool_dump *dump, void *buffer);
	int (*set_dump)(struct net_device *netdev, struct ethtool_dump *dump);
	int (*get_coalesce)(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce *kernel_ec,
			    struct netlink_ext_ack *extack);
	int (*set_coalesce)(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce *kernel_ec,
			    struct netlink_ext_ack *extack);

	int (*get_rxnfc)(struct net_device *netdev, struct ethtool_rxnfc *cmd, u32 *rule_locs);
	int (*set_rxnfc)(struct net_device *netdev, struct ethtool_rxnfc *cmd);
	u32 (*get_rxfh_indir_size)(struct net_device *netdev);
	u32 (*get_rxfh_key_size)(struct net_device *netdev);
	int (*get_rxfh)(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc);
	int (*set_rxfh)(struct net_device *netdev, const u32 *indir, const u8 *key, const u8 hfunc);
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
	void (*get_pause_stats)(struct net_device *netdev, struct ethtool_pause_stats *pause_stats);
	void (*get_rmon_stats)(struct net_device *netdev, struct ethtool_rmon_stats *rmon_stats,
			       const struct ethtool_rmon_hist_range **range);
	int (*set_pause_param)(struct net_device *netdev, struct ethtool_pauseparam *param);
	void (*get_pause_param)(struct net_device *netdev, struct ethtool_pauseparam *param);
	int (*set_fec_param)(struct net_device *netdev, struct ethtool_fecparam *fec);
	int (*get_fec_param)(struct net_device *netdev, struct ethtool_fecparam *fec);
	int (*get_ts_info)(struct net_device *netdev, struct ethtool_ts_info *ts_info);
	int (*set_phys_id)(struct net_device *netdev, enum ethtool_phys_id_state state);
	int (*nway_reset)(struct net_device *netdev);

	void (*set_link_state)(void *priv, struct net_device *netdev);
	void (*get_rep_strings)(struct net_device *netdev, u32 stringset, u8 *data);
	int (*get_rep_sset_count)(struct net_device *netdev, int sset);
	void (*get_rep_ethtool_stats)(struct net_device *netdev,
				      struct ethtool_stats *stats, u64 *data);
	void (*get_wol)(struct net_device *netdev, struct ethtool_wolinfo *wol);
	int (*set_wol)(struct net_device *netdev, struct ethtool_wolinfo *wol);

	void (*get_rdma_cap_num)(void *priv, u16 *cap_num, u16 *my_cap_num);
	void (*setup_rdma_id)(void *priv, struct ida *adev_ida,
			      struct ida *grc_adev_ida, struct mutex *lock);
	void (*remove_rdma_id)(void *priv, struct ida *adev_ida,
			       struct ida *grc_adev_ida, struct mutex *lock);
	int (*register_rdma_grc_id)(void *priv, u16 vsi_id, int *grc_id);
	void (*unregister_rdma_grc_id)(void *priv, u16 vsi_id);
	int (*register_rdma)(void *priv, u16 vsi_id, struct nbl_rdma_register_param *param);
	void (*unregister_rdma)(void *priv, u16 vsi_id);
	int (*enable_up_rdma_bypass)(void *priv, u16 vsi_id, bool enable);
	u8 __iomem * (*get_hw_addr)(void *priv, size_t *size);
	u8 __iomem * (*get_rdma_hw_addr)(void *priv);
	u64 (*get_real_hw_addr)(void *priv, u16 vsi_id);
	u16 (*get_function_id)(void *priv, u16 vsi_id);
	void (*get_real_bdf)(void *priv, u16 vsi_id, u8 *bus, u8 *dev, u8 *function);
	int (*set_eth_mac_addr)(void *priv, u8 *mac, u8 eth_id);
	int (*process_abnormal_event)(void *priv);
	int (*get_owned_pf_bitmap)(void *priv,
				   unsigned long **owned_pf_bitmap, u8 *max_pf, u16 *bdf);
	int (*process_sfp_plug_event)(void *priv);
	void (*adapt_desc_gother)(void *priv);
	void (*process_flr)(void *priv, u16 vfid);
	bool (*check_vf_is_active)(void *priv, u16 func_id);
	void (*process_qinfo_cfg)(void *priv, u16 vfid);
	u16 (*covert_vfid_to_vsi_id)(void *priv, u16 vfid);

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
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	int (*add_tls_dev)(struct net_device *netdev, struct sock *sk,
			   enum tls_offload_ctx_dir direction,
			   struct tls_crypto_info *crypto_info,
			   u32 start_offload_tcp_sn);
	void (*del_tls_dev)(struct net_device *netdev, struct tls_context *tls_ctx,
			    enum tls_offload_ctx_dir direction);
	int (*resync_tls_dev)(struct net_device *netdev, struct sock *sk,
			      u32 tcp_seq, u8 *rec_num,
			      enum tls_offload_ctx_dir direction);
#endif
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
	int (*add_xdo_dev_state)(struct xfrm_state *x, struct netlink_ext_ack *extack);
	void (*delete_xdo_dev_state)(struct xfrm_state *x);
	void (*free_xdo_dev_state)(struct xfrm_state *x);
	bool (*xdo_dev_offload_ok)(struct sk_buff *skb, struct xfrm_state *x);
	void (*xdo_dev_state_advance_esn)(struct xfrm_state *x);
	bool (*check_ipsec_status)(void *priv);
	void (*handle_ipsec_event)(void *priv);
#endif
	void (*configure_virtio_dev_msix)(void *priv, u16 vector);
	void (*configure_rdma_msix_off)(void *priv, u16 vector);
	void (*configure_virtio_dev_ready)(void *priv);
	void (*reset_virtio_dev)(void *priv);
	bool (*get_ecpu_bond_status)(void *priv);

	int (*setup_st)(void *priv, void *st_table_param, char *st_name);
	void (*remove_st)(void *priv, void *st_table_param);
	void (*register_real_st_name)(void *priv, char *st_name);

	u16 (*get_vf_base_vsi_id)(void *priv, u16 func_id);
	int (*setup_vf_config)(void *priv, int num_vfs, bool is_flush);
	void (*remove_vf_config)(void *priv);
	void (*register_dev_name)(void *priv, u16 vsi_id, char *name);
	void (*get_dev_name)(void *priv, u16 vsi_id, char *name);

	void (*get_mirror_table_id)(void *priv, u16 vsi_id, int dir, bool mirror_en,
				    u8 *mt_id);
	int (*configure_mirror)(void *priv, u16 func_id, bool mirror_en, int dir,
				u8 mt_id);
	int (*configure_tx_mirror_to_rdma)(void *priv,
					   struct nbl_ch_prm_tx_mirror_to_rdma *param);
	int (*configure_mirror_table)(void *priv, bool mirror_en, u16 func_id, u8 mt_id);
	int (*clear_mirror_cfg)(void *priv, u16 func_id);

	int (*setup_vf_resource)(void *priv, int num_vfs);
	void (*remove_vf_resource)(void *priv);
	void (*cfg_fd_update_event)(void *priv, bool enable);

#if IS_ENABLED(CONFIG_MACSEC)
	int (*init_macsec)(void *priv);
	void (*uninit_macsec)(void *priv);
	int (*add_macsec_txsa)(struct macsec_context *ctx);
	int (*upd_macsec_txsa)(struct macsec_context *ctx);
	int (*del_macsec_txsa)(struct macsec_context *ctx);
	int (*add_macsec_rxsc)(struct macsec_context *ctx);
	int (*upd_macsec_rxsc)(struct macsec_context *ctx);
	int (*del_macsec_rxsc)(struct macsec_context *ctx);
	int (*add_macsec_rxsa)(struct macsec_context *ctx);
	int (*upd_macsec_rxsa)(struct macsec_context *ctx);
	int (*del_macsec_rxsa)(struct macsec_context *ctx);
	int (*add_macsec_secy)(struct macsec_context *ctx);
	int (*upd_macsec_secy)(struct macsec_context *ctx);
	int (*del_macsec_secy)(struct macsec_context *ctx);
#endif
	void (*get_xdp_queue_info)(void *priv, u16 *queue_num, u16 *queue_size, u16 vsi_id);
	int (*set_xdp)(struct net_device *netdev, struct netdev_bpf *xdp);
	void (*set_hw_status)(void *priv, enum nbl_hw_status hw_status);
	void (*check_hw_status)(void *priv);
	enum nbl_hw_status (*get_hw_status)(void *priv);
	void (*get_active_func_bitmaps)(void *priv, unsigned long *bitmap, int max_func);
	struct nbl_qos_info *(*get_qos_info)(void *priv);
	int (*configure_qos)(void *priv, u8 eth_id, u8 *pfc, u8 trust, u8 *dscp2prio_map);
	int (*get_pfc_buffer_size)(void *priv, u8 eth_id, u8 prio, int *xoff, int *xon);
	int (*configure_rdma_bw)(void *priv, u8 eth_id, int rdma_bw);
	int (*set_pfc_buffer_size)(void *priv, u8 eth_id, u8 prio, int xoff, int xon);
	int (*set_rate_limit)(void *priv, u16 func_id, enum nbl_traffic_type type, u32 rate);
	ssize_t (*trust_mode_show)(void *priv, u8 eth_id, char *buf);
	ssize_t (*pfc_show)(void *priv, u8 eth_id, char *buf);
	ssize_t (*dscp2prio_show)(void *priv, u8 eth_id, char *buf);
	ssize_t (*pfc_buffer_size_show)(void *priv, u8 eth_id, char *buf);

	/* dcb nl ops */
#ifdef CONFIG_DCB
	int (*ieee_setets)(struct net_device *netdev, struct ieee_ets *ets);
	int (*ieee_getets)(struct net_device *netdev, struct ieee_ets *ets);
	int (*ieee_setpfc)(struct net_device *netdev, struct ieee_pfc *pfc);
	int (*ieee_getpfc)(struct net_device *netdev, struct ieee_pfc *pfc);
	int (*ieee_setapp)(struct net_device *netdev, struct dcb_app *app);
	int (*ieee_delapp)(struct net_device *netdev, struct dcb_app *app);
	void (*dcbnl_getpfccfg)(struct net_device *netdev, int prio, u8 *setting);
	void (*dcbnl_setpfccfg)(struct net_device *netdev, int prio, u8 set);
	int (*dcbnl_getnumtcs)(struct net_device *netdev, int tcid, u8 *num);
	u8 (*ieee_getdcbx)(struct net_device *netdev);
	u8 (*ieee_setdcbx)(struct net_device *netdev, u8 mode);
	u8 (*dcbnl_getstate)(struct net_device *netdev);
	u8 (*dcbnl_setstate)(struct net_device *netdev, u8 state);
	u8 (*dcbnl_getpfcstate)(struct net_device *netdev);
	u8 (*dcbnl_getcap)(struct net_device *netdev, int capid, u8 *cap);
#endif
	u16 (*get_vf_function_id)(void *priv, int vf_id);
	void (*cfg_mirror_outputport_event)(void *priv, bool enable);
};

struct nbl_service_ops_tbl {
	struct nbl_resource_pt_tbl pt_tbl;
	struct nbl_service_ops *ops;
	void *priv;
};

int nbl_serv_init(void *priv, struct nbl_init_param *param);
void nbl_serv_remove(void *priv);

#endif
