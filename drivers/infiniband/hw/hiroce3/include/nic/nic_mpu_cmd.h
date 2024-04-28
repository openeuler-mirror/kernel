/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef NIC_MPU_CMD_H
#define NIC_MPU_CMD_H

/** Commands between NIC to MPU
 */
enum hinic3_nic_cmd {
	HINIC3_NIC_CMD_VF_REGISTER = 0, /**< Only for PFD and VFD @see > hinic3_cmd_register_vf */

	/** FUNC CFG */
	HINIC3_NIC_CMD_SET_FUNC_TBL = 5, /**< Set function table @see > hinic3_cmd_set_func_tbl */
	HINIC3_NIC_CMD_SET_VPORT_ENABLE, /**< Enable a vport @see > hinic3_vport_state */
	HINIC3_NIC_CMD_SET_RX_MODE, /**< Set nic rx mode. @see > hinic3_rx_mode_config */
	HINIC3_NIC_CMD_SQ_CI_ATTR_SET,	/**< Set SQ CI attr @see > hinic3_cmd_cons_idx_attr */
	/**< Get vport stat @see > hinic3_port_stats_info, < hinic3_cmd_vport_stats */
	HINIC3_NIC_CMD_GET_VPORT_STAT,
	/**< Clean vport stat @see > hinic3_cmd_clear_vport_stats */
	HINIC3_NIC_CMD_CLEAN_VPORT_STAT,
	/**< Clean queue pair resource @see > hinic3_cmd_clear_qp_resource */
	HINIC3_NIC_CMD_CLEAR_QP_RESOURCE,
	HINIC3_NIC_CMD_CFG_FLEX_QUEUE,	/**< Set flex queue @see > hinic3_cmd_cfg_qps */
	/** LRO CFG */
	HINIC3_NIC_CMD_CFG_RX_LRO,	 /**< Set rx LRO @see > hinic3_cmd_lro_config */
	HINIC3_NIC_CMD_CFG_LRO_TIMER,	  /**< Set LRO timer @see > hinic3_cmd_lro_timer */
	/**< negotiate features @see > hinic3_cmd_feature_nego */
	HINIC3_NIC_CMD_FEATURE_NEGO,
	/**< Configure local LRO state @see > hinic3_cmd_local_lro_state */
	HINIC3_NIC_CMD_CFG_LOCAL_LRO_STATE,

	/**< Cache out queue pair resource @see > hinic3_cmd_cache_out_qp_resource */
	HINIC3_NIC_CMD_CACHE_OUT_QP_RES,

	/** MAC & VLAN CFG */
	HINIC3_NIC_CMD_GET_MAC = 20,	   /**< Get mac address @see > hinic3_port_mac_set */
	HINIC3_NIC_CMD_SET_MAC,	/**< Set mac address @see > hinic3_port_mac_set */
	HINIC3_NIC_CMD_DEL_MAC,	/**< Delete mac address @see > hinic3_port_mac_set */
	/**< Update mac address @see > hinic3_port_mac_update */
	HINIC3_NIC_CMD_UPDATE_MAC,
	/**< Get all default mac address @see > cmd_mac_info_get_s */
	HINIC3_NIC_CMD_GET_ALL_DEFAULT_MAC,

	/**< Configure function vlan @see > hinic3_cmd_vlan_config */
	HINIC3_NIC_CMD_CFG_FUNC_VLAN,
	/**< Enable vlan filter @see > hinic3_cmd_set_vlan_filter */
	HINIC3_NIC_CMD_SET_VLAN_FILTER_EN,
	/**< Set rx vlan offload @see > hinic3_cmd_vlan_offload */
	HINIC3_NIC_CMD_SET_RX_VLAN_OFFLOAD,
	HINIC3_NIC_CMD_SMAC_CHECK_STATE,

	/** SR-IOV */
	/**< Configure vf vlan @see > hinic3_cmd_vf_vlan_config */
	HINIC3_NIC_CMD_CFG_VF_VLAN = 40,
	/**< Set snoopchk state @see > hinic3_cmd_spoofchk_set */
	HINIC3_NIC_CMD_SET_SPOOPCHK_STATE,
	/* RATE LIMIT */
	/**< Set rate limit @see > HINIC3_NIC_CMD_SET_MAX_MIN_RATE */
	HINIC3_NIC_CMD_SET_MAX_MIN_RATE,

	/** RSS CFG */
	HINIC3_NIC_CMD_RSS_CFG = 60,	   /**< Set rss config @see > hinic3_cmd_rss_config */
	HINIC3_NIC_CMD_RSS_TEMP_MGR, /**< TODO: delete after implement nego cmd */
	HINIC3_NIC_CMD_GET_RSS_CTX_TBL, /**< TODO: delete: move to ucode cmd */
	/**< Set rss hash key @see > hinic3_cmd_rss_hash_key */
	HINIC3_NIC_CMD_CFG_RSS_HASH_KEY,
	/**< Set rss hash engine type @see > hinic3_cmd_rss_engine_type */
	HINIC3_NIC_CMD_CFG_RSS_HASH_ENGINE,
	/**< Set rss context table info @see > hinic3_rss_context_table */
	HINIC3_NIC_CMD_SET_RSS_CTX_TBL_INTO_FUNC,
	/** IP checksum error packets, enable rss quadruple hash */
	/**< Set rss config @see > hinic3_ipcs_err_rss_enable_operation_s */
	HINIC3_NIC_CMD_IPCS_ERR_RSS_ENABLE_OP = 66,

	/** PPA/FDIR */
	HINIC3_NIC_CMD_ADD_TC_FLOW = 80,	/**< Add tc flow @see > nic_cmd_fdir_add_rule */
	HINIC3_NIC_CMD_DEL_TC_FLOW, /**< Delete tc flow @see > nic_cmd_fdir_del_rules */
	HINIC3_NIC_CMD_GET_TC_FLOW, /**< Get tc flow @see > nic_cmd_fdir_get_rule */
	HINIC3_NIC_CMD_FLUSH_TCAM,  /**< Flush TCAM @see > nic_cmd_flush_tcam_rules */
	/**< Configure TCAM block @see > nic_cmd_ctrl_tcam_block_out */
	HINIC3_NIC_CMD_CFG_TCAM_BLOCK,
	/**< Enable TCAM @see > nic_cmd_set_tcam_enable */
	HINIC3_NIC_CMD_ENABLE_TCAM,
	/**< Get TCAM block @see > nic_cmd_dfx_fdir_tcam_block_table */
	HINIC3_NIC_CMD_GET_TCAM_BLOCK,
	/**< Configure PPA table id @see > hinic3_ppa_cfg_table_id_cmd */
	HINIC3_NIC_CMD_CFG_PPA_TABLE_ID,
	/**< Set PPA enable @see > hinic3_ppa_cfg_ppa_en_cmd */
	HINIC3_NIC_CMD_SET_PPA_EN = 88,
	/**< Configure PPA mode @see > hinic3_ppa_cfg_mode_cmd */
	HINIC3_NIC_CMD_CFG_PPA_MODE,
	/**< Configure PPA flush @see > hinic3_ppa_cfg_flush_cmd */
	HINIC3_NIC_CMD_CFG_PPA_FLUSH,
	/**< Set FDIR status @see > hinic3_set_fdir_ethertype_rule */
	HINIC3_NIC_CMD_SET_FDIR_STATUS,
	/**< Get PPA counter @see > hinic3_ppa_fdir_query_cmd */
	HINIC3_NIC_CMD_GET_PPA_COUNTER,
	/**< Set flow bifur status @see > cmd_flow_bifur_func_handle */
	HINIC3_NIC_CMD_SET_FUNC_FLOW_BIFUR_ENABLE,
	/**< Set flow bifur bond @see > cmd_flow_bifur_bond_handle */
	HINIC3_NIC_CMD_SET_BOND_MASK,
	/**< Get func tcam table @see > get_fdir_func_tcam_table */
	HINIC3_NIC_CMD_GET_BLOCK_TC_FLOWS,
	/**< Get flow bifur bond @see > cmd_flow_bifur_bond_handle */
	HINIC3_NIC_CMD_GET_BOND_MASK,

	/** PORT CFG */
	HINIC3_NIC_CMD_SET_PORT_ENABLE = 100,	 /**< set port enable @see > hinic3_port_state */
	HINIC3_NIC_CMD_CFG_PAUSE_INFO,	/**< Configure pause info @see > hinic3_cmd_pause_config */

	HINIC3_NIC_CMD_SET_PORT_CAR,	  /**< Set port Car @see > hinic3_cmd_set_port_car */
	HINIC3_NIC_CMD_SET_ER_DROP_PKT,   /**< Unused */

	HINIC3_NIC_CMD_VF_COS,	/**< Get vf CoS @see > hinic3_cmd_vf_dcb_state */
	HINIC3_NIC_CMD_SETUP_COS_MAPPING,	 /**< Unused */
	HINIC3_NIC_CMD_SET_ETS,   /**< Unused */
	HINIC3_NIC_CMD_SET_PFC,   /**< Unused */
	HINIC3_NIC_CMD_QOS_ETS,   /**< Set QoS ETS @see > hinic3_cmd_ets_cfg */
	HINIC3_NIC_CMD_QOS_PFC,   /**< Set QoS PFC @see > hinic3_cmd_set_pfc */
	HINIC3_NIC_CMD_QOS_DCB_STATE,	 /**< Get QoS DCB state @see > hinic3_cmd_set_dcb_state */
	HINIC3_NIC_CMD_QOS_PORT_CFG,	  /**< Get QoS port cfg @see > hinic3_cmd_qos_port_cfg */
	HINIC3_NIC_CMD_QOS_MAP_CFG,	 /**< Get QoS map cfg @see > hinic3_cmd_qos_map_cfg */
	HINIC3_NIC_CMD_FORCE_PKT_DROP,	/**< Force pkt drop @see > hinic3_force_pkt_drop */
	/**< Configure nic tx promisc skip @see > hinic3_tx_promisc_cfg */
	HINIC3_NIC_CMD_CFG_TX_PROMISC_SKIP = 114,
	/**< Set flow bifur port switch @see > cmd_flow_bifur_port_handle */
	HINIC3_NIC_CMD_SET_PORT_FLOW_BIFUR_ENABLE = 117,
	/**< Set tx pause exc notice @see > nic_cmd_tx_pause_notice */
	HINIC3_NIC_CMD_TX_PAUSE_EXCP_NOTICE = 118,
	/**< Inquirt pause cfg @see > nic_cmd_pause_inquiry_cfg_s */
	HINIC3_NIC_CMD_INQUIRT_PAUSE_CFG = 119,

	/** MISC */
	HINIC3_NIC_CMD_BIOS_CFG = 120,  /**< Set QoS ETS @see > nic_cmd_bios_cfg */
	HINIC3_NIC_CMD_SET_FIRMWARE_CUSTOM_PACKETS_MSG, /**< Set QoS ETS @see > fault_msg_st */

	/** BOND */
	/**< Create bond device @see > hinic3_cmd_create_bond */
	HINIC3_NIC_CMD_BOND_DEV_CREATE = 134,
	HINIC3_NIC_CMD_BOND_DEV_DELETE, /**< Delete bond device @see > hinic3_cmd_delete_bond */
	/**<Open/close bond dev @see > hinic3_cmd_open_close_bond */
	HINIC3_NIC_CMD_BOND_DEV_OPEN_CLOSE,
	HINIC3_NIC_CMD_BOND_INFO_GET,   /**< Set QoS ETS @see > hinic3_bond_status_info */
	/**< Get bond active info @see > hinic3_bond_active_report_info */
	HINIC3_NIC_CMD_BOND_ACTIVE_INFO_GET,
	/**< Bond active notice report @see > nic_cmd_bond_active_report_info */
	HINIC3_NIC_CMD_BOND_ACTIVE_NOTICE,

	/** DFX */
	HINIC3_NIC_CMD_GET_SM_TABLE = 140,  /**< Get sm table @see > nic_cmd_dfx_sm_table */
	/**< Set RD line table @see > nic_mpu_lt_opera, < nic_mpu_lt_opera */
	HINIC3_NIC_CMD_RD_LINE_TBL,

	HINIC3_NIC_CMD_SET_UCAPTURE_OPT = 160, /**< TODO: move to roce */
	HINIC3_NIC_CMD_SET_VHD_CFG, /**< Set VHD configuration @see > hinic3_set_vhd_mode */

	/** TODO: move to HILINK */
	/**< Get port stat @see > hinic3_port_stats_info, < hinic3_port_stats */
	HINIC3_NIC_CMD_GET_PORT_STAT = 200,
	HINIC3_NIC_CMD_CLEAN_PORT_STAT, /**< Unused */
	HINIC3_NIC_CMD_CFG_LOOPBACK_MODE,	   /**< Unused */
	HINIC3_NIC_CMD_GET_SFP_QSFP_INFO,	   /**< Unused */
	HINIC3_NIC_CMD_SET_SFP_STATUS,	  /**< Unused */
	HINIC3_NIC_CMD_GET_LIGHT_MODULE_ABS,		/**< Unused */
	HINIC3_NIC_CMD_GET_LINK_INFO,	   /**< Unused */
	HINIC3_NIC_CMD_CFG_AN_TYPE, /**< Unused */
	HINIC3_NIC_CMD_GET_PORT_INFO,	  /**< Get port info @see > hinic3_cmd_port_info */
	HINIC3_NIC_CMD_SET_LINK_SETTINGS,	   /**< Unused */
	HINIC3_NIC_CMD_ACTIVATE_BIOS_LINK_CFG,	  /**< Unused */
	HINIC3_NIC_CMD_RESTORE_LINK_CFG,	 /**< Unused */
	HINIC3_NIC_CMD_SET_LINK_FOLLOW, /**< Unused */
	HINIC3_NIC_CMD_GET_LINK_STATE,	  /**< Unused */
	HINIC3_NIC_CMD_LINK_STATUS_REPORT,  /**< Unused */
	HINIC3_NIC_CMD_CABLE_PLUG_EVENT,	   /**< Unused */
	HINIC3_NIC_CMD_LINK_ERR_EVENT,	  /**< Unused */
	HINIC3_NIC_CMD_SET_LED_STATUS,	  /**< Unused */

	HINIC3_NIC_CMD_MAX = 256,
};

#endif /* NIC_MPU_CMD_H */
