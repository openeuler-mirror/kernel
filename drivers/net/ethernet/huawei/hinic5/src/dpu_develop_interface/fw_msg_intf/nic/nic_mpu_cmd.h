/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_mpu_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : NIC Commands between Driver and MPU
 */

#ifndef HINIC5_NIC_CMD_H
#define HINIC5_NIC_CMD_H

/**
 * @brief enum hinic5_nic_cmd
 * @details nic hinic commands
 */
enum hinic5_nic_cmd {
	HINIC5_NIC_CMD_VF_REGISTER = 0, /** <  @see hinic5_cmd_register_vf */
	HINIC5_NIC_CMD_SET_FUNC_TBL = 5, /* Set FUNC table initialization, mtu value, etc.
					  * @see hinic5_cmd_set_func_tbl
					  */
	HINIC5_NIC_CMD_SET_VPORT_ENABLE = 6, /* func enable/disable flag (OVS uses PF to send on behalf)
					      * @see hinic5_vport_state
					      */
	HINIC5_NIC_CMD_SET_RX_MODE = 7, /* Set unicast, multicast promiscuous mode flags
					 * @see hinic5_rx_mode_config
					 */
	HINIC5_NIC_CMD_SQ_CI_ATTR_SET = 8, /* Set func CI attribute table
					    * @see hinic5_cmd_cons_idx_attr
					    */
	HINIC5_NIC_CMD_GET_VPORT_STAT = 9, /* Get func unicast, discard statistics
					    * @see hinic5_port_stats_info/hinic5_cmd_vport_stats
					    */
	HINIC5_NIC_CMD_CLEAN_VPORT_STAT = 10, /* Clean func unicast, discard statistics
					       * @see hinic5_port_stats_info
					       */
	HINIC5_NIC_CMD_CLEAR_QP_RESOURCE = 11, /* Clear func queue CPI CI value to 0
						* @see hinic5_cmd_clear_qp_resource
						*/
	HINIC5_NIC_CMD_CFG_FLEX_QUEUE = 12, /** < rsvd */
	HINIC5_NIC_CMD_CFG_RX_LRO = 13, /** < Configure LRO enable @see hinic5_cmd_lro_config */
	HINIC5_NIC_CMD_CFG_LRO_TIMER = 14, /** < Enable LRO Timer @see hinic5_cmd_lro_timer */
	HINIC5_NIC_CMD_FEATURE_NEGO = 15, /** < func attribute negotiation @see hinic5_cmd_feature_nego */
	HINIC5_NIC_CMD_CFG_LOCAL_LRO_STATE = 16, /* Set func local_switch_lro_en
						  * @see hinic5_cmd_local_lro_state
						  */
	HINIC5_NIC_CMD_CACHE_OUT_QP_RES = 17, /* Clean L2NIC/SMMC_CLA Cache resource
					       * @see hinic5_cmd_cache_out_qp_resource
					       */
	HINIC5_NIC_CMD_SET_FUNC_ER_FWD_ID = 18, /* Set NIC ER forwarding ID, used for flow bifurcation (for computation, rsvd) */
	HINIC5_NIC_CMD_GET_MAC = 20, /** < func get MAC address @see hinic5_port_mac_set */
	HINIC5_NIC_CMD_SET_MAC = 21, /** < func set MAC address @see hinic5_port_mac_set */
	HINIC5_NIC_CMD_DEL_MAC = 22, /** < func delete MAC address @see hinic5_port_mac_set */
	HINIC5_NIC_CMD_UPDATE_MAC = 23, /** < func update MAC address @see hinic5_port_mac_update */
	HINIC5_NIC_CMD_GET_ALL_DEFAULT_MAC = 24, /* Get all default MAC addresses
						  * @see nic_cmd_mac_info
						  */
	HINIC5_NIC_CMD_CFG_FUNC_VLAN = 25, /* Add/delete func vlan device
					    * @see hinic5_cmd_vlan_config
					    */
	HINIC5_NIC_CMD_SET_VLAN_FILTER_EN = 26, /* Set func VLAN filter function
						 * @see hinic5_cmd_set_vlan_filter
						 */
	HINIC5_NIC_CMD_SET_RX_VLAN_OFFLOAD = 27, /* Set func table rx_vlan_offload_en
						  * @see hinic5_cmd_vlan_offload
						  */
	HINIC5_NIC_CMD_SMAC_CHECK_STATE = 28, /* IPSUTX source MAC check switch
					       * @see hinic5_smac_check_state
					       */
	HINIC5_NIC_CMD_OUTBAND_SET_FUNC_VLAN = 29, /* Outband set func vlan (for computation, rsvd) */
	HINIC5_NIC_CMD_CFG_VXLAN_PORT = 30, /** < Set vxlan_dprot (for computation, rsvd) */
	HINIC5_NIC_CMD_RX_RATE_CFG = 31, /** < rx rate limit bios setting (for computation, rsvd) */
	HINIC5_NIC_CMD_WR_ORDERING_CFG = 32, /* Set PCIe read/write strong ordering or relaxed ordering (for computation, rsvd) */
	HINIC5_NIC_CMD_MAC_SYNC = 33, /** < Set mac sync (for computation, rsvd) */
	HINIC5_NIC_CMD_SET_RQ_CI_CTX = 34, /** <  @see hinic5_rq_cqe_ctx */
	HINIC5_NIC_CMD_SET_RQ_ENABLE = 35, /** <  @see hinic5_rq_enable */
	HINIC5_NIC_CMD_CFG_VF_VLAN = 40, /* Add/delete func vlan device (QinQ)
					  * @see hinic5_cmd_vf_vlan_config
					  */
	HINIC5_NIC_CMD_SET_SPOOFCHK_STATE = 41, /** <  @see hinic5_cmd_spoofchk_set */
	HINIC5_NIC_CMD_SET_MAX_MIN_RATE = 42, /** < Set func rate limit @see hinic5_cmd_rate_cfg */
	HINIC5_NIC_CMD_CFG_CQE_COALESCE_OFFLOAD = 43, /* Set cqe coalesce offload function (for computation, rsvd) */
	HINIC5_NIC_CMD_CFG_CQE_COALESCE_OFFLOAD_TIMER = 44, /* Set cqe coalesce offload function timer
							     * (for computation, rsvd)
							     */
	HINIC5_NIC_CMD_CFG_VF_TRUST = 46, /** < Set vf trust enable @see hinic5_set_vf_trust */
	HINIC5_NIC_CMD_RSS_CFG = 60, /* Set func rss enable, rq_pri_num, etc.
				      * @see hinic5_cmd_rss_config
				      */
	HINIC5_NIC_CMD_RSS_TEMP_MGR = 61, /* Allocate/free func rss template table
					   * @see hinic5_rss_template_mgmt
					   */
	HINIC5_NIC_CMD_GET_RSS_CTX_TBL = 62, /* Set func rss context
					      * @see hinic5_rss_context_table
					      */
	HINIC5_NIC_CMD_CFG_RSS_HASH_KEY = 63, /* Set func rss key
					       * @see hinic5_cmd_rss_hash_key
					       */
	HINIC5_NIC_CMD_CFG_RSS_HASH_ENGINE = 64, /* Set func rss engine
						  * @see hinic5_cmd_rss_engine_type
						  */
	HINIC5_NIC_CMD_SET_RSS_CTX_TBL_INTO_FUNC = 65, /* Set func rss type and rss type en
							* @see hinic5_rss_context_table
							*/
	HINIC5_NIC_CMD_IPCS_ERR_RSS_ENABLE_OP = 66, /* Set global table ipcs_err_rss_en
						     * @see hinic5_ipcs_err_rss_enable_operation_s
						     */
	HINIC5_NIC_CMD_GTP_INNER_PARSE_STATUS = 67, /* Control gtp inner parse status (for computation, rsvd) */
	HINIC5_NIC_CMD_ADD_TC_FLOW = 80, /** < Add TCAM rule @see nic_cmd_fdir_add_rule */
	HINIC5_NIC_CMD_DEL_TC_FLOW = 81, /** < Delete TCAM rule @see nic_cmd_fdir_del_rules */
	HINIC5_NIC_CMD_GET_TC_FLOW = 82, /** < Get TCAM rule @see nic_cmd_fdir_get_rule */
	HINIC5_NIC_CMD_FLUSH_TCAM = 83, /* Clear all TCAM rules and blocks for a func
					 * @see nic_cmd_flush_tcam_rules
					 */
	HINIC5_NIC_CMD_CFG_TCAM_BLOCK = 84, /* Allocate/free func block resource
					     * @see nic_cmd_ctrl_tcam_block_in/
					     * @see nic_cmd_ctrl_tcam_block_out
					     */
	HINIC5_NIC_CMD_ENABLE_TCAM = 85, /* Set func fdir_tcam_enable
					  * @see nic_cmd_set_tcam_enable
					  */
	HINIC5_NIC_CMD_GET_TCAM_BLOCK = 86, /* Get which func is using a certain block
					     * @see nic_cmd_dfx_fdir_tcam_block_table
					     */
	HINIC5_NIC_CMD_CFG_PPA_TABLE_ID = 87, /** <  @see hinic5_ppa_cfg_table_id_cmd */
	HINIC5_NIC_CMD_SET_PPA_EN = 88, /* Set func table ppa enable @see hinic5_ppa_cfg_ppa_en_cmd */
	HINIC5_NIC_CMD_CFG_PPA_MODE = 89, /** <  @see hinic5_ppa_cfg_mode_cmd */
	HINIC5_NIC_CMD_CFG_PPA_FLUSH = 90, /* Set global table ppa_flow_flush_en
					    * @see hinic5_ppa_flush_en_cmd
					    */
	HINIC5_NIC_CMD_SET_FDIR_STATUS = 91, /* Set SML FDIR linear table @see nic_cmd_set_fdir_status */
	HINIC5_NIC_CMD_GET_PPA_COUNTER = 92, /** <  @see hinic5_ppa_fdir_query_cmd */
	HINIC5_NIC_CMD_SET_FUNC_FLOW_BIFUR_ENABLE = 93, /* Set/query func table flow_bifur_en
							 * (for computation, rsvd)
							 */
	HINIC5_NIC_CMD_SET_BOND_MASK = 94, /** < Set bond mask (for computation, rsvd) */
	HINIC5_NIC_CMD_GET_BLOCK_TC_FLOWS = 95, /* Get all rules under a block?
						 * @see nic_cmd_fdir_get_block_rules
						 */
	HINIC5_NIC_CMD_GET_BOND_MASK = 96, /** < Read bond mask (for computation, rsvd) */
	HINIC5_NIC_CMD_SET_PORT_ENABLE = 100, /** <  @see hinic5_port_state */
	HINIC5_NIC_CMD_CFG_PAUSE_INFO = 101, /* Set/query port pause status
					      * @see hinic5_cmd_pause_config
					      */
	HINIC5_NIC_CMD_CFG_PORT_CAR = 102, /* Set/query/enable arp/icmp car rate limit
					    * @see 182x:hinic5_cmd_set_port_car\
					    * @see 1872:hinic5_cmd_set_car/hinic5_car_profile
					    */
	HINIC5_NIC_CMD_SET_ER_DROP_PKT = 103, /** < rsvd */
	HINIC5_NIC_CMD_VF_COS = 104, /** <  @see hinic5_cmd_vf_dcb_state */
	HINIC5_NIC_CMD_SETUP_COS_MAPPING = 105, /** < rsvd */
	HINIC5_NIC_CMD_SET_ETS = 106, /** < rsvd */
	HINIC5_NIC_CMD_SET_PFC = 107, /** < rsvd */
	HINIC5_NIC_CMD_QOS_ETS = 108, /* QoS ETS scheduling weight configuration/query @see hinic5_cmd_ets_cfg */
	HINIC5_NIC_CMD_QOS_PFC = 109, /** < QoS PFC configuration/query @see hinic5_cmd_set_pfc */
	HINIC5_NIC_CMD_QOS_DCB_STATE = 110, /* QoS configure func and its Port DCB state
					     * @see hinic5_cmd_set_dcb_state
					     */
	HINIC5_NIC_CMD_QOS_PORT_CFG = 111, /* QoS Port trust information configuration/query
					    * @see hinic5_cmd_qos_port_cfg
					    */
	HINIC5_NIC_CMD_QOS_MAP_CFG = 112, /* QoS PCP/DSCP mapping configuration/query
					   * @see hinic5_cmd_qos_map_cfg
					   */
	HINIC5_NIC_CMD_FORCE_PKT_DROP = 113, /* QoS Port PFC/Pause forced packet drop
					      * @see hinic5_force_pkt_drop
					      */
	HINIC5_NIC_CMD_CFG_TX_PROMISC_SKIP = 114, /* Set promisc PF whether to receive TX unknown unicast packets
						   * @see hinic5_tx_promisc_cfg
						   */
	HINIC5_NIC_CMD_GET_CIR_DROP = 115, /** < Read cir (for computation, rsvd) */
	HINIC5_NIC_CMD_SET_PORT_FLOW_BIFUR_ENABLE = 117, /* Set/query port table flow_bifur_en
							  * (for computation, rsvd)
							  */
	HINIC5_NIC_CMD_TX_PAUSE_EXCP_NOTICE = 118, /** <  @see nic_cmd_tx_pause_notice */
	HINIC5_NIC_CMD_INQUIRT_PAUSE_CFG = 119, /* QoS PFC storm detection parameter configuration
						 * @see nic_cmd_pause_inquiry_cfg
						 */
	HINIC5_NIC_CMD_BIOS_CFG = 120, /** < Persist BIOS configuration/query @see nic_cmd_bios_cfg */
	HINIC5_NIC_CMD_SET_FIRMWARE_CUSTOM_PACKETS_MSG = 121, /* Receive fast fault notification content
							       * @see fault_msg_s
							       */
	HINIC5_NIC_CMD_QOS_EXTEND_CFG = 122, /** < QoS extended configuration, supports TC rate limit configuration/query */
	HINIC5_NIC_CMD_BOND_LINK_INFO_GET = 130, /** <  @see hinic5_bond_link_info */
	HINIC5_NIC_CMD_MACSEC_PN_EXPIRED_NOTICE = 131, /* @see tag_macsec_pn_expired_report_cmd_s */
	HINIC5_NIC_CMD_PASS_ARP_PKT = 132, /** <  @see hinic5_arp_pkt_info */
	HINIC5_NIC_CMD_BOND_DEV_CFG = 133, /** <  @see hinic5_cmd_cfg_bond */
	HINIC5_NIC_CMD_BOND_DEV_CREATE = 134, /** <  @see hinic5_cmd_create_bond */
	HINIC5_NIC_CMD_BOND_DEV_DELETE = 135, /** <  @see hinic5_cmd_delete_bond */
	HINIC5_NIC_CMD_BOND_DEV_OPEN_CLOSE = 136, /** <  @see hinic5_cmd_open_close_bond */
	HINIC5_NIC_CMD_BOND_INFO_GET = 137, /** <  @see hinic5_bond_status_info */
	HINIC5_NIC_CMD_BOND_ACTIVE_INFO_GET = 138, /** <  @see hinic5_bond_active_report_info */
	HINIC5_NIC_CMD_BOND_ACTIVE_NOTICE = 139, /** <  @see nic_cmd_bond_active_report_info */
	HINIC5_NIC_CMD_GET_SM_TABLE = 140, /* Get MAC table and other information @see nic_cmd_dfx_sm_table */
	HINIC5_NIC_CMD_RD_LINE_TBL = 141, /* Get SM linear table information @see nic_mpu_lt_opera */
	HINIC5_NIC_CMD_SET_VEB = 143, /** < Query or configure veb offload mode @see hinic5_veb_set */
	HINIC5_NIC_CMD_NIC_VPORT_CNT = 144, /* Query or configure VF vport count
					     * @see hinic5_nic_vport_cnt_info
					     */
	HINIC5_NIC_CMD_SET_UCAPTURE_OPT = 160, /* RoCE packet capture function switch @see nic_cmd_capture_info */
	HINIC5_NIC_CMD_SET_VHD_CFG = 161, /* Set func table vhd_type related parameters @see nic_cmd_vhd_config */
	HINIC5_NIC_CMD_GET_UCAPTURE_INFO = 162, /* Get PF packet capture function enable status, iterate through PFs,
						 * return bitmap of enabled packet capture functions (for computation, rsvd)
						 */
	HINIC5_NIC_CMD_GET_OUTBAND_CFG = 170, /** < Get outband settings (for computation, rsvd) */
	HINIC5_NIC_CMD_OUTBAND_CFG_NOTICE = 171, /* Outband information get (for computation, rsvd) */
	HINIC5_NIC_CMD_FLUSH_TC_FLOW = 176, /** <  @see hinic5_tc_flush_info */
	HINIC5_NIC_CMD_CFG_VXLAN_TBL = 177, /** <  @see hinic5_tc_vxlan_tbl_cfg_info */
	HINIC5_NIC_CMD_MOVE_TC_TBL = 178, /** <  @see hinic5_tc_move_info */
	HINIC5_NIC_CMD_CFG_TC_AGING_TBL = 179, /** <  @see hinic5_tc_aging_info */
	HINIC5_NIC_CMD_PFE_CNT = 180, /** <  @see hinic5_tc_pfe_cnt_info */
	HINIC5_NIC_CMD_GET_PFE_CFG = 181, /** <  @see hinic5_tc_pfe_cfg_reg_info */
	HINIC5_NIC_CMD_CFG_PFE_TCAM = 182, /** <  @see hinic5_tc_tcam_info */
	HINIC5_NIC_CMD_CFG_PFE_VTEP_IP = 183, /** <  @see hinic5_tc_pfe_vtep_ip_cmd */
	HINIC5_NIC_CMD_SET_PFE_DEFAULT_ACTION = 184, /** <  @see hinic5_tc_default_action_info */
	HINIC5_NIC_CMD_PFE_TCAM_FREQ = 185, /** <  @see hinic5_tc_pfe_tcam_freq_info */
	HINIC5_NIC_CMD_CFG_TCAM_CLOCK_GATING = 186, /* @see hinic5_tc_tcam_clock_gating_cfg_info */
	HINIC5_NIC_CMD_CFG_TC_FLOW_RULE = 187, /** <  @see hinic5_tc_cfg_info */
	HINIC5_NIC_CMD_SET_PFE_CFG_PROFILE = 188, /** <  @see hinic5_tc_pfe_cfg_profile_info */
	HINIC5_NIC_CMD_GET_PORT_STAT = 200, /** < rsvd */
	HINIC5_NIC_CMD_CLEAN_PORT_STAT = 201, /** < rsvd */
	HINIC5_NIC_CMD_CFG_LOOPBACK_MODE = 202, /** < rsvd */
	HINIC5_NIC_CMD_GET_SFP_QSFP_INFO = 203, /** < rsvd */
	HINIC5_NIC_CMD_SET_SFP_STATUS = 204, /** < rsvd */
	HINIC5_NIC_CMD_GET_LIGHT_MODULE_ABS = 205, /** < rsvd */
	HINIC5_NIC_CMD_GET_LINK_INFO = 206, /** < rsvd */
	HINIC5_NIC_CMD_CFG_AN_TYPE = 207, /** < rsvd */
	HINIC5_NIC_CMD_GET_PORT_INFO = 208, /** <  @see hinic5_cmd_port_info */
	HINIC5_NIC_CMD_SET_LINK_SETTINGS = 209, /** < rsvd */
	HINIC5_NIC_CMD_ACTIVATE_BIOS_LINK_CFG = 210, /** < rsvd */
	HINIC5_NIC_CMD_RESTORE_LINK_CFG = 211, /** < rsvd */
	HINIC5_NIC_CMD_SET_LINK_FOLLOW = 212, /** < rsvd */
	HINIC5_NIC_CMD_GET_LINK_STATE = 213, /** < rsvd */
	HINIC5_NIC_CMD_LINK_STATUS_REPORT = 214, /** < rsvd */
	HINIC5_NIC_CMD_CABLE_PLUG_EVENT = 215, /** < rsvd */
	HINIC5_NIC_CMD_LINK_ERR_EVENT = 216, /** < rsvd */
	HINIC5_NIC_CMD_SET_LED_STATUS = 217, /** < rsvd */
	HINIC5_NIC_CMD_MIG_SET_CEQ_CTRL = 230, /** <  @see mig_nic_set_ceq_ctrl */
	HINIC5_NIC_CMD_MIG_CFG_MSIX_INFO = 231, /** <  @see mig_nic_msix_info_rw */
	HINIC5_NIC_CMD_MIG_CFG_FUNC_VAT_TBL = 232, /** <  @see mig_nic_func_vat_tbl */
	HINIC5_NIC_CMD_MIG_GET_VF_INFO = 233, /** <  @see mig_nic_func_cfg */
	HINIC5_NIC_CMD_MIG_CHK_MBX_EMPTY = 234, /** <  @see mig_nic_chk_mbx_empty */
	HINIC5_NIC_CMD_MIG_SET_VPORT_ENABLE = 235, /** <  @see mig_nic_vport_state */
	HINIC5_NIC_CMD_MIG_CFG_SQ_CI = 236, /** <  @see mig_nic_sq_ci */
	HINIC5_NIC_CMD_MIG_CFG_RSS_TBL = 237, /** <  @see mig_nic_cfg_rss_tbl */
	HINIC5_NIC_CMD_MIG_TMP_SET_CMDQ_CTX = 238, /** <  @see mig_nic_tmp_cfg_cmdq_ctx */
	HINIC5_NIC_CMD_MIG_STOP_SQ = 239, /** <  @see nic_mig_sq_stop */
	HINIC5_NIC_CMD_MIG_CFG_FAST_MSG_ADDR = 240, /** <  @see mig_nic_fast_msg_addr */
	HINIC5_NIC_CMD_MIG_SET_FUNC_FLR_MGMT = 241, /** <  @see hinic5_cmd_set_pcie_flr_mgmt */
	HINIC5_NIC_CMD_LRO_CFG = 242, /** <  @see hinic5_cmd_lro_cfg */
	HINIC5_NIC_CMD_CFG_VF_LAG = 243, /** < Set vf_lag (for computation, rsvd) */
	HINIC5_NIC_CMD_VF_LAG_SYNC_BOND_STATE = 244, /* vf_lag sync bond state (for computation, rsvd) */
	HINIC5_NIC_CMD_EXTEND_SECTION1_START = 257, /* NIC Mbox reserved command code start, for computing product line use */
	HINIC5_NIC_CMD_EXTEND_SECTION1_END = 384, /* NIC Mbox reserved command code end, for computing product line use */
	HINIC5_NIC_CMD_EXTEND_SECTION2_START = 385, /* NIC Mbox reserved command code start, for storage product line use */
	HINIC5_NIC_CMD_EXTEND_SECTION2_END = 512  /* NIC Mbox reserved command code end, for storage product line use */
};

#endif /* HINIC5_NIC_CMD_H */
