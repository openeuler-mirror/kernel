/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_outband_ncsi_cmd.h
 * Version       : Initial Draft
 * Created       : 2023/09/22
 * Last Modified : 2026/09/16
 * Description   : NCSI protocol out-of-band commands
 */

#ifndef MPU_OUTBAND_NCSI_CMD_H
#define MPU_OUTBAND_NCSI_CMD_H

/**
 * @brief NCSI protocol out-of-band operation commands
 *
 */
typedef enum {
	NCSI_CLEAR_INITIAL_STATE = 0x00,     /**< ncsi clear initial state command @see struct tg_clear_initial_state */
	NCSI_SELECT_PACKAGE,                 /**< ncsi select packag command @see struct tg_select_package */
	NCSI_DESELECT_PACKAGE,               /**< ncsi deselect packag command @see struct tg_deselect_package */
	NCSI_ENABLE_CHANNEL,                 /**< ncsi enable channel command @see struct tg_enable_channel */
	NCSI_DISABLE_CHANNEL,                /**< ncsi disable channel command @see struct tg_disable_channel */
	NCSI_RESET_CHANNEL = 0x05,           /**< ncsi reset channel command @see struct tg_reset_channel */
	NCSI_ENABLE_CHANNEL_NETWORK_TX,      /**< ncsi enable channel network TX command @see struct tg_enable_chn_tx */
	NCSI_DISABLE_CHANNEL_NETWORK_TX,     /**< ncsi disable channel network TX command @see struct tg_disable_chn_tx */
	NCSI_AEN_ENABLE,                     /**< ncsi AEN enable command @see struct tg_enable_aen */
	NCSI_SET_LINK,                       /**< ncsi set link command @see struct tg_set_link */
	NCSI_GET_LINK_STATUS = 0x0a,         /**< ncsi get link status command @see struct tg_get_link_status */
	NCSI_SET_VLAN_FILTER,                /**< ncsi set vlan filter command @see struct tg_set_vlan_filter */
	NCSI_ENABLE_VLAN,                    /**< ncsi enable vlan command @see struct tg_enable_vlan */
	NCSI_DISABLE_VLAN,                   /**< ncsi disable VLAN command @see struct tg_disable_vlan */
	NCSI_SET_MAC_ADDRESS,                /**< ncsi get MAC Address command @see struct tg_set_mac_address */
	NCSI_ENABLE_BROADCAST_FILTERING = 0x10,      /**< ncsi enable broadcast filter command
							@see struct tg_enable_broadcast */
	NCSI_DISABLE_BROADCAST_FILTERING,            /**< ncsi disbale broadcast filter command
							@see struct tg_disable_broadcast */
	NCSI_ENABLE_GLOBAL_MULTICAST_FILTERING,      /**< ncsi enable global multicast filter command
							@see struct tg_enable_multicast */
	NCSI_DISABLE_GLOBAL_MULTICAST_FILTERING,     /**< ncsi disable global multicast filter command
							@see struct tg_disable_multicast */
	NCSI_SET_NCSI_FLOW_CONTROL,                  /**< ncsi set ncsi flow control command
							@see struct tg_set_flow_control */
	NCSI_GET_VERSION_ID = 0x15,                  /**< ncsi get version id command @see struct tg_get_version_id */
	NCSI_GET_CAPABILITIES,                       /**< ncsi get capabilities command @see struct tg_get_capabilities */
	NCSI_GET_PARAMETERS,                         /**< ncsi get parameters command @see struct tg_get_parameters */
	NCSI_GET_CONTROLLER_PACKET_STATISTICS,       /**< ncsi get controller packet statistics command
							@see struct tg_get_packet_statistics */
	NCSI_GET_NCSI_STATISTICS,                    /**< request the packet statistics specific to the NC-SI command
							@see struct tg_get_ncsi_statistics */
	NCSI_GET_NCSI_PASSTHROUGH_STATISTICS = 0x1a, /**< request NC-SI Pass-through packet statistics command
							@see struct tg_get_passthrough_statistics */
	NCSI_GET_CHANNEL_STATE,                      /**< ncsi get channel state command
							@see struct tg_get_channel_state */
	NCSI_GET_REGISTER_VALUE,                     /**< ncsi get register value command
							@see struct tg_get_register_value */
	NCSI_SET_FWD_ACT,                            /**< ncsi set Fwd Act command @see struct tg_set_fwd_act */
	NCSI_SET_FILTER_MODE = 0X1E,                 /**< reserved */
	NCSI_SET_ARP_IP,                             /**< reserved */
	NCSI_UPDATE_FIRMWARE,                        /**< reserved */
	NCSI_GET_INVENTORY_INFO = 0x4e,              /**< ncsi get inventory info command
							@see struct tg_get_inventory_info */
	NCSI_OEM_COMMAND = 0x50,                     /**< ncsi oem command response @see struct tg_ncsi_oem_cmd_req */
	NCSI_AEN_COMMAND = 0xff                      /**< reserved */
} NCSI_CMD_E;

/**
 * @brief NCSI protocol out-of-band operation response
 *
 */
typedef enum {
	NCSI_CLEAR_INITIAL_STATE_RSP = 0x80,    /**< ncsi clear initial state response
							@see struct tg_clear_initial_state_rsp */
	NCSI_SELECT_PACKAGE_RSP,                /**< ncsi select packag response @see struct tg_select_package_rsp */
	NCSI_DESELECT_PACKAGE_RSP,              /**< ncsi deselect packag response
							@see struct tg_deselect_package_rsp */
	NCSI_ENABLE_CHANNEL_RSP,                /**< ncsi enable channel response @see struct tg_enable_channel_rsp */
	NCSI_DISABLE_CHANNEL_RSP,               /**< ncsi disable channel response
							@see struct tg_disable_channel_rsp */
	NCSI_RESET_CHANNEL_RSP,                 /**< ncsi reset channel response @see struct tg_reset_channel_rsp */
	NCSI_ENABLE_CHANNEL_NETWORK_TX_RSP,     /**< ncsi enable channel network TX response
							@see struct tg_enable_chn_tx_rsp */
	NCSI_DISABLE_CHANNEL_NETWORK_TX_RSP,    /**< ncsi disable channel network TX response
							@see struct tg_disable_chn_tx_rsp */
	NCSI_AEN_ENABLE_RSP,                    /**< ncsi AEN enable response @see struct tg_enable_aen_rsp */
	NCSI_SET_LINK_RSP,                      /**< ncsi set link response @see struct tg_set_link_rsp */
	NCSI_GET_LINK_STATUS_RSP,               /**< ncsi get link status response @see struct tg_get_link_status_rsp */
	NCSI_SET_VLAN_FILTER_RSP,               /**< ncsi set vlan filter response @see struct tg_set_vlan_filter_rsp */
	NCSI_ENABLE_VLAN_RSP,                   /**< ncsi enable vlan response @see struct tg_enable_vlan_rsp */
	NCSI_DISABLE_VLAN_RSP,                  /**< ncsi disable VLAN response @see struct tg_disable_vlan */
	NCSI_SET_MAC_ADDRESS_RSP,               /**< ncsi get MAC Address response @see struct tg_set_mac_address_rsp */
	NCSI_ENABLE_BROADCAST_FILTERING_RSP = 0x90, /**< enable broadcast filter response
							@see struct tg_enable_broadcast_rsp */
	NCSI_DISABLE_BROADCAST_FILTERING_RSP,      /**< ncsi disbale broadcast filter response
							@see struct tg_disable_broadcast_rsp */
	NCSI_ENABLE_GLOBAL_MULTICAST_FILTERING_RSP, /**< ncsi enable global multicast filter response
							@see struct tg_enable_multicast_rsp */
	NCSI_DISABLE_GLOBAL_MULTICAST_FILTERING_RSP, /**< ncsi disable global multicast filter response
							@see struct tg_disable_multicast_rsp */
	NCSI_SET_NCSI_FLOW_CONTROL_RSP,             /**< ncsi set ncsi flow control response
							@see struct tg_set_flow_control_rsp */
	NCSI_GET_VERSION_ID_RSP,                    /**< ncsi get version id response @see struct tg_get_version_id_rsp */
	NCSI_GET_CAPABILITIES_RSP,                  /**< ncsi get capabilities response
							@see struct tg_get_capabilities_rsp */
	NCSI_GET_PARAMETERS_RSP,                    /**< ncsi get parameters response @see struct tg_get_parameters_rsp */
	NCSI_GET_CONTROLLER_PACKET_STATISTICS_RSP,  /**< ncsi get controller packet statistics response
							@see struct tg_get_packet_statistics_rsp */
	NCSI_GET_NCSI_STATISTICS_RSP,               /**< request the packet statistics specific to the NC-SI command
							@see struct tg_get_ncsi_statistics_rsp */
	NCSI_GET_NCSI_PASSTHROUGH_STATISTICS_RSP,   /**< request NC-SI Pass-through packet statistics response
							@see struct tg_get_passthrough_statistics_rsp */
	NCSI_GET_CHANNEL_STATE_RSP,                 /**< ncsi get channel state response
							@see struct tg_get_channel_state_rsp */
	NCSI_GET_REGISTER_VALUE_RSP,                /**< ncsi get regiset value response
							@see struct tg_get_register_value_rsp */
	NCSI_SET_FWD_ACT_RSP,                       /**< ncsi set Fwd Act response @see struct tg_set_fwd_act_rsp */
	NCSI_SET_FILTER_MODE_RSP = 0X9E,            /**< reserved */
	NCSI_SET_ARP_IP_RSP,                        /**< reserved */
	NCSI_UPDATE_FIRMWARE_RSP,                   /**< reserved */
	NCSI_GET_INVENTORY_INFO_RSP = 0xCE,         /**< ncsi get inventory info response
							@see struct tg_get_inventory_info_rsp */
	NCSI_OEM_COMMAND_RSP = 0xD0                 /**< ncsi oem command response @see struct tg_ncsi_oem_cmd_req */
} NCSI_CMD_RSP_E;

/* ncsi oem command sub id low 8 bits, huawei_id high 8 bits */
/**
 * @brief ncsi oem command sub id low 8 bits, huawei_id high 8 bits
 *
 */
typedef enum {
	OEM_GET_NETWORK_INTERFACE_BDF = 0x1,         /**< oem get network interface bdf response
							@see struct tg_oem_get_bdf_rsp */
	OEM_GET_PART_NUMBER = 0x2,                   /**< reserved */
	OEM_GET_DRIVER_NAME = 0x4,                   /**< reserved */
	OEM_GET_PCIE_ABILITY = 0x5,                  /**< oem get the pcie interface ability response
							@see struct tg_oem_get_pcie_ability_rsp */
	OEM_GET_PCIE_STATUS = 0x6,                   /**< oem get the pcie interface status
							@see struct tg_oem_get_pcie_status_rsp */
	OEM_GET_NETWORK_INTERFACE_DATA_RATE = 0x7,   /**< reserved */
	OEM_GET_NETWORK_INTERFACE_MEDIA_TYPE = 0x9,  /**< oem get network interface media type response
							@see struct tag_oem_get_network_interface_media_type_rsp */
	OEM_GET_JUNCTION_TEMP = 0xa,                 /**< oem get the junction temperature response
							@see struct tag_oem_get_junction_temp_rsp */
	OEM_GET_OPTICAL_MODULE_TEMP = 0xb,           /**< oem get the optical module temperature response
							@see struct tag_oem_get_opt_modu_temp_rsp */
	OEM_GET_ERR_CODE = 0xc,                      /**< oem get the err code response @see struct tag_oem_get_err_code_rsp */
	OEM_GET_NETWORK_INTERFACE_TRANS_CABLE_INFO = 0xd, /**< oem get the transceiver or cable information response
								@see struct tag_oem_get_trans_or_cable_info_rsp */
	OEM_ENABLE_LLDP_CAPTURE = 0xe,               /**< oem enable LLDP capture response
							@see struct tag_oem_enable_lldp_capture_rsp */
	OEM_GET_LLDP_CAPBILITY = 0xf,                /**< oem get lldp capbility response
							@see struct tag_oem_get_lldp_capbility_rsp */
	OEM_GET_HW_OEM_CMD_CAPABILITY = 0x11,        /**< oem get oem command capbility response
							@see struct tag_oem_get_oem_command_cap_resp */
	OEM_GET_LLDP_TX_CAPBILITY = 0x13,            /**< oem enable/disable lldp tx @see struct tag_oem_get_lldp_tx_capbility_rsp */
	OEM_ENABLE_LLDP_TX = 0x14,                   /**< oem get lldp tx cap @see struct tag_oem_enable_lldp_tx_rsp */
	OEM_GET_LOG_INFO = 0x15,                     /**< oem get log info response @see struct tag_oem_get_log_info_rsp */
	OEM_GET_NEW_LOG_INFO = 0x16,
	OEM_SET_OPTICAL_MODULE_SWITCH = 0x19,        /**< oem enable/disable optical_module
							@see struct tag_set_optical_module_switch_rsp */
	OEM_SET_OPTICAL_MODULE_POWER = 0x1a,         /**< oem enable/disable optical_module power
							@see struct tag_set_optical_module_power_rsp */
	OEM_GET_PCIE_ALARM_INFO = 0x1b,              /**< oem get pcie alarm info
							@see struct tag_oem_get_pcie_alarm_info_rsp */
	OEM_GET_XSFP_PRESENT_STATUS = 0x20,                 /**< oem get sfp present status response @see struct tag_oem_get_xsfp_status_rsp */
} OEM_SUB_CMD_ID_NIC_PUB_E;

/* ncsi oem command sub id (nic info) */
/**
 * @brief ncsi oem command sub id (nic info)
 *
 */
typedef enum {
	OEM_GET_NETWORK_INTERFACE_MAC_ADDR = 0x100,  /**< oem get netork interface mac addr response
							@see struct tag_oem_get_netork_interface_mac_addr_rsp */
	OEM_GET_NETWORK_INTERFACE_IP_ADDR = 0x101,   /**< reserved */
	OEM_GET_NETWORK_INTERFACE_DCBX = 0x102,      /**< oem get networ interface dcbx response
							@see struct tag_oem_get_network_interface_dcbx_rsp */
	OEM_GET_NETWORK_DEFAULT_MAC_ADDR = 0x104     /**< oem get default mac addr response
							@see struct tag_oem_get_default_mac_addr_rsp */
} OEM_SUB_CMD_ID_NIC_INFO_E;

/* base configuration(NIC) */
typedef enum {
	OEM_ENABLE_LLDP_OVER_NCSI = 0x40A,           /**< oem enable lldp over ncsi command
							@see struct tag_oem_enable_lldp_over_ncsi
							@see struct tag_oem_enable_lldp_over_ncsi_resp */
	OEM_GET_LLDP_OVER_NCSI_STATUS = 0x40B,       /**< oem enable lldp over ncsi command
							@see struct tag_oem_get_lldp_over_ncsi_status
							@see struct tag_oem_get_lldp_over_ncsi_status_resp */
	OEM_ENABLE_LOW_POWER_MODE = 0x40C,           /**< oem enable low power mode command
							@see struct tag_oem_enable_low_power_mode
							@see struct tag_oem_enable_low_power_mode_resp */
	OEM_GET_LOW_POWER_MODE_STATUS = 0x40D        /**< oem get low power mode status command
							@see struct tag_oem_get_low_power_mode_status
							@see struct tag_oem_enable_low_power_mode_resp  */
} OEM_SUB_CMD_ID_BASE_CFG_NIC;

/* Stateless compute configuration NIC */
typedef enum {
	OEM_SET_VOLATILE_MAC = 0x508,                /**< ncsi oem set volatile mac command
							@see struct tag_oem_set_volatile_mac
							@see struct tag_oem_set_volatile_mac_resp */
	OEM_GET_VOLATILE_MAC = 0x509                 /**< ncsi oem get volatile mac command
							@see struct tag_oem_get_volatile_mac
							@see struct tag_oem_get_volatile_mac_resp */
} OEM_SUB_CMD_ID_NIC_STATELESS_CFG_E;

#endif