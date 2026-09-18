/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : outband_mpu_ncsi_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/05/13
 * Last Modified : 2026/09/16
 * Description   : mpu cmd
 */

#ifndef OUTBAND_MPU_NCSI_CMD_DEFS_H
#define OUTBAND_MPU_NCSI_CMD_DEFS_H

#include "base_type.h"
#include "mpu_outband_ncsi_cmd_defs.h"

#pragma pack(1)
/* Clear Initial State Command (0x00) */
/**
 * @brief ncsi clear initial state command (0x00) struct defination
 * @see NCSI_CLEAR_INITIAL_STATE
 *
 */
typedef struct tg_clear_initial_state {
	u32 check_sum;             /**< clear initial state check sum */
} clear_initial_state_s, *p_clear_initial_state_s;

/* Clear Initial State Response (0x80)  */
/**
 * @brief ncsi clear initial state response (0x80) struct defination
 * @see NCSI_CLEAR_INITIAL_STATE_RSP
 *
 */
typedef struct tg_clear_initial_state_rsp {
	u16 rsp_code;             /**< clear initial state response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;          /**< clear initial state response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;            /**< clear initial state response check sum */
} clear_initial_state_rsp_s, *p_clear_initial_state_rsp_s;

/* Select Package Command (0x01) */
/**
 * @brief ncsi select packag command (0x01) struct defination
 * @see NCSI_SELECT_PACKAGE
 *
 */
typedef struct tg_select_package {
	u8 reserved1[3];          /**< select package reserved1 */
#ifdef BIG_ENDIAN
	u8 reserved2 : 7;         /**< select package reserved2 */
	u8 hd_arbitration : 1;    /**< select package hd arbitration */
#else
	u8 hd_arbitration : 1;    /**< select package hd arbitration */
	u8 reserved2 : 7;         /**< select package reserved2 */
#endif
	u32 check_sum;            /**< select package check sum */
} select_package_s, *p_select_package_s;

/* Select Package Response (0x81) */
/**
 * @brief ncsi select packag response (0x81) struct defination
 * @see NCSI_SELECT_PACKAGE_RSP
 *
 */
typedef struct tg_select_package_rsp {
	u16 rsp_code;             /**< select package response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;          /**< select package response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;            /**< select package response check sum */
} select_package_rsp_s, *p_select_package_rsp_s;

/* Deselect Package Command (0x02)  */
/**
 * @brief ncsi deselect packag command (0x02) struct defination
 * @see NCSI_DESELECT_PACKAGE
 *
 */
typedef struct tg_deselect_package {
	u32 check_sum;            /**< deselect package check sum */
} deselect_package_s, *p_deselect_package_s;

/* Deselect Package Response (0x82)  */
/**
 * @brief ncsi deselect packag response (0x82) struct defination
 * @see NCSI_DESELECT_PACKAGE_RSP
 *
 */
typedef struct tg_deselect_package_rsp {
	u16 reason_code;     /**< deselect package response reason code */
	u16 rsp_code;        /**< deselect package response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u32 check_sum;       /**< deselect package response check sum @see enum NCSI_REASON_CODE_E */
} deselect_package_rsp_s, *p_deselect_package_rsp_s;

/* Enable Channel Command (0x03)  */
/**
 * @brief ncsi enable channel command (0x03) struct defination
 * @see NCSI_ENABLE_CHANNEL
 *
 */
typedef struct tg_enable_channel {
	u32 check_sum;       /**< enable channel response check sum */
} enable_channel_s, *p_enable_channel_s;

/* Enable Channel Response (0x83) */
/**
 * @brief ncsi enable channel response (0x83) struct defination
 * @see NCSI_ENABLE_CHANNEL_RSP
 *
 */
typedef struct tg_enable_channel_rsp {
	u16 rsp_code;       /**< enable channel response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;    /**< enable channel response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;      /**< enable channel response check sum */
} enable_channel_rsp_s, *p_enable_channel_rsp_s;

/* Disable Channel Command (0x04)  */
/**
 * @brief ncsi disable channel command (0x04) struct defination
 * @see NCSI_DISABLE_CHANNEL
 *
 */
typedef struct tg_disable_channel {
	u8 reserved1[3];        /**< disable channel command reserved1 */
#ifdef BIG_ENDIAN
	u8 rsvd : 7;            /**< disable channel command reserved */
	u8 ald : 1;             /**< disable channel command ald */
#else
	u8 ald : 1;             /**< disable channel command ald */
	u8 rsvd : 7;            /**< disable channel command reserved */
#endif
	u32 check_sum;          /**< disable channel command check sum */
} disable_channel_s, *p_disable_channel_s;
/* Disable Channel Response (0x84) */
/**
 * @brief ncsi disable channel response (0x84) struct defination
 * @see NCSI_DISABLE_CHANNEL_RSP
 *
 */
typedef struct tg_disable_channel_rsp {
	u16 rsp_code;        /**< disable channel response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;     /**< disable channel response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;       /**< disable channel response check sum */
} disable_channel_rsp_s, *p_disable_channel_rsp_s;

/* Reset Channel Command (0x05) */
/**
 * @brief ncsi reset channel command (0x05) struct defination
 * @see NCSI_RESET_CHANNEL
 *
 */
typedef struct tg_reset_channel {
	u32 rsvd;              /**< reset channel command reserved */
	u32 check_sum;         /**< reset channel command check sum */
} reset_channel_s, *p_reset_channel_s;

/* Reset Channel Response (0x85) */
/**
 * @brief ncsi reset channel response (0x85) struct defination
 * @see NCSI_RESET_CHANNEL_RSP
 *
 */
typedef struct tg_reset_channel_rsp {
	u16 rsp_code;          /**< reset channel response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;       /**< reset channel response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;         /**< reset channel response check sum */
} reset_channel_rsp_s, *p_reset_channel_rsp_s;

/* Enable Channel Network TX Command (0x06) */
/**
 * @brief ncsi enable channel network TX command (0x06) struct defination
 * @see NCSI_ENABLE_CHANNEL_NETWORK_TX
 *
 */
typedef struct tg_enable_chn_tx {
	u32 check_sum;         /**< enable channel network TX command check sum */
} enable_chn_tx_s, *p_enable_chn_tx_s;
/*  Enable Channel Network TX Response (0x86) ) */
/**
 * @brief ncsi enable channel network TX response (0x86) struct defination
 * @see NCSI_ENABLE_CHANNEL_NETWORK_TX_RSP
 *
 */
typedef struct tg_enable_chn_tx_rsp {
	u16 reason_code;       /**< enable channel network TX response reason code @see enum NCSI_REASON_CODE_E */
	u16 rsp_code;          /**< enable channel network TX response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u32 check_sum;         /**< enable channel network TX response check sum */
} enable_chn_tx_rsp_s, *p_enable_chn_tx_rsp_s;

/* Disable Channel Network TX Command (0x07) */
/**
 * @brief ncsi disable channel network TX command (0x07) struct defination
 * @see NCSI_DISABLE_CHANNEL_NETWORK_TX
 *
 */
typedef struct tg_disable_chn_tx {
	u32 check_sum;           /**< disable channel network TX command check sum */
} disable_chn_tx_s, *p_disable_chn_tx_s;
/*  Disable Channel Network TX Response (0x87) ) */
/**
 * @brief ncsi disable channel network TX response (0x87) struct defination
 * @see NCSI_DISABLE_CHANNEL_NETWORK_TX_RSP
 *
 */
typedef struct tg_disable_chn_tx_rsp {
	u16 rsp_code;            /**< disable channel network TX response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;         /**< disable channel network TX response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;           /**< disable channel network TX response check sum */
} disable_chn_tx_rsp_s, *p_disable_chn_tx_rsp_s;

/* AEN Enable Command (0x08)  */
#define AEN_CTRL_LINK_STATUS_SHIFT 0
#define AEN_CTRL_CONFIG_REQ_SHIFT 1
#define AEN_CTRL_DRV_CHANGE_SHIFT 2

/* AEN Type */
typedef enum {
	AEN_LINK_STATUS_CHANGE_TYPE = 0x0,
	AEN_CONFIG_REQUIRED_TYPE    = 0x1,
	OEM_AEN_CONFIG_REQUEST_TYPE = 0x80,
	AEN_TYPE_MAX = 0x100
} aen_type_e;

typedef union tg_aen_control {
	struct {
	u16 oem_ctl;        /**< AEN control oem control */
	u8 reserved;        /**< AEN control reserved */
#ifdef BD_BIG_ENDIAN
	u8 reserved2 : 5;   /**< AEN control reserved2 */
	u8 drv_change : 1;  /**< AEN control driver change
				 * 1b  = Enable Host NC Driver Status Change AEN 0=disable */
	u8 config_req : 1;  /**< AEN control config_req */
	u8 link_status : 1; /**< AEN control driver change
				 * 1b  = Enable Link Status Change AEN  0=disable */
#else
	u8 link_status : 1; /**< AEN control driver change
				 * 1b  = Enable Link Status Change AEN  0=disable */
	u8 config_req : 1;  /**< AEN control config_req */
	u8 drv_change : 1;  /**< AEN control driver change
				 * 1b  = Enable Host NC Driver Status Change AEN 0=disable */
	u8 reserved2 : 5;   /**< AEN control reserved2 */
#endif
	} bits;

	u32 aen_ctrl;       /**< AEN control check sum */
} aen_control_s;
/**
 * @brief ncsi AEN enable command (0x08) struct defination
 * @see NCSI_AEN_ENABLE
 *
 */
typedef struct tg_enable_aen {
	u8 reserved1[3];            /**< AEN enable command reserved2 */
	u8 mc_id;                   /**< AEN enable command management control ID */
	aen_control_s aen_control;  /**< AEN control */
	u32 check_sum;              /**< AEN enable command check sum */
} enable_aen_s, *p_enable_aen_s;
/* AEN Enable Response (0x88)  */
/**
 * @brief ncsi AEN enable response (0x88) struct defination
 * @see NCSI_AEN_ENABLE_RSP
 *
 */
typedef struct tg_enable_aen_rsp {
	u16 rsp_code;      /**< AEN enable response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;   /**< AEN enable response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;     /**< AEN enable response check sum */
} enable_aen_rsp_s, *p_enable_aen_rsp_s;

/* set link: 0x09 */
/**
 * @brief ncsi set link command (0x09) struct defination
 * @see NCSI_SET_LINK
 *
 */
typedef struct tg_set_link {
	u32 link_settings;        /**< set link command link settings */
	u32 OEM_link_settings;    /**< set link command OEM link settings */
	u32 check_sum;            /**< set link command check sum */
} set_link_s, *p_set_link_s;
/* set link response (0x89) */
/**
 * @brief ncsi set link response (0x89) struct defination
 * @see NCSI_SET_LINK_RSP
 *
 */
typedef struct tg_set_link_rsp {
	u16 rsp_code;            /**< set link response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;         /**< set link response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;           /**< set link response check sum */
} set_link_rsp_s, *p_set_link_rsp_s;

/**
 * @brief ncsi get link status command (0x0A) struct defination
 * @see NCSI_GET_LINK_STATUS
 *
 */
typedef struct tg_get_link_status {
	u32 check_sum;          /**< get link status command check sum */
} get_link_status_s, *p_get_link_status_s;

/* get link status response 0x8A */
/**
 * @brief link status struct defination
 *
 */
typedef union {
	struct {
#ifdef BD_BIG_ENDIAN
	u32 ex_speed_duplex : 8;    /**< link status extended speed and duplex */

	u32 modulation_cheme : 2;   /**< link status modulation scheme */
	u32 oem_link_speed : 1;     /**< link status oem link speed @see enum NCSI_CMD_LINK_SPEED_E */
	u32 serdes_link : 1;        /**< link status serdes link */
	u32 link_partner8 : 2;      /**< link status link partner8 */
	u32 rx_flow_control : 1;    /**< link status rx flow control */
	u32 tx_flow_control : 1;    /**< link status tx flow control */

	u32 link_partner7 : 1;      /**< link status link partner7 */
	u32 link_partner6 : 1;      /**< link status link partner6 */
	u32 link_partner5 : 1;      /**< link status link partner5 */
	u32 link_partner4 : 1;      /**< link status link partner4 */
	u32 link_partner3 : 1;      /**< link status link partner3 */
	u32 link_partner2 : 1;      /**< link status link partner2 */
	u32 link_partner1 : 1;      /**< link status link partner1 */
	u32 channel_available : 1;  /**< link status channel available */

	u32 parallel_detection : 1; /**< link status parallel detection */
	u32 negotiate_complete : 1; /**< link status negotiate complete */
	u32 negotiate_flag : 1;     /**< link status negotiate flag */
	u32 speed_duplex : 4;       /**< link status speed duplex */
	u32 link_flag : 1;          /**< link status link flag */
#else
	u32 ex_speed_duplex : 8;    /**< link status extended speed and duplex */

	u32 tx_flow_control : 1;    /**< link status tx flow control */
	u32 rx_flow_control : 1;    /**< link status rx flow control */
	u32 link_partner8 : 2;      /**< link status link partner8 */
	u32 serdes_link : 1;        /**< link status serdes link */
	u32 oem_link_speed : 1;     /**< link status oem link speed @see enum NCSI_CMD_LINK_SPEED_E */
	u32 modulation_cheme : 2;   /**< link status modulation scheme */

	u32 channel_available : 1;  /**< link status channel available */
	u32 link_partner1 : 1;      /**< link status link partner1 */
	u32 link_partner2 : 1;      /**< link status link partner2 */
	u32 link_partner3 : 1;      /**< link status link partner3 */
	u32 link_partner4 : 1;      /**< link status link partner4 */
	u32 link_partner5 : 1;      /**< link status link partner5 */
	u32 link_partner6 : 1;      /**< link status link partner6 */
	u32 link_partner7 : 1;      /**< link status link partner7 */

	u32 link_flag : 1;          /**< link status link flag */
	u32 speed_duplex : 4;       /**< link status speed duplex */
	u32 negotiate_flag : 1;     /**< link status negotiate flag */
	u32 negotiate_complete : 1; /**< link status negotiate complete */
	u32 parallel_detection : 1; /**< link status parallel detection */
#endif
	} bits;
	u32 val32;
} ncsi_link_status;

/**
 * @brief ncsi get link status response (0x8A) struct defination
 * @see NCSI_GET_LINK_STATUS_RSP
 *
 */
typedef struct tg_get_link_status_rsp {
	u16 rsp_code;          /**< get link status response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;       /**< get link status response reason code @see enum NCSI_REASON_CODE_E */
	u32 link_status;       /**< get link status response link status */
	u32 other_indications; /**< get link status response other indications */
	u32 OEM_link_status;   /**< get link status response OEM link status */
	u32 check_sum;         /**< get link status response check sum */
} get_link_status_rsp_s, *p_get_link_status_rsp_s;

/* Set Vlan Filter (0x0B)  */
/* Only VLAN-tagged packets that match the enabled VLAN Filter settings are accepted. */
#define VLAN_MODE_UNSET 0X00
#define VLAN_ONLY 0x01
/* if match the MAC address ,any vlan-tagged and non-vlan-tagged will be
	accepted */
#define ANYVLAN_NONVLAN 0x03
#define VLAN_MODE_SUPPORT 0x05

/* chanel vlan filter enable */
#define CHNL_VALN_FL_ENABLE 0x01
#define CHNL_VALN_FL_DISABLE 0x00

/* vlan id invalid */
#define VLAN_ID_VALID 0x01
#define VLAN_ID_INVALID 0x00

/* ncsi_get_controller_packet_statistics_config */
#define NO_INFORMATION_STATISTICS 0xff

/**
 * @brief ncsi set vlan filter command (0x0B) struct defination
 * @see NCSI_SET_VLAN_FILTER
 *
 */
typedef struct tg_set_vlan_filter {
	u8 reserved1[2];           /**< set vlan filter command reserved1 */
#ifdef BD_BIG_ENDIAN
	u8 user_priority : 4;      /**< set vlan filter command user priority */
	u8 vlan_id_hi : 4;         /**< set vlan filter command vlan id high */
#else
	u8 vlan_id_hi : 4;         /**< set vlan filter command vlan id high */
	u8 user_priority : 4;      /**< set vlan filter command user priority */
#endif
	u8 vlan_id_low;            /**< set vlan filter command vlan id low */
	u8 reserved2[2];           /**< set vlan filter command reserved2 */
	u8 filter;                 /**< set vlan filter command filter */
#ifdef BD_BIG_ENDIAN
	u8 reserved3 : 7;          /**< set vlan filter command reserved3 */
	u8 enable : 1;             /**< set vlan filter command enable */
#else
	u8 enable : 1;             /**< set vlan filter command enable */
	u8 reserved3 : 7;          /**< set vlan filter command reserved3 */
#endif
	u32 check_sum;             /**< set vlan filter command check sum */
} set_vlan_filter_s, *p_set_vlan_filter_s;
/* Set Vlan Filter Response (0x8B)  */
/**
 * @brief ncsi set vlan filter response (0x8B) struct defination
 * @see NCSI_SET_VLAN_FILTER_RSP
 *
 */
typedef struct tg_set_vlan_filter_rsp {
	u16 rsp_code;             /**< set vlan filter response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;          /**< set vlan filter response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;            /**< set vlan filter response check sum */
} set_vlan_filter_rsp_s, *p_set_vlan_filter_rsp_s;

/* Enable VLAN Command (0x0C)   */

/* register for a specific vlan filter corresponding to the channel */
#define VLAN_REG_ADDR(chan_id, filter_selector) \
	(CSR_IPSURX_CSR_IPSURX_NCSI_VLAN7_CTRL_0_REG + (chan_id) * 4 + (VLAN_FL_MAX_ID - (filter_selector)) * 16)

/**
 * @brief ncsi enable vlan command (0x0C) struct defination
 * @see NCSI_ENABLE_VLAN
 *
 */
typedef struct tg_enable_vlan {
	u8 reserved[3];        /**< enable vlan command reserved */
	u8 vlan_mode;          /**< enable vlan command vlan mode */
	u32 check_sum;         /**< enable vlan command check sum */
} enable_vlan_s, *p_enable_vlan_s;
/* Enable VLAN Response (0x8C)   */
/**
 * @brief ncsi enable vlan response (0x8C) struct defination
 * @see NCSI_ENABLE_VLAN_RSP
 *
 */
typedef struct tg_enable_vlan_rsp {
	u16 rsp_code;         /**< enable vlan response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;      /**< enable vlan response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;        /**< enable vlan response check sum */
} enable_vlan_rsp_s, *p_enable_vlan_rsp_s;

/* Disable VLAN Command (0x0D)   */
/**
 * @brief ncsi disable VLAN command (0x0D) struct defination
 * @see NCSI_DISABLE_VLAN
 *
 */
typedef struct tg_disable_vlan {
	u32 check_sum;       /**< disable vlan command check sum */
} disable_vlan_s, *p_disable_vlan_s;
/* Disable VLAN Response (0x8D) */
/**
 * @brief ncsi disable VLAN response (0x8D) struct defination
 * @see NCSI_DISABLE_VLAN_RSP
 *
 */
typedef struct tg_disable_vlan_rsp {
	u16 rsp_code;        /**< disable vlan response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;     /**< disable vlan response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;       /**< disable vlan response check sum */
} disable_vlan_rsp_s, *p_disable_vlan_rsp_s;

/* get MAC Address 0x0E */

#define UNICAST_ADDRESS_TYPE          (0x0)
#define MULTICAST_ADDRESS_TYPE        (0x1)

/**
 * @brief ncsi get MAC Address command (0x0E) struct defination
 * @see NCSI_SET_MAC_ADDRESS
 *
 */
typedef struct tg_set_mac_address {
	u8 mac_filter5;      /**< set MAC Address command mac filter5 */
	u8 mac_filter4;      /**< set MAC Address command mac filter4 */
	u8 mac_filter3;      /**< set MAC Address command mac filter3 */
	u8 mac_filter2;      /**< set MAC Address command mac filter2 */
	u8 mac_filter1;      /**< set MAC Address command mac filter1 */
	u8 mac_filter0;      /**< set MAC Address command mac filter0 */
	u8 mac_number;       /**< set MAC Address command mac number */
#ifdef BD_BIG_ENDIAN
	u8 address_type : 3; /**< set MAC Address command address type */
	u8 reserved : 4;     /**< set MAC Address command reserved */
	u8 mac_enable : 1;   /**< set MAC Address command mac enable */
#else
	u8 mac_enable : 1;   /**< set MAC Address command mac enable */
	u8 reserved : 4;     /**< set MAC Address command reserved */
	u8 address_type : 3; /**< set MAC Address command address type */
#endif
	u32 check_sum;       /**< set MAC Address command check sum */
} set_mac_address_s, *p_set_mac_address_s;
/* set MAC Address response (0x8E) */
/**
 * @brief ncsi get MAC Address response (0x8E) struct defination
 * @see NCSI_SET_MAC_ADDRESS_RSP
 *
 */
typedef struct tg_set_mac_address_rsp {
	u16 rsp_code;        /**< set MAC Address response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;     /**< set MAC Address response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;       /**< set MAC Address response check sum */
} set_mac_address_rsp_s, *p_set_mac_address_rsp_s;

/* Enable BC Filter Command (0x10) */

typedef union {
	struct {
#ifdef BD_BIG_ENDIAN
	u32 reserved1 : 28;         /**< boradcast filter reserved1 */
	u32 netbios_packet : 1;     /**< boradcast filter netbios packet, This field is optional */
	u32 dhcp_server_packet : 1; /**< boradcast filter dhcp server packet, This field is optional */
	u32 dhcp_client_packet : 1; /**< boradcast filter dhcp client packet, This field is optional */
	u32 arp_packet : 1;         /**< boradcast filter arp packet, This field is mandatory */
#else
	u32 arp_packet : 1;         /**< boradcast filter arp packet, This field is mandatory */
	u32 dhcp_client_packet : 1; /**< boradcast filter dhcp client packet, This field is optional */
	u32 dhcp_server_packet : 1; /**< boradcast filter dhcp server packet, This field is optional */
	u32 netbios_packet : 1;     /**< boradcast filter netbios packet, This field is optional */
	u32 reserved1 : 28;         /**< boradcast filter reserved1 */
#endif
	} bits;
	u32 val32;
} boradcast_filter, *p_boradcast_filter;

/**
 * @brief ncsi enable broadcast filter command (0x10) struct defination
 * @see NCSI_ENABLE_BROADCAST_FILTERING
 *
 */
typedef struct tg_enable_broadcast {
	boradcast_filter brd_filter; /**< enable broadcast filter command boradcast filter */
	u32 check_sum;               /**< enable broadcast filter command check sum */
} enable_broadcast_s, *p_enable_broadcast_s;
/**
 * @brief enable broadcast filter response (0x90) struct defination
 * @see NCSI_ENABLE_BROADCAST_FILTERING_RSP
 *
 */
typedef struct tg_enable_broadcast_rsp {
	u16 rsp_code;                /**< enable broadcast filter response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;             /**< enable broadcast filter response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;               /**< enable broadcast filter response check sum */
} enable_broadcast_rsp_s, *p_enable_broadcast_rsp_s;

/* disbale broadcast filter command(0x11) */
/**
 * @brief ncsi disbale broadcast filter command(0x11) struct defination
 * @see NCSI_DISABLE_BROADCAST_FILTERING
 *
 */
typedef struct tg_disable_broadcast {
	u32 check_sum;    /**< disable broadcast filter response check sum */
} disable_broadcast_s, *p_disable_broadcast_s;
/**
 * @brief ncsi disbale broadcast filter response(0x91) struct defination
 * @see NCSI_DISABLE_BROADCAST_FILTERING_RSP
 *
 */
typedef struct tg_disable_broadcast_rsp {
	u16 rsp_code;    /**< disable broadcast filter response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code; /**< disable broadcast filter response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;   /**< disable broadcast filter response check sum */
} disable_broadcast_rsp_s, *p_disable_broadcast_rsp_s;

/* Enable Global Multicast Filter Command (0x12) */

typedef union {
	struct tg_multicast_packet_filter {
#ifdef BD_BIG_ENDIAN
	u8 reserved1[3];                          /**< multicast packet filter reserved1 */
	u8 reserved2 : 2;                         /**< multicast packet filter reserved2 */
	u8 IPv6_Neighbor_Solicitation : 1;            /**< multicast packet IPv6 Neighbor Solicitation */
	u8 IPv6_MLD : 1;                              /**< multicast packet IPv6 MLD */
	u8 DHCPv6_multicasts_from_server_to_clients : 1; /**< multicast packet DHCPv6 multicasts from server to clients
								 * listening on well-known UDP ports */
	u8 DHCPv6_relay_and_server_multicast : 1; /**< multicast packet DHCPv6 relay and server multicast */
	u8 IPv6_router_advertisement : 1;         /**< multicast packet IPv6 router advertisement */
	u8 IPv6_neighbor_advertisement : 1;       /**< multicast packet IPv6 neighbor advertisement */
#else
	u8 IPv6_neighbor_advertisement : 1;       /**< multicast packet IPv6 neighbor advertisement */
	u8 IPv6_router_advertisement : 1;         /**< multicast packet IPv6 router advertisement */
	u8 DHCPv6_relay_and_server_multicast : 1; /**< multicast packet DHCPv6 relay and server multicast */
	u8 DHCPv6_multicasts_from_server_to_clients : 1; /**< multicast packet DHCPv6 multicasts from server to clients
								 * listening on well-known UDP ports */
	u8 IPv6_MLD : 1;                              /**< multicast packet IPv6 MLD */
	u8 IPv6_Neighbor_Solicitation : 1;            /**< multicast packet IPv6 Neighbor Solicitation */
	u8 reserved2 : 2;                         /**< multicast packet filter reserved2 */
	u8 reserved1[3];                          /**< multicast packet filter reserved1 */
#endif
	} bits;
	u32 val32;
} multicast_packet_filter, *p_multicast_packet_filter;

/**
 * @brief ncsi enable global multicast filter command(0x12) struct defination
 * @see NCSI_ENABLE_GLOBAL_MULTICAST_FILTERING
 *
 */
typedef struct tg_enable_multicast {
	multicast_packet_filter multicast_filter; /**< enable global multicast filter command multicast packet filter */
	u32 check_sum;                            /**< enable global multicast filter command check sum */
} enable_multicast_s, *p_enable_multicast_s;

/**
 * @brief ncsi enable global multicast filter response(0x92) struct defination
 * @see NCSI_ENABLE_GLOBAL_MULTICAST_FILTERING_RSP
 *
 */
typedef struct tg_enable_multicast_rsp {
	u16 rsp_code;    /**< enable global multicast filter response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code; /**< enable global multicast filter response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;   /**< enable global multicast filter response check sum */
} enable_multicast_rsp_s, *p_enable_multicast_rsp_s;

/* Disable Global Multicast Filter Command (0x13) */
/**
 * @brief ncsi disable global multicast filter command(0x13) struct defination
 * @see NCSI_ENABLE_GLOBAL_MULTICAST_FILTERING
 *
 */
typedef struct tg_disable_multicast {
	u32 check_sum;              /**< disable global multicast filter command check sum */
} disable_multicast_s, *p_disable_multicast_s;
/**
 * @brief ncsi disable global multicast filter response(0x93) struct defination
 * @see NCSI_DISABLE_GLOBAL_MULTICAST_FILTERING_RSP
 *
 */
typedef struct tg_disable_multicast_rsp {
	u16 rsp_code;    /**< disable global multicast filter response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code; /**< disable global multicast filter response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;   /**< disable global multicast filter response check sum */
} disable_multicast_rsp_s, *p_disable_multicast_rsp_s;

/* ncsi flow control (0x14) */
/**
 * @brief ncsi set ncsi flow control command(0x14) struct defination
 * @see NCSI_SET_NCSI_FLOW_CONTROL
 *
 */
typedef struct tg_set_flow_control {
	u8 reserved[3];            /**< set flow control command reserved */
	u8 flow_control_enable;    /**< set flow control command flow control enable */
	u32 check_sum;             /**< set flow control command check sum */
} set_flow_control_s, *p_set_flow_control_s;
/**
 * @brief ncsi set ncsi flow control response(0x94) struct defination
 * @see NCSI_SET_NCSI_FLOW_CONTROL_RSP
 *
 */
typedef struct tg_set_flow_control_rsp {
	u16 rsp_code;              /**< set flow control response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;           /**< set flow control response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;             /**< set flow control response check sum */
} set_flow_control_rsp_s, *p_set_flow_control_rsp_s;

/* Get Version ID Command (0x15) */
/* maximum value of fw_name */
#define FW_NAME_MAX_SIZE (12)
/**
 * @brief ncsi get version id command(0x15) struct defination
 * @see NCSI_GET_VERSION_ID
 *
 */
typedef struct tg_get_version_id {
	u32 check_sum;            /**< get version id command check sum */
} get_version_id_s, *p_get_version_id_s;
/**
 * @brief ncsi get version id response(0x95) struct defination
 * @see NCSI_GET_VERSION_ID_RSP
 *
 */
typedef struct tg_get_version_id_rsp {
	u16 rsp_code;                     /**< get version id response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                  /**< get version id response reason code */
	u8 pl_major;                      /**< get version id response pl major */
	u8 pl_minor;                      /**< get version id response pl minor */
	u8 update;                        /**< get version id response update */
	u8 alpha1;                        /**< get version id response alpha1 */
	u8 reserved[3];                   /**< get version id response reserved */
	u8 alpha2;                        /**< get version id response alpha2 */
	u8 name_string[FW_NAME_MAX_SIZE]; /**< get version id response name_string
					 * BIG_ENDIAN, The first byte received is the first byte of the string. */
	u8 ms_byte3;                      /**< get version id response ms byte3 */
	u8 byte2;                         /**< get version id response byte2 */
	u8 byte1;                         /**< get version id response byte1 */
	u8 ls_byte0;                      /**< get version id response ls byte0 */
	u16 pci_did;                      /**< get version id response pci did */
	u16 pci_vid;                      /**< get version id response pci vid */
	u16 pci_ssid;                     /**< get version id response pci ssid */
	u16 pci_svid;                     /**< get version id response pci svid */
	u32 manufacturer_id;              /**< get version id response manufacturer id
					 * This field is unused, the value shall be set to 0xFFFFFFFF */
	u32 check_sum;                    /**< get version id response check sum */
} get_version_id_rsp_s, *p_get_version_id_rsp_s;

/* get_capabilities: 0x16 */
/**
 * @brief ncsi get capabilities command(0x16) struct defination
 * @see NCSI_GET_CAPABILITIES
 *
 */
typedef struct tg_get_capabilities {
	u32 check_sum;                    /**< get capabilities command check sum */
} get_capabilities_s, *p_get_capabilities_s;

/* NCSI channel capabilities */
typedef struct tag_ncsi_chan_capa {
	u32 capa_flags;                     /**< NCSI channel capabilities capa flags */
	u32 bcast_filter;                   /**< NCSI channel capabilities bcast filter */
	u32 multicast_filter;               /**< NCSI channel capabilities multicast filter */
	u32 buffering;                      /**< NCSI channel capabilities buffering */
	u32 aen_ctrl;                       /**< NCSI channel capabilities aen ctrl */
	u8 vlan_count;                      /**< NCSI channel capabilities vlan count */
	u8 mixed_count;                     /**< NCSI channel capabilities mixed count */
	u8 multicast_count;                 /**< NCSI channel capabilities multicast count */
	u8 unicast_count;                   /**< NCSI channel capabilities unicast count */
	u16 rsvd;                           /**< NCSI channel capabilities reserved */
	u8 vlan_mode;                       /**< NCSI channel capabilities vlan mode */
	u8 chan_count;                      /**< NCSI channel capabilities channel count */
} ncsi_chan_capa_s;
/**
 * @brief ncsi get capabilities response(0x96) struct defination
 * @see NCSI_GET_CAPABILITIES_RSP
 *
 */
typedef struct tg_get_capabilities_rsp {
	u16 rsp_code;                       /**< get capabilities response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                    /**< get capabilities response reason code @see enum NCSI_REASON_CODE_E */
	ncsi_chan_capa_s chan_capabilities; /**< get capabilities response channel capabilities */
	u32 check_sum;                      /**< get capabilities response check sum */
} get_capabilities_rsp_s, *p_get_capabilities_rsp_s;

/* get parameters(0x17) */
/**
 * @brief ncsi get parameters command(0x17) struct defination
 * @see NCSI_GET_PARAMETERS
 *
 */
typedef struct tg_get_parameters {
	u32 check_sum;                     /**< get parameters command check sum */
} get_parameters_s, *p_get_parameters_s;

typedef struct ncsi_parameters {
	u8 mac_address_count;
	u8 reserved1[2];
	u8 mac_address_flags;
	u8 vlan_tag_count;
	u8 reserved2;
	u16 vlan_tag_flags;
	u32 link_settings;
	u32 broadcast_packet_filter_settings;
	u8 broadcast_packet_filter_status : 1;
	u8 channel_enable : 1;
	u8 channel_network_tx_enable : 1;
	u8 global_mulicast_packet_filter_status : 1;
	u8 config_flags_reserved1 : 4;               /**< bit0-3:mac_add0-mac_add3 address type: 0 unicast, 1 multicast */
	u8 config_flags_reserved2[3];
	u8 vlan_mode;                                /**< current vlan mode */
	u8 flow_control_enable;
	u16 reserved3;
	u32 AEN_control;
	u8 mac_add[4][6];
	u16 vlan_tag[8];
} ncsi_parameters_s;

/**
 * @brief ncsi get parameters response(0x97) struct defination
 * @see NCSI_GET_PARAMETERS_RSP
 *
 */
typedef struct tg_get_parameters_rsp {
	u16 rsp_code;                    /**< get parameters response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                 /**< get parameters response reason code @see enum NCSI_REASON_CODE_E */
	ncsi_parameters_s parameters;    /**< get parameters response ncsi parameters */
	u32 check_sum;
} get_parameters_rsp_s, *p_get_parameters_rsp_s;

/* get current packet statistics for the Ethernet Controller(0x18) */
/**
 * @brief ncsi get controller packet statistics command(0x18) struct defination
 * @see NCSI_GET_CONTROLLER_PACKET_STATISTICS
 *
 */
typedef struct tg_get_packet_statistics {
	u32 check_sum;
} get_packet_statistics_s, *p_get_packet_statistics_s;

typedef struct tg_controller_packet_statistics {
	u32 counter_cleared_from_last_read_MS;
	u32 counter_cleared_from_last_read_LS;
	u64 total_bytes_received;
	u64 total_bytes_transmitted;
	u64 total_unicast_packets_received;
	u64 total_multicast_packets_received;
	u64 total_broadcast_packets_received;
	u64 total_unicast_packets_transmitted;
	u64 total_multicast_packets_transmitted;
	u64 total_broadcast_packets_transmitted;
	u32 FCS_receive_errors;
	u32 alignment_errors;
	u32 false_carrier_detections;
	u32 runt_packets_received;
	u32 jabber_packets_received;
	u32 pause_XON_frames_received;
	u32 pause_XOFF_frames_received;
	u32 pause_XON_frames_transmitted;
	u32 pause_XOFF_frames_transmitted;
	u32 single_collision_transmit_frames;
	u32 multiple_collision_transmit_frames;
	u32 late_collision_frames;
	u32 excessive_collision_frames;
	u32 control_frames_received;
	u32 B64_frames_received;
	u32 B65_127_frames_received;
	u32 B128_255_frames_received;
	u32 B256_511_frames_received;
	u32 B512_1023_frames_received;
	u32 B1024_1522_frames_received;
	u32 B1523_9022_frames_received;
	u32 B64_frames_transmitted;
	u32 B65_127_frames_transmitted;
	u32 B128_255_frames_transmitted;
	u32 B256_511_frames_transmitted;
	u32 B512_1023_frames_transmitted;
	u32 B1024_1522_frames_transmitted;
	u32 B1523_9022_frames_transmitted;
	u64 valid_bytes_received;
	u32 error_runt_packets_received;
	u32 error_jabber_packets_received;
} controller_packet_statistics, *p_controller_packet_statistics;
/**
 * @brief ncsi get controller packet statistics response(0x98) struct defination
 * @see NCSI_GET_CONTROLLER_PACKET_STATISTICS_RSP
 *
 */
typedef struct tg_get_packet_statistics_rsp {
	u16 rsp_code;
	u16 reason_code;
	controller_packet_statistics pkt_statistics;
	u32 check_sum;
} get_packet_statistics_rsp_s, *p_get_packet_statistics_rsp_s;

/* request the packet statistics specific to the NC-SI (0x19) */
/**
 * @brief request the packet statistics specific to the NC-SI command(0x19) struct defination
 * @see NCSI_GET_NCSI_STATISTICS
 *
 */
typedef struct tg_get_ncsi_statistics {
	u32 check_sum;
} get_ncsi_statistics_s, *p_get_ncsi_statistics_s;
/**
 * @brief request the packet statistics specific to the NC-SI response(0x99) struct defination
 * @see NCSI_GET_NCSI_STATISTICS_RSP
 *
 */
typedef struct tg_get_ncsi_statistics_rsp {
	u16 rsp_code;    /**< get ncsi statistics response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code; /**< get ncsi statistics response reason code @see enum NCSI_REASON_CODE_E */
	u32 ncsi_commands_received;
	u32 ncsi_control_packets_dropped;
	u32 ncsi_command_type_error;
	u32 ncsi_command_checksun_errors;
	u32 ncsi_receive_packets;
	u32 ncsi_transmit_packets;
	u32 aens_sent;
	u32 check_sum;
} get_ncsi_statistics_rsp_s, *p_get_ncsi_statistics_rsp_s;

/* get inventory info (0x4E) */
#define NCSI_INVERTORY_INFO_DADA_LEN 512
#define NUMBER_OF_TLVS_LEN 1
#define INVENTORY_TYPE_LEN 1
#define INVENTORY_VALUE_LEN 1

/* Inventory Type */
typedef enum {
	NCSI_MANUFACTURER            = 0x0,
	NCSI_PRODUCT_OR_MODEL        = 0x1,
	NCSI_INVENTORY_VERSION       = 0x2,
	NCSI_PART_NUMBER             = 0x3,
	NCSI_SERIAL_NUMBER           = 0x4,
	NCSI_MANUFACTURING_TIMESTAMP = 0x5,
} inventory_type_e;

/* request the inventory info (0x4E) */
/**
 * @brief request the inventory info command(0x4E) struct defination
 * @see NCSI_GET_INVENTORY_INFO
 *
 */
typedef struct tg_get_inventory_info {
	u32 check_sum;
} get_inventory_info_s, *p_get_inventory_info_s;
/**
 * @brief request the inventory info response(0xCE) struct defination
 * @see NCSI_GET_INVENTORY_INFO_RSP
 *
 */
typedef struct tg_get_inventory_info_rsp {
	u16 rsp_code;    /**< get inventory info response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code; /**< get inventory info response reason code @see enum NCSI_REASON_CODE_E */
	u8  data[NCSI_INVERTORY_INFO_DADA_LEN];
	u32 check_sum;
} get_inventory_info_rsp_s, *p_get_inventory_info_rsp_s;

/* request NC-SI Pass-through packet statistics(0x1A) */
/**
 * @brief request NC-SI Pass-through packet statistics command(0x1A) struct defination
 * @see NCSI_GET_PASSTHOUGH_STATISTICS
 *
 */
typedef struct tg_get_passthrough_statistics {
	u32 check_sum;
} get_passthrough_statistics_s, *p_get_passthrough_statistics_s;
/**
 * @brief request NC-SI Pass-through packet statistics response(0x9A) struct defination
 * @see NCSI_GET_PASSTHOUGH_STATISTICS_RSP
 *
 */
typedef struct tg_get_passthrough_statistics_rsp {
	u16 rsp_code;    /**< get passthrough statisticse response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code; /**< get passthrough statisticse response @see enum NCSI_REASON_CODE_E */
	u64 pass_through_TX_received;
	u32 pass_through_TX_dropped;
	u32 pass_through_TX_channel_state_error;
	u32 pass_through_TX_packet_undersized_error;
	u32 pass_through_TX_packet_oversized_error;
	u32 pass_through_RX_received;
	u32 pass_through_RX_dropped;
	u32 pass_through_RX_packet_channel_state_errors;
	u32 pass_through_RX_packet_undersized_error;
	u32 pass_through_RX_packet_oversized_error;
	u32 check_sum;
} get_passthrough_statistics_rsp_s, *p_get_passthrough_statistics_rsp_s;

/* OEM:get channel state (0X1B) */
/**
 * @brief ncsi get channel state command(0X1B) struct defination
 * @see NCSI_GET_CHANNEL_STATE
 *
 */
typedef struct tg_get_channel_state {
	u32 check_sum;
} get_channel_state_s, *p_get_channel_state_s;

/**
 * @brief ncsi get channel state response(0X9B) struct defination
 * @see NCSI_GET_CHANNEL_STATE_RSP
 *
 */
typedef struct tg_get_channel_state_rsp {
	u16 rsp_code;           /**< get channel state response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;        /**< get channel state response reason code @see enum NCSI_REASON_CODE_E */
	u32 channel_state;      /**< get channel state response channel state */
	u32 check_sum;          /**< get channel state response check sum */
} get_channel_state_rsp_s, *p_get_channel_state_rsp_s;

/* get regiset value (0X1C) */
/**
 * @brief ncsi get register value command(0X1C) struct defination
 * @see NCSI_GET_REGISTER_VALUE
 *
 */
typedef struct tg_get_register_value {
	u32 base_address;
	u32 offset_address;
	u32 module;
	u32 check_sum;
} get_register_value_s, *p_get_register_value_s;

/**
 * @brief ncsi get regiset value response(0X9C) struct defination
 * @see NCSI_GET_REGISTER_VALUE_RSP
 *
 */
typedef struct tg_get_register_value_rsp {
	u16 rsp_code;       /**< get regiset value response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;    /**< get regiset value response reason code @see enum NCSI_REASON_CODE_E */
	u32 register_value;
	u32 check_sum;
} get_register_value_rsp_s, *p_get_register_value_rsp_s;

/* Set Fwd Act Cammand 0x1D */
/**
 * @brief ncsi Set Fwd Act command(0x1D) struct defination
 * @see NCSI_SET_FWD_ACT
 *
 */
typedef struct tg_set_fwd_act {
	u8 reserved[3];
	u8 fwd_mode;
	u32 check_sum;   /**< Set Fwd Act command check sum */
} set_fwd_act_s, *p_set_fwd_act_s;
/**
 * @brief ncsi Set Fwd Act response(0x9D) struct defination
 * @see NCSI_SET_FWD_ACT_RSP
 *
 */
typedef struct tg_set_fwd_act_rsp {
	u16 rsp_code;    /**< Set Fwd Act response rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code; /**< Set Fwd Act response reason code @see enum NCSI_REASON_CODE_E */
	u32 check_sum;   /**< Set Fwd Act response check sum */
} set_fwd_act_rsp_s, *p_set_fwd_act_rsp_s;

/* New error reason codes for NCSI OEM commands */
typedef enum {
	OEM_MANUFAC_ID_ERROR = 0x8001, /**< For internal identification only, reason code is not written back to rsp packet */
	OEM_CMD_HEAD_INFO_INVALID = 0x8002,
	OEM_GET_INFO_FAILED = 0x8003,
	OEM_ERR_CODE_NUM_OVER = 0x8004,
	OEM_ERR_UP_GET_DRIVER_INFO_FAILED = 0x8005,
	OEM_CABLE_TYPE_NOT_SUPPORT = 0x8006,
	OEM_CABLE_TYPE_UNDEF = 0x8007,
	OEM_OPTICAL_MODULE_ABS = 0x8008,
	OEM_ENABLE_LLDP_CAPTURE_FAILED = 0x8009,
    /* 0x9000~0xFFFF used for new oem reason codes of ncsi standard commands */
	OEM_GET_CONTROLLER_STATISTIC_FAILED = 0x9000, /**< reason code for NIC statistics information retrieval failure */
	OEM_ENABLE_LLDP_OVER_NCSI_FAILED = 0x9001,
	OEM_GET_LLDP_OVER_NCSI_STATUS_FAILED = 0x9002
} NCSI_OEM_REASON_CODE_E;

/* ncsi oem command related */
/* ncsi oem command common header */
typedef struct tg_ncsi_oem_cmd_head {
	u32 manufac_id; /**< manufacturer id, huawei(0x07db) */
	u8 cmd_rev;
	u8 hw_cmd_id;  /**< cmd number */
	u8 sub_cmd_id; /**< sub cmd number */
	u8 index;      /**< index: only valid for commands that care about pf_id (except for the get log 0x12 command which represents the log type), treated as rsv field in other cases */
} ncsi_oem_cmd_head_s;

/* Common part of ncsi oem command response packet payload (includes first 12 bytes of payload) */
typedef struct tg_ncsi_oem_rsp_payload_comm {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
} ncsi_oem_rsp_payload_comm_s;

/* ncsi oem command request packet */
/**
 * @brief ncsi oem command(0x50) struct defination
 * @see NCSI_OEM_COMMAND
 *
 */
typedef struct tg_ncsi_oem_cmd_req {
	ncsi_oem_cmd_head_s oem_head;       /**< oem command header */
	u32 check_sum;
} ncsi_oem_cmd_req_s;

#define OEM_PROC_FAILED_RSP_LEN (4)     /* payload size of the response packet returned to BMC side after oem command internal processing failure */
/* structure of the response packet returned to BMC side after oem command internal processing failure */
typedef struct tg_oem_proc_failed_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	u32 check_sum;                     /**< check sum */
} oem_proc_failed_rsp_s;

/**
 * @brief oem get network interface bdf response(huawei_id:0x0, sub_id:0x1) struct defination
 * @see OEM_GET_NETWORK_INTERFACE_BDF
 *
 */
typedef struct tg_oem_get_bdf_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 rsvd;
	u8 bus;                            /**< bus id */
	u8 device;                         /**< device id */
	u8 function;                       /**< function id */
	u32 check_sum;                     /**< check sum */
} oem_get_bdf_rsp_s;

/* get the pcie interface ability(huawei_id:0x0, sub_id:0x5) */
#define OEM_GET_PCIE_ABILITY_RSP_LEN (16)
/**
 * @brief oem get the pcie interface ability response(huawei_id:0x0, sub_id:0x5) struct defination
 * @see OEM_GET_PCIE_ABILITY
 *
 */
typedef struct tg_oem_get_pcie_ability_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 pcie_link_width;                /**< pcie link width */
	u8 pcie_link_speed;                /**< pcie link speed */
	u8 rsv[2];
	u32 check_sum;                     /**< check sum */
} oem_get_pcie_ability_rsp_s;

/* get the pcie interface status(huawei_id:0x0, sub_id:0x6) */
#define OEM_GET_PCIE_STATUS_RSP_LEN (16)
/**
 * @brief oem get the pcie interface status(huawei_id:0x0, sub_id:0x6) struct defination
 * @see OEM_GET_PCIE_STATUS
 *
 */
typedef struct tg_oem_get_pcie_status_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 pcie_link_width;                /**< pcie link width */
	u8 pcie_link_speed;                /**< pcie link speed */
	u8 rsv[2];
	u32 check_sum;                     /**< check sum */
} oem_get_pcie_status_rsp_s;

/* get the network interface media type(huawei_id:0x0, sub_id:0x9) */
#define OEM_GET_NETWORK_INTERFACE_MEDIA_TYPE_SP_LEN (16)
/**
 * @brief oem get network interface media type response(huawei_id:0x0, sub_id:0x9) struct defination
 * @see OEM_GET_NETWORK_INTERFACE_MEDIA_TYPE
 *
 */
typedef struct tag_oem_get_network_interface_media_type_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command heade */
	u8 media_type; /**< 0x0: Fiber(BASE-SR/LR/ER),0x1:DAC(BASE-CR),0x2:Copper(BASE-T/RJ45),0x3:Backplane(BASE-KR) */
	u8 rsv[3];
	u32 check_sum;                     /**< check sum */
} oem_get_network_interface_media_type_rsp_s;

/* get the junction temperature(huawei_id:0x0, sub_id:0x0a) */
#define OEM_GET_JUNCTION_TEMP_RSP_LEN (16)
/**
 * @brief oem get the junction temperature response(huawei_id:0x0, sub_id:0x0a) struct defination
 * @see OEM_GET_JUNCTION_TEMP
 *
 */
typedef struct tag_oem_get_junction_temp_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u16 junction_temp;                 /**< junction temperature */
	u8 rsv[2];
	u32 check_sum;                     /**< check sum */
} oem_get_junction_temp_rsp_s;

/* get the optical module temperature(huawei_id:0x0, sub_id:0x0b) */
/**
 * @brief oem get the optical module temperature response(huawei_id:0x0, sub_id:0x0b) struct defination
 * @see OEM_GET_OPTICAL_MODULE_TEMP
 *
 */
#define OEM_GET_OPT_MODU_TEMP_RSP_LEN (16)
typedef struct tag_oem_get_opt_modu_temp_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u16 opt_modu_temp;                 /**< optical module temperature */
	u8 rsv[2];
	u32 check_sum;                     /**< check sum */
} oem_get_opt_modu_temp_rsp_s;

/* get the err code(huawei_id:0x0, sub_id:0x0c) */
#define NCSI_OEM_ERR_CODE_MAX_NUM (11) /* maximum number of reported error codes, currently defined as 11 */
#define OEM_GET_ERR_CODE_RSP_LEN (36)
/**
 * @brief oem get the err code response(huawei_id:0x0, sub_id:0x0c) struct defination
 * @see OEM_GET_ERR_CODE
 *
 */
typedef struct tag_oem_get_err_code_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head;       /**< oem command header */
	u8 health_status;                        /**< Health status (0: normal; 1: minor; 2: major; 3: critical) */
	u8 err_code_count;                       /**< error code count */
	u16 err_code[NCSI_OEM_ERR_CODE_MAX_NUM]; /**< Error code array. The size is an odd number and must be 4-byte aligned. */
	u32 check_sum;                           /**< check sum */
} oem_get_err_code_rsp_s;

/* get the transceiver or cable information(huawei_id:0x0, sub_id:0x0d) */
#define OEM_GET_CABLE_INFO_RSP_LEN (120)
#define PART_NUM_MAX_LEN (16)
#define MPU_VENDOR_MAX_LEN  (16)
#define SERIAL_NUM_MAX_LEN (16)
#define CABLE_INFO_UNSUPPORTED16 (0xFFFF)
#define CABLE_INFO_UNSUPPORTED8 (0xFF)

#define QSFP_WAVE_LENGTH_DIVIDER (20)
/**
 * @brief oem get the transceiver or cable information response(huawei_id:0x0, sub_id:0x0d) struct defination
 * @see OEM_GET_NETWORK_INTERFACE_TRANS_CABLE_INFO
 *
 */
typedef struct tag_oem_get_trans_or_cable_info_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */

	u8 device_part_number[PART_NUM_MAX_LEN];     /**< device part_number */
	u8 device_vendor[MPU_VENDOR_MAX_LEN];            /**< device vendor */
	u8 device_serial_number[SERIAL_NUM_MAX_LEN]; /**< device serial number */

	u8 device_identifier;   /**< device identification SFP+/QSFP+/SFP28/QSFP28 */
	u8 device_type;         /**< device type (SR/LR/CR_Passive/CR_Active/SR4/LR4/CR4_Passive/CR4_Active) */
	u8 device_connect_type; /**< device connection type (LC/MPO/DAC/RJ45) */
	u8 rsv;

	u16 device_trans_distance; /**< device transmission distance */
	u16 device_wavelen;        /**< device wavelength */

	u16 work_para_temp;            /**< operating temperature */
	u16 work_para_voltage;         /**< operating voltage */
	u16 work_para_tx_bias_current; /**< tx current */
	u16 work_para_tx_power;        /**< tx power */
	u16 work_para_rx_power;        /**< rx power */
	u16 warn_threshold_low_temp;   /**< low temperature warning threshold */
	u16 warn_threshold_high_temp;  /**< high temperature warning threshold */
	u16 warn_threshold_tx_power;   /**< tx power warning threshold */
	u16 warn_threshold_rx_power;   /**< rx power warning threshold */
	u16 alarm_threshold_low_temp;  /**< low temperature alarm threshold */
	u16 alarm_threshold_high_temp; /**< high temperature alarm threshold */
	u16 alarm_threshold_tx_power;  /**< tx power alarm threshold */
	u16 alarm_threshold_rx_power;  /**< rx power alarm threshold */
	u8 rx_los_state;
	u8 tx_fult_state;

	u8 rsv1[24];

	u32 check_sum;                 /**< check sum */
} oem_get_trans_or_cable_info_rsp_s;

/* enable LLDP capture(huawei_id:0x0, sub_id:0x0e) */
#define OEM_ENABLE_LLDP_CAPTURE_RSP_LEN (12)
/**
 * @brief oem enable LLDP capture response(0xe) struct defination
 * @see OEM_ENABLE_LLDP_CAPTURE
 *
 */
typedef struct tag_oem_enable_lldp_capture_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */

	u32 check_sum;                     /**< check sum */
} oem_enable_lldp_capture_rsp_s;

/* get lldp capbility(huawei_id:0x0, sub_id:0x0f) */
#define OEM_GET_LLDP_CAPBILITY_RSP_LEN (16)
/**
 * @brief oem get lldp capbility response(huawei_id:0x0, sub_id:0x0f) struct defination
 * @see OEM_GET_LLDP_CAPBILITY
 *
 */
typedef struct tag_oem_get_lldp_capbility_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 capbility;
	u8 rsv[3];
	u32 check_sum;                     /**< check sum */
} oem_get_lldp_capbility_rsp_s;

/**
 * @brief oem get lldp capbility response(huawei_id:0x0, sub_id:0x11) struct defination
 * @see OEM_GET_HW_OEM_CMD_CAPABILITY (0x11)
 *
 */
typedef struct tag_oem_get_oem_command_cap {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u32 check_sum;                     /**< check sum */
} oem_get_oem_command_cap;

/**
 * @brief oem get oem command capbility response(huawei_id:0x0, sub_id:0x11) struct defination
 * @see OEM_GET_HW_OEM_CMD_CAPABILITY (0x11)
 * @see OEM_ENABLE_LOW_POWER_MODE (0x40C)
 * @see OEM_GET_LOW_POWER_MODE_STATUS (0x40D)
 * @see OEM_ENABLE_LLDP_OVER_NCSI (0x40A)
 * @see OEM_GET_LLDP_OVER_NCSI_STATUS (0x40B)
 *
 */
typedef struct tag_oem_get_oem_command_cap_resp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */

	u32 bitmap;    /**< Capability Bit Map
			 * bit0: Enable/disable low power consumption mode
			 * bit1: Get low power consumption mode
			 * bit2: Enable/disable LLDP forward over NCSI
			 * bit3: Get LLDP forward over NCSI status
			 * other bit: Reserved
			 */
	u32 rsvd[13];
	u32 check_sum;                     /**< check sum */
} oem_get_oem_command_cap_resp;

/* get lldp tx capbility(huawei_id:0x0, sub_id:0x13) */
#define OEM_GET_LLDP_TX_CAPBILITY_RSP_LEN (16)
/**
 * @brief oem get lldp tx capbility response(huawei_id:0x0, sub_id:0x13) struct defination
 * @see OEM_GET_LLDP_TX_CAPBILITY
 *
 */
typedef struct tag_oem_get_lldp_tx_capbility_rsp {
	u16 rsp_code;
	u16 reason_code;
	ncsi_oem_cmd_head_s ncsi_oem_head; /* oem cmd common header */
	u8 capbility;
	u8 rsv[3];
	u32 check_sum;
} oem_get_lldp_tx_capbility_rsp_s;

/* enable LLDP capture(huawei_id:0x0, sub_id:0x14) */
#define OEM_ENABLE_LLDP_TX_RSP_LEN (12)
/**
 * @brief oem enable lldp tx response(huawei_id:0x0, sub_id:0x14) struct defination
 * @see OEM_ENABLE_LLDP_TX
 *
 */
typedef struct tag_oem_enable_lldp_tx_rsp {
	u16 rsp_code;
	u16 reason_code;
	ncsi_oem_cmd_head_s ncsi_oem_head; /* oem cmd common header */

	u32 check_sum;
} oem_enable_lldp_tx_rsp_s;

typedef struct tag_oem_get_log_info_head {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u32 offset;
	u32 len;
	u32 check_sum;                     /**< check sum */
} oem_get_log_head;

#define OEM_GET_LOG_INFO_MAX_LEN (1024)    // maximum 1024B per transfer
#define OEM_GET_LOG_INFO_RSP_LEN (1036)
/**
 * @brief oem get log info response(huawei_id:0x0, sub_id:0x12) struct defination
 * @see OEM_GET_LOG_INFO
 *
 */
typedef struct tag_oem_get_log_info_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 log_data[OEM_GET_LOG_INFO_MAX_LEN];
	u32 check_sum;                     /**< check sum */
} oem_get_log_rsp;

#define OEM_GET_NEW_LOG_CTRL_FRAME 0x5a5a5a5a
#define OEM_GET_NEW_LOG_DATA_FRAME 0

#define OEM_GET_NEW_LOG_REQ_PAYLD_LEN 20

typedef struct {
	ncsi_oem_cmd_head_s ncsi_oem_head;
	u32 frame_type;
	u32 offset;
	u32 len;
	u32 check_sum;
} oem_get_new_log_req;

typedef struct {
	u16 rsp_code;                               /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                            /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head;
} oem_get_new_log_rsp_head;

#define OEM_MAX_SUB_LOG_NUM (16)

typedef struct {
	oem_get_new_log_rsp_head head;
	u32 total_len;
	u8 sub_log_num;
	u8 reserved;
	u16 sub_log_len[OEM_MAX_SUB_LOG_NUM];
	u32 check_sum;
} oem_get_new_log_ctrl_frame_rsp;

typedef struct {
	oem_get_new_log_rsp_head head;
	u8 last; // last frame: 1, non-last frame: 0
	u8 reserved[3];
	u8 data[OEM_GET_LOG_INFO_MAX_LEN];
	u32 checksum;
} oem_get_new_log_data_frame_rsp;

/**
 * @brief oem enable lldp over ncsi command(0x40A) struct defination
 * @see OEM_ENABLE_LLDP_OVER_NCSI
 *
 */
typedef struct tag_oem_enable_lldp_over_ncsi {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 enable;
	u8 rsvd[3];
	u32 check_sum;                     /**< check sum */
} oem_enable_lldp_over_ncsi;

/**
 * @brief oem enable lldp over ncsi response(0x40A) struct defination
 * @see OEM_ENABLE_LLDP_OVER_NCSI
 *
 */
typedef struct tag_oem_enable_lldp_over_ncsi_resp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u32 check_sum;                     /**< check sum */
} oem_enable_lldp_over_ncsi_resp;

/**
 * @brief oem get lldp over ncsi status command(0x40B) struct defination
 * @see OEM_GET_LLDP_OVER_NCSI_STATUS
 *
 */
typedef struct tag_oem_get_lldp_over_ncsi_status {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u32 check_sum;                     /**< check sum */
} oem_get_lldp_over_ncsi_status;

/**
 * @brief oem get lldp over ncsi status response(0x40B) struct defination
 * @see OEM_GET_LLDP_OVER_NCSI_STATUS
 *
 */
typedef struct tag_oem_get_lldp_over_ncsi_status_resp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 enable;
	u8 rsvd[3];
	u32 check_sum;                     /**< check sum */
} oem_get_lldp_over_ncsi_status_resp;

/**
 * @brief oem enable low power mode command(0x40C) struct defination
 * @see OEM_ENABLE_LOW_POWER_MODE
 *
 */
typedef struct tag_oem_enable_low_power_mode {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem cmd common header */
	u8 enable;
	u8 rsvd[3];
	u32 check_sum;                     /**< check sum */
} oem_enable_low_power_mode;

/**
 * @brief oem oem enable low power mode response(0x40C) struct defination
 * @see OEM_ENABLE_LOW_POWER_MODE
 *
 */
typedef struct tag_oem_enable_low_power_mode_resp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u32 check_sum;                     /**< check sum */
} oem_enable_low_power_mode_resp;

/**
 * @brief oem get low power mode status command(0x40D) struct defination
 * @see OEM_GET_LOW_POWER_MODE_STATUS
 *
 */
typedef struct tag_oem_get_low_power_mode_status {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header @see struct ncsi_oem_cmd_head_s */
	u32 check_sum;                     /**< check sum */
} oem_get_low_power_mode_status;

/**
 * @brief oem get low power mode status response(0x40D) struct defination
 * @see OEM_GET_LOW_POWER_MODE_STATUS
 *
 */
typedef struct tag_oem_get_low_power_mode_status_resp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 enable;
	u8 rsvd[3];
	u32 check_sum;                     /**< check sum */
} oem_get_low_power_mode_status_resp;

/* get the network interface mac addr(huawei_id:0x1, sub_id:0x00) */
#define MAC_ADDRESS_LEN (6)
#define OEM_GET_NETWORK_INTERFACE_MAC_ADDR_RSP_LEN (64)
#define OEM_NETWORK_INTERFACE_MAC_ADDR_MAX_NUM (8) /* at most 8 mac addr presented in the data structure */
/**
 * @brief oem get netork interface mac addr response(0x100) struct defination
 * @see OEM_GET_NETWORK_INTERFACE_MAC_ADDR
 *
 */
typedef struct tag_oem_get_netork_interface_mac_addr_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u16 mac_addr_count;                /**< actual number of mac_addr (may be more than 8, at most 8 are displayed) */
	u8 rsv[2];
	u8 mac_addr[MAC_ADDRESS_LEN * OEM_NETWORK_INTERFACE_MAC_ADDR_MAX_NUM]; /* mac addr, must ensure 4-byte alignment */

	u32 check_sum;                     /**< check sum */
} oem_get_netork_interface_mac_addr_rsp_s;

/* get the network interface dcbx(huawei_id:0x1, sub_id:0x02) */
#define OEM_GET_NETWORK_INTERFACE_DCBX_RSP_LEN (48)

/**
 * @brief oem get networ interface dcbx response(0x102) struct defination
 * @see OEM_GET_NETWORK_INTERFACE_DCBX
 *
 */
typedef struct tag_oem_get_network_interface_dcbx_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 up2cos[8];                      /**< mapping from user_priority to cos */
	u8 up_pgid[8];                     /**< COS TC mapping of DCB ETS */
	u8 pgpct[8];                       /**< bandwidth ratio between tc */
	u8 strict[8];                      /**< scheduling mode is SP or DWRR */
	u8 pfcmap;                         /**< dcb pfc enable and disable status */
	u8 rsv[3];

	u32 check_sum;                     /**< check sum */
} oem_get_network_interface_dcbx_rsp_s;

#define OEM_PGPCT_TC_WGT_INDEX 100

/* get dafault mac address(huawei_id:0x1, sub_id:0x04) */
#define OEM_GET_DEFAULT_MAC_ADDR_RSP_LEN (64)
#define OEM_DEFAULT_MAC_ADDRESS_MAX_COUNT (8) /* maximum number of default mac addresses */
#define PORT_DEFAULT_MAC_ADDR_MAX_SIZE (MAC_ADDRESS_NUM * OEM_DEFAULT_MAC_ADDRESS_MAX_COUNT)

/**
 * @brief oem get default mac addr response(0x104) struct defination
 * @see OEM_GET_NETWORK_DEFAULT_MAC_ADDR
 *
 */
typedef struct tag_oem_get_default_mac_addr_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 mac_count;                      /**< mac address count */
	u8 rsv[3];
	u8 mac_addr[PORT_DEFAULT_MAC_ADDR_MAX_SIZE]; /**< default mac addr, must ensure 4-byte alignment */

	u32 check_sum;                     /**< check sum */
} oem_get_default_mac_addr_rsp_s;

/**
 * @brief ncsi oem set volatile mac command(0x508) struct defination
 * @see OEM_SET_VOLATILE_MAC
 *
 */
typedef struct tag_oem_set_volatile_mac {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 mac[MAC_ADDRESS_LEN];
	u8 rsv[2];
	u32 check_sum;                     /**< check sum */
} oem_set_volatile_mac;

#define OEM_SET_VOLATILE_MAC_REQ_PAYLD_LEN 16
#define OEM_SET_VOLATILE_MAC_RESP_LEN 12
#define OEM_GET_VOLATILE_MAC_RESP_LEN 20

/**
 * @brief ncsi oem set volatile mac response(0x508) struct defination
 * @see OEM_SET_VOLATILE_MAC
 *
 */
typedef struct tag_oem_set_volatile_mac_resp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u32 check_sum;                     /**< check sum */
} oem_set_volatile_mac_resp;

/**
 * @brief ncsi oem get volatile mac command(0x509) struct defination
 * @see OEM_SET_VOLATILE_MAC
 *
 */
typedef struct tag_oem_get_volatile_mac {
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u32 check_sum;                     /**< check sum */
} oem_get_volatile_mac;

/**
 * @brief ncsi oem get volatile mac response(0x509) struct defination
 * @see OEM_SET_VOLATILE_MAC
 *
 */
typedef struct tag_oem_get_volatile_mac_resp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_OEM_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 mac[MAC_ADDRESS_LEN];
	u8 rsv[2];
	u32 check_sum;                     /**< check sum */
} oem_get_volatile_mac_resp;


/* get xsfp present status */
#define OEM_GET_XSFP_STATUS_RSP_LEN (16)
/**
 * @brief oem get get xsfp present status response(huawei_id:0x0, sub_id:0x17) struct defination
 * @see OEM_GET_XSFP_STATUS
 *
 */
typedef struct tag_oem_get_xsfp_status_rsp {
	u16 rsp_code;                      /**< rsp code @see enum NCSI_RESPONSE_CODE_E */
	u16 reason_code;                   /**< reason code @see enum NCSI_REASON_CODE_E */
	ncsi_oem_cmd_head_s ncsi_oem_head; /**< oem command header */
	u8 rsv[3];
	u8 present_status;                 /**< Optical module present status */
	u32 check_sum;                     /**< check sum */
} oem_get_xsfp_status_rsp_s;

#pragma pack()

#endif