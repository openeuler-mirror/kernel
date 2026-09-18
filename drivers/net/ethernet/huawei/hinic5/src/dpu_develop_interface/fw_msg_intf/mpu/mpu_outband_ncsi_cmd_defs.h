/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_outband_ncsi_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2023/09/22
 * Last Modified : 2026/09/16
 * Description   : NCSI protocol out-of-band command related structure
 */

#ifndef MPU_OUTBAND_NCSI_CMD_DEFS_H
#define MPU_OUTBAND_NCSI_CMD_DEFS_H

#include "base_type.h"

#pragma pack(1)

typedef enum {
	COMMAND_COMPLETED = 0x00,       /**< command completed */
	COMMAND_FAILED = 0x01,          /**< command failed */
	COMMAND_UNAVAILABLE = 0x02,     /**< command unavailable */
	COMMAND_UNSPORRTED = 0x03       /**< command unsporrted */
} NCSI_RESPONSE_CODE_E;

typedef enum {
	NO_ERROR = 0x00,                /**< no error */
	INTERFACE_INIT_REQUIRED = 0x01, /**< interface init required */
	INVALID_PARA = 0x02,            /**< invalid parameter */
	CHAN_NOT_READY = 0x03,          /**< channel not ready */
	PKG_NOT_READY = 0x04,           /**< package not ready */
	INVALID_PAYLOAD_LEN = 0x05,     /**< invalid payload len */
	FLOW_CONTROL_UNSUPPORTED = 0x09, /**< flow control unsupported */
	CHECKSUM_ERR = 0xA,              /**< check sum error */
	LINK_STATUS_ERROR = 0xA06,      /**< set or get link status failed */
	VLAN_TAG_INVALID = 0xB07,        /**< vlan tag invalid */
	MAC_Add_IS_ZERO = 0xE08,         /**< mac add is zero */
	GET_INVENTORY_INFO_ERROR = 0xE09,  /**< get inventory info error */
	UNSUPPORTED_COMMAND_TYPE = 0x7FFF /**< the command type is unsupported only when the response code is 0x03 */
} NCSI_REASON_CODE_E;

typedef enum {
	NCSI_RMII_TYPE = 1,             /**< rmii client */
	NCSI_MCTP_TYPE = 2,             /**< MCTP client */
	NCSI_AEN_TYPE = 3               /**< AEN client */
} NCSI_CLIENT_TYPE_E;

/**
 * @brief ncsi ctrl packet header
 *
 */
typedef struct tag_ncsi_ctrl_packet_header {
	u8 mc_id;              /**< management control ID */
	u8 head_revision;      /**< head revision */
	u8 reserved0;          /**< reserved */
	u8 iid;                /**< instance ID */
	u8 pkt_type;           /**< packet type */
#ifdef NCSI_BIG_ENDIAN
	u8 pkg_id : 3;         /**< packet ID */
	u8 inter_chan_id : 5;  /**< channel ID */
#else
	u8 inter_chan_id : 5;  /**< channel ID */
	u8 pkg_id : 3;         /**< packet ID */
#endif
#ifdef BD_BIG_ENDIAN
	u8 reserved1 : 4;      /**< reserved1 */
	u8 payload_len_hi : 4; /**< payload len have 12bits */
#else
	u8 payload_len_hi : 4; /**< payload len have 12bits */
	u8 reserved1 : 4;      /**< reserved1 */
#endif
	u8 payload_len_lo;     /**< payload len lo */
	u32 reserved2;         /**< reserved2 */
	u32 reserved3;         /**< reserved3 */
} ncsi_ctrl_pkt_header_s;

#define NCSI_MAX_PAYLOAD_LEN 1500
#define NCSI_MAC_LEN 6
/* get dafault mac address(huawei_id:0x1, sub_id:0x04) */
#define MAC_ADDRESS_NUM (6) // Defined, can be used later

/**
 * @brief ncsi clear initial state command struct defination
 *
 */
typedef struct tag_ncsi_ctrl_packet {
	ncsi_ctrl_pkt_header_s packet_head; /**< ncsi ctrl packet header */
	u8 payload[NCSI_MAX_PAYLOAD_LEN];   /**< ncsi ctrl packet payload */
} ncsi_ctrl_packet_s;

/**
 * @brief ethernet header description
 *
 */
typedef struct tag_ethernet_header {
	u8 dst_addr[NCSI_MAC_LEN];       /**< ethernet destination address */
	u8 src_addr[NCSI_MAC_LEN];       /**< ethernet source address */
	u16 ether_type;                  /**< ethernet type */
} ethernet_header_s;

/**
 * @brief ncsi common packet description
 *
 */
typedef struct tg_ncsi_common_packet {
	ethernet_header_s frame_head;     /**< common packet ethernet frame header */
	ncsi_ctrl_packet_s ctrl_packet;   /**< common packet ncsi ctrl packet */
} ncsi_common_packet_s, *p_ncsi_common_packet_s;

/**
 * @brief ncsi clear initial state command struct defination
 *
 */
typedef struct tag_ncsi_client_info {
	u32 type;                  /**< client info type of ncsi media  @see enum NCSI_CLIENT_TYPE_E */
	u8 bmc_mac[NCSI_MAC_LEN];  /**< client info BMC mac addr */
	u8 ncsi_mac[NCSI_MAC_LEN]; /**< client info local mac addr */
	u8 reserve[2];             /**< client info reserved, Four-byte alignment */
	u32 rsp_len;               /**< client info include pad */
	ncsi_common_packet_s ncsi_packet_rsp; /**< ncsi common packet response */
} ncsi_client_info_s;

#pragma pack()

#endif