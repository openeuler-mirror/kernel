/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_outband_mctp_cmd.h
 * Version       : Initial Draft
 * Created       : 2023/09/22
 * Last Modified : 2026/09/16
 * Description   : MCTP protocol out-of-band commands
 */

#ifndef MPU_OUTBAND_MCTP_CMD_H
#define MPU_OUTBAND_MCTP_CMD_H

/**
 * @brief MCTP command code
 */
typedef enum {
	RESERVED_ID = 0,                            /**< Reserved for future use */
	SET_ENDPOINT_ID = 0x01,                     /**< Set end point id @see struct res_data_eidset */
	GET_ENDPOINT_ID = 0x02,                     /**< Get end point id @see struct res_data_eidget */
	GET_ENDPOINT_UUID = 0x03,                   /**< Get end point uuid @see struct mctp_pcie_header */
	GET_MCTP_VERSION_SUPPORT = 0x04,            /**< Get MCTP version support @see struct mctp_ver_type */
	GET_MESSAGE_TYPE_SUPPORT = 0x05,            /**< Get message type support */
	GET_VENDOR_DEFINED_MESSAGE_SUPPORT = 0x06,  /**< Get vendor defined message support */
	RESOLVE_ENDPOINT_ID = 0x07,                 /**< resolve endpoint id */
	ALLOCATE_ENDPOINT_IDS = 0x08,               /**< Allocate endpoint ids, @see struct mctp_pcie_header */
	ROUTING_INFORMATION_UPDATE = 0x09,          /**< Routing endpoint ids */
	GET_ROUTING_TABLE_ENTRIES = 0x0a,           /**< Get routing table entries, @see struct res_data_routing_tbl_get */
	PREPARE_FOR_ENDPOINT_DISCOVERY = 0x0b,      /**< Prepare for endpoint discovery */
	ENDPOINT_DISCOVERY = 0x0c,                  /**< Discovery endpoint */
	DISCOVERY_NOTIFY = 0x0d,                    /**< Discovery Notify */
	GET_NETWORK_ID = 0x0e,                      /**< Get network id */
	QUERY_HOP = 0x0f,                           /**< Query HOP */
	RESOVLE_ENDPOINT_UUID = 0x10                /**< resolve endpoint uuid */
} mctp_cmd_type;

#endif