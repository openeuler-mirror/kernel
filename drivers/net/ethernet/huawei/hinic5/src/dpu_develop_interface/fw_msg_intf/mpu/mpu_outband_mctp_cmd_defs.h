/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_outband_mctp_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2023/09/22
 * Last Modified : 2026/09/16
 * Description   : MCTP protocol out-of-band command related structure
 */

#ifndef MPU_OUTBAND_MCTP_CMD_DEFS_H
#define MPU_OUTBAND_MCTP_CMD_DEFS_H

#define MAX_NUM_ROUTING_TBL 5
#define MAX_NUM_PHY_ADDR_SIZE 2

/**
 * @brief Define a struct named mctp_endpoint
 */
typedef struct {
	u8 port_index;      /**< Port index */
	u8 eid;             /**< Endpoint ID */
	u16 bdf;            /**< Bus, Device, Function */
	u32 version;        /**< MCTP version */
	u8 discovery;       /**< Discovery status */
	u8 mc_id;           /**< Management controller ID */
	u16 mc_bdf;         /**< Management controller Bus, Device, Function */
	u8 trans_tag;       /**< Transport layer tag */
	u8 ctrl_msg_iid;    /**< Control message instance ID */
	u8 mc_inst_id;      /**< Management controller instance ID */
	u8 pcie_type;       /**< PCIe device type */
	u8 *msg;            /**< Pointer to message buffer */
	u8 rsv0;            /**< Reserved */
	u8 first_pkt_flag;  /**< First packet flag */
	u16 pkt_cnt;        /**< Packet count */
	u8 *mctp_rcv_buf;   /**< Pointer to MCTP receive buffer */
	u8 *mctp_send_buf;  /**< Pointer to MCTP send buffer */
	u16 rcv_offset;     /**< Receive buffer offset */
	u16 send_offset;    /**< Send buffer offset */
	u8 breq;            /**< Request or response flag */
	u8 rq;              /**< MCTP control message rq field */
	u8 cmd_code;        /**< MCTP control header command code */
	u8 msg_type;        /**< MCTP control header message type */
	u8 msg_tag;         /**< MCTP control header message tag */
	u8 tag_owner;       /**< MCTP control header tag owner */
} mctp_endpoint;

/**
 * @brief Define a struct named res_data_eidset
 */
typedef struct {
	u8 complete_code;       /**< The completion status of the EID set operation */

	u8 eid_alloc_stat : 2;  /**< The allocation status of the EID */
	u8 rsv1 : 2;            /**< Reserved for future use */
	u8 eid_assign_stat : 2; /**< The assignment status of the EID */
	u8 rsv2 : 2;            /**< Reserved for future use */

	u8 eid_set;             /**< The EID set */

	u8 eid_pool_size;       /**< The size of the EID pool */
} res_data_eidset;

/**
 * @brief Define the structure type as req_data_eidset
 */
typedef struct {
	u8 operate : 2; /**< The eid set mode */
	u8 rsv1 : 6;    /**< Reserved for future use */
	u8 eid;         /**< The eid to be set */
} req_data_eidset;

/**
 * @brief Define the structure type as res_data_eidget
 */
typedef struct {
	u8 complete_code;       /**< The complete code of the event */

	u8 eid;                 /**< The endpoint identifier */

	u8 eid_type : 2;        /**< The eid type. 0:dynamic EID, 1:static EID */
	u8 rsv1 : 2;
	u8 endpoint_type : 2;   /**< The endpoint type. 0:normal ep, 1:bus owner/brige */
	u8 rsv2 : 2;            /**< Reserved for future use */

	u8 medium_info;         /**< The medium info */
} res_data_eidget;

/**
 * @brief Define the structure type as mctp_pcie_header
 */
typedef struct {
	u16 length : 10;    /**< The data length */
	u16 rsv3 : 2;       /**< Reserved for future use */
	u16 attr : 2;       /**< The attribute */
	u16 ep : 1;         /**< The error present */
	u16 td : 1;         /**< The owner of the tag field */

	u8 rsv2 : 4;        /**< Reserved for future use */
	u8 tc : 3;          /**< The traffic class */
	u8 rsv1 : 1;        /**< Reserved for future use */

	u8 tpye : 5;        /**< The message type */
	u8 fmt : 2;         /**< The message format */
	u8 rsv : 1;         /**< Reserved for future use */

	u8 msg_code;        /**< The MCTP message code. 0111_1111b */

	u8 vdm_code : 4;    /**< The VDM code */
	u8 pad_len : 2;     /**< The pad len of message */
	u8 rsv4 : 2;        /**< Reserved for future use */

	u16 pci_request_id; /**< The pci request id, filled by hardware */

	u16 vendor;         /**< The vendor id */

	u16 pci_target_id;  /**< The pci target id */
} mctp_pcie_header;


/**
 * @brief Define the structure type as res_resolve_eid
 */
typedef struct {
	u8 complete_code;                       /**< The complete code of the event */
	u8 bridge_eid;                          /**< The bridge eid */
	u8 phy_addr[MAX_NUM_PHY_ADDR_SIZE];     /**< The physical address */
} res_resolve_eid;

/**
 * @brief Define the structure type as mctp_ver_type
 */
typedef struct {
	u8 major_ver;   /**< The major version */
	u8 minor_ver;   /**< The minor version */
	u8 update_ver;  /**< The update version */
	u8 pre_ver;     /**< The previous version */
} mctp_ver_type;

/**
 * @brief Define the structure type as routing_tbl_format
 */
typedef struct {
	unsigned char size_of_EID_range;                /**< The size of EID range */

	unsigned char start_EID;                        /**< The start eid */

	unsigned char port_num : 5;                     /**< The port number */
	unsigned char dyna_static : 1;                  /**< The dynamic static */
	unsigned char entry_type : 2;                   /**< The entry type */

	unsigned char phy_binding_type;                 /**< The physical binding type */

	unsigned char phy_media_type;                   /**< The physical media type */

	unsigned char phy_addr_size;                    /**< The physical address size */

	unsigned char phy_addr[MAX_NUM_PHY_ADDR_SIZE];  /**< The physical address */
} routing_tbl_format;

/**
 * @brief Define the structure type as res_data_routing_info_update_entry
 */
typedef struct {
	u8 entry_type : 4;                                       /**< The entry type */
	u8 rsv : 4;
	u8 size_eid_range;                                       /**< The size of EID range */
	u8 first_eid_in_eid_range;                               /**< The first eid */
	u8 phy_addr[MAX_NUM_PHY_ADDR_SIZE];                      /**< The physical address */
} res_data_routing_info_update_entry;

/**
 * @brief Define the structure type as res_data_routing_tbl_get
 */
typedef struct {
	unsigned char complete_code;                            /**< The complete code of event */

	unsigned char next_enty_handle;                         /**< The next enty handle */

	unsigned char num_routing_tbl;                          /**< The number of routing table */

	routing_tbl_format routing_tbl[MAX_NUM_ROUTING_TBL];    /**< Support saving 5 routing information */
} res_data_routing_tbl_get;

/**
 * @brief Define the structure type as resolve_uuid_message_entry_format
 */
typedef struct {
	u8 eid;                                                     /**< Endpoint ID */
	u8 phy_transport_binding_type_id;                           /**< The physical transport binding type id */
	u8 phy_media_type_id;                                       /**< The physical transport type id */
	u8 phy_addr_size;                                           /**< The physical address size */
	u8 phy_addr[MAX_NUM_PHY_ADDR_SIZE];                         /**< The physical addresss */
} resolve_uuid_message_entry_format;

/**
 * @brief Define the structure type as res_requry_hop_data
 */
typedef struct {
	u8 complete_code;                                           /**< The complete code of event */
	u8 next_bridge_eid;                                         /**< Next bridge eid */
	u8 message_type;                                            /**< Message type */
	u16 max_incoming_transmission_unit_size;                    /**< Max incoming transmission unit size */
	u16 max_outcoming_transmission_unit_size;                   /**< Max outcoming transmission unit size */
} res_requry_hop_data;

#endif