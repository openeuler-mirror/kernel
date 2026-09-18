/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_npu_wqe_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : NIC NPU WQE definitions
 */

#ifndef NIC_NPU_WQE_DEFINE_H
#define NIC_NPU_WQE_DEFINE_H

#include "typedef.h"

/**
 * @brief Internal/external IP type
 * @details Defines an enum type used to represent internal/external IP type
 */
typedef enum {
    /*
     * 00 - non ip packet or packet type is not defined by software
     * 01 - ipv6 packet
     * 10 - ipv4 packet with no ip checksum offload
     * 11 - ipv4 packet with ip checksum offload
     */
	NON_IP_TYPE = 0,
	TYPE_IPV6,
	TYPE_IPV4,
	TYPE_IPV4_CS_OFF
} qsf_ip_type_e;

/**
 * @brief Defines a tunnel type enum used to represent different tunnel types
 * @details This enum is used to represent different tunnel types, including no tunnel, UDP tunnel (no CS), UDP tunnel (with CS), and GRE tunnel.
 */
typedef enum {
    /*
     * 0 - no udp / gre tunneling / no tunnel
     * 1 - udp tunneling header with no cs
     * 2 - udp tunneling header with cs
     * 3 - gre tunneling header
     */
	L4_TUNNEL_NO_TUNNEL = 0,
	L4_TUNNEL_UDP_NO_CS,
	L4_TUNNEL_UDP_CS,
	L4_TUNNEL_GRE
} qsf_tunnel_type_e;

/**
 * @brief Defines an enum type used to represent different layer-4 protocol types
 * @details This enum type contains four different layer-4 protocol types: unknown/fragmented packet, Transmission Control Protocol, Stream Control Transmission Protocol, and User Datagram Protocol.
 */
typedef enum {
    /*
     * 00b - unknown / fragmented packet
     * 01b - tcp
     * 10b - sctp
     * 11b - udp
     */

	L4_TYPE_UNKNOWN = 0,
	L4_TYPE_TCP,
	L4_TYPE_SCTP,
	L4_TYPE_UDP
} qsf_l4_offload_type_e;

/**
 * @struct tag_l2nic_rx_compact_cqe
 * @brief Defines a receive completion queue entry (Completion Queue Entry, CQE) struct,
 *        which is used to describe various attributes of received packets.
 * @details This struct is used to represent the completion status of received packets,
 *          it contains various flags and error information about the packets.
 */
typedef struct tag_l2nic_rx_compact_cqe {
    /**
     * @union dw0
     * @brief This union is used to store various attributes of received packets.
     */
	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 rx_done : 1;  /**< Receive done flag */
		u32 cqe_type : 1; /**< CQE type */
		u32 ts_flag : 1;  /**< Timestamp flag */
		u32 vlan_offload : 1; /**< VLAN hardware parse flag */
		u32 pkt_fmt : 3;      /**< Packet format */
		u32 ip_type : 1;      /**< IP type */
		u32 cqe_len : 1;      /**< CQE length */
		u32 pkt_mc : 2;       /**< Packet multicast flag */
		u32 checksum_err : 2; /**< Checksum error flag */
		u32 pkt_type : 3;     /**< Packet type */
		u32 pkt_len : 16;     /**< Packet length */
#else
		u32 pkt_len : 16;   /**< Packet length */
		u32 pkt_type : 3;   /**< Packet type */
		u32 checksum_err : 2;   /**< Checksum error flag */
		u32 pkt_mc : 2;     /**< Packet multicast flag */
		u32 cqe_len : 1;    /**< CQE length */
		u32 ip_type : 1;    /**< IP type */
		u32 pkt_fmt : 3;    /**< Packet format */
		u32 vlan_offload : 1;   /**< VLAN hardware parse flag */
		u32 ts_flag : 1;    /**< Timestamp flag */
		u32 cqe_type : 1;   /**< CQE type */
		u32 rx_done : 1;    /**< Receive done flag */
#endif
	} bs;
	u32 value; /**< Stores the value of all fields */
	} dw0;

    /**
     * @union dw1
     * @brief This union is used to store the RSS hash value of received packets.
     */
	union {
	struct {
		u32 rss_hash_value; /**< RSS hash value */
	} bs;
	u32 value; /**< Stores the value of all fields */
	} dw1;

    /**
     * @union dw2
     * @brief This union is used to store various attributes of received packets.
     */
	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 lro_num : 8;       /**< LRO (Large Receive Offload) count */
		u32 vlan_tag : 16;     /**< VLAN tag */
		u32 rsvd2 : 2;         /**< Reserved field */
		u32 pfe_tx_pkt_en : 1; /**< PFE (Physical Function Engine) transmit packet enable */
		u32 port_id : 2;       /**< Port ID */
		u32 flow_mark_vld : 1; /**< Flow mark valid flag */
		u32 src_function_id_h : 2; /**< High 8 bits of source function ID */
#else
		u32 src_function_id_h : 2;  /**< High 8 bits of source function ID */
		u32 flow_mark_vld : 1;  /**< Flow mark valid flag */
		u32 port_id : 2;        /**< Port ID */
		u32 pfe_tx_pkt_en : 1;  /**< PFE (Physical Function Engine) transmit packet enable */
		u32 rsvd2 : 2;          /**< Reserved field */
		u32 vlan_tag : 16;      /**< VLAN tag */
		u32 lro_num : 8;        /**< LRO (Large Receive Offload) count */
#endif
	} bs;
	u32 value; /**< Stores the value of all fields */
	} dw2;

    /**
     * @union dw3
     * @brief This union is used to store various attributes of received packets.
     */
	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 src_function_id_l : 8; /**< Low 8 bits of source function ID */
		u32 flow_mark : 24;        /**< Flow mark */
#else
		u32 flow_mark : 24;         /**< Flow mark */
		u32 src_function_id_l : 8;  /**< Low 8 bits of source function ID */
#endif
	} bs;
	u32 value; /**< Stores the value of all fields */
	} dw3;
}  l2nic_rx_compact_cqe_s;

/**
 * @struct l2nic_rx_cqe_s.
 * @brief L2nic_rx_cqe_s data structure.
 * @details This struct is used to represent the completion status of received packets,
 *          it contains various flags and error information about the packets.
 */
typedef struct tag_l2nic_rx_cqe {
	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 rx_done : 1; /**< Indicates the packet has been fully received */
		u32 bp_en : 1;   /**< Indicates the buffer pool has been enabled */
		u32 decry_pkt : 1; /**< Indicates the packet needs to be decrypted */
		u32 flush : 1; /**< Indicates the packet needs to be flushed */
		u32 spec_flags : 3; /**< Special flags */
		u32 rsvd0 : 1; /**< Reserved field */
		u32 lro_num : 8; /**< Large receive offload count */
		u32 checksum_err : 16; /**< Checksum error info */
#else
		u32 checksum_err : 16; /**< Checksum error info */
		u32 lro_num : 8; /**< Large receive offload count */
		u32 rsvd0 : 1; /**< Reserved field */
		u32 spec_flags : 3; /**< Special flags */
		u32 flush : 1; /**< Indicates the packet needs to be flushed */
		u32 decry_pkt : 1; /**< Indicates the packet needs to be decrypted */
		u32 bp_en : 1; /**< Indicates the buffer pool has been enabled */
		u32 rx_done : 1; /**< Indicates the packet has been fully received */
#endif
	} bs;
	u32 value; /**< Value of the struct */
	} dw0;

	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 length : 16;    /**< Packet length */
		u32 vlan : 16;  /**< VLAN ID */
#else
		u32 vlan : 16;  /**< VLAN ID */
		u32 length : 16;    /**< Packet length */
#endif
	} bs;
	u32 value;  /**< Value of the struct */
	} dw1;

	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 rss_type : 8;   /**< RSS type */
		u32 rsvd0 : 2;  /**< Reserved field */
		u32 vlan_offload_en : 1;    /**< VLAN offload enable bit */
		u32 umbcast : 2;    /**< Unicast/multicast/broadcast */
		u32 rsvd1 : 7;  /**< Reserved field */
		u32 pkt_types : 12; /**< Packet type */
#else
		u32 pkt_types : 12; /**< Packet type */
		u32 rsvd1 : 7;  /**< Reserved field */
		u32 umbcast : 2;    /**< Unicast/multicast/broadcast */
		u32 vlan_offload_en : 1;    /**< VLAN offload enable bit */
		u32 rsvd0 : 2;  /**< Reserved field */
		u32 rss_type : 8;   /**< RSS type */
#endif
	} bs;
	u32 value;  /**< Value of the struct */
	} dw2;

	union {
	struct {
		u32 rss_hash_value; /**< RSS hash value */
	} bs;
	u32 value;  /**< Value of the struct */
	} dw3;

    /**< dw4~dw7 field for nic/ovs multipexing */
	union {
	struct { /**< for nic */
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 if_1588 : 1; /**< Defines a 32-bit unsigned integer used to indicate whether 1588 protocol is supported */
		u32 if_tx_ts : 1; /**< Defines a 32-bit unsigned integer used to indicate whether transmit timestamp is supported */
		u32 if_rx_ts : 1; /**< Defines a 32-bit unsigned integer used to indicate whether receive timestamp is supported */
		u32 rsvd : 1; /**< Defines a 32-bit unsigned integer used for reservation */
		u32 msg_1588_type : 4; /**< Defines a 32-bit unsigned integer used to indicate the type of 1588 protocol */
		u32 msg_1588_offset : 8; /**< Defines a 32-bit unsigned integer used to indicate the offset of 1588 protocol */
		u32 tx_ts_seq : 16; /**< Defines a 32-bit unsigned integer used to indicate the sequence number of transmit timestamp */
#else
		u32 tx_ts_seq : 16; /**< Defines a 32-bit unsigned integer used to indicate the sequence number of transmit timestamp */
		u32 msg_1588_offset : 8; /**< Defines a 32-bit unsigned integer used to indicate the offset of 1588 protocol */
		u32 msg_1588_type : 4; /**< Defines a 32-bit unsigned integer used to indicate the type of 1588 protocol */
		u32 rsvd : 1; /**< Defines a 32-bit unsigned integer used for reservation */
		u32 if_rx_ts : 1; /**< Defines a 32-bit unsigned integer used to indicate whether receive timestamp is supported */
		u32 if_tx_ts : 1; /**< Defines a 32-bit unsigned integer used to indicate whether transmit timestamp is supported */
		u32 if_1588 : 1; /**< Defines a 32-bit unsigned integer used to indicate whether 1588 protocol is supported */
#endif
	} bs;

	struct { /**< for ovs */
		u32 reserved;   /**< Reserved field */
	} ovs_bs;

	struct {
		u32 xid;    /**< x id for crypt*/
	} crypt_bs;

	u32 value;  /**< Value of the struct */
	} dw4;

	union {
	struct { /**< for nic */
		u32 msg_1588_ts;
	} bs;

	struct { /**< for ovs */
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 mac_type : 2; /**< for ovs. mac_type */
		u32 l3_type : 3;  /**< for ovs. l3_type */
		u32 l4_type : 3;  /**< for ovs. l4_type */
		u32 rsvd0 : 2;  /**< Reserved field */
		u32 traffic_type : 6;  /**< for ovs. traffic type: 0-default l2nic pkt, 1-fallback traffic, 2-miss upcall
					traffic, 2-command */
		u32 traffic_from : 16; /**< for ovs. traffic from: vf_id, only support traffic_type=0(default l2nic) or 2(miss
					upcall) */
#else
		u32 traffic_from : 16;  /**< for ovs. traffic from: vf_id, only support traffic_type=0(default l2nic) or 2(miss
					upcall) */
		u32 traffic_type : 6;   /**< for ovs. traffic type: 0-default l2nic pkt, 1-fallback traffic, 2-miss upcall
					traffic, 2-command */
		u32 rsvd0 : 2;  /**< Reserved field */
		u32 l4_type : 3;    /**< for ovs. l4_type */
		u32 l3_type : 3;    /**< for ovs. l3_type */
		u32 mac_type : 2;   /**< for ovs. mac_type */
#endif
	} ovs_bs;

	struct { /**< for crypt */
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd : 16;  /**< Reserved field */
		u32 decrypt_status : 8; /**< Decrypt status */
		u32 esp_next_head : 8;  /**< Next header */
#else
		u32 esp_next_head : 8;  /**< Next header */
		u32 decrypt_status : 8; /**< Decrypt status */
		u32 rsvd : 16;  /**< Reserved field */
#endif
	} crypt_bs; /**< Value of the struct */

	u32 value;
	} dw5;

	union {
	struct { /**< for nic */
		u32 lro_ts; /**< Unused */
	} bs;

	struct { /**< for ovs */
		u32 reserved;   /**< Reserved field */
	} ovs_bs;

	u32 value;  /**< Value of the struct */
	} dw6;

	union {
	struct { /**< for nic */
		u32 first_len : 13;   /**< Datalen of the first or middle pkt size. */
		u32 last_len : 13;    /**< Data len of the last pkt size. */
		u32 pkt_num : 5;      /**< the number of packet. */
		u32 super_cqe_en : 1; /**< only this bit = 1, other fileds in this DW is valid. */
	} bs;

	struct { /**< for ovs */
		u32 localtag;   /**< local tag */
	} ovs_bs;

	u32 value;  /**< Value of the struct */
	} dw7;
} l2nic_rx_cqe_s;


#endif
