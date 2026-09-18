/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_mpu_cmd_structs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : Mailbox command word structure definition file
 */

#ifndef HINIC5_NIC_CMD_STRUCTS_H
#define HINIC5_NIC_CMD_STRUCTS_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#endif

#include "mpu_cmd_base_defs.h"

/**
 * @brief Management message header struct
 * @details This struct is used to store management message header information, including status, version and reserved fields.
 */
struct hinic5_mgmt_msg_head {
	u8 status;     /**< Status field */
	u8 version;     /**< Version field */
	u8 rsvd0[6];     /**< Reserved field */
};

/**
 * @brief struct hinic5_cmd_register_vf
 * @details nic vf register
 */
struct hinic5_cmd_register_vf {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u8 op_register;     /**< 0 - unregister, 1 - register */
	u8 rsvd1[3];     /**< Reserved field */
	u32 support_extra_feature;     /**< support extra feature */
	u8 rsvd2[32];     /**< Reserved field */
};

/**
 * @brief Store function table configuration information
 * @details This struct contains the receive queue WQE buffer size, maximum transmission unit (MTU) and reserved fields.
 */
struct hinic5_func_tbl_cfg {
	u16 rx_wqe_buf_size;     /**< Receive queue WQE buffer size */
	u16 mtu;     /**< Maximum transmission unit (MTU) */
	u8 rx_compact_wqe_en;     /**< rx 8Byte wqe (combined cqe) enable */
	u8 rsvd0[3];     /**< Reserved field */
	u8 mac[6];
	u16 vlan_id;
	u32 rsvd1[6];     /**< Reserved field */
};

/**
 * @brief Struct used to set function table
 * @details This struct is used to set the function table, containing management message header, function ID, reserved fields, configuration bitmap and function table configuration.
 */
struct hinic5_cmd_set_func_tbl {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 rsvd;     /**< Reserved field */
	u32 cfg_bitmap;     /**< Set bitmap, defined by hinic5_func_tbl_cfg_bitmap */
	struct hinic5_func_tbl_cfg tbl_cfg;     /**< Configuration table */
};

/**
 * @brief Configurable func-level attributes
 * @details nic vport state info
 */
struct hinic5_vport_state {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 rsvd1;     /**< Reserved field */
	u8 state;     /**< 0--disable, 1--enable */
	u8 num_qps;     /**< queue pairs number */
	u8 rx_compact_wqe_en;
	u8 rsvd2;     /**< Reserved field */
};

/**
 * @brief Configurable func-level attributes
 * @details nic configure rx_mode command struct
 */
struct hinic5_rx_mode_config {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 rsvd1;     /**< Reserved field */
	u32 rx_mode;     /**< rx mode */
};

/**
 * @brief Configurable func-level attributes
 * @details nic set cons idx attr
 */
struct hinic5_cmd_cons_idx_attr {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_idx;     /**< Func ID */
	u8 dma_attr_off;     /**< dma attribute offset */
	u8 pending_limit;     /**< pending limit */
	u8 coalescing_time;     /**< coalescing time */
	u8 intr_en;     /**< interrupt enable */
	u16 intr_idx;     /**< interrupt index */
	u32 l2nic_sqn;     /**< l2nic sequence number */
	u32 rsvd1;     /**< Reserved field */
	u64 ci_addr;     /**< ci address */
};

/**
 * @brief Defines a struct for storing port statistics information
 * @details This struct contains management message header and two fields for storing port statistics information.
 */
struct hinic5_port_stats_info {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 rsvd1;     /**< Reserved field */
};

/**
 * @brief Defines a struct for storing vport statistics information
 * @details vport transmit and receive statistics information, including unicast, multicast, broadcast packet counts and byte counts, as well as transmit and receive discarded and error packet counts.
 */
struct hinic5_vport_stats {
	u64 tx_unicast_pkts_vport;     /**< Transmitted unicast packet count */
	u64 tx_unicast_bytes_vport;     /**< Transmitted unicast byte count */
	u64 tx_multicast_pkts_vport;     /**< Transmitted multicast packet count */
	u64 tx_multicast_bytes_vport;     /**< Transmitted multicast byte count */
	u64 tx_broadcast_pkts_vport;     /**< Transmitted broadcast packet count */
	u64 tx_broadcast_bytes_vport;     /**< Transmitted broadcast byte count */
	u64 rx_unicast_pkts_vport;     /**< Received unicast packet count */
	u64 rx_unicast_bytes_vport;     /**< Received unicast byte count */
	u64 rx_multicast_pkts_vport;     /**< Received multicast packet count */
	u64 rx_multicast_bytes_vport;     /**< Received multicast byte count */
	u64 rx_broadcast_pkts_vport;     /**< Received broadcast packet count */
	u64 rx_broadcast_bytes_vport;     /**< Received broadcast byte count */
	u64 tx_discard_vport;     /**< Transmitted discarded packet count */
	u64 rx_discard_vport;     /**< Received discarded packet count */
	u64 tx_err_vport;     /**< Transmitted error packet count */
	u64 rx_err_vport;     /**< Received error packet count */
};

/**
 * @brief Defines a struct for storing vport statistics information
 * @details This struct contains vport statistics related data, including management message header, statistics size, reserved fields, vport statistics and additional reserved fields.
 */
struct hinic5_cmd_vport_stats {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u32 stats_size;     /**< Statistics information size */
	u32 rsvd1;     /**< Reserved field */
	struct hinic5_vport_stats stats;     /**< vport statistics information */
	u64 rsvd2[6];     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_clear_qp_resource
 * @details nic clear qp resource command struct
 */
struct hinic5_cmd_clear_qp_resource {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 rsvd1;     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_lro_config
 * @details nic configure lro struct
 */
struct hinic5_cmd_lro_config {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 opcode;     /**< operation code */
	u8 rsvd1;     /**< Reserved field */
	u8 lro_ipv4_en;     /**< LRO for IPv4 */
	u8 lro_ipv6_en;     /**< LRO for IPv6 */
	u8 lro_max_pkt_len;     /**< unit is 1K */
	u8 resv2[13];     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_lro_timer
 * @details nic configure lro timer
 */
struct hinic5_cmd_lro_timer {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u8 opcode;     /**< 1: set timer value, 0: get timer value */
	u8 rsvd1;     /**< Reserved field */
	u16 rsvd2;     /**< Reserved field */
	u32 timer;     /**< timer value */
};

#define NIC_MAX_FEATURE_QWORD 4

/**
 * @brief hinic5_cmd_feature_nego
 * @details nic auto-negotiation feature command struct
 */
struct hinic5_cmd_feature_nego {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 opcode;     /**< opeartion code 1: set, 0: get */
	u8 rsvd;     /**< Reserved field */
	u64 s_feature[NIC_MAX_FEATURE_QWORD];     /**< feature */
};

/**
 * @brief hinic5_cmd_local_lro_state
 * @details nic set lro state
 */
struct hinic5_cmd_local_lro_state {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< 1: set timer value, 0: get timer value */
	u8 opcode;     /**< 0: get state, 1: set state */
	u8 state;     /**< 0: disable, 1: enable */
};

/**
 * @brief hinic5_cmd_cache_out_qp_resource
 * @details nic set cache_out_qp_resource
 */
struct hinic5_cmd_cache_out_qp_resource {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 rsvd1;     /**< Reserved field */
};

/**
 * @brief Defines a receive queue complete queue context struct
 * @details This struct is used to describe the context information of the receive queue complete queue
 */
struct hinic5_rq_cqe_ctx {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u8 cqe_type;     /**< completequeuetype */
	u8 rq_id;     /**< receivequeueID */
	u8 threshold_cqe_num;     /**< completequeuethreshold */
	u8 rsvd1;     /**< Reserved field */
	u16 msix_entry_idx;     /**< MSI-X entry index */
	u16 rsvd2;     /**< Reserved field */
	u32 ci_addr_hi;     /**< High bits of complete queue address */
	u32 ci_addr_lo;     /**< Low bits of complete queue address */
	u16 timer_loop;     /**< Timer loop count */
	u16 rsvd3;     /**< Reserved field */
};

struct hinic5_rq_enable {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u32 rq_id;
	u8 rq_enable;
	u8 rsvd1[3];     /**< Reserved field */
};

#define ETH_ALEN 6     /**< Ethernet address length */

/**
 * @brief hinic5_port_mac_set
 * @details nic port macsetcommandstruct
 */
struct hinic5_port_mac_set {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 vlan_id;     /**< vlan id */
	u8 vf_lag_en;     /**< vf_lag enable flag (used by compute, reserved) */
	u8 rsvd1;     /**< Reserved field */
	u8 mac[ETH_ALEN];     /**< mac address */
};

/**
 * @brief hinic5_port_mac_update
 * @details nic port mac modification command struct
 */
struct hinic5_port_mac_update {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u16 vlan_id;     /**< vlan id */
	u16 rsvd1;     /**< Reserved field */
	u8 old_mac[ETH_ALEN];     /**< mac address */
	u16 rsvd2;     /**< Reserved field */
	u8 new_mac[ETH_ALEN];     /**< mac address */
};

#define CHIP_ATTR_MAC_MAX_SIZE 192

/**
 * @brief nic_cmd_mac_info
 * @details MAC module interface
 */
struct nic_cmd_mac_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 valid_bitmap;     /**< valid bitmap, unused */
	u16 rsvd1;     /**< Reserved field */
	u8 host_id[32];     /**< host id, unused */
	u8 port_id[32];     /**< port id, unused */
	u8 mac_addr[CHIP_ATTR_MAC_MAX_SIZE];     /**< mac addr */
};

/**
 * @brief hinic5_cmd_vlan_config
 * @details nic configurevlaninformation
 */
struct hinic5_cmd_vlan_config {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 opcode;     /**< opration code */
	u8 rsvd1;     /**< Reserved field */
	u16 vlan_id;     /**< vlan id */
	u8 blacklist_flag;     /**< blacklist flag (used by compute, reserved) */
	u8 rsvd2;     /**< Reserved field */
};

struct hinic5_cmd_vxlan_port_info {
	struct hinic5_mgmt_msg_head msg_head;   /**< Command word message header */
	u16 func_id;  /**< Func ID */
	u8 opcode;  /**< opration code */
	u8 cfg_mode;  /**< priority flag */
	u16 vxlan_port;  /**< targetport */
	u8 pkt_fmt;  /**< 0：vxlanpacket  1：vxlan_gpepacket */
	u8 rsvd2;  /**< Reserved field */
};

/**
 * @brief hinic5_cmd_set_vlan_filter
 * @details nic set vlan filter
 */
struct hinic5_cmd_set_vlan_filter {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 rsvd1[2];     /**< Reserved field */
	u32 vlan_filter_ctrl;     /**< bit0:vlan filter en; bit1:broadcast_filter_en */
};

/**
 * @brief hinic5_cmd_vlan_offload
 * @details nic set vlan offload
 */
struct hinic5_cmd_vlan_offload {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 vlan_offload;     /**< vlan offload */
	u8 rsvd1[5];     /**< Reserved field */
};

struct hinic5_smac_check_state {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 smac_check_en;     /**< 1: enable 0: disable */
	u8 op_code;     /**< 1: set 0: get */
	u8 flash_en;     /**< flash enable flag */
	u8 rsvd;     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_vf_vlan_config
 * @details nic configure vf vlan information
 */
struct hinic5_cmd_vf_vlan_config {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 opcode;     /**< opration code */
	u8 rsvd1;     /**< Reserved field */
	u16 vlan_id;     /**< vlan id */
	u8 qos;     /**< qos */
	u8 rsvd2[5];     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_vf_trust_config
 * @details nic configure vf trust information
 */
struct hinic5_cmd_vf_trust_config {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;    /**< Func ID */
	u16 vlan_id;    /**< vlan id */
	u8 trust;   /* vf_trust: 0-disable; 1-enable */
	u8 rsvd2[67];    /**< Reserved field */
};

/**
 * @brief hinic5_cmd_spoofchk_set
 * @details nic configure spoofchk
 */
struct hinic5_cmd_spoofchk_set {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 state;     /**< state */
	u8 rsvd1;     /**< Reserved field */
};

#define NIC_RATE_DIRECT_RX_BW 0     /**< RX bandwidth rate limit */
#define NIC_RATE_DIRECT_TX_BW 1     /**< TX bandwidth rate limit */
#define NIC_RATE_DIRECT_RX_PERCENT 2     /**< RX percentage rate limit (set command 1872 implementation differs) other parts are exactly the same */
#define NIC_RATE_DIRECT_TX_PERCENT 3     /**< TX percentage rate limit */
#define NIC_RATE_OP_SET 0     /**< rate limitset */
#define NIC_RATE_OP_GET 1     /**< rate limitquery */
#define NIC_RATE_OP_FLASH 2     /**< FLASH persist */
#define NIC_RATE_OP_UNUSE 4     /**< used for compatibility adaptation, for 1823 (since it does not read this field, it actually does rate limit configure operation), 1872/1825 and later generations do not do any operation and return directly */

/**
 * @brief hinic5_cmd_rate_cfg
 * @details nic rate speed configure
 */
struct hinic5_cmd_rate_cfg {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 cfg_mode;     /**< BIT[0]: set and query, 0-set, 1-query; BIT[1]: whether to support persisting to Flash, currently only supports percentage rate limit persisting; BIT[2]: if 1, indicates do nothing and return directly */
	u8 direct;     /**< direction：  0-RX bandwidth rate limit 1-TX bandwidth rate limit 2-RX_RATEpercentage 3-TX_RATEpercentage */
	u32 cir;     /**< C bucket rate Mbps, old field name min_rate */
	u32 pir;     /**< P bucket rate Mbps, if bandwidth rate limit, represents C bucket rate (Mbps), if direct is percentage rate limit, represents percentage, old field name max_rate */
	u32 cbs;     /**< C bucket depth Mbit, 0 uses default bucket depth */
	u32 pbs;     /**< P bucket depth Mbit, 0 uses default bucket depth */
};

#define NIC_RATE_MODE_PERCENT 0     /**< Takes effect by percentage rate limit. */
#define NIC_RATE_MODE_BANDWIDTH 1     /**< Takes effect by bandwidth rate limit. */

#define ERR_RATE_BW_PARAM_OVERFLOW 254 /**< Bandwidth rate param overflow．*/
/**
 * @brief hinic5_cmd_rate_cfg_ret
 * @details nic rate speed configurequery
 */
struct hinic5_cmd_rate_cfg_ret {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 car_id;     /**< RX direction rate limit needs to return CAR_ID */
	u8 rate_mode;     /**< Current rate limit effective mode: 0-percentage rate limit 1-bandwidth rate limit */
	u8 rsvd;     /**< Reserved field */
	u32 cir;     /**< C bucket rate Mbps, old field name min_rate */
	u32 pir;     /**< P bucket rate Mbps, if bandwidth rate limit, represents C bucket rate (Mbps), if direct is percentage rate limit, represents percentage, old field name max_rate */
	u32 cbs;     /**< C bucket depth Mbit, 0 uses default bucket depth */
	u32 pbs;     /**< P bucket depth Mbit, 0 uses default bucket depth */
};

#define NIC_DCB_COS_MAX 0x8     /**< definition of network interface control packet (NIC DCB) max priority (COS) */

/**
 * @brief Defines a struct used for RSS configuration
 * @details This struct contains various parameters required for RSS configuration, such as Function ID, RSS enable flag, priority queue count, priority to traffic class mapping, queue pair count, etc.
 */
struct hinic5_cmd_rss_config {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Function ID, used to identify which function RSS is currently configured */
	u8 rss_en;     /**< RSS enable flag, if 1 indicates RSS function is enabled, 0 indicates disabled */
	u8 rq_priority_number;     /**< Priority queue count, determines the specific implementation of RSS */
	u8 prio_tc[NIC_DCB_COS_MAX];     /**< Priority to traffic class mapping, array length is NIC_DCB_COS_MAX */
	u16 num_qps;     /**< Queue pair count, determines the specific implementation of RSS */
	u16 rsvd1;     /**< Reserved field */
};

/**
 * @brief Defines a RSS (Receive Side Scaling) template management struct
 * @details This struct is used to manage RSS templates, contains management message header, Function ID, command, template ID and other information
 */
struct hinic5_rss_template_mgmt {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Function ID, used to identify the function module corresponding to the current message */
	u8 cmd;     /**< Command, used to identify the operation to be executed */
	u8 template_id;     /**< Template ID, used to identify the template corresponding to the current operation */
	u8 rsvd1[4];     /**< Reserved field */
};

/**
 * @brief Defines a RSS (Receive Side Scaling) context table struct
 * @details This struct contains related data in the rss context table, contains management message header, func id, context information and reserved fields.
 */
struct hinic5_rss_context_table {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Function ID, used to identify the function module corresponding to the current message */
	u16 rsvd1;     /**< Reserved field */
	u32 context;     /**< RSS context */
};

#define NIC_RSS_KEY_SIZE 40     /**< definition of RSS key size as 40 */

/**
 * @brief Defines a struct used for RSS hash key
 * @details This struct is used to store RSS hash key related information
 */
struct hinic5_cmd_rss_hash_key {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Function ID */
	u8 opcode;     /**< operation code */
	u8 rsvd1;     /**< Reserved field */
	u8 key[NIC_RSS_KEY_SIZE];     /**< RSS hash key */
};

/**
 * @brief Defines a struct used for RSS engine type
 * @details This struct is used to describe RSS engine type related information
 */
struct hinic5_cmd_rss_engine_type {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< Function ID */
	u8 opcode;     /**< operation code */
	u8 hash_engine;     /**< hash engine */
	u8 rsvd1[4];     /**< Reserved field */
};

/**
 * @brief hinic5_ipcs_err_rss_enable_operation_s
 * @details IP checksum error packets, enable rss quadruple hash
 */
struct hinic5_ipcs_err_rss_enable_operation_s {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 en_tag;
	u8 type;     /**< 1: set  0: get */
	u8 rsvd[2];     /**< Reserved field */
};

/**
 * @brief Struct used for network interface command filter delete rule
 * @details This struct is used to store network interface command filter delete rule related information.
 */
struct nic_cmd_fdir_del_rules {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< Function ID */
	u8 type;     /**< type */
	u8 rsvusrdata;     /**< user data */
	u32 index_start;     /**< index start position */
	u32 index_num;     /**< indexcount */
};

/**
 * @brief Defines a struct used for flushing TCAM rules
 * @details This struct contains the management message header and Function ID members, used for flushing TCAM rules.
 */
struct nic_cmd_flush_tcam_rules {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< Function ID */
	u16 rsvd;     /**< Reserved field */
};

/**
 * @brief Input struct for allocating TCAM block
 * @details This struct is used for input parameters of allocating TCAM block, contains header information, Function ID, allocation flag, TCAM type, TCAM block index and allocation block count etc. information.
 */
struct nic_cmd_ctrl_tcam_block_in {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< Function ID */
	u8 alloc_en;     /**< 0: free allocated tcam block, 1: request new tcam block */
	u8 tcam_type;     /**< 0: allocate 16 size tcam block, 1: allocate 0 size tcam block, others reserved */
	u16 tcam_block_index;     /**< index */
	u16 alloc_block_num;     /**< driver sends to uP indicates the block size driver wants to allocate. uP returns to driver the interface, indicates the allocated tcam block size supported by uP */
};

/**
 * @brief Output struct for allocating TCAM block
 * @details This struct is used to store output information of allocating TCAM block.
 */
struct nic_cmd_ctrl_tcam_block_out {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< Function ID */
	u8 alloc_en;     /**< 0: free allocated tcam block, 1: request new tcam block */
	u8 tcam_type;     /**< 0: allocate 16 size tcam block, 1: allocate 0 size tcam block, others reserved */
	u16 tcam_block_index;     /**< index */
	u16 mpu_alloc_block_size;     /**< driver sends to uP indicates the block size driver wants to allocate, uP returns to driver the interface, indicates the allocated tcam block size supported by uP */
};

/**
 * @brief nic_cmd_set_tcam_enable
 * @details enable tcam
 */
struct nic_cmd_set_tcam_enable {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< Function ID */
	u8 tcam_enable;     /**< tcam enable */
	u8 rsvd1;     /**< Reserved field */
	u32 rsvd2;     /**< Reserved field */
};

/**
 * @brief Input struct for allocating TCAM block
 * @details This struct is used for input parameters of allocating TCAM block, contains header information, Function ID, allocation flag, TCAM type, TCAM block index and allocation block count etc. information.
 */
struct nic_cmd_dfx_fdir_tcam_block_table {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 tcam_type;     /**< TCAM type */
	u8 valid;     /**< valid flag bit */
	u16 tcam_block_index;     /**< TCAM block index */
	u16 use_function_id;     /**< used Function ID */
	u16 rsvd;     /**< Reserved field */
};

struct hinic5_ppa_cfg_table_id_cmd {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 rsvd0;     /**< Reserved field */
	u16 cmd;     /**< command */
	u16 table_id;     /**< table id */
	u16 rsvd1;     /**< Reserved field */
};

struct hinic5_ppa_cfg_ppa_en_cmd {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< function id */
	u8 ppa_en;     /**< ppa enable */
	u8 rsvd;     /**< Reserved field */
};

struct hinic5_ppa_cfg_mode_cmd {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 rsvd0;     /**< function id */
	u8 ppa_mode;     /**< ppa mode */
	u8 qpc_func_nums;     /**< qpc function numbers */
	u16 base_qpc_func_id;     /**< base qpc function id */
	u16 rsvd1;     /**< Reserved field */
};

struct hinic5_ppa_flush_en_cmd {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 rsvd0;     /**< Reserved field */
	u8 flush_en;     /**< 0 flush done, 1 in flush operation */
	u8 rsvd1;     /**< Reserved field */
};

struct nic_cmd_set_fdir_status {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< function id */
	u16 index;     /**< index */
	u8 pkt_type_en;     /**< packet type enable */
	u8 pkt_type;     /**< packet type */
	u8 qid;     /**< queue id */
	u8 flag;     /**< packet drop flag */
};

struct hinic5_ppa_fdir_query_cmd {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u32 index;     /**< index */
	u32 rsvd;     /**< Reserved field */
	u64 pkt_nums;     /**< packet type */
	u64 pkt_bytes;     /**< packet bytes */
};

struct hinic5_port_state {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< function id */
	u16 rsvd1;     /**< Reserved field */
	u8 state;     /**< 0--disable, 1--enable */
	u8 rsvd2[3];     /**< Reserved field */
};

struct hinic5_cmd_pause_config {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u8 port_id;     /**< port id */
	u8 opcode;     /**< operation code */
	u16 rsvd1;     /**< Reserved field */
	u8 auto_neg;     /**< auto negotiation */
	u8 rx_pause;     /**< receive pause */
	u8 tx_pause;     /**< send pause */
	u8 rsvd2[5];     /**< Reserved field */
};

struct hinic5_port_car_info {
	u32 cir;     /**< unit: kbps, range:[1,400*1000*1000], i.e. 1Kbps~400Gbps(400M*kbps) */
	u32 xir;     /**< unit: kbps, range:[1,400*1000*1000], i.e. 1Kbps~400Gbps(400M*kbps) */
	u32 cbs;     /**< unit: Byte, range:[1,320*1000*1000], i.e. 1byte~2560Mbit */
	u32 xbs;     /**< unit: Byte, range:[1,320*1000*1000], i.e. 1byte~2560Mbit */
};

/**
 * @brief hinic5_cmd_set_port_car
 * @details nic setcarrate limitcommandstruct(1825)
 */
struct hinic5_cmd_set_port_car {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u8 port_id;     /**< port id */
	u8 opcode;     /**< 0--set car profile, 1--set car state, 2--get car profile */
	u8 state;     /**< 0--disable, 1--enable */
	u8 level;     /**< limit level */
	struct hinic5_port_car_info car;     /**< car info */
};

struct hinic5_cmd_set_car_option {
	u8 type;     /**< 0:port, 1:func, 2:vnic group*/
	u8 port_id;
	u16 func_id;
	u8 car_enable;
	u8 opcode;     /**< 0--set car profile, 1--get car profile */
	u8 pkt_type;
	u8 car_alg_type;
};

/**
 * @brief hinic5_cmd_set_car
 * @details nic setcarrate limitcommandstruct(1872)
 */
struct hinic5_cmd_set_car {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	struct hinic5_cmd_set_car_option option;
	struct hinic5_port_car_info car;     /**< car info */
};

/**
 * @brief hinic5_car_profile
 * @details nic setcarrate limitcommandstruct(1872)
 */
struct hinic5_car_profile {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 car_id;     /**< car id */
	u8 level;     /**< limit level */
	u8 rsvd;     /**< Reserved field */
	u32 profile[4];     /**< car profile */
};

#define NIC_DCB_TC_MAX 0x8     /**< definition of network interface control packet (NIC DCB) max traffic class (TC) */

/**
 * @brief hinic5_cmd_ets_cfg
 * @details nic configureetscommandstruct
 */
struct hinic5_cmd_ets_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 port_id;     /**< port id */
	u8 op_code;     /**< 1 - set, 0 - get */
	u8 cfg_bitmap;     /**< bit0 - cos_tc, bit1 - tc_bw, bit2 - cos_prio, bit3 - cos_bw, bit4 - tc_prio */
	u8 rsvd;     /**< Reserved field */
	u8 cos_tc[NIC_DCB_COS_MAX];
	u8 tc_bw[NIC_DCB_TC_MAX];
	u8 cos_prio[NIC_DCB_COS_MAX];     /**< 0 - DWRR, 1 - STRICT */
	u8 cos_bw[NIC_DCB_COS_MAX];
	u8 tc_prio[NIC_DCB_TC_MAX];     /**< 0 - DWRR, 1 - STRICT */
};

struct hinic5_cmd_set_pfc {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 port_id;     /**< port id */
	u8 op_code;     /**< 0：get 1: set pfc_en  2: set pfc_bitmap 3: set all */
	u8 pfc_en;     /**< pfc_en and pfc_bitmap must simultaneously set */
	u8 pfc_bitmap;     /**< pfc bitmap */
	u8 rsvd[4];     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_set_dcb_state
 * @details nic setdcb statecommandstruct
 */
struct hinic5_cmd_set_dcb_state {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< port id */
	u8 op_code;     /**< 0 - get dcb state, 1 - set dcb state */
	u8 state;     /**< 0 - disable, 1 - enable dcb */
	u8 port_state;     /**< 0 - disable, 1 - enable dcb */
	u8 rsvd[7];     /**< Reserved field */
};

struct hinic5_cmd_qos_port_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 port_id;     /**< port id */
	u8 op_code;     /**< 0 - get, 1 - set */
	u8 cfg_bitmap;     /**< bit0 - trust, bit1 - dft_cos */
	u8 rsvd0;     /**< Reserved field */
	u8 trust;     /**< trust state */
	u8 dft_cos;     /**< dft cos */
	u8 rsvd1[18];     /**< Reserved field */
};

struct hinic5_cmd_qos_map_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 op_code;     /**< operation code */
	u8 cfg_bitmap;     /**< bit0 - pcp2cos, bit1 - dscp2cos */
	u16 rsvd0;     /**< Reserved field */
	u8 pcp2cos[8];     /**< must configure 8 entries together */
	u8 dscp2cos[64];     /**< when configuring dscp2cos, if cos value is set to 0xFF, MPU ignores configuration of this dscp priority, allows configuring mapping of multiple dscp to cos at once */
	u32 rsvd1[4];     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_qos_extend_cfg
 * @details nic configure qos command extension struct
 */
struct hinic5_cmd_qos_extend_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 port_id;     /**< port id */
	u8 op_code;     /**< bit0: 1-set tc rate limit, 0-get tc rate limit */
	u16 rsvd0;     /**< Reserved field */
	u16 port_speed;     /**< port speed, unit Gbps */
	u16 rsvd1;     /**< Reserved field */
	u32 rate_limit[NIC_DCB_COS_MAX];     /**< tc rate limit speed value, unit Mbps */
	u32 port_cir; /**< port cir value, unit Mbps  */
	u32 rsvd2[115];     /**< Reserved field */
};

/**
 * @brief hinic5_force_pkt_drop
 * @details nic force pkt dropcommandstruct
 */
struct hinic5_force_pkt_drop {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u8 port;     /**< port id */
	u8 rsvd1[3];     /**< Reserved field */
};

/**
 * @brief nic_cmd_pause_inquiry_cfg
 * @details pfc storm detect configuration
 */
struct nic_cmd_pause_inquiry_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 valid;     /**< valid */
	u32 type;     /**< 1: set, 2: get */
	u32 rx_inquiry_pause_drop_pkts_en;     /**< rx drop packet enable */
	u32 rx_inquiry_pause_period_ms;     /**< rx pause detect period default 200ms */
	u32 rx_inquiry_pause_times;     /**< rx pause detect times default 1 time */
	u32 rx_inquiry_pause_frame_thd;     /**< rx pause detect threshold default PAUSE_FRAME_THD_10G/25G/40G/100 */
	u32 rx_inquiry_tx_total_pkts;     /**< rx pause detect tx received packet total count */
	u32 tx_inquiry_pause_en;     /**< tx pause detect enable */
	u32 tx_inquiry_pause_period_ms;     /**< tx pause detect period default 200ms */
	u32 tx_inquiry_pause_times;     /**< tx pause detect times default 5 times */
	u32 tx_inquiry_pause_frame_thd;     /**< tx pause detect threshold */
	u32 tx_inquiry_rx_total_pkts;     /**< tx pause detect rx received packet total count */
	u32 rsvd[4];     /**< Reserved field */
};

struct nic_bios_cfg {
	u32 signature;     /**< signature, used for verifying the legitimacy of FLASH content */
	u8 pxe_en;     /**< PXE enable: 0 - disable 1 - enable */
	u8 extend_mode;
	u8 rsvd0[2];     /**< Reserved field */
	u8 pxe_vlan_en;     /**< PXE VLAN enable: 0 - disable 1 - enable */
	u8 pxe_vlan_pri;     /**< PXE VLAN priority: 0-7 */
	u16 pxe_vlan_id;     /**< PXE VLAN ID 1-4094 */
	u32 service_mode;     /**< reference CHIPIF_SERVICE_MODE_x macro */
	u32 pf_bw;     /**< PF speed, percentage 0-100 */
	u8 speed;     /**< enum of port speed */
	u8 auto_neg;     /**< auto-negotiation switch 0 - field invalid 1 - on 2 - off */
	u8 lanes;     /**< lane num */
	u8 fec;     /**< FEC mode, reference enum mag_cmd_port_fec */
	u8 auto_adapt;     /**< auto-adapt mode configure 0 - invalid configure 1 - enabled 2 - disabled */
	u8 func_valid;     /**< indicates whether func_id is valid; 0 - invalid, other - valid */
	u8 func_id;     /**< only meaningful when func_valid is not 0 */
	u8 sriov_en;     /**< SRIOV-EN: 0 - invalid configure, 1 - enabled, 2 - disabled */
};

struct nic_cmd_bios_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 op_code;     /**< Operation Code: Bit0[0: read 1:write, BIT1-6: cfg_mask */
	struct nic_bios_cfg bios_cfg;     /**< BIOS configuration */
};

/**
 * @brief Defines a struct used for storing semi-offload bond func link status information
 * @details Semi-offload bond create/update/delete will transmit link message to non-slave func
 */
struct hinic5_bond_link_info {
	struct hinic5_mgmt_msg_head head;     /**< management message header information */
	u8 bond_en;     /**< bond whether enabled 0:disabled 1:enabled */
	u8 port_id;     /**< port id */
	u8 link_status;     /**< link status of bond non-slave device 0:down 1:up */
	u8 rsvd[13];     /**< Reserved field */
};

/**
 * @brief Internal parsing information struct when PN exceeds threshold interrupt occurs
 * @details contains threshold, SC index, AN etc. information
 */
struct macsec_pn_expired_report_info {
	u64 sci[32];     /**< SCI of corresponding SC when threshold-exceeded event occurs */
	u8 an[32];     /**< AN number of corresponding SA when threshold-exceeded event occurs */
	u8 pn_expired_size;     /**< SA threshold */
	u8 reserved[7];     /**< Reserved field */
};

/**
 * @brief macsec pn threshold report message struct
 * @details Message struct definition reported to driver when PN exceeds threshold interrupt occurs
 */
struct macsec_pn_expired_report_cmd {
	struct hinic5_mgmt_msg_head head;     /**< management message header information */
	struct macsec_pn_expired_report_info info;     /**< threshold-exceeded related struct information */
	u64 reserved;     /**< Reserved field */
};

/**
 * @brief Defines a struct used for deleting bond
 * @details This struct contains all information required for deleting bond
 */
struct hinic5_cmd_delete_bond {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 bond_id;     /**< bond ID */
	u32 rsvd[2];     /**< Reserved field */
};

/**
 * @brief definition of a struct used for storing bond device enabled/disabled information
 * @details This struct contains bond device enabled/disabled information, including bond device number, enabled/disabled identify and Reserved field.
 */
struct hinic5_open_close_bond_info {
	u32 bond_id;     /**< bond device number */
	u32 open_close_flag;     /**< enabled/disabled bond identify: 1 for open, 0 for close */
	u32 rsvd[2];     /**< Reserved field */
};

/**
 * @brief Defines a struct used to store MPU bond message interface related information
 * @details This struct contains management message header information and MPU bond enabled or disabled related information
 */
struct hinic5_cmd_open_close_bond {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	struct hinic5_open_close_bond_info open_close_bond_info;     /**< stores MPU bond enabled or disabled related information */
};

/**
 * @brief LACPDU port related fields
 * @details This struct is used to describe port related parameters in LACPDU (Link Aggregation Control Protocol Data Unit).
 */
struct lacp_port_params {
	u16 port_number;     /**< port number */
	u16 port_priority;     /**< portpriority */
	u16 key;     /**< key */
	u16 system_priority;     /**< system priority */
	u8 system[ETH_ALEN];     /**< system MAC address */
	u8 port_state;     /**< portstatus */
	u8 rsvd;     /**< Reserved field */
};

/**
 * @brief Defines a struct used to store LACP (Link Aggregation Control Protocol) port information
 * @details This struct contains multiple members, each with its specific meaning and purpose.
 */
struct lacp_port_info {
	u32 selected;     /**< indicates whether this port is selected */
	u32 aggregator_port_id;     /**< used aggregator port ID */
	struct lacp_port_params actor;     /**< actor port parameters */
	struct lacp_port_params partner;     /**< partner port parameters */
	u64 tx_lacp_pkts;     /**< count of LACP packets transmitted */
	u64 rx_lacp_pkts;     /**< count of LACP packets received */
	u64 rx_8023ad_drop;     /**< count of discarded 802.3ad packets */
	u64 tx_8023ad_drop;     /**< count of 802.3ad packets transmitted */
	u64 unknown_pkt_drop;     /**< count of discarded unknown packets */
	u64 rx_marker_pkts;     /**< count of marker packets received */
	u64 tx_marker_pkts;     /**< count of marker packets transmitted */
};

#define BOND_MAX_PORT_NUM 4     /**< bond supportmaxportcount */
#define BOND_MAX_HOST_NUM 4     /**< bond supportmaxhostcount */

/**
 * @brief Defines a struct used to store bond status information
 * @details This struct contains various bond status information, such as bond_id, link status, slave port status, port count, etc., and also contains LACP information of each port, as well as the number of successful and failed LACP negotiation result reports per host, etc.
 */
struct hinic5_bond_status_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 bond_id;     /**< bond id */
	u32 bon_mmi_status;     /**< link status of this bond sub-device */
	u32 active_bitmap;     /**< slave port status of this bond sub-device */
	u32 port_count;     /**< number of this bond sub-devices */
	struct lacp_port_info port_info[BOND_MAX_PORT_NUM];     /**< LACP information of each port */
	u64 success_report_cnt[BOND_MAX_HOST_NUM];     /**< number of successful LACP negotiation result reports per host */
	u64 fail_report_cnt[BOND_MAX_HOST_NUM];     /**< number of failed LACP negotiation result reports per host */
	u64 poll_timeout;     /**< polling timeout */
	u64 fast_periodic_timeout;     /**< fast periodic timeout */
	u64 slow_periodic_timeout;     /**< slow periodic timeout */
	u64 short_timeout;     /**< short timeout */
	u64 long_timeout;     /**< long timeout */
	u64 aggregate_wait_timeout;     /**< aggregation wait timeout */
	u64 tx_period_timeout;     /**< transmit period timeout */
	u64 rx_marker_timer;     /**< RXflagtimer */
	u8 bond_mode;     /**< bondmode */
	u8 arp_dual_en;     /**< ARP dual-transmit enable flag */
	u8 rsvd[6];     /**< Reserved field */
};

/**
 * @brief Defines a struct used to store bond activity report information
 * @details This struct contains bond activity report related information, such as management message header information, bond device ID, bond sub-device link status, bond sub-device slave port status, etc.
 */
struct hinic5_bond_active_report_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 bond_id;     /**< bond ID */
	u32 bon_mmi_status;     /**< link status of bond sub-device */
	u32 active_bitmap;     /**< slave port status of bond sub-device */
	u8 rsvd[16];     /**< Reserved field */
};

#define DFX_SM_TBL_BUF_MAX 768     /**< defines that the SM table allocated by DFX is at most 768B */
#define MAC_TBL_RD_TYPE_MAC_INFO 0     /**< identifies the data type as MAC table content */
#define MAC_TBL_RD_TYPE_MAC_RES_STAT 1     /**< identifies the data type as MAC resource statistics */

/**
 * @brief MAC table parameters
 * @details This struct is used to store MAC table parameters, including tbl_index, cnt and total_cnt.
 */
struct mac_table_arg {
	u32 tbl_index;     /**< MAC table index */
	u32 cnt;     /**< count */
	u32 total_cnt;     /**< total count */
	u8 mac_tbl_rd_type;     /**< 0: read MAC content, 1: read MAC table resource statistics */
	u8 rsvd[3];     /**< Reserved field */
};

/**
 * @brief VLAN circuit table parameters
 * @details This struct is used to store VLAN circuit table parameters, including er_id and vlan_id.
 */
struct vlan_elb_table_arg {
	u32 er_id;     /**< er ID */
	u32 vlan_id;     /**< VLAN ID */
};

/**
 * @brief VLAN filter parameters (VLAN Filter1 Table)
 * @details This struct is used to store VLAN filter parameters, including tbl_index and func_id.
 */
struct vlan_filter_arg {
	u32 tbl_index;     /**< VLAN Filter1 table index */
	u32 func_id;     /**< function ID */
};

/**
 * @brief VLAN filter parameters (VLAN Filter2 Table)
 * @details This struct is used to store VLAN filter parameters, including vlan_id.
 */
struct vlan_filter2_arg {
	u32 vlan_id;     /**< VLAN ID */
};

/**
 * @brief multicast circuit table parameters
 * @details This struct is used to store multicast circuit table parameters, including mc_id.
 */
struct mc_elb_arg {
	u32 mc_id;     /**< multicast ID */
};

/**
 * @brief function table parameters
 * @details This struct is used to store function table parameters, including func_id.
 */
struct func_tbl_arg {
	u32 func_id;     /**< function ID */
};

/**
 * @brief port table parameters
 * @details This struct is used to store port table parameters, including port_id.
 */
struct port_tbl_arg {
	u32 port_id;     /**< portID */
};

/**
 * @brief This struct is used to store FDIR IO table parameters, including tbl_index, cnt and total_cnt.
 * @details This struct is used to store port table parameters, including port_id.
 */
struct fdir_io_table_arg {
	u32 tbl_index;     /**< FDIR IO table index */
	u32 cnt;     /**< count */
	u32 total_cnt;     /**< total count */
};

/**
 * @brief FlexQ table parameters
 * @details This struct is used to store FlexQ table parameters, including tbl_index, cnt, total_cnt, left_cnt_die0 and left_cnt_die1.
 */
struct flexq_table_arg {
	u32 tbl_index;     /**< FlexQ table index */
	u32 cnt;     /**< count */
	u32 total_cnt;     /**< total count */
	u16 left_cnt_die0;     /**< remaining count DIE0 */
	u16 left_cnt_die1;     /**< remaining count DIE1 */
};

/**
 * @brief Defines a union used to store various types of parameters
 * @details This union contains multiple structs, each struct represents a different parameter type. These parameter types include MAC table parameters, VLAN circuit table parameters, VLAN filter parameters, multicast circuit table parameters, function table parameters, port table parameters, FDIR IO table parameters and FlexQ table parameters. Each parameter type has its specific member variables, such as tbl_index, cnt, total_cnt, etc.
 */
typedef union {
	struct mac_table_arg mac_table_arg;
	struct vlan_elb_table_arg vlan_elb_table_arg;
	struct vlan_filter_arg vlan_filter_arg;
	struct vlan_filter2_arg vlan_filter2_arg;
	struct mc_elb_arg mc_elb_arg;
	struct func_tbl_arg func_tbl_arg;
	struct port_tbl_arg port_tbl_arg;
	struct fdir_io_table_arg fdir_io_table_arg;
	struct flexq_table_arg flexq_table_arg;
	u32 args[4];     /**< parameter array */
} sm_tbl_args;

/**
 * @brief Defines a network interface controller command data analysis table struct
 * @details This struct is used to store network interface controller command data analysis table related information
 */
struct nic_cmd_dfx_sm_table {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u32 tbl_type;     /**< table type, used to identify the table purpose */
	sm_tbl_args args;     /**< table parameters, used to pass table-related parameters */
	u8 tbl_buf[DFX_SM_TBL_BUF_MAX];     /**< table buffer, used to store table data */
};

#define MAC_TBL_UC_CNT_FUNC_RD_NUM 256     /**< read up to 256 Functions' unicast statistics per command */

/**
 * @brief Defines a struct for MAC entry shared data resources (used to convert tbl_buf data of nic_cmd_dfx_sm_table struct)
 * @details This struct is used to store usage of unicast, multicast, shared resources, and unicast exclusive resources
 */
typedef struct nic_cmd_dfx_mac_res_stats_info {
	u16 uc_mac_cnt;                                     /**< unicast table resource usage statistics */
	u16 mc_mac_cnt;                                     /**< multicast table resource usage statistics */
	u16 share_mac_res_cur_cnt;                          /**< current shared resource pool usage statistics */
	u16 share_mac_res_total;                            /**< total size of shared resource pool */
	u16 func_uc_mac_cnt[MAC_TBL_UC_CNT_FUNC_RD_NUM];    /**< Func-granularity unicast table resource usage statistics */
	u8 rsvd[248];                                       /**< Reserved field */
} nic_cmd_dfx_mac_res_stats_info_s;

/**
 * @brief mpu_lt_info
 * @details nic liner tabel info
 */
struct mpu_lt_info {
	u8 node;     /**< node id */
	u8 inst;     /**< instance id */
	u8 entry_size;     /**< entry size */
	u8 sml_table_id;     /**< sml table id */
	u32 lt_index;     /**< liner tabel index */
	u32 offset;     /**< offset */
	u32 len;     /**< length */
};

struct nic_mpu_lt_opera {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	struct mpu_lt_info net_lt_cmd;
	u8 data[100];     /**< data */
};

struct hinic5_veb_set {
	struct hinic5_mgmt_msg_head msg_head;   /**< Command word message header */

	u16 opcode;      /**< operationtype: 0=query, 1=configure */
	u16 set_status;  /**< configuration request value: 0=off, 1=on */
	u16 cur_status;  /**< currentstatus: 0=off, 1=on, 2=error */
	u16 rsvd0;       /**< Reserved field */
	u32 rsvd[30];    /**< Reserved field */
};

/**
 * @brief nic_cmd_capture_info
 * @details ucode capture cfg info
 */
struct nic_cmd_capture_info {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u32 op_type;     /**< operation type */
	u32 func_port;     /**< function port */
	u32 is_en_trx;     /**< also used as tx_rx */
	u32 offset_cos;     /**< also used as cos */
	u32 data_vlan;     /**< also used as vlan */
};

struct nic_cmd_vhd_config {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< function id */
	u8 vhd_type;     /**< vhd type */
	u8 virtio_small_enable;     /**< 0: mergeable mode, 1: small mode */
};

#define TC_ACL_KEY_BYTE 44     /**< 320 bits + 2 byte pad align to 4 byte */

/**
 * @brief struct hinic5_tc_action_info
 * @details info about tc action
 */
struct hinic5_tc_action_info {
	u16 action_flag;     /**< action flag */
	u16 output;     /**< output */
	u8 flow_queue;     /**< flow queue */
	u8 vxlan_tbl_index;     /**< vxlan table index */
	u16 vlan_tag;     /**< vlan tag */
	u32 flow_mark;     /**< flow mark */
	u16 vlan_sel;     /**< type of vlan frame */
	u16 count_id;     /**< count id */
};

/**
 * @brief struct hinic5_tc_cfg_info
 * @details info about add/del tc flower rule
 */
struct hinic5_tc_cfg_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 key_tcam_mem[TC_ACL_KEY_BYTE];     /**< tcam key mem */
	u8 mask_tcam_mem[TC_ACL_KEY_BYTE];     /**< tcam mask mem */
	struct hinic5_tc_action_info action;     /**< action info */
	u16 opcode;     /**< 0:del, 1:add */
	u16 index;     /**< index id */
	u8 group_vld;     /**< tcam group vld */
	u8 group_id;     /**< tcam group id */
	u16 rsvd;     /**< Reserved field */
};

#define ACL_LCAM_BITMAP_LEN 32     /**< 320 bits + 2 byte pad align to 4 byte */

/**
 * @brief struct hinic5_tc_flush_info
 * @details info about add/del tc flower rule
 */
struct hinic5_tc_flush_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u64 active_bitmap[ACL_LCAM_BITMAP_LEN];     /**< active bitmap */
};

/**
 * @brief struct hinic5_tc_vxlan_hdr_info
 * @details info about tc vxlan header
 */
struct hinic5_tc_vxlan_hdr_info {
	u8 dmac[6];     /**< destination mac */
	u8 smac[6];     /**< source mac */
	u16 vlan;     /**< vlan tag */
	u8 tos;     /**< type of service */
	u8 rsvd0;     /**< Reserved field */
	u8 sip[4];     /**< source ip */
	u8 dip[4];     /**< destination ip */
	u16 sport;     /**< source port */
	u16 rsvd1;     /**< Reserved field */
	u32 vni;     /**< bit[0:23]: vni, bit[24:31]: rsvd */
};

/**
 * @brief struct hinic5_tc_vxlan_tbl_cfg_info
 * @details info about add/get/del tunnel encap vxlan table entry
 */
struct hinic5_tc_vxlan_tbl_cfg_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	struct hinic5_tc_vxlan_hdr_info vxlan_hdr;     /**< vxlan header */
	u16 index;     /**< index id */
	u16 opcode;     /**< 0:del, 1:add, 2:get */
	u32 rsvd;     /**< Reserved field */
};

/**
 * @brief struct hinic5_tc_move_info
 * @details pfe tcam rule deletecommandstruct
 */
struct hinic5_tc_move_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 old_index;     /**< old index */
	u32 new_index;     /**< new index */
	u32 len;     /**< length */
};

/**
 * @brief struct hinic5_tc_pfe_cfg_profile_info
 * @details pfe profile config from register
 */
struct hinic5_tc_pfe_cfg_profile_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 reg_value;     /**< register value */
	u32 opcode;     /**< 0: select profile 1: 3-2 shift 2: 3-1-2 shift */
	u32 rsvd;     /**< Reserved field */
};

#define PFE_ACL_AGING_BLOCK_NUM 128

/**
 * @brief struct hinic5_tc_aging_info
 * @details info about pfe tc aging table
 */
struct hinic5_tc_aging_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 addr;     /**< address */
	u16 opcode;     /**< 0:get, 1:set, 2:status */
	u32 entry_h[PFE_ACL_AGING_BLOCK_NUM];     /**< high 32 entry */
	u32 entry_l[PFE_ACL_AGING_BLOCK_NUM];     /**< lower 32 entry */
	u16 status;     /**< pfe aging table enable status, 0:disable; 1:enable */
	u16 rsvd;     /**< Reserved field */
};

#define HTN_CNT_SIZE 8

/**
 * @brief struct hinic5_tc_pfe_cnt_info
 * @details pfe count info
 */
struct hinic5_tc_pfe_cnt_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 htn_cnt[HTN_CNT_SIZE];     /**< HTN count */
	u16 mode;     /**< 0:tx, 1:rx */
	u16 opcode;     /**< 0:get, 1:reset */
	u32 count_id;     /**< count id */
};

/* Available vport count resources for VF */
#define MAX_NIC_COUNT_ID 24

/**
 * @brief struct hinic5_nic_vport_cnt_info
 * @details nic vport count info
 */
struct hinic5_nic_vport_cnt_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	struct hinic5_vport_stats stats;     /**< vportstatistics */
	u32 cnt_res[MAX_NIC_COUNT_ID];     /**< func id for allocating vport count resources */
	u32 cur_cnt;     /**< currently occupied resource count */
	u32 func_id;     /**< func id to configure or query */
	u32 index;     /**< chip index corresponding to the func id to configure or query */
	u32 opcode;     /**< refer to nic_vport_cnt_op_e */
	u32 rsv1;     /**< Reserved field */
	u64 rsv2[192];     /**< Reserved field */
};

/**
 * @brief struct hinic5_tc_pfe_cfg_reg_info
 * @details pfe config from register
 */
struct hinic5_tc_pfe_cfg_reg_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 reg_value;     /**< register value */
	u32 reg_value2;     /**< register value */
	u32 rsvd;     /**< Reserved field */
};

#define TC_XY_KEY_SIZE 11

/**
 * @brief struct hinic5_tc_tcam_info
 * @details info about tcam info
 */
struct hinic5_tc_tcam_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 key_x[TC_XY_KEY_SIZE];     /**< tcam key_x info */
	u32 key_y[TC_XY_KEY_SIZE];     /**< tcam key_y info */
	struct hinic5_tc_action_info action;     /**< action info */
	u16 opcode;     /**< 0:del, 1:add, 2:group, 3:get */
	u16 index;     /**< index id */
	u8 group_cnt;     /**< group cnt */
	u8 rsvd[3];     /**< Reserved field */
};

#define PFE_VTEP_TBL_IP_SIZE 4
#define PFE_VTEP_TBL_IP_NUM 8

struct pfe_vtep_ip {
	u32 is_ipv6;     /**< 0: ipv4, 1: ipv6 */
	u32 ip_addr[PFE_VTEP_TBL_IP_SIZE];     /**< ip_addr[0]: IPv6 DIP[127:96] or IPv4 DIP[31:0]
											ip_addr[1]: IPv6 DIP[95:64] or IPv4 need set to 0
											ip_addr[2]: IPv6 DIP[63:32] or IPv4 need set to 0
											ip_addr[3]: IPv6 DIP[31:0] or IPv4 need set to 0 */
};

/**
 * @brief struct hinic5_tc_pfe_vtep_ip_cmd
 * @details pfe vtep table configuration
 */
struct hinic5_tc_pfe_vtep_ip_cmd {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	struct pfe_vtep_ip dip[PFE_VTEP_TBL_IP_NUM];     /**< destination ip */
	u16 num;     /**< num of ip in dip table */
	u16 opcode;     /**< 0: del, 1: add, 2: query */
	u32 rsvd;     /**< Reserved field */
};

#define DEFAULT_ACTION_REG_NUM 9     /**< number of registers involved in default ACTION (TX 2, RX 1, each ACTION 3 registers) */

/**
 * @brief struct hinic5_tc_default_action_info
 * @details info about pfe default action
 */
struct hinic5_tc_default_action_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 opcode;     /**< action type: 0:drop; 1:upcall; 2:show; 3:output to port */
	u8 addr;     /**< default action reg addr: 0:tx default action1; 1:tx default action2; 2:rx default action */
	u16 index;     /**< func index */
	u32 action[DEFAULT_ACTION_REG_NUM];     /**< default action info */
};

/**
 * @brief struct hinic5_tc_pfe_tcam_freq_info
 * @details pfe tcam_freq info
 */
struct hinic5_tc_pfe_tcam_freq_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 tcam_sel;     /**< TCAM_CLK_SEL */
	u8 mode;     /**< 1:500MHz, 2:250MHz, 3:125MHz */
	u8 opcode;     /**< 0:get, 1:set */
	u16 rsvd;     /**< Reserved field */
};

/**
 * @brief struct hinic5_tc_tcam_clock_gating_cfg_info
 * @details info about tcam clock gating
 */
struct hinic5_tc_tcam_clock_gating_cfg_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 opcode;     /**< 0: get, 1: set */
	u8 status;     /**< 0: clock off, 1: clock on */
	u16 rsvd;     /**< Reserved field */
};

#define MAX_CEQ_PER_FUNC 0x20

/**
 * @brief Defines a struct for setting NIC interrupt control
 * @details This struct contains various information required for setting NIC interrupt control
 */
struct mig_nic_set_ceq_ctrl {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 ceq_num;     /**< interrupt control count */
	u8 rsvd;     /**< Reserved field */
	u32 ceq_ctrl0[MAX_CEQ_PER_FUNC];     /**< interrupt controller 0 array, each element corresponds to one interrupt controller */
	u32 ceq_ctrl1[MAX_CEQ_PER_FUNC];     /**< interrupt controller 1 array, each element corresponds to one interrupt controller */
};

#define MAX_INTR_NUM 0x80     /**< maxinterruptcount128 */

/**
 * @brief Defines a struct for migrating NIC interrupt information
 * @details This struct contains management message header, Function ID, interrupt number, MSI-X control register operation, and values of MSI-X control register 0 and 4.
 */
struct mig_nic_msix_info_rw {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 intr_num;     /**< interrupt number */
	u8 msi_ctl_csr_op;     /**< MSI-X control register operation, used to identify the operation type on MSI-X control register */
	u32 msix_ctrl0[MAX_INTR_NUM];     /**< value of MSI-X control register 0, each interrupt corresponds to one value */
	u32 msix_ctrl4[MAX_INTR_NUM];     /**< value of MSI-X control register 1, each interrupt corresponds to one value */
};

#define MIG_FUNC_TBL_SIZE 0x50     /**< TBL size = (64 + 16(rsvd)) */
#define MIG_VAT_TBL_SIZE 0x10     /**< vat size: 0x10 */

/**
 * @brief Defines a struct used to store network interface card function and virtual address table information
 * @details This struct contains network interface card management message header, function ID, operation code, function used flag, function table and virtual address table etc. information.
 */
struct mig_nic_func_vat_tbl {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 opcode;     /**< operation code */
	u8 func_used;     /**< functionusedflag */
	u8 func_tbl[MIG_FUNC_TBL_SIZE];     /**< func table */
	u8 vat_tbl[MIG_VAT_TBL_SIZE];     /**< virtual address table */
	u8 rsvd[4];     /**< Reserved field */
};

#define MIG_FAST_MSG_VF_PAGE_NUM 4

/**
 * @brief Defines a struct used to store virtual function information of network interface
 * @details The struct contains virtual function information of network interface, such as transmit queue count, receive queue count, command queue count, etc.
 */
struct mig_nic_vf_info {
	u8 sq_num;     /**< transmitqueuecount */
	u8 rq_num;     /**< receivequeuecount */
	u8 cmdq_num;     /**< commandqueuecount */
	u8 cmdq_depth;     /**< command queue depth */
	u32 rq_depth;     /**< receive queue depth */
	u32 sq_depth;     /**< transmit queue depth */
	u32 sq_ci_base_addr_h;     /**< high bits of transmit queue complete pointer base address */
	u32 sq_ci_base_addr_l;     /**< low bits of transmit queue complete pointer base address */
	u16 bat_size;     /**< batch process size */
	u8 valid;     /**< validflag */
	u8 fast_msg_en;
	u8 fast_msg_page_num;
	u8 rsvd[3];
	u64 fast_msg_page_addr[MIG_FAST_MSG_VF_PAGE_NUM];
};

/**
 * @brief Defines a struct used to store NIC function configuration information
 * @details This struct contains NIC management message header information, function ID, Reserved field and virtual function information.
 */
struct mig_nic_func_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u16 rsvd;     /**< Reserved field */
	struct mig_nic_vf_info vf_info;     /**< VFinformation */
};

/**
 * @brief This struct is used to check whether the mailbox is empty
 * @details This struct is mainly used to check whether the network interface card mailbox is empty, in order to perform subsequent operations.
 */
struct mig_nic_chk_mbx_empty {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 bme;     /**< flag indicating whether the mailbox is empty */
	u8 is_func_used;     /**< flag indicating whether the func is used */
	u8 cmdq_num;     /**< get cmdq num for stop cmdq */
	u8 rsvd[3];     /**< Reserved field */
};

/**
 * @brief Defines a struct used to indicate the status of migrating network interface virtual port
 * @details This struct contains network interface virtual port status information, such as management message header, function ID, status, etc.
 */
struct mig_nic_vport_state {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u16 rsvd1;     /**< Reserved field */
	u8 state;     /**< 0--disable, 1--enable */
	u8 rsvd2[3];     /**< Reserved field */
};

#define SQ_CI_ATTR_SIZE 0x14     /**< SQ CIaddresslength */
#define SQ_CI_INDIR_TBL_SIZE 0x20     /**< SQ CI indirect table size */
#define MAX_CI_TBL_NUM 0x20     /**< mailbox max 2kb, one sq ci(attr + tbl) 52B, 32 *52 = 1664B < 2kb */

/**
 * @brief Defines a struct used to store single NIC transmit queue control information
 * @details This struct contains two members, sq_ci_tbl and sq_ci_attr, used to store transmit queue control table and transmit queue control attributes respectively.
 */
struct mig_nic_single_sq_ci {
	u8 sq_ci_tbl[SQ_CI_INDIR_TBL_SIZE];     /**< sq ci table */
	u8 sq_ci_attr[SQ_CI_ATTR_SIZE];     /**< sq ci address table */
};

/**
 * @brief Network interface struct, used to store network interface information
 * @details This struct contains basic network interface information and service queue information
 */
struct mig_nic_sq_ci {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< function ID, used to identify the network interface function */
	u8 opcode;     /**< operation code, used to identify the network interface operation type */
	u8 curr_sq_id;     /**< current service queue ID, used to identify the currently used service queue */
	u8 round_queue_num;     /**< round-robin queue count, used to identify the number of round-robin queues of network interface */
	u8 rsvd[3];     /**< Reserved field */
	struct mig_nic_single_sq_ci sq_ci[MAX_CI_TBL_NUM];     /**< ci information of a single sq */
};

#define RSS_INDIR_TBL_SIZE 0x200     /**< RSS indirect table size */
#define RSS_KEY_SIZE 0x28     /**< RSS key size */

/**
 * @brief Defines a struct for network interface receive side scaling (RSS)
 * @details This struct contains various RSS-related parameters, used to configure the RSS function of the network interface.
 */
struct mig_nic_rss_tbl {
	u8 rss_enable;     /**< flag to enable or disable RSS */
	u8 rss_hash_engine;     /**< RSS hash engine type */
	u16 rsvd;     /**< Reserved field */
	u32 rss_ctx;     /**< RSS context */
	u8 rss_indri_tbl[RSS_INDIR_TBL_SIZE];     /**< RSS indirect table */
	u8 rss_key[RSS_KEY_SIZE];     /**< RSS key */
};

/**
 * @brief Defines a struct for network interface configuration, contains management message header, function ID, operation code, reserved field and RSS table information
 * @details This struct is used for network interface configuration, contains management message header, function ID, operation code, reserved field and RSS table information, can be used to implement various network interface configuration operations.
 */
struct mig_nic_cfg_rss_tbl {
	struct mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 opcode;     /**< operation code */
	u8 rsvd;     /**< Reserved field */
	struct mig_nic_rss_tbl rss_tbl;     /**< RSS table */
};

#define MAX_CMDQ_NUM 0x4     /**< maxcmdqcount */
#define ENHANCED_CMDQ_CTX_SIZE 0x30     /**< defines enhanced cmdq context size as 48 */

/**
 * @brief Defines a struct used to store NIC temporary configuration command queue context information
 * @details This struct contains management message header, Function ID, command queue count, Reserved field and command queue context etc. information
 */
struct mig_nic_tmp_cfg_cmdq_ctx {
	struct mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 cmdq_num;     /**< cmdqcount */
	u8 rsvd;     /**< Reserved field */
	u8 cmdq_ctx[MAX_CMDQ_NUM * ENHANCED_CMDQ_CTX_SIZE];     /**< cmdqcontext */
};

/**
 * @brief NIC migration queue stop information struct
 * @details This struct is used to describe information related to NIC migration queue stop.
 */
struct nic_mig_sq_stop {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 is_stop;     /**< whether stopped */
	u8 sq_num;     /**< sq queue number */
	u8 rsvd[4];     /**< Reserved field */
};

struct mig_nic_fast_msg_addr {
	struct mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 opcode;     /**< operation code */
	u8 page_num;     /**< page num */
	u32 rsvd;     /**< Reserved field */
	u64 page_addr[MIG_FAST_MSG_VF_PAGE_NUM];     /**< page addr */
};

/**
 * @brief struct hinic5_cmd_set_pcie_flr_mgmt
 * @details nic setpcie flrcommandstruct
 */
struct hinic5_cmd_set_pcie_flr_mgmt {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u16 rsvd1;     /**< Reserved field */
};

struct hinic5_cmd_lro_cfg {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< func id */
	u8 data;     /**< data to be set or get */
	u8 data_type;     /**< data type: refer to lro_cfg_operate_type enum definition */
	u8 opcode;     /**< 0: get, 1: set */
	u8 rsvd1[3];     /**< Reserved field */
};

#define NIC_DCB_UP_MAX 0x8     /**< defines the max user priority (UP) of network interface control data packet (NIC DCB) */

/**
 * @brief hinic5_dcb_state
 * @details nic dcb statecommandstruct
 */
struct hinic5_dcb_state {
	u8 dcb_on;     /**< dcb on or off */
	u8 default_cos;     /**< default cos */
	u8 trust;     /**< trust state */
	u8 rsvd1;     /**< Reserved field */
	u8 pcp2cos[NIC_DCB_UP_MAX];     /**< pcp to cos */
	u8 dscp2cos[64];     /**< dscp to cos */
	u32 rsvd2[7];     /**< Reserved field */
};

/**
 * @brief hinic5_cmd_vf_dcb_state
 * @details nic vf dcb statecommandstruct
 */
struct hinic5_cmd_vf_dcb_state {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	struct hinic5_dcb_state state;     /**< dcb state */
};

struct hinic5_cmd_port_info {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u8 port_id;
	u8 rsvd1[3];     /**< Reserved field */
	u8 port_type;
	u8 autoneg_cap;
	u8 autoneg_state;
	u8 duplex;
	u8 speed;
	u8 fec;
	u16 rsvd2;     /**< Reserved field */
	u32 rsvd3[4];     /**< Reserved field */
};

/**
 * @brief nic_cmd_bond_active_report_info
 * @details struct for asynchronous message notification sent to host after LACP negotiation result update
 */
struct nic_cmd_bond_active_report_info {
	struct mgmt_msg_head head;     /**< Command word message header */
	u32 bond_id;
	u32 bon_mmi_status;     /**< link status of this bond sub-device */
	u32 active_bitmap;     /**< slave port status of this bond sub-device */
	u8 rsvd[16];     /**< Reserved field */
};

/**
 * @brief nic_cmd_tx_pause_notice
 * @details pfc/pause storm tx exception report
 */
struct nic_cmd_tx_pause_notice {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 tx_pause_except;     /**< 1: abnormal, 0: normal */
	u32 except_level;     /**< exception level */
	u32 rsvd;     /**< Reserved field */
};

#pragma pack(4)
typedef struct fault_msg_s {
	struct mgmt_msg_head msg_head;     /**< Command word message header */
	u8 num;     /**< count of custom packets transmitted */
	u8 rsvd[3];     /**< Reserved field */
	u16 real_size;
	u8 mode;     /**< 0: read, 1: write */
	u8 type;     /**< 0: do not send notification immediately, 1: send notification immediately */
	u8 data[0];     /**< size specified by real_size */
} fault_msg_t;
#pragma pack()

#define TCAM_FLOW_KEY_SIZE 44     /**< definition of tcam key size as 44B */

typedef struct {
	u32 qid : 10;     /**< if flag==1, fdir_qid indicates group id; if flag==0, fdir_qid indicates qid */
	u32 flag : 1;
	u32 rsvd : 21;     /**< Reserved field */
} qid_htn_s;

typedef union {
	qid_htn_s qid_htn;
	u32 qid;
} qid_u;

/**
 * @brief Defines a struct used to store TCAM lookup results
 * @details contains Flow Director composite target information (qid/group + flag) and Reserved field.
 */
struct tcam_result {
	qid_u fdir_info;
	u32 rsvd;     /**< Reserved field */
};

/**
 * @brief Defines a struct used to store the x and y values of the TCAM flow key
 * @details This struct is used to store the x and y values of the TCAM flow key. TCAM flow key is a data structure used for flow table lookup, where x and y values are the two components of the flow key.
 */
struct tcam_key_x_y {
	u8 x[TCAM_FLOW_KEY_SIZE];     /**< x value, size is TCAM_FLOW_KEY_SIZE */
	u8 y[TCAM_FLOW_KEY_SIZE];     /**< y value, size is TCAM_FLOW_KEY_SIZE */
};

/**
 * @brief used to store TCAM configuration rules of network interface controller (NIC)
 * @details contains the index, data, and key of TCAM configuration rules, used to store and manage TCAM configuration rules in NIC.
 */
struct nic_tcam_cfg_rule {
	u32 index;     /**< rule index */
	struct tcam_result data;     /**< rule data */
	struct tcam_key_x_y key;     /**< rule key */
};

/**
 * @brief TCAM configuration rule
 * @details contains various configuration information of TCAM rules, such as key values, masks, actions, etc. of rules.
 */
struct nic_cmd_fdir_add_rule {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< Func ID */
	u8 type;     /**< rule type */
	u8 usrdata;     /**< user data */
	struct nic_tcam_cfg_rule rule;     /**< Configuration table */
};

/**
 * @brief struct for getting network interface command filter rules
 * @details This struct is used to store information related to getting network interface command filter rules.
 */
struct nic_cmd_fdir_get_rule {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u32 index;     /**< indexfield */
	u8 valid;     /**< validity field */
	u8 type;     /**< typefield */
	u16 rsvd;     /**< Reserved field */
	struct tcam_key_x_y key;     /**< TCAM key field */
	struct tcam_result data;     /**< TCAM result field */
	u64 packet_count;     /**< packet count field */
	u64 byte_count;     /**< byte count field */
};

#define NIC_TCAM_BLOCK_LARGE_NUM 256     /**< defines TCAM BLOCK max value as 256 */
#define NIC_TCAM_BLOCK_LARGE_SIZE 16     /**< defines a block max size as 16 */
#define TCAM_RULE_FDIR_TYPE 0     /**< defines TCAM rule type, FDIR type corresponding value is 0 */
#define TCAM_RULE_PPA_TYPE 1     /**< defines TCAM rule type, PPA type corresponding value is 1 */

/**
 * @brief struct for getting TCAM block rules
 * @details This struct is used to get TCAM block rules, including TCAM block type, TCAM table type, TCAM block index, validity array, TCAM key array and TCAM result array.
 */
struct nic_cmd_fdir_get_block_rules {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 tcam_block_type;     /**< TCAM block type, currently only NIC_TCAM_BLOCK_TYPE_LARGE */
	u8 tcam_table_type;     /**< TCAM rule type, TCAM_RULE_PPA_TYPE or TCAM_RULE_FDIR_TYPE */
	u16 tcam_block_index;     /**< TCAM block index */
	u8 valid[NIC_TCAM_BLOCK_LARGE_SIZE];     /**< validity array */
	struct tcam_key_x_y key[NIC_TCAM_BLOCK_LARGE_SIZE];     /**< TCAM key array */
	struct tcam_result data[NIC_TCAM_BLOCK_LARGE_SIZE];     /**< TCAM result array */
};

struct hinic5_rate_xir_xbs {
	u32 cir;     /**< unit: kbps */
	u32 pir;     /**< unit: kbps */
	u32 cbs;     /**< unit: Byte */
	u32 pbs;     /**< unit: Byte */
};

/**
 * @brief nic tx MQMspeedconfigure
 * @details used to set and get func MQM rate limit parameters and set fun mapping table.
 */
struct hinic5_cmd_tx_limit_rate {
	struct hinic5_mgmt_msg_head msg_head;     /**< Command word message header */
	u16 func_id;     /**< func ID */
	u8 op_code;     /**< operationtype： 0 - default； 1 - get； 2 - set； 3 - map */
	u8 vnicgrp_flag;     /**< vnicgrpoperationidentify：0 - vnic；1 - vnic group */
	u32 vnicgrp_id;     /**< vnic group ID */
	u32 vnic_id;     /**< vnic ID */
	u8 limit_type;     /**< rate limittype：0 - pps; 1-bps */
	u8 rsvd1[3];     /**< Reserved field */
	struct hinic5_rate_xir_xbs rate_para;     /**< rate_cfg */
	u32 rsvd2[64];     /**< Reserved field */
};

#define HINIC5_TX_SET_PROMISC_SKIP 0     /**< set promiscuous receive unknown unicast packet */
#define HINIC5_TX_GET_PROMISC_SKIP 1     /**< read promiscuous receive unknown unicast packet */

/**
 * @brief set whether promiscuous receives unknown unicast packet
 * @details This struct is used for toggling whether to deliver unknown unicast packets to promiscuous-enabled PF, including
 */
struct hinic5_tx_promisc_cfg {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u8 port_id;     /**< network side port id */
	u8 promisc_skip_en;     /**< 0: disable delivery 1: enable delivery */
	u8 opcode;     /**< 0: set 1: read */
	u8 rsvd;     /**< Reserved field */
};

#define HINIC5_ARP_PKT_MAX_LEN 512

/**
 * @brief Struct for passing ARP related packet content to MPU
 * @details This struct is used for passing ARP or ND packets that need to be forwarded on behalf to MPU
 */
struct hinic5_arp_pkt_info {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;     /**< func ID */
	u16 pkt_length;     /**< packetlength */
	u16 origin_queue_id;     /**< queue id of driver transmitted packet */
	u8  rsvd[2];     /**< Reserved field */
	u32 rsvd1[4];     /**< Reserved field */
	u8 pkt_buf[HINIC5_ARP_PKT_MAX_LEN];     /**< packetbuffer */
};

/**
 * @brief Struct for passing Bond configure information to MPU
 * @details This struct is used for passing offload Bond configure information to MPU
 */
struct hinic5_cmd_cfg_bond {
	struct hinic5_mgmt_msg_head head;     /**< Command word message header */
	u16 func_id;
	u8 opcode;     /**< operation code: 1 set arp status, 0 get arp status */
	u8 arp_en;     /**< ARP dual-transmit enable */
	u32 rsvd;     /**< Reserved field */
};

#endif /* HINIC5_NIC_CMD_STRUCTS_H */

