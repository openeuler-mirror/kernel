/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_cfg_comm.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : NIC common configuration
 */

#ifndef NIC_CFG_COMM_H
#define NIC_CFG_COMM_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#endif

#include "nic_mpu_cmd_structs.h"
#include "nic_mpu_cmd_structs_extend.h"
/* rss */
#define HINIC5_RSS_TYPE_VALID_SHIFT 23 /**< Offset of RSS (Receive Side Scaling) type valid bit */
#define HINIC5_RSS_TYPE_TCP_IPV6_EXT_SHIFT 24 /**< Offset of RSS type TCP IPv6 extension */
#define HINIC5_RSS_TYPE_IPV6_EXT_SHIFT 25 /**< Offset of RSS type IPv6 extension header */
#define HINIC5_RSS_TYPE_TCP_IPV6_SHIFT 26 /**< Offset of RSS type TCP IPv6 */
#define HINIC5_RSS_TYPE_IPV6_SHIFT 27 /**< Offset of RSS type IPv6 */
#define HINIC5_RSS_TYPE_TCP_IPV4_SHIFT 28 /**< Offset of RSS type TCP IPv4 */
#define HINIC5_RSS_TYPE_IPV4_SHIFT 29 /**< Offset of RSS type IPv4 */
#define HINIC5_RSS_TYPE_UDP_IPV6_SHIFT 30 /**< Offset of RSS type UDP IPv6 */
#define HINIC5_RSS_TYPE_UDP_IPV4_SHIFT 31 /**< Offset of RSS type UDP IPv4 */

/* vlan */
#define NIC_CVLAN_INSERT_ENABLE 0x1
#define NIC_QINQ_INSERT_ENABLE  0x3
#define NIC_CONFIG_ALL_QUEUE_VLAN_CTX 0xffff

/**
 * @brief Define a macro to set RSS type
 * @param val Value to set
 * @param member Member to set
 * @return Returns the result after setting
 */
#define HINIC5_RSS_TYPE_SET(val, member) (((u32)(val) & 0x1) << HINIC5_RSS_TYPE_##member##_SHIFT)
/**
 * @brief Define a macro to get RSS type
 * @param val Value to get
 * @param member Member to get
 * @return Returns the result obtained
 */
#define HINIC5_RSS_TYPE_GET(val, member) (((u32)(val) >> HINIC5_RSS_TYPE_##member##_SHIFT) & 0x1)

/**
 * @brief Define RSS hash type enum
 * @details This enum is used to represent the Receive Side Scaling (RSS) hash type of the NIC
 */
enum nic_rss_hash_type {
	NIC_RSS_HASH_TYPE_XOR = 0,  /**< XOR hash type */
	NIC_RSS_HASH_TYPE_TOEP,     /**< TOEP hash type */

	NIC_RSS_HASH_TYPE_MAX       /**< MUST BE THE LAST ONE */
};

/**
 * @brief Define csum_err type enum reported by microcode in CQE merge scenario
 * @details In CQE merge scenario, csum_err in CQE is compressed from 9bit to 2bit, and works with the driver as follows:
 * NIC_RX_CSUM_IPSU_OTHER_ERR, i.e. non-CQE merge scenario csum_err bit[8] != 0 ---> CQE merge scenario csum_err changed to 2
 * NIC_RX_CSUM_HW_BYPASS_ERR, i.e. non-CQE merge scenario csum_err bit[7] != 0 ---> CQE merge scenario csum_err changed to 3
 * l3 or l4 layer packet csum error, non-CQE merge scenario csum_err bit[0]~bit[6] != 0 ---> CQE merge scenario csum_err changed to 1
 */
enum nic_compact_cqe_csum_err_type {
	NIC_RX_COMPACT_CSUM_NO_ERROR = 0,
	NIC_RX_COMPACT_L3_L4_CSUM_ERROR,
	NIC_RX_COMPACT_CSUM_OTHER_ERROR,
	NIC_RX_COMPACT_HW_BYPASS_ERROR
};

#define NIC_RSS_INDIR_SIZE      256     /**< Define RSS indirection table size as 256 */
#define NIC_RSS_KEY_SIZE        40      /**< Define RSS key size as 40 */

/* *
 * Definition of the NIC receiving mode
 */
#define NIC_RX_MODE_UC          0x01 /**< Unicast mode */
#define NIC_RX_MODE_MC          0x02 /**< Multicast mode */
#define NIC_RX_MODE_BC          0x04 /**< Broadcast mode */
#define NIC_RX_MODE_MC_ALL      0x08 /**< All multicast mode */
#define NIC_RX_MODE_PROMISC     0x10 /**< Promiscuous mode, receive all packets */

/* IEEE 802.1Qaz std */
#define NIC_DCB_DSCP_NUM        0x8 /**< Define the maximum DSCP value for NIC DCB */
#define NIC_DCB_IP_PRI_MAX      0x40    /**< Define the maximum IP priority for NIC DCB */

#define NIC_DCB_PRIO_DWRR       0x0 /**< Define a macro indicating priority allocation as DWRR bandwidth allocation */
#define NIC_DCB_PRIO_STRICT     0x1 /**< Define a macro indicating priority allocation as strict priority */

#define NIC_DCB_MAX_PFC_NUM     0x4 /**< Define a macro indicating the maximum number of Priority Flow Control (PFC) */

#ifndef ETH_ALEN
#define ETH_ALEN 6  /**< Define single MAC address length as 6B */
#endif

#ifndef BIT
/**
 * @brief Define a macro to left-shift a number's binary form by n bits
 * @param n Number of bits to left-shift
 * @return Returns the result after left-shifting n bits
 */
#define BIT(n) (1UL << (n))
#endif

/**
 * @brief Network interface card feature capability enum definition
 *
 * @details The enum type nic_feature_cap defines various feature capabilities of the NIC.
 *          Each enum value is a BIT bit of a bitmask, and you can set or check whether
 *          a feature is supported through bit operations.
 */

enum nic_feature_cap {
	NIC_F_CSUM_BIT = 0,                    /**< Checksum calculation */
	NIC_F_SCTP_CRC_BIT = 1,                /**< SCTP CRC check */
	NIC_F_TSO_BIT = 2,                     /**< TCP Segmentation Offload */
	NIC_F_LRO_BIT = 3,                     /**< Large Receive Offload */
	NIC_F_UFO_BIT = 4,                     /**< UDP Fragmentation Offload */
	NIC_F_RSS_BIT = 5,                     /**< Receive Side Scaling */
	NIC_F_RX_VLAN_FILTER_BIT = 6,          /**< Receive VLAN filter */
	NIC_F_RX_VLAN_STRIP_BIT = 7,           /**< Receive VLAN strip */
	NIC_F_TX_VLAN_INSERT_BIT = 8,          /**< Transmit VLAN insert */
	NIC_F_VXLAN_OFFLOAD_BIT = 9,           /**< VXLAN Offload */
	NIC_F_IPSEC_OFFLOAD_BIT = 10,          /**< IPsec Offload */
	NIC_F_FDIR_BIT = 11,                   /**< Flow Director */
	NIC_F_PROMISC_BIT = 12,                /**< Promiscuous mode */
	NIC_F_ALLMULTI_BIT = 13,               /**< Receive all multicast */
	NIC_F_XSFP_REPORT_BIT = 14,            /**< XSFP status report */
	NIC_F_VF_MAC_BIT = 15,                 /**< Virtual function MAC address */
	NIC_F_RATE_LIMIT_BIT = 16,             /**< Rate limit */
	NIC_F_RESV1_BIT = 17,                  /**< RESV1 */
	NIC_F_PTP_1588_V2_BIT = 18,            /**< PTP 1588v2 */
	NIC_F_TX_WQE_COMPACT_TASK_BIT = 19,    /**< Transmit WQE compact */
	NIC_F_RX_HW_COMPACT_CQE_BIT = 20,      /**< HTN compact CQE */
	NIC_F_HTN_CMDQ_BIT = 21,               /**< HTN command queue */
	NIC_F_GENEVE_OFFLOAD_BIT = 22,         /**< Geneve Offload */
	NIC_F_IPXIP_OFFLOAD_BIT = 23,          /**< IPXIP Offload */
	NIC_F_TC_FLOWER_OFFLOAD_BIT = 24,      /**< TCAM flower offload */
	NIC_F_HTN_FDIR_BIT = 25,               /**< HTN FDIR feature */
	NIC_F_SQ_RQ_CI_COALESCE_BIT = 26,      /**< SQ RQ CI shared */
	NIC_F_RX_SW_COMPACT_CQE_BIT = 27,      /**< ucode compact CQE */
	NIC_F_HALF_BOND_OFFLOAD_BIT = 28,      /**< Half bond offload */
	NIC_F_MACSEC_OFFLOAD_BIT = 29,         /**< MACSec offload */
	NIC_F_VEB_OFFLOAD_BIT = 30,            /**< VEB offload */
	NIC_F_GET_COUNTER_BY_CMDQ_BIT = 31,    /**< Support reading vport counter via CMDQ */
	NIC_F_HTN_CMDQ_CAR_BIT = 32,           /**< Support setting CAR rate limit via CMDQ */
	NIC_F_ARP_DUAL_BIT = 33,                    /**< Support ARP dual-send */
};

#define NIC_F_BIT(bit)    ((u64)1 << (bit))
#define NIC_F(name)       NIC_F_BIT(NIC_F_##name##_BIT)

#define NIC_F_CSUM          NIC_F(CSUM)
#define NIC_F_SCTP_CRC      NIC_F(SCTP_CRC)
#define NIC_F_TSO           NIC_F(TSO)
#define NIC_F_LRO           NIC_F(LRO)
#define NIC_F_UFO           NIC_F(UFO)
#define NIC_F_RSS           NIC_F(RSS)
#define NIC_F_RX_VLAN_FILTER NIC_F(RX_VLAN_FILTER)
#define NIC_F_RX_VLAN_STRIP NIC_F(RX_VLAN_STRIP)
#define NIC_F_TX_VLAN_INSERT NIC_F(TX_VLAN_INSERT)
#define NIC_F_VXLAN_OFFLOAD NIC_F(VXLAN_OFFLOAD)
#define NIC_F_IPSEC_OFFLOAD NIC_F(IPSEC_OFFLOAD)
#define NIC_F_FDIR          NIC_F(FDIR)
#define NIC_F_PROMISC       NIC_F(PROMISC)
#define NIC_F_ALLMULTI      NIC_F(ALLMULTI)
#define NIC_F_XSFP_REPORT   NIC_F(XSFP_REPORT)
#define NIC_F_VF_MAC        NIC_F(VF_MAC)
#define NIC_F_RATE_LIMIT    NIC_F(RATE_LIMIT)
#define NIC_F_PTP_1588_V2   NIC_F(PTP_1588_V2)
#define NIC_F_TX_WQE_COMPACT_TASK NIC_F(TX_WQE_COMPACT_TASK)
#define NIC_F_RX_HW_COMPACT_CQE NIC_F(RX_HW_COMPACT_CQE)
#define NIC_F_HTN_CMDQ      NIC_F(HTN_CMDQ)
#define NIC_F_GENEVE_OFFLOAD NIC_F(GENEVE_OFFLOAD)
#define NIC_F_IPXIP_OFFLOAD NIC_F(IPXIP_OFFLOAD)
#define NIC_F_TC_FLOWER_OFFLOAD NIC_F(TC_FLOWER_OFFLOAD)
#define NIC_F_HTN_FDIR      NIC_F(HTN_FDIR)
#define NIC_F_SQ_RQ_CI_COALESCE NIC_F(SQ_RQ_CI_COALESCE)
#define NIC_F_RX_SW_COMPACT_CQE NIC_F(RX_SW_COMPACT_CQE)
#define NIC_F_HALF_BOND_OFFLOAD NIC_F(HALF_BOND_OFFLOAD)
#define NIC_F_MACSEC_OFFLOAD NIC_F(MACSEC_OFFLOAD)
#define NIC_F_VEB_OFFLOAD   NIC_F(VEB_OFFLOAD)
#define NIC_F_GET_COUNTER_BY_CMDQ NIC_F(GET_COUNTER_BY_CMDQ)
#define NIC_F_HTN_CMDQ_CAR      NIC_F(HTN_CMDQ_CAR)
#define NIC_F_ARP_DUAL      NIC_F(ARP_DUAL)

#define NIC_F_1823_MASK 0x1FFEF   /**< All attributes of 1823 */
#define NIC_F_1825_MASK (NIC_F_CSUM | NIC_F_SCTP_CRC | NIC_F_TSO | NIC_F_LRO | NIC_F_RSS | NIC_F_RX_VLAN_FILTER | \
			NIC_F_RX_VLAN_STRIP | NIC_F_TX_VLAN_INSERT | NIC_F_VXLAN_OFFLOAD | NIC_F_IPSEC_OFFLOAD | NIC_F_FDIR | \
			NIC_F_PROMISC | NIC_F_ALLMULTI | NIC_F_XSFP_REPORT | NIC_F_VF_MAC | NIC_F_RATE_LIMIT | \
			NIC_F_TX_WQE_COMPACT_TASK | NIC_F_RX_SW_COMPACT_CQE | NIC_F_HALF_BOND_OFFLOAD | NIC_F_GET_COUNTER_BY_CMDQ)

#define NIC_F_182X_MASK (NIC_F_1823_MASK | NIC_F_1825_MASK) /**< All attributes of 182x */

#define NIC_F_1872_PF_MASK (NIC_F_CSUM | NIC_F_SCTP_CRC | NIC_F_TSO | NIC_F_TX_WQE_COMPACT_TASK | NIC_F_RX_HW_COMPACT_CQE | \
			NIC_F_HTN_CMDQ | NIC_F_PROMISC | NIC_F_ALLMULTI | NIC_F_VXLAN_OFFLOAD | NIC_F_GENEVE_OFFLOAD |  \
			NIC_F_IPXIP_OFFLOAD | NIC_F_RX_VLAN_STRIP | NIC_F_TX_VLAN_INSERT | NIC_F_RSS | NIC_F_RX_VLAN_FILTER |   \
			NIC_F_LRO | NIC_F_FDIR | NIC_F_HTN_FDIR | NIC_F_SQ_RQ_CI_COALESCE | NIC_F_PTP_1588_V2 | NIC_F_TC_FLOWER_OFFLOAD | \
			NIC_F_MACSEC_OFFLOAD | NIC_F_VEB_OFFLOAD | NIC_F_RATE_LIMIT | NIC_F_HTN_CMDQ_CAR | NIC_F_ARP_DUAL | \
			NIC_F_XSFP_REPORT) /**< All attributes of 187x PF */

#define NIC_F_1872_VF_MASK (NIC_F_CSUM | NIC_F_SCTP_CRC | NIC_F_TSO | NIC_F_TX_WQE_COMPACT_TASK | NIC_F_RX_HW_COMPACT_CQE | \
			NIC_F_HTN_CMDQ | NIC_F_ALLMULTI | NIC_F_VXLAN_OFFLOAD | NIC_F_GENEVE_OFFLOAD | NIC_F_IPXIP_OFFLOAD | \
			NIC_F_RX_VLAN_STRIP | NIC_F_TX_VLAN_INSERT | NIC_F_RSS | NIC_F_RX_VLAN_FILTER | NIC_F_LRO | NIC_F_FDIR | \
			NIC_F_HTN_FDIR | NIC_F_SQ_RQ_CI_COALESCE | NIC_F_TC_FLOWER_OFFLOAD | NIC_F_MACSEC_OFFLOAD | \
			NIC_F_VEB_OFFLOAD | NIC_F_RATE_LIMIT | NIC_F_HTN_CMDQ_CAR | NIC_F_ARP_DUAL) /**< All attributes of 187x VF */

#define NIC_F_1872_MASK (NIC_F_1872_PF_MASK | NIC_F_1872_VF_MASK)
#define NIC_F_ALL_MASK (NIC_F_182X_MASK | NIC_F_1872_MASK)

#define HINIC5_TCAM_BLOCK_ENABLE      1 /**< TCAM block enable */
#define HINIC5_TCAM_BLOCK_DISABLE     0 /**< TCAM block disable */
#define HINIC5_MAX_TCAM_RULES_NUM   4096 /**< Maximum number of TCAM rules */

/**
 * @brief Define an enum type used to represent the NIC TCAM block type.
 * @details This enum type contains two types: NIC_TCAM_BLOCK_TYPE_LARGE and NIC_TCAM_BLOCK_TYPE_SMALL.
 *          NIC_TCAM_BLOCK_TYPE_LARGE indicates block size 16, NIC_TCAM_BLOCK_TYPE_SMALL indicates block size 0.
 */
enum {
	NIC_TCAM_BLOCK_TYPE_LARGE = 0, /**< block_size: 16 */
	NIC_TCAM_BLOCK_TYPE_SMALL,     /**< block_size: 0 */
	NIC_TCAM_BLOCK_TYPE_MAX
};

/**
 * @struct hinic5_tcam_key_ipv4_mem
 * @brief Define a struct for storing IPv4 TCAM key
 * @details This struct contains various fields of the IPv4 TCAM key, including reserved bits,
 *          tunnel type, IP protocol type, IP type, Func ID, source IPv4 address, destination IPv4 address,
 *          destination port, source port, outer source IPv4 address, outer destination IPv4 address, VNI, etc.
 */
struct hinic5_tcam_key_ipv4_mem {
	u32 rsvd1 : 4; /**< Reserved bit 1 */
	u32 tunnel_type : 4; /**< Tunnel type */
	u32 ip_proto : 8; /**< IP protocol type */
	u32 rsvd0 : 16; /**< Reserved bit 0 */
	u32 sipv4_h : 16; /**< High 16 bits of source IPv4 address */
	u32 ip_type : 1; /**< IP type */
	u32 function_id : 15; /**< Func ID */
	u32 dipv4_h : 16; /**< High 16 bits of destination IPv4 address */
	u32 sipv4_l : 16; /**< Low 16 bits of source IPv4 address */
	u32 rsvd2 : 16; /**< Reserved bit 2 */
	u32 dipv4_l : 16; /**< Low 16 bits of destination IPv4 address */
	u32 rsvd3; /**< Reserved bit 3 */
	u32 dport : 16; /**< Destination port */
	u32 rsvd4 : 16; /**< Reserved bit 4 */
	u32 rsvd5 : 16; /**< Reserved bit 5 */
	u32 sport : 16; /**< Source port */
	u32 outer_sipv4_h : 16; /**< High 16 bits of outer source IPv4 address */
	u32 rsvd6 : 16; /**< Reserved bit 6 */
	u32 outer_dipv4_h : 16; /**< High 16 bits of outer destination IPv4 address */
	u32 outer_sipv4_l : 16; /**< Low 16 bits of outer source IPv4 address */
	u32 vni_h : 16; /**< High 16 bits of VNI */
	u32 outer_dipv4_l : 16; /**< Low 16 bits of outer destination IPv4 address */
	u32 rsvd7 : 16; /**< Reserved bit 7 */
	u32 vni_l : 16; /**< Low 16 bits of VNI */
};

/**
 * @struct hinic5_tcam_key_ipv6_mem
 * @brief Define a struct for storing IPv6 TCAM key
 * @details This struct is used to store IPv6 TCAM key, containing various parts of the source IPv6 address
 *          and destination IPv6 address, as well as related protocol type, port number and other information.
 */
struct hinic5_tcam_key_ipv6_mem {
	u32 rsvd1 : 3; /**< Reserved bit 1 */
	u32 outer_ip_type : 1; /**< Outer IP type */
	u32 tunnel_type : 4; /**< Tunnel type */
	u32 ip_proto : 8; /**< IP protocol type */
	u32 rsvd0 : 16; /**< Reserved bit 0 */
	u32 sipv6_key0 : 16; /**< Low 16 bits of source IPv6 address */
	u32 ip_type : 1; /**< IP type */
	u32 function_id : 15; /**< Function ID */
	u32 sipv6_key2 : 16; /**< Second part of source IPv6 address */
	u32 sipv6_key1 : 16; /**< First part of source IPv6 address */
	u32 sipv6_key4 : 16; /**< Fourth part of source IPv6 address */
	u32 sipv6_key3 : 16; /**< Third part of source IPv6 address */
	u32 sipv6_key6 : 16; /**< Sixth part of source IPv6 address */
	u32 sipv6_key5 : 16; /**< Fifth part of source IPv6 address */
	u32 dport : 16; /**< Destination port */
	u32 sipv6_key7 : 16; /**< Seventh part of source IPv6 address */
	u32 dipv6_key0 : 16; /**< Low 16 bits of destination IPv6 address */
	u32 sport : 16; /**< Source port */
	u32 dipv6_key2 : 16; /**< Second part of destination IPv6 address */
	u32 dipv6_key1 : 16; /**< First part of destination IPv6 address */
	u32 dipv6_key4 : 16; /**< Fourth part of destination IPv6 address */
	u32 dipv6_key3 : 16; /**< Third part of destination IPv6 address */
	u32 dipv6_key6 : 16; /**< Sixth part of destination IPv6 address */
	u32 dipv6_key5 : 16; /**< Fifth part of destination IPv6 address */
	u32 rsvd2 : 16; /**< Reserved bit 2 */
	u32 dipv6_key7 : 16; /**< Seventh part of destination IPv6 address */
};

/**
 * @struct hinic5_tcam_key_vxlan_ipv6_mem
 * @brief Define a struct for storing VXLAN IPv6 TCAM key
 * @details This struct contains various fields of the VXLAN IPv6 TCAM key, including reserved bits,
 *          tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_vxlan_ipv6_mem {
	u32 rsvd1 : 4; /**< Reserved bit 1 */
	u32 tunnel_type : 4; /**< Tunnel type */
	u32 ip_proto : 8; /**< IP protocol type */
	u32 rsvd0 : 16; /**< Reserved bit 0 */

	u32 dipv6_key0 : 16; /**< Low 16 bits of IPv6 destination address */
	u32 ip_type : 1; /**< IP type */
	u32 function_id : 15; /**< Function ID */

	u32 dipv6_key2 : 16; /**< Second part of IPv6 destination address */
	u32 dipv6_key1 : 16; /**< First part of IPv6 destination address */

	u32 dipv6_key4 : 16; /**< Fourth part of IPv6 destination address */
	u32 dipv6_key3 : 16; /**< Third part of IPv6 destination address */

	u32 dipv6_key6 : 16; /**< Sixth part of IPv6 destination address */
	u32 dipv6_key5 : 16; /**< Fifth part of IPv6 destination address */

	u32 dport : 16; /**< Destination port */
	u32 dipv6_key7 : 16; /**< Seventh part of IPv6 destination address */

	u32 rsvd2 : 16; /**< Reserved bit 2 */
	u32 sport : 16; /**< Source port */

	u32 outer_sipv4_h : 16; /**< High 16 bits of outer source IPv4 address */
	u32 rsvd3 : 16; /**< Reserved bit 3 */

	u32 outer_dipv4_h : 16; /**< High 16 bits of outer destination IPv4 address */
	u32 outer_sipv4_l : 16; /**< Low 16 bits of outer source IPv4 address */

	u32 vni_h : 16; /**< High 16 bits of VXLAN network identifier */
	u32 outer_dipv4_l : 16; /**< Low 16 bits of outer destination IPv4 address */

	u32 rsvd4 : 16; /**< Reserved bit 4 */
	u32 vni_l : 16; /**< Low 16 bits of VXLAN network identifier */
};

/**
 * @struct hinic5_tcam_key_mem_htn
 * @brief Define a struct for storing htn TCAM key
 * @details This struct contains various fields of the htn TCAM key, including reserved bits,
 *          tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_mem_htn {
	u32 function_id_h : 5; /**< High 5 bits of function id */
	u32 tunnel_type : 3;   /**< Store tunnel type */
	u32 ip_proto : 8;      /**< Store IP protocol type */
	u32 rsvd0 : 16;        /**< Reserved 16 bits */

	u32 outer_sipv4_h : 16; /**< High 16 bits of outer source IPv4 */
	u32 rsvd1 : 8;          /**< Reserved 8 bits */
	u32 outer_ip_type : 1;  /**< Store outer IP type */
	u32 ip_type : 2;        /**< Store IP type */
	u32 function_id_l : 5;  /**< Low 5 bits of function id */

	u32 outer_dipv4_h : 16; /**< High 16 bits of outer destination IPv4 */
	u32 outer_sipv4_l : 16; /**< Low 16 bits of outer source IPv4 */

	u32 vni_h : 8; /**< High 8 bits store virtual network identifier */
	u32 rsvd2 : 8; /**< Reserved 8 bits */
	u32 outer_dipv4_l : 16; /**< Low 16 bits of outer destination IPv4 */

	u32 sipv4_h : 16; /**< High 16 bits of source IPv4 */
	u32 vni_l : 16;   /**< Low 8 bits store virtual network identifier */

	u32 rsvd5 : 16; /**< Reserved 16 bits */
	u32 sipv4_l : 16; /**< Low 16 bits of source IPv4 */

	u32 rsvd6; /**< Reserved */
	u32 rsvd7; /**< Reserved */

	u32 dipv4_h : 16; /**< High 16 bits of destination IPv4 */
	u32 rsvd8 : 16;   /**< Reserved 16 bits */

	u32 sport : 16; /**< Source port */
	u32 dipv4_l : 16; /**< Low 16 bits of destination IPv4 */

	u32 rsvd9 : 16; /**< Reserved 16 bits */
	u32 dport : 16; /**< Destination port */
};

/**
 * @struct hinic5_tcam_key_ipv6_mem_htn
 * @brief Define a struct for storing htn ipv6 TCAM key
 * @details This struct contains various fields of the htn ipv6 TCAM key, including reserved bits,
 *          tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_ipv6_mem_htn {
	u32 function_id_h : 5;  /**< High 5 bits of function id */
	u32 tunnel_type : 3;    /**< Store tunnel type */
	u32 ip_proto : 8;       /**< Store IP protocol type */
	u32 rsvd0 : 16;         /**< Reserved 16 bits */

	u32 sipv6_key0 : 16; /**< First part of source IPv6 */
	u32 rsvd1 : 8; /**< Reserved field 1, unused */
	u32 outer_ip_type : 1; /**< Outer IP type, 1 bit */
	u32 ip_type : 2; /**< IP type, 2 bits */
	u32 function_id_l : 5; /**< Low 5 bits of function id */

	u32 sipv6_key2 : 16; /**< Second part of source IPv6 */
	u32 sipv6_key1 : 16; /**< First part of source IPv6 */

	u32 sipv6_key4 : 16; /**< Fourth part of source IPv6 */
	u32 sipv6_key3 : 16; /**< Third part of source IPv6 */

	u32 sipv6_key6 : 16; /**< Sixth part of source IPv6 */
	u32 sipv6_key5 : 16; /**< Fifth part of source IPv6 */

	u32 dipv6_key0 : 16; /**< First part of destination IPv6 */
	u32 sipv6_key7 : 16; /**< Seventh part of source IPv6 */

	u32 dipv6_key2 : 16; /**< Second part of destination IPv6 */
	u32 dipv6_key1 : 16; /**< First part of destination IPv6 */

	u32 dipv6_key4 : 16; /**< Fourth part of destination IPv6 */
	u32 dipv6_key3 : 16; /**< Third part of destination IPv6 */

	u32 dipv6_key6 : 16; /**< Sixth part of destination IPv6 */
	u32 dipv6_key5 : 16; /**< Fifth part of destination IPv6 */

	u32 sport : 16; /**< Source port */
	u32 dipv6_key7 : 16; /**< Seventh part of destination IPv6 */

	u32 rsvd2 : 16; /**< Reserved field 2, unused */
	u32 dport : 16; /**< Destination port */
};

/**
 * @struct hinic5_tcam_key_vxlan_ipv6_mem_htn
 * @brief Define a struct for storing htn vxlan ipv6 TCAM key
 * @details This struct contains various fields of the htn vxlan ipv6 TCAM key, including reserved bits,
 *          tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_vxlan_ipv6_mem_htn {
	u32 function_id_h : 5; /**< High 5 bits of function id */
	u32 tunnel_type : 3;  /**< Tunnel type */
	u32 ip_proto : 8;     /**< IP protocol */
	u32 rsvd0 : 16;       /**< Reserved 16 bits */

	u32 outer_sipv4_h : 16; /**< High 16 bits of outer source IPv4 address */
	u32 rsvd1 : 8;         /**< Reserved 8 bits */
	u32 outer_ip_type : 1; /**< Outer IP type */
	u32 ip_type : 2;       /**< IP type */
	u32 function_id_l : 5; /**< Low 5 bits of function id */

	u32 outer_dipv4_h : 16; /**< High 16 bits of outer destination IPv4 address */
	u32 outer_sipv4_l : 16; /**< Low 16 bits of outer source IPv4 address */

	u32 vni_h : 8; /**< High 8 bits of virtual network identifier */
	u32 rsvd2 : 8; /**< Reserved 8 bits */
	u32 outer_dipv4_l : 16; /**< Low 16 bits of outer destination IPv4 address */

	u32 rsvd3 : 16; /**< Reserved 16 bits */
	u32 vni_l : 16; /**< Low 16 bits of virtual network identifier */

	u32 dipv6_key0 : 16; /**< Part 0 of destination IPv6 address */
	u32 rsvd4 : 16;      /**< Reserved 16 bits */

	u32 dipv6_key2 : 16; /**< Part 2 of destination IPv6 address */
	u32 dipv6_key1 : 16; /**< Part 1 of destination IPv6 address */

	u32 dipv6_key4 : 16; /**< Part 4 of destination IPv6 address */
	u32 dipv6_key3 : 16; /**< Part 3 of destination IPv6 address */

	u32 dipv6_key6 : 16; /**< Part 6 of destination IPv6 address */
	u32 dipv6_key5 : 16; /**< Part 5 of destination IPv6 address */

	u32 sport : 16; /**< Source port */
	u32 dipv6_key7 : 16; /**< Part 7 of destination IPv6 address */

	u32 rsvd5 : 16; /**< Reserved 16 bits */
	u32 dport : 16; /**< Destination port */
};

/**
 * @struct tcam_key_ctrl_mem
 * @brief Define a struct for storing htn control packet TCAM key
 * @details This struct contains various fields of the htn vxlan ipv6 TCAM key, including reserved bits,
 *          tunnel type, IP protocol type, etc.
 */
struct tcam_key_ctrl_mem {
	u32 function_id1 : 5;   /**< High 5 bits of function id */
	u32 pkt_fmt : 3;    /**< Packet format */
	u32 packet_type : 8;    /**< Packet type */
	u32 rsvd0 : 16;     /**< Reserved field 0 */

	u32 rsvd2 : 16;     /**< Reserved field 2 */
	u32 rsvd1 : 8;      /**< Reserved field 1 */
	u32 outer_type : 1;     /**< Outer type */
	u32 inner_type : 2;     /**< Inner type */
	u32 function_id2 : 5;   /**< Low 5 bits of function id */

	u32 rsvd3;      /**< Reserved field 3 */
	u32 rsvd4;      /**< Reserved field 4 */
	u32 rsvd5;      /**< Reserved field 5 */
	u32 rsvd6;      /**< Reserved field 6 */
	u32 rsvd7;      /**< Reserved field 7 */
	u32 rsvd8;      /**< Reserved field 8 */
	u32 rsvd9;      /**< Reserved field 9 */
	u32 rsvd10;     /**< Reserved field 10 */
	u32 rsvd11;     /**< Reserved field 11 */
};

/**
 * @struct tag_tcam_key
 * @brief TCAM key struct, used to store TCAM key information and mask
 * @details This struct contains two unions, used to store IPv4 key information and mask respectively.
 */
struct tag_tcam_key {
	/**
	 * @union
	 * @brief TCAM key information
	 */
	union {
		struct hinic5_tcam_key_ipv4_mem key_info;
		struct tcam_key_ctrl_mem key_info_ctrl;
		struct hinic5_tcam_key_ipv6_mem key_info_ipv6;
		struct hinic5_tcam_key_vxlan_ipv6_mem key_info_vxlan_ipv6;
		struct hinic5_tcam_key_mem_htn key_info_htn;
		struct hinic5_tcam_key_ipv6_mem_htn key_info_ipv6_htn;
		struct hinic5_tcam_key_vxlan_ipv6_mem_htn key_info_vxlan_ipv6_htn;
	};

	/**
	 * @union
	 * @brief TCAM key mask
	 */
	union {
		struct hinic5_tcam_key_ipv4_mem key_mask;
		struct tcam_key_ctrl_mem key_mask_ctrl;
		struct hinic5_tcam_key_ipv6_mem key_mask_ipv6;
		struct hinic5_tcam_key_vxlan_ipv6_mem key_mask_vxlan_ipv6;
		struct hinic5_tcam_key_mem_htn key_mask_htn;
		struct hinic5_tcam_key_ipv6_mem_htn key_mask_ipv6_htn;
		struct hinic5_tcam_key_vxlan_ipv6_mem_htn key_mask_vxlan_ipv6_htn;
	};
};

#define TCAM_RULE_FDIR_TYPE 0 /**< Define TCAM rule type, FDIR type corresponds to value 0 */
#define TCAM_RULE_PPA_TYPE  1 /**< Define TCAM rule type, PPA type corresponds to value 1 */
#define TCAM_RULE_BIFURCATION_TYPE  2 /**< Define TCAM rule type, BIFURCATION type corresponds to value 1 */

/**
 * @struct hinic5_phy_fpga_port_stats
 * @brief Define a struct for storing PHY FPGA port statistics
 * @details Detailed description of the struct here
 */
struct hinic5_phy_fpga_port_stats {
	u64 mac_rx_total_octs_port; /**< Total received bytes */
	u64 mac_tx_total_octs_port; /**< Total transmitted bytes */
	u64 mac_rx_under_frame_pkts_port; /**< Number of received packets with frame length less than 64 bytes */
	u64 mac_rx_frag_pkts_port; /**< Number of received fragment packets */
	u64 mac_rx_64_oct_pkts_port; /**< Number of received 64-byte packets */
	u64 mac_rx_127_oct_pkts_port; /**< Number of received 127-byte packets */
	u64 mac_rx_255_oct_pkts_port; /**< Number of received 255-byte packets */
	u64 mac_rx_511_oct_pkts_port; /**< Number of received 511-byte packets */
	u64 mac_rx_1023_oct_pkts_port; /**< Number of received 1023-byte packets */
	u64 mac_rx_max_oct_pkts_port; /**< Number of received maximum length packets */
	u64 mac_rx_over_oct_pkts_port; /**< Number of received oversized packets */
	u64 mac_tx_64_oct_pkts_port; /**< Number of transmitted 64-byte packets */
	u64 mac_tx_127_oct_pkts_port; /**< Number of transmitted 127-byte packets */
	u64 mac_tx_255_oct_pkts_port; /**< Number of transmitted 255-byte packets */
	u64 mac_tx_511_oct_pkts_port; /**< Number of transmitted 511-byte packets */
	u64 mac_tx_1023_oct_pkts_port; /**< Number of transmitted 1023-byte packets */
	u64 mac_tx_max_oct_pkts_port; /**< Number of transmitted maximum length packets */
	u64 mac_tx_over_oct_pkts_port; /**< Number of transmitted oversized packets */
	u64 mac_rx_good_pkts_port; /**< Number of received error-free packets */
	u64 mac_rx_crc_error_pkts_port; /**< Number of received CRC error packets */
	u64 mac_rx_broadcast_ok_port; /**< Number of received broadcast packets */
	u64 mac_rx_multicast_ok_port; /**< Number of received multicast packets */
	u64 mac_rx_mac_frame_ok_port; /**< Number of received MAC frame packets */
	u64 mac_rx_length_err_pkts_port; /**< Number of received length error packets */
	u64 mac_rx_vlan_pkts_port; /**< Number of received VLAN packets */
	u64 mac_rx_pause_pkts_port; /**< Number of received pause packets */
	u64 mac_rx_unknown_mac_frame_port; /**< Number of received unknown MAC frame packets */
	u64 mac_tx_good_pkts_port; /**< Number of transmitted error-free packets */
	u64 mac_tx_broadcast_ok_port; /**< Number of transmitted broadcast packets */
	u64 mac_tx_multicast_ok_port; /**< Number of transmitted multicast packets */
	u64 mac_tx_underrun_pkts_port; /**< Number of transmitted buffer-underrun packets */
	u64 mac_tx_mac_frame_ok_port; /**< Number of transmitted MAC frame packets */
	u64 mac_tx_vlan_pkts_port; /**< Number of transmitted VLAN packets */
	u64 mac_tx_pause_pkts_port; /**< Number of transmitted pause packets */
};

/**
 * @struct hinic5_port_stats
 * @brief Define hinic5 port statistics struct
 * @details This struct contains management message header information and physical port statistics
 */
struct hinic5_port_stats {
	struct hinic5_mgmt_msg_head msg_head;   /**< Management message header information */

	struct hinic5_phy_fpga_port_stats stats;    /**< Physical port statistics */
};

/**
 * @struct hinic5_rss_indir_table
 * @brief Define an RSS (Receive Side Scaling) indirection lookup table struct
 * @details This struct is used to store RSS related information, including management message header,
 *          function ID, reserved fields and indirection lookup table.
 */
struct hinic5_rss_indir_table {
	struct hinic5_mgmt_msg_head msg_head;   /**< Management message header */

	u16 func_id;    /**< func id */
	u16 rsvd1;  /** Reserved field 1 */
	u8 indir[NIC_RSS_INDIR_SIZE];   /**< Indirection lookup table */
};

#define NIC_RSS_CMD_TEMP_ALLOC 0x01     /**< Used to temporarily allocate rss resources */
#define NIC_RSS_CMD_TEMP_FREE 0x02      /**< Used to temporarily free rss resources */

/**
 * @struct hinic5_func_tbl_cfg_bitmap
 * @brief Function table configuration bitmap struct
 * @details This struct is used to represent the function table configuration bitmap,
 *          including initialization configuration, receive buffer size configuration and maximum transmission unit configuration.
 */
enum hinic5_func_tbl_cfg_bitmap {
	FUNC_CFG_INIT,              /**< Initialization configuration */
	FUNC_CFG_RX_BUF_SIZE,       /**< Receive buffer size configuration */
	FUNC_CFG_MTU,               /**< Maximum transmission unit configuration */
	FUNC_CFG_ISOLATION_VF_MAC,    /**< Cluster mode VF MAC configuration */
	FUNC_CFG_ISOLATION_VF_SVLAN,    /**< Cluster mode VF SVLAN configuration */
};

typedef struct mac_table_cnt {
	u32 valid_table_cnt;  /**< Valid MAC table count */
	u32 mac_table_cnt;    /**< Maximum supported MAC table count */
	u16 uc_mac_cnt;       /**< Unicast count */
	u16 mc_mac_cnt;       /**< Multicast count */
} mac_table_cnt_s;

#define NIC_FUNC_MAX_NUM 4096
typedef struct mac_table_res_stat {
	u16 uc_mac_cnt;                               /**< Unicast table resource usage statistics */
	u16 mc_mac_cnt;                               /**< Multicast table resource usage statistics */
	u16 share_mac_res_cur_cnt;                    /**< Current shared resource pool usage statistics */
	u16 share_mac_res_total;                      /**< Total size of shared resource pool */
	u16 func_uc_mac_cnt[NIC_FUNC_MAX_NUM];        /**< Func-granularity unicast table resource usage statistics */
} mac_table_res_stat_s;

#define HINIC5_CMD_OP_SET	1   /**< cmd operation type is set */
#define HINIC5_CMD_OP_GET	0   /**< cmd operation type is get */

#define HINIC5_CMD_OP_ADD	1   /**< cmd operation type is add */
#define HINIC5_CMD_OP_DEL	0   /**< cmd operation type is del */

/**
 * @brief Define enum type used to represent different command types
 * @details This enum type defines a series of command types, used to represent different operations in different contexts.
 */
enum {
	PPA_TABLE_ID_CLEAN_CMD = 0, /**< Command to clean PPA table */
	PPA_TABLE_ID_ADD_CMD,   /**< Command to add PPA table */
	PPA_TABLE_ID_DEL_CMD,   /**< Command to delete PPA table */
	FDIR_TABLE_ID_ADD_CMD,  /**< Command to add FDIR table */
	FDIR_TABLE_ID_DEL_CMD,  /**< Command to delete FDIR table */
	PPA_TABEL_ID_MAX    /**< Maximum value of PPA table */
};

/**
 * @brief Define an enum type used to represent the NIC NVM data type
 * @details This enum type contains multiple flag bits, each flag bit represents a type of NIC NVM data.
 */
enum {
	NIC_NVM_DATA_SET = BIT(0), /**< 1-save, 0-read */
	NIC_NVM_DATA_PXE = BIT(1),  /**< PXE */
	NIC_NVM_DATA_VLAN = BIT(2), /**< VLAN */
	NIC_NVM_DATA_VLAN_PRI = BIT(3), /**< VLAN PRI */
	NIC_NVM_DATA_VLAN_ID = BIT(4),  /**< VLAN ID */
	NIC_NVM_DATA_WORK_MODE = BIT(5),    /**< Task type */
	NIC_NVM_DATA_PF_SPEED_LIMIT = BIT(6),   /**< PPF rate limit */
	NIC_NVM_DATA_GE_MODE = BIT(7),  /**< GE mode */
	NIC_NVM_DATA_AUTO_NEG = BIT(8), /**< AUTO NEG */
	NIC_NVM_DATA_LINK_FEC = BIT(9), /**< LINK FEC */
	NIC_NVM_DATA_PF_ADAPTIVE_LINK = BIT(10),    /**< PF adaptive link */
	NIC_NVM_DATA_SRIOV_CONTROL = BIT(11),   /**< SRIOV CONTROL */
	NIC_NVM_DATA_EXTEND_MODE = BIT(12), /**< Extended mode */
	NIC_NVM_DATA_RESET = BIT(31),   /**< RESET */
};

#define BIOS_CFG_SIGNATURE                  0x1923E518    /**< Define BIOS configuration signature */
#define BIOS_OP_CFG_ALL(op_code_val)        ((((op_code_val) >> 1) & (0xFFFFFFFF)) != 0)    /**< Define macro for BIOS opcode all configuration */
#define BIOS_OP_CFG_WRITE(op_code_val)      ((((op_code_val) & NIC_NVM_DATA_SET)) != 0)    /**< Define macro for BIOS opcode write configuration */
#define BIOS_OP_CFG_PXE_EN(op_code_val)     (((op_code_val) & NIC_NVM_DATA_PXE) != 0)    /**< Define macro for BIOS opcode PXE enable */
#define BIOS_OP_CFG_VLAN_EN(op_code_val)    (((op_code_val) & NIC_NVM_DATA_VLAN) != 0)    /**< Define macro for BIOS opcode VLAN enable */
#define BIOS_OP_CFG_VLAN_PRI(op_code_val)   (((op_code_val) & NIC_NVM_DATA_VLAN_PRI) != 0)    /**< Define macro for BIOS opcode VLAN priority */
#define BIOS_OP_CFG_VLAN_ID(op_code_val)    (((op_code_val) & NIC_NVM_DATA_VLAN_ID) != 0)    /**< Define macro for BIOS opcode VLAN ID */
#define BIOS_OP_CFG_WORK_MODE(op_code_val)  (((op_code_val) & NIC_NVM_DATA_WORK_MODE) != 0)    /**< Define macro for BIOS opcode work mode */
#define BIOS_OP_CFG_PF_BW(op_code_val)      (((op_code_val) & NIC_NVM_DATA_PF_SPEED_LIMIT) != 0)    /**< Define macro for BIOS opcode PF bandwidth */
#define BIOS_OP_CFG_GE_SPEED(op_code_val)   (((op_code_val) & NIC_NVM_DATA_GE_MODE) != 0)    /**< Define macro for BIOS opcode GE speed */
#define BIOS_OP_CFG_AUTO_NEG(op_code_val)   (((op_code_val) & NIC_NVM_DATA_AUTO_NEG) != 0)    /**< Define macro for BIOS opcode auto negotiation */
#define BIOS_OP_CFG_LINK_FEC(op_code_val)   (((op_code_val) & NIC_NVM_DATA_LINK_FEC) != 0)    /**< Define macro for BIOS opcode link FEC */
#define BIOS_OP_CFG_AUTO_ADPAT(op_code_val) (((op_code_val) & NIC_NVM_DATA_PF_ADAPTIVE_LINK) != 0)    /**< Define macro for BIOS opcode auto adapt */
#define BIOS_OP_CFG_SRIOV_ENABLE(op_code_val) (((op_code_val) & NIC_NVM_DATA_SRIOV_CONTROL) != 0)    /**< Define macro for BIOS opcode SR-IOV enable */
#define BIOS_OP_CFG_EXTEND_MODE(op_code_val)  (((op_code_val) & NIC_NVM_DATA_EXTEND_MODE) != 0)    /**< Define macro for BIOS opcode extended mode */
#define BIOS_OP_CFG_RST_DEF_SET(op_code_val)  (((op_code_val) & (u32)NIC_NVM_DATA_RESET) != 0)    /**< Define macro for BIOS opcode reset default settings */

#define ENHANCED_CMDQ_CTX_SIZE 0x30     /**< Define enhanced cmdq context size as 48 */

#define FLOW_BIFURCATE_BIT  (1U << 10) /* 1872 flow bifurcate bit is 10 */

#define HINIC5_LRO_DEFAULT_COAL_PKT_SIZE	32
#define HINIC5_LRO_DEFAULT_TIME_LIMIT		16

#define HINIC5_SET_PORT_CAR_PROFILE 0
#define HINIC5_SET_PORT_CAR_STATE 1
#define HINIC5_GET_PORT_CAR_LIMIT_SPEED 2

#define HINIC5_SET_CAR_PROFILE 0
#define HINIC5_GET_CAR_PROFILE 1

#define HINIC5_FUNC_CAR_ID_OFFSET 16

#define HINIC5_HTN_CMD_SET_CAR    0x26
#define HINIC5_HTN_CMD_GET_CAR    0x27

#define CAR_PROFILE_SIZE 	32
#define CAR_INDEX_UNIT		16

#define NIC_MPU_LT_RD_NOT_SUPPORT_ERROR 253
#define NIC_MPU_LT_OPERA_RANGE_ERROR 254

#define CMD_QOS_ETS_COS_TC     BIT(0)
#define CMD_QOS_ETS_TC_BW      BIT(1)
#define CMD_QOS_ETS_COS_PRIO   BIT(2)
#define CMD_QOS_ETS_COS_BW     BIT(3)
#define CMD_QOS_ETS_TC_PRIO    BIT(4)

#define CMD_QOS_PORT_TRUST     BIT(0)
#define CMD_QOS_PORT_DFT_COS   BIT(1)

#define CMD_QOS_MAP_PCP2COS     BIT(0)
#define CMD_QOS_MAP_DSCP2COS    BIT(1)

#define STD_SFP_INFO_MAX_SIZE 640

#define HINIC5_PF_SET_VF_ALREADY 0x4

typedef enum {
	HINIC5_GET_CNT = 0,
	HINIC5_GET_CNT_RES,
	HINIC5_ADD_CNT,
	HINIC5_DEL_CNT,
	HINIC5_DEL_ALL_CNT,
	HINIC5_RESET_CNT,
	HINIC5_RESET_ALL_CNT,
	HINIC5_NIC_OP_MAX,
} nic_cnt_op_e;

#define VEB_OFFLOAD_QUERY      0
#define VEB_OFFLOAD_SET        1
#define VEB_OFFLOAD_STATUS_OFF      0
#define VEB_OFFLOAD_STATUS_ON       1
#define VEB_OFFLOAD_STATUS_INVALID  2

enum hinic5_port_car_type {
	HINIC5_PORT_CAR_TYPE_PORT = 0,
	HINIC5_PORT_CAR_TYPE_FUNC,
	HINIC5_PORT_CAR_TYPE_VNIC_GROUP,
};

enum hinic5_port_car_pkt_type {
	HINIC5_PORT_CAR_PKT_TYPE_TCP = 0,
	HINIC5_PORT_CAR_PKT_TYPE_UDP,
	HINIC5_PORT_CAR_PKT_TYPE_ARP,
	HINIC5_PORT_CAR_PKT_TYPE_ICMP,
	HINIC5_PORT_CAR_PKT_TYPE_MAX,
};

enum hinic5_port_car_level {
	HINIC5_PORT_CAR_LEVEL_256M = 0,
	HINIC5_PORT_CAR_LEVEL_500M,
	HINIC5_PORT_CAR_LEVEL_1G,
	HINIC5_PORT_CAR_LEVEL_2G,
	HINIC5_PORT_CAR_LEVEL_INVALID_NUM = 0xFF,
};

typedef enum {
	NIC_SOFT_LRO_EN_OPERATE = 0,   /* Software LRO enable operation */
	NIC_HW_LRO_LEN_OPERATE,        /* Hardware LRO coalesce length operation */
	NIC_HW_LRO_NUM_OPERATE,        /* Hardware LRO coalesce count operation */
	NIC_HW_LRO_TIMER_OPERATE,      /* Hardware LRO coalesce time operation */
	NIC_LRO_CFG_OPERATE_MAX
} lro_cfg_operate_type_u;

struct cmd_mac_info_set_s {
	struct mgmt_msg_head head;

	u16 is_valid;
	u16 rsvd0;
	u8 mac_addr[ETH_ALEN];
	u8 rsvd1[2];
};

#endif
