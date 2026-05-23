/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_cfg_comm.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : nic config common header file
 */



#ifndef NIC_CFG_COMM_H
#define NIC_CFG_COMM_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#endif

#include "nic_mpu_cmd_structs.h"
#include "nic_mpu_cmd_structs_extend.h"
/* rss */
#define HINIC5_RSS_TYPE_VALID_SHIFT 23 /**< RSS type valid bit shift */
#define HINIC5_RSS_TYPE_TCP_IPV6_EXT_SHIFT 24 /**< RSS type TCP IPv6 extension shift */
#define HINIC5_RSS_TYPE_IPV6_EXT_SHIFT 25 /**< RSS type IPv6 extension header shift */
#define HINIC5_RSS_TYPE_TCP_IPV6_SHIFT 26 /**< RSS type TCP IPv6 shift */
#define HINIC5_RSS_TYPE_IPV6_SHIFT 27 /**< RSS type IPv6 shift */
#define HINIC5_RSS_TYPE_TCP_IPV4_SHIFT 28 /**< RSS type TCP IPv4 shift */
#define HINIC5_RSS_TYPE_IPV4_SHIFT 29 /**< RSS type IPv4 shift */
#define HINIC5_RSS_TYPE_UDP_IPV6_SHIFT 30 /**< RSS type UDP IPv6 shift */
#define HINIC5_RSS_TYPE_UDP_IPV4_SHIFT 31 /**< RSS type UDP IPv4 shift */

/* vlan */
#define NIC_CVLAN_INSERT_ENABLE 0x1
#define NIC_QINQ_INSERT_ENABLE  0x3
#define NIC_CONFIG_ALL_QUEUE_VLAN_CTX 0xffff

/**
 * @brief Macro for setting RSS type
 * @param val value to set
 * @param member member to set
 * @return result after setting
 */
#define HINIC5_RSS_TYPE_SET(val, member) (((u32)(val) & 0x1) << HINIC5_RSS_TYPE_##member##_SHIFT)
/**
 * @brief Macro for getting RSS type
 * @param val value to get
 * @param member member to get
 * @return result after getting
 */
#define HINIC5_RSS_TYPE_GET(val, member) (((u32)(val) >> HINIC5_RSS_TYPE_##member##_SHIFT) & 0x1)

/**
 * @brief RSS hash type enum definition
 * @details This enum represents the NIC RSS hash type
 */
enum nic_rss_hash_type {
	NIC_RSS_HASH_TYPE_XOR = 0,  /**< XOR hash type */
	NIC_RSS_HASH_TYPE_TOEP,     /**< TOEP hash type */

	NIC_RSS_HASH_TYPE_MAX       /**< MUST BE THE LAST ONE */
};

/**
 * @brief CQE compact scenario ucode reported csum_err type enum
 * @details In CQE compact scenario, csum_err in CQE is compressed from 9bit to 2bit, with driver coordination as follows:
 * NIC_RX_CSUM_IPSU_OTHER_ERR: non-CQE-compact csum_err bit[8] != 0 ---> CQE compact csum_err = 2
 * NIC_RX_CSUM_HW_BYPASS_ERR: non-CQE-compact csum_err bit[7] != 0 ---> CQE compact csum_err = 3
 * l3 or l4 layer packet csum error: non-CQE-compact csum_err bit[0]~bit[6] != 0 ---> CQE compact csum_err = 1
 */
enum nic_compact_cqe_csum_err_type {
	NIC_RX_COMPACT_CSUM_NO_ERROR = 0,
	NIC_RX_COMPACT_L3_L4_CSUM_ERROR,
	NIC_RX_COMPACT_CSUM_OTHER_ERROR,
	NIC_RX_COMPACT_HW_BYPASS_ERROR
};

#define NIC_RSS_INDIR_SIZE      256     /**< RSS indirect table size */
#define NIC_RSS_KEY_SIZE        40      /**< RSS key size */

/* *
 * Definition of the NIC receiving mode
 */
#define NIC_RX_MODE_UC          0x01 /**< unicast mode */
#define NIC_RX_MODE_MC          0x02 /**< multicast mode */
#define NIC_RX_MODE_BC          0x04 /**< broadcast mode */
#define NIC_RX_MODE_MC_ALL      0x08 /**< all multicast mode */
#define NIC_RX_MODE_PROMISC     0x10 /**< promiscuous mode, receive all packets */

/* IEEE 802.1Qaz std */
#define NIC_DCB_DSCP_NUM        0x8 /**< NIC DCB max DSCP value */
#define NIC_DCB_IP_PRI_MAX      0x40    /**< NIC DCB max IP priority */

#define NIC_DCB_PRIO_DWRR       0x0 /**< Priority allocation by strict bandwidth */
#define NIC_DCB_PRIO_STRICT     0x1 /**< Priority allocation by strict priority */

#define NIC_DCB_MAX_PFC_NUM     0x4 /**< Max priority flow control (PFC) number */

#ifndef ETH_ALEN
#define ETH_ALEN 6  /**< Single MAC address length */
#endif

#ifndef BIT
/**
 * @brief Macro to left shift a number by n bits in binary form
 * @param n number of bits to shift
 * @return result after left shifting by n bits
 */
#define BIT(n) (1UL << (n))
#endif

/**
 * @brief NIC feature capability enum definition
 *
 * @details Enum nic_feature_cap defines various feature capabilities of NIC.
 *          Each enum value is a BIT mask position, which can be set or checked via bit operations.
 */

enum nic_feature_cap {
	NIC_F_CSUM_BIT = 0,                    /**< checksum calculation */
	NIC_F_SCTP_CRC_BIT = 1,                /**< SCTP CRC check */
	NIC_F_TSO_BIT = 2,                     /**< TCP Segmentation Offload */
	NIC_F_LRO_BIT = 3,                     /**< Large Receive Offload */
	NIC_F_UFO_BIT = 4,                     /**< UDP Fragmentation Offload */
	NIC_F_RSS_BIT = 5,                     /**< Receive Side Scaling */
	NIC_F_RX_VLAN_FILTER_BIT = 6,          /**< receive VLAN filter */
	NIC_F_RX_VLAN_STRIP_BIT = 7,           /**< receive VLAN strip */
	NIC_F_TX_VLAN_INSERT_BIT = 8,          /**< transmit VLAN insert */
	NIC_F_VXLAN_OFFLOAD_BIT = 9,           /**< VXLAN Offload */
	NIC_F_IPSEC_OFFLOAD_BIT = 10,          /**< IPsec Offload */
	NIC_F_FDIR_BIT = 11,                   /**< Flow Director */
	NIC_F_PROMISC_BIT = 12,                /**< promiscuous mode */
	NIC_F_ALLMULTI_BIT = 13,               /**< receive all multicast */
	NIC_F_XSFP_REPORT_BIT = 14,            /**< XSFP status report */
	NIC_F_VF_MAC_BIT = 15,                 /**< virtual function MAC address */
	NIC_F_RATE_LIMIT_BIT = 16,             /**< rate limit */
	NIC_F_RXQ_RECOVERY_BIT = 17,           /**< receive queue recovery */
	NIC_F_PTP_1588_V2_BIT = 18,            /**< PTP 1588v2 */
	NIC_F_TX_WQE_COMPACT_TASK_BIT = 19,    /**< transmit WQE compact */
	NIC_F_RX_HW_COMPACT_CQE_BIT = 20,      /**< HTN compact CQE */
	NIC_F_HTN_CMDQ_BIT = 21,               /**< HTN command queue */
	NIC_F_GENEVE_OFFLOAD_BIT = 22,         /**< Geneve Offload */
	NIC_F_IPXIP_OFFLOAD_BIT = 23,          /**< IPXIP Offload */
	NIC_F_TC_FLOWER_OFFLOAD_BIT = 24,      /**< TCAM flow control offload */
	NIC_F_HTN_FDIR_BIT = 25,               /**< HTN FDIR function */
	NIC_F_SQ_RQ_CI_COALESCE_BIT = 26,      /**< SQ RQ CI coalesce */
	NIC_F_RX_SW_COMPACT_CQE_BIT = 27,      /**< ucode compact CQE */
	NIC_F_HALF_BOND_OFFLOAD_BIT = 28,      /**< half Bond offload */
	NIC_F_MACSEC_OFFLOAD_BIT = 29,         /**< MACSec offload */
	NIC_F_VEB_OFFLOAD_BIT = 30,            /**< VEB offload */
	NIC_F_GET_COUNTER_BY_CMDQ_BIT = 31,    /**< support reading vport counter via CMDQ */
	NIC_F_HTN_CMDQ_CAR_BIT = 32,           /**< support setting CAR rate limit via CMDQ */
	NIC_F_ARP_DUAL_BIT = 33,               /**< support ARP dual transmit */
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
#define NIC_F_RXQ_RECOVERY  NIC_F(RXQ_RECOVERY)
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

#define NIC_F_1823_MASK 0x1FFEF   /**< all 1823 attributes */
#define NIC_F_1825_MASK (NIC_F_CSUM | NIC_F_SCTP_CRC | NIC_F_TSO | NIC_F_LRO | NIC_F_RSS | \
			 NIC_F_RX_VLAN_FILTER | NIC_F_RX_VLAN_STRIP | NIC_F_TX_VLAN_INSERT | \
			 NIC_F_VXLAN_OFFLOAD | NIC_F_IPSEC_OFFLOAD | NIC_F_FDIR | NIC_F_PROMISC | \
			 NIC_F_ALLMULTI | NIC_F_XSFP_REPORT | NIC_F_VF_MAC | NIC_F_RATE_LIMIT | \
			 NIC_F_TX_WQE_COMPACT_TASK | NIC_F_RX_SW_COMPACT_CQE | \
			 NIC_F_HALF_BOND_OFFLOAD | NIC_F_GET_COUNTER_BY_CMDQ)

#define NIC_F_182X_MASK (NIC_F_1823_MASK | NIC_F_1825_MASK) /**< all 182x attributes */

#define NIC_F_1872_PF_MASK (NIC_F_CSUM | NIC_F_SCTP_CRC | NIC_F_TSO | NIC_F_TX_WQE_COMPACT_TASK | \
			    NIC_F_RX_HW_COMPACT_CQE | NIC_F_HTN_CMDQ | NIC_F_PROMISC | \
			    NIC_F_ALLMULTI | NIC_F_VXLAN_OFFLOAD | NIC_F_GENEVE_OFFLOAD |  \
			    NIC_F_IPXIP_OFFLOAD | NIC_F_RX_VLAN_STRIP | NIC_F_TX_VLAN_INSERT | \
			    NIC_F_RSS | NIC_F_RX_VLAN_FILTER | NIC_F_LRO | NIC_F_FDIR | \
			    NIC_F_HTN_FDIR | NIC_F_SQ_RQ_CI_COALESCE | NIC_F_PTP_1588_V2 | \
			    NIC_F_TC_FLOWER_OFFLOAD | NIC_F_MACSEC_OFFLOAD | NIC_F_VEB_OFFLOAD | \
			    NIC_F_RATE_LIMIT | NIC_F_HTN_CMDQ_CAR | NIC_F_ARP_DUAL | \
			    NIC_F_XSFP_REPORT) /**< all 187x PF attributes */

#define NIC_F_1872_VF_MASK (NIC_F_CSUM | NIC_F_SCTP_CRC | NIC_F_TSO | NIC_F_TX_WQE_COMPACT_TASK | \
			    NIC_F_RX_HW_COMPACT_CQE | NIC_F_HTN_CMDQ | NIC_F_ALLMULTI | \
			    NIC_F_VXLAN_OFFLOAD | NIC_F_GENEVE_OFFLOAD | NIC_F_IPXIP_OFFLOAD | \
			    NIC_F_RX_VLAN_STRIP | NIC_F_TX_VLAN_INSERT | NIC_F_RSS | \
			    NIC_F_RX_VLAN_FILTER | NIC_F_LRO | NIC_F_FDIR | NIC_F_HTN_FDIR | \
			    NIC_F_SQ_RQ_CI_COALESCE | NIC_F_TC_FLOWER_OFFLOAD | \
			    NIC_F_MACSEC_OFFLOAD | NIC_F_VEB_OFFLOAD | NIC_F_RATE_LIMIT | \
			    NIC_F_HTN_CMDQ_CAR | NIC_F_ARP_DUAL) /**< all 187x VF attributes */

#define NIC_F_1872_MASK (NIC_F_1872_PF_MASK | NIC_F_1872_VF_MASK)
#define NIC_F_ALL_MASK (NIC_F_182X_MASK | NIC_F_1872_MASK)

#define HINIC5_TCAM_BLOCK_ENABLE      1 /**< TCAM block enable */
#define HINIC5_TCAM_BLOCK_DISABLE     0 /**< TCAM block disable */
#define HINIC5_MAX_TCAM_RULES_NUM   4096 /**< TCAM max rules number */

/**
 * @brief NIC TCAM block type enum
 * @details This enum contains two types: NIC_TCAM_BLOCK_TYPE_LARGE and NIC_TCAM_BLOCK_TYPE_SMALL.
 *          NIC_TCAM_BLOCK_TYPE_LARGE indicates block size 16, NIC_TCAM_BLOCK_TYPE_SMALL indicates block size 0.
 */
enum {
	NIC_TCAM_BLOCK_TYPE_LARGE = 0, /**< block_size: 16 */
	NIC_TCAM_BLOCK_TYPE_SMALL,     /**< block_size: 0 */
	NIC_TCAM_BLOCK_TYPE_MAX
};

/**
 * @struct hinic5_tcam_key_ipv4_mem
 * @brief IPv4 TCAM key structure
 * @details This structure contains fields for IPv4 TCAM key including reserved bits, tunnel type, IP protocol type, IP type,
 *          Func ID, source IPv4 address, destination IPv4 address, destination port, source port, outer source IPv4 address, outer destination IPv4 address, VNI, etc.
 */
struct hinic5_tcam_key_ipv4_mem {
	u32 rsvd1 : 4; /**< reserved bit 1 */
	u32 tunnel_type : 4; /**< tunnel type */
	u32 ip_proto : 8; /**< IP protocol type */
	u32 rsvd0 : 16; /**< reserved bit 0 */
	u32 sipv4_h : 16; /**< source IPv4 address high 16 bits */
	u32 ip_type : 1; /**< IP type */
	u32 function_id : 15; /**< Func ID */
	u32 dipv4_h : 16; /**< destination IPv4 address high 16 bits */
	u32 sipv4_l : 16; /**< source IPv4 address low 16 bits */
	u32 rsvd2 : 16; /**< reserved bit 2 */
	u32 dipv4_l : 16; /**< destination IPv4 address low 16 bits */
	u32 rsvd3; /**< reserved bit 3 */
	u32 dport : 16; /**< destination port */
	u32 rsvd4 : 16; /**< reserved bit 4 */
	u32 rsvd5 : 16; /**< reserved bit 5 */
	u32 sport : 16; /**< source port */
	u32 outer_sipv4_h : 16; /**< outer source IPv4 address high 16 bits */
	u32 rsvd6 : 16; /**< reserved bit 6 */
	u32 outer_dipv4_h : 16; /**< outer destination IPv4 address high 16 bits */
	u32 outer_sipv4_l : 16; /**< outer source IPv4 address low 16 bits */
	u32 vni_h : 16; /**< VNI high 16 bits */
	u32 outer_dipv4_l : 16; /**< outer destination IPv4 address low 16 bits */
	u32 rsvd7 : 16; /**< reserved bit 7 */
	u32 vni_l : 16; /**< VNI low 16 bits */
};

/**
 * @struct hinic5_tcam_key_ipv6_mem
 * @brief IPv6 TCAM key structure
 * @details This structure stores IPv6 TCAM key including source and destination IPv6 address parts,
 *          and related protocol type, port number, etc.
 */
struct hinic5_tcam_key_ipv6_mem {
	u32 rsvd1 : 3; /**< reserved bit 1 */
	u32 outer_ip_type : 1; /**< outer IP type */
	u32 tunnel_type : 4; /**< tunnel type */
	u32 ip_proto : 8; /**< IP protocol type */
	u32 rsvd0 : 16; /**< reserved bit 0 */
	u32 sipv6_key0 : 16; /**< source IPv6 address low 16 bits */
	u32 ip_type : 1; /**< IP type */
	u32 function_id : 15; /**< function ID */
	u32 sipv6_key2 : 16; /**< source IPv6 address part 2 */
	u32 sipv6_key1 : 16; /**< source IPv6 address part 1 */
	u32 sipv6_key4 : 16; /**< source IPv6 address part 4 */
	u32 sipv6_key3 : 16; /**< source IPv6 address part 3 */
	u32 sipv6_key6 : 16; /**< source IPv6 address part 6 */
	u32 sipv6_key5 : 16; /**< source IPv6 address part 5 */
	u32 dport : 16; /**< destination port */
	u32 sipv6_key7 : 16; /**< source IPv6 address part 7 */
	u32 dipv6_key0 : 16; /**< destination IPv6 address low 16 bits */
	u32 sport : 16; /**< source port */
	u32 dipv6_key2 : 16; /**< destination IPv6 address part 2 */
	u32 dipv6_key1 : 16; /**< destination IPv6 address part 1 */
	u32 dipv6_key4 : 16; /**< destination IPv6 address part 4 */
	u32 dipv6_key3 : 16; /**< destination IPv6 address part 3 */
	u32 dipv6_key6 : 16; /**< destination IPv6 address part 6 */
	u32 dipv6_key5 : 16; /**< destination IPv6 address part 5 */
	u32 rsvd2 : 16; /**< reserved bit 2 */
	u32 dipv6_key7 : 16; /**< destination IPv6 address part 7 */
};

/**
 * @struct hinic5_tcam_key_vxlan_ipv6_mem
 * @brief VXLAN IPv6 TCAM key structure
 * @details This structure contains fields for VXLAN IPv6 TCAM key including reserved bits, tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_vxlan_ipv6_mem {
	u32 rsvd1 : 4; /**< reserved bit 1 */
	u32 tunnel_type : 4; /**< tunnel type */
	u32 ip_proto : 8; /**< IP protocol type */
	u32 rsvd0 : 16; /**< reserved bit 0 */

	u32 dipv6_key0 : 16; /**< IPv6 destination address low 16 bits */
	u32 ip_type : 1; /**< IP type */
	u32 function_id : 15; /**< function ID */

	u32 dipv6_key2 : 16; /**< IPv6 destination address part 2 */
	u32 dipv6_key1 : 16; /**< IPv6 destination address part 1 */

	u32 dipv6_key4 : 16; /**< IPv6 destination address part 4 */
	u32 dipv6_key3 : 16; /**< IPv6 destination address part 3 */

	u32 dipv6_key6 : 16; /**< IPv6 destination address part 6 */
	u32 dipv6_key5 : 16; /**< IPv6 destination address part 5 */

	u32 dport : 16; /**< destination port */
	u32 dipv6_key7 : 16; /**< IPv6 destination address part 7 */

	u32 rsvd2 : 16; /**< reserved bit 2 */
	u32 sport : 16; /**< source port */

	u32 outer_sipv4_h : 16; /**< outer source IPv4 address high 16 bits */
	u32 rsvd3 : 16; /**< reserved bit 3 */

	u32 outer_dipv4_h : 16; /**< outer destination IPv4 address high 16 bits */
	u32 outer_sipv4_l : 16; /**< outer source IPv4 address low 16 bits */

	u32 vni_h : 16; /**< VXLAN network ID high 16 bits */
	u32 outer_dipv4_l : 16; /**< outer destination IPv4 address low 16 bits */

	u32 rsvd4 : 16; /**< reserved bit 4 */
	u32 vni_l : 16; /**< VXLAN network ID low 16 bits */
};

/**
 * @struct hinic5_tcam_key_mem_htn
 * @brief HTN TCAM key structure
 * @details This structure contains fields for HTN TCAM key including reserved bits, tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_mem_htn {
	u32 function_id_h : 5; /**< function id high 5 bits */
	u32 tunnel_type : 3;   /**< tunnel type */
	u32 ip_proto : 8;      /**< IP protocol type */
	u32 rsvd0 : 16;        /**< reserved 16 bits */

	u32 outer_sipv4_h : 16; /**< outer source IPv4 high 16 bits */
	u32 rsvd1 : 8;          /**< reserved 8 bits */
	u32 outer_ip_type : 1;  /**< outer IP type */
	u32 ip_type : 2;        /**< IP type */
	u32 function_id_l : 5;  /**< function id low 5 bits */

	u32 outer_dipv4_h : 16; /**< outer destination IPv4 high 16 bits */
	u32 outer_sipv4_l : 16; /**< outer source IPv4 low 16 bits */

	u32 vni_h : 8; /**< high 8 bits virtual network identifier */
	u32 rsvd2 : 8; /**< reserved 8 bits */
	u32 outer_dipv4_l : 16; /**< outer destination IPv4 low 16 bits */

	u32 sipv4_h : 16; /**< source IPv4 high 16 bits */
	u32 vni_l : 16;   /**< low 8 bits virtual network identifier */

	u32 rsvd5 : 16; /**< reserved 16 bits */
	u32 sipv4_l : 16; /**< source IPv4 low 16 bits */

	u32 rsvd6; /**< reserved */
	u32 rsvd7; /**< reserved */

	u32 dipv4_h : 16; /**< destination IPv4 high 16 bits */
	u32 rsvd8 : 16;   /**< reserved 16 bits */

	u32 sport : 16; /**< source port */
	u32 dipv4_l : 16; /**< destination IPv4 low 16 bits */

	u32 rsvd9 : 16; /**< reserved 16 bits */
	u32 dport : 16; /**< destination port */
};

/**
 * @struct hinic5_tcam_key_ipv6_mem_htn
 * @brief HTN IPv6 TCAM key structure
 * @details This structure contains fields for HTN IPv6 TCAM key including reserved bits, tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_ipv6_mem_htn {
	u32 function_id_h : 5;  /**< function id high 5 bits */
	u32 tunnel_type : 3;    /**< tunnel type */
	u32 ip_proto : 8;       /**< IP protocol type */
	u32 rsvd0 : 16;         /**< reserved 16 bits */

	u32 sipv6_key0 : 16; /**< source IPv6 part 1 */
	u32 rsvd1 : 8; /**< reserved field 1, unused */
	u32 outer_ip_type : 1; /**< outer IP type, 1 bit */
	u32 ip_type : 2; /**< IP type, 2 bits */
	u32 function_id_l : 5; /**< function id low 5 bits */

	u32 sipv6_key2 : 16; /**< source IPv6 part 2 */
	u32 sipv6_key1 : 16; /**< source IPv6 part 1 */

	u32 sipv6_key4 : 16; /**< source IPv6 part 4 */
	u32 sipv6_key3 : 16; /**< source IPv6 part 3 */

	u32 sipv6_key6 : 16; /**< source IPv6 part 6 */
	u32 sipv6_key5 : 16; /**< source IPv6 part 5 */

	u32 dipv6_key0 : 16; /**< destination IPv6 part 1 */
	u32 sipv6_key7 : 16; /**< source IPv6 part 7 */

	u32 dipv6_key2 : 16; /**< destination IPv6 part 2 */
	u32 dipv6_key1 : 16; /**< destination IPv6 part 1 */

	u32 dipv6_key4 : 16; /**< destination IPv6 part 4 */
	u32 dipv6_key3 : 16; /**< destination IPv6 part 3 */

	u32 dipv6_key6 : 16; /**< destination IPv6 part 6 */
	u32 dipv6_key5 : 16; /**< destination IPv6 part 5 */

	u32 sport : 16; /**< source port */
	u32 dipv6_key7 : 16; /**< destination IPv6 part 7 */

	u32 rsvd2 : 16; /**< reserved field 2, unused */
	u32 dport : 16; /**< destination port */
};

/**
 * @struct hinic5_tcam_key_vxlan_ipv6_mem_htn
 * @brief HTN VXLAN IPv6 TCAM key structure
 * @details This structure contains fields for HTN VXLAN IPv6 TCAM key including reserved bits, tunnel type, IP protocol type, etc.
 */
struct hinic5_tcam_key_vxlan_ipv6_mem_htn {
	u32 function_id_h : 5; /**< function id high 5 bits */
	u32 tunnel_type : 3;  /**< tunnel type */
	u32 ip_proto : 8;     /**< IP protocol */
	u32 rsvd0 : 16;       /**< reserved 16 bits */

	u32 outer_sipv4_h : 16; /**< outer source IPv4 address high 16 bits */
	u32 rsvd1 : 8;         /**< reserved 8 bits */
	u32 outer_ip_type : 1; /**< outer IP type */
	u32 ip_type : 2;       /**< IP type */
	u32 function_id_l : 5; /**< function id low 5 bits */

	u32 outer_dipv4_h : 16; /**< outer destination IPv4 address high 16 bits */
	u32 outer_sipv4_l : 16; /**< outer source IPv4 address low 16 bits */

	u32 vni_h : 8; /**< high 8 bits virtual network identifier */
	u32 rsvd2 : 8; /**< reserved 8 bits */
	u32 outer_dipv4_l : 16; /**< outer destination IPv4 address low 16 bits */

	u32 rsvd3 : 16; /**< reserved 16 bits */
	u32 vni_l : 16; /**< low 16 bits virtual network identifier */

	u32 dipv6_key0 : 16; /**< destination IPv6 address part 0 */
	u32 rsvd4 : 16;      /**< reserved 16 bits */

	u32 dipv6_key2 : 16; /**< destination IPv6 address part 2 */
	u32 dipv6_key1 : 16; /**< destination IPv6 address part 1 */

	u32 dipv6_key4 : 16; /**< destination IPv6 address part 4 */
	u32 dipv6_key3 : 16; /**< destination IPv6 address part 3 */

	u32 dipv6_key6 : 16; /**< destination IPv6 address part 6 */
	u32 dipv6_key5 : 16; /**< destination IPv6 address part 5 */

	u32 sport : 16; /**< source port */
	u32 dipv6_key7 : 16; /**< destination IPv6 address part 7 */

	u32 rsvd5 : 16; /**< reserved 16 bits */
	u32 dport : 16; /**< destination port */
};

/**
 * @struct tcam_key_ctrl_mem
 * @brief HTN control packet TCAM key structure
 * @details This structure contains fields for HTN VXLAN IPv6 TCAM key including reserved bits, tunnel type, IP protocol type, etc.
 */
struct tcam_key_ctrl_mem {
	u32 function_id1 : 5;   /**< function id high 5 bits */
	u32 pkt_fmt : 3;    /**< packet format */
	u32 packet_type : 8;    /**< packet type */
	u32 rsvd0 : 16;     /**< reserved field 0 */

	u32 rsvd2 : 16;     /**< reserved field 2 */
	u32 rsvd1 : 8;      /**< reserved field 1 */
	u32 outer_type : 1;     /**< outer type */
	u32 inner_type : 2;     /**< inner type */
	u32 function_id2 : 5;   /**< function id low 5 bits */

	u32 rsvd3;      /**< reserved field 3 */
	u32 rsvd4;      /**< reserved field 4 */
	u32 rsvd5;      /**< reserved field 5 */
	u32 rsvd6;      /**< reserved field 6 */
	u32 rsvd7;      /**< reserved field 7 */
	u32 rsvd8;      /**< reserved field 8 */
	u32 rsvd9;      /**< reserved field 9 */
	u32 rsvd10;     /**< reserved field 10 */
	u32 rsvd11;     /**< reserved field 11 */
};

/**
 * @struct tag_tcam_key
 * @brief TCAM key structure for storing TCAM key information and mask
 * @details This structure contains two unions for storing IPv4 key information and mask respectively.
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

#define TCAM_RULE_FDIR_TYPE 0 /**< TCAM rule type, FDIR type value is 0 */
#define TCAM_RULE_PPA_TYPE  1 /**< TCAM rule type, PPA type value is 1 */
#define TCAM_RULE_BIFURCATION_TYPE  2 /**< TCAM rule type, BIFURCATION type value is 2 */

/**
 * @struct hinic5_phy_fpga_port_stats
 * @brief PHY FPGA port statistics structure
 * @details This structure stores PHY FPGA port statistics
 */
struct hinic5_phy_fpga_port_stats {
	u64 mac_rx_total_octs_port; /**< total received bytes */
	u64 mac_tx_total_octs_port; /**< total transmitted bytes */
	u64 mac_rx_under_frame_pkts_port; /**< received frames with length less than 64 bytes */
	u64 mac_rx_frag_pkts_port; /**< received fragment packets */
	u64 mac_rx_64_oct_pkts_port; /**< received 64-byte packets */
	u64 mac_rx_127_oct_pkts_port; /**< received 127-byte packets */
	u64 mac_rx_255_oct_pkts_port; /**< received 255-byte packets */
	u64 mac_rx_511_oct_pkts_port; /**< received 511-byte packets */
	u64 mac_rx_1023_oct_pkts_port; /**< received 1023-byte packets */
	u64 mac_rx_max_oct_pkts_port; /**< received max length packets */
	u64 mac_rx_over_oct_pkts_port; /**< received oversized packets */
	u64 mac_tx_64_oct_pkts_port; /**< transmitted 64-byte packets */
	u64 mac_tx_127_oct_pkts_port; /**< transmitted 127-byte packets */
	u64 mac_tx_255_oct_pkts_port; /**< transmitted 255-byte packets */
	u64 mac_tx_511_oct_pkts_port; /**< transmitted 511-byte packets */
	u64 mac_tx_1023_oct_pkts_port; /**< transmitted 1023-byte packets */
	u64 mac_tx_max_oct_pkts_port; /**< transmitted max length packets */
	u64 mac_tx_over_oct_pkts_port; /**< transmitted oversized packets */
	u64 mac_rx_good_pkts_port; /**< received good packets */
	u64 mac_rx_crc_error_pkts_port; /**< received CRC error packets */
	u64 mac_rx_broadcast_ok_port; /**< received broadcast packets */
	u64 mac_rx_multicast_ok_port; /**< received multicast packets */
	u64 mac_rx_mac_frame_ok_port; /**< received MAC frame packets */
	u64 mac_rx_length_err_pkts_port; /**< received length error packets */
	u64 mac_rx_vlan_pkts_port; /**< received VLAN packets */
	u64 mac_rx_pause_pkts_port; /**< received pause packets */
	u64 mac_rx_unknown_mac_frame_port; /**< received unknown MAC frame packets */
	u64 mac_tx_good_pkts_port; /**< transmitted good packets */
	u64 mac_tx_broadcast_ok_port; /**< transmitted broadcast packets */
	u64 mac_tx_multicast_ok_port; /**< transmitted multicast packets */
	u64 mac_tx_underrun_pkts_port; /**< transmitted underrun packets */
	u64 mac_tx_mac_frame_ok_port; /**< transmitted MAC frame packets */
	u64 mac_tx_vlan_pkts_port; /**< transmitted VLAN packets */
	u64 mac_tx_pause_pkts_port; /**< transmitted pause packets */
};

/**
 * @struct hinic5_port_stats
 * @brief hinic5 port statistics structure
 * @details This structure contains management message header and physical port statistics
 */
struct hinic5_port_stats {
	struct hinic5_mgmt_msg_head msg_head;   /**< management message header */

	struct hinic5_phy_fpga_port_stats stats;    /**< physical port statistics */
};

/**
 * @struct hinic5_rss_indir_table
 * @brief RSS indirect table structure
 * @details This structure stores RSS information including management message header, function ID, reserved field and indirect table.
 */
struct hinic5_rss_indir_table {
	struct hinic5_mgmt_msg_head msg_head;   /**< management message header */

	u16 func_id;    /**< func id */
	u16 rsvd1;  /**< reserved field 1 */
	u8 indir[NIC_RSS_INDIR_SIZE];   /**< indirect table */
};

#define NIC_RSS_CMD_TEMP_ALLOC 0x01     /**< temporary RSS resource allocation */
#define NIC_RSS_CMD_TEMP_FREE 0x02      /**< temporary RSS resource release */

/**
 * @struct hinic5_func_tbl_cfg_bitmap
 * @brief function table configuration bitmap structure
 * @details This structure represents function table configuration bitmap including init config, RX buffer size config and MTU config.
 */
enum hinic5_func_tbl_cfg_bitmap {
	FUNC_CFG_INIT,              /**< init config */
	FUNC_CFG_RX_BUF_SIZE,       /**< RX buffer size config */
	FUNC_CFG_MTU,               /**< max transmission unit config */
	FUNC_CFG_ISOLATION_VF_MAC,    /**< cluster mode VF MAC config */
	FUNC_CFG_ISOLATION_VF_SVLAN,    /**< cluster mode VF SVLAN config */
};

typedef struct mac_table_cnt {
	u32 valid_table_cnt;  /**< valid MAC table count */
	u32 mac_table_cnt;    /**< max supported MAC table count */
	u16 uc_mac_cnt;       /**< unicast count */
	u16 mc_mac_cnt;       /**< multicast count */
} mac_table_cnt_s;

#define NIC_FUNC_MAX_NUM 4096
typedef struct mac_table_res_stat {
	u16 uc_mac_cnt;                               /**< unicast table resource usage */
	u16 mc_mac_cnt;                               /**< multicast table resource usage */
	u16 share_mac_res_cur_cnt;                    /**< current shared resource pool usage */
	u16 share_mac_res_total;                      /**< shared resource pool total size */
	u16 func_uc_mac_cnt[NIC_FUNC_MAX_NUM];        /**< Func level unicast table resource usage */
} mac_table_res_stat_s;

#define HINIC5_CMD_OP_SET	1   /**< cmd operation type set */
#define HINIC5_CMD_OP_GET	0   /**< cmd operation type get */

#define HINIC5_CMD_OP_ADD	1   /**< cmd operation type add */
#define HINIC5_CMD_OP_DEL	0   /**< cmd operation type del */

/**
 * @brief command type enum for different command types
 * @details This enum defines a series of command types for different contexts.
 */
enum {
	PPA_TABLE_ID_CLEAN_CMD = 0, /**< clean PPA table command*/
	PPA_TABLE_ID_ADD_CMD,   /**< add PPA table command*/
	PPA_TABLE_ID_DEL_CMD,   /**< delete PPA table command*/
	FDIR_TABLE_ID_ADD_CMD,  /**< add FDIR table command*/
	FDIR_TABLE_ID_DEL_CMD,  /**< delete FDIR table command*/
	PPA_TABEL_ID_MAX    /**< PPA table max value*/
};

/**
 * @brief NIC NVM data type enum
 * @details This enum contains multiple flags, each representing a type of NIC NVM data.
 */
enum {
	NIC_NVM_DATA_SET = BIT(0), /**< 1-save, 0-read */
	NIC_NVM_DATA_PXE = BIT(1),  /**< PXE */
	NIC_NVM_DATA_VLAN = BIT(2), /**< VLAN */
	NIC_NVM_DATA_VLAN_PRI = BIT(3), /**< VLAN PRI */
	NIC_NVM_DATA_VLAN_ID = BIT(4),  /**< VLAN ID */
	NIC_NVM_DATA_WORK_MODE = BIT(5),    /**< work mode */
	NIC_NVM_DATA_PF_SPEED_LIMIT = BIT(6),   /**< PF speed limit */
	NIC_NVM_DATA_GE_MODE = BIT(7),  /**< GE mode */
	NIC_NVM_DATA_AUTO_NEG = BIT(8), /**< AUTO NEG */
	NIC_NVM_DATA_LINK_FEC = BIT(9), /**< LINK FEC */
	NIC_NVM_DATA_PF_ADAPTIVE_LINK = BIT(10),    /**< PF adaptive link */
	NIC_NVM_DATA_SRIOV_CONTROL = BIT(11),   /**< SRIOV CONTROL */
	NIC_NVM_DATA_EXTEND_MODE = BIT(12), /**< extend mode */
	NIC_NVM_DATA_RESET = BIT(31),   /**< RESET */
};

#define BIOS_CFG_SIGNATURE                  0x1923E518    /**< BIOS config signature */
#define BIOS_OP_CFG_ALL(op_code_val)        ((((op_code_val) >> 1) & (0xFFFFFFFF)) != 0)    /**< BIOS op code all config macro */
#define BIOS_OP_CFG_WRITE(op_code_val)      ((((op_code_val) & NIC_NVM_DATA_SET)) != 0)    /**< BIOS op code write config macro */
#define BIOS_OP_CFG_PXE_EN(op_code_val)     (((op_code_val) & NIC_NVM_DATA_PXE) != 0)    /**< BIOS op code PXE enable macro */
#define BIOS_OP_CFG_VLAN_EN(op_code_val)    (((op_code_val) & NIC_NVM_DATA_VLAN) != 0)    /**< BIOS op code VLAN enable macro */
#define BIOS_OP_CFG_VLAN_PRI(op_code_val)   (((op_code_val) & NIC_NVM_DATA_VLAN_PRI) != 0)    /**< BIOS op code VLAN priority macro */
#define BIOS_OP_CFG_VLAN_ID(op_code_val)    (((op_code_val) & NIC_NVM_DATA_VLAN_ID) != 0)    /**< BIOS op code VLAN ID macro */
#define BIOS_OP_CFG_WORK_MODE(op_code_val)  (((op_code_val) & NIC_NVM_DATA_WORK_MODE) != 0)    /**< BIOS op code work mode macro */
#define BIOS_OP_CFG_PF_BW(op_code_val)      (((op_code_val) & NIC_NVM_DATA_PF_SPEED_LIMIT) != 0)    /**< BIOS op code PF bandwidth macro */
#define BIOS_OP_CFG_GE_SPEED(op_code_val)   (((op_code_val) & NIC_NVM_DATA_GE_MODE) != 0)    /**< BIOS op code GE speed macro */
#define BIOS_OP_CFG_AUTO_NEG(op_code_val)   (((op_code_val) & NIC_NVM_DATA_AUTO_NEG) != 0)    /**< BIOS op code auto negotiation macro */
#define BIOS_OP_CFG_LINK_FEC(op_code_val)   (((op_code_val) & NIC_NVM_DATA_LINK_FEC) != 0)    /**< BIOS op code link FEC macro */
#define BIOS_OP_CFG_AUTO_ADPAT(op_code_val) (((op_code_val) & NIC_NVM_DATA_PF_ADAPTIVE_LINK) != 0)    /**< BIOS op code auto adapt macro */
#define BIOS_OP_CFG_SRIOV_ENABLE(op_code_val) (((op_code_val) & NIC_NVM_DATA_SRIOV_CONTROL) != 0)    /**< BIOS op code SR-IOV enable macro */
#define BIOS_OP_CFG_EXTEND_MODE(op_code_val)  (((op_code_val) & NIC_NVM_DATA_EXTEND_MODE) != 0)    /**< BIOS op code extend mode macro */
#define BIOS_OP_CFG_RST_DEF_SET(op_code_val)  (((op_code_val) & (u32)NIC_NVM_DATA_RESET) != 0)    /**< BIOS op code reset default macro */

#define ENHANCED_CMDQ_CTX_SIZE 0x30     /**< enhanced cmdq context size is 48 */

#define FLOW_BIFURCATE_BIT  (1U << 10) /* 1872 flow bifurcation bit is 10 */

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
	NIC_SOFT_LRO_EN_OPERATE = 0,   /* software LRO enable operation */
	NIC_HW_LRO_LEN_OPERATE,        /* hardware LRO aggregation length operation */
	NIC_HW_LRO_NUM_OPERATE,        /* hardware LRO aggregation count operation */
	NIC_HW_LRO_TIMER_OPERATE,      /* hardware LRO aggregation time operation */
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
