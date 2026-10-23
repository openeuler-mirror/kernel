/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_INCLUDE_H_
#define _NBL_INCLUDE_H_

#include <linux/mod_devicetable.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/iopoll.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/ethtool.h>
#include <linux/debugfs.h>
#include <linux/firmware.h>
#include <linux/list.h>
#include <net/ip_tunnels.h>
#include <linux/pldmfw.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/kfifo.h>
#include <net/inet6_hashtables.h>
#include <linux/compiler.h>
#include <linux/netdevice.h>
#include <net/devlink.h>
#include <net/ipv6.h>
#include <net/pkt_cls.h>
#include <net/bonding.h>
#include <linux/if_bridge.h>
#include <linux/rtnetlink.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <uapi/linux/elf.h>
#include <linux/crc32.h>
#include <net/vxlan.h>
#include <net/gre.h>
#include <net/geneve.h>
#include "nbl_compat.h"
#include <linux/nbl/nbl_core_common.h>

/* When the kernel lacks the auxiliary bus (NEED_AUX_BUS=1), this resolves to
 * the vendored backport via -I $(src)/../../../base added by the Makefile.
 */
#include <linux/auxiliary_bus.h>

#include <linux/termios_internal.h>
#if IS_ENABLED(CONFIG_TLS_DEVICE)
#include <net/tls.h>
#endif
#if IS_ENABLED(CONFIG_MACSEC)
#include <net/macsec.h>
#endif

#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>

#include <net/xdp.h>
#include <linux/bpf.h>

#ifndef GIT_COMMIT
#define GIT_COMMIT "unknown"
#endif

/*  ------  Basic definitions  -------  */
#define NBL_DRIVER_NAME					"nbl_core"
#define NBL_REP_DRIVER_NAME				"nbl_rep"
/* "product NO-V NO.R NO.B NO.SP NO"
 * product NO define:
 * 1 reserve for develop branch
 * 2 df200
 * 3 ASIC snic
 * 4 x4
 */
#define NBL_DRIVER_DEV_MAX				24

#define NBL_PAIR_ID_GET_TX(id)				((id) * 2 + 1)
#define NBL_PAIR_ID_GET_RX(id)				((id) * 2)

#define NBL_MAX_PF					8

#define NBL_IPV6_ADDR_LEN_AS_U8				16

#define NBL_P4_NAME_LEN					64

#define NBL_MAC_ADDR_LEN_AS_U8				6
#define NBL_IPV6_ADDR_LEN_AS_U8				16
#define NBL_FLOW_INDEX_BYTE_LEN				8

#define NBL_RATE_MBPS_100G				(100000)
#define NBL_RATE_MBPS_25G				(25000)
#define NBL_RATE_MBPS_10G				(10000)

#define NBL_NEXT_ID(id, max)	({ typeof(id) _id = (id); ((_id) == (max) ? 0 : (_id) + 1); })
#define NBL_IPV6_U32LEN					4
/* macro for counter */
#define NBL_FLOW_COUNT_NUM				8
#define NBL_COUNTER_MAX_STAT_ID				2048
/* counter_id + stat_id */
#define NBL_COUNTER_MAX_ID				(128 * 1024)

#define NBL_TC_MCC_MEMBER_MAX				16

#define NBL_IP_VERSION_V4				4
#define NBL_IP_VERSION_V6				6
#define NBL_MAX_FUNC					(520)
#define NBL_MAX_MTU					15

#define NBL_FRIMWARE_VERSION_LEN			32

#define NBL_MAX_ETHPORTS				516
#define NBL_FLOW_ETH_REP_0				2048
#define NBL_FLOW_ETH_REP_1				2049
#define NBL_FLOW_ETH_REP_2				2050
#define NBL_FLOW_ETH_REP_3				2051
#define NBL_FLOW_BOND_REP_PORT_ID			2052
#define NBL_ETHER_TYPE_IPV4				4
#define NBL_ETHER_TYPE_IPV6				6
#define NBL_FLOW_MAX_REP_ID				0xFFFF

#define NBL_BITS_IN_NIBBLE				(4)
#define NBL_BITS_IN_U8					(8)
#define NBL_BITS_IN_U16					(16)
#define NBL_BITS_IN_U24					(24)
#define NBL_BITS_IN_U32					(32)
#define NBL_BITS_IN_U64					(64)

#define NBL_FLOW_TABLE_IPV4_DEFAULT_MASK		0xFFFFFFFF
#define NBL_FLOW_TABLE_L4_PORT_DEFAULT_MASK		0xFFFF
#define NBL_FLOW_TABLE_FULL_MASK_AS_U32			0xFFFFFFFF
#define NBL_FLOW_TABLE_FULL_MASK_AS_U16			0xFFFF
#define NBL_FLOW_TABLE_FULL_MASK_AS_U8			0xFF
#define NBL_TC_MAX_PED_H_IDX				512

#define NBL_FEM_KT_LEN					320
#define NBL_FEM_KT_HALF_LEN				160

#define NBL_FLOW_TABLE_IPV4_DEFAULT_MASK		0xFFFFFFFF
#define NBL_FLOW_TABLE_L4_PORT_DEFAULT_MASK		0xFFFF
#define NBL_TC_MAX_PED_H_IDX 512

#define NBL_TC_PEDIT_SET_NODE_RES_PRO(node) ((node).pedit_proto = 1)
#define NBL_TC_PEDIT_GET_NODE_RES_PRO(node) ((node).pedit_proto)

#define NBL_TC_PEDIT_INC_NODE_RES_EDITS(node) ((node).pedits++)
#define NBL_TC_PEDIT_DEC_NODE_RES_EDITS(node, dec) ((node).pedits -= dec)

#define NBL_FLOW_TAB_ONE_TIME				1
#define NBL_FLOW_TAB_TWO_TIME				2
#define NBL_INVALID_U32					0xFFFFFFFF

#define NBL_IPV6_ICMPV6_IPPROTO		58
#define NBL_IPV46_SCTP_IPPROTO		132
#define NBL_IPV6_ICMPV6_CODE_PING	0
#define NBL_IPV6_ICMPV6_TYPE_PING_REQ	128
#define NBL_IPV6_ICMPV6_TYPE_PING_REP	129
#define NBL_IPV6_ICMPV6_TYPE_NS		135
#define NBL_IPV6_ICMPV6_TYPE_NA		136

#define NBL_VLAN_PCP_SHIFT		13

/* key element: key flag bitmap */
#define NBL_FLOW_KEY_TABLE_IDX_FLAG			(BIT_ULL(0))
#define NBL_FLOW_KEY_INPORT8_FLAG			(BIT_ULL(1))
#define NBL_FLOW_KEY_INPORT4_FLAG			(BIT_ULL(39))
#define NBL_FLOW_KEY_INPORT2_FLAG			(BIT_ULL(40))	// error
#define NBL_FLOW_KEY_INPORT2L_FLAG			(BIT_ULL(41))	// error
#define NBL_FLOW_KEY_T_DIPV4_FLAG			(BIT_ULL(2))
#define NBL_FLOW_KEY_T_DIPV6_FLAG			(BIT_ULL(3))
#define NBL_FLOW_KEY_T_OPT_DATA_FLAG			(BIT_ULL(4))
#define NBL_FLOW_KEY_T_VNI_FLAG				(BIT_ULL(5))
#define NBL_FLOW_KEY_T_DSTMAC_FLAG			(BIT_ULL(6))// error
#define NBL_FLOW_KEY_T_SRCMAC_FLAG			(BIT_ULL(7))	// error
#define NBL_FLOW_KEY_T_SVLAN_FLAG			(BIT_ULL(8))	// error
#define NBL_FLOW_KEY_T_CVLAN_FLAG			(BIT_ULL(9))	// error
#define NBL_FLOW_KEY_T_ETHERTYPE_FLAG			(BIT_ULL(10))	// error
#define NBL_FLOW_KEY_T_SRCPORT_FLAG			(BIT_ULL(11))
#define NBL_FLOW_KEY_T_DSTPORT_FLAG			(BIT_ULL(12))
#define NBL_FLOW_KEY_T_NPROTO_FLAG			(BIT_ULL(13))	// delete
#define NBL_FLOW_KEY_T_OPT_CLASS_FLAG			(BIT_ULL(14))
#define NBL_FLOW_KEY_T_PROTOCOL_FLAG			(BIT_ULL(15))
#define NBL_FLOW_KEY_T_TCPSTAT_FLAG			(BIT_ULL(16))   // delete
#define NBL_FLOW_KEY_T_TOS_FLAG				(BIT_ULL(17))
#define NBL_FLOW_KEY_T_TTL_FLAG				(BIT_ULL(18))
#define NBL_FLOW_KEY_SIPV4_FLAG				(BIT_ULL(19))
#define NBL_FLOW_KEY_SIPV6_FLAG				(BIT_ULL(20))
#define NBL_FLOW_KEY_DIPV4_FLAG				(BIT_ULL(21))
#define NBL_FLOW_KEY_DIPV6_FLAG				(BIT_ULL(22))
#define NBL_FLOW_KEY_DSTMAC_FLAG			(BIT_ULL(23))
#define NBL_FLOW_KEY_SRCMAC_FLAG			(BIT_ULL(24))
#define NBL_FLOW_KEY_SVLAN_FLAG				(BIT_ULL(25))
#define NBL_FLOW_KEY_CVLAN_FLAG				(BIT_ULL(26))
#define NBL_FLOW_KEY_ETHERTYPE_FLAG			(BIT_ULL(27))
#define NBL_FLOW_KEY_SRCPORT_FLAG			(BIT_ULL(28))
#define NBL_FLOW_KEY_ICMP_TYPE_FLAG			(BIT_ULL(28))
#define NBL_FLOW_KEY_DSTPORT_FLAG			(BIT_ULL(29))
#define NBL_FLOW_KEY_ICMP_CODE_FLAG			(BIT_ULL(29))
#define NBL_FLOW_KEY_ARP_OP_FLAG			(BIT_ULL(30))	// error
#define NBL_FLOW_KEY_ICMPV6_TYPE_FLAG			(BIT_ULL(31))	// error
#define NBL_FLOW_KEY_PROTOCOL_FLAG			(BIT_ULL(32))
#define NBL_FLOW_KEY_TCPSTAT_FLAG			(BIT_ULL(33))
#define NBL_FLOW_KEY_TOS_FLAG				(BIT_ULL(34))
#define NBL_FLOW_KEY_DSCP_FLAG				(BIT_ULL(34))
#define NBL_FLOW_KEY_TTL_FLAG				(BIT_ULL(35))
#define NBL_FLOW_KEY_HOPLIMIT_FLAG			(BIT_ULL(35))
#define NBL_FLOW_KEY_RDMA_ACK_SEQ_FLAG			(BIT_ULL(36))	// error
#define NBL_FLOW_KEY_RDMA_QPN_FLAG			(BIT_ULL(37))	// error
#define NBL_FLOW_KEY_RDMA_OP_FLAG			(BIT_ULL(38))	// error
#define NBL_FLOW_KEY_INPORT4_FLAG			(BIT_ULL(39))
#define NBL_FLOW_KEY_INPORT2_FLAG			(BIT_ULL(40))
#define NBL_FLOW_KEY_INPORT2L_FLAG			(BIT_ULL(41))
#define NBL_FLOW_KEY_INPORT16_FLAG			(BIT_ULL(42))
#define NBL_FLOW_KEY_EXEHASH_FLAG			(BIT_ULL(43))
#define NBL_FLOW_KEY_MARK_IS_TNL			(BIT_ULL(43))
#define NBL_FLOW_KEY_NEED_ACL_FLAG			(BIT_ULL(44))
#define NBL_FLOW_KEY_DPHASH_FLAG			(BIT_ULL(44))
#define NBL_FLOW_KEY_MARK_IS_TCP_UDP			(BIT_ULL(45))
#define NBL_FLOW_KEY_MARK_IS_ICMP_SCTP			(BIT_ULL(46))
#define NBL_FLOW_KEY_RECIRC_FLAG			(BIT_ULL(63))

/* action flag */
#define NBL_FLOW_ACTION_METADATA_FLAG			(BIT_ULL(1))
#define NBL_FLOW_ACTION_DROP				(BIT_ULL(2))
#define NBL_FLOW_ACTION_REDIRECT			(BIT_ULL(3))
#define NBL_FLOW_ACTION_MIRRED				(BIT_ULL(4))
#define NBL_FLOW_ACTION_TUNNEL_ENCAP			(BIT_ULL(5))
#define NBL_FLOW_ACTION_TUNNEL_DECAP			(BIT_ULL(6))
#define NBL_FLOW_ACTION_COUNTER				(BIT_ULL(7))
#define NBL_FLOW_ACTION_SET_IPV4_SRC_IP			(BIT_ULL(8))
#define NBL_FLOW_ACTION_SET_IPV4_DST_IP			(BIT_ULL(9))
#define NBL_FLOW_ACTION_SET_IPV6_SRC_IP			(BIT_ULL(10))
#define NBL_FLOW_ACTION_SET_IPV6_DST_IP			(BIT_ULL(11))
#define NBL_FLOW_ACTION_SET_SRC_MAC			(BIT_ULL(12))
#define NBL_FLOW_ACTION_SET_DST_MAC			(BIT_ULL(13))
#define NBL_FLOW_ACTION_SET_SRC_PORT			(BIT_ULL(14))
#define NBL_FLOW_ACTION_SET_DST_PORT			(BIT_ULL(15))
#define NBL_FLOW_ACTION_SET_TTL				(BIT_ULL(16))
#define NBL_FLOW_ACTION_SET_IPV4_DSCP			(BIT_ULL(17))
#define NBL_FLOW_ACTION_SET_IPV6_DSCP			(BIT_ULL(18))
#define NBL_FLOW_ACTION_RSS				(BIT_ULL(19))
#define NBL_FLOW_ACTION_QUEUE				(BIT_ULL(20))
#define NBL_FLOW_ACTION_MARK				(BIT_ULL(21))
#define NBL_FLOW_ACTION_PUSH_INNER_VLAN			(BIT_ULL(22))
#define NBL_FLOW_ACTION_PUSH_OUTER_VLAN			(BIT_ULL(23))
#define NBL_FLOW_ACTION_POP_INNER_VLAN			(BIT_ULL(24))
#define NBL_FLOW_ACTION_POP_OUTER_VLAN			(BIT_ULL(25))
#define NBL_FLOW_ACTION_REPLACE_INNER_VLAN		(BIT_ULL(26))
#define NBL_FLOW_ACTION_REPLACE_SINGLE_INNER_VLAN	(BIT_ULL(27))
#define NBL_FLOW_ACTION_REPLACE_OUTER_VLAN		(BIT_ULL(28))
#define NBL_FLOW_ACTION_PHY_PORT			(BIT_ULL(29))
#define NBL_FLOW_ACTION_PORT_ID				(BIT_ULL(30))
#define NBL_FLOW_ACTION_INGRESS				(BIT_ULL(31))
#define NBL_FLOW_ACTION_EGRESS				(BIT_ULL(32))
#define NBL_FLOW_ACTION_IPV4				(BIT_ULL(33))
#define NBL_FLOW_ACTION_IPV6				(BIT_ULL(34))
#define NBL_FLOW_ACTION_CAR				(BIT_ULL(35))
#define NBL_FLOW_ACTION_MCC				(BIT_ULL(36))
#define NBL_FLOW_ACTION_MIRRED_ENCAP			(BIT_ULL(37))
#define NBL_FLOW_ACTION_META_RECIRC			(BIT_ULL(38))
#define NBL_FLOW_ACTION_STAT				(BIT_ULL(39))
#define NBL_ACTION_FLAG_OFFSET_MAX			(BIT_ULL(40))

#define NBL_FLOW_TABLE_IPV4_DEFAULT_MASK		0xFFFFFFFF
#define NBL_FLOW_TABLE_VLAN_MASK_AS_U16			0xFFFF
#define NBL_FLOW_TABLE_VLAN_MASK_AS_U12			0xFFF
#define NBL_FLOW_TABLE_FULL_MASK_AS_U8			0xFF
#define NBL_BITS_IN_U8					(8)
#define NBL_U16_MASK					(0xffff)

#define SET_DEV_MIN_MTU(netdev, mtu) ((netdev)->min_mtu = (mtu))
#define SET_DEV_MAX_MTU(netdev, mtu) ((netdev)->max_mtu = (mtu))

#define NBL_USER_DEV_SHMMSGRING_SIZE		(PAGE_SIZE)
#define NBL_USER_DEV_SHMMSGBUF_SIZE		(NBL_USER_DEV_SHMMSGRING_SIZE - 8)

/* Used for macros to pass checkpatch */
#define NBL_NAME(x)					x

#define NBL_SET_INTR_COALESCE(param, tx_usecs, tx_max_frames, rx_usecs, rx_max_frames)	\
do {		\
	typeof(param)		__param = param;			\
	__param->tx_coalesce_usecs = tx_usecs;				\
	__param->tx_max_coalesced_frames = tx_max_frames;		\
	__param->rx_coalesce_usecs = rx_usecs;				\
	__param->rx_max_coalesced_frames = rx_max_frames;		\
} while (0)

enum nbl_product_type {
	NBL_LEONIS_TYPE,
	NBL_DRACO_TYPE,
	NBL_PRODUCT_MAX,
};

enum nbl_flex_cap_type {
	NBL_DUMP_FLOW_CAP,
	NBL_DUMP_FD_CAP,
	NBL_SECURITY_TLS_CAP,
	NBL_SECURITY_IPSEC_CAP,
	NBL_SECURITY_MACSEC_CAP,
	NBL_DUMP_FUNC_INFO_CAP,
	NBL_FLEX_CAP_NBITS
};

enum nbl_fix_cap_type {
	NBL_TASK_OFFLOAD_NETWORK_CAP,
	NBL_TASK_FW_HB_CAP,
	NBL_TASK_FW_RESET_CAP,
	NBL_TASK_CLEAN_ADMINDQ_CAP,
	NBL_TASK_CLEAN_MAILBOX_CAP,
	NBL_TASK_IPSEC_AGE_CAP,
	NBL_TASK_CHECK_PORT_LINK_CAP,
	NBL_ETH_SUPPORT_NRZ_RS_FEC_544,
	NBL_RESTOOL_CAP,
	NBL_TASK_SFP_PLUG_CAP,
	NBL_HWMON_TEMP_CAP,
	NBL_ITR_DYNAMIC,
	NBL_TASK_ADAPT_DESC_GOTHER,
	NBL_MSIX_AUTO_MASK_CAP,
	NBL_P4_CAP,
	NBL_PROCESS_FLR_CAP,
	NBL_PMD_DEBUG,
	NBL_PRIO_STATS_CAP,
	NBL_MSIX_FAST_RESTRAIN_CAP,
	NBL_XDP_CAP,
	NBL_TASK_RESET_CAP,
	NBL_TASK_RESET_CTRL_CAP,
	NBL_QOS_SYSFS_CAP,
	NBL_MIRROR_SYSFS_CAP,
	NBL_HIGH_THROUGHPUT_CAP,
	NBL_TASK_HEALTH_REPORT_TEMP_CAP,
	NBL_TASK_HEALTH_REPORT_REBOOT_CAP,
	NBL_DVN_DESC_REQ_SYSFS_CAP,
	NBL_UDF_EXTRACT_CAP, /* when vlan offload and transparent vlan, ext header VLAN via UDF */
	NBL_MSIX_UNMASK_USE_GLOBAL_CAP,
	NBL_QUEUE_NOTIFY_USE_LOCAL_CAP,
	NBL_RXFH_KEY_SET_CAP,
	NBL_PROMISC_NOT_SUPPORT,
	NBL_NEED_DESTROY_CHIP,
	NBL_INTERLEAVE_SEG_DISABLE,
	NBL_TX_FC_SEGREGATGE_ENABLE,
	NBL_RX_CSUM_ERR_DROP_CAP,
	NBL_XDP_ENHANCE,
	NBL_ABNORMAL_INTR_SYSFS_CAP,
	NBL_DEVSHR_IDX_CAP,
	NBL_RXQ_LARGE_BUF,
	NBL_LINK_DOWN_ON_CLOSE,
	NBL_RESUME_CAP,
	NBL_VLAN_FILTERING_DISABLE_CAP,
	NBL_FIX_CAP_NBITS
};

enum nbl_sfp_module_state {
	NBL_SFP_MODULE_OFF,
	NBL_SFP_MODULE_ON,
};

enum nbl_vsi_type {
	NBL_VSI_DATA = 0,/* default vsi in kernel or independent dpdk */
	NBL_VSI_CTRL,
	NBL_VSI_USER, /* dpdk used vsi in coexist dpdk */
	NBL_VSI_XDP,
	NBL_VSI_MAX,
};

enum {
	NBL_P4_DEFAULT = 0,
	NBL_P4_TYPE_MAX,
};

enum {
	NBL_TX = 0,
	NBL_RX,
};

enum nbl_hw_status {
	NBL_HW_NOMAL,
	NBL_HW_FATAL_ERR, /* Most hw module is not work nomal exclude pcie/emp */
	NBL_HW_PCIE_RESET_ERR, /* pcie link retrainning */
	NBL_HW_STATUS_MAX,
};

enum nbl_reset_event {
	NBL_HW_FATAL_ERR_EVENT, /* Most hw module is not work nomal exclude pcie/emp */
	NBL_HW_MAX_EVENT
};

/*  ------  Params that go through multiple layers  ------  */
struct nbl_driver_info {
#define NBL_DRIVER_VERSION_LEN_MAX	(32)
	char	driver_version[NBL_DRIVER_VERSION_LEN_MAX];
};

struct nbl_func_caps {
	u32 has_ctrl:1;
	u32 has_net:1;
	u32 is_vf:1;
	u32 is_nic:1;
	u32 is_blk:1;
	u32 has_user:1;
	u32 support_lag:1;
	u32 has_grc:1;
	u32 has_factory_ctrl:1;
	u32 is_ocp:1;
	u32 rsv:23;
};

struct nbl_init_param {
	struct nbl_func_caps caps;
	enum nbl_product_type product_type;
	bool is_rep;
	bool pci_using_dac;
};

struct nbl_abnormal_ring_param {
	int ring_index;
	int type;
};

struct nbl_stop_abnormal_sw_queue_param {
	u16 local_queue_id;
	int type;
};

struct nbl_get_local_queue_id_param {
	u16 vsi_id;
	u16 global_queue_id;
};

struct nbl_txrx_queue_param {
	u16 vsi_id;
	u64 dma;
	u64 avail;
	u64 used;
	u16 desc_num;
	u16 local_queue_id;
	u16 intr_en;
	u16 intr_mask;
	u16 global_vector_id;
	u16 half_offload_en;
	u16 split;
	u16 extend_header;
	u16 cxt;
	u16 rxcsum;
};

struct nbl_cfg_rx_half_offload_param {
	u16 vsi_index;
	u16 half_offload_en;
};

struct nbl_cfg_txrx_vlan_param {
	u16 vlan_tci;
	u16 vlan_proto;
	u8 vsi_index;
};

struct nbl_tc_qidsc_info {
	u16 count;
	u16 offset;
	u32 pad;
	u64 max_tx_rate;
};

#define NBL_EPRO_RSS_SK_SIZE 40

#define NBL_MAX_TC_NUM		(8)
struct nbl_tc_qidsc_param {
	struct nbl_tc_qidsc_info info[NBL_MAX_TC_NUM];
	bool enable;
	u16 num_tc;
	u16 origin_qps;
	u16 vsi_id;
	u8 gravity;
};

struct nbl_qid_map_table {
	u32 local_qid;
	u32 notify_addr_l;
	u32 notify_addr_h;
	u32 global_qid;
	u32 ctrlq_flag;
};

struct nbl_qid_map_param {
	struct nbl_qid_map_table *qid_map;
	u16 start;
	u16 len;
};

struct nbl_ecpu_qid_map_param {
	u8 valid;
	u16 table_id;
	u16 max_qid;
	u16 base_qid;
	u16 device_type;
	u64 notify_addr;
};

struct nbl_rss_alg_param {
	u8 hash_field_type_v4;
	u8 hash_field_type_v6;
	u8 hash_field_mask_dport;
	u8 hash_field_mask_sport;
	u8 hash_field_mask_dip;
	u8 hash_field_mask_sip;
	u8 hash_alg_type;
};

struct nbl_vnet_queue_info_param {
	u32 function_id;
	u32 device_id;
	u32 bus_id;
	u32 msix_idx;
	u32 msix_idx_valid;
	u32 valid;
};

struct nbl_queue_cfg_param {
	/* queue args*/
	u64 desc;
	u64 avail;
	u64 used;
	u16 size;
	u16 extend_header;
	u16 split;
	u16 last_avail_idx;
	u16 global_queue_id;

	/*interrupt args*/
	u16 global_vector;
	u16 intr_en;
	u16 intr_mask;

	/* dvn args */
	u16 tx;
	u16 vsi_id;
	bool interleave_seg_disable;

	/* uvn args*/
	u16 rxcsum;
	u16 half_offload_en;
};

struct nbl_msix_info_param {
	u16 msix_num;
	struct msix_entry *msix_entries;
};

struct nbl_set_msix_fast_restrain_param {
	u16 global_vector_id;
	u16 pnum;
	u16 rate;
};

struct nbl_set_intr_suppress_level_fast_param {
	u16 global_vector_id;
	u16 level;
};

struct nbl_get_intr_suppress_level_param {
	u64 rate;
	u16 last_level;
};

struct nbl_queue_stats {
	u64 packets;
	u64 bytes;
	u64 descs;
};

struct nbl_get_queue_stats_param {
	u8 queue_id;
	bool is_tx;
};

struct nbl_rep_stats {
	u64 packets;
	u64 bytes;
	u64 dropped;
};

struct nbl_alloc_rep_data_param {
	int num_vfs;
	u16 vf_base_vsi_id;
};

struct nbl_get_rep_stats_param {
	u16 rep_vsi_id;
	bool is_tx;
};

struct nbl_tx_queue_stats {
	u64 tso_packets;
	u64 tso_bytes;
	u64 tso_inner_packets;
	u64 tso_inner_bytes;
	u64 tx_csum_packets;
	u64 tx_csum_inner_packets;
	u64 tx_busy;
	u64 tx_dma_busy;
	u64 tx_multicast_packets;
	u64 tx_unicast_packets;
	u64 tx_skb_free;
	u64 tx_desc_addr_err_cnt;
	u64 tx_desc_len_err_cnt;
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	u64 tls_encrypted_packets;
	u64 tls_encrypted_bytes;
	u64 tls_ooo_packets;
#endif
	u64 tx_added_vlan_packets;
};

struct nbl_rx_queue_stats {
	u64 rx_csum_packets;
	u64 rx_csum_inner_packets;
	u64 rx_csum_errors;
	u64 rx_multicast_packets;
	u64 rx_unicast_packets;
	u64 rx_desc_addr_err_cnt;
	u64 rx_alloc_buf_err_cnt;
	u64 rx_cache_reuse;
	u64 rx_cache_full;
	u64 rx_cache_empty;
	u64 rx_cache_busy;
	u64 rx_cache_waive;
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	u64 tls_decrypted_packets;
	u64 tls_resync_req_num;
#endif
	u64 rx_removed_vlan_packets;
	u64 rx_rss_hash_packets;
	u64 xdp_tx_packets;
	u64 xdp_redirect_packets;
	u64 xdp_drop_packets;
	u64 rx_oversize_pkts_sw_drop;
};

struct nbl_stats {
	/* for toe stats */
	u64 tso_packets;
	u64 tso_bytes;
	u64 tso_inner_packets;
	u64 tso_inner_bytes;
	u64 tx_csum_packets;
	u64 tx_csum_inner_packets;
	u64 rx_csum_packets;
	u64 rx_csum_inner_packets;
	u64 rx_csum_errors;
	u64 tx_busy;
	u64 tx_dma_busy;
	u64 tx_multicast_packets;
	u64 tx_unicast_packets;
	u64 xdp_tx_packets;
	u64 xdp_redirect_packets;
	u64 xdp_drop_packets;
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	u64 tls_encrypted_packets;
	u64 tls_encrypted_bytes;
	u64 tls_ooo_packets;
	u64 tls_decrypted_packets;
	u64 tls_resync_req_num;
#endif
	u64 rx_multicast_packets;
	u64 rx_unicast_packets;
	u64 tx_skb_free;
	u64 tx_desc_addr_err_cnt;
	u64 tx_desc_len_err_cnt;
	u64 rx_desc_addr_err_cnt;
	u64 rx_alloc_buf_err_cnt;
	u64 rx_cache_reuse;
	u64 rx_cache_full;
	u64 rx_cache_empty;
	u64 rx_cache_busy;
	u64 rx_cache_waive;
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_added_vlan_packets;
	u64 rx_removed_vlan_packets;
	u64 rx_rss_hash_packets;
	u64 rx_oversize_pkts_sw_drop;
	u64 total_fake_packets;
};

struct nbl_priv_stats {
	u64 total_dvn_pkt_drop_cnt;
	u64 total_uvn_stat_pkt_drop;
};

struct nbl_prio_stats {
	u64 packets;
	u64 bytes;
	u64 drop_packets;
};

struct nbl_vf_stats {
	u64 rx_packets;
	u64 tx_packets;
	u64 rx_bytes;
	u64 tx_bytes;
	u64 broadcast;
	u64 multicast;
	u64 rx_dropped;
	u64 tx_dropped;
};

struct nbl_eth_abnormal_stats {
	/* detailed rx_errors: */
	u64 rx_length_errors;
	u64 rx_over_errors;
	u64 rx_crc_errors;
	u64 rx_frame_errors;
	u64 rx_fifo_errors;
	u64 rx_missed_errors;

	/* detailed tx_errors */
	u64 tx_aborted_errors;
	u64 tx_carrier_errors;
	u64 tx_fifo_errors;
	u64 tx_heartbeat_errors;
	u64 tx_window_errors;
};

struct nbl_notify_param {
	u16 notify_qid;
	u16 tail_ptr;
};

#define NBL_LAG_MAX_PORTS		8
#define NBL_LAG_MAX_NUM			2
#define NBL_LAG_MAX_RESOURCE_NUM	NBL_DRIVER_DEV_MAX

struct nbl_enable_lag_param {
	bool enable;
	u16 pa_ext_type_tbl_id;
	u16 flow_tbl_id;
	u16 upcall_vsi;
	u16 upcall_queue;
};

struct nbl_enable_up_rdma_bypass_param {
	u8 mac[ETH_ALEN];
	u16 vsi_id;
	bool enable;
};

struct nbl_flash_image_param {
	u32 module;
	const u8 *data;
	size_t len;
};

enum nbl_stat_type {
	STAT_TYPE_USTORE,
	STAT_TYPE_FAKE,
	STAT_TYPE_RX_DROPPED_QUEUE_DISABLE,
};

enum nbl_eth_speed {
	LINK_SPEED_100M = 0,
	LINK_SPEED_1000M = 1,
	LINK_SPEED_5G = 2,
	LINK_SPEEP_10G = 3,
	LINK_SPEED_25G = 4,
	LINK_SPEED_50G = 5,
	LINK_SPEED_100G = 6,
	LINK_SPEED_200G = 7
};

struct nbl_macsec_pn {
	u32 pn;
	u32 epn;
};

#define NBL_MACSEC_KEY_LEN		32
#define NBL_MACSEC_SALT_LEN		12

struct nbl_macsec_sa {
	u8 sec_key[NBL_MACSEC_KEY_LEN];
	u8 salt[NBL_MACSEC_SALT_LEN];
	u32 ssci;
	u32 active : 1;
	u32 rsv1 : 31;
	u32 rsv2[3];
	struct nbl_macsec_pn sa_pn;
};

struct nbl_macsec_tx_sc {
	u32 offset : 7;
	u32 icv_len : 4;
	u32 an : 2;
	u32 svlan_clear : 1;
	u32 cvlan_clear : 1;
	u32 key_type : 1;
	u32 key_len : 1;
	u32 xpn : 1;
	u32 scb : 1;
	u32 end_station : 1;
	u32 send_sci : 1;
	u32 encrypt : 1;
	u32 protect : 1;
	u32 active : 1;
	u32 rsv : 8;
	u32 index;
	struct nbl_macsec_sa *tx_sa[4];
};

struct nbl_macsec_rx_sc {
	u32 active : 1;
	u32 win_size : 2;
	u32 offset : 7;
	u32 icv_len : 4;
	u32 validate_frame : 2;
	u32 key_type : 1;
	u32 key_len : 1;
	u32 xpn : 1;
	u32 replay : 1;
	u32 sci_l : 12;
	u32 sci_m;
	u32 sci_h : 20;
	u32 sport_id : 2;
	u32 rsv1 : 10;
	u32 rsv2;
	u32 index;
	struct nbl_macsec_sa *rx_sa[4];
	struct list_head rx_sc_node;
	struct metadata_dst *md_dst;
};

struct nbl_macsec_fs {
	u64 sci;
	u8 dmac[6];
	u8 smac[6];
	u32 svlan;
	u32 cvlan;
	u8 port_id : 2;
	u8 mask : 5;
	u8 vld : 1;
};

struct nbl_macsec_dev {
	const struct net_device *netdev;
	struct list_head macsec_rx_sc_list;
	struct nbl_macsec_fs macsec_fs;
	struct nbl_macsec_tx_sc tx_sc;
	struct list_head macsec_dev_node;
};

struct nbl_macsec_info {
	struct list_head macsec_dev_list;
	int dev_num;
	struct mutex lock; /* for macsec operation*/
};

#define NBL_KTLS_IV_LEN				8
#define NBL_KTLS_REC_LEN			8
#define NBL_KTLS_SALT_LEN			4
#define NBL_KTLS_KEY_HALF			16
#define NBL_KTLS_KEY_LEN			32
#define NBL_KTLS_PAD_LEN			4

struct nbl_ktls_offload_context_tx {
	u32 index;
	u32 expected_tcp;
	u8 iv[NBL_KTLS_IV_LEN];
	u8 rec_num[NBL_KTLS_REC_LEN];
	u8 salt[NBL_KTLS_SALT_LEN];
	u8 key[NBL_KTLS_KEY_LEN];
	bool ctx_post_pending;
	u8 crypto_type;
	__be16 sync_redlen;
	__be64 sync_rec_num;
	__be64 sync_iv;
	struct tls_offload_context_tx	*tx_ctx;
};

struct nbl_ktls_offload_context_rx {
	u32 index;
	u32 tcp_seq;
	u8 rec_num[NBL_KTLS_REC_LEN];
};

struct aes_gcm_keymat {
	u8 crypto_type;
	u32 salt;
	u32 icv_len;
#define NBL_IPSEC_KEY_LEN			8
	u32 aes_key[NBL_IPSEC_KEY_LEN];
	u64 seq_iv;
};

struct nbl_accel_esp_xfrm_attrs {
	u8 is_ipv6;
	u8 nat_flag;
	u8 tunnel_mode;
	u16 sport;
	u16 dport;
	u32 spi;
	xfrm_address_t saddr;
	xfrm_address_t daddr;
	struct aes_gcm_keymat aes_gcm;
};

struct nbl_ipsec_esn_state {
	u32 sn;
	u32 esn;
	u8 wrap_en : 1;
	u8 overlap : 1;
	u8 enable : 1;
	u8 window_en : 1;
	u8 option : 2;
};

struct nbl_sa_search_key {
	u16 family;
	u32 mark;
	__be32 spi;
	xfrm_address_t daddr;
};

struct nbl_ipsec_cfg_info {
	struct nbl_sa_search_key sa_key;
	bool vld;

	u32 lft_cnt;
	u32 lft_diff;
	u32 hard_round;
	u32 soft_round;
	u32 hard_remain;
	u32 soft_remain;

	u16 vsi;
	u8 limit_type;
	u8 limit_enable;
	u64 hard_limit;
	u64 soft_limit;
};

struct nbl_ipsec_sa_entry {
	struct nbl_ipsec_cfg_info cfg_info;
	struct nbl_ipsec_esn_state esn_state;
	struct nbl_accel_esp_xfrm_attrs attrs;
	u32 index;
};

union nbl_ipsec_lft_info {
	u32 data;
	struct {
		u32 soft_sad_index : 11;
		u32 soft_vld :1;
		u32 rsv1 : 4;
		u32 hard_sad_index : 11;
		u32 hard_vld :1;
		u32 rsv2 : 4;
	};
};

struct nbl_common_irq_num {
	int mbx_irq_num;
};

struct nbl_ctrl_irq_num {
	int adminq_irq_num;
	int abnormal_irq_num;
	int sfp_plug_irq_num;
};

enum nbl_flow_ctrl {
	NBL_PORT_TX_PAUSE = 0x1,
	NBL_PORT_RX_PAUSE = 0x2,
	NBL_PORT_TXRX_PAUSE_OFF = 0x4, /* used for ethtool, means ethtool close tx and rx pause */
};

enum nbl_port_fec {
	NBL_PORT_FEC_OFF = 1,
	NBL_PORT_FEC_RS = 2,
	NBL_PORT_FEC_BASER = 3,
	NBL_PORT_FEC_AUTO = 4, /* ethtool may set Auto mode, used for PF mailbox msg*/
};

enum nbl_port_autoneg {
	NBL_PORT_AUTONEG_DISABLE = 0x1,
	NBL_PORT_AUTONEG_ENABLE = 0x2,
};

enum nbl_port_type {
	NBL_PORT_TYPE_UNKNOWN = 0,
	NBL_PORT_TYPE_FIBRE,
	NBL_PORT_TYPE_COPPER,
	NBL_PORT_TYPE_TP,
};

enum nbl_port_max_rate {
	NBL_PORT_MAX_RATE_UNKNOWN = 0,
	NBL_PORT_MAX_RATE_1G,
	NBL_PORT_MAX_RATE_10G,
	NBL_PORT_MAX_RATE_25G,
	NBL_PORT_MAX_RATE_100G,
	NBL_PORT_MAX_RATE_100G_PAM4,
	NBL_PORT_MAX_RATE_200G,
	NBL_PORT_MAX_RATE_400G,
};

enum nbl_port_mode {
	NBL_PORT_NRZ_NORSFEC = 1,
	NBL_PORT_NRZ_544,
	NBL_PORT_NRZ_528,
	NBL_PORT_PAM4_544,
	NBL_PORT_MODE_MAX,
};

enum nbl_led_reg_ctrl {
	NBL_LED_REG_ACTIVE,
	NBL_LED_REG_ON,
	NBL_LED_REG_OFF,
	NBL_LED_REG_INACTIVE,
};

#define NBL_PORT_CAP_AUTONEG_MASK (BIT(NBL_PORT_CAP_AUTONEG))
#define NBL_PORT_CAP_FEC_MASK \
	(BIT(NBL_PORT_CAP_FEC_OFF) | BIT(NBL_PORT_CAP_FEC_RS) | BIT(NBL_PORT_CAP_FEC_BASER))
#define NBL_PORT_CAP_PAUSE_MASK (BIT(NBL_PORT_CAP_TX_PAUSE) | BIT(NBL_PORT_CAP_RX_PAUSE))
#define NBL_PORT_CAP_SPEED_1G_MASK\
	(BIT(NBL_PORT_CAP_1000BASE_T) | BIT(NBL_PORT_CAP_1000BASE_X))
#define NBL_PORT_CAP_SPEED_2_5G_MASK BIT_ULL(NBL_PORT_CAP_2500BASE_T)
#define NBL_PORT_CAP_SPEED_5G_MASK BIT_ULL(NBL_PORT_CAP_5GBASE_T)
#define NBL_PORT_CAP_SPEED_10G_MASK\
	(BIT(NBL_PORT_CAP_10GBASE_T) | BIT(NBL_PORT_CAP_10GBASE_KR) | BIT(NBL_PORT_CAP_10GBASE_SR))
#define NBL_PORT_CAP_SPEED_25G_MASK \
	(BIT(NBL_PORT_CAP_25GBASE_KR) | BIT(NBL_PORT_CAP_25GBASE_SR) |\
	 BIT(NBL_PORT_CAP_25GBASE_CR) | BIT(NBL_PORT_CAP_25G_AUI))
#define NBL_PORT_CAP_SPEED_50G_MASK \
	(BIT(NBL_PORT_CAP_50GBASE_KR2) | BIT(NBL_PORT_CAP_50GBASE_SR2) |\
	 BIT(NBL_PORT_CAP_50GBASE_CR2) | BIT(NBL_PORT_CAP_50G_AUI2) |\
	 BIT(NBL_PORT_CAP_50GBASE_KR_PAM4) | BIT(NBL_PORT_CAP_50GBASE_SR_PAM4) |\
	 BIT(NBL_PORT_CAP_50GBASE_CR_PAM4) | BIT(NBL_PORT_CAP_50G_AUI_PAM4))
#define NBL_PORT_CAP_SPEED_100G_MASK \
	(BIT(NBL_PORT_CAP_100GBASE_KR4) | BIT(NBL_PORT_CAP_100GBASE_SR4) |\
	 BIT(NBL_PORT_CAP_100GBASE_CR4) | BIT(NBL_PORT_CAP_100G_AUI4) |\
	 BIT(NBL_PORT_CAP_100G_CAUI4) | BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4) |\
	 BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4) | BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4) |\
	 BIT(NBL_PORT_CAP_100G_AUI2_PAM4))
#define NBL_PORT_CAP_SPEED_200G_MASK \
	(BIT_ULL(NBL_PORT_CAP_200GBASE_KR4) | BIT_ULL(NBL_PORT_CAP_200GBASE_CR4) |\
	 BIT_ULL(NBL_PORT_CAP_200G_AUI4))
#define NBL_PORT_CAP_SPEED_400G_MASK \
	(BIT_ULL(NBL_PORT_CAP_400GBASE_KR4) | BIT_ULL(NBL_PORT_CAP_400GBASE_CR4) |\
	 BIT_ULL(NBL_PORT_CAP_400G_AUI4))
#define NBL_PORT_CAP_SPEED_MASK \
	(NBL_PORT_CAP_SPEED_1G_MASK | NBL_PORT_CAP_SPEED_2_5G_MASK |\
	 NBL_PORT_CAP_SPEED_5G_MASK | NBL_PORT_CAP_SPEED_10G_MASK |\
	 NBL_PORT_CAP_SPEED_25G_MASK | NBL_PORT_CAP_SPEED_50G_MASK |\
	 NBL_PORT_CAP_SPEED_100G_MASK | NBL_PORT_CAP_SPEED_200G_MASK |\
	 NBL_PORT_CAP_SPEED_400G_MASK)
#define NBL_PORT_CAP_PAM4_MASK\
	(BIT(NBL_PORT_CAP_50GBASE_KR_PAM4) | BIT(NBL_PORT_CAP_50GBASE_SR_PAM4) |\
	 BIT(NBL_PORT_CAP_50GBASE_CR_PAM4) | BIT(NBL_PORT_CAP_50G_AUI_PAM4) |\
	 BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4) | BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4) |\
	 BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4) | BIT(NBL_PORT_CAP_100G_AUI2_PAM4))
#define NBL_ETH_1G_DEFAULT_FEC_MODE	NBL_PORT_FEC_OFF
#define NBL_ETH_2_5G_DEFAULT_FEC_MODE	NBL_PORT_FEC_OFF
#define NBL_ETH_5G_DEFAULT_FEC_MODE	NBL_PORT_FEC_OFF
#define NBL_ETH_10G_DEFAULT_FEC_MODE	NBL_PORT_FEC_OFF
#define NBL_ETH_25G_DEFAULT_FEC_MODE	NBL_PORT_FEC_RS
#define NBL_ETH_100G_DEFAULT_FEC_MODE	NBL_PORT_FEC_RS

enum nbl_port_cap {
	NBL_PORT_CAP_TX_PAUSE,
	NBL_PORT_CAP_RX_PAUSE,
	NBL_PORT_CAP_AUTONEG,
	NBL_PORT_CAP_FEC_NONE,
	NBL_PORT_CAP_FEC_OFF = NBL_PORT_CAP_FEC_NONE,
	NBL_PORT_CAP_FEC_RS,
	NBL_PORT_CAP_FEC_BASER,
	NBL_PORT_CAP_1000BASE_T,
	NBL_PORT_CAP_1000BASE_X,
	NBL_PORT_CAP_10GBASE_T,
	NBL_PORT_CAP_10GBASE_KR,
	NBL_PORT_CAP_10GBASE_SR,
	NBL_PORT_CAP_25GBASE_KR,
	NBL_PORT_CAP_25GBASE_SR,
	NBL_PORT_CAP_25GBASE_CR,
	NBL_PORT_CAP_25G_AUI,
	NBL_PORT_CAP_50GBASE_KR2,
	NBL_PORT_CAP_50GBASE_SR2,
	NBL_PORT_CAP_50GBASE_CR2,
	NBL_PORT_CAP_50G_AUI2,
	NBL_PORT_CAP_50GBASE_KR_PAM4,
	NBL_PORT_CAP_50GBASE_SR_PAM4,
	NBL_PORT_CAP_50GBASE_CR_PAM4,
	NBL_PORT_CAP_50G_AUI_PAM4,
	NBL_PORT_CAP_100GBASE_KR4,
	NBL_PORT_CAP_100GBASE_SR4,
	NBL_PORT_CAP_100GBASE_CR4,
	NBL_PORT_CAP_100G_AUI4,
	NBL_PORT_CAP_100G_CAUI4,
	NBL_PORT_CAP_100GBASE_KR2_PAM4,
	NBL_PORT_CAP_100GBASE_SR2_PAM4,
	NBL_PORT_CAP_100GBASE_CR2_PAM4,
	NBL_PORT_CAP_100G_AUI2_PAM4,
	NBL_PORT_CAP_FEC_AUTONEG,
	NBL_PORT_CAP_200GBASE_KR4,
	NBL_PORT_CAP_200GBASE_CR4,
	NBL_PORT_CAP_200G_AUI4,
	NBL_PORT_CAP_400GBASE_KR4,
	NBL_PORT_CAP_400GBASE_CR4,
	NBL_PORT_CAP_400G_AUI4,
	NBL_PORT_CAP_2500BASE_T,
	NBL_PORT_CAP_5GBASE_T,
	NBL_PORT_CAP_MAX
};

enum nbl_fw_port_speed {
	NBL_FW_PORT_SPEED_10G,
	NBL_FW_PORT_SPEED_25G,
	NBL_FW_PORT_SPEED_50G,
	NBL_FW_PORT_SPEED_100G,
};

enum nbl_fw_port_type {
	NBL_FW_PORT_FIBER_OR_COPPER,
	NBL_FW_PORT_RJ45,
};

static inline u32 nbl_port_speed_to_speed(enum nbl_fw_port_speed port_speed)
{
	switch (port_speed) {
	case NBL_FW_PORT_SPEED_10G:
		return SPEED_10000;
	case NBL_FW_PORT_SPEED_25G:
		return SPEED_25000;
	case NBL_FW_PORT_SPEED_50G:
		return SPEED_50000;
	case NBL_FW_PORT_SPEED_100G:
		return SPEED_100000;
	default:
		return SPEED_25000;
	}

	return SPEED_25000;
}

static inline u8 nbl_fw_speed_to_port_speed(enum nbl_fw_port_speed port_speed)
{
	switch (port_speed) {
	case NBL_FW_PORT_SPEED_10G:
		return NBL_PORT_MAX_RATE_10G;
	case NBL_FW_PORT_SPEED_25G:
		return NBL_PORT_MAX_RATE_25G;
	case NBL_FW_PORT_SPEED_100G:
		return NBL_PORT_MAX_RATE_100G;
	default:
		return NBL_PORT_MAX_RATE_100G;
	}

	return NBL_PORT_MAX_RATE_100G;
}

#define PASSTHROUGH_FW_CMD_DATA_LEN			(3072)
struct nbl_passthrough_fw_cmd_param {
	u16 opcode;
	u16 errcode;
	u16 in_size;
	u16 out_size;
	u8 data[PASSTHROUGH_FW_CMD_DATA_LEN];
};

#define NBL_NET_RING_NUM_CMD_LEN				(520)
struct nbl_fw_cmd_net_ring_num_param {
	u16 pf_def_max_net_qp_num;
	u16 vf_def_max_net_qp_num;
	u16 net_max_qp_num[NBL_NET_RING_NUM_CMD_LEN];
};

#define NBL_RDMA_CAP_CMD_LEN					(65)
struct nbl_fw_cmd_rdma_cap_param {
	u32 valid;
	u8 rdma_func_bitmaps[NBL_RDMA_CAP_CMD_LEN];
	u8 rsv[7];
};

#define NBL_RDMA_MEM_TYPE_MAX					(2)
struct nbl_fw_cmd_rdma_mem_type_param {
	u32 mem_type;
};

#define NBL_VF_NUM_CMD_LEN					(8)
struct nbl_fw_cmd_vf_num_param {
	u32 valid;
	u16 vf_max_num[NBL_VF_NUM_CMD_LEN];
};

#define NBL_RESTOOL_NAME_LEN	32
#define NBL_ST_INFO_NAME_LEN				(64)
#define NBL_ST_INFO_NETDEV_MAX				(8)
#define NBL_ST_INFO_RESERVED_LEN			(344)
struct nbl_st_info_param {
	u8 version;
	u8 bus;
	u8 devid;
	u8 function;
	u16 domain;
#define NBL_NIC_TYPE_SNIC_V1R1		0
#define NBL_NIC_TYPE_SNIC_V2R1		1
#define NBL_NIC_TYPE_RNIC		2
	u16 nic_type;
	char driver_name[NBL_ST_INFO_NAME_LEN];
	char driver_ver[NBL_ST_INFO_NAME_LEN];
	char netdev_name[NBL_ST_INFO_NETDEV_MAX][NBL_ST_INFO_NAME_LEN];
	char real_chrdev_flag;
	char real_chrdev_name[31];
	u8 rsv[NBL_ST_INFO_RESERVED_LEN];
} __packed;

static inline u64 nbl_speed_to_link_mode(unsigned int speed, u8 autoneg, u8 port_type)
{
	u64 link_mode = 0;
	int speed_support = 0;

	if (port_type == NBL_PORT_TYPE_TP) {
		switch (speed) {
		case SPEED_10000:
			link_mode |= BIT(NBL_PORT_CAP_10GBASE_T);
			speed_support = 1;
			break;
		case SPEED_5000:
			link_mode |= BIT_ULL(NBL_PORT_CAP_5GBASE_T);
			speed_support = 1;
			break;
		case SPEED_2500:
			link_mode |= BIT_ULL(NBL_PORT_CAP_2500BASE_T);
			speed_support = 1;
			break;
		case SPEED_1000:
			link_mode |= BIT(NBL_PORT_CAP_1000BASE_T);
			speed_support = 1;
			break;
		default:
			break;
		}
		if (autoneg && speed_support)
			link_mode |= BIT(NBL_PORT_CAP_AUTONEG);
		return link_mode;
	}

	switch (speed) {
	case SPEED_100000:
		link_mode |= BIT(NBL_PORT_CAP_100GBASE_KR4) | BIT(NBL_PORT_CAP_100GBASE_SR4) |
			BIT(NBL_PORT_CAP_100GBASE_CR4) | BIT(NBL_PORT_CAP_100G_AUI4) |
			BIT(NBL_PORT_CAP_100G_CAUI4) | BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4) |
			BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4) | BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4) |
			BIT(NBL_PORT_CAP_100G_AUI2_PAM4);
		fallthrough;
	case SPEED_50000:
		link_mode |= BIT(NBL_PORT_CAP_50GBASE_KR2) | BIT(NBL_PORT_CAP_50GBASE_SR2) |
			BIT(NBL_PORT_CAP_50GBASE_CR2) | BIT(NBL_PORT_CAP_50G_AUI2) |
			BIT(NBL_PORT_CAP_50GBASE_KR_PAM4) | BIT(NBL_PORT_CAP_50GBASE_SR_PAM4) |
			BIT(NBL_PORT_CAP_50GBASE_CR_PAM4) | BIT(NBL_PORT_CAP_50G_AUI_PAM4);
		fallthrough;
	case SPEED_25000:
		link_mode |= BIT(NBL_PORT_CAP_25GBASE_KR) | BIT(NBL_PORT_CAP_25GBASE_SR) |
			BIT(NBL_PORT_CAP_25GBASE_CR) | BIT(NBL_PORT_CAP_25G_AUI);
		fallthrough;
	case SPEED_10000:
		link_mode |= BIT(NBL_PORT_CAP_10GBASE_KR) | BIT(NBL_PORT_CAP_10GBASE_SR);
		fallthrough;
	case SPEED_1000:
		link_mode |= BIT(NBL_PORT_CAP_1000BASE_X);
		speed_support = 1;
	}

	if (autoneg && speed_support)
		link_mode |= BIT(NBL_PORT_CAP_AUTONEG);

	return link_mode;
}

enum nbl_flow_key_mask_tag {
	/* flag used by inner init, and cannot modified when app start */
	NBL_FLOW_ITEM_SKEY_MASK = 0,
	NBL_FLOW_ITEM_SKEY_EXACT,
	NBL_FLOW_ITEM_SKEY_IGN,

	NBL_FLOW_ITEM_DKEY_MASK,
	NBL_FLOW_ITEM_DKEY_EXACT,
	NBL_FLOW_ITEM_DKEY_IGN,

	NBL_FLOW_ITEM_KEY_MASK,
	NBL_FLOW_ITEM_KEY_EXACT,
	NBL_FLOW_ITEM_KEY_IGN,

	/* flag used by inner process, could be modified when app process */
	NBL_FLOW_ITEM_KEY_OUTER,
	NBL_FLOW_ITEM_KEY_VLAN1,
	NBL_FLOW_ITEM_KEY_VLAN2,
};

enum {
	NBL_FLOW_TYPE_IPV4,
	NBL_FLOW_TYPE_TCPV4,
	NBL_FLOW_TYPE_UDPV4,
	NBL_FLOW_TYPE_SCTPV4,
	NBL_FLOW_TYPE_IPV6,
	NBL_FLOW_TYPE_TCPV6,
	NBL_FLOW_TYPE_UDPV6,
	NBL_FLOW_TYPE_SCTPV6,
	NBL_FLOW_TYPE_OFFLOAD,
};

enum {
	NBL_HASH_FILED_SRC_IP		= 1 << 0,
	NBL_HASH_FILED_DST_IP		= 1 << 1,
	NBL_HASH_FILED_L4_SPORT		= 1 << 2,
	NBL_HASH_FILED_L4_DPORT		= 1 << 3,
};

enum {
	TMPT_SEL_SCTPV6_DP		= 1 << 0,
	TMPT_SEL_SCTPV6_SP		= 1 << 1,
	TMPT_SEL_SCTPV6_DIP		= 1 << 2,
	TMPT_SEL_SCTPV6_SIP		= 1 << 3,
	TMPT_SEL_UDPV6_DP		= 1 << 4,
	TMPT_SEL_UDPV6_SP		= 1 << 5,
	TMPT_SEL_UDPV6_DIP		= 1 << 6,
	TMPT_SEL_UDPV6_SIP		= 1 << 7,
	TMPT_SEL_TCPV6_DP		= 1 << 8,
	TMPT_SEL_TCPV6_SP		= 1 << 9,
	TMPT_SEL_TCPV6_DIP		= 1 << 10,
	TMPT_SEL_TCPV6_SIP		= 1 << 11,
	TMPT_SEL_IPV6_DIP		= 1 << 12,
	TMPT_SEL_IPV6_SIP		= 1 << 13,
	TMPT_SEL_SCTPV4_DP		= 1 << 14,
	TMPT_SEL_SCTPV4_SP		= 1 << 15,
	TMPT_SEL_SCTPV4_DIP		= 1 << 16,
	TMPT_SEL_SCTPV4_SIP		= 1 << 17,
	TMPT_SEL_UDPV4_DP		= 1 << 18,
	TMPT_SEL_UDPV4_SP		= 1 << 19,
	TMPT_SEL_UDPV4_DIP		= 1 << 20,
	TMPT_SEL_UDPV4_SIP		= 1 << 21,
	TMPT_SEL_TCPV4_DP		= 1 << 22,
	TMPT_SEL_TCPV4_SP		= 1 << 23,
	TMPT_SEL_TCPV4_DIP		= 1 << 24,
	TMPT_SEL_TCPV4_SIP		= 1 << 25,
	TMPT_SEL_IPV4_DIP		= 1 << 26,
	TMPT_SEL_IPV4_SIP		= 1 << 27,
};

#define NBL_DEFINE_NAME_WITH_WIDTH_CHECK(_struct, _size) \
_struct; \
static inline int nbl_##_struct##_size_is_not_equal_to_define(void) \
{ \
	int check[((sizeof(_struct) * 8) == (_size)) ? 1 :  -1]; \
	return check[0]; \
}

#define nbl_list_entry_is_head(pos, head, member)	\
	list_entry_is_head(pos, head, member)

/**
 * list_is_first -- tests whether @ list is the first entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int nbl_list_is_first(const struct list_head *list,
				    const struct list_head *head)
{
	return list->prev == head;
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int nbl_list_is_last(const struct list_head *list,
				   const struct list_head *head)
{
	return list->next == head;
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int nbl_list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;
}

#define nbl_read_poll_timeout(op, val, cond, sleep_us, timeout_us, \
			      sleep_before_read, args...) \
	read_poll_timeout(op, val, cond, sleep_us, timeout_us, sleep_before_read, args)

#define NBL_OPS_CALL(func, para)								\
	({											\
		typeof(func) _func = (func);							\
		(!_func) ? 0 : _func para;							\
	})

enum {
	NBL_TC_PORT_TYPE_INVALID = 0,
	NBL_TC_PORT_TYPE_VSI,
	NBL_TC_PORT_TYPE_ETH,
	NBL_TC_PORT_TYPE_BOND,
};

struct nbl_tc_port {
	u32 id:24;
	u32 type:8;
};

enum nbl_cmd_status {
	NBL_CMDQ_SUCCESS	= 0,
	/* failed establishing cmd */
	NBL_CMDQ_PARAM_ERR	= -1,
	NBL_CMDQ_NOT_SUPP	= -3,
	NBL_CMDQ_NO_MEMORY	= -4,
	NBL_CMDQ_NOT_READY	= -5,
	NBL_CMDQ_UNDONE		= -6,
	/* failed sending cmd */
	NBL_CMDQ_CQ_ERR		= -100,
	NBL_CMDQ_CQ_FULL	= -102,
	NBL_CMDQ_CQ_NOT_READY	= -103,
	NBL_CMDQ_CQ_ERR_PARAMS	= -104,
	NBL_CMDQ_CQ_ERR_BUFFER	= -105,
	/* failed executing cmd */
	NBL_CMDQ_FAILED		= -200,
	NBL_CMDQ_NOBUF_ERR	= -201,
	NBL_CMDQ_TIMEOUT_ERR	= -202,
	NBL_CMDQ_NOHIT_ERR	= -203,
	NBL_CMDQ_RESEND_FAIL	= -204,
	NBL_CMDQ_RESET_FAIL	= -205,
	NBL_CMDQ_NEED_RESEND	= -206,
	NBL_CMDQ_NEED_RESET	= -207,
	NBL_CMDQ_EXCEED_RANGE	= -208,
};

struct nbl_fdir_l2 {
	u8 dst_mac[ETH_ALEN];  /* dest MAC address */
	u8 src_mac[ETH_ALEN];  /* src MAC address */
	u16 ether_type;		/* for NON_IP_L2 */
};

struct nbl_fdir_l4 {
	u16 dst_port;
	u16 src_port;
	u8 tcp_flag;
};

struct nbl_fdir_l3 {
	union {
		u32 addr;
		u8 v6_addr[NBL_IPV6_ADDR_LEN_AS_U8];
	} src_ip, dst_ip;

	u8 ip_ver;
	u8 tos;
	u8 ttl;
	u8 proto;
};

struct nbl_tc_fdir_tnl {
	u32 flags;
	u32 vni;
};

struct nbl_port_mcc {
	u16 dport_id:12;
	u16 port_type:4;
};

#define NBL_VLAN_TYPE_ETH_BASE		1027
#define NBL_VLAN_TPID_VALUE		0x8100
#define NBL_QINQ_TPID_VALUE		0x88A8
struct nbl_vlan {
	u16 vlan_tag;
	u16 eth_proto;
	u32 port_id;
	u8 port_type;
};

/* encap info */
#define NBL_FLOW_ACTION_ENCAP_TOTAL_LEN			128
#define NBL_FLOW_ACTION_ENCAP_OFFSET_LEN		9
#define NBL_FLOW_ACTION_ENCAP_HALF_LEN			45
#define NBL_FLOW_ACTION_ENCAP_MAX_LEN			90
#define NBL_FLOW_DRACO_ACTION_ENCAP_MAX_LEN		96

struct nbl_encap_key {
	struct ip_tunnel_key ip_tun_key;
	void *tc_tunnel;
};

struct nbl_tc_tunnel_route_info {
	struct net_device *out_dev;
	struct net_device *out_dev_parent;
	struct net_device *real_out_dev;
	union {
		struct flowi4 fl4;
		struct flowi6 fl6;
	} fl;
	struct neighbour *n;
	u8 ttl;
	u8 vlan_num;
	u16 ivlan_pcp;
	u16 ivlan_id;
	u16 ovlan_pcp;
	u16 ovlan_id;
	bool is_ip6;
	struct nbl_common_info *common;
};

struct nbl_tc_tun_create_header_param {
	struct nbl_rule_action *rule_act;
	unsigned char *hw_dst;
	struct nbl_tc_tunnel_route_info *tun_route;
	struct nbl_encap_key *key;
};

struct nbl_encap_entry {
	struct nbl_encap_key key;
	unsigned char hw_dst[ETH_ALEN];

	struct net_device *out_dev;
	u8 encap_buf[NBL_FLOW_ACTION_ENCAP_TOTAL_LEN];
	u16 encap_size;
	u16 encap_idx;
	u32 vni;
	u32 ref_cnt;
};

union nbl_flow_encap_offset_tbl_u {
	struct nbl_flow_encap_offset_tbl {
		u16 phid3_offset:7;
		u16 phid2_offset:7;
		u16 l4_ck_mod:3;
		u16 l3_ck_en:1;
		u16 len_offset1:7;
		u16 len_en1:1;
		u16 len_offset0:7;
		u16 len_en0:1;
		u16 dscp_offset:10;
		u16 vlan_offset:7;
		u16 vni_offset:7;
		u16 sport_offset:7;
		u16 tnl_len:7;
	} __packed info;
#define NBL_FLOW_ENCAP_OFFSET_TBL_WIDTH (sizeof(struct nbl_flow_encap_offset_tbl) \
		/ sizeof(u32))
	u32 data[NBL_FLOW_ENCAP_OFFSET_TBL_WIDTH];
} __packed;

struct nbl_tc_pedit_headers {
	struct ethhdr   eth;
	struct iphdr    ip4;
	struct ipv6hdr  ip6;
	struct tcphdr   tcp;
	struct udphdr   udp;
};

enum nbl_flow_ped_type {
	/* ped type: default is src dir if ped_type is ip & mac */
	NBL_FLOW_PED_UMAC_TYPE = 0,
	NBL_FLOW_PED_DMAC_TYPE,
	NBL_FLOW_PED_UIP_TYPE,
	NBL_FLOW_PED_DIP_TYPE,

	/* ped for mac & ip got src and dst, _D_TYPE represents the dst dir */
	NBL_FLOW_PED_UMAC_D_TYPE,
	NBL_FLOW_PED_DMAC_D_TYPE,
	NBL_FLOW_PED_UIP_D_TYPE,
	NBL_FLOW_PED_DIP_D_TYPE,

	NBL_FLOW_PED_RES_MAX,
	/* the following no need store rsource */
	NBL_FLOW_PED_UIP6_TYPE,
	NBL_FLOW_PED_DIP6_TYPE,
	NBL_FLOW_PED_RECORD_MAX,
};

enum nbl_draco_ped_type {
	NBL_DRACO_PED_UMAC_TYPE = 0,
	NBL_DRACO_PED_DMAC_TYPE,
	NBL_DRACO_PED_UIP_TYPE,
	NBL_DRACO_PED_DIP_TYPE,
	NBL_DRACO_PED_TNL_TYPE,
	NBL_DRACO_PED_TNL_VTEP_TYPE,
	NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE,
	NBL_DRACO_PED_MIRROR_TYPE,

	NBL_DRACO_PED_MIRROR_TNL_TYPE,
	NBL_DRACO_PED_MIRROR_VTEP_TYPE,
	/* the following no need init resource */
	NBL_DRACO_NEED_RESOURCE_TYPE_END,
	/* the following no need init resource but need a ped idx record */
	NBL_DRACO_PED_MCC_TYPE,
	/* the following no need record ped idx */
	NBL_DRACO_NEED_PED_RECORD_TYPE_END,
	NBL_DRACO_PED_VLAN_TYPE,
	NBL_DRACO_PED_TNL_DECAP_ASSD_TYPE,
	NBL_DRACO_EPRO_MIRROR_TYPE,
	NBL_DRACO_PED_MAX,
};

struct nbl_tc_pedit_node_res {
	void *pedit_node[NBL_FLOW_PED_RES_MAX];
	u32 pedits:30;
	u32 pedit_val:1;
	/* 0 tcp, 1 udp */
	u32 pedit_proto:1;
};

struct nbl_tc_pedit_info {
	struct nbl_tc_pedit_headers val;
	struct nbl_tc_pedit_headers mask;
	struct nbl_tc_pedit_node_res pedit_node;
};

#pragma pack(1)
struct nbl_flow_tnl_decap_tcam_node {
	u8 dip[NBL_IPV6_ADDR_LEN_AS_U8];
	u8 dmac[NBL_MAC_ADDR_LEN_AS_U8];
	u64 cvlan_id:12;
	u64 svlan_id:12;
	u64 cvlan_tpid:2;
	u64 svlan_tpid:2;
	u64 tnl_type:2;
	u64 tnl_base:1;

	u64 dip_mask:1;
	u64 dmac_mask:1;
	u64 cvlan_mask:1;
	u64 svlan_mask:1;
	u64 cvlan_tpid_mask:1;
	u64 svlan_tpid_mask:1;
	u64 tnl_type_mask:1;
	u64 tnl_base_mask:1;

	u64 valid_bit:1;

	u64 rsv0:24;
	u64 rsv1:16;
};

#pragma pack()

struct nbl_flow_item_vlan {
	u16 push_vlan_cnt:3;
	u16 pop_vlan_cnt:3;
	u16 cur_push_num:3;
	u16 cur_pop_num:3;
	u16 vlan_op:4;
	u16 ivlan_tag;
	u16 ovlan_tag;
	u16 ieth_proto;
	u16 oeth_proto;
	u16 itpid_sel:8;
	u16 otpid_sel:8;
	u16 last_vlan:7;
	u16 has_vlan:1;
	u16 ivlan_idx:3;
	u16 ovlan_idx:3;
	u16 need_set_ped_vsi_type:2;
};

struct nbl_draco_vtep_info {
	u8 vtep_id:6;
	u8 vtep_is_ref:1;
	u8 vtep_vld:1;
	struct nbl_flow_tnl_decap_tcam_node decap_key;
};

struct nbl_flow_ped_tag_info {
	u32 ped_valid:1;
	u32 ped_idx:31;
	void *data;
};

struct nbl_draco_ped_info {
	struct nbl_flow_ped_tag_info ped_info[NBL_DRACO_NEED_PED_RECORD_TYPE_END];
	struct nbl_flow_ped_tag_info mirror_vtep;
	struct nbl_flow_ped_tag_info mirror_encap;
};

struct nbl_rule_action {
	u64 flag; /* action flag, eg:set ipv4 src/redirect */
	u32 drop_flag:1; /* drop or forward */
	u32 counter_id:31;

	u32 port_id:15;
	u32 port_type:8;
	u32 action_cnt:5;  /* different action type total cnt */
	u32 next_stg_sel:4;

	u32 vni;
	u16 tnl_type:4;
	u16 encap_size:12;
	u16 encap_idx:15;
	u16 encap_parse_ok:1;

	u32 encap_out_dev_ifindex:14;
	u32 encap_in_hw:1;
	u32 dscp:8;
	u32 lag_id:4;
	u32 mcc_cnt:5;

	u16 car_id;	/* set car_id */
	u16 counter_oft:12;
	u16 outer_type:4;

	struct nbl_port_mcc port_mcc[NBL_TC_MCC_MEMBER_MAX];
	struct nbl_vlan vlan;
	struct ip_tunnel_info *tunnel;
	struct nbl_encap_key encap_key;
	union nbl_flow_encap_offset_tbl_u encap_idx_info;
	u8 encap_buf[NBL_FLOW_ACTION_ENCAP_TOTAL_LEN];
	u8 draco_encap_buf[NBL_FLOW_DRACO_ACTION_ENCAP_MAX_LEN];
	struct net_device *in_port;
	struct net_device *tc_tun_encap_out_dev;
	struct nbl_tc_pedit_info tc_pedit_info;

	/* for draco */
	struct nbl_flow_item_vlan vlan_info;
	struct nbl_draco_vtep_info vtep_info;
	struct nbl_draco_ped_info ped_info;
};

struct nbl_fdir_fltr {
	struct nbl_fdir_l2 l2_data_outer;
	struct nbl_fdir_l2 l2_mask_outer;
	struct nbl_fdir_l2 l2_data;
	struct nbl_fdir_l2 l2_mask;

	struct nbl_fdir_l3 ip;
	struct nbl_fdir_l3 ip_mask;
	struct nbl_fdir_l3 ip_outer;
	struct nbl_fdir_l3 ip_mask_outer;

	struct nbl_fdir_l4 l4;
	struct nbl_fdir_l4 l4_mask;
	struct nbl_fdir_l4 l4_outer;
	struct nbl_fdir_l4 l4_mask_outer;

	struct nbl_tc_fdir_tnl tnl;
	struct nbl_tc_fdir_tnl tnl_mask;

	u16 svlan_type;
	u16 svlan_tag;
	u16 cvlan_type;
	u16 cvlan_tag;
	u16 svlan_mask;
	u16 cvlan_mask;
	u32 tnl_flag:1;
	u32 tnl_cnt:1;
	u32 vlan_cnt:2;
	u32 metadata : 16;
	u32 acl_flow:1;
	u32 dir:1;
	u32 rsv:1;

	u8 lag_id;
	u16 port;
	bool is_cvlan;
	u16 encoded_port;
	u16 encoded_port_mask;
};

/**
 * struct nbl_flow_pattern_conf:
 * input : storage key info from pattern
 * input_set : storage key flag in order to get ptype
 */
struct nbl_flow_pattern_conf {
	struct nbl_fdir_fltr input;
	struct net_device *input_dev;
	struct nbl_common_info *common;
	u8  flow_send;
	u8  graph_idx;
	u8 acl_graph_idx;
	u16 pp_flag;
	u64 input_set;
	u64 key_flag;
	bool wildcard_flow;
	bool in_same_bond;
};

struct nbl_flow_index_key {
	union {
		u64 cookie;
		u8 data[NBL_FLOW_INDEX_BYTE_LEN];
	};
};

#define NBL_ASSOC_PROFILE_STAGE_NUM			(8)

struct nbl_tc_flow {
	u8 acl_flag:1;
	u8 is_spec:7;
	int flow_stat_id;
	u64 act_flags;
	struct nbl_flow_index_key key;
	u8 profile_id[NBL_ASSOC_PROFILE_STAGE_NUM];

	struct {
		void *profile_rule[NBL_ASSOC_PROFILE_STAGE_NUM];
	};
	struct nbl_encap_key *encap_key;
	struct nbl_tc_pedit_node_res pedit_node;
	struct nbl_flow_index_key index_key;
};

struct nbl_tc_flow_param {
	struct nbl_tc_port in;
	struct nbl_tc_port out;
	struct nbl_tc_port mirror_out;
	struct nbl_flow_pattern_conf filter;
	struct nbl_rule_action act;
	struct nbl_flow_index_key key;
	struct nbl_tc_parse_info *parse_info;
	struct ip_tunnel_info *tunnel;
	bool encap;
	struct nbl_common_info *common;
	struct nbl_service_mgt *serv_mgt;
};

struct nbl_stats_param {
	struct flow_cls_offload *f;
};

enum nbl_hwmon_type {
	NBL_HWMON_TEMP_INPUT,
	NBL_HWMON_TEMP_MAX,
	NBL_HWMON_TEMP_CRIT,
	NBL_HWMON_TEMP_HIGHEST,
	NBL_HWMON_TEMP_TYPE_MAX,
};

struct nbl_ethtool_module_eeprom {
	u32	offset;
	u32	length;
	u8	page;
	u8	bank;
	u8	i2c_address;
	u8	*data;
};

struct nbl_load_p4_param {
#define NBL_P4_SECTION_NAME_LEN		32
	u8 name[NBL_P4_SECTION_NAME_LEN];
	u32 addr;
	u32 size;
	u16 section_index;
	u16 section_offset;
	u8 *data;
	bool start;
	bool end;
};

struct nbl_tc_parse_key_info {
	u16 mask_type;
	u16 ignore_parse_pattern;
	int (*parse_func_after)(const void *rule,
				struct nbl_flow_pattern_conf *filter,
				u16 flag);
};

struct nbl_tc_parse_act_info {
	u16 ignore_parse_action;
	int (*parse_func_after)(struct nbl_rule_action *rule_act,
				const void *act_entry,
				struct nbl_flow_pattern_conf *filter);
};

#define TC_FLOWER_KEY_MAX 40
#define TC_FLOWER_ACT_MAX 40

struct nbl_tc_parse_info {
	struct nbl_tc_parse_key_info key_parse_info[TC_FLOWER_KEY_MAX];
	struct nbl_tc_parse_act_info act_parse_info[TC_FLOWER_ACT_MAX];
	int (*set_in_port_info)(struct nbl_tc_flow_param *param,
				struct nbl_flow_pattern_conf *filter);
	int (*set_out_port_info)(struct nbl_tc_flow_param *param,
				 struct nbl_rule_action *rule_act);
};

#define NBL_ACL_TCAM_KEY_LEN				5
#define NBL_ACL_TCAM_KEY_MAX				16

struct nbl_acl_tcam_key_param {
	u8 data[NBL_ACL_TCAM_KEY_LEN];
} __packed;

struct nbl_acl_tcam_param {
	union nbl_acl_tcam_info {
		struct nbl_acl_tcam_key_param key[NBL_ACL_TCAM_KEY_MAX];
		u8 data[NBL_ACL_TCAM_KEY_LEN * NBL_ACL_TCAM_KEY_MAX];
	} info;
	u8 len;
};

enum {
	NBL_NETIF_F_SG_BIT,			/* Scatter/gather IO. */
	NBL_NETIF_F_IP_CSUM_BIT,		/* Can checksum TCP/UDP over IPv4. */
	NBL_NETIF_F_HW_CSUM_BIT,		/* Can checksum all the packets. */
	NBL_NETIF_F_IPV6_CSUM_BIT,		/* Can checksum TCP/UDP over IPV6 */
	NBL_NETIF_F_HIGHDMA_BIT,		/* Can DMA to high memory. */
	NBL_NETIF_F_HW_VLAN_CTAG_TX_BIT,	/* Transmit VLAN CTAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_CTAG_RX_BIT,	/* Receive VLAN CTAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_CTAG_FILTER_BIT,	/* Receive filtering on VLAN CTAGs */
	NBL_NETIF_F_TSO_BIT,			/* ... TCPv4 segmentation */
	NBL_NETIF_F_GSO_ROBUST_BIT,		/* ... ->SKB_GSO_DODGY */
	NBL_NETIF_F_TSO6_BIT,			/* ... TCPv6 segmentation */
	NBL_NETIF_F_GSO_GRE_BIT,		/* ... GRE with TSO */
	NBL_NETIF_F_GSO_GRE_CSUM_BIT,		/* ... GRE with csum with TSO */
	NBL_NETIF_F_GSO_UDP_TUNNEL_BIT,		/* ... UDP TUNNEL with TSO */
	NBL_NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT,	/* ... UDP TUNNEL with TSO & CSUM */
	NBL_NETIF_F_GSO_PARTIAL_BIT,		/* ... Only segment inner-most L4
						 *     in hardware and all other
						 *     headers in software.
						 */
	NBL_NETIF_F_GSO_UDP_L4_BIT,		/* ... UDP payload GSO (not UFO) */
	NBL_NETIF_F_SCTP_CRC_BIT,		/* SCTP checksum offload */
	NBL_NETIF_F_NTUPLE_BIT,			/* N-tuple filters supported */
	NBL_NETIF_F_RXHASH_BIT,			/* Receive hashing offload */
	NBL_NETIF_F_RXCSUM_BIT,			/* Receive checksumming offload */
	NBL_NETIF_F_HW_VLAN_STAG_TX_BIT,	/* Transmit VLAN STAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_STAG_RX_BIT,	/* Receive VLAN STAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_STAG_FILTER_BIT,	/* Receive filtering on VLAN STAGs */
	NBL_NETIF_F_HW_TC_BIT,			/* Offload TC infrastructure */
	NBL_NETIF_F_GSO_IPXIP4_BIT,		/* ... IP4 or IP6 over IP4 with TSO */
	NBL_NETIF_F_GSO_IPXIP6_BIT,		/* ... IP4 or IP6 over IP6 with TSO */
	NBL_FEATURES_COUNT
};

static const netdev_features_t nbl_netdev_features[] = {
	[NBL_NETIF_F_SG_BIT] = NETIF_F_SG,
	[NBL_NETIF_F_IP_CSUM_BIT] = NETIF_F_IP_CSUM,
	[NBL_NETIF_F_IPV6_CSUM_BIT] = NETIF_F_IPV6_CSUM,
	[NBL_NETIF_F_HIGHDMA_BIT] = NETIF_F_HIGHDMA,
	[NBL_NETIF_F_HW_VLAN_CTAG_TX_BIT] = NETIF_F_HW_VLAN_CTAG_TX,
	[NBL_NETIF_F_HW_VLAN_CTAG_RX_BIT] = NETIF_F_HW_VLAN_CTAG_RX,
	[NBL_NETIF_F_HW_VLAN_CTAG_FILTER_BIT] = NETIF_F_HW_VLAN_CTAG_FILTER,
	[NBL_NETIF_F_TSO_BIT] = NETIF_F_TSO,
	[NBL_NETIF_F_GSO_ROBUST_BIT] = NETIF_F_GSO_ROBUST,
	[NBL_NETIF_F_TSO6_BIT] = NETIF_F_TSO6,
	[NBL_NETIF_F_GSO_GRE_BIT] = NETIF_F_GSO_GRE,
	[NBL_NETIF_F_GSO_GRE_CSUM_BIT] = NETIF_F_GSO_GRE_CSUM,
	[NBL_NETIF_F_GSO_UDP_TUNNEL_BIT] = NETIF_F_GSO_UDP_TUNNEL,
	[NBL_NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT] = NETIF_F_GSO_UDP_TUNNEL_CSUM,
	[NBL_NETIF_F_GSO_PARTIAL_BIT] = NETIF_F_GSO_PARTIAL,
	[NBL_NETIF_F_GSO_UDP_L4_BIT] = NETIF_F_GSO_UDP_L4,
	[NBL_NETIF_F_SCTP_CRC_BIT] = NETIF_F_SCTP_CRC,
	[NBL_NETIF_F_NTUPLE_BIT] = NETIF_F_NTUPLE,
	[NBL_NETIF_F_RXHASH_BIT] = NETIF_F_RXHASH,
	[NBL_NETIF_F_RXCSUM_BIT] = NETIF_F_RXCSUM,
	[NBL_NETIF_F_HW_VLAN_STAG_TX_BIT] = NETIF_F_HW_VLAN_STAG_TX,
	[NBL_NETIF_F_HW_VLAN_STAG_RX_BIT] = NETIF_F_HW_VLAN_STAG_RX,
	[NBL_NETIF_F_HW_VLAN_STAG_FILTER_BIT] = NETIF_F_HW_VLAN_STAG_FILTER,
	[NBL_NETIF_F_HW_TC_BIT] = NETIF_F_HW_TC,
	[NBL_NETIF_F_GSO_IPXIP4_BIT] = NETIF_F_GSO_IPXIP4,
	[NBL_NETIF_F_GSO_IPXIP6_BIT] = NETIF_F_GSO_IPXIP6,
};

#define NBL_FEATURE(name)			(1 << (NBL_##name##_BIT))
#define NBL_FEATURE_TEST_BIT(val, loc)		(((val) >> (loc)) & 0x1)

static inline netdev_features_t nbl_features_to_netdev_features(u64 features)
{
	netdev_features_t netdev_features = 0;
	int i = 0;

	for (i = 0; i < NBL_FEATURES_COUNT; i++) {
		if (NBL_FEATURE_TEST_BIT(features, i))
			netdev_features += nbl_netdev_features[i];
	}

	return netdev_features;
};

enum nbl_abnormal_event_module {
	NBL_ABNORMAL_EVENT_DVN = 0,
	NBL_ABNORMAL_EVENT_UVN,
	NBL_ABNORMAL_EVENT_MAX,
};

struct nbl_abnormal_details {
	bool abnormal;
	u16 qid;
	u16 vsi_id;
};

struct nbl_abnormal_event_info {
	struct nbl_abnormal_details details[NBL_ABNORMAL_EVENT_MAX];
	u32 other_abnormal_info;
};

enum nbl_performance_mode {
	NBL_QUIRKS_NO_TOE,
	NBL_QUIRKS_UVN_PREFETCH_ALIGN,
};

extern int performance_mode;

struct nbl_vsi_param {
	u16 vsi_id;
	u16 queue_offset;
	u16 queue_num;
	u8 index;
};

struct nbl_ring_param {
	u16 tx_ring_num;
	u16 rx_ring_num;
	u16 xdp_ring_offset; /* xdp-vsi queue'vertor share data-vsi queue */
	u16 queue_size;
	struct net_device *netdev;
};

struct nbl_tx_ring_start_param {
	u8 ring_index;
	bool interleave_seg_disable;
	u16 queue_size;
};

struct nbl_rx_ring_start_param {
	u8 ring_index;
	bool use_napi;
	u16 queue_size;
	bool rxq_large_buf;
};

struct nbl_net_features_param {
	struct net_device *netdev;
	netdev_features_t features;
};

struct nbl_dump_ring_param {
	struct seq_file *m;
	bool is_tx;
	int index;
};

struct nbl_vec_info_param {
	u8 *irq_enable_base;
	u32 irq_data;
	u16 index;
	bool mask_en;
};

struct nbl_vsi_ring_param {
	u16 vsi_index;
	u16 ring_offset;
	u16 ring_num;
};

enum nbl_trust_mode {
	NBL_TRUST_MODE_8021P,
	NBL_TRUST_MODE_DSCP
};

#define NBL_VSI_MAX_ID 1024
#define NBL_DRACO_VSI_MAX_ID 278
#define RDMA_RX_VLAN_VSI_ID(vsi)	(16 + (vsi) / 3)

struct nbl_mtu_entry {
	u32 ref_count;
	u16 mtu_value;
};

#define NBL_MAX_PFC_PRIORITIES (8)
#define NBL_DSCP_MAX (64)
#define NBL_TC_MAX_BW (100)
#define NBL_MAX_TC_NUM (8)
#define NBL_MAX_BW (100)

struct nbl_qos_info {
	u8 dcbx_mode;
	u8 dcbx_state;
	u8 trust_mode;		/* Trust Mode value 0:802.1p 1: dscp */
	u8 pfc[NBL_MAX_PFC_PRIORITIES];
	u8 dscp2prio_map[NBL_DSCP_MAX]; /* DSCP -> Priority map */
	int rdma_bw;
	u32 rdma_rate;
	u32 net_rate;
	DECLARE_BITMAP(dscp_mapped, NBL_DSCP_MAX);
#ifdef CONFIG_DCB
	struct ieee_ets ets;
#endif
	int buffer_sizes[NBL_MAX_PFC_PRIORITIES][2];
};

enum nbl_traffic_type {
	NBL_TRAFFIC_RDMA_TYPE,
	NBL_TRAFFIC_NET_TYPE,
};

struct nbl_napi_struct {
	struct napi_struct napi;
	atomic_t is_irq;
	u32 irq_cnt;
	u32 mask_cnt;
	u32 unmask_cnt;
	u32 complete_cnt;
};

#endif
