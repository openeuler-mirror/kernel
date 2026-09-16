/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _VIRTCHNL_H_
#define _VIRTCHNL_H_

/* These macros are used to generate compilation errors if a structure/union
 * is not exactly the correct length. It gives a divide by zero error if the
 * structure/union is not of the correct size, otherwise it creates an enum
 * that is never used.
 */
#define VIRTCHNL_CHECK_STRUCT_LEN(n, X) enum virtchnl_static_assert_enum_##X \
	{ virtchnl_static_assert_##X = (n)/((sizeof(struct X) == (n)) ? 1 : 0) }
#define VIRTCHNL_CHECK_UNION_LEN(n, X) enum virtchnl_static_asset_enum_##X \
	{ virtchnl_static_assert_##X = (n)/((sizeof(union X) == (n)) ? 1 : 0) }

/* Error Codes
 * Note that many older versions of various iAVF drivers convert the reported
 * status code directly into an iavf_status enumeration. For this reason, it
 * is important that the values of these enumerations line up.
 */
enum virtchnl_status_code {
	VIRTCHNL_STATUS_SUCCESS				= 0,
	VIRTCHNL_STATUS_ERR_PARAM			= -5,
	VIRTCHNL_STATUS_ERR_NO_MEMORY			= -18,
	VIRTCHNL_STATUS_ERR_TIMEOUT				= -19,
	VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH		= -38,
	VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR		= -39,
	VIRTCHNL_STATUS_ERR_INVALID_VF_ID		= -40,
	VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR		= -53,
	VIRTCHNL_STATUS_ERR_NOT_SUPPORTED		= -64,
};

#define VIRTCHNL_LINK_SPEED_10MB_SHIFT		0
#define VIRTCHNL_LINK_SPEED_100MB_SHIFT		1
#define VIRTCHNL_LINK_SPEED_1GB_SHIFT		2
#define VIRTCHNL_LINK_SPEED_2_5GB_SHIFT		3
#define VIRTCHNL_LINK_SPEED_5GB_SHIFT		4
#define VIRTCHNL_LINK_SPEED_10GB_SHIFT		5
#define VIRTCHNL_LINK_SPEED_20GB_SHIFT		6
#define VIRTCHNL_LINK_SPEED_25GB_SHIFT		7
#define VIRTCHNL_LINK_SPEED_40GB_SHIFT		8
#define VIRTCHNL_LINK_SPEED_50GB_SHIFT		9
#define VIRTCHNL_LINK_SPEED_100GB_SHIFT		10
#define VIRTCHNL_LINK_SPEED_200GB_SHIFT		11
#define VIRTCHNL_LINK_SPEED_400GB_SHIFT		12
#define VIRTCHNL_LINK_SPEED_800GB_SHIFT		13

enum virtchnl_link_speed {
	VIRTCHNL_LINK_SPEED_UNKNOWN	= 0,
	VIRTCHNL_LINK_SPEED_10MB	= BIT(VIRTCHNL_LINK_SPEED_10MB_SHIFT),
	VIRTCHNL_LINK_SPEED_100MB	= BIT(VIRTCHNL_LINK_SPEED_100MB_SHIFT),
	VIRTCHNL_LINK_SPEED_1GB		= BIT(VIRTCHNL_LINK_SPEED_1GB_SHIFT),
	VIRTCHNL_LINK_SPEED_2_5GB	= BIT(VIRTCHNL_LINK_SPEED_2_5GB_SHIFT),
	VIRTCHNL_LINK_SPEED_5GB		= BIT(VIRTCHNL_LINK_SPEED_5GB_SHIFT),
	VIRTCHNL_LINK_SPEED_10GB	= BIT(VIRTCHNL_LINK_SPEED_10GB_SHIFT),
	VIRTCHNL_LINK_SPEED_20GB	= BIT(VIRTCHNL_LINK_SPEED_20GB_SHIFT),
	VIRTCHNL_LINK_SPEED_25GB	= BIT(VIRTCHNL_LINK_SPEED_25GB_SHIFT),
	VIRTCHNL_LINK_SPEED_40GB	= BIT(VIRTCHNL_LINK_SPEED_40GB_SHIFT),
	VIRTCHNL_LINK_SPEED_50GB	= BIT(VIRTCHNL_LINK_SPEED_50GB_SHIFT),
	VIRTCHNL_LINK_SPEED_100GB	= BIT(VIRTCHNL_LINK_SPEED_100GB_SHIFT),
	VIRTCHNL_LINK_SPEED_200GB	= BIT(VIRTCHNL_LINK_SPEED_200GB_SHIFT),
	VIRTCHNL_LINK_SPEED_400GB	= BIT(VIRTCHNL_LINK_SPEED_400GB_SHIFT),
	VIRTCHNL_LINK_SPEED_800GB	= BIT(VIRTCHNL_LINK_SPEED_800GB_SHIFT),
};

/* Opcodes for VF-PF communication. These are placed in the v_opcode field
 * of the virtchnl_msg structure.
 */
enum virtchnl_ops {
/* The PF sends status change events to VFs using
 * the VIRTCHNL_OP_EVENT opcode.
 * VFs send requests to the PF using the other ops.
 * Use of "advanced opcode" features must be negotiated as part of capabilities
 * exchange and are not considered part of base mode feature set.
 *
 */
	VIRTCHNL_OP_UNKNOWN = 0,
	VIRTCHNL_OP_VERSION = 1, /* must ALWAYS be 1 */
	VIRTCHNL_OP_RESET_VF = 2,
	VIRTCHNL_OP_GET_VF_RESOURCES = 3,
	VIRTCHNL_OP_CONFIG_VSI_QUEUES = 6,
	VIRTCHNL_OP_CONFIG_IRQ_MAP = 7,
	VIRTCHNL_OP_ENABLE_QUEUES = 8,
	VIRTCHNL_OP_DISABLE_QUEUES = 9,
	VIRTCHNL_OP_ADD_ETH_ADDR = 10,
	VIRTCHNL_OP_DEL_ETH_ADDR = 11,
	VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE = 14,
	VIRTCHNL_OP_GET_STATS = 15,
	VIRTCHNL_OP_RSVD = 16,
	VIRTCHNL_OP_EVENT = 17, /* must ALWAYS be 17 */

	VIRTCHNL_OP_RESET_VF_RDMA = 19,

	VIRTCHNL_OP_IWARP = 20, /* advanced opcode */
	VIRTCHNL_OP_RDMA = VIRTCHNL_OP_IWARP,
	VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP = 21, /* advanced opcode */
	VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP = VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP,
	VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP = 22, /* advanced opcode */
	VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP = VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP,
	VIRTCHNL_OP_CONFIG_RSS_KEY = 23,
	VIRTCHNL_OP_CONFIG_RSS_LUT = 24,
	VIRTCHNL_OP_CONFIG_RSS_ALG = 25,

	VIRTCHNL_OP_SET_FDIR_INPUT_MASK = 26,

	VIRTCHNL_OP_SET_LOGALL_BITMAP = 27,

	VIRTCHNL_OP_QUERY_QUEUE_INFO = 28,

	/* opcode 34 is reserved */
	VIRTCHNL_OP_GET_SUPPORTED_RXDIDS = 44,
	VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS = 51,
	VIRTCHNL_OP_ADD_VLAN_V2 = 52,
	VIRTCHNL_OP_DEL_VLAN_V2 = 53,
	VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2 = 54,
	VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2 = 55,
	VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2 = 56,
	VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2 = 57,
	VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2 = 58,
	VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2 = 59,
	/* opcodes 60 through 65 are reserved */
	VIRTCHNL_OP_GET_QOS_CAPS = 66,
	VIRTCHNL_OP_CONFIG_QUEUE_TC_MAP = 67,
	/* opcode 68 through 70 are reserved */
	VIRTCHNL_OP_CONFIG_QUEUE_BW = 112,
	VIRTCHNL_OP_CONFIG_QUANTA = 113,
	VIRTCHNL_OP_FLOW_SUBSCRIBE = 114,
	VIRTCHNL_OP_FLOW_UNSUBSCRIBE = 115,
	VIRTCHNL_OP_MAX,
};

static const inline char *virtchnl_op_str(enum virtchnl_ops v_opcode)
{
	switch (v_opcode) {
	case VIRTCHNL_OP_UNKNOWN:
		return "VIRTCHNL_OP_UNKNOWN";
	case VIRTCHNL_OP_VERSION:
		return "VIRTCHNL_OP_VERSION";
	case VIRTCHNL_OP_RESET_VF:
		return "VIRTCHNL_OP_RESET_VF";
	case VIRTCHNL_OP_RESET_VF_RDMA:
		return "VIRTCHNL_OP_RESET_VF_RDMA";
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		return "VIRTCHNL_OP_GET_VF_RESOURCES";
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		return "VIRTCHNL_OP_CONFIG_VSI_QUEUES";
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		return "VIRTCHNL_OP_CONFIG_IRQ_MAP";
	case VIRTCHNL_OP_ENABLE_QUEUES:
		return "VIRTCHNL_OP_ENABLE_QUEUES";
	case VIRTCHNL_OP_DISABLE_QUEUES:
		return "VIRTCHNL_OP_DISABLE_QUEUES";
	case VIRTCHNL_OP_QUERY_QUEUE_INFO:
		return "VIRTCHNL_OP_QUERY_QUEUE_INFO";
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		return "VIRTCHNL_OP_ADD_ETH_ADDR";
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		return "VIRTCHNL_OP_DEL_ETH_ADDR";
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		return "VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE";
	case VIRTCHNL_OP_GET_STATS:
		return "VIRTCHNL_OP_GET_STATS";
	case VIRTCHNL_OP_RSVD:
		return "VIRTCHNL_OP_RSVD";
	case VIRTCHNL_OP_EVENT:
		return "VIRTCHNL_OP_EVENT";
	case VIRTCHNL_OP_RDMA:
		return "VIRTCHNL_OP_RDMA";
	case VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP:
		return "VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP:";
	case VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP:
		return "VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP";
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		return "VIRTCHNL_OP_CONFIG_RSS_KEY";
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		return "VIRTCHNL_OP_CONFIG_RSS_LUT";
	case VIRTCHNL_OP_CONFIG_RSS_ALG:
		return "VIRTCHNL_OP_CONFIG_RSS_ALG";
	case VIRTCHNL_OP_SET_FDIR_INPUT_MASK:
		return "VIRTCHNL_OP_SET_FDIR_INPUT_MASK";
	case VIRTCHNL_OP_SET_LOGALL_BITMAP:
		return "VIRTCHNL_OP_SET_LOGALL_BITMAP";

	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		return "VIRTCHNL_OP_GET_SUPPORTED_RXDIDS";
	case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS:
		return "VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS";
	case VIRTCHNL_OP_ADD_VLAN_V2:
		return "VIRTCHNL_OP_ADD_VLAN_V2";
	case VIRTCHNL_OP_DEL_VLAN_V2:
		return "VIRTCHNL_OP_DEL_VLAN_V2";
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
		return "VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2";
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
		return "VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2";
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
		return "VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2";
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
		return "VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2";
	case VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2:
		return "VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2";
	case VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2:
		return "VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2";
	case VIRTCHNL_OP_FLOW_SUBSCRIBE:
		return "VIRTCHNL_OP_FLOW_SUBSCRIBE";
	case VIRTCHNL_OP_FLOW_UNSUBSCRIBE:
		return "VIRTCHNL_OP_FLOW_UNSUBSCRIBE";
	case VIRTCHNL_OP_MAX:
		return "VIRTCHNL_OP_MAX";
	default:
		return "Unsupported (update virtchnl.h)";
	}
}

static const inline char *virtchnl_stat_str(enum virtchnl_status_code v_status)
{
	switch (v_status) {
	case VIRTCHNL_STATUS_SUCCESS:
		return "VIRTCHNL_STATUS_SUCCESS";
	case VIRTCHNL_STATUS_ERR_PARAM:
		return "VIRTCHNL_STATUS_ERR_PARAM";
	case VIRTCHNL_STATUS_ERR_NO_MEMORY:
		return "VIRTCHNL_STATUS_ERR_NO_MEMORY";
	case VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH:
		return "VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH";
	case VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR:
		return "VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR";
	case VIRTCHNL_STATUS_ERR_INVALID_VF_ID:
		return "VIRTCHNL_STATUS_ERR_INVALID_VF_ID";
	case VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR:
		return "VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR";
	case VIRTCHNL_STATUS_ERR_NOT_SUPPORTED:
		return "VIRTCHNL_STATUS_ERR_NOT_SUPPORTED";
	default:
		return "Unknown status code (update virtchnl.h)";
	}
}

/* Message descriptions and data structures. */

/* VIRTCHNL_OP_VERSION
 * VF posts its version number to the PF. PF responds with its version number
 * in the same format, along with a return code.
 * Reply from PF has its major/minor versions also in param0 and param1.
 * If there is a major version mismatch, then the VF cannot operate.
 * If there is a minor version mismatch, then the VF can operate but should
 * add a warning to the system log.
 *
 * This enum element MUST always be specified as == 1, regardless of other
 * changes in the API. The PF must always respond to this message without
 * error regardless of version mismatch.
 */
#define VIRTCHNL_VERSION_MAJOR		1
#define VIRTCHNL_VERSION_MINOR		0

struct virtchnl_version_info {
	u32 major;
	u32 minor;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_version_info);

/* VSI types that use VIRTCHNL interface for VF-PF communication. VSI_SRIOV
 * vsi_type should always be 6 for backward compatibility. Add other fields
 * as needed.
 */
enum virtchnl_vsi_type {
	VIRTCHNL_VSI_TYPE_INVALID = 0,
	VIRTCHNL_VSI_SRIOV = 6,
};

/* VIRTCHNL_OP_GET_VF_RESOURCES
 * Version 1.0 VF sends this request to PF with no parameters
 * Version 1.1 VF sends this request to PF with u32 bitmap of its capabilities
 * PF responds with an indirect message containing
 * virtchnl_vf_resource and one or more
 * virtchnl_vsi_resource structures.
 */

struct virtchnl_vsi_resource {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 num_queue_pairs;

	/* see enum virtchnl_vsi_type */
	u8 vsi_type;
	u8 vsi_mode;
	u16 qset_handle;
	u8 default_mac_addr[ETH_ALEN];
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_vsi_resource);

/* VF capability flags
 * VIRTCHNL_VF_OFFLOAD_L2 flag is inclusive of base mode L2 offloads including
 * TX/RX Checksum offloading and TSO for non-tunnelled packets.
 */
#define VIRTCHNL_VF_OFFLOAD_L2			BIT(0)
#define VIRTCHNL_VF_OFFLOAD_IWARP		BIT(1)
#define VIRTCHNL_VF_CAP_RDMA			VIRTCHNL_VF_OFFLOAD_IWARP
#define VIRTCHNL_VF_OFFLOAD_WB_ON_ITR		BIT(5)
#define VIRTCHNL_VF_OFFLOAD_BYPASS_SWITCH	BIT(6)

/* used to negotiate communicating link speeds in Mbps */
#define VIRTCHNL_VF_CAP_ADV_LINK_SPEED		BIT(7)

#define VIRTCHNL_VF_CAP_LAN_TX_USE_CQ		BIT(8)	/* if VF does not ask, but PF give, then VF must use CQ */
#define VIRTCHNL_VF_CAP_LAN_RX_USE_RSC		BIT(9)
#define VIRTCHNL_VF_CAP_FDIR				BIT(10)
#define VIRTCHNL_VF_CAP_LOGALL				BIT(11)

#define VIRTCHNL_VF_OFFLOAD_FSUB_PF		BIT(14)
#define VIRTCHNL_VF_OFFLOAD_VLAN_V2		BIT(15)
#define VIRTCHNL_VF_OFFLOAD_RX_POLLING		BIT(17)
#define VIRTCHNL_VF_OFFLOAD_RSS_PF		BIT(19)
#define VIRTCHNL_VF_OFFLOAD_ENCAP		BIT(20)
#define VIRTCHNL_VF_OFFLOAD_ENCAP_TSO		VIRTCHNL_VF_OFFLOAD_ENCAP
#define VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM		BIT(21)
#define VIRTCHNL_VF_OFFLOAD_RX_ENCAP_CSUM	BIT(22)

#define VIRTCHNL_VF_OFFLOAD_LSO			BIT(25)
#define VIRTCHNL_VF_OFFLOAD_TSO			VIRTCHNL_VF_OFFLOAD_LSO

#define VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC	BIT(26)
#define VIRTCHNL_VF_OFFLOAD_QOS			BIT(29)
	/* BIT(30) is reserved */
	/* BIT(31) is reserved */

#define VF_BASE_MODE_OFFLOADS (VIRTCHNL_VF_OFFLOAD_L2 | \
			       VIRTCHNL_VF_OFFLOAD_RSS_PF)

struct virtchnl_vf_resource {
	u16 num_vsis;
	u16 num_queue_pairs;
	u16 max_vectors;
	u16 max_mtu;

	u16 lan_txcq_base_abs_id;
	u16 lan_txcq_num;	/* should be max_vectors - 1 */
	u8	lan_txcq_initial_hw_gen;
	u8	platform_info;
	u16 lan_rxq_base_abs_id;	/* VF-RXQ-space base absolute ID */

	u64 vf_cap_flags;

	u32 rss_key_size;
	u32 rss_lut_size;
	u32 rss_ctl_alg;
	u32 rss_hash_alg;	/* not used for now */

	u32 fdir_mode;
	u16 fdir_drp_rxq_abs_id;
	u8 pf_id;
	u8 lan_channel_pf_id;

	__le32 fdir_hkey;
	__le32 fdir_skey;

	u32 fdir_max_num_pfilter;
	u32 fdir_max_num_sfilter;

	struct virtchnl_vsi_resource vsi_res;

	u16 max_lan_vectors;	/* max lan-irq-vector should be used, 0 for no limit (max_vectors - 1) */
	u16 pad0;
	u32 rsv[31];	//for future usage
};

VIRTCHNL_CHECK_STRUCT_LEN(208, virtchnl_vf_resource);

/* Tx queue config info */
struct virtchnl_txq_info {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 queue_id;		/* relative ID in VF lan-rxq/txq space */
	u16 ring_len;		/* number of descriptors, multiple of 8 */

	u64 dma_ring_addr;

	/* following only used for virtio */
	u64 dma_drv_addr;
	u64 dma_dev_addr;

	u16	tx_head;
	u16	tx_tail;
	u8 pad0[4];
};

VIRTCHNL_CHECK_STRUCT_LEN(40, virtchnl_txq_info);

/* RX descriptor IDs (range from 0 to 63) */
enum virtchnl_rx_desc_ids {
	VIRTCHNL_RXDID_0_32B_BASE		= 0,
	VIRTCHNL_RXDID_1_FLEX_NIC		= 1,
};

/* RX descriptor ID bitmasks */
enum virtchnl_rx_desc_id_bitmasks {
	VIRTCHNL_RXDID_0_32B_BASE_M		= BIT(VIRTCHNL_RXDID_0_32B_BASE),
	VIRTCHNL_RXDID_1_FLEX_NIC_M		= BIT(VIRTCHNL_RXDID_1_FLEX_NIC),
};

enum virtchnl_vsi_mode {
	VIRTCHNL_VSI_MODE_NATIVE	= 0,
	VIRTCHNL_VSI_MODE_VIRTIO	= 1,
};

/* Rx queue config info */
struct virtchnl_rxq_info {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 queue_id;		/* relative ID in VF lan-rxq/txq space */
	u8 pad0[2];

	u32 ring_len;		/* number of descriptors, multiple of 32 */
	u16 hdr_size;
	u16 splithdr_enabled; /* deprecated with AVF 1.0 */

	u32 databuffer_size;
	u32 max_pkt_size;

	/* see enum virtchnl_rx_desc_ids;
	 * only used when VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC is supported. Note
	 * that when the offload is not supported, the descriptor format aligns
	 * with VIRTCHNL_RXDID_1_32B_BASE.
	 */
	u8 rxdid;
	u8 pad1[3];
	/* see enum virtchnl_rx_hsplit; deprecated with AVF 1.0 */
	s32 rx_split_pos;

	u64 dma_ring_addr;

	/* following only used for virtio */
	u64 dma_drv_addr;
	u64 dma_dev_addr;

	u16	rx_head;
	u16	rx_tail;
	u8 pad2[4];
};

VIRTCHNL_CHECK_STRUCT_LEN(64, virtchnl_rxq_info);

/* VIRTCHNL_OP_CONFIG_VSI_QUEUES
 * VF sends this message to set parameters for active TX and RX queues
 * associated with the specified VSI.
 * PF configures queues and returns status.
 * If the number of queues specified is greater than the number of queues
 * associated with the VSI, an error is returned and no queues are configured.
 * NOTE: The VF is not required to configure all queues in a single request.
 * It may send multiple messages. PF drivers must correctly handle all VF
 * requests.
 */
struct virtchnl_queue_pair_info {
	/* NOTE: vsi_id and queue_id should be identical for both queues. */
	struct virtchnl_txq_info txq;
	struct virtchnl_rxq_info rxq;
};

VIRTCHNL_CHECK_STRUCT_LEN(104, virtchnl_queue_pair_info);

struct virtchnl_lan_txcq_info {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 queue_id;		/* relative ID in VF space */
	u8 pad0[2];

	u32 ring_len;		/* number of descriptors */
	u8 pad1[4];

	u64 dma_ring_addr;

	u64 rsv[2];
};

VIRTCHNL_CHECK_STRUCT_LEN(40, virtchnl_lan_txcq_info);

struct virtchnl_vsi_queue_config_info {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 num_queue_pairs;
	u16 num_txcq;

	u16 lan_tx_use_cq;
	u8 pad0[2];

	u8 vsi_mode;	/* enum virtchnl_vsi_mode */
	u8 pad1[3];

	struct virtchnl_queue_pair_info qpair[];
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_vsi_queue_config_info);

struct virtchnl_vsi_query_queue_info {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 num_qps;
	u8 vsi_mode;
	u8 pad;

	struct virtchnl_queue_pair_info qpair[];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_vsi_query_queue_info);

/* VIRTCHNL_OP_CONFIG_IRQ_MAP
 * VF uses this message to map vectors to queues.
 * The rxq_map and txq_map fields are bitmaps used to indicate which queues
 * are to be associated with the specified vector.
 * The "other" causes are always mapped to vector 0. The VF may not request
 * that vector 0 be used for traffic.
 * PF configures interrupt mapping and returns status.
 * NOTE: due to hardware requirements, all active queues (both TX and RX)
 * should be mapped to interrupts, even if the driver intends to operate
 * only in polling mode. In this case the interrupt may be disabled, but
 * the ITR timer will still run to trigger writebacks.
 */
struct virtchnl_vector_map {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 vector_id;
	u16 rxq_map;
	u16 txq_map;
	u8 pad[2];
};

VIRTCHNL_CHECK_STRUCT_LEN(12, virtchnl_vector_map);

struct virtchnl_irq_map_info {
	u16 num_vectors;
	u8 pad[2];

	struct virtchnl_vector_map vecmap[];
};

VIRTCHNL_CHECK_STRUCT_LEN(4, virtchnl_irq_map_info);

/* VIRTCHNL_OP_ENABLE_QUEUES
 * VIRTCHNL_OP_DISABLE_QUEUES
 * VF sends these message to enable or disable TX/RX queue pairs.
 * The queues fields are bitmaps indicating which queues to act upon.
 * (Currently, we only support 16 queues per VF, but we make the field
 * u32 to allow for expansion.)
 * PF performs requested action and returns status.
 * NOTE: The VF is not required to enable/disable all queues in a single
 * request. It may send multiple messages.
 * PF drivers must correctly handle all VF requests.
 */
struct virtchnl_queue_select {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u32 rx_queues;
	u32 tx_queues;
	u32 txcq_queues;
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_queue_select);

/* VIRTCHNL_OP_ADD_ETH_ADDR
 * VF sends this message in order to add one or more unicast or multicast
 * address filters for the specified VSI.
 * PF adds the filters and returns status.
 */

/* VIRTCHNL_OP_DEL_ETH_ADDR
 * VF sends this message in order to remove one or more unicast or multicast
 * filters for the specified VSI.
 * PF removes the filters and returns status.
 */

/* VIRTCHNL_ETHER_ADDR_LEGACY
 * Prior to adding the @type member to virtchnl_ether_addr, there were 2 pad
 * bytes. Moving forward all VF drivers should not set type to
 * VIRTCHNL_ETHER_ADDR_LEGACY. This is only here to not break previous/legacy
 * behavior. The control plane function (i.e. PF) can use a best effort method
 * of tracking the primary/device unicast in this case, but there is no
 * guarantee and functionality depends on the implementation of the PF.
 */

/* VIRTCHNL_ETHER_ADDR_PRIMARY
 * All VF drivers should set @type to VIRTCHNL_ETHER_ADDR_PRIMARY for the
 * primary/device unicast MAC address filter for VIRTCHNL_OP_ADD_ETH_ADDR and
 * VIRTCHNL_OP_DEL_ETH_ADDR. This allows for the underlying control plane
 * function (i.e. PF) to accurately track and use this MAC address for
 * displaying on the host and for VM/function reset.
 */

/* VIRTCHNL_ETHER_ADDR_EXTRA
 * All VF drivers should set @type to VIRTCHNL_ETHER_ADDR_EXTRA for any extra
 * unicast and/or multicast filters that are being added/deleted via
 * VIRTCHNL_OP_DEL_ETH_ADDR/VIRTCHNL_OP_ADD_ETH_ADDR respectively.
 */
struct virtchnl_ether_addr {
	u8 addr[ETH_ALEN];
	u8 type;
#define VIRTCHNL_ETHER_ADDR_LEGACY	0
#define VIRTCHNL_ETHER_ADDR_PRIMARY	1
#define VIRTCHNL_ETHER_ADDR_EXTRA	2
#define VIRTCHNL_ETHER_ADDR_TYPE_MASK	3 /* first two bits of type are valid */
	u8 pad;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_ether_addr);

struct virtchnl_ether_addr_list {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 num_elements;
	u8 pad[2];

	struct virtchnl_ether_addr list[];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_ether_addr_list);

/* This enum is used for all of the VIRTCHNL_VF_OFFLOAD_VLAN_V2_CAPS related
 * structures and opcodes.
 *
 * VIRTCHNL_VLAN_UNSUPPORTED - This field is not supported and if a VF driver
 * populates it the PF should return VIRTCHNL_STATUS_ERR_NOT_SUPPORTED.
 *
 * VIRTCHNL_VLAN_ETHERTYPE_8100 - This field supports 0x8100 ethertype.
 * VIRTCHNL_VLAN_ETHERTYPE_88A8 - This field supports 0x88A8 ethertype.
 *
 *
 * VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1 - Used to tell the VF to insert and/or
 * strip the VLAN tag using the L2TAG1 field of the Tx/Rx descriptors.
 *
 * VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2 - Used to tell the VF to insert hardware
 * offloaded VLAN tags using the L2TAG2 field of the Tx descriptor.
 *
 * VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2 - Used to tell the VF to strip hardware
 * offloaded VLAN tags using the L2TAG2_2 field of the Rx descriptor.
 *
 * VIRTCHNL_VLAN_PRIO - This field supports VLAN priority bits. This is used for
 * VLAN filtering if the underlying PF supports it.
 *
 * VIRTCHNL_VLAN_TOGGLE_ALLOWED - This field is used to say whether a
 * certain VLAN capability can be toggled. For example if the underlying PF/CP
 * allows the VF to toggle VLAN filtering, stripping, and/or insertion it should
 * set this bit along with the supported ethertypes.
 */
enum virtchnl_vlan_support {
	VIRTCHNL_VLAN_UNSUPPORTED =		0,
	VIRTCHNL_VLAN_ETHERTYPE_8100 =		0x00000001,
	VIRTCHNL_VLAN_ETHERTYPE_88A8 =		0x00000002,

	VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1 =	0x00000100,		/* make sense for both TXQ and RXQ, means TXQ-desc L2TAG1 and RXQ-desc L2TAG1 */
	VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2 =	0x00000200,		/* Only make sense for TXQ, means TXQ-desc L2TAG2 field, there is only 16 bit, no (2nd) and (1st) like RXQ-desc */
	VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2ND =	0x00000400,	/* Only make sense for RXQ, means RXQ-desc L2TAG2 (2nd) field, not L2TAG1 (1st) field */
	VIRTCHNL_VLAN_PRIO =			0x01000000,
	VIRTCHNL_VLAN_FILTER_MASK =		0x10000000,
	VIRTCHNL_VLAN_TOGGLE =			0x80000000
};

/* This structure is used as part of the VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS
 * for filtering, insertion, and stripping capabilities.
 *
 * If only outer capabilities are supported (for filtering, insertion, and/or
 * stripping) then this refers to the outer most or single VLAN from the VF's
 * perspective.
 *
 * If only inner capabilities are supported (for filtering, insertion, and/or
 * stripping) then this refers to the outer most or single VLAN from the VF's
 * perspective. Functionally this is the same as if only outer capabilities are
 * supported. The VF driver is just forced to use the inner fields when
 * adding/deleting filters and enabling/disabling offloads (if supported).
 *
 * If both outer and inner capabilities are supported (for filtering, insertion,
 * and/or stripping) then outer refers to the outer most or single VLAN and
 * inner refers to the second VLAN, if it exists, in the packet.
 *
 * There is no support for tunneled VLAN offloads, so outer or inner are never
 * referring to a tunneled packet from the VF's perspective.
 */
struct virtchnl_vlan_supported_caps {
	u32 outer;
	u32 inner;
};

/* The PF populates these fields based on the supported VLAN filtering. If a
 * field is VIRTCHNL_VLAN_UNSUPPORTED then it's not supported and the PF will
 * reject any VIRTCHNL_OP_ADD_VLAN_V2 or VIRTCHNL_OP_DEL_VLAN_V2 messages using
 * the unsupported fields.
 *
 * Also, a VF is only allowed to toggle its VLAN filtering setting if the
 * VIRTCHNL_VLAN_TOGGLE bit is set.
 *
 * The ethertype(s) specified in the ethertype_init field are the ethertypes
 * enabled for VLAN filtering. VLAN filtering in this case refers to the outer
 * most VLAN from the VF's perspective. If both inner and outer filtering are
 * allowed then ethertype_init only refers to the outer most VLAN as only
 * VLAN ethertype supported for inner VLAN filtering is
 * VIRTCHNL_VLAN_ETHERTYPE_8100. By default, inner VLAN filtering is disabled
 * when both inner and outer filtering are allowed.
 *
 * The max_filters field tells the VF how many VLAN filters it's allowed to have
 * at any one time. If it exceeds this amount and tries to add another filter,
 * then the request will be rejected by the PF. To prevent failures, the VF
 * should keep track of how many VLAN filters it has added and not attempt to
 * add more than max_filters.
 */
struct virtchnl_vlan_filtering_caps {
	struct virtchnl_vlan_supported_caps filtering_support;
	u32 ethertype_init;
	u16 max_filters;
	u8 pad[2];
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_vlan_filtering_caps);

/* This enum is used for the virtchnl_vlan_offload_caps structure to specify
 * if the PF supports a different ethertype for stripping and insertion.
 *
 * VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION - The ethertype(s) specified
 * for stripping affect the ethertype(s) specified for insertion and visa versa
 * as well. If the VF tries to configure VLAN stripping via
 * VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2 with VIRTCHNL_VLAN_ETHERTYPE_8100 then
 * that will be the ethertype for both stripping and insertion.
 *
 * VIRTCHNL_ETHERTYPE_MATCH_NOT_REQUIRED - The ethertype(s) specified for
 * stripping do not affect the ethertype(s) specified for insertion and visa
 * versa.
 */
enum virtchnl_vlan_ethertype_match {
	VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION = 0,
	VIRTCHNL_ETHERTYPE_MATCH_NOT_REQUIRED = 1,
};

/* The PF populates these fields based on the supported VLAN offloads. If a
 * field is VIRTCHNL_VLAN_UNSUPPORTED then it's not supported and the PF will
 * reject any VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2 or
 * VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2 messages using the unsupported fields.
 *
 * Also, a VF is only allowed to toggle its VLAN offload setting if the
 * VIRTCHNL_VLAN_TOGGLE_ALLOWED bit is set.
 *
 * The VF driver needs to be aware of how the tags are stripped by hardware and
 * inserted by the VF driver based on the level of offload support. The PF will
 * populate these fields based on where the VLAN tags are expected to be
 * offloaded via the VIRTHCNL_VLAN_TAG_LOCATION_* bits. The VF will need to
 * interpret these fields. See the definition of the
 * VIRTCHNL_VLAN_TAG_LOCATION_* bits above the virtchnl_vlan_support
 * enumeration.
 */
struct virtchnl_vlan_offload_caps {
	struct virtchnl_vlan_supported_caps stripping_support;
	struct virtchnl_vlan_supported_caps insertion_support;
	u32 ethertype_init;
	u8 ethertype_match;
	u8 pad[3];
};

VIRTCHNL_CHECK_STRUCT_LEN(24, virtchnl_vlan_offload_caps);

/* VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS
 * VF sends this message to determine its VLAN capabilities.
 *
 * PF will mark which capabilities it supports based on hardware support and
 * current configuration. For example, if a port VLAN is configured the PF will
 * not allow outer VLAN filtering, stripping, or insertion to be configured so
 * it will block these features from the VF.
 *
 * The VF will need to cross reference its capabilities with the PFs
 * capabilities in the response message from the PF to determine the VLAN
 * support.
 */
struct virtchnl_vlan_caps {
	struct virtchnl_vlan_filtering_caps filtering;
	struct virtchnl_vlan_offload_caps offloads;
};

VIRTCHNL_CHECK_STRUCT_LEN(40, virtchnl_vlan_caps);

struct virtchnl_vlan {
	u16 tci;	/* tci[15:13] = PCP and tci[11:0] = VID */
	u16 tci_mask;	/* only valid if VIRTCHNL_VLAN_FILTER_MASK set in
			 * filtering caps
			 */
	u16 tpid;	/* 0x8100, 0x88a8, etc. and only type(s) set in
			 * filtering caps. Note that tpid here does not refer to
			 * VIRTCHNL_VLAN_ETHERTYPE_*, but it refers to the
			 * actual 2-byte VLAN TPID
			 */
	u8 pad[2];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_vlan);

struct virtchnl_vlan_filter {
	struct virtchnl_vlan inner;
	struct virtchnl_vlan outer;
	u8 pad[16];
};

VIRTCHNL_CHECK_STRUCT_LEN(32, virtchnl_vlan_filter);

/* VIRTCHNL_OP_ADD_VLAN_V2
 * VIRTCHNL_OP_DEL_VLAN_V2
 *
 * VF sends these messages to add/del one or more VLAN tag filters for Rx
 * traffic.
 *
 * The PF attempts to add the filters and returns status.
 *
 * The VF should only ever attempt to add/del virtchnl_vlan_filter(s) using the
 * supported fields negotiated via VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS.
 */
struct virtchnl_vlan_filter_list_v2 {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 num_elements;
	u8 pad[2];

	struct virtchnl_vlan_filter filters[];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_vlan_filter_list_v2);

/* VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2
 * VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2
 * VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2
 * VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2
 *
 * VF sends this message to enable or disable VLAN stripping or insertion. It
 * also needs to specify an ethertype. The VF knows which VLAN ethertypes are
 * allowed and whether or not it's allowed to enable/disable the specific
 * offload via the VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS message. The VF needs to
 * parse the virtchnl_vlan_caps.offloads fields to determine which offload
 * messages are allowed.
 *
 * For example, if the PF populates the virtchnl_vlan_caps.offloads in the
 * following manner the VF will be allowed to enable and/or disable 0x8100 inner
 * VLAN insertion and/or stripping via the opcodes listed above. Inner in this
 * case means the outer most or single VLAN from the VF's perspective. This is
 * because no outer offloads are supported. See the comments above the
 * virtchnl_vlan_supported_caps structure for more details.
 *
 * virtchnl_vlan_caps.offloads.stripping_support.inner =
 *			VIRTCHNL_VLAN_TOGGLE |
 *			VIRTCHNL_VLAN_ETHERTYPE_8100;
 *
 * virtchnl_vlan_caps.offloads.insertion_support.inner =
 *			VIRTCHNL_VLAN_TOGGLE |
 *			VIRTCHNL_VLAN_ETHERTYPE_8100;
 *
 * In order to enable inner (again note that in this case inner is the outer
 * most or single VLAN from the VF's perspective) VLAN stripping for 0x8100
 * VLANs, the VF would populate the virtchnl_vlan_setting structure in the
 * following manner and send the VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2 message.
 *
 * virtchnl_vlan_setting.inner_ethertype_setting =
 *			VIRTCHNL_VLAN_ETHERTYPE_8100;
 *
 * virtchnl_vlan_setting.vport_id = vport_id or vsi_id assigned to the VF on
 * initialization.
 *
 * The reason that VLAN TPID(s) are not being used for the
 * outer_ethertype_setting and inner_ethertype_setting fields is because it's
 * possible a device could support VLAN insertion and/or stripping offload on
 * multiple ethertypes concurrently, so this method allows a VF to request
 * multiple ethertypes in one message using the virtchnl_vlan_support
 * enumeration.
 *
 * For example, if the PF populates the virtchnl_vlan_caps.offloads in the
 * following manner the VF will be allowed to enable 0x8100 and 0x88a8 outer
 * VLAN insertion and stripping simultaneously. The
 * virtchnl_vlan_caps.offloads.ethertype_match field will also have to be
 * populated based on what the PF can support.
 *
 * virtchnl_vlan_caps.offloads.stripping_support.outer =
 *			VIRTCHNL_VLAN_TOGGLE |
 *			VIRTCHNL_VLAN_ETHERTYPE_8100 |
 *			VIRTCHNL_VLAN_ETHERTYPE_88A8 |
 *			VIRTCHNL_VLAN_ETHERTYPE_AND;
 *
 * virtchnl_vlan_caps.offloads.insertion_support.outer =
 *			VIRTCHNL_VLAN_TOGGLE |
 *			VIRTCHNL_VLAN_ETHERTYPE_8100 |
 *			VIRTCHNL_VLAN_ETHERTYPE_88A8 |
 *			VIRTCHNL_VLAN_ETHERTYPE_AND;
 *
 * In order to enable outer VLAN stripping for 0x8100 and 0x88a8 VLANs, the VF
 * would populate the virthcnl_vlan_offload_structure in the following manner
 * and send the VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2 message.
 *
 * virtchnl_vlan_setting.outer_ethertype_setting =
 *			VIRTHCNL_VLAN_ETHERTYPE_8100 |
 *			VIRTHCNL_VLAN_ETHERTYPE_88A8;
 *
 * virtchnl_vlan_setting.vport_id = vport_id or vsi_id assigned to the VF on
 * initialization.
 *
 * There is also the case where a PF and the underlying hardware can support
 * VLAN offloads on multiple ethertypes, but not concurrently. For example, if
 * the PF populates the virtchnl_vlan_caps.offloads in the following manner the
 * VF will be allowed to enable and/or disable 0x8100 XOR 0x88a8 outer VLAN
 * offloads. The ethertypes must match for stripping and insertion.
 *
 * virtchnl_vlan_caps.offloads.stripping_support.outer =
 *			VIRTCHNL_VLAN_TOGGLE |
 *			VIRTCHNL_VLAN_ETHERTYPE_8100 |
 *			VIRTCHNL_VLAN_ETHERTYPE_88A8 |
 *			VIRTCHNL_VLAN_ETHERTYPE_XOR;
 *
 * virtchnl_vlan_caps.offloads.insertion_support.outer =
 *			VIRTCHNL_VLAN_TOGGLE |
 *			VIRTCHNL_VLAN_ETHERTYPE_8100 |
 *			VIRTCHNL_VLAN_ETHERTYPE_88A8 |
 *			VIRTCHNL_VLAN_ETHERTYPE_XOR;
 *
 * virtchnl_vlan_caps.offloads.ethertype_match =
 *			VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION;
 *
 * In order to enable outer VLAN stripping for 0x88a8 VLANs, the VF would
 * populate the virtchnl_vlan_setting structure in the following manner and send
 * the VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2. Also, this will change the
 * ethertype for VLAN insertion if it's enabled. So, for completeness, a
 * VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2 with the same ethertype should be sent.
 *
 * virtchnl_vlan_setting.outer_ethertype_setting = VIRTHCNL_VLAN_ETHERTYPE_88A8;
 *
 * virtchnl_vlan_setting.vport_id = vport_id or vsi_id assigned to the VF on
 * initialization.
 *
 * VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2
 * VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2
 *
 * VF sends this message to enable or disable VLAN filtering. It also needs to
 * specify an ethertype. The VF knows which VLAN ethertypes are allowed and
 * whether or not it's allowed to enable/disable filtering via the
 * VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS message. The VF needs to
 * parse the virtchnl_vlan_caps.filtering fields to determine which, if any,
 * filtering messages are allowed.
 *
 * For example, if the PF populates the virtchnl_vlan_caps.filtering in the
 * following manner the VF will be allowed to enable/disable 0x8100 and 0x88a8
 * outer VLAN filtering together. Note, that the VIRTCHNL_VLAN_ETHERTYPE_AND
 * means that all filtering ethertypes will to be enabled and disabled together
 * regardless of the request from the VF. This means that the underlying
 * hardware only supports VLAN filtering for all VLAN the specified ethertypes
 * or none of them.
 *
 * virtchnl_vlan_caps.filtering.filtering_support.outer =
 *			VIRTCHNL_VLAN_TOGGLE |
 *			VIRTCHNL_VLAN_ETHERTYPE_8100 |
 *			VIRTHCNL_VLAN_ETHERTYPE_88A8 |
 *			VIRTCHNL_VLAN_ETHERTYPE_9100 |
 *			VIRTCHNL_VLAN_ETHERTYPE_AND;
 *
 * In order to enable outer VLAN filtering for 0x88a8 and 0x8100 VLANs (0x9100
 * VLANs aren't supported by the VF driver), the VF would populate the
 * virtchnl_vlan_setting structure in the following manner and send the
 * VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2. The same message format would be used
 * to disable outer VLAN filtering for 0x88a8 and 0x8100 VLANs, but the
 * VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2 opcode is used.
 *
 * virtchnl_vlan_setting.outer_ethertype_setting =
 *			VIRTCHNL_VLAN_ETHERTYPE_8100 |
 *			VIRTCHNL_VLAN_ETHERTYPE_88A8;
 *
 */
struct virtchnl_vlan_setting {
	u32 outer_ethertype_setting;
	u32 inner_ethertype_setting;

	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u8 pad[4];
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_vlan_setting);

/* VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE
 * VF sends VSI id and flags.
 * PF returns status code in retval.
 * Note: we assume that broadcast accept mode is always enabled.
 */
struct virtchnl_promisc_info {
	u16 vsi_abs_id;
	u16 vsi_rel_id;

	u16 flags;
	u8 pad[2];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_promisc_info);

#define FLAG_VF_UNICAST_PROMISC	0x00000001
#define FLAG_VF_MULTICAST_PROMISC	0x00000002

/* VIRTCHNL_OP_CONFIG_RSS_KEY
 * VIRTCHNL_OP_CONFIG_RSS_LUT
 * VF sends these messages to configure RSS. Only supported if both PF
 * and VF drivers set the VIRTCHNL_VF_OFFLOAD_RSS_PF bit during
 * configuration negotiation. If this is the case, then the RSS fields in
 * the VF resource struct are valid.
 * Both the key and LUT are initialized to 0 by the PF, meaning that
 * RSS is effectively disabled until set up by the VF.
 */
struct virtchnl_rss_key {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 key_len;
	u8 key[1];         /* RSS hash key, packed bytes */
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_rss_key);

struct virtchnl_rss_lut {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u16 lut_entries;
	u16 lut[1];        /* RSS lookup table */
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_rss_lut);

/* VIRTCHNL_OP_CONFIG_RSS_ALG
 */
struct virtchnl_rss_alg {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	u32 ctl_alg;
	u32 hash_alg;	/* not used for now */
};

VIRTCHNL_CHECK_STRUCT_LEN(12, virtchnl_rss_alg);

struct virtchnl_fdir_input_mask {
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	__le32 flex_cfg;
	__le32 mask[7];
};

VIRTCHNL_CHECK_STRUCT_LEN(36, virtchnl_fdir_input_mask);

struct virtchnl_logall_ctl {
	u16 vsi_abs_id; /* vsi to enable logall */
	u16 vsi_rel_id; /* unused */
	u32 bitmap_len; /* length for mem to set logall enable/disable */
	u64 bitmap_addr; /* bitmap base address */
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_logall_ctl);

struct virtchnl_supported_rxdids {
	/* see enum virtchnl_rx_desc_id_bitmasks */
	u64 supported_rxdids;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_supported_rxdids);

/* VIRTCHNL_OP_EVENT
 * PF sends this message to inform the VF driver of events that may affect it.
 * No direct response is expected from the VF, though it may generate other
 * messages in response to this one.
 */
enum virtchnl_event_codes {
	VIRTCHNL_EVENT_UNKNOWN = 0,
	VIRTCHNL_EVENT_LINK_CHANGE,
	VIRTCHNL_EVENT_RESET_IMPENDING,
	VIRTCHNL_EVENT_PF_DRIVER_CLOSE,
};

#define PF_EVENT_SEVERITY_INFO		0
#define PF_EVENT_SEVERITY_CERTAIN_DOOM	255

struct virtchnl_pf_event {
	/* see enum virtchnl_event_codes */
	s32 event;
	union {
		/* If the PF driver does not support the new speed reporting
		 * capabilities then use link_event else use link_event_adv to
		 * get the speed and link information. The ability to understand
		 * new speeds is indicated by setting the capability flag
		 * VIRTCHNL_VF_CAP_ADV_LINK_SPEED in vf_cap_flags parameter
		 * in virtchnl_vf_resource struct and can be used to determine
		 * which link event struct to use below.
		 */
		struct {
			enum virtchnl_link_speed link_speed;
			bool link_status;
			u8 flags;
			u8 pad[2];
#define VIRTCHNL_LINK_EVENT_FLAG_FORCE_UPDATE	0x1
		} link_event;
		struct {
			/* link_speed provided in Mbps */
			u32 link_speed;
			u8 link_status;
			u8 flags;
			u8 pad[2];
		} link_event_adv;
		struct {
			u8 reset_type;	/* nse_reset_req (1 for pf reset, 2 for high-reset, 0 for normal VF reset ) */
		} reset_event;
	} event_data;

	s32 severity;
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_pf_event);

/* used to specify if a ceq_idx or aeq_idx is invalid */
#define VIRTCHNL_RDMA_INVALID_QUEUE_IDX	0xFFFF
/* VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP
 * VF uses this message to request PF to map RDMA vectors to RDMA queues.
 * The request for this originates from the VF RDMA driver through
 * a client interface between VF LAN and VF RDMA driver.
 * A vector could have an AEQ and CEQ attached to it although
 * there is a single AEQ per VF RDMA instance in which case
 * most vectors will have an VIRTCHNL_RDMA_INVALID_QUEUE_IDX for aeq and valid
 * idx for ceqs There will never be a case where there will be multiple CEQs
 * attached to a single vector.
 * PF configures interrupt mapping and returns status.
 */
#define virtchnl_iwarp_qv_info virtchnl_rdma_qv_info
struct virtchnl_rdma_qv_info {
	u32 v_idx; /* msix_vector */
	u16 ceq_idx; /* set to VIRTCHNL_RDMA_INVALID_QUEUE_IDX if invalid */
	u16 aeq_idx; /* set to VIRTCHNL_RDMA_INVALID_QUEUE_IDX if invalid */
	u8 itr_idx;
};

VIRTCHNL_CHECK_STRUCT_LEN(12, virtchnl_rdma_qv_info);

#define virtchnl_iwarp_qvlist_info virtchnl_rdma_qvlist_info
struct virtchnl_rdma_qvlist_info {
	u32 num_vectors;
	struct virtchnl_rdma_qv_info qv_info[];
};

VIRTCHNL_CHECK_STRUCT_LEN(4, virtchnl_rdma_qvlist_info);

/* Since VF messages are limited by u16 size, precalculate the maximum possible
 * values of nested elements in virtchnl structures that virtual channel can
 * possibly handle in a single message.
 */
enum virtchnl_vector_limits {
	VIRTCHNL_OP_CONFIG_VSI_QUEUES_MAX	=
		((u16)(~0) - sizeof(struct virtchnl_vsi_queue_config_info)) /
		sizeof(struct virtchnl_queue_pair_info),

	VIRTCHNL_OP_CONFIG_IRQ_MAP_MAX		=
		((u16)(~0) - sizeof(struct virtchnl_irq_map_info)) /
		sizeof(struct virtchnl_vector_map),

	VIRTCHNL_OP_ADD_DEL_ETH_ADDR_MAX	=
		((u16)(~0) - sizeof(struct virtchnl_ether_addr_list)) /
		sizeof(struct virtchnl_ether_addr),

	VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP_MAX	=
		((u16)(~0) - sizeof(struct virtchnl_rdma_qvlist_info)) /
		sizeof(struct virtchnl_rdma_qv_info),

	VIRTCHNL_OP_ADD_DEL_VLAN_V2_MAX		=
		((u16)(~0) - sizeof(struct virtchnl_vlan_filter_list_v2)) /
		sizeof(struct virtchnl_vlan_filter),
};

/**
 * virtchnl_vc_validate_vf_msg
 * @ver: Virtchnl version info
 * @v_opcode: Opcode for the message
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 *
 * validate msg format against struct for each opcode
 *
 * The opcodes carrying a trailing array expect the structure header, one
 * entry for that array and the entries named by the element count field.
 * Those structures used to declare the array as a one-element array, so
 * sizeof() covered one entry; it is added explicitly now that the array is
 * a C99 flexible array, which keeps the message layout unchanged.
 */
static inline int
virtchnl_vc_validate_vf_msg(struct virtchnl_version_info *ver, u32 v_opcode,
			    u8 *msg, u16 msglen)
{
	bool err_msg_format = false;
	u32 valid_len = 0;

	/* Validate message length. */
	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
		valid_len = sizeof(struct virtchnl_version_info);
		break;
	case VIRTCHNL_OP_RESET_VF:
	case VIRTCHNL_OP_RESET_VF_RDMA:
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		valid_len = sizeof(u64);
		break;
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		valid_len = sizeof(struct virtchnl_vsi_queue_config_info);
		if (msglen >= valid_len) {
			struct virtchnl_vsi_queue_config_info *vqc =
			    (struct virtchnl_vsi_queue_config_info *)msg;

			if (vqc->num_queue_pairs == 0 || vqc->num_queue_pairs >
			    VIRTCHNL_OP_CONFIG_VSI_QUEUES_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += (vqc->num_queue_pairs + 1) *
				      sizeof(struct
					     virtchnl_queue_pair_info);

			if (vqc->lan_tx_use_cq)
				valid_len += (vqc->num_txcq * sizeof(struct virtchnl_lan_txcq_info));
		}
		break;
	case VIRTCHNL_OP_QUERY_QUEUE_INFO:
		valid_len = sizeof(struct virtchnl_vsi_query_queue_info);

		if (msglen >= valid_len) {
			struct virtchnl_vsi_query_queue_info *qqc =
				(struct virtchnl_vsi_query_queue_info *)msg;

			if (qqc->num_qps == 0 ||
				(qqc->num_qps > VIRTCHNL_OP_CONFIG_VSI_QUEUES_MAX)) {
				err_msg_format = true;
				break;
			}

			if (qqc->num_qps)
				valid_len += (qqc->num_qps *
						sizeof(struct
							virtchnl_queue_pair_info));
		}

		break;

	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		valid_len = sizeof(struct virtchnl_irq_map_info);
		if (msglen >= valid_len) {
			struct virtchnl_irq_map_info *vimi =
			    (struct virtchnl_irq_map_info *)msg;

			if (vimi->num_vectors == 0 || vimi->num_vectors >
			    VIRTCHNL_OP_CONFIG_IRQ_MAP_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += (vimi->num_vectors + 1) *
				      sizeof(struct virtchnl_vector_map);
		}
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
	case VIRTCHNL_OP_DISABLE_QUEUES:
		valid_len = sizeof(struct virtchnl_queue_select);
		break;
	case VIRTCHNL_OP_ADD_ETH_ADDR:
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		valid_len = sizeof(struct virtchnl_ether_addr_list);
		if (msglen >= valid_len) {
			struct virtchnl_ether_addr_list *veal =
			    (struct virtchnl_ether_addr_list *)msg;

			if (veal->num_elements == 0 || veal->num_elements >
			    VIRTCHNL_OP_ADD_DEL_ETH_ADDR_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += (veal->num_elements + 1) *
			    sizeof(struct virtchnl_ether_addr);
		}
		break;
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		valid_len = sizeof(struct virtchnl_promisc_info);
		break;
	case VIRTCHNL_OP_GET_STATS:
		valid_len = sizeof(struct virtchnl_queue_select);
		break;
	case VIRTCHNL_OP_RDMA:
		/* These messages are opaque to us and will be validated in
		 * the RDMA client code. We just need to check for nonzero
		 * length. The firmware will enforce max length restrictions.
		 */
		if (msglen)
			valid_len = msglen;
		else
			err_msg_format = true;
		break;
	case VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP:
		break;
	case VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP:
		valid_len = sizeof(struct virtchnl_rdma_qvlist_info);
		if (msglen >= valid_len) {
			struct virtchnl_rdma_qvlist_info *qv =
				(struct virtchnl_rdma_qvlist_info *)msg;

			if (qv->num_vectors == 0 || qv->num_vectors >
			    VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += (qv->num_vectors *
				sizeof(struct virtchnl_rdma_qv_info));
		}
		break;
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		valid_len = sizeof(struct virtchnl_rss_key);
		if (msglen >= valid_len) {
			struct virtchnl_rss_key *vrk =
				(struct virtchnl_rss_key *)msg;

			if (vrk->key_len == 0) {
				/* zero length is allowed as input */
				break;
			}

			valid_len += vrk->key_len - 1;
		}
		break;
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		valid_len = sizeof(struct virtchnl_rss_lut);
		if (msglen >= valid_len) {
			struct virtchnl_rss_lut *vrl =
				(struct virtchnl_rss_lut *)msg;

			if (vrl->lut_entries == 0) {
				/* zero entries is allowed as input */
				break;
			}

			valid_len += (sizeof(u16) * vrl->lut_entries) - 2;
		}
		break;

	case VIRTCHNL_OP_CONFIG_RSS_ALG:
		valid_len = sizeof(struct virtchnl_rss_alg);
		break;

	case VIRTCHNL_OP_SET_FDIR_INPUT_MASK:
		valid_len = sizeof(struct virtchnl_fdir_input_mask);
		break;

	case VIRTCHNL_OP_SET_LOGALL_BITMAP:
		valid_len = sizeof(struct virtchnl_logall_ctl);
		break;

	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		break;

	case VIRTCHNL_OP_GET_QOS_CAPS:
		break;
	case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS:
		break;
	case VIRTCHNL_OP_ADD_VLAN_V2:
	case VIRTCHNL_OP_DEL_VLAN_V2:
		valid_len = sizeof(struct virtchnl_vlan_filter_list_v2);
		if (msglen >= valid_len) {
			struct virtchnl_vlan_filter_list_v2 *vfl =
			    (struct virtchnl_vlan_filter_list_v2 *)msg;

			if (vfl->num_elements == 0 || vfl->num_elements >
			    VIRTCHNL_OP_ADD_DEL_VLAN_V2_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += vfl->num_elements *
				sizeof(struct virtchnl_vlan_filter);
		}
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
	case VIRTCHNL_OP_ENABLE_VLAN_FILTERING_V2:
	case VIRTCHNL_OP_DISABLE_VLAN_FILTERING_V2:
		valid_len = sizeof(struct virtchnl_vlan_setting);
		break;
	/* These are always errors coming from the VF. */
	case VIRTCHNL_OP_EVENT:
	case VIRTCHNL_OP_UNKNOWN:
	default:
		return VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
	}
	/* few more checks */
	if (err_msg_format || valid_len > msglen)
		return VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH;

	return 0;
}
#endif

