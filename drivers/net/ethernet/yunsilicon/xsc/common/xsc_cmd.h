/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_CMD_H
#define XSC_CMD_H

#define CMDQ_VERSION 0x32

#define ETH_ALEN	6

#define QOS_PRIO_MAX		7
#define	QOS_DSCP_MAX		63
#define MAC_PORT_DSCP_SHIFT	6
#define	QOS_PCP_MAX		7
#define DSCP_PCP_UNSET		255
#define MAC_PORT_PCP_SHIFT	3
#define XSC_MAX_MAC_NUM		8
#define XSC_BOARD_SN_LEN	32
#define MAX_PKT_LEN		9800
#define XSC_RTT_CFG_QPN_MAX 32
#define XSC_QP_MEASURE_QP_NUM_MAX  128

#define XSC_PCIE_LAT_CFG_INTERVAL_MAX	8
#define XSC_PCIE_LAT_CFG_HISTOGRAM_MAX	9
#define XSC_PCIE_LAT_EN_DISABLE		0
#define XSC_PCIE_LAT_EN_ENABLE		1
#define XSC_PCIE_LAT_PERIOD_MIN		1
#define XSC_PCIE_LAT_PERIOD_MAX		20
#define DPU_PORT_WGHT_CFG_MAX		1

#define XSC_MAX_NUM_PCIE_INTF		2
#define XSC_MAX_PF_NUM_PER_PCIE		8

/* xsc_cmd_status_code is used to indicate the result of a xsc cmd executing.
 * How to use it please refer to the design doc:
 * https://eb72aga9oq.feishu.cn/docx/UF0GdlGBRoEtvvx1FrAcrnmLnug
 */
enum xsc_cmd_status_code {
	/* common status code, range: 0x0 ~ 0x1f */
	XSC_CMD_STATUS_OK			= 0x0,
	XSC_CMD_STATUS_FAIL			= 0x1,
	XSC_CMD_STATUS_NOT_SUPPORTED		= 0x2,
	XSC_CMD_STATUS_BAD_PARAM		= 0x3,
	XSC_CMD_STATUS_INVAL_RES		= 0x5,
	XSC_CMD_STATUS_BUSY			= 0x6,
	XSC_CMD_STATUS_PENDING			= 0x7,
	XSC_CMD_STATUS_INVAL_DATA		= 0x8,
	XSC_CMD_STATUS_NOT_FOUND		= 0xa,
	XSC_CMD_STATUS_NO_RES			= 0xf,

	/* extended status code, range: 0x20 ~ 0x4f */
	XSC_CMD_STATUS_INVAL_FUNC		= 0x41,
	XSC_CMD_STATUS_NO_MPT_RES		= 0x42,
	XSC_CMD_STATUS_NO_MTT_RES		= 0x43,
	XSC_CMD_STATUS_NO_EQN_RES		= 0x44,
	XSC_CMD_STATUS_NO_EQ_PA_RES		= 0x45,
	XSC_CMD_STATUS_NO_CQN_RES		= 0x46,
	XSC_CMD_STATUS_NO_CQ_PA_RES		= 0x47,
	XSC_CMD_STATUS_NO_QPN_RES		= 0x48,
	XSC_CMD_STATUS_NO_QP_PA_RES		= 0x49,
	XSC_CMD_STATUS_NO_PDN_RES		= 0x4a,
	XSC_CMD_STATUS_QP_FLUSH_BUSY		= 0x4b,
	XSC_CMD_STATUS_QP_FLUSH_PENDING		= 0x4c,

	/* Cmdq prototol status code, range: 0x50 ~ 0x5f */
	XSC_CMD_STATUS_BAD_INBUF		= 0x50,
	XSC_CMD_STATUS_BAD_OUTBUF		= 0x51,
	XSC_CMD_STATUS_INVAL_OPCODE		= 0x52,

	XSC_CMD_STATUS_CODE_MAX			= 0xff,
};

#define XSC_CMD_STATUS_CODE_COUNT		(XSC_CMD_STATUS_CODE_MAX + 1)

struct xsc_cmd_status_code_map {
	int errno;
	const char *str;
};

enum {
	DPU_PORT_WGHT_TARGET_HOST,
	DPU_PORT_WGHT_TARGET_SOC,
	DPU_PORT_WGHT_TARGET_NUM,
};

enum {
	DPU_PRIO_WGHT_TARGET_HOST2SOC,
	DPU_PRIO_WGHT_TARGET_SOC2HOST,
	DPU_PRIO_WGHT_TARGET_HOSTSOC2LAG,
	DPU_PRIO_WGHT_TARGET_NUM,
};

#define XSC_AP_FEAT_UDP_SPORT_MIN	1024
#define XSC_AP_FEAT_UDP_SPORT_MAX	65535

enum {
	XSC_CMD_OP_QUERY_HCA_CAP		= 0x100,
	XSC_CMD_OP_QUERY_ADAPTER		= 0x101,
	XSC_CMD_OP_INIT_HCA			= 0x102,
	XSC_CMD_OP_TEARDOWN_HCA			= 0x103,
	XSC_CMD_OP_ENABLE_HCA			= 0x104,
	XSC_CMD_OP_DISABLE_HCA			= 0x105,
	XSC_CMD_OP_MODIFY_HCA			= 0x106,
	XSC_CMD_OP_QUERY_PAGES			= 0x107,
	XSC_CMD_OP_MANAGE_PAGES			= 0x108,
	XSC_CMD_OP_SET_HCA_CAP			= 0x109,
	XSC_CMD_OP_QUERY_CMDQ_VERSION		= 0x10a,
	XSC_CMD_OP_QUERY_MSIX_TBL_INFO		= 0x10b,
	XSC_CMD_OP_FUNCTION_RESET		= 0x10c,
	XSC_CMD_OP_DUMMY			= 0x10d,
	XSC_CMD_OP_SET_DEBUG_INFO		= 0x10e,
	XSC_CMD_OP_QUERY_PSV_FUNCID		= 0x10f,
	XSC_CMD_OP_ALLOC_IA_LOCK		= 0x110,
	XSC_CMD_OP_RELEASE_IA_LOCK		= 0x111,
	XSC_CMD_OP_ENABLE_RELAXED_ORDER		= 0x112,
	XSC_CMD_OP_QUERY_GUID			= 0x113,
	XSC_CMD_OP_ACTIVATE_HW_CONFIG		= 0x114,
	XSC_CMD_OP_QUERY_READ_FLUSH		= 0x115,
	XSC_CMD_OP_SEND_TUNNEL_CMD_REQ		= 0x116,
	XSC_CMD_OP_RECV_TUNNEL_CMD_REQ		= 0x117,
	XSC_CMD_OP_SEND_TUNNEL_CMD_RESP		= 0x118,
	XSC_CMD_OP_RECV_TUNNEL_CMD_RESP		= 0x119,
	XSC_CMD_OP_GET_IOCTL_INFO		= 0x11a,
	XSC_CMD_OP_ANNOUNCE_DRIVER_INSTANCE	= 0x11b,

	XSC_CMD_OP_CREATE_MKEY			= 0x200,
	XSC_CMD_OP_QUERY_MKEY			= 0x201,
	XSC_CMD_OP_DESTROY_MKEY			= 0x202,
	XSC_CMD_OP_QUERY_SPECIAL_CONTEXTS	= 0x203,
	XSC_CMD_OP_REG_MR			= 0x204,
	XSC_CMD_OP_DEREG_MR			= 0x205,
	XSC_CMD_OP_SET_MPT			= 0x206,
	XSC_CMD_OP_SET_MTT			= 0x207,
	XSC_CMD_OP_SYNC_MR_TO_FW		= 0x208,
	XSC_CMD_OP_SYNC_MR_FROM_FW		= 0x209,

	XSC_CMD_OP_CREATE_EQ			= 0x301,
	XSC_CMD_OP_DESTROY_EQ			= 0x302,
	XSC_CMD_OP_QUERY_EQ			= 0x303,

	XSC_CMD_OP_CREATE_CQ			= 0x400,
	XSC_CMD_OP_DESTROY_CQ			= 0x401,
	XSC_CMD_OP_QUERY_CQ			= 0x402,
	XSC_CMD_OP_MODIFY_CQ			= 0x403,
	XSC_CMD_OP_ALLOC_MULTI_VIRTQ_CQ    = 0x404,
	XSC_CMD_OP_RELEASE_MULTI_VIRTQ_CQ  = 0x405,
	XSC_CMD_OP_SET_CQ_CONTEXT		= 0x406,
	XSC_CMD_OP_SET_CQ_BUF_PA		= 0x407,
	XSC_CMD_OP_CREATE_CQ_EX			= 0x408,

	XSC_CMD_OP_CREATE_QP			= 0x500,
	XSC_CMD_OP_DESTROY_QP			= 0x501,
	XSC_CMD_OP_RST2INIT_QP			= 0x502,
	XSC_CMD_OP_INIT2RTR_QP			= 0x503,
	XSC_CMD_OP_RTR2RTS_QP			= 0x504,
	XSC_CMD_OP_RTS2RTS_QP			= 0x505,
	XSC_CMD_OP_SQERR2RTS_QP			= 0x506,
	XSC_CMD_OP_2ERR_QP			= 0x507,
	XSC_CMD_OP_RTS2SQD_QP			= 0x508,
	XSC_CMD_OP_SQD2RTS_QP			= 0x509,
	XSC_CMD_OP_2RST_QP			= 0x50a,
	XSC_CMD_OP_QUERY_QP			= 0x50b,
	XSC_CMD_OP_CONF_SQP			= 0x50c,
	XSC_CMD_OP_MAD_IFC			= 0x50d,
	XSC_CMD_OP_INIT2INIT_QP			= 0x50e,
	XSC_CMD_OP_SUSPEND_QP			= 0x50f,
	XSC_CMD_OP_UNSUSPEND_QP			= 0x510,
	XSC_CMD_OP_SQD2SQD_QP			= 0x511,
	XSC_CMD_OP_ALLOC_QP_COUNTER_SET		= 0x512,
	XSC_CMD_OP_DEALLOC_QP_COUNTER_SET	= 0x513,
	XSC_CMD_OP_QUERY_QP_COUNTER_SET		= 0x514,
	XSC_CMD_OP_CREATE_MULTI_QP		= 0x515,
	XSC_CMD_OP_ALLOC_MULTI_VIRTQ    = 0x516,
	XSC_CMD_OP_RELEASE_MULTI_VIRTQ  = 0x517,
	XSC_CMD_OP_QUERY_QP_FLUSH_STATUS	= 0x518,
	XSC_CMD_OP_ALLOC_QPN			= 0x519,
	XSC_CMD_OP_DEALLOC_QPN			= 0x520,
	XSC_CMD_OP_SET_QP_INFO			= 0x521,
	XSC_CMD_QP_UNSET_QP_INFO		= 0x522,

	XSC_CMD_OP_CREATE_PSV			= 0x600,
	XSC_CMD_OP_DESTROY_PSV			= 0x601,
	XSC_CMD_OP_QUERY_PSV			= 0x602,
	XSC_CMD_OP_QUERY_SIG_RULE_TABLE		= 0x603,
	XSC_CMD_OP_QUERY_BLOCK_SIZE_TABLE	= 0x604,

	XSC_CMD_OP_CREATE_SRQ			= 0x700,
	XSC_CMD_OP_DESTROY_SRQ			= 0x701,
	XSC_CMD_OP_QUERY_SRQ			= 0x702,
	XSC_CMD_OP_ARM_RQ			= 0x703,
	XSC_CMD_OP_RESIZE_SRQ			= 0x704,

	XSC_CMD_OP_ALLOC_PD			= 0x800,
	XSC_CMD_OP_DEALLOC_PD			= 0x801,
	XSC_CMD_OP_ALLOC_UAR			= 0x802,
	XSC_CMD_OP_DEALLOC_UAR			= 0x803,

	XSC_CMD_OP_ATTACH_TO_MCG		= 0x806,
	XSC_CMD_OP_DETACH_FROM_MCG		= 0x807,

	XSC_CMD_OP_ALLOC_XRCD			= 0x80e,
	XSC_CMD_OP_DEALLOC_XRCD			= 0x80f,

	XSC_CMD_OP_ACCESS_REG			= 0x805,

	XSC_CMD_OP_MODIFY_RAW_QP		= 0x81f,

	XSC_CMD_OP_ENABLE_NIC_HCA		= 0x810,
	XSC_CMD_OP_DISABLE_NIC_HCA		= 0x811,
	XSC_CMD_OP_MODIFY_NIC_HCA		= 0x812,
	XSC_CMD_OP_QUERY_PKT_DST_INFO		= 0x813,
	XSC_CMD_OP_MODIFY_PKT_DST_INFO		= 0x814,

	XSC_CMD_OP_QUERY_NIC_VPORT_CONTEXT	= 0x820,
	XSC_CMD_OP_MODIFY_NIC_VPORT_CONTEXT	= 0x821,
	XSC_CMD_OP_QUERY_VPORT_STATE		= 0x822,
	XSC_CMD_OP_MODIFY_VPORT_STATE		= 0x823,
	XSC_CMD_OP_QUERY_HCA_VPORT_CONTEXT	= 0x824,
	XSC_CMD_OP_MODIFY_HCA_VPORT_CONTEXT	= 0x825,
	XSC_CMD_OP_QUERY_HCA_VPORT_GID		= 0x826,
	XSC_CMD_OP_QUERY_HCA_VPORT_PKEY		= 0x827,
	XSC_CMD_OP_QUERY_VPORT_COUNTER		= 0x828,
	XSC_CMD_OP_QUERY_PRIO_STATS		= 0x829,
	XSC_CMD_OP_QUERY_PHYPORT_STATE		= 0x830,
	XSC_CMD_OP_QUERY_EVENT_TYPE		= 0x831,
	XSC_CMD_OP_QUERY_LINK_INFO		= 0x832,
	XSC_CMD_OP_QUERY_PFC_PRIO_STATS		= 0x833,
	XSC_CMD_OP_MODIFY_LINK_INFO		= 0x834,
	XSC_CMD_OP_QUERY_FEC_PARAM		= 0x835,
	XSC_CMD_OP_MODIFY_FEC_PARAM		= 0x836,
	XSC_CMD_OP_MODIFY_NIC_VPORT_UC_MAC	= 0x837,
	XSC_CMD_OP_MODIFY_NIC_VPORT_MC_MAC	= 0x838,

	XSC_CMD_OP_LAG_CREATE				= 0x840,
	XSC_CMD_OP_LAG_ADD_MEMBER			= 0x841,
	XSC_CMD_OP_LAG_REMOVE_MEMBER		= 0x842,
	XSC_CMD_OP_LAG_UPDATE_MEMBER_STATUS	= 0x843,
	XSC_CMD_OP_LAG_UPDATE_HASH_TYPE		= 0x844,
	XSC_CMD_OP_LAG_DESTROY				= 0x845,

	XSC_CMD_OP_LAG_SET_QOS			= 0x848,
	XSC_CMD_OP_ENABLE_MSIX			= 0x850,

	XSC_CMD_OP_IOCTL_FLOW			= 0x900,
	XSC_CMD_OP_IOCTL_OTHER			= 0x901,
	XSC_CMD_OP_IOCTL_NETLINK		= 0x902,
	XSC_CMD_OP_IOCTL_GET_HW_COUNTERS	= 0x903,

	XSC_CMD_OP_IOCTL_SET_DSCP_PMT		= 0x1000,
	XSC_CMD_OP_IOCTL_GET_DSCP_PMT		= 0x1001,
	XSC_CMD_OP_IOCTL_SET_TRUST_MODE		= 0x1002,
	XSC_CMD_OP_IOCTL_GET_TRUST_MODE		= 0x1003,
	XSC_CMD_OP_IOCTL_SET_PCP_PMT		= 0x1004,
	XSC_CMD_OP_IOCTL_GET_PCP_PMT		= 0x1005,
	XSC_CMD_OP_IOCTL_SET_DEFAULT_PRI	= 0x1006,
	XSC_CMD_OP_IOCTL_GET_DEFAULT_PRI	= 0x1007,
	XSC_CMD_OP_IOCTL_SET_PFC		= 0x1008,
	XSC_CMD_OP_IOCTL_GET_PFC		= 0x1009,
	XSC_CMD_OP_IOCTL_SET_RATE_LIMIT		= 0x100a,
	XSC_CMD_OP_IOCTL_GET_RATE_LIMIT		= 0x100b,
	XSC_CMD_OP_IOCTL_SET_SP			= 0x100c,
	XSC_CMD_OP_IOCTL_GET_SP			= 0x100d,
	XSC_CMD_OP_IOCTL_SET_WEIGHT		= 0x100e,
	XSC_CMD_OP_IOCTL_GET_WEIGHT		= 0x100f,
	XSC_CMD_OP_IOCTL_DPU_SET_PORT_WEIGHT	= 0x1010,
	XSC_CMD_OP_IOCTL_DPU_GET_PORT_WEIGHT	= 0x1011,
	XSC_CMD_OP_IOCTL_DPU_SET_PRIO_WEIGHT	= 0x1012,
	XSC_CMD_OP_IOCTL_DPU_GET_PRIO_WEIGHT	= 0x1013,
	XSC_CMD_OP_IOCTL_SET_WATCHDOG_EN	= 0x1014,
	XSC_CMD_OP_IOCTL_GET_WATCHDOG_EN	= 0x1015,
	XSC_CMD_OP_IOCTL_SET_WATCHDOG_PERIOD	= 0x1016,
	XSC_CMD_OP_IOCTL_GET_WATCHDOG_PERIOD	= 0x1017,
	XSC_CMD_OP_IOCTL_SET_PFC_DROP_TH	= 0x1018,
	XSC_CMD_OP_IOCTL_GET_PFC_CFG_STATUS	= 0x1019,
	XSC_CMD_OP_IOCTL_SET_PFC_NEW		= 0x101a,
	XSC_CMD_OP_IOCTL_GET_PFC_CFG_STATUS_NEW	= 0x101b,

	XSC_CMD_OP_IOCTL_SET_ENABLE_RP = 0x1030,
	XSC_CMD_OP_IOCTL_SET_ENABLE_NP = 0x1031,
	XSC_CMD_OP_IOCTL_SET_INIT_ALPHA = 0x1032,
	XSC_CMD_OP_IOCTL_SET_G = 0x1033,
	XSC_CMD_OP_IOCTL_SET_AI = 0x1034,
	XSC_CMD_OP_IOCTL_SET_HAI = 0x1035,
	XSC_CMD_OP_IOCTL_SET_TH = 0x1036,
	XSC_CMD_OP_IOCTL_SET_BC_TH = 0x1037,
	XSC_CMD_OP_IOCTL_SET_CNP_OPCODE = 0x1038,
	XSC_CMD_OP_IOCTL_SET_CNP_BTH_B = 0x1039,
	XSC_CMD_OP_IOCTL_SET_CNP_BTH_F = 0x103a,
	XSC_CMD_OP_IOCTL_SET_CNP_ECN = 0x103b,
	XSC_CMD_OP_IOCTL_SET_DATA_ECN = 0x103c,
	XSC_CMD_OP_IOCTL_SET_CNP_TX_INTERVAL = 0x103d,
	XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_RSTTIME = 0x103e,
	XSC_CMD_OP_IOCTL_SET_CNP_DSCP = 0x103f,
	XSC_CMD_OP_IOCTL_SET_CNP_PCP = 0x1040,
	XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_ALPHA = 0x1041,
	XSC_CMD_OP_IOCTL_GET_CC_CFG = 0x1042,
	XSC_CMD_OP_IOCTL_GET_CC_STAT = 0x104b,
	XSC_CMD_OP_IOCTL_SET_CLAMP_TGT_RATE = 0x1052,
	XSC_CMD_OP_IOCTL_SET_MAX_HAI_FACTOR = 0x1053,
	XSC_CMD_OP_IOCTL_SET_SCALE = 0x1054,

	XSC_CMD_OP_IOCTL_SET_HWC = 0x1060,
	XSC_CMD_OP_IOCTL_GET_HWC = 0x1061,

	XSC_CMD_OP_SET_MTU = 0x1100,
	XSC_CMD_OP_QUERY_ETH_MAC = 0X1101,
	XSC_CMD_OP_QUERY_MTU = 0X1102,

	XSC_CMD_OP_QUERY_HW_STATS = 0X1200,
	XSC_CMD_OP_QUERY_PAUSE_CNT = 0X1201,
	XSC_CMD_OP_IOCTL_QUERY_PFC_STALL_STATS = 0x1202,
	XSC_CMD_OP_QUERY_HW_STATS_RDMA = 0X1203,
	XSC_CMD_OP_QUERY_HW_STATS_ETH = 0X1204,
	XSC_CMD_OP_QUERY_HW_GLOBAL_STATS = 0X1210,
	XSC_CMD_OP_QUERY_HW_PF_UC_STATS = 0X1211,
	XSC_CMD_OP_QUERY_HW_PRS_CHK_ERR_STATS = 0x1212,

	XSC_CMD_OP_SET_RTT_EN = 0X1220,
	XSC_CMD_OP_GET_RTT_EN = 0X1221,
	XSC_CMD_OP_SET_RTT_QPN = 0X1222,
	XSC_CMD_OP_GET_RTT_QPN = 0X1223,
	XSC_CMD_OP_SET_RTT_PERIOD = 0X1224,
	XSC_CMD_OP_GET_RTT_PERIOD = 0X1225,
	XSC_CMD_OP_GET_RTT_RESULT = 0X1226,
	XSC_CMD_OP_GET_RTT_STATS = 0X1227,

	XSC_CMD_OP_SET_LED_STATUS = 0X1228,

	XSC_CMD_OP_AP_FEAT			= 0x1400,
	XSC_CMD_OP_PCIE_LAT_FEAT		= 0x1401,
	XSC_CMD_OP_OOO_STATISTIC_FEAT		= 0x1402,

	XSC_CMD_OP_GET_LLDP_STATUS = 0x1500,
	XSC_CMD_OP_SET_LLDP_STATUS = 0x1501,

	XSC_CMD_OP_SET_VPORT_RATE_LIMIT = 0x1600,

	XSC_CMD_OP_IOCTL_SET_ROCE_ACCL	= 0x1700,
	XSC_CMD_OP_IOCTL_GET_ROCE_ACCL	= 0x1701,
	XSC_CMD_OP_IOCTL_SET_ROCE_ACCL_NEXT	= 0x1702,
	XSC_CMD_OP_IOCTL_GET_ROCE_ACCL_NEXT	= 0x1703,
	XSC_CMD_OP_IOCTL_PRGRMMBL_CC	= 0x1704,
	XSC_CMD_OP_IOCTL_SET_FLEXCC_NEXT	= 0x1705,
	XSC_CMD_OP_IOCTL_GET_FLEXCC_NEXT	= 0x1706,
	XSC_CMD_OP_IOCTL_GET_STAT_FLEXCC_NEXT	= 0x1707,
	XSC_CMD_OP_IOCTL_GET_SPORT_ROCE_ACCL_NEXT = 0x1708,
	XSC_CMD_OP_IOCTL_SET_ROCE_ACCL_DISC_SPORT = 0x1709,
	XSC_CMD_OP_IOCTL_GET_ROCE_ACCL_DISC_SPORT = 0x170a,

	XSC_CMD_OP_GET_LINK_SUB_STATE = 0x1800,
	XSC_CMD_OP_SET_PORT_ADMIN_STATUS = 0x1801,

	XSC_CMD_OP_IOCTL_GET_BYTE_CNT = 0x1900,

	XSC_CMD_OP_USER_EMU_CMD = 0x8000,

	XSC_CMD_OP_MAX
};

enum {
	XSC_CMD_EVENT_RESP_CHANGE_LINK	= 0x0001,
	XSC_CMD_EVENT_RESP_TEMP_WARN	= 0x0002,
	XSC_CMD_EVENT_RESP_OVER_TEMP_PROTECTION	= 0x0004,
	XSC_CMD_EVENT_RECV_TUNNEL_CMD_REQ	= 0x0008,
	XSC_CMD_EVENT_RECV_TUNNEL_CMD_RSP	= 0x0010,
	XSC_CMD_EVENT_CHANGE_TO_EXCLUSIVE	= 0x0020,
	XSC_CMD_EVENT_CHANGE_TO_SHARE		= 0x0040,
};

enum xsc_eth_qp_num_sel {
	XSC_ETH_QP_NUM_8K_SEL = 0,
	XSC_ETH_QP_NUM_8K_8TC_SEL,
	XSC_ETH_QP_NUM_SEL_MAX,
};

enum xsc_eth_vf_num_sel {
	XSC_ETH_VF_NUM_SEL_8 = 0,
	XSC_ETH_VF_NUM_SEL_16,
	XSC_ETH_VF_NUM_SEL_32,
	XSC_ETH_VF_NUM_SEL_64,
	XSC_ETH_VF_NUM_SEL_128,
	XSC_ETH_VF_NUM_SEL_256,
	XSC_ETH_VF_NUM_SEL_512,
	XSC_ETH_VF_NUM_SEL_1024,
	XSC_ETH_VF_NUM_SEL_MAX
};

enum {
	LINKSPEED_MODE_UNKNOWN = -1,
	LINKSPEED_MODE_10G = 10000,
	LINKSPEED_MODE_25G = 25000,
	LINKSPEED_MODE_40G = 40000,
	LINKSPEED_MODE_50G = 50000,
	LINKSPEED_MODE_100G = 100000,
	LINKSPEED_MODE_200G = 200000,
	LINKSPEED_MODE_400G = 400000,
};

enum {
	MODULE_SPEED_UNKNOWN,
	MODULE_SPEED_10G,
	MODULE_SPEED_25G,
	MODULE_SPEED_40G_R4,
	MODULE_SPEED_50G_R,
	MODULE_SPEED_50G_R2,
	MODULE_SPEED_100G_R2,
	MODULE_SPEED_100G_R4,
	MODULE_SPEED_200G_R4,
	MODULE_SPEED_200G_R8,
	MODULE_SPEED_400G_R8,
	MODULE_SPEED_400G_R4,
};

enum xsc_dma_direct {
	DMA_DIR_TO_MAC,
	DMA_DIR_READ,
	DMA_DIR_WRITE,
	DMA_DIR_LOOPBACK,
	DMA_DIR_MAX,
};

/* hw feature bitmap, 32bit */
enum xsc_hw_feature_flag {
	XSC_HW_RDMA_SUPPORT = 0x1,
	XSC_HW_PFC_PRIO_STATISTIC_SUPPORT = 0x2,
	XSC_HW_THIRD_FEATURE = 0x4,
	XSC_HW_PFC_STALL_STATS_SUPPORT = 0x8,
	XSC_HW_RDMA_CM_SUPPORT = 0x20,
	XSC_HW_OFFLOAD_UNSUPPORT = 0x40,
	XSC_HW_PF_UC_STATISTIC_SUPPORT = 0x80,
	XSC_HW_PRGRMMBL_CC_SUPPORT = 0x100,

	XSC_HW_LAST_FEATURE = 0x80000000,
};

enum xsc_lldp_dcbx_sub_cmd {
	XSC_OS_HANDLE_LLDP_STATUS = 0x1,
	XSC_DCBX_STATUS
};

struct xsc_inbox_hdr {
	__be16		opcode;
	u8		rsvd[4];
	__be16		ver;
};

struct xsc_outbox_hdr {
	u8		status;
	u8		rsvd[5];
	__be16		ver;
};

enum {
	DRIVER_INSTANCE_LAUNCH,
	DRIVER_INSTANCE_PHASE_OUT,
	DRIVER_INSTANCE_UPDATE_REP_FUNC,
};

struct xsc_cmd_announce_driver_instance_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			rep_func_id;
	u8			status;
	u8			rsvd[5];
};

enum {
	EXCLUSIVE_MODE,
	SHARE_MODE,
};

struct xsc_cmd_announce_driver_instance_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			resource_access_mode;
	u8			rsvd[7];
};

struct xsc_alloc_ia_lock_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			lock_num;
	u8			rsvd[7];
};

#define XSC_RES_NUM_IAE_GRP 16

struct xsc_alloc_ia_lock_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			lock_idx[XSC_RES_NUM_IAE_GRP];
};

struct xsc_release_ia_lock_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			lock_idx[XSC_RES_NUM_IAE_GRP];
};

struct xsc_release_ia_lock_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_pci_driver_init_params_in {
	struct xsc_inbox_hdr	hdr;
	__be32			s_wqe_mode;
	__be32			r_wqe_mode;
	__be32			local_timeout_retrans;
	u8				mac_lossless_prio[XSC_MAX_MAC_NUM];
	__be32			group_mod;
};

struct xsc_pci_driver_init_params_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

/*CQ mbox*/
struct xsc_cq_context {
	__be16		eqn;
	__be16		pa_num;
	__be16		glb_func_id;
	u8		log_cq_sz;
	u8		cq_type;
};

struct xsc_create_cq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_cq_context	ctx;
	__be64			pas[];
};

struct xsc_cq_context_ex {
	struct xsc_cq_context ctx;
	u8		page_shift;
	u8		rsvd[7];
};

struct xsc_create_cq_ex_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_cq_context_ex ctx_ex;
	__be64			pas[];
};

struct xsc_create_cq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			cqn;
	u8			rsvd[4];
};

struct xsc_destroy_cq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			cqn;
	u8			rsvd[4];
};

struct xsc_destroy_cq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_set_cq_context_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_cq_context_ex	ctx_ex;
};

struct xsc_set_cq_context_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			cqn;
	__be32			cq_pa_list_base;
};

struct xsc_set_cq_buf_pa_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			pa_list_start;
	__be32			pa_num;
	__be64			pas[];
};

struct xsc_set_cq_buf_pa_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

/*QP mbox*/
struct xsc_create_qp_request {
	__be16		input_qpn;
	__be16		pa_num;
	u8		qp_type;
	u8		log_sq_sz;
	u8		log_rq_sz;
	u8		dma_direct;//0 for dma read, 1 for dma write
	__be32		pdn;
	__be16		cqn_send;
	__be16		cqn_recv;
	__be16		glb_funcid;
	/*rsvd,rename logic_port used to transfer logical_port to fw*/
	u8		page_shift;
	u8		rsvd;
	__be64		pas[];
};

struct xsc_create_qp_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_create_qp_request	req;
};

struct xsc_create_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			qpn;
	u8			rsvd[4];
};

struct xsc_destroy_qp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			qpn;
	u8			rsvd[4];
};

struct xsc_destroy_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_query_qp_flush_status_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			qpn;
};

struct xsc_query_qp_flush_status_mbox_out {
	struct xsc_outbox_hdr	hdr;
};

enum qp_access_flag {
	QP_ACCESS_REMOTE_READ = (1 << 0),
	QP_ACCESS_REMOTE_WRITE = (1 << 1),
};

#define	XSC_QP_CONTEXT_V1	1
struct xsc_qp_context {
	__be32		remote_qpn;
	__be32		cqn_send;
	__be32		cqn_recv;
	__be32		next_send_psn;
	__be32		next_recv_psn;
	__be32		pdn;
	__be16		src_udp_port;
	__be16		path_id;
	u8		mtu_mode;
	u8		lag_sel;
	u8		lag_sel_en;
	u8		retry_cnt;
	u8		rnr_retry;
	u8		dscp;
	u8		state;
	u8		hop_limit;
	u8		dmac[6];
	u8		smac[6];
	__be32		dip[4];
	__be32		sip[4];
	__be16		ip_type;
	__be16		grp_id;
	u8		vlan_valid;
	u8		dci_cfi_prio_sl;
	__be16		vlan_id;
	u8		qp_out_port;
	u8		pcie_no;
	__be16		lag_id;
	__be16		func_id;
	__be16		rsvd;
	u8		no_need_wait;
	u8		rsvd0[3];
	__be32		qp_access_flags;
};

struct xsc_query_qp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			qpn;
	u8			rsvd[4];
};

struct xsc_query_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_qp_context	ctx;
};

struct xsc_modify_qp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			qpn;
	struct xsc_qp_context	ctx;
};

struct xsc_modify_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_create_multiqp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			qp_num;
	u8			qp_type;
	u8			rsvd;
	__be32			req_len;
	u8			data[];
};

struct xsc_create_multiqp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			qpn_base;
};

struct xsc_alloc_multi_virtq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			qp_or_cq_num;
	__be16			pa_num;
	__be32			rsvd;
	__be32			rsvd2;
};

struct xsc_alloc_multi_virtq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			qnum_base;
	__be32			pa_list_base;
	__be32			rsvd;
};

struct xsc_release_multi_virtq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			qp_or_cq_num;
	__be16			pa_num;
	__be32			qnum_base;
	__be32			pa_list_base;
};

struct xsc_release_multi_virtq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			rsvd;
	__be32			rsvd2;
	__be32			rsvd3;
};

struct xsc_alloc_qpn_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			qp_cnt;
	u8			qp_type;
	u8			rsvd[5];
};

struct xsc_alloc_qpn_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be16			qpn_base;
};

struct xsc_dealloc_qpn_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			qpn_base;
	__be16			qp_cnt;
	u8			qp_type;
	u8			rsvd[3];
};

struct xsc_dealloc_qpn_mbox_out {
	struct xsc_outbox_hdr	hdr;
};

struct xsc_set_qp_info_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_create_qp_request	qp_info;
};

struct xsc_set_qp_info_out {
	struct xsc_outbox_hdr	hdr;
};

struct xsc_unset_qp_info_in {
	struct xsc_inbox_hdr	hdr;
	__be16			qpn;
	u8			rsvd[6];
};

struct xsc_unset_qp_info_out {
	struct xsc_outbox_hdr	hdr;
};

/* MSIX TABLE mbox */
struct xsc_msix_table_info_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			index;
	u8			rsvd[6];
};

struct xsc_msix_table_info_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			addr_lo;
	__be32			addr_hi;
	__be32			data;
};

/*EQ mbox*/
struct xsc_eq_context {
	__be16			vecidx;
	__be16			pa_num;
	u8			log_eq_sz;
	__be16			glb_func_id;
	u8			is_async_eq;
	u8			page_shift;
};

struct xsc_create_eq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_eq_context	ctx;
	__be64			pas[];
};

struct xsc_create_eq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			eqn;
	u8			rsvd[4];
};

struct xsc_destroy_eq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			eqn;
	u8			rsvd[4];

};

struct xsc_destroy_eq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

/*PD mbox*/
struct xsc_alloc_pd_request {
	u8	rsvd[8];
};

struct xsc_alloc_pd_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_alloc_pd_request	req;
};

struct xsc_alloc_pd_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			pdn;
	u8			rsvd[4];
};

struct xsc_dealloc_pd_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			pdn;
	u8			rsvd[4];

};

struct xsc_dealloc_pd_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

/*MR mbox*/
struct xsc_register_mr_request {
	__be32		pdn;
	__be32		pa_num;
	__be64		len;
	__be32		mkey;
	u8		is_gpu;
	u8		acc;
	u8		page_mode;
	u8		map_en;
	__be64		va_base;
	__be64		pas[];
};

struct xsc_register_mr_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_register_mr_request	req;
};

struct xsc_register_mr_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			mkey;
	u8			rsvd[4];
};

struct xsc_unregister_mr_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			mkey;
	u8			rsvd[4];
};

struct xsc_unregister_mr_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_mpt_item {
	__be32		pdn;
	__be32		pa_num;
	__be32		len;
	__be32		mkey;
	u8		rsvd[5];
	u8		acc;
	u8		page_mode;
	u8		map_en;
	__be64		va_base;
};

struct xsc_set_mpt_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_mpt_item	mpt_item;
};

struct xsc_set_mpt_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			mtt_base;
	u8			rsvd[4];
};

struct xsc_mtt_setting {
	__be32		mtt_base;
	__be32		pa_num;
	__be64		pas[];
};

struct xsc_set_mtt_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_mtt_setting	mtt_setting;
};

struct xsc_set_mtt_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_create_mkey_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8	rsvd[4];
};

struct xsc_create_mkey_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32	mkey;
};

struct xsc_destroy_mkey_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32	mkey;
};

struct xsc_destroy_mkey_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd;
};

struct xsc_mr_info {
	__be32	mpt_idx;
	__be32	mtt_base;
	__be32	mtt_num;
};

struct xsc_cmd_sync_mr_to_fw_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[6];
	__be16			mr_num;
	struct xsc_mr_info	data[];
};

struct xsc_cmd_sync_mr_to_fw_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_sync_mr_from_fw_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			start;
	u8			rsvd[4];
};

struct xsc_cmd_sync_mr_from_fw_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[6];
	__be16			mr_num;
	struct xsc_mr_info	data[];
};

struct xsc_access_reg_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd0[2];
	__be16			register_id;
	__be32			arg;
	__be32			data[];
};

struct xsc_access_reg_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
	__be32			data[];
};

struct xsc_mad_ifc_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			remote_lid;
	u8			rsvd0;
	u8			port;
	u8			rsvd1[4];
	u8			data[256];
};

struct xsc_mad_ifc_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
	u8			data[256];
};

struct xsc_query_eq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd0[3];
	u8			eqn;
	u8			rsvd1[4];
};

struct xsc_query_eq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
	struct xsc_eq_context	ctx;
};

struct xsc_query_cq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			cqn;
	u8			rsvd0[4];
};

struct xsc_query_cq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd0[8];
	struct xsc_cq_context	ctx;
	u8			rsvd6[16];
	__be64			pas[];
};

struct xsc_cmd_query_cmdq_ver_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_query_cmdq_ver_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be16		cmdq_ver;
	u8			rsvd[6];
};

struct xsc_cmd_dummy_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_dummy_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_fw_version {
	u8		fw_version_major;
	u8		fw_version_minor;
	__be16	fw_version_patch;
	__be32	fw_version_tweak;
	u8		fw_version_extra_flag;
	u8		rsvd[7];
};

struct xsc_hca_cap {
	u8		rsvd1[12];
	u8		send_seg_num;
	u8		send_wqe_shift;
	u8		recv_seg_num;
	u8		recv_wqe_shift;
	u8		log_max_srq_sz;
	u8		log_max_qp_sz;
	u8		log_max_mtt;
	u8		log_max_qp;
	u8		log_max_strq_sz;
	u8		log_max_srqs;
	u8		rsvd4[2];
	u8		log_max_tso;
	u8		log_max_cq_sz;
	u8		rsvd6;
	u8		log_max_cq;
	u8		log_max_eq_sz;
	u8		log_max_mkey;
	u8		log_max_msix;
	u8		log_max_eq;
	u8		max_indirection;
	u8		log_max_mrw_sz;
	u8		log_max_bsf_list_sz;
	u8		log_max_klm_list_sz;
	u8		rsvd_8_0;
	u8		log_max_ra_req_dc;
	u8		rsvd_8_1;
	u8		log_max_ra_res_dc;
	u8		rsvd9;
	u8		log_max_ra_req_qp;
	u8		log_max_qp_depth;
	u8		log_max_ra_res_qp;
	__be16		max_vfs;
	__be16		raweth_qp_id_end;
	__be16		raw_tpe_qp_num;
	__be16		max_qp_count;
	__be16		raweth_qp_id_base;
	u8		rsvd13;
	u8		local_ca_ack_delay;
	u8		max_num_eqs;
	u8		num_ports;
	u8		log_max_msg;
	u8		mac_port;
	__be16		raweth_rss_qp_id_base;
	__be16		stat_rate_support;
	u8		rsvd16[2];
	__be64		flags;
	u8		rsvd17;
	u8		uar_sz;
	u8		rsvd18;
	u8		log_pg_sz;
	__be16		bf_log_bf_reg_size;
	__be16		msix_base;
	__be16		msix_num;
	__be16		max_desc_sz_sq;
	u8		rsvd20[2];
	__be16		max_desc_sz_rq;
	u8		rsvd21[2];
	__be16		max_desc_sz_sq_dc;
	u8		rsvd22[4];
	__be16		max_qp_mcg;
	u8		rsvd23;
	u8		log_max_mcg;
	u8		rsvd24;
	u8		log_max_pd;
	u8		rsvd25;
	u8		log_max_xrcd;
	u8		rsvd26[40];
	__be32		uar_page_sz;
	u8		rsvd27[8];
	__be32		hw_feature_flag;/*enum xsc_hw_feature_flag*/
	__be16		pf0_vf_funcid_base;
	__be16		pf0_vf_funcid_top;
	__be16		pf1_vf_funcid_base;
	__be16		pf1_vf_funcid_top;
	__be16		pcie0_pf_funcid_base;
	__be16		pcie0_pf_funcid_top;
	__be16		pcie1_pf_funcid_base;
	__be16		pcie1_pf_funcid_top;
	u8		log_msx_atomic_size_qp;
	u8		pcie_host;
	u8		rsvd28;
	u8		log_msx_atomic_size_dc;
	u8		board_sn[XSC_BOARD_SN_LEN];
	u8		max_tc;
	u8		mac_bit;
	__be16		funcid_to_logic_port;
	u8		rsvd29[6];
	u8		nif_port_num;
	u8		reg_mr_via_cmdq;
	__be32		hca_core_clock;
	__be32		max_rwq_indirection_tables;/*rss_caps*/
	__be32		max_rwq_indirection_table_size;/*rss_caps*/
	__be32		chip_ver_h;
	__be32		chip_ver_m;
	__be32		chip_ver_l;
	__be32		hotfix_num;
	__be32		feature_flag;
	__be32		rx_pkt_len_max;
	__be32		glb_func_id;
	__be64		tx_db;
	__be64		rx_db;
	__be64		complete_db;
	__be64		complete_reg;
	__be64		event_db;
	__be32		qp_rate_limit_min;
	__be32		qp_rate_limit_max;
	struct xsc_fw_version  fw_ver;
	u8	lag_logic_port_ofst;
	/* V1 */
	__be64		max_mr_size;
	__be16		max_cmd_in_len;
	__be16		max_cmd_out_len;
	/* V2 */
	__be32		max_qp;
	__be32		max_cq;
	__be32		max_pd;
	__be32		max_mtt;
	/* V3 */
	__be32		mpt_tbl_addr;
	__be32		mpt_tbl_depth;
	__be32		mpt_tbl_width;
	__be32		mtt_inst_base_addr;
	__be32		mtt_inst_stride;
	__be32		mtt_inst_num_log;
	__be32		mtt_inst_depth;
	/* V4 */
	__be16		vf_funcid_base[XSC_MAX_NUM_PCIE_INTF][XSC_MAX_PF_NUM_PER_PCIE];
	__be16		vf_funcid_top[XSC_MAX_NUM_PCIE_INTF][XSC_MAX_PF_NUM_PER_PCIE];
	__be16		pf_funcid_base[XSC_MAX_NUM_PCIE_INTF];
	__be16		pf_funcid_top[XSC_MAX_NUM_PCIE_INTF];
	u8		pcie_no;
	u8		pf_id;
	__be16		vf_id;
	u8		pcie_host_num;
	u8		pf_num_per_pcie;
};

#define CMD_QUERY_HCA_CAP_V1	1
#define CMD_QUERY_HCA_CAP_V2	2
#define CMD_QUERY_HCA_CAP_V3	3
#define CMD_QUERY_HCA_CAP_V4	4
struct xsc_cmd_query_hca_cap_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			cpu_num;
	u8			rsvd[6];
};

struct xsc_cmd_query_hca_cap_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd0[8];
	struct xsc_hca_cap	hca_cap;
};

struct xsc_cmd_enable_hca_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16	vf_num;
	__be16  max_msix_vec;
	__be16	cpu_num;
	u8	pp_bypass;
	u8	esw_mode;
};

struct xsc_cmd_enable_hca_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd0[4];
};

struct xsc_cmd_disable_hca_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16	vf_num;
	u8	pp_bypass;
	u8	esw_mode;
};

struct xsc_cmd_disable_hca_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd0[4];
};

struct xsc_cmd_modify_hca_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8	pp_bypass;
	u8	esw_mode;
	u8	rsvd0[6];
};

struct xsc_cmd_modify_hca_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd0[4];
};

struct xsc_query_special_ctxs_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_query_special_ctxs_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			dump_fill_mkey;
	__be32			reserved_lkey;
};

/* vport mbox */
struct xsc_nic_vport_context {
	__be32		min_wqe_inline_mode:3;
	__be32		disable_mc_local_lb:1;
	__be32		disable_uc_local_lb:1;
	__be32		roce_en:1;

	__be32		arm_change_event:1;
	__be32		event_on_mtu:1;
	__be32		event_on_promisc_change:1;
	__be32		event_on_vlan_change:1;
	__be32		event_on_mc_address_change:1;
	__be32		event_on_uc_address_change:1;
	__be32		affiliation_criteria:4;
	__be32		affiliated_vhca_id;

	__be16		mtu;

	__be64		system_image_guid;
	__be64		port_guid;
	__be64		node_guid;

	__be32		qkey_violation_counter;

	__be16		spoofchk:1;
	__be16		trust:1;
	__be16		promisc:1;
	__be16		allmcast:1;
	__be16		vlan_allowed:1;
	__be16		allowed_list_type:3;
	__be16		allowed_list_size:10;

	__be16		vlan_proto;
	__be16		vlan;
	u8		qos;
	u8		permanent_address[6];
	u8		current_address[6];
	u8		current_uc_mac_address[0][2];
};

enum {
	XSC_HCA_VPORT_SEL_PORT_GUID	= 1 << 0,
	XSC_HCA_VPORT_SEL_NODE_GUID	= 1 << 1,
	XSC_HCA_VPORT_SEL_STATE_POLICY	= 1 << 2,
};

struct xsc_hca_vport_context {
	u32		field_select;
	u32		port_physical_state:4;
	u32		vport_state_policy:4;
	u32		port_state:4;
	u32		vport_state:4;
	u32		rcvd0:16;

	u64		system_image_guid;
	u64		port_guid;
	u64		node_guid;

	u16		qkey_violation_counter;
	u16		pkey_violation_counter;
};

struct xsc_query_nic_vport_context_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_nic_vport_context nic_vport_ctx;
};

struct xsc_query_nic_vport_context_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			vport_number:16;
	u32			allowed_list_type:3;
	u32			rsvd:12;
};

struct xsc_modify_nic_vport_context_out {
	struct xsc_outbox_hdr	hdr;
	__be16			outer_vlan_id;
	u8			rsvd[2];
};

struct xsc_modify_nic_vport_field_select {
	__be32		affiliation:1;
	__be32		disable_uc_local_lb:1;
	__be32		disable_mc_local_lb:1;
	__be32		node_guid:1;
	__be32		port_guid:1;
	__be32		min_inline:1;
	__be32		mtu:1;
	__be32		change_event:1;
	__be32		promisc:1;
	__be32		allmcast:1;
	__be32		permanent_address:1;
	__be32		current_address:1;
	__be32		addresses_list:1;
	__be32		roce_en:1;
	__be32		spoofchk:1;
	__be32		trust:1;
	__be32		rsvd:16;
};

struct xsc_modify_nic_vport_context_in {
	struct xsc_inbox_hdr	hdr;
	__be32		other_vport:1;
	__be32		vport_number:16;
	__be32		rsvd:15;
	__be16		caps;
	__be16		caps_mask;
	__be16		lag_id;

	struct xsc_modify_nic_vport_field_select field_select;
	struct xsc_nic_vport_context nic_vport_ctx;
};

struct xsc_modify_nic_vport_uc_mac_out {
	struct xsc_outbox_hdr	hdr;
	__be16			out_pct_prio;
};

struct xsc_modify_nic_vport_uc_mac_in {
	struct xsc_inbox_hdr	hdr;
	__be16			in_pct_prio;
	bool			add_mac;
	u8			mac_addr[6];
};

struct xsc_modify_nic_vport_mc_mac_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[2];
};

struct xsc_modify_nic_vport_mc_mac_in {
	struct xsc_inbox_hdr	hdr;
	u8			action;
	u8			mac[ETH_ALEN];
	u8			rsvd[1];
};

struct xsc_query_hca_vport_context_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_hca_vport_context hca_vport_ctx;
};

struct xsc_query_hca_vport_context_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			port_num:4;
	u32			vport_number:16;
	u32			rsvd0:11;
};

struct xsc_modify_hca_vport_context_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[2];
};

struct xsc_modify_hca_vport_context_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			port_num:4;
	u32			vport_number:16;
	u32			rsvd0:11;

	struct xsc_hca_vport_context hca_vport_ctx;
};

struct xsc_array128 {
	u8			array128[16];
};

struct xsc_query_hca_vport_gid_out {
	struct xsc_outbox_hdr	hdr;
	u16			gids_num;
	struct xsc_array128	gid[];
};

struct xsc_query_hca_vport_gid_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			port_num:4;
	u32			vport_number:16;
	u32			rsvd0:11;
	u16			gid_index;
};

struct xsc_pkey {
	u16			pkey;
};

struct xsc_query_hca_vport_pkey_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_pkey		pkey[];
};

struct xsc_query_hca_vport_pkey_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			port_num:4;
	u32			vport_number:16;
	u32			rsvd0:11;
	u16			pkey_index;
};

struct xsc_query_vport_state_out {
	struct xsc_outbox_hdr	hdr;
	u8			admin_state:4;
	u8			state:4;
};

struct xsc_query_vport_state_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			vport_number:16;
	u32			rsvd0:15;
};

struct xsc_modify_vport_state_out {
	struct xsc_outbox_hdr	hdr;
};

struct xsc_modify_vport_state_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			vport_number:16;
	u32			rsvd0:15;
	u8			admin_state:4;
	u8			rsvd1:4;
};

struct xsc_traffic_counter {
	u64         packets;
	u64         bytes;
};

struct xsc_link_sub_state_mbox_in {
	struct xsc_inbox_hdr hdr;
};

struct xsc_link_sub_state_mbox_out {
	struct xsc_outbox_hdr hdr;
	__be32 state_code;
};

struct xsc_query_vport_counter_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_traffic_counter received_errors;
	struct xsc_traffic_counter transmit_errors;
	struct xsc_traffic_counter received_ib_unicast;
	struct xsc_traffic_counter transmitted_ib_unicast;
	struct xsc_traffic_counter received_ib_multicast;
	struct xsc_traffic_counter transmitted_ib_multicast;
	struct xsc_traffic_counter received_eth_broadcast;
	struct xsc_traffic_counter transmitted_eth_broadcast;
	struct xsc_traffic_counter received_eth_unicast;
	struct xsc_traffic_counter transmitted_eth_unicast;
	struct xsc_traffic_counter received_eth_multicast;
	struct xsc_traffic_counter transmitted_eth_multicast;
};

struct xsc_query_vport_counter_in {
	struct xsc_inbox_hdr	hdr;
	u32			other_vport:1;
	u32			port_num:4;
	u32			vport_number:16;
	u32			rsvd0:11;
};

/* ioctl mbox */
struct xsc_ioctl_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			len;
	__be16			rsvd;
	u8			data[];
};

struct xsc_ioctl_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32    error;
	__be16	len;
	__be16	rsvd;
	u8	data[];
};

struct xsc_modify_raw_qp_request {
	u16		qpn;
	u16		lag_id;
	u16		func_id;
	u8		dma_direct;
	u8		prio;
	u8		qp_out_port;
	u8		rsvd[7];
};

struct xsc_modify_raw_qp_mbox_in {
	struct xsc_inbox_hdr				hdr;
	u8		pcie_no;
	u8		rsv[7];
	struct xsc_modify_raw_qp_request	req;
};

struct xsc_modify_raw_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8						rsvd[8];
};

#define ETH_ALEN	6

#define LAG_CMD_V1	1

struct slave_func_data {
	u8	pf_id;
	u8	pcie_no;
	u8	valid;
};

struct xsc_create_lag_request {
	__be16	lag_id;
	u8	lag_type;
	u8	lag_sel_mode;
	u8	pf_idx;
	u8	netdev_addr[ETH_ALEN];
	u8	bond_mode;
	u8	slave_status;
};

struct xsc_add_lag_member_request {
	__be16	lag_id;
	u8	lag_type;
	u8	lag_sel_mode;
	u8	pf_idx;
	u8	netdev_addr[ETH_ALEN];
	u8	bond_mode;
	u8	slave_status;
	u8	roce_pf_idx;
	struct	slave_func_data roce_pf_func_data;
};

struct xsc_remove_lag_member_request {
	__be16	lag_id;
	u8	lag_type;
	u8	pf_idx;
	u8	roce_pf_idx;
	u8	bond_mode;
	u8	is_roce_lag_xdev;
	u8	not_roce_lag_xdev_mask;
	struct	slave_func_data roce_pf_func_data;
	struct	slave_func_data func_data[6];
};

struct xsc_update_lag_member_status_request {
	__be16	lag_id;
	u8	lag_type;
	u8	pf_idx;
	u8	bond_mode;
	u8	slave_status;
	u8	rsvd;
};

struct xsc_update_lag_hash_type_request {
	__be16	lag_id;
	u8	lag_sel_mode;
	u8	rsvd[5];
};

struct xsc_destroy_lag_request {
	__be16	lag_id;
	u8	lag_type;
	u8	pf_idx;
	u8	bond_mode;
	u8	slave_status;
	u8	rsvd[3];
};

struct xsc_set_lag_qos_request {
	__be16	lag_id;
	u8	member_idx;
	u8	lag_op;
	u8	resv[4];
};

struct xsc_create_lag_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_create_lag_request	req;
};

struct xsc_create_lag_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

struct xsc_add_lag_member_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_add_lag_member_request	req;
};

struct xsc_add_lag_member_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

struct xsc_remove_lag_member_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_remove_lag_member_request	req;
};

struct xsc_remove_lag_member_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

struct xsc_update_lag_member_status_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_update_lag_member_status_request	req;
};

struct xsc_update_lag_member_status_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

struct xsc_update_lag_hash_type_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_update_lag_hash_type_request	req;
};

struct xsc_update_lag_hash_type_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

struct xsc_destroy_lag_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_destroy_lag_request	req;
};

struct xsc_destroy_lag_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

struct xsc_set_lag_qos_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_set_lag_qos_request	req;
};

struct xsc_set_lag_qos_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

/*ioctl qos*/
struct xsc_qos_req_prfx {
	u8 mac_port;
	u8 rsvd[7];
};

struct xsc_qos_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_qos_req_prfx		req_prfx;
	u8				data[];
};

struct xsc_qos_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			data[];
};

struct xsc_prio_stats {
	u64 tx_bytes;
	u64 rx_bytes;
	u64 tx_pkts;
	u64 rx_pkts;
};

struct xsc_prio_stats_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 pport;
};

struct xsc_prio_stats_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_prio_stats	prio_stats[QOS_PRIO_MAX + 1];
};

struct xsc_pfc_prio_stats {
	u64 tx_pause;
	u64 tx_pause_duration;
	u64 rx_pause;
	u64 rx_pause_duration;
};

struct xsc_pfc_prio_stats_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			pport;
};

struct xsc_pfc_prio_stats_mbox_out {
	struct xsc_outbox_hdr		hdr;
	struct xsc_pfc_prio_stats	prio_stats[QOS_PRIO_MAX + 1];
};

struct xsc_hw_stats_rdma_pf {
	/*by mac port*/
	u64 rdma_tx_pkts;
	u64 rdma_tx_bytes;
	u64 rdma_rx_pkts;
	u64 rdma_rx_bytes;
	u64 np_cnp_sent;
	u64 rp_cnp_handled;
	u64 np_ecn_marked_roce_packets;
	u64 rp_cnp_ignored;
	u64 read_rsp_out_of_seq;
	u64 implied_nak_seq_err;
	/*by function*/
	u64 out_of_sequence;
	u64 packet_seq_err;
	u64 out_of_buffer;
	u64 rnr_nak_retry_err;
	u64 local_ack_timeout_err;
	u64 rx_read_requests;
	u64 rx_write_requests;
	u64 duplicate_requests;
	u64 rdma_tx_pkts_func;
	u64 rdma_tx_payload_bytes;
	u64 rdma_rx_pkts_func;
	u64 rdma_rx_payload_bytes;
	/*global*/
	u64 rdma_loopback_pkts;
	u64 rdma_loopback_bytes;
	/*for diamond*/
	u64 out_of_sequence_sr;
	u64 packet_seq_err_sr;
	u64 rdma_ndp_rx_pkts;
	u64 rdma_ndp_rx_trimmed_pkts;
	u64 rdma_ndp_trimmed_pkts_sr;
};

struct xsc_hw_stats_rdma_vf {
	/*by function*/
	u64 rdma_tx_pkts_func;
	u64 rdma_tx_payload_bytes;
	u64 rdma_rx_pkts_func;
	u64 rdma_rx_payload_bytes;

	u64 out_of_sequence;
	u64 packet_seq_err;
	u64 out_of_buffer;
	u64 rnr_nak_retry_err;
	u64 local_ack_timeout_err;
	u64 rx_read_requests;
	u64 rx_write_requests;
	u64 duplicate_requests;
};

struct xsc_hw_stats_rdma {
	u8 is_pf;
	u8 rsv[3];
	union {
		struct xsc_hw_stats_rdma_pf pf_stats;
		struct xsc_hw_stats_rdma_vf vf_stats;
	} stats;
};

struct xsc_hw_stats_eth_pf {
	/*by mac port*/
	u64 rdma_tx_pkts;
	u64 rdma_tx_bytes;
	u64 rdma_rx_pkts;
	u64 rdma_rx_bytes;
	u64 tx_pause;
	u64 rx_pause;
	u64 rx_fcs_errors;
	u64 rx_discards;
	u64	tx_multicast_phy;
	u64 tx_broadcast_phy;
	u64 rx_multicast_phy;
	u64 rx_broadcast_phy;
	/*by global*/
	u64 rdma_loopback_pkts;
	u64 rdma_loopback_bytes;
};

struct xsc_hw_uc_stats_eth {
	u64 tx_unicast_phy;
	u64 rx_unicast_phy;
};

struct xsc_hw_stats_eth_vf {
	/*by function*/
	u64 rdma_tx_pkts;
	u64 rdma_tx_bytes;
	u64 rdma_rx_pkts;
	u64 rdma_rx_bytes;
};

struct xsc_hw_stats_eth {
	u8 is_pf;
	u8 rsv[3];
	union {
		struct xsc_hw_stats_eth_pf pf_stats;
		struct xsc_hw_stats_eth_vf vf_stats;
	} stats;
};

struct xsc_hw_uc_stats {
	u8 is_pf;
	u8 rsv[3];
	struct xsc_hw_uc_stats_eth eth_uc_stats;
};

struct xsc_hw_stats_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 mac_port;
	u8 is_lag;
	u8 lag_member_num;
	u8 member_port[];
};

struct xsc_hw_stats_rdma_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_hw_stats_rdma	hw_stats;
};

struct xsc_hw_stats_eth_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_hw_stats_eth	hw_stats;
};

struct xsc_hw_global_stats_rdma {
	/*by global*/
	u64 rdma_loopback_pkts;
	u64 rdma_loopback_bytes;
	u64 rx_icrc_encapsulated;
	u64 req_cqe_error;
	u64 resp_cqe_error;
	u64 cqe_msg_code_error;
};

struct xsc_hw_uc_stats_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8 mac_port;
};

struct xsc_hw_uc_stats_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_hw_uc_stats	hw_uc_stats;
};

struct xsc_hw_global_stats_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 rsv[4];
};

struct xsc_hw_global_stats_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_hw_global_stats_rdma	hw_stats;
};

struct xsc_pfc_stall_stats {
	/*by mac port*/
	u64 tx_pause_storm_triggered;
};

struct xsc_pfc_stall_stats_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 mac_port;
};

struct xsc_pfc_stall_stats_mbox_out {
	struct xsc_outbox_hdr hdr;
	struct xsc_pfc_stall_stats pfc_stall_stats;
};

struct xsc_prs_chk_err_stats {
	__be64 inner_sip_dip_eq;	/* sip == dip */
	__be64 inner_sip_invalid;	/* sip is loopbak/multicast/0/linklocal */
	__be64 inner_smac_invalid;	/* smac is 0/multicast/broadcast */
	__be64 inner_ip_ver;		/* ip ver !=4 && !=6 */
	__be64 inner_smac_dmac_eq;	/* smac == dmac */
	__be64 inner_dmac_zero;		/* dmac is zero */
	__be64 outer_sip_dip_eq;	/* sip == dip */
	__be64 outer_sip_invalid;	/* sip is loopbak/multicast/0/linklocal */
	__be64 outer_smac_invalid;	/* smac is 0/multicast/broadcast */
	__be64 outer_ip_ver;		/* ip ver !=4 && !=6 */
	__be64 outer_smac_dmac_eq;	/* smac == dmac */
	__be64 outer_dmac_zero;		/* dmac is zero */
	__be64 inner_udp_len;		/* udp len error */
	__be64 inner_tp_checksum;	/* tcp/udp checksum error */
	__be64 inner_ipv4_checksum;	/* ipv4 checksum error */
	__be64 inner_ip_ttl;		/* ip ttl is 0 */
	__be64 inner_ip_len;		/* ip len error */
	__be64 inner_ipv4_ihl;		/* ipv4 ihl error */
	__be64 outer_udp_len;		/* udp len error */
	__be64 outer_tp_checksum;	/* tcp/udp checksum error */
	__be64 outer_ipv4_checksum;	/* ipv4 checksum error */
	__be64 outer_ip_ttl;		/* ip ttl is 0 */
	__be64 outer_ip_len;		/* ip len error */
	__be64 outer_ipv4_ihl;		/* ipv4 ihl error */
};

struct xsc_query_hw_prs_chk_err_stats_mbox_in {
	struct xsc_inbox_hdr hdr;
};

struct xsc_query_hw_prs_chk_err_stats_mbox_out {
	struct xsc_outbox_hdr hdr;
	struct xsc_prs_chk_err_stats stats;
};

struct xsc_dscp_pmt_set {
	u8 dscp;
	u8 priority;
	u8 rsvd[6];
};

struct xsc_dscp_pmt_get {
	u8 prio_map[QOS_DSCP_MAX + 1];
	u8 max_prio;
	u8 rsvd[7];
};

struct xsc_trust_mode_set {
	u8 is_pcp;
	u8 rsvd[7];
};

struct xsc_trust_mode_get {
	u8 is_pcp;
	u8 rsvd[7];
};

struct xsc_pcp_pmt_set {
	u8 pcp;
	u8 priority;
	u8 rsvd[6];
};

struct xsc_pcp_pmt_get {
	u8 prio_map[QOS_PCP_MAX + 1];
	u8 max_prio;
	u8 rsvd[7];
};

struct xsc_default_pri_set {
	u8 priority;
	u8 rsvd[7];
};

struct xsc_default_pri_get {
	u8 priority;
	u8 rsvd[7];
};

#define PFC_WATCHDOG_EN_OFF 0
#define PFC_WATCHDOG_EN_ON 1
struct xsc_watchdog_en_set {
	u8 en;
};

struct xsc_watchdog_en_get {
	u8 en;
};

#define PFC_WATCHDOG_PERIOD_MIN 1
#define PFC_WATCHDOG_PERIOD_MAX 4000000
struct xsc_watchdog_period_set {
	u32 period;
};

struct xsc_watchdog_period_get {
	u32 period;
};

struct xsc_event_resp {
	u8 resp_cmd_type; /* bitmap:0x0001: link up/down */
};

struct xsc_event_linkstatus_resp {
	u8 linkstatus; /*0:down, 1:up*/
};

struct xsc_event_linkinfo {
	u8 linkstatus; /*0:down, 1:up*/
	u8 port;
	u8 duplex;
	u8 autoneg;
	u32 linkspeed;
	u64 supported;
	u64 advertising;
	u64 supported_fec;	/* reserved, not support currently */
	u64 advertised_fec;	/* reserved, not support currently */
	u64 supported_speed[2];
	u64 advertising_speed[2];
};

struct xsc_lldp_status_mbox_in {
	struct xsc_inbox_hdr hdr;
	__be32 os_handle_lldp;
	u8 sub_type;
};

struct xsc_lldp_status_mbox_out {
	struct xsc_outbox_hdr hdr;
	union {
		__be32 os_handle_lldp;
		__be32 dcbx_status;
	} status;
};

struct xsc_vport_rate_limit_mobox_in {
	struct xsc_inbox_hdr hdr;
	u8 other_vport;
	__be16 vport_number;
	__be16 rsvd0;
	__be32 rate;
};

struct xsc_vport_rate_limit_mobox_out {
	struct xsc_outbox_hdr hdr;
};

struct xsc_event_query_type_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[2];
};

struct xsc_event_query_type_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_event_resp	ctx;
};

struct xsc_event_query_linkstatus_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[2];
};

struct xsc_event_query_linkstatus_mbox_out {
	struct xsc_outbox_hdr		hdr;
	struct xsc_event_linkstatus_resp	ctx;
};

struct xsc_event_query_linkinfo_mbox_in {
	struct xsc_inbox_hdr	hdr;
};

struct xsc_event_query_linkinfo_mbox_out {
	struct xsc_outbox_hdr		hdr;
	struct xsc_event_linkinfo	ctx;
};

struct xsc_event_modify_linkinfo_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_event_linkinfo	ctx;
};

struct xsc_event_modify_linkinfo_mbox_out {
	struct xsc_outbox_hdr		hdr;
	u32	status;
};

struct xsc_event_set_port_admin_status_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u16	admin_status;

};

struct xsc_event_set_port_admin_status_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u32	status;
};

struct xsc_event_set_led_status_mbox_in {
	struct xsc_inbox_hdr		hdr;
	u8	port_id;
};

struct xsc_event_set_led_status_mbox_out {
	struct xsc_outbox_hdr		hdr;
	u32	status;
};

struct xsc_event_modify_fecparam_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u32	fec;
};

struct xsc_event_modify_fecparam_mbox_out {
	struct xsc_outbox_hdr		hdr;
	u32	status;
};

struct xsc_event_query_fecparam_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[2];
};

struct xsc_event_query_fecparam_mbox_out {
	struct xsc_outbox_hdr		hdr;
	u32	active_fec;
	u32	fec_cfg;
	u32	status;
};

#define PFC_ON_PG_PRFL_IDX	0
#define PFC_OFF_PG_PRFL_IDX	1
#define PFC_ON_QMU_VALUE	0
#define PFC_OFF_QMU_VALUE	1

#define NIF_PFC_EN_ON		1
#define NIF_PFC_EN_OFF		0

#define PFC_CFG_CHECK_TIMEOUT_US	8000000
#define PFC_CFG_CHECK_SLEEP_TIME_US	200
#define PFC_CFG_CHECK_MAX_RETRY_TIMES \
	(PFC_CFG_CHECK_TIMEOUT_US / PFC_CFG_CHECK_SLEEP_TIME_US)
#define PFC_CFG_CHECK_VALID_CNT		3

#define PFC_CFG_CHECK_TIMEOUT_CNT	80
#define PFC_CFG_CHECK_SLEEP_TIME_MS	100

enum {
	SET_PFC_STATUS_INIT = 0,
	SET_PFC_STATUS_IN_PROCESS,
	SET_PFC_STATUS_MAX,
};

enum {
	SET_PFC_COMP_SUCCESS = 0,
	SET_PFC_COMP_FAIL,
	SET_PFC_COMP_TIMEOUT,
	SET_PFC_COMP_MAX,
};

enum {
	PFC_OP_ENABLE = 0,
	PFC_OP_DISABLE,
	PFC_OP_MODIFY,
	PFC_OP_TYPE_MAX,
};

enum {
	DROP_TH_CLEAR = 0,
	DROP_TH_RECOVER,
	DROP_TH_RECOVER_LOSSY,
	DROP_TH_RECOVER_LOSSLESS,
};

struct xsc_pfc_cfg {
	u8 req_prio;
	u8 req_pfc_en;
	u8 curr_prio;
	u8 curr_pfc_en;
	u8 pfc_op;
	u8 lossless_num;
};

#define LOSSLESS_NUM_INVALID	9
struct xsc_pfc_set {
	u8 priority;
	u8 pfc_on;
	u8 type;
	u8 src_prio;
	u8 lossless_num;
};

#define PFC_PRIO_MAX 7
struct xsc_pfc_get {
	u8 pfc_on[PFC_PRIO_MAX + 1];
	u8 max_prio;
};

struct xsc_pfc_set_drop_th_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 prio;
	u8 cfg_type;
};

struct xsc_pfc_set_drop_th_mbox_out {
	struct xsc_outbox_hdr hdr;
};

struct xsc_pfc_get_cfg_status_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 prio;
};

struct xsc_pfc_get_cfg_status_mbox_out {
	struct xsc_outbox_hdr hdr;
};

struct xsc_pfc_set_new {
	u8 req_prio;
	u8 pfc_on;
	u8 pfc_op;
	u8 cur_prio_en;//every bit represents one priority, eg: 0x1 represents prio_0 pfc on
	u8 lossless_num;//num of supported lossless priority
};

struct xsc_get_pfc_cfg_status_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 mac_port;
};

struct xsc_get_pfc_cfg_status_mbox_out {
	struct xsc_outbox_hdr hdr;
	u8 status;
	u8 comp;
};

struct xsc_rate_limit_set {
	u32 rate_cir;
	u32 limit_id;
	u8 limit_level;
	u8 rsvd[7];
};

struct xsc_rate_limit_get {
	u32 rate_cir[QOS_PRIO_MAX + 1];
	u32 max_limit_id;
	u8 limit_level;
	u8 rsvd[3];
};

struct xsc_sp_set {
	u8 sp[QOS_PRIO_MAX + 1];
};

struct xsc_sp_get {
	u8 sp[QOS_PRIO_MAX + 1];
	u8 max_prio;
	u8 rsvd[7];
};

struct xsc_weight_set {
	u8 weight[QOS_PRIO_MAX + 1];
};

struct xsc_weight_get {
	u8 weight[QOS_PRIO_MAX + 1];
	u8 max_prio;
	u8 rsvd[7];
};

struct xsc_dpu_port_weight_set {
	u8 target;
	u8 weight[DPU_PORT_WGHT_CFG_MAX + 1];
	u8 rsv[5];
};

struct xsc_dpu_port_weight_get {
	u8 weight[DPU_PORT_WGHT_TARGET_NUM][DPU_PORT_WGHT_CFG_MAX + 1];
	u8 rsvd[4];
};

struct xsc_dpu_prio_weight_set {
	u8 target;
	u8 weight[QOS_PRIO_MAX + 1];
	u8 rsv[7];
};

struct xsc_dpu_prio_weight_get {
	u8 weight[DPU_PRIO_WGHT_TARGET_NUM][QOS_PRIO_MAX + 1];
};

struct xsc_cc_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			data[];
};

struct xsc_cc_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			data[];
};

struct xsc_cc_ctrl_cmd {
	u16 cmd;
	u16 len;
	u8 val[];
};

struct xsc_cc_cmd_enable_rp {
	u16 cmd;
	u16 len;
	u32 enable;
	u32 section;
};

struct xsc_cc_cmd_enable_np {
	u16 cmd;
	u16 len;
	u32 enable;
	u32 section;
};

struct xsc_cc_cmd_init_alpha {
	u16 cmd;
	u16 len;
	u32 alpha;
	u32 section;
};

struct xsc_cc_cmd_g {
	u16 cmd;
	u16 len;
	u32 g;
	u32 section;
};

struct xsc_cc_cmd_ai {
	u16 cmd;
	u16 len;
	u32 ai;
	u32 section;
};

struct xsc_cc_cmd_hai {
	u16 cmd;
	u16 len;
	u32 hai;
	u32 section;
};

struct xsc_cc_cmd_th {
	u16 cmd;
	u16 len;
	u32 threshold;
	u32 section;
};

struct xsc_cc_cmd_bc {
	u16 cmd;
	u16 len;
	u32 bytecount;
	u32 section;
};

struct xsc_cc_cmd_cnp_opcode {
	u16 cmd;
	u16 len;
	u32 opcode;
};

struct xsc_cc_cmd_cnp_bth_b {
	u16 cmd;
	u16 len;
	u32 bth_b;
};

struct xsc_cc_cmd_cnp_bth_f {
	u16 cmd;
	u16 len;
	u32 bth_f;
};

struct xsc_cc_cmd_cnp_ecn {
	u16 cmd;
	u16 len;
	u32 ecn;
};

struct xsc_cc_cmd_data_ecn {
	u16 cmd;
	u16 len;
	u32 ecn;
};

struct xsc_cc_cmd_cnp_tx_interval {
	u16 cmd;
	u16 len;
	u32 interval; // us
	u32 section;
};

struct xsc_cc_cmd_evt_rsttime {
	u16 cmd;
	u16 len;
	u32 period;
};

struct xsc_cc_cmd_cnp_dscp {
	u16 cmd;
	u16 len;
	u32 dscp;
	u32 section;
};

struct xsc_cc_cmd_cnp_pcp {
	u16 cmd;
	u16 len;
	u32 pcp;
	u32 section;
};

struct xsc_cc_cmd_evt_period_alpha {
	u16 cmd;
	u16 len;
	u32 period;
};

struct xsc_cc_cmd_clamp_tgt_rate {
	u16 cmd;
	u16 len;
	u32 clamp_tgt_rate;
	u32 section;
};

struct xsc_cc_cmd_max_hai_factor {
	u16 cmd;
	u16 len;
	u32 max_hai_factor;
	u32 section;
};

struct xsc_cc_cmd_scale {
	u16 cmd;
	u16 len;
	u32 scale;
	u32 section;
};

struct xsc_cc_cmd_get_cfg {
	u16 cmd;
	u16 len;
	u32 enable_rp;
	u32 enable_np;
	u32 init_alpha;
	u32 g;
	u32 ai;
	u32 hai;
	u32 threshold;
	u32 bytecount;
	u32 opcode;
	u32 bth_b;
	u32 bth_f;
	u32 cnp_ecn;
	u32 data_ecn;
	u32 cnp_tx_interval;
	u32 evt_period_rsttime;
	u32 cnp_dscp;
	u32 cnp_pcp;
	u32 evt_period_alpha;
	u32 clamp_tgt_rate;
	u32 max_hai_factor;
	u32 scale;
	u32 section;
};

struct xsc_cc_cmd_get_stat {
	u16 cmd;
	u16 len;
	u32 section;
};

struct xsc_cc_cmd_stat {
	u32 cnp_handled;
	u32 alpha_recovery;
	u32 reset_timeout;
	u32 reset_bytecount;
};

struct xsc_perf_rate_measure {
	u32 qp_num;
	u32 qp_id_list[XSC_QP_MEASURE_QP_NUM_MAX];
	u32 qp_byte_cnt[XSC_QP_MEASURE_QP_NUM_MAX];
	u32 hw_ts;
};

struct xsc_perf_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			data[];
};

struct xsc_perf_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			data[];
};

struct xsc_set_mtu_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			mtu;
	__be16			rx_buf_sz_min;
	u8			mac_port;
	u8			rsvd;
};

struct xsc_hwc_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			data[];
};

struct xsc_hwc_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			data[];
};

struct hwc_set_t {
	u8 type;
	u8 s_wqe_mode;
	u8 r_wqe_mode;
	u8 ack_timeout;
	u8 group_mode;
	u8 lossless_prio[XSC_MAX_MAC_NUM];
	u8 lossless_prio_len;
	u8 retry_cnt_th;
	u8 adapt_to_other;
	u8 alloc_qp_id_mode;
	u16 vf_num_per_pf;
	u16 max_vf_num_per_pf;
	u8 eth_pkt_offset;
	u8 rdma_pkt_offset;
	u8 tso_eth_pkt_offset;
	u8 tx_dedi_pref;
	u8 reg_mr_via_cmdq;
	u8 per_dst_grp_thr;
	u8 per_dst_grp_cnt;
	u8 dcbx_status[XSC_MAX_MAC_NUM];
	u8 dcbx_port_cnt;
	u8 read_flush;
};

struct hwc_get_t {
	u8 cur_s_wqe_mode;
	u8 next_s_wqe_mode;
	u8 cur_r_wqe_mode;
	u8 next_r_wqe_mode;
	u8 cur_ack_timeout;
	u8 next_ack_timeout;
	u8 cur_group_mode;
	u8 next_group_mode;
	u8 cur_lossless_prio[XSC_MAX_MAC_NUM];
	u8 next_lossless_prio[XSC_MAX_MAC_NUM];
	u8 lossless_prio_len;
	u8 cur_retry_cnt_th;
	u8 next_retry_cnt_th;
	u8 cur_adapt_to_other;
	u8 next_adapt_to_other;
	u16 cur_vf_num_per_pf;
	u16 next_vf_num_per_pf;
	u16 cur_max_vf_num_per_pf;
	u16 next_max_vf_num_per_pf;
	u8 cur_eth_pkt_offset;
	u8 next_eth_pkt_offset;
	u8 cur_rdma_pkt_offset;
	u8 next_rdma_pkt_offset;
	u8 cur_tso_eth_pkt_offset;
	u8 next_tso_eth_pkt_offset;
	u8 cur_alloc_qp_id_mode;
	u8 next_alloc_qp_id_mode;
	u8 cur_tx_dedi_pref;
	u8 next_tx_dedi_pref;
	u8 cur_reg_mr_via_cmdq;
	u8 next_reg_mr_via_cmdq;
	u8 cur_per_dst_grp_thr;
	u8 next_per_dst_grp_thr;
	u8 cur_per_dst_grp_cnt;
	u8 next_per_dst_grp_cnt;
	u8 cur_dcbx_status[XSC_MAX_MAC_NUM];
	u8 next_dcbx_status[XSC_MAX_MAC_NUM];
	u8 dcbx_port_cnt;
	u8 cur_read_flush;
	u8 next_read_flush;
};

struct xsc_set_mtu_mbox_out {
	struct xsc_outbox_hdr	hdr;
};

struct xsc_query_eth_mac_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			index;
};

struct xsc_query_eth_mac_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			mac[6];
};

struct xsc_query_mtu_mbox_in {
	struct xsc_inbox_hdr	hdr;
};

struct xsc_query_mtu_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be16			mtu;
};

struct xsc_query_pause_cnt_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u16    mac_port;
	u16    cnt_type;
	u32    reg_addr;
};

struct xsc_query_pause_cnt_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u64    val;
};

enum {
	XSC_TBM_CAP_HASH_PPH = 0,
	XSC_TBM_CAP_RSS,
	XSC_TBM_CAP_PP_BYPASS,
	XSC_TBM_CAP_MAC_DROP_CONFIG,
	XSC_TBM_CAP_PF_ISOLATE_CONFIG,
};

struct xsc_nic_attr {
	__be16	caps;
	__be16	caps_mask;
	u8	mac_addr[6];
};

struct xsc_rss_attr {
	u8	rss_en;
	u8	hfunc;
	__be16	rqn_base;
	__be16	rqn_num;
	__be32	hash_tmpl;
};

struct xsc_cmd_enable_nic_hca_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_nic_attr	nic;
	struct xsc_rss_attr	rss;
};

struct xsc_cmd_enable_nic_hca_mbox_out {
	struct xsc_outbox_hdr		hdr;
	u8	rsvd0[2];
};

struct xsc_nic_dis_attr {
	__be16	caps;
};

struct xsc_cmd_disable_nic_hca_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_nic_dis_attr		nic;
};

struct xsc_cmd_disable_nic_hca_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd0[4];
};

enum {
	XSC_RSS_HASH_KEY_UPDATE	= 0,
	XSC_RSS_HASH_TEMP_UPDATE,
	XSC_RSS_HASH_FUNC_UPDATE,
	XSC_RSS_RXQ_UPDATE,
	XSC_RSS_RXQ_DROP,
};

struct xsc_rss_modify_attr {
	u8	caps_mask;
	u8	rss_en;
	__be16	rqn_base;
	__be16	rqn_num;
	u8	hfunc;
	__be32	hash_tmpl;
	u8	hash_key[52];
};

struct xsc_cmd_modify_nic_hca_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_nic_attr		nic;
	struct xsc_rss_modify_attr	rss;
};

struct xsc_cmd_modify_nic_hca_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd0[4];
};

struct xsc_cmd_query_pkt_dst_info_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8	mac_bitmap;
	u16	pkt_bitmap;
	u32	resv0;
};

struct xsc_cmd_query_pkt_dst_info_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u16	dst_info[8];
	u32	resv0;
};

struct xsc_cmd_modify_pkt_dst_info_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8	mac_bitmap;
	u16	pkt_bitmap;
	u16	dst_info;
	u16	resv0;
};

struct xsc_cmd_modify_pkt_dst_info_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u32	resv0;
};

struct xsc_function_reset_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16	glb_func_id;
	u8	rsvd[6];
};

struct xsc_function_reset_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

enum {
	XSC_OOO_STATISTIC_FEAT_SET_RESET = 0,
	XSC_OOO_STATISTIC_FEAT_SET_RANGE,
	XSC_OOO_STATISTIC_FEAT_GET_RANGE,
	XSC_OOO_STATISTIC_FEAT_GET_SHOW,
};

#define XSC_OOO_STATISTIC_RANGE_MAX	16
#define XSC_OOO_STATISTIC_SHOW_MAX	17

#define XSC_OOO_STATISTIC_RESET		1
#define XSC_OOO_STATISTIC_RANGE_VAL_MIN	0
#define XSC_OOO_STATISTIC_RANGE_VAL_MAX	4095

struct xsc_ooo_statistic {
	u8 ooo_statistic_reset;
	u32 ooo_statistic_range[XSC_OOO_STATISTIC_RANGE_MAX];
	u32 ooo_statistic_show[XSC_OOO_STATISTIC_SHOW_MAX];
};

struct xsc_ooo_statistic_feat_mbox_in {
	struct xsc_inbox_hdr hdr;
	__be16 xsc_ooo_statistic_feature_opcode;
	struct xsc_ooo_statistic ooo_statistic;
};

struct xsc_ooo_statistic_feat_mbox_out {
	struct xsc_outbox_hdr hdr;
	__be16 xsc_ooo_statistic_feature_opcode;
	struct xsc_ooo_statistic ooo_statistic;
};

enum {
	XSC_PCIE_LAT_FEAT_SET_EN	= 0,
	XSC_PCIE_LAT_FEAT_GET_EN,
	XSC_PCIE_LAT_FEAT_SET_INTERVAL,
	XSC_PCIE_LAT_FEAT_GET_INTERVAL,
	XSC_PCIE_LAT_FEAT_GET_HISTOGRAM,
	XSC_PCIE_LAT_FEAT_GET_PEAK,
	XSC_PCIE_LAT_FEAT_HW,
	XSC_PCIE_LAT_FEAT_HW_INIT,
};

struct xsc_pcie_lat {
	u8 pcie_lat_enable;
	u32 pcie_lat_interval[XSC_PCIE_LAT_CFG_INTERVAL_MAX];
	u32 pcie_lat_histogram[XSC_PCIE_LAT_CFG_HISTOGRAM_MAX];
	u32 pcie_lat_peak;
};

struct xsc_pcie_lat_feat_mbox_in {
	struct xsc_inbox_hdr hdr;
	__be16 xsc_pcie_lat_feature_opcode;
	struct xsc_pcie_lat pcie_lat;
};

struct xsc_pcie_lat_feat_mbox_out {
	struct xsc_outbox_hdr hdr;
	__be16 xsc_pcie_lat_feature_opcode;
	struct xsc_pcie_lat pcie_lat;
};

struct xsc_reg_mcia {
	u8         module;
	u8         status;

	u8         i2c_device_address;
	u8         page_number;
	u8         device_address;

	u8         size;

	u8         dword_0[0x20];
	u8         dword_1[0x20];
	u8         dword_2[0x20];
	u8         dword_3[0x20];
	u8         dword_4[0x20];
	u8         dword_5[0x20];
	u8         dword_6[0x20];
	u8         dword_7[0x20];
	u8         dword_8[0x20];
	u8         dword_9[0x20];
	u8         dword_10[0x20];
	u8         dword_11[0x20];
};

struct xsc_rtt_en_mbox_in {
	struct xsc_inbox_hdr    hdr;
	u8    en;//0-disable, 1-enable
	u8    rsvd[7];
};

struct xsc_rtt_en_mbox_out {
	struct xsc_outbox_hdr    hdr;
	u8    en;//0-disable, 1-enable
	u8    rsvd[7];
};

struct xsc_rtt_qpn_mbox_in {
	struct xsc_inbox_hdr    hdr;
	__be32    qpn[32];
};

struct xsc_rtt_qpn_mbox_out {
	struct xsc_outbox_hdr    hdr;
	u8    rsvd[8];
};

struct xsc_get_rtt_qpn_mbox_out {
	struct xsc_outbox_hdr    hdr;
	__be32    qpn[32];
};

struct xsc_rtt_period_mbox_in {
	struct xsc_inbox_hdr    hdr;
	__be32    period; //ms
};

struct xsc_rtt_period_mbox_out {
	struct xsc_outbox_hdr    hdr;
	__be32    period; //ms
	u8    rsvd[4];
};

struct xsc_rtt_result_mbox_out {
	struct xsc_outbox_hdr    hdr;
	__be64    result[32];
};

struct rtt_stats {
	u64 rtt_succ_snd_req_cnt;
	u64 rtt_succ_snd_rsp_cnt;
	u64 rtt_fail_snd_req_cnt;
	u64 rtt_fail_snd_rsp_cnt;
	u64 rtt_rcv_req_cnt;
	u64 rtt_rcv_rsp_cnt;
	u64 rtt_rcv_unk_cnt;
	u64 rtt_grp_invalid_cnt;
};

struct xsc_rtt_stats_mbox_out {
	struct xsc_outbox_hdr	 hdr;
	struct rtt_stats stats;
};

enum {
	XSC_AP_FEAT_SET_UDP_SPORT = 0,
};

struct xsc_ap_feat_set_udp_sport {
	u32 qpn;
	u32 udp_sport;
};

struct xsc_ap {
	struct xsc_ap_feat_set_udp_sport set_udp_sport;
};

struct xsc_ap_feat_mbox_in {
	struct xsc_inbox_hdr hdr;
	__be16 xsc_ap_feature_opcode;
	struct xsc_ap ap;
};

struct xsc_ap_feat_mbox_out {
	struct xsc_outbox_hdr hdr;
	__be16 xsc_ap_feature_opcode;
	struct xsc_ap ap;
};

struct xsc_set_debug_info_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			set_field;
	u8			log_level;
	u8			cmd_verbose;
	u8			rsvd[5];
};

struct xsc_set_debug_info_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_roce_accl_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			data[];
};

struct xsc_roce_accl_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			data[];
};

#define XSC_DISCRETE_SPORT_NUM_MAX  128

struct xsc_roce_accl_set {
	u64 sr_timeout;
	u32 flag;
	u8  retrans_mode;
	u8  sr_mode;
	u16 sr_count;
	u16 sr_drop_limit;
	u16 ndp_dst_port;
	u8  bth_rsv7;
	u8  packet_spray_mode;
	u16  cont_sport_start;
	u16  max_num_exponent;
	u16  disturb_period;
	u16  disturb_th;
	u8   mac_port;
	u8  lag_mode;
};

struct xsc_roce_accl_get {
	u64 sr_timeout;
	u8  retrans_mode;
	u8  sr_mode;
	u16 sr_count;
	u16 sr_drop_limit;
	u16 ndp_dst_port;
	u8  bth_rsv7;
	u8  packet_spray_mode;
	u16  cont_sport_start;
	u16  max_num_exponent;
	u16  disturb_period;
	u16  disturb_th;
	u8  lag_mode;
	u8  rsv[5];
};

struct xsc_roce_accl_disc_sport {
	u16  discrete_sports[XSC_DISCRETE_SPORT_NUM_MAX];
	u32  discrete_sports_num;
	u8   mac_port;
	u8   rsv[3];
};

struct xsc_cmd_enable_relaxed_order_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_enable_relaxed_order_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_query_guid_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_query_guid_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be64			guid;
};

struct xsc_cmd_activate_hw_config_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_activate_hw_config_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_read_flush_hw_config_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_read_flush_hw_config_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			read_flush;
	u8			rsvd[7];
};

enum {
	ROCE_ACCL_NEXT_FLAG_SHOW_SHIFT				= 0,
	ROCE_ACCL_NEXT_FLAG_SACK_THRESHOLD_SHIFT		= 2,
	ROCE_ACCL_NEXT_FLAG_SACK_TIMEOUT_SHIFT			= 3,
	ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_MODE_SHIFT		= 4,
	ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_REQ_THRESHOLD_SHIFT	= 5,
	ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_RSP_WINDOW_SHIFT	= 6,
	ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_RSP_TIMEOUT_SHIFT	= 7,
	ROCE_ACCL_NEXT_FLAG_PATH_NUM_SHIFT			= 8,
	ROCE_ACCL_NEXT_FLAG_PACKET_SPRAY_MODE_SHIFT		= 9,
	ROCE_ACCL_NEXT_FLAG_QP_ID_SHIFT				= 10,
	ROCE_ACCL_NEXT_FLAG_PATH_UDP_SPORT_SHIFT		= 11,
	ROCE_ACCL_NEXT_FLAG_SHOW_PATH_UDP_SPORT_SHIFT		= 12,
	ROCE_ACCL_NEXT_FLAG_MAX_NUM				= 13,
};

#define ROCE_ACCL_NEXT_FLAG_SHOW_MASK				\
	(1ULL << ROCE_ACCL_NEXT_FLAG_SHOW_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_SACK_THRESHOLD_MASK			\
	(1ULL << ROCE_ACCL_NEXT_FLAG_SACK_THRESHOLD_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_SACK_TIMEOUT_MASK			\
	(1ULL <<  ROCE_ACCL_NEXT_FLAG_SACK_TIMEOUT_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_MODE_MASK		\
	(1ULL <<  ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_MODE_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_REQ_THRESHOLD_MASK	\
	(1ULL <<  ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_REQ_THRESHOLD_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_RSP_WINDOW_MASK	\
	(1ULL <<  ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_RSP_WINDOW_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_RSP_TIMEOUT_MASK	\
	(1ULL <<  ROCE_ACCL_NEXT_FLAG_ACK_AGGREGATION_RSP_TIMEOUT_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_PATH_NUM_MASK			\
	(1ULL <<  ROCE_ACCL_NEXT_FLAG_PATH_NUM_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_PACKET_SPRAY_MODE_MASK		\
	(1ULL <<  ROCE_ACCL_NEXT_FLAG_PACKET_SPRAY_MODE_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_QP_ID_MASK				\
	(1ULL << ROCE_ACCL_NEXT_FLAG_QP_ID_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_PATH_UDP_SPORT_MASK			\
	(1ULL << ROCE_ACCL_NEXT_FLAG_PATH_UDP_SPORT_SHIFT)
#define ROCE_ACCL_NEXT_FLAG_SHOW_PATH_UDP_SPORT_MASK		\
	(1ULL << ROCE_ACCL_NEXT_FLAG_SHOW_PATH_UDP_SPORT_SHIFT)

struct xsc_roce_accl_next_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			data[0];
};

struct xsc_roce_accl_next_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			data[0];
};

#define ROCE_ACCL_NEXT_PATH_UDP_SPORT_NUM_MAX	16

struct xsc_roce_accl_next_set {
	u64	flag;
	u32	sack_threshold;
	u32	sack_timeout;
	u32	ack_aggregation_mode;
	u32	ack_aggregation_req_threshold;
	u32	ack_aggregation_rsp_window;
	u32	ack_aggregation_rsp_timeout;
	u32	path_num;
	u32	packet_spray_mode;
	u32	qp_id;
	u32	path_udp_sport[ROCE_ACCL_NEXT_PATH_UDP_SPORT_NUM_MAX];
	u32	path_udp_sport_num;
};

struct xsc_roce_accl_next_get {
	u32	sack_threshold;
	u32	sack_timeout;
	u32	ack_aggregation_mode;
	u32	ack_aggregation_req_threshold;
	u32	ack_aggregation_rsp_window;
	u32	ack_aggregation_rsp_timeout;
	u32	path_num;
	u32	packet_spray_mode;
};

struct xsc_flexcc_next_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			data[];
};

struct xsc_flexcc_next_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			data[];
};

#define YUN_CC_CMD_DATA_LEN_MAX			120

enum {
	YUN_CC_CMD_SET_SP_TH,
	YUN_CC_CMD_SET_RTT_INTERVAL_INBAND,
	YUN_CC_CMD_SET_RTT_INTERVAL_OUTBAND,
	YUN_CC_CMD_SET_BYTE_RST_INTERVAL,
	YUN_CC_CMD_SET_BWU_INTERVAL,
	YUN_CC_CMD_SET_CSP_DSCP,
	YUN_CC_CMD_SET_RTT_DSCP_OUTBAND,
	YUN_CC_CMD_SET_CSP_ECN_AGGREGATION,
	YUN_CC_CMD_SET_CC_ALG,
	YUN_CC_CMD_SET_ENABLE,
	YUN_CC_CMD_GET_ALL,
	YUN_CC_CMD_GET_ALL_STAT,
	YUN_CC_CMD_SET_CE_PROC_INTERVAL,
};

struct yun_cc_next_get_all {
	u32 sp_threshold;
	u32 rtt_interval_inband;
	u32 rtt_interval_outband;
	u32 byte_rst_interval;
	u32 bwu_interval;
	u32 csp_dscp;
	u32 rtt_dscp_outband;
	u32 csp_ecn_aggregation;
	u32 enable;
	u32 ce_proc_interval;
	u32 cc_alg;
	u32 cc_alg_mask;
	u8 cc_alg_slot1_vrsn[32];
	u8 cc_alg_slot2_vrsn[32];
};

struct yun_cc_next_get_all_stat {
	u32 evt_sp_deliverd;
	u32 evt_ce_deliverd;
	u32 evt_rtt_req_deliverd;
	u32 evt_rtt_rsp_deliverd;
	u32 evt_rto_deliverd;
	u32 evt_sack_deliverd;
	u32 evt_byte_deliverd;
	u32 evt_time_deliverd;
	u32 evt_bwu_deliverd;
	u32 evt_sp_aggregated;
	u32 evt_ce_aggregated;
	u32 evt_rtt_req_aggregated;
	u32 evt_rtt_rsp_aggregated;
	u32 evt_rto_aggregated;
	u32 evt_sack_aggregated;
	u32 evt_byte_aggregated;
	u32 evt_time_aggregated;
	u32 evt_bwu_aggregated;
	u32 evt_sp_dropped;
	u32 evt_ce_dropped;
	u32 evt_rtt_req_dropped;
	u32 evt_rtt_rsp_dropped;
	u32 evt_rto_dropped;
	u32 evt_sack_dropped;
	u32 evt_byte_dropped;
	u32 evt_time_dropped;
	u32 evt_bwu_dropped;
};

struct yun_cc_next_sp_th {
	u32 threshold;
};

struct yun_cc_next_rtt_interval_inband {
	u32 interval;
};

struct yun_cc_next_rtt_interval_outband {
	u32 interval;
};

struct yun_cc_next_byte_rst_interval {
	u32 interval;
};

struct yun_cc_next_bwu_interval {
	u32 interval;
};

struct yun_cc_next_csp_dscp {
	u32 dscp;
};

struct yun_cc_next_rtt_dscp_outband {
	u32 dscp;
};

struct yun_cc_csp_ecn_aggregation {
	u32 agg;
};

struct yun_cc_next_cc_alg {
	u32 user_alg_en;
	u32 slot_mask;
	u32 slot;
};

struct yun_cc_enable {
	u32 en;
};

struct yun_cc_next_cmd_hdr {
	u32 cmd;
	u32 len;
	u8 data[];
};

struct yun_cc_next_ce_proc_interval {
	u32 interval;
};

#define FLEXCC_IOCTL_USER_DATA_MAX 240

struct flexcc_ioctl_buf {
	u8 data[FLEXCC_IOCTL_USER_DATA_MAX];
};

struct flexcc_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8			data[];
};

struct flexcc_mbox_out {
	struct xsc_outbox_hdr hdr;
	u8			data[];
};

struct xsc_cmd_get_ioctl_info_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			ioctl_opcode;
	__be16			length;
	u8			rsvd[4];
	u8			data[];
};

struct xsc_cmd_get_ioctl_info_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
	u8			data[];
};

struct xsc_target_info {
	__be32			domain;
	__be32			bus;
	__be32			devfn;
	__be32			data_length;
};

struct xsc_send_tunnel_cmd_req_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_target_info	target;
	u8			data[];
};

struct xsc_send_tunnel_cmd_req_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_recv_tunnel_cmd_req_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_recv_tunnel_cmd_req_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_target_info	target;
	u8			data[];
};

struct xsc_send_tunnel_cmd_resp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
	u8			data[];
};

struct xsc_send_tunnel_cmd_resp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_recv_tunnel_cmd_resp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_recv_tunnel_cmd_resp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
	u8			data[];
};

struct xsc_cmd_netlink_msg_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			nlmsg_len;
	u8			rsvd[6];
	u8			data[];
};

struct xsc_cmd_netlink_msg_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
	u8			data[];
};

struct xsc_cmd_ioctl_get_hw_counters_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			length;
	u8			rsvd[4];
	u8			data[];
};

struct xsc_cmd_ioctl_get_hw_counters_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
	u8			data[];
};

#endif /* XSC_CMD_H */
