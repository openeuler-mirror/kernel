/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_CMD_H
#define XSC_CMD_H

#define CMDQ_VERSION 0x21

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

#define XSC_PCIE_LAT_CFG_INTERVAL_MAX	8
#define XSC_PCIE_LAT_CFG_HISTOGRAM_MAX	9
#define XSC_PCIE_LAT_EN_DISABLE		0
#define XSC_PCIE_LAT_EN_ENABLE		1
#define XSC_PCIE_LAT_PERIOD_MIN		1
#define XSC_PCIE_LAT_PERIOD_MAX		20
#define DPU_PORT_WGHT_CFG_MAX		1

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

	XSC_CMD_OP_CREATE_MKEY			= 0x200,
	XSC_CMD_OP_QUERY_MKEY			= 0x201,
	XSC_CMD_OP_DESTROY_MKEY			= 0x202,
	XSC_CMD_OP_QUERY_SPECIAL_CONTEXTS	= 0x203,
	XSC_CMD_OP_REG_MR			= 0x204,
	XSC_CMD_OP_DEREG_MR			= 0x205,
	XSC_CMD_OP_SET_MPT			= 0x206,
	XSC_CMD_OP_SET_MTT			= 0x207,

	XSC_CMD_OP_CREATE_EQ			= 0x301,
	XSC_CMD_OP_DESTROY_EQ			= 0x302,
	XSC_CMD_OP_QUERY_EQ			= 0x303,

	XSC_CMD_OP_CREATE_CQ			= 0x400,
	XSC_CMD_OP_DESTROY_CQ			= 0x401,
	XSC_CMD_OP_QUERY_CQ			= 0x402,
	XSC_CMD_OP_MODIFY_CQ			= 0x403,
	XSC_CMD_OP_ALLOC_MULTI_VIRTQ_CQ    = 0x404,
	XSC_CMD_OP_RELEASE_MULTI_VIRTQ_CQ  = 0x405,

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

	XSC_CMD_OP_LAG_CREATE			= 0x840,
	XSC_CMD_OP_LAG_MODIFY			= 0x841,
	XSC_CMD_OP_LAG_DESTROY			= 0x842,
	XSC_CMD_OP_LAG_SET_QOS			= 0x848,
	XSC_CMD_OP_ENABLE_MSIX			= 0x850,

	XSC_CMD_OP_IOCTL_FLOW			= 0x900,
	XSC_CMD_OP_IOCTL_OTHER			= 0x901,

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
	XSC_CMD_OP_IOCTL_DPU_SET_PORT_WEIGHT		= 0x1010,
	XSC_CMD_OP_IOCTL_DPU_GET_PORT_WEIGHT		= 0x1011,
	XSC_CMD_OP_IOCTL_DPU_SET_PRIO_WEIGHT		= 0x1012,
	XSC_CMD_OP_IOCTL_DPU_GET_PRIO_WEIGHT		= 0x1013,

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

	XSC_CMD_OP_IOCTL_SET_HWC = 0x1060,
	XSC_CMD_OP_IOCTL_GET_HWC = 0x1061,

	XSC_CMD_OP_SET_MTU = 0x1100,
	XSC_CMD_OP_QUERY_ETH_MAC = 0X1101,

	XSC_CMD_OP_QUERY_HW_STATS = 0X1200,
	XSC_CMD_OP_QUERY_PAUSE_CNT = 0X1201,

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

	XSC_CMD_OP_USER_EMU_CMD = 0x8000,

	XSC_CMD_OP_MAX
};

enum {
	XSC_CMD_EVENT_RESP_CHANGE_LINK	= 0x0001,
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

	XSC_HW_LAST_FEATURE = 0x80000000,
};

struct xsc_inbox_hdr {
	__be16		opcode;
	u8		rsvd[4];
	__be16		opmod;
};

struct xsc_outbox_hdr {
	u8		status;
	u8		rsvd[3];
	__be32		syndrome;
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
	u8		rsvd[2];
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
	u8			no_need_wait;
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
	u8			rsvd[1];
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
	__be32		len;
	__be32		mkey;
	u8		rsvd;
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
	u8		rsvd29[7];
	u8		nif_port_num;
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
};

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

	__be16		promisc_uc:1;
	__be16		promisc_mc:1;
	__be16		promisc_all:1;
	__be16		vlan_allowed:1;
	__be16		allowed_list_type:3;
	__be16		allowed_list_size:10;

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
	__be32		permanent_address:1;
	__be32		current_address:1;
	__be32		addresses_list:1;
	__be32		roce_en:1;
	__be32		rsvd:19;
};

struct xsc_modify_nic_vport_context_in {
	struct xsc_inbox_hdr	hdr;
	__be32		other_vport:1;
	__be32		vport_number:16;
	__be32		rsvd:15;
	__be16		caps;
	__be16		caps_mask;

	struct xsc_modify_nic_vport_field_select field_select;
	struct xsc_nic_vport_context nic_vport_ctx;
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

struct xsc_lag_port_info {
	u8	netdev_addr[ETH_ALEN];
	u8	gw_dmac[ETH_ALEN];
	__be16	glb_func_id;
};

struct xsc_create_lag_request {
	struct xsc_lag_port_info	info_mac0;
	struct xsc_lag_port_info	info_mac1;
	u8	mp_lag;
	u8	roce_lag;
	u8	lag_num;
	__be16	lag_id;
	__be16	lag_start;
	u8	lag_sel_mode;
	u8	remap_port1;
	u8	remap_port2;
	u8	kernel_bond;
	u8	rsvd[5];
};

struct xsc_modify_lag_request {
	u8	mp_lag;
	u8	roce_lag;
	__be16	lag_id;
	u8	lag_sel_mode;
	u8	remap_port1;
	u8	remap_port2;
	u8	rsvd[2];
};

struct xsc_destroy_lag_request {
	__be16	lag_id;
	u8	kernel_bond;
	u8	rsvd[5];
};

struct xsc_set_lag_qos_request {
	__be16		lag_id;
	u8		member_bitmap;
	u8		lag_del;
	u8		pcie_no;
	u8		resv[3];
};

struct xsc_create_lag_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_create_lag_request	req;
};

struct xsc_create_lag_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8	rsvd[8];
};

struct xsc_modify_lag_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_modify_lag_request	req;
};

struct xsc_modify_lag_mbox_out {
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

struct xsc_hw_stats {
	/*by mac port*/
	u64 rdma_tx_pkts;
	u64 rdma_tx_bytes;
	u64 rdma_rx_pkts;
	u64 rdma_rx_bytes;
	u64 np_cnp_sent;
	u64 rp_cnp_handled;
	u64 np_ecn_marked_roce_packets;
	u64 rp_cnp_ignored;
	u64 tx_pause;
	u64 rx_pause;
	u64 rx_fcs_errors;
	u64 rx_discards;
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
	/*by global*/
	u64 rdma_loopback_pkts;
	u64 rdma_loopback_bytes;
};

struct xsc_hw_stats_mbox_in {
	struct xsc_inbox_hdr hdr;
	u8 mac_port;
	u8 is_lag;
	u8 lag_member_num;
	u8 member_port[];
};

struct xsc_hw_stats_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_hw_stats	hw_stats;
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

struct xsc_event_resp {
	u16 resp_cmd_type; /* bitmap:0x0001: link up/down */
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

struct xsc_pfc_set {
	u8 priority;
	u8 pfc_on;
	u8 rsvd[6];
};

#define PFC_PRIO_MAX 7
struct xsc_pfc_get {
	u8 pfc_on[PFC_PRIO_MAX + 1];
	u8 max_prio;
	u8 rsvd[7];
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
	u16 max_vf_num;
	u8 eth_pkt_offset;
	u8 rdma_pkt_offset;
	u8 tso_eth_pkt_offset;
	u8 tx_dedi_pref;
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
	u16 cur_max_vf_num;
	u16 next_max_vf_num;
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
	XSC_TBM_CAP_PCT_DROP_CONFIG,
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
	__be16    qpn[32];
};

struct xsc_rtt_qpn_mbox_out {
	struct xsc_outbox_hdr    hdr;
	u8    rsvd[8];
};

struct xsc_get_rtt_qpn_mbox_out {
	struct xsc_outbox_hdr    hdr;
	__be16    qpn[32];
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
	u64 rtt_grp_invaild_cnt;
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

#endif /* XSC_CMD_H */
