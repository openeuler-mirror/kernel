/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_IB_USER_H
#define XSC_IB_USER_H

#include <linux/types.h>
#include <linux/if_ether.h>	/* For ETH_ALEN. */
#include <rdma/ib_user_ioctl_cmds.h>

enum xsc_ib_devx_methods {
	XSC_IB_METHOD_DEVX_OTHER  = (1U << UVERBS_ID_NS_SHIFT),
	XSC_IB_METHOD_DEVX_QUERY_UAR,
	XSC_IB_METHOD_DEVX_QUERY_EQN,
};

enum  xsc_ib_devx_other_attrs {
	XSC_IB_ATTR_DEVX_OTHER_CMD_IN = (1U << UVERBS_ID_NS_SHIFT),
	XSC_IB_ATTR_DEVX_OTHER_CMD_OUT,
};

enum xsc_ib_objects {
	XSC_IB_OBJECT_DEVX = (1U << UVERBS_ID_NS_SHIFT),
	XSC_IB_OBJECT_DEVX_OBJ,
	XSC_IB_OBJECT_DEVX_UMEM,
	XSC_IB_OBJECT_FLOW_MATCHER,
};

/* Increment this value if any changes that break userspace ABI
 * compatibility are made.
 */
#define XSC_IB_UVERBS_ABI_VERSION	1

/* Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 * In particular do not use pointer types -- pass pointers in __u64
 * instead.
 */

enum {
	XSC_QP_FLAG_SIGNATURE		= 1 << 0,
	XSC_QP_FLAG_SCATTER_CQE	= 1 << 1,
	XSC_QP_FLAG_TUNNEL_OFFLOADS	= 1 << 2,
	XSC_QP_FLAG_BFREG_INDEX	= 1 << 3,
	XSC_QP_FLAG_TYPE_DCT		= 1 << 4,
	XSC_QP_FLAG_TYPE_DCI		= 1 << 5,
	XSC_QP_FLAG_TIR_ALLOW_SELF_LB_UC = 1 << 6,
	XSC_QP_FLAG_TIR_ALLOW_SELF_LB_MC = 1 << 7,
	XSC_QP_FLAG_ALLOW_SCATTER_CQE	= 1 << 8,
	XSC_QP_FLAG_RAWPACKET_TSO       = 1 << 9,
	XSC_QP_FLAG_RAWPACKET_TX	= 1 << 10,
};

struct xsc_ib_alloc_ucontext_req {
	__u32	rsvd0;
	__u32	rsvd1;
};

enum xsc_user_cmds_supp_uhw {
	XSC_USER_CMDS_SUPP_UHW_QUERY_DEVICE = 1 << 0,
	XSC_USER_CMDS_SUPP_UHW_CREATE_AH    = 1 << 1,
};

struct xsc_ib_alloc_ucontext_resp {
	__u32	qp_tab_size;
	__u32	cache_line_size;
	__u16	max_sq_desc_sz;
	__u16	max_rq_desc_sz;
	__u32	max_send_wqebb;
	__u32	max_recv_wr;
	__u16	num_ports;
	__u16	reserved;
	__u64	qpm_tx_db;
	__u64	qpm_rx_db;
	__u64	cqm_next_cid_reg;
	__u64	cqm_armdb;
	__u32	send_ds_num;
	__u32	recv_ds_num;
	__u32   cmds_supp_uhw;
};

struct xsc_ib_create_qp {
	__u64	buf_addr;
	__u64	db_addr;
	__u32	sq_wqe_count;
	__u32	rq_wqe_count;
	__u32	rq_wqe_shift;
	__u32	flags;
};

struct xsc_ib_create_qp_resp {
	__u32	uuar_index;
	__u32 reserved;
};

struct xsc_ib_create_cq {
	__u64 buf_addr;
	__u64 db_addr;
	__u32	cqe_size;
};

struct xsc_ib_create_cq_resp {
	__u32	cqn;
	__u32	reserved;
};

struct xsc_ib_create_ah_resp {
	__u32	response_length;
	__u8	dmac[ETH_ALEN];
	__u8	reserved[6];
};

struct xsc_ib_alloc_pd_resp {
	__u32	pdn;
};

struct xsc_ib_tso_caps {
	__u32 max_tso; /* Maximum tso payload size in bytes */

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_UD
	 */
	__u32 supported_qpts;
};

/* RX Hash function flags */
enum xsc_rx_hash_function_flags {
	XSC_RX_HASH_FUNC_TOEPLITZ	= 1 << 0,
};

enum xsc_rdma_link_speed {
	XSC_RDMA_LINK_SPEED_2_5GB	= 1 << 0,
	XSC_RDMA_LINK_SPEED_5GB		= 1 << 1,
	XSC_RDMA_LINK_SPEED_10GB	= 1 << 3,
	XSC_RDMA_LINK_SPEED_14GB	= 1 << 4,
	XSC_RDMA_LINK_SPEED_25GB	= 1 << 5,
	XSC_RDMA_LINK_SPEED_50GB	= 1 << 6,
	XSC_RDMA_LINK_SPEED_100GB	= 1 << 7,
};

enum xsc_rdma_phys_state {
	XSC_RDMA_PHY_STATE_SLEEP	= 1,
	XSC_RDMA_PHY_STATE_POLLING,
	XSC_RDMA_PHY_STATE_DISABLED,
	XSC_RDMA_PHY_STATE_PORT_CONFIGURATION_TRAINNING,
	XSC_RDMA_PHY_STATE_LINK_UP,
	XSC_RDMA_PHY_STATE_LINK_ERROR_RECOVERY,
	XSC_RDMA_PHY_STATE_PHY_TEST,
};

/*
 * RX Hash flags, these flags allows to set which incoming packet's field should
 * participates in RX Hash. Each flag represent certain packet's field,
 * when the flag is set the field that is represented by the flag will
 * participate in RX Hash calculation.
 * Note: *IPV4 and *IPV6 flags can't be enabled together on the same QP
 * and *TCP and *UDP flags can't be enabled together on the same QP.
 */
enum xsc_rx_hash_fields {
	XSC_RX_HASH_SRC_IPV4	= 1 << 0,
	XSC_RX_HASH_DST_IPV4	= 1 << 1,
	XSC_RX_HASH_SRC_IPV6	= 1 << 2,
	XSC_RX_HASH_DST_IPV6	= 1 << 3,
	XSC_RX_HASH_SRC_PORT_TCP	= 1 << 4,
	XSC_RX_HASH_DST_PORT_TCP	= 1 << 5,
	XSC_RX_HASH_SRC_PORT_UDP	= 1 << 6,
	XSC_RX_HASH_DST_PORT_UDP	= 1 << 7,
	XSC_RX_HASH_IPSEC_SPI		= 1 << 8,
	/* Save bits for future fields */
	XSC_RX_HASH_INNER		= (1UL << 31),
};

struct xsc_ib_rss_caps {
	__aligned_u64 rx_hash_fields_mask; /* enum xsc_rx_hash_fields */
	__u8 rx_hash_function; /* enum xsc_rx_hash_function_flags */
	__u8 reserved[7];
};

enum xsc_ib_cqe_comp_res_format {
	XSC_IB_CQE_RES_FORMAT_HASH	= 1 << 0,
	XSC_IB_CQE_RES_FORMAT_CSUM	= 1 << 1,
	XSC_IB_CQE_RES_FORMAT_CSUM_STRIDX = 1 << 2,
};

struct xsc_ib_cqe_comp_caps {
	__u32 max_num;
	__u32 supported_format; /* enum xsc_ib_cqe_comp_res_format */
};

enum xsc_ib_packet_pacing_cap_flags {
	XSC_IB_PP_SUPPORT_BURST	= 1 << 0,
};

struct xsc_packet_pacing_caps {
	__u32 qp_rate_limit_min;
	__u32 qp_rate_limit_max; /* In kpbs */

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_RAW_PACKET
	 */
	__u32 supported_qpts;
	__u8  cap_flags; /* enum xsc_ib_packet_pacing_cap_flags */
	__u8  reserved[3];
};

enum xsc_ib_mpw_caps {
	MPW_RESERVED		= 1 << 0,
	XSC_IB_ALLOW_MPW	= 1 << 1,
	XSC_IB_SUPPORT_EMPW	= 1 << 2,
};

enum xsc_ib_sw_parsing_offloads {
	XSC_IB_SW_PARSING = 1 << 0,
	XSC_IB_SW_PARSING_CSUM = 1 << 1,
	XSC_IB_SW_PARSING_LSO = 1 << 2,
};

struct xsc_ib_sw_parsing_caps {
	__u32 sw_parsing_offloads; /* enum xsc_ib_sw_parsing_offloads */

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_RAW_PACKET
	 */
	__u32 supported_qpts;
};

struct xsc_ib_striding_rq_caps {
	__u32 min_single_stride_log_num_of_bytes;
	__u32 max_single_stride_log_num_of_bytes;
	__u32 min_single_wqe_log_num_of_strides;
	__u32 max_single_wqe_log_num_of_strides;

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_RAW_PACKET
	 */
	__u32 supported_qpts;
	__u32 reserved;
};

enum xsc_ib_query_dev_resp_flags {
	/* Support 128B CQE compression */
	XSC_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_COMP = 1 << 0,
	XSC_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_PAD  = 1 << 1,
};

enum xsc_ib_tunnel_offloads {
	XSC_IB_TUNNELED_OFFLOADS_VXLAN  = 1 << 0,
	XSC_IB_TUNNELED_OFFLOADS_GRE    = 1 << 1,
	XSC_IB_TUNNELED_OFFLOADS_GENEVE = 1 << 2,
	XSC_IB_TUNNELED_OFFLOADS_MPLS_GRE = 1 << 3,
	XSC_IB_TUNNELED_OFFLOADS_MPLS_UDP = 1 << 4,
};

struct xsc_ib_query_device_resp {
	__u32	comp_mask;
	__u32	response_length;
	struct	xsc_ib_tso_caps tso_caps;
	struct	xsc_ib_rss_caps rss_caps;
	struct	xsc_ib_cqe_comp_caps cqe_comp_caps;
	struct	xsc_packet_pacing_caps packet_pacing_caps;
	__u32	xsc_ib_support_multi_pkt_send_wqes;
	__u32	flags; /* Use enum xsc_ib_query_dev_resp_flags */
	struct xsc_ib_sw_parsing_caps sw_parsing_caps;
	struct xsc_ib_striding_rq_caps striding_rq_caps;
	__u32	tunnel_offloads_caps; /* enum xsc_ib_tunnel_offloads */
	__u32	reserved;
};

#endif /* XSC_IB_USER_H */
