/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_HSI_H
#define XSC_HSI_H

#include <asm/byteorder.h>

#include <linux/types.h>
#include <linux/bitops.h>
#include "common/xsc_macro.h"

#ifdef MSIX_SUPPORT
#else
#define NEED_CREATE_RX_THREAD
#endif

#define PAGE_SHIFT_4K          12
#define PAGE_SIZE_4K           (_AC(1, UL) << PAGE_SHIFT_4K)
#define PAGE_MASK_4K           (~(PAGE_SIZE_4K - 1))

#ifndef EQ_NUM_MAX
#define EQ_NUM_MAX		1024
#endif
#ifndef EQ_SIZE_MAX
#define EQ_SIZE_MAX		1024
#endif

#define XSC_RSS_INDIR_TBL_S     256
#define XSC_MAX_TSO_PAYLOAD     0x10000/*64kb*/

#define MAX_BOARD_NUM	8

#define DMA_LO_LE(x)		__cpu_to_le32(lower_32_bits(x))
#define DMA_HI_LE(x)		__cpu_to_le32(upper_32_bits(x))
#define DMA_REGPAIR_LE(x, val)	do { \
					(x).hi = DMA_HI_LE((val)); \
					(x).lo = DMA_LO_LE((val)); \
				} while (0)

#define WR_LE_16(x, val)	(x = __cpu_to_le16(val))
#define WR_LE_32(x, val)	(x = __cpu_to_le32(val))
#define WR_LE_64(x, val)	(x = __cpu_to_le64(val))
#define WR_LE_R64(x, val)	(DMA_REGPAIR_LE(x, val))
#define WR_BE_32(x, val)	(x = __cpu_to_be32(val))

#define RD_LE_16(x)		__le16_to_cpu(x)
#define RD_LE_32(x)		__le32_to_cpu(x)
#define RD_BE_32(x)		__be32_to_cpu(x)

#define WR_REG(addr, val)	mmio_write64_le(addr, val)
#define RD_REG(addr)		mmio_read64_le(addr)

#define XSC_MPT_MAP_EN		0

/* FIXME: 32-byte alignment for SW descriptors for Amber for now */
#define XSC_DESC_ALIGNMENT	32

/* each ds holds one fragment in skb */
#define XSC_MAX_RX_FRAGS        4
#define XSC_RX_FRAG_SZ_ORDER    0
#define XSC_RX_FRAG_SZ          (PAGE_SIZE << XSC_RX_FRAG_SZ_ORDER)
#define DEFAULT_FRAG_SIZE       (2048)

/* message opcode */
enum {
	XSC_MSG_OPCODE_SEND		= 0,
	XSC_MSG_OPCODE_RDMA_WRITE	= 1,
	XSC_MSG_OPCODE_RDMA_READ	= 2,
	XSC_MSG_OPCODE_MAD		= 3,
	XSC_MSG_OPCODE_RDMA_ACK		= 4,
	XSC_MSG_OPCODE_RDMA_ACK_READ	= 5,
	XSC_MSG_OPCODE_RDMA_CNP		= 6,
	XSC_MSG_OPCODE_RAW		= 7,
	XSC_MSG_OPCODE_VIRTIO_NET	= 8,
	XSC_MSG_OPCODE_VIRTIO_BLK	= 9,
	XSC_MSG_OPCODE_RAW_TPE		= 10,
	XSC_MSG_OPCODE_INIT_QP_REQ	= 11,
	XSC_MSG_OPCODE_INIT_QP_RSP	= 12,
	XSC_MSG_OPCODE_INIT_PATH_REQ	= 13,
	XSC_MSG_OPCODE_INIT_PATH_RSP	= 14,
};

/* TODO: sw cqe opcode*/
enum {
	XSC_OPCODE_RDMA_REQ_SEND	= 0,
	XSC_OPCODE_RDMA_REQ_SEND_IMMDT	= 1,
	XSC_OPCODE_RDMA_RSP_RECV	= 2,
	XSC_OPCODE_RDMA_RSP_RECV_IMMDT	= 3,
	XSC_OPCODE_RDMA_REQ_WRITE	= 4,
	XSC_OPCODE_RDMA_REQ_WRITE_IMMDT	= 5,
	XSC_OPCODE_RDMA_RSP_WRITE_IMMDT	= 6,
	XSC_OPCODE_RDMA_REQ_READ	= 7,
	XSC_OPCODE_RDMA_REQ_ERROR	= 8,
	XSC_OPCODE_RDMA_RSP_ERROR	= 9,
	XSC_OPCODE_RDMA_CQE_ERROR	= 10,
	XSC_OPCODE_RDMA_MAD_REQ_SEND,
	XSC_OPCODE_RDMA_MAD_RSP_RECV,
};

enum {
	XSC_REQ		= 0,
	XSC_RSP		= 1,
};

enum {
	XSC_WITHOUT_IMMDT	= 0,
	XSC_WITH_IMMDT		= 1,
};

enum {
	XSC_ERR_CODE_NAK_RETRY			= 0x40,
	XSC_ERR_CODE_NAK_OPCODE			= 0x41,
	XSC_ERR_CODE_NAK_MR			= 0x42,
	XSC_ERR_CODE_NAK_OPERATION		= 0x43,
	XSC_ERR_CODE_NAK_RNR			= 0x44,
	XSC_ERR_CODE_LOCAL_MR			= 0x45,
	XSC_ERR_CODE_LOCAL_LEN			= 0x46,
	XSC_ERR_CODE_LOCAL_OPCODE		= 0x47,
	XSC_ERR_CODE_CQ_OVER_FLOW		= 0x48,
	XSC_ERR_CODE_STRG_ACC_GEN_CQE		= 0x4c,
	XSC_ERR_CODE_CQE_ACC			= 0x4d,
	XSC_ERR_CODE_FLUSH			= 0x4e,
	XSC_ERR_CODE_MALF_WQE_HOST		= 0x50,
	XSC_ERR_CODE_MALF_WQE_INFO		= 0x51,
	XSC_ERR_CODE_MR_NON_NAK			= 0x52,
	XSC_ERR_CODE_OPCODE_GEN_CQE		= 0x61,
	XSC_ERR_CODE_MANY_READ			= 0x62,
	XSC_ERR_CODE_LEN_GEN_CQE		= 0x63,
	XSC_ERR_CODE_MR				= 0x65,
	XSC_ERR_CODE_MR_GEN_CQE			= 0x66,
	XSC_ERR_CODE_OPERATION			= 0x67,
	XSC_ERR_CODE_MALF_WQE_INFO_GEN_NAK	= 0x68,
};

/* QP type */
enum {
	XSC_QUEUE_TYPE_RDMA_RC		= 0,
	XSC_QUEUE_TYPE_RDMA_MAD		= 1,
	XSC_QUEUE_TYPE_RAW		= 2,
	XSC_QUEUE_TYPE_VIRTIO_NET	= 3,
	XSC_QUEUE_TYPE_VIRTIO_BLK	= 4,
	XSC_QUEUE_TYPE_RAW_TPE		= 5,
	XSC_QUEUE_TYPE_RAW_TSO		= 6,
	XSC_QUEUE_TYPE_RAW_TX		= 7,
	XSC_QUEUE_TYPE_INVALID		= 0xFF,
};

/* CQ type */
enum {
	XSC_CQ_TYPE_NORMAL		= 0,
	XSC_CQ_TYPE_VIRTIO		= 1,
};

enum xsc_qp_state {
	XSC_QP_STATE_RST			= 0,
	XSC_QP_STATE_INIT			= 1,
	XSC_QP_STATE_RTR			= 2,
	XSC_QP_STATE_RTS			= 3,
	XSC_QP_STATE_SQER			= 4,
	XSC_QP_STATE_SQD			= 5,
	XSC_QP_STATE_ERR			= 6,
	XSC_QP_STATE_SQ_DRAINING		= 7,
	XSC_QP_STATE_SUSPENDED			= 9,
	XSC_QP_NUM_STATE
};

enum {
	XSC_SEND_SEG_MAX		= 32,
	XSC_BASE_WQE_SHIFT		= 4,
	XSC_SEND_SEG_NUM		= 4,
	XSC_SEND_WQE_SHIFT		= 6,
	XSC_CTRL_SEG_NUM		= 1,
	XSC_RADDR_SEG_NUM		= 1,
};

enum {
	XSC_RECV_SEG_MAX		= 4,
	XSC_RECV_SEG_NUM		= 1,
	XSC_RECV_WQE_SHIFT		= 4,
};

enum {
	XSC_INLINE_SIZE_MAX		= 15,
};

/* Descriptors that are allocated by SW and accessed by HW, 32-byte aligned
 * this is to keep descriptor structures packed
 */
struct regpair {
	__le32	lo;
	__le32	hi;
};

struct xsc_cqe {
	union {
		u8		msg_opcode;
		struct {
			u8		error_code:7;
			u8		is_error:1;
		};
	};
	__le32		qp_id:15;
	u8		rsv1:1;
	u8		se:1;
	u8		has_pph:1;
	u8		type:1;
	u8		with_immdt:1;
	u8		csum_err:4;
	__le32		imm_data;
	__le32		msg_len;
	__le32		vni;
	__le64		ts:48;
	__le16		wqe_id;
	__le16		rsv[3];
	__le16		rsv2:15;
	u8		owner:1;
};

/* CQ doorbell */
union xsc_cq_doorbell {
	struct{
	u32	cq_next_cid:16;
	u32	cq_id:15;
	u32	arm:1;
	};
	u32	val;
};

/* EQE TBD */
struct xsc_eqe {
	u8 type;
	u8 sub_type;
	__le16 queue_id:15;
	u8 rsv1:1;
	u8 err_code;
	u8 rsvd[2];
	u8 rsv2:7;
	u8 owner:1;
};

/* EQ doorbell */
union xsc_eq_doorbell {
	struct{
		u32 eq_next_cid : 11;
		u32 eq_id : 11;
		u32 arm : 1;
	};
	u32 val;
};

/*for beryl tcam table .begin*/
#define XSC_TBM_PCT_DW_SIZE_MAX 20
#define XSC_TCAM_REG_ADDR_STRIDE 4

enum xsc_tbm_tcam_type {
	XSC_TBM_TCAM_PCT = 0,
	XSC_TBM_TCAM_PRS_STAGE0,
	XSC_TBM_TCAM_PRS_STAGE1,
	XSC_TBM_TCAM_PRS_STAGE2,
};

enum xsc_tbm_tcam_oper {
	XSC_TCAM_OP_X_WRITE = 0,
	XSC_TCAM_OP_Y_WRITE,
	XSC_TCAM_OP_ACTION_WRITE,
	XSC_TCAM_OP_X_READ,
	XSC_TCAM_OP_Y_READ,
	XSC_TCAM_OP_ACTION_READ,
	XSC_TCAM_OP_TCAM_FLUSH,
	XSC_TCAM_OP_ACTION_FLUSH,
	XSC_TCAM_OP_CPU_SEARCH,
	XSC_TCAM_OP_LONG_X_WRT,
	XSC_TCAM_OP_LONG_Y_WRT
};

enum xsc_tbm_prs_stage_encode {
	XSC_PRS_STAGE0_HDR_TYPE_NONE	= 0x00,
	XSC_PRS_STAGE0_HDR_TYPE_ETH0	= 0x01,
	XSC_PRS_STAGE1_HDR_TYPE_NONE	= 0x10,
	XSC_PRS_STAGE1_HDR_TYPE_RSV	= 0x11,
	XSC_PRS_STAGE1_HDR_TYPE_IPV4	= 0x12,
	XSC_PRS_STAGE1_HDR_TYPE_IPV6	= 0x13,
	XSC_PRS_STAGE2_HDR_TYPE_NONE	= 0x20,
	XSC_PRS_STAGE2_HDR_TYPE_TCP	= 0x21,
	XSC_PRS_STAGE2_HDR_TYPE_UDP	= 0x22,
	XSC_PRS_STAGE2_HDR_TYPE_GRE	= 0x23,
	XSC_PRS_STAGE2_HDR_TYPE_RSV	= 0x24,
	XSC_PRS_STAGE2_HDR_TYPE_IFA_TCP	= 0x25,
	XSC_PRS_STAGE2_HDR_TYPE_IFA_UDP	= 0x26,
	XSC_PRS_STAGE2_HDR_TYPE_IFA_GRE	= 0x27,
	XSC_PRS_STAGE6_HDR_TYPE_ICMP	= 0x63,
	XSC_PRS_STAGEX_HDR_TYPE_PAYLOAD	= 0xa0,
	XSC_PRS_STAGEX_HDR_TYPE_BTH	= 0xa1,
};

enum xsc_tbm_prs_eth_hdr_type_encode {
	ETH_HDR_TYPE_MAC0	= 0x0,
	ETH_HDR_TYPE_MAC0_VLANA = 0x2,
	ETH_HDR_TYPE_MAC0_VLANA_VLANB = 0x3,
};

enum xsc_tbm_pct_pkttype {
	XSC_PCT_RDMA_NORMAL	= 0x0,
	XSC_PCT_RDMA_CNP,
	XSC_PCT_RDMA_MAD,
	XSC_PCT_RAW,
	XSC_PCT_RAW_TPE,
	XSC_PCT_VIRTIO_NET_TO_HOST,
	XSC_PCT_SOC_WITH_PPH,
};

enum xsc_tbm_pct_inport {
	XSC_PCT_PORT_NIF0	= 0x0,
	XSC_PCT_PORT_NIF1,
	XSC_PCT_PORT_PCIE0_PF0,
	XSC_PCT_PORT_PCIE0_PF1,
	XSC_PCT_PORT_PCIE1_PF0,
};

/*for beryl tcam table .end*/

/* Size of WQE */
#define XSC_SEND_WQE_SIZE BIT(XSC_SEND_WQE_SHIFT)
#define XSC_RECV_WQE_SIZE BIT(XSC_RECV_WQE_SHIFT)

union xsc_db_data {
	struct {
		__le32 sq_next_pid:16;
		__le32 sqn:15;
		__le32:1;
	};
	struct {
		__le32 rq_next_pid:13;
		__le32 rqn:15;
		__le32:4;
	};
	struct {
		__le32 cq_next_cid:16;
		__le32 cqn:15;
		__le32 solicited:1;

	};
	__le32 raw_data;
};

#define XSC_BROADCASTID_MAX		2
#define XSC_TBM_BOMT_DESTINFO_SHIFT	(XSC_BROADCASTID_MAX / 2)

/* Doorbell registers */

enum {
	XSC_EQ_VEC_ASYNC		= 0,
	XSC_VEC_CMD			= 1,
	XSC_VEC_CMD_EVENT		= 2,
	XSC_DMA_READ_DONE_VEC		= 3,
	XSC_EQ_VEC_COMP_BASE,
};

struct rxe_bth {
	u8			opcode;
	u8			flags;
	__be16			pkey;
	__be32			qpn;
	__be32			apsn;
};

struct rxe_deth {
	__be32			qkey;
	__be32			sqp;
};

#endif /* XSC_HSI_H */
