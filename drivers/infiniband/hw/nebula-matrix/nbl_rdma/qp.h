/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_QP_H
#define NBL_IB_QP_H

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>
#include "main.h"
#include "pd.h"
#include "cq.h"

/*when user open direct wqe ,need to flush sqe/rqec, default is 0*/
#define NBL_DIRECT_WQE_EN 0

#define NBL_QP_SPORT_L3L4_HASH_MAX 48
#define NBL_QP_GID_V4_BEGIN 12

#define NBL_SQRQ_2M_PAGE_NUM 1
#define NBL_IO_POST_DB_MODE 1
#define IB_MTU_INVALID_NBL 0xff /* must > IB_MTU_4096 = 5 */
enum nbl_mtu {
	NBL_MTU_256 = 0,
	NBL_MTU_512 = 1,
	NBL_MTU_1024 = 2,
	NBL_MTU_2048 = 3,
	NBL_MTU_4096 = 4,
	NBL_MTU_INVALID = 5,
};
/******QPC*******/
/*RAM0 0-7 BYTE*/
#define NBL_QPC_P_KEY GENMASK_ULL(15, 0)
#define NBL_QPC_QPN GENMASK_ULL(39, 16)
#define NBL_QPC_VFID GENMASK_ULL(48, 40)
#define NBL_QPC_HOST_ID GENMASK_ULL(51, 49)
#define NBL_QPC_STAT_ID GENMASK_ULL(59, 52)
#define NBL_QPC_TVER GENMASK_ULL(61, 60)
#define NBL_QPC_MIG BIT_ULL(62)
#define NBL_QPC_VLD BIT_ULL(63)

/*RAM0 8-15 BYTE*/
#define NBL_QPC_IRQ_BA GENMASK_ULL(51, 0)
#define NBL_QPC_PMTU GENMASK_ULL(55, 52)
#define NBL_QPC_QP_STATE GENMASK_ULL(59, 56)
#define NBL_QPC_SERVICE_TYPE GENMASK_ULL(63, 60)

/*RAM0 16-23 BYTE*/
#define NBL_QPC_LOCAL_RNR_TIMER_VALUE GENMASK_ULL(4, 0)
#define NBL_QPC_ATOMIC_EN  BIT_ULL(5)
#define NBL_QPC_RQ_PM GENMASK_ULL(7, 6)
#define NBL_QPC_SQ_PM GENMASK_ULL(9, 8)
#define NBL_QPC_DMA_LEN_MAX GENMASK_ULL(14, 10)
#define NBL_QPC_RQ_WQE_SIZE BIT_ULL(15)
#define NBL_QPC_RQ_SIZE GENMASK_ULL(19, 16)
#define NBL_QPC_SPORT_ID GENMASK_ULL(33, 24)
#define NBL_QPC_CREDIT_EN BIT_ULL(23)
#define NBL_QPC_CC_PKT_NUM_EN BIT_ULL(22)
#define NBL_QPC_PD_IDX GENMASK_ULL(59, 36)
#define NBL_QPC_SCH_NET_TC GENMASK_ULL(62, 60)
#define NBL_QPC_QP1_MODE BIT_ULL(63)

/*RAM0 24-31 BYTE*/
#define NBL_QPC_SWRQPI_TH GENMASK_ULL(63, 61)
#define NBL_QPC_CC_MODE GENMASK_ULL(60, 59)
#define NBL_QPC_ATOMIC_NO_FENCE BIT_ULL(58)
#define NBL_QPC_WQE_PREFETCH_EN BIT_ULL(57)
#define NBL_QPC_WQE_CAP GENMASK_ULL(56, 52)
#define NBL_QPC_ORQ_BA GENMASK_ULL(51, 0)

/*RAM0 32-39 BYTE*/
#define NBL_QPC_VLAN_TAG GENMASK_ULL(63, 48)
#define NBL_QPC_DFT_RAQE_CAP GENMASK_ULL(44, 40)
#define NBL_QPC_RQ_PD_BA_H GENMASK_ULL(39, 0)

/*RAM0 40 -47 BYTE */
#define NBL_QPC_RQ_PD_BA_L GENMASK_ULL(63, 52)
#define NBL_QPC_CC_TARGETWIN_MIN GENMASK_ULL(51, 32)
#define NBL_QPC_UD_QKEY GENMASK_ULL(31, 0)

/*RAM0 48 -55 BYTE*/
#define NBL_QPC_CC_OAM_ACK_NET_TC GENMASK_ULL(2, 0)
#define NBL_QPC_CC_OAM_ACK_TC_EN BIT_ULL(3)
#define NBL_QPC_CC_SENDACK_BLK_CNT_TH GENMASK_ULL(11, 4)
#define NBL_QPC_CC_RTTMINTH_ADD_MULT GENMASK_ULL(13, 12)
#define NBL_QPC_RTO_TIMER_VALUE GENMASK_ULL(19, 15)
#define NBL_QPC_CC_TXP_SENDREQ_DB_TH GENMASK_ULL(27, 20)
#define NBL_QPC_FRMR_EN BIT_ULL(14)
#define NBL_QPC_IRQ_SIZE GENMASK_ULL(30, 28)
#define NBL_QPC_TX_RETRY_TH GENMASK_ULL(35, 33)
#define NBL_QPC_DEST_QPN GENMASK_ULL(59, 36)
#define NBL_QPC_SQ_SIZE GENMASK_ULL(63, 60)

/*RAN0 56-63 BYTE*/
#define NBL_QPC_SQ_PD_BA GENMASK_ULL(51, 0)
#define NBL_QPC_ACKREQ_TH GENMASK_ULL(59, 52)
#define NBL_QPC_OAM_REQ_NET_TC GENMASK_ULL(62, 60)
#define NBL_QPC_OAM_REQ_TC_EN BIT_ULL(63)

/*RAM0 64-71 BYTE*/
#define NBL_QPC_UDP_SPORT GENMASK_ULL(15, 0)
#define NBL_QPC_FLOW_LABLE GENMASK_ULL(35, 16)
#define NBL_QPC_SRC_ADDR_IDX GENMASK_ULL(43, 36)
#define NBL_QPC_VLAN BIT_ULL(46)
#define NBL_QPC_IPV4 BIT_ULL(47)
#define NBL_QPC_DPORT_ID GENMASK_ULL(57, 48)
#define NBL_QPC_DPORT GENMASK_ULL(60, 58)
#define NBL_QPC_FWD GENMASK_ULL(62, 61)
#define NBL_QPC_RSS_LAG_EN BIT_ULL(63)

/*RAM0 72-79 BYTE*/
#define NBL_QPC_HOP_LIMIT GENMASK_ULL(7, 0)
#define NBL_QPC_TCLASS GENMASK_ULL(15, 8)
#define NBL_QPC_DMAC GENMASK_ULL(63, 16)

/*RAM0 80-87 BYTE*/
/*RAM0 88-95 BYTE*/
#define NBL_QPC_DSIP_TOTAL_LEN 16

/*RAM0 96-103 BYTE*/
#define NBL_QPC_UNAQ_BA GENMASK_ULL(51, 0)

/*RAM0 104 - 111 BYTE*/
#define NBL_QPC_SHADOW_AREA_BA GENMASK_ULL(54, 0)
#define NBL_QPC_SQ_CE_EN BIT_ULL(55)

/*RAM0 112-119 BYTE*/
#define NBL_QPC_RQ_CQN GENMASK_ULL(23, 0)
#define NBL_QPC_SQ_CQN GENMASK_ULL(47, 24)
#define NBL_QPC_CEAQ_RQ_TH GENMASK_ULL(51, 48)
#define NBL_QPC_CEAQ_SQ_TH GENMASK_ULL(55, 52)

/*RAM0 120-127 BYTE*/
#define NBL_QPC_QP_COMP_CTX GENMASK_ULL(63, 0)

/*CQP*/
#define NBL_CQP_NEXT_QP_STATE GENMASK_ULL(43, 40)
#define NBL_CQP_QP_ID GENMASK_ULL(23, 0)

#define NBL_CQP_QP_CONTEXT_ADDRESS GENMASK_ULL(63, 0)

/*HW QPC*/
#define NBL_QPC_HW_SQ_PI GENMASK_ULL(14, 0)
#define NBL_QPC_HW_SQ_CI GENMASK_ULL(14, 0)
#define NBL_QPC_HW_RQ_PI GENMASK_ULL(30, 16)
#define NBL_QPC_HW_RQ_CI GENMASK_ULL(30, 16)
#define NBL_QPC_HW_RAQ_CI GENMASK_ULL(62, 56)
#define NBL_QPC_HW_RAQ_PI GENMASK_ULL(6, 0)

#define NBL_QPC_RNR_RETRY_NUM GENMASK_ULL(63, 60)
#define NBL_QPC_RNR_RETRY_TH GENMASK_ULL(59, 56)

#define NBL_QPC_IRQ_BA_CLONE GENMASK_ULL(51, 0)
#define NBL_QPC_SEQ_NUM GENMASK_ULL(23, 8)
#define NBL_QPC_RAQ_BA GENMASK_ULL(51, 0)

#define NBL_QPC_TXP_SQ_CUR_PD_PA GENMASK_ULL(51, 0)
#define NBL_QPC_TXP_SQ_CUR_PD_PA_VLD  BIT_ULL(52)
#define NBL_QPC_TXP_SQ_NXT_PD_PA_VLD  BIT_ULL(52)
#define NBL_QPC_TXP_SQ_NXT_PD_PA GENMASK_ULL(51, 0)

#define NBL_QPC_RXP_RQ_NXT_PD_PA_VLD  BIT_ULL(36)
#define NBL_QPC_RXP_RQ_NXT_PD_PA_H GENMASK_ULL(35, 0)
#define NBL_QPC_RXP_RQ_NXT_PD_PA_L GENMASK_ULL(63, 48)

#define NBL_QPC_RXP_RQ_CUR_PD_PA_VLD  BIT_ULL(44)
#define NBL_QPC_RXP_RQ_CUR_PD_PA_H GENMASK_ULL(43, 0)
#define NBL_QPC_RXP_RQ_CUR_PD_PA_L GENMASK_ULL(63, 56)

#define NBL_QPC_RXP_REQ_PRE_OPCODE  GENMASK_ULL(31, 24)
#define NBL_QPC_RXP_EPSN  GENMASK_ULL(23, 0)
#define NBL_QPC_SQ_NEXT_WQE_CAP GENMASK_ULL(28, 24)
#define NBL_QPC_PSN_MAX  GENMASK_ULL(63, 40)
#define NBL_QPC_RX_RESP_PRE_OPCODE  GENMASK_ULL(63, 56)
#define NBL_QPC_RAQ_NEXT_WQE_CAP GENMASK_ULL(44, 40)
#define NBL_QPC_RETRY_CNT GENMASK_ULL(2, 0)

/* RAM1 128-135 BYTE QCN */
#define NBL_QPC_QCN_REMAIN_TRANS_BITS GENMASK_ULL(63, 46)
/* RAM1 136-143 BYTE QCN */
#define NBL_QPC_QCN_SENDPKT_TARGETWIN GENMASK_ULL(63, 54)
/* RAM1 144-151 BYTE QCN */
#define NBL_QPC_QCN_FIRST_RECDB_FLAG BIT_ULL(62)
/* RAM1 152-159 BYTE QCN */
#define NBL_QPC_QCN_LIMIT_RP GENMASK_ULL(45, 28)
#define NBL_QPC_QCN_TARGET_RP GENMASK_ULL(27, 10)
#define NBL_QPC_QCN_MAIN_STATUS GENMASK_ULL(9, 8)
/* RAM2 288-319 BYTE */
/* CC status fields */
/* BASE 0x138(312) */
#define NBL_QPC_CC_RECREQ_SENDTX_BLK_CNT		GENMASK_ULL(63, 44)
#define NBL_QPC_CC_WINM_BUSY					BIT_ULL(43)
#define NBL_QPC_CC_TA_SN_PHASE_CHG				BIT_ULL(42)
#define NBL_QPC_CC_TA_SN						GENMASK_ULL(41, 36)
#define NBL_QPC_CC_RECACK_LASTWINM_BLK_CNT		GENMASK_ULL(35, 16)
#define NBL_QPC_CC_RECACK_EPSN					GENMASK_ULL(15, 0)
/* BASE 0x130(304) */
#define NBL_QPC_CC_TIME_LASTTA					GENMASK_ULL(63, 32)
#define NBL_QPC_CCQCN_REQCARRY_SENDCNP_TIME		GENMASK_ULL(31, 0)
/* BASE 0x128(296) */
#define NBL_QPC_QCN_RECECN_FLAG					BIT_ULL(63)
#define NBL_QPC_CC_MORE_RTTMINTH_FLAG			BIT_ULL(62)
#define NBL_QPC_CC_LESS_RTTMINTH_FLAG			BIT_ULL(61)
#define NBL_QPC_CC_RECACK_RTTFLAG				BIT_ULL(60)
#define NBL_QPC_CC_SENDACK_MID_BLK_CNT			GENMASK_ULL(59, 52)
#define NBL_QPC_CC_RECREQ_BLK_CNT				GENMASK_ULL(51, 32)
#define NBL_QPC_CC_RECREQ_MID_BLK_CNT			GENMASK_ULL(31, 12)
#define NBL_QPC_CC_RECREQ_EPSN					GENMASK_ULL(11, 0)
/* BASE 0x120(288) */
#define NBL_QPC_CC_RTT_MEASURE					GENMASK_ULL(59, 48)
#define NBL_QPC_CC_RTTMIN						GENMASK_ULL(31, 16)
#define NBL_QPC_CC_OAMACK_NEXT_PSN				GENMASK_ULL(15, 0)

/* RAM3 400-407 BYTE CC */
/* BASE 0x198(408) */
#define NBL_QPC_CC_RTTM_BUSY					BIT_ULL(40)
#define NBL_QPC_CC_RECACK_RECTX_BLK_CNT			GENMASK_ULL(39, 20)
#define NBL_QPC_CC_TARGETWIN					GENMASK_ULL(19, 0)
/* BASE 0x190(400) */
#define NBL_QPC_CC_RTTM_PSNTS					GENMASK_ULL(35, 24)
#define NBL_QPC_CC_TXP_SENDPLD_BLK_CNT			GENMASK_ULL(19, 0)

/*BASE 0x1D8(472)*/
#define NBL_FMR_NOFENCE_EN						BIT_ULL(63)

#define NBL_OPCODE_NOP 0xF
#define NBL_OPCODE_SEND 0x1
#define NBL_OPCODE_SEND_WITH_IMM 0x2
#define NBL_OPCODE_SEND_WITH_INV 0x3
#define NBL_OPCODE_READ 0x4
#define NBL_OPCODE_WRITE 0x5
#define NBL_OPCODE_WRITE_WITH_IMM 0x6
#define NBL_OPCODE_ATOMIC_CMP_AND_SWP 0x7
#define NBL_OPCODE_ATOMIC_FETCH_AND_ADD 0x8
#define NBL_OPCODE_BIND_MW 0x9
#define NBL_OPCODE_LOCAL_INV 0xA
#define NBL_OPCODE_RQ_WQE 0xE
#define NBL_OPCODE_FAST_MR 0xB

#define NBL_OPCODE_RECV 0x3e /* used by cqe handle */
#define NBL_OPCODE_RECV_IMM 0x3f /* used by cqe handle */

#define NBL_GET_WR_SIZE(wr_size)						\
	((wr_size < NBL_MIN_WR_SIZE) ? NBL_MIN_WR_SIZE : wr_size)
#define NBL_RING_USED_QUANTA(_ring)                                            \
	((((_ring).head + (_ring).size - (_ring).tail) % (_ring).size))
#define NBL_RING_FULL_ERR(_ring, count)                                        \
	((NBL_RING_USED_QUANTA(_ring) == ((_ring).size - count)))
#define NBL_RING_MOVE_HEAD_BY_COUNT(_ring, count, retcode)                     \
	{                                                                      \
		register u32 size;                                             \
		size = (_ring).size;                                           \
		if (!NBL_RING_FULL_ERR(_ring, count)) {                        \
			(_ring).head = ((_ring).head + count) % size;          \
			(retcode) = 0;                                         \
		} else {                                                       \
			(retcode) = -1;                                        \
		}                                                              \
	}
#define NBL_RING_CURRENT_HEAD(_ring) ((_ring).head)
#define NBL_ATOMIC_RING_MOVE_HEAD_BY_COUNT(_ring, index, count, retcode)       \
	{                                                                      \
		index = NBL_RING_CURRENT_HEAD(_ring);                          \
		NBL_RING_MOVE_HEAD_BY_COUNT(_ring, count, retcode);            \
	}
#define NBL_SQ_RING_MOVE_HEAD_BY_COUNT(_ring, _count)                          \
	(_ring).head = ((_ring).head + (_count)) % (_ring).size
#define NBL_RING_EMPTY(_ring)		\
	(((_ring).head) == ((_ring).tail))
#define NBL_MIN_WQE_SIZE 64
#define NBL_MAX_WQE_SIZE 128
#define MIN_WR_SGE 2
#define NBL_WQE_2nd_VLD_SHIFT 76
#define NBL_WQE_SIZE 8
#define NBL_WQE_CTRL_SIZE 16
#define NBL_WQE_RSV_SIZE 16
#define NBL_WQE_DATA_SIZE 16
#define NBL_RQ_WQE_CTRL_VALID (1 << 7)
#define NBL_RE_WQE_CTRL_DATA_COUNT_SHIFT 28
#define NBL_WQE_MIN_QUANTA 1
#define NBL_WQE_RADDR_SIZE 16
#define NBL_WQE_ATOMIC_SIZE 16
#define NBL_WQE_DATAGRAM_SIZE 48
#define NBL_WQE_LOCAL_OPERATE_SIZE 128
#define NBL_WQE_FAST_MR_SIZE 128
#define NBL_MIN_RQ_WQE_SIZE 64
#define NBL_QPC_MIN_RQ_WQE_SIZE 0
#define NBL_MAX_RQ_WQE_SIZE 128
#define NBL_QPC_MAX_RQ_WQE_SIZE 1
#define NBL_MIN_SQ_SIZE (1 << 15)
#define NBL_MIN_WR_SIZE 256
#define NBL_QP_QUEUE_ALIGN_SIZE 256
#define NBL_WR_SQ_QUANTA_SIZE 2 /* the max quanta size of one wr sq */
#define NBL_WQE_CTRL_FENCE 2
#define NBL_WQE_CTRL_STRONG_ORD_FENCE 3

#define NBL_WQE_CTRL_VALID (1 << 7)
#define NBL_WQE_CTRL_DATA_SIZE_SHIFT 0x4
#define NBL_WQE_CTRL_QPN_SHIFT 0x8
#define NBL_QP_DB_RAQ_FLUSH 0x1C
#define NBL_QP_DB_TC 0x1D
#define NBL_QP_CTX_SIZE 0x200
#define NBL_QP_SHADOW_OFFST 0x1E0
#define NBL_QP_SHADOW_SIZE 0x20
#define NBL_DEFAULT_PKEY 0xFFFF
#define NBL_DEFAULT_SWRQPI_TH 1
#define NBL_MAX_SEQ_NUM 0xFFFF
#define NBL_UNAQ_SIZE 0x1000 /*4KB*/
#define NBL_IRQ_SIZE 0x1000 /*4KB*/
#define NBL_ORQ_SIZE 0x1000 /*4KB*/
#define NBL_RAQ_SIZE 0x1000  /*4KB*/
#define NBL_DMA_LEN_MAX 0x20
#define NBL_DEFAULT_ACKREQ_TH 64
#define NBL_DEFAULT_CEAQ_SQ_TH 0x6
#define NBL_DEFAULT_CEAQ_RQ_TH 0x6
#define NBL_DEFAULT_FWD 0x3    /*LEONIS fwd= 3 specify fwd*/
#define NBL_NORMAL_FWD 1
#define NBL_DEFAULT_DPORT 0
#define NBL_DEFAULT_DPORT_ID 0
#define NBL_DEFAULT_RSS_LAG_EN 0
#define NBL_DEFAULT_TUNNEL_EN 0
#define NBL_DEFAULT_TVER 0
#define NBL_DEFAULT_MIG 0
#define NBL_DEFAULT_SQ_CE_EN 0
#define NBL_DEFAULT_RXP_REQ_PRE_OPCODE 4
#define NBL_DEFAULT_RX_RESP_PRE_OPCODE 0x10
#define NBL_DEFAULT_RNR_RETRY_TH 0x6
#define NBL_DEFAULT_RNR_RETRY_NUM 0x6
#define NBL_DEFAULT_WQE_CAP 0x8
#define NBL_DEFAULT_WQE_PREFETCH 0
#define NBL_DEFAULT_RAQ_WQE_CAP 8
#define NBL_DEFAULT_RNR_TIMER 0xD /*960 us*/
#define NBL_DEFAULT_RTO_TIMER 0xC /*16777 us*/
#define NBL_RTO_ARRY_MAX_SIZE 0x20
#define NBL_RTO_MAX_VALUE 0x1F
#define NBL_QP_INVALD_ERRCODE 0xFF
#define NBL_DEFAULT_BATCH_WQE_TH 8
/*TODO */
#define NBL_DEFAULT_SPORT_ID 0
#define NBL_DEFAULT_VLAN_TAG 0

#define NBL_QPC_SHADOW_AREA_HW_DROP_DB_CI GENMASK_ULL(46, 32)
#define NBL_QPC_SHADOW_AREA_HW_SEQ_NUM GENMASK_ULL(63, 48)
#define NBL_QPC_SHADOW_AREA_HW_DROP_DB_CI_PHASE BIT_ULL(47)
#define NBL_QPC_SHADOW_AREA_SW_SQ_PI GENMASK_ULL(14, 0)
#define NBL_QPC_SHADOW_AREA_SW_SQ_PI_PHASE BIT_ULL(15)

#define NBL_QPC_SHADOW_AREA_SW_RQ_PI GENMASK_ULL(14, 0)
#define NBL_QPC_SHADOW_AREA_SW_RQ_PI_PHASE BIT_ULL(15)
#define NBL_QPC_SHADOW_AREA_HW_SEQ_NUM GENMASK_ULL(63, 48)
#define NBL_QPC_SHADOW_AREA_SW_RQ_PI_LOAD_FLAG BIT_ULL(0)
#define NBL_QPC_SHADOW_HIGH_TEMP_ALARM_FLAG BIT_ULL(63)
#define NBL_QPC_SHADOW_ENABLE_RDMA_DUMP_FLAG BIT_ULL(62)
#define NBL_QP_DB_TC 0x1D

/* UD WQE SEG field */
#define NBL_QP_WQE_UD_IPV4 0x1F
#define NBL_AH_VLAN_EN_SHIFT 1
#define NBL_QP_WQE_UD_VLAN 0x1E
#define NBL_QP_WQE_UD_SRC_ADDR_IDX 0x14
#define NBL_QP_WQE_UD_RSS_LAG_EN 0x10
#define NBL_QP_WQE_UD_TUNNEL_EN 0xF
#define NBL_QP_WQE_UD_FWD 0xD
#define NBL_QP_WQE_UD_DPORT 0xA

/* RQ DB*/
#define NBL_RQ_DB_QPN GENMASK_ULL(55, 32)
#define NBL_RQ_DB_PI GENMASK_ULL(14, 0)
#define NBL_RQ_DB_PI_PHASE BIT_ULL(15)
/* SQ WQE CTRL*/
#define NBL_SQ_WQE_VLD BIT_ULL(31)
#define NBL_SQ_WQE_FENCE GENMASK_ULL(30, 28)
#define NBL_SQ_WQE_CE BIT_ULL(27)
#define NBL_SQ_WQE_SE BIT_ULL(26)
#define NBL_SQ_WQE_INLINE BIT_ULL(25)
#define NBL_SQ_WQE_IMM BIT_ULL(24)
#define NBL_SQ_WQE_IDX_PHASE BIT_ULL(23)
#define NBL_SQ_WQE_IDX GENMASK_ULL(22, 8)
#define NBL_SQ_WQE_OPCODE GENMASK_ULL(7, 0)

/* SQ DB*/
#define NBL_SQ_DB_QPN GENMASK_ULL(23, 0)
#define NBL_SQ_DB_TC GENMASK_ULL(31, 29)
/*  WQE SGE*/
#define NBL_SQ_WQE_SGE_LEN GENMASK_ULL(30, 0)
#define NBL_SQ_WQE_SGE_VLD BIT_ULL(31)
#define NBL_WQE_ADDR_BIT_OFFSET 63
#define NBL_WQE_DMA_LEN GENMASK_ULL(30, 0)
#define NBL_WQE_DMA_ADDR_BIT BIT_ULL(31)
#define NBL_WQE_DMA_ADDR GENMASK_ULL(62, 0)
#define NBL_WQE_DMA_ADDR_WQE_VLD BIT_ULL(63)

#define NBL_QP_FLUSH_AE_EXP_NUM 2 /* flush wqe expect 2 ae(sq & rq) come */
/* QP number reserved */
#define NBL_QP_NUM_FOR_RSV 0 /* qp num 0 is reserve */
#define NBL_QP_NUM_FOR_CM 1  /* qp num 1 is cm use */

enum ecn_mask {
	ECN_NON_ECT = 0,
	ECN_ECT_0 = 1,
	ECN_ECT_1 = 2,
	ECN_CE = 3,
};

static const u32 nbl_opcode[] = {
	[IB_WR_SEND] = NBL_OPCODE_SEND,
	[IB_WR_SEND_WITH_IMM] = NBL_OPCODE_SEND_WITH_IMM,
	[IB_WR_SEND_WITH_INV] = NBL_OPCODE_SEND_WITH_INV,
	[IB_WR_RDMA_READ] = NBL_OPCODE_READ,
	[IB_WR_RDMA_WRITE] = NBL_OPCODE_WRITE,
	[IB_WR_RDMA_WRITE_WITH_IMM] = NBL_OPCODE_WRITE_WITH_IMM,
	[IB_WR_ATOMIC_CMP_AND_SWP] = NBL_OPCODE_ATOMIC_CMP_AND_SWP,
	[IB_WR_ATOMIC_FETCH_AND_ADD] = NBL_OPCODE_ATOMIC_FETCH_AND_ADD,
	[IB_WR_LOCAL_INV] = NBL_OPCODE_LOCAL_INV,
	[IB_WR_REG_MR] = NBL_OPCODE_FAST_MR,
};

struct flush_work {
	struct work_struct work;
	struct nbl_qp *qp;
};

struct nbl_sq_uk_wr_trk_info {
	u64 wrid;
	u32 wr_len;
	u16 quanta;
	u8 driver_ce; /* if set, need filter in poll cqe */
	u8 reserved;
};

struct nbl_qp_block {
	__be64 elem[NBL_WQE_SIZE];
};

struct nbl_ib_qp_buf {
	struct nbl_frag_buf frag_buf;
	struct ib_umem *umem;
};

enum nbl_qp_status {
	NBL_QP_STATE_NON = 0,
	NBL_QP_STATE_RST = 1,
	NBL_QP_STATE_INIT = 2,
	NBL_QP_STATE_RTR = 3,
	NBL_QP_STATE_RTS = 4,
	NBL_QP_STATE_SQD = 5,
	NBL_QP_STATE_SQER = 6,
	NBL_QP_STATE_ERR = 7,
};

enum nbl_qp_caps {
	NBL_WRITE_WITH_IMM = 1,
	NBL_SEND_WITH_IMM = 2,
	NBL_ATOMIC = 4,
};

enum nbl_qp_cmd_code {
	NBL_CREATE_QP_CMD_CODE = 0,
	NBL_MODIFY_QP_CMD_CODE = 1,
	NBL_DESTROY_QP_CMD_CODE = 2,
};

enum nbl_qp_service_type {
	NBL_QP_SERVICE_TYPE_RC = 0,
	NBL_QP_SERVICE_TYPE_UD = 3,
};

struct nbl_qp_kmode {
	struct nbl_dma_mem dma_mem;
	struct nbl_sq_uk_wr_trk_info *sq_wrid_mem;
	u64 *rq_wrid_mem;
};

struct nbl_uk_qp {
	struct nbl_qp_block *sq_base;
	struct nbl_qp_block *rq_base;
	struct nbl_uk_attrs *uk_attrs;
	u64 __iomem *sq_db;
	u64 __iomem *rq_db;
	u32 qpn;
	u32 sq_size;
	u32 rq_size;
	u32 qp_caps;
	u32 max_inline_data;
	u32 max_send_sge;
	u32 max_recv_sge;
	u32 max_send_wr;
	u32 max_recv_wr;
	u32 max_outstanding_read;
	u32 rq_wqe_size;
	u8 rq_wqe_size_multiplier;
	struct nbl_ring rq_ring;
	struct nbl_ring sq_ring;
	struct nbl_sq_uk_wr_trk_info
		*sq_wrtrk_array; /*TODO when create qp alloc mem*/
	u64 *rq_wrid_array;
	void *back_qp;
	u32 tc;
	u8 qp_type;
	enum nbl_qp_service_type nbl_qp_service_type;
	u8 sq_flush_seen; /* CQE sq flush flag*/
	u8 rq_flush_seen; /* CQE rq flush flag*/
	bool sq_flush_complete : 1; /* CQE sq flush complete*/
	bool rq_flush_complete : 1; /* CQE rq flush complete*/
	bool destroy_pending : 1;
	bool swqe_polarity : 1;
	bool rwqe_polarity : 1;
	bool sig_all;
	u16 sw_ring_db_pi;
	int seq_num;
	bool rq_db_flag;
	int next_fence;
	bool seq_err;
	bool seq_first_err;
	bool err_db_done;
	bool fmr_nofence;
	u32 hw_drop_db_ci;
	int safe_rsv;
};


struct nbl_qp_ctx {
	u8 vfid;
	u8 pmtu;
	u8 qp_st;
	u8 service_type;

	u8 local_rnr_timer_value;
	u8 dma_len_max;
	u8 src_addr_idx;
	u8 hop_limit;

	u8 tclass;
	u32 rq_size;
	u8 ackreq_th;
	u8 sch_net_tc;

	u32 sq_size;
	u8 stat_id;
	u16 p_key;

	u32 ud_qkey;
	u16 udp_sport;
	u16 flow_label;

	u32 qpn;
	u64 irq_ba;

	u32 pd_idx;
	u8 swrqpi_th;
	u64 orq_ba;

	u32 dest_qpn;
	u64 unaq_ba;
	u32 sq_cqn;
	u32 rq_cqn;
	u32 sq_psn;
	u32 psn_max;
	u32 rq_psn;
	u64 sq_pd_ba;
	u64 rq_pd_ba;
	u64 qp_completion_ctx; /* used by cqe to get qp */
	u64 shadow_area_ba;


	u8 dest_mac[ETH_ALEN];
	u8 dest_ip[16];
	u8 dport;
	u8 fwd;
	u8 ceaq_sq_th;
	u8 ceaq_rq_th;
	u8 rsv[2];

	bool tver;
	bool mig;
	bool rq_wqe_size;
	bool vlan_en;
	bool ipv4;
	bool txmr_frmr_en;

	u8 host_id;
	u8 sq_pm;
	u8 rq_pm;
	bool rss_lag_en;
	bool tunnel_en;
	u8 rto_timer_value;
	u8 tx_retry_th;
	u8 ack_req_th;
	u16 dport_id;
	u64 raq_ba;
	u16 seq_num;
	bool sq_ce_en;
	u64 txp_sq_cur_pd_pa;
	u64 txp_sq_nxt_pd_pa;
	u64 rxp_rq_cur_pd_pa_h;
	u64 rxp_rq_cur_pd_pa_l;
	u64 rxp_rq_nxt_pd_pa_h;
	u64 rxp_rq_nxt_pd_pa_l;
	bool qp1_mode;
	bool wqe_prefetch_en;
	u8 default_wqe_cap;
	u16 vlan_tag;
	u16 sport_id;
	u32 irq_size;

	/* used by CC */
	u8 cc_oamreq_tc_en:1;
	u8 cc_oamreq_net_tc:3;
	u8 cc_oamack_tc_en:1;
	u8 cc_oamack_net_tc:3;
	u8 cc_oamack_blk_th;
	u32 cc_targetwin_min:20;
	u8 cc_mode:2;
	u8 cc_pkt_num_en:1;
	u8 cc_rtt_qp_mult:2;

	u32 qcn_limit_rp;
	u32 qcn_target_rp;
	u32 qcn_first_recdb_flag:1;
	u32 qcn_sendpkt_tarwin:10;
	u32 qcn_remain_trans_bits:18;
	u32 targetwin;
	u8  qcn_main_status;
	bool fmr_nofence;
	u8 rnr_retry;
};

struct nbl_sc_qp {
	struct nbl_uk_qp uk_qp;
	struct nbl_dma_mem qp_shadow;
	struct nbl_dma_mem sqmem;
	struct nbl_dma_mem rqmem;
	struct nbl_dma_mem qp_ctx_mem;
	struct nbl_dma_mem unaq_mem;
	struct nbl_dma_mem irq_mem;
	struct nbl_dma_mem orq_mem;
	struct nbl_dma_mem raq_mem;
	struct nbl_ib_qp_buf sqbuf;
	struct nbl_ib_qp_buf rqbuf;
	struct nbl_sc_dev *dev;
	struct nbl_sc_pd *sc_pd;
	__u32 sq_pagen; /*sq page_num*/
	__u32 rq_pagen; /*rq page_num*/
	bool sq_pm;
	bool rq_pm;
	__u32 sq_pdsize; /*sqpd size 4K or 8K*/
	__u32 rq_pdsize; /*rqpd size 4K or 8K*/
	__u32 sqrq_pdsize; /*sq/rq use 12K pd together*/
	bool sqrq_one_pd; /*sq/rq use 12k pd*/
};

struct nbl_qp {
	struct ib_qp ibqp;
	struct nbl_pd *nblpd;
	struct nbl_sc_qp sc_qp;
	struct nbl_device *nbldev;
	struct nbl_cq *scq;
	struct nbl_cq *rcq;
	struct nbl_qp_ctx ctx_info;
	struct delayed_work dwork_flush;
	enum ib_qp_state ibqp_state;
	u32 last_aeq;
	u8 qp_state;
	u8 user_mode; /* 1: user qp, 0: kernel qp */
	u8 flush_issued;
	refcount_t refcnt;
	refcount_t flush_cnt;
	struct nbl_qp_kmode kqp;
	struct completion free_qp; /* make sure qp freeed in rf */
	struct completion flush_qp; /* make sure qp flused */
	spinlock_t lock;
	struct mutex qp_err_mutex;
	u8 sgid_index;
	bool first_4a;
	bool first_4b;
};

#pragma pack(1)

struct nbl_wqe_fast_mr_ctrl_seg {
	u8 fm_ce_se; /*wqe_valid/fence_mode/ce/se/is_inline/is_imm*/
	__be16 wqe_idx;
	u8 opcode;
	u8 reserved[3];
	u8 ds_ts; /*data_seg number/total size(64byte)*/
	u8 leaf_size : 2;
	u8 access_rights : 6;
	u8 rsv1 : 5;
	u8 addr_type : 1;
	u8 pg_sz : 2;
	u8 rsv2[2];
	__be32 rsv;
};

struct nbl_wqe_fast_mr_addr_seg {
	__be64 va;
	__be32 stag;
	__be32 len;
};

struct nbl_wqe_fast_mr_pbl_seg {
	__be64 pbl_addr;
	__be32 first_pbl_idx;
	__be32 rsv;
};
struct nbl_wqe_datagram_seg {
	__be32 ipv4_vlan_src_flow;
	__be32 q_key;
	__be32 dest_qp;
	__be16 udp_sport;
	__be16 vlan_id;
	u8 dest_mac[6];
	u8 tclass;
	u8 hop_limit;
	__be32 pd_idx;
	__be32 rss_tunnel_fwd_dport;
	u8 dest_ip[16];
};

struct nbl_wqe_raddr_seg {
	__be64 raddr;
	__be32 rkey;
	__be32 len;
};

struct nbl_wqe_ctrl_seg {
	u8 fm_ce_se; /*wqe_valid/fence_mode/ce/se/is_inline/is_imm*/
	__be16 wqe_idx;
	u8 opcode;
	__be32 qpn_ds_ts;
	__be32 payload_len;
	__be32 imm_inv_rkey; /*imm_data or invalid_key*/
};

struct nbl_wqe_info {
	u8 fence;
	bool ce;
	bool se;
	bool is_inline;
	bool is_imm;
	bool is_inv;
	u16 wqe_idx;
	u8 ib_opcode;
	u32 qpn;
	u8 wqe_size;
	u8 num_sge;
	u32 payload_len;
	u32 imm_data;
	u32 inv_rkey;
	bool wqe_vld;
	__u32 temp_sge_len;
	__u64 addr;
};
struct nbl_nop_wqe {
	u8 wqe_valid;
	u8 resv[2];
	u8 opcode;
	__be32 qpn_ds_ts;
	__be32 reserved[14];
};

struct nbl_wqe_atomic_seg {
	__be64 swap_add;
	__be64 compare;
};
struct nbl_wqe_data_seg {
	__be64 local_addr;
	__be32 lkey;
	__be32 byte_count;
};

struct nbl_rq_wqe_ctrl_seg {
	u8 wqe_valid;
	__be16 wqe_idx;
	u8 opcode;
	__be32 qpn_ds_ts;
	__be32 payload_len;
	__be32 rsv3;
};
#pragma pack()


enum nbl_qpc_mask {
	NBL_QPC_STAT_ID_MASK = 1,
	NBL_QPC_OAMREQ_TC_EN_MASK,
	NBL_QPC_OAMREQ_NET_TC_MASK,
	NBL_QPC_OAMACK_TC_EN_MASK,
	NBL_QPC_OAMACK_NET_TC_MASK,
	NBL_QPC_OAMACK_BLK_TH_MASK,
	NBL_QPC_TARGETWIN_MIN_MASK,
	NBL_QPC_TARGETWIN_MASK,
	NBL_QPC_CC_MODE_MASK,
	NBL_QPC_CC_PKT_NUM_EN_MASK,
	NBL_QPC_CC_CMP_RTT_QP_MULT_MASK,
	NBL_QPC_QCN_START_RATE_MASK,
	NBL_QPC_MAX_MASK,
};
int nbl_umem_get(struct nbl_qp *qp, struct nbl_ib_qp_buf *q_buf, struct nbl_device *dev,
						unsigned long addr, int q_size,
						struct ib_udata *udata);
int nbl_qp_use_8k_pd(struct nbl_device *dev, struct nbl_ib_qp_buf *q_buf,
			struct nbl_dma_mem *mem, __u32 page_num, __u32 *pd_size);
int nbl_sqrq_use_one_12k_pd(struct nbl_device *dev, struct nbl_sc_qp *sc_qp);
void nbl_process_level0_buffer(struct nbl_dma_mem *mem,
				struct nbl_ib_qp_buf *q_buf, __u64 addr);
void nbl_flush_work(struct nbl_qp *qp);
void nbl_set_qp_ctx(struct nbl_qp *qp, __be64 *qp_ctx);


int nbl_check_qp_init_attr(struct ib_qp_init_attr *init_attr,
			   struct nbl_uk_attrs *uk_attrs);

int nbl_ib_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr,
		     struct ib_udata *udata);

int nbl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		     struct ib_udata *udata);
int __nbl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask);
int nbl_ib_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);
int nbl_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_qp_init_attr *init_attr);
void nbl_free_qp_rsrc(struct nbl_qp *qp);
void nbl_free_qp_num(struct nbl_pci_f *rf, u32 qp_num);
int nbl_modify_qp_to_err(struct nbl_qp *nblqp);
void nbl_qp_rem_ref(struct ib_qp *ibqp);
bool nbl_modify_qp_is_ok(enum ib_qp_state cur_state,
			 enum ib_qp_state next_state, enum ib_qp_type type,
			 enum ib_qp_attr_mask mask);
int nbl_cqp_modify_qp_cmd(struct nbl_device *nbldev, struct nbl_qp *qp,
			  u8 next_qp_state);
int nbl_alloc_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			struct nbl_ib_qp_buf *q_buf, unsigned long addr,
			int q_size, bool is_sq, struct ib_udata *udata);
void nbl_qp_add_ref(struct nbl_qp *qp);
int nbl_create_kmode_qp(struct nbl_device *nbldev, struct nbl_qp *qp,
			struct ib_qp_init_attr *init_attr);
void nbl_calc_sq_size(u32 sq_size, u32 *sqdepth);
int nbl_calc_rq_size(u32 wr_size, u32 max_recv_sge, u32 *rqdepth,
	u8 *rq_wqe_size_multiplier);
void nbl_free_user_qp_buffer(struct nbl_pci_f *rf,
				struct nbl_sc_qp *sc_qp);
int nbl_alloc_kmode_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			      struct nbl_ib_qp_buf *q_buf, int q_size,
			      bool is_sq);

void nbl_free_kmode_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			     struct nbl_ib_qp_buf *q_buf, bool is_sq);
void nbl_fill_qpc_info(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info);
int nbl_cqp_create_qp_cmd(struct nbl_qp *qp);
int nbl_cqp_destroy_qp_cmd(struct nbl_qp *qp);
int nbl_modify_hw_qpc(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
		      int qpc_mask);
int nbl_cqp_flush_sqrq_cache_cmd(struct nbl_qp *qp);
int nbl_cqp_flush_s1_cache_cmd(struct nbl_qp *qp);
void nbl_modify_qp_fwd(struct nbl_pci_f *rf);
#endif /* NBL_IB_QP_H */
