/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */

/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_QP_H
#define NBL_IB_QP_H

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>
#include "main.h"
#include "pd.h"
#include "cq.h"
#include "defs.h"

/*when user open direct wqe ,need to flush sqe/rqec, default is 0*/
#define NBL_DIRECT_WQE_EN 0

#define NBL_SQRQ_2M_PAGE_NUM 1
#define NBL_IO_POST_DB_MODE 1
#define NBL_INVALID_DPAGE_IDX 0xff
#define NBL_MAX_DPAGE 64 /* only 64 valid direct wqe page per function */
#define NBL_DPAGE_SIZE 4096

#define NBL_RQ_NXT_PD_PA_MASK 0xffff
#define NBL_RQ_NXT_PD_PA_SHIFT 16
#define NBL_RQ_CUR_PD_PA_MASK 0xff
#define NBL_RQ_CUR_PD_PA_SHIFT 8

#define NBL_WQE_VLD_TRUE_MASK 0x80
#define NBL_WQE_VLD_FALSE_MASK 0x7F
#define NBL_WQE_SGE_VLD_SHIFT 32

#define NBL_EXTEN_IB_MTU_8192 6
#define IB_MTU_INVALID_NBL 0xffff /* must > IB_MTU_4096 = 6 */
enum nbl_mtu {
	NBL_MTU_256 = 0,
	NBL_MTU_512 = 1,
	NBL_MTU_1024 = 2,
	NBL_MTU_2048 = 3,
	NBL_MTU_4096 = 4,
	NBL_MTU_8192 = 5,
};

#define NBL_QPC_HPSN_MASK 0x3ff

/******QPC FIELD V2*******/
/*V2 RAM0 0-7 BYTE*/
#define NBL_QPC_V2_SRP_SPRAY FIELD_LOC(0, 63, 63)
#define NBL_QPC_V2_MIG FIELD_LOC(0, 62, 62)
#define NBL_QPC_V2_TVER FIELD_LOC(0, 61, 60)
#define NBL_QPC_V2_STAT_ID FIELD_LOC(0, 59, 52)
#define NBL_QPC_V2_HOST_ID FIELD_LOC(0, 51, 49)
#define NBL_QPC_V2_VF_ID FIELD_LOC(0, 48, 40)
#define NBL_QPC_V2_QPN FIELD_LOC(0, 39, 16)
#define NBL_QPC_V2_PKEY FIELD_LOC(0, 15, 0)

/*V2 RAM0 8-15 BYTE*/
#define NBL_QPC_V2_SERVICE_TYPE FIELD_LOC(8, 63, 60)
#define NBL_QPC_V2_QP_STATE FIELD_LOC(8, 59, 56)
#define NBL_QPC_V2_PMTU FIELD_LOC(8, 55, 52)
#define NBL_QPC_V2_IORQ_BA FIELD_LOC(8, 51, 0)

/*V2 RAM0 16-23 BYTE*/
#define NBL_QPC_V2_QP1_MODE FIELD_LOC(16, 63, 63)
#define NBL_QPC_V2_SCH_NET_TC FIELD_LOC(16, 62, 60)
#define NBL_QPC_V2_PD_IDX FIELD_LOC(16, 59, 36)
#define NBL_QPC_V2_READ_OPTIMIZE_EN FIELD_LOC(16, 35, 35)
#define NBL_QPC_V2_SPORT_ID FIELD_LOC(16, 34, 24)
#define NBL_QPC_V2_CREDIT_EN FIELD_LOC(16, 23, 23)
#define NBL_QPC_V2_CC_PKT_NUM_EN FIELD_LOC(16, 22, 22)
#define NBL_QPC_V2_WQE_PREFETCH_EN FIELD_LOC(16, 21, 21)
#define NBL_QPC_V2_TUNNEL_EN FIELD_LOC(16, 20, 20)
#define NBL_QPC_V2_RQ_SIZE FIELD_LOC(16, 19, 16)
#define NBL_QPC_V2_RQWQE_TS FIELD_LOC(16, 15, 12)
#define NBL_QPC_V2_QP_TYPE FIELD_LOC(16, 11, 10)
#define NBL_QPC_V2_SQ_PM FIELD_LOC(16, 9, 8)
#define NBL_QPC_V2_RQ_PM FIELD_LOC(16, 7, 6)
#define NBL_QPC_V2_ATOMIC_EN FIELD_LOC(16, 5, 5)
#define NBL_QPC_V2_RNR_TIMER_VAL FIELD_LOC(16, 4, 0)

/*V2 RAM0 24-31 BYTE*/
#define NBL_QPC_V2_SWRQPI_TH FIELD_LOC(24, 63, 61)
#define NBL_QPC_V2_CC_MODE FIELD_LOC(24, 60, 58)
#define NBL_QPC_V2_HW_RQCI_TH FIELD_LOC(24, 57, 55)
#define NBL_QPC_V2_SHADOW_BA FIELD_LOC(24, 54, 0)

/*V2 RAM0 32-39 BYTE*/
#define NBL_QPC_V2_VLAN_TAG FIELD_LOC(32, 63, 48)
#define NBL_QPC_V2_IPV4 FIELD_LOC(32, 47, 47)
#define NBL_QPC_V2_SRP_SRACK_TIMER_VALUE FIELD_LOC(32, 46, 42)
/* 1,  1us;          2,  1us*2
 * 3,  1us*4-1       4,  1us*4
 * 5,  1us*8-2       6,  1us*8
 * 7,  1us*16-4      8,  1us*16
 * 9,  1us*32-8      10, 1us*32
 * 11, 1us*64-16     12, 1us*64
 * 13, 1us*128-32    14, 1us*128
 * 15, 1us*256-64    16, 1us*256
 */

enum nic_spray_mode {
	NBL_DEF_SRP_NIC_SPRAY_VALUE = 0,
	/* the incremental range of sport is 0-f for QP leavl */
	NBL_SRP_NIC_SPRAY_MODE_QP = 1,
	/* the incremental range of sport is 0-f for global leavl */
	NBL_SRP_NIC_SPRAY_MODE_GLOBAL = 2,
	/* the incremental range of sport is not limited for QP leavl */
	NBL_SRP_NIC_SPRAY_MODE_QP_RANGE_ALL = 3,
	/* the incremental range of sport is not limited for global leavl */
	NBL_SRP_NIC_SPRAY_MODE_GLOBAL_RANGE_ALL = 4,
	NBL_SRP_NIC_SPRAY_MODE_MAX = 5,
};

#define NBL_SRP_SRACK_TIMER_VALUE_MAX 16
#define NBL_SRP_SRACK_TIMER_VALUE_DEFAULT 16
#define NBL_SRP_EXT_BMP_QPN_MAX_2X200 511
#define NBL_SRP_EXT_BMP_QPN_MAX_1X400 1023
#define NBL_QPC_V2_SRP_EXT_BMP_EN FIELD_LOC(32, 41, 41)
#define NBL_QPC_V2_ATOMIC_NO_FENCE FIELD_LOC(32, 40, 40)
#define NBL_QPC_V2_RQPD_BA_H_OR_SRQN_H FIELD_LOC(32, 39, 0)

/*V2 RAM0 40 -47 BYTE */
#define NBL_QPC_V2_RQPD_BA_L_OR_SRQN_L FIELD_LOC(40, 63, 52)
#define NBL_QPC_V2_CC_TARGETWIN_MIN FIELD_LOC(40, 51, 32)
#define NBL_QPC_V2_UD_QKEY FIELD_LOC(40, 31, 0)
/*V2 RAM0 48 -55 BYTE*/
#define NBL_QPC_V2_SQ_SIZE FIELD_LOC(48, 63, 60)
#define NBL_QPC_V2_DEST_QPN FIELD_LOC(48, 59, 36)
#define NBL_QPC_V2_TX_RETRY_TH FIELD_LOC(48, 35, 33)
#define NBL_QPC_V2_SRP_EN FIELD_LOC(48, 32, 32)
#define NBL_QPC_V2_SRQ_EN FIELD_LOC(48, 31, 31)
#define NBL_QPC_V2_IRQ_SIZE FIELD_LOC(48, 30, 28)
#define NBL_QPC_V2_RTO_TIMER_VALUE FIELD_LOC(48, 19, 15)
#define NBL_QPC_V2_FRMR_EN FIELD_LOC(48, 14, 14)
#define NBL_QPC_V2_CC_RTTMINTH_ADD_MULT FIELD_LOC(48, 13, 12)
#define NBL_QPC_V2_READ_EN FIELD_LOC(48, 11, 11)
#define NBL_QPC_V2_WRITE_EN FIELD_LOC(48, 10, 10)
#define NBL_QPC_V2_QP_SPRAY_EN FIELD_LOC(48, 8, 8) /* multi plane spray for 4pf bond */
#define NBL_QPC_V2_SRC_ADDR_SEQ_NUM FIELD_LOC(48, 7, 4)
#define NBL_QPC_V2_CC_OAM_ACK_TC_EN  FIELD_LOC(48, 3, 3)
#define NBL_QPC_V2_CC_OAM_ACK_NET_TC FIELD_LOC(48, 2, 0)
/*V2 RAM0 56-63 BYTE*/
#define NBL_QPC_V2_OAM_REQ_TC_EN FIELD_LOC(56, 63, 63)
#define NBL_QPC_V2_OAM_REQ_NET_TC FIELD_LOC(56, 62, 60)
#define NBL_QPC_V2_RNR_RETRY_TH FIELD_LOC(56, 59, 56)
/*domain or srqwc ba*/
#define NBL_QPC_V2_DOMAIN FIELD_LOC(56, 55, 32)
#define NBL_QPC_V2_SRQWC_BA FIELD_LOC(56, 51, 0)

/*RAM0 64-71 BYTE*/
#define NBL_QPC_V2_RSS_LAG_EN FIELD_LOC(64, 63, 63)
#define NBL_QPC_V2_FWD FIELD_LOC(64, 62, 61)
#define NBL_QPC_V2_DPORT FIELD_LOC(64, 60, 58)
#define NBL_QPC_V2_DPORT_ID FIELD_LOC(64, 57, 47)
#define NBL_QPC_V2_VLAN FIELD_LOC(64, 46, 46)
#define NBL_QPC_V2_SRC_ADDR_IDX FIELD_LOC(64, 45, 36)
#define NBL_QPC_V2_FLOW_LABLE FIELD_LOC(64, 35, 16)
#define NBL_QPC_V2_UDP_SPORT FIELD_LOC(64, 15, 0)
/*RAM0 72-79 BYTE*/
#define NBL_QPC_V2_TCLASS FIELD_LOC(72, 15, 8)
#define NBL_QPC_V2_HOP_LIMIT FIELD_LOC(72, 7, 0)
#define NBL_QPC_V2_DMAC FIELD_LOC(72, 63, 16)
/*RAM0 96-103 BYTE*/
#define NBL_QPC_V2_TC_CLASS_HIGH FIELD_LOC(96, 63, 56)
#define NBL_QPC_V2_VLAN_PRI_HIGH FIELD_LOC(96, 55, 52)
#define NBL_QPC_V2_UNAQ_BA FIELD_LOC(96, 51, 0)
/*RAM0 104-111 BYTE*/
#define NBL_QPC_V2_TXP_NOFENCE FIELD_LOC(104, 61, 61)
#define NBL_QPC_V2_SQ_CE_EN FIELD_LOC(104, 60, 60)
#define NBL_QPC_V2_ACKREQ_TH FIELD_LOC(104, 59, 52)
#define NBL_QPC_V2_SQ_PD_BA FIELD_LOC(104, 51, 0)
/*RAM0 112-119 BYTE*/
#define NBL_QPC_V2_CEAQ_SQ_TH FIELD_LOC(112, 55, 52)
#define NBL_QPC_V2_CEAQ_RQ_TH FIELD_LOC(112, 51, 48)
#define NBL_QPC_V2_SQ_CQN FIELD_LOC(112, 47, 24)
#define NBL_QPC_V2_RQ_CQN FIELD_LOC(112, 23, 0)
/*RAM0 120-127 BYTE*/
#define NBL_QPC_V2_QP_SEQ_NUM FIELD_LOC(120, 14, 0)

/*RAM1 HW QPC*/
#define NBL_QPC_V2_RETRY_CNT FIELD_LOC(192, 2, 0)
#define NBL_QPC_V2_TLP_TIMER FIELD_LOC(192, 55, 51)
#define NBL_QPC_V2_TLP_RETRY_TH FIELD_LOC(192, 50, 48)
#define NBL_QPC_V2_TLP_RETRY_CNT FIELD_LOC(192, 42, 40)
#define NBL_QPC_V2_TXP_SQ_RETRY_CNT_PSN FIELD_LOC(208, 23, 0)
#define NBL_TLP_RETRY_TH_DEFAULT 3
#define NBL_TLP_RETRY_TH_MAX 7
#define NBL_TLP_RETRY_TIMER_DEFAULT 31
#define NBL_TLP_RETRY_TIMER_MAX 31

#define NBL_QPC_V2_RAQ_BA FIELD_LOC(248, 51, 0)
/* RAM2 HW QPC 288-319 Byte */
#define NBL_QPC_V2_RXP_REQ_PRE_OPCODE FIELD_LOC(256, 31, 24)
#define NBL_QPC_V2_RXP_REQ_PRE_OPCODE_V4 FIELD_LOC(344, 15, 8) /* RNIC400 only */
#define NBL_QPC_V2_EPSN FIELD_LOC(264, 55, 32)

/* before RNIC400 qcn status fields */
/* BASE 0x88(136) */
#define NBL_QPC_V2_QCN_SENDPKT_TARGETWIN FIELD_LOC(136, 62, 52)
/* BASE 0x90(144) */
#define NBL_QPC_V2_QCN_REMAIN_TRANS_BITS FIELD_LOC(144, 27, 6)
/* BASE 0x98(152) */
#define NBL_QPC_V2_QCN_FIRST_RECDB_FLAG FIELD_LOC(152, 50, 50)
#define NBL_QPC_V2_QCN_LIMIT_RP FIELD_LOC(152, 49, 30)
#define NBL_QPC_V2_QCN_TARGET_RP FIELD_LOC(152, 29, 10)
#define NBL_QPC_V2_QCN_MAIN_STATUS FIELD_LOC(152, 9, 8)

/* RNIC400 qcn status fields */
/* BASE 0x88(136) */
#define NBL_QPC_V4_QCN_SENDPKT_TARGETWIN FIELD_LOC(136, 56, 46)
#define NBL_QPC_V4_QCN_ALPHA FIELD_LOC(136, 9, 0)
/* BASE 0x90(144) */
#define NBL_QPC_V4_QCN_REMAIN_TRANS_BITS FIELD_LOC(144, 30, 9)
/* BASE 0x98(152) */
#define NBL_QPC_V4_QCN_FIRST_RECDB_FLAG FIELD_LOC(152, 42, 42)
#define NBL_QPC_V4_QCN_LIMIT_RP FIELD_LOC(152, 41, 22)
#define NBL_QPC_V4_QCN_TARGET_RP FIELD_LOC(152, 21, 2)
#define NBL_QPC_V4_QCN_MAIN_STATUS FIELD_LOC(152, 1, 0)

#define NBL_QPC_V2_TXP_SQ_NEXT_WQE_CAP FIELD_LOC(160, 28, 24)
#define NBL_QPC_V2_TXP_RAQ_NEXT_WQE_CAP FIELD_LOC(168, 44, 40)
/* CC status fields */
/* BASE 0x138(312) */
#define NBL_QPC_V2_CC_WINM_BUSY FIELD_LOC(312, 57, 57)
#define NBL_QPC_V2_CC_RCVACK_FLAG FIELD_LOC(312, 56, 56)
#define NBL_QPC_V2_CC_RECREQ_SENDTX_BLK_CNT FIELD_LOC(312, 55, 36)
#define NBL_QPC_V2_CC_RECACK_LASTWINM_BLK_CNT FIELD_LOC(312, 35, 16)
#define NBL_QPC_V2_CC_RECACK_EPSN FIELD_LOC(312, 15, 0)

#define NBL_QPC_V4_RMT_REC_ECN_CNT FIELD_LOC(312, 63, 58)

/* BASE 0x130(304) */
#define NBL_QPC_V2_CC_TIME_LASTTA FIELD_LOC(304, 63, 32)
#define NBL_QPC_V2_CCQCN_REQCARRY_SENDCNP_TIME FIELD_LOC(304, 31, 0)

#define NBL_QPC_V4_CC_MORE_RTTMINTH_FLAG FIELD_LOC(304, 63, 63)
#define NBL_QPC_V4_CC_LESS_RTTMINTH_FLAG FIELD_LOC(304, 62, 62)
#define NBL_QPC_V4_INIT_REC_ECN_CNT FIELD_LOC(304, 61, 54)
#define NBL_QPC_V4_CC_TIME_LASTTA FIELD_LOC(304, 53, 32)

/* BASE 0x128(296) */
#define NBL_QPC_V2_CC_SENDACK_MID_BLK_CNT FIELD_LOC(296, 63, 52)
#define NBL_QPC_V2_CC_RECREQ_BLK_CNT FIELD_LOC(296, 51, 32)
#define NBL_QPC_V2_CC_RECREQ_MID_BLK_CNT FIELD_LOC(296, 31, 12)
#define NBL_QPC_V2_CC_RECREQ_EPSN FIELD_LOC(296, 11, 0)

/* BASE 0x120(288) */
#define NBL_QPC_V2_QCN_RECECN_FLAG FIELD_LOC(288, 63, 63)
#define NBL_QPC_V2_CC_MORE_RTTMINTH_FLAG FIELD_LOC(288, 62, 62)
#define NBL_QPC_V2_CC_LESS_RTTMINTH_FLAG FIELD_LOC(288, 61, 61)
#define NBL_QPC_V2_CC_RECACK_RTTFLAG FIELD_LOC(288, 60, 60)
#define NBL_QPC_V2_CC_RTT_MEASURE FIELD_LOC(288, 59, 48)

#define NBL_QPC_V4_QCN_RECECN_FLAG FIELD_LOC(288, 63, 63)
#define NBL_QPC_V4_CC_RCVACK_FLAG FIELD_LOC(288, 62, 62)
#define NBL_QPC_V4_CC_RTT_MEASURE FIELD_LOC(288, 61, 47)
#define NBL_QPC_V4_CC_HIGH_PRIORRTT_MIDCNT FIELD_LOC(288, 46, 39)
#define NBL_QPC_V4_CC_RTTMID_OAMACK_CNT FIELD_LOC(288, 38, 31)
#define NBL_QPC_V4_CC_RTTMIN FIELD_LOC(288, 30, 16)

#define NBL_QPC_V2_CC_HIGH_PRIORRTT_MIDCNT FIELD_LOC(288, 47, 40)
#define NBL_QPC_V2_CC_RTTMID_OAMACK_CNT FIELD_LOC(288, 39, 32)
#define NBL_QPC_V2_CC_RTTMIN FIELD_LOC(288, 31, 16)
#define NBL_QPC_V2_CC_OAMACK_NEXT_PSN FIELD_LOC(288, 15, 0)

/* BASE 0x180(384) */
#define NBL_QPC_V2_RXP_HPSN FIELD_LOC(384, 9, 0)

/* RAM3 400-407 BYTE CC */
/* BASE 0x198(408) */
#define NBL_QPC_V2_CC_HIGH_PRIOR_OAM FIELD_LOC(408, 41, 41)
#define NBL_QPC_V2_CC_RTTM_BUSY FIELD_LOC(408, 40, 40)
#define NBL_QPC_V2_CC_RECACK_RECTX_BLK_CNT FIELD_LOC(408, 39, 20)
#define NBL_QPC_V2_CC_TARGETWIN FIELD_LOC(408, 19, 0)

#define NBL_QPC_V4_CC_HIGH_PRIOR_OAM FIELD_LOC(408, 57, 57)
#define NBL_QPC_V4_CC_RTTM_BUSY FIELD_LOC(408, 56, 56)
#define NBL_QPC_V4_CC_RECACK_RECTX_BLK_CNT FIELD_LOC(408, 43, 24)

/* BASE 0x190(400) */
#define NBL_QPC_V2_CC_RTTM_PSNTS FIELD_LOC(400, 35, 24)
#define NBL_QPC_V2_CC_TXP_SENDPLD_BLK_CNT FIELD_LOC(400, 19, 0)

/*SRQ */
#define NBL_QPC_V2_RXP_RQ_FPDPA FIELD_LOC(336, 51, 0) /*TODO*/

#define NBL_QPC_V2_SRP_RQ_FPDPA FIELD_LOC(360, 51, 0) /* first PD PA */
/*send_psn/resv_psn*/
#define NBL_QPC_V2_RNR_RETRY_NUM FIELD_LOC(368, 27, 24)
#define NBL_QPC_V2_RXP_RESP_PRE_OPCODE FIELD_LOC(376, 63, 59)
#define NBL_QPC_V2_PSN_MAX FIELD_LOC(400, 63, 40)
/*SQ_PD/RQ_PD*/
#define NBL_QPC_V2_RQ_NXT_PD_PA_VLD  FIELD_LOC(416, 52, 52)
#define NBL_QPC_V2_RQ_NXT_PD_PA FIELD_LOC(416, 51, 0)
#define NBL_QPC_V2_RQ_CUR_PD_PA_VLD  FIELD_LOC(424, 52, 52)
#define NBL_QPC_V2_RQ_CUR_PD_PA FIELD_LOC(424, 51, 0)

#define NBL_QPC_V2_SQ_NXT_PD_PA_VLD  FIELD_LOC(432, 52, 52)
#define NBL_QPC_V2_SQ_NXT_PD_PA FIELD_LOC(432, 51, 0)
#define NBL_QPC_V2_SQ_CUR_PD_PA_VLD  FIELD_LOC(440, 52, 52)
#define NBL_QPC_V2_SQ_CUR_PD_PA FIELD_LOC(440, 51, 0)
#define NBL_QPC_V2_E2E_FC_EN FIELD_LOC(472, 24, 24)
#define NBL_QPC_V2_AE_FLAG FIELD_LOC(472, 25, 25)
/*shadow*/
#define NBL_QPC_V2_SHADOW_QPC_BA FIELD_LOC(496, 54, 0)
#define NBL_QPC_V2_SHADOW_SEQ_NUM FIELD_LOC(504, 35, 32)

/******V1 QPC*******/
/*V1 RAM0 0-7 BYTE*/
#define NBL_QPC_V1_MIG FIELD_LOC(0, 62, 62)
#define NBL_QPC_V1_TVER FIELD_LOC(0, 61, 60)
#define NBL_QPC_V1_STAT_ID FIELD_LOC(0, 59, 52)
#define NBL_QPC_V1_HOST_ID FIELD_LOC(0, 51, 49)
#define NBL_QPC_V1_VF_ID FIELD_LOC(0, 48, 40)
#define NBL_QPC_V1_QPN FIELD_LOC(0, 39, 16)
#define NBL_QPC_V1_PKEY FIELD_LOC(0, 15, 0)

/*V1 RAM0 8-15 BYTE*/
#define NBL_QPC_V1_SERVICE_TYPE FIELD_LOC(8, 63, 60)
#define NBL_QPC_V1_QP_STATE FIELD_LOC(8, 59, 56)
#define NBL_QPC_V1_PMTU FIELD_LOC(8, 55, 52)
#define NBL_QPC_V1_IRQ_BA FIELD_LOC(8, 51, 0)

/*V1 RAM0 16-23 BYTE*/
#define NBL_QPC_V1_QP1_MODE FIELD_LOC(16, 63, 63)
#define NBL_QPC_V1_SCH_NET_TC FIELD_LOC(16, 62, 60)
#define NBL_QPC_V1_PD_IDX FIELD_LOC(16, 59, 36)
#define NBL_QPC_V1_SPORT_ID FIELD_LOC(16, 33, 24)
#define NBL_QPC_V1_CREDIT_EN FIELD_LOC(16, 23, 23)
#define NBL_QPC_V1_CC_PKT_NUM_EN FIELD_LOC(16, 22, 22)
#define NBL_QPC_V1_TUNNEL_EN FIELD_LOC(16, 20, 20)
#define NBL_QPC_V1_RQ_SIZE FIELD_LOC(16, 19, 16)
#define NBL_QPC_V1_RQWQE_TS FIELD_LOC(16, 15, 15)
#define NBL_QPC_V1_DMA_MAX_LEN FIELD_LOC(16, 14, 10)
#define NBL_QPC_V1_SQ_PM FIELD_LOC(16, 9, 8)
#define NBL_QPC_V1_RQ_PM FIELD_LOC(16, 7, 6)
#define NBL_QPC_V1_ATOMIC_EN FIELD_LOC(16, 5, 5)
#define NBL_QPC_V1_RNR_TIMER_VAL FIELD_LOC(16, 4, 0)

/*V1 RAM0 24-31 BYTE*/
#define NBL_QPC_V1_SWRQPI_TH FIELD_LOC(24, 63, 61)
#define NBL_QPC_V1_CC_MODE FIELD_LOC(24, 60, 59)
#define NBL_QPC_V1_ATOMIC_NO_FENCE FIELD_LOC(24, 58, 58)
#define NBL_QPC_V1_WQE_PREFETCH_EN FIELD_LOC(24, 57, 57)
#define NBL_QPC_V1_WQE_CAP FIELD_LOC(24, 56, 52)
#define NBL_QPC_V1_ORQ_BA FIELD_LOC(24, 51, 0)

/*V1 RAM0 32-39 BYTE*/
#define NBL_QPC_V1_VLAN_TAG FIELD_LOC(32, 63, 48)
#define NBL_QPC_V1_DFT_RAQE_CAP FIELD_LOC(32, 44, 40)
#define NBL_QPC_V1_RQ_PD_BA_H FIELD_LOC(32, 39, 0)

/*V1 RAM0 40 -47 BYTE */
#define NBL_QPC_V1_RQPD_BA_L FIELD_LOC(40, 63, 52)
#define NBL_QPC_V1_CC_TARGETWIN_MIN FIELD_LOC(40, 51, 32)
#define NBL_QPC_V1_UD_QKEY FIELD_LOC(40, 31, 0)

/*V1 RAM0 48 -55 BYTE*/
#define NBL_QPC_V1_SQ_SIZE FIELD_LOC(48, 63, 60)
#define NBL_QPC_V1_DEST_QPN FIELD_LOC(48, 59, 36)
#define NBL_QPC_V1_TX_RETRY_TH FIELD_LOC(48, 35, 33)
#define NBL_QPC_V1_IRQ_SIZE FIELD_LOC(48, 30, 28)
#define NBL_QPC_V1_CC_TXP_SENDREQ_DB_TH FIELD_LOC(48, 27, 20) /*TODO*/
#define NBL_QPC_V1_RTO_TIMER_VALUE FIELD_LOC(48, 19, 15)
#define NBL_QPC_V1_FRMR_EN FIELD_LOC(48, 14, 14)
#define NBL_QPC_V1_CC_RTTMINTH_ADD_MULT FIELD_LOC(48, 13, 12)
#define NBL_QPC_V1_CC_SENDACK_BLK_CNT_TH FIELD_LOC(48, 11, 4)
#define NBL_QPC_V1_CC_OAM_ACK_TC_EN  FIELD_LOC(48, 3, 3)
#define NBL_QPC_V1_CC_OAM_ACK_NET_TC FIELD_LOC(48, 2, 0)

/*V1 RAM0 56-63 BYTE*/
#define NBL_QPC_V1_OAM_REQ_TC_EN FIELD_LOC(56, 63, 63)
#define NBL_QPC_V1_OAM_REQ_NET_TC FIELD_LOC(56, 62, 60)
#define NBL_QPC_V1_ACKREQ_TH FIELD_LOC(56, 59, 52)
#define NBL_QPC_V1_SQ_PD_BA FIELD_LOC(56, 51, 0)

/*V1 RAM0 64-71 BYTE*/
#define NBL_QPC_V1_RSS_LAG_EN FIELD_LOC(64, 63, 63)
#define NBL_QPC_V1_FWD FIELD_LOC(64, 62, 61)
#define NBL_QPC_V1_DPORT FIELD_LOC(64, 60, 58)
#define NBL_QPC_V1_DPORT_ID FIELD_LOC(64, 57, 48)
#define NBL_QPC_V1_UDP_SPORT FIELD_LOC(64, 15, 0)
#define NBL_QPC_V1_IPV4 FIELD_LOC(64, 47, 47)
#define NBL_QPC_V1_VLAN FIELD_LOC(64, 46, 46)
#define NBL_QPC_V1_SRC_ADDR_IDX FIELD_LOC(64, 43, 36)
#define NBL_QPC_V1_FLOW_LABLE FIELD_LOC(64, 35, 16)
/*V1 RAM0 72-79 BYTE*/
#define NBL_QPC_V1_TCLASS FIELD_LOC(72, 15, 8)
#define NBL_QPC_V1_HOP_LIMIT FIELD_LOC(72, 7, 0)
#define NBL_QPC_V1_DMAC FIELD_LOC(72, 63, 16)

/*TODO*/
#define NBL_QPC_CC_MODE GENMASK_ULL(60, 59)
#define NBL_QPC_CC_TARGETWIN_MIN GENMASK_ULL(51, 32)
#define NBL_QPC_CC_TARGETWIN GENMASK_ULL(19, 0)
#define NBL_QPC_CC_SENDACK_BLK_CNT_TH GENMASK_ULL(11, 4)

#define NBL_QPC_DSIP_TOTAL_LEN 16

/*RAM0 96-103 BYTE*/
#define NBL_QPC_V1_UNAQ_BA FIELD_LOC(96, 51, 0)

/*RAM0 104 - 111 BYTE*/
#define NBL_QPC_V1_SHADOW_AREA_BA FIELD_LOC(104, 54, 0)
#define NBL_QPC_V1_SQ_CE_EN FIELD_LOC(104, 55, 55)

/*RAM0 112-119 BYTE*/
#define NBL_QPC_V1_RQ_CQN FIELD_LOC(112, 23, 0)
#define NBL_QPC_V1_SQ_CQN FIELD_LOC(112, 47, 24)
#define NBL_QPC_V1_CEAQ_RQ_TH FIELD_LOC(112, 51, 48)
#define NBL_QPC_V1_CEAQ_SQ_TH FIELD_LOC(112, 55, 52)

/*RAM0 120-127 BYTE*/
#define NBL_QPC_V1_QP_COMP_CTX FIELD_LOC(120, 63, 0)

/*HW QPC*/
#define NBL_QPC_V1_RNR_RETRY_NUM FIELD_LOC(392, 63, 60)
#define NBL_QPC_V1_RNR_RETRY_TH FIELD_LOC(392, 59, 56)

#define NBL_QPC_V1_IRQ_BA_CLONE FIELD_LOC(336, 51, 0)
#define NBL_QPC_V1_SEQ_NUM FIELD_LOC(456, 23, 8)
#define NBL_QPC_V1_RAQ_BA FIELD_LOC(248, 51, 0)

#define NBL_QPC_V1_RXP_REQ_PRE_OPCODE FIELD_LOC(256, 31, 24)
#define NBL_QPC_V1_RXP_EPSN FIELD_LOC(256, 23, 0)
#define NBL_QPC_V1_SQ_NEXT_WQE_CAP FIELD_LOC(160, 28, 24)

#define NBL_QPC_V1_RX_RESP_PRE_OPCODE FIELD_LOC(320, 63, 56)
#define NBL_QPC_V1_RAQ_NEXT_WQE_CAP FIELD_LOC(168, 44, 40)
#define NBL_QPC_V1_RETRY_CNT FIELD_LOC(192, 2, 0)

#define NBL_QPC_V1_RXP_RQ_NXT_PD_PA_VLD FIELD_LOC(416, 36, 36)
#define NBL_QPC_V1_RXP_RQ_NXT_PD_PA_H FIELD_LOC(416, 35, 0)
#define NBL_QPC_V1_PSN_MAX FIELD_LOC(416, 63, 40)

#define NBL_QPC_V1_RXP_RQ_NXT_PD_PA_L FIELD_LOC(424, 63, 48)
#define NBL_QPC_V1_RXP_RQ_CUR_PD_PA_VLD FIELD_LOC(424, 44, 44)
#define NBL_QPC_V1_RXP_RQ_CUR_PD_PA_H FIELD_LOC(424, 43, 0)

#define NBL_QPC_V1_RXP_RQ_CUR_PD_PA_L FIELD_LOC(432, 63, 56)
#define NBL_QPC_V1_TXP_SQ_NXT_PD_PA FIELD_LOC(432, 51, 0)
#define NBL_QPC_V1_TXP_SQ_NXT_PD_PA_VLD FIELD_LOC(432, 52, 52)

#define NBL_QPC_V1_TXP_SQ_CUR_PD_PA FIELD_LOC(440, 51, 0)
#define NBL_QPC_V1_TXP_SQ_CUR_PD_PA_VLD FIELD_LOC(440, 52, 52)

/*BASE 0x1D8(472)*/
#define NBL_V1_TXMR_NOFENCE FIELD_LOC(472, 63, 63)

/*BASE 0x1F0(496)*/
/* only prototype(taihang), df200, asic v2r1 */
#define NBL_QPC_BA_SHIFT 9
#define NBL_QPC_SHADOW_QPC_BA FIELD_LOC(496, 54, 0)
/*BASE 0x1F8(504)*/
/* only prototype(taihang), df200, asic v2r1 */
#define NBL_QPC_SHADOW_QPN FIELD_LOC(504, 55, 32)
/*use for set hmc qpc shadow*/
#define NBL_HMC_QPC_SHADOW_QPC_BA FIELD_LOC(16, 54, 0)
#define NBL_HMC_QPC_SHADOW_SEQ_NUM FIELD_LOC(8, 63, 49)
#define NBL_HMC_QPC_SHADOW_SW_SEQ_NUM FIELD_LOC(24, 35, 32)
/* RAM1 128-135 BYTE QCN */
#define NBL_QPC_V1_QCN_REMAIN_TRANS_BITS FIELD_LOC(128, 63, 46)
/* RAM1 136-143 BYTE QCN */
#define NBL_QPC_V1_QCN_SENDPKT_TARGETWIN FIELD_LOC(136, 63, 54)
/* RAM1 144-151 BYTE QCN */
#define NBL_QPC_V1_QCN_FIRST_RECDB_FLAG FIELD_LOC(144, 62, 62)
/* RAM1 152-159 BYTE QCN */
#define NBL_QPC_V1_QCN_LIMIT_RP FIELD_LOC(152, 45, 28)
#define NBL_QPC_V1_QCN_TARGET_RP FIELD_LOC(152, 27, 10)
#define NBL_QPC_V1_QCN_MAIN_STATUS FIELD_LOC(152, 9, 8)
/* RAM2 288-319 BYTE */
/* CC status fields */
/* BASE 0x138(312) */
#define NBL_QPC_V1_CC_RECREQ_SENDTX_BLK_CNT FIELD_LOC(312, 63, 44)
#define NBL_QPC_V1_CC_WINM_BUSY FIELD_LOC(312, 43, 43)
#define NBL_QPC_V1_CC_TA_SN_PHASE_CHG FIELD_LOC(312, 42, 42)
#define NBL_QPC_V1_CC_TA_SN FIELD_LOC(312, 41, 36)
#define NBL_QPC_V1_CC_RECACK_LASTWINM_BLK_CNT FIELD_LOC(312, 35, 16)
#define NBL_QPC_V1_CC_RECACK_EPSN FIELD_LOC(312, 15, 0)

/* BASE 0x130(304) */
#define NBL_QPC_V1_CC_TIME_LASTTA FIELD_LOC(304, 63, 32)
#define NBL_QPC_V1_CCQCN_REQCARRY_SENDCNP_TIME FIELD_LOC(304, 31, 0)
/* BASE 0x128(296) */
#define NBL_QPC_V1_QCN_RECECN_FLAG FIELD_LOC(296, 63, 63)
#define NBL_QPC_V1_CC_MORE_RTTMINTH_FLAG FIELD_LOC(296, 62, 62)
#define NBL_QPC_V1_CC_LESS_RTTMINTH_FLAG FIELD_LOC(296, 61, 61)
#define NBL_QPC_V1_CC_RECACK_RTTFLAG FIELD_LOC(296, 60, 60)
#define NBL_QPC_V1_CC_SENDACK_MID_BLK_CNT FIELD_LOC(296, 59, 52)
#define NBL_QPC_V1_CC_RECREQ_BLK_CNT FIELD_LOC(296, 51, 32)
#define NBL_QPC_V1_CC_RECREQ_MID_BLK_CNT FIELD_LOC(296, 31, 12)
#define NBL_QPC_V1_CC_RECREQ_EPSN FIELD_LOC(296, 11, 0)
/* BASE 0x120(288) */
#define NBL_QPC_V1_CC_RTT_MEASURE FIELD_LOC(288, 59, 48)
#define NBL_QPC_V1_CC_RTTMIN FIELD_LOC(288, 31, 16)
#define NBL_QPC_V1_CC_OAMACK_NEXT_PSN FIELD_LOC(288, 15, 0)

/* RAM3 400-407 BYTE CC */
/* BASE 0x198(408) */
#define NBL_QPC_V1_CC_RTTM_BUSY FIELD_LOC(408, 40, 40)
#define NBL_QPC_V1_CC_RECACK_RECTX_BLK_CNT FIELD_LOC(408, 39, 20)
#define NBL_QPC_V1_CC_TARGETWIN FIELD_LOC(408, 19, 0)
/* BASE 0x190(400) */
#define NBL_QPC_V1_CC_RTTM_PSNTS FIELD_LOC(400, 35, 24)
#define NBL_QPC_V1_CC_TXP_SENDPLD_BLK_CNT FIELD_LOC(400, 19, 0)

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
#define NBL_OPCODE_UMR_REVOKE 0x10

#define NBL_OPCODE_RECV 0x3e /* used by cqe handle */
#define NBL_OPCODE_RECV_IMM 0x3f /* used by cqe handle */
/*SQ WQE CTRL V2*/
#define NBL_WQE_VLD FIELD_LOC(0, 31, 31)
#define NBL_WQE_FENCE FIELD_LOC(0, 30, 28)
#define NBL_WQE_CE FIELD_LOC(0, 27, 27)
#define NBL_WQE_SE FIELD_LOC(0, 26, 26)
#define NBL_WQE_INLINE FIELD_LOC(0, 25, 25)
#define NBL_WQE_IMM FIELD_LOC(0, 24, 24)
#define NBL_WQE_IDX_PHASE FIELD_LOC(0, 23, 23)
#define NBL_WQE_IDX FIELD_LOC(0, 22, 8)
#define NBL_WQE_DS_H FIELD_LOC(0, 7, 6)
#define NBL_WQE_OPCODE FIELD_LOC(0, 5, 0)

#define NBL_WQE_QPN FIELD_LOC(4, 31, 8)
#define NBL_WQE_DS_L FIELD_LOC(4, 7, 4)
#define NBL_WQE_TS FIELD_LOC(4, 3, 0)

/*FAST MR CTRL*/
#define NBL_WQE_FMR_ACCESS_RIGHT FIELD_LOC(8, 31, 26)
#define NBL_WQE_FMR_LEAF_SIZE FIELD_LOC(8, 25, 24)
#define NBL_WQE_FMR_PG_SZ FIELD_LOC(8, 23, 22)
#define NBL_WQE_FMR_ADDR_TYPE FIELD_LOC(8, 21, 21)

/*FAST MR ADDR SGE*/
#define NBL_WQE_FMR_LEN FIELD_LOC(16, 31, 0)
#define NBL_WQE_FMR_VA FIELD_LOC(20, 63, 0)
#define NBL_WQE_FMR_VA_H FIELD_LOC(20, 31, 0)
#define NBL_WQE_FMR_VA_L FIELD_LOC(24, 31, 0)
#define NBL_WQE_FMR_STAG FIELD_LOC(28, 31, 0)
#define NBL_WQE_FMR_PBL_SEG_VLD FIELD_LOC(32, 31, 31)
#define NBL_WQE_FMR_PBL_IDX FIELD_LOC(32, 27, 0)
#define NBL_WQE_FMR_PBL_ADDR_H FIELD_LOC(36, 31, 0)
#define NBL_WQE_FMR_PBL_ADDR_L FIELD_LOC(40, 31, 0)
#define NBL_WQE_FMR_PBL_KEY FIELD_LOC(44, 31, 21)
#define NBL_WQE_FMR_PA0 FIELD_LOC(48, 63, 12)
#define NBL_WQE_FMR_PA1 FIELD_LOC(56, 63, 12)

#define NBL_WQE_LOCAL_INV_VLD FIELD_LOC(32, 31, 31)

#define WQE_CTRL_DS_H_MASK 0b110000
#define WQE_CTRL_DS_H_SHIFT 4

#define WQE_CTRL_DS_L_MASK 0b1111
#define WQE_CTRL_DS_L_SHIFT 4
/*muti sge */
#define NBL_WQE_SGE_VLD BIT_ULL(31)
#define NBL_WQE_SGE_LEN GENMASK_ULL(30, 0)

#define NBL_REV_PAGE_TH 56
#define NBL_MAX_WQE_PER_PAGE 64
#define MAX_HW_SQ_MSGE_QUANTA 8

#define NBL_RSV_SET_VLD_LEN 32
#define NBL_INLINE_FRAGMENT_LEN 31
#define NBL_GET_INLINE_WQE_SPLIT_NUM(pld_len)                                  \
	(ALIGN(pld_len, NBL_INLINE_FRAGMENT_LEN) / NBL_INLINE_FRAGMENT_LEN)

#define NBL_CHECK_RING_EMPTY(_ring) ((_ring).head == (_ring).tail)
#define NBL_GET_WR_SIZE(wr_size)                                               \
	(((wr_size) < NBL_MIN_WR_SIZE) ? NBL_MIN_WR_SIZE : (wr_size))
#define NBL_GET_RQ_WR_SIZE(wr_size)                                            \
	(((wr_size) < NBL_MIN_RQ_WR_SIZE) ? NBL_MIN_RQ_WR_SIZE : (wr_size))
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
#define NBL_ATOMIC_RING_MOVE_HEAD_BY_COUNT(_ring, index, count, retcode)       \
	{                                                                      \
		index = NBL_RING_CURRENT_HEAD(_ring);                          \
		NBL_RING_MOVE_HEAD_BY_COUNT(_ring, count, retcode);            \
	}
#define NBL_SQ_RING_MOVE_HEAD_BY_COUNT(_ring, _count)                          \
	(_ring).head = ((_ring).head + (_count)) % (_ring).size

#define NBL_RING_EMPTY(_ring) (((_ring).head) == ((_ring).tail))

#define NBL_MIN_WQE_SIZE 64
#define NBL_MAX_WQE_SIZE 128
#define NBL_SQ_OST_CNT 128
#define NBL_SQ_OST_CNT_V2 512
#define NBL_LOCAL_CNT_TH 64
#define NBL_V2_MAX_WQE_SIZE 512
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
#define NBL_MIN_RQ_SIZE (1 << 16)
#define NBL_MIN_RQ_WR_SIZE 1024
#define NBL_MIN_WR_SIZE 256
#define NBL_QP_QUEUE_ALIGN_SIZE 256
#define NBL_WQE_CTRL_FENCE 2
#define NBL_WQE_CTRL_STRONG_ORD_FENCE 3

#define NBL_WQE_CTRL_VALID (1 << 7)
#define NBL_WQE_CTRL_DATA_SIZE_SHIFT 0x4
#define NBL_WQE_CTRL_QPN_SHIFT 0x8
#define NBL_QP_DB_RAQ_FLUSH 0x1C
#define NBL_QP_DB_TC 0x1D
#define NBL_SQ_RSVD 129
#define NBL_SQ_RSVD_V2 137
#define NBL_RQ_RSVD 1
#define NBL_QP_CTX_SIZE 0x200
#define NBL_QP_SHADOW_OFFST 0x1E0
#define NBL_QP_SHADOW_SIZE 0x20
#define NBL_DEFAULT_SWRQPI_TH 1
#define NBL_MAX_SEQ_NUM 0xFFFF
#define NBL_MAX_SEQ_NUM_V2 0x7FFF
#define NBL_DMA_LEN_MAX 0x20
#define NBL_DEFAULT_ACKREQ_TH 64
#define NBL_DEFAULT_CEAQ_SQ_TH 0x6
#define NBL_DEFAULT_CEAQ_RQ_TH 0x6
#define NBL_NORMAL_FWD 0x1 /*LEONIS fwd= 1 normal fwd*/
#define NBL_CPU_FWD 0x3
#define NBL_DEFAULT_DPORT 0
#define NBL_DEFAULT_DPORT_HOST 0x1
#define NBL_DEFAULT_DPORT_ECPU 0x2
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
#define NBL_DEFAULT_WQE_CAP_V2 0x10
#define NBL_DEFAULT_RAQ_WQE_CAP_V4 0x8
#define NBL_DEFAULT_RAQ_WQE_CAP_V2 0x10
#define NBL_DEFAULT_WQE_PREFETCH 0
#define NBL_DEFAULT_RAQ_WQE_CAP 16
#define NBL_DEFAULT_RQCI_TH 7
#define NBL_MAX_RNR_TIMER 0x1F
#define NBL_DEFAULT_LOAD_PI_INTERVAL 0x6 /* ud reuse with rnr time */
#define NBL_DEFAULT_RNR_TIMER 0xD /* 960 us, rnr time */
#define NBL_DEFAULT_RTO_TIMER 0xC /* 16777 us */
#define NBL_DEFAULT_RETRY_TH 7
#define NBL_RTO_ARRY_MAX_SIZE 0x20
#define NBL_RTO_MAX_VALUE 0x1F
#define NBL_DEFAULT_TXP_SQ_RETRY_CNT_PSN 0x400000 /* 4M just away from 0 */

#define NBL_SQE_SAFE_QUANTA 257
#define NBL_QP_INVALD_ERRCODE 0xFF

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
#define NBL_QPC_SHADOW_AREA_SW_RQ_PI_LOAD_FLAG BIT_ULL(0)

/* UD WQE SEG field */
#define NBL_AH_VLAN_EN_SHIFT 1
#define NBL_QP_WQE_UD_IPV4 0x1F
#define NBL_QP_WQE_UD_VLAN 0x1E
#define NBL_QP_WQE_UD_SRC_ADDR_IDX 0x14
#define NBL_QP_WQE_UD_RSS_LAG_EN 0x10
#define NBL_QP_WQE_UD_TUNNEL_EN 0xF
#define NBL_QP_WQE_UD_FWD 0xD
#define NBL_QP_WQE_UD_DPORT 0xA

/* SQ WQE V2 UD datagram*/
#define NBL_WQE_UD_IPV4_VLD FIELD_LOC(0, 31, 31)
#define NBL_WQE_UD_VLAN_EN FIELD_LOC(0, 30, 30)
#define NBL_WQE_UD_SRC_ADDR_IDX FIELD_LOC(0, 29, 20)
#define NBL_WQE_UD_FLOW_LABLE FIELD_LOC(0, 19, 0)

#define NBL_WQE_UD_QKEY FIELD_LOC(4, 31, 0)
#define NBL_WQE_UD_DEST_QPN FIELD_LOC(8, 23, 0)
#define NBL_WQE_UD_UDP_SPORT FIELD_LOC(12, 31, 16)
#define NBL_WQE_UD_VLAN_TAG FIELD_LOC(12, 15, 0)

#define NBL_WQE_UD_WQE_VLD FIELD_LOC(16, 31, 31)
#define NBL_WQE_UD_RSS_LAG_EN FIELD_LOC(16, 16, 16)
#define NBL_WQE_UD_TUNNEL_EN FIELD_LOC(16, 15, 15)
#define NBL_WQE_UD_FWD FIELD_LOC(16, 14, 13)
#define NBL_WQE_UD_DPORT FIELD_LOC(16, 12, 10)
#define NBL_WQE_UD_DPORT_ID FIELD_LOC(16, 9, 0)

#define NBL_WQE_UD_TCLASS FIELD_LOC(24, 15, 8)
#define NBL_WQE_UD_HOPE_LIMIT FIELD_LOC(24, 7, 0)

#define NBL_WQE_UD_PD_IDX FIELD_LOC(28, 31, 8)

#define NBL_WQE_UD_V2_DMAC_OFFSET 20
#define NBL_WQE_UD_V2_DIP_OFFSET 32
/* RQ DB*/
#define NBL_RQ_DB_SEQ_NUM GENMASK_ULL(59, 56)
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
#define NBL_UMR_QP_RSV 1 /*UMR QP RSV*/

#define NBL_QP_NEED_DBG_QP(qpn) \
	((qpn) != NBL_QP_NUM_FOR_RSV && \
	(qpn) != NBL_QP_NUM_FOR_DUMP)

#define NBL_CALC_SFAE_RSV_CNT(wqe_size, ost_cnt)                               \
	((wqe_size * ost_cnt + NBL_LOCAL_CNT_TH * NBL_MIN_WQE_SIZE) /          \
	 NBL_MIN_WQE_SIZE)
#define IB_MTU_TO_NBL(mtu) (mtu - 1)
enum ecn_mask {
	ECN_NON_ECT = 0,
	ECN_ECT_0 = 1,
	ECN_ECT_1 = 2,
	ECN_CE = 3,
};

/* set DSCP (6-bit) into TC byte, preserving ECN (low 2 bits) */
#define NBL_SET_TC_DSCP(tc, dscp) \
	((tc) = (((dscp) & 0x3F) << 2) | ((tc) & ECN_CE))

/* extract high 3 bits of DSCP value for priority */
#define NBL_DSCP_TO_PRI(dscp) (((dscp) >> 3) & 0x7)

/*set VLAN tag priority */
#define NBL_SET_VLAN_TAG_PRI(vlan_tag, pri) \
	((vlan_tag) = ((pri) << 13) | ((vlan_tag) & 0x1FFF))

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
	u32 ae_id;
};

struct nbl_sq_uk_wr_trk_info {
	u64 wrid;
	u32 wr_len;
	u16 quanta;
	u8 driver_ce; /* if set, need filter in poll cqe */
	enum ib_wr_opcode ib_op;
	u8 reserved;
};

struct nbl_qp_block {
	__be64 elem[NBL_WQE_SIZE];
};

struct nbl_ib_qp_buf {
	struct nbl_frag_buf frag_buf;
	struct ib_umem *umem;
	bool nbl_peer;
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

enum nbl_qp_type {
	NBL_QPT_OTHER = 0,
	NBL_QPT_INI = 1,
	NBL_QPT_TGT = 2,
};

struct nbl_qp_kmode {
	struct nbl_dma_mem dma_mem;
	struct nbl_sq_uk_wr_trk_info *sq_wrid_mem;
	u64 *rq_wrid_mem;
};

enum nbl_qp_caps {
	NBL_WRITE_WITH_IMM = 1,
	NBL_SEND_WITH_IMM = 2,
	NBL_ATOMIC = 4,
	NBL_SRP_EN = 8, /* SRP enable flag */
};

enum nbl_qp_service_type {
	NBL_QP_SERVICE_TYPE_RC = 0,
	NBL_QP_SERVICE_TYPE_UD = 3,
	NBL_QP_SERVICE_TYPE_XRC = 5,
	NBL_QP_SERVICE_TYPE_SRP = 7,
	NBL_QP_SERVICE_TYPE_UMR = 8,
};

#define NBL_QP_HW_QUEUE_MAX 4

enum nbl_qp_hw_v2_queue_mem {
	NBL_QP_HW_V2_RAQE = 0,
	NBL_QP_HW_V2_IORQE = 1,
	NBL_QP_HW_V2_SRQEW = 2,
	NBL_QP_HW_V2_UNAQE = 3,
};

enum nbl_qp_hw_v1_queue_mem {
	NBL_QP_HW_V1_RAQE = 0,
	NBL_QP_HW_V1_IRQE = 1,
	NBL_QP_HW_V1_ORQE = 2,
	NBL_QP_HW_V1_UNAQE = 3,
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
	u32 atomic_rd_en;
	u32 resp_depth;
	u32 max_inline_data;
	u32 max_send_sge;
	u32 max_recv_sge;
	u32 max_send_wr;
	u32 max_recv_wr;
	u32 qp_max_dest_rd_atom; /*qp max recv read/atomic ost*/
	u32 qp_max_rd_atom; /*qp max send read/atomic ost*/
	u32 rq_wqe_size;
	u8 rqe_mult;
	struct nbl_ring rq_ring;
	struct nbl_ring sq_ring;
	struct nbl_sq_uk_wr_trk_info
		*sq_wrtrk_array; /*TODO when create qp alloc mem*/
	u64 *rq_wrid_array;
	void *back_qp;
	u8 db_tc;
	enum ib_qp_type qp_type; /* IB_QPT_RC or others */
	enum nbl_qp_service_type nbl_qp_service_type;
	u8 sq_flush_seen; /* CQE sq flush flag*/
	u8 rq_flush_seen; /* CQE rq flush flag*/
	bool sq_flush_complete; /* CQE sq flush complete*/
	bool rq_flush_complete; /* CQE rq flush complete*/
	bool destroy_pending;
	bool swqe_polarity;
	bool rwqe_polarity;
	u16 sw_ring_db_pi;
	int seq_num;
	bool rq_db_flag;
	int next_fence;
	bool seq_err;
	bool seq_first_err;
	bool err_db_done;
	bool nvme_fmr_en;
	bool txp_fmr_nofence;
	u32 hw_drop_db_ci;

	bool sig_all;
	bool has_sq; /*XRC TGT NO SQ*/
	bool has_rq;

	u32 xrcdn;   /* DF200/V2R1, only TGT QP have xrcdn */
	bool use_srq; /* DF200/V2R1, srq is enabled on this QP */
	u32 srqn;    /* DF200/V2R1, srqn this qp used */

	bool dwqe_en;
	struct rdma_user_mmap_entry *dpage_mmap_entry;
	__u64 dpage_mmap_key;
	__u32 dpage_offset;
	__u32 dpage_idx;
	__u32 local_cnt;

	bool first_sq_cqe_come;
	bool first_rq_cqe_come;
	bool sq_cqe_err_occur;
	bool rq_cqe_err_occur;

	bool is_sq_last_wqe_succ;
	u32 sq_wqe_index_last;
	u32 rq_wqe_index_last;
	int sq_safe_rsv;
};
struct nbl_pd_info {
	u64 pd_ba;
	u64 cur_pd_pa;
	u64 nxt_pd_pa;
	bool cur_pa_vld; /*use for v2 QPC*/
	bool nxt_pa_vld; /*use for v2 QPC*/
};
struct nbl_qp_ctx {
	u8 vfid;
	u8 pmtu;
	u8 qp_st;
	u8 service_type;

	u8 local_rnr_timer_value;
	u8 dma_len_max;
	u16 src_addr_idx;
	u8 src_addr_idx_seq_num;
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
	u32 pd_idx;
	u8 swrqpi_th;

	u32 dest_qpn;
	u32 sq_cqn;
	u32 rq_cqn;
	u32 sq_psn;
	u32 psn_max;
	u32 rq_psn;
	u32 rxp_hpsn;
	u64 qp_completion_ctx; /* used by cqe to get qp */
	u64 qpc_ba_low9bit_mask; /* 512B align, low 9 bit masked */
	u32 txp_sq_retry_cnt_psn; /* fill this to 4M away form 0 */

	u8 dest_mac[ETH_ALEN];
	u8 dest_ip[16];
	u8 dport;
	u8 fwd;
	u8 ceaq_sq_th;
	u8 ceaq_rq_th;
	u8 rsv[2];
	u8 rq_wqe_size;

	bool tver;
	bool mig;
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
	u64 irq_ba;
	u64 orq_ba;
	u64 unaq_ba;
	u64 iorq_ba;
	u64 srqew_ba;
	u16 seq_num;
	bool sq_ce_en;
	struct nbl_pd_info sq_pd;
	struct nbl_pd_info rq_pd;
	u64 rxp_rq_cur_pd_pa_h;
	u64 rxp_rq_cur_pd_pa_l;
	u64 rxp_rq_nxt_pd_pa_h;
	u64 rxp_rq_nxt_pd_pa_l;
	bool qp1_mode;
	bool wqe_prefetch_en;
	u8 default_wqe_cap;
	u8 default_raq_wqe_cap;
	u8 raqe_cap;
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
	u8 cc_mode : 3;
	u8 cc_pkt_num_en:1;
	u8 cc_rtt_qp_mult:2;

	u32 qcn_limit_rp;
	u32 qcn_target_rp;
	u32 qcn_first_recdb_flag:1;
	u32 qcn_sendpkt_tarwin:11;
	u32 qcn_remain_trans_bits:22;
	u32 targetwin;
	u32 qcn_alpha;
	u8  qcn_main_status;
	bool nvme_fmr_en;
	bool txp_fmr_nofence; /*TODO*/
	u8 rnr_retry;

	/* DF200/V2R1 only begin, TODO, check all QPC field position */
	u8 q_type;   /* 2'b00 for RC/UD, 2'b01 for INI QP, 2'b10 for TGT QP */
	u32 xrcdn;   /* only TGT QP have xrcdn */
	bool srq_en; /* srq is enabled on this QP */
	bool srp_en;
	bool srp_spray_en;
	bool mp_port_spray_en; /* multi plane spray en, only for srp qp */
	u8 srp_srack_timer;
	bool sr_ext_bmp_en; /* use ext bmp or not */
	u32 srqn; /* srqn this qp used */
	u8 rqci_th;
	bool read_en;
	bool write_en;
	bool atomic_en;
	u8 tlp_retry_th;
	u8 tlp_timer;

	bool read_optimize_en;

	/* Packet Trim (PT) */
	u8 tc_class_high;
	u8 vlan_pri_high;
};

struct nbl_sc_qp {
	struct nbl_uk_qp uk_qp;
	struct nbl_dma_mem qp_shadow;
	struct nbl_dma_mem sqmem;
	struct nbl_dma_mem rqmem;
	struct nbl_dma_mem qp_ctx_mem;
	struct nbl_dma_mem *mem_list;
	struct nbl_ib_qp_buf sqbuf;
	struct nbl_ib_qp_buf rqbuf;
	struct nbl_sc_dev *sc_dev;
	struct nbl_sc_pd *sc_pd; /* TGT QP has no PD and NULL */
	bool sq_pm;
	bool rq_pm;
	void *qp_ctx_mem_copy;
};

struct nbl_ib_flow {
	struct ib_flow flow;
};

struct nbl_dv_qp_info {
	u8 sq_umem_valid;
	u8 rq_umem_valid;
	u8 use_srq;

	u32 srqn;
	u32 pdn;
	u32 cqn_snd;
	u8 max_recv_sge;
	u32 cqn_rcv;

	u32 log_sq_size; /* num of 64 */
	u32 sq_umem_id;
	u32 sq_umem_offset;

	u32 log_rq_size; /* num of 64 */
	u32 rq_umem_id;
	u32 rq_umem_offset;
};

struct nbl_qp {
	struct ib_qp ibqp;
	struct nbl_pd *nblpd; /* TGT QP has no pd and NULL here */
	struct nbl_sc_qp sc_qp;
	struct nbl_device *nbldev;
	struct device *device;
	struct nbl_cq *scq; /* TGT QP NULL */
	struct nbl_cq *rcq; /* INI QP TGT QP NULL */
	struct nbl_srq *srq;
	struct nbl_qp_ctx ctx_info;
	struct nbl_qp_ctx ctx_info_copy;
	struct delayed_work dwork_flush;
	enum ib_qp_state ibqp_state;
	u8 qp_state;
	u8 user_mode; /* 1: user qp, 0: kernel qp */
	bool flush_issued;
	refcount_t refcnt;
	refcount_t flush_cnt; /* init value NBL_QP_FLUSH_AE_EXP_NUM */
	u32 dpage_idx;
	struct nbl_qp_kmode kqp;
	struct completion free_qp; /* make sure qp freeed in rf */
	struct completion flush_qp; /* make sure qp flused */
	struct completion qp_err; /*modify qp stat to err success seam*/
	spinlock_t lock;
	struct mutex modify_mutex;
	/* use to store src ip of src_addr_tbl when modifying qp for df50 and asic v1r1*/
	u8 src_ip[NBL_SRC_IP_SIZE];
	u8 sgid_index;
	bool first_4a;
	bool first_4b;
	bool dst_is_local; /* rc and dst ip is local ip */
	struct nbl_ib_flow *nbl_flow;
	bool ae_flag;
	bool is_dev_obj; /* IBGDA use only */
	struct nbl_dv_qp_info *dev_obj;
	struct nbl_rsc_debug *dbg;
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

/* fast mr support no-check PBL, fill in PA of the first two pble */
struct nbl_wqe_fast_mr_pa_seg {
	__be64 first_pa;
	__be64 second_pa;
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

struct nbl_wqe_raddr_seg_v2 {
	__be32 len;
	__be64 raddr;
	__be32 rkey;
};
struct nbl_wqe_raddr_seg {
	__be64 raddr;
	__be32 rkey;
	__be32 len;
};

struct nbl_wqe_inline_data_seg {
	void *data;
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
	bool dst_is_local;
	bool local_rd_no_pkt;
	bool is_inv;
	bool is_ud;
	bool is_local;
	u16 wqe_idx;
	u8 ib_opcode;
	u32 qpn;
	u8 wqe_size; /*64 Byte align*/
	__u32 real_wqe_size; /*non 64B align*/
	u16 cur_size;
	u8 num_sge;
	u32 payload_len;
	u32 imm_data;
	u32 inv_rkey;
	bool wqe_vld;
	__u32 temp_sge_len;
	__u16 cur_sge_num;
	__u64 addr;
	bool rev_page;
	u32 avl_size;
	u16 next_wqe_idx;
	bool is_umr;
	u8 umr_opcode;
	u64 umr_wr_id;
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
struct nbl_wqe_data_seg_v2 {
	__be32 len;
	__be64 local_addr;
	__be32 lkey;
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

extern int rto_arry[NBL_RTO_ARRY_MAX_SIZE];

static inline const char *nbl_qp_type_str(enum nbl_qp_service_type type)
{
	switch (type) {
	case NBL_QP_SERVICE_TYPE_RC:
	return "RC";
	case NBL_QP_SERVICE_TYPE_UD:
	return "UD";
	case NBL_QP_SERVICE_TYPE_XRC:
	return "XRC";
	case NBL_QP_SERVICE_TYPE_SRP:
	return "RC_SRP";
	case NBL_QP_SERVICE_TYPE_UMR:
	return "REG_UMR";
	default:
	return "INVALID";
	}
}

static inline const char *nbl_qp_stat_to_str(u8 state)
{
	switch (state) {
	case NBL_QP_STATE_NON:
	return "NONE";
	case NBL_QP_STATE_RST:
	return "RST";
	case NBL_QP_STATE_INIT:
	return "INIT";
	case NBL_QP_STATE_RTR:
	return "RTR";
	case NBL_QP_STATE_RTS:
	return "RTS";
	case NBL_QP_STATE_SQD:
	return "SQD";
	case NBL_QP_STATE_SQER:
	return "SQERR";
	case NBL_QP_STATE_ERR:
	return "ERR";
	default:
	return "INVALID";
	}
}

static inline const char *ib_qp_stat_to_str(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:
	return "ib_rst";
	case IB_QPS_INIT:
	return "ib_init";
	case IB_QPS_RTR:
	return "ib_rtr";
	case IB_QPS_RTS:
	return "ib_rts";
	case IB_QPS_SQD:
	return "ib_sqd";
	case IB_QPS_SQE:
	return "ib_sqe";
	case IB_QPS_ERR:
	return "ib_err";
	default:
	return "ib_invalid";
	}
}

void nbl_flush_work(struct nbl_qp *qp, u32 ae_id);
void nbl_fill_qp_ctx(struct nbl_qp *qp, __be64 *qp_ctx);
void nbl_set_qp_ctx_v2(struct nbl_qp *qp, __be64 *qp_ctx);

int nbl_ib_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr, struct ib_udata *udata);
int nbl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		     struct ib_udata *udata);

int nbl_ib_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);
int nbl_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_qp_init_attr *init_attr);
int nbl_modify_qp_to_err(struct nbl_qp *nblqp, struct ib_udata *udata);
int nbl_modify_qp_to_reset(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata);
int nbl_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata);
void nbl_qp_rem_ref(struct ib_qp *ibqp);
bool nbl_modify_qp_is_ok(enum ib_qp_state cur_state,
			 enum ib_qp_state next_state, enum ib_qp_type type,
			 enum ib_qp_attr_mask mask);
int nbl_cqp_modify_qp_cmd(struct nbl_device *nbldev, struct nbl_qp *qp,
			  u8 next_qp_state);
int nbl_alloc_user_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			struct nbl_ib_qp_buf *q_buf, unsigned long addr,
			int q_size, bool is_sq, struct ib_udata *udata);
int nbl_create_kernel_sq(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr);
int nbl_create_kernel_rq(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr);
int nbl_create_kernel_qp(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr);
void nbl_qp_add_ref(struct nbl_qp *qp);
void nbl_calc_rqwqe_size(struct nbl_uk_qp *uk_qp, __u32 max_sge);
int nbl_alloc_kmode_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			      struct nbl_ib_qp_buf *q_buf, int q_size,
			      bool is_sq);

void nbl_free_kmode_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			     struct nbl_ib_qp_buf *q_buf, bool is_sq);
void nbl_fill_qpc_info(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info);
int nbl_cqp_create_qp_cmd(struct nbl_qp *qp);
int nbl_cqp_process_dpage_idx_cmd(struct nbl_pci_f *rf, int dpage_idx,
					__u32 cmd_code);
int nbl_cqp_destroy_qp_cmd(struct nbl_qp *qp);
int nbl_modify_hw_qpc(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
		      int qpc_mask);
int nbl_cqp_flush_sqrq_cache_cmd(struct nbl_qp *qp);
int nbl_cqp_v2_flush_s1_cache_cmd(u32 qpn, u16 flush_vfid,
				  struct nbl_pci_f *rf, bool vf_flush_flag);
void nbl_qp_ae_handle(struct nbl_qp *nblqp, u16 ae_id);
struct ib_flow *nbl_ib_create_flow(struct ib_qp *qp, struct ib_flow_attr *flow_attr,
				   struct ib_udata *udata);
int nbl_ib_destroy_flow(struct ib_flow *dump_flow);
int nbl_get_sq_safe_rsv(u16 sq_ost_count, int wqe_size);
int nbl_alloc_hw_queue_mem(struct nbl_pci_f *rf, struct nbl_qp *qp);
void nbl_free_qp_hw_queue_mem(struct nbl_pci_f *rf,
				     struct nbl_sc_qp *sc_qp);
void nbl_fill_qpc_seq_num(struct nbl_pci_f *rf, struct nbl_sc_qp *sc_qp);
void nbl_copy_qp_ctx(struct nbl_qp *qp);
int nbl_get_qpc_base_addr(struct nbl_pci_f *rf, u32 qp_num,
				 struct nbl_ctx_hmc_base_info *hmc_info,
				 struct nbl_hmc_obj_sd_info *qp_sd_info);
int nbl_check_qp_state(struct nbl_qp *qp, enum ib_qp_state ibst,
				struct nbl_qp_ctx *ctx_info);
void nbl_flush_operation(struct nbl_qp *qp, struct nbl_device *nbldev);
int nbl_get_mtu(struct nbl_qp_ctx *ctx_info,
			      struct nbl_device *nbldev, enum ib_mtu user_mtu);
void nbl_check_srp_ext_bmp_en(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info);
int nbl_dv_modify_qp_to_err(struct nbl_qp *qp);
int nbl_get_qp_num(struct nbl_qp *qp);
void nbl_free_qp_num(struct nbl_pci_f *rf, u32 qp_num);
int nbl_rts_set_irq_size(u32 qp_max_rd_atom, u32 qp_max_dest_rd_atom, struct nbl_qp_ctx *ctx_info);
void nbl_rtr_set_irq_size(u32 qp_max_dest_rd_atom, struct nbl_qp_ctx *ctx_info);
#endif /* NBL_IB_QP_H */
