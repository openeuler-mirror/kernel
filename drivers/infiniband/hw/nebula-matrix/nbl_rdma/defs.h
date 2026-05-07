/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_DEFS_H
#define NBL_IB_DEFS_H

#define NBL_QPN_MASK 0x1ffffff /* QPN mask */
#define NBL_CQN_MASK 0x3ffffff /* CQN mask */

#define NBL_QP_USE_12K_PD_SIZE 12288 /*sqrq together use 12K*/
#define NBL_QP_USE_8K_PD_SIZE 8192   /*sq use 8k rq use 8k*/

#define NBL_LEVEL0_PAGE_MODE 0
#define NBL_LEVEL1_PAGE_MODE 1
#define NBL_AEQ_ALIGNMENT 0x1000
#define NBL_CEQ_ALIGNMENT 0x1000 /*52 bit addr ,low 12bit is 0*/
#define NBL_QP_ALIGNMENT 0X1000 /*52 bit addr ,low 11bit is 0*/

/*FLUSH WQE wait time*/
#define FLUSH_TIME_OUT 500


#define NBL_CQE_QTYPE_RQ 0
#define NBL_CQE_QTYPE_SQ 1

/* CQ shadowarea*/
#define NBL_CQ_SHADOWAREA_CI GENMASK_ULL(14, 0)
#define NBL_CQ_SHADOWAREA_CI_PHASE BIT_ULL(15)

/* CQE BYTE0-7 */
#define NBL_CQ_VALID BIT_ULL(63)
#define NBL_CQ_SQ BIT_ULL(62)
#define NBL_CQ_ERROR BIT_ULL(61)
#define NBL_CQ_SOEVENT BIT_ULL(60)
#define NBL_CQ_MKEY_VALID BIT_ULL(59)
#define NBL_CQ_IMMVALID BIT_ULL(58)
#define NBL_CQ_OP GENMASK_ULL(39, 32)
#define NBL_CQ_PAYLDLEN GENMASK_ULL(31, 0)

/* CQE BYTE8-15 */
/* QP compltion context */
#define NBL_CQ_CTX_INVALID BIT_ULL(63)
#define NBL_CQ_CTX_QPN GENMASK_ULL(23, 0)

/* CQE BYTE16-23 */
#define NBL_CQ_QPN GENMASK_ULL(55, 32)

/* CQE BYTE24-31 */
#define NBL_CQ_MAJOR_ERROR GENMASK_ULL(63, 48)
#define NBL_CQ_WQEIDX GENMASK_ULL(46, 32)
#define NBL_CQ_INVMKEY GENMASK_ULL(31, 0)
#define NBL_CQ_IMMDATA GENMASK_ULL(31, 0)

/* CQE BYTE32-39, ud */
/* CQE BYTE40-47, rsvd */
/* CQE BYTE48-55, rsvd */
/* CQE BYTE56-63, rsvd */

/* UD-CQE BYTE0-7 */
#define NBL_CQ_UDVALID BIT_ULL(57)
#define NBL_CQ_IPV4 BIT_ULL(56)
#define NBL_CQ_UDVLANVALID BIT_ULL(55)

/* UD-CQE BYTE16-23 */
#define NBL_CQ_UDSRCQPN GENMASK_ULL(23, 0)

/* UD-CQE BYTE 32-39 */
#define NBL_CQ_UDVLAN GENMASK_ULL(63, 48)

/* Version1
 * for every vf, use 3 msix_vec
 * indx 0 for AEQ, idx 1,2 for CEQ
 */
#define NBL_MSIX_ID_AEQ 0
#define NBL_MSIX_ID_CEQ_BASE 1

#define NBL_MAX_IRQ_NAME (32)

#define NBL_ERR_IS_TXP_ERRCQE(err)					\
	(((err) == NBL_ERR_SQ_INVALID_OPCODE) ||		\
	((err) == NBL_ERR_SQ_PSN_ERR_RETRY) ||			\
	((err) == NBL_ERR_SQ_RTO_RETRY))

#define NBL_ERR_IS_TXMR_ERRCQE(err)					\
	(((err) == NBL_ERR_TXMR_FMR_DISABLE) ||			\
	(((err) >= NBL_ERR_TXMR_INDEX_ERR) &&			\
	((err) <= NBL_ERR_TXMR_BIND_BDY_ERR)))

#define NBL_ERR_SQ_DRAINED			0x7A
#define NBL_ERR_QP_FLUSH_ERR		0x7E /* for SQ and RQ flush */
#define NBL_ERR_CQ_LOAD_DIFF		0x7F
#define NBL_ERR_CQP_EXEC_RESP		0x80
#define NBL_ERR_CQP_FATAL			0x81
#define NBL_ERR_CEQ_OVERFLOW		0x82
#define NBL_ERR_CEQ_LOAD_PAGE		0x83
#define NBL_ERR_AEQ_OVERFLOW		0x84
#define NBL_ERR_AEQ_LOAD_PAGE		0x85

#define NBL_ERR_MAX_AEID			0x90

/* AE Source*/
enum nbl_ae_source {
	NBL_AE_SOURCE_QP,
	NBL_AE_SOURCE_CQ,
	NBL_AE_SOURCE_CEQ,
	NBL_AE_SOURCE_AEQ,
	NBL_AE_SOURCE_RAQ,
	NBL_AE_SOURCE_CQP,
};

/* Hardware Error Codes(all in one),
 * TODO, check each error code and change to NBL_ERR_
 */
#define NBL_ERR_DEST_QPN 0x2
#define NBL_ERR_CACHE_FLAG 0x3
#define NBL_ERR_INV_QPC 0x4
#define NBL_ERR_PDPA 0x5
#define NBL_ERR_TVER 0x8
#define NBL_ERR_SERVICE_TYPE 0x9
#define NBL_ERR_QPC_STATE 0xA
#define NBL_ERR_RX_PKT_QPC_MR_ERR 0xB
#define NBL_ERR_RX_PKT_ERR_RC_OPCODE 0xC /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_UD_OPCODE 0xD /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_ATOMIC_BYTE_ALIGN 0xE /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_OAQ_PI_CI 0xF /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_RESPONER_SEND_REQ_OPCODE 0x10 /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_WRITE_OPCODE 0x11 /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_SEND_REQ_OPCODE 0x12 /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_WRITE_REQ_OPCODE 0x13 /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_WRITE_PKT_LEN 0x14 /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_PKT_LEN 0x15 /* RXP packet*/
#define NBL_ERR_RX_PKT_ERR_HW_FLAG 0x16 /* RXP packet*/
#define NBL_ERR_RX_PKT_RECV_OPCODE_IN_RNR 0x17 /* RXP packet*/
#define NBL_ERR_RX_PKT_REQ_PKT_LEN_ERR 0x1A /* RXP packet */
#define NBL_ERR_RX_UD_RQE_ERR 0x1B /* RXP packet */
#define NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_OVERFLOW 0x1C /* RXP packet */
#define NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_ILLEGAL 0x1D /* RXP packet */
#define NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_TOOLONG 0x1E /* RXP packet */
#define NBL_ERR_RX_PKT_READ_RESP_OPCODE_OUT_ORDER 0x1F /* RXP packet */
#define NBL_ERR_RX_PKT_SEND_WRITE_REPEAT 0x20 /* RXP packet */
#define NBL_ERR_RX_PKT_READ_ATOMIC_REPEAT_WITH_ACK 0x21 /* RXP packet */
#define NBL_ERR_RX_PKT_READ_ATOMIC_REPEAT_NO_ACK 0x22 /* RXP packet */
#define NBL_ERR_RX_PKT_LOST_REQ 0x23 /* RXP packet */
#define NBL_ERR_RX_PKT_ERR_GOST_ACK 0x28 /* RXP packet */
#define NBL_ERR_RX_PKT_REPEAT_RESP 0x29 /* RXP packet */
#define NBL_ERR_RX_PKT_RECV_ACK_NEED_RAQ 0x2A /* RXP packet */
#define NBL_ERR_RX_PKT_LOST_RSP_NEED_RAQ 0x2B /* RXP packet */
#define NBL_ERR_RX_PKT_RECV_NACK_PSN_ERR_NEED_RAQ 0x2D /* RXP packet */
#define NBL_ERR_RX_PKT_RECV_NACK_RNR_NAK_NEED_RAQ 0x2E /* RXP packet */
#define NBL_ERR_RX_PKT_OUT_OF_ORDER 0x2F /* RXP packet */
#define NBL_ERR_RX_RESP_RECV_NOT_PSN_SEQ_ERR_NAK 0x30 /* RXP packet */
#define NBL_ERR_RNR_RETRY 0x31
#define NBL_ERR_NAK_NOT_PSN_ERR1 0x33
#define NBL_ERR_NAK_NOT_PSN_ERR2 0x34
#define NBL_ERR_NAK_NOT_PSN_ERR3 0x35
#define NBL_ERR_NAK_NOT_PSN_ERR4 0x36

#define NBL_ERR_RX_MR_INDEX_ILLEGAL 0x38 /* RXMR */
#define NBL_ERR_RX_MR_INVALID 0x39 /* RXMR */
#define NBL_ERR_RX_MR_KEY_ILLEGAL 0x3A /* RXMR */
#define NBL_ERR_RX_PD_MISS_MATCH 0x3B /* RXMR */
#define NBL_ERR_RX_ACCESS_RIGHT_CHECK_ERR 0x3C /* RXMR */
#define NBL_ERR_RX_BOUNDARY_CHECK_ERR 0x3D /* RXMR */
#define NBL_ERR_RX_REMOTE_INV_PERMISSION_CHK_ERR 0x3E /* RXMR */
#define NBL_ERR_RX_REMOTE_INV_WITH_MW_STILL_BIND 0x3F /* RXMR */
#define NBL_ERR_RX_REMOTE_INV_TO_TYPE1_MW 0x40 /* RXMR */
#define NBL_ERR_RX_MR_REQ_ERR 0x41 /* RXMR */
#define NBL_ERR_RX_MR_RESP_ERR 0x42 /* RXMR */
#define NBL_ERR_RX_MR_MRTC_ERR 0x43 /* RXMR */
#define NBL_ERR_RX_MR_PBLC_INV 0x44 /* RXMR */

#define NBL_ERR_RAQ_OVERFLOW 0x48
#define NBL_ERR_RAQP_DROP_PKT 0x49

#define NBL_ERR_SQ_FLUSH_COMPLETE	0x4A
#define NBL_ERR_RQ_FLUSH_COMPLETE	0x4B
#define NBL_ERR_SQ_RQ_LOAD_DIFF		0x4C
#define NBL_ERR_SQ_RQ_LOAD_CNT		0x4D
#define NBL_ERR_ARM_CQ_OVERFLOW		0x4E
#define NBL_ERR_CQ_OVERFLOW			0x4F
#define NBL_ERR_SQ_INVALID_OPCODE	0x55 /* txp err */
#define NBL_ERR_SQ_PSN_ERR_RETRY	0x57 /* txp err */
#define NBL_ERR_SQ_RTO_RETRY		0x5B /* txp err */

#define NBL_ERR_TXMR_INDEX_ERR		0x60 /* txmr err */
#define NBL_ERR_TX_MR_INVALID 0x61
#define NBL_ERR_TX_MR_KEY_ILLEGAL 0x62
#define NBL_ERR_TX_PD_MISS_MATCH 0x63
#define NBL_ERR_TX_ACCESS_RIGHT_CHECK_ERR 0x64
#define NBL_ERR_TX_BOUNDARY_CHECK_ERR 0x65
#define NBL_ERR_TX_LOCAL_INV_TO_TYPE1_MW 0x66
#define NBL_ERR_TX_REMOTE_INV_WITH_MW_STILL_BIND 0x67
#define NBL_ERR_TX_MR_BIND_INV_MR 0x68
#define NBL_ERR_TX_MR_BIND_INV_MW 0x69
#define NBL_ERR_TX_MR_BIND_KEY_BUT_FIND_MW 0x6A
#define NBL_ERR_TX_MR_BIND_KEY_BUT_FIND_MR 0x6B
#define NBL_ERR_TX_MR_BIND_INV_MR_TYPE 0x6C
#define NBL_ERR_TX_MR_BIND_INV_MW_TYPE 0x6D
#define NBL_ERR_TX_MR_BIND_MR_ZERO_BASE 0x6E
#define NBL_ERR_TX_MR_BIND_PD_INV 0x6F
#define NBL_ERR_TX_MR_BIND_RIGHT_INV 0x70
#define NBL_ERR_TXMR_BIND_BDY_ERR	0x71 /* txmr err */
#define NBL_ERR_TX_MR_REQ_ERR 0x72
#define NBL_ERR_TX_MR_RESP_ERR 0x73
#define NBL_ERR_TX_MR_MRTC_ERR 0x74
#define NBL_ERR_TX_MR_PBLC_INV 0x75
#define NBL_ERR_TXMR_FMR_DISABLE	0x76 /* txmr err */

#define NBL_ERR_TXP_SQ_OP_INV 0x52
#define NBL_ERR_TXP_SQ_INV_OPCODE 0x53
#define NBL_ERR_TXP_SQ_WQE_INV 0x54
#define NBL_ERR_TXP_RAQ_TIMEOUT 0x55
#define NBL_ERR_TXP_RNR_TIMEOUT 0x56

/* AEQE format */
#define NBL_AEQE_VALID BIT_ULL(63)
#define NBL_AEQE_AECODE GENMASK_ULL(47, 40)
#define NBL_AEQE_WQE_CMD_IDX GENMASK_ULL(39, 24)
#define NBL_AEQE_QP_CQ_CEQ_ID GENMASK_ULL(23, 0)
#define NBL_AEQE_CQ_CTX GENMASK_ULL(63, 0)

/* CQP WQE FORMAT */
#define NBL_CQP_PM_0_CONTINUS 0
#define NBL_CQP_PM_1_UNCONTINUS 1

#define NBL_CQPSQ_OPCODE GENMASK_ULL(52, 48)

#define NBL_CQP_QP_TYPE GENMASK_ULL(47, 44)
#define NBL_CQP_QP_NEXT_STATE GENMASK_ULL(43, 40)
#define NBL_CQP_QP_MODIFY_EPSN BIT_ULL(39)
#define NBL_CQP_QP_MODIFY_PSNMAX BIT_ULL(38)
#define NBL_CQP_QP_NUM GENMASK_ULL(23, 0)
#define NBL_CQP_QP_CTX_ADDR GENMASK_ULL(63, 0)
#define NBL_CQP_QP_EPSN GENMASK_ULL(63, 40)
#define NBL_CQP_QP_PSNMAX GENMASK_ULL(39, 16)

/* CQP FLUSH WQE */
#define NBL_CQP_QP_SQEN BIT_ULL(47)
#define NBL_CQP_QP_RQEN BIT_ULL(46)
#define NBL_CQP_OP_HOST_ID GENMASK_ULL(47, 45)
#define NBL_CQP_OP_VF_ID GENMASK_ULL(44, 36)
#define NBL_CQP_OP_FLUSH_QPN GENMASK_ULL(35, 12)

/* CQP FLUSH CACHE */
#define NBL_CQP_FLUASH_CACHE_TYPE GENMASK_ULL(47, 46)
#define NBL_CQP_FLUASH_CACHE_QPN GENMASK_ULL(45, 28)
#define NBL_CQP_FLUASH_CACHE_VFID GENMASK_ULL(8, 0)

/* CQP CQ */
#define NBL_CQPSQ_CQ_STAT GENMASK_ULL(47, 46)
#define NBL_CQPSQ_CQ_CQSIZE GENMASK_ULL(45, 42)
#define NBL_CQPSQ_CQ_CQID GENMASK_ULL(40, 22)
#define NBL_CQPSQ_CQ_CEQID BIT_ULL(21)
#define NBL_CQPSQ_CQ_QP_REF BIT_ULL(20)
#define NBL_CQPSQ_CQ_PS GENMASK_ULL(19, 18)
#define NBL_CQPSQ_CQ_SHADOWTH GENMASK_ULL(13, 0)
#define NBL_CQPSQ_CQ_CONTEXT GENMASK_ULL(63, 0)
#define NBL_CQPSQ_CQ_BASEADDR GENMASK_ULL(51, 0)
#define NBL_CQPSQ_CQ_CUR_ADDR GENMASK_ULL(51, 0)
#define NBL_CQPSQ_CQ_NXT_ADDR GENMASK_ULL(51, 0)
#define NBL_CQ_CQC_BASE_ADDR_SHIFT 6 /* CQC base addr low 6 bit all 0 */
#define NBL_CQPSQ_CQ_CQC_BASE_ADDR GENMASK_ULL(57, 0)
#define NBL_CQPSQ_CQ_UPLOAD_ADDRESS GENMASK_ULL(63, 0)

/*CQP ArmCQ*/
#define NBL_CQPSQ_ARMCQ_CQN GENMASK_ULL(47, 29)
#define NBL_CQPSQ_ARMCQ_CQECI GENMASK_ULL(28, 14)
#define NBL_CQPSQ_ARMCQ_SE BIT_ULL(13)

/* CQP query voa */
#define NBL_CQP_QUERY_VOA_VFID GENMASK_ULL(47, 39)

/* CQP query cache */
#define NBL_CACHE_DUMP_CQP_MASK 0x80000000
#define NBL_CACHE_KEY_BASE_SIZE 16
/* QPC cache define */
#define NBL_CACHE_QPCC_DATA_MASK 0x00000001
#define NBL_CACHE_QPCC_CC_DATA_MASK 0x10000000
#define NBL_CACHE_QPCC_FIELDS_MASK 0x20000000
#define NBL_CACHE_QPCC_FIELDS_QPN_MASK 0x3FFFF
#define NBL_CACHE_QPCC_FIELDS_VFID_MASK 0x3F
#define NBL_CACHE_QPCC_SIZE 512
#define NBL_CACHE_QPCC_DEEP 512
#define NBL_CACHE_QPCC_NUM_ONCE 8
#define NBL_CACHE_QPCC_KEY_VLD_IX 3
#define NBL_CACHE_QPCC_KEY_VLD_MSK 0x80
/* CQC cache define */
#define NBL_CACHE_CQCC_DATA_MASK 0x00000001
#define NBL_CACHE_CQCC_SIZE 64
#define NBL_CACHE_CQCC_DEEP 1024
#define NBL_CACHE_CQCC_NUM_ONCE 32
#define NBL_CACHE_CQCC_KEY_VLD_IX 3
#define NBL_CACHE_CQCC_KEY_VLD_MSK 0x40
/* MRTE cache define */
#define NBL_CACHE_MRTE_DATA_MASK 0x00000001
#define NBL_CACHE_MRTE_MKEY_DUMP_MASK 0x10000000
#define NBL_CACHE_MRTE_SIZE 32
#define NBL_CACHE_MRTE_DEEP 512
#define NBL_CACHE_MRTE_NUM_ONCE 32
#define NBL_CACHE_MRTE_KEY_VLD_IX 3
#define NBL_CACHE_MRTE_KEY_VLD_MSK 0x02
/* PBLE cache define */
#define NBL_CACHE_PBLE_DATA_MASK 0x00000001
#define NBL_CACHE_PBLE_SIZE 16
#define NBL_CACHE_PBLE_DEEP 512
#define NBL_CACHE_PBLE_NUM_ONCE 32
#define NBL_CACHE_PBLE_KEY_VLD_IX 4
#define NBL_CACHE_PBLE_KEY_VLD_MSK 0x20
/* SQRQE cache define */
#define NBL_CACHE_SQRQE_DATA_MASK 0x00000001
#define NBL_CACHE_SQRQE_SIZE 128
#define NBL_CACHE_SQRQE_DEEP 1024
#define NBL_CACHE_SQRQE_NUM_ONCE 8
#define NBL_CACHE_SQRQE_KEY_VLD_IX 13
#define NBL_CACHE_SQRQE_KEY_VLD_MSK 0x80
/* IRQE cache define */
#define NBL_CACHE_IRQE_DATA_MASK 0x00000001
#define NBL_CACHE_IRQE_SIZE 128
#define NBL_CACHE_IRQE_DEEP 256
#define NBL_CACHE_IRQE_NUM_ONCE 8
#define NBL_CACHE_IRQE_KEY_VLD_IX 11
#define NBL_CACHE_IRQE_KEY_VLD_MSK 0x04
/* RAQE cache define */
#define NBL_CACHE_RAQE_DATA_MASK 0x00000001
#define NBL_CACHE_RAQE_SIZE 32
#define NBL_CACHE_RAQE_DEEP 512
#define NBL_CACHE_RAQE_NUM_ONCE 32
#define NBL_CACHE_RAQE_KEY_VLD_IX 11
#define NBL_CACHE_RAQE_KEY_VLD_MSK 0x01

enum nbl_cqp_cache_type {
	NBL_CACHE_QPCC,
	NBL_CACHE_CQCC,
	NBL_CACHE_MRTC,
	NBL_CACHE_IRQEC,
	NBL_CACHE_ORQEC,
	NBL_CACHE_SQRQEC,
	NBL_CACHE_RAQEC,
	NBL_CACHE_PBLC,
	NBL_CACHE_UNAQC,
};
#define NBL_CQP_CACHE_TYPE GENMASK_ULL(47, 44)
#define NBL_CQP_START_INDEX GENMASK_ULL(43, 33)
#define NBL_CQP_KEY_NUM GENMASK_ULL(32, 27)
#define NBL_CQP_UNIT_BNUM GENMASK_ULL(26, 16)

/* CQP SQ opcode*/
#define NBL_CQP_OP_CREATE_QP 0x0
#define NBL_CQP_OP_MODIFY_QP 0x1
#define NBL_CQP_OP_DESTROY_QP 0x2
#define NBL_CQP_OP_QUERY_QP 0x3
#define NBL_CQP_QP_FLUSH_WQE 0x10
#define NBL_CQP_OP_CREATE_CQ 0x4
#define NBL_CQP_OP_MODIFY_CQ 0x5
#define NBL_CQP_OP_DESTROY_CQ 0x6
#define NBL_CQP_OP_QUERY_CQ 0x7
#define NBL_CQP_OP_ALLOC_STAG 0x8
#define NBL_CQP_OP_REG_MR 0x9
#define NBL_CQP_OP_DEALLOC_STAG 0xA
#define NBL_CQP_OP_QUERY_STAG 0xB
#define NBL_CQP_OP_UPDATE_SD 0xC
#define NBL_CQP_OP_QUERY_SD 0xD
#define NBL_CQP_OP_UPDATE_VOA 0xE
#define NBL_CQP_OP_QUERY_VOA 0xF
#define NBL_CQP_OP_CREATE_AEQ 0x11
#define NBL_CQP_OP_DESTROY_AEQ 0x12
#define NBL_CQP_OP_QUERY_AEQ 0x13
#define NBL_CQP_OP_CREATE_CEQ 0x14
#define NBL_CQP_OP_DESTROY_CEQ 0x15
#define NBL_CQP_OP_QUERY_CEQ 0x16
#define NBL_CQP_OP_ARMCQ 0x17
#define NBL_CQP_OP_FLUSH_CACHE 0x18
#define NBL_CQP_OP_QUERY_CACHE 0x19

#define FLUSH_CACHE_SQRQC 1 /* flush sq rq cache */
#define FLUSH_CACHE_PBLC 0 /* flush pblc cache */
#define FLUSH_CACHE_S1 2 /* flush irq,orq,unaq,raq cache */
#define FLUSH_CACHE_S2 3 /* flush qpcc/cqcc/mrtc */

#define NBL_RING_MOVE_HEAD_NOCHECK(_ring)                                      \
	(_ring).head = ((_ring).head + 1) % (_ring).size

#define NBL_RING_MORE_WORK(_ring) ((NBL_RING_USED_QUANTA(_ring) != 0))

#define NBL_RING_SET_TAIL(_ring, _pos) (_ring).tail = (_pos) % (_ring).size

#define NBL_GET_CURRENT_CQ_ELEM(_cq)                                           \
	((_cq)->cq_base[NBL_RING_CURRENT_HEAD((_cq)->cq_ring)].buf)

#define NBL_RING_CURRENT_HEAD(_ring) ((_ring).head)
#define NBL_RING_CURRENT_TAIL(_ring) ((_ring).tail)

#define NBL_RING_GET_NEXT_TAIL(_ring, _idx)                                    \
	(((_ring).tail + (_idx)) % (_ring).size)

#define NBL_RING_MOVE_TAIL(_ring)                                              \
	(_ring).tail = ((_ring).tail + 1) % (_ring).size

#define NBL_RING_SIZE(_ring) ((_ring).size)

#define NBL_GET_CEQ_ELEM_AT_POS(_ceq, _pos) ((_ceq)->ceqe_base[_pos].buf)

#define NBL_GET_CURRENT_AEQ_ELEM(_aeq)                                         \
	((_aeq)->aeqe_base[NBL_RING_CURRENT_TAIL((_aeq)->aeq_ring)].buf)

/**
 * set_64bit_val - set 64 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_64bit_val(__be64 *wqe_words, u32 byte_index, u64 val)
{
	wqe_words[byte_index >> 3] = cpu_to_be64(val);
}

/**
 * set_16bit_val - set 16 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_16bit_val(__be16 *wqe_words, __u32 byte_index, __u16 val)
{
	wqe_words[byte_index >> 1] = cpu_to_be16(val);
}

/**
 * set_32bit_val - set 32 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_32bit_val(__be32 *wqe_words, u32 byte_index, u32 val)
{
	wqe_words[byte_index >> 2] = cpu_to_be32(val);
}

/**
 * get_32bit_val - read 32 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to reaad from
 * @val: return 32 bit value
 **/
static inline void get_32bit_val(__be32 *wqe_words, u32 byte_index, u32 *val)
{
	*val = be32_to_cpu(wqe_words[byte_index >> 2]);
}

/**
 * get_64bit_val - read 64 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to read from
 * @val: read value
 **/
static inline void get_64bit_val(__be64 *wqe_words, u32 byte_index, u64 *val)
{
	*val = be64_to_cpu(wqe_words[byte_index >> 3]);
}

/**
 * write64_reg - write 64 bit value to reg
 * @val: value to be write
 * @dest: addr to write
 **/
static inline void write64_reg(u64 val, void __iomem *dest)
{
	writeq(val, dest);
}

/**
 * read32_reg - read 32 bit value from reg
 * @val: value read pointer, output
 * @dest: addr to read
 **/
static inline void read32_reg(u32 *val, void __iomem *dest)
{
	*val = readl(dest);
}

#define NBL_GET_CURRENT_CEQ_ELEM(_ceq)                                         \
	((_ceq)->ceqe_base[NBL_RING_CURRENT_TAIL((_ceq)->ceq_ring)].buf)

#define NBL_RING_CURRENT_TAIL(_ring) ((_ring).tail)
#define NBL_RING_MOVE_TAIL(_ring)                                              \
	(_ring).tail = ((_ring).tail + 1) % (_ring).size

#define NBL_RING_INIT(_ring, _size)                                            \
	{                                                                      \
		(_ring).head = 0;                                              \
		(_ring).tail = 0;                                              \
		(_ring).size = (_size);                                        \
	}

#endif /* NBL_IB_DEFS_H */
