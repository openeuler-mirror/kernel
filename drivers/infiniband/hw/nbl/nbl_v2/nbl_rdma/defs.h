/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_DEFS_V2_H
#define NBL_IB_DEFS_V2_H

#include "shared.h"
#include "nbl_bit_op.h"
#include "nbl_cqp_fmt_v2.h"
#include "nbl_error_code_v2.h"

#define NBL_QPN_MASK 0x1ffffff /* QPN mask */
#define NBL_CQN_MASK 0x3ffffff /* CQN mask */

#define NBL_LEVEL0_PAGE_MODE 0
#define NBL_LEVEL1_PAGE_MODE 1
#define NBL_AEQ_ALIGNMENT 0x1000
#define NBL_CEQ_ALIGNMENT 0x1000 /*52 bit addr ,low 12bit is 0*/
#define NBL_QP_ALIGNMENT 0X1000 /*52 bit addr ,low 11bit is 0*/

/*FLUSH WQE wait time*/
#define FLUSH_TIME_OUT 500
#define MODIFY_QP_ERR_TIME_OUT 20

#define NBL_CQE_QTYPE_RQ 0
#define NBL_CQE_QTYPE_SQ 1

/* CQ shadowarea*/
#define NBL_CQ_SHADOWAREA_CI GENMASK_ULL(14, 0)
#define NBL_CQ_SHADOWAREA_CI_PHASE BIT_ULL(15)
#define NBL_CQ_SHADOWAREA_SCNT GENMASK_ULL(17, 16) /* resize sw select cnt */

/* CQE BYTE0-7 */
#define NBL_CQ_VALID FIELD_LOC(0, 63, 63)
#define NBL_CQ_SQ FIELD_LOC(0, 62, 62)
#define NBL_CQ_ERROR FIELD_LOC(0, 61, 61)
#define NBL_CQ_SOEVENT FIELD_LOC(0, 60, 60)
#define NBL_CQ_MKEY_VALID FIELD_LOC(0, 59, 59)
#define NBL_CQ_IMMVALID FIELD_LOC(0, 58, 58)
#define NBL_CQ_OP FIELD_LOC(0, 39, 32)
#define NBL_CQ_PAYLDLEN FIELD_LOC(0, 31, 0)

/* CQE BYTE8-15 */
#define NBL_CQ_SRQ_SUBID FIELD_LOC(8, 31, 24)
#define NBL_CQ_SRQN FIELD_LOC(8, 23, 0)
#define NBL_CQ_V1_MARK_INVALID FIELD_LOC(8, 63, 0)
#define NBL_CQ_V1_MARK_INVALID_VAL 0xffffffffffffffff

/* CQE BYTE16-23 */
#define NBL_CQ_QPN FIELD_LOC(16, 55, 32)
#define NBL_CQ_V2_MARK_INVALID FIELD_LOC(16, 56, 56) /* TODO, check */
#define NBL_CQ_V2_MARK_INVALID_VAL 1

/* CQE BYTE24-31 */
#define NBL_CQ_MAJOR_ERROR FIELD_LOC(24, 55, 48)
#define NBL_CQ_WQEIDX_PHASE FIELD_LOC(24, 47, 47)
#define NBL_CQ_WQEIDX FIELD_LOC(24, 46, 32)
#define NBL_CQ_INVMKEY FIELD_LOC(24, 31, 0)
#define NBL_CQ_IMMDATA FIELD_LOC(24, 31, 0)

/* CQE BYTE32-39, ud */
/* CQE BYTE40-47, rsvd */
/* CQE BYTE48-55, rsvd */
/* CQE BYTE56-63, rsvd */

/* UD-CQE BYTE0-7 */
#define NBL_CQ_UDVALID FIELD_LOC(0, 57, 57)
#define NBL_CQ_IPV4 FIELD_LOC(0, 56, 56)
#define NBL_CQ_UDVLANVALID FIELD_LOC(0, 55, 55)

/* UD-CQE BYTE16-23 */
#define NBL_CQ_UDSRCQPN FIELD_LOC(16, 23, 0)

/* UD-CQE BYTE 32-39 */
#define NBL_CQ_UDVLAN FIELD_LOC(32, 63, 48)
#define NBL_CQ_UDSMAC FIELD_LOC(32, 47, 0)

/* Version1
 * for every vf, use 3 msix_vec
 * indx 0 for AEQ, idx 1,2 for CEQ
 */
#define NBL_MSIX_ID_AEQ 0
#define NBL_MSIX_ID_CEQ_BASE 1

#define NBL_MAX_IRQ_NAME (32)

/* AE Source*/
enum nbl_ae_source {
	NBL_AE_SOURCE_QP,
	NBL_AE_SOURCE_CQ,
	NBL_AE_SOURCE_CEQ,
	NBL_AE_SOURCE_AEQ,
	NBL_AE_SOURCE_RAQ,
	NBL_AE_SOURCE_CQP,
	NBL_AE_SOURCE_SRQ,
	NBL_AE_SOURCE_XRC,
};

/* AEQE format */
#define NBL_AEQE_VALID BIT_ULL(63)
#define NBL_AEQE_SEQ_NUM GENMASK_ULL(53, 48)
#define NBL_AEQE_AECODE GENMASK_ULL(47, 40)
#define NBL_AEQE_WQE_CMD_IDX GENMASK_ULL(39, 24)
#define NBL_AEQE_QP_CQ_CEQ_ID GENMASK_ULL(23, 0)
#define NBL_AEQE_CQ_CTX GENMASK_ULL(63, 0)
#define NBL_AEQE_QP_SEQ_MASK 0x3F

/* CQP WQE FORMAT */

/* CQP query cache */
#define NBL_CACHE_DUMP_CQP_MASK 0x80000000
#define NBL_CACHE_KEY_BASE_SIZE 16
/* QPC cache define */
#define NBL_CACHE_QPCC_DATA_MASK 0x00000001
#define NBL_CACHE_QPCC_CC_DATA_MASK 0x10000000
#define NBL_CACHE_QPCC_FIELDS_MASK 0x20000000
#define NBL_CACHE_QPCC_QCN_DATA_MASK 0x40000000
#define NBL_CACHE_QPCC_FIELDS_QPN_MASK 0x3FFFF
#define NBL_CACHE_QPCC_FIELDS_VFID_MASK 0x3F
#define NBL_CACHE_QPCC_SIZE 512
#define NBL_CACHE_QPCC_DEEP_V5 1024
#define NBL_CACHE_QPCC_DEEP_V4 512
#define NBL_CACHE_QPCC_DEEP_V3 256
#define NBL_CACHE_QPCC_DEEP_V2 128
#define NBL_CACHE_QPCC_NUM_ONCE 8
#define NBL_CACHE_QPCC_KEY_VLD_IX_V3 2
#define NBL_CACHE_QPCC_KEY_VLD_MSK_V3 0x08
#define NBL_CACHE_QPCC_KEY_VLD_IX_V2 3
#define NBL_CACHE_QPCC_KEY_VLD_MSK_V2 0x08
#define NBL_CACHE_QPCC_KEY_QPN_SHIFT_V2 4 /* ASIC V2 */
#define NBL_CACHE_QPCC_KEY_QPN_SHIFT_V34 12 /* DF200 && RNIC400*/

#define NBL_CACHE_QPCC_KEY_QPN_MASK_V2 0xFFFFF /* ASIC V2 */
#define NBL_CACHE_QPCC_KEY_QPN_MASK_V34 0x3FFFF /* DF200 && RNIC400*/

#define NBL_CACHE_QPCC_KEY_VFID_SHIFT_V2 24 /* ASIC V2 */
#define NBL_CACHE_QPCC_KEY_VFID_SHIFT_V34 30 /* DF200 && RNIC400*/

/* CQC cache define */
#define NBL_CACHE_CQCC_DATA_MASK 0x00000001
#define NBL_CACHE_CQCC_SIZE 64
#define NBL_CACHE_CQCC_DEEP_V4 512
#define NBL_CACHE_CQCC_DEEP_V3 256
#define NBL_CACHE_CQCC_DEEP_V2 128
#define NBL_CACHE_CQCC_NUM_ONCE 32
#define NBL_CACHE_CQCC_KEY_VLD_IX_V3 2
#define NBL_CACHE_CQCC_KEY_VLD_MSK_V3 0x04
#define NBL_CACHE_CQCC_KEY_VLD_IX_V2 3
#define NBL_CACHE_CQCC_KEY_VLD_MSK_V2 0x04
/* MRTE cache define */
#define NBL_CACHE_MRTE_DATA_MASK 0x00000001
#define NBL_CACHE_MRTE_MKEY_DUMP_MASK 0x10000000
#define NBL_CACHE_MRTE_SIZE_V2 64
#define NBL_CACHE_MRTE_DEEP_V4 512
#define NBL_CACHE_MRTE_DEEP_V3 256
#define NBL_CACHE_MRTE_DEEP_V2 128
#define NBL_CACHE_MRTE_NUM_ONCE 32
#define NBL_CACHE_MRTE_KEY_VLD_IX_V3 3
#define NBL_CACHE_MRTE_KEY_VLD_MSK_V3 0x20
#define NBL_CACHE_MRTE_KEY_VLD_IX 3
#define NBL_CACHE_MRTE_KEY_VLD_IX_V2 4
#define NBL_CACHE_MRTE_KEY_VLD_MSK_V2 0x80
/* SRQC cache define */
#define NBL_CACHE_SRQC_DATA_MASK 0x00000001
#define NBL_CACHE_SRQC_SIZE 64
#define NBL_CACHE_SRQC_DEEP 128
#define NBL_CACHE_SRQC_NUM_ONCE 32
#define NBL_CACHE_SRQC_KEY_VLD_IX 2
#define NBL_CACHE_SRQC_KEY_VLD_MSK 0x20
#define NBL_CACHE_SRQC_KEY_VLD_IX_V2 3
#define NBL_CACHE_SRQC_KEY_VLD_MSK_V2 0x20
/* PBLE cache define */
#define NBL_CACHE_PBLE_DATA_MASK 0x00000001
#define NBL_CACHE_PBLE_SIZE_V2 64
#define NBL_CACHE_PBLE_DEEP_V4 512
#define NBL_CACHE_PBLE_DEEP_V3 256
#define NBL_CACHE_PBLE_DEEP_V2 128
#define NBL_CACHE_PBLE_NUM_ONCE 32
#define NBL_CACHE_PBLE_KEY_VLD_IX_V3 3
#define NBL_CACHE_PBLE_KEY_VLD_MSK_V3 0x02
#define NBL_CACHE_PBLE_KEY_VLD_IX_V2 4
#define NBL_CACHE_PBLE_KEY_VLD_MSK_V2 0x08
/* SQRQE cache define */
#define NBL_CACHE_SQRQE_DATA_MASK 0x00000001
#define NBL_CACHE_SQRQE_SIZE 128
#define NBL_CACHE_SQRQE_DEEP_V2 256
#define NBL_CACHE_SQRQE_DEEP_V4 512
#define NBL_CACHE_SQRQE_NUM_ONCE 8
#define NBL_CACHE_SQRQE_KEY_VLD_IX_V4 13
#define NBL_CACHE_SQRQE_KEY_VLD_MSK_V4 0x20
#define NBL_CACHE_SQRQE_KEY_VLD_IX_V3 11
#define NBL_CACHE_SQRQE_KEY_VLD_MSK_V3 0x80
#define NBL_CACHE_SQRQE_KEY_VLD_IX_V2 14
#define NBL_CACHE_SQRQE_KEY_VLD_MSK_V2 0x20
/* IRQE cache define, V2 is iorqec */
#define NBL_CACHE_IRQE_DATA_MASK 0x00000001
#define NBL_CACHE_IRQE_SIZE 32
#define NBL_CACHE_IRQE_DEEP 256
#define NBL_CACHE_IRQE_DEEP_V4 512
#define NBL_CACHE_IRQE_NUM_ONCE 32
#define NBL_CACHE_IRQE_KEY_VLD_IX 11
#define NBL_CACHE_IRQE_KEY_VLD_MSK_V4 0x20
#define NBL_CACHE_IRQE_KEY_VLD_MSK_V3 0x40
#define NBL_CACHE_IRQE_KEY_VLD_IX_V2 12
#define NBL_CACHE_IRQE_KEY_VLD_MSK_V2 0x40
/* RAQE cache define */
#define NBL_CACHE_RAQE_DATA_MASK 0x00000001
#define NBL_CACHE_RAQE_SIZE 32
#define NBL_CACHE_RAQE_DEEP 1024
#define NBL_CACHE_RAQE_DEEP_V2 256
#define NBL_CACHE_RAQE_DEEP_V4 512
#define NBL_CACHE_RAQE_DEEP_V5 1024
#define NBL_CACHE_RAQE_NUM_ONCE 32
#define NBL_CACHE_RAQE_KEY_VLD_IX 11
#define NBL_CACHE_RAQE_KEY_VLD_MSK_V3 0x10
#define NBL_CACHE_RAQE_KEY_VLD_IX_V2 12
#define NBL_CACHE_RAQE_KEY_VLD_MSK_V2 0x10
/* ORQEC cache define, V2 is iorqec */
#define NBL_CACHE_ORQE_DATA_MASK 0x00000001
#define NBL_CACHE_ORQE_SIZE 32
#define NBL_CACHE_ORQE_DEEP 256
#define NBL_CACHE_ORQE_DEEP_V4 512
#define NBL_CACHE_ORQE_DEEP_V5 1024
#define NBL_CACHE_ORQE_NUM_ONCE 32
#define NBL_CACHE_ORQE_KEY_VLD_IX 11
#define NBL_CACHE_ORQE_KEY_VLD_MSK_V3 0x20
#define NBL_CACHE_ORQE_KEY_VLD_IX_V2 12
#define NBL_CACHE_ORQE_KEY_VLD_MSK_V2 0x40
/* UNAQE cache define */
#define NBL_CACHE_UNAQ_DATA_MASK 0x00000001
#define NBL_CACHE_UNAQ_SIZE 8
#define NBL_CACHE_UNAQ_DEEP 512
#define NBL_CACHE_UNAQ_DEEP_V2 256
#define NBL_CACHE_UNAQ_NUM_ONCE 8
#define NBL_CACHE_UNAQ_KEY_VLD_IX 11
#define NBL_CACHE_UNAQ_KEY_VLD_MSK_V4 0x04
#define NBL_CACHE_UNAQ_KEY_VLD_MSK_V3 0x10
#define NBL_CACHE_UNAQ_KEY_VLD_IX_V2 12
#define NBL_CACHE_UNAQ_KEY_VLD_MSK_V2 0x10
/* PD cache define only for RNIC400 */
#define NBL_CACHE_PD_DATA_MASK 0x00000001
#define NBL_CACHE_PD_SIZE 32
#define NBL_CACHE_PD_DEEP 512
#define NBL_CACHE_PD_DEEP_V2 128
#define NBL_CACHE_PD_DEEP_V3 256
#define NBL_CACHE_PD_NUM_ONCE 32
#define NBL_CACHE_PD_KEY_VLD_IX 12
#define NBL_CACHE_PD_KEY_VLD_MSK 0x20

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
 * write64_reg - write 64 bit value to reg
 * @val: value to be write
 * @dest: addr to write
 **/
static inline void write64_reg(u64 val, void __iomem *dest)
{
#ifdef CONFIG_64BIT
	writeq(val, dest);
#else
	writel((u32)val, dest);
	writel((u32)(val >> 32), dest + 4);
#endif
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

#define NBL_RING_INIT(_ring, _size)                                            \
	{                                                                      \
		(_ring).head = 0;                                              \
		(_ring).tail = 0;                                              \
		(_ring).size = (_size);                                        \
	}

#endif /* NBL_IB_DEFS_H */
