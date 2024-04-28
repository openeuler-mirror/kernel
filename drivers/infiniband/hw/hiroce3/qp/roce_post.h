/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_POST_H
#define ROCE_POST_H

#include <linux/types.h>

#include <rdma/ib_verbs.h>

#include "roce_wqe_format.h"
#include "roce_xqe_format.h"

#define ROCE_SQ_DB_TYPE 2
#define ROCE_UD_MTU_SHIFT 3 /* 4K mtu */
#define ROCE_IMM_EXT_LEN 4
#define ROCE_TASK_SEG_ALIGN 8

#define ROCE_ATOMIC_WR atomic_wr
#define ROCE_RDMA_WR rdma_wr
#define ROCE_REG_WR reg_wr
#define ROCE_UD_WR ud_wr

enum roce_tsl_8_byte_aligned_size_e {
	ROCE_SEND_LOCAL_WQE_TSL = 2,
	ROCE_RDMA_WQE_TSL = 4,
	ROCE_ATOMIC_CWP_WQE_TSL = 6,
	ROCE_UD_WQE_COM_TSL = 8
};

enum {
	ROCE_WQE_OPCODE_SEND = 0x00,
	ROCE_WQE_OPCODE_SEND_INVAL = 0x01,
	ROCE_WQE_OPCODE_SEND_IMM = 0x02,

	ROCE_WQE_OPCODE_RDMA_WRITE = 0x04,
	ROCE_WQE_OPCODE_RDMA_WRITE_IMM = 0x05,

	ROCE_WQE_OPCODE_RDMA_READ = 0x08,

	ROCE_WQE_OPCODE_ATOMIC_CMP_SWP = 0x0c,
	ROCE_WQE_OPCODE_ATOMIC_FETCH_ADD = 0x0d,
	ROCE_WQE_OPCODE_MASKED_ATOMIC_CMP_SWP = 0x0e,
	ROCE_WQE_OPCODE_MASKED_ATOMIC_FETCH_ADD = 0x0f,

	ROCE_WQE_OPCODE_FRMR = 0x10,
	ROCE_WQE_OPCODE_LOCAL_INVAL = 0x11,
	ROCE_WQE_OPCODE_BIND_MW = 0x12,
	ROCE_WQE_OPCODE_REG_SIG_MR = 0x13 /* Extended for further local opreation */
};

enum {
	ROCE_DWQE_DB_SUBTYPE_SEND = 0x1,
	ROCE_DWQE_DB_SUBTYPE_SEND_IMM = 0x2,
	ROCE_DWQE_DB_SUBTYPE_RDMA_WRITE = 0x3,
	ROCE_DWQE_DB_SUBTYPE_RDMA_WRITE_IMM = 0x4,
	ROCE_DWQE_DB_SUBTYPE_RDMA_READ = 0x5,
	ROCE_DWQE_DB_SUBTYPE_ATOMIC_CMP_SWP = 0x6,
	ROCE_DWQE_DB_SUBTYPE_ATOMIC_FETCH_ADD = 0x7
};

/* UD send WQE task seg1 */
struct roce3_wqe_ud_tsk_seg_cycle1 {
	union roce3_wqe_tsk_com_seg common;

	/* DW0 */
	u32 data_len;

	/* DW1 */
	u32 immdata_invkey;

	/* DW2 */
/*
 *	0: No limit on the static rate (100% port speed)
 *  1-6: reserved
 *  7: 2.5 Gb/s.  8: 10 Gb/s.  9: 30 Gb/s. 10: 5 Gb/s. 11: 20 Gb/s.
 *  12: 40 Gb/s. 13: 60 Gb/s. 14: 80 Gb/s.15: 120 Gb/s.
 */
	union {
		struct {
			u32 pd : 18;
			u32 rsvd0 : 6;
			u32 stat_rate : 4;
			u32 rsvd1 : 3;
			u32 fl : 1;
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
			u32 hop_limit : 8;
			u32 sgid_idx : 7;
			u32 rsvd0 : 1;
			u32 port : 4;
			u32 rsvd1 : 4;
			u32 tc : 8;
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	union {
		struct {
			u32 flow_label : 20;
			u32 rsvd0 : 4;
			u32 smac_index : 3;
			u32 rsvd1 : 5;
		} bs;
		u32 value;
	} dw4;

	/* DW5~8 */
	u8 dgid[16];

	/* DW9 */
	union {
		struct {
			u32 dst_qp : 24;
			u32 rsvd : 8;
		} bs;
		u32 value;
	} dw9;

	/* DW10 */
	u32 qkey;
};

/* UD send WQE task seg2; */
struct roce3_wqe_ud_tsk_seg_cycle2 {
	/* DW0 */
	union {
		struct {
			u32 dmac_h16 : 16;
			u32 vlan_id : 12;
			u32 cfi : 1;
			u32 vlan_prio : 3;
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	u32 dmac_l32;
};

struct roce3_post_send_normal_param {
	struct roce3_wqe_ctrl_seg *ctrl_seg;
	union roce3_wqe_tsk_com_seg *tsk_com_seg;
	u32 wqe_size;
	u8 *wqe;
	struct roce3_wqe_data_seg *dseg;
	union roce_sq_db sq_db;
	u32 wr_num;	  /* record posted WR numbers */
	u32 index;	   /* WQEBB id */
	int inline_flag; /* Inline flag */
	u32 data_len;
	u32 *data_len_addr;
	u32 sq_rmd_size;
	s32 opcode;
	s32 cycle;
	struct roce3_wqe_ctrl_seg ctrl_seg_tmp;

	unsigned long flags;
};

#endif /* ROCE_POST_H */
