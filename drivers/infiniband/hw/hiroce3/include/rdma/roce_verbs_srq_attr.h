/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_SRQ_ATTR_H
#define ROCE_VERBS_SRQ_ATTR_H

#include "roce_verbs_mr_attr.h"

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#pragma pack(4)
struct tag_roce_verbs_srq_cont_attr {
	/* DW0 */
	u32 head_gpa_h;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 head_gpa_l : 20;
			u32 rsvd : 11;
			u32 head_gpa_vld : 1;
#else
			u32 head_gpa_vld : 1;
			u32 rsvd : 11;
			u32 head_gpa_l : 20;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cont_size : 2;
			u32 rsvd : 10;
			u32 warn_th : 4;
			u32 head_idx : 16;
#else
			u32 head_idx : 16;
			u32 warn_th : 4;
			u32 rsvd : 10;
			u32 cont_size : 2;
#endif
		} bs;
		u32 value;
	} dw2;
};

struct tag_roce_verbs_srq_attr {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 xrcd : 16;
			u32 mtt_page_size : 4;
			u32 wqebb_size : 3;
			u32 page_size : 4;
			u32 size : 5;
#else
			/*
			 * Shared Receive Queue size, equals to (2^srq_size)*WQEBB,
			 * the maximum SRQ size is 16K WQEs, so this field doesn't exceed 14.
			 */
			u32 size : 5;
			/* Page size of SRQ, equals to (2^srq_page_size)*4KB */
			u32 page_size : 4;
			/*
			 * Shared Receive WQE Basic Block (WQEBB) size in bytes
			 * is (2^rq_wqebb_size)*16B.
			 * The minimum size is 32B and the values 0, 4, 5, 6, 7 are reserved
			 */
			u32 wqebb_size : 3;
			/* Page size of MTT for SRQ, equals to (2^srq_mtt_page_size)*4KB. */
			u32 mtt_page_size : 4;
			u32 xrcd : 16;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 state : 4;
			u32 rsvd : 14;
			u32 ep : 3;
			u32 cos : 3;
			u32 so_ro : 2;
			u32 dma_attr_idx : 6;
#else
			/*
			 * It specifies the outbound PCIe TLP header attribute of the
			 * DMA operation.This filed is only valid when processing CQ's CQEs.
			 */
			u32 dma_attr_idx : 6;
			/* It specifies the ATTR[1:0] bits in the outbound PCIe TLP headers
			 * of the DMA operation.This field is only valid when processing
			 * CQ's CQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 */
			u32 so_ro : 2;
			u32 cos : 3;
			u32 ep : 3;
			u32 rsvd : 14;
			u32 state : 4;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 wqe_prefetch_max_num : 3;
			u32 wqe_prefetch_min_num : 3;
			u32 wqe_cache_thd_sel : 2;
			u32 wqecnt_lth : 4;
			u32 wqecnt_ctrl_en : 1;
			u32 wqecnt_rctl : 1;
			u32 mtt_prefetch_maxlen : 2;
			u32 next_wqe_idx : 16;
#else
			/*
			 * The current WQE index; uses this field to get
			 * the corresponding WQE from SRQ.
			 */
			u32 next_wqe_idx : 16;
			u32 mtt_prefetch_maxlen : 2;
			/*
			 * The hardware clear it to zero when performing a SRQ PCnt updating,
			 * and driver set it to one to indicate the hardware can performing
			 * SRQ PCnt updating.
			 */
			u32 wqecnt_rctl : 1;
			u32 wqecnt_ctrl_en : 1;
			u32 wqecnt_lth : 4;
			/*
			 * Maximum length of prefetch MTTs for SRQ.
			 * 000: prefetch length equals to zero;
			 * Others: prefetch length equals to
			 * (2^(srq_mtt_prefetch_maxlen-1)*1KB).
			 */
			u32 wqe_cache_thd_sel : 2;
			/*
			 * Minimum number of prefetch WQEBBs for SRQ.
			 * 000: prefetch number equals to zero;
			 * Others: prefetch number equals to (2^(srq_wqe_prefetch_minnum-1)).
			 */
			u32 wqe_prefetch_min_num : 3;
			/*
			 * Maximum number of prefetch WQEBBs for SRQ.
			 * 000: prefetch number equals to zero;
			 * Others: prefetch number equals to (2^srq_wqe_prefetch_maxnum).
			 */
			u32 wqe_prefetch_max_num : 3;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 container : 1;
			u32 pcnt_on_chip : 1;
			u32 lth_pre_en : 1;
			u32 rkey_en : 1;
			u32 wqe_check_en : 1;
			u32 lth_gap : 4;
			u32 rsvd : 5;
			u32 pd : 18;
#else
			u32 pd : 18;
			u32 rsvd : 5;
			u32 lth_gap : 4;
			u32 wqe_check_en : 1;
			u32 rkey_en : 1;
			u32 lth_pre_en : 1;
			u32 pcnt_on_chip : 1;
			u32 container : 1;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	u32 srqn;

	/* DW5 */
	u32 xrc_cqn;

	/* DW6~7 */
	union {
		/*
		 * The GPA of Layer 0 MTT. It may point to the CQ's buffer directly.
		 * low 3bits(cq_gpa_sign)
		 */
		u64 l0mtt_gpa;
		struct {
			u32 l0mtt_gpa_hi;
			u32 l0mtt_gpa_lo;
		} dw6_dw7;
	};

	/* DW8~9 */
	union {
		/*
		 * The GPA of stored CI of Complete Queue.
		 * Address translation hop numbers.
		 * 0x0: the 'cq_l0mtt_gpa' points to the buffer of CQ directly.
		 * 0x1: it need to perform one hop address translation to get the buffer's
		 * address of CQ; 0x2: there is two hop address translation to get the buffer's
		 * address of CQ; 0x3: reserved.
		 */
		u64 record_gpa_at_hop_num;
		struct {
			u32 record_gpa_hi;
			u32 record_gpa_lo_at_hop_num; /* bit[1:0] Address translation hop numbers */
		} dw8_dw9;
	};

	struct tag_roce_verbs_srq_cont_attr cont;
};

struct tag_roce_verbs_srq_hw2sw_info {
	/* DW0~3 */
	u32 srq_buf_len;
	u32 wqe_cache_line_start;
	u32 wqe_cache_line_end;
	u32 wqe_cache_line_size;

	/* DW4~8 */
	struct tag_roce_verbs_mtt_cacheout_info cmtt_cache;
};

union tag_roce_verbs_arm_srq_info {
	u32 limitwater;
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 lwm : 16;
		u32 warth : 4;
		u32 th_up_en : 1;
		u32 cont_en : 1;
		u32 rsvd : 10;
#else
		u32 rsvd : 10;
		u32 cont_en : 1;
		u32 th_up_en : 1;
		u32 warth : 4;
		u32 lwm : 16;
#endif
	} bs;
};
#pragma pack()

#endif /* ROCE_VERBS_SRQ_ATTR_H */
