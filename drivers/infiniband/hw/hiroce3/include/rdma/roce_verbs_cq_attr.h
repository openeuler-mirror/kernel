/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_CQ_ATTR_H
#define ROCE_VERBS_CQ_ATTR_H

#include "roce_verbs_mr_attr.h"

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#pragma pack(push, 4)
struct roce_verbs_cq_attr {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 signature : 5;
			u32 ci_on_chip : 1;
			u32 cnt_clear_en : 1;
			u32 cnt_adjust_en : 1;
			u32 rsvd : 3;
			u32 timer_mode : 1;
			u32 arm_timer_en : 1;
			u32 tss_timer_num : 3;
			u32 mtt_page_size : 4;
			u32 cqe_size : 3;
			u32 page_size : 4;
			u32 size : 5;
#else
			/*
			 * Completion Queue size, equals to (2^cq_size)*CQE.
			 * The maximum CQ size is 2^23 CQEs.
			 */
			u32 size : 5;
			u32 page_size : 4;  /* Page size of CQ, equals to (2^cq_page_size)*4KB. */
			/*
			 * Completion Queue Entry (CQE) size in bytes is (2^cq_cqe_size)*16B.
			 * The minimum size is 32B and the values 0, 3, 4, 5, 6, 7 are reserved.
			 */
			u32 cqe_size : 3;
			u32 mtt_page_size : 4;
			u32 tss_timer_num : 3;
			u32 arm_timer_en : 1;
			u32 timer_mode : 1;
			u32 rsvd : 3;
			u32 cnt_adjust_en : 1;
			u32 cnt_clear_en : 1;
			/*
			 * If set, the CI of Complete Queue is stored in the chip,
			 * the counter is absolute value.
			 */
			u32 ci_on_chip : 1;
			u32 signature : 5;
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
			/*
			 * It specifies the ATTR[1:0] bits in the outbound PCIe
			 * TLP headers of the DMA operation.
			 * This field is only valid when processing CQ's CQEs.
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
			u32 ceqn : 8;
			u32 rsvd : 1;
			u32 arm_ceqe_en : 1;
			u32 ceqe_en : 1;
			u32 cqecnt_rctl_en : 1;
			u32 cqecnt_lth : 4;
			u32 idle_max_count : 16;
#else
			u32 idle_max_count : 16;
			u32 cqecnt_lth : 4;
			u32 cqecnt_rctl_en : 1;
			u32 ceqe_en : 1;
			u32 arm_ceqe_en : 1;
			u32 rsvd : 1;
			u32 ceqn : 8;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 max_cnt : 16;
			u32 timeout : 16;
#else
			/*
			 * Completion Event Moderation timer in microseconds.
			 * 0x0: interrupt moderation disabled.
			 */
			u32 timeout : 16;
			/*
			 * Completion Event Moderation counters.
			 * 0x0: interrupt moderation disabled.
			 */
			u32 max_cnt : 16;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 - DW5 */
	union {
		/*
		 * The GPA of Layer 0 MTT. It may point to the CQ's buffer directly.
		 * low 3bits(cq_gpa_sign)
		 */
		u64 cqc_l0mtt_gpa;
		struct {
			u32 cqc_l0mtt_gpa_hi;
			u32 cqc_l0mtt_gpa_lo;
		} dw4_dw5;
	};

	/* DW6 - DW7 */
	union {
		/* The GPA of stored CI of Complete Queue.
		 * Address translation hop numbers.
		 * 0x0: the 'cq_l0mtt_gpa' points to the buffer of CQ directly.
		 * 0x1: it need to perform one hop address translation to get the buffer's
		 * address of CQ; 0x2: there is two hop address translation to get the buffer's
		 * address of CQ; 0x3: reserved.
		 */
		u64 ci_record_gpa_at_hop_num;
		struct {
			u32 ci_record_gpa_hi;
			/* bit[1:0] Address translation hop numbers */
			u32 ci_record_gpa_lo_at_hop_num;
		} dw6_dw7;
	};
};

struct tag_roce_verbs_cq_resize_info {
	/* DW0~3 */
	u32 mtt_page_size; /* Size of the mtt page after resize. */
	u32 page_size;	 /* Size of the resize buf page. */
	u32 log_cq_size;   /* Cq depth after resize */
	u32 mtt_layer_num; /* Number of mtt levels after resize */

	/* DW4~5 */
	union {
		u64 mtt_base_addr; /* Start address of mr or mw */
		u32 cqc_l0mtt_gpa[2];
	};

	/* DW6~10 */
	struct tag_roce_verbs_mtt_cacheout_info cmtt_cache;
};

struct tag_roce_verbs_modify_cq_info {
	u32 max_cnt;
	u32 timeout;
};
#pragma pack(pop)

#endif /* ROCE_VERBS_CQ_ATTR_H */
