/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_ATTR_QPC_CHIP_H
#define ROCE_VERBS_ATTR_QPC_CHIP_H

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#pragma pack(push, 4)
struct tag_roce_verbs_qpc_attr_chip {
	/* DW0~1 */
	union {
		u64 sq_rq_l0mtt_gpa; /* hi[63:32],lo[31:03],sq_rq_gpa_sign[02:00] */
		struct {
			u32 sq_rq_l0mtt_gpa_hi;
			u32 sq_rq_l0mtt_gpa_lo;
		} bs;
	} dw0;

	/* DW2~3 */
	union {
		/* hi[63:32],lo[31:02],sq_rq_at_hop_num[01:00] */
		u64 sq_rq_pi_record_gpa_at_hop_num;
		struct {
			u32 sq_rq_pi_record_gpa_hi;
			u32 sq_rq_pi_record_gpa_lo_at_hop_num; /* at_hop_num: bit[01:00] */
		} bs;
	} dw2;

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 qp_page_size : 4;
			u32 sq_rq_mtt_page_size : 4;
			u32 rsvd1 : 3;
			u32 qp_signature : 5;
			u32 rsvd0 : 1;
			u32 dsgl : 1;
			u32 rrw_mtt_prefetch_maxlen : 2;
			u32 rc_size : 4;
			u32 rc_max_size : 3;
			u32 rq_base_ci : 5;
#else
			u32 rq_base_ci : 5;
			u32 rc_max_size : 3;
			u32 rc_size : 4;
			u32 rrw_mtt_prefetch_maxlen : 2;
			u32 dsgl : 1;
			u32 rsvd0 : 1;
			u32 qp_signature : 5;
			u32 rsvd1 : 3;
			u32 sq_rq_mtt_page_size : 4;
			u32 qp_page_size : 4;
#endif
		} bs;
		u32 value;
	} dw4;

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_wqe_prefetch_maxnum : 3;
			u32 sq_wqe_prefetch_minnum : 3;
			u32 sq_wqe_cache_thd_sel : 2;
			u32 sq_wqecnt_lth : 4;
			u32 sq_wqecnt_rctl_en : 1;
			u32 sq_wqecnt_rctl : 1;
			u32 sq_prefetch_one_wqe : 1;
			u32 sq_prewqe_mode : 1;
			u32 sqa_wqe_prefetch_maxnum : 3;
			u32 sqa_wqe_prefetch_minnum : 3;
			u32 sqa_wqe_cache_thd_sel : 2;
			u32 sq_wqe_check_en : 1;
			u32 sq_pi_on_chip : 1;
			u32 sq_inline_en : 1;
			u32 sq_size : 5;
#else
			u32 sq_size : 5;
			u32 sq_inline_en : 1;
			u32 sq_pi_on_chip : 1;
			u32 sq_wqe_check_en : 1;
			u32 sqa_wqe_cache_thd_sel : 2;
			u32 sqa_wqe_prefetch_minnum : 3;
			u32 sqa_wqe_prefetch_maxnum : 3;
			u32 sq_prewqe_mode : 1;
			u32 sq_prefetch_one_wqe : 1;
			u32 sq_wqecnt_rctl : 1;
			u32 sq_wqecnt_rctl_en : 1;
			u32 sq_wqecnt_lth : 4;
			u32 sq_wqe_cache_thd_sel : 2;
			u32 sq_wqe_prefetch_minnum : 3;
			u32 sq_wqe_prefetch_maxnum : 3;
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_wqe_prefetch_mode : 1;
			u32 sq_mtt_prefetch_maxlen : 3;
			u32 sqa_mtt_prefetch_maxlen : 3;
			u32 srq_pd : 18;
			u32 rsvd : 7;
#else
			u32 rsvd : 7;
			u32 srq_pd : 18;
			u32 sqa_mtt_prefetch_maxlen : 3;
			u32 sq_mtt_prefetch_maxlen : 3;
			u32 sq_wqe_prefetch_mode : 1;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_wqe_prefetch_maxnum : 3;
			u32 rq_wqe_prefetch_minnum : 3;
			u32 rq_wqe_cache_thd_sel : 2;
			u32 rq_wqecnt_lth : 4;
			u32 rq_wqecnt_rctl_en : 1;
			u32 rq_wqecnt_rctl : 1;
			u32 srqn : 18;
#else
			u32 srqn : 18;
			u32 rq_wqecnt_rctl : 1;
			u32 rq_wqecnt_rctl_en : 1;
			u32 rq_wqecnt_lth : 4;
			u32 rq_wqe_cache_thd_sel : 2;
			u32 rq_wqe_prefetch_minnum : 3;
			u32 rq_wqe_prefetch_maxnum : 3;
#endif
		} bs;
		u32 value;
	} dw7;

	/* DW8 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_wqe_rthd_sel : 2;
			u32 srq_rqecnt_th : 4;
			u32 rq_pi_on_chip : 1;
			u32 rq_inline_en : 1;
			u32 rq_wqebb_size : 3;
			u32 rq_size : 5;
			u32 xrcd : 16;
#else
			u32 xrcd : 16;
			u32 rq_size : 5;
			u32 rq_wqebb_size : 3;
			u32 rq_inline_en : 1;
			u32 rq_pi_on_chip : 1;
			u32 srq_rqecnt_th : 4;
			u32 srq_wqe_rthd_sel : 2;
#endif
		} bs;
		u32 value;
	} dw8;

	/* DW9 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 container_en : 1;
			u32 container_sz : 2;
			u32 srq_warth_flag : 1;
			u32 srq_mtt_prefetch_maxlen1 : 2;
			u32 rq_mtt_prefetch_maxwqe : 3;
			u32 rq_mtt_prefetch_maxlen0 : 2;
			u32 rq_mtt_prefetch_maxlen1 : 2;
			u32 rsvd : 19;
#else
			u32 rsvd : 19;
			u32 rq_mtt_prefetch_maxlen1 : 2;
			u32 rq_mtt_prefetch_maxlen0 : 2;
			u32 rq_mtt_prefetch_maxwqe : 3;
			u32 srq_mtt_prefetch_maxlen1 : 2;
			u32 srq_warth_flag : 1;
			u32 container_sz : 2;
			u32 container_en : 1;
#endif
		} bs;
		u32 value;
	} dw9;

	/* DW10 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_entry_prefetch_maxnum : 3;
			u32 rc_mtt_prefetch_maxlen : 2;
			u32 rsvd : 1;
			u32 rc_entry_size : 2;
			u32 rc_page_gpa_h : 24;
#else
			/*
			 * bit[63:40] Indicates the start GPA of RDMARC table.
			 * The driver needs to allocate continuous physical address for
			 * the RDMARC table.Configured by Driver
			 */
			u32 rc_page_gpa_h : 24;
			u32 rc_entry_size : 2;
			u32 rsvd : 1;
			u32 rc_mtt_prefetch_maxlen : 2;
			/*
			 * Maximum number of prefetch Entries for RDMARC table.000: prefetch
			 * number equals to zero; Others: prefetch number equals to
			 * (2^(rc_entry_prefetch_maxnum-1)). Configured by Driver
			 */
			u32 rc_entry_prefetch_maxnum : 3;
#endif
		} bs;
		u32 value;
	} dw10;

	/* DW11 */
	u32 rc_page_gpa_l; /* bit[39:8] */

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 1;
			u32 srq_pd : 18;
			u32 srq_wqebb_size : 3;
			u32 srq_page_size : 4;
			u32 srq_size : 5;
			u32 srq_rkey_en : 1;
#else
			u32 srq_rkey_en : 1;
			u32 srq_size : 5;
			u32 srq_page_size : 4;
			u32 srq_wqebb_size : 3;
			u32 srq_pd : 18;
			u32 rsvd : 1;
#endif
		} bs;
		u32 value;
	} dw12;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 srq_cqn : 20;
			u32 srq_state : 4;
#else
			u32 srq_state : 4;
			u32 srq_cqn : 20;
			u32 rsvd : 8;
#endif
		} bs;
		u32 value;
	} dw13;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 15;
			u32 qp_rkey_en : 1;
			u32 srq_xrcd : 16;
#else
			u32 srq_xrcd : 16;
			u32 qp_rkey_en : 1;
			u32 rsvd : 15;
#endif
		} bs;
		u32 value;
	} dw14;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 4;
			u32 rq_page_size : 4;
			u32 rq_pd : 18;
			u32 rq_rkey_en : 1;
			u32 rq_size : 5;
#else
			u32 rq_size : 5;
			u32 rq_rkey_en : 1;
			u32 rq_pd : 18;
			u32 rq_page_size : 4;
			u32 rsvd : 4;
#endif
		} bs;
		u32 value;
	} dw15;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 6;
			u32 sq_wqebb_size : 3;
			u32 sq_pd : 18;
			u32 sq_page_size : 4;
			u32 sq_rkey_en : 1;
#else
			u32 sq_rkey_en : 1;
			u32 sq_page_size : 4;
			u32 sq_pd : 18;
			u32 sq_wqebb_size : 3;
			u32 rsvd : 6;
#endif
		} bs;
		u32 value;
	} dw16;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 12;
			u32 sqa_cqn : 20;
#else
			u32 sqa_cqn : 20;
			u32 rsvd : 12;
#endif
		} bs;
		u32 value;
	} dw17;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 14;
			u32 ud_pd : 18;
#else
			u32 ud_pd : 18;
			u32 rsvd : 14;
#endif
		} bs;
		u32 value;
	} dw18;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 14;
			u32 qp_pd : 18;
#else
			u32 qp_pd : 18;
			u32 rsvd : 14;
#endif
		} bs;
		u32 value;
	} dw19;
};

#pragma pack(pop)

#endif /* ROCE_VERBS_ATTR_QPC_CHIP_H */
