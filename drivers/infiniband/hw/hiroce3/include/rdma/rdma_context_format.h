/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef RDMA_CONTEXT_FORMAT_H
#define RDMA_CONTEXT_FORMAT_H

#include "roce_hmm_context.h"
#include "rdma_ext_ctx_format.h"


/* Align each field with 4bytes. */
#pragma pack(push, 4)

/* **************** Macro Definition ****************** */
#define ROCE_BASE_GID_IDX 1
#define RDMA_SGID_TBL_KEY_VFID_OFFSET (4)
#define RDMA_SGID_TBL_KEY_SGIDIDX_OFFSET (0)
#define ROCE_SPU_HOST_ID (4)
#define ROCE_SPU_OQID_HOST_ID (5)
#define ROCE_SDI_SHOST_HOST_ID	0
#define ROCE_SDI_MHOST_HOST_ID	1
#define QU_OQID_RW_CHANNEL 1
#define ROCE_GET_HOST_OQID(host_id, xid) \
	((((128U * (host_id) + ((xid) & 0x7f)) << 2) & 0x7ff) | \
	(((host_id) & 0x7) << 11U) | (((xid) & 0x1) + 1))
#define ROCE_GET_SPU_HOST_OQID(host_id, fid, xid) \
	(((((fid) & 0x1ff) << 2) & 0x7FF) | (((host_id) & 0x7) << 11U) | (QU_OQID_RW_CHANNEL))

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN	0x1234
#endif

#define ETH_ADDR_LEN (6)

/* **************** Data Structure Definition ****************** */
/* * QPC Format start */

/* Send Queue Context 64B */
struct chip_seg_sqc {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_pd : 18;
			u32 sq_inline_en : 1;
			u32 sq_pi_on_chip : 1;
			u32 sq_wqebb_size : 3;
			u32 sq_page_size : 4;
			u32 sq_size : 5;
#else
			/*
			 * Send WQ size is (2^sq_size)*WQEBBs; the
			 * maximum SQ size is 16K WQEs, so this field
			 * doesn't exceed 14. They have same configuration
			 * value: SQC.sq_size and SQAC.sq_size.
			 * Configured by Driver
			 */
			u32 sq_size : 5;

			/*
			 * Page size of SQ and RQ, equals to (2^sq_page_size)*4KB.
			 * The following three Page size have same configuration
			 * value: SQC.sq_page_size,
			 * SQAC.sq_page_size and RQC.rq_page_size. Configured by Driver
			 */
			u32 sq_page_size : 4;
			/*
			 * Send WQE Basic Block (WQEBB) size in
			 * bytes is 16*(2^sq_weqbb_size).
			 * for the SQ, this field should be fixed to 2.
			 * They have same configuration value: SQC.sq_wqebb_size
			 * and SQAC.sq_wqebb_size.
			 * Configured by Driver
			 */
			u32 sq_wqebb_size : 3;
			/*
			 * If set, the counter (PI index) of Send Queue is
			 * stored in the chip, the counter is
			 * absolute value. Configured by Driver
			 */
			u32 sq_pi_on_chip : 1;
			/*
			 * Indicates if the SQ supports inline data operation.
			 * Configured by Driver
			 */
			u32 sq_inline_en : 1;
			/*
			 * Protection Domain.
			 * The following five Protection Domains have
			 * same configuration value: QCC.rc_pd,
			 * QC.sq_pd, SQAC.sq_pd, RQC.rq_pd and RRWC.rrw_pd.
			 * Configured by Driver
			 */
			u32 sq_pd : 18;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_so_ro : 2;
			u32 sq_dma_attr_idx : 6;
			u32 sq_wqecnt_rctl : 1;
			u32 sq_prewqe_mode : 1;
			u32 sq_pi_vld : 1;
			u32 sq_wqecnt_rctl_en : 1;
			u32 sq_wqecnt_lth : 4;
			u32 rsvd : 16;
#else
			u32 rsvd : 16;
			/*
			 * WQE Counter Low Threshold, equals to (2^sq_wqecnt_lth).
			 * Configured by Driver
			 */
			u32 sq_wqecnt_lth : 4;
			/*
			 * If this field is equal to zero, the SQ
			 * PI updating should be not controlled by
			 * the "sq_wqecnt_rctl" field; else the SQ
			 * RI updating can be performed only if
			 * the "sq_wqecnt_rctl" is equal to one.
			 * Configured by Driver
			 */
			u32 sq_wqecnt_rctl_en : 1;
			/*
			 * If set, the SQ should use the Index Mechanism,
			 * else the SQ uses the Owner Bit
			 * Mechanism. Configured by Driver
			 */
			u32 sq_pi_vld : 1;
			/*
			 * If set,the engine just performs prefetch WQE
			 * processing after completing the current WQE in
			 * the SQ_DMA_GEN_API flow.
			 */
			u32 sq_prewqe_mode : 1;
			/*
			 * The hardware clear it to zero when performing a SQ
			 * PI updating, and driver set it
			 * to one to indicate the hardware can performing SQ PI updating.
			 * N/A
			 */
			u32 sq_wqecnt_rctl : 1;
			/*
			 * bit[05:00] It specifies the outbound PCIe TLP
			 * header attribute of the DMA
			 * operation. This filed is only valid when processing
			 * SQ's WQEs. The following two
			 * "dma_attr_idx" have same configuration value:
			 * SQC.sq_dma_attr_idx and
			 * SQAC.sq_dma_attr_idx. Configured by Driver
			 */
			u32 sq_dma_attr_idx : 6;
			/*
			 * It specifies the ATTR[1:0] bits in the outbound
			 * PCIe TLP headers of the DMA operation.
			 * This field is only valid when processing SQ's WQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 * The following two "so_ro" have same configuration value:
			 * SQC.sq_so_ro and
			 * SQAC.sq_so_ro. Configured by Driver
			 */
			u32 sq_so_ro : 2;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_state : 4;
			u32 rsvd2 : 4;
			u32 sq_rkey_en : 1;
			u32 sq_wqe_check_en : 1;
			u32 rsvd1 : 6;
			u32 sq_pi : 16;
#else
			/* The Producer Index (PI) of Send Queue (Step: WQEBB) 0x0 */
			u32 sq_pi : 16;
			u32 rsvd1 : 6;
			u32 sq_wqe_check_en : 1;
			u32 sq_rkey_en : 1;
			u32 rsvd2 : 4;
			/*
			 * Send Queue State.0x0:ok;0x1:error;
			 * 0xf:hardware has no access right.Other:reserved.
			 * 0x0
			 */
			u32 sq_state : 4;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_ci : 16;
			u32 rsvd : 3;
			u32 dsgl_en : 1; /* Whether to work in dual sgl mode */
			u32 sq_load_pi : 1;
			u32 sq_load_page_gpa : 1;
			u32 sq_wqe_curt_page_vld : 1;
			u32 sq_wqe_next_page_vld : 1;
			u32 sq_wqe_curt_page_gpa_h : 8;
#else
			/*
			 * bit[63:56] Indicates the GPA of current SQ
			 * buffer's page pointed by
			 * "sq_ci". 0x0
			 */
			u32 sq_wqe_curt_page_gpa_h : 8;
			/* Indicates if the "sq_wqe_next_page_gpa" field is valid. */
			u32 sq_wqe_next_page_vld : 1;
			/*
			 * Indicates if the "sq_wqe_curt_page_gpa" field is valid.
			 * 1: it is valid;0: it is invalid.
			 * 0x0
			 */
			u32 sq_wqe_curt_page_vld : 1;
			/*
			 * Indicates the thread is performing a
			 * prefetch for GPA of WQE page. 0x0
			 */
			u32 sq_load_page_gpa : 1;
			/* Indicates the thread is performing a PI prefetch processing */
			u32 sq_load_pi : 1;
			u32 dsgl_en : 1;
			u32 rsvd : 3;
			/* bit[19:00] The CI index of Send Queue (Step: WQEBB) 0x0 */
			u32 sq_ci : 16;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	u32 sq_wqe_curt_page_gpa_m; /* bit[55:24] */

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_wqe_curt_page_gpa_l : 12;
			u32 sq_wqe_next_page_gpa_h : 20;
#else
			u32 sq_wqe_next_page_gpa_h : 20; /* bit[63:44] */
			u32 sq_wqe_curt_page_gpa_l : 12; /* bit[23:12] */
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	/*
	 * bit[43:12] Indicates the page GPA of next
	 * SQ buffer's page pointed by "sq_ci". 0x0
	 */
	u32 sq_wqe_next_page_gpa_l;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_wqe_prefetch_ci : 16;
			u32 rsvd : 4;
			u32 sq_signature : 3;
			u32 sq_wqe_prefetch_curtmax : 3;
			u32 sq_wqe_prefetch_maxnum : 3;
			u32 sq_wqe_prefetch_minnum : 3;
#else
			u32 sq_wqe_prefetch_minnum : 3;
			u32 sq_wqe_prefetch_maxnum : 3;
			u32 sq_wqe_prefetch_curtmax : 3;
			u32 sq_signature : 3;
			u32 rsvd : 4;
			/*
			 * bit[15:00] The prefetch CI index of
			 * Send Queue (Step: WQEBB).0x0
			 */
			u32 sq_wqe_prefetch_ci : 16;
#endif
		} bs;
		u32 value;
	} dw7;

	/* DW8 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_curt_sge_vld : 1;
			u32 rsvd : 3;
			u32 sq_curt_sge_lkey : 28;
#else
			/*
			 * bit[27:00] Indicates the L_Key of current SGE.
			 * Using sq_curt_sge_lkey[27:8] to
			 * access the corresponding MPT. 0x0
			 */
			u32 sq_curt_sge_lkey : 28;
			u32 rsvd : 3;
			/*
			 * Indicates current SGE information is valid.
			 * The remaining sq_curt_sge_* field are
			 * only valid when the sq_curt_sge_vld is
			 * asserted.1: SGE is valid;,0: SGE is
			 * invalid. 0x0
			 */
			u32 sq_curt_sge_vld : 1;
#endif
		} bs;
		u32 value;
	} dw8;

	/* DW9~10 */
	union {
		u64 sq_curt_sge_va; /* hi:bit[63:32],lo:bit[31:00] */
		struct {
			u32 sq_curt_sge_va_hi;
			u32 sq_curt_sge_va_lo;
		} dw9;
	};

	/* DW11 */
	/* bit[31:00] Indicates the remaining memory space of current SGE. 0x0 */
	u32 sq_curt_sge_remain_len;

	/* DW12 */
	/*
	 * bit[63:32] Indicates the GPA of current data buffer page pointed by
	 * "sq_curt_sge_va".0x0
	 */
	u32 sq_curt_sge_dbuff_gpa_h;

	/* DW13 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_curt_sge_dbuff_gpa_l : 20;
			u32 sq_curt_sge_dbuff_gpa_vld : 1;
			u32 sq_curt_sge_dsgl : 1;
			u32 sq_curt_sge_used : 1;
			u32 sq_curt_sge_last : 1;
			u32 rsvd : 8;
#else
			u32 rsvd : 8;
			/*
			 * Indicates the current SGE is the
			 * last SGE for the current WQE. 0x0
			 */
			u32 sq_curt_sge_last : 1;
			u32 sq_curt_sge_used : 1;
			u32 sq_curt_sge_dsgl : 1;
			/*
			 * Indicates if the "sq_curt_sge_dbuff_gpa"
			 * field is valid. 1: it is
			 * valid;0:it is invalid.
			 */
			u32 sq_curt_sge_dbuff_gpa_vld : 1;
			/*
			 * bit[31:12] Indicates the GPA of current
			 * data buffer page pointed by
			 * "sq_curt_sge_va".0x0
			 */
			u32 sq_curt_sge_dbuff_gpa_l : 20;
#endif
		} bs;
		u32 value;
	} dw13;

	/* DW14 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_mtt_prefetch_cline_num : 5;
			u32 sq_mtt_prefetch_cline_ptr : 6;
			u32 sq_wqe_prefetch_finish : 1;
			u32 rsvd : 4;
			u32 sq_mtt_prefetch_wqe_ci : 16;
#else
			/* bit[15:0] Indicates the WQE index of prefetch MTTs operation */
			u32 sq_mtt_prefetch_wqe_ci : 16;
			u32 rsvd : 4;
			u32 sq_wqe_prefetch_finish : 1;
			u32 sq_mtt_prefetch_cline_ptr : 6;
			u32 sq_mtt_prefetch_cline_num : 5;
#endif
		} bs;
		u32 value;
	} dw14;

	/* DW15 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_wqe_cache_thd_sel : 2;
			u32 sq_mtt_prefetch_maxlen : 3;
			u32 sq_wqe_prefetch_mode : 1;
			u32 sq_prefetch_one_wqe : 1;
			u32 sq_curt_sge_idx : 6;
			u32 rsvd : 8;
			u32 sq_mtt_prefetch_sge_idx : 6;
			u32 sq_load_wqe : 1;
			u32 sq_load_mtt : 1;
			u32 sq_load_dbuff : 1;
			u32 sq_prefetch_thread_num : 2;
#else
			u32 sq_prefetch_thread_num : 2;
			u32 sq_load_dbuff : 1;
			u32 sq_load_mtt : 1;
			u32 sq_load_wqe : 1;
			u32 sq_mtt_prefetch_sge_idx : 6;
			u32 rsvd : 8;
			/* The SGE index of current accessed WQE. 0x0 */
			u32 sq_curt_sge_idx : 6;
			u32 sq_prefetch_one_wqe : 1;
			u32 sq_wqe_prefetch_mode : 1;
			u32 sq_mtt_prefetch_maxlen : 3;
			u32 sq_wqe_cache_thd_sel : 2;
#endif
		} bs;
		u32 value;
	} dw15;
};

/* Send Queue ACK Context 64B */
struct chip_seg_sqac {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_pd : 18;
			u32 rsvd : 1;
			u32 vbs_sqa_pi_on_chip : 1;
			u32 sq_wqebb_size : 3;
			u32 sq_page_size : 4;
			u32 sq_size : 5;
#else
			/*
			 * Send WQ size is (2^sq_size)*WQEBBs; the maximum
			 * SQ size is 16K WQEs, so this field
			 * doesn't exceed 14. They have same configuration
			 * value: SQC.sq_size and SQAC.sq_size.
			 * Configured by Driver
			 */
			u32 sq_size : 5;

			/*
			 * Page size of SQ and RQ, equals to (2^sq_page_size)*4KB.
			 * The following three Page size have same configuration
			 * value: SQC.sq_page_size,
			 * SQAC.sq_page_size and RQC.rq_page_size. Configured by Driver
			 */
			u32 sq_page_size : 4;
			/* Send WQE Basic Block (WQEBB) size in bytes is 16*(2^sq_weqbb_size).
			 * for the SQ, this field should be fixed to 2.
			 * They have same configuration value: SQC.
			 * sq_wqebb_size and SQAC.sq_wqebb_size.
			 * Configured by Driver
			 */
			u32 sq_wqebb_size : 3;
			u32 vbs_sqa_pi_on_chip : 1;
			u32 rsvd : 1;
			/*
			 * Protection Domain.
			 * The following five Protection Domains have same
			 * configuration value: QCC.rc_pd,
			 * SQC.sq_pd, SQAC.sq_pd, RQC.rq_pd and RRWC.rrw_pd.
			 * Configured by Driver
			 */
			u32 sq_pd : 18;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sq_so_ro : 2;
			u32 sq_dma_attr_idx : 6;
			u32 rsvd2 : 1;
			u32 sqa_prewqe_mode : 1;
			u32 vbs_sqa_pi_vld : 1;
			u32 rsvd1 : 1;
			u32 sqa_cqn : 20;
#else
			/* bit[19:00] SQ's Completion Queue Number. */
			u32 sqa_cqn : 20;
			u32 rsvd1 : 1;
			u32 vbs_sqa_pi_vld : 1;
			u32 sqa_prewqe_mode : 1;
			u32 rsvd2 : 1;
			/*
			 * bit[05:00] It specifies the outbound PCIe
			 * TLP header attribute of the DMA
			 * operation. This filed is only valid when
			 * processing SQ's WQEs. The following two
			 * "dma_attr_idx"have same configuration value:
			 * SQC. sq_dma_attr_idx and
			 * SQAC.sq_dma_attr_idx. Configured by Driver
			 */
			u32 sq_dma_attr_idx : 6;
			u32 sq_so_ro : 2;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_state : 4;
			u32 rsvd2 : 4;
			u32 sq_rkey_en : 1;
			u32 sq_wqe_check_en : 1;
			u32 rsvd1 : 6;
			u32 sqa_wqe_index : 16;
#else
			u32 sqa_wqe_index : 16; /* bit[15:00] */
			u32 rsvd1 : 6;
			u32 sq_wqe_check_en : 1;
			u32 sq_rkey_en : 1;
			u32 rsvd2 : 4;
			u32 sqa_state : 4;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_ci : 16;
			u32 rsvd1 : 3;
			u32 dsgl_en : 1;
			u32 rsvd : 1;
			u32 sqa_load_page_gpa : 1;
			u32 sqa_wqe_curt_page_vld : 1;
			u32 sqa_wqe_next_page_vld : 1;
			u32 sqa_wqe_curt_page_gpa_h : 8;
#else
			u32 sqa_wqe_curt_page_gpa_h : 8; /* bit[63:56] */
			u32 sqa_wqe_next_page_vld : 1;
			u32 sqa_wqe_curt_page_vld : 1;
			u32 sqa_load_page_gpa : 1;
			u32 rsvd : 1;
			u32 dsgl_en : 1;
			u32 rsvd1 : 3;
			u32 sqa_ci : 16; /* bit[15:00] */
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	u32 sqa_wqe_curt_page_gpa_m; /* bit[55:24] */

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_wqe_curt_page_gpa_l : 12;
			u32 sqa_wqe_next_page_gpa_h : 20;
#else
			u32 sqa_wqe_next_page_gpa_h : 20; /* bit[63:44] */
			u32 sqa_wqe_curt_page_gpa_l : 12; /* bit[23:12] */
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	u32 sqa_wqe_next_page_gpa_l; /* bit[43:12] */

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_wqe_prefetch_ci : 16;
			u32 rsvd2 : 4;
			u32 sqa_signature : 3;
			u32 rsvd1 : 3;
			u32 sqa_wqe_prefetch_maxnum : 3;
			u32 sqa_wqe_prefetch_minnum : 3;
#else
			u32 sqa_wqe_prefetch_minnum : 3;
			u32 sqa_wqe_prefetch_maxnum : 3;
			u32 rsvd1 : 3;
			u32 sqa_signature : 3;
			u32 rsvd2 : 4;
			u32 sqa_wqe_prefetch_ci : 16;
#endif
		} bs;
		u32 value;
	} dw7;

	/* DW8 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_curt_sge_vld : 1;
			u32 rsvd : 3;
			u32 sqa_curt_sge_lkey : 28;
#else
			u32 sqa_curt_sge_lkey : 28; /* bit[27:00] */
			u32 rsvd : 3;
			u32 sqa_curt_sge_vld : 1;
#endif
		} bs;
		u32 value;
	} dw8;

	/* DW9~10 */
	union {
		u64 sqa_curt_sge_va; /* hi:bit[63:32],lo:bit[31:00] */
		struct {
			u32 sqa_curt_sge_va_hi;
			u32 sqa_curt_sge_va_lo;
		} dw9;
	};

	/* DW11 */
	u32 sqa_curt_sge_remain_len; /* bit[31:00] */

	/* DW12 */
	u32 sqa_curt_sge_dbuff_gpa_h; /* bit[63:32] */

	/* DW13 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_curt_sge_dbuff_gpa_l : 20;
			u32 sqa_curt_sge_dbuff_gpa_vld : 1;
			u32 sqa_curt_sge_dsgl : 1;
			u32 sqa_curt_sge_used : 1;
			u32 sqa_curt_sge_last : 1;
			u32 rsvd : 8;
#else
			u32 rsvd : 8;
			u32 sqa_curt_sge_last : 1;
			u32 sqa_curt_sge_used : 1;
			u32 sqa_curt_sge_dsgl : 1;
			u32 sqa_curt_sge_dbuff_gpa_vld : 1;
			u32 sqa_curt_sge_dbuff_gpa_l : 20; /* bit[31:12] */
#endif
		} bs;
		u32 value;
	} dw13;

	/* DW14 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_mtt_prefetch_cline_num : 5;
			u32 sqa_mtt_prefetch_cline_ptr : 6;
			u32 sqa_mtt_prefetch_finish : 1;
			u32 rsvd : 4;
			u32 sqa_mtt_prefetch_wqe_ci : 16;
#else
			u32 sqa_mtt_prefetch_wqe_ci : 16;
			u32 rsvd : 4;
			u32 sqa_mtt_prefetch_finish : 1;
			u32 sqa_mtt_prefetch_cline_ptr : 6;
			u32 sqa_mtt_prefetch_cline_num : 5;
#endif
		} bs;
		u32 value;
	} dw14;

	/* DW15 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqa_wqe_cache_thd_sel : 2;
			u32 sqa_mtt_prefetch_maxlen : 3;
			u32 rsvd2 : 2;
			u32 sqa_curt_sge_idx : 6;
			u32 rsvd1 : 8;
			u32 sqa_mtt_prefetch_sge_idx : 6;
			u32 sqa_load_wqe : 1;
			u32 sqa_load_mtt : 1;
			u32 sqa_load_dbuff : 1;
			u32 sqa_prefetch_thread_num : 2;
#else
			u32 sqa_prefetch_thread_num : 2;
			u32 sqa_load_dbuff : 1;
			u32 sqa_load_mtt : 1;
			u32 sqa_load_wqe : 1;
			u32 sqa_mtt_prefetch_sge_idx : 6;
			u32 rsvd1 : 8;
			u32 sqa_curt_sge_idx : 6;
			u32 rsvd2 : 2;
			u32 sqa_mtt_prefetch_maxlen : 3;
			u32 sqa_wqe_cache_thd_sel : 2;
#endif
		} bs;
		u32 value;
	} dw15;
};

/* Receive Queue Context 64B */
struct chip_seg_rqc {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_pd : 18;
			u32 rq_inline_en : 1;
			u32 rq_pi_on_chip : 1;
			u32 rq_wqebb_size : 3;
			u32 rq_page_size : 4;
			u32 rq_size : 5;
#else
			/*
			 * Receive Queue size, equals to (2^rq_size)*WQEBB.
			 * The maximum RQ size is 16K WQEs,
			 * so this field doesn't exceed 14.
			 * Configured by Driver
			 */
			u32 rq_size : 5;
			/*
			 * Page size of SQ and RQ, equals to (2^rq_page_size)*4KB.
			 * Configured by Driver
			 */
			u32 rq_page_size : 4;
			/*
			 * Receive WQE Basic Block (WQEBB) size
			 * in bytes is (2^rq_wqebb_size)*16B.
			 * The minimum size is 16B and the values 4, 5, 6, 7 are reserved.
			 * Configured by Driver
			 */
			u32 rq_wqebb_size : 3;
			/*
			 * If set, the counter (PI index) of Receive
			 * Queue is stored in the chip, the counter
			 * is absolute value. Configured by Driver
			 */
			u32 rq_pi_on_chip : 1;
			/*
			 * If set, in-line scatter is enabled for this RQ.
			 * Configured by Driver
			 */
			u32 rq_inline_en : 1;
			/*
			 * bit[17:00] Protection Domain.The following five
			 * Protection Domains have same configuration
			 * value: QCC.rc_pd, SQC.sq_pd, SQAC.sq_pd,
			 * RQC.rq_pd and RRWC.rrw_pd. Configured by
			 * Driver
			 */
			u32 rq_pd : 18;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_so_ro : 2;
			u32 rq_dma_attr_idx : 6;
			u32 rq_rkey_en : 1;
			u32 rq_signature : 3;
			u32 rq_cqn : 20;
#else
			/*
			 * bit[19:00] Receive Queue completions are
			 * to be reported to this CQ number.
			 * Configured by Driver
			 */
			u32 rq_cqn : 20;
			u32 rq_signature : 3;
			u32 rq_rkey_en : 1;
			/*
			 * bit[05:00] It specifies the outbound PCIe
			 * TLP header attribute of the DMA
			 * operation. This filed is only valid when
			 * processing RQ's WQEs. Configured by
			 * Driver
			 */
			u32 rq_dma_attr_idx : 6;
			/* It specifies the ATTR[1:0] bits in the outbound
			 * PCIe TLP headers of the DMA operation.
			 * This field is only valid when processing RQ's WQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 * Configured by Driver
			 */
			u32 rq_so_ro : 2;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_state : 4;
			u32 rsvd2 : 13;
			u32 rq_wqe_cache_thd_sel : 2;
			u32 rq_inlin_len : 4;
			u32 rq_wqecnt_rctl : 1;
			u32 rsvd1 : 2;
			u32 rq_wqecnt_rctl_en : 1;
			u32 rq_wqecnt_lth : 4;
			u32 rq_srq_en : 1;
#else
			/*
			 * If set, indicates it should use SRQ as the receive queue.
			 * Configured by Driver
			 */
			u32 rq_srq_en : 1;
			/*
			 * WQE Counter Low Threshold, equals to (2^rq_wqecnt_lth).
			 * Configured by Driver
			 */
			u32 rq_wqecnt_lth : 4;
			/*
			 * If this field is equal to zero, the RQ PI updating
			 * should be not controlled by
			 * the "rq_wqecnt_rctl" field; else the RQ RI updating
			 * can be performed only if
			 * the "rq_wqecnt_rctl" is equal to one. Configured by Driver
			 */
			u32 rq_wqecnt_rctl_en : 1;
			u32 rsvd1 : 2;
			/*
			 * The hardware clear it to zero when performing
			 * a RQ PI updating, and driver set it
			 * to one to indicate the hardware can performing
			 * RQ PI updating. N/A
			 */
			u32 rq_wqecnt_rctl : 1;
			/*
			 * Inline Data Length, equals to (2^rq_inline_len) bytes.
			 * Configured by Driver
			 */
			u32 rq_inlin_len : 4;
			u32 rq_wqe_cache_thd_sel : 2;
			u32 rsvd2 : 13;
			/*
			 * Receive Queue State.0xf: ok;0x1: error;0x0:
			 * hardware has no access right.Other:
			 * reserved. 0x0
			 */
			u32 rq_state : 4;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_state : 4;
			u32 rsvd : 2;
			u32 container_en : 1;
			u32 rsvd0 : 1;
			u32 rq_srqn : 18;
			u32 rsvd1 : 5;
			u32 rq_srq_en : 1;
#else
			u32 rq_srq_en : 1;
			u32 rsvd1 : 5;
			u32 rq_srqn : 18;
			u32 rsvd0 : 1;
			u32 container_en : 1;
			u32 rsvd : 2;
			u32 rq_state : 4;
#endif
		} srq;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_state : 4;
			u32 container_size : 2;
			u32 container_en : 1;
			u32 rsvd : 6;
			u32 rq_srqn : 18;
			u32 rq_srq_en : 1;
#else
			u32 rq_srq_en : 1;
			u32 rq_srqn : 18;
			u32 rsvd : 6;
			u32 container_en : 1;
			u32 container_size : 2;
			u32 rq_state : 4;
#endif
		} srq_c;

		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_ci : 16;
			u32 rsvd : 4;
			u32 rq_load_pi : 1;
			u32 rq_load_page_gpa : 1;
			u32 rq_wqe_curt_page_vld : 1;
			u32 rq_wqe_next_page_vld : 1;
			u32 rq_wqe_curt_page_gpa_h : 8;
#else
			/*
			 * bit[63:56] Indicates the GPA of current
			 * RQ buffer's page pointed by
			 * "rq_ci". 0x0
			 */
			u32 rq_wqe_curt_page_gpa_h : 8;
			/*
			 * Indicates if the "rq_wqe_curt_page_gpa" field is valid.
			 * 1: it is valid;0: it is invalid.
			 * 0x0
			 */
			u32 rq_wqe_next_page_vld : 1;
			/*
			 * Indicates if the "rq_wqe_curt_page_gpa" field is valid.
			 * 1: it is valid;0: it is invalid.
			 * 0x0
			 */
			u32 rq_wqe_curt_page_vld : 1;
			/*
			 * Indicates the thread is performing a
			 * prefetch for GPA of WQE page.0x0
			 */
			u32 rq_load_page_gpa : 1;
			u32 rq_load_pi : 1;
			u32 rsvd : 4;
			/* bit[15:00] The CI index of Receive Queue (Step: WQEBB) 0x0 */
			u32 rq_ci : 16;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	u32 rq_wqe_curt_page_gpa_m; /* bit[55:24] */

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_wqe_curt_page_gpa_l : 12; /* bit[23:12] */
			u32 rq_wqe_next_page_gpa_h : 20; /* bit[63:44] */
#else
			u32 rq_wqe_next_page_gpa_h : 20; /* bit[63:44] */
			u32 rq_wqe_curt_page_gpa_l : 12; /* bit[23:12] */
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	u32 rq_wqe_next_page_gpa_l; /* bit[43:12] */

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_pi : 16;
			u32 rq_wqe_prefetch_ci : 16;
#else
			/*
			 * bit[15:00] The prefetch CI index of
			 * Receive Queue (Step: WQEBB).0x0
			 */
			u32 rq_wqe_prefetch_ci : 16;
			/*
			 * bit[15:00] The Producer Index (PI) of
			 * Receive Queue (Step: WQEBB).0x0
			 */
			u32 rq_pi : 16;
#endif
		} bs;
		u32 value;
	} dw7;

	/* DW8 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_curt_sge_vld : 1;
			u32 rsvd : 3;
			u32 rq_curt_sge_lkey : 28;
#else
			/*
			 * bit[27:00] Indicates the L_Key of current SGE.
			 * Using rq_curt_sge_lkey[27:8] to
			 * access the corresponding MPT.0x0
			 */
			u32 rq_curt_sge_lkey : 28;
			u32 rsvd : 3;
			/*
			 * Indicates current SGE information is valid. The remaining
			 * rq_curt_sge_* field are
			 * only valid when the rq_curt_sge_vld is asserted.
			 * 1: SGE is valid;0: SGE is
			 * invalid.0x0
			 */
			u32 rq_curt_sge_vld : 1;
#endif
		} bs;
		u32 value;
	} dw8;

	/* DW9~10 */
	union {
		u64 rq_curt_sge_va; /* hi:bit[63:32],lo:bit[31:00] */
		struct {
			u32 rq_curt_sge_va_hi;
			u32 rq_curt_sge_va_lo;
		} dw9;
	};

	/* DW11 */
	/* bit[31:00] Indicates the remaining memory space of current SGE.0x0 */
	u32 rq_curt_sge_remain_len;

	/* DW12 */
	/*
	 * bit[63:32] Indicates the GPA of current data buffer page pointed by
	 * "rq_curt_sge_va".0x0
	 */
	u32 rq_curt_sge_dbuff_gpa_h;

	/* DW13 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_curt_sge_dbuff_gpa_l : 20;  /* bit[51:32] */
			/*
			 * Indicates if the "rq_curt_sge_dbuff_gpa" field is valid.1: it is
			 * valid;0: it is invalid.0x0
			 */
			u32 rq_curt_sge_dbuff_gpa_vld : 1;
			u32 rq_curt_sge_dsgl : 1;
			u32 rq_curt_sge_used : 1;
			/* Indicates the current SGE is the last SGE for the current WQE.0x0 */
			u32 rq_curt_sge_last : 1;
			/*
			 * Indicates the current Receive WQE's status.
			 * 0: the Receive WQE don't be
			 * accessed; 1: the Receive WQE has been accessed.0x0
			 */
			u32 rq_curt_wqe_status : 1;
			u32 rsvd : 3;
			u32 rq_mtt_prefetch_sge_idx : 4;
#else
			u32 rq_mtt_prefetch_sge_idx : 4;
			u32 rsvd : 3;
			u32 rq_curt_wqe_status : 1;
			u32 rq_curt_sge_last : 1;
			u32 rq_curt_sge_used : 1;
			u32 rq_curt_sge_dsgl : 1;
			u32 rq_curt_sge_dbuff_gpa_vld : 1;
			u32 rq_curt_sge_dbuff_gpa_l : 20; /* bit[31:12] */
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_curt_sge_remain_len : 17;
			u32 rq_curt_sge_meta_lkey : 3;
			u32 rsvd1 : 1;
			u32 rq_curt_sge_dsgl : 1;
			u32 rq_curt_sge_used : 1;
			u32 rq_curt_sge_last : 1;

			u32 rq_curt_meta_used : 1;
			u32 rq_curt_meta_last : 1;
			u32 rq_curt_meta_vld : 1;
			u32 rq_prefetch_thread_num : 2;
			u32 rq_curt_meta_lkey : 3;
#else

			u32 rq_curt_meta_lkey : 3;
			u32 rq_prefetch_thread_num : 2;
			u32 rq_curt_meta_vld : 1;
			u32 rq_curt_meta_last : 1;
			u32 rq_curt_meta_used : 1;

			u32 rq_curt_sge_last : 1;
			u32 rq_curt_sge_used : 1;
			u32 rq_curt_sge_dsgl : 1;
			u32 rsvd1 : 1;
			u32 rq_curt_sge_meta_lkey : 3;
			u32 rq_curt_sge_remain_len : 17;
#endif
		} bs_dsgl;
		u32 value;
	} dw13;

	/* DW14 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_prefetch_thread_num : 2;
			u32 rq_mtt_prefetch_cline_num : 4;
			u32 rq_mtt_prefetch_cline_ptr : 6;
			u32 rq_mtt_prefetch_finish : 1;
			u32 rsvd : 3;
			u32 rq_mtt_prefetch_wqe_ci : 16;
#else
			u32 rq_mtt_prefetch_wqe_ci : 16;
			u32 rsvd : 3;
			u32 rq_mtt_prefetch_finish : 1;
			u32 rq_mtt_prefetch_cline_ptr : 6;
			u32 rq_mtt_prefetch_cline_num : 4;
			u32 rq_prefetch_thread_num : 2;
#endif
		} bs;
		struct {
		} bc_c;
		u32 value;
	} dw14;

	/* DW15 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_wqe_prefetch_maxnum : 3;
			u32 rq_wqe_prefetch_minnum : 3;
			u32 rq_mtt_prefetch_maxwqe : 3;
			u32 rq_mtt_prefetch_maxlen0 : 2;
			u32 rq_mtt_prefetch_maxlen1 : 2;
			u32 rq_curt_sge_idx : 4;
			u32 rsvd : 11;
			u32 rq_load_next_mtt : 1;
			u32 rq_load_wqe : 1;
			u32 rq_load_curt_mtt : 1;
			u32 rq_load_dbuff : 1;
#else
			u32 rq_load_dbuff : 1;
			u32 rq_load_curt_mtt : 1;
			u32 rq_load_wqe : 1;
			u32 rq_load_next_mtt : 1;
			u32 rsvd : 11;
			/* The SGE index of current accessed WQE.0x0 */
			u32 rq_curt_sge_idx : 4;
			u32 rq_mtt_prefetch_maxlen1 : 2;
			u32 rq_mtt_prefetch_maxlen0 : 2;
			u32 rq_mtt_prefetch_maxwqe : 3;
			u32 rq_wqe_prefetch_minnum : 3;
			u32 rq_wqe_prefetch_maxnum : 3;
#endif
		} bs;
		u32 value;
	} dw15;
};

/* SRQ info in QPC */
struct chip_seg_srqc {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_pd : 18;
			u32 rsvd : 2;
			u32 srq_wqebb_size : 3;
			u32 srq_page_size : 4;
			u32 srq_size : 5;
#else
			u32 srq_size : 5;
			u32 srq_page_size : 4;
			/*
			 * Shared Receive WQE Basic Block (WQEBB) size in bytes is
			 * (2^rq_srq_wqebb_size)*16B. The minimum size is 32B and
			 * the values 0, 4, 5, 6, 7 are reserved.
			 * This field is updated by SRQC.srq_wqebb_size.
			 * 0x0
			 */
			u32 srq_wqebb_size : 3;
			u32 rsvd : 2;
			/*
			 * bit[17:00]Protection Domain. If the QP is a
			 * XRC transport service type,
			 * this filed should be updated by the "srq_pd"
			 * in the SRQ context
			 * pointed by XRCSRQ; else this field is updated
			 * by the "srq_pd" in the
			 * SRQ context associated with the QP.
			 * The following five Protection Domains have
			 * same configuration value:
			 * QCC.rc_pd, SQC.sq_pd, SQAC.sq_pd, RQC.rq_pd and RRWC.rrw_pd.
			 * 0x0
			 */
			u32 srq_pd : 18;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_so_ro : 2;
			u32 srq_dma_attr_idx : 6;
			u32 srq_rkey_en : 1;
			u32 srq_signature : 3;
			u32 srq_cqn : 20;
#else
			/*
			 * bit[19:00] Receive Queue completions are
			 * to be reported to this CQ number.
			 * If the QP is a XRC transport service type,
			 * this filed should be updated
			 * by the "srq_xrc_cqn" in the SRQ context
			 * pointed by XRCSRQ; else this
			 * field is configured by the driver.
			 * Configured by Driver
			 */
			u32 srq_cqn : 20;
			u32 srq_signature : 3;
			u32 srq_rkey_en : 1;
			u32 srq_dma_attr_idx : 6; /* bit[05:00] */
			/*
			 * It specifies the ATTR[1:0] bits in the
			 * outbound PCIe TLP headers of the
			 * DMA operation. This field is only valid when processing SRQ's WQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 * This field is updated by SRQC.srq_so_ro.
			 * 0x0
			 */
			u32 srq_so_ro : 2;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_state : 4;
			u32 rsvd2 : 4;
			u32 srqn : 18;
			u32 rsvd1 : 5;
			u32 srq_en : 1;
#else
			/*
			 * If set, indicates it should use SRQ as the receive queue.
			 * Configured by Driver
			 */
			u32 srq_en : 1;
			u32 rsvd1 : 5;
			/*
			 * SRQ number. If the QP is a XRC transport service type, this
			 * filed should be updated by the XRCSRQ; else this field is
			 * configured by the driver. Configured by Driver
			 */
			u32 srqn : 18;
			u32 rsvd2 : 4;
			/*
			 * Receive Queue State.
			 * 0x0: hardware has no access right;0x1: error;0xf: ok.Other: reserved.
			 * 0x0
			 */
			u32 srq_state : 4;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 state : 4;
			u32 container_sz : 2;
			u32 container_en : 1;
			u32 ep : 3;
			u32 cos : 3;
			u32 rq_srqn : 18;
			u32 rq_srq_en : 1;
#else
			u32 rq_srq_en : 1;
			u32 rq_srqn : 18;
			u32 cos : 3;
			u32 ep : 3;
			u32 container_en : 1;
			u32 container_sz : 2;
			u32 state : 4;
#endif
		} bs_c;

		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 16;
			u32 srq_xrcd : 16;
#else
			u32 srq_xrcd : 16;
			u32 rsvd : 16;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	u32 rsvd_dw4;

	/* DW5 */
	u32 srq_curt_wqe_gpa_h;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_curt_wqe_gpa_l : 24; /* bit[15:00] */
			u32 rsvd : 8;
#else
			u32 rsvd : 8; /* bit[15:00] */
			u32 srq_curt_wqe_gpa_l : 24;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 wqe_gpa : 20;
			u32 gpa_vld : 1; /* bit[15:00] */
			u32 wqe_gpa_flag : 1;
			u32 warth_flag : 1;
			u32 last_op_wqe : 1;
			u32 link_wqe : 1;
			u32 rqe_cnt_th : 4;
			u32 rsvd : 3;
#else
			u32 rsvd : 3;
			u32 rqe_cnt_th : 4;
			u32 link_wqe : 1;
			u32 last_op_wqe : 1;
			u32 warth_flag : 1;
			u32 wqe_gpa_flag : 1;
			u32 gpa_vld : 1;
			u32 wqe_gpa : 20;
#endif
		} bs_c;
		u32 value;
	} dw6;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 pre_ci : 16; /* bit[15:00] */
			u32 pi : 16;
#else
			u32 pi : 16; /* bit[15:00] */
			u32 pre_ci : 16;
#endif
		} bs;
		u32 value;
	} dw7;

	/* DW8 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_curt_sge_vld : 1;
			u32 srq_curt_sge_idx : 3;
			u32 srq_curt_sge_lkey : 28; /* bit[27:00] */
#else
			u32 srq_curt_sge_lkey : 28; /* bit[27:00] */
			u32 srq_curt_sge_idx : 3;
			u32 srq_curt_sge_vld : 1;
#endif
		} bs;
		u32 value;
	} dw8;

	/* DW9~10 */
	union {
		u64 srq_curt_sge_va; /* lo:bit[31:00],hi:bit[63:32] */
		struct {
			u32 srq_curt_sge_va_hi;
			u32 srq_curt_sge_va_lo;
		} dw9;
	};

	/* DW11 */
	u32 srq_curt_sge_remain_len; /* bit[31:00] */

	/* DW12 */
	u32 srq_curt_sge_dbuff_gpa_h; /* bit[63:32] */

	/* DW13 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_curt_sge_dbuff_gpa_l : 20;
			u32 srq_curt_sge_dbuff_gpa_vld : 1;
			u32 srq_curt_sge_dsgl : 1;
			u32 srq_curt_sge_used : 1;
			u32 srq_curt_sge_last : 1;
			u32 rsvd : 8;
#else
			u32 rsvd : 8;
			u32 srq_curt_sge_last : 1;
			u32 srq_curt_sge_used : 1;
			u32 srq_curt_sge_dsgl : 1;
			u32 srq_curt_sge_dbuff_gpa_vld : 1;
			u32 srq_curt_sge_dbuff_gpa_l : 20; /* bit[31:12] */
#endif
		} bs;
		u32 value;
	} dw13;

	/* DW14 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 srq_prefetch_thread_num : 2;
			u32 srq_mtt_prefetch_cline_num : 4;
			u32 srq_mtt_prefetch_cline_ptr : 6;
			u32 srq_mtt_prefetch_finish : 1;
			u32 srq_mtt_prefetch_sge_idx : 3;
			u32 rsvd : 16;
#else
			u32 rsvd : 16;
			u32 srq_mtt_prefetch_sge_idx : 3;
			u32 srq_mtt_prefetch_finish : 1;
			u32 srq_mtt_prefetch_cline_ptr : 6;
			u32 srq_mtt_prefetch_cline_num : 4;
			u32 srq_prefetch_thread_num : 2;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 prefetch_thread_num : 2;
			u32 mtt_page_size : 4;
			u32 rsvd1 : 10;
			u32 xrcd : 16;
#else
			u32 xrcd : 16;
			u32 rsvd1 : 10;
			u32 mtt_page_size : 4;
			u32 prefetch_thread_num : 2;
#endif
		} bs_c;

		u32 value;
	} dw14;

	/* DW15 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd2 : 11;
			u32 srq_mtt_prefetch_maxlen1 : 2;
			u32 rsvd1 : 17;
			u32 srq_load_mtt : 1;
			u32 srq_load_dbuff : 1;
#else
			u32 srq_load_dbuff : 1;
			u32 srq_load_mtt : 1;
			u32 rsvd1 : 17;
			u32 srq_mtt_prefetch_maxlen1 : 2;
			u32 rsvd2 : 11;
#endif
		} bs;

		u32 value;
	} dw15;
};

/* Queue Pair Common Context Format */
struct chip_seg_qpcc {
	/* DW0~1 */
	union {
		/* hi[63:32],lo[31:03],sq_rq_gpa_sign[02:00] */
		u64 sq_rq_l0mtt_gpa;
		struct {
			u32 sq_rq_l0mtt_gpa_hi;
			u32 sq_rq_l0mtt_gpa_lo;
		} dw0;
	};

	/* DW2~3 */
	union {
		/* hi[63:32],lo[31:02],sq_rq_at_hop_num[01:00] */
		u64 sq_rq_pi_record_gpa_at_hop_num;
		struct {
			u32 sq_rq_pi_record_gpa_hi;
			u32 sq_rq_pi_record_gpa_lo_at_hop_num; /* at_hop_num: bit[01:00] */
		} dw2;
	};

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rq_base_ci : 5;
			u32 rsvd : 2;
			u32 rc_max_size : 3;
			u32 sq_rq_mtt_page_size : 4;
			u32 qp_pd : 18;
#else
			u32 qp_pd : 18;
			u32 sq_rq_mtt_page_size : 4;
			u32 rc_max_size : 3;
			u32 rsvd : 2;
			u32 rq_base_ci : 5;
#endif
		} bs;
		u32 value;
	} dw4;

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_entry_size : 2;
			u32 rc_size : 4;
			u32 qp_rkey_en : 1;
			u32 qp_rwe : 1;
			u32 qp_rae : 1;
			u32 qp_rre : 1;
			u32 rsvd : 1;
			u32 qp_signature : 5;
			u32 qp_xrcd : 16;
#else
			u32 qp_xrcd : 16;
			u32 qp_signature : 5;
			u32 rsvd : 1;
			u32 qp_rre : 1;
			u32 qp_rae : 1;
			u32 qp_rwe : 1;
			u32 qp_rkey_en : 1;
			/*
			 * RDMARC table size, equals to (2^rc_size)*Entry Size.
			 * 0x0: the depth of table is equal to 1;
			 * 0x1: the depth of table is equal to 2;
			 * 0x2: the depth of table is equal to 4;
			 * ...
			 * 0x7: the depth of table is equal to 128;
			 * Others: reserved.
			 * Configured by Driver
			 */
			u32 rc_size : 4;
			/*
			 * Entry size of RDMARC table in bytes is (2^rc_entry_size)*16B.
			 * The minimum size is 32B and the maximum size is 64B;
			 * so the values 0 and 3 are
			 * reserved. Configured by Driver
			 */
			u32 rc_entry_size : 2;
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_entry_prefetch_maxnum : 3;
			u32 rsvd : 5;
			u32 rc_page_gpa_h : 24;
#else
			/*
			 * bit[63:40] Indicates the start GPA of RDMARC table.
			 * The driver needs to allocate
			 * continuous physical address for the RDMARC table.
			 * Configured by Driver
			 */
			u32 rc_page_gpa_h : 24;
			u32 rsvd : 5;
			/*
			 * Maximum number of prefetch Entries for RDMARC table.
			 * 000: prefetch number
			 * equals to zero; Others: prefetch number equals to
			 * (2^(rc_entry_prefetch_maxnum-1)). Configured by Driver
			 */
			u32 rc_entry_prefetch_maxnum : 3;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	u32 rc_page_gpa_l; /* bit[39:8] */
};

/* RDMARC Context Format */
struct chip_seg_rcc {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_curt_sge_vld : 1;
			u32 rsvd : 3;
			u32 rc_curt_sge_rkey : 28;
#else
			/*
			 * bit[27:00] Indicates the R_Key of current SGE.
			 * Using rc_curt_sge_rkey[27:8] to
			 * access the corresponding MPT.0x0
			 */
			u32 rc_curt_sge_rkey : 28;
			u32 rsvd : 3;
			/*
			 * Indicates current SGE information is valid.
			 * The remaining rc_curt_sge_* field are
			 * only valid when the rc_curt_sge_vld is asserted.
			 * 1: SGE is valid;0: SGE is
			 * invalid.
			 */
			u32 rc_curt_sge_vld : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1~2 */
	union {
		u64 rc_curt_sge_va;
		struct {
			u32 rc_curt_sge_va_hi;
			u32 rc_curt_sge_va_lo;
		} dw1;
	};

	/* DW3 */
	/* bit[31:00]Indicates the remaining memory space of current SGE.0x0 */
	u32 rc_curt_sge_remain_len;

	/* DW4 */
	u32 rc_curt_sge_dbuff_gpa_h; /* bit[63:32] */

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_curt_sge_dbuff_gpa_l : 20; /* bit[31:12] */
			u32 rc_curt_sge_dbuff_gpa_vld : 1;
			u32 rc_curt_sge_dsgl : 1;
			u32 rc_curt_sge_used : 1;
			u32 dsgl_en : 1;
			u32 rc_pi : 8;
#else
			/*
			 * bit[07:00] The Producer Index (PI) of
			 * RDMARC table (Step: Entry Size).0x0
			 */
			u32 rc_pi : 8;
			u32 dsgl_en : 1;
			u32 rc_curt_sge_used : 1;
			u32 rc_curt_sge_dsgl : 1;
			/*
			 * Indicates if the "rc_curt_sge_dbuff_gpa" field is valid.1: it is
			 * valid;0: it is invalid.0x0
			 */
			u32 rc_curt_sge_dbuff_gpa_vld : 1;
			u32 rc_curt_sge_dbuff_gpa_l : 20;  /* bit[31:12] */
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_pd : 18;
			u32 rc_signature : 3;
			u32 rsvd : 3;
			u32 rc_ci : 8;
#else
			/*
			 * bit[07:00] The Consumer Index (CI) of
			 * RDMARC table (Step: Entry Size).
			 */
			u32 rc_ci : 8;
			u32 rsvd : 3;
			u32 rc_signature : 3;
			/*
			 * bit[17:00] Protection Domain. If the QP is a XRC transport
			 * service type, this filed should
			 * be updated by the "srq_pd" in the SRQ context pointed by
			 * XRCSRQ; else this field should
			 * be equal to QCC.rc_pd.0x0
			 */
			u32 rc_pd : 18;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_state : 4;
			u32 rc_rae : 1;
			u32 rc_rre : 1;
			u32 rsvd2 : 1;
			u32 rc_mtt_prefetch_maxlen : 2;
			u32 rc_prefetch_thread_num : 2;
			u32 rc_load_entry : 1;
			u32 rc_load_mtt : 1;
			u32 rc_load_dbuff : 1;
			u32 rc_mtt_prefetch_finish : 1;
			u32 rc_mtt_prefetch_cline_num : 4;
			u32 rsvd1 : 5;
			u32 rc_prefetch_ci : 8;
#else
			u32 rc_prefetch_ci : 8;
			u32 rsvd1 : 5;
			u32 rc_mtt_prefetch_cline_num : 4;
			u32 rc_mtt_prefetch_finish : 1;
			u32 rc_load_dbuff : 1;
			u32 rc_load_mtt : 1;
			u32 rc_load_entry : 1;
			u32 rc_prefetch_thread_num : 2;
			u32 rc_mtt_prefetch_maxlen : 2;
			u32 rsvd2 : 1;
			u32 rc_rre : 1;
			u32 rc_rae : 1;
			u32 rc_state : 4;
#endif
		} bs;
		u32 value;
	} dw7;
};

/* RQ RDMA Write Context */
struct chip_seg_rrwc {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rrw_curt_sge_vld : 1;
			u32 rsvd : 3;
			u32 rrw_curt_sge_rkey : 28;
#else
			u32 rrw_curt_sge_rkey : 28; /* bit[27:00] */
			u32 rsvd : 3;			   /* bit[30:28] */
			u32 rrw_curt_sge_vld : 1;   /* bit[31] */
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1~2 */
	union {
		u64 rrw_curt_sge_va; /* hi:bit[63:32],lo:bit[31:00] */
		struct {
			u32 rrw_curt_sge_va_hi;
			u32 rrw_curt_sge_va_lo;
		} dw1;
	};

	/* DW3 */
	u32 rrw_curt_sge_remain_len; /* bit[31:00] */

	/* DW4 */
	u32 rrw_curt_sge_dbuff_gpa_h; /* bit[63:32] */

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rrw_curt_sge_dbuff_gpa_l : 20; /* bit[31:12] */
			u32 rrw_curt_sge_dbuff_gpa_vld : 1;
			u32 rrw_curt_sge_dsgl : 1;
			u32 rrw_curt_sge_used : 1;
			u32 rsvd : 9;
#else
			u32 rsvd : 9;
			u32 rrw_curt_sge_used : 1;
			u32 rrw_curt_sge_dsgl : 1;
			u32 rrw_curt_sge_dbuff_gpa_vld : 1;
			u32 rrw_curt_sge_dbuff_gpa_l : 20; /* bit[31:12] */
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rrw_pd : 18;
			u32 rrw_signature : 3;
			u32 rsvd : 11;
#else
			u32 rsvd : 11;
			u32 rrw_signature : 3;
			u32 rrw_pd : 18;

#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rrw_state : 4;
			u32 rrw_rwe : 1;
			u32 rsvd3 : 2;
			u32 rrw_mtt_prefetch_maxlen : 2;
			u32 rrw_prefetch_thread_num : 2;
			u32 rsvd2 : 1;
			u32 rrw_load_mtt : 1;
			u32 rrw_load_dbuff : 1;
			u32 rrw_mtt_prefetch_finish : 1;
			u32 rrw_mtt_prefetch_cline_num : 4;
			u32 rsvd1 : 13;
#else
			u32 rsvd1 : 13;
			u32 rrw_mtt_prefetch_cline_num : 4;
			u32 rrw_mtt_prefetch_finish : 1;
			u32 rrw_load_dbuff : 1;
			u32 rrw_load_mtt : 1;
			u32 rsvd2 : 1;
			u32 rrw_prefetch_thread_num : 2;
			u32 rrw_mtt_prefetch_maxlen : 2;
			u32 rsvd3 : 2;
			u32 rrw_rwe : 1;
			u32 rrw_state : 4;
#endif
		} bs;
		u32 value;
	} dw7;
};

/*
 *****************************************************************************
	Data Structure:  SQPC
	Description:
*****************************************************************************
*/
struct chip_seg_sqpc {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqp_signature : 5;
			u32 rsvd0 : 14;
			u32 sqp_ci_on_chip : 1;
			u32 sqp_wqe_size : 3;
			u32 sqp_page_size : 4;
			u32 sqp_size : 5;
#else
			u32 sqp_size : 5;
			u32 sqp_page_size : 4;
			u32 sqp_wqe_size : 3;
			u32 sqp_ci_on_chip : 1;
			u32 rsvd0 : 14;
			u32 sqp_signature : 5;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqp_so_ro : 2;
			u32 sqp_dma_attr_idx : 6;
			u32 rsvd0 : 8;
			u32 sqp_ci : 16;
#else
			u32 sqp_ci : 16;
			u32 rsvd0 : 8;
			u32 sqp_dma_attr_idx : 6;
			u32 sqp_so_ro : 2;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqp_state : 4;
			u32 rsvd0 : 12;
			u32 sqp_pi : 16;
#else
			u32 sqp_pi : 16;
			u32 rsvd0 : 12;
			u32 sqp_state : 4;
#endif
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqp_wqecnt_lth : 4;
			u32 sqp_wqecnt_rctl_en : 1;
			u32 rsvd0 : 15;
			u32 sqp_load_ci : 1;
			u32 sqp_load_page_gpa : 1;
			u32 sqp_wqe_curt_page_vld : 1;
			u32 sqp_wqe_next_page_vld : 1;
			u32 sqp_wqe_curt_page_gpa_h : 8;
#else
			u32 sqp_wqe_curt_page_gpa_h : 8;
			u32 sqp_wqe_next_page_vld : 1;
			u32 sqp_wqe_curt_page_vld : 1;
			u32 sqp_load_page_gpa : 1;
			u32 sqp_load_ci : 1;
			u32 rsvd0 : 15;
			u32 sqp_wqecnt_rctl_en : 1;
			u32 sqp_wqecnt_lth : 4;
#endif
		} bs;
		u32 value;
	} dw3;

	u32 sqp_wqe_curt_page_gpa_m;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqp_wqe_curt_page_gpa_l : 12;
			u32 sqp_wqe_next_page_gpa_h : 20;
#else
			u32 sqp_wqe_next_page_gpa_h : 20;
			u32 sqp_wqe_curt_page_gpa_l : 12;
#endif
		} bs;
		u32 value;
	} dw5;

	u32 sqp_wqe_next_page_gpa_l;

	u32 rsvd_dw7;

	u32 rsvd_dw8;

	u32 rsvd_dw9;

	u32 rsvd_dw10;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd0 : 16;
			u32 sqp_prefetch_thread_num : 2;
			u32 rsvd1 : 10;
			u32 sqp_mtt_page_size : 4;
#else
			u32 sqp_mtt_page_size : 4;
			u32 rsvd1 : 10;
			u32 sqp_prefetch_thread_num : 2;
			u32 rsvd0 : 16;
#endif
		} bs;
		u32 value;
	} dw11;

	u32 sqp_l0mtt_gpa_h;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqp_l0mtt_gpa_l : 29;
			u32 sqp_gpa_sign : 3;
#else
			u32 sqp_gpa_sign : 3;
			u32 sqp_l0mtt_gpa_l : 29;
#endif
		} bs;
		u32 value;
	} dw13;

	u32 sqp_pi_record_gpa_h;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sqp_pi_record_gpa_l : 30;
			u32 sqp_at_hop_num : 2;
#else
			u32 sqp_at_hop_num : 2;
			u32 sqp_pi_record_gpa_l : 30;
#endif
		} bs;
		u32 value;
	} dw15;
};

/* Queue Pair Context */
struct qpc_chip_seg {
	/* RQ RDMA Write Context (32B) */
	struct chip_seg_rrwc rrwc;
	/* RDMARDC Context (32B) */
	struct chip_seg_rcc rcc;

	/* Send Queue Context (64B) */
	struct chip_seg_sqc sqc;
	/* Send Queue ACK Context (64B) */
	struct chip_seg_sqac sqac;
	union {
		/* Receive Queue Context (64B) */
		struct chip_seg_rqc rqc;
		/* RQC Shared Receive Queue Mode(64B) */
		struct chip_seg_srqc srqc;
	};

	/* Queue Pair Common Context (32B) */
	struct chip_seg_qpcc qpcc;
};

/* Timer Section(32B) */
struct qpc_timer_seg {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd3 : 1;
			/*
			 * Indicate how many timers this timer section
			 * supports:0:rsvd,X:support up to X timers
			 */
			u32 tss_timer_num : 3;
			/*
			 * Lock flag indicates whether this timer
			 * section is locked by one API or not
			 * 1: locked 0: unlock
			 */
			u32 tss_lock_flag : 1;
			/*
			 * Modify flag indicates whether this timer section
			 * has been modified by other API
			 * without lock or not. 1: has been modified,0: has not been modified
			 */
			u32 tss_modify_flag : 1;
			u32 rsvd2 : 1;
			/*
			 * close flag indicates this connection needs to close
			 * and this XID context will be
			 * de-allocated by control plane; 0: not close,1:
			 * close,this timer section will be
			 * picked off from timer wheel and issue a special
			 * time-out API to tell ucode this
			 * context resource can be de-allocated.
			 */
			u32 tss_close_flag : 1;
			u32 rsvd1 : 3;
			u32 rsvd0 : 2;
			/*
			 * Timer link valid,
			 * 1: this timer section is hung in timing wheel
			 * 0: this timer section is not hung in any timing wheel
			 */
			u32 tlwi_lv : 1;
			/* indicate which timer is hung in timing wheel */
			u32 tlwi_timer_id : 3;
			/* indicate which timing wheel this timer section is hung in */
			u32 tlwi_wheel_id : 3;
			/* indicate which fire spoke this timer section is hung in */
			u32 tlwi_link_spoke : 12;
#else
			u32 tlwi_link_spoke : 12;
			u32 tlwi_wheel_id : 3;
			u32 tlwi_timer_id : 3;
			u32 tlwi_lv : 1;
			u32 rsvd0 : 2;
			u32 rsvd1 : 3;

			u32 tss_cl : 1;
			u32 rsvd2 : 1;
			u32 tss_modify_flag : 1;
			u32 tss_lock_flag : 1;
			u32 tss_timer_num : 3;
			u32 rsvd3 : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	/*
	 * Previous link pointer, data structure is referred
	 * to timer pointer data structure
	 */
	u32 pre_link_ptr0;

	/* DW2 */
	u32 pre_link_ptr1;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 pre_link_ptr : 8;
			u32 next_link_ptr : 24;
#else
			u32 next_link_ptr : 24;
			u32 pre_link_ptr : 8;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	/*
	 * Next link pointer, data structure is referred
	 * to timer pointer data structure
	 */
	u32 next_link_ptr1;

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 next_link_ptr : 16;
			u32 rsvd : 16;
#else
			u32 rsvd : 16;
			u32 next_link_ptr : 16;
#endif
		} bs;
		u32 value;
	} dw5;

	u32 ts_rsvd[2]; /* reserve 2DW */
};

union ucode_rq_last {
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 rq_last_optype : 1;
		u32 rq_last_opcode : 1;
		u32 rsvd : 1;
		u32 atomic_aloc_fail : 1;
		u32 comm_est : 1;
		u32 rnr_state : 1;
		u32 err_state : 1;
		u32 rq_ready_n : 1;
		u32 last_msn : 24;
#else
		u32 last_msn : 24;
		u32 rq_ready_n : 1;
		u32 err_state : 1;
		u32 rnr_state : 1;
		u32 comm_est : 1;
		u32 atomic_aloc_fail : 1;
		u32 rsvd : 1;
		u32 rq_last_opcode : 1;
		u32 rq_last_optype : 1;
#endif
	} bs;

	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 rq_last_op : 2;
		u32 rsv_com : 30;
#else
		u32 rsv_com : 30;
		u32 rq_last_op : 2;
#endif
	} bs1;

	u32 value;
};

/* * sq ack ctx */
struct ucode_sq_ack_ctx {
	/* DW12 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 time_interval : 6;
			u32 timestamp : 26;
#else
			u32 timestamp : 26;
			u32 time_interval : 6; // timer update interval
#endif
		} bs;
		u32 value;
	} dw12;

	/* DW13 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 last_md_nrcv : 1;
			u32 nof_sw : 1;
			u32 rx_port : 3;
			u32 credit_nlimit : 1;
			u32 rsvd : 2;
			u32 lsn : 24;
#else
			u32 lsn : 24;
			u32 rsvd : 2;
			u32 credit_nlimit : 1;
			u32 rx_port : 3;
			u32 nof_sw : 1;
			u32 last_md_nrcv : 1; // last metadata flag in dif
#endif
		} bs;
		u32 value;
	} dw13;

	/* DW14 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 timer_type : 1;
			u32 timer_en : 1;
			u32 rnr_retry_cnt : 3;
			u32 retry_cnt : 3;
			u32 sq_rcv_psn : 24;
#else
			u32 sq_rcv_psn : 24;
			u32 retry_cnt : 3;
			u32 rnr_retry_cnt : 3;
			u32 timer_en : 1;
			u32 timer_type : 1;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsv_com : 2;
			u32 retry_reset : 6;
			u32 rsv_com1 : 24;
#else
			u32 rsv_com1 : 24;
			u32 retry_reset : 6;
			u32 rsv_com : 2;
#endif
		} bs1;
		u32 value;
	} dw14;

	/* DW15 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 next_rdat : 1;
			u32 sq_db : 1;
			u32 rnr_state : 1;
			u32 retry_state : 1;
			u32 rsvd : 2;
			u32 err_state : 1;
			u32 sqa_ready_n : 1;
			u32 sq_rcv_msn : 24;
#else
			u32 sq_rcv_msn : 24;
			u32 sqa_ready_n : 1;
			u32 err_state : 1;
			u32 rsvd : 2;
			u32 retry_state : 1;
			u32 rnr_state : 1;
			u32 sq_db : 1;
			u32 next_rdat : 1;
#endif
		} bs;
		u32 value;
	} dw15;

	/* DW16 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sra_ack_cnt : 8;
			u32 wqe_first_psn : 24;
#else
			u32 wqe_first_psn : 24;
			u32 sra_ack_cnt : 8;
#endif
		} bs;
		u32 value;
	} dw16;

	/* DW17 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 lcn : 8;
			u32 max_fwd_psn : 24;
#else
			u32 max_fwd_psn : 24;
			u32 lcn : 8;
#endif
		} bs;
		u32 value;
	} dw18;

	/* DW18 */
	u32 sq_rcv_len;

	/* DW19 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 18;
			u32 task_tag : 14;
#else
			u32 task_tag : 14;
			u32 rsvd : 18;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 wqe2host_ci : 8;
			u32 last_nak_psn : 24;
#else
			u32 last_nak_psn : 24;
			u32 wqe2host_ci : 8;
#endif
		} nofaa;
		u32 value;
	} dw17;
};

struct ucode_sq_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sra_cnt : 8;
			u32 next_send_psn : 24;
#else
			/*
			 * Initial value of the driver in BTH Packet
			 * Sequence Number(initial)RTR2RTS mode
			 */
			u32 next_send_psn : 24;
			u32 sra_cnt : 8;		/* Initiator depth count value */
#endif
		} bs;
		u32 value;
	} dw8;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 lcn : 8;
			u32 ssn : 24;
#else
			u32 ssn : 24;
			u32 lcn : 8;
#endif
		} bs;
		u32 value;
	} dw9;

	/* DW2 */
	u32 send_left_len;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 17;
			u32 last_md_nst : 1;
			u32 task_tag : 14;
#else
			u32 task_tag : 14;
			u32 last_md_nst : 1;
			u32 rsvd : 17;
#endif
		} dif;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 10;
			u32 dci_state : 2;
			u32 drctn : 20;
#else
			u32 drctn : 20;
			u32 dci_state : 2;
			u32 rsvd : 10;
#endif
		} drc;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sticky : 1;
			u32 work_queue : 2;
			u32 wqe2host_pi : 8;
			u32 rsvd : 21;
#else
			u32 rsvd : 21;
			u32 wqe2host_pi : 8;
			u32 work_queue : 2;
			u32 sticky : 1;
#endif
		} nofaa;
		u8 vbs_sq[4];
		u32 value;
	} dw11;

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sync : 1;
			u32 credit_ignore : 1;
			u32 err_state : 1;
			u32 sq_ready_n : 1;
			u32 sq_flush_wait : 1;
			u32 port_err : 1;
			u32 ud_last_time : 26;
#else
			u32 ud_last_time : 26;
			u32 port_err : 1;
			u32 sq_flush_wait : 1;
			u32 sq_ready_n : 1;
			u32 err_state : 1;
			u32 credit_ignore : 1;
			u32 sync : 1;
#endif
		} bs;
		u32 value;
	} dw12;

	struct ucode_sq_ack_ctx ack_ctx;
};

/* * rq ack ctx */
struct ucode_rq_ack_ctx {
	/* DW24 */
	u32 rq_rsp_left;

	/* DW25 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rra_ack_cnt : 8;
			u32 next_ack_psn : 24;
#else
			u32 next_ack_psn : 24;
			u32 rra_ack_cnt : 8;
#endif
		} bs;
		u32 value;
	} dw25;

	/* DW26 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rqa_last_optype : 1;
			u32 port_err : 1;
			u32 nxt_rdat : 1;
			u32 repeat_flag : 1;
			u32 nak_rsp : 1;
			u32 err_state : 1;
			u32 rqa_ready_n : 1;
			u32 remote_db : 1;
			u32 last_ackpsn_low : 8;
			u32 atomic_aloc_fail : 1;
			u32 rq_flush_wait : 1;
			u32 last_wqe_reached : 1;
			u32 rq_recv_psn_cnt : 5;
			u32 syndrome : 8;
#else
			u32 syndrome : 8;
			u32 rq_recv_psn_cnt : 5;
			u32 last_wqe_reached : 1;
			u32 rq_flush_wait : 1;
			u32 atomic_aloc_fail : 1;
			u32 last_ackpsn_low : 8;
			u32 remote_db : 1;
			u32 rqa_ready_n : 1;
			u32 err_state : 1;
			u32 nak_rsp : 1;
			u32 repeat_flag : 1;
			u32 nxt_rdat : 1;
			u32 port_err : 1;
			u32 rqa_last_optype : 1;
#endif
		} bs;

		u32 value;
	} dw26;

	/* DW27 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 1;
			u32 credit : 7;
			u32 msn : 24;
#else
			u32 msn : 24;
			u32 credit : 7;
			u32 rsvd : 1;
#endif
		} bs;
		u32 value;
	} dw27;

	/* DW28 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 32;
#else
			u32 rsvd : 32;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd0 : 3;
			u32 back_len : 13;
			u32 last_md_nst : 1;
			u32 rsvd1 : 1;
			u32 task_tag : 14;
#else
			u32 task_tag : 14;
			u32 rsvd1 : 1;
			u32 last_md_nst : 1;
			u32 back_len : 13;
			u32 rsvd0 : 3;
#endif
		} dif;
		u32 value;
	} dw28;
};

struct ucode_rq_ctx {
	/* DW20 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rra_cnt : 8;
			u32 next_rcv_psn : 24;
#else
			u32 next_rcv_psn : 24;
			u32 rra_cnt : 8;
#endif
		} bs;
		u32 value;
	} dw20;

	/* DW21 */
	union {
		u32 rq_rcv_len;
	} dw21;

	/* DW22 */
	union ucode_rq_last dw22;

	/* DW23 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 last_md_nrcv : 1;
			u32 rsvd : 7;
			u32 mpt_index : 24;
#else
			u32 mpt_index : 24;
			u32 rsvd : 7;
			u32 last_md_nrcv : 1; // last metadata flag in dif
#endif
		} bs;
		u32 value;
	} dw23;
	/* DW24 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 18;
			u32 task_tag : 14;
#else
			u32 task_tag : 14;
			u32 rsvd : 18;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ctrl_rcv : 2;
			u32 repeat : 1;
			u32 rsvd : 29;
#else
			u32 rsvd : 29;
			u32 repeat : 1;
			u32 ctrl_rcv : 2;
#endif
		} nofaa;
		u32 value;
	} dw24;
	/* DW24~27 */
	struct ucode_rq_ack_ctx ack_ctx;
};

struct ucode_dcqcn_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cnp_flag : 1;
			u32 f_cnt : 3;
			u32 cnp_receive : 1;
			u32 ai_cnt : 3;
			u32 reinq_times : 12;
			u32 rsvd : 2;
			u32 alpha : 10;
#else
			u32 alpha : 10;
			u32 rsvd : 2;
			u32 reinq_times : 12;
			u32 ai_cnt : 3;
			u32 cnp_receive : 1;
			u32 f_cnt : 3;
			u32 cnp_flag : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 token_period : 4;
			u32 rate_period : 4;
			u32 cur_rate : 24;
#else
			u32 cur_rate : 24;
			u32 rate_period : 4;
			u32 token_period : 4;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 target_rate : 24;
#else
			u32 target_rate : 24;
			u32 rsvd : 8;
#endif
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 token : 24; /* valid token */
#else
			u32 token : 24;
			u32 rsvd : 8;
#endif
		} bs;
		u32 value;
	} dw3;

	u32 rcnp_timestamp;  /* last receive cnp */
	u32 alpha_timestamp; /* last update alpha */
	u32 rate_timestamp;  /* last update rate */
};

struct ucode_common_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsp_ready_n : 1;
			u32 req_ready_n : 1;
			u32 rq_flush : 1;
			u32 sq_flush : 1;
			u32 rsvd : 3;
			u32 ccf_appid : 3;
			u32 port : 2;
			/* for user plugin extension */
			u32 ulp_type : 4;
			u32 fake : 1;
			/* Cq overflow Indicates whether WQ CATAS is generated. */
			u32 cq_ovl_flag : 1;
			u32 sqd_event : 1;
			u32 vf_id : 13;
#else
			u32 vf_id : 13;
			u32 sqd_event : 1;
			/* Cq overflow Indicates whether WQ CATAS is generated. */
			u32 cq_ovl_flag : 1;
			u32 fake : 1;
			u32 ulp_type : 4;
			u32 port : 2;
			u32 ccf_appid : 3;
			u32 rsvd : 3;
			u32 sq_flush : 1;
			u32 rq_flush : 1;
			u32 req_ready_n : 1;
			u32 rsp_ready_n : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 unit_time : 8;
			u32 rsvd : 11;
			u32 dst_vfid : 13;
#else
			u32 dst_vfid : 13;
			u32 rsvd : 11;
			u32 unit_time : 8;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 14;
			u32 pd : 18;
#else
			u32 pd : 18;
			u32 rsvd : 14;
#endif
		} ud;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 12;
			u32 drcin : 20;
#else
			u32 drcin : 20;
			u32 rsvd : 12;
#endif
		} drct;
		u32 drci_drc_key_h;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		u32 qkey;
		u32 drci_drc_key_l;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cnp_tx_filter_ts : 12;
			u32 rq_cqn : 20;
#else
			u32 rq_cqn : 20;
			u32 cnp_tx_filter_ts : 12;
#endif
		} bs;
		u32 value;
	} dw3;
};

struct drv_ucode_all_info {
	/* DW0~DW4 */
	struct ucode_common_ctx common;

	/* DW5~DW18 */
	struct ucode_sq_ctx sq_ctx;

	/* DW19~DW27 */
	struct ucode_rq_ctx rq_ctx;
};

struct drv_path_info {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 bond_tx_hash_value : 16;
			u32 dmac_h16 : 16;
#else
			u32 dmac_h16 : 16;
			u32 bond_tx_hash_value : 16;
#endif
		} bs;
		u32 value;
	} dw0;

	u32 dmac_l32;

	/* DW2~5 */
	u8 dgid[16];

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ext_mtu : 1;
			u32 ext_md : 1;
			u32 rcq_lb1 : 1;
			u32 scq_lb1 : 1;
			u32 tclass : 8;
			u32 flow_label : 20;
#else
			u32 flow_label : 20; /* GRH flow lable */
			u32 tclass : 8;
			u32 scq_lb1 : 1;
			u32 rcq_lb1 : 1;
			u32 ext_md : 1;
			u32 ext_mtu : 1;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sl : 3;
			u32 loop : 1;
			u32 udp_src_port : 8;
			u32 rsvd : 4;
			u32 base_sgid_n : 1;
			u32 sgid_index : 7;
			u32 hoplmt : 8;
#else
			u32 hoplmt : 8;
			u32 sgid_index : 7;
			u32 base_sgid_n : 1;
			u32 rsvd : 4;
			u32 udp_src_port : 8;
			u32 loop : 1;
			u32 sl : 3;
#endif
		} bs;
		u32 value;
	} dw7;
};

/* Driver use segment ,16B */
struct qpc_drv_seg {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 service_type : 3;
			u32 fre : 1;
			u32 state : 4;
			u32 dest_qp : 24;
#else
			/*
			 * Destination QP number, which is extended to 24
			 * bits in consideration of interconnection
			 * with commercial devices.
			 */
			u32 dest_qp : 24;
			/*
			 * QP state 0000:RST 0001:INIT 0010:RTR 0011:RTS 0100:SQEr
			 * 0101:SQD(Drained) 0110:ERR
			 * 0111:Draining This field is not modified for the
			 * *1XXX:Reserved driver verbs and is
			 * modified by the microcode based on the command type.
			 */
			u32 state : 4;
			/* Indicates whether the local FRPMR is enabled. */
			u32 fre : 1;
			/*
			 * Transmission Type
			 * 000:RC
			 * 001:UC
			 * 010:RD
			 * 011 UD
			 * 101:XRC
			 * Other:Reserved
			 */
			u32 service_type : 3;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rc_flag : 1;
			u32 dif_en : 1;
			u32 datagram : 1;
			u32 local_trans : 1;
			u32 srq_en : 1;
			u32 drc : 1;
			u32 vroce_en : 1;
			u32 rsvd : 1;
			u32 xrc_vld : 1;
			u32 ep : 4;
			u32 db_cos : 3;
			u32 host_oqid : 16;
#else
			u32 host_oqid : 16;
			u32 db_cos : 3;
			u32 ep : 4;
			u32 xrc_vld : 1;
			u32 rsvd : 1;
			u32 vroce_en : 1;
			u32 drc : 1;
			u32 srq_en : 1;
			u32 local_trans : 1;
			u32 datagram : 1;
			u32 dif_en : 1;
			u32 rc_flag : 1; /* Reliable service : */
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ack_to : 5;
			/*
			 * NAK code of RNR. This parameter is mandatory when INIT2RNR and
			 * RTR2RTS\SQE2RTS\SQD2SQD\SQD2RTS is optional.
			 */
			u32 min_rnr_nak : 5;
			/*
			 * The maximum number of RNR retransmissions is 7.
			 * The value 7 indicates that the
			 * maximum number of retransmissions is 7,
			 * and the value 0 indicates that the
			 * retransmission is not performed.
			 */
			u32 rnr_retry_limit : 3;
			/*
			 * Number of ACK retransmissions. The value 7
			 * indicates unlimited times, and the
			 * value 0 indicates no retransmission.
			 */
			u32 to_retry_limit : 3;
			u32 ack_timer_step : 6;
			u32 rsvd : 2;
			u32 base_mtu_n : 1;
			u32 mtu_code : 4;
			u32 pmtu : 3;
#else
			u32 pmtu : 3;
			u32 mtu_code : 4;
			u32 base_mtu_n : 1;
			u32 rsvd : 2;
			u32 ack_timer_step : 6;
			u32 to_retry_limit : 3;
			u32 rnr_retry_limit : 3;
			u32 min_rnr_nak : 5;
			u32 ack_to : 5;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 com_rsvd0 : 10;
			u32 retry_reset : 6;
			u32 com_rsvd : 16;
#else
			u32 com_rsvd : 16;
			u32 retry_reset : 6;
			u32 com_rsvd0 : 10;
#endif
		} bs1;

		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/* The maximum value of initiator depth is 128. */
			u32 sra_max : 3;
			/* The maximum value of responser resource is 128. */
			u32 rra_max : 3;
			/*
			 * Indicates whether the RQ disables the credit.
			 * The SRQ is disabled by default and
			 * must be set to 1.
			 */
			u32 invalid_credit : 1;
			u32 ackto_overstep : 1;
			u32 rsvd : 2;
			u32 srq_container : 1;
			u32 dsgl : 1;
			u32 local_qp : 20;	  /* Local QP number */
#else
			u32 local_qp : 20;
			u32 dsgl : 1;
			u32 srq_container : 1;
			u32 rsvd : 2;
			u32 ackto_overstep : 1;
			u32 invalid_credit : 1;
			u32 rra_max : 3;
			u32 sra_max : 3;
#endif
		} bs;
		u32 value;
	} dw3;
};

/* QPC Struct */
struct qpc_sw_seg {
	/* driver seg, DW0 ~ DW3 */
	struct qpc_drv_seg drv_seg;

	/* path seg, DW4 ~ DW11 */
	struct drv_path_info path_seg;

	/* 112B(DW12~DW39) */
	struct drv_ucode_all_info ucode_seg;

	/* 32B(DW40~DW47) */
	struct ucode_ext_ctx ext_seg;
};

/* QPC Struct */
struct roce_qp_context {
	struct qpc_chip_seg chip_seg;
	struct qpc_timer_seg timer_seg;
	struct qpc_sw_seg sw_seg;
};

struct roce_aa_qp_context {
	struct qpc_chip_seg chip_seg;
	struct qpc_timer_seg timer_seg;
	struct qpc_sw_seg sw_seg;
	struct ucode_nofaa_ctx nofaa;
};

/* *QPC Format end */

/* * SRQC Format start */
struct roce_srq_context {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 pdn : 18; /* Protection Domain. */
			u32 lth_pre_en : 1;
			/*
			 * If set, the producer counter of Shared Receive Queue
			 * is stored in the chip, the counter is absolute value.
			 */
			u32 pcnt_on_chip : 1;
			/*
			 * Shared Receive WQE Basic Block (WQEBB) size
			 * in bytes is (2^rq_wqebb_size)*16B.
			 * The minimum size is 32B and the
			 * values 0, 4, 5, 6, 7 are reserved
			 */
			u32 wqebb_size : 3;
			/* Page size of SRQ, equals to (2^srq_page_size)*4KB */
			u32 page_size : 4;
			/*
			 * Shared Receive Queue size, equals to (2^srq_size)*WQEBB,
			 * the maximum SRQ size is 16K WQEs, so this field doesn't exceed 14.
			 */
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
			 * Shared Receive WQE Basic Block (WQEBB) size
			 * in bytes is (2^rq_wqebb_size)*16B.
			 * The minimum size is 32B and the
			 * values 0, 4, 5, 6, 7 are reserved
			 */
			u32 wqebb_size : 3;
			/*
			 * If set, the producer counter of Shared Receive Queue
			 * is stored in the chip, the counter is absolute value.
			 */
			u32 pcnt_on_chip : 1;
			u32 lth_pre_en : 1;
			u32 pdn : 18; /* Protection Domain. */
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * It specifies the ATTR[1:0] bits in the outbound
			 * PCIe TLP headers of the DMA operation.
			 * This field is only valid when processing SRQ's WQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 */
			u32 so_ro : 2;
			/*
			 * It specifies the outbound PCIe TLP header
			 * attribute of the DMA operation.
			 * This filed is only valid when processing SRQ's WQEs.
			 */
			u32 dma_attr_idx : 6;
			u32 rkey_en : 1;
			u32 srq_wqe_check_en : 1;
			u32 rsvd : 2;
			/*
			 * Completion Queue to report XRC messages
			 * directed to this SRQ (XRC only)
			 */
			u32 xrc_cqn : 20;
#else
			/*
			 * Completion Queue to report XRC messages
			 * directed to this SRQ (XRC only)
			 */
			u32 xrc_cqn : 20;
			u32 rsvd : 2;
			u32 srq_wqe_check_en : 1;
			u32 rkey_en : 1;
			/*
			 * It specifies the outbound PCIe TLP header
			 * attribute of the DMA operation.
			 * This filed is only valid when processing SRQ's WQEs.
			 */
			u32 dma_attr_idx : 6;
			/*
			 * It specifies the ATTR[1:0] bits in the outbound
			 * PCIe TLP headers of the DMA operation.
			 * This field is only valid when processing SRQ's WQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 */
			u32 so_ro : 2;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * It specifies the ATTR[1:0] bits in the outbound
			 * PCIe TLP headers of the DMA operation.
			 * This field is only valid when processing SRQ's WQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 */
			u32 so_ro : 2;
			/*
			 * It specifies the outbound PCIe TLP header
			 * attribute of the DMA operation.
			 * his filed is only valid when processing SRQ's WQEs.
			 */
			u32 dma_attr_idx : 6;
			u32 rkey_en : 1;
			u32 xrc_cqn2 : 7;
			u32 ccnt : 16;
#else
			u32 ccnt : 16;
			u32 xrc_cqn2 : 7;
			u32 rkey_en : 1;
			/*
			 * It specifies the outbound PCIe TLP header
			 * attribute of the DMA operation.
			 * This filed is only valid when processing SRQ's WQEs.
			 */
			u32 dma_attr_idx : 6;
			/*
			 * It specifies the ATTR[1:0] bits in the outbound
			 * PCIe TLP headers of the DMA operation.
			 * This field is only valid when processing SRQ's WQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 */
			u32 so_ro : 2;
#endif
		} bs_c;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * SRQ status.
			 * 0x0: hardware has no access right;
			 * 0x1: error;
			 * 0xf: ok.
			 * Other: reserved.
			 */
			u32 state : 4;
			u32 rsvd2 : 2;
			u32 container_en : 1;
			u32 ep : 3;
			u32 cos : 3;
			u32 rsvd1 : 1;
			u32 srqn : 18;		  /* SRQ number. */
#else
			u32 srqn : 18; /* SRQ number. */
			u32 rsvd1 : 1;
			u32 cos : 3;
			u32 ep : 3;
			u32 container_en : 1;
			u32 rsvd2 : 2;
			/*
			 * SRQ status.
			 * 0x0: hardware has no access right;
			 * 0x1: error;
			 * 0xf: ok.
			 * Other: reserved.
			 */
			u32 state : 4;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * SRQ status.
			 * 0x0: hardware has no access right;
			 * 0x1: error;
			 * 0xf: ok.
			 * Other: reserved.
			 */
			u32 state : 4;
			/*
			 * 0:15 normal + 1 link wqe; 1:7 normal + 1 linkwqe
			 * 2:3normal + 1 linkwqe 3:1
			 * normal + 1 linkwqe
			 */
			u32 container_size : 2;
			u32 container_en : 1;
			u32 xrc_cqn1 : 3;
			u32 warn_th : 4;	 /* warn thresthod */
			u32 srqn : 18;	   /* SRQ number. */
#else
			u32 srqn : 18; /* SRQ number. */
			u32 warn_th : 4;
			u32 xrc_cqn1 : 3;
			u32 container_en : 1;
			/*
			 * 0:15 normal + 1 link wqe; 1:7 normal + 1 linkwqe
			 * 2:3normal + 1 linkwqe 3:1
			 * normal + 1 linkwqe
			 */
			u32 container_size : 2;
			/*
			 * SRQ status.
			 * 0x0: hardware has no access right;
			 * 0x1: error;
			 * 0xf: ok.
			 * Other: reserved.
			 */
			u32 state : 4;
#endif
		} bs_c;

		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * Limit Threshold. If the "srq_lth" is not zero, and the "srq_wqe_cnt"
			 * drops below the "srq_lth" when a WQE is de-queued from the SRQ,
			 * then an SRQ
			 * limit event is fired and the "srq_lth" is set to zero.
			 */
			u32 lth : 16;
			/*
			 * The Scalable RC Domain. The received message
			 * can be served only if the XRC
			 * Domain of the transport QP of received message
			 * matches this field.
			 */
			u32 xrcd : 16;
#else
			/*
			 * The Scalable RC Domain. The received message
			 * can be served only if the XRC
			 * Domain of the transport QP of received message
			 * matches this field.
			 */
			u32 xrcd : 16;
			/*
			 * Limit Threshold. If the "srq_lth" is not
			 * zero, and the "srq_wqe_cnt"
			 * drops below the "srq_lth" when a WQE is
			 * de-queued from the SRQ, then an SRQ
			 * limit event is fired and the "srq_lth" is set to zero.
			 */
			u32 lth : 16;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/* Limit Threshold. If the "srq_lth" is not zero,
			 * and the "srq_wqe_cnt"
			 * drops below the "srq_lth" when a WQE is de-queued from the
			 * SRQ, then an SRQ
			 * limit event is fired and the "srq_lth" is set to zero.
			 */
			u32 head_index : 16;
			/*
			 * The Scalable RC Domain. The received
			 * message can be served only if the XRC
			 * Domain of the transport QP of received
			 * message matches this field.
			 */
			u32 pcnt : 16;
#else
			/*
			 * The Scalable RC Domain. The received message
			 * can be served only if the XRC
			 * Domain of the transport QP of
			 * received message matches this field.
			 */
			u32 pcnt : 16;
			/*
			 * Limit Threshold. If the "srq_lth" is
			 * not zero, and the "srq_wqe_cnt"
			 * drops below the "srq_lth" when a WQE is
			 * de-queued from the SRQ, then an SRQ
			 * limit event is fired and the "srq_lth" is set to zero.
			 */
			u32 head_index : 16;
#endif
		} bs_c;

		u32 value;
	} dw3;

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * A 16-bit counter incremented for
			 * each WQE posted to the SRQ.
			 */
			u32 pcnt : 16;
			u32 ccnt : 16;	   /* WQE count on the SRQ. */
#else
			u32 ccnt : 16; /* WQE count on the SRQ. */
			/*
			 * A 16-bit counter incremented for
			 * each WQE posted to the SRQ.
			 */
			u32 pcnt : 16;
#endif
		} bs;

		u32 head_gpa;

		u32 value;
	} dw4;

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 wqe_prefetch_ccnt : 16;
			/*
			 * The current WQE index; uses this field to
			 * get the corresponding WQE from SRQ.
			 */
			u32 next_wqe_idx : 16;
#else
			/*
			 * The current WQE index; uses this field
			 * to get the corresponding WQE from SRQ.
			 */
			u32 next_wqe_idx : 16;
			u32 wqe_prefetch_ccnt : 16;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 head_gpa : 20;
			u32 rsvd : 1;
			u32 pcnt_on_chip : 1;
			u32 xrc_cqn0 : 10;
#else
			u32 xrc_cqn0 : 10;
			u32 pcnt_on_chip : 1;
			u32 rsvd : 1;
			u32 head_gpa : 20;
#endif
		} bs_c;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 head_gpa : 24;
			u32 rsvd : 1;
			u32 pcnt_on_chip : 1;
			/*
			 * The current WQE index; uses this field to
			 * get the corresponding WQE from SRQ.
			 */
			u32 resd : 6;
#else
			u32 resd : 6;
			u32 pcnt_on_chip : 1;
			/*
			 * The current WQE index; uses this field to
			 * get the corresponding WQE from SRQ.
			 */
			u32 rsvd : 1;
			u32 head_gpa : 24;
#endif
		} bs_osd;

		u32 value;
	} dw5;

	/* DW6 */
	union {
		u32 next_wqe_gpa;	  /* bit[63:32] */
		u32 pcnt_record_gpa_h; /* bit[63:32] */
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 next_wqe_gpa : 20;
			u32 next_wqe_gpa_vld : 1;
			u32 load_wqe_gpa : 1;
			u32 load_pcnt : 1;
			u32 rsvd : 4;
			u32 wqecnt_lth : 4;
			u32 wqecnt_ctrl_en : 1;
#else
			u32 wqecnt_ctrl_en : 1;
			u32 wqecnt_lth : 4;
			u32 rsvd : 4;
			u32 load_pcnt : 1;
			u32 load_wqe_gpa : 1;
			u32 next_wqe_gpa_vld : 1;
			u32 next_wqe_gpa : 20;

#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 pcnt_record_gpa_l : 30;
			u32 rsvd : 2;
#else
			u32 rsvd : 30;
			u32 pcnt_record_gpa_l : 2;
#endif
		} bs_c;
		u32 value;
	} dw7;

	/* DW8~9 */
	union {
		/*
		 * The GPA of Layer 0 MTT. It may point to the SRQ's buffer directly.
		 * low 3bits srq_gpa_sign
		 */
		u64 l0mtt_gpa;
		struct {
			u32 l0mtt_gpa_hi;
			u32 l0mtt_gpa_lo;
		} dw8;
	};

	/* DW10~11 */
	union {
		/*
		 * bit[63:2]:The GPA of stored producer counters of Shared Receive Queue.
		 *  bit[1:0]: Address translation hop numbers.
		 * 0x0: the "srq_l0mtt_gpa" points to the buffer of SRQ directly.
		 * 0x1: it need to perform one hop address translation to get the
		 * buffer's address of SRQ; 0x2: there is two hop address translation to get
		 * the buffer's address of SRQ; 0x3: reserved.
		 */
		u64 pcnt_record_gpa_at_hop_num;
		struct {
			u32 pcnt_record_gpa_hi;
			/* bit[1:0]: Address translation hop numbers. */
			u32 pcnt_record_gpa_lo_at_hop_num;
		} dw10;

		struct {
			union {
				struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
					u32 rsvd : 16;
					u32 xrcd : 16;
#else
					u32 xrcd : 16;
					u32 rsvd : 16;
#endif
				} bs;

				u32 value;
			} dw10;

			u32 dw11;
		} dw10_container;
	};

	/* DW12 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * The hardware clear it to zero when performing
			 * a SRQ PCnt updating, and driver
			 * set it to one to indicate the hardware can performing SRQ PCnt updating.
			 */
			u32 wqecnt_rctl : 1;
			u32 rsvd3 : 7;
			/*
			 * Maximum number of prefetch WQEBBs for SRQ.
			 * 000: prefetch number equals to zero;
			 * Others: prefetch number equals to (2^srq_wqe_prefetch_maxnum).
			 */
			u32 wqe_prefetch_max_num : 3;
			/*
			 * Minimum number of prefetch WQEBBs for SRQ.
			 * 000: prefetch number equals to zero;
			 * Others: prefetch number equals to (2^(srq_wqe_prefetch_minnum-1)).
			 */
			u32 wqe_prefetch_min_num : 3;
			/*
			 * Maximum length of prefetch MTTs for SRQ.
			 * 000: prefetch length equals to zero;
			 * Others: prefetch length equals to
			 * (2^(srq_mtt_prefetch_maxlen-1)*1KB).
			 */
			u32 wqe_cache_thd_sel : 2;
			u32 mtt_prefetch_maxlen : 2;
			u32 rsvd2 : 5;
			/* Page size of MTT for SRQ, equals to (2^srq_mtt_page_size)*4KB. */
			u32 mtt_page_size : 4;
			u32 rsvd1 : 4;
			u32 load_wqe : 1;
#else
			u32 load_wqe : 1;
			u32 rsvd1 : 4;
			/* Page size of MTT for SRQ, equals to (2^srq_mtt_page_size)*4KB. */
			u32 mtt_page_size : 4;
			u32 rsvd2 : 5;
			u32 mtt_prefetch_maxlen : 2;
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
			u32 rsvd3 : 7;
			/*
			 * The hardware clear it to zero when performing
			 * a SRQ PCnt updating, and driver
			 * set it to one to indicate the hardware can performing SRQ PCnt updating.
			 */
			u32 wqecnt_rctl : 1;
#endif
		} bs;
		u32 value;
	} dw12;

	/* DW13 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 16;
			u32 wqe_prefetch_idx : 16; /* The WQE index of prefetch MTTs operation. */
#else
			u32 wqe_prefetch_idx : 16; /* The WQE index of prefetch MTTs operation. */
			u32 rsvd : 16;
#endif
		} bs;
		u32 value;
	} dw13;

	/* DW14 */
	u32 srq_prefetch_wqe_gpa_hi; /* bit[63:32] */

	/* DW15 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 mtt_prefetch_wqe_gpa_lo : 20;
			u32 srq_prefetch_wqe_gpa_vld : 1;
			u32 rsvd : 9;
			u32 srq_prefetch_thread_num : 2;
#else
			u32 srq_prefetch_thread_num : 2;
			u32 rsvd : 9;
			u32 srq_prefetch_wqe_gpa_vld : 1;
			u32 mtt_prefetch_wqe_gpa_lo : 20; /* bit[31:12] */
#endif
		} bs;
		u32 value;
	} dw15;
};

/* *SRQC Format end */

struct roce_ssgl_mpt_context {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 buf_page_size : 4; /* Page_size of the buffer */
			u32 mtt_layer_num : 3; /* Mtt level */
			u32 mtt_page_size : 4; /* Page_size of mtt */
			u32 rsvd2 : 4;
			/* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
			u32 zbva : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			/*
			 * The value 1 indicates that the local
			 * write permission is supported.
			 */
			u32 access_lw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			/* 1: The remote write permission is supported. */
			u32 access_rw : 1;
			/*
			 * The value 1 indicates that the remote
			 * Atomic permission is supported.
			 */
			u32 access_ra : 1;
			u32 bpd : 1;	   /* 1: Bound to pd */
			u32 bqp : 1;	   /* 1: Bound to qp */
			u32 dif_mode : 1;
			u32 rkey : 1;
			u32 pa : 1;				/* Flag bit of DMA_MR */
			/* Mr or mw. The value 1 indicates MR, and the value 0 indicates MW. */
			u32 r_w : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			/* Indicates whether the FRMR operation is supported. */
			u32 fast_reg_en : 1;
			/* Indicates whether the FRMR can specify remote rights. */
			u32 remote_access_en : 1;
			/* Whether the mr supports the binding of the mw */
			u32 access_bind : 1;
#else
			/* Whether the mr supports the binding of the mw */
			u32 access_bind : 1;
			/* Indicates whether the FRMR can specify remote rights. */
			u32 remote_access_en : 1;
			/* Indicates whether the FRMR operation is supported. */
			u32 fast_reg_en : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			u32 r_w : 1;			   /* Mr or mw */
			u32 pa : 1;				/* Flag bit of DMA_MR */
			u32 rkey : 1;
			u32 dif_mode : 1;
			u32 bqp : 1;	   /* 1: Bound to qp */
			u32 bpd : 1;	   /* 1: Bound to pd */
			/*
			 * The value 1 indicates that the remote
			 * Atomic permission is supported.
			 */
			u32 access_ra : 1;
			/* 1: The remote write permission is supported. */
			u32 access_rw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			/* The value 1 indicates that the local write permission is supported. */
			u32 access_lw : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			/* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
			u32 zbva : 1;
			u32 rsvd2 : 4;
			u32 mtt_page_size : 4; /* Page_size of mtt */
			u32 mtt_layer_num : 3; /* Number of mtt levels */
			u32 buf_page_size : 4; /* Page_size of the buffer */
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 so_ro : 2;			 /* Dma sequence preserving flag */
			u32 dma_attr_idx : 6;	  /* Dma attribute index */
			u32 sector_size : 1;	   /* 0:512B, 1:4KB */
			u32 ep : 3;
			u32 qpn : 20;   /* Qp bound to the mw. */
#else
			u32 qpn : 20; /* Qp bound to mw */
			u32 ep : 3;
			u32 sector_size : 1;  /* 0:512B, 1:4KB */
			u32 dma_attr_idx : 6; /* Dma attribute index */
			u32 so_ro : 2;		/* Dma order-preserving flag */
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
			u32 rsvd : 1;
			u32 cos : 3;
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 pdn : 18;	   /* Pd bound to mr or mw */
#else
			u32 pdn : 18;	   /* Pd bound to mr or mw */
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 cos : 3;
			u32 rsvd : 1;
			u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 mkey : 8;	   /* The index is not included. */
			u32 sgl_mode : 1;   /* If set, indicates this MPT is double SGL type. */
			u32 page_mode : 1;
			u32 fbo : 22;
#else
			u32 fbo : 22;
			u32 page_mode : 1;
			u32 sgl_mode : 1; /* If set, indicates this MPT is double SGL type. */
			u32 mkey : 8;	 /* The index is not included. */
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4~5 */
	union {
		u64 iova; /* Start address of mr or mw */
		struct {
			u32 iova_hi; /* Upper 32 bits of the start address of mr or mw */
			u32 iova_lo; /* Lower 32 bits of the start address of mr or mw */
		} dw4;
	};

	/* DW6~7 */
	union {
		u64 length; /* Length of mr or mw */
		struct {
			u32 length_hi; /* Length of mr or mw */
			u32 length_lo; /* Length of mr or mw */
		} dw6;
	};

	/* DW8~9 */
	union {
		u64 mtt_base_addr; /* Mtt base address (pa) */
		struct {
			u32 mtt_base_addr_hi; /* Mtt base address (pa) upper 32 bits */
			u32 mtt_base_addr_lo; /* Lower 32 bits of mtt base address (pa) */
		} dw8;
	};

	/* DW10 */
	union {
		u32 mr_mkey; /* This parameter is valid for MW. */
		u32 mw_cnt;  /* This parameter is valid when the MR is used. */
		u32 task_id;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 9;
			u32 ext_mtu : 1;
			u32 tp2_fst_sct : 1;
			u32 smd_size : 1; /* metadata size[0]:0 is 512, 1'b1 is 4096 */
			u32 smd_type : 4; /* smd_type[3:2]:reserved. */
			u32 task_id : 16; /* This parameter is valid when SIG MR. */
#else
			u32 task_id : 16; /* This parameter is valid when SIG MR. */
			/*
			 * This is sector metadata type: 2b'0x is 8B;
			 * 2b'10 is [8B+56B];2b'11 is [56B+8B]
			 */
			u32 smd_type : 4;
			u32 smd_size : 1; /* metadata size[0]:0 is 512, 1'b1 is 4096 */
			u32 tp2_fst_sct : 1;
			u32 ext_mtu : 1;
			u32 rsvd : 9;
#endif
		} dw10;
	};

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 w_cmp_app_tag_msk : 16;
			u32 m_cmp_app_tag_msk : 16;
#else
			u32 m_cmp_app_tag_msk : 16;
			u32 w_cmp_app_tag_msk : 16;
#endif
		} bs;
		u32 value;
	} dw11;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 w_app_tag : 16;
			u32 m_app_tag : 16;
#else
			u32 m_app_tag : 16;
			u32 w_app_tag : 16;
#endif
		} bs;
		u32 value;
	} dw12;

	u32 m_ref_tag;
	u32 w_ref_tag;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 w_dif_en : 1;	  /* Dif enable in the wire domain */
			u32 rx_w_dif_type : 2; /* type 0 ~ 3,def:1 */
			u32 rx_m_dif_type : 2; /* type 0 ~ 3,def:1 */
			u32 rx_dif_en : 1;	 /* IO_1ST_SCT 1 */
			u32 w_app_esc : 1;
			u32 w_ref_esc : 1;

			u32 m_dif_en : 1;	  /* mem */
			u32 tx_m_dif_type : 2; /* type 0 ~ 3,def:1 */
			u32 tx_w_dif_type : 2; /* type 0 ~ 3,def:1 */
			u32 tx_dif_en : 1;	 /* IO_1ST_SCT 1 */
			u32 m_app_esc : 1;
			u32 m_ref_esc : 1;

			u32 grd_verify : 1;	  /* Indicates whether to verify the guard. */
			u32 grd_ctrl : 2;		/* guard tag ctrl */
			/* The host memory is CRC(0) or IP CheckSum(1). */
			u32 m_bg_type : 1;
			/* Indicates whether the line is CRC(0) or IP CheckSum(1). */
			u32 w_bg_type : 1;
			u32 grd_agm_ini_ctl : 3; /* GRD_AGM_INI_CTRL */

			u32 ref_tag_verify : 1; /* Indicates whether to verify the ref_tag. */
			u32 ref_ctrl : 2;	   /* ref tag ctrl */
			u32 m_ref_tag_mode : 1; /* Obtained from mem.dif.ref_remap */
			u32 w_ref_tag_mode : 1; /* Obtained from wire.dif.ref_remap */
			u32 app_tag_verify : 1; /* Indicates whether to verify the app_tag. */
			u32 app_ctrl : 2;	   /* app tag ctrl */
#else
			u32 app_ctrl : 2;	   /* app tag ctrl */
			u32 app_tag_verify : 1; /* Indicates whether to verify the app_tag. */
			u32 w_ref_tag_mode : 1; /* Obtained from wire.dif.ref_remap */
			u32 m_ref_tag_mode : 1; /* Obtained from mem.dif.ref_remap */
			u32 ref_ctrl : 2;	   /* ref tag ctrl */
			u32 ref_tag_verify : 1; /* Indicates whether to verify the ref_tag. */

			u32 grd_agm_ini_ctl : 3; /* GRD_AGM_INI_CTRL */
			u32 w_bg_type : 1;	   /* Is CRC(0) or IP CheckSum(1) on the line? */
			/* The host memory is CRC(0) or IP CheckSum(1). */
			u32 m_bg_type : 1;
			u32 grd_ctrl : 2;		/* guard tag ctrl */
			u32 grd_verify : 1;	  /* Indicates whether to verify the guard. */

			u32 m_ref_esc : 1;
			u32 m_app_esc : 1;
			u32 tx_dif_en : 1;	 /* IO_1ST_SCT 1 */
			u32 tx_w_dif_type : 2; /* type 0 ~ 3,def:1 */
			u32 tx_m_dif_type : 2; /* type 0 ~ 3,def:1 */
			u32 m_dif_en : 1;	  /* mem */

			u32 w_ref_esc : 1;
			u32 w_app_esc : 1;
			u32 rx_dif_en : 1;	 /* IO_1ST_SCT 1 */
			u32 rx_m_dif_type : 2; /* type 0 ~ 3,def:1 */
			u32 rx_w_dif_type : 2; /* type 0 ~ 3,def:1 */
			/* Indicates whether dif is enabled in the wire domain. */
			u32 w_dif_en : 1;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u8 w_dif_ctl;
			u8 m_dif_ctl;
			u8 m_grd_ctl;
			u8 m_ref_ctl;
#else
			u8 m_ref_ctl;
			u8 m_grd_ctl;
			u8 m_dif_ctl;
			u8 w_dif_ctl;
#endif
		} ctrl;
		u32 value;
	} dw15;
};

struct roce_dsgl_mpt_context {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 buf_page_size : 4; /* Page_size of the buffer */
			u32 mtt_layer_num : 3; /* Number of mtt levels */
			u32 mtt_page_size : 4; /* Page_size of mtt */
			u32 signature : 4;
			/* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
			u32 zbva : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			/* The value 1 indicates that the local write permission is supported. */
			u32 access_lw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			u32 access_rw : 1; /* 1: The remote write permission is supported. */
			/* The value 1 indicates that the remote Atomic permission is supported. */
			u32 access_ra : 1;
			u32 bpd : 1;	   /* 1: Bound to pd */
			u32 bqp : 1;	   /* 1: Bound to qp */
			u32 dif_mode : 1;
			u32 rkey : 1;
			u32 pa : 1;				/* Flag bit of DMA_MR */
			/* Mr or mw. The value 1 indicates MR, and the value 0 indicates MW. */
			u32 r_w : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			/* Indicates whether the FRMR operation is supported. */
			u32 fast_reg_en : 1;
			/* Indicates whether the FRMR can specify remote rights. */
			u32 remote_access_en : 1;
			u32 access_bind : 1;	   /* Whether mr can be bound to mw */
#else
			/* Whether the mr supports the binding of the mw */
			u32 access_bind : 1;
			/* Indicates whether the FRMR can specify remote rights. */
			u32 remote_access_en : 1;
			/* Indicates whether the FRMR operation is supported. */
			u32 fast_reg_en : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			u32 r_w : 1;			   /* Mr or mw */
			u32 pa : 1;				/* Flag bit of DMA_MR */
			u32 rkey : 1;
			u32 dif_mode : 1;
			u32 bqp : 1;	   /* 1: Bound to qp */
			u32 bpd : 1;	   /* 1: Bound to pd */
			/*
			 * The value 1 indicates that the remote
			 * Atomic permission is supported.
			 */
			u32 access_ra : 1;
			/* 1: The remote write permission is supported. */
			u32 access_rw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			/*
			 * The value 1 indicates that the local
			 * write permission is supported.
			 */
			u32 access_lw : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			/* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
			u32 zbva : 1;
			u32 signature : 4;
			u32 mtt_page_size : 4; /* Page_size of mtt */
			u32 mtt_layer_num : 3; /* Mtt level */
			u32 buf_page_size : 4; /* Page_size of the buffer */
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 so_ro : 2;			 /* Dma order-preserving flag */
			u32 dma_attr_idx : 6;	  /* Dma attribute index */
			u32 sector_size : 1;	   /* 0:512B, 1:4KB */
			u32 ep : 3;
			u32 qpn : 20;   /* Qp bound to mw */
#else
			u32 qpn : 20;   /* Qp bound to mw */
			u32 ep : 3;
			u32 sector_size : 1;  /* 0:512B, 1:4KB */
			u32 dma_attr_idx : 6; /* Dma attribute index */
			u32 so_ro : 2;		/* Dma order-preserving flag */
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
			u32 indirect_mr : 1;
			u32 cos : 3;
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 pdn : 18;	   /* Pd bound to mr or mw */
#else
			u32 pdn : 18;	   /* Pd bound to mr or mw */
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 cos : 3;
			u32 indirect_mr : 1;
			u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 mkey : 8;	   /* The index is not included. */
			u32 sgl_mode : 1;   /* If set, indicates this MPT is double SGL type. */
			u32 page_mode : 1;
			u32 sectfbo : 22;
#else
			u32 sectfbo : 22;
			u32 page_mode : 1;
			u32 sgl_mode : 1; /* If set, indicates this MPT is double SGL type. */
			u32 mkey : 8;	 /* The index is not included. */
#endif
		} bs;
		u32 value;
	} dw3;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 4;
			u32 data_mr_key : 28;
#else
			u32 data_mr_key : 28;
			u32 rsvd : 4;
#endif
		} bs;
		u32 value;
	} dw4;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 4;
			u32 mtt_offset : 28;
#else
			u32 mtt_offset : 28;
			u32 rsvd : 4;
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6~DW9 */
	u32 rsvd[4];

	/* DW10 */
	union {
		u32 mr_mkey; /* This parameter is valid for MW. */
		u32 mw_cnt;  /* This parameter is valid when the MR is used. */
		u32 task_id;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 12;
			u32 smd_type : 4; /* smd_type[3:2]:reserved. */
			u32 task_id : 16; /* This parameter is valid when SIG MR. */
#else

			u32 task_id : 16; /* This parameter is valid when SIG MR. */
			/*
			 * This is sector metadata type: 2b'0x is 8B;
			 * 2b'10 is [8B+56B];2b'11 is [56B+8B]
			 */
			u32 smd_type : 4;
			u32 rsvd : 12;

#endif
		} dw10;
	};

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 w_cmp_app_tag_msk : 16;
			u32 m_cmp_app_tag_msk : 16;
#else
			u32 m_cmp_app_tag_msk : 16;
			u32 w_cmp_app_tag_msk : 16;
#endif
		} bs;
		u32 value;
	} dw11;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 w_app_tag : 16;
			u32 m_app_tag : 16;
#else
			/*
			 * TX: Verify ref tag domain
			 * RX: Insert&replace ref tag domain
			 */
			u32 m_app_tag : 16;

			/*
			 * TX: Insert&replace ref tag domain
			 * RX: Verify ref tag domain
			 */
			u32 w_app_tag : 16;
#endif
		} bs;
		u32 value;
	} dw12;

	/*
	 *  TX: Verify ref tag domain
	 *  RX: Insert&replace ref tag domain
	 */
	u32 m_ref_tag;

	/*
	 * TX: Insert&replace ref tag domain
	 * RX: Verify ref tag domain
	 */
	u32 w_ref_tag;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 w_dif_en : 1;	  // Wire domain dif enable
			u32 rx_w_dif_type : 2; // type 0 ~ 3,def:1
			u32 rx_m_dif_type : 2; // type 0 ~ 3,def:1
			u32 rx_dif_en : 1;	 // IO_1ST_SCT 1
			u32 w_app_esc : 1;
			u32 w_ref_esc : 1;

			u32 m_dif_en : 1;	  // mem
			u32 tx_m_dif_type : 2; // type 0 ~ 3,def:1
			u32 tx_w_dif_type : 2; // type 0 ~ 3,def:1
			u32 tx_dif_en : 1;	 // IO_1ST_SCT 1
			u32 m_app_esc : 1;
			u32 m_ref_esc : 1;

			u32 grd_verify : 1;	  // Indicates whether to verify the guard.
			u32 grd_ctrl : 2;		// guard tag ctrl; ucode
			u32 m_bg_type : 1;	   // The host memory is CRC(0) or IP CheckSum(1).
			// Indicates whether the line is CRC(0) or IP CheckSum(1).
			u32 w_bg_type : 1;
			u32 grd_agm_ini_ctl : 3; // GRD_AGM_INI_CTRL

			u32 ref_tag_verify : 1; // Indicates whether to verify the ref_tag.
			u32 ref_ctrl : 2;	   // ref tag ctrl; ucode
			u32 m_ref_tag_mode : 1; // Obtained from mem.dif.ref_remap
			u32 w_ref_tag_mode : 1; // Obtained from wire.dif.ref_remap
			u32 app_tag_verify : 1; // Indicates whether to verify the app_tag.
			u32 app_ctrl : 2;	   // app tag ctrl; ucode
#else
			/* REF APP CTRL segment */
			u32 app_ctrl : 2;	   // app tag ctrl
			u32 app_tag_verify : 1; // Indicates whether to verify the app_tag.
			u32 w_ref_tag_mode : 1; // Obtained from wire.dif.ref_remap
			u32 m_ref_tag_mode : 1; // Obtained from mem.dif.ref_remap
			u32 ref_ctrl : 2;	   // ref tag ctrl
			u32 ref_tag_verify : 1; // Indicates whether to verify the ref_tag.

			/* GRD CTRL segment */
			u32 grd_agm_ini_ctl : 3; // GRD_AGM_INI_CTRL
			u32 w_bg_type : 1;	   // Is CRC(0) or IP CheckSum(1) on the line?
			u32 m_bg_type : 1;	   // The host memory is CRC(0) or IP CheckSum(1).
			u32 grd_ctrl : 2;		// guard tag ctrl
			u32 grd_verify : 1;	  // Indicates whether to verify the guard.

			u32 m_ref_esc : 1;
			u32 m_app_esc : 1;
			u32 tx_dif_en : 1;	 // IO_1ST_SCT 1
			u32 tx_w_dif_type : 2; // type 0 ~ 3,def:1
			u32 tx_m_dif_type : 2; // type 0 ~ 3,def:1
			u32 m_dif_en : 1;	  // mem

			u32 w_ref_esc : 1;
			u32 w_app_esc : 1;
			u32 rx_dif_en : 1;	 // IO_1ST_SCT 1
			u32 rx_m_dif_type : 2; // type 0 ~ 3,def:1
			u32 rx_w_dif_type : 2; // type 0 ~ 3,def:1
			u32 w_dif_en : 1;	  // Dif enable in the wire domain
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u8 w_dif_ctl;
			u8 m_dif_ctl;
			u8 m_grd_ctl;
			u8 m_ref_ctl;
#else
			u8 m_ref_ctl;
			u8 m_grd_ctl;
			u8 m_dif_ctl;
			u8 w_dif_ctl;

#endif
		} ctrl;
		u32 value;
	} dw15;
};

struct iw_mpt_context {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 buf_page_size : 4; /* Page_size of the buffer */
			u32 mtt_layer_num : 3; /* Mtt level */
			u32 mtt_page_size : 4; /* Page_size of mtt */
			u32 rsvd2 : 4;
			/* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
			u32 zbva : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			/*
			 * The value 1 indicates that the local
			 * write permission is supported.
			 */
			u32 access_lw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			u32 access_rw : 1; /* 1: The remote write permission is supported. */
			/*
			 * The value 1 indicates that the remote
			 * Atomic permission is supported.
			 */
			u32 access_ra : 1;
			u32 bpd : 1;	   /* 1: Bound to pd */
			u32 bqp : 1;	   /* 1: Bound to qp */
			u32 rsvd1 : 1;
			u32 rkey : 1;
			u32 pa : 1;				/* Flag bit of DMA_MR */
			/* Mr or mw. The value 1 indicates MR, and the value 0 indicates MW. */
			u32 r_w : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			/* Indicates whether the FRMR operation is supported. */
			u32 fast_reg_en : 1;
			/* Indicates whether the FRMR can specify remote rights. */
			u32 remote_access_en : 1;
			u32 access_bind : 1;	   /* Can mr be bound to mw? */
#else
			/* Whether the mr supports the binding of the mw */
			u32 access_bind : 1;
			/* Indicates whether the FRMR can specify remote rights. */
			u32 remote_access_en : 1;
			/* Indicates whether the FRMR operation is supported. */
			u32 fast_reg_en : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			u32 r_w : 1;			   /* Mr or mw */
			u32 pa : 1;				/* Flag bit of DMA_MR */
			u32 rkey : 1;
			u32 rsvd1 : 1;
			u32 bqp : 1;	   /* 1: Bound to qp */
			u32 bpd : 1;	   /* 1: Bound to pd */
			/*
			 * The value 1 indicates that the remote
			 * Atomic permission is supported.
			 */
			u32 access_ra : 1;
			/* 1: The remote write permission is supported. */
			u32 access_rw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			/*
			 * The value 1 indicates that the local
			 * write permission is supported.
			 */
			u32 access_lw : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			/* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
			u32 zbva : 1;
			u32 rsvd2 : 4;
			u32 mtt_page_size : 4; /* Page_size of mtt */
			u32 mtt_layer_num : 3; /* Number of mtt levels */
			u32 buf_page_size : 4; /* Page_size of the buffer */
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 so_ro : 2;			 /* Dma order-preserving flag */
			u32 dma_attr_idx : 6;	  /* Indicates the dma attribute index. */
			u32 sector_size : 1;	   /* 0:512B, 1:4KB */
			u32 rsvd : 3;
			u32 qpn : 20;   /* Qp bound to mw */
#else
			u32 qpn : 20; /* Qp bound to mw */
			u32 rsvd : 3;
			u32 sector_size : 1;  /* 0:512B, 1:4KB */
			u32 dma_attr_idx : 6; /* Dma attribute index */
			u32 so_ro : 2;		/* Dma order-preserving flag */
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
			u32 rsvd : 4;
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 pdn : 18;	   /* Pd bound to mr or mw */
#else
			u32 pdn : 18;	   /* Pd bound to mr or mw */
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 rsvd : 4;
			u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 mkey : 8;	   /* The index is not included. */
			u32 sgl_mode : 1;   /* If set, indicates this MPT is double SGL type. */
			u32 page_mode : 1;
			u32 fbo : 22;
#else
			u32 fbo : 22;
			u32 page_mode : 1;
			u32 sgl_mode : 1; /* If set, indicates this MPT is double SGL type. */
			u32 mkey : 8;	 /* The index is not included. */
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4~5 */
	union {
		u64 iova; /* Start address of mr or mw */

		struct {
			u32 iova_hi; /* Upper 32 bits of the start address of mr or mw */
			u32 iova_lo; /* Lower 32 bits of the start address of mr or mw */
		} dw4;
	};

	/* DW6~7 */
	union {
		u64 length; /* Length of mr or mw */

		struct {
			u32 length_hi; /* Length of mr or mw */
			u32 length_lo; /* Length of mr or mw */
		} dw6;
	};

	/* DW8~9 */
	union {
		u64 mtt_base_addr; /* Mtt base address (pa) */

		struct {
			u32 mtt_base_addr_hi; /* Upper 32 bits of the base address (pa) of mtt */
			u32 mtt_base_addr_lo; /* Lower 32 bits of mtt base address (pa) */
		} dw8;
	};

	/* DW10 */
	union {
		u32 mr_mkey; /* This parameter is valid for MW. */
		u32 mw_cnt;  /* This parameter is valid when the MR is used. */
	};

	/* DW11 */
	u32 mtt_sz; /* This parameter is valid when FRMR. */

	/* DW12 ~ DW13 */
	u32 rsvd[2];

	/* DW14 */
	u32 mw_base_addr_hi;
	u32 mw_base_addr_lo;
};

/* * MPT Format end */

/* * CQC Format start */
struct roce_cq_context {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 signature : 5;
			u32 last_solicited_pi : 9;
			u32 ceqn_low : 5;
			u32 ci_on_chip : 1;
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
			/*
			 * If set, the CI of Complete Queue is stored in the chip,
			 * the counter is absolute value.
			 */
			u32 ci_on_chip : 1;
			/*
			 * Completion Event Queue, this CQ reports
			 * Completion Events to this CQE (cq_ceqn[04:00])
			 */
			u32 ceqn_low : 5;
			u32 last_solicited_pi : 9; /* bit[23:15] */
			u32 signature : 5;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 so_ro : 2;
			u32 dma_attr_idx : 6;
			u32 ci : 24;
#else
			/* The CI index of Receive Queue (Step: CQE). */
			u32 ci : 24;
			/*
			 * It specifies the outbound PCIe TLP header attribute
			 * of the DMA operation.
			 * This filed is only valid when processing CQ's CQEs.
			 */
			u32 dma_attr_idx : 6;
			/*
			 * It specifies the ATTR[1:0] bits in the outbound
			 * PCIe TLP headers of the DMA operation.
			 * This field is only valid when processing CQ's CQEs.
			 * 2'b00: Strict Ordering;
			 * 2'b01: Relaxed Ordering;
			 * 2'b10: ID Based Ordering;
			 * 2'b11: Both Relaxed Ordering and ID Based Ordering.
			 */
			u32 so_ro : 2;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 state : 4;
			u32 rsvd : 1;
			u32 ceqn_high : 3;
			u32 pi : 24;
#else
			/* The PI index of Completion Queue (Step: CQE) */
			u32 pi : 24;
			/*
			 * Completion Event Queue, this CQ reports
			 * Completion Events to this CQE (cq_ceqn[07:05])
			 */
			u32 ceqn_high : 3;
			u32 rsvd : 1;
			/*
			 * CQ status.
			 * 0x0: hardware has no access right;
			 * 0x1: CQ is error;
			 * 0x2: CQ is overflow;
			 * 0xf: ok.
			 * Other: reserved.
			 */
			u32 state : 4;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cqecnt_lth : 4;
			u32 cqecnt_rctl_en : 1;
			u32 last_solicited_pi : 15;
			u32 load_ci : 1;
			u32 load_page_gpa : 1;
			u32 cqe_cur_pg_vld : 1;
			u32 cqe_next_pg_vld : 1;
			u32 cqe_cur_pg_gpa_h : 8;
#else
			u32 cqe_cur_pg_gpa_h : 8; /* curt_pg_gpa[63:56]bit */
			/*
			 * Indicates if the "cq_cqe_next_page_gpa" field is valid.
			 * 1: it is valid;
			 * 0: it is invalid.
			 */
			u32 cqe_next_pg_vld : 1;
			/*
			 * Indicates if the "cq_cqe_curt_page_gpa" field is valid.
			 * 1: it is valid;
			 * 0: it is invalid.
			 */
			u32 cqe_cur_pg_vld : 1;
			/* Indicates the thread is performing a prefetch for GPA of CQE page. */
			u32 load_page_gpa : 1;
			u32 load_ci : 1;
			u32 last_solicited_pi : 15; /* bit[14:00] */
			u32 cqecnt_rctl_en : 1;
			u32 cqecnt_lth : 4;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	/*
	 * Indicates the page GPA of current CQ buffer's page pointed by "cq_pi".
	 * curt_pg_gpa[55:24]bit
	 */
	u32 cqe_curt_pg_gpa_m;
	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cqe_curt_pg_gpa_l : 12; /* curt_pg_gpa[23:12]bit */
			u32 cqe_next_pg_gpa_h : 20; /* next_pg_gpa[63:44]bit */
#else
			u32 cqe_next_pg_gpa_h : 20; /* next_pg_gpa[63:44]bit */
			u32 cqe_curt_pg_gpa_l : 12; /* curt_pg_gpa[23:12]bit */
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	/*
	 * Indicates the page GPA of next CQ buffer's page pointed by "cq_pi".
	 * next_pg_gpa[43:12]bit
	 */
	u32 cqe_next_pg_gpa_l;
	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * Completion Event Moderation counters.
			 * 0x0: interrupt moderation disabled.
			 */
			u32 max_cnt : 16;
			/*
			 * Completion Event Moderation timer in microseconds.
			 * 0x0: interrupt moderation disabled.
			 */
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
	} dw7;

	/* DW8 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cmd_sn : 2;
			u32 arm_state : 2;
			u32 rsvd : 12;
			u32 cqe_cnt : 16;
#else
			u32 cqe_cnt : 16;
			u32 rsvd : 12;
			/*
			 * The CQ ARM State machine.
			 * 0x0: idle state;
			 * 0x1: solicited state;
			 * 0x2: next state;
			 * Others: reserved.
			 */
			u32 arm_state : 2;
			u32 cmd_sn : 2;	/* The last received command sequence number. */
#endif
		} bs;
		u32 value;
	} dw8;

	/* DW9 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 timer_mode : 1;
			u32 arm_timer_en : 1;
			u32 solicited_cqe_en : 1;
			u32 rsvd : 3;
			u32 cnt_clear_en : 1;
			u32 cnt_adjust_en : 1;
			u32 last_notified_pi : 24; /* The last notified PI of CQ. */
#else
			u32 last_notified_pi : 24; /* The last notified PI of CQ. bit[23:00] */
			u32 cnt_adjust_en : 1;
			u32 cnt_clear_en : 1;
			u32 rsvd : 3;
			u32 solicited_cqe_en : 1;
			u32 arm_timer_en : 1;
			u32 timer_mode : 1;
#endif
		} bs;
		u32 value;
	} dw9;

	/* DW10 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 16;
			u32 idle_max_count : 16;
#else
			u32 idle_max_count : 16;
			u32 rsvd : 16;
#endif
		} bs;
		u32 value;
	} dw10;

	/* DW11 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cqecnt_rctl : 1;
			u32 rsvd3 : 15;
			u32 prefetch_thread_num : 2;
			u32 rsvd2 : 6;
			u32 ceqe_en : 1;
			u32 arm_ceqe_en : 1;
			u32 rsvd1 : 2;
			u32 mtt_page_size : 4;
#else
			u32 mtt_page_size : 4;
			u32 rsvd1 : 2;
			u32 arm_ceqe_en : 1;
			u32 ceqe_en : 1;
			u32 rsvd2 : 6;
			u32 prefetch_thread_num : 2;
			u32 rsvd3 : 15;
			u32 cqecnt_rctl : 1;
#endif
		} bs;
		u32 value;
	} dw11;

	/* DW12~13 */
	union {
		/*
		 * The GPA of Layer 0 MTT. It may point to the CQ's buffer directly.
		 * low 3bits(cq_gpa_sign)
		 */
		u64 cqc_l0mtt_gpa;
		struct {
			u32 cqc_l0mtt_gpa_hi;
			u32 cqc_l0mtt_gpa_lo;
		} dw12;
	};

	/* DW14 */
	union {
		/*
		 * The GPA of stored CI of Complete Queue.
		 * Address translation hop numbers.
		 * 0x0: the "cq_l0mtt_gpa" points to the buffer of CQ directly.
		 * 0x1: it need to perform one hop address translation to get the buffer's
		 * address of CQ; 0x2: there is two hop address translation to get the buffer's
		 * address of CQ; 0x3: reserved.
		 */
		u64 ci_record_gpa_at_hop_num;
		struct {
			u32 ci_record_gpa_hi;
			/* bit[1:0] Address translation hop numbers */
			u32 ci_record_gpa_lo_at_hop_num;
		} dw14;
	};

	/* timer seg info */
	struct qpc_timer_seg timer_seg;

	u32 rsvd[8]; /* The 32B is reserved, and the entire CQC is aligned with the 128B. */
};
/* * CQC Format end */

/* * GID Format start */
struct roce_gid_context {
	/* DW0~3 */
	u32 gid[4];

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 svlan : 12;	   /* outer vlan */
			u32 cvlan : 12;	   /* inner vlan */
			u32 is_vroce : 1;
			u32 rsvd : 7;
#else
			u32 rsvd : 7;
			u32 is_vroce : 1;
			u32 ppe_rsvd0 : 12;
			u32 svlan : 12;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 svlan : 12;	   /* outer vlan */
			u32 cvlan : 12;	   /* inner vlan */
			u32 rsvd : 4;
			u32 ip_ctrl_bmp : 4;
#else
			u32 ip_ctrl_bmp : 4;
			u32 rsvd : 4;
			u32 ppe_rsvd0 : 12;
			u32 svlan : 12;
#endif
		} nofaa_master_gid;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 svlan : 12;	   /* outer vlan */
			u32 ppe_rsvd0 : 12;	   /* inner vlan */
			u32 rsvd : 1;
			u32 master_gid_index : 7;
#else
			u32 master_gid_index : 7;
			u32 rsvd : 1;
			u32 ppe_rsvd0 : 12;
			u32 svlan : 12;
#endif
		} nofaa_slave_gid;

		u32 value;
	} dw4;

	/* DW5 */
	union {
		u32 value;
	} dw5;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 add_value : 6;
			u32 gid_update : 1;
			u32 ppe_rsvd3 : 1;
			u32 outer_tag : 2;
			u32 ppe_rsvd1 : 1;
			u32 gid_type : 2;
			u32 tunnel : 1;
			u32 tag : 2;
			u32 smac_hi16 : 16;
#else
			u32 smac_hi16 : 16;
			u32 tag : 2;
			u32 tunnel : 1; // tunnel
			u32 gid_type : 2;
			u32 ppe_rsvd1 : 1; // outer_ip_type
			u32 outer_tag : 2; // outer_tag
			u32 ppe_rsvd3 : 1; // stag
			u32 gid_update : 1;
			u32 add_value : 6;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd_com : 8;
			u32 outer_value : 3;
			u32 misc_idx : 5;
			u32 smac_hi16 : 16;
#else
			u32 smac_hi16 : 16;
			u32 misc_idx : 5;
			u32 outer_value : 3;
			u32 rsvd_com : 8;
#endif
		} bs1;
		u32 value;
	} dw6;

	u32 smac_lo32;
};
/* * GID Format end */

/* * sqrq db Format start */
struct roce_sqrq_db {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
	u32 rsvd : 16;
	u32 _wqe_counter : 16;
#else
	u32 _wqe_counter : 16;
	u32 rsvd : 16;
#endif
};
/* * sqrq db Format end */

/* * srq db Format start */
struct roce_srq_db {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
	u32 rsvd : 16;
	u32 _wqe_counter : 16;
#else
	u32 _wqe_counter : 16;
	u32 rsvd : 16;
#endif
};
/* * srq db Format end */

/* * VTEP Format start */
struct roce_vtep_context {
	u32 dmac_h32;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 dmac_l16 : 16;
			u32 smac_h16 : 16;
#else
			u32 smac_h16 : 16;
			u32 dmac_l16 : 16;
#endif
		} bs;
		u32 value;
	} dw1;

	u32 smac_l32;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 portid : 8;
			u32 vni : 24;
#else
			u32 vni : 24;
			u32 portid : 8;
#endif
		} bs;
		u32 value;
	} dw3;

	u32 sip[4]; // dw4 ~ 7
	u32 dip[4]; // dw8 ~ 11

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 src_port : 16;
			u32 dst_port : 16;
#else
			u32 dst_port : 16;
			u32 src_port : 16;
#endif
		} bs;
		u32 value;
	} dw12;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 base_id : 8;	/* vf cfg id */
			u32 cvlan : 12;
			u32 svlan : 12;
#else
			u32 svlan : 12;
			u32 cvlan : 12;
			u32 base_id : 8;
#endif
		} bs;
		u32 value;
	} dw13;

	u32 racl_id;

	/* DW15 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 5;
			u32 vm_dp_capture_en : 1;
			u32 vm_dp_chk_en : 1;
			u32 vm_dp_chk_invld : 1;
			u32 dscp_rc : 8;
			u32 dscp_ud : 8;
			u32 dscp_xrc : 8;
#else
			u32 dscp_xrc : 8;
			u32 dscp_ud : 8;
			u32 dscp_rc : 8;
			u32 vm_dp_chk_invld : 1;
			u32 vm_dp_chk_en : 1;
			u32 vm_dp_capture_en : 1;
			u32 rsvd : 5;
#endif
		} bs;
		u32 value;
	} dw15;
};
/* * vtep Format end */

union tag_roce_qu_db_dw4 {
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 sub_type : 4;
		u32 udf_3 : 12;
		u32 rsvd0 : 8;
		u32 pi : 8;
#else
		u32 pi : 8;
		u32 rsvd0 : 8;
		u32 udf_3 : 12;
		u32 sub_type : 4;
#endif
	} bs;
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 sub_type : 4;
		u32 sgid_index : 7;
		u32 mtu_shift : 3; /* 256B:0;512B:1;1024B:2;2048B:3;4096B:4 */
		u32 rsvd : 1;
		u32 xrc_vld : 1;
		u32 rsvd0 : 8;
		u32 pi : 8;
#else
		u32 pi : 8;
		u32 rsvd0 : 8;
		u32 xrc_vld : 1;
		u32 rsvd : 1;
		u32 mtu_shift : 3;
		u32 sgid_index : 7;
		u32 sub_type : 4;
#endif
	} bs1;
	u32 value;
};

struct tag_roce_cq_mtt_info {
	/* Indicates whether to kick out cache. by queue (0) or VF(1). */
	u32 mtt_flags;
	/*
	 * Number of cmtt, which needs to be assigned by the
	 * driver when the is kicked out by queue.
	 */
	u32 mtt_num;
	/* The driver needs to read the driver from the configuration file. */
	u32 mtt_cache_line_start;
	/* The driver needs to read the driver from the configuration file. */
	u32 mtt_cache_line_end;
	u32 mtt_cache_line_size;  /* 0:256B,1:512B */
};

struct tag_timer_section {
	union {
		u32 value;
		struct {
			u32 timer_num : 4; // last immeth+cmdlen
			u32 rsvd : 9;
			u32 lv : 1;
			u32 link_timer_id : 3;
			u32 link_wheel_id : 3;
			u32 link_spoke : 12;
		} bs;
	} dw0;

	union {
		u32 value;
		struct {
			u32 v : 1; // last immeth+cmdlen
			u32 service_type : 5;
			u32 rsvd : 9;
			u32 instance_id : 5;
			u32 vf : 12;
		} bs;
	} dw1;
	union {
		u32 value;
		struct {
			u32 xid : 20;
			u32 cid : 12;
		} bs;
	} dw2;
	union {
		u32 value;
		struct {
			u32 cid : 8;
			u32 v : 1; // last immeth+cmdlen
			u32 service_type : 5;
			u32 rsvd : 9;
			u32 instance_id : 5;
			u32 vf : 4;
		} bs;
	} dw3;
	union {
		u32 value;
		struct {
			u32 vf : 8;
			u32 xid : 20;
			u32 cid : 4;
		} bs;
	} dw4;

	u16 cid;
	u16 te0;
	u16 te1;
	u16 te2;
	u16 te3;
	u16 te4;
};

struct tag_spoke_info {
	union {
		u32 value;
		struct {
			u32 v : 1;
			u32 rsvd : 19;
			u32 vf : 12;
		} bs;
	} dw0;

	union {
		u32 value;
		struct {
			u32 xid : 20;
			u32 cid : 12;
		} bs;
	} dw1;
	union {
		u32 value;
		struct {
			u32 cid : 8;
			u32 v : 1; // last immeth+cmdlen
			u32 service_type : 5;
			u32 rsvd : 9;
			u32 instance_id : 5;
			u32 vf : 4;
		} bs;
	} dw2;
	union {
		u32 value;
		struct {
			u32 vf : 8;
			u32 xid : 20;
			u32 cid : 4;
		} bs;
	} dw3;

	u16 cid;
	u16 rsvd;
	u32 total_cnt;
	u32 scan_cnt;
	u32 rsvd1;
};

struct racl_value_rsp {
	u32 vni;
	u32 vtep_ip;
	u16 vf_id;
	u8 mode;
	u8 gw_mac[ETH_ADDR_LEN];
	u8 vm_mac[ETH_ADDR_LEN];
	u8 rsvd;
};

struct racl_value {
	u32 vip;
	u32 vni;
	u32 vtep_ip;

	union {
		struct {
			u32 gw_mac_h : 16;
			u32 gw_mac_m : 16;
		} bs;
		u32 value;
	} dw3;

	union {
		struct {
			u32 gw_mac_l : 16;
			u32 vf_id : 8;
			u32 rsv0 : 7;
			u32 mode : 1;
		} bs;
		u32 value;
	} dw4;
};
#pragma pack(pop)

#endif // RDMA_CONTEXT_FORMAT_H
