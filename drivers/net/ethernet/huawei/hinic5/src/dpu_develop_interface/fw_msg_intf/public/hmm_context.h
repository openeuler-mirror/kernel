/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hmm_context.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : common command queue interface
 */

#ifndef HMM_CONTEXT_H
#define HMM_CONTEXT_H

/* **************** Macro Definition ****************** */
#ifndef BIG_ENDIAN
#define BIG_ENDIAN    0x4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN    0x1234
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* **************** Data Structure Definition ****************** */
/* * MPT Format start */
typedef struct roce_mpt_context {
    /* DW0 */
	union {
	struct {
#if (BYTE_ORDER != BIG_ENDIAN)
		u32 access_bind : 1;       /* Whether mr can be bound to mw */
		u32 remote_access_en : 1;  /* Indicates whether the FRMR can specify remote rights. */
		u32 fast_reg_en : 1;       /* Indicates whether the FRMR operation is supported. */
		u32 invalid_en : 1;        /* Indicates whether to support the INVALID operation. */
		u32 remote_invalid_en : 1; /* Indicates whether to support the remote INVALID operation. */
		u32 r_w : 1;               /* Mr or mw */
		u32 pa : 1;                /* Flag bit of DMA_MR */
		u32 rkey : 1;
		u32 dif_mode : 1;
		u32 bqp : 1;       /* 1: Bound to qp */
		u32 bpd : 1;       /* 1: Bound to pd */
		u32 access_ra : 1; /* The value 1 indicates that the remote Atomic permission is supported. */
		u32 access_rw : 1; /* 1: The remote write permission is supported. */
		u32 access_rr : 1; /* 1: Indicates that the remote read permission is supported. */
		u32 access_lw : 1; /* The value 1 indicates that the local write permission is supported. */
		u32 access_lr : 1; /* 1: Indicates that the local read permission is supported. */
		u32 zbva : 1;      /* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
		u32 signature : 4;
		u32 mtt_page_size : 4; /* Page_size of mtt */
		u32 mtt_layer_num : 3; /* Mtt level */
		u32 buf_page_size : 4; /* Page_size of the buffer */
#else
		u32 buf_page_size : 4; /* Page_size of the buffer */
		u32 mtt_layer_num : 3; /* Number of mtt levels */
		u32 mtt_page_size : 4; /* Page_size of mtt */
		u32 signature : 4;
		u32 zbva : 1;      /* The value 1 indicates that ZBVA is supported, that is, iova = 0. */
		u32 access_lr : 1; /* 1: Indicates that the local read permission is supported. */
		u32 access_lw : 1; /* The value 1 indicates that the local write permission is supported. */
		u32 access_rr : 1; /* 1: Indicates that the remote read permission is supported. */
		u32 access_rw : 1; /* 1: The remote write permission is supported. */
		u32 access_ra : 1; /* The value 1 indicates that the remote Atomic permission is supported. */
		u32 bpd : 1;       /* 1: Bound to pd */
		u32 bqp : 1;       /* 1: Bound to qp */
		u32 dif_mode : 1;
		u32 rkey : 1;
		u32 pa : 1;                /* Flag bit of DMA_MR */
		u32 r_w : 1;               /* Mr or mw. The value 1 indicates MR, and the value 0 indicates MW. */
		u32 remote_invalid_en : 1; /* Indicates whether to support the remote INVALID operation. */
		u32 invalid_en : 1;        /* Indicates whether to support the INVALID operation. */
		u32 fast_reg_en : 1;       /* Indicates whether the FRMR operation is supported. */
		u32 remote_access_en : 1;  /* Indicates whether the FRMR can specify the remote authority. */
		u32 access_bind : 1;       /* Whether mr can be bound to mw */
#endif
	} bs;
	u32 value;
	} dw0;

    /* DW1 */
	union {
	struct {
#if (BYTE_ORDER != BIG_ENDIAN)
		u32 qpn : 20; /* Qp bound to mw */
		u32 ep : 3;
		u32 sector_size : 1;  /* 0:512B, 1:4KB */
		u32 dma_attr_idx : 6; /* Dma attribute index */
		u32 so_ro : 2;        /* Dma order-preserving flag */
#else
		u32 so_ro : 2;             /* Dma sequence preserving flag */
		u32 dma_attr_idx : 6;      /* Dma attribute index */
		u32 sector_size : 1;       /* 0:512B, 1:4KB */
		u32 ep : 3;
		u32 qpn : 20;        /* Qp bound to mw */
#endif
	} bs;

	struct {
#if (BYTE_ORDER != BIG_ENDIAN)
		u32 rsvd : 22;
		u32 prp_list_en : 1;   /* nvme prp list mode */
		u32 sector_size : 1;   /* 0:512B, 1:4KB */
		u32 dma_attr_idx : 6;  /* Dma attribute index */
		u32 so_ro : 2;         /* Dma order-preserving flag */
#else
		u32 so_ro : 2;         /* Dma sequence preserving flag */
		u32 dma_attr_idx : 6;  /* Dma attribute index */
		u32 sector_size : 1;   /* 0:512B, 1:4KB */
		u32 prp_list_en : 1;   /* nvme prp list mode */
		u32 rsvd : 22;
#endif
	} dpu;
	u32 value;
	} dw1;

    /* DW2 */
	union {
	struct {
#if (BYTE_ORDER != BIG_ENDIAN)
		u32 pdn : 18;       /* Pd bound to mr or mw */
		u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
		u32 cos : 3;
		u32 indirect_mr : 1;
		u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
#else
		u32 status : 4;      /* Mpt status. Valid values are VALID, FREE, and INVALID. */
		u32 indirect_mr : 1; /* indirect mr flag */
		u32 cos : 3;
		u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
		u32 pdn : 18;       /* Pd bound to mr or mw */
#endif
	} bs;
	u32 value;
	} dw2;

    /* DW3 */
	union {
	struct {
#if (BYTE_ORDER != BIG_ENDIAN)
		u32 fbo : 22;
		u32 page_mode : 1;
		u32 sgl_mode : 1; /* If set, indicates this MPT is double SGL type. */
		u32 mkey : 8;     /* The index is not included. */
#else
		u32 mkey : 8;       /* The index is not included. */
		u32 sgl_mode : 1;   /* If set, indicates this MPT is double SGL type. */
		u32 page_mode : 1;
		u32 fbo : 22;
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
	u64 mtt_base_addr; /* Mtt base address (pa)hi:bit[63:32], lo:bit[31:03], gpa_sign[02:00] */
	struct {
		u32 mtt_base_addr_hi; /* Mtt base address (pa) upper 32 bits */
		u32 mtt_base_addr_lo; /* Mtt base address (pa) lower 32 bits */
	} dw8;
	};

    /* DW10 */
	union {
	u32 mr_mkey; /* This parameter is valid for MW. */
	u32 mw_cnt;  /* This parameter is valid when the MR is used. */
	};

    /* DW11 */
	union {
	struct {
#if (BYTE_ORDER != BIG_ENDIAN)
		u32 david_en : 1;
		u32 rsvd : 1;
		u32 fe_valid_num : 2;
		u32 fe_id : 12;
		u32 fe_offset : 8;
		u32 rsvd1 : 8;
#else
		u32 rsvd1 : 8;
		u32 fe_offset : 8;
		u32 fe_id : 12;
		u32 fe_valid_num : 2;
		u32 rsvd : 1;
		u32 david_en : 1;
#endif
	} dw11;
	u32 mtt_sz; /* This parameter is valid when FRMR. */
	};

    /* DW12~DW13 */
	u32 rsvd[2];

    /* DW14~15 */
	union {
	u64 mw_vaddr; /* Mtt base address (pa)hi:bit[63:32], lo:bit[31:03], gpa_sign[02:00] */
	struct {
		u32 mw_vaddr_hi; /* Mtt base address (pa) upper 32 bits */
		u32 mw_vaddr_lo; /* Mtt base address (pa) lower 32 bits */
	} dw14;
	struct {
		u32 mw_vaddr_hi; /* Mtt base address (pa) upper 32 bits */
		u32 mw_vaddr_lo; /* Mtt base address (pa) lower 32 bits */
	} dw15;
	};
} roce_mpt_context_s;

#endif

