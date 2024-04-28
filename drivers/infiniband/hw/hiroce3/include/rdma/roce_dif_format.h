/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_DIF_FORMAT_H
#define ROCE_DIF_FORMAT_H

#include "roce_wqe_format.h"
#include "roce_xqe_format.h"
#include "roce_verbs_mr_attr.h"

struct tag_roce_dif_cqe_s {
	// roce_cqe_s roce_cqe;
	u32 common[8]; /* dif multiplexes the first 32 Bits of standard cqe */
	u32 timestamp_h;
	u32 timestamp_l;
	u32 mr_lkey;
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd1 : 4;
			u32 app_err : 1;
			u32 ref_err : 1;
			u32 grd_err : 1;
			u32 rsvd2 : 17;
			u32 rcv_pi_vb : 8;
#else
			u32 rcv_pi_vb : 8;
			u32 rsvd2 : 17;
			u32 grd_err : 1;
			u32 ref_err : 1;
			u32 app_err : 1;
			u32 rsvd1 : 4;
#endif
		} bs;
		u32 value;
	} dw11;
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rcv_pi_h;
			u32 rcv_pi_l;
#else
			u32 rcv_pi_l;
			u32 rcv_pi_h;
#endif
		} bs;
		u64 value;
	} rcv_pi;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 vrf_agm_imm : 16;
			u32 ri_agm_imm : 16;
#else
			u32 ri_agm_imm : 16;
			u32 vrf_agm_imm : 16;
#endif
		} bs;
		u32 value;
	} dw14;
	u32 rsvd3;
};

struct tag_roce_dif_com_s {
	struct tag_roce_dif_user_data_s *dif_data;

	u32 sd_pdu_ofs;
	u32 sd_pdu_len;

	u16 difx_cnt;
	u16 mss;
	u16 metadata_len;
	u16 sector_len;
};

union tag_roce_dif_misc_rx_s {
	struct {
		u32 rsvd : 18;
		u32 fst_bt_tp : 1;
		u32 fst_sector : 1;
		u32 fst_bt_ofs : 12;
	} bs;
	u32 value;
};

struct tag_roce_dif_wqe_rdma_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 data_len;

	/* DW2 */
	u32 imm_data;

	/* DW3 */
	u32 rsvd1;

	/* DW4~5 */
	union {
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} dw4;
	};

	/* DW6 */
	u32 rkey;
	struct tag_roce_dif_user_data_s dif_data;
	/* DW7 */
	// u32 sig_key;
};

struct tag_roce_dif_wqe_snd_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW0 */
	u32 data_len; /* Length of the data sent by the SQ WQE */

	/* DW1 */
	/* This parameter is valid for the immediate data operation or SEND invalidate. */
	u32 immdata_invkey;

	struct tag_roce_dif_user_data_s dif_data;
};


/* REG SIG MR Local WQE */
struct roce_wqe_reg_sig_mr_seg {
	union roce3_wqe_tsk_com_seg common;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rre : 1;		 /* Remote read enable */
			u32 rwe : 1;		 /* Remote write enable */
			u32 lwe : 1;		 /* Local write enable */
			u32 sgl_mode : 1;	/* 0: Single SGL, 1: Dual SGL */
			u32 sector_size : 1; /* 0 : 512B, 1: 4096B */
			u32 rsvd1 : 3;
			/* Block size, which is the same as the MPT data definition. */
			u32 block_size : 6;
			u32 rsvd2 : 18;
#else
			u32 rsvd2 : 18;
			/* Block size, which is the same as the MPT data definition. */
			u32 block_size : 6;
			u32 rsvd1 : 3;
			u32 sector_size : 1; /* 0 : 512B, 1: 4096B */
			u32 sgl_mode : 1;	/* 0: Single SGL, 1: Dual SGL */
			u32 lwe : 1;		 /* Local write enable */
			u32 rwe : 1;		 /* Remote write enable */
			u32 rre : 1;		 /* Remote read enable */
#endif
		} bs;
		u32 value;
	} dw0;

	u32 sig_mr_mkey;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 10;
			u32 mtt_offset : 22;
#else
			u32 mtt_offset : 22;
			u32 rsvd : 10;
#endif
		} bs;
		u32 value;
	} dw2;
	struct tag_roce_dif_user_data_s dif_data;
	u32 data_mr_key;
	u32 metadata_mr_key;
	u32 rsvd1;
};


struct roce_wqe_reg_mr_dsgl_seg {
	struct roce_wqe_reg_sig_mr_seg reg_mr_seg;
	struct roce3_sge_info data_sge;
	struct roce3_sge_info prot_sge;
};

struct roce_dif_ssgl_mpt_context {
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
			/* The value 1 indicates that the local write permission is supported. */
			u32 access_lw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			u32 access_rw : 1; /* 1: The remote write permission is supported. */
			/* The value 1 indicates that the remote Atomic permission is supported. */
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
			u32 rsvd1 : 1;
			u32 bqp : 1;	   /* 1: Bound to qp */
			u32 bpd : 1;	   /* 1: Bound to pd */
			/* The value 1 indicates that the remote Atomic permission is supported. */
			u32 access_ra : 1;
			u32 access_rw : 1; /* 1: The remote write permission is supported. */
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
			u32 indirect_mr : 1;
			u32 cos : 3;
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 pdn : 18;	   /* Pd bound to mr or mw */
#else
			u32 pdn : 18;	   /* Pd bound to mr or mw */
			u32 block_size : 6; /* 2^(page_size+12) + 8*block_size */
			u32 cos : 3;
			u32 indirect_mr : 1; /* If set, indicates this MPT is double SGL type. */
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
			u32 sw_dif_en : 1;   /* If set, indicates dif mode. */
			u32 page_mode : 1;
			u32 fbo : 22;
#else
			u32 fbo : 22;
			u32 page_mode : 1;
			u32 sw_dif_en : 1; /* If set, indicates dif mode. */
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
	};
	struct tag_roce_dif_user_data_s dif_data;
};

struct roce_dif_dsgl_mpt_context {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd6 : 11;
			u32 signature : 4;
			u32 rsvd5 : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			/* The value 1 indicates that the local write permission is supported. */
			u32 access_lw : 1;
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			u32 access_rw : 1; /* 1: The remote write permission is supported. */
			u32 rsvd4 : 1;
			u32 bpd : 1; /* 1: Bound to pd */
			u32 bqp : 1; /* 1: Bound to qp */
			u32 rsvd3 : 1;
			u32 rkey : 1;
			u32 rsvd2 : 1;
			/* Mr or mw. The value 1 indicates MR, and the value 0 indicates MW. */
			u32 r_w : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			u32 rsvd0 : 1;
			u32 rsvd1 : 1;
			u32 access_bind : 1; /* Whether mr can be bound to mw */
#else
			u32 access_bind : 1; /* Whether the mr supports the binding of the mw */
			u32 rsvd0 : 1;
			u32 rsvd1 : 1;
			/* Indicates whether to support the INVALID operation. */
			u32 invalid_en : 1;
			/* Indicates whether to support the remote INVALID operation. */
			u32 remote_invalid_en : 1;
			u32 r_w : 1;			   /* Mr or mw */
			u32 rsvd2 : 1;
			u32 rkey : 1;
			u32 rsvd3 : 1;
			u32 bqp : 1; /* 1: Bound to qp */
			u32 bpd : 1; /* 1: Bound to pd */
			u32 rsvd4 : 1;
			u32 access_rw : 1; /* 1: The remote write permission is supported. */
			/* 1: Indicates that the remote read permission is supported. */
			u32 access_rr : 1;
			/* The value 1 indicates that the local write permission is supported. */
			u32 access_lw : 1;
			/* 1: Indicates that the local read permission is supported. */
			u32 access_lr : 1;
			u32 rsvd5 : 1;
			u32 signature : 4;
			u32 rsvd6 : 11;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
			u32 rsvd;
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/* Mpt status. Valid values are VALID, FREE, and INVALID. */
			u32 status : 4;
			u32 indirect_mr : 1; /* If set, indicates this MPT is double SGL type. */
			u32 rsvd : 27;
#else
			u32 rsvd : 27;
			u32 indirect_mr : 1; /* If set, indicates this MPT is double SGL type. */
			u32 status : 4; /* Mpt status. Valid values are VALID, FREE, and INVALID. */
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 mkey : 8;	 /* The index is not included. */
			u32 sw_dif_en : 1; /* If set, indicates dif mode. */
			u32 rsvd : 23;
#else
			u32 rsvd : 23;
			u32 sw_dif_en : 1; /* If set, indicates dif mode. */
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
			u32 metadata_mr_key : 28;
#else
			u32 metadata_mr_key : 28;
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
	};
	struct tag_roce_dif_user_data_s dif_data;
};

#endif
