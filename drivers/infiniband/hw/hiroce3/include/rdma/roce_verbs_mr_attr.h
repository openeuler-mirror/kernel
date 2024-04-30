/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_MR_ATTR_H
#define ROCE_VERBS_MR_ATTR_H


#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#pragma pack(4)
struct tag_roce_verbs_mr_sge {
	u32 rsvd;
	u32 new_key;

	/* DW2~3 */
	union {
		u64 length; /* Length of mr or mw */

		struct {
			u32 length_hi; /* Length of mr or mw */
			u32 length_lo; /* Length of mr or mw */
		} dw2;
	};

	/* DW4~5 */
	union {
		u64 iova; /* Start address of mr or mw */

		struct {
			u32 iova_hi; /* Upper 32 bits of the start address of mr or mw */
			u32 iova_lo; /* Lower 32 bits of the start address of mr or mw */
		} dw4;
	};
};

struct tag_roce_verbs_mtt_cacheout_info {
	u32 mtt_flags;	/* Indicates whether to kick out cache. by queue (0) or VF(1). */
	/*
	 * Number of cmtt, which needs to be assigned by
	 * the driver when the is kicked out by queue.
	 */
	u32 mtt_num;
	/* The driver needs to read the driver from the configuration file. */
	u32 mtt_cache_line_start;
	/* The driver needs to read the driver from the configuration file. */
	u32 mtt_cache_line_end;
	u32 mtt_cache_line_size;  /* 0:256B,1:512B */
};

struct tag_roce_verbs_wqe_cacheout_info {
	u32 wqe_flags;	/* Indicates whether to kick out cache. by queue (0) or VF(1). */
	/*
	 * Number of wqe, which needs to be assigned by the
	 * driver when the is kicked out by queue.
	 */
	u32 wqe_num;
	/* The driver needs to read the driver from the configuration file. */
	u32 wqe_cache_line_start;
	/* The driver needs to read the driver from the configuration file. */
	u32 wqe_cache_line_end;
	u32 wqe_cache_line_size;  /* 0:256B,1:512B */
};


struct tag_roce_verbs_query_mtt_info {
	u32 mtt_addr_start_hi32;
	u32 mtt_addr_start_lo32;
	u32 mtt_num;
	u32 rsvd;
};

struct tag_roce_dif_user_data_s {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 smd_tp : 2;
			u32 app_esc : 1;
			u32 ref_esc : 1;
			u32 sct_v_tp : 2;
			u32 sct_sz : 1;
			u32 md_sz : 1;
			u32 hdr_vld : 1;
			u32 sec_num : 23;
#else
			u32 sec_num : 23;
			u32 hdr_vld : 1; // tx: 0->no nvme hdr, 1: hdr
			u32 md_sz : 1;
			u32 sct_sz : 1;
			u32 sct_v_tp : 2;
			u32 ref_esc : 1;
			u32 app_esc : 1;
			u32 smd_tp : 2;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rep_app_tag : 16;
			u32 grd_v_en	: 1;
			u32 grd_rid	 : 2;
			u32 grd_v_agm   : 1;
			u32 grd_ri_agm  : 1;
			u32 grd_agm_ini : 1;
			u32 crc16_ini   : 1;
			u32 ipcs_ini	: 1;
			u32 ref_v_en	: 1;
			u32 ref_rid	 : 2;
			u32 ref_v_inc   : 1;
			u32 ref_ri_inc  : 1;
			u32 app_v_en	: 1;
			u32 app_rid	 : 2;
#else
			u32 app_rid	 : 2;
			u32 app_v_en	: 1;
			u32 ref_ri_inc  : 1;
			u32 ref_v_inc   : 1;
			u32 ref_rid	 : 2;
			u32 ref_v_en	: 1;
			u32 ipcs_ini	: 1;
			u32 crc16_ini   : 1;
			u32 grd_agm_ini : 1;
			u32 grd_ri_agm  : 1;
			u32 grd_v_agm   : 1;
			u32 grd_rid	 : 2;
			u32 grd_v_en	: 1;
			u32 rep_app_tag : 16;
#endif
		} bs;
		u32 value;
	} dw1;
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cmp_app_tag	  : 16;
			u32 cmp_app_tag_mask : 16;
#else
			u32 cmp_app_tag_mask : 16;
			u32 cmp_app_tag	  : 16;
#endif
		} bs;
		u32 value;
	} dw2;

	u32 cmp_ref_tag;
	u32 rep_ref_tag;
};

struct tag_roce_verbs_mr_attr {
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
			u32 so_ro : 2;
			u32 dma_attr_idx : 6;
			u32 sector_size : 1;
			u32 ep : 3;
			u32 qpn : 20;
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
			u32 status : 4;
			u32 indirect_mr : 1;
			u32 cos : 3;
			u32 block_size : 6;
			u32 pdn : 18;
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
			u32 mkey : 8;
			u32 sw_dif_en : 1;
			u32 page_mode : 1;
			u32 fbo : 22;
#else
			u32 fbo : 22;
			u32 page_mode : 1;
			u32 sw_dif_en : 1;
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
		u64 mtt_base_addr; /* Mtt base address (pa),low 3bits(gpa_sign) */
		struct {
			u32 mtt_base_addr_hi; /* Mtt base address (pa) upper 32 bits */
			/* Lower 32 bits of mtt base address (pa),low 3bits(gpa_sign) */
			u32 mtt_base_addr_lo;
		} dw8;
	};

	/* DW10 */
	union {
		u32 mr_mkey; /* This parameter is valid for MW. */
		u32 mw_cnt;  /* This parameter is valid when the MR is used. */
	};

	/* DW11 */
	u32 mtt_sz;

	/* DW12~16 */
	struct tag_roce_dif_user_data_s dif_info;

	/* DW17 */
	u32 rsvd;
};
#pragma pack()

#endif /* ROCE_VERBS_MR_ATTR_H */
