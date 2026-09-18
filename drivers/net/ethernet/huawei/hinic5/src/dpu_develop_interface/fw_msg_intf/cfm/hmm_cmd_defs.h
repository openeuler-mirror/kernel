/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hmm_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2025/11/21
 * Last Modified : 2026/09/16
 * Description   : hmm cmd define
 */

#ifndef HMM_CMD_DEFS_H
#define HMM_CMD_DEFS_H

/**
 * @brief enum rdma_hmm_cmd
 * @details This enum type defines the various command codes used in the RDMA HMM module
 */
enum rdma_hmm_cmd {
	RDMA_CMD_SW2HW_MPT = 0x70,     /**< Convert software multi-path entry (MPT) to hardware multi-path entry */
	RDMA_CMD_HW2SW_MPT = 0x71,     /**< Convert hardware multi-path entry to software multi-path entry */
	RDMA_CMD_MODIFY_MPT = 0x72,    /**< Modify multi-path entry */
	RDMA_CMD_QUERY_MPT = 0x73,     /**< Query multi-path entry */
	RDMA_CMD_FLUSH_TPT = 0x74,     /**< Flush transport page table entry */
	RDMA_CMD_SYNC_TPT = 0x75       /**< Sync transport page table entry */
};

#define HMM_RDMA_USER_DATA_LENGTH 6 // mr_attr userdata segment size
#define DAVID_PATH_MAX_NUM 0x4      // Maximum number of paths for a single david and dpu bus side

#pragma pack(4)
typedef struct tag_hmm_verbs_cmd_header {
	union {
	u32 value;

	struct {
		u32 version : 8;
		u32 sub_cmd : 8;
		u32 cmd_bitmask : 16; // CMD_TYPE_BITMASK_E
	} bs;
	} dw0;

	u32 index; // qpn/cqn/srqn/mpt_index/gid idx

	u32 opt;

	union {
	u32 value;

	struct {
		u32 cmd_type : 8;
		u32 rsvd : 7;
		u32 seg_ext : 1;
		u32 cmd_len : 16; // verbs cmd total len(include cmd_com),unit:byte
	} bs;
	} dw3;
} hmm_verbs_cmd_header_s;

typedef struct tag_hmm_verbs_mr_attr {
    /* DW0 */
	union {
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 buf_page_size : 4; /* Page_size of the buffer */
		u32 mtt_layer_num : 3; /* Mtt level */
		u32 mtt_page_size : 4; /* Page_size of mtt */
		u32 rsvd2 : 3;
		u32 david_en : 1;
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
		u32 remote_access_en : 1;  /* Indicates whether the FRMR can specify remote rights. */
		u32 access_bind : 1;       /* Whether the mr supports the binding of the mw */
#else
		u32 access_bind : 1;       /* Whether the mr supports the binding of the mw */
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
		u32 david_en : 1;
		u32 rsvd2 : 3;
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
		u32 so_ro : 2;        /* Dma order-preserving flag */
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
		u32 pdn : 18;       /* Pd bound to mr or mw */
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
		u32 mkey : 8;     /* The index is not included. */
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
		u32 mtt_base_addr_lo; /* Lower 32 bits of mtt base address (pa),low 3bits(gpa_sign) */
	} dw8;
	};

    /* DW10 */
	union {
	u32 mr_mkey; /* This parameter is valid for MW. */
	u32 mw_cnt;  /* This parameter is valid when the MR is used. */
	};

    /* DW11 */
	u32 mtt_sz;

    /* DW12~17 */
	u32 userdata[HMM_RDMA_USER_DATA_LENGTH];
} hmm_verbs_mr_attr_s;

typedef struct tag_hmm_verbs_mtt_cacheout_info {
	u32 mtt_flags;    /* Indicates whether to kick out cache. by queue (0) or VF(1). */
	u32 mtt_num; /* Number of cmtt, which needs to be assigned by the driver when the is kicked out by queue. */
	u32 mtt_cache_line_start; /* The driver needs to read the driver from the configuration file. */
	u32 mtt_cache_line_end;   /* The driver needs to read the driver from the configuration file. */
	u32 mtt_cache_line_size;  /* 0:256B,1:512B */
} hmm_verbs_mtt_cacheout_info_s;
#pragma pack()

typedef struct tag_hmm_uni_cmd_mpt_hw2sw {
	hmm_verbs_cmd_header_s com;
	hmm_verbs_mtt_cacheout_info_s dmtt_cache;
} hmm_uni_cmd_mpt_hw2sw_s;

typedef struct tag_hmm_uni_cmd_sw2hw_mpt {
	hmm_verbs_cmd_header_s com;
	hmm_verbs_mr_attr_s mr_attr;
} hmm_uni_cmd_mpt_sw2hw_s;

#define HMM_CMDQ_CREAT_MR_LOAD_PERMISSION_SPF global_spram_f11
#define HMM_CMDQ_CREAT_MR_LOAD_PERMISSION_SPF_ID 11

#define HMM_CMDQ_CREAT_MR_LOAD_TID_FE_SPF global_spram_f6
#define HMM_CMDQ_CREAT_MR_LOAD_TID_FE_SPF_ID 6

typedef struct {
	u16 rsvd0 : 1;
	u16 ubc_port_id : 3;    /* Current port_id, used to select oq_id, does not need to strictly correspond to the port number */
	u16 david_ue_id : 12;   /* The logical first UBC port fe assigned to the current David */
} david_port_ue_s;

/**
 * @brief struct mptc_david - david fe information
 * @details In david passthrough scenario, mptc needs to carry david fe and other related information
 */
typedef struct mptc_david {
    /* DW0 ~ DW1 */
	david_port_ue_s david_port_ue[DAVID_PATH_MAX_NUM];

	struct {
	u32 david_en : 1;        /* Indicates whether the current func has david passthrough capability, when enabled, david passthrough can be bypassed */
	u32 at_flag : 1;         /* Used to record whether TID0 or TID1 is used */
	u32 rsvd4 : 2;
	u32 active_port_num : 4; /* Current number of valid UBC Port planes */
	u32 rsvd5 : 2;
	u32 david_id : 6;        /* The david id in the template table, indicating the unified number of the current David within the PoD, used for OQ rate limiting of different davids */
	u32 rsvd6 : 16;
	} dw2;
} mptc_david_s;

/**
 * @brief Edit mptc content during hmm cmdq flow of creating mptc
 * @param mpt_addr: address of mptc
 * @details This interface is located in the cmdq flow of initializing mptc, can be overloaded
 * @return 0: no error; others: error
 */
u32 hmm_creat_mpt_ext_edit_mptc(u8 *mpt_addr);

/**
 * @brief Get vf id in the cmdq flow of creating mr
 * @param void
 * @attention void
 * @return Return vf id
 */
u16 hmm_cmdq_mr_vf_id_get(void);

/**
 * @brief Get user_data of mr_attr in the cmdq flow of creating mr
 * @param user_data_len Output parameter, returns user_data_len size
 * @attention void
 * @return Return user_data address pointer
 */
u8 *hmm_cmdq_mr_user_data_get(u8 *user_data_len);

/**
 * @brief Set mr to pa mode in the hmm cmdq flow of creating mr
 * @param mpt_addr: address of mptc
 * @attention Default is non-pa mode, enable pa mode when va-to-pa conversion is not needed
 * @return void
 */
void hmm_cmdq_mr_pa_mode_set(u8 *mpt_addr);

/**
 * @brief Set david segment in mptc in the hmm cmdq flow of creating mr
 * @param mpt_addr: address of mptc; mptc_david: david segment content in mptc
 * @attention void
 * @return void
 */
void hmm_cmdq_creat_mr_mptc_david_set(u8 *mpt_addr, mptc_david_s *mptc_david);

#endif /* HMM_CMD_DEFS_H */
