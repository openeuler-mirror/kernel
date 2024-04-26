/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef HMM_COMP_H
#define HMM_COMP_H

#ifndef ROCE_SERVICE
#include "ossl_knl.h"
#endif
#include <linux/delay.h>
#include <linux/types.h>
#include "roce_hmm_context.h"
#include "hinic3_crm.h"
#include "hinic3_cqm.h"
#include "hinic3_rdma.h"
#include "hmm_buddy.h"
#include "hmm_em.h"

/* x86 */
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 0x4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 0x1234
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#define PCIE_LINK_DOWN 0xFFFFFFFF

#define RDMA_MPT_STATUS_INVALID 0xf
#define RDMA_MPT_STATUS_FREE 0x3
#define RDMA_MPT_STATUS_VALID 0x1
#define RDMA_MPT_STATUS_MEM_INIT 0xa

#define RDMA_MS_DELAY 5
#define RDMA_MAX_RETRY 200

#define RDMA_MPT_DMA_ATTR_IDX 0
#define RDMA_MPT_SO_RO 0x1

#define RDMA_PA_SIZE ((u32)sizeof(dma_addr_t))

#define PAGE_SIZE_4k 4096 /* page size is 4K */
#define PAGE_SHIFT_4K 12  /* page size is 1 left shift 12 */

#define PAGE_SIZE_64k (64 * 4096) /* page size is 64K */
#define PAGE_SHIFT_64K 16		 /* page size is 1 left shift 16 */

#define PAGE_SIZE_2M (2 * 1024 * 1024) /* page size is 2M */
#define PAGE_SHIFT_2M 21			   /* page size is 1 left shift 21 */

#define RDMA_MTT_PA_VALID 0x1

#define HMM_MTT_NUM_PER_CACHELINE 32 /* 256B Cache line has 32 records */

#define BLOCK_SIZE_DEVIDE_SECTOR 8 /* Chip logic: 8 */


#define MPT_GPA_SIG_LEN 3

#define RDMA_CMDQ_ERR 1
#define RDMA_CMDQ_TIMEOUT 2

#ifndef VERBS_CMD_TYPE_MR_BITMASK
#define VERBS_CMD_TYPE_MR_BITMASK (1u << 12) /* verbs_mr_bitmask */
#endif

enum {
	RDMA_MTT_PAGE_SIZE_4K = 0,
	RDMA_MTT_PAGE_SIZE_64K = 1,
	RDMA_MTT_PAGE_SIZE_2M = 2
};

#ifdef __EMU_X86__
enum {
	RDMA_CMD_TIME_OUT_A = 30000000,
	RDMA_CMD_TIME_OUT_B = 40000000,
	RDMA_CMD_TIME_OUT_C = 50000000
};
#else
enum {
	RDMA_CMD_TIME_OUT_A = 30000,
	RDMA_CMD_TIME_OUT_B = 40000,
	RDMA_CMD_TIME_OUT_C = 50000
};
#endif

enum rdma_mr_mw {
	RDMA_MPT_MW = 0,
	RDMA_MPT_MR = 1
};

enum rdma_roce_cmd {
	RDMA_ROCE_CMD_SW2HW_MPT = 0x70,
	RDMA_ROCE_CMD_HW2SW_MPT = 0x71,
	RDMA_ROCE_CMD_MODIFY_MPT = 0x72,
	RDMA_ROCE_CMD_QUERY_MPT = 0x73,
	RDMA_ROCE_CMD_FLUSH_TPT = 0x74,
	RDMA_ROCE_CMD_SYNC_TPT = 0x75
};


enum mtt_layer {
	RDMA_MTT_NO_LAYER = -1,  /* dma mr needs no mtt */
	RDMA_MTT_ZERO_LAYER = 0, /* 1 page mr has 0 level mtt */
	RDMA_MTT_ONE_LAYER = 1,
	RDMA_MTT_TWO_LAYER = 2,
	RDMA_MTT_THREE_LAYER = 3
};

struct rdma_verbs_cmd_com {
	union {
		__be32 value;

		struct {
			__be32 version : 8;
			__be32 rsvd : 8;
			__be32 cmd_bitmask : 16;
		} bs;
	} dw0;

	__be32 index;
};

struct hmm_service_cap {
	struct dev_rdma_svc_cap dev_rdma_cap;
	/*
	 * 1. the number of MTT PA must be integer power of 2
	 * 2. represented by logarithm. Each MTT table can
	 * contain 1, 2, 4, 8, and 16 PA)
	 */
	u8 log_mtt;
	/* todo: need to check whether related to max_mtt_seg */
	/*
	 * Number of MTT table (4M),
	 * is actually MTT seg number
	 */
	u32 num_mtts;
	/* todo: max value needs to be confirmed */
	/* MTT table number of Each MTT seg(3) */
	u32 log_mtt_seg;
	u32 mtt_entry_sz; /* MTT table size 8B, including 1 PA(64bits) */
	u32 mpt_entry_sz; /* MPT table size (64B) */

	u32 dmtt_cl_start;
	u32 dmtt_cl_end;
	u32 dmtt_cl_sz;
	u32 mtt_page_size;  /* 4K, 8K, 16K, 32K */
	u32 mtt_page_shift; /* 12, 13, 14, 15 */
};


struct hmm_comp_priv {
	struct rdma_comp_resource rdma_comp_res; /* gid & guid */
	struct hmm_buddy mtt_buddy;
	struct hmm_em_table mtt_em_table;
	void *hwdev;
	struct pci_dev *pdev;
	struct rdma_mr rsvd_lkey;
	struct rdma_mr fixed_mr;
	u32 mtt_page_size;  /* 4K, 8K, 16K, 32K */
	u32 mtt_page_shift; /* 12, 13, 14, 15 */

	struct hmm_service_cap rdma_cap;
};

struct rdma_mpt_entry {
	struct roce_mpt_context roce_mpt_ctx;
};

struct rdma_mpt_sw2hw_inbuf {
	struct rdma_verbs_cmd_com com;
	struct rdma_mpt_entry mpt_entry;
};

struct rdma_mpt_hw2sw_inbuf {
	struct rdma_verbs_cmd_com com;

	__be32 dmtt_flags;
	__be32 dmtt_num;
	__be32 dmtt_cache_line_start;
	__be32 dmtt_cache_line_end;
	__be32 dmtt_cache_line_size;
};

struct rdma_mpt_modify_inbuf {
	struct rdma_verbs_cmd_com com;
	__be32 new_key;
	__be64 length;
	__be64 iova;
};


/* for llt to set stub */
int hmm_disable_roce_mpt(struct hmm_comp_priv *comp_priv, struct rdma_mpt *mpt, u16 channel);

int hmm_modify_roce_mpt(void *hwdev, u32 mpt_index,
			u32 new_key, u64 length, u64 iova, u16 channel);

struct hmm_comp_priv *get_hmm_comp_priv(void *hwdev, u32 service_type);

int hmm_rdma_mpt_alloc(void *hwdev, struct rdma_mpt *mpt, u32 service_type);

int hmm_enable_roce_mpt(void *hwdev, struct tag_cqm_cmd_buf *cqm_cmd_inbuf, u16 channel);

#ifdef RDMA_SIGN_MTT_EN
u64 hmm_gen_mtt_sign(u64 mtt_base_gpa, enum mtt_data_type_e type);

#define RDMA_CMTT_SIGN_MASK 0x7ff
#define RDMA_CMTT_SIGN_SHIFT0 3
#define RDMA_CMTT_SIGN_SHIFT1 14
#define RDMA_CMTT_SIGN_SHIFT2 25

#define RDMA_DMTT_SIGN_MASK 0x3ff

#define RDMA_DMTT_ADD_SHIFT0 7
#define RDMA_DMTT_SIGN_SHIFT0 3
#define RDMA_DMTT_SIGN_SHIFT1 6
#define RDMA_DMTT_SIGN_SHIFT2 16
#define RDMA_DMTT_SIGN_SHIFT3 26

#endif

#endif // HMM_COMP_H
