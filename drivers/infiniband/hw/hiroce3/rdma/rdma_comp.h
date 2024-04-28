/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef RDMA_COMP_H
#define RDMA_COMP_H

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

#include <linux/delay.h>
#include <linux/types.h>

#include "rdma_context_format.h"
#include "hinic3_crm.h"
#include "hinic3_cqm.h"
#include "hinic3_rdma.h"

#include "roce_verbs_cmd.h"
#include "roce_verbs_ulp_format.h"

#include "rdma_bitmap.h"
#include "hmm_buddy.h"
#include "hmm_em.h"
#include "hmm_comp.h"

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": [RDMA]" fmt
#endif

#define RDMA_DEFAULT_GID_SUBNET_PREFIX 0xFE80000000000000ULL

#define RDMA_KEY_MASK 0xFFFFFF00

#define RDMA_INVALID_GUID 0

#define RDMA_SERVICE_TYPE_ROCE SERVICE_T_ROCE

#define RDMA_BIT_SHIFT_1 1
#define RDMA_BIT_SHIFT_2 2
#define RDMA_BIT_SHIFT_4 4
#define RDMA_BIT_SHIFT_8 8
#define RDMA_BIT_SHIFT_16 16

#define ROCE3_RDMARC_MIN_DEPTH 1
#define ROCE3_RDMARC_MAX_DEPTH 512
#define ROCE3_RDMARC_MIN_ENTRY 8   /* min entry aligned required by engine */
#define ROCE3_RDMARC_EXT_ENTRY 384   // 384 /* ext tbl 12K. 12k/32 = 384 */

extern u32 g_mtt_page_size;

#define RDMA_EM_MIN_ORDER 2 /* rdma rc extend table at least 4 page */

#define ROCE_MTT_PAGE_SIZE_4K 4096
#define ROCE_MTT_PAGE_SIZE_64K (64 * 1024)
#define ROCE_MTT_PAGE_SIZE_2M (2 * 1024 * 1024)
#define ROCE_MTT_PAGE_SIZE_4K_SHIFT 12
#define ROCE_MTT_PAGE_SIZE_64K_SHIFT 16
#define ROCE_MTT_PAGE_SIZE_2M_SHIFT 21

enum {
	ROCE3_RDMA_MTT_PAGE_SIZE_4K = 0,
	ROCE3_RDMA_MTT_PAGE_SIZE_64K = 1,
	ROCE3_RDMA_MTT_PAGE_SIZE_2M = 2
};

enum {
	ROCE3_RDMA_CMD_TIME_OUT_A = 30000,
	ROCE3_RDMA_CMD_TIME_OUT_B = 40000,
	ROCE3_RDMA_CMD_TIME_OUT_C = 50000
};

enum rdma_roce3_cmd {
	RDMA_ROCE_CMD_UPDATE_GID = 0x60,
	RDMA_ROCE_CMD_QUERY_GID = 0x61,
	RDMA_ROCE_CMD_CLEAR_GID = 0x62
};

struct rdma_comp_priv {
	struct rdma_comp_resource rdma_comp_res; /* gid & guid */

	struct hmm_buddy mtt_buddy;
	struct hmm_em_table mtt_em_table;
	void *hwdev;
	struct pci_dev *pdev;
	struct rdma_mr rsvd_lkey;
	struct rdma_mr fixed_mr;
	u32 mtt_page_size;  /* 4K, 8K, 16K, 32K */
	u32 mtt_page_shift; /* 12, 13, 14, 15 */
	struct rdma_service_cap rdma_cap;

	struct rdma_bitmap pd_bitmap;
	struct rdma_bitmap xrcd_bitmap;

	struct hmm_buddy rdmarc_buddy;
	struct hmm_em_table rdmarc_em_table;
};

struct rdma_gid_update_inbuf {
	struct tag_roce_verbs_cmd_com com;
	__be32 port;
	__be32 rsvd;
	struct rdma_gid_entry gid_entry;
};

struct rdma_gid_clear_inbuf {
	__be32 port;
	__be32 gid_num;
};

/* for llt to set stub */
void rdma_cleanup_pd_table(struct rdma_comp_priv *comp_priv);

struct rdma_comp_priv *get_rdma_comp_priv(void *hwdev);

int rdma_gid_entry_cmp(struct rdma_gid_entry *gid_tbl_entry, struct rdma_gid_entry *gid_entry);

int roce3_rdma_init_rsvd_lkey(void *hwdev);

void roce3_rdma_free_rsvd_lkey(void *hwdev);

#endif // RDMA_COMP_H
