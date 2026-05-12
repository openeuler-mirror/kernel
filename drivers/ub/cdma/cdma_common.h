/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_COMMON_H__
#define __CDMA_COMMON_H__

#include <linux/iommu.h>
#include <linux/types.h>
#include "cdma_context.h"
#include "cdma.h"

#define JETTY_DSQE_OFFSET 0x1000
#define CDMA_USER_DATA_H_OFFSET 32U

#define SQE_TOKEN_ID_L_MASK GENMASK(11, 0)
#define SQE_TOKEN_ID_H_OFFSET 12U
#define SQE_TOKEN_ID_H_MASK GENMASK(7, 0)
#define SQE_VA_L_OFFSET 12U
#define SQE_VA_L_VALID_BIT GENMASK(19, 0)
#define SQE_VA_H_OFFSET 32U
#define SQE_VA_H_VALID_BIT GENMASK(31, 0)
#define WQE_BB_SIZE_SHIFT 6
#define AVAIL_SGMT_OST_INIT 512

#define CDMA_RANGE_INDEX_ENTRY_CNT 0x100000
#define CDMA_SEGMENT_ENTRY_CNT 0x10000

#define CDMA_ENABLE_FLAG 1
#define CDMA_DISABLE_FLAG 0

#define CDMA_DB_SIZE 64

#define CDMA_ATOMIC_LEN_4 4
#define CDMA_ATOMIC_LEN_8 8
#define CDMA_ATOMIC_LEN_16 16

#define SQE_PLD_TOKEN_ID_MASK GENMASK(19, 0)

/* thanks to include/rdma/ib_verbs.h */
enum cdma_sq_opcode {
	CDMA_OPC_WRITE = 0x3,
	CDMA_OPC_WRITE_WITH_NOTIFY = 0x5,
	CDMA_OPC_READ = 0x6,
	CDMA_OPC_CAS,
	CDMA_OPC_FAA = 0xb,
	CDMA_OPC_INVALID = 0x12,
};

enum cdma_jfsc_mode {
	CDMA_JFS_MODE,
	CDMA_JETTY_MODE,
};

enum cdma_jetty_state {
	CDMA_JETTY_RESET,
	CDMA_JETTY_READY,
	CDMA_JETTY_ERROR,
	CDMA_JETTY_SUSPENDED,
};

enum cdma_jetty_type {
	CDMA_JETTY_ROL = 2,
	CDMA_JETTY_ROI,
	CDMA_JETTY_TYPE_RESERVED,
};

struct cdma_jetty_queue {
	struct cdma_buf buf;
	void *kva_curr;
	u32 id;
	void __iomem *db_addr;
	void __iomem *dwqe_addr;
	u32 pi;
	u32 ci;
	spinlock_t lock;
	u32 max_inline_size;
	u32 max_sge_num;
	u32 tid;
	bool flush_flag;
	bool is_jetty;
	u32 sqe_bb_cnt;
	enum cdma_jetty_state state;
	u32 non_pin;
	u32 ta_tmo;
};

struct cdma_umem_param {
	struct cdma_dev *dev;
	u64 va;
	u64 len;
	union cdma_umem_flag flag;
	bool is_kernel;
};

static inline u64 cdma_cal_npages(u64 va, u64 len)
{
	return (ALIGN(va + len, PAGE_SIZE) - ALIGN_DOWN(va, PAGE_SIZE)) /
		PAGE_SIZE;
}

struct cdma_umem *cdma_umem_get(struct cdma_dev *cdev, u64 va, u64 len,
				bool is_kernel, struct cdma_context *ctx);
void cdma_put_umem(struct cdma_umem *umem, bool is_kernel);

int cdma_k_alloc_buf(struct cdma_dev *cdev, size_t memory_size,
		     struct cdma_buf *buf);
void cdma_k_free_buf(struct cdma_dev *cdev, size_t memory_size,
		     struct cdma_buf *buf);

static inline void cdma_ksva_tlb_inv(struct iommu_domain *domain,
				     unsigned long addr, size_t size)
{
	struct iommu_iotlb_gather gather;

	iommu_iotlb_gather_init(&gather);
	iommu_iotlb_gather_add_range(&gather, addr, PAGE_ALIGN(size));
	iommu_iotlb_sync(domain, &gather);
}

#endif /* __CDMA_COMMON_H__ */
