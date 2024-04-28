/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef HMM_MR_H
#define HMM_MR_H

#include "hmm_umem.h"
#include "hmm_comp.h"


#define ROCE_DMA_MR_SIZE (~0ULL)
#define ROCE_FRMR_MAX_PAGES 512
#define MR_KEY_RIGHT_SHIFT_OFS 24
#define MR_KEY_LEFT_SHIFT_OFS 8

struct hmm_mr {
	struct hmm_umem *umem;
	struct rdma_mr rdmamr;
	void *hwdev;
};

int hmm_rdma_enable_mr_mpt(void *hwdev, struct rdma_mr *mr, u16 channel);

int hmm_rdma_disable_mr_mpt(void *hwdev, struct rdma_mr *mr, u32 service_type, u16 channel);

void hmm_rdma_mpt_free(void *hwdev, struct rdma_mpt *mpt);

int hmm_init_resource(void *hwdev, u32 service_type);

void hmm_cleanup_resource(void *hwdev, u32 service_type);

#endif // HMM_MR_H_
