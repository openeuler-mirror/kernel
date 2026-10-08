/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Memory manage module
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: Peter.Pan <peter.pan@nebula-matrix.com>
 */

#ifndef MEM_V1_H
#define MEM_V1_H

#include <rdma/ib_umem.h>
#include "user.h"

#define NBL_DMA_ADDR_CHK_SHIFT 16

struct nbl_dma_alloc_addr {
	void *va;
	dma_addr_t dma_addr;
};

#define NBL_MEM_PA_BYTE_CNT 8
void *nbl_get_wqe_v1(void *base, struct nbl_frag_buf *buf, int wqe_size,
		  int wqe_idx, bool pa_continue);
void nbl_get_umem_info_v1(struct ib_umem *umem, u32 *pg_num, bool *is_contiguous);
int nbl_copy_user_pgaddrs_v1(struct ib_umem *umem, u64 *pas, u32 pas_size,
			  u32 total_cnt, u32 *copy_num);
void *nbl_dma_alloc_coherent_v1(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp);
dma_addr_t nbl_get_first_sg_dma_addr_v1(struct ib_umem *umem);
#endif
