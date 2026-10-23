/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Memory manage module
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: Peter.Pan <peter.pan@nebula-matrix.com>
 */

#ifndef MEM_H
#define MEM_H

#include <rdma/ib_umem.h>
#include "user.h"

struct nbl_dma_alloc_addr {
	void *va;
	dma_addr_t dma_addr;
};

#define NBL_MEM_PA_BYTE_CNT 8
void *nbl_get_wqe(void *base, struct nbl_frag_buf *buf, int wqe_size,
		  int wqe_idx, bool pa_continue);
void nbl_get_umem_info(struct ib_umem *umem, u32 *pg_num, bool *is_contiguous, bool use_sys_page);
int nbl_copy_user_pgaddrs(struct ib_umem *umem, u64 *pas, u32 pas_size,
			  u32 total_cnt, u32 *copy_num);
int nbl_user_buf_get(struct ib_ucontext *ibctx,
	struct nbl_device *dev, u64 usr_addr, u64 length,
	struct nbl_buf_desc *info, struct ib_udata *udata);
void nbl_user_buf_release(struct nbl_device *dev, struct nbl_buf_desc *bd);
void *nbl_dma_alloc_coherent(struct nbl_hw *hw, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp);
dma_addr_t nbl_get_first_sg_dma_addr(struct ib_umem *umem);
int nbl_check_umem_period_contiguous(struct ib_umem *umem,
	u32 offset, u32 size, bool *is_contiguous);
int nbl_get_umem_period_start(struct ib_umem *umem, u32 offset, dma_addr_t *addr);
int nbl_copy_period_pgaddrs(struct ib_umem *umem, u64 *pas, u32 offset, u32 size);
#endif
