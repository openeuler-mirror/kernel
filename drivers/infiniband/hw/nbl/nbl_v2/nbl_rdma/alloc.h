/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_ALLOC_H
#define NBL_IB_ALLOC_H

#include <linux/dma-mapping.h>

#include "main.h"

int nbl_frag_buf_alloc(struct nbl_hw *hw, void **va, dma_addr_t *dma_handle,
		       struct nbl_frag_buf *buf);
void nbl_frag_buf_free(struct nbl_hw *hw, void *va, dma_addr_t dma_handle,
		       struct nbl_frag_buf *buf);
int nbl_kernel_buf_alloc(struct nbl_hw *hw, int rsize,
	struct nbl_buf_desc *info);
void nbl_kernel_buf_free(struct nbl_hw *hw, struct nbl_buf_desc *bd);
#endif /* NBL_IB_ALLOC_H */
