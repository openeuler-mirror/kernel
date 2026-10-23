/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_ALLOC_V1_H
#define NBL_IB_ALLOC_V1_H

#include <linux/dma-mapping.h>

#include "main.h"

int nbl_frag_buf_alloc_v1(struct device *device, void **va, dma_addr_t *dma_handle,
		       struct nbl_frag_buf *buf);
void nbl_frag_buf_free_v1(struct device *device, void *va, dma_addr_t dma_handle,
		       struct nbl_frag_buf *buf);

#endif /* NBL_IB_ALLOC_V1_H */
