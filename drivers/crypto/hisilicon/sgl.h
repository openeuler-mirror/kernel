/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2019 HiSilicon Limited. */
#ifndef HISI_ACC_SGL_H
#define HISI_ACC_SGL_H

struct acc_hw_sgl *acc_sg_buf_map_to_hw_sgl(struct device *dev,
					    struct scatterlist *sgl,
					    struct dma_pool *pool,
					    dma_addr_t *hw_sgl_dma);
void acc_sg_buf_unmap(struct device *dev, struct scatterlist *sgl,
		      struct acc_hw_sgl *hw_sgl, dma_addr_t hw_sgl_dma,
		      struct dma_pool *pool);
struct dma_pool *acc_create_sgl_pool(struct device *dev, const char *name);
#endif
