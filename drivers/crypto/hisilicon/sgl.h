/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2019 HiSilicon Limited. */
#ifndef HISI_ACC_SGL_H
#define HISI_ACC_SGL_H

#define ACC_SGL_SGE_NR_MIN	1
#define ACC_SGL_SGE_NR_MAX	255
#define ACC_SGL_SGE_NR		64
#define ACC_SGL_NR_MAX		256
#define ACC_SGL_ALIGN_SIZE	64

struct acc_hw_sge {
	dma_addr_t buf;
	void *page_ctrl;
	__le32 len;
	__le32 pad;
	__le32 pad0;
	__le32 pad1;
};

/* use default sgl head size 64B */
struct acc_hw_sgl {
	dma_addr_t next_dma;
	__le16 entry_sum_in_chain;
	__le16 entry_sum_in_sgl;
	__le16 entry_length_in_sgl;
	__le16 pad0;
	__le64 pad1[5];
	struct acc_hw_sgl *next;
	struct acc_hw_sge sge_entries[ACC_SGL_SGE_NR];
};

struct acc_hw_sgl *acc_sg_buf_map_to_hw_sgl(struct device *dev,
					    struct scatterlist *sgl,
					    struct dma_pool *pool,
					    dma_addr_t *hw_sgl_dma);
void acc_sg_buf_unmap(struct device *dev, struct scatterlist *sgl,
		      struct acc_hw_sgl *hw_sgl, dma_addr_t hw_sgl_dma,
		      struct dma_pool *pool);
struct dma_pool *acc_create_sgl_pool(struct device *dev, const char *name);

struct acc_hw_sgl *acc_alloc_multi_sgl(struct device *dev,
	dma_addr_t *hw_sgl_dma, int sgl_num);
void acc_free_multi_sgl(struct device *dev, struct acc_hw_sgl *hw_sgl,
	dma_addr_t hw_sgl_dma, int sgl_num);

int acc_sg_buf_map_v2(struct device *dev, struct scatterlist *sgl,
	struct acc_hw_sgl *hw_sgl, int sge_num);
void acc_sg_buf_unmap_v2(struct device *dev, struct scatterlist *sgl);

#endif
