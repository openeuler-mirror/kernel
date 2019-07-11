// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 HiSilicon Limited. */
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/module.h>
#include <linux/delay.h>
#include "./sgl.h"

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
} __aligned(1);

/**
 * acc_create_sgl_pool() - Create a hw sgl pool.
 * @dev: The device which hw sgl pool belongs to.
 * @name: Name of this pool.
 *
 * This function creates a hw sgl pool for a device, after this user can
 * allocate hw sgl memory from it.
 */
struct dma_pool *acc_create_sgl_pool(struct device *dev, const char *name)
{
	if (!dev || !name)
		return ERR_PTR(-EINVAL);

	return dmam_pool_create(name, dev, sizeof(struct acc_hw_sgl),
				ACC_SGL_ALIGN_SIZE, 0);
}
EXPORT_SYMBOL_GPL(acc_create_sgl_pool);

void acc_free_sgl_pool(struct dma_pool *pool) {}

struct acc_hw_sgl *acc_allocate_sgl(struct dma_pool *pool,
				    dma_addr_t *hw_sgl_dma)
{
	if (!pool || !hw_sgl_dma)
		return ERR_PTR(-EINVAL);

	return dma_pool_zalloc(pool, GFP_KERNEL, hw_sgl_dma);
}

void acc_free_sgl(struct dma_pool *pool, struct acc_hw_sgl *hw_sgl,
		  dma_addr_t hw_sgl_dma)
{
	if (!pool || !hw_sgl_dma)
		return;

	return dma_pool_free(pool, hw_sgl, hw_sgl_dma);
}

/* return true if sgl has empty sge */
static bool has_empty_sge(struct acc_hw_sgl *hw_sgl)
{
	return (hw_sgl->entry_sum_in_sgl < hw_sgl->entry_length_in_sgl);
}

static void add_to_sgl(struct acc_hw_sgl *last_hw_sgl,
		       struct acc_hw_sgl *new_hw_sgl, dma_addr_t new_sgl_dma)
{
	last_hw_sgl->next = new_hw_sgl;
	last_hw_sgl->next_dma = new_sgl_dma;
}

static void __sg_map_to_hw_sg(struct scatterlist *sgl,
			      struct acc_hw_sge *hw_sge)
{
	hw_sge->buf = sgl->dma_address;
	hw_sge->len = sgl->dma_length;
}

static void inc_hw_sgl_sge(struct acc_hw_sgl *hw_sgl)
{
	hw_sgl->entry_sum_in_sgl++;
}

static void update_hw_sgl_sum_sge(struct acc_hw_sgl *hw_sgl, u16 sum)
{
	hw_sgl->entry_sum_in_chain = sum;
}

static void acc_free_sgls(struct dma_pool *pool, struct acc_hw_sgl *hw_sgl,
			  dma_addr_t hw_sgl_dma)
{
	if (!pool || !hw_sgl)
		return;

	if (!hw_sgl->next) {
		acc_free_sgl(pool, hw_sgl, hw_sgl_dma);
	} else {
		acc_free_sgls(pool, hw_sgl->next, hw_sgl->next_dma);
		acc_free_sgl(pool, hw_sgl, hw_sgl_dma);
	}
}

/**
 * acc_sg_buf_map_to_hw_sgl - Map a scatterlist to a hw sgl.
 * @dev: The device which hw sgl belongs to.
 * @sgl: Scatterlist which will be mapped to hw sgl.
 * @pool: Pool which hw sgl memory will be allocated in.
 * @hw_sgl_dma: The dma address of allocated hw sgl.
 *
 * This function builds hw sgl according input sgl, user can use hw_sgl_dma
 * as src/dst in its BD.
 */
struct acc_hw_sgl *acc_sg_buf_map_to_hw_sgl(struct device *dev,
					    struct scatterlist *sgl,
					    struct dma_pool *pool,
					    dma_addr_t *hw_sgl_dma)
{
	struct acc_hw_sgl *head_hw_sgl, *curr_hw_sgl, *last_hw_sgl;
	dma_addr_t curr_sgl_dma, head_sgl_dma;
	struct acc_hw_sge *curr_hw_sge;
	struct scatterlist *sg;
	int sg_n = sg_nents(sgl);
	int i, ret, sgl_n = 0;

	if (!dev || !sgl || !pool || !hw_sgl_dma)
		return ERR_PTR(-EINVAL);

	ret = dma_map_sg(dev, sgl, sg_n, DMA_BIDIRECTIONAL);
	if (!ret)
		return ERR_PTR(-EINVAL);

	curr_hw_sgl = acc_allocate_sgl(pool, &curr_sgl_dma);
	if (!curr_hw_sgl) {
		ret = -ENOMEM;
		goto err_unmap_sg;
	}
	curr_hw_sgl->entry_length_in_sgl = ACC_SGL_SGE_NR;
	sgl_n++;

	head_sgl_dma = curr_sgl_dma;
	head_hw_sgl = last_hw_sgl = curr_hw_sgl;
	curr_hw_sge = curr_hw_sgl->sge_entries;

	for_each_sg(sgl, sg, sg_n, i) {
		/* if there is no sge in this hw sgl, allocate a new hw sgl */
		if (unlikely(!has_empty_sge(curr_hw_sgl))) {
			if (sgl_n == ACC_SGL_NR_MAX) {
				ret = -ENOSPC;
				dev_err(dev, "sgl number should not be more than %d\n",
					ACC_SGL_NR_MAX);
				goto err_free_sgls;
			}

			curr_hw_sgl = acc_allocate_sgl(pool, &curr_sgl_dma);
			if (!curr_hw_sgl) {
				ret = -ENOMEM;
				goto err_free_sgls;
			}
			curr_hw_sgl->entry_length_in_sgl = ACC_SGL_SGE_NR;
			sgl_n++;

			add_to_sgl(last_hw_sgl, curr_hw_sgl, curr_sgl_dma);

			last_hw_sgl = curr_hw_sgl;
			curr_hw_sge = curr_hw_sgl->sge_entries;
		}

		__sg_map_to_hw_sg(sg, curr_hw_sge);

		inc_hw_sgl_sge(curr_hw_sgl);
		curr_hw_sge++;
		usleep_range(1, 2);
	}

	update_hw_sgl_sum_sge(head_hw_sgl, ACC_SGL_SGE_NR * sgl_n);
	*hw_sgl_dma = head_sgl_dma;

	return head_hw_sgl;

err_free_sgls:
	acc_free_sgls(pool, head_hw_sgl, head_sgl_dma);
err_unmap_sg:
	dma_unmap_sg(dev, sgl, sg_n, DMA_BIDIRECTIONAL);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(acc_sg_buf_map_to_hw_sgl);

/**
 * acc_sg_buf_unmap() - Destroy and unmap allocated hw sgl.
 * @dev: The device which hw sgl belongs to.
 * @sgl: Related scatterlist.
 * @hw_sgl: Virtual address of hw sgl.
 * @hw_sgl_dma: DMA address of hw sgl.
 * @pool: Pool which hw sgl is allocated in.
 *
 * This function destroies and unmap allocated hw sgl.
 */
void acc_sg_buf_unmap(struct device *dev, struct scatterlist *sgl,
		      struct acc_hw_sgl *hw_sgl, dma_addr_t hw_sgl_dma,
		      struct dma_pool *pool)
{
	int sg_n = sg_nents(sgl);

	if (!dev || !sgl || !hw_sgl || !hw_sgl_dma || !pool)
		return;

	acc_free_sgls(pool, hw_sgl, hw_sgl_dma);

	dma_unmap_sg(dev, sgl, sg_n, DMA_BIDIRECTIONAL);
}
EXPORT_SYMBOL_GPL(acc_sg_buf_unmap);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator SGL support");
