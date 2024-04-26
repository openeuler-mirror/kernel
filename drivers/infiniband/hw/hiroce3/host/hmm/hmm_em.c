// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include "hmm_em.h"

static void hmm_em_chunk_free(struct pci_dev *pdev, struct hmm_em_chunk *em_chunk)
{
	struct hmm_em_buf *cur_buf = NULL;
	struct hmm_em_buf *next_buf = NULL;

	cur_buf = &em_chunk->em_buf_list;
	next_buf = cur_buf->next_buf;

	while (next_buf != NULL) {
		cur_buf = next_buf;
		next_buf = cur_buf->next_buf;

		if ((cur_buf->buf != NULL) && (cur_buf->length > 0)) {
			memset(cur_buf->buf, 0, cur_buf->length);
			dma_free_coherent(&pdev->dev, (unsigned long)cur_buf->length,
				cur_buf->buf, cur_buf->dma_addr);
			cur_buf->buf = NULL;
			cur_buf->length = 0;
		}

		kfree(cur_buf);
		cur_buf = NULL;
	}

	kfree(em_chunk);
}

static int hmm_em_chunk_alloc_npages(struct pci_dev *pdev, struct hmm_em_chunk *em_chunk,
	int min_order)
{
	int cur_order = 0;
	int npages = 0;
	unsigned int chunk_size = HMM_EM_CHUNK_SIZE;
	struct hmm_em_buf *cur_buf = &em_chunk->em_buf_list;
	struct hmm_em_buf *next_buf = NULL;

	cur_buf->next_buf = NULL;
	cur_buf->length = 0;
	cur_order = get_order(chunk_size); //lint !e834 !e587
	npages = (int)(1U << (unsigned int)cur_order);
	while (npages > 0) {
		if (next_buf == NULL) {
			next_buf = kzalloc(sizeof(struct hmm_em_buf), GFP_KERNEL);
			if (next_buf == NULL)
				return (-ENOMEM);

			next_buf->length = 0;
			next_buf->next_buf = NULL;
		}
		cur_buf->next_buf = next_buf;

		next_buf->buf = dma_alloc_coherent(&pdev->dev, (size_t)HMM_EM_PAGE_SIZE <<
			(unsigned int)cur_order, &next_buf->dma_addr, GFP_KERNEL);
		if (next_buf->buf == NULL) {
			cur_order--;
			if (cur_order < min_order) {
				dev_err(&pdev->dev,
					"[HMM] %s:em_chunk alloc dma buf failed, err(%d)\n",
					__func__, -ENOMEM);
				return (-ENOMEM);
			}
			dev_err(&pdev->dev,
				"[HMM, WARN] %s: em_chunk alloc %d dma failed, alloc small mem\n",
				__func__, cur_order);
			continue;
		}

		next_buf->length = (u32)HMM_EM_PAGE_SIZE << (unsigned int)cur_order;
		em_chunk->buf_num++;
		npages -= (int)(1U << (unsigned int)cur_order);

		cur_buf = next_buf;
		next_buf = NULL;
	}

	return 0;
}
static struct hmm_em_chunk *hmm_em_chunk_alloc(struct pci_dev *pdev, int min_order)
{
	struct hmm_em_chunk *em_chunk = NULL;
	int ret;

	em_chunk = kzalloc(sizeof(struct hmm_em_chunk), GFP_KERNEL);
	if (em_chunk == NULL)
		return (struct hmm_em_chunk *)ERR_PTR((long)-ENOMEM);

	em_chunk->buf_num = 0;
	ret = hmm_em_chunk_alloc_npages(pdev, em_chunk, min_order);
	if (ret != 0) {
		hmm_em_chunk_free(pdev, em_chunk);
		return (struct hmm_em_chunk *)ERR_PTR((long)ret);
	}

	em_chunk->refcount = 0;

	return em_chunk;
}

static void hmm_em_table_put(struct pci_dev *pdev, struct hmm_em_table *em_table, u32 obj)
{
	u32 i = 0;

	if (obj >= em_table->obj_num) {
		dev_err(&pdev->dev, "[HMM] %s: Obj over range, obj(0x%x), max(0x%x)\n",
			__func__, obj, em_table->obj_num - 1);
		return;
	}

	i = obj / (HMM_EM_CHUNK_SIZE / em_table->obj_size);

	mutex_lock(&em_table->mutex);

	if ((em_table->em_chunk[i] == NULL) || (IS_ERR(em_table->em_chunk[i]))) {
		dev_err(&pdev->dev, "[HMM] %s: Em_table->em_chunk[%d] not alloced, obj(0x%x)\n",
			__func__, i, obj);
		mutex_unlock(&em_table->mutex);
		return;
	}

	if (em_table->em_chunk[i]->refcount == 1) {
		em_table->em_chunk[i]->refcount = 0;
		hmm_em_chunk_free(pdev, em_table->em_chunk[i]);
		em_table->em_chunk[i] = NULL;
	} else {
		--em_table->em_chunk[i]->refcount;
	}

	mutex_unlock(&em_table->mutex);
}

static int hmm_em_table_get(struct pci_dev *pdev, struct hmm_em_table *em_table, u32 obj)
{
	int ret = 0;
	u32 i;

	if (obj >= em_table->obj_num) {
		dev_err(&pdev->dev, "[HMM] %s: Obj over range, obj(0x%x), max(0x%x)\n",
			__func__, obj, em_table->obj_num - 1);
		return -EINVAL;
	}

	i = obj / (HMM_EM_CHUNK_SIZE / em_table->obj_size);

	mutex_lock(&em_table->mutex);

	if (em_table->em_chunk[i]) {
		++em_table->em_chunk[i]->refcount;
		goto out;
	}

	em_table->em_chunk[i] = hmm_em_chunk_alloc(pdev, em_table->min_order);
	if (IS_ERR(em_table->em_chunk[i])) {
		ret = (int)PTR_ERR(em_table->em_chunk[i]);
		dev_err(&pdev->dev, "[HMM] %s: Alloc em_chunk failed, ret(%d)\n",
			__func__, ret);
		goto out;
	}

	++em_table->em_chunk[i]->refcount;

out:
	mutex_unlock(&em_table->mutex);

	return ret;
}

void *hmm_em_table_find(struct hmm_em_table *em_table, u32 obj, dma_addr_t *dma_handle)
{
	void *vaddr = NULL;
	struct hmm_em_chunk *em_chunk = NULL;
	struct hmm_em_buf *cur_buf = NULL;
	struct hmm_em_buf *next_buf = NULL;
	u64 table_offset;
	u32 offset;

	if (em_table == NULL) {
		pr_err("%s: Em_table is null, err(%d)\n", __func__, -EINVAL);
		return NULL;
	}

	if (obj >= em_table->obj_num) {
		pr_err("%s: Obj over range, obj(0x%x), max(0x%x)\n",
			__func__, obj, em_table->obj_num - 1);
		return NULL;
	}

	mutex_lock(&em_table->mutex);

	table_offset = (u64)obj * em_table->obj_size;
	em_chunk = em_table->em_chunk[table_offset / HMM_EM_CHUNK_SIZE];
	offset = table_offset % HMM_EM_CHUNK_SIZE;

	if (em_chunk == NULL) {
		pr_err("%s: Em_chunk has not been alloced, err(%d)\n", __func__, -EINVAL);
		goto err_out;
	}

	cur_buf = &em_chunk->em_buf_list;
	next_buf = cur_buf->next_buf;

	while (next_buf != NULL) {
		cur_buf = next_buf;
		if (offset < cur_buf->length) {
			if (dma_handle)
				*dma_handle = cur_buf->dma_addr + offset;

			vaddr = (void *)((char *)(cur_buf->buf) + offset);
			mutex_unlock(&em_table->mutex);
			return vaddr;
		}

		offset -= cur_buf->length;
		next_buf = cur_buf->next_buf;
	}

err_out:
	mutex_unlock(&em_table->mutex);

	return NULL;
}

void hmm_em_table_put_range(struct pci_dev *pdev, struct hmm_em_table *em_table,
			    u32 start, u32 end)
{
	int i = 0;
	int inc = 0;

	if ((pdev == NULL) || (em_table == NULL)) {
		dev_err(&pdev->dev, "[HMM] %s: Pdev or em_table is null, err(%d)\n",
			__func__, -EINVAL);
		return;
	}

	inc = (int)(HMM_EM_CHUNK_SIZE / em_table->obj_size);
	for (i = (int)start; i <= (int)end; i += inc)
		hmm_em_table_put(pdev, em_table, (u32)i);
}

int hmm_em_table_get_range(struct pci_dev *pdev, struct hmm_em_table *em_table, u32 start, u32 end)
{
	int ret = 0;
	int i = 0;
	int inc = 0;

	if ((pdev == NULL) || (em_table == NULL)) {
		dev_err(&pdev->dev, "[HMM] %s: Pdev or em_table is null, err(%d)\n",
			__func__, -EINVAL);
		return -EINVAL;
	}

	inc = (int)(HMM_EM_CHUNK_SIZE / em_table->obj_size);

	for (i = (int)start; i <= (int)end; i += inc) {
		ret = hmm_em_table_get(pdev, em_table, (u32)i);
		if (ret != 0) {
			dev_err(&pdev->dev,
				"[HMM] %s: Get entry failed, start(%d), end(%d), i(%d), ret(%d)\n",
				__func__, start, end, i, ret);
			goto err_out;
		}
	}

	return 0;

err_out:
	while (i > (int)start) {
		i -= inc;
		hmm_em_table_put(pdev, em_table, (u32)i);
	}

	return ret;
}

int hmm_em_init_table(struct pci_dev *pdev, struct hmm_em_table *em_table, u32 obj_size,
	u32 nobj, u32 reserved_bot, int min_order)
{
	u32 obj_per_chunk = 0;
	u32 chunk_num = 0;

	if ((pdev == NULL) || (em_table == NULL)) {
		dev_err(&pdev->dev, "[HMM] %s: Pdev or em_table is null\n", __func__);
		return -EINVAL;
	}

	if (nobj == 0) {
		dev_err(&pdev->dev, "[HMM] %s: Nobj is invalid\n", __func__);
		return -EINVAL;
	}

	/*lint -e587 */
	if (nobj != HMM_EM_ROUNDUP_POW_OF_TWO(nobj)) {
		dev_err(&pdev->dev, "[HMM] %s: Obj isn't pow of two, nobj(0x%x)\n",
			__func__, nobj);
		return -EINVAL;
	}

	if (obj_size != HMM_EM_ROUNDUP_POW_OF_TWO(obj_size)) {
		dev_err(&pdev->dev, "[HMM] %s: Obj_size isn't pow of two, obj_size(0x%x)\n",
			__func__, obj_size);
		return -EINVAL;
	}
	/*lint +e587 */

	obj_per_chunk = HMM_EM_CHUNK_SIZE / obj_size;
	chunk_num = (nobj + obj_per_chunk - 1) / obj_per_chunk;

	em_table->em_chunk = kcalloc((size_t)chunk_num,
		sizeof(struct hmm_em_chunk *), GFP_KERNEL);
	if (em_table->em_chunk == NULL)
		return -ENOMEM;

	em_table->chunk_num = chunk_num;
	em_table->obj_num = nobj;
	em_table->obj_size = obj_size;
	em_table->min_order = min_order;

	mutex_init(&em_table->mutex);

	return 0;
}

void hmm_em_cleanup_table(struct pci_dev *pdev, struct hmm_em_table *em_table)
{
	u32 i = 0;

	if ((pdev == NULL) || (em_table == NULL)) {
		dev_err(&pdev->dev, "[HMM] %s: Pdev or em_table is null\n", __func__);
		return;
	}

	for (i = 0; i < em_table->chunk_num; i++) {
		if (em_table->em_chunk[i]) {
			hmm_em_chunk_free(pdev, em_table->em_chunk[i]);
			em_table->em_chunk[i] = NULL;
		}
	}

	kfree(em_table->em_chunk);
	em_table->em_chunk = NULL;
}
