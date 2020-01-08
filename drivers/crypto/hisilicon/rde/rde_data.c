// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include "rde_data.h"

static inline u32 sgl_addr_cnt(struct sgl_hw *sgl)
{
	u32 cnt = 0;
	struct sgl_hw *cur_sgl = sgl;

	if (!sgl) {
		pr_err("[%s] Sgl address is NULL.\n", __func__);
		return 0;
	}

	while (cur_sgl) {
		cnt += 1;
		cnt += cur_sgl->entry_sum_in_sgl;
		cur_sgl = cur_sgl->next;
	}

	return cnt;
}

int acc_sgl_dump(struct sgl_hw *data)
{
	u32 i;
	u32 cnt_entries;
	struct sgl_hw *cur_sgl;
	struct sgl_hw *next_sgl;
	struct sgl_entry_hw *entry;

	if (unlikely(!data->entry_sum_in_sgl)) {
		pr_err("Error! The entrysum of sgl is zero.\n");
		return -EINVAL;
	}
	cnt_entries = sgl_addr_cnt(data);
	pr_info("Sgl entries:%d.\n", cnt_entries);

	for (cur_sgl = data; cur_sgl; ) {
		pr_info("Sgl addr: 0x%pK.\n", cur_sgl);
		pr_info("NextSgl: 0x%pK.\n", cur_sgl->next);
		pr_info("EntrySumInChain: %u.\n", cur_sgl->entry_sum_in_chain);
		pr_info("EntrySumInSgl: %u.\n", cur_sgl->entry_sum_in_sgl);

		entry = cur_sgl->entries;
		for (i = 0; (i < cur_sgl->entry_sum_in_sgl &&
			entry->buf); i++) {
			pr_info("Entries[%d]:addr = 0x%pK.\n", i, entry->buf);
			entry++;
		}
		if (cur_sgl->next)
			next_sgl = cur_sgl->next;
		else
			next_sgl = NULL;

		cur_sgl = next_sgl;
	}

	return 0;
}

static void acc_sgl_to_scatterlist(struct pci_dev *pdev, struct sgl_hw *data,
	struct scatterlist *sglist, u32 smmu_state)
{
	u16 i;
	struct sgl_hw *cur_sgl;
	struct sgl_hw *next_sgl;
	struct sgl_entry_hw *entry;
	dma_addr_t pa;

	cur_sgl = data;
	while (cur_sgl) {
		entry = cur_sgl->entries;
		for (i = 0; (i < cur_sgl->entry_sum_in_sgl &&
			entry->buf); i++) {
			sg_set_buf(sglist, (void *)entry->buf, entry->len);
			pa = acc_virt_to_phys(pdev, sg_virt(sglist),
					      (size_t)sglist->length,
					      smmu_state);
			sg_dma_address(sglist) = pa;
			sglist++;
			entry->buf = (char *)pa;
			entry++;
		}
		if (cur_sgl->next) {
			next_sgl = cur_sgl->next;
			sg_set_buf(sglist, (void *)next_sgl,
				   (u32)(sizeof(struct sgl_hw) +
				   sizeof(struct sgl_entry_hw) *
				   (next_sgl->entry_sum_in_sgl)));
			pa = acc_virt_to_phys(pdev, sg_virt(sglist),
					      (size_t)sglist->length,
					      smmu_state);
			sg_dma_address(sglist) = pa;
			sglist++;
			cur_sgl->next = (struct sgl_hw *)pa;
		} else {
			next_sgl = NULL;
		}
		cur_sgl = next_sgl;
	}
}

int acc_sgl_virt_to_phys(struct pci_dev *pdev, struct sgl_hw *data,
	void **sglist_head, u32 smmu_state)
{
	u32 addr_cnt;
	struct scatterlist *sglist;

	if (!data) {
		pr_err("[%s] Para sgl_s is NULL.\n", __func__);
		return -EINVAL;
	}

	if (unlikely(!data->entry_sum_in_sgl) ||
		     data->entry_sum_in_sgl > data->entry_num_in_sgl) {
		pr_err("[%s] Para sge num is wrong.\n", __func__);
		return -EINVAL;
	}

	addr_cnt = sgl_addr_cnt(data);
	sglist = kcalloc(addr_cnt, sizeof(*sglist), GFP_KERNEL);
	if (unlikely(!sglist)) {
		pr_err("[%s] Malloc sglist fail.\n", __func__);
		return -ENOMEM;
	}

	*sglist_head = sglist;
	sg_init_table(sglist, addr_cnt);
	sg_set_buf(sglist, (void *)data, (u32)(sizeof(struct sgl_hw) +
		   sizeof(struct sgl_entry_hw) * (data->entry_sum_in_sgl)));
	sg_dma_address(sglist) = acc_virt_to_phys(pdev, sg_virt(sglist),
				 (size_t)sglist->length, smmu_state);
	sglist++;
	acc_sgl_to_scatterlist(pdev, data, sglist, smmu_state);

	return 0;
}

int acc_sgl_phys_to_virt(struct pci_dev *pdev, void *sglist_head,
	u32 smmu_state)
{
	int i;
	struct sgl_hw *cur_sgl;
	struct sgl_hw *next_sgl;
	struct sgl_entry_hw *entry;
	struct scatterlist *sglist;
	struct scatterlist *sg;
	int ret = -EFAULT;

	if (!sglist_head) {
		pr_err("[%s] Para sglist_head is NULL.\n", __func__);
		return -EINVAL;
	}

	sglist = (struct scatterlist *)sglist_head;
	sg = sglist;
	cur_sgl = (struct sgl_hw *)sg_virt(sg);
	acc_phys_to_virt(pdev, sg_dma_address(sg),
			 (size_t)sg->length, smmu_state);
	while (cur_sgl) {
		entry = cur_sgl->entries;
		for (i = 0; (i < cur_sgl->entry_sum_in_sgl &&
			entry->buf); i++) {
			sg = sg_next(sg);
			if (unlikely(!sg)) {
				pr_err("[%s][%d]Scatterlist happens to be NULL.\n",
				       __func__, __LINE__);
				goto FAIL;
			}
			entry->buf = (char *)sg_virt(sg);
			acc_phys_to_virt(pdev, sg_dma_address(sg),
					 (size_t)sg->length, smmu_state);
			entry++;
		}

		if (cur_sgl->next) {
			sg = sg_next(sg);
			if (unlikely(!sg)) {
				pr_err("[%s][%d]Scatterlist happens to be NULL.\n",
				       __func__, __LINE__);
				goto FAIL;
			}
			next_sgl = (struct sgl_hw *)sg_virt(sg);
			acc_phys_to_virt(pdev, sg_dma_address(sg),
					 (size_t)sg->length, smmu_state);
			cur_sgl->next = next_sgl;
		} else {
			next_sgl = NULL;
		}

		cur_sgl = next_sgl;
	}

	ret = 0;

FAIL:
	kfree(sglist);
	return ret;
}

