// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/acpi.h>
#include <linux/iommu.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include "urma/ubcore_api.h"
#include "hns3_udma_device.h"
#include "hns3_udma_hem.h"

bool udma_check_whether_mhop(struct udma_dev *udma_dev, uint32_t type)
{
	int hop_num = 0;

	switch (type) {
	case HEM_TYPE_QPC:
		hop_num = udma_dev->caps.qpc_hop_num;
		break;
	case HEM_TYPE_MTPT:
		hop_num = udma_dev->caps.mpt_hop_num;
		break;
	case HEM_TYPE_CQC:
		hop_num = udma_dev->caps.cqc_hop_num;
		break;
	case HEM_TYPE_SRQC:
		hop_num = udma_dev->caps.srqc_hop_num;
		break;
	case HEM_TYPE_SCCC:
		hop_num = udma_dev->caps.sccc_hop_num;
		break;
	case HEM_TYPE_QPC_TIMER:
		hop_num = udma_dev->caps.qpc_timer_hop_num;
		break;
	case HEM_TYPE_CQC_TIMER:
		hop_num = udma_dev->caps.cqc_timer_hop_num;
		break;
	case HEM_TYPE_GMV:
		hop_num = udma_dev->caps.gmv_hop_num;
		break;
	default:
		return false;
	}

	return hop_num ? true : false;
}

static bool udma_check_hem_null(struct udma_hem **hem, uint64_t hem_idx,
				uint32_t bt_chunk_num, uint64_t hem_max_num)
{
	uint64_t start_idx = round_down(hem_idx, bt_chunk_num);
	uint64_t check_max_num = start_idx + bt_chunk_num;
	uint64_t i;

	for (i = start_idx; (i < check_max_num) && (i < hem_max_num); i++)
		if (i != hem_idx && hem[i])
			return false;

	return true;
}

static bool udma_check_bt_null(uint64_t **bt, uint64_t ba_idx,
			       uint32_t bt_chunk_num)
{
	uint64_t start_idx = round_down(ba_idx, bt_chunk_num);
	uint32_t i;

	for (i = start_idx; i < bt_chunk_num; i++)
		if (i != ba_idx && bt[i])
			return false;

	return true;
}

static int udma_get_bt_num(uint32_t table_type, uint32_t hop_num)
{
	if (check_whether_bt_num_3(table_type, hop_num))
		return 3;
	else if (check_whether_bt_num_2(table_type, hop_num))
		return 2;
	else if (check_whether_bt_num_1(table_type, hop_num))
		return 1;
	else
		return 0;
}

static int get_hem_table_config(struct udma_dev *udma_dev,
				struct udma_hem_mhop *mhop,
				uint32_t type)
{
	struct device *dev = udma_dev->dev;

	switch (type) {
	case HEM_TYPE_QPC:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.qpc_buf_pg_sz
					     + PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.qpc_ba_pg_sz
					     + PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.qpc_bt_num;
		mhop->hop_num = udma_dev->caps.qpc_hop_num;
		break;
	case HEM_TYPE_MTPT:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.mpt_buf_pg_sz
					     + PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.mpt_ba_pg_sz
					     + PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.mpt_bt_num;
		mhop->hop_num = udma_dev->caps.mpt_hop_num;
		break;
	case HEM_TYPE_CQC:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.cqc_buf_pg_sz
					     + PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.cqc_ba_pg_sz
					    + PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.cqc_bt_num;
		mhop->hop_num = udma_dev->caps.cqc_hop_num;
		break;
	case HEM_TYPE_SCCC:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.sccc_buf_pg_sz
					     + PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.sccc_ba_pg_sz
					    + PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.sccc_bt_num;
		mhop->hop_num = udma_dev->caps.sccc_hop_num;
		break;
	case HEM_TYPE_QPC_TIMER:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.qpc_timer_buf_pg_sz
					     + PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.qpc_timer_ba_pg_sz
					    + PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.qpc_timer_bt_num;
		mhop->hop_num = udma_dev->caps.qpc_timer_hop_num;
		break;
	case HEM_TYPE_CQC_TIMER:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.cqc_timer_buf_pg_sz
					     + PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.cqc_timer_ba_pg_sz
					    + PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.cqc_timer_bt_num;
		mhop->hop_num = udma_dev->caps.cqc_timer_hop_num;
		break;
	case HEM_TYPE_SRQC:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.srqc_buf_pg_sz
					     + PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.srqc_ba_pg_sz
					     + PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.srqc_bt_num;
		mhop->hop_num = udma_dev->caps.srqc_hop_num;
		break;
	case HEM_TYPE_GMV:
		mhop->buf_chunk_size = 1 << (udma_dev->caps.gmv_buf_pg_sz +
					     PAGE_SHIFT);
		mhop->bt_chunk_size = 1 << (udma_dev->caps.gmv_ba_pg_sz +
					    PAGE_SHIFT);
		mhop->ba_l0_num = udma_dev->caps.gmv_bt_num;
		mhop->hop_num = udma_dev->caps.gmv_hop_num;
		break;
	default:
		dev_err(dev, "table %u not support multi-hop addressing!\n",
			type);
		return -EINVAL;
	}

	return 0;
}

int udma_calc_hem_mhop(struct udma_dev *udma_dev,
		       struct udma_hem_table *table, uint64_t *obj,
		       struct udma_hem_mhop *mhop)
{
	struct device *dev = udma_dev->dev;
	uint32_t chunk_ba_num;
	uint32_t chunk_size;
	uint32_t table_idx;
	uint32_t bt_num;
	int ret;

	ret = get_hem_table_config(udma_dev, mhop, table->type);
	if (ret)
		return ret;

	if (!obj)
		return 0;

	/*
	 * QPC/MTPT/CQC/SRQC/SCCC alloc hem for buffer pages.
	 * MTT/CQE alloc hem for bt pages.
	 */
	bt_num = udma_get_bt_num(table->type, mhop->hop_num);
	chunk_ba_num = mhop->bt_chunk_size / BA_BYTE_LEN;
	chunk_size = table->type < HEM_TYPE_MTT ? mhop->buf_chunk_size :
			      mhop->bt_chunk_size;
	table_idx = *obj / (chunk_size / table->obj_size);
	switch (bt_num) {
	case 3:
		mhop->l2_idx = table_idx & (chunk_ba_num - 1);
		mhop->l1_idx = table_idx / chunk_ba_num & (chunk_ba_num - 1);
		mhop->l0_idx = (table_idx / chunk_ba_num) / chunk_ba_num;
		break;
	case 2:
		mhop->l1_idx = table_idx & (chunk_ba_num - 1);
		mhop->l0_idx = table_idx / chunk_ba_num;
		break;
	case 1:
		mhop->l0_idx = table_idx;
		break;
	default:
		dev_err(dev, "table %u not support hop_num = %u!\n",
			table->type, mhop->hop_num);
		return -EINVAL;
	}
	if (mhop->l0_idx >= mhop->ba_l0_num)
		mhop->l0_idx %= mhop->ba_l0_num;

	return 0;
}

static void udma_free_hem(struct udma_dev *udma_dev, struct udma_hem *hem)
{
	struct udma_hem_chunk *chunk, *tmp;
	int i;

	if (!hem)
		return;

	list_for_each_entry_safe(chunk, tmp, &hem->chunk_list, list) {
		for (i = 0; i < chunk->npages; ++i)
			dma_free_coherent(udma_dev->dev,
					  sg_dma_len(&chunk->mem[i]),
					  chunk->buf[i],
					  sg_dma_address(&chunk->mem[i]));
		kfree(chunk);
	}

	kfree(hem);
}

static struct udma_hem *udma_alloc_hem(struct udma_dev *udma_dev, int npages,
				       uint64_t hem_alloc_size, gfp_t gfp_mask)
{
	struct udma_hem_chunk *chunk = NULL;
	struct scatterlist *mem;
	struct udma_hem *hem;
	int pages = npages;
	int order;
	void *buf;

	hem = kmalloc(sizeof(*hem), gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN));
	if (!hem)
		return NULL;

	refcount_set(&hem->refcount, 0);
	INIT_LIST_HEAD(&hem->chunk_list);

	order = get_order(hem_alloc_size);

	chunk = kmalloc(sizeof(*chunk), gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN));
	if (!chunk)
		goto fail;

	sg_init_table(chunk->mem, UDMA_HEM_CHUNK_LEN);
	chunk->npages = 0;
	chunk->nsg = 0;
	memset(chunk->buf, 0, sizeof(chunk->buf));
	list_add_tail(&chunk->list, &hem->chunk_list);
	while (pages > 0) {
		while (1 << order > pages)
			--order;
		mem = &chunk->mem[chunk->npages];
		buf = dma_alloc_coherent(udma_dev->dev, PAGE_SIZE << order,
					 &sg_dma_address(mem), gfp_mask);
		if (!buf)
			goto fail;

		chunk->buf[chunk->npages] = buf;
		sg_dma_len(mem) = PAGE_SIZE << order;

		++chunk->npages;
		++chunk->nsg;
		pages -= 1 << order;
	}

	return hem;

fail:
	udma_free_hem(udma_dev, hem);
	return NULL;
}

static int calc_hem_config(struct udma_dev *udma_dev,
			   struct udma_hem_table *table, uint64_t obj,
			   struct udma_hem_mhop *mhop,
			   struct udma_hem_index *index)
{
	struct device *dev = udma_dev->dev;
	uint32_t l0_idx, l1_idx, l2_idx;
	uint64_t mhop_obj = obj;
	uint32_t chunk_ba_num;
	uint32_t bt_num;
	int ret;

	ret = udma_calc_hem_mhop(udma_dev, table, &mhop_obj, mhop);
	if (ret)
		return ret;

	l0_idx = mhop->l0_idx;
	l1_idx = mhop->l1_idx;
	l2_idx = mhop->l2_idx;
	chunk_ba_num = mhop->bt_chunk_size / BA_BYTE_LEN;
	bt_num = udma_get_bt_num(table->type, mhop->hop_num);
	switch (bt_num) {
	case 3:
		index->l1 = l0_idx * chunk_ba_num + l1_idx;
		index->l0 = l0_idx;
		index->buf = l0_idx * chunk_ba_num * chunk_ba_num +
			     l1_idx * chunk_ba_num + l2_idx;
		break;
	case 2:
		index->l0 = l0_idx;
		index->buf = l0_idx * chunk_ba_num + l1_idx;
		break;
	case 1:
		index->buf = l0_idx;
		break;
	default:
		dev_err(dev, "table %u not support mhop.hop_num = %u!\n",
			table->type, mhop->hop_num);
		return -EINVAL;
	}

	if (unlikely(index->buf >= table->num_hem)) {
		dev_err(dev, "table %u exceed hem limt idx %llu, max %llu!\n",
			table->type, index->buf, table->num_hem);
		return -EINVAL;
	}

	return 0;
}

static void free_mhop_hem(struct udma_dev *udma_dev,
			  struct udma_hem_table *table,
			  struct udma_hem_mhop *mhop,
			  struct udma_hem_index *index)
{
	uint32_t bt_size = mhop->bt_chunk_size;
	struct device *dev = udma_dev->dev;

	if (index->inited & HEM_INDEX_BUF) {
		udma_free_hem(udma_dev, table->hem[index->buf]);
		table->hem[index->buf] = NULL;
	}

	if (index->inited & HEM_INDEX_L1) {
		dma_free_coherent(dev, bt_size, table->bt_l1[index->l1],
				  table->bt_l1_dma_addr[index->l1]);
		table->bt_l1[index->l1] = NULL;
	}

	if (index->inited & HEM_INDEX_L0) {
		dma_free_coherent(dev, bt_size, table->bt_l0[index->l0],
				  table->bt_l0_dma_addr[index->l0]);
		table->bt_l0[index->l0] = NULL;
	}
}

static int alloc_mhop_hem(struct udma_dev *udma_dev,
			  struct udma_hem_table *table,
			  struct udma_hem_mhop *mhop,
			  struct udma_hem_index *index)
{
	uint32_t bt_size = mhop->bt_chunk_size;
	struct device *dev = udma_dev->dev;
	struct udma_hem_iter iter;
	uint64_t bt_ba;
	uint32_t size;
	gfp_t flag;
	int ret;

	/* alloc L1 BA's chunk */
	if ((check_whether_bt_num_3(table->type, mhop->hop_num) ||
	     check_whether_bt_num_2(table->type, mhop->hop_num)) &&
	     !table->bt_l0[index->l0]) {
		table->bt_l0[index->l0] = dma_alloc_coherent(dev, bt_size,
					  &table->bt_l0_dma_addr[index->l0],
					  GFP_KERNEL);
		if (!table->bt_l0[index->l0]) {
			ret = -ENOMEM;
			goto out;
		}
		index->inited |= HEM_INDEX_L0;
	}

	/* alloc L2 BA's chunk */
	if (check_whether_bt_num_3(table->type, mhop->hop_num) &&
	    !table->bt_l1[index->l1])  {
		table->bt_l1[index->l1] = dma_alloc_coherent(dev, bt_size,
					  &table->bt_l1_dma_addr[index->l1],
					  GFP_KERNEL);
		if (!table->bt_l1[index->l1]) {
			ret = -ENOMEM;
			goto err_alloc_hem;
		}
		index->inited |= HEM_INDEX_L1;
		*(table->bt_l0[index->l0] + mhop->l1_idx) =
					       table->bt_l1_dma_addr[index->l1];
	}

	/*
	 * alloc buffer space chunk for QPC/MTPT/CQC/SRQC/SCCC.
	 * alloc bt space chunk for MTT/CQE.
	 */
	size = table->type < HEM_TYPE_MTT ? mhop->buf_chunk_size : bt_size;
	flag = GFP_KERNEL | __GFP_NOWARN;
	table->hem[index->buf] = udma_alloc_hem(udma_dev, size >> PAGE_SHIFT,
						size, flag);
	if (!table->hem[index->buf]) {
		ret = -ENOMEM;
		goto err_alloc_hem;
	}

	index->inited |= HEM_INDEX_BUF;
	udma_hem_first(table->hem[index->buf], &iter);
	bt_ba = udma_hem_addr(&iter);
	if (table->type < HEM_TYPE_MTT) {
		if (mhop->hop_num == 2)
			*(table->bt_l1[index->l1] + mhop->l2_idx) = bt_ba;
		else if (mhop->hop_num == 1)
			*(table->bt_l0[index->l0] + mhop->l1_idx) = bt_ba;
	} else if (mhop->hop_num == 2) {
		*(table->bt_l0[index->l0] + mhop->l1_idx) = bt_ba;
	}

	return 0;
err_alloc_hem:
	free_mhop_hem(udma_dev, table, mhop, index);
out:
	return ret;
}

static int set_mhop_hem(struct udma_dev *udma_dev,
			struct udma_hem_table *table, uint64_t obj,
			struct udma_hem_mhop *mhop,
			struct udma_hem_index *index)
{
	struct device *dev = udma_dev->dev;
	int step_idx;
	int ret = 0;

	if (index->inited & HEM_INDEX_L0) {
		ret = udma_dev->hw->set_hem(udma_dev, table, obj, 0);
		if (ret) {
			dev_err(dev, "set HEM step 0 failed!\n");
			goto out;
		}
	}

	if (index->inited & HEM_INDEX_L1) {
		ret = udma_dev->hw->set_hem(udma_dev, table, obj, 1);
		if (ret) {
			dev_err(dev, "set HEM step 1 failed!\n");
			goto out;
		}
	}

	if (index->inited & HEM_INDEX_BUF) {
		if (mhop->hop_num == UDMA_HOP_NUM_0)
			step_idx = 0;
		else
			step_idx = mhop->hop_num;
		ret = udma_dev->hw->set_hem(udma_dev, table, obj, step_idx);
		if (ret)
			dev_err(dev, "set HEM step last failed!\n");
	}
out:
	return ret;
}

static int udma_table_mhop_get(struct udma_dev *udma_dev,
			       struct udma_hem_table *table,
			       uint64_t obj)
{
	struct device *dev = udma_dev->dev;
	struct udma_hem_index index = {};
	struct udma_hem_mhop mhop = {};
	int ret;

	ret = calc_hem_config(udma_dev, table, obj, &mhop, &index);
	if (ret) {
		dev_err(dev, "calc hem config failed!\n");
		return ret;
	}

	mutex_lock(&table->mutex);
	if (table->hem[index.buf]) {
		refcount_inc(&table->hem[index.buf]->refcount);
		goto out;
	}

	ret = alloc_mhop_hem(udma_dev, table, &mhop, &index);
	if (ret) {
		dev_err(dev, "alloc mhop hem failed!\n");
		goto out;
	}

	/* set HEM base address to hardware */
	if (table->type < HEM_TYPE_MTT) {
		ret = set_mhop_hem(udma_dev, table, obj, &mhop, &index);
		if (ret) {
			dev_err(dev, "set HEM address to HW failed!\n");
			goto err_alloc;
		}
	}

	refcount_set(&table->hem[index.buf]->refcount, 1);
	goto out;

err_alloc:
	free_mhop_hem(udma_dev, table, &mhop, &index);
out:
	mutex_unlock(&table->mutex);
	return ret;
}

int udma_table_get(struct udma_dev *udma_dev,
		   struct udma_hem_table *table, uint64_t obj)
{
	struct device *dev = udma_dev->dev;
	int ret = 0;
	uint64_t i;

	if (udma_check_whether_mhop(udma_dev, table->type))
		return udma_table_mhop_get(udma_dev, table, obj);

	i = obj / (table->table_chunk_size / table->obj_size);

	mutex_lock(&table->mutex);

	if (table->hem[i]) {
		refcount_inc(&table->hem[i]->refcount);
		goto out;
	}

	table->hem[i] = udma_alloc_hem(udma_dev,
				       table->table_chunk_size >> PAGE_SHIFT,
				       table->table_chunk_size,
				       GFP_KERNEL | __GFP_NOWARN);
	if (!table->hem[i]) {
		ret = -ENOMEM;
		goto out;
	}

	/* Set HEM base address(128K/page, pa) to Hardware */
	if (udma_dev->hw->set_hem(udma_dev, table, obj, HEM_HOP_STEP_DIRECT)) {
		udma_free_hem(udma_dev, table->hem[i]);
		table->hem[i] = NULL;
		ret = -ENODEV;
		dev_err(dev, "set HEM base address to HW failed.\n");
		goto out;
	}

	refcount_set(&table->hem[i]->refcount, 1);
out:
	mutex_unlock(&table->mutex);
	return ret;
}

static void clear_mhop_hem(struct udma_dev *udma_dev,
			   struct udma_hem_table *table, uint64_t obj,
			   struct udma_hem_mhop *mhop,
			   struct udma_hem_index *index)
{
	struct device *dev = udma_dev->dev;
	uint32_t hop_num = mhop->hop_num;
	uint32_t chunk_ba_num;
	int step_idx;

	index->inited = HEM_INDEX_BUF;
	chunk_ba_num = mhop->bt_chunk_size / BA_BYTE_LEN;
	if (check_whether_bt_num_2(table->type, hop_num)) {
		if (udma_check_hem_null(table->hem, index->buf,
					chunk_ba_num, table->num_hem))
			index->inited |= HEM_INDEX_L0;
	} else if (check_whether_bt_num_3(table->type, hop_num)) {
		if (udma_check_hem_null(table->hem, index->buf,
					chunk_ba_num, table->num_hem)) {
			index->inited |= HEM_INDEX_L1;
			if (udma_check_bt_null(table->bt_l1, index->l1,
					       chunk_ba_num))
				index->inited |= HEM_INDEX_L0;
		}
	}

	if (table->type < HEM_TYPE_MTT) {
		if (hop_num == UDMA_HOP_NUM_0)
			step_idx = 0;
		else
			step_idx = hop_num;

		if (udma_dev->hw->clear_hem(udma_dev, table, obj, step_idx))
			dev_err(dev, "failed to clear hop%u HEM.\n", hop_num);

		if (index->inited & HEM_INDEX_L1)
			if (udma_dev->hw->clear_hem(udma_dev, table, obj, 1))
				dev_err(dev, "failed to clear HEM step 1.\n");

		if (index->inited & HEM_INDEX_L0)
			if (udma_dev->hw->clear_hem(udma_dev, table, obj, 0))
				dev_err(dev, "failed to clear HEM step 0.\n");
	}
}

static void udma_table_mhop_put(struct udma_dev *udma_dev,
				struct udma_hem_table *table, uint64_t obj,
				int check_refcount)
{
	struct device *dev = udma_dev->dev;
	struct udma_hem_index index = {};
	struct udma_hem_mhop mhop = {};
	int ret;

	ret = calc_hem_config(udma_dev, table, obj, &mhop, &index);
	if (ret) {
		dev_err(dev, "calc hem config failed!\n");
		return;
	}

	if (!check_refcount)
		mutex_lock(&table->mutex);
	else if (!refcount_dec_and_mutex_lock(&table->hem[index.buf]->refcount,
					      &table->mutex))
		return;

	clear_mhop_hem(udma_dev, table, obj, &mhop, &index);
	free_mhop_hem(udma_dev, table, &mhop, &index);

	mutex_unlock(&table->mutex);
}

void udma_table_put(struct udma_dev *udma_dev,
		    struct udma_hem_table *table, uint64_t obj)
{
	struct device *dev = udma_dev->dev;
	uint64_t i;

	if (udma_check_whether_mhop(udma_dev, table->type)) {
		udma_table_mhop_put(udma_dev, table, obj, 1);
		return;
	}

	i = obj / (table->table_chunk_size / table->obj_size);

	if (!refcount_dec_and_mutex_lock(&table->hem[i]->refcount,
					 &table->mutex))
		return;

	if (udma_dev->hw->clear_hem(udma_dev, table, obj, HEM_HOP_STEP_DIRECT))
		dev_warn(dev, "failed to clear HEM base address.\n");

	udma_free_hem(udma_dev, table->hem[i]);
	table->hem[i] = NULL;

	mutex_unlock(&table->mutex);
}

void *udma_table_find(struct udma_dev *udma_dev,
		      struct udma_hem_table *table,
		      uint64_t obj, dma_addr_t *dma_handle)
{
	struct udma_hem_chunk *chunk;
	struct udma_hem_mhop mhop;
	uint64_t mhop_obj = obj;
	uint64_t obj_per_chunk;
	int offset, dma_offset;
	struct udma_hem *hem;
	uint32_t hem_idx = 0;
	uint64_t idx_offset;
	void *addr = NULL;
	uint32_t length;
	uint32_t i, j;

	mutex_lock(&table->mutex);

	if (!udma_check_whether_mhop(udma_dev, table->type)) {
		obj_per_chunk = table->table_chunk_size / table->obj_size;
		hem = table->hem[obj / obj_per_chunk];
		idx_offset = obj % obj_per_chunk;
		dma_offset = offset = idx_offset * table->obj_size;
	} else {
		/* 8 bytes per BA and 8 BA per segment */
		uint32_t seg_size = 64;

		if (udma_calc_hem_mhop(udma_dev, table, &mhop_obj, &mhop))
			goto out;
		/* mtt mhop */
		i = mhop.l0_idx;
		j = mhop.l1_idx;
		if (mhop.hop_num == 2)
			hem_idx = i * (mhop.bt_chunk_size / BA_BYTE_LEN) + j;
		else if (mhop.hop_num == 1 ||
			 mhop.hop_num == UDMA_HOP_NUM_0)
			hem_idx = i;

		hem = table->hem[hem_idx];
		dma_offset = offset = obj * seg_size % mhop.bt_chunk_size;
		if (mhop.hop_num == 2)
			dma_offset = offset = 0;
	}

	if (!hem)
		goto out;

	list_for_each_entry(chunk, &hem->chunk_list, list) {
		for (i = 0; (int)i < chunk->npages; ++i) {
			length = sg_dma_len(&chunk->mem[i]);
			if (dma_handle && dma_offset >= 0) {
				*dma_handle = length > (uint32_t)dma_offset ? sg_dma_address(
						&chunk->mem[i]) + dma_offset : *dma_handle;
				dma_offset -= length;
			}

			if (length > (uint32_t)offset) {
				addr = (char *)chunk->buf[i] + offset;
				goto out;
			}
			offset -= length;
		}
	}

out:
	mutex_unlock(&table->mutex);
	return addr;
}

int udma_init_hem_table(struct udma_dev *udma_dev,
			struct udma_hem_table *table, uint32_t type,
			uint64_t obj_size, uint64_t nobj)
{
	uint64_t obj_per_chunk;
	uint64_t num_hem;

	if (!udma_check_whether_mhop(udma_dev, type)) {
		table->table_chunk_size = udma_dev->caps.chunk_sz;
		obj_per_chunk = table->table_chunk_size / obj_size;
		num_hem = DIV_ROUND_UP(nobj, obj_per_chunk);

		table->hem = kcalloc(num_hem, sizeof(*table->hem),
							 GFP_KERNEL);
		if (!table->hem)
			return -ENOMEM;
	} else {
		struct udma_hem_mhop mhop = {};
		uint64_t buf_chunk_size;
		uint64_t bt_chunk_size;
		uint64_t bt_chunk_num;
		uint64_t num_bt_l0;
		uint32_t hop_num;
		int ret;

		ret = get_hem_table_config(udma_dev, &mhop, type);
		if (ret)
			return ret;

		buf_chunk_size = mhop.buf_chunk_size;
		bt_chunk_size = mhop.bt_chunk_size;
		num_bt_l0 = mhop.ba_l0_num;
		hop_num = mhop.hop_num;

		obj_per_chunk = buf_chunk_size / obj_size;
		num_hem = DIV_ROUND_UP(nobj, obj_per_chunk);
		bt_chunk_num = bt_chunk_size / BA_BYTE_LEN;

		if (type >= HEM_TYPE_MTT)
			num_bt_l0 = bt_chunk_num;

		table->hem = kcalloc(num_hem, sizeof(*table->hem),
							 GFP_KERNEL);
		if (!table->hem)
			goto err_kcalloc_hem_buf;

		if (check_whether_bt_num_3(type, hop_num)) {
			uint64_t num_bt_l1;

			num_bt_l1 = DIV_ROUND_UP(num_hem, bt_chunk_num);
			table->bt_l1 = kcalloc(num_bt_l1, sizeof(*table->bt_l1),
					       GFP_KERNEL);
			if (!table->bt_l1)
				goto err_kcalloc_bt_l1;

			table->bt_l1_dma_addr = kcalloc(num_bt_l1,
						 sizeof(*table->bt_l1_dma_addr),
						 GFP_KERNEL);

			if (!table->bt_l1_dma_addr)
				goto err_kcalloc_l1_dma;
		}

		if (check_whether_bt_num_2(type, hop_num) ||
		    check_whether_bt_num_3(type, hop_num)) {
			table->bt_l0 = kcalloc(num_bt_l0, sizeof(*table->bt_l0),
						       GFP_KERNEL);
			if (!table->bt_l0)
				goto err_kcalloc_bt_l0;

			table->bt_l0_dma_addr = kcalloc(num_bt_l0,
						 sizeof(*table->bt_l0_dma_addr),
						 GFP_KERNEL);
			if (!table->bt_l0_dma_addr)
				goto err_kcalloc_l0_dma;
		}
	}

	table->type = type;
	table->num_hem = num_hem;
	table->obj_size = obj_size;
	mutex_init(&table->mutex);

	return 0;

err_kcalloc_l0_dma:
	kfree(table->bt_l0);
	table->bt_l0 = NULL;

err_kcalloc_bt_l0:
	kfree(table->bt_l1_dma_addr);
	table->bt_l1_dma_addr = NULL;

err_kcalloc_l1_dma:
	kfree(table->bt_l1);
	table->bt_l1 = NULL;

err_kcalloc_bt_l1:
	kfree(table->hem);
	table->hem = NULL;

err_kcalloc_hem_buf:
	return -ENOMEM;
}

static void udma_cleanup_mhop_hem_table(struct udma_dev *udma_dev,
					struct udma_hem_table *table)
{
	struct udma_hem_mhop mhop;
	uint32_t buf_chunk_size;
	uint64_t obj;
	uint32_t i;

	if (udma_calc_hem_mhop(udma_dev, table, NULL, &mhop))
		return;
	buf_chunk_size = table->type < HEM_TYPE_MTT ? mhop.buf_chunk_size :
					mhop.bt_chunk_size;

	for (i = 0; i < table->num_hem; ++i) {
		obj = i * buf_chunk_size / table->obj_size;
		if (table->hem[i])
			udma_table_mhop_put(udma_dev, table, obj, 0);
	}

	kfree(table->hem);
	table->hem = NULL;
	kfree(table->bt_l1);
	table->bt_l1 = NULL;
	kfree(table->bt_l1_dma_addr);
	table->bt_l1_dma_addr = NULL;
	kfree(table->bt_l0);
	table->bt_l0 = NULL;
	kfree(table->bt_l0_dma_addr);
	table->bt_l0_dma_addr = NULL;
}

void udma_cleanup_hem_table(struct udma_dev *udma_dev,
			    struct udma_hem_table *table)
{
	struct device *dev = udma_dev->dev;
	uint64_t i;

	if (udma_check_whether_mhop(udma_dev, table->type)) {
		udma_cleanup_mhop_hem_table(udma_dev, table);
		return;
	}

	for (i = 0; i < table->num_hem; ++i)
		if (table->hem[i]) {
			if (udma_dev->hw->clear_hem(udma_dev, table,
						    i * table->table_chunk_size
						    / table->obj_size, 0))
				dev_err(dev, "Clear HEM base address failed.\n");

			udma_free_hem(udma_dev, table->hem[i]);
		}

	kfree(table->hem);
	table->hem = NULL;
}

static struct udma_hem_item *
hem_list_alloc_item(struct udma_dev *udma_dev, int start, int end, int count,
		    bool exist_bt)
{
	struct udma_hem_item *hem;

	hem = kzalloc(sizeof(*hem), GFP_KERNEL);
	if (!hem)
		return NULL;

	if (exist_bt) {
		hem->addr = dma_alloc_coherent(udma_dev->dev,
					       count * BA_BYTE_LEN,
					       &hem->dma_addr, GFP_KERNEL);
		if (!hem->addr) {
			kfree(hem);
			return NULL;
		}
	}

	hem->count = count;
	hem->start = start;
	hem->end = end;
	INIT_LIST_HEAD(&hem->list);
	INIT_LIST_HEAD(&hem->sibling);

	return hem;
}

static void hem_list_free_item(struct udma_dev *udma_dev,
			       struct udma_hem_item *hem, bool exist_bt)
{
	if (exist_bt)
		dma_free_coherent(udma_dev->dev, hem->count * BA_BYTE_LEN,
				  hem->addr, hem->dma_addr);
	kfree(hem);
}

static void hem_list_free_all(struct udma_dev *udma_dev,
			      struct list_head *head, bool exist_bt)
{
	struct udma_hem_item *hem, *temp_hem;

	list_for_each_entry_safe(hem, temp_hem, head, list) {
		list_del(&hem->list);
		hem_list_free_item(udma_dev, hem, exist_bt);
	}
}

static void hem_list_link_bt(struct udma_dev *udma_dev, void *base_addr,
			     uint64_t table_addr)
{
	*(uint64_t *)(base_addr) = table_addr;
}

/* assign L0 table address to hem from root bt */
static void hem_list_assign_bt(struct udma_dev *udma_dev,
			       struct udma_hem_item *hem, void *cpu_addr,
			       uint64_t phy_addr)
{
	hem->addr = cpu_addr;
	hem->dma_addr = (dma_addr_t)phy_addr;
}

static inline bool hem_list_page_is_in_range(struct udma_hem_item *hem,
					     int offset)
{
	return (hem->start <= offset && offset <= hem->end);
}

static struct udma_hem_item *hem_list_search_item(struct list_head *ba_list,
						  int page_offset)
{
	struct udma_hem_item *found = NULL;
	struct udma_hem_item *hem;

	list_for_each_entry(hem, ba_list, list) {
		if (hem_list_page_is_in_range(hem, page_offset)) {
			found = hem;
			break;
		}
	}

	return found;
}

static bool hem_list_is_bottom_bt(int hopnum, int bt_level)
{
	/*
	 * hopnum    base address table levels
	 * 0		L0(buf)
	 * 1		L0 -> buf
	 * 2		L0 -> L1 -> buf
	 * 3		L0 -> L1 -> L2 -> buf
	 */
	return bt_level >= (hopnum ? hopnum - 1 : hopnum);
}

/**
 * calc base address entries num
 * @hopnum: num of mutihop addressing
 * @bt_level: base address table level
 * @unit: ba entries per bt page
 */
static uint32_t hem_list_calc_ba_range(int hopnum, int bt_level, int unit)
{
	uint32_t step;
	int max;
	int i;

	if (hopnum <= bt_level)
		return 0;
	/*
	 * hopnum  bt_level   range
	 * 1	      0       unit
	 * ------------
	 * 2	      0       unit * unit
	 * 2	      1       unit
	 * ------------
	 * 3	      0       unit * unit * unit
	 * 3	      1       unit * unit
	 * 3	      2       unit
	 */
	step = 1;
	max = hopnum - bt_level;
	for (i = 0; i < max; i++)
		step = step * unit;

	return step;
}

/**
 * calc the root ba entries which could cover all regions
 * @regions: buf region array
 * @region_cnt: array size of @regions
 * @unit: ba entries per bt page
 */
static int udma_hem_list_calc_root_ba(const struct udma_buf_region *regions,
				      int region_cnt, int unit)
{
	struct udma_buf_region *r;
	int total = 0;
	int step;
	int i;

	for (i = 0; i < region_cnt; i++) {
		r = (struct udma_buf_region *)&regions[i];
		if (r->hopnum > 1) {
			step = hem_list_calc_ba_range(r->hopnum, 1, unit);
			if (step > 0)
				total += (r->count + step - 1) / step;
		} else {
			total += r->count;
		}
	}

	return total;
}

static int hem_list_alloc_mid_bt(struct udma_dev *udma_dev,
				 const struct udma_buf_region *r, int unit,
				 uint32_t offset, struct list_head *mid_bt,
				 struct list_head *btm_bt)
{
	struct udma_hem_item *hem_ptrs[UDMA_MAX_BT_LEVEL] = { NULL };
	struct list_head temp_list[UDMA_MAX_BT_LEVEL];
	struct udma_hem_item *cur, *pre;
	const int hopnum = r->hopnum;
	int start_aligned;
	uint32_t step;
	int distance;
	int ret = 0;
	int max_ofs;
	int level;
	int end;

	if (hopnum <= 1)
		return 0;

	if (hopnum > UDMA_MAX_BT_LEVEL) {
		dev_err(udma_dev->dev, "invalid hopnum %d!\n", hopnum);
		return -EINVAL;
	}

	if (offset < r->offset) {
		dev_err(udma_dev->dev, "invalid offset %d, min %u!\n",
			offset, r->offset);
		return -EINVAL;
	}

	distance = offset - r->offset;
	max_ofs = r->offset + r->count - 1;
	for (level = 0; level < hopnum; level++)
		INIT_LIST_HEAD(&temp_list[level]);

	/* config L1 bt to last bt and link them to corresponding parent */
	for (level = 1; level < hopnum; level++) {
		cur = hem_list_search_item(&mid_bt[level], offset);
		if (cur) {
			hem_ptrs[level] = cur;
			continue;
		}

		step = hem_list_calc_ba_range(hopnum, level, unit);
		if (step < 1) {
			ret = -EINVAL;
			goto err_exit;
		}

		start_aligned = (distance / step) * step + r->offset;
		end = min_t(int, start_aligned + step - 1, max_ofs);
		cur = hem_list_alloc_item(udma_dev, start_aligned, end, unit,
					  true);
		if (!cur) {
			ret = -ENOMEM;
			goto err_exit;
		}
		hem_ptrs[level] = cur;
		list_add(&cur->list, &temp_list[level]);
		if (hem_list_is_bottom_bt(hopnum, level))
			list_add(&cur->sibling, &temp_list[0]);

		/* link bt to parent bt */
		if (level > 1) {
			pre = hem_ptrs[level - 1];
			step = (cur->start - pre->start) / step * BA_BYTE_LEN;
			hem_list_link_bt(udma_dev, (char *)pre->addr + step,
					 cur->dma_addr);
		}
	}

	list_splice(&temp_list[0], btm_bt);
	for (level = 1; level < hopnum; level++)
		list_splice(&temp_list[level], &mid_bt[level]);

	return 0;

err_exit:
	for (level = 1; level < hopnum; level++)
		hem_list_free_all(udma_dev, &temp_list[level], true);

	return ret;
}

static struct udma_hem_item *
alloc_root_hem(struct udma_dev *udma_dev, int unit, int *max_ba_num,
	       const struct udma_buf_region *regions, int region_cnt)
{
	const struct udma_buf_region *r;
	struct udma_hem_item *hem;
	int ba_num;
	int offset;

	ba_num = udma_hem_list_calc_root_ba(regions, region_cnt, unit);
	if (ba_num < 1)
		return ERR_PTR(-ENOMEM);

	if (ba_num > unit)
		return ERR_PTR(-ENOBUFS);

	offset = regions[0].offset;
	/* indicate to last region */
	r = &regions[region_cnt - 1];
	hem = hem_list_alloc_item(udma_dev, offset, r->offset + r->count - 1,
				  ba_num, true);
	if (!hem)
		return ERR_PTR(-ENOMEM);

	*max_ba_num = ba_num;

	return hem;
}

static int alloc_fake_root_bt(struct udma_dev *udma_dev, void *cpu_base,
			      uint64_t phy_base,
			      const struct udma_buf_region *r,
			      struct list_head *branch_head,
			      struct list_head *leaf_head)
{
	struct udma_hem_item *hem;

	hem = hem_list_alloc_item(udma_dev, r->offset, r->offset + r->count - 1,
				  r->count, false);
	if (!hem)
		return -ENOMEM;

	hem_list_assign_bt(udma_dev, hem, cpu_base, phy_base);
	list_add(&hem->list, branch_head);
	list_add(&hem->sibling, leaf_head);

	return r->count;
}

static int setup_middle_bt(struct udma_dev *udma_dev, void *cpu_base,
			   int unit, const struct udma_buf_region *r,
			   const struct list_head *branch_head)
{
	struct udma_hem_item *hem;
	int total = 0;
	int offset;
	int step;

	step = hem_list_calc_ba_range(r->hopnum, 1, unit);
	if (step < 1)
		return -EINVAL;

	/* if exist mid bt, link L1 to L0 */
	list_for_each_entry(hem, branch_head, list) {
		offset = (hem->start - r->offset) / step * BA_BYTE_LEN;
		hem_list_link_bt(udma_dev, (char *)cpu_base + offset,
				 hem->dma_addr);
		total++;
	}

	return total;
}

static int
setup_root_hem(struct udma_dev *udma_dev, struct udma_hem_list *hem_list,
	       int unit, int max_ba_num, struct udma_hem_head *head,
	       const struct udma_buf_region *regions, int region_cnt)
{
	const struct udma_buf_region *r;
	struct udma_hem_item *root_hem;
	uint64_t phy_base;
	void *cpu_base;
	int i, total;
	int ret;

	root_hem = list_first_entry(&head->root,
				    struct udma_hem_item, list);
	if (!root_hem)
		return -ENOMEM;

	total = 0;
	for (i = 0; i < region_cnt && total < max_ba_num; i++) {
		r = &regions[i];
		if (!r->count)
			continue;

		/* all regions's mid[x][0] shared the root_bt's trunk */
		cpu_base = (char *)root_hem->addr + total * BA_BYTE_LEN;
		phy_base = root_hem->dma_addr + total * BA_BYTE_LEN;

		/* if hopnum is 0 or 1, cut a new fake hem from the root bt
		 * which's address share to all regions.
		 */
		if (hem_list_is_bottom_bt(r->hopnum, 0))
			ret = alloc_fake_root_bt(udma_dev, cpu_base, phy_base,
						 r, &head->branch[i],
						 &head->leaf);
		else
			ret = setup_middle_bt(udma_dev, cpu_base, unit, r,
					      &hem_list->mid_bt[i][1]);

		if (ret < 0)
			return ret;

		total += ret;
	}

	list_splice(&head->leaf, &hem_list->btm_bt);
	list_splice(&head->root, &hem_list->root_bt);
	for (i = 0; i < region_cnt; i++)
		list_splice(&head->branch[i], &hem_list->mid_bt[i][0]);

	return 0;
}

static int hem_list_alloc_root_bt(struct udma_dev *udma_dev,
				  struct udma_hem_list *hem_list, int unit,
				  const struct udma_buf_region *regions,
				  int region_cnt)
{
	struct udma_hem_item *root_hem;
	struct udma_hem_head head;
	int max_ba_num;
	int ret;
	int i;

	/* Existed in hem list */
	root_hem = hem_list_search_item(&hem_list->root_bt, regions[0].offset);
	if (root_hem)
		return 0;

	max_ba_num = 0;
	root_hem = alloc_root_hem(udma_dev, unit, &max_ba_num, regions,
				  region_cnt);
	if (IS_ERR(root_hem))
		return PTR_ERR(root_hem);

	/* List head for storing all allocated HEM items */
	INIT_LIST_HEAD(&head.root);
	INIT_LIST_HEAD(&head.leaf);
	for (i = 0; i < region_cnt; i++)
		INIT_LIST_HEAD(&head.branch[i]);

	hem_list->root_ba = root_hem->dma_addr;
	list_add(&root_hem->list, &head.root);
	ret = setup_root_hem(udma_dev, hem_list, unit, max_ba_num, &head,
			     regions, region_cnt);
	if (ret) {
		for (i = 0; i < region_cnt; i++)
			hem_list_free_all(udma_dev, &head.branch[i], false);

		hem_list_free_all(udma_dev, &head.root, true);
	}

	return ret;
}

static void udma_hem_list_release(struct udma_dev *udma_dev,
				  struct udma_hem_list *hem_list)
{
	int i, j;

	for (i = 0; i < UDMA_MAX_BT_REGION; i++)
		for (j = 0; j < UDMA_MAX_BT_LEVEL; j++)
			hem_list_free_all(udma_dev, &hem_list->mid_bt[i][j],
					  j != 0);

	hem_list_free_all(udma_dev, &hem_list->root_bt, true);
	INIT_LIST_HEAD(&hem_list->btm_bt);
	hem_list->root_ba = 0;
}

/* construct the base address table and link them by address hop config */
static int udma_hem_list_request(struct udma_dev *udma_dev,
				 struct udma_hem_list *hem_list,
				 const struct udma_buf_region *regions,
				 int region_cnt, uint32_t bt_pg_shift)
{
	const struct udma_buf_region *r;
	uint32_t ofs;
	uint32_t end;
	int unit;
	int ret;
	int i;

	if (region_cnt > UDMA_MAX_BT_REGION) {
		dev_err(udma_dev->dev, "invalid region region_cnt %d!\n",
			region_cnt);
		return -EINVAL;
	}

	unit = (1 << bt_pg_shift) / BA_BYTE_LEN;
	for (i = 0; i < region_cnt; i++) {
		r = &regions[i];
		if (!r->count)
			continue;

		end = r->offset + r->count;
		for (ofs = r->offset; ofs < end; ofs += unit) {
			ret = hem_list_alloc_mid_bt(udma_dev, r, unit, ofs,
						    hem_list->mid_bt[i],
						    &hem_list->btm_bt);
			if (ret) {
				dev_err(udma_dev->dev,
					"alloc hem trunk fail ret = %d!\n",
					ret);
				goto err_alloc;
			}
		}
	}

	ret = hem_list_alloc_root_bt(udma_dev, hem_list, unit, regions,
				     region_cnt);
	if (ret)
		dev_err(udma_dev->dev, "alloc hem root fail ret = %d!\n", ret);
	else
		return 0;

err_alloc:
	udma_hem_list_release(udma_dev, hem_list);

	return ret;
}

static void udma_hem_list_init(struct udma_hem_list *hem_list)
{
	int i, j;

	INIT_LIST_HEAD(&hem_list->root_bt);
	INIT_LIST_HEAD(&hem_list->btm_bt);
	for (i = 0; i < UDMA_MAX_BT_REGION; i++)
		for (j = 0; j < UDMA_MAX_BT_LEVEL; j++)
			INIT_LIST_HEAD(&hem_list->mid_bt[i][j]);
}

static void *udma_hem_list_find_mtt(struct udma_dev *udma_dev,
				    struct udma_hem_list *hem_list, int offset,
				    int *mtt_cnt, uint64_t *phy_addr)
{
	struct list_head *head = &hem_list->btm_bt;
	struct udma_hem_item *hem;
	int relative_offset = 0;
	void *cpu_base = NULL;
	uint64_t phy_base = 0;

	if (IS_ERR_OR_NULL(head->next))
		return cpu_base;
	list_for_each_entry(hem, head, sibling) {
		if (hem_list_page_is_in_range(hem, offset)) {
			relative_offset = offset - hem->start;
			cpu_base = (char *)hem->addr + relative_offset *
				   BA_BYTE_LEN;
			phy_base = hem->dma_addr + relative_offset *
				   BA_BYTE_LEN;
			relative_offset = hem->end + 1 - offset;
			break;
		}
	}

	if (mtt_cnt)
		*mtt_cnt = relative_offset;

	if (phy_addr)
		*phy_addr = phy_base;

	return cpu_base;
}

static inline bool mtr_has_mtt(struct udma_buf_attr *attr)
{
	uint32_t i;

	for (i = 0; i < attr->region_count; i++)
		if (attr->region[i].hopnum != UDMA_HOP_NUM_0 &&
		    attr->region[i].hopnum > 0)
			return true;

	/* Mtr only has one root base address, when hopnum 0 means root base
	 * address equals the first buffer address. So all alloced memory must
	 * in a continuous space accessed by direct mode.
	 */
	return false;
}

static inline size_t mtr_bufs_size(struct udma_buf_attr *attr)
{
	size_t size = 0;
	uint32_t i;

	for (i = 0; i < attr->region_count; i++)
		size += attr->region[i].size;

	return size;
}

static bool need_split_huge_page(struct udma_hem_cfg *cfg)
{
	/* When HEM buffer uses 0-level addressing, the page size is
	 * equal to the whole buffer size. If the current MTR has multiple
	 * regions, we split the buffer into small pages(4k, required by
	 * UDMA). These pages will be used in multiple regions.
	 */
	return cfg->is_direct && cfg->region_count > 1;
}

static int mtr_init_buf_cfg(struct udma_dev *udma_dev,
			    struct udma_buf_attr *attr,
			    struct udma_hem_cfg *cfg,
			    uint32_t *buf_page_shift, int unalinged_size)
{
	uint32_t page_count, region_count;
	struct udma_buf_region *r;
	int first_region_pad;
	uint32_t page_shift;
	size_t buf_size;

	/* If mtt is disabled, all pages must be within a continuous range */
	cfg->is_direct = !mtr_has_mtt(attr);
	buf_size = mtr_bufs_size(attr);
	if (need_split_huge_page(cfg)) {
		/* When HEM buffer uses 0-level addressing, the page size is
		 * equal to the whole buffer size, and we split the buffer into
		 * small pages which is used to check whether the adjacent
		 * units are in the continuous space and its size is fixed to
		 * 4K based on hns ROCEE's requirement.
		 */
		page_shift = UDMA_HW_PAGE_SHIFT;

		cfg->buf_pg_count = 1;
		cfg->buf_pg_shift = UDMA_HW_PAGE_SHIFT +
			order_base_2(DIV_ROUND_UP(buf_size, UDMA_PAGE_SIZE));
		first_region_pad = 0;
	} else {
		page_shift = attr->page_shift;
		cfg->buf_pg_count = DIV_ROUND_UP(buf_size + unalinged_size,
						 1 << page_shift);
		cfg->buf_pg_shift = page_shift;
		first_region_pad = unalinged_size;
	}

	/* Convert buffer size to page index and page count for each region.
	 * The buffer's offset needs to be appended to the first region.
	 */
	for (page_count = 0, region_count = 0; region_count < attr->region_count &&
	     region_count < ARRAY_SIZE(cfg->region); region_count++) {
		r = &cfg->region[region_count];
		r->offset = page_count;
		buf_size = UDMA_HW_PAGE_ALIGN(attr->region[region_count].size +
					    first_region_pad);
		r->count = DIV_ROUND_UP(buf_size, 1 << page_shift);
		first_region_pad = 0;
		page_count += r->count;
		r->hopnum = to_udma_hem_hopnum(attr->region[region_count].hopnum,
					       r->count);
	}

	cfg->region_count = region_count;
	*buf_page_shift = page_shift;

	return page_count;
}

static int mtr_alloc_mtt(struct udma_dev *udma_dev, struct udma_mtr *mtr,
			 uint32_t ba_pg_shift)
{
	struct udma_hem_cfg *cfg = &mtr->hem_cfg;
	int ret;

	udma_hem_list_init(&mtr->hem_list);
	if (!cfg->is_direct) {
		ret = udma_hem_list_request(udma_dev, &mtr->hem_list,
					    cfg->region, cfg->region_count,
					    ba_pg_shift);
		if (ret)
			return ret;
		cfg->root_ba = mtr->hem_list.root_ba;
		cfg->ba_pg_shift = ba_pg_shift;
	} else {
		cfg->ba_pg_shift = cfg->buf_pg_shift;
	}

	return 0;
}

struct udma_buf *udma_buf_alloc(struct udma_dev *udma_dev, uint32_t size,
				uint32_t page_shift, uint32_t flags)
{
	uint32_t trunk_size, page_size, alloced_size;
	struct udma_buf_list *trunks;
	struct udma_buf *buf;
	uint32_t ntrunk, i;
	gfp_t gfp_flags;

	/* The minimum shift of the page accessed by hw is UDMA_PAGE_SHIFT */
	if (WARN_ON(page_shift < UDMA_HW_PAGE_SHIFT))
		return ERR_PTR(-EINVAL);

	gfp_flags = (flags & UDMA_BUF_NOSLEEP) ? GFP_ATOMIC : GFP_KERNEL;
	buf = kzalloc(sizeof(*buf), gfp_flags);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	buf->page_shift = page_shift;
	page_size = 1 << buf->page_shift;

	/* Calc the trunk size and num by required size and page_shift */
	if (flags & UDMA_BUF_DIRECT) {
		buf->trunk_shift = order_base_2(ALIGN(size, PAGE_SIZE));
		ntrunk = 1;
	} else {
		buf->trunk_shift = order_base_2(ALIGN(page_size, PAGE_SIZE));
		ntrunk = DIV_ROUND_UP(size, 1 << buf->trunk_shift);
	}

	trunks = kcalloc(ntrunk, sizeof(*trunks), gfp_flags);
	if (!trunks) {
		kfree(buf);
		return ERR_PTR(-ENOMEM);
	}

	trunk_size = 1 << buf->trunk_shift;
	alloced_size = 0;
	for (i = 0; i < ntrunk; i++) {
		trunks[i].buf = dma_alloc_coherent(udma_dev->dev, trunk_size,
						   &trunks[i].map, gfp_flags);
		if (!trunks[i].buf)
			break;

		alloced_size += trunk_size;
	}

	buf->ntrunks = i;

	/* In nofail mode, it's only failed when the alloced size is 0 */
	if ((flags & UDMA_BUF_NOFAIL) ? i == 0 : i != ntrunk) {
		for (i = 0; i < buf->ntrunks; i++)
			dma_free_coherent(udma_dev->dev, trunk_size,
					  trunks[i].buf, trunks[i].map);

		kfree(trunks);
		kfree(buf);
		return ERR_PTR(-ENOMEM);
	}

	buf->npages = DIV_ROUND_UP(alloced_size, page_size);
	buf->trunk_list = trunks;

	return buf;
}

static int mtr_alloc_bufs(struct udma_dev *udma_dev, struct udma_mtr *mtr,
			  struct udma_buf_attr *buf_attr,
			  uint64_t user_addr, bool is_user)
{
	struct ubcore_device *ubcore_dev = &udma_dev->ub_dev;
	union ubcore_umem_flag access;
	size_t total_size;

	total_size = mtr_bufs_size(buf_attr);

	if (is_user) {
		mtr->kmem = NULL;
		access.bs.non_pin = 0;
		access.bs.writable = 1;
		mtr->umem = ubcore_umem_get(ubcore_dev, user_addr, total_size,
					    access);
		if (IS_ERR_OR_NULL(mtr->umem)) {
			dev_err(udma_dev->dev,
				"failed to get umem, ret = %ld.\n",
				PTR_ERR(mtr->umem));
			return -ENOMEM;
		}
	} else {
		mtr->umem = NULL;
		mtr->kmem = udma_buf_alloc(udma_dev, total_size,
					   buf_attr->page_shift,
					   mtr->hem_cfg.is_direct ?
					   UDMA_BUF_DIRECT : 0);
		if (IS_ERR(mtr->kmem)) {
			dev_err(udma_dev->dev,
				"failed to alloc kmem, ret = %ld.\n",
				PTR_ERR(mtr->kmem));
			return PTR_ERR(mtr->kmem);
		}
	}

	return 0;
}

int udma_get_umem_bufs(struct udma_dev *udma_dev, dma_addr_t *bufs,
		       int buf_cnt, struct ubcore_umem *umem,
		       uint32_t page_shift)
{
	struct scatterlist *sg;
	int npage_per_sg;
	dma_addr_t addr;
	int npage = 0;
	int total = 0;
	uint32_t k;
	int i;

	for_each_sg(umem->sg_head.sgl, sg, umem->sg_head.nents, k) {
		npage_per_sg = sg_dma_len(sg) >> page_shift;
		for (i = 0; i < npage_per_sg; i++) {
			addr = sg_dma_address(sg) + (i << page_shift);
			if (addr & ((1 << page_shift) - 1)) {
				dev_err(udma_dev->dev,
					"Umem addr not align to page_shift %d!\n",
					page_shift);
				return -EFAULT;
			}

			bufs[total++] = addr;
			if (total >= buf_cnt)
				goto done;

			npage++;
		}
	}
done:
	return total;
}

static inline int mtr_check_direct_pages(dma_addr_t *pages, int page_cnt,
					 uint32_t page_shift)
{
	size_t page_sz = 1 << page_shift;
	int i;

	for (i = 1; i < page_cnt; i++)
		if (pages[i] - pages[i - 1] != page_sz)
			return i;

	return 0;
}

static int mtr_map_region(struct udma_dev *udma_dev, struct udma_mtr *mtr,
			  struct udma_buf_region *region, dma_addr_t *pages,
			  int max_count)
{
	int offset, end;
	uint64_t *mtts;
	uint64_t addr;
	int npage = 0;
	int count;
	int i;

	offset = region->offset;
	end = offset + region->count;
	while (offset < end && npage < max_count) {
		count = 0;
		mtts = (uint64_t *)udma_hem_list_find_mtt(udma_dev,
							  &mtr->hem_list,
							  offset, &count, NULL);
		if (!mtts)
			return -ENOBUFS;

		for (i = 0; i < count && npage < max_count; i++) {
			addr = pages[npage];
			mtts[i] = cpu_to_le64(addr);
			npage++;
		}
		offset += count;
	}

	return npage;
}

int udma_mtr_map(struct udma_dev *udma_dev, struct udma_mtr *mtr,
		 dma_addr_t *pages, uint32_t page_count)
{
	struct device *dev = udma_dev->dev;
	struct udma_buf_region *r;
	uint32_t i, mapped_count;
	int ret = 0;

	/*
	 * Only first page address was used as root ba when hopnum is 0,
	 * because the addresses of all pages are consecutive in this case.
	 */
	if (mtr->hem_cfg.is_direct) {
		mtr->hem_cfg.root_ba = pages[0];
		return 0;
	}

	for (i = 0, mapped_count = 0; i < mtr->hem_cfg.region_count &&
	     mapped_count < page_count; i++) {
		r = &mtr->hem_cfg.region[i];
		/* no need to map pages in this region when hopnum is 0 */
		if (!r->hopnum) {
			mapped_count += r->count;
			continue;
		}

		if (r->offset + r->count > page_count) {
			ret = -EINVAL;
			dev_err(dev,
				"failed to check mtr%u count %u + %u > %u.\n",
				i, r->offset, r->count, page_count);
			return ret;
		}

		ret = mtr_map_region(udma_dev, mtr, r, &pages[r->offset],
				     page_count - mapped_count);
		if (ret < 0) {
			dev_err(dev,
				"failed to map mtr %u offset 0x%x, ret = %d.\n",
				i, r->offset, ret);
			return ret;
		}
		mapped_count += ret;
	}
	ret = 0;

	if (mapped_count < page_count) {
		ret = -ENOBUFS;
		dev_err(dev, "failed to map mtr pages count: %u < %u.\n",
			mapped_count, page_count);
	}

	return ret;
}

int udma_get_kmem_bufs(struct udma_dev *udma_dev, dma_addr_t *bufs,
		       int buf_cnt, struct udma_buf *buf,
		       uint32_t page_shift)
{
	uint32_t offset, max_size;
	int total = 0;
	int i;

	if (page_shift > buf->trunk_shift) {
		dev_err(udma_dev->dev,
			"failed to check kmem buf shift %u > %u\n",
			page_shift, buf->trunk_shift);
		return -EINVAL;
	}

	offset = 0;
	max_size = buf->ntrunks << buf->trunk_shift;
	for (i = 0; i < buf_cnt && offset < max_size; i++) {
		bufs[total++] = udma_buf_dma_addr(buf, offset);
		offset += (1 << page_shift);
	}

	return total;
}

static int mtr_map_bufs(struct udma_dev *udma_dev, struct udma_mtr *mtr,
			int page_count, uint32_t page_shift)
{
	struct device *dev = udma_dev->dev;
	dma_addr_t *pages;
	int npage;
	int ret;

	page_shift = need_split_huge_page(&mtr->hem_cfg) ?
		     UDMA_HW_PAGE_SHIFT : page_shift;

	/* alloc a tmp array to store buffer's dma address */
	pages = kvcalloc(page_count, sizeof(dma_addr_t), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	if (mtr->umem)
		npage = udma_get_umem_bufs(udma_dev, pages, page_count,
					   mtr->umem, page_shift);
	else
		npage = udma_get_kmem_bufs(udma_dev, pages, page_count,
					   mtr->kmem, page_shift);
	if (npage != page_count) {
		dev_err(dev, "failed to get mtr page %d != %d.\n", npage,
			page_count);
		ret = -ENOBUFS;
		goto err_alloc_list;
	}

	if (need_split_huge_page(&mtr->hem_cfg) && npage > 1) {
		ret = mtr_check_direct_pages(pages, npage, page_shift);
		if (ret) {
			dev_err(dev, "failed to check %s page: %d / %d.\n",
				mtr->umem ? "umtr" : "kmtr", ret, npage);
			ret = -ENOBUFS;
			goto err_alloc_list;
		}
	}

	ret = udma_mtr_map(udma_dev, mtr, pages, page_count);
	if (ret)
		dev_err(dev, "failed to map mtr pages, ret = %d.\n", ret);

err_alloc_list:
	kvfree(pages);

	return ret;
}

void udma_buf_free(struct udma_dev *udma_dev, struct udma_buf *buf)
{
	struct udma_buf_list *trunks;
	uint32_t i;

	if (!buf)
		return;

	trunks = buf->trunk_list;
	if (trunks) {
		buf->trunk_list = NULL;
		for (i = 0; i < buf->ntrunks; i++)
			dma_free_coherent(udma_dev->dev, 1 << buf->trunk_shift,
					  trunks[i].buf, trunks[i].map);

		kfree(trunks);
	}

	kfree(buf);
}

static void mtr_free_bufs(struct udma_dev *udma_dev, struct udma_mtr *mtr)
{
	/* release user buffers */
	ubcore_umem_release(mtr->umem);
	mtr->umem = NULL;

	/* release kernel buffers */
	udma_buf_free(udma_dev, mtr->kmem);
	mtr->kmem = NULL;
}

static void mtr_free_mtt(struct udma_dev *udma_dev, struct udma_mtr *mtr)
{
	udma_hem_list_release(udma_dev, &mtr->hem_list);
}

/*
 * udma_mtr_create - Create memory translate region.
 */
int udma_mtr_create(struct udma_dev *udma_dev, struct udma_mtr *mtr,
		    struct udma_buf_attr *buf_attr, uint32_t ba_page_shift,
		    uint64_t user_addr, bool is_user)
{
	struct device *dev = udma_dev->dev;
	uint32_t buf_page_shift = 0;
	int buf_page_cnt;
	int ret;

	buf_page_cnt = mtr_init_buf_cfg(udma_dev, buf_attr, &mtr->hem_cfg,
					&buf_page_shift,
					is_user ? user_addr & ~PAGE_MASK : 0);
	if (buf_page_cnt < 1 || buf_page_shift < UDMA_HW_PAGE_SHIFT) {
		dev_err(dev, "failed to init mtr cfg, count %d shift %u.\n",
			buf_page_cnt, buf_page_shift);
		return -EINVAL;
	}

	ret = mtr_alloc_mtt(udma_dev, mtr, ba_page_shift);
	if (ret) {
		dev_err(dev, "failed to alloc mtr mtt, ret = %d.\n", ret);
		return ret;
	}

	/* The caller has its own buffer list and invokes the udma_mtr_map()
	 * to finish the MTT configuration.
	 */
	if (buf_attr->mtt_only) {
		mtr->umem = NULL;
		mtr->kmem = NULL;
		return 0;
	}

	ret = mtr_alloc_bufs(udma_dev, mtr, buf_attr, user_addr, is_user);
	if (ret) {
		dev_err(dev, "failed to alloc mtr bufs, ret = %d.\n", ret);
		goto err_alloc_mtt;
	}

	/* Write buffer's dma address to MTT */
	ret = mtr_map_bufs(udma_dev, mtr, buf_page_cnt, buf_page_shift);
	if (ret)
		dev_err(dev, "failed to map mtr bufs, ret = %d.\n", ret);
	else
		return 0;

	mtr_free_bufs(udma_dev, mtr);
err_alloc_mtt:
	mtr_free_mtt(udma_dev, mtr);
	return ret;
}

void udma_mtr_destroy(struct udma_dev *udma_dev, struct udma_mtr *mtr)
{
	/* release multi-hop addressing resource */
	udma_hem_list_release(udma_dev, &mtr->hem_list);

	/* free buffers */
	mtr_free_bufs(udma_dev, mtr);
}

int udma_mtr_find(struct udma_dev *udma_device, struct udma_mtr *mtr,
		  int offset, uint64_t *mtt_buf, int mtt_max,
		  uint64_t *base_addr)
{
	int mtt_count, left, start_idx, total;
	struct udma_hem_cfg *cfg;
	uint32_t npage;
	uint64_t *mtts;
	uint64_t addr;

	cfg = &mtr->hem_cfg;
	total = 0;

	if (!mtt_buf || mtt_max < 1)
		goto out;

	/* no mtt memory in direct mode, so just return the buffer address */
	if (cfg->is_direct) {
		start_idx = offset >> UDMA_HW_PAGE_SHIFT;
		for (mtt_count = 0; (uint32_t)mtt_count < cfg->region_count &&
		     total < mtt_max; mtt_count++) {
			npage = cfg->region[mtt_count].offset;
			if ((int)npage < start_idx)
				continue;
			addr = cfg->root_ba + (npage << UDMA_HW_PAGE_SHIFT);
			mtt_buf[total] = addr;

			total++;
		}
		goto out;
	}

	start_idx = offset >> cfg->buf_pg_shift;
	left = mtt_max;
	while (left > 0) {
		mtt_count = 0;
		mtts = (uint64_t *)udma_hem_list_find_mtt(udma_device,
							  &mtr->hem_list,
							  start_idx + total,
							  &mtt_count, NULL);
		if (!mtts || !mtt_count)
			goto out;

		npage = min(mtt_count, left);
		left -= npage;
		for (mtt_count = 0; (uint32_t)mtt_count < npage; mtt_count++)
			mtt_buf[total++] = le64_to_cpu(mtts[mtt_count]);
	}

out:
	if (base_addr)
		*base_addr = cfg->root_ba;

	return total;
}

void udma_mtr_move(struct udma_mtr *from_mtr, struct udma_mtr *to_mtr)
{
	int i, j;

	*to_mtr = *from_mtr;
	udma_hem_list_init(&to_mtr->hem_list);

	list_splice_init(&from_mtr->hem_list.root_bt,
			 &to_mtr->hem_list.root_bt);
	list_splice_init(&from_mtr->hem_list.btm_bt, &to_mtr->hem_list.btm_bt);

	for (i = 0; i < UDMA_MAX_BT_REGION; i++)
		for (j = 0; j < UDMA_MAX_BT_LEVEL; j++)
			list_splice_init(&from_mtr->hem_list.mid_bt[i][j],
					 &to_mtr->hem_list.mid_bt[i][j]);
}
