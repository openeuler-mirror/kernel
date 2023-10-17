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
