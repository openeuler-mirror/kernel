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

#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "urma/ubcore_api.h"
#include "hns3_udma_device.h"
#include "hns3_udma_db.h"

int udma_db_map_user(struct udma_ucontext *udma_ctx, uint64_t virt,
		     struct udma_db *db)
{
	struct udma_dev *udma_dev = to_udma_dev(udma_ctx->uctx.ub_dev);
	uint64_t page_addr = virt & PAGE_MASK;
	union ubcore_umem_flag access = {};
	struct udma_user_db_page *db_page;
	uint32_t offset;
	int ret = 0;

	mutex_lock(&udma_ctx->pgdir_mutex);

	list_for_each_entry(db_page, &udma_ctx->pgdir_list, list) {
		if (db_page->user_virt == page_addr)
			goto found;
	}

	db_page = kmalloc(sizeof(*db_page), GFP_KERNEL);
	if (!db_page) {
		ret = -ENOMEM;
		goto out;
	}

	refcount_set(&db_page->refcount, 1);
	db_page->user_virt = page_addr;
	access.bs.non_pin = 0;
	access.bs.writable = 1;
	db_page->umem = ubcore_umem_get(&udma_dev->ub_dev, page_addr,
					PAGE_SIZE, access);
	if (IS_ERR(db_page->umem)) {
		ret = PTR_ERR(db_page->umem);
		kfree(db_page);
		goto out;
	}

	list_add(&db_page->list, &udma_ctx->pgdir_list);

found:
	offset = virt - page_addr;
	db->dma = sg_dma_address(db_page->umem->sg_head.sgl) + offset;
	db->virt_addr = (char *)sg_virt(db_page->umem->sg_head.sgl) + offset;
	db->user_page = db_page;
	refcount_inc(&db_page->refcount);

out:
	mutex_unlock(&udma_ctx->pgdir_mutex);

	return ret;
}

void udma_db_unmap_user(struct udma_ucontext *udma_ctx, struct udma_db *db)
{
	mutex_lock(&udma_ctx->pgdir_mutex);

	refcount_dec(&db->user_page->refcount);
	if (refcount_dec_if_one(&db->user_page->refcount)) {
		list_del(&db->user_page->list);
		ubcore_umem_release(db->user_page->umem);
		kfree(db->user_page);
	}

	mutex_unlock(&udma_ctx->pgdir_mutex);
}
