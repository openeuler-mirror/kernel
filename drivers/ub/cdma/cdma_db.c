// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/bitmap.h>
#include "cdma_common.h"
#include "cdma_context.h"
#include "cdma_db.h"

static int cdma_alloc_db_from_page(struct cdma_k_sw_db_page *page,
				   struct cdma_sw_db *db)
{
	u32 index;

	index = find_first_bit(page->bitmap, page->num_db);
	if (index == page->num_db)
		return -ENOMEM;

	clear_bit(index, page->bitmap);

	db->index = index;
	db->kpage = page;
	db->db_addr = page->db_buf.addr + db->index * CDMA_DB_SIZE;
	db->db_record = (u32 *)(page->db_buf.kva + db->index * CDMA_DB_SIZE);

	return 0;
}

static struct cdma_k_sw_db_page *cdma_alloc_db_page(struct cdma_dev *dev)
{
	struct cdma_k_sw_db_page *page;
	int ret;

	page = kzalloc(sizeof(*page), GFP_KERNEL);
	if (!page)
		return NULL;

	page->num_db = PAGE_SIZE / CDMA_DB_SIZE;

	page->bitmap = bitmap_alloc(page->num_db, GFP_KERNEL);
	if (!page->bitmap) {
		dev_err(dev->dev, "alloc db bitmap failed\n");
		goto err_bitmap;
	}

	bitmap_fill(page->bitmap, page->num_db);

	ret = cdma_k_alloc_buf(dev, PAGE_SIZE, &page->db_buf);
	if (ret)
		goto err_kva;

	return page;
err_kva:
	bitmap_free(page->bitmap);
err_bitmap:
	kfree(page);

	return NULL;
}

static void cdma_free_db_page(struct cdma_dev *cdev, struct cdma_sw_db *db)
{
	cdma_k_free_buf(cdev, PAGE_SIZE, &db->kpage->db_buf);
	bitmap_free(db->kpage->bitmap);
	kfree(db->kpage);
	db->kpage = NULL;
}

int cdma_pin_sw_db(struct cdma_context *ctx, struct cdma_sw_db *db)
{
	u64 page_addr = db->db_addr & PAGE_MASK;
	struct cdma_sw_db_page *page;
	int ret = 0;

	mutex_lock(&ctx->pgdir_mutex);

	list_for_each_entry(page, &ctx->pgdir_list, list) {
		if (page->user_virt == page_addr)
			goto found;
	}

	page = kzalloc(sizeof(*page), GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	refcount_set(&page->refcount, 1);
	page->user_virt = page_addr;
	page->umem = cdma_umem_get(ctx->cdev, page_addr, PAGE_SIZE, false, ctx);
	if (IS_ERR(page->umem)) {
		ret = PTR_ERR(page->umem);
		dev_err(ctx->cdev->dev, "get umem failed, ret = %d\n", ret);
		kfree(page);
		goto out;
	}

	list_add(&page->list, &ctx->pgdir_list);
	db->page = page;
	mutex_unlock(&ctx->pgdir_mutex);
	return 0;

found:
	db->page = page;
	refcount_inc(&page->refcount);
out:
	mutex_unlock(&ctx->pgdir_mutex);

	return ret;
}

void cdma_unpin_sw_db(struct cdma_context *ctx, struct cdma_sw_db *db)
{
	mutex_lock(&ctx->pgdir_mutex);

	if (refcount_dec_and_test(&db->page->refcount)) {
		list_del(&db->page->list);
		cdma_put_umem(db->page->umem, false);
		kfree(db->page);
		db->page = NULL;
	}

	mutex_unlock(&ctx->pgdir_mutex);
}

int cdma_alloc_sw_db(struct cdma_dev *cdev, struct cdma_sw_db *db)
{
	struct cdma_k_sw_db_page *page;
	int ret = 0;

	mutex_lock(&cdev->db_mutex);

	list_for_each_entry(page, &cdev->db_page, list)
		if (!cdma_alloc_db_from_page(page, db))
			goto out;

	page = cdma_alloc_db_page(cdev);
	if (!page) {
		ret = -ENOMEM;
		dev_err(cdev->dev, "alloc sw db page failed\n");
		goto out;
	}

	list_add(&page->list, &cdev->db_page);

	ret = cdma_alloc_db_from_page(page, db);
	if (ret)
		dev_err(cdev->dev, "alloc sw db from page failed, ret = %d\n", ret);
out:
	mutex_unlock(&cdev->db_mutex);

	return ret;
}

void cdma_free_sw_db(struct cdma_dev *cdev, struct cdma_sw_db *db)
{
	mutex_lock(&cdev->db_mutex);

	set_bit(db->index, db->kpage->bitmap);

	if (bitmap_full(db->kpage->bitmap, db->kpage->num_db)) {
		list_del(&db->kpage->list);
		cdma_free_db_page(cdev, db);
	}

	mutex_unlock(&cdev->db_mutex);
}
