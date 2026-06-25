// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include "udma_common.h"
#include "udma_db.h"

int udma_pin_sw_db(struct udma_context *ctx, struct udma_sw_db *db)
{
	uint64_t page_addr = db->db_addr & PAGE_MASK;
	struct udma_sw_db_page *page;
	struct udma_umem_param param;
	uint32_t offset = 0;
	int ret = 0;

	param.ub_dev = &ctx->dev->ub_dev;
	param.va = page_addr;
	param.len = PAGE_SIZE;
	param.flag.bs.writable = 1;
	param.flag.bs.non_pin = 0;
	param.is_kernel = false;
	offset = db->db_addr - page_addr;

	mutex_lock(&ctx->pgdir_mutex);

	list_for_each_entry(page, &ctx->pgdir_list, list) {
		if (page->user_virt == page_addr)
			goto found;
	}

	page = kmalloc(sizeof(*page), GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	refcount_set(&page->refcount, 1);
	page->user_virt = page_addr;
	page->umem = udma_umem_get(&param);
	if (IS_ERR(page->umem)) {
		ret = PTR_ERR(page->umem);
		dev_err(ctx->dev->dev, "failed to get user memory, ret: %d.\n", ret);
		kfree(page);
		goto out;
	}

	list_add(&page->list, &ctx->pgdir_list);
	db->page = page;
	db->virt_addr = (char *)sg_virt(page->umem->append.sgt.sgl) + offset;
	mutex_unlock(&ctx->pgdir_mutex);

	return 0;
found:
	db->page = page;
	db->virt_addr = (char *)sg_virt(page->umem->append.sgt.sgl) + offset;
	refcount_inc(&page->refcount);
out:
	mutex_unlock(&ctx->pgdir_mutex);

	return ret;
}

void udma_unpin_sw_db(struct udma_context *ctx, struct udma_sw_db *db, bool dirty)
{
	mutex_lock(&ctx->pgdir_mutex);

	if (refcount_dec_and_test(&db->page->refcount)) {
		list_del(&db->page->list);
		udma_umem_release(db->page->umem, false, dirty);
		kfree(db->page);
		db->page = NULL;
	}

	mutex_unlock(&ctx->pgdir_mutex);
}

struct udma_page_priv *udma_get_sw_db(struct udma_context *ctx, uint64_t db_addr)
{
	uint64_t page_addr = db_addr & PAGE_MASK;
	struct udma_page_priv *priv = NULL;
	struct udma_page_priv *tmp;

	mutex_lock(&ctx->page_lock);
	list_for_each_entry_safe(priv, tmp, &ctx->page_list, list) {
		if (page_addr == (uintptr_t)priv->va_base)
			goto found;
	}

	priv = udma_get_map_page_priv(ctx, page_addr, PAGE_SIZE);
	if (!priv) {
		dev_err(ctx->dev->dev, "failed to get page private.\n");
		mutex_unlock(&ctx->page_lock);
		return NULL;
	}

	refcount_set(&priv->refcnt, 1);
	list_add(&priv->list, &ctx->page_list);
	mutex_unlock(&ctx->page_lock);

	return priv;

found:
	refcount_inc(&priv->refcnt);
	mutex_unlock(&ctx->page_lock);

	return priv;
}

void udma_put_sw_db(struct udma_context *ctx, uint64_t db_addr)
{
	uint64_t page_addr = db_addr & PAGE_MASK;
	struct udma_page_priv *priv = NULL;
	struct udma_page_priv *tmp;

	mutex_lock(&ctx->page_lock);
	list_for_each_entry_safe(priv, tmp, &ctx->page_list, list) {
		if (page_addr == (uintptr_t)priv->va_base)
			goto found;
	}
	mutex_unlock(&ctx->page_lock);

	return;

found:
	if (refcount_dec_and_test(&priv->refcnt)) {
		list_del(&priv->list);
		udma_put_map_page_priv(ctx, priv);
	}

	mutex_unlock(&ctx->page_lock);
}

static int udma_alloc_db_from_page(struct udma_k_sw_db_page *page,
				   struct udma_sw_db *db, enum udma_db_type type)
{
	uint32_t index;

	index = find_first_bit(page->bitmap, page->num_db);
	if (index >= page->num_db)
		return -ENOMEM;

	clear_bit(index, page->bitmap);

	db->index = index;
	db->kpage = page;
	db->type = type;
	db->db_addr = page->db_buf.addr + db->index * UDMA_DB_SIZE;
	db->db_record = page->db_buf.kva + db->index * UDMA_DB_SIZE;
	*db->db_record = 0;

	return 0;
}

static struct udma_k_sw_db_page *udma_alloc_db_page(struct udma_dev *dev,
						    enum udma_db_type type)
{
	struct udma_k_sw_db_page *page;
	int ret;

	page = kzalloc(sizeof(*page), GFP_KERNEL);
	if (!page)
		return NULL;

	page->num_db = PAGE_SIZE / UDMA_DB_SIZE;

	page->bitmap = bitmap_alloc(page->num_db, GFP_KERNEL);
	if (!page->bitmap) {
		dev_err(dev->dev, "failed to alloc doorbell bitmap, DB type is %u.\n", type);
		goto err_bitmap;
	}

	bitmap_fill(page->bitmap, page->num_db);

	ret = udma_alloc_normal_buf(dev, PAGE_SIZE, &page->db_buf);
	if (ret) {
		dev_err(dev->dev, "failed to alloc doorbell page buffer, ret is %d.\n", ret);
		goto err_kva;
	}

	return page;
err_kva:
	bitmap_free(page->bitmap);
err_bitmap:
	kfree(page);

	return NULL;
}

int udma_alloc_sw_db(struct udma_dev *dev, struct udma_sw_db *db,
		     enum udma_db_type type)
{
	struct udma_k_sw_db_page *page;
	int ret = 0;

	mutex_lock(&dev->db_mutex);

	list_for_each_entry(page, &dev->db_list[type], list)
		if (!udma_alloc_db_from_page(page, db, type))
			goto out;

	page = udma_alloc_db_page(dev, type);
	if (!page) {
		ret = -ENOMEM;
		dev_err(dev->dev, "failed to alloc SW DB page db_type = %u\n", type);
		goto out;
	}

	list_add(&page->list, &dev->db_list[type]);

	/* This should never fail */
	(void)udma_alloc_db_from_page(page, db, type);
out:
	mutex_unlock(&dev->db_mutex);

	return ret;
}

void udma_free_sw_db(struct udma_dev *dev, struct udma_sw_db *db)
{
	mutex_lock(&dev->db_mutex);

	set_bit(db->index, db->kpage->bitmap);

	if (bitmap_full(db->kpage->bitmap, db->kpage->num_db)) {
		udma_free_normal_buf(dev, PAGE_SIZE, &db->kpage->db_buf);
		bitmap_free(db->kpage->bitmap);
		list_del(&db->kpage->list);
		kfree(db->kpage);
		db->kpage = NULL;
	}

	mutex_unlock(&dev->db_mutex);
}
