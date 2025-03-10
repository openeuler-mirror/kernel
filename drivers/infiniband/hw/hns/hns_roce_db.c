/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
/*
 * Copyright (c) 2017 Hisilicon Limited.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
 */

#include <rdma/ib_umem.h>
#include "hns_roce_device.h"

int hns_roce_db_map_user(struct hns_roce_ucontext *context, unsigned long virt,
			 struct hns_roce_db *db)
{
	unsigned long page_addr = virt & PAGE_MASK;
	struct hns_roce_user_db_page *page;
	struct ib_umem *umem;
	unsigned int offset;
	int ret = 0;

	mutex_lock(&context->page_mutex);

	list_for_each_entry(page, &context->page_list, list)
		if (page->user_virt == page_addr)
			goto found;

	page = kmalloc(sizeof(*page), GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto err_out;
	}

	refcount_set(&page->refcount, 1);
	page->user_virt = page_addr;
	page->db_node = kvzalloc(sizeof(*page->db_node), GFP_KERNEL);
	if (!page->db_node) {
		ret = -ENOMEM;
		goto err_page;
	}

	umem = ib_umem_get(context->ibucontext.device, page_addr, PAGE_SIZE, 0);
	if (IS_ERR(umem)) {
		ret = PTR_ERR(umem);
		goto err_dbnode;
	}

	page->db_node->umem = umem;
	list_add(&page->list, &context->page_list);

found:
	offset = virt - page_addr;
	db->dma = sg_dma_address(page->db_node->umem->sg_head.sgl) + offset;
	db->virt_addr = sg_virt(page->db_node->umem->sg_head.sgl) + offset;
	db->u.user_page = page;
	refcount_inc(&page->refcount);
	mutex_unlock(&context->page_mutex);
	return 0;

err_dbnode:
	kvfree(page->db_node);
err_page:
	kfree(page);
err_out:
	mutex_unlock(&context->page_mutex);

	return ret;
}

void hns_roce_db_unmap_user(struct hns_roce_ucontext *context,
			    struct hns_roce_db *db,
			    bool delayed_unmap_flag)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(context->ibucontext.device);
	struct hns_roce_db_pg_node *db_node = db->u.user_page->db_node;

	mutex_lock(&context->page_mutex);

	db_node->delayed_unmap_flag |= delayed_unmap_flag;

	refcount_dec(&db->u.user_page->refcount);
	if (refcount_dec_if_one(&db->u.user_page->refcount)) {
		list_del(&db->u.user_page->list);
		if (db_node->delayed_unmap_flag) {
			hns_roce_add_unfree_db(db_node, hr_dev);
		} else {
			ib_umem_release(db_node->umem);
			kvfree(db_node);
		}
		kfree(db->u.user_page);
	}

	mutex_unlock(&context->page_mutex);
}

static struct hns_roce_db_pgdir *hns_roce_alloc_db_pgdir(
					struct device *dma_device)
{
	struct hns_roce_db_pgdir *pgdir;
	dma_addr_t db_dma;
	u32 *page;

	pgdir = kzalloc(sizeof(*pgdir), GFP_KERNEL);
	if (!pgdir)
		return NULL;

	bitmap_fill(pgdir->order1,
			HNS_ROCE_DB_PER_PAGE / HNS_ROCE_DB_TYPE_COUNT);
	pgdir->bits[0] = pgdir->order0;
	pgdir->bits[1] = pgdir->order1;
	pgdir->db_node = kvzalloc(sizeof(*pgdir->db_node), GFP_KERNEL);
	if (!pgdir->db_node)
		goto err_node;

	page = dma_alloc_coherent(dma_device, PAGE_SIZE, &db_dma, GFP_KERNEL);
	if (!page)
		goto err_dma;

	pgdir->db_node->kdb.page = page;
	pgdir->db_node->kdb.db_dma = db_dma;

	return pgdir;

err_dma:
	kvfree(pgdir->db_node);
err_node:
	kfree(pgdir);
	return NULL;

}

static int hns_roce_alloc_db_from_pgdir(struct hns_roce_db_pgdir *pgdir,
					struct hns_roce_db *db, int order)
{
	unsigned long o;
	unsigned long i;

	for (o = order; o <= 1; ++o) {
		i = find_first_bit(pgdir->bits[o], HNS_ROCE_DB_PER_PAGE >> o);
		if (i < HNS_ROCE_DB_PER_PAGE >> o)
			goto found;
	}

	return -ENOMEM;

found:
	clear_bit(i, pgdir->bits[o]);

	i <<= o;

	if (o > order)
		set_bit(i ^ 1, pgdir->bits[order]);

	db->u.pgdir	= pgdir;
	db->index	= i;
	db->db_record	= pgdir->db_node->kdb.page + db->index;
	db->dma	= pgdir->db_node->kdb.db_dma + db->index * HNS_ROCE_DB_UNIT_SIZE;
	db->order	= order;

	return 0;
}

int hns_roce_alloc_db(struct hns_roce_dev *hr_dev, struct hns_roce_db *db,
		      int order)
{
	struct hns_roce_db_pgdir *pgdir;
	int ret = 0;

	mutex_lock(&hr_dev->pgdir_mutex);

	list_for_each_entry(pgdir, &hr_dev->pgdir_list, list)
		if (!hns_roce_alloc_db_from_pgdir(pgdir, db, order))
			goto out;

	pgdir = hns_roce_alloc_db_pgdir(hr_dev->dev);
	if (!pgdir) {
		ret = -ENOMEM;
		goto out;
	}

	list_add(&pgdir->list, &hr_dev->pgdir_list);

	/* This should never fail -- we just allocated an empty page: */
	WARN_ON(hns_roce_alloc_db_from_pgdir(pgdir, db, order));

out:
	mutex_unlock(&hr_dev->pgdir_mutex);

	return ret;
}

void hns_roce_free_db(struct hns_roce_dev *hr_dev, struct hns_roce_db *db,
		      bool delayed_unmap_flag)
{
	struct hns_roce_db_pg_node *db_node = db->u.pgdir->db_node;
	unsigned long o;
	unsigned long i;

	mutex_lock(&hr_dev->pgdir_mutex);

	db_node->delayed_unmap_flag |= delayed_unmap_flag;

	o = db->order;
	i = db->index;

	if (db->order == 0 && test_bit(i ^ 1, db->u.pgdir->order0)) {
		clear_bit(i ^ 1, db->u.pgdir->order0);
		++o;
	}

	i >>= o;
	set_bit(i, db->u.pgdir->bits[o]);

	if (bitmap_full(db->u.pgdir->order1,
			HNS_ROCE_DB_PER_PAGE / HNS_ROCE_DB_TYPE_COUNT)) {
		list_del(&db->u.pgdir->list);
		if (db_node->delayed_unmap_flag) {
			hns_roce_add_unfree_db(db_node, hr_dev);
		} else {
			dma_free_coherent(hr_dev->dev, PAGE_SIZE,
					  db_node->kdb.page,
							  db_node->kdb.db_dma);
			kvfree(db_node);
		}
		kfree(db->u.pgdir);
	}

	mutex_unlock(&hr_dev->pgdir_mutex);
}
