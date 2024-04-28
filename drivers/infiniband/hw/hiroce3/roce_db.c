// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/kernel.h>

#include "roce.h"

/*
 ****************************************************************************
 Prototype	: roce3_db_map_user
 Description  : roce3_db_map_user
 Input		: struct roce3_ucontext *context
				unsigned long virt
				struct roce3_db *db
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

****************************************************************************
*/
int roce3_db_map_user(struct roce3_ucontext *context, unsigned long virt, struct roce3_db *db)
{
	int ret = 0;
	struct roce3_db_page *db_page = NULL;

	mutex_lock(&context->db_page_mutex);

	list_for_each_entry(db_page, &context->db_page_list, list) {
		if (db_page->user_virt == (virt & PAGE_MASK))
			goto found;
	}

	db_page = kmalloc(sizeof(*db_page), GFP_KERNEL);
	if (db_page == NULL) {
		ret = -ENOMEM;
		pr_err("[ROCE, ERR] %s: Failed to alloc DB page\n", __func__);
		goto out;
	}

	db_page->user_virt = (virt & PAGE_MASK);
	db_page->refcnt = 0;
	db_page->umem = ib_umem_get(context->ibucontext.device, virt & PAGE_MASK, PAGE_SIZE, 0);
	if (IS_ERR(db_page->umem)) {
		ret = (int)PTR_ERR(db_page->umem);
		pr_err("[ROCE, ERR] %s: Failed to get ib_umem ret:%d\n", __func__, ret);
		kfree(db_page);
		goto out;
	}

	list_add(&db_page->list, &context->db_page_list);

found:
	db->dma = sg_dma_address(db_page->umem->sgt_append.sgt.sgl) + (virt & ~PAGE_MASK);
	db->user_page = db_page;
	++db_page->refcnt;

out:
	mutex_unlock(&context->db_page_mutex);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_db_unmap_user
 Description  : roce3_db_unmap_user
 Input		: struct roce3_ucontext *context
				struct roce3_db *db
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

****************************************************************************
*/
void roce3_db_unmap_user(struct roce3_ucontext *context, struct roce3_db *db)
{
	mutex_lock(&context->db_page_mutex);

	if ((--db->user_page->refcnt) == 0) {
		list_del(&db->user_page->list);
		ib_umem_release(db->user_page->umem);
		kfree(db->user_page);
	}

	mutex_unlock(&context->db_page_mutex);
}
