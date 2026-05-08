// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_db.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <rdma/uverbs_ioctl.h>
#define UVERBS_MODULE_NAME sxe2
#include <rdma/uverbs_named_ioctl.h>
#include <rdma/ib_verbs.h>
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_db.h"
#include "sxe2_drv_rdma_debugfs.h"

#define SXE2_DRV_LLWQE_PER_DB	 15
#define SXE2_DRV_LLWQE_SIZE	 256
#define SXE2_DRV_LLWQE_OFFSET	 256
#define SXE2_DRV_LLWQE_DB_SIZE	 16
#define SXE2_DRV_LLWQE_DB_OFFSET 16
#define SXE2_DRV_DB_PAGE_SIZE	 4096
#define SXE2_DRV_DB_PAGE_RSV_NUM 1

#ifndef RDMA_MMAP_DB_NOT_SUPPORT
struct rdma_user_mmap_entry *
sxe2_kinsert_user_mmap_entry(struct sxe2_rdma_kcontext *ctx,
			     enum sxe2_drv_db_mmap_type mmap_flag,
			     u64 *mmap_offset)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ctx->ibucontext.device);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	int ret_code			  = 0;

	struct sxe2_user_mmap_entry *entry =
		kzalloc(sizeof(*entry), GFP_KERNEL);

	if (!entry) {
		DRV_RDMA_LOG_ERROR_BDF("kzalloc entry fail\n");
		return NULL;
	}

	entry->page_idx = SXE2_DRV_DB_PAGE_RSV_NUM;
	if (SXE2_DRV_DB_PAGE_SIZE == PAGE_SIZE)
		entry->address	= (rdma_func->bar_db_addr + PAGE_SIZE);
	else
		entry->address	= rdma_func->bar_db_addr;
	if (mmap_flag == SXE2_DRV_DB_MMAP_TYPE_WC)
		entry->mmap_flag = SXE2_DRV_DB_MMAP_TYPE_WC;
	else
		entry->mmap_flag = SXE2_DRV_DB_MMAP_TYPE_NC;

	ret_code = rdma_user_mmap_entry_insert(
		&ctx->ibucontext, &entry->rdma_entry, PAGE_SIZE);
	if (ret_code) {
		DRV_RDMA_LOG_ERROR_BDF(
			"db mmap entry insert fail, ret_code:%d\n", ret_code);
		kfree(entry);
		return NULL;
	}

	*mmap_offset = rdma_user_mmap_get_offset(&entry->rdma_entry);

	return &entry->rdma_entry;
}
#else
struct sxe2_user_mmap_entry *
rdma_find_user_mmap_entry(struct sxe2_rdma_kcontext *kcontext,
			  struct vm_area_struct *vma)
{
	struct sxe2_user_mmap_entry *entry;
	unsigned long flags;

	if (vma->vm_end - vma->vm_start != PAGE_SIZE)
		return NULL;

	spin_lock_irqsave(&kcontext->mmap_tbl_lock, flags);
	hash_for_each_possible(kcontext->mmap_hash_tbl, entry, hlist,
				vma->vm_pgoff) {
		if (entry->pgoff_key == vma->vm_pgoff) {
			spin_unlock_irqrestore(&kcontext->mmap_tbl_lock, flags);
			return entry;
		}
	}

	spin_unlock_irqrestore(&kcontext->mmap_tbl_lock, flags);

	return NULL;
}

bool find_key_in_mmap_tbl(struct sxe2_rdma_kcontext *ucontext, u64 key)
{
	struct sxe2_user_mmap_entry *entry;
	int ret_code = 0;

	hash_for_each_possible(ucontext->mmap_hash_tbl, entry, hlist, key) {
		if (entry->pgoff_key == key)
			ret_code = true;
		goto end;
	}

	ret_code = false;

end:
	return ret_code;
}

struct sxe2_user_mmap_entry *
rdma_user_mmap_entry_add_hash(struct sxe2_rdma_kcontext *ucontext,
			      enum sxe2_drv_db_mmap_type mmap_flag,
			      u64 *mmap_offset)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ucontext->ibucontext.device);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	struct sxe2_user_mmap_entry *entry =
		kzalloc(sizeof(*entry), GFP_KERNEL);
	unsigned long flags;
	int retry_cnt = 0;

	if (!entry)
		return NULL;

	entry->address	 = (rdma_func->bar_db_addr + PAGE_SIZE);
	entry->mmap_flag = mmap_flag;
	entry->ucontext	 = ucontext;
	do {
		get_random_bytes(&entry->pgoff_key, sizeof(entry->pgoff_key));

		entry->pgoff_key >>= PAGE_SHIFT;

		spin_lock_irqsave(&ucontext->mmap_tbl_lock, flags);
		if (!find_key_in_mmap_tbl(ucontext, entry->pgoff_key)) {
			hash_add(ucontext->mmap_hash_tbl, &entry->hlist,
				 entry->pgoff_key);
			spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);
			goto hash_add_done;
		}
		spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);
	} while (retry_cnt++ < 10);

	DRV_RDMA_LOG_ERROR_BDF(
		"mmap table add failed: Cannot find a unique key\n",
		&ucontext->rdma_dev->ibdev);
	kfree(entry);
	return NULL;

hash_add_done:
	*mmap_offset = entry->pgoff_key << PAGE_SHIFT;

	return entry;
}

void rdma_user_mmap_entry_del_hash(struct sxe2_user_mmap_entry *entry)
{
	struct sxe2_rdma_kcontext *ucontext;
	unsigned long flags;

	if (!entry)
		return;

	ucontext = entry->ucontext;

	spin_lock_irqsave(&ucontext->mmap_tbl_lock, flags);
	hash_del(&entry->hlist);
	spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);

	kfree(entry);
}
#endif
int sxe2_kmmap(struct ib_ucontext *ibcontext, struct vm_area_struct *vma)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ibcontext->device);
	struct sxe2_user_mmap_entry *mentry;
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	struct rdma_user_mmap_entry *entry = NULL;
#else
	struct sxe2_rdma_kcontext *kcontext = ibuctxto_kctx(ibcontext);
#endif
	pgprot_t prot;
	phys_addr_t pfn;
	int ret_code = 0;

#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	entry = rdma_user_mmap_entry_get(ibcontext, vma);
	if (!entry) {
		ret_code = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("pgoff %#lx does not has valid entry\n",
				     vma->vm_pgoff);
		goto end;
	}
	mentry = to_mmap(entry);
#else
	mentry = rdma_find_user_mmap_entry(kcontext, vma);
	if (!mentry) {
		DRV_RDMA_LOG_ERROR_BDF(
			"verbs: pgoff[0x%lx] does not have valid entry\n",
			vma->vm_pgoff);
		ret_code = -EINVAL;
		goto end;
	}
#endif

	pfn = (mentry->address >> PAGE_SHIFT);
	if (mentry->mmap_flag == SXE2_DRV_DB_MMAP_TYPE_NC)
		prot = pgprot_noncached(vma->vm_page_prot);
	else
		prot = pgprot_writecombine(vma->vm_page_prot);
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	ret_code = rdma_user_mmap_io(ibcontext, vma, pfn,
				     entry->npages * PAGE_SIZE, prot,
				     entry);
	if (ret_code)
		DRV_RDMA_LOG_DEV_ERR("mmap error ret %d, npages %ld\n",
				     ret_code, entry->npages);
#else
	ret_code = rdma_user_mmap_io(ibcontext, vma, pfn,
				     (u32)DIV_ROUND_UP(PAGE_SIZE,
						       PAGE_SIZE) *
					     PAGE_SIZE,
				     prot);
	if (ret_code)
		DRV_RDMA_LOG_ERROR_BDF("mmap error ret %d\n", ret_code);

#endif
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	rdma_user_mmap_entry_put(&mentry->rdma_entry);
#endif
end:
	return ret_code;
}
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
void sxe2_kmmap_free(struct rdma_user_mmap_entry *entry)
{
	struct sxe2_user_mmap_entry *mentry = to_mmap(entry);
	struct sxe2_rdma_device *rdma_dev   = to_dev(entry->ucontext->device);

	switch (mentry->mmap_flag) {
	case SXE2_DRV_DB_MMAP_TYPE_WC:
	case SXE2_DRV_DB_MMAP_TYPE_NC:
		kfree(mentry);
		break;
	default:
		DRV_RDMA_LOG_DEV_ERR("mmap free flag invalid %#x\n",
				     mentry->mmap_flag);
	}
}
#endif
static void db_kdec_count_and_free(struct kref *kref)
{
	struct sxe2_db_page *db_page =
		container_of(kref, struct sxe2_db_page, ref_count);
	struct sxe2_rdma_pci_f *rdma_func = db_page->rdma_func;

	list_del(&db_page->list);
	iounmap(db_page->map);
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_dbs, db_page->index);
	bitmap_free(db_page->llwqe_bitmap);
	kfree(db_page);
}

static void db_kput_llwqe_kernel(struct sxe2_rdma_pci_f *rdma_func,
				 struct sxe2_llwqe *llwqe)
{
	struct sxe2_db_llwqe_head *db_head;
	struct sxe2_db_page *db_page;
	struct list_head *head;
	struct mutex *lock;
	u32 dbi;

	db_head = &rdma_func->db_head;
	head	= &db_head->list;
	lock	= &db_head->lock;
	db_page = llwqe->db_page;

	dbi = (u32)((uintptr_t)llwqe->wqe_addr - (uintptr_t)db_page->map -
		    SXE2_DRV_LLWQE_OFFSET) /
	      SXE2_DRV_LLWQE_SIZE;

	mutex_lock(lock);
	db_page->llwqe_avail++;
	clear_bit((int)dbi, db_page->llwqe_bitmap);

	if (db_page->llwqe_avail == 1)
		list_add_tail(&db_page->list, head);

	if (refcount_dec_and_test(&db_page->ref_count.refcount)) {
		db_kdec_count_and_free(&db_page->ref_count);
		rdma_func->db = NULL;
	}

	memset(llwqe, 0, sizeof(*llwqe));
	mutex_unlock(lock);
}

static void db_kfree_db_kernel(struct sxe2_rdma_pci_f *rdma_func)
{
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;

	mutex_lock(&rdma_func->db_head.lock);
	if (refcount_dec_and_test(&rdma_func->db->ref_count.refcount)) {
		db_kdec_count_and_free(&rdma_func->db->ref_count);
		rdma_func->db = NULL;
	} else {
		DRV_RDMA_LOG_DEV_ERR(
			"db ref_count %#x, > 0\n",
			refcount_read(&rdma_func->db->ref_count.refcount));
	}
	mutex_unlock(&rdma_func->db_head.lock);
}

u32 get_db_page_multiplier(void)
{
	return PAGE_SIZE/SXE2_RDMA_DB_PAGE_SIZE;
}

static int db_kalloc_page(struct sxe2_rdma_pci_f *rdma_func,
			  struct sxe2_db_page *db_page, bool map_wc)
{
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	phys_addr_t pfn;
	int ret_code = 0;
	u32 page_index_mod;
	u32 db_page_multiplier = get_db_page_multiplier();

	db_page->rdma_func = rdma_func;
	db_page->llwqe_bitmap =
		bitmap_zalloc(SXE2_DRV_LLWQE_PER_DB, GFP_KERNEL);
	if (unlikely(!db_page->llwqe_bitmap)) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("db page bitmap zalloc fail, ret:%d\n",
				     ret_code);
		goto end;
	}

	db_page->llwqe_num   = SXE2_DRV_LLWQE_PER_DB;
	db_page->llwqe_avail = SXE2_DRV_LLWQE_PER_DB;

	ret_code = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_dbs,
				    rdma_func->max_dbs, &db_page->index,
				    &rdma_func->next_db);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("db page index alloc fail, ret:%d\n",
				     ret_code);
		goto free_bitmap;
	}

	pfn = (rdma_func->bar_db_addr >> PAGE_SHIFT) +
			db_page->index / (db_page_multiplier);

	if (map_wc) {
		db_page->wc  = true;
		db_page->map = ioremap_wc(pfn << PAGE_SHIFT,
					  PAGE_SIZE);
		if (!db_page->map) {
			ret_code = -EAGAIN;
			DRV_RDMA_LOG_DEV_ERR(
				"db page ioremap_wc fail, pfn:%llu ret:%d\n",
				pfn, ret_code);
			goto free_index;
		}
	} else {
		db_page->wc = false;
		db_page->map =
			ioremap(pfn << PAGE_SHIFT, PAGE_SIZE);
		if (!db_page->map) {
			ret_code = -EAGAIN;
			DRV_RDMA_LOG_DEV_ERR(
				"db page ioremap fail, pfn:%llu ret:%d\n", pfn,
				ret_code);
			goto free_index;
		}
	}

	page_index_mod = db_page->index % db_page_multiplier;
	if (page_index_mod != 0)
		db_page->map = (void *)((u64)db_page->map +
			page_index_mod * SXE2_RDMA_DB_PAGE_SIZE);
	kref_init(&db_page->ref_count);

	if (db_page->map) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"alloc db page: map_addr %p, map_addrlx %#lx, index %d, llwqe_num %d\n",
			db_page->map, (uintptr_t)db_page->map, db_page->index,
			db_page->llwqe_num);
		DRV_RDMA_LOG_DEV_DEBUG(
			"alloc db page: [void++] cq_arm %p, cq_info %p, eq %p\n",
			(db_page->map + SXE2_RDMA_DB_CQ_ARM_OFFSET),
			(db_page->map + SXE2_RDMA_DB_CQ_INFO_OFFSET),
			(db_page->map + SXE2_RDMA_DB_EQ_INFO_OFFSET));
		DRV_RDMA_LOG_DEV_DEBUG(
			"alloc db page: [uintptr++] cq_arm %#lx, cq_info %#lx, eq %#lx\n",
			((uintptr_t)db_page->map + 0x8),
			((uintptr_t)db_page->map + 0xC),
			((uintptr_t)db_page->map + 0x4));
		DRV_RDMA_LOG_DEV_DEBUG(
			"alloc db page: [u32*++] cq_arm %p, cq_info %p, eq %p\n",
			(u32 __iomem *)((uintptr_t)db_page->map + 0x8),
			(u32 __iomem *)((uintptr_t)db_page->map + 0xC),
			(u32 __iomem *)((uintptr_t)db_page->map + 0x4));
	} else {
		DRV_RDMA_LOG_DEV_DEBUG(
			"alloc db page: index %d, llwqe_num %d\n",
			db_page->index, db_page->llwqe_num);
	}

	goto end;

free_index:
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_dbs, db_page->index);
free_bitmap:
	bitmap_free(db_page->llwqe_bitmap);
end:
	return ret_code;
}

static int db_kget_llwqe_kernel(struct sxe2_rdma_pci_f *rdma_func,
				struct sxe2_llwqe *llwqe, bool map_wc)
{
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_db_llwqe_head *db_head;
	struct sxe2_db_page *db_page = NULL;
	struct list_head *head;
	struct mutex *lock;
	u64 dbi;
	int ret_code = 0;

	db_head = &rdma_func->db_head;
	head	= &db_head->list;
	lock	= &db_head->lock;

	mutex_lock(lock);
	if (list_empty(head)) {
		db_page = kzalloc_node(sizeof(*db_page), GFP_KERNEL,
				       rdma_dev->numa_node);
		if (unlikely(!db_page)) {
			ret_code = -ENOMEM;
			DRV_RDMA_LOG_DEV_ERR("db page kzalloc fail, ret:%d\n",
					     ret_code);
			goto end;
		}
		ret_code = db_kalloc_page(rdma_func, db_page, map_wc);
		if (ret_code) {
			DRV_RDMA_LOG_DEV_ERR(
				"alloc kernel db page fail, ret:%d\n",
				ret_code);
			goto free_db;
		}
		rdma_func->db = db_page;
		list_add(&db_page->list, head);
	} else {
		db_page = list_entry(head->next, struct sxe2_db_page, list);
		kref_get(&db_page->ref_count);
	}

	dbi = find_first_zero_bit(db_page->llwqe_bitmap, db_page->llwqe_num);
	set_bit((int)dbi, db_page->llwqe_bitmap);
	db_page->llwqe_avail--;
	if (db_page->llwqe_avail == 0)
		list_del(&db_page->list);

	llwqe->wqe_addr = db_page->map + SXE2_DRV_LLWQE_OFFSET +
			  dbi * SXE2_DRV_LLWQE_SIZE;
	llwqe->db_addr = db_page->map + SXE2_DRV_LLWQE_DB_OFFSET +
			 dbi * SXE2_DRV_LLWQE_DB_SIZE;
	llwqe->db_page = db_page;
	llwqe->wc      = db_page->wc;
	llwqe->index   = db_page->index;

	goto end;

free_db:
	kfree(db_page);
end:
	mutex_unlock(lock);
	return ret_code;
}

static int db_kalloc_page_kernel(struct sxe2_rdma_pci_f *rdma_func)
{
	struct sxe2_db_page *db_page	   = NULL;
	struct sxe2_db_llwqe_head *db_head = &rdma_func->db_head;
	struct sxe2_rdma_device *rdma_dev  = rdma_func->rdma_dev;
	int ret_code			   = 0;

	mutex_lock(&db_head->lock);

	if (!list_empty(&db_head->list)) {
		db_page = list_first_entry(&db_head->list, struct sxe2_db_page,
					   list);
		kref_get(&db_page->ref_count);
		rdma_func->db = db_page;
		goto end;
	}

	db_page =
		kzalloc_node(sizeof(*db_page), GFP_KERNEL, rdma_dev->numa_node);
	if (unlikely(!db_page)) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("db page kzalloc fail, ret:%d\n",
				     ret_code);
		goto end;
	}

	ret_code = db_kalloc_page(rdma_func, db_page, false);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("alloc kernel db page fail, ret:%d\n",
				     ret_code);
		goto free_db;
	}
	rdma_func->db = db_page;
	list_add(&db_page->list, &db_head->list);

	goto end;

free_db:
	kfree(db_page);
end:
	mutex_unlock(&db_head->lock);
	return ret_code;
}

int sxe2_kinit_doorbell(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	int ret_code			  = 0;

#ifdef SXE2_CFG_DEBUG
	ret_code = drv_rdma_debug_db_add(rdma_dev);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("init db debugfs fail, ret:%d\n",
				     ret_code);
		goto end;
	}
#endif

	mutex_init(&rdma_func->db_head.lock);
	INIT_LIST_HEAD(&rdma_func->db_head.list);
	mutex_init(&rdma_func->db_mmap_entry_head.lock);
	INIT_LIST_HEAD(&rdma_func->db_mmap_entry_head.list);

	ret_code = db_kalloc_page_kernel(rdma_func);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("alloc db page fail, ret:%d\n", ret_code);
		goto err_db_page;
	}

	ret_code = db_kget_llwqe_kernel(rdma_func, &rdma_func->llwqe, false);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("get LL_WQE fail, ret:%d\n", ret_code);
		goto err_llwqe;
	}
	spin_lock_init(&rdma_func->llwqe.lock);

	goto end;

err_llwqe:
	db_kfree_db_kernel(rdma_func);
err_db_page:
	mutex_destroy(&rdma_func->db_mmap_entry_head.lock);
	mutex_destroy(&rdma_func->db_head.lock);
end:
	return ret_code;
}

void sxe2_kfree_doorbell(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	db_kput_llwqe_kernel(rdma_func, &rdma_func->llwqe);
	db_kfree_db_kernel(rdma_func);
}
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
static struct sxe2_user_mmap_entry *
db_kalloc_entry(struct sxe2_rdma_kcontext *ctx,
		enum sxe2_drv_db_page_type alloc_type, u32 db_page_id_align)
{
	struct sxe2_user_mmap_entry *entry;
	struct sxe2_rdma_device *rdma_dev = to_dev(ctx->ibucontext.device);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	int ret_code;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		entry = ERR_PTR(-ENOMEM);
		DRV_RDMA_LOG_DEV_ERR("kzalloc entry fail\n");
		goto end;
	}

	entry->page_idx = db_page_id_align;
	entry->address =
		(rdma_func->bar_db_addr + db_page_id_align * SXE2_DRV_DB_PAGE_SIZE);
	if (alloc_type == SXE2_DRV_DB_PAGE_TYPE_LLWQE)
		entry->mmap_flag = SXE2_DRV_DB_MMAP_TYPE_WC;
	else
		entry->mmap_flag = SXE2_DRV_DB_MMAP_TYPE_NC;

	ret_code = rdma_user_mmap_entry_insert(
		&ctx->ibucontext, &entry->rdma_entry, PAGE_SIZE);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("db mmap entry insert fail, ret_code:%d\n",
				     ret_code);
		goto free_entry;
	}
	goto end;
free_entry:
	kfree(entry);
	entry = ERR_PTR(ret_code);
end:
	return entry;
}
#endif
#ifdef UVERBS_UOBJ_CREATE_NOT_SUPPORT
void uverbs_finalize_uobj_create(const struct uverbs_attr_bundle *bundle,
				 u16 idx)
{
	struct bundle_priv *pbundle =
		container_of(bundle, struct bundle_priv, bundle);

	__set_bit(uapi_bkey_attr(uapi_key_attr(idx)),
		  pbundle->uobj_hw_obj_valid);
}
EXPORT_SYMBOL(uverbs_finalize_uobj_create);
#endif

bool uctx_db_page_has_alloced(struct sxe2_rdma_device *rdma_dev,
	struct ib_ucontext *uctx, u32 page_idx)
{
	bool ret = false;
	struct sxe2_db_ucontext *db_ucontext_entry;
	struct sxe2_db_ucontext *uconetxt_next;
	struct sxe2_db_mmap_entry *db_mmap_entry;
	struct sxe2_db_mmap_entry *entry_next;

	mutex_lock(&rdma_dev->rdma_func->db_mmap_entry_head.lock);
	list_for_each_entry_safe(db_ucontext_entry, uconetxt_next,
		&rdma_dev->rdma_func->db_mmap_entry_head.list, list) {
		if (db_ucontext_entry->ibucontext == uctx) {
			list_for_each_entry_safe(db_mmap_entry,
				entry_next, &db_ucontext_entry->entry_list, list) {
				if (db_mmap_entry->page_idx == page_idx) {
					ret = true;
					mutex_unlock(&rdma_dev->rdma_func->db_mmap_entry_head.lock);
					goto end;
				}
			}
		}
	}
	mutex_unlock(&rdma_dev->rdma_func->db_mmap_entry_head.lock);

end:
	return ret;
}

int db_kalloc_llwqe_mmap_entry(struct sxe2_rdma_device *rdma_dev,
	struct ib_udata *udata,
	struct sxe2_rdma_qp *qp,
	u32 *page_id,
	u32 *length,
	u64 *mmap_offset)
{
	struct sxe2_user_mmap_entry *entry;
	int ret_code = 0;
	struct sxe2_rdma_pci_f *rdma_func;
	u32 db_index;
	u32 db_page_id_align;
	u32 db_paga_id_mod;
	struct sxe2_rdma_kcontext *ucontext;
	struct sxe2_db_ucontext *db_ucontext_entry;
	struct sxe2_db_ucontext *next;
	struct sxe2_db_mmap_entry *db_mmap_entry = NULL;
	struct sxe2_db_page_idx *db_page_idx_entry = NULL;
	u32 db_page_multiplier = get_db_page_multiplier();
#ifdef HAVE_NO_RDMA_UDATA_TO_DRV_CONTEXT
	ucontext = to_rdma_kcontext(qp->pd->ibpd.uobject->context);
#else
	ucontext = rdma_udata_to_drv_context(
		udata, struct sxe2_rdma_kcontext, ibucontext);
#endif
	rdma_func = rdma_dev->rdma_func;

	ret_code = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_dbs,
				    rdma_func->max_dbs, &db_index,
				    &rdma_func->next_db);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("db page index alloc fail, ret_code:%d\n",
				     ret_code);
		goto end;
	}
	*page_id = db_index;
	db_paga_id_mod = db_index % db_page_multiplier;
	db_page_id_align = db_index - db_paga_id_mod;
	db_page_idx_entry = kzalloc(sizeof(*db_page_idx_entry), GFP_KERNEL);
	if (!db_page_idx_entry) {
		DRV_RDMA_LOG_DEV_ERR("kzalloc db_page_idx_entry fail\n");
		goto free_rsrc;
	}
	db_page_idx_entry->db_page_idx = db_index;
	mutex_lock(&rdma_func->db_mmap_entry_head.lock);
	list_for_each_entry_safe(db_ucontext_entry, next,
		&rdma_func->db_mmap_entry_head.list, list) {
		if (db_ucontext_entry->ibucontext == &ucontext->ibucontext)
			list_add_tail(&db_page_idx_entry->list, &db_ucontext_entry->db_pageid_list);
	}
	mutex_unlock(&rdma_func->db_mmap_entry_head.lock);
	if ((db_paga_id_mod != 0) &&
			uctx_db_page_has_alloced(rdma_dev,
				&ucontext->ibucontext, db_page_id_align)) {
		DRV_RDMA_LOG_DEV_DEBUG("uctx(%p) has alloced page_id(%u).\n",
			&ucontext->ibucontext, *page_id);
		*length = 0;
		*mmap_offset = 0;
		goto end;
	}
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	entry = db_kalloc_entry(ucontext, SXE2_DRV_DB_PAGE_TYPE_LLWQE, db_page_id_align);
	if (IS_ERR(entry)) {
		ret_code = (int)PTR_ERR(entry);
		DRV_RDMA_LOG_DEV_ERR("alloc db entry fail, ret_code %d\n",
				     ret_code);
		goto free_idx_entry;
	}

	*mmap_offset  = rdma_user_mmap_get_offset(&entry->rdma_entry);
	*length	     = entry->rdma_entry.npages * PAGE_SIZE;
#else
	spin_lock_init(&ucontext->mmap_tbl_lock);
	entry	 = rdma_user_mmap_entry_add_hash(ucontext, SXE2_DRV_DB_MMAP_TYPE_NC,
						 mmap_offset);
	if (!entry) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("alloc db entry fail, ret_code %d\n",
				     ret_code);
		goto free_idx_entry;
	}
	entry->mmap_flag = SXE2_DRV_DB_MMAP_TYPE_WC;
	entry->page_idx = db_page_id_align;
	entry->address =
		(rdma_func->bar_db_addr + db_page_id_align * SXE2_DRV_DB_PAGE_SIZE);
	*length = (u32)DIV_ROUND_UP(PAGE_SIZE, PAGE_SIZE) *
		 PAGE_SIZE;
#endif
	db_mmap_entry = kzalloc(sizeof(*db_mmap_entry), GFP_KERNEL);
	if (!db_mmap_entry) {
		DRV_RDMA_LOG_DEV_ERR("kzalloc db_mmap_entry fail\n");
		goto free_entry;
	}
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	db_mmap_entry->mmap_entry = &entry->rdma_entry;
#else
	db_mmap_entry->mmap_entry = entry;
#endif
	db_mmap_entry->page_idx = db_page_id_align;
	mutex_lock(&rdma_func->db_mmap_entry_head.lock);
	list_for_each_entry_safe(db_ucontext_entry, next,
		&rdma_func->db_mmap_entry_head.list, list) {
		if (db_ucontext_entry->ibucontext == &ucontext->ibucontext)
			list_add_tail(&db_mmap_entry->list, &db_ucontext_entry->entry_list);
	}
	mutex_unlock(&rdma_func->db_mmap_entry_head.lock);
	goto end;

free_entry:
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	rdma_user_mmap_entry_remove(&entry->rdma_entry);
#else
	rdma_user_mmap_entry_del_hash(entry);
#endif
free_idx_entry:
	list_del(&db_page_idx_entry->list);
	kfree(db_page_idx_entry);
	db_page_idx_entry = NULL;
free_rsrc:
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_dbs, db_index);
end:
	return ret_code;
}

