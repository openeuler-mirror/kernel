// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/iommu.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/highmem.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <uapi/ub/urma/udma/udma_abi.h>
#include "udma_dev.h"
#include "udma_cmd.h"
#include "udma_common.h"

static int udma_verify_input(struct udma_umem_param *param)
{
	struct udma_dev *udma_dev = to_udma_dev(param->ub_dev);

	if (((param->va + param->len) < param->va) ||
		PAGE_ALIGN(param->va + param->len) < (param->va + param->len)) {
		dev_err(udma_dev->dev, "invalid pin_page param, len=%llu.\n",
			param->len);
		return -EINVAL;
	}
	return 0;
}

static void udma_fill_umem(struct udma_umem *umem, struct udma_umem_param *param)
{
	umem->ub_dev = param->ub_dev;
	umem->va = param->va;
	umem->length = param->len;
	umem->flag = param->flag;
	umem->is_writable = !!param->flag.bs.writable;
}

static int udma_pin_pages(uint64_t cur_base, uint64_t npages,
			  uint32_t gup_flags, struct page **page_list)
{
	return pin_user_pages_fast(cur_base, min_t(unsigned long, (unsigned long)npages,
				   PAGE_SIZE / sizeof(struct page *)),
				   gup_flags | FOLL_LONGTERM |
				   FOLL_HONOR_NUMA_FAULT, page_list);
}

static inline void udma_unpin_pages_by_sgtable(struct udma_umem *umem, bool dirty)
{
	bool make_dirty = umem->is_writable && dirty;
	struct scatterlist *sg;
	uint32_t i;

	for_each_sgtable_sg(&umem->append.sgt, sg, i)
		unpin_user_page_range_dirty_lock(sg_page(sg),
			DIV_ROUND_UP(sg->length, PAGE_SIZE), make_dirty);

	sg_free_append_table(&umem->append);
}

static inline void udma_k_unpin_by_sgtable(struct udma_umem *umem, uint64_t nents)
{
	struct scatterlist *sg;
	struct page *page;
	uint32_t i;

	for_each_sg(umem->append.sgt.sgl, sg, nents, i) {
		page = sg_page(sg);
		put_page(page);
	}

	sg_free_table(&umem->append.sgt);
}

static void udma_unpin_pages(struct udma_umem *umem, uint64_t nents, bool is_kernel, bool dirty)
{
	if (is_kernel)
		udma_k_unpin_by_sgtable(umem, nents);
	else
		udma_unpin_pages_by_sgtable(umem, dirty);
}

static uint64_t udma_pin_all_pages(struct udma_dev *udma_dev, struct udma_umem *umem,
				   uint64_t npages, uint32_t gup_flags,
				   struct page **page_list)
{
	uint64_t cur_base = umem->va & PAGE_MASK;
	uint64_t page_count = npages;
	uint64_t pinned_count;
	int pinned;
	int ret;

	while (page_count != 0) {
		cond_resched();
		pinned = udma_pin_pages(cur_base, page_count, gup_flags, page_list);
		if (pinned <= 0) {
			dev_err(udma_dev->dev,
				"failed to pin_user_pages_fast, page_count: %llu, pinned: %d.\n",
				page_count, pinned);
			break;
		}
		cur_base += (uint64_t)pinned * PAGE_SIZE;
		page_count -= (uint64_t)pinned;
		ret = sg_alloc_append_table_from_pages(&umem->append, page_list, pinned, 0,
						       pinned * PAGE_SIZE, UINT_MAX, page_count,
						       GFP_KERNEL);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to sg alloc append table failed, page_count: %llu.\n",
				page_count);
			unpin_user_pages_dirty_lock(page_list, pinned, 0);
			udma_unpin_pages_by_sgtable(umem, false);
			return 0;
		}
	}
	pinned_count = npages - page_count;

	return pinned_count;
}

static uint64_t udma_k_pin_pages(struct udma_dev *dev, struct udma_umem *umem,
				 uint64_t npages)
{
	uint64_t cur_base = umem->va & PAGE_MASK;
	struct scatterlist *sg_cur;
	struct page *pg;
	uint64_t pinned;
	int ret;

	ret = sg_alloc_table(&umem->append.sgt, (unsigned int)npages, GFP_KERNEL);
	if (ret) {
		dev_err(dev->dev, "failed to sg alloc table failed.\n");
		return 0;
	}
	sg_cur = umem->append.sgt.sgl;

	for (pinned = 0; pinned < npages; pinned++) {
		if (is_vmalloc_addr((void *)(uintptr_t)cur_base))
			pg = vmalloc_to_page((void *)(uintptr_t)cur_base);
		else
			pg = kmap_to_page((void *)(uintptr_t)cur_base);
		if (!pg) {
			dev_err(dev->dev, "vmalloc or kmap to page failed.\n");
			break;
		}
		get_page(pg);

		cur_base += PAGE_SIZE;

		sg_set_page(sg_cur, pg, PAGE_SIZE, 0);
		sg_cur = sg_next(sg_cur);
	}

	return pinned;
}

static struct udma_umem *udma_get_target_umem(struct udma_umem_param *param)
{
	struct udma_dev *udma_dev = to_udma_dev(param->ub_dev);
	struct page **page_list;
	struct udma_umem *umem;
	uint32_t gup_flags;
	uint64_t npages;
	uint64_t pinned;
	int ret = 0;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (umem == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	udma_fill_umem(umem, param);

	npages = udma_cal_npages(umem->va, umem->length);
	if (npages == 0 || npages > UINT_MAX) {
		dev_err(udma_dev->dev,
			"Invalid npages %llu in getting target umem process.\n", npages);
		ret = -EINVAL;
		goto umem_kfree;
	}

	if (param->is_kernel) {
		pinned = udma_k_pin_pages(udma_dev, umem, npages);
	} else {
		gup_flags = (param->flag.bs.writable == 1) ? FOLL_WRITE : 0;
		page_list = (struct page **)__get_free_page(GFP_KERNEL);
		if (page_list == 0) {
			ret = -ENOMEM;
			goto umem_kfree;
		}

		pinned = udma_pin_all_pages(udma_dev, umem, npages, gup_flags, page_list);
		free_page((uintptr_t)page_list);
	}

	if (pinned != npages) {
		ret = -ENOMEM;
		goto umem_release;
	}

	goto out;

umem_release:
	if (pinned)
		udma_unpin_pages(umem, pinned, param->is_kernel, false);
umem_kfree:
	kfree(umem);
out:
	return ret != 0 ? ERR_PTR(ret) : umem;
}

struct udma_umem *udma_umem_get(struct udma_umem_param *param)
{
	struct udma_umem *umem;
	int ret;

	ret = udma_verify_input(param);
	if (ret < 0)
		return ERR_PTR(ret);

	umem = udma_get_target_umem(param);

	return umem;
}

void udma_umem_release(struct udma_umem *umem, bool is_kernel, bool dirty)
{
	if (IS_ERR_OR_NULL(umem))
		return;

	udma_unpin_pages(umem, umem->append.sgt.nents, is_kernel, dirty);
	kfree(umem);
}

int udma_ioummu_map(struct udma_context *ctx, int r_tid, int prot, uint64_t addr,
		    struct sg_table *sgt)
{
	struct ummu_matt_domain domain = {};
	int ret;

	domain.l_tid = ctx->tid;
	domain.r_tid = r_tid;
	domain.mm = current->mm;

	ret = ummu_sva_matt_map(&domain, addr, sgt, prot);
	if (ret)
		dev_err(ctx->dev->dev, "failed to ummu sva matt map, ret:%d.\n", ret);

	return ret;
}

void udma_ioummu_unmap(struct udma_context *ctx, int r_tid, uint64_t addr, size_t size)
{
	struct ummu_matt_domain domain = {};

	domain.l_tid = ctx->tid;
	domain.r_tid = r_tid;
	domain.mm = current->mm;

	ummu_sva_matt_unmap(&domain, addr, size);
}

int udma_id_alloc_auto_grow(struct udma_dev *udma_dev, struct udma_ida *ida_table,
			    uint32_t *idx)
{
	int id;

	spin_lock(&ida_table->lock);
	id = ida_alloc_range(&ida_table->ida, ida_table->next, ida_table->max,
			     GFP_ATOMIC);
	if (id < 0) {
		id = ida_alloc_range(&ida_table->ida, ida_table->min, ida_table->max,
				     GFP_ATOMIC);
		if (id < 0) {
			spin_unlock(&ida_table->lock);
			dev_err(udma_dev->dev, "failed to alloc id, ret = %d.\n", id);
			return id == -ENOSPC ? -ENOSR : id;
		}
	}

	ida_table->next = (uint32_t)id + 1 > ida_table->max ?
			  ida_table->min : (uint32_t)id + 1;

	*idx = (uint32_t)id;
	spin_unlock(&ida_table->lock);

	return 0;
}

int udma_id_alloc(struct udma_dev *udma_dev, struct udma_ida *ida_table,
		  uint32_t *idx)
{
	int id;

	id = ida_alloc_range(&ida_table->ida, ida_table->min, ida_table->max,
			     GFP_ATOMIC);
	if (id < 0) {
		dev_err(udma_dev->dev, "failed to alloc id, ret = %d.\n", id);
		return id;
	}

	*idx = (uint32_t)id;

	return 0;
}

int udma_specify_adv_id(struct udma_dev *udma_dev, struct udma_group_bitmap *bitmap_table,
			uint32_t user_id)
{
	uint32_t id_bit_idx = (user_id - bitmap_table->min);
	uint32_t bit_idx = id_bit_idx % NUM_JETTY_PER_GROUP;
	uint32_t block = id_bit_idx / NUM_JETTY_PER_GROUP;
	uint32_t *bit = bitmap_table->bit;

	spin_lock(&bitmap_table->lock);
	if ((bit[block] & (1U << bit_idx)) == 0) {
		spin_unlock(&bitmap_table->lock);
		dev_err(udma_dev->dev,
			"user specify id %u been used.\n", user_id);
		return -ENOMEM;
	}

	bit[block] &= ~(1U << bit_idx);
	spin_unlock(&bitmap_table->lock);

	return 0;
}

static inline uint32_t udma_adv_jetty_id_alloc(struct udma_dev *udma_dev, uint32_t *bit,
					       uint32_t next_bit, uint32_t start_idx,
					       struct udma_group_bitmap *bitmap_table)
{
	uint32_t bit_idx;

	bit_idx = find_next_bit((unsigned long *)bit, NUM_JETTY_PER_GROUP, next_bit);
	*bit &= ~(1U << bit_idx);

	return bitmap_table->min + start_idx + bit_idx;
}

int udma_adv_id_alloc(struct udma_dev *udma_dev, struct udma_group_bitmap *bitmap_table,
		      uint32_t *start_idx, bool is_grp, uint32_t next)
{
	uint32_t next_block = (next - bitmap_table->min) / NUM_JETTY_PER_GROUP;
	uint32_t next_bit = (next - bitmap_table->min) % NUM_JETTY_PER_GROUP;
	uint32_t bitmap_cnt = bitmap_table->bitmap_cnt;
	uint32_t *bit = bitmap_table->bit;
	uint32_t i;

	spin_lock(&bitmap_table->lock);

	for (i = next_block;
	     (i < bitmap_cnt && bit[i] == 0) ||
	     (i == next_block &&
	      ((bit[i] & GENMASK(NUM_JETTY_PER_GROUP - 1, next_bit)) == 0)); ++i)
		;

	if (i == bitmap_cnt) {
		spin_unlock(&bitmap_table->lock);
		return -ENOMEM;
	}

	if (!is_grp) {
		*start_idx =
			udma_adv_jetty_id_alloc(udma_dev, bit + i, i == next_block ? next_bit : 0,
						i * NUM_JETTY_PER_GROUP, bitmap_table);

		spin_unlock(&bitmap_table->lock);
		return 0;
	}

	for (; i < bitmap_cnt && ~bit[i] != 0; ++i)
		;
	if (i == bitmap_cnt ||
	    (i + 1) * NUM_JETTY_PER_GROUP > bitmap_table->n_bits) {
		spin_unlock(&bitmap_table->lock);
		return -ENOMEM;
	}

	bit[i] = 0;
	*start_idx = i * NUM_JETTY_PER_GROUP + bitmap_table->min;

	spin_unlock(&bitmap_table->lock);

	return 0;
}

void udma_adv_id_free(struct udma_group_bitmap *bitmap_table, uint32_t start_idx,
		      bool is_grp)
{
	uint32_t bitmap_num;
	uint32_t bit_num;

	start_idx -= bitmap_table->min;
	bitmap_num = start_idx / NUM_JETTY_PER_GROUP;
	spin_lock(&bitmap_table->lock);

	if (bitmap_num >= bitmap_table->bitmap_cnt) {
		spin_unlock(&bitmap_table->lock);
		return;
	}

	if (is_grp) {
		bitmap_table->bit[bitmap_num] = ~0U;
	} else {
		bit_num = start_idx % NUM_JETTY_PER_GROUP;
		bitmap_table->bit[bitmap_num] |= (1U << bit_num);
	}

	spin_unlock(&bitmap_table->lock);
}

static void udma_init_ida_table(struct udma_ida *ida_table, uint32_t max, uint32_t min)
{
	ida_init(&ida_table->ida);
	spin_lock_init(&ida_table->lock);
	ida_table->max = max;
	ida_table->min = min;
	ida_table->next = min;
}

void udma_init_udma_table(struct udma_table *table, uint32_t max, uint32_t min, bool irq_lock)
{
	udma_init_ida_table(&table->ida_table, max, min);
	if (irq_lock)
		xa_init_flags(&table->xa, XA_FLAGS_LOCK_IRQ);
	else
		xa_init(&table->xa);
}

void udma_init_udma_table_mutex(struct xarray *table, struct mutex *udma_mutex, bool irq_lock)
{
	if (irq_lock)
		xa_init_flags(table, XA_FLAGS_LOCK_IRQ);
	else
		xa_init(table);
	mutex_init(udma_mutex);
}

void udma_destroy_npu_cb_table(struct udma_dev *dev)
{
	struct udma_ctrlq_event_nb *nb = NULL;
	unsigned long index = 0;

	mutex_lock(&dev->npu_nb_mutex);
	if (!xa_empty(&dev->npu_nb_table)) {
		xa_for_each(&dev->npu_nb_table, index, nb) {
			ubase_ctrlq_unregister_crq_event(dev->comdev.adev,
							 UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
							 nb->opcode);
			__xa_erase(&dev->npu_nb_table, index);
			kfree(nb);
			nb = NULL;
		}
	}

	mutex_unlock(&dev->npu_nb_mutex);
	xa_destroy(&dev->npu_nb_table);
	mutex_destroy(&dev->npu_nb_mutex);
}

void udma_destroy_udma_table(struct udma_dev *dev, struct udma_table *table,
				    const char *table_name)
{
	if (!ida_is_empty(&table->ida_table.ida))
		dev_err(dev->dev, "IDA not empty in clean up %s table.\n",
			table_name);
	ida_destroy(&table->ida_table.ida);

	if (!xa_empty(&table->xa))
		dev_err(dev->dev, "%s not empty.\n", table_name);
	xa_destroy(&table->xa);
}

static void udma_clear_eid_table(struct udma_dev *udma_dev)
{
	struct udma_ctrlq_eid_info *eid_entry = NULL;
	unsigned long index = 0;
	eid_t ummu_eid = 0;
	guid_t guid = {};

	if (!xa_empty(&udma_dev->eid_table)) {
		xa_for_each(&udma_dev->eid_table, index, eid_entry) {
			xa_erase(&udma_dev->eid_table, index);
			if (!udma_dev->is_ue) {
				(void)memcpy(&ummu_eid, eid_entry->eid.raw, sizeof(ummu_eid));
				ummu_core_del_eid(&guid, ummu_eid, EID_NONE);
			}
			kfree(eid_entry);
			eid_entry = NULL;
		}
	}
}

static void udma_clear_eid_guid_table(struct udma_dev *udma_dev)
{
	struct udma_ctrlq_ue_eid_guid_out *eid_guid_entry = NULL;
	unsigned long index = 0;
	eid_t ummu_eid = 0;
	guid_t guid = {};

	mutex_lock(&udma_dev->eid_guid_mutex);
	if (!xa_empty(&udma_dev->eid_guid_table)) {
		xa_for_each(&udma_dev->eid_guid_table, index, eid_guid_entry) {
			xa_erase(&udma_dev->eid_guid_table, index);
			(void)memcpy(&ummu_eid, eid_guid_entry->eid_info.eid.raw, sizeof(ummu_eid));
			(void)memcpy(&guid, &eid_guid_entry->ue_guid, sizeof(guid));
			ummu_core_del_eid(&guid, ummu_eid, EID_NONE);
			kfree(eid_guid_entry);
			eid_guid_entry = NULL;
		}
	}
	mutex_unlock(&udma_dev->eid_guid_mutex);
}

void udma_destroy_eid_guid_table(struct udma_dev *udma_dev)
{
	udma_clear_eid_guid_table(udma_dev);
	xa_destroy(&udma_dev->eid_guid_table);
	mutex_destroy(&udma_dev->eid_guid_mutex);
}

void udma_destroy_eid_table(struct udma_dev *udma_dev)
{
	udma_clear_eid_table(udma_dev);
	xa_destroy(&udma_dev->eid_table);
	mutex_destroy(&udma_dev->eid_mutex);
}

void udma_dfx_store_id(struct udma_dev *udma_dev, struct udma_dfx_entity *entity,
		       uint32_t id, const char *name)
{
	uint32_t *entry;
	int ret;

	entry = (uint32_t *)xa_load(&entity->table, id);
	if (entry) {
		dev_warn(udma_dev->dev, "%s(%u) already exists in DFX.\n", name, id);
		return;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	*entry = id;

	write_lock(&entity->rwlock);
	ret = xa_err(xa_store(&entity->table, id, entry, GFP_KERNEL));
	if (ret) {
		write_unlock(&entity->rwlock);
		dev_err(udma_dev->dev, "store %s to table failed in DFX.\n", name);
		kfree(entry);
		return;
	}

	++entity->cnt;
	write_unlock(&entity->rwlock);
}

void udma_dfx_delete_id(struct udma_dev *udma_dev, struct udma_dfx_entity *entity,
			uint32_t id)
{
	void *entry;

	write_lock(&entity->rwlock);
	entry = xa_load(&entity->table, id);
	if (!entry) {
		write_unlock(&entity->rwlock);
		return;
	}

	xa_erase(&entity->table, id);
	kfree(entry);
	--entity->cnt;
	write_unlock(&entity->rwlock);
}

static struct udma_umem *udma_pin_k_addr(struct ubcore_device *ub_dev, uint64_t va,
				    uint64_t len)
{
	struct udma_umem_param param;

	param.ub_dev = ub_dev;
	param.va = va;
	param.len = len;
	param.flag.bs.writable = true;
	param.flag.bs.non_pin = 0;
	param.is_kernel = true;

	return udma_umem_get(&param);
}

static void udma_unpin_k_addr(struct udma_umem *umem)
{
	udma_umem_release(umem, true, true);
}

int udma_alloc_normal_buf(struct udma_dev *udma_dev, size_t memory_size,
			  struct udma_buf *buf)
{
	size_t aligned_memory_size = PAGE_ALIGN(memory_size);
	int ret;

	buf->aligned_va = vmalloc(aligned_memory_size);
	if (!buf->aligned_va) {
		dev_err(udma_dev->dev,
			"failed to vmalloc kernel buf, size = %lu.\n",
			aligned_memory_size);
		return -ENOMEM;
	}

	memset(buf->aligned_va, 0, aligned_memory_size);
	buf->umem = udma_pin_k_addr(&udma_dev->ub_dev, (uint64_t)buf->aligned_va,
				    aligned_memory_size);
	if (IS_ERR(buf->umem)) {
		ret = PTR_ERR(buf->umem);
		vfree(buf->aligned_va);
		buf->aligned_va = NULL;
		dev_err(udma_dev->dev, "pin kernel buf failed, ret = %d.\n", ret);
		return ret;
	}

	buf->addr = (uintptr_t)buf->aligned_va;
	buf->kva = buf->aligned_va;

	return 0;
}

void udma_free_normal_buf(struct udma_dev *udma_dev, size_t memory_size,
		     struct udma_buf *buf)
{
	udma_unpin_k_addr(buf->umem);
	vfree(buf->aligned_va);
	buf->aligned_va = NULL;
	buf->kva = NULL;
	buf->addr = 0;
}

static struct udma_hugepage_priv *
udma_alloc_hugepage_priv(struct udma_dev *dev, uint32_t len)
{
	struct udma_hugepage_priv *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->va_len = ALIGN(len, UDMA_HUGEPAGE_SIZE);
	priv->left_va_len = priv->va_len;
	priv->va_base = vmalloc_huge(priv->va_len, GFP_KERNEL);
	if (!priv->va_base) {
		dev_err(dev->dev, "failed to vmalloc_huge, size=%u.\n", priv->va_len);
		goto err_vmalloc_huge;
	}
	memset(priv->va_base, 0, priv->va_len);

	priv->umem = udma_pin_k_addr(&dev->ub_dev, (uint64_t)priv->va_base, priv->va_len);
	if (IS_ERR(priv->umem)) {
		dev_err(dev->dev, "pin kernel buf failed.\n");
		goto err_pin;
	}

	refcount_set(&priv->refcnt, 1);
	priv->seq = (uint32_t)atomic_inc_return(&dev->hugepage_seq);
	list_add(&priv->list, &dev->hugepage_list);

	if (dfx_switch)
		dev_info_ratelimited(dev->dev, "alloc_hugepage, seq=%u, 2m_page_num=%u.\n",
				     priv->seq, priv->va_len >> UDMA_HUGEPAGE_SHIFT);
	return priv;

err_pin:
	vfree(priv->va_base);
err_vmalloc_huge:
	kfree(priv);

	return NULL;
}

static struct udma_hugepage *
udma_alloc_hugepage(struct udma_dev *dev, uint32_t len)
{
	struct udma_hugepage_priv *priv = NULL;
	struct udma_hugepage *hugepage;
	bool b_reuse = false;

	hugepage = kzalloc(sizeof(*hugepage), GFP_KERNEL);
	if (!hugepage)
		return NULL;

	mutex_lock(&dev->hugepage_lock);
	if (!list_empty(&dev->hugepage_list)) {
		priv = list_first_entry(&dev->hugepage_list, struct udma_hugepage_priv, list);
		b_reuse = len <= priv->left_va_len;
	}

	if (b_reuse) {
		refcount_inc(&priv->refcnt);
	} else {
		priv = udma_alloc_hugepage_priv(dev, len);
		if (!priv) {
			mutex_unlock(&dev->hugepage_lock);
			kfree(hugepage);
			return NULL;
		}
	}

	hugepage->va_start = priv->va_base + priv->left_va_offset;
	hugepage->va_len = len;
	hugepage->priv = priv;
	priv->left_va_offset += len;
	priv->left_va_len -= len;
	mutex_unlock(&dev->hugepage_lock);

	if (dfx_switch)
		dev_info_ratelimited(dev->dev, "occupy_hugepage, seq=%u, 4k_page_num=%u.\n",
				     priv->seq, len >> UDMA_HW_PAGE_SHIFT);
	return hugepage;
}

static void udma_free_hugepage(struct udma_dev *dev, struct udma_hugepage *hugepage)
{
	struct udma_hugepage_priv *priv = NULL;

	if (hugepage == NULL)
		return;

	priv = hugepage->priv;

	if (dfx_switch)
		dev_info_ratelimited(dev->dev, "return_hugepage, seq=%u.\n", priv->seq);
	mutex_lock(&dev->hugepage_lock);
	if (refcount_dec_and_test(&priv->refcnt)) {
		if (dfx_switch)
			dev_info_ratelimited(dev->dev, "free_hugepage, seq=%u.\n", priv->seq);
		list_del(&priv->list);

		udma_unpin_k_addr(priv->umem);
		vfree(priv->va_base);
		kfree(priv);
	} else {
		memset(hugepage->va_start, 0, hugepage->va_len);
	}
	mutex_unlock(&dev->hugepage_lock);
	kfree(hugepage);
}

int udma_k_alloc_buf(struct udma_dev *dev, struct udma_buf *buf)
{
	uint32_t size = buf->entry_size * buf->entry_cnt;
	uint32_t hugepage_size;
	int ret = 0;

	if (ubase_adev_prealloc_supported(dev->comdev.adev)) {
		hugepage_size = ALIGN(size, UDMA_HW_PAGE_SIZE);
		buf->hugepage = udma_alloc_hugepage(dev, hugepage_size);
		if (buf->hugepage) {
			buf->kva = buf->hugepage->va_start;
			buf->addr = (uint64_t)buf->kva;
			buf->is_hugepage = true;
		} else {
			dev_warn(dev->dev,
				 "failed to alloc hugepage buf, switch to alloc normal buf.\n");
			ret = udma_alloc_normal_buf(dev, size, buf);
		}
	} else {
		ret = udma_alloc_normal_buf(dev, size, buf);
	}

	return ret;
}

void udma_k_free_buf(struct udma_dev *dev, struct udma_buf *buf)
{
	uint32_t size = buf->entry_cnt * buf->entry_size;

	if (buf->is_hugepage)
		udma_free_hugepage(dev, buf->hugepage);
	else
		udma_free_normal_buf(dev, size, buf);
}

int udma_query_ue_idx(struct ubcore_device *ubcore_dev, struct ubcore_devid *devid,
		      uint16_t *ue_idx)
{
	struct udma_dev *dev = to_udma_dev(ubcore_dev);
	struct udma_ue_index_cmd cmd = {};
	struct ubase_cmd_buf out;
	struct ubase_cmd_buf in;
	int ret;

	if (!devid) {
		dev_err(dev->dev, "failed to query ue idx, devid is NULL.\n");
		return -EINVAL;
	}

	(void)memcpy(cmd.guid, devid->raw, sizeof(devid->raw));

	udma_fill_buf(&in, UDMA_CMD_QUERY_UE_INDEX, true, sizeof(cmd), &cmd);
	udma_fill_buf(&out, UDMA_CMD_QUERY_UE_INDEX, true, sizeof(cmd), &cmd);

	ret = ubase_cmd_send_inout(dev->comdev.adev, &in, &out);
	if (ret) {
		dev_err(dev->dev, "failed to query ue idx, ret = %d.\n", ret);
		return ret;
	}
	*ue_idx = cmd.ue_idx;

	return 0;
}

void udma_dfx_ctx_print(struct udma_dev *udev, const char *name, uint32_t id, uint32_t len,
			uint32_t *ctx)
{
	uint32_t i;

	pr_info("*************udma%u %s(%u) CONTEXT INFO *************\n",
		udev->adev_id, name, id);

	for (i = 0; i < len; ++i)
		pr_info("udma%u %s(%u) CONTEXT(byte%4lu): %08x\n",
			udev->adev_id, name, id, (i + 1) * sizeof(uint32_t), ctx[i]);

	pr_info("**************************************************\n");
}

void udma_swap_endian(const uint8_t arr[], uint8_t res[], uint32_t res_size)
{
	uint32_t i;

	for (i = 0; i < res_size; i++)
		res[i] = arr[res_size - i - 1];
}

void udma_init_hugepage(struct udma_dev *dev)
{
	INIT_LIST_HEAD(&dev->hugepage_list);
	mutex_init(&dev->hugepage_lock);
}

void udma_destroy_hugepage(struct udma_dev *dev)
{
	struct udma_hugepage_priv *priv;
	struct udma_hugepage_priv *tmp;

	mutex_lock(&dev->hugepage_lock);
	list_for_each_entry_safe(priv, tmp, &dev->hugepage_list, list) {
		list_del(&priv->list);
		dev_info_ratelimited(dev->dev, "free_hugepage, seq=%u.\n", priv->seq);
		udma_unpin_k_addr(priv->umem);
		vfree(priv->va_base);
		kfree(priv);
	}
	mutex_unlock(&dev->hugepage_lock);
	mutex_destroy(&dev->hugepage_lock);
}
