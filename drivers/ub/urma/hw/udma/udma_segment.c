// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/iommu.h>
#include <linux/slab.h>
#include <linux/ummu_core.h>
#include "udma_common.h"
#include "udma_cmd.h"
#include "udma_eid.h"
#include "udma_tid.h"
#include "udma_segment.h"

static int udma_align_segment(struct udma_segment *seg)
{
	uint64_t end_addr;

	if (seg->addr > U64_MAX - seg->length)
		return -EINVAL;

	end_addr = PAGE_ALIGN(seg->addr + seg->length);
	seg->addr = PAGE_ALIGN_DOWN(seg->addr);
	seg->length = end_addr - seg->addr;

	return 0;
}

static int udma_pin_segment(struct ubcore_device *ub_dev, struct ubcore_seg_cfg *cfg,
			    struct udma_segment *seg, bool is_writable)
{
	struct udma_dev *udma_dev = to_udma_dev(ub_dev);
	struct udma_umem_param param;
	int ret = 0;

	param.ub_dev = ub_dev;
	param.va = seg->addr;
	param.len = seg->length;

	param.flag.bs.writable = is_writable;
	param.flag.bs.non_pin = cfg->flag.bs.non_pin;
	param.is_kernel = seg->kernel_mode;

	seg->umem = udma_umem_get(&param);
	if (IS_ERR(seg->umem)) {
		ret = PTR_ERR(seg->umem);
		dev_err(udma_dev->dev,
			"failed to get segment umem, ret = %d.\n", ret);
	}

	return ret;
}

static void udma_unpin_seg(struct udma_segment *seg, bool dirty)
{
	if (!seg->core_tseg.seg.attr.bs.non_pin)
		udma_umem_release(seg->umem, seg->kernel_mode, dirty);
}

static int udma_check_seg_cfg(struct udma_dev *udma_dev, struct ubcore_seg_cfg *cfg)
{
	if (!cfg->token_id || cfg->flag.bs.access >= UDMA_SEGMENT_ACCESS_GUARD ||
	    cfg->flag.bs.token_policy >= UBCORE_TOKEN_SIGNED) {
		dev_err(udma_dev->dev,
			"error segment input, access = %d, token_policy = %d, or null key_id.\n",
			cfg->flag.bs.access, cfg->flag.bs.token_policy);
		return -EINVAL;
	}

	return 0;
}

static void udma_init_seg_cfg(struct udma_segment *seg, struct ubcore_seg_cfg *cfg)
{
	seg->core_tseg.token_id = cfg->token_id;
	seg->core_tseg.seg.token_id = cfg->token_id->token_id;
	seg->core_tseg.seg.attr.value = cfg->flag.value;
	seg->token_value = cfg->token_value.token;
	seg->token_value_valid = cfg->flag.bs.token_policy != UBCORE_TOKEN_NONE;
	seg->addr = cfg->va;
	seg->length = cfg->len;
}

static int udma_u_get_seg_perm(struct ubcore_seg_cfg *cfg)
{
	bool local_only_flag = cfg->flag.bs.access & UBCORE_ACCESS_LOCAL_ONLY;
	bool atomic_flag = cfg->flag.bs.access & UBCORE_ACCESS_ATOMIC;
	bool write_flag = cfg->flag.bs.access & UBCORE_ACCESS_WRITE;
	bool read_flag = cfg->flag.bs.access & UBCORE_ACCESS_READ;

	/* After setting ACCESS_LOCAL, other operations cannot be configured. */
	if (local_only_flag && !atomic_flag && !write_flag && !read_flag)
		return UMMU_DEV_ATOMIC | UMMU_DEV_WRITE | UMMU_DEV_READ;

	/* Atomic require additional configuration of write and read. */
	if (!local_only_flag && atomic_flag && write_flag && read_flag)
		return UMMU_DEV_ATOMIC | UMMU_DEV_WRITE | UMMU_DEV_READ;

	/* Write require additional configuration of read. */
	if (!local_only_flag && !atomic_flag && write_flag && read_flag)
		return UMMU_DEV_WRITE | UMMU_DEV_READ;

	if (!local_only_flag && !atomic_flag && !write_flag && read_flag)
		return UMMU_DEV_READ;

	/* All other configurations are illegal. */
	return 0;
}

static int udma_sva_grant(struct ubcore_seg_cfg *cfg, struct iommu_sva *ksva)
{
#define UDMA_TOKEN_VALUE_INPUT 0
	struct ummu_seg_attr seg_attr = {.token = NULL, .e_bit = UMMU_EBIT_ON};
	struct ummu_token_info token_info;
	int perm;
	int ret;

	perm = udma_u_get_seg_perm(cfg);

	seg_attr.e_bit = (enum ummu_ebit_state)cfg->flag.bs.access &
			  UBCORE_ACCESS_LOCAL_ONLY;

	if (cfg->flag.bs.token_policy == UBCORE_TOKEN_NONE) {
		return iommu_sva_grant(ksva, (void *)(uintptr_t)cfg->va, cfg->len,
					    perm, (void *)&seg_attr);
	} else {
		seg_attr.token = &token_info;
		token_info.input = UDMA_TOKEN_VALUE_INPUT;
		token_info.tokenVal = cfg->token_value.token;
		ret = iommu_sva_grant(ksva, (void *)(uintptr_t)cfg->va, cfg->len,
					    perm, (void *)&seg_attr);
		token_info.tokenVal = 0;

		return ret;
	}
}

static void udma_dfx_store_seg(struct udma_dev *udma_dev,
			       struct ubcore_seg_cfg *cfg)
{
	struct udma_dfx_seg *seg;
	int ret;

	seg = (struct udma_dfx_seg *)xa_load(&udma_dev->dfx_info->seg.table,
					     cfg->token_id->token_id);
	if (seg) {
		dev_warn(udma_dev->dev, "segment already exists in DFX.\n");
		return;
	}

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return;

	seg->id = cfg->token_id->token_id;
	seg->ubva.va = cfg->va;
	seg->len = cfg->len;
	seg->token_value = cfg->token_value;

	write_lock(&udma_dev->dfx_info->seg.rwlock);
	ret = xa_err(xa_store(&udma_dev->dfx_info->seg.table, cfg->token_id->token_id,
			      seg, GFP_ATOMIC));
	if (ret) {
		write_unlock(&udma_dev->dfx_info->seg.rwlock);
		dev_err(udma_dev->dev, "store segment to table failed in DFX.\n");
		kfree(seg);
		return;
	}

	++udma_dev->dfx_info->seg.cnt;
	write_unlock(&udma_dev->dfx_info->seg.rwlock);
}

static void udma_dfx_delete_seg(struct udma_dev *udma_dev, uint32_t token_id,
				uint64_t va)
{
	struct udma_dfx_seg *seg;

	write_lock(&udma_dev->dfx_info->seg.rwlock);
	seg = (struct udma_dfx_seg *)xa_load(&udma_dev->dfx_info->seg.table,
					     token_id);
	if (seg && seg->id == token_id && seg->ubva.va == va) {
		xa_erase(&udma_dev->dfx_info->seg.table, token_id);
		seg->token_value.token = 0;
		kfree(seg);
		--udma_dev->dfx_info->seg.cnt;
	}
	write_unlock(&udma_dev->dfx_info->seg.rwlock);
}

static int udma_get_user_page(struct udma_dev *dev, struct udma_segment *seg)
{
	uint64_t page_left = udma_cal_npages(seg->addr, seg->length);
	uint64_t arr_num = PAGE_SIZE / sizeof(struct page *);
	uint64_t va = seg->addr;
	struct page **pages;
	int ret = -ENOMEM;
	uint64_t pfn;
	uint64_t i;

	if (page_left == 0 || page_left > UINT_MAX) {
		dev_err(dev->dev, "invalid page_num %llu.\n", page_left);
		return -EINVAL;
	}

	seg->umem = kzalloc(sizeof(*seg->umem), GFP_KERNEL);
	if (!seg->umem)
		return ret;

	pages = kcalloc(arr_num, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		goto err_alloc_pages;

	seg->first_page = NULL;
	while (page_left != 0) {
		for (i = 0; i < min_t(uint64_t, page_left, arr_num); i++) {
			if (!remap_va_to_pfn(dev, va, &pfn))
				goto err_tr_va;

			if (!pfn_valid(pfn)) {
				dev_err(dev->dev, "invalid pfn=0x%llx.\n", pfn);
				goto err_tr_va;
			}

			pages[i] = pfn_to_page(pfn);
			if (!pages[i] || PageReserved(pages[i])) {
				dev_err(dev->dev, "invalid page structure for pfn=0x%llx.\n", pfn);
				goto err_tr_va;
			}

			if (!seg->first_page)
				seg->first_page = pages[i];

			va += PAGE_SIZE;
		}
		page_left -= i;
		ret = sg_alloc_append_table_from_pages(&seg->umem->append, pages,
						       i, 0, i * PAGE_SIZE, UINT_MAX,
						       page_left, GFP_KERNEL);
		if (ret) {
			dev_err(dev->dev, "failed to sg alloc append table, ret=%d.\n", ret);
			goto err_append;
		}
	}

	if (!try_get_page(seg->first_page)) {
		dev_err(dev->dev, "failed to get_page.\n");
		ret = -EINVAL;
		goto err_get_page;
	}

	kfree(pages);

	return 0;

err_get_page:
err_append:
err_tr_va:
	sg_free_append_table(&seg->umem->append);
	kfree(pages);
err_alloc_pages:
	kfree(seg->umem);
	seg->umem = NULL;

	return ret;
}

static void udma_put_user_page(struct udma_segment *seg)
{
	put_page(seg->first_page);
	sg_free_append_table(&seg->umem->append);
	kfree(seg->umem);
	seg->umem = NULL;
}

static int udma_pin_seg_pages(struct ubcore_device *ub_dev,
			      struct udma_context *ctx, struct udma_segment *seg,
			      struct ubcore_seg_cfg *cfg, int *prot)
{
	struct vm_area_struct *vma;
	int ret;

	mmap_read_lock(current->mm);
	vma = vma_lookup(current->mm, seg->addr);
	if (!vma) {
		mmap_read_unlock(current->mm);
		dev_err(ctx->dev->dev, "failed to vma_lookup.\n");
		return -EINVAL;
	}

	if (vma->vm_flags & VM_PFNMAP) {
		ret = udma_get_user_page(ctx->dev, seg);
		mmap_read_unlock(current->mm);
	} else {
		mmap_read_unlock(current->mm);

		ret = udma_align_segment(seg);
		if (unlikely(ret)) {
			dev_err(ctx->dev->dev, "failed to align segment addr and length.\n");
			return ret;
		}

		ret = udma_pin_segment(ub_dev, cfg, seg, true);
		if (unlikely(ret)) {
			*prot = IOMMU_READ;
			ret = udma_pin_segment(ub_dev, cfg, seg, false);
		}
	}

	if (unlikely(ret)) {
		dev_err(ctx->dev->dev, "failed to get_user_page, ret = %d.\n", ret);
		return ret;
	}

	return ret;
}

static void udma_unpin_seg_pages(struct udma_segment *seg, bool dirty)
{
	if (seg == NULL)
		return;

	if (seg->umem->va)
		udma_umem_release(seg->umem, seg->kernel_mode, dirty);
	else
		udma_put_user_page(seg);
}

static int udma_ioummu_remote_map(uint32_t tid, struct udma_segment *seg, int prot)
{
	return udma_ioummu_map(UMMU_INVALID_TID, tid, prot,
			       seg->addr, &(seg->umem->append.sgt));
}

static int udma_iommu_partial_overlap_seg(struct ubcore_device *ub_dev,
					  struct udma_context *ctx,
					  struct udma_segment *seg,
					  struct ubcore_seg_cfg *cfg,
					  struct udma_range_list *pageList)
{
	struct udma_range_list_node *none_overlap_node;
	struct udma_range_list mappedList = {};
	struct udma_segment none_overlap_seg;
	int prot = IOMMU_WRITE | IOMMU_READ;
	bool dirty = false;
	int ret = 0;

	none_overlap_seg.kernel_mode = seg->kernel_mode;
	udma_init_seg_cfg(&none_overlap_seg, cfg);
	none_overlap_node = pageList->head;
	while (none_overlap_node != NULL) {
		none_overlap_seg.addr = none_overlap_node->start;
		none_overlap_seg.length = none_overlap_node->length;
		ret = udma_pin_seg_pages(ub_dev, ctx, &none_overlap_seg,
					 cfg, &prot);
		if (unlikely(ret)) {
			dev_err(ctx->dev->dev, "failed to pin none_overlap_seg, ret = %d.\n", ret);
			goto err_local_page_ping_segment;
		}

		ret = udma_ioummu_map(ctx->tid, UMMU_INVALID_TID, prot,
				      none_overlap_seg.addr,
				      &(none_overlap_seg.umem->append.sgt));
		if (unlikely(ret)) {
			dev_err(ctx->dev->dev, "failed to iommu map none_overlap_seg, ret = %d.\n",
				ret);
			goto err_local_page_ioummu_map;
		}

		ret = udma_range_list_rollback(&mappedList, none_overlap_node);
		if (unlikely(ret)) {
			dirty = true;
			dev_err(ctx->dev->dev, "failed to rollback list, ret = %d.\n", ret);
			goto err_local_page_ioummu_map;
		}

		udma_unpin_seg_pages(&none_overlap_seg, true);
		none_overlap_node = none_overlap_node->next;
	}

	udma_range_list_destroy(&mappedList);

	return 0;

err_local_page_ioummu_map:
	udma_unpin_seg_pages(&none_overlap_seg, dirty);
err_local_page_ping_segment:
	none_overlap_node = mappedList.head;
	while (none_overlap_node != NULL) {
		udma_ioummu_unmap(ctx->tid, UMMU_INVALID_TID,
				  none_overlap_node->start,
				  PAGE_SIZE * udma_cal_npages(none_overlap_node->start,
				  none_overlap_node->length));
		none_overlap_node = none_overlap_node->next;
	}
	udma_range_list_destroy(&mappedList);

	return ret;
}

static int udma_iommu_local_map(struct ubcore_device *ub_dev,
				struct udma_context *ctx, struct udma_segment *seg,
				struct ubcore_seg_cfg *cfg, int prot)
{
	struct udma_range_list pageList = {};
	int ret;

	mutex_lock(&ctx->seg_node->lock);
	ret = udma_seg_range_occupy(ctx->seg_node, seg->addr,
				    seg->addr + PAGE_ALIGN(seg->length) - 1,
				    &pageList);
	if (unlikely(ret)) {
		mutex_unlock(&ctx->seg_node->lock);
		dev_err(ctx->dev->dev, "segment have invalid parameter,ret = %d.\n", ret);
		return ret;
	}

	if (pageList.head == NULL) {
		mutex_unlock(&ctx->seg_node->lock);
		return 0;
	}

	if (pageList.head->length == PAGE_ALIGN(seg->length)) {
		ret = udma_ioummu_map(ctx->tid, UMMU_INVALID_TID, prot,
				      seg->addr, &(seg->umem->append.sgt));
		if (unlikely(ret)) {
			udma_range_list_destroy(&pageList);
			mutex_unlock(&ctx->seg_node->lock);
			dev_err(ctx->dev->dev, "ioummu segment failed, ret = %d.\n", ret);
			return ret;
		}
	} else {
		ret = udma_iommu_partial_overlap_seg(ub_dev, ctx, seg, cfg,
						     &pageList);
		if (unlikely(ret)) {
			udma_range_list_destroy(&pageList);
			mutex_unlock(&ctx->seg_node->lock);
			dev_err(ctx->dev->dev,
				"ioummu partial overlap segment failed, ret = %d.\n", ret);
			return ret;
		}
	}

	udma_range_list_destroy(&pageList);
	mutex_unlock(&ctx->seg_node->lock);
	return ret;
}

static int udma_pin_pages_and_ioummu_map(struct ubcore_device *ub_dev, struct udma_context *ctx,
					 struct udma_segment *seg, struct ubcore_seg_cfg *cfg,
					 uint32_t tid)
{
	uint32_t access = seg->core_tseg.seg.attr.bs.access;
	bool local_only = access & UBCORE_ACCESS_LOCAL_ONLY;
	int prot = IOMMU_WRITE | IOMMU_READ;
	bool dirty = false;
	int ret = 0;

	ret = udma_pin_seg_pages(ub_dev, ctx, seg, cfg, &prot);
	if (unlikely(ret))
		return ret;

	if (!local_only) {
		ret = udma_ioummu_remote_map(tid, seg, prot);
		if (unlikely(ret)) {
			dev_err(ctx->dev->dev, "ioummu remote map failed, ret = %d.\n", ret);
			goto err_ioummu_remote_map;
		}
	}

	ret = udma_iommu_local_map(ub_dev, ctx, seg, cfg, prot);
	if (unlikely(ret)) {
		dirty = true;
		dev_err(ctx->dev->dev, "ioummu local map failed, ret = %d.\n", ret);
		goto err_ioummu_local_map;
	}

	return ret;

err_ioummu_local_map:
	if (!local_only)
		udma_ioummu_unmap(UMMU_INVALID_TID, tid, seg->addr,
				  PAGE_SIZE * udma_cal_npages(seg->addr, seg->length));
err_ioummu_remote_map:
	udma_unpin_seg_pages(seg, dirty);

	return ret;
}

static void udma_unpin_pages_and_unioummu_map(struct udma_context *ctx, struct udma_segment *seg,
					      uint32_t tid)
{
	uint32_t access = seg->core_tseg.seg.attr.bs.access;
	bool local_only = access & UBCORE_ACCESS_LOCAL_ONLY;
	struct udma_range_list_node *current_node;
	struct udma_range_list pageList = {};

	if (!local_only)
		udma_ioummu_unmap(UMMU_INVALID_TID, tid, seg->addr,
				  PAGE_SIZE * udma_cal_npages(seg->addr, seg->length));

	mutex_lock(&ctx->seg_node->lock);
	udma_seg_range_realease(ctx->seg_node, seg->addr,
				seg->addr + PAGE_ALIGN(seg->length) - 1, &pageList);
	current_node = pageList.head;
	while (current_node != NULL) {
		udma_ioummu_unmap(ctx->tid, UMMU_INVALID_TID, current_node->start,
				  PAGE_SIZE * udma_cal_npages(current_node->start,
				  current_node->length));
		current_node = current_node->next;
	}
	udma_range_list_destroy(&pageList);
	mutex_unlock(&ctx->seg_node->lock);

	udma_unpin_seg_pages(seg, true);
}

struct ubcore_target_seg *udma_register_seg(struct ubcore_device *ub_dev,
					    struct ubcore_seg_cfg *cfg,
					    struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(ub_dev);
	struct udma_tid *udma_tid;
	struct udma_segment *seg;
	struct iommu_sva *ksva;
	int ret = 0;

	ret = udma_check_seg_cfg(udma_dev, cfg);
	if (ret)
		return NULL;

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return NULL;

	seg->kernel_mode = udata == NULL;
	udma_init_seg_cfg(seg, cfg);
	udma_tid = to_udma_tid(seg->core_tseg.token_id);

	if (udata && udma_dev->caps.sva_sep_mode_en) {
		ret = udma_pin_pages_and_ioummu_map(ub_dev, to_udma_context(udata->uctx), seg,
						    cfg, udma_tid->tid);
		if (ret) {
			dev_err(udma_dev->dev, "ioummu map failed, ret = %d.\n", ret);
			goto err_pin_seg;
		}
		return &seg->core_tseg;
	}

	if (!cfg->flag.bs.non_pin) {
		ret = udma_pin_segment(ub_dev, cfg, seg,
				       !!(cfg->flag.bs.access & UBCORE_ACCESS_WRITE));
		if (ret) {
			dev_err(udma_dev->dev, "pin segment failed, ret = %d.\n", ret);
			goto err_pin_seg;
		}
	}

	if (udata)
		return &seg->core_tseg;

	mutex_lock(&udma_dev->ksva_mutex);
	ksva = (struct iommu_sva *)xa_load(&udma_dev->ksva_table, udma_tid->tid);
	if (!ksva) {
		dev_err(udma_dev->dev,
			"unable to get ksva while register segment, token maybe is free.\n");
		goto err_load_ksva;
	}

	ret = udma_sva_grant(cfg, ksva);
	if (ret) {
		dev_err(udma_dev->dev,
			"ksva grant failed token policy %d, access %d, ret = %d.\n",
			cfg->flag.bs.token_policy, cfg->flag.bs.access, ret);
		goto err_load_ksva;
	}
	mutex_unlock(&udma_dev->ksva_mutex);

	if (dfx_switch)
		udma_dfx_store_seg(udma_dev, cfg);

	return &seg->core_tseg;

err_load_ksva:
	mutex_unlock(&udma_dev->ksva_mutex);
	udma_unpin_seg(seg, false);
err_pin_seg:
	seg->token_value = 0;
	kfree(seg);
	return NULL;
}

int udma_unregister_seg(struct ubcore_target_seg *ubcore_seg)
{
	struct udma_tid *udma_tid = to_udma_tid(ubcore_seg->token_id);
	struct udma_dev *udma_dev = to_udma_dev(ubcore_seg->ub_dev);
	struct udma_segment *seg = to_udma_seg(ubcore_seg);
	struct ummu_token_info token_info;
	struct iommu_sva *ksva;
	int ret;

	if (!seg->kernel_mode)
		goto common_process;

	mutex_lock(&udma_dev->ksva_mutex);
	ksva = (struct iommu_sva *)xa_load(&udma_dev->ksva_table, udma_tid->tid);
	if (!ksva) {
		dev_warn(udma_dev->dev,
			 "unable to get ksva while unregister segment, token maybe is free.\n");
	} else {
		if (seg->token_value_valid) {
			token_info.tokenVal = seg->token_value;
			ret = iommu_sva_ungrant(ksva,
						     (void *)(uintptr_t)ubcore_seg->seg.ubva.va,
						     ubcore_seg->seg.len, &token_info);
			token_info.tokenVal = 0;
		} else {
			ret = iommu_sva_ungrant(ksva,
						     (void *)(uintptr_t)ubcore_seg->seg.ubva.va,
						     ubcore_seg->seg.len, NULL);
		}
		if (ret) {
			mutex_unlock(&udma_dev->ksva_mutex);
			dev_err(udma_dev->dev, "unregister segment failed, ret = %d.\n", ret);
			return ret;
		}
	}
	mutex_unlock(&udma_dev->ksva_mutex);

	udma_iotlb_sync(udma_dev, seg->addr, seg->length);
	if (dfx_switch)
		udma_dfx_delete_seg(udma_dev, ubcore_seg->token_id->token_id,
				    ubcore_seg->seg.ubva.va);

common_process:
	if (!seg->kernel_mode && udma_dev->caps.sva_sep_mode_en)
		udma_unpin_pages_and_unioummu_map(to_udma_context(ubcore_seg->uctx),
						  seg, udma_tid->tid);
	else
		udma_unpin_seg(seg, true);
	seg->token_value = 0;
	kfree(seg);

	return 0;
}

struct ubcore_target_seg *udma_import_seg(struct ubcore_device *dev,
					  struct ubcore_target_seg_cfg *cfg,
					  struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_segment *seg;

	if (cfg->seg.attr.bs.token_policy > UBCORE_TOKEN_PLAIN_TEXT) {
		dev_err(udma_dev->dev, "invalid token policy = %d.\n",
			cfg->seg.attr.bs.token_policy);
		return NULL;
	}

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return NULL;

	if (cfg->seg.attr.bs.token_policy != UBCORE_TOKEN_NONE) {
		seg->token_value = cfg->token_value.token;
		seg->token_value_valid = true;
	}

	seg->tid = cfg->seg.token_id >> UDMA_TID_SHIFT;

	return &seg->core_tseg;
}

int udma_unimport_seg(struct ubcore_target_seg *tseg)
{
	struct udma_segment *seg;

	seg = to_udma_seg(tseg);
	seg->token_value = 0;
	kfree(seg);

	return 0;
}

void udma_destroy_seg_tree_table(struct udma_dev *dev)
{
	struct udma_seg_tree_node *seg_node = NULL;
	unsigned long tid = 0;

	mutex_lock(&dev->seg_tree_mutex);
	xa_for_each(&dev->seg_tree_table, tid, seg_node) {
		__xa_erase(&dev->seg_tree_table, tid);
		udma_seg_tree_destroy(seg_node);
	}
	mutex_unlock(&dev->seg_tree_mutex);
	xa_destroy(&dev->seg_tree_table);
	mutex_destroy(&dev->seg_tree_mutex);
}
