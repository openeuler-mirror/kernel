// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <asm/current.h>
#include <linux/iommu.h>
#include <linux/scatterlist.h>
#include <ub/urma/ubcore_api.h>
#include "udma_jfs.h"
#include "udma_jetty.h"
#include "udma_ctrlq_tp.h"
#include "udma_cmd.h"
#include "udma_seg_tree.h"
#include "udma_ctx.h"

static int udma_init_ctx_resp(struct udma_dev *dev, struct ubcore_udrv_priv *udrv_data, bool dtu_en)
{
	struct udma_create_ctx_resp resp = {};
	unsigned long byte;

	if (!udrv_data->out_addr ||
	    udrv_data->out_len < sizeof(resp)) {
		dev_err(dev->dev,
			"Invalid ctx resp out: len %u or address is invalid.\n",
			udrv_data->out_len);
		return -EINVAL;
	}

	resp.cqe_size = dev->caps.cqe_size;
	resp.dwqe_enable = !!(dev->caps.feature & UDMA_CAP_FEATURE_DIRECT_WQE);
	resp.reduce_enable = !!(dev->caps.feature & UDMA_CAP_FEATURE_REDUCE);
	resp.ue_id = dev->ue_id;
	resp.chip_id = dev->chip_id;
	resp.die_id = dev->die_id;
	resp.dump_aux_info = dump_aux_info;
	resp.jfr_sge = dev->caps.jfr_sge;
	resp.sq_reserved = dev->sq_reserved_info.sq_reserved;
	resp.sq_reserved_va = dev->sq_reserved_info.va_start;
	resp.sq_reserved_len = dev->sq_reserved_info.va_size;
	resp.lock_buffer_en = dev->caps.lock_buffer_en;
	resp.ccu_jfc_property_en = dev->caps.ccu_jfc_property_en;
	resp.lock_buf_bb_shift = dev->caps.lock_buf_bb_shift;
	resp.atomic_add_en = dev->caps.atomic_add_en;
	resp.u_dtu_enable = dtu_en;
	resp.dtu_va_base = dev->dtu_info.va_base;
	resp.dtu_va_size = dev->dtu_info.pa_size;
	resp.ccu_jetty_start_id = dev->caps.ccu_jetty.start_idx;
	resp.ccu_jetty_max_cnt = dev->caps.ccu_jetty.max_cnt;
	resp.hugepage_enable = ubase_adev_prealloc_supported(dev->comdev.adev) & hugepage_enable;
	resp.sva_sep_mode_en = dev->caps.sva_sep_mode_en;
	resp.st64b_en = dev->caps.st64b_en;

	byte = copy_to_user((void *)(uintptr_t)udrv_data->out_addr, &resp,
			   (uint32_t)sizeof(resp));
	if (byte) {
		dev_err(dev->dev,
			"copy ctx resp to user failed, byte = %lu.\n", byte);
		return -EFAULT;
	}

	return 0;
}

static void udma_put_usva_tid(struct udma_dev *dev, struct udma_context *ctx)
{
	struct udma_seg_tree *to_destroy = NULL;

	if (dev->caps.sva_sep_mode_en) {
		mutex_lock(&g_seg_tree_mutex);
		if (refcount_dec_and_test(&ctx->seg_tree->ctx_refcnt))
			to_destroy = __xa_erase(&g_seg_tree_table, ctx->tid);
		mutex_unlock(&g_seg_tree_mutex);
		if (to_destroy)
			udma_seg_tree_destroy(to_destroy);

		ummu_core_free_tdev(ctx->ummu_dev);
	} else {
		iommu_sva_unbind_device_isolated(ctx->sva);
	}
}

static int udma_get_usva_tid(struct udma_dev *dev, struct udma_context *ctx)
{
	struct tdev_opt opt = { current->mm, true };
	int ret = -ENOMEM;

	if (dev->caps.sva_sep_mode_en) {
		ctx->tid = UMMU_INVALID_TID;
		ctx->ummu_dev = ummu_core_alloc_separate_tdev(&opt, &ctx->tid);
		if (!ctx->ummu_dev) {
			dev_err(dev->dev, "failed to alloc separate pages USVA device.\n");
			goto err_alloc_tdev_separated;
		}

		mutex_lock(&g_seg_tree_mutex);
		ctx->seg_tree = xa_load(&g_seg_tree_table, ctx->tid);
		if (ctx->seg_tree) {
			refcount_inc(&ctx->seg_tree->ctx_refcnt);
			ret = 0;
		} else {
			ctx->seg_tree = udma_seg_tree_init();
			if (!ctx->seg_tree) {
				dev_err(dev->dev, "failed to init segment_range.\n");
				goto err_segment_range_init;
			}
			ret = xa_err(__xa_store(&g_seg_tree_table, ctx->tid,
						ctx->seg_tree, GFP_ATOMIC));
			if (ret) {
				dev_err(dev->dev, "failed to store segment_range, ret=%d.\n", ret);
				goto err_segment_range_store;
			}
		}
		mutex_unlock(&g_seg_tree_mutex);
	} else {
		ctx->sva = iommu_sva_bind_device_isolated(dev->dev, current->mm, NULL);
		if (IS_ERR(ctx->sva)) {
			dev_err(dev->dev, "SVA failed to bind device.\n");
			return -EINVAL;
		}

		ret = ummu_get_tid(dev->dev, ctx->sva, &ctx->tid);
		if (ret) {
			dev_err(dev->dev, "failed to get TID, ret = %d.\n", ret);
			iommu_sva_unbind_device_isolated(ctx->sva);
		}
	}

	return ret;

err_segment_range_store:
	udma_seg_tree_destroy(ctx->seg_tree);
err_segment_range_init:
	mutex_unlock(&g_seg_tree_mutex);
	ummu_core_free_tdev(ctx->ummu_dev);
err_alloc_tdev_separated:

	return ret;
}

struct ubcore_ucontext *udma_alloc_ucontext(struct ubcore_device *ub_dev,
					    uint32_t eid_index,
					    struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *dev = to_udma_dev(ub_dev);
	struct udma_context *ctx;
	int ret;

	ctx = kzalloc(sizeof(struct udma_context), GFP_KERNEL);
	if (ctx == NULL)
		return NULL;

	ret = udma_get_usva_tid(dev, ctx);
	if (ret) {
		dev_err(dev->dev, "failed to get USVA TID, ret = %d.\n", ret);
		goto err_free_ctx;
	}
	ctx->dtu_en = dev->dtu_info.u_dtu_enable;
	ret = udma_set_dtu_va_info(dev, ctx);
	if (ret) {
		dev_warn(dev->dev, "Could not set DTU, ret = %d.\n", ret);
		ctx->dtu_en = false;
	}
	ctx->dev = dev;
	ctx->mm = current->mm;
	INIT_LIST_HEAD(&ctx->pgdir_list);
	mutex_init(&ctx->pgdir_mutex);
	INIT_LIST_HEAD(&ctx->hugepage_list);
	mutex_init(&ctx->hugepage_lock);
	INIT_LIST_HEAD(&ctx->page_list);
	mutex_init(&ctx->page_lock);

	ret = udma_init_ctx_resp(dev, udrv_data, ctx->dtu_en);
	if (ret) {
		dev_err(dev->dev, "init context response failed.\n");
		goto err_init_ctx_resp;
	}

	return &ctx->base;

err_init_ctx_resp:
	mutex_destroy(&ctx->page_lock);
	mutex_destroy(&ctx->hugepage_lock);
	mutex_destroy(&ctx->pgdir_mutex);
	udma_unset_dtu_va_info(dev, ctx);
	udma_put_usva_tid(dev, ctx);
err_free_ctx:
	kfree(ctx);

	return NULL;
}

int udma_free_ucontext(struct ubcore_ucontext *ucontext)
{
	struct udma_dev *udma_dev = to_udma_dev(ucontext->ub_dev);
	struct udma_hugepage_priv *priv;
	struct udma_hugepage_priv *tmp;
	struct vm_area_struct *vma;
	struct udma_context *ctx;
	uint32_t i;

	ctx = to_udma_context(ucontext);

	mutex_destroy(&ctx->pgdir_mutex);
	udma_unset_dtu_va_info(udma_dev, ctx);
	udma_put_usva_tid(udma_dev, ctx);

	mutex_lock(&ctx->hugepage_lock);
	list_for_each_entry_safe(priv, tmp, &ctx->hugepage_list, list) {
		list_del(&priv->list);
		if (ctx->dev->caps.sva_sep_mode_en) {
			udma_ioummu_unmap(ctx->tid, UMMU_INVALID_TID,
					  (uintptr_t)priv->va_base, priv->va_len);
			sg_free_table(&priv->sgt);
		}
		if (current->mm) {
			mmap_write_lock(current->mm);
			vma = find_vma(current->mm, (unsigned long)priv->va_base);
			if (vma != NULL && vma->vm_start <= (unsigned long)priv->va_base &&
			    vma->vm_end >= (unsigned long)(priv->va_base + priv->va_len))
				zap_vma_ptes(vma, (unsigned long)priv->va_base, priv->va_len);
			mmap_write_unlock(current->mm);
		}

		dev_info_ratelimited(udma_dev->dev, "free_hugepage, seq=%u.\n", priv->seq);
		for (i = 0; i < priv->page_num; i++)
			udma_free_pages(priv->pages[i], get_order(priv->page_size));
		kfree(priv->pages);
		kfree(priv);
	}
	mutex_unlock(&ctx->hugepage_lock);
	mutex_destroy(&ctx->hugepage_lock);
	mutex_destroy(&ctx->page_lock);
	kfree(ctx);

	return 0;
}

static int udma_mmap_jetty_dsqe(struct udma_dev *dev, struct ubcore_ucontext *uctx,
				struct vm_area_struct *vma)
{
	struct ubcore_ucontext *jetty_uctx;
	struct udma_jetty_queue *sq;
	uint64_t address;
	uint64_t j_id;

	j_id = get_mmap_idx(vma);

	xa_lock(&dev->jetty_table.xa);
	sq = xa_load(&dev->jetty_table.xa, j_id);
	if (!sq) {
		xa_unlock(&dev->jetty_table.xa);
		dev_err(dev->dev,
			"mmap failed, j_id: %llu not exist\n", j_id);
		return -EINVAL;
	}

	if (sq->is_jetty)
		jetty_uctx = to_udma_jetty_from_queue(sq)->ubcore_jetty.uctx;
	else
		jetty_uctx = to_udma_jfs_from_queue(sq)->ubcore_jfs.uctx;

	if (jetty_uctx != uctx) {
		xa_unlock(&dev->jetty_table.xa);
		dev_err(dev->dev,
			"mmap failed, j_id: %llu, uctx invalid\n", j_id);
		return -EINVAL;
	}
	xa_unlock(&dev->jetty_table.xa);

	address = (uint64_t)dev->db_base + JETTY_DSQE_OFFSET + j_id * UDMA_HW_PAGE_SIZE;

	if (io_remap_pfn_range(vma, vma->vm_start, address >> PAGE_SHIFT,
			       PAGE_SIZE, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static int udma_check_mmap_size(struct udma_dev *dev, struct vm_area_struct *vma,
				uint32_t align_size)
{
	uint32_t max_map_size = dev->caps.cqe_size * dev->caps.jfc.depth;
	uint32_t map_size = vma->vm_end - vma->vm_start;

	if (!IS_ALIGNED(map_size, align_size)) {
		dev_err(dev->dev, "mmap size is not alignment.\n");
		return -EINVAL;
	}

	if (map_size == 0) {
		dev_err(dev->dev, "mmap size is zero.\n");
		return -EINVAL;
	}

	if (map_size > max_map_size) {
		dev_err(dev->dev, "mmap size(%u) is greater than the max_size.\n",
			map_size);
		return -EINVAL;
	}

	return 0;
}

static struct udma_page_priv *
udma_alloc_page_priv(struct udma_context *ctx, struct vm_area_struct *vma, uint32_t page_num)
{
	struct udma_page_priv *priv;
	uint32_t i;
	gfp_t flag;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->page_num = page_num;
	priv->pages = kcalloc(priv->page_num, sizeof(*priv->pages), GFP_KERNEL);
	if (!priv->pages)
		goto err_alloc_arr;

	if (debug_switch)
		dev_info_ratelimited(ctx->dev->dev, "vm_flags=0x%lx, vm_page_prot=0x%llx.\n",
				     vma->vm_flags, vma->vm_page_prot.pgprot);

	vma->vm_page_prot = __pgprot(((~PTE_ATTRINDX_MASK) & vma->vm_page_prot.pgprot) |
				     PTE_ATTRINDX(MT_NORMAL));
	for (i = 0; i < priv->page_num; i++) {
		flag = ctx->dev->caps.non_mirror_en == true ? (GFP_HIGHUSER_MOVABLE | __GFP_ZERO) :
			(GFP_KERNEL | __GFP_ZERO);
		priv->pages[i] = udma_alloc_pages(flag, 0);
		if (!priv->pages[i]) {
			dev_err(ctx->dev->dev, "failed to alloc normal page.\n");
			goto err_alloc_pages;
		}
		ret = remap_pfn_range(vma, vma->vm_start + i * PAGE_SIZE,
				      page_to_pfn(priv->pages[i]), PAGE_SIZE,
				      vma->vm_page_prot);
		if (ret) {
			dev_err(ctx->dev->dev, "failed to remap PFN range, ret=%d.\n", ret);
			goto err_remap_pfn_range;
		}
	}

	ret = sg_alloc_table_from_pages(&priv->sgt, priv->pages, priv->page_num, 0,
					priv->page_num << PAGE_SHIFT, GFP_KERNEL);
	if (ret) {
		dev_err(ctx->dev->dev, "failed to create SG table, ret=%d.\n", ret);
		goto err_remap_pfn_range;
	}
	priv->va_base = (void *)vma->vm_start;
	priv->va_len = priv->page_num << PAGE_SHIFT;

	if (debug_switch)
		dev_info_ratelimited(ctx->dev->dev, "map normal page, page num=%u.\n",
				     priv->page_num);
	return priv;

err_remap_pfn_range:
	zap_vma_ptes(vma, vma->vm_start, i * PAGE_SIZE);
err_alloc_pages:
	for (i = 0; i < priv->page_num; i++) {
		if (priv->pages[i])
			udma_free_pages(priv->pages[i], 0);
		else
			break;
	}
	kfree(priv->pages);
err_alloc_arr:
	kfree(priv);

	return NULL;
}

static int udma_mmap_kernel_buf(struct udma_dev *dev, struct ubcore_ucontext *uctx,
			      struct vm_area_struct *vma)
{
	if (udma_check_mmap_size(dev, vma, PAGE_SIZE))
		return -EINVAL;

	vm_flags_set(vma, VM_WIPEONFORK | VM_DONTEXPAND | VM_DONTDUMP |
			  VM_DONTCOPY | VM_PFNMAP | VM_LOCKED | VM_WRITE | VM_IO);

	return 0;
}

int udma_mmap(struct ubcore_ucontext *uctx, struct vm_area_struct *vma)
{
#define JFC_DB_UNMAP_BOUND 1
	struct udma_dev *udma_dev = to_udma_dev(uctx->ub_dev);
	uint64_t vm_size = vma->vm_end - vma->vm_start;
	uint32_t cmd;

	if ((vm_size % PAGE_SIZE) != 0) {
		dev_err(udma_dev->dev, "mmap failed, unexpected vm area size.\n");
		return -EINVAL;
	}

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	cmd = get_mmap_cmd(vma);
	switch (cmd) {
	case UDMA_MMAP_JFC_PAGE:
		if (io_remap_pfn_range(vma, vma->vm_start,
				       jfc_arm_mode > JFC_DB_UNMAP_BOUND ?
				       (uint64_t)udma_dev->db_base >> PAGE_SHIFT :
				       page_to_pfn(udma_dev->db_page),
				       PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		break;
	case UDMA_MMAP_JETTY_DSQE:
		return udma_mmap_jetty_dsqe(udma_dev, uctx, vma);
	case UDMA_MMAP_HUGEPAGE:
		if (udma_check_mmap_size(udma_dev, vma, UDMA_HUGEPAGE_SIZE))
			return -EINVAL;

		vm_flags_set(vma, VM_WIPEONFORK | VM_DONTEXPAND | VM_DONTDUMP |
			     VM_DONTCOPY | VM_PFNMAP | VM_LOCKED | VM_WRITE | VM_IO);
		vma->vm_page_prot = __pgprot(((~PTE_ATTRINDX_MASK) & vma->vm_page_prot.pgprot)
					     | PTE_ATTRINDX(MT_NORMAL));
		break;
	case UDMA_MMAP_RESERVED_SQ:
		if (vma->vm_start != udma_dev->sq_reserved_info.va_start) {
			dev_err(udma_dev->dev, "mmap failed, invalid vm_start.\n");
			return -EINVAL;
		}

		if (vm_size != udma_dev->sq_reserved_info.va_size) {
			dev_err(udma_dev->dev, "mmap failed, invalid vm_size=0x%llx.\n", vm_size);
			return -EINVAL;
		}

		vm_flags_set(vma, VM_WIPEONFORK | VM_DONTEXPAND | VM_DONTDUMP |
			     VM_DONTCOPY | VM_PFNMAP | VM_LOCKED | VM_WRITE | VM_IO);
		vma->vm_page_prot = __pgprot(((~PTE_ATTRINDX_MASK) & vma->vm_page_prot.pgprot)
					     | PTE_ATTRINDX(MT_NORMAL));
		break;
	case UDMA_MMAP_KERNEL_BUF:
		return udma_mmap_kernel_buf(udma_dev, uctx, vma);
	default:
		dev_err(udma_dev->dev, "mmap failed, command(%u) not support\n", cmd);
		return -EINVAL;
	}

	return 0;
}

int udma_create_sgt_from_pages(struct sg_table *sgt, struct page **pages,
			       uint32_t page_num, uint32_t page_size)
{
	struct scatterlist *sg;
	uint32_t i;

	if (sg_alloc_table(sgt, page_num, GFP_KERNEL))
		return -ENOMEM;

	sg = sgt->sgl;
	for (i = 0; i < page_num; i++, sg = sg_next(sg)) {
		sg_set_page(sg, pages[i], page_size, 0);
		if (i == page_num - 1)
			sg_mark_end(sg);
	}

	return 0;
}

static inline bool udma_check_vma_flags(struct vm_area_struct *vma)
{
	//TODO: Check user va and length
	return (vma->vm_flags & VM_WIPEONFORK) && (vma->vm_flags & VM_DONTEXPAND) &&
	       (vma->vm_flags & VM_DONTCOPY) && (vma->vm_flags & VM_IO);
}

static struct udma_page_priv *
udma_get_page_priv(struct udma_context *ctx, uint64_t va, uint32_t len)
{
	unsigned long align_size = PAGE_ALIGN(len);
	struct udma_page_priv *priv;
	struct vm_area_struct *vma;
	int ret = 0;

	mmap_write_lock(current->mm);
	vma = find_vma(current->mm, va);
	if (vma == NULL || vma->vm_start != va || vma->vm_end < va + align_size ||
	    va & ~PAGE_MASK || vma->vm_end & ~PAGE_MASK) {
		dev_err(ctx->dev->dev, "failed to find VMA.\n");
		ret = -EINVAL;
		goto err_unlock;
	}

	// zap vma ptes before remap to avoid existed page
	zap_vma_ptes(vma, (unsigned long)va, align_size);
	if (!udma_check_vma_flags(vma)) {
		dev_err(ctx->dev->dev, "failed to check VMA flags.\n");
		ret = -EINVAL;
		goto err_unlock;
	}

	priv = udma_alloc_page_priv(ctx, vma, align_size >> PAGE_SHIFT);
	if (!priv) {
		dev_err(ctx->dev->dev, "failed to alloc page priv.\n");
		ret = -EINVAL;
	}
err_unlock:
	mmap_write_unlock(current->mm);

	return ret ? NULL : priv;
}

static void udma_free_page_priv(struct udma_context *ctx, struct udma_page_priv *priv)
{
	struct vm_area_struct *vma;
	uint32_t i;

	sg_free_table(&priv->sgt);
	if (current->mm) {
		mmap_write_lock(current->mm);
		vma = find_vma(current->mm, (unsigned long)priv->va_base);
		if (vma != NULL && vma->vm_start <= (unsigned long)priv->va_base &&
		    vma->vm_end >= (unsigned long)(priv->va_base + priv->va_len))
			zap_vma_ptes(vma, (unsigned long)priv->va_base, priv->va_len);
		mmap_write_unlock(current->mm);
	} else {
		dev_warn_ratelimited(ctx->dev->dev, "current mm released.\n");
	}

	for (i = 0; i < priv->page_num; i++)
		udma_free_pages(priv->pages[i], 0);

	kfree(priv->pages);
	priv->pages = NULL;
	kfree(priv);
	priv = NULL;
}

struct udma_page_priv *udma_get_map_page_priv(struct udma_context *ctx, uint64_t va, uint32_t len)
{
	struct udma_page_priv *priv;
	int ret;

	priv = udma_get_page_priv(ctx, va, len);
	if (priv == NULL)
		return priv;

	if (ctx->dev->caps.sva_sep_mode_en) {
		ret = udma_ioummu_map(ctx->tid, UMMU_INVALID_TID, IOMMU_READ | IOMMU_WRITE,
				      (uint64_t)priv->va_base, &(priv->sgt));
		if (ret) {
			dev_err(ctx->dev->dev, "UDMA IOMMU map failed, ret = %d.\n", ret);
			udma_free_page_priv(ctx, priv);
			return NULL;
		}
	}

	return priv;
}

void udma_put_map_page_priv(struct udma_context *ctx, struct udma_page_priv *priv)
{
	if (ctx->dev->caps.sva_sep_mode_en)
		udma_ioummu_unmap(ctx->tid, UMMU_INVALID_TID,
				  (uintptr_t)priv->va_base, priv->va_len);

	udma_free_page_priv(ctx, priv);
}

static struct udma_hugepage_priv *udma_list_find_before(struct udma_context *ctx, uint64_t va)
{
	struct udma_hugepage_priv *priv;

	list_for_each_entry(priv, &ctx->hugepage_list, list) {
		if (va >= (uintptr_t)priv->va_base &&
		    va < (uintptr_t)(priv->va_base + priv->va_len))
			return priv;
	}

	return NULL;
}

static void udma_unremap_hugepage(struct vm_area_struct *vma, struct udma_hugepage_priv *priv,
				  uint32_t remaped_num)
{
	uint32_t i;

	if (remaped_num)
		zap_vma_ptes(vma, vma->vm_start, remaped_num * priv->page_size);

	for (i = 0; i < priv->page_num; i++) {
		if (priv->pages[i])
			udma_free_pages(priv->pages[i], get_order(priv->page_size));
		else
			break;
	}

	kfree(priv->pages);
	priv->pages = NULL;
}

static int udma_remap_hugepage(struct udma_context *ctx, struct vm_area_struct *vma,
			       struct udma_hugepage_priv *priv, uint32_t page_shift)
{
	int ret = -ENOMEM;
	uint32_t i;
	gfp_t flag;

	priv->page_size = 1 << page_shift;
	priv->page_num = (vma->vm_end - vma->vm_start) >> page_shift;
	priv->pages = kcalloc(priv->page_num, sizeof(*priv->pages), GFP_KERNEL);
	if (!priv->pages)
		return ret;

	if (debug_switch)
		dev_info_ratelimited(ctx->dev->dev, "vm_flags=0x%lx, vm_page_prot=0x%llx.\n",
				     vma->vm_flags, vma->vm_page_prot.pgprot);

	zap_vma_ptes(vma, vma->vm_start, priv->page_num << page_shift);
	for (i = 0; i < priv->page_num; i++) {
		flag = ctx->dev->caps.non_mirror_en == true ?
			(GFP_HIGHUSER_MOVABLE | __GFP_NOWARN | __GFP_ZERO) :
			(GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
		priv->pages[i] = udma_alloc_pages(flag, get_order(priv->page_size));
		if (!priv->pages[i]) {
			dev_err(ctx->dev->dev, "failed to alloc pages.\n");
			goto err_alloc_pages;
		}
		ret = udma_remap_pfn_range(vma, vma->vm_start + i * priv->page_size,
					   page_to_pfn(priv->pages[i]), priv->page_size,
					   vma->vm_page_prot);
		if (ret) {
			dev_err(ctx->dev->dev, "failed to remap PFN range, ret=%d.\n", ret);
			goto err_remap_pfn_range;
		}
	}

	priv->va_base = (void *)vma->vm_start;
	priv->va_len = priv->page_num << page_shift;
	priv->left_va_len = priv->va_len;
	refcount_set(&priv->refcnt, 1);
	priv->seq = (uint32_t)atomic_inc_return(&ctx->dev->hugepage_seq);

	return ret;

err_remap_pfn_range:
err_alloc_pages:
	udma_unremap_hugepage(vma, priv, i);

	return -ENOMEM;
}

static struct udma_hugepage_priv *
udma_alloc_u_hugepage_priv(struct udma_context *ctx, struct vm_area_struct *vma)
{
	struct udma_hugepage_priv *priv = NULL;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	if (udma_remap_hugepage(ctx, vma, priv, UDMA_HUGEPAGE_SHIFT)) {
		dev_warn(ctx->dev->dev,
			 "failed to alloc hugepage buf, switch to alloc normal buf.\n");
		if (udma_remap_hugepage(ctx, vma, priv, PAGE_SHIFT))
			goto err_remap_hugepage;
	}

	if (ctx->dev->caps.sva_sep_mode_en) {
		ret = udma_create_sgt_from_pages(&priv->sgt, priv->pages, priv->page_num,
						 priv->page_size);
		if (ret) {
			dev_err(ctx->dev->dev, "failed to create SG table, ret=%d.\n", ret);
			goto err_create_sgt_from_pages;
		}

		ret = udma_ioummu_map(ctx->tid, UMMU_INVALID_TID, IOMMU_READ | IOMMU_WRITE,
				      vma->vm_start, &priv->sgt);
		if (ret) {
			dev_err(ctx->dev->dev, "failed to map SGT, ret = %d.\n", ret);
			goto err_ioummu_map;
		}
	}

	list_add(&priv->list, &ctx->hugepage_list);

	if (debug_switch)
		dev_info_ratelimited(ctx->dev->dev,
			"alloc_hugepage, seq=%u, 2m_page_num=%u.\n",
			priv->seq, priv->va_len >> UDMA_HUGEPAGE_SHIFT);
	return priv;

err_ioummu_map:
	if (ctx->dev->caps.sva_sep_mode_en)
		sg_free_table(&priv->sgt);
err_create_sgt_from_pages:
	udma_unremap_hugepage(vma, priv, priv->page_num);
err_remap_hugepage:
	kfree(priv);

	return NULL;
}

bool udma_alloc_u_hugepage(struct udma_context *ctx, uint64_t buf_addr, uint32_t buf_len)
{
	struct udma_hugepage_priv *priv = NULL;
	struct vm_area_struct *vma;

	mutex_lock(&ctx->hugepage_lock);
	priv = udma_list_find_before(ctx, buf_addr);
	if (priv) {
		if (debug_switch)
			dev_info_ratelimited(ctx->dev->dev,
				"occupy_hugepage, seq=%u, 4k_page_num=%u.\n",
				priv->seq, buf_len >> UDMA_HW_PAGE_SHIFT);
		refcount_inc(&priv->refcnt);
		goto unlock_hugepage;
	} else {
		mmap_write_lock(current->mm);
		vma = find_vma(current->mm, buf_addr);
		if (vma == NULL || vma->vm_start > buf_addr || vma->vm_end < buf_addr + buf_len) {
			dev_err(ctx->dev->dev, "failed to find_vma.\n");
			goto unlock_mm;
		}

		if (udma_check_mmap_size(ctx->dev, vma, UDMA_HUGEPAGE_SIZE))
			goto unlock_mm;

		if (!udma_check_vma_flags(vma)) {
			dev_err(ctx->dev->dev, "failed to check VMA flags.\n");
			goto unlock_mm;
		}

		priv = udma_alloc_u_hugepage_priv(ctx, vma);
	}

unlock_mm:
	mmap_write_unlock(current->mm);
unlock_hugepage:
	mutex_unlock(&ctx->hugepage_lock);

	return priv != NULL;
}

void udma_free_u_hugepage(struct udma_context *ctx, uint64_t buf_addr)
{
	struct udma_hugepage_priv *priv;
	struct vm_area_struct *vma;
	uint32_t i;

	mutex_lock(&ctx->hugepage_lock);
	priv = udma_list_find_before(ctx, buf_addr);
	if (!priv) {
		mutex_unlock(&ctx->hugepage_lock);
		dev_warn(ctx->dev->dev, "buffer address is invalid address.\n");
		return;
	}

	if (!refcount_dec_and_test(&priv->refcnt)) {
		mutex_unlock(&ctx->hugepage_lock);
		if (debug_switch)
			dev_info_ratelimited(ctx->dev->dev,
					     "return_hugepage, seq=%u.\n", priv->seq);
		return;
	} else {
		list_del(&priv->list);
		if (debug_switch)
			dev_info_ratelimited(ctx->dev->dev, "free_hugepage, seq=%u.\n", priv->seq);
	}

	if (ctx->dev->caps.sva_sep_mode_en) {
		udma_ioummu_unmap(ctx->tid, UMMU_INVALID_TID,
				  (uintptr_t)priv->va_base, priv->va_len);
		sg_free_table(&priv->sgt);
	}
	if (current->mm) {
		mmap_write_lock(current->mm);
		vma = find_vma(current->mm, (unsigned long)priv->va_base);
		if (vma != NULL && vma->vm_start <= (unsigned long)priv->va_base &&
		    vma->vm_end >= (unsigned long)(priv->va_base + priv->va_len))
			zap_vma_ptes(vma, (unsigned long)priv->va_base, priv->va_len);
		mmap_write_unlock(current->mm);
	} else {
		dev_warn_ratelimited(ctx->dev->dev, "current mm released.\n");
	}
	mutex_unlock(&ctx->hugepage_lock);

	for (i = 0; i < priv->page_num; i++)
		udma_free_pages(priv->pages[i], get_order(priv->page_size));

	kfree(priv->pages);
	kfree(priv);
}
