// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2025-05-14
 *   - Fixed Hygon platform flicker: changed memory mapping to __phys_to_pfn
 * Modified: 2026-03-30
 *   - Removed LINUX_VERSION_CODE macros for checkpatch.pl compliance
 */

#include <linux/dma-buf.h>
#include <asm/set_memory.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/export.h>
#include <linux/dma-buf.h>
#include <linux/rbtree.h>

#include <drm/drm.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_gem.h>
#include <drm/drm_prime.h>

#include "vs_drv.h"
#include "vs_gem.h"
#include "vs_egt_drm.h"

static const struct drm_gem_object_funcs vs_gem_default_funcs;

static void nonseq_free(struct page **pages, unsigned int nr_page)
{
	u32 i;

	if (!pages)
		return;

	for (i = 0; i < nr_page; i++)
		__free_page(pages[i]);
}

static void put_pages(unsigned int nr_page, struct vs_gem_object *vs_obj)
{
	u32 i;

	for (i = 0; i < nr_page; i++)
		ClearPageReserved(vs_obj->pages[i]);

#ifdef CONFIG_X86
	set_pages_array_wb(vs_obj->pages, nr_page);
#endif

	nonseq_free(vs_obj->pages, nr_page);
}

#ifdef CONFIG_ENGIANT_VS_MMU
static int get_pages(unsigned int nr_page, struct vs_gem_object *vs_obj)
{
	struct page *pages;
	u32 i, num_page, page_count = 0;
	int order = 0;
	gfp_t gfp = GFP_KERNEL;

	if (!vs_obj->pages)
		return -EINVAL;

	gfp &= ~__GFP_HIGHMEM;
	gfp |= __GFP_DMA32;

	num_page = nr_page;

	do {
		pages = NULL;
		order = get_order(num_page * PAGE_SIZE);
		num_page = 1 << order;

		if ((num_page + page_count > nr_page) || (order >= MAX_ORDER)) {
			num_page = num_page >> 1;
			continue;
		}

		pages = alloc_pages(gfp, order);
		if (!pages) {
			if (num_page == 1) {
				nonseq_free(vs_obj->pages, page_count);
				return -ENOMEM;
			}

			num_page = num_page >> 1;
		} else {
			for (i = 0; i < num_page; i++) {
				vs_obj->pages[page_count + i] = &pages[i];
				SetPageReserved(vs_obj->pages[page_count + i]);
			}

			page_count += num_page;
			num_page = nr_page - page_count;
		}
	} while (page_count < nr_page);

#ifdef CONFIG_X86
	if (set_pages_array_uc(vs_obj->pages, nr_page))
		DRM_DEV_ERROR(vs_obj->base.dev->dev, "failed to set_pages_array_uc.\n");
#endif

	vs_obj->get_pages = true;

	return 0;
}
#endif

#ifdef CONFIG_ENGIANT_VS_MMU
static void _vs_mmu_free_buf(struct vs_gem_object *vs_obj)
{
	struct drm_device *dev = vs_obj->base.dev;
	struct vs_drm_private *priv = dev->dev_private;
	unsigned int nr_pages;

	if (!priv->mmu) {
		DRM_DEV_ERROR(dev->dev, "invalid mmu.\n");
		return;
	}

	nr_pages = vs_obj->size >> PAGE_SHIFT;
	egt_dc_mmu_unmap_memory(priv->mmu, (u32)vs_obj->iova, nr_pages);
}
#endif

static __maybe_unused void vs_gem_free_buf(struct vs_gem_object *vs_obj)
{
	struct drm_device *dev = vs_obj->base.dev;
#ifdef CONFIG_ENGIANT_VS_MMU
	struct vs_drm_private *priv = dev->dev_private;
	unsigned int nr_pages;
#endif

	if ((!vs_obj->get_pages) && (!vs_obj->dma_addr)) {
		DRM_DEV_DEBUG_KMS(dev->dev, "dma_addr is invalid.\n");
		return;
	}

#ifdef CONFIG_ENGIANT_VS_MMU
	if (!priv->mmu) {
		DRM_DEV_ERROR(dev->dev, "invalid mmu.\n");
		return;
	}

	nr_pages = vs_obj->size >> PAGE_SHIFT;
	egt_dc_mmu_unmap_memory(priv->mmu, (u32)vs_obj->iova, nr_pages);
#endif

	if (!vs_obj->get_pages) {
#ifdef CONFIG_X86
		set_memory_wb((unsigned long)(vs_obj->cookie), vs_obj->size >> PAGE_SHIFT);
#endif
		dma_free_attrs(to_dma_dev(dev), vs_obj->size, vs_obj->cookie,
				   (dma_addr_t)vs_obj->dma_addr, vs_obj->dma_attrs);
	} else {
		put_pages(vs_obj->size >> PAGE_SHIFT, vs_obj);
	}

	kvfree(vs_obj->pages);
}

void vs_egt_gem_free_object(struct drm_gem_object *obj)
{
	struct vs_gem_object *vs_obj = to_vs_gem_object(obj);
	struct pci_dev *pdev = to_pci_dev(obj->dev->dev);

	if (vs_obj->vram) {
		pr_debug("Free drm_mm_node address is %pa\n", &(vs_obj->vram->start));

		drm_mm_remove_node(vs_obj->vram);
		kfree(vs_obj->vram);
		vs_obj->vram = NULL;
	} else if (obj->import_attach) {
		drm_prime_gem_destroy(obj, vs_obj->sgt);
	}

	/* Unmap CPU address if mapped */
	if (vs_obj->cpu_addr) {
		pci_iounmap(pdev, vs_obj->cpu_addr);
		vs_obj->cpu_addr = NULL;
	}

	/* Release mmap offset */
	drm_gem_free_mmap_offset(obj);

	drm_gem_object_release(obj);

	kfree(vs_obj);
}

static struct vs_gem_object *vs_gem_alloc_object(struct drm_device *dev, size_t size)
{
	struct vs_gem_object *vs_obj;
	struct drm_gem_object *obj;
	int ret;

	vs_obj = kzalloc(sizeof(*vs_obj), GFP_KERNEL);
	if (!vs_obj)
		return ERR_PTR(-ENOMEM);

	vs_obj->size = size;
	obj = &vs_obj->base;

	ret = drm_gem_object_init(dev, obj, size);
	if (ret)
		goto err_free;

	vs_obj->base.funcs = &vs_gem_default_funcs;
	ret = drm_gem_create_mmap_offset(obj);
	if (ret) {
		drm_gem_object_release(obj);
		goto err_free;
	}

	return vs_obj;

err_free:
	kfree(vs_obj);
	return ERR_PTR(ret);
}

struct vs_gem_object *vs_egt_gem_create_object(struct drm_device *dev, size_t size)
{
	struct vs_gem_object *vs_obj;

	size = PAGE_ALIGN(size);

	vs_obj = vs_gem_alloc_object(dev, size);
	if (IS_ERR(vs_obj))
		return vs_obj;

	return vs_obj;
}

struct drm_gem_object *vs_egt_gem_create_with_handle(struct drm_device *dev,
						size_t size, struct vs_gem_private *gem_priv)
{
	struct vs_gem_object *vs_obj;
	struct drm_mm_node *node;
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	int ret;

	vs_obj = vs_egt_gem_create_object(dev, size);
	if (IS_ERR(vs_obj))
		return ERR_PTR(PTR_ERR(vs_obj));

	/*create drm mm node*/
	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		ret = -ENOMEM;
		goto err_free_vs_obj;
	}

	mutex_lock(&gem_priv->vram_lock);
	ret = drm_mm_insert_node(&gem_priv->vram, node, size);
	mutex_unlock(&gem_priv->vram_lock);
	if (ret) {
		pr_err("Failed to create drm_mm_insert_node\n");
		kfree(node);
		goto err_free_vs_obj;
	}

	/*alloc device memory*/
	vs_obj->vram = node;
	vs_obj->dma_addr = vs_obj->vram->start;
	vs_obj->resv = vs_obj->base.resv;
	vs_obj->cpu_addr = pci_iomap_range(pdev, 2, 0, pci_resource_len(pdev, 2));
	if (!vs_obj->cpu_addr) {
		ret = -ENOMEM;
		goto err_free_vs_obj;
	}
	vs_obj->offset = vs_obj->dma_addr-(u64)gem_priv->pci_addr;

	pr_debug("alloc device memory address is %pad  offset = %#llx size = %#llx\n",
			&vs_obj->dma_addr,
			(unsigned long long)vs_obj->offset,
			(unsigned long long)vs_obj->vram->size);

	return &vs_obj->base;

err_free_vs_obj:
	vs_egt_gem_free_object(&vs_obj->base);
	return ERR_PTR(ret);
}

u64 vs_egt_gem_get_dev_addr(struct drm_gem_object *obj)
{
	struct vs_gem_object *vs_obj = to_vs_gem_object(obj);

	return vs_obj->dma_addr;
}

static int vs_egt_gem_mmap_obj(struct drm_gem_object *obj, struct vm_area_struct *vma)
{
	struct vs_gem_object *vs_obj = to_vs_gem_object(obj);
	unsigned long vm_size;
	int ret = 0;
	u32 pfn = 0U;
	unsigned long start;

	vm_size = vma->vm_end - vma->vm_start;
	if (vm_size > vs_obj->size)
		return -EINVAL;

	vma->vm_pgoff = 0;

#ifdef CONFIG_X86
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#else
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
#endif

	vm_flags_set(vma, VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP);

	start = vma->vm_start;
	vm_size = PAGE_ALIGN(vm_size);
	pfn = __phys_to_pfn(vs_obj->dma_addr);

	ret = remap_pfn_range(vma, start, pfn, vm_size, vma->vm_page_prot);
	if (ret < 0) {
		pr_err("DRM mmap for user failed: %d\n", ret);
		return ret;
	}

	if (ret)
		drm_gem_vm_close(vma);

	return ret;
}

struct sg_table *vs_egt_gem_prime_get_sg_table(struct drm_gem_object *obj)
{
	struct vs_gem_object *vs_obj = to_vs_gem_object(obj);

	return drm_prime_pages_to_sg(obj->dev, vs_obj->pages, vs_obj->size >> PAGE_SHIFT);
}

static int vs_gem_prime_vmap(__maybe_unused struct drm_gem_object *obj,
				__maybe_unused struct iosys_map *map)
{
	return 0;
}

static void vs_egt_gem_prime_vunmap(__maybe_unused struct drm_gem_object *obj,
				__maybe_unused struct iosys_map *map)
{
	/* Nothing to do */
}

static const struct vm_operations_struct vs_vm_ops = {
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};

static const struct drm_gem_object_funcs vs_gem_default_funcs = {
	.free = vs_egt_gem_free_object,
	.get_sg_table = vs_egt_gem_prime_get_sg_table,
	.vmap = vs_gem_prime_vmap,
	.vunmap = vs_egt_gem_prime_vunmap,
	.vm_ops = &vs_vm_ops,
};

static __maybe_unused int vs_gem_dumb_map_offset(struct drm_file *file,
				struct drm_device *dev,
				uint32_t handle,
				uint64_t *offset)
{
	struct drm_gem_object *obj;
	int err = 0;

	mutex_lock(&dev->struct_mutex);

	obj = drm_gem_object_lookup(file, handle);
	if (!obj) {
		err = -ENOENT;
		goto exit_unlock;
	}

	err = drm_gem_create_mmap_offset(obj);
	if (err)
		goto exit_obj_unref;

	pr_err("mmap offset ret = 0x%x\n", err);

	*offset = drm_vma_node_offset_addr(&obj->vma_node);
exit_obj_unref:
	drm_gem_object_put(obj);
exit_unlock:
	mutex_unlock(&dev->struct_mutex);
	return err;
}

int vs_egt_gem_dumb_create(struct drm_file *file, struct drm_device *dev,
			struct drm_mode_create_dumb *args)
{
	struct vs_drm_private *dev_priv = dev->dev_private;

	return vs_egt_gem_dumb_create_priv(file, dev, dev_priv->gem_priv, args);
}

int vs_egt_gem_dumb_create_priv(struct drm_file *file, struct drm_device *dev,
				struct vs_gem_private *gem_priv,
				struct drm_mode_create_dumb *args)
{
	struct vs_drm_private *priv = dev->dev_private;
	struct drm_gem_object *gem_obj;
	unsigned int pitch = DIV_ROUND_UP(args->width * args->bpp, 8);
	int ret;

	/*1. width align*/
	if (args->bpp % 10)
		args->pitch = ALIGN(pitch, priv->pitch_alignment);
	else
		/* for costum 10bit format with no bit gaps */
		args->pitch = pitch;

	args->size = PAGE_ALIGN(args->pitch * args->height);
	pr_debug("Buffer width x height is %d %d\n", args->width, args->height);

	/*2. create gem_object and  alloc device memory*/
	gem_obj = vs_egt_gem_create_with_handle(dev, args->size, gem_priv);
	if (IS_ERR(gem_obj)) {
		pr_err("Failed to create gem object\n");
		return PTR_ERR(gem_obj);
	}

	/*3. create gem handle*/
	ret = drm_gem_handle_create(file, gem_obj, &args->handle);
	if (ret) {
		pr_err("drm gem handle create failed\n");
		drm_gem_object_put(gem_obj);
		return ret;
	}

	drm_gem_object_put(gem_obj);

	return 0;
}

struct drm_gem_object *vs_egt_gem_prime_import(struct drm_device *dev, struct dma_buf *dma_buf)
{
	return drm_gem_prime_import_dev(dev, dma_buf, to_dma_dev(dev));
}

struct drm_gem_object *vs_egt_gem_prime_import_sg_table(struct drm_device *dev,
							struct dma_buf_attachment *attach,
							struct sg_table *sgt)
{
	struct vs_gem_object *vs_obj;
	int npages;
	int ret;
	size_t size = attach->dmabuf->size;
#ifndef CONFIG_ENGIANT_VS_MMU
	struct scatterlist *s;
	u32 i = 0;
#else
	u32 iova = 0;
	struct vs_drm_private *priv = dev->dev_private;

	if (!priv->mmu) {
		DRM_ERROR("invalid mmu.\n");
		ret = -EINVAL;
		return ERR_PTR(ret);
	}
#endif

	size = PAGE_ALIGN(size);
	vs_obj = vs_gem_alloc_object(dev, size);

	if (IS_ERR(vs_obj))
		return ERR_CAST(vs_obj);

#ifndef CONFIG_ENGIANT_VS_MMU
	for_each_sg(sgt->sgl, s, sgt->nents, i) {
		if (i == 0)
			vs_obj->iova = (u64)sg_dma_address(s);
	}
#endif

	npages = vs_obj->size >> PAGE_SHIFT;
	vs_obj->pages = kvmalloc_array(npages, sizeof(struct page *), GFP_KERNEL);
	if (!vs_obj->pages) {
		ret = -ENOMEM;
		goto err;
	}

	ret = drm_prime_sg_to_page_array(sgt, vs_obj->pages, npages);
	if (ret)
		goto err_free_page;

#ifdef CONFIG_ENGIANT_VS_MMU
	ret = egt_dc_mmu_map_memory(priv->mmu, (u64)vs_obj->pages, npages, &iova, false,
				false);
	if (ret) {
		DRM_ERROR("failed to do mmu map.\n");
		goto err_free_page;
	}

	vs_obj->iova = (u64)iova;
#endif

	vs_obj->dma_addr = sg_dma_address(sgt->sgl);
	vs_obj->sgt = sgt;

	return &vs_obj->base;

err_free_page:
	kvfree(vs_obj->pages);
err:
	vs_egt_gem_free_object(&vs_obj->base);

	return ERR_PTR(ret);
}

int vs_egt_gem_prime_mmap(struct drm_gem_object *obj, struct vm_area_struct *vma)
{
	int ret = 0;

	ret = drm_gem_mmap_obj(obj, obj->size, vma);
	if (ret < 0)
		return ret;

	return vs_egt_gem_mmap_obj(obj, vma);
}

int vs_egt_gem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_gem_object *obj;
	int ret;

	ret = drm_gem_mmap(filp, vma);
	if (ret)
		return ret;

	obj = vma->vm_private_data;

	if (obj->import_attach)
		return dma_buf_mmap(obj->dma_buf, vma, 0);

	return vs_egt_gem_mmap_obj(obj, vma);
}
