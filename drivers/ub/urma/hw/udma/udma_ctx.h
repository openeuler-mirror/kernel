/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_CTX_H__
#define __UDMA_CTX_H__

#include <linux/ummu_core.h>
#include <ub/urma/ubcore_api.h>
#include "udma_dev.h"

struct udma_context {
	struct ubcore_ucontext base;
	struct udma_dev *dev;
	uint32_t uasid;
	struct list_head pgdir_list;
	struct mutex pgdir_mutex;
	struct iommu_sva *sva;
	uint32_t tid;
	struct mutex hugepage_lock;
	struct list_head hugepage_list;
	struct mutex page_lock;
	struct list_head page_list;
	struct device *ummu_dev;
	struct mm_struct *mm;
	struct udma_seg_tree *seg_tree;
	bool dtu_en;
	uint32_t dtu_win_num;
};

static inline struct udma_context *to_udma_context(struct ubcore_ucontext *uctx)
{
	return container_of(uctx, struct udma_context, base);
}

static inline uint64_t get_mmap_idx(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff >> MAP_INDEX_SHIFT) & MAP_INDEX_MASK;
}

static inline uint32_t get_mmap_cmd(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff & MAP_COMMAND_MASK);
}

struct ubcore_ucontext *udma_alloc_ucontext(struct ubcore_device *ub_dev,
					    uint32_t eid_index,
					    struct ubcore_udrv_priv *udrv_data);
int udma_free_ucontext(struct ubcore_ucontext *ucontext);
int udma_mmap(struct ubcore_ucontext *uctx, struct vm_area_struct *vma);

bool udma_alloc_u_hugepage(struct udma_context *ctx, uint64_t buf_addr, uint32_t buf_len);
void udma_free_u_hugepage(struct udma_context *ctx, uint64_t buf_addr);

struct udma_page_priv *udma_get_map_page_priv(struct udma_context *ctx, uint64_t va, uint32_t len);
void udma_put_map_page_priv(struct udma_context *ctx, struct udma_page_priv *priv);
int udma_create_sgt_from_pages(struct sg_table *sgt, struct page **pages, uint32_t page_num,
			       uint32_t page_size);

#endif /* __UDMA_CTX_H__ */
