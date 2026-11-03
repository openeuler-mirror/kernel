// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: export-pool backend and EXPORT ioctl composition.
 */

#include <linux/err.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/huge_mm.h>	/* after mm.h: needs its pgtable/vma context */
#include <linux/pfn_t.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/nodemask.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/types.h>

#include "ubmempool_allocator.h"
#include "conti_mem_allocator.h"
#include "obmm_core.h"
#include "obmm_backend.h"
#include "obmm_export.h"
#include "obmm_export_region_ops.h"
#include "obmm_shm_dev.h"

/* SGL size is specified as an unsigned int. It's best to limit the size of single SGL
 * no larger than (1 << MAX_CHUNK_SHIFT)
 */
#define MAX_CHUNK_SHIFT (31)
#define MAX_CHUNK_SIZE (1U << MAX_CHUNK_SHIFT)
#define MAX_CHUNK_MASK (MAX_CHUNK_SIZE - 1)

static unsigned long size_to_chunk_count(size_t size)
{
	return (size >> MAX_CHUNK_SHIFT) + (unsigned long)((size & MAX_CHUNK_MASK) != 0);
}

static unsigned long memseg_list_to_chunk_count(struct list_head *head)
{
	struct memseg_node *node;
	phys_addr_t start = 0, end = 0;
	unsigned long chunk_count = 0;

	list_for_each_entry(node, head, list) {
		/* whether the new node follows previous ones */
		if (end == node->addr) {
			end += OBMM_MEMSEG_SIZE;
			continue;
		}
		chunk_count += size_to_chunk_count(end - start);

		start = node->addr;
		end = node->addr + OBMM_MEMSEG_SIZE;
	}
	chunk_count += size_to_chunk_count(end - start);
	return chunk_count;
}

static struct scatterlist *fill_sg_chunks(struct scatterlist *s, phys_addr_t start, size_t size,
					  unsigned long *filled_chunks)
{
	size_t chunk_size;
	unsigned long num_chunks_to_fill;

	*filled_chunks = 0;
	num_chunks_to_fill = size_to_chunk_count(size);
	while (num_chunks_to_fill--) {
		if (s == NULL) {
			/* this error is not expected to show up in release version, thus proper
			 * error handling is not included
			 */
			pr_warn_once("bug: scatterlist is not big enough.\n");
			return s;
		}
		chunk_size = size > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : size;
		sg_set_page(s, pfn_to_page(start >> PAGE_SHIFT), chunk_size, 0);
		s = sg_next(s);

		start += chunk_size;
		size -= chunk_size;
		*filled_chunks += 1;
	}
	return s;
}
/* Return the number of chunks to fill in the scatterlist. If @sg is NULL, the
 * function performs a dry run.
 */
static struct scatterlist *fill_sg_list(struct scatterlist *s, struct list_head *head,
					unsigned long *filled_chunks)
{
	struct memseg_node *node;
	phys_addr_t start = 0, end = 0;
	unsigned long chunk_count;

	*filled_chunks = 0;
	list_for_each_entry(node, head, list) {
		/* whether the new node follows previous ones */
		if (end == node->addr) {
			end += OBMM_MEMSEG_SIZE;
			continue;
		}

		if (end != 0) {
			s = fill_sg_chunks(s, start, end - start, &chunk_count);
			*filled_chunks += chunk_count;
		}

		/* track the first piece of new chunk */
		start = node->addr;
		end = node->addr + OBMM_MEMSEG_SIZE;
	}

	if (end != 0) {
		s = fill_sg_chunks(s, start, end - start, &chunk_count);
		*filled_chunks += chunk_count;
	}

	return s;
}

static int sg_alloc_table_from_memdesc(struct sg_table *sgt, struct mem_description_pool *desc,
				       gfp_t gfp_mask)
{
	unsigned long chunk_count, total_chunks, filled_chunks;
	struct scatterlist *s;
	int ret, i;

	total_chunks = 0;
	for (i = 0; i < OBMM_MAX_LOCAL_NUMA_NODES; i++)
		total_chunks += memseg_list_to_chunk_count(&desc->head[i]);
	if (total_chunks == 0) {
		pr_err("%s: no memory.\n", __func__);
		return -EINVAL;
	}

	ret = sg_alloc_table(sgt, total_chunks, gfp_mask);
	if (ret) {
		pr_err("alloc sgt failed.\n");
		return ret;
	}

	s = sgt->sgl;
	filled_chunks = 0;
	for (i = 0; i < OBMM_MAX_LOCAL_NUMA_NODES; i++) {
		s = fill_sg_list(s, &desc->head[i], &chunk_count);
		filled_chunks += chunk_count;
	}

	if (filled_chunks != total_chunks || s != NULL) {
		pr_err("%s: internal error.\n", __func__);
		ret = -ENOTRECOVERABLE;
		goto sg_err;
	}
	return 0;

sg_err:
	sg_free_table(sgt);

	return ret;
}

static int export_pool_alloc_memory(struct obmm_export_pool_backend *pb, u64 export_flags)
{
	bool allow_slow;
	unsigned int i;
	int ret;

	for (i = 0; i < pb->exp.node_count; i++) {
		if (pb->exp.node_mem_size[i] == 0)
			continue;
		if (pb->exp.node_mem_size[i] % OBMM_MEMSEG_SIZE) {
			pr_err("invalid size 0x%llx on node %d: not aligned to mempool granu %#lx\n",
			       pb->exp.node_mem_size[i], i, OBMM_MEMSEG_SIZE);
			return -EINVAL;
		}
	}

	allow_slow = !(export_flags & OBMM_EXPORT_FLAG_FAST);
	pr_debug("export_from_pool: allocation started.\n");
	ret = allocate_memory_contiguous(pb->exp.node_mem_size, pb->exp.node_count, &pb->desc,
					 true, allow_slow);
	if (ret)
		return ret;
	pr_debug("export_from_pool: allocation completed. sgtable preparation started.\n");

	ret = sg_alloc_table_from_memdesc(&pb->exp.sgt, &pb->desc, GFP_KERNEL);
	if (ret) {
		free_memory_contiguous(&pb->desc);
		return ret;
	}
	pr_debug("export_from_pool: sgtable preparation completed.\n");

	return 0;
}

static int calculate_export_region_size(unsigned long *total_size,
					const struct obmm_export_pool_spec *spec)
{
	nodemask_t nodes = NODE_MASK_NONE;
	int i, min_numa_id = NUMA_NO_NODE, max_numa_id = 0;

	if (spec->node_count > OBMM_MAX_LOCAL_NUMA_NODES) {
		pr_err("Size list is too long: max=%d, actual_length=%u\n",
		       OBMM_MAX_LOCAL_NUMA_NODES, spec->node_count);
		return -E2BIG;
	}
	if (spec->pxm_numa >= OBMM_MAX_LOCAL_NUMA_NODES ||
	    spec->pxm_numa < 0) {
		pr_err("Invalid pxm_numa %d\n", spec->pxm_numa);
		return -EINVAL;
	}

	*total_size = 0;
	for (i = 0; i < spec->node_count; i++) {
		if (!IS_ALIGNED(spec->size[i], OBMM_MEMSEG_SIZE)) {
			pr_err("The size of new OBMM region 0x%llx on node %d is not aligned to OBMM memseg size %#lx.\n",
			       spec->size[i], (int)i, OBMM_MEMSEG_SIZE);
			return -EINVAL;
		}
		if (spec->size[i] != 0 && !is_online_local_node(i)) {
			pr_err("Cannot export memory from offlined or remote numa node %d\n",
			       (int)i);
			return -ENODEV;
		}
		if (spec->size[i] != 0) {
			if (*total_size > ULONG_MAX - spec->size[i]) {
				pr_err("Memory size overflowed!\n");
				return -EOVERFLOW;
			}
			if (min_numa_id == NUMA_NO_NODE)
				min_numa_id = i;

			max_numa_id = i;
			*total_size += spec->size[i];
			node_set(i, nodes);
		}
	}
	if (*total_size == 0) {
		pr_err("The size of new OBMM region is 0. Non-zero value expected\n");
		return -EINVAL;
	}
	node_set(spec->pxm_numa, nodes);
	if (!nodes_on_same_package(&nodes)) {
		pr_err("Cannot use memory from multiple sockets or memory and ub controller is from different sockets.\n");
		pr_err("memory numa id ranges: [%d, %d], ub controller pxm: %d.\n", min_numa_id,
			max_numa_id, spec->pxm_numa);
		return -EINVAL;
	}

	return 0;
}

/* teardown_ummu (rolls back on failure), free_memory_contiguous, vendor
 * copy; the object is freed by obmm_backend_put regardless of the result.
 */
static int export_pool_destroy(struct obmm_backend *be)
{
	struct obmm_export_pool_backend *pb = obmm_backend_to_export_pool(be);
	int ret;

	ret = teardown_ummu(&pb->exp);
	if (ret)
		goto out_free_vendor;

	sg_free_table(&pb->exp.sgt);
	free_memory_contiguous(&pb->desc);

out_free_vendor:
	kfree(pb->exp.vendor_info);
	return ret;
}

static vm_fault_t export_pool_pte_fault(struct obmm_export_pool_backend *pb,
					struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	u64 off, phys;

	off = (vma->vm_pgoff << PAGE_SHIFT) + (vmf->address - vma->vm_start);
	if (obmm_export_phys_at(&pb->exp.sgt, off, &phys))
		return VM_FAULT_SIGBUS;

	return vmf_insert_pfn_prot(vma, vmf->address, phys >> PAGE_SHIFT,
				   vma->vm_page_prot);
}

/* ops->fault; the sg table is the only source of truth for the PA. A PMD leaf
 * needs a PMD_SIZE-aligned base and a linear PA proof of the whole
 * [addr, addr + PMD_SIZE) window -- every sg seam inside it must continue the
 * line, since the table follows allocation order, not PA order; a miss on
 * either degrades this page to a PTE.
 */
static vm_fault_t export_pool_fault(struct obmm_backend *be, struct vm_fault *vmf,
				    bool is_pmd)
{
	struct obmm_export_pool_backend *pb = obmm_backend_to_export_pool(be);
	struct vm_area_struct *vma = vmf->vma;
	unsigned long addr, off;
	u64 phys;

	if (!is_pmd)
		return export_pool_pte_fault(pb, vmf);

	addr = vmf->address & PMD_MASK;
	off = (vma->vm_pgoff << PAGE_SHIFT) + (addr - vma->vm_start);
	if (obmm_export_phys_linear_at(&pb->exp.sgt, off, PMD_SIZE, &phys) ||
	    !IS_ALIGNED(phys, PMD_SIZE))
		return export_pool_pte_fault(pb, vmf);

	return vmf_insert_pfn_pmd(vmf, pfn_to_pfn_t(phys >> PAGE_SHIFT),
				  vmf->flags & FAULT_FLAG_WRITE);
}

static int export_pool_flush_range(struct obmm_backend *be, u64 off, u64 len, u8 cache_ops)
{
	return export_flush_sgt(&obmm_backend_to_export_pool(be)->exp.sgt, off, len, cache_ops);
}

static const struct obmm_backend_ops obmm_export_pool_backend_ops = {
	.fault		= export_pool_fault,
	.flush_range	= export_pool_flush_range,
	/* query/covers_pa: shared export ops (obmm_export_region_ops.c) */
	.query		= export_query,
	.covers_pa	= export_covers_pa,
	.destroy	= export_pool_destroy,
};

/*
 * Create an export-pool backend: allocate_memory_contiguous, sg_table
 * build, setup_ummu. The size-list
 * validation runs ONCE, in the ioctl (calculate_export_region_size);
 * @mem_size is that validated sum - a mismatch with the spec would be a
 * caller bug, owned by obmm_backend_attach's WARN_ON_ONCE invariant.
 *
 * spec->vendor_info ownership transfers here (contract in obmm_backend.h):
 * the only pre-ownership failure is the kzalloc below.
 *
 * Returns a backend holding its existence reference (refcnt == 1) or an
 * ERR_PTR.
 */
struct obmm_backend *
obmm_export_pool_backend_create(const struct obmm_export_pool_spec *spec, u64 mem_size)
{
	struct obmm_export_pool_backend *pb;
	int ret;

	pb = kzalloc(sizeof(*pb), GFP_KERNEL);
	if (!pb) {
		/* hand-off not reached: the vendor buffer is still ours */
		kfree(spec->vendor_info);
		return ERR_PTR(-ENOMEM);
	}

	pb->base.type = OBMM_BACKEND_EXPORT_POOLED;
	pb->base.mem_size = mem_size;
	pb->base.mem_cap = OBMM_MEM_ALLOW_CACHEABLE_MMAP | OBMM_MEM_ALLOW_NONCACHEABLE_MMAP;
	pb->base.ops = &obmm_export_pool_backend_ops;
	refcount_set(&pb->base.refcnt, 1); /* the existence reference */

	pb->exp.affinity = spec->pxm_numa;
	memcpy(pb->exp.deid, spec->deid, sizeof(pb->exp.deid));
	memcpy(pb->exp.node_mem_size, spec->size, sizeof(spec->size[0]) * spec->node_count);
	pb->exp.node_count = spec->node_count;
	/* compaction */
	while (pb->exp.node_count > 1 && pb->exp.node_mem_size[pb->exp.node_count - 1] == 0)
		pb->exp.node_count--;

	pb->exp.vendor_info = spec->vendor_info;
	pb->exp.vendor_len = spec->vendor_len;

	ret = export_pool_alloc_memory(pb, spec->export_flags);
	if (ret)
		goto out_free_vendor;

	ret = setup_ummu(&pb->exp);
	if (ret)
		goto out_free_memory;

	return &pb->base;

out_free_memory:
	sg_free_table(&pb->exp.sgt);
	free_memory_contiguous(&pb->desc);
out_free_vendor:
	kfree(pb->exp.vendor_info);
	kfree(pb);
	return ERR_PTR(ret);
}

static void print_export_param(const struct obmm_cmd_export *cmd_export)
{
	pr_debug("obmm_export: len(sizes)=%#llx flags=%#llx deid=" EID_FMT64 " priv_len=%u\n",
		 cmd_export->length, cmd_export->flags, EID_ARGS64_H(cmd_export->deid),
		 EID_ARGS64_L(cmd_export->deid), cmd_export->priv_len);
}

/* Fill the kernel-side pool spec from the uapi command (infallible: the
 * size-list length is validated by calculate_export_region_size's own
 * -E2BIG guard, which runs immediately after this fill and before any
 * state is created; vendor data is copied in later by the caller).
 */
static void pool_spec_from_cmd(const struct obmm_cmd_export *cmd_export,
			       struct obmm_export_pool_spec *spec)
{
	memcpy(spec->size, cmd_export->size, sizeof(spec->size));
	spec->node_count = (u32)cmd_export->length;
	spec->pxm_numa = cmd_export->pxm_numa;
	spec->export_flags = cmd_export->flags;
	memcpy(spec->deid, cmd_export->deid, sizeof(spec->deid));
}

/* obmm_export_from_pool: create an OBMM-exported memory region. The region is
 * physically located on this host and can be accessed from remote host.
 * In OBMM's terminology, it is an export region.
 */
int obmm_export_from_pool(struct obmm_cmd_export *cmd_export)
{
	struct obmm_export_pool_spec spec = { 0 };
	struct obmm_region *reg;
	struct obmm_backend *be;
	unsigned long total_size;
	void *vendor;
	uint64_t uba, mem_id;
	uint32_t token_id;
	int ret;

	print_export_param(cmd_export);

	/* Check the u64 length before pool_spec_from_cmd truncates it to u32;
	 * the -E2BIG guard would otherwise miss 2^32 + n and accept n nodes.
	 */
	if (cmd_export->length > OBMM_MAX_LOCAL_NUMA_NODES) {
		pr_err("Size list is too long: max=%d, actual_length=%llu\n",
		       OBMM_MAX_LOCAL_NUMA_NODES, cmd_export->length);
		return -E2BIG;
	}

	/* arguments to region (logs produced by callee) */
	pool_spec_from_cmd(cmd_export, &spec);
	ret = calculate_export_region_size(&total_size, &spec);
	if (ret)
		return ret;

	reg = kzalloc(sizeof(struct obmm_region), GFP_KERNEL);
	if (reg == NULL)
		return -ENOMEM;

	reg->created_as = OBMM_EXPORT_REGION;
	reg->mem_size = total_size;
	ret = export_flags_to_region_flags(&reg->flags, cmd_export->flags);
	if (ret)
		goto out_free_reg;
	ret = set_obmm_region_priv(reg, cmd_export->priv_len, cmd_export->priv);
	if (ret)
		goto out_free_reg;

	ret = init_obmm_region(reg);
	if (ret)
		goto out_free_reg;

	/* from here on the device core owns the region's memory */
	ret = obmm_shm_dev_init_device(reg);
	if (ret)
		goto out_unit_reg;

	/* hand-off to the creator below, which consumes it on every path (obmm_backend.h) */
	vendor = dup_export_vendor(cmd_export->vendor_info, cmd_export->vendor_len);
	if (IS_ERR(vendor)) {
		ret = PTR_ERR(vendor);
		goto out_dev_put;
	}
	spec.vendor_info = vendor;
	spec.vendor_len = cmd_export->vendor_len;

	be = obmm_export_pool_backend_create(&spec, reg->mem_size);
	if (IS_ERR(be)) {
		ret = PTR_ERR(be);
		pr_err("Failed to prepare export memory: ret=%pe\n", ERR_PTR(ret));
		goto out_dev_put;
	}

	token_id = obmm_backend_to_export_common(be)->tokenid;
	uba = obmm_backend_to_export_common(be)->uba;
	mem_id = (uint64_t)reg->regionid;

	ret = obmm_region_publish(reg, be, "export");
	if (ret)
		return ret;

	cmd_export->tokenid = token_id;
	cmd_export->uba = uba;
	cmd_export->mem_id = mem_id;

	pr_debug("obmm_export: mem_id=%llu online.\n", mem_id);
	return 0;

out_dev_put:
	uninit_obmm_region(reg);
	/* frees the region via the device release callback */
	obmm_shm_dev_put(reg);
	return ret;
out_unit_reg:
	uninit_obmm_region(reg);
out_free_reg:
	kfree(reg);
	return ret;
}
