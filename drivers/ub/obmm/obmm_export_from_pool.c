// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/nodemask.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/numa.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>

#include "ubmempool_allocator.h"
#include "conti_mem_allocator.h"
#include "obmm_export.h"
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

int alloc_export_memory_pool(struct obmm_export_region *e_reg)
{
	int ret;
	unsigned int i;
	struct mem_description_pool *desc;
	bool allow_slow = !region_fast_alloc(&e_reg->region);

	for (i = 0; i < e_reg->node_count; i++) {
		if (e_reg->node_mem_size[i] == 0)
			continue;
		if (e_reg->node_mem_size[i] % OBMM_MEMSEG_SIZE) {
			pr_err("invalid size 0x%llx on node %d: not aligned to mempool granu %#lx\n",
			       e_reg->node_mem_size[i], i, OBMM_MEMSEG_SIZE);
			return -EINVAL;
		}
	}

	pr_debug("export_from_pool: allocation started.\n");
	desc = &e_reg->mem_desc;
	ret = allocate_memory_contiguous(e_reg->node_mem_size, e_reg->node_count, desc, true,
					 allow_slow);
	if (ret)
		return ret;
	pr_debug("export_from_pool: allocation completed. sgtable preparation started.\n");

	ret = sg_alloc_table_from_memdesc(&e_reg->sgt, desc, GFP_KERNEL);
	if (ret) {
		free_memory_contiguous(desc);
		return ret;
	}
	pr_debug("export_from_pool: sgtable preparation completed.\n");

	return 0;
}

static int calculate_export_region_size(unsigned long *total_size,
					struct obmm_cmd_export *cmd_export)
{
	nodemask_t nodes = NODE_MASK_NONE;
	int i, min_numa_id = NUMA_NO_NODE, max_numa_id = 0;

	if (cmd_export->length > OBMM_MAX_LOCAL_NUMA_NODES) {
		pr_err("Size list is too long: max=%d, actual_length=%lld\n",
		       OBMM_MAX_LOCAL_NUMA_NODES, cmd_export->length);
		return -E2BIG;
	}
	if (cmd_export->pxm_numa > OBMM_MAX_LOCAL_NUMA_NODES ||
	    cmd_export->pxm_numa < 0) {
		pr_err("Invalid pxm_numa %d\n", cmd_export->pxm_numa);
		return -EINVAL;
	}

	*total_size = 0;
	for (i = 0; i < cmd_export->length; i++) {
		if (!IS_ALIGNED(cmd_export->size[i], OBMM_MEMSEG_SIZE)) {
			pr_err("The size of new OBMM region 0x%llx on node %d is not aligned to OBMM memseg size %#lx.\n",
			       cmd_export->size[i], (int)i, OBMM_MEMSEG_SIZE);
			return -EINVAL;
		}
		if (cmd_export->size[i] != 0 && !is_online_local_node(i)) {
			pr_err("Cannot export memory from offlined or remote numa node %d\n",
			       (int)i);
			return -ENODEV;
		}
		if (cmd_export->size[i] != 0) {
			if (*total_size > ULONG_MAX - cmd_export->size[i]) {
				pr_err("Memory size overflowed!\n");
				return -EOVERFLOW;
			}
			if (min_numa_id == NUMA_NO_NODE)
				min_numa_id = i;

			max_numa_id = i;
			*total_size += cmd_export->size[i];
			node_set(i, nodes);
		}
	}
	if (*total_size == 0) {
		pr_err("The size of new OBMM region is 0. Non-zero value expected\n");
		return -EINVAL;
	}
	node_set(cmd_export->pxm_numa, nodes);
	if (!nodes_on_same_package(&nodes)) {
		pr_err("Cannot use memory from multiple sockets or memory and ub controller is from different sockets.\n");
		pr_err("memory numa id ranges: [%d, %d], ub controller pxm: %d.\n", min_numa_id,
			max_numa_id, cmd_export->pxm_numa);
		return -EINVAL;
	}

	return 0;
}

static struct obmm_export_region *alloc_region_from_cmd(struct obmm_cmd_export *cmd_export)
{
	struct obmm_export_region *e_reg;
	unsigned long total_size;
	int ret;

	ret = calculate_export_region_size(&total_size, cmd_export);
	if (ret)
		return ERR_PTR(ret);

	e_reg = kzalloc(sizeof(struct obmm_export_region), GFP_KERNEL);
	if (e_reg == NULL)
		return ERR_PTR(-ENOMEM);

	e_reg->region.type = OBMM_EXPORT_REGION;
	e_reg->region.mem_size = total_size;
	e_reg->region.mem_cap = OBMM_MEM_ALLOW_CACHEABLE_MMAP | OBMM_MEM_ALLOW_NONCACHEABLE_MMAP;
	e_reg->affinity = cmd_export->pxm_numa;
	memcpy(e_reg->deid, cmd_export->deid, sizeof(e_reg->deid));
	ret = export_flags_to_region_flags(&e_reg->region.flags, cmd_export->flags);
	if (ret) {
		kfree(e_reg);
		return ERR_PTR(ret);
	}
	e_reg->node_count = cmd_export->length;
	memcpy(e_reg->node_mem_size, cmd_export->size, sizeof(uint64_t) * e_reg->node_count);
	/* compaction */
	while (e_reg->node_count - 1 > 0 && e_reg->node_mem_size[e_reg->node_count - 1] == 0)
		e_reg->node_count--;
	ret = set_obmm_region_priv(&e_reg->region, cmd_export->priv_len, cmd_export->priv);
	if (ret) {
		kfree(e_reg);
		return ERR_PTR(ret);
	}
	ret = set_export_vendor(e_reg, cmd_export->vendor_info, cmd_export->vendor_len);
	if (ret) {
		kfree(e_reg);
		return ERR_PTR(ret);
	}
	return e_reg;
}

static void print_export_param(const struct obmm_cmd_export *cmd_export)
{
	pr_debug("obmm_export: len(sizes)=%#llx flags=%#llx deid=" EID_FMT64 " priv_len=%u\n",
		 cmd_export->length, cmd_export->flags, EID_ARGS64_H(cmd_export->deid),
		 EID_ARGS64_L(cmd_export->deid), cmd_export->priv_len);
}

/* obmm_export_from_pool: create an OBMM-exported memory region. The region is
 * physically located on this host and can be accessed from remote host.
 * In OBMM's terminology, it is an export region.
 */
int obmm_export_from_pool(struct obmm_cmd_export *cmd_export)
{
	struct obmm_export_region *e_reg;
	uint64_t uba, mem_id;
	uint32_t token_id;
	int ret;

	print_export_param(cmd_export);
	e_reg = alloc_region_from_cmd(cmd_export);
	if (IS_ERR(e_reg))
		return PTR_ERR(e_reg);

	ret = init_obmm_region(&e_reg->region);
	if (ret)
		goto out_free_reg;

	/* from here on the device core owns the region's memory */
	ret = obmm_shm_dev_init_device(&e_reg->region);
	if (ret)
		goto out_unit_reg;

	ret = obmm_export_common(e_reg);
	if (ret)
		goto out_put_dev;

	token_id = e_reg->tokenid;
	uba = e_reg->uba;
	mem_id = (uint64_t)e_reg->region.regionid;

	ret = register_obmm_region(&e_reg->region);
	if (ret)
		goto out_unexport;
	activate_obmm_region(&e_reg->region);

	cmd_export->tokenid = token_id;
	cmd_export->uba = uba;
	cmd_export->mem_id = mem_id;

	pr_debug("obmm_export: mem_id=%llu online.\n", mem_id);
	return 0;

out_unexport:
	obmm_unexport_common(e_reg);
out_put_dev:
	uninit_obmm_region(&e_reg->region);
	/* frees the region via the device release callback */
	obmm_shm_dev_put(&e_reg->region);
	return ret;
out_unit_reg:
	uninit_obmm_region(&e_reg->region);
out_free_reg:
	free_export_region(e_reg);
	return ret;
}
