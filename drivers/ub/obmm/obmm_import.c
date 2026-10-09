// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 */
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/sizes.h>

#include <ub/ubus/ub-mem-decoder.h>
#include <linux/numa_remote.h>

#include "obmm_core.h"
#include "obmm_cache.h"
#include "obmm_import.h"
#include "obmm_preimport.h"
#include "obmm_resource.h"
#include "obmm_addr_check.h"
#include "obmm_shm_dev.h"

static void set_import_region_datapath(const struct obmm_import_region *i_reg,
				       struct obmm_datapath *datapath)
{
	datapath->scna = i_reg->scna;
	datapath->dcna = i_reg->dcna;
	/* shallow copy */
	datapath->seid = i_reg->seid;
	datapath->deid = i_reg->deid;
}

static unsigned long get_pa_range_mem_cap(u32 scna, phys_addr_t pa, size_t size)
{
	phys_addr_t pa_start = pa;
	phys_addr_t pa_end = pa + size - 1;
	unsigned long mem_cap = 0;

	if (ub_memory_validate_pa(scna, pa_start, pa_end, true))
		mem_cap |= OBMM_MEM_ALLOW_CACHEABLE_MMAP;
	if (ub_memory_validate_pa(scna, pa_start, pa_end, false))
		mem_cap |= OBMM_MEM_ALLOW_NONCACHEABLE_MMAP;
	if (mem_cap == 0)
		pr_err("PA range invalid. Non-UBMEM memory cannot be mmaped as import memory\n");

	return mem_cap;
}

static int setup_pa(struct obmm_import_region *i_reg)
{
	int ret;
	phys_addr_t start, end;
	struct obmm_datapath datapath;

	i_reg->region.mem_cap =
		get_pa_range_mem_cap(i_reg->scna, i_reg->pa, i_reg->region.mem_size);
	if (i_reg->region.mem_cap == 0)
		return -EINVAL;

	if (!region_preimport(&i_reg->region)) {
		struct ubmem_resource *ubmem_res;

		ubmem_res = setup_ubmem_resource(i_reg->pa, i_reg->region.mem_size, false);
		if (IS_ERR(ubmem_res)) {
			pr_err("failed to setup ubmem resource: ret=%pe\n", ubmem_res);
			return PTR_ERR(ubmem_res);
		}
		i_reg->ubmem_res = ubmem_res;

		return 0;
	}

	start = i_reg->pa;
	end = i_reg->pa + i_reg->region.mem_size - 1;
	set_import_region_datapath(i_reg, &datapath);

	ret = preimport_commit_prefilled(start, end, &datapath, &i_reg->numa_id,
					  &i_reg->preimport_handle);
	if (ret)
		return ret;

	i_reg->ubmem_res = preimport_get_resource_prefilled(i_reg->preimport_handle);

	return 0;
}

/* NOTE: do not clear PA in the teardown process. Error rollback procedure may rely on it. */
static int teardown_pa(struct obmm_import_region *i_reg)
{
	bool preimport = region_preimport(&i_reg->region);

	if (!preimport)
		return release_ubmem_resource(i_reg->ubmem_res);
	/* prefilled and preimport */
	return preimport_uncommit_prefilled(i_reg->preimport_handle, i_reg->pa,
					    i_reg->pa + i_reg->region.mem_size - 1);
}

static int teardown_remote_numa(struct obmm_import_region *i_reg, bool force)
{
	int ret, this_ret;

	ret = lock_save_memdev_descendents(i_reg->ubmem_res);
	if (ret)
		return ret;

	pr_debug("call external: remove_memory_remote(nid=%d, size=%#llx)\n",
		i_reg->numa_id, i_reg->region.mem_size);
	ret = remove_memory_remote(i_reg->numa_id, i_reg->pa, i_reg->region.mem_size);
	pr_debug("external called: remove_memory_remote, ret=%pe\n", ERR_PTR(ret));
	/* a full rollback is still possible: check whether this is a full teardown */
	if (ret != 0 && !force) {
		pr_err("remove_memory_remote(nid=%d, size=%#llx) failed: ret=%pe.\n",
		       i_reg->numa_id, i_reg->region.mem_size, ERR_PTR(ret));
		goto out_recover_resource;
	}

	if (region_preimport(&i_reg->region)) {
		pr_debug("call external: add_memory_remote(nid=%d, size=0x%llx, flags=MEMORY_KEEP_ISOLATED)\n",
			i_reg->numa_id, i_reg->region.mem_size);
		this_ret = add_memory_remote(i_reg->numa_id, i_reg->pa, i_reg->region.mem_size,
					     MEMORY_KEEP_ISOLATED);
		pr_debug("external called: add_memory_remote() returned %d\n", this_ret);
		if (this_ret == NUMA_NO_NODE) {
			pr_err("failed to reset preimport memory.\n");
			ret = -ENOTRECOVERABLE;
		}
	}

out_recover_resource:
	restore_unlock_memdev_descendents(i_reg->ubmem_res);
	return ret;
}

static int setup_remote_numa(struct obmm_import_region *i_reg)
{
	int ret, flags;

	if (region_preimport(&i_reg->region))
		flags = 0;
	else
		flags = MEMORY_DIRECT_ONLINE;

	if (!(i_reg->region.mem_cap & OBMM_MEM_ALLOW_CACHEABLE_MMAP)) {
		pr_err("PA range invalid. Cacheable memory cannot be managed with numa.remote\n");
		return -EINVAL;
	}

	pr_debug("call external: add_memory_remote(nid=%d, flags=%d)\n",
		i_reg->numa_id, flags);
	ret = add_memory_remote(i_reg->numa_id, i_reg->pa, i_reg->region.mem_size, flags);
	pr_debug("external called: add_memory_remote() returned %d\n", ret);
	if (ret < 0) {
		pr_err("Remote NUMA creation failed: %d\n", ret);
		return -EPERM;
	}
	WARN_ON(i_reg->numa_id != NUMA_NO_NODE && i_reg->numa_id != ret);
	i_reg->numa_id = ret;

	if (!region_preimport(&i_reg->region)) {
		ret = obmm_set_numa_distance(i_reg->scna, i_reg->numa_id, i_reg->base_dist);
		if (ret < 0) {
			pr_err("Failed to set remote numa distance: %pe\n", ERR_PTR(ret));
			goto out_teardown_remote_numa;
		}
	}

	return 0;
out_teardown_remote_numa:
	WARN_ON(teardown_remote_numa(i_reg, true));
	return ret;
}

static inline int occupy_addr_range(const struct obmm_import_region *i_reg)
{
	struct obmm_pa_range pa;

	if (!region_preimport(&i_reg->region)) {
		pa.start = i_reg->pa;
		pa.end = i_reg->pa + i_reg->region.mem_size - 1;
		pa.info.user = OBMM_ADDR_USER_DIRECT_IMPORT;
		pa.info.data = (void *)i_reg;
		return occupy_pa_range(&pa);
	}

	/* preimport + decoder_prefilled: address conflicts managed by its perimport range */
	return 0;
}

static int free_addr_range(const struct obmm_import_region *i_reg)
{
	struct obmm_pa_range pa;

	if (!region_preimport(&i_reg->region)) {
		pa.start = i_reg->pa;
		pa.end = i_reg->pa + i_reg->region.mem_size - 1;
		return free_pa_range(&pa);
	}

	/* preimport + decoder_prefilled: address conflicts managed by its perimport range */
	return 0;
}

static int setup_iomem_resource(struct obmm_import_region *i_reg)
{
	struct resource *memdev_res;

	memdev_res = setup_memdev_resource(i_reg->ubmem_res, i_reg->pa,
					   i_reg->region.mem_size, i_reg->region.regionid);
	if (IS_ERR(memdev_res)) {
		pr_err("memid=%d: failed to setup memdev resource: %pe\n",
		       i_reg->region.regionid, memdev_res);
		return PTR_ERR(memdev_res);
	}

	i_reg->memdev_res = memdev_res;

	return 0;
}

static int teardown_iomem_resource(struct obmm_import_region *i_reg)
{
	int ret;

	ret = release_memdev_resource(i_reg->ubmem_res, i_reg->memdev_res);
	if (ret)
		pr_err("memid=%d: failed to release memdev resource: %pe\n",
		       i_reg->region.regionid, ERR_PTR(ret));

	return ret;
}

static int prepare_import_memory(struct obmm_import_region *i_reg)
{
	int ret, rollback_ret;

	if (!validate_scna(i_reg->scna))
		return -ENODEV;

	ret = occupy_addr_range(i_reg);
	if (ret)
		return ret;

	ret = setup_pa(i_reg);
	if (ret)
		goto out_free_addr_range;

	/* register numa node */
	if (region_numa_remote(&i_reg->region)) {
		ret = setup_remote_numa(i_reg);
		if (ret)
			goto out_teardown_pa;
	} else {
		i_reg->numa_id = NUMA_NO_NODE;
	}

	ret = setup_iomem_resource(i_reg);
	if (ret)
		goto out_teardown_numa;

	return 0;
out_teardown_numa:
	if (region_numa_remote(&i_reg->region)) {
		rollback_ret = teardown_remote_numa(i_reg, true);
		if (rollback_ret) {
			pr_err("failed to teardown remote numa on rollback, ret=%pe.\n",
			       ERR_PTR(rollback_ret));
			ret = -ENOTRECOVERABLE;
		}
	}
out_teardown_pa:
	rollback_ret = teardown_pa(i_reg);
	if (rollback_ret) {
		pr_err("failed to teardown PA level mapping on rollback, ret=%pe.\n",
		       ERR_PTR(rollback_ret));
		ret = -ENOTRECOVERABLE;
	}
out_free_addr_range:
	rollback_ret = free_addr_range(i_reg);
	if (rollback_ret) {
		pr_err("failed to free address range on rollback, ret=%pe.\n",
		       ERR_PTR(rollback_ret));
		ret = -ENOTRECOVERABLE;
	}
	return ret;
}

static int release_import_memory(struct obmm_import_region *i_reg)
{
	int ret, rollback_ret, old_numa_id;

	ret = teardown_iomem_resource(i_reg);
	if (ret)
		return ret;

	if (region_numa_remote(&i_reg->region)) {
		old_numa_id = i_reg->numa_id;
		ret = teardown_remote_numa(i_reg, false);
		if (ret)
			goto err_teardown_numa;
	}

	ret = flush_import_region(i_reg, 0, i_reg->region.mem_size, OBMM_SHM_CACHE_INVAL);
	if (ret) {
		pr_err("failed to flush import region, ret=%pe.\n", ERR_PTR(ret));
		goto err_flush;
	}

	/* unplug memory */
	ret = teardown_pa(i_reg);
	if (ret) {
		pr_err("failed to release PA level mapping of region %d, ret=%pe.\n",
		       i_reg->region.regionid, ERR_PTR(ret));
		goto err_flush;
	}

	ret = free_addr_range(i_reg);
	if (ret)
		goto err_free_addr_range;

	return 0;

err_free_addr_range:
	rollback_ret = setup_pa(i_reg);
	if (rollback_ret) {
		pr_err("failed to restore PA level mapping, ret=%pe.\n", ERR_PTR(rollback_ret));
		return -ENOTRECOVERABLE; /* rollback cannot proceed */
	}
err_flush:
	if (region_numa_remote(&i_reg->region)) {
		i_reg->numa_id = old_numa_id;

		rollback_ret = setup_remote_numa(i_reg);
		if (rollback_ret) {
			pr_err("failed to restore remote NUMA, ret=%pe.\n", ERR_PTR(rollback_ret));
			return -ENOTRECOVERABLE; /* rollback cannot proceed */
		}
	}
err_teardown_numa:
	rollback_ret = setup_iomem_resource(i_reg);
	if (rollback_ret) {
		pr_err("failed to restore iomem resource on rollback, ret=%pe.\n",
		       ERR_PTR(rollback_ret));
		return -ENOTRECOVERABLE;
	}
	return ret;
}

static bool validate_pa_range(phys_addr_t pa, size_t size)
{
	/* the PA alignment of OBMM_BASIC_GRANU might be an overkill if PAGE_SIZE is not 4K. But
	 * this is not be a common use case for now.
	 */
	if (!IS_ALIGNED(pa, OBMM_BASIC_GRANU) || !IS_ALIGNED(size, OBMM_BASIC_GRANU)) {
		pr_err("PA segments not aligned to OBMM basic granu: base=%#llx, size=%#zx, granularity=%#lx.\n",
		       pa, size, OBMM_BASIC_GRANU);
		return false;
	}

	if (pa == 0) {
		pr_err("PA=0 unexpected.\n");
		return false;
	}
	if (pa + size < pa) {
		pr_err("PA range overflow: base=%#llx, size=%#zx.\n", pa, size);
		return false;
	}

	return true;
}

static bool validate_import_region(const struct obmm_import_region *i_reg)
{
	/* size and alignment check */
	if (i_reg->region.mem_size == 0) {
		pr_err("Zero memory segment size is invalid\n");
		return false;
	}

	/* PA as parameter */
	if (!validate_pa_range(i_reg->pa, i_reg->region.mem_size))
		return false;
	return true;
}

static int import_to_region_flags(unsigned long *region_flags, unsigned long import_flags)
{
	*region_flags = 0;

	if (import_flags & (~OBMM_IMPORT_FLAG_MASK)) {
		pr_err("Invalid import flags %#lx (unknown flags: %#lx).\n", import_flags,
		       import_flags & (~OBMM_IMPORT_FLAG_MASK));
		return -EINVAL;
	}
	if (!!(import_flags & OBMM_IMPORT_FLAG_ALLOW_MMAP) +
	    !!(import_flags & OBMM_IMPORT_FLAG_NUMA_REMOTE) != 1) {
		pr_err("Exactly one of {ALLOW_MMAP, NUMA_REMOTE} must be specified as import flag.\n");
		return -EINVAL;
	}
	if ((import_flags & OBMM_IMPORT_FLAG_PREIMPORT) &&
	    !(import_flags & OBMM_IMPORT_FLAG_NUMA_REMOTE)) {
		pr_err("Preimport must be used with NUMA_REMOTE.\n");
		return -EINVAL;
	}

	if (import_flags & OBMM_IMPORT_FLAG_ALLOW_MMAP)
		*region_flags |= OBMM_REGION_FLAG_ALLOW_MMAP;
	if (import_flags & OBMM_IMPORT_FLAG_PREIMPORT)
		*region_flags |= OBMM_REGION_FLAG_PREIMPORT;
	if (import_flags & OBMM_IMPORT_FLAG_NUMA_REMOTE)
		*region_flags |= OBMM_REGION_FLAG_NUMA_REMOTE;

	return 0;
}

static int init_import_region_from_cmd(const struct obmm_cmd_import *param,
				       struct obmm_import_region *i_reg)
{
	int ret;
	bool config_numa_dist;
	struct obmm_region *region = &i_reg->region;

	i_reg->region.type = OBMM_IMPORT_REGION;
	i_reg->region.mem_size = param->length;
	/* set flags */
	ret = import_to_region_flags(&region->flags, param->flags);
	if (ret)
		return ret;

	i_reg->pa = param->addr;

	i_reg->dcna = param->dcna;
	i_reg->scna = param->scna;
	memcpy(i_reg->deid, param->deid, sizeof(i_reg->deid));
	memcpy(i_reg->seid, param->seid, sizeof(i_reg->seid));
	i_reg->numa_id = region_numa_remote(&i_reg->region) ? param->numa_id : NUMA_NO_NODE;

	ret = set_obmm_region_priv(region, param->priv_len, param->priv);
	if (ret)
		return ret;

	if (!validate_import_region(i_reg))
		return -EINVAL;

	config_numa_dist = region_numa_remote(&i_reg->region) && !region_preimport(&i_reg->region);
	if (config_numa_dist && !is_numa_base_dist_valid(param->base_dist))
		return -EINVAL;
	i_reg->base_dist = param->base_dist;

	/* NOTE: this function initializes the data structure but not the device */
	return 0;
}

static void print_import_param(const struct obmm_cmd_import *cmd_import)
{
	pr_debug("obmm_import: scna=%#x {pa=%#llx length=%#llx} flags=%#llx nid=%d base_dist=%u seid="
		EID_FMT64 " priv_len=%u\n",
		cmd_import->scna, cmd_import->addr, cmd_import->length, cmd_import->flags,
		cmd_import->numa_id, cmd_import->base_dist, EID_ARGS64_H(cmd_import->seid),
		EID_ARGS64_L(cmd_import->seid), cmd_import->priv_len);
}

int obmm_import(struct obmm_cmd_import *cmd_import)
{
	int retval, rollback_ret, numa_id;
	struct obmm_import_region *i_reg;
	uint64_t mem_id;

	print_import_param(cmd_import);
	/* create obmm region */
	i_reg = kzalloc(sizeof(struct obmm_import_region), GFP_KERNEL);
	if (i_reg == NULL)
		return -ENOMEM;

	/* arguments to region (logs produced by callee) */
	retval = init_import_region_from_cmd(cmd_import, i_reg);
	if (retval)
		goto out_free_ireg;

	retval = init_obmm_region(&i_reg->region);
	if (retval)
		goto out_free_ireg;

	/* from here on the device core owns the region's memory */
	retval = obmm_shm_dev_init_device(&i_reg->region);
	if (retval)
		goto out_region_uninit;

	retval = prepare_import_memory(i_reg);
	if (retval) {
		pr_err("Failed to prepare import memory: ret=%pe\n", ERR_PTR(retval));
		goto out_dev_put;
	}

	numa_id = i_reg->numa_id;
	mem_id = (uint64_t)i_reg->region.regionid;

	retval = register_obmm_region(&i_reg->region);
	if (retval) {
		pr_err("Failed to create import device. ret=%pe\n", ERR_PTR(retval));
		goto out_release_memory;
	}
	activate_obmm_region(&i_reg->region);

	/* pass back output value */
	cmd_import->numa_id = numa_id;
	cmd_import->mem_id = mem_id;

	pr_debug("%s: mem_id=%llu online\n", __func__, cmd_import->mem_id);
	return 0;

out_release_memory:
	rollback_ret = release_import_memory(i_reg);
	if (rollback_ret)
		pr_warn("Failed to release import memory on rollback, ret=%pe.\n",
			ERR_PTR(rollback_ret));
out_dev_put:
	uninit_obmm_region(&i_reg->region);
	/* frees the region via the device release callback */
	obmm_shm_dev_put(&i_reg->region);
	return retval;
out_region_uninit:
	uninit_obmm_region(&i_reg->region);
out_free_ireg:
	kfree(i_reg);
	return retval;
}

/* NOTE: the operation order is not precisely the reverse order of initialization for the ease of
 * error rollback. Please make careful evaluation on modifications.
 */
int obmm_unimport(const struct obmm_cmd_unimport *cmd_unimport)
{
	int ret;
	struct obmm_region *reg;
	struct obmm_import_region *i_reg;

	pr_debug("%s: mem_id=%llu, flags=%#llx.\n", __func__, cmd_unimport->mem_id,
		cmd_unimport->flags);
	if (!validate_obmm_mem_id(cmd_unimport->mem_id))
		return -ENOENT;
	if (cmd_unimport->flags & (~OBMM_UNIMPORT_FLAG_MASK)) {
		pr_err("%s: invalid flags %#llx.\n", __func__, cmd_unimport->flags);
		return -EINVAL;
	}

	reg = search_deactivate_obmm_region(cmd_unimport->mem_id);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	if (reg->type != OBMM_IMPORT_REGION) {
		pr_err("%s: mem_id=%llu region type mismatched.\n", __func__, cmd_unimport->mem_id);
		ret = -EINVAL;
		goto err_unimport;
	}
	i_reg = container_of(reg, struct obmm_import_region, region);
	ret = release_import_memory(i_reg);
	if (ret)
		goto err_unimport;

	deregister_obmm_region(reg);
	uninit_obmm_region(reg);
	/* the region is freed by the device release callback */
	obmm_shm_dev_put(reg);

	pr_debug("%s: mem_id=%llu completed.\n", __func__, cmd_unimport->mem_id);
	return 0;

err_unimport:
	activate_obmm_region(reg);
	pr_err("%s: mem_id=%llu failed, %pe.\n", __func__, cmd_unimport->mem_id, ERR_PTR(ret));
	return ret;
}

int flush_import_region(struct obmm_import_region *i_reg, unsigned long offset,
			unsigned long length, unsigned long cache_ops)
{
	int ret;

	ret = flush_cache_by_pa(i_reg->pa + offset, length, cache_ops);
	if (ret)
		return ret;

	if (cache_ops == OBMM_SHM_CACHE_WB_INVAL || cache_ops == OBMM_SHM_CACHE_WB_ONLY)
		return ub_write_queue_flush(i_reg->scna);
	return 0;
}

int map_import_region(struct vm_area_struct *vma, struct obmm_import_region *i_reg,
		      enum obmm_mmap_granu mmap_granu)
{
	unsigned long pfn, size;

	size = vma->vm_end - vma->vm_start;
	pfn = __phys_to_pfn(i_reg->pa) + vma->vm_pgoff;
	if (mmap_granu == OBMM_MMAP_GRANU_PAGE)
		return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
	else if (mmap_granu == OBMM_MMAP_GRANU_PMD)
		return remap_pfn_range_try_pmd(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
	pr_err("invalid mmap granu %d\n", mmap_granu);

	return -EINVAL;
}

int get_pa_detail_import(const struct obmm_import_region *i_reg, unsigned long pa,
			 struct obmm_ext_addr *ext_addr)
{
	if (pa < i_reg->pa || pa >= i_reg->pa + i_reg->region.mem_size)
		return -EFAULT;

	ext_addr->region_type = OBMM_IMPORT_REGION;
	ext_addr->regionid = i_reg->region.regionid;
	ext_addr->offset = pa - i_reg->pa;
	ext_addr->tid = 0;
	ext_addr->uba = 0;
	ext_addr->numa_id = i_reg->numa_id;
	ext_addr->pa = pa;

	return 0;
}

int get_offset_detail_import(const struct obmm_import_region *i_reg, unsigned long offset,
			     struct obmm_ext_addr *ext_addr)
{
	if (offset >= i_reg->region.mem_size) {
		pr_err("%s: invalid offset 0x%lx\n", __func__, offset);
		return -EINVAL;
	}

	ext_addr->region_type = i_reg->region.type;
	ext_addr->regionid = i_reg->region.regionid;
	ext_addr->offset = offset;
	ext_addr->tid = 0;
	ext_addr->uba = 0;
	ext_addr->pa = i_reg->pa + offset;
	ext_addr->numa_id = i_reg->numa_id;

	return 0;
}
