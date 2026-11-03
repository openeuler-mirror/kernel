// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 *
 * Import backend create/destroy and ops, plus the IMPORT/UNIMPORT ioctls;
 * memory state lives in struct obmm_import_backend via reg->backend.
 */
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/sizes.h>
#include <linux/huge_mm.h>
#include <linux/pfn_t.h>

#include <ub/ubus/ub-mem-decoder.h>
#include <linux/numa_remote.h>

#include "obmm_core.h"
#include "obmm_backend.h"
#include "obmm_cache.h"
#include "obmm_import.h"
#include "obmm_preimport.h"
#include "obmm_resource.h"
#include "obmm_addr_check.h"
#include "obmm_shm_dev.h"

static void set_import_datapath(const struct obmm_import_backend *imp,
				struct obmm_datapath *datapath)
{
	datapath->scna = imp->scna;
	datapath->dcna = imp->dcna;
	/* shallow copy */
	datapath->seid = imp->seid;
	datapath->deid = imp->deid;
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

static int setup_pa(struct obmm_import_backend *imp)
{
	int ret;
	phys_addr_t start, end;
	struct obmm_datapath datapath;

	imp->base.mem_cap = get_pa_range_mem_cap(imp->scna, imp->pa, imp->base.mem_size);
	if (imp->base.mem_cap == 0) {
		pr_err("import: PA=%#llx size=%#llx not mappable, ret=%pe\n",
		       imp->pa, imp->base.mem_size, ERR_PTR(-EINVAL));
		return -EINVAL;
	}

	if (!imp->preimport) {
		struct ubmem_resource *ubmem_res;

		ubmem_res = setup_ubmem_resource(imp->pa, imp->base.mem_size, false);
		if (IS_ERR(ubmem_res)) {
			pr_err("failed to setup ubmem resource: ret=%pe\n", ubmem_res);
			return PTR_ERR(ubmem_res);
		}
		imp->ubmem_res = ubmem_res;

		return 0;
	}

	start = imp->pa;
	end = imp->pa + imp->base.mem_size - 1;
	set_import_datapath(imp, &datapath);

	ret = preimport_commit_prefilled(start, end, &datapath, &imp->numa_id,
					  &imp->preimport_handle);
	if (ret)
		return ret;

	imp->ubmem_res = preimport_get_resource_prefilled(imp->preimport_handle);

	return 0;
}

/* NOTE: do not clear PA in the teardown process. Error rollback procedure may rely on it. */
static int teardown_pa(struct obmm_import_backend *imp)
{
	if (!imp->preimport)
		return release_ubmem_resource(imp->ubmem_res);
	/* prefilled and preimport */
	return preimport_uncommit_prefilled(imp->preimport_handle, imp->pa,
					    imp->pa + imp->base.mem_size - 1);
}

static int teardown_remote_numa(struct obmm_import_backend *imp, bool force)
{
	int ret, this_ret;

	ret = lock_save_memdev_descendents(imp->ubmem_res);
	if (ret)
		return ret;

	pr_debug("call external: remove_memory_remote(nid=%d, size=%#llx)\n",
		imp->numa_id, imp->base.mem_size);
	ret = remove_memory_remote(imp->numa_id, imp->pa, imp->base.mem_size);
	pr_debug("external called: remove_memory_remote, ret=%pe\n", ERR_PTR(ret));
	/* a full rollback is still possible: check whether this is a full teardown */
	if (ret != 0 && !force) {
		pr_err("remove_memory_remote(nid=%d, size=%#llx) failed: ret=%pe.\n",
		       imp->numa_id, imp->base.mem_size, ERR_PTR(ret));
		goto out_recover_resource;
	}

	if (imp->preimport) {
		pr_debug("call external: add_memory_remote(nid=%d, size=0x%llx, flags=MEMORY_KEEP_ISOLATED)\n",
			imp->numa_id, imp->base.mem_size);
		this_ret = add_memory_remote(imp->numa_id, imp->pa, imp->base.mem_size,
					     MEMORY_KEEP_ISOLATED);
		pr_debug("external called: add_memory_remote() returned %d\n", this_ret);
		if (this_ret == NUMA_NO_NODE) {
			pr_err("failed to reset preimport memory.\n");
			ret = -ENOTRECOVERABLE;
		}
	}

out_recover_resource:
	restore_unlock_memdev_descendents(imp->ubmem_res);
	return ret;
}

static int setup_remote_numa(struct obmm_import_backend *imp)
{
	int ret, flags;

	if (imp->preimport)
		flags = 0;
	else
		flags = MEMORY_DIRECT_ONLINE;

	if (!(imp->base.mem_cap & OBMM_MEM_ALLOW_CACHEABLE_MMAP)) {
		pr_err("PA range invalid. Cacheable memory cannot be managed with numa.remote\n");
		return -EINVAL;
	}

	pr_debug("call external: add_memory_remote(nid=%d, flags=%d)\n",
		imp->numa_id, flags);
	ret = add_memory_remote(imp->numa_id, imp->pa, imp->base.mem_size, flags);
	pr_debug("external called: add_memory_remote() returned %d\n", ret);
	if (ret < 0) {
		pr_err("Remote NUMA creation failed: %d\n", ret);
		return -EPERM;
	}
	WARN_ON(imp->numa_id != NUMA_NO_NODE && imp->numa_id != ret);
	imp->numa_id = ret;

	if (!imp->preimport) {
		ret = obmm_set_numa_distance(imp->scna, imp->numa_id, imp->base_dist);
		if (ret < 0) {
			pr_err("Failed to set remote numa distance: %pe\n", ERR_PTR(ret));
			goto out_teardown_remote_numa;
		}
	}

	return 0;
out_teardown_remote_numa:
	WARN_ON(teardown_remote_numa(imp, true));
	return ret;
}

static inline int occupy_addr_range(const struct obmm_import_backend *imp)
{
	struct obmm_pa_range pa;

	if (!imp->preimport) {
		pa.start = imp->pa;
		pa.end = imp->pa + imp->base.mem_size - 1;
		pa.info.user = OBMM_ADDR_USER_DIRECT_IMPORT;
		/* the occupancy points at the backend object, not at a region */
		pa.info.data = (void *)imp;
		return occupy_pa_range(&pa);
	}

	/* preimport + decoder_prefilled: address conflicts managed by its perimport range */
	return 0;
}

static int free_addr_range(const struct obmm_import_backend *imp)
{
	struct obmm_pa_range pa;

	if (!imp->preimport) {
		pa.start = imp->pa;
		pa.end = imp->pa + imp->base.mem_size - 1;
		return free_pa_range(&pa);
	}

	/* preimport + decoder_prefilled: address conflicts managed by its perimport range */
	return 0;
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

static void import_spec_from_cmd(const struct obmm_cmd_import *param,
				 unsigned long region_flags,
				 struct obmm_import_spec *spec)
{
	spec->addr = param->addr;
	spec->scna = param->scna;
	spec->dcna = param->dcna;
	spec->base_dist = param->base_dist;
	memcpy(spec->deid, param->deid, sizeof(spec->deid));
	memcpy(spec->seid, param->seid, sizeof(spec->seid));
	spec->remote = (region_flags & OBMM_REGION_FLAG_NUMA_REMOTE) != 0;
	spec->preimport = (region_flags & OBMM_REGION_FLAG_PREIMPORT) != 0;
	/* raw uapi value; the creator defaults NUMA_NO_NODE when not remote */
	spec->numa_id = param->numa_id;
}

static int init_import_region_from_cmd(const struct obmm_cmd_import *param,
				       struct obmm_region *region,
				       struct obmm_import_spec *spec)
{
	int ret;
	bool config_numa_dist;

	region->created_as = OBMM_IMPORT_REGION;
	region->mem_size = param->length;
	/* set flags */
	ret = import_to_region_flags(&region->flags, param->flags);
	if (ret)
		return ret;

	import_spec_from_cmd(param, region->flags, spec);

	ret = set_obmm_region_priv(region, param->priv_len, param->priv);
	if (ret)
		return ret;

	/* PA alignment/overflow is checked in obmm_import_backend_create();
	 * only the zero-length rule lives here.
	 */
	if (region->mem_size == 0) {
		pr_err("Zero memory segment size is invalid\n");
		return -EINVAL;
	}

	config_numa_dist = region_numa_remote(region) && !region_preimport(region);
	if (config_numa_dist && !is_numa_base_dist_valid(param->base_dist))
		return -EINVAL;

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

/* pfn derivation of every import mapping */
static unsigned long import_base_pfn(const struct obmm_import_backend *imp,
				     const struct vm_area_struct *vma)
{
	return __phys_to_pfn(imp->pa) + vma->vm_pgoff;
}

/* ops->fault; PFN_DEV is safe because VM_IO|VM_PFNMAP excludes GUP and
 * update_range normalizes the entry. A PMD leaf needs a PMD_SIZE-aligned
 * base, but the import PA is only OBMM_BASIC_GRANU-aligned (weaker than
 * PMD_SIZE on 64K pages), so an unaligned base degrades this page to a PTE.
 */
static vm_fault_t import_fault(struct obmm_backend *be, struct vm_fault *vmf,
			       bool is_pmd)
{
	struct obmm_import_backend *imp = obmm_backend_to_import(be);
	struct vm_area_struct *vma = vmf->vma;
	unsigned long addr, pfn, base_pfn;

	base_pfn = import_base_pfn(imp, vma);
	if (is_pmd) {
		addr = vmf->address & PMD_MASK;
		pfn = base_pfn + ((addr - vma->vm_start) >> PAGE_SHIFT);
		if (IS_ALIGNED(pfn, HPAGE_PMD_NR))
			return vmf_insert_pfn_pmd(vmf, __pfn_to_pfn_t(pfn, PFN_DEV),
						  vmf->flags & FAULT_FLAG_WRITE);
	}

	addr = vmf->address;
	pfn = base_pfn + ((addr - vma->vm_start) >> PAGE_SHIFT);

	return vmf_insert_pfn_prot(vma, vmf->address, pfn, vma->vm_page_prot);
}

static int import_flush_range(struct obmm_backend *be, u64 off, u64 len, u8 cache_ops)
{
	struct obmm_import_backend *imp = obmm_backend_to_import(be);
	int ret;

	ret = flush_cache_by_pa(imp->pa + off, len, cache_ops);
	if (ret)
		return ret;

	if (cache_ops == OBMM_SHM_CACHE_WB_INVAL || cache_ops == OBMM_SHM_CACHE_WB_ONLY)
		return ub_write_queue_flush(imp->scna);
	return 0;
}

static void import_fill_ext_addr(const struct obmm_import_backend *imp, u32 regionid,
				 u64 offset, u64 pa, struct obmm_ext_addr *ext_addr)
{
	ext_addr->region_type = OBMM_IMPORT_REGION;
	ext_addr->regionid = regionid;
	ext_addr->offset = offset;
	ext_addr->tid = 0;
	ext_addr->uba = 0;
	ext_addr->pa = pa;
	ext_addr->numa_id = imp->numa_id;
}

/* @out->offset is in/out: validated here, the rest filled in */
static int import_query(struct obmm_backend *be, struct obmm_ext_addr *out)
{
	struct obmm_import_backend *imp = obmm_backend_to_import(be);

	if (!be->shell)
		return -EINVAL;
	if (out->offset >= be->mem_size) {
		pr_err("%s: invalid offset 0x%llx\n", __func__, out->offset);
		return -EINVAL;
	}

	import_fill_ext_addr(imp, be->shell->regionid, out->offset,
			     imp->pa + out->offset, out);

	return 0;
}

static bool import_covers_pa(struct obmm_backend *be, u64 pa, u64 len,
			     struct obmm_ext_addr *out)
{
	struct obmm_import_backend *imp = obmm_backend_to_import(be);
	u64 offset = pa - imp->pa;

	if (pa < imp->pa || offset > be->mem_size || len > be->mem_size - offset)
		return false;

	if (out)
		import_fill_ext_addr(imp, be->regionid, offset, pa, out);

	return true;
}

/* ops->destroy keeps the flush-failure ladder; MEMID leaf is attach/detach-managed */
static int obmm_import_backend_destroy(struct obmm_backend *be)
{
	int ret, rollback_ret, old_numa_id;
	struct obmm_import_backend *imp = obmm_backend_to_import(be);

	if (imp->numa_remote) {
		old_numa_id = imp->numa_id;
		ret = teardown_remote_numa(imp, false);
		if (ret)
			goto err_teardown_numa;
	}

	ret = import_flush_range(be, 0, be->mem_size, OBMM_SHM_CACHE_INVAL);
	if (ret) {
		pr_err("failed to flush import region, ret=%pe.\n", ERR_PTR(ret));
		goto err_flush;
	}

	/* unplug memory */
	ret = teardown_pa(imp);
	if (ret) {
		pr_err("failed to release PA level mapping (pa=%#llx, size=%#llx), ret=%pe.\n",
		       imp->pa, be->mem_size, ERR_PTR(ret));
		goto err_flush;
	}

	ret = free_addr_range(imp);
	if (ret)
		goto err_free_addr_range;

	return 0;

err_free_addr_range:
	rollback_ret = setup_pa(imp);
	if (rollback_ret) {
		pr_err("failed to restore PA level mapping, ret=%pe.\n", ERR_PTR(rollback_ret));
		return -ENOTRECOVERABLE; /* rollback cannot proceed */
	}
err_flush:
	if (imp->numa_remote) {
		imp->numa_id = old_numa_id;

		rollback_ret = setup_remote_numa(imp);
		if (rollback_ret) {
			pr_err("failed to restore remote NUMA, ret=%pe.\n", ERR_PTR(rollback_ret));
			return -ENOTRECOVERABLE; /* rollback cannot proceed */
		}
	}
err_teardown_numa:
	/* the iomem leaf belongs to the shell's detach path, not this rollback */
	return ret;
}

static const struct obmm_backend_ops obmm_import_backend_ops = {
	.fault		= import_fault,
	.flush_range	= import_flush_range,
	.query		= import_query,
	.covers_pa	= import_covers_pa,
	.destroy	= obmm_import_backend_destroy,
};

/*
 * Create an import backend (existence ref held or ERR_PTR); MEMID leaf is
 * obmm_backend_attach's. @full=false is the restricted switch target.
 */
struct obmm_backend *
obmm_import_backend_create(const struct obmm_import_spec *spec, u64 mem_size, bool full)
{
	struct obmm_import_backend *imp;
	int ret, rollback_ret;

	if (!validate_scna(spec->scna))
		return ERR_PTR(-ENODEV);

	if (!validate_pa_range(spec->addr, mem_size))
		return ERR_PTR(-EINVAL);

	if (!full && (spec->remote || spec->preimport)) {
		pr_err("numa-remote and preimport imports are unsupported on the restricted entry.\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	imp = kzalloc(sizeof(*imp), GFP_KERNEL);
	if (!imp)
		return ERR_PTR(-ENOMEM);

	imp->base.type = OBMM_BACKEND_IMPORT;
	imp->base.mem_size = mem_size;
	imp->base.ops = &obmm_import_backend_ops;
	refcount_set(&imp->base.refcnt, 1); /* the existence reference (design 2.3) */

	imp->pa = spec->addr;
	imp->scna = spec->scna;
	imp->dcna = spec->dcna;
	memcpy(imp->deid, spec->deid, sizeof(imp->deid));
	memcpy(imp->seid, spec->seid, sizeof(imp->seid));
	imp->base_dist = spec->base_dist;
	imp->numa_remote = spec->remote;
	imp->preimport = spec->preimport;
	imp->numa_id = spec->remote ? spec->numa_id : NUMA_NO_NODE;

	ret = occupy_addr_range(imp);
	if (ret)
		goto out_free_backend;

	ret = setup_pa(imp);
	if (ret)
		goto out_free_addr_range;

	/* register numa node */
	if (imp->numa_remote) {
		ret = setup_remote_numa(imp);
		if (ret)
			goto out_teardown_pa;
	}

	return &imp->base;

out_teardown_pa:
	rollback_ret = teardown_pa(imp);
	if (rollback_ret) {
		pr_err("failed to teardown PA level mapping on rollback, ret=%pe.\n",
		       ERR_PTR(rollback_ret));
		ret = -ENOTRECOVERABLE;
	}
out_free_addr_range:
	rollback_ret = free_addr_range(imp);
	if (rollback_ret) {
		pr_err("failed to free address range on rollback, ret=%pe.\n",
		       ERR_PTR(rollback_ret));
		ret = -ENOTRECOVERABLE;
	}
out_free_backend:
	kfree(imp);
	return ERR_PTR(ret);
}

int obmm_import(struct obmm_cmd_import *cmd_import)
{
	int retval, numa_id;
	struct obmm_region *reg;
	struct obmm_import_spec spec;
	struct obmm_backend *be;
	uint64_t mem_id;

	print_import_param(cmd_import);
	reg = kzalloc(sizeof(struct obmm_region), GFP_KERNEL);
	if (reg == NULL)
		return -ENOMEM;

	/* arguments to region (logs produced by callee) */
	retval = init_import_region_from_cmd(cmd_import, reg, &spec);
	if (retval)
		goto out_free_reg;

	retval = init_obmm_region(reg);
	if (retval)
		goto out_free_reg;

	/* from here on the device core owns the region's memory */
	retval = obmm_shm_dev_init_device(reg);
	if (retval)
		goto out_region_uninit;

	be = obmm_import_backend_create(&spec, reg->mem_size, true);
	if (IS_ERR(be)) {
		retval = PTR_ERR(be);
		pr_err("Failed to prepare import memory: ret=%pe\n", ERR_PTR(retval));
		goto out_dev_put;
	}

	numa_id = obmm_backend_to_import(be)->numa_id;
	mem_id = (uint64_t)reg->regionid;

	retval = obmm_region_publish(reg, be, "import");
	if (retval)
		return retval;

	/* pass back output value */
	cmd_import->numa_id = numa_id;
	cmd_import->mem_id = mem_id;

	pr_debug("%s: mem_id=%llu online\n", __func__, cmd_import->mem_id);
	return 0;

out_dev_put:
	uninit_obmm_region(reg);
	/* frees the region via the device release callback */
	obmm_shm_dev_put(reg);
	return retval;
out_region_uninit:
	uninit_obmm_region(reg);
out_free_reg:
	kfree(reg);
	return retval;
}

/* NOTE: the operation order is not precisely the reverse order of initialization for the ease of
 * error rollback. Please make careful evaluation on modifications.
 */
int obmm_unimport(const struct obmm_cmd_unimport *cmd_unimport)
{
	int ret;
	struct obmm_region *reg;

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

	if (reg->created_as != OBMM_IMPORT_REGION) {
		pr_err("%s: mem_id=%llu region type mismatched.\n", __func__, cmd_unimport->mem_id);
		ret = -EINVAL;
		goto err_unimport;
	}

	ret = obmm_region_teardown(reg);
	if (ret)
		goto err_teardown_aborted;

	pr_debug("%s: mem_id=%llu completed.\n", __func__, cmd_unimport->mem_id);
	return 0;

err_teardown_aborted:
	pr_err("%s: mem_id=%llu failed, %pe.\n", __func__, cmd_unimport->mem_id, ERR_PTR(ret));
	return ret;
err_unimport:
	activate_obmm_region(reg);
	pr_err("%s: mem_id=%llu failed, %pe.\n", __func__, cmd_unimport->mem_id, ERR_PTR(ret));
	return ret;
}
