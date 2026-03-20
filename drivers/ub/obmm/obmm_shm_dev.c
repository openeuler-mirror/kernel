// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <linux/cacheflush.h>
#include <asm/tlbflush.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include "obmm_cache.h"
#include "obmm_sysfs.h"
#include "obmm_export_region_ops.h"
#include "obmm_import.h"
#include "obmm_ownership.h"
#include "obmm_shm_dev.h"

static dev_t obmm_devt;

static const char *obmm_shm_region_name = "OBMM_SHMDEV";
static const char *obmm_shm_rootdev_name = "obmm";
static struct device *obmm_shm_rootdev;

static int scan_and_flush(struct obmm_region *reg, struct vm_area_struct *vma,
			  const struct obmm_cmd_update_range *update_info);

/**
 * Convert VM flags to mem state
 */
static unsigned long get_vma_mem_state(const vm_flags_t vm_flags, bool cacheable)
{
	unsigned long mem_state;

	if (vm_flags & VM_WRITE)
		mem_state = OBMM_SHM_MEM_READWRITE;
	else if ((vm_flags & VM_READ) && (vm_flags & VM_EXEC))
		mem_state = OBMM_SHM_MEM_READEXEC;
	else if (vm_flags & VM_READ)
		mem_state = OBMM_SHM_MEM_READONLY;
	else
		mem_state = OBMM_SHM_MEM_NO_ACCESS;

	if (cacheable && mem_state != OBMM_SHM_MEM_NO_ACCESS)
		mem_state |= OBMM_SHM_MEM_NORMAL;
	else
		mem_state |= OBMM_SHM_MEM_NORMAL_NC;
	pr_debug("VMA init mem_state: vma_flags=0x%lx, cacheable=%d, mem_state=0x%lx\n",
		 vm_flags, cacheable, mem_state);
	return mem_state;
}

/* VMA operations for obmm-mmaped VMA */
static void obmm_vma_open(struct vm_area_struct *vma)
{
	pr_debug("VMA opened range (0x%lx-0x%lx)\n", vma->vm_start, vma->vm_end);
}

static void obmm_vma_close(struct vm_area_struct *vma)
{
	struct obmm_region *reg;
	int ret;

	reg = (struct obmm_region *)vma->vm_file->private_data;

	mutex_lock(&reg->state_mutex);
	/* cc-mmap */
	if (reg->mmap_mode == OBMM_MMAP_NORMAL && reg->ownership_info) {
		/* flush cache */
		struct obmm_cmd_update_range update_info = {
			.start = vma->vm_start,
			.end = vma->vm_end,
			.mem_state = OBMM_SHM_MEM_NO_ACCESS,
			.cache_ops = OBMM_SHM_CACHE_INFER,
		};
		ret = scan_and_flush(reg, vma, &update_info);
		if (ret)
			pr_err("vma close: failed to flush cache\n");

		remove_mapping_permission(reg, vma, vma->vm_start, vma->vm_end);
		release_local_state_info(vma);
	}

	reg->mmap_count--;
	if (reg->mmap_count == 0) {
		/* reset mmap_mode */
		reg->mmap_mode = OBMM_MMAP_INIT;
	}
	mutex_unlock(&reg->state_mutex);
	pr_debug("obmm_shmdev munmap: mem_id=%d pid=%d vma=[%#lx, %#lx]\n", reg->regionid,
		 current->pid, vma->vm_start, vma->vm_end);
}

static int obmm_vma_may_split(struct vm_area_struct *vma __always_unused,
			      unsigned long addr __always_unused)
{
	/* not supported */
	pr_err("VMA may split at 0x%lx (range: 0x%lx-0x%lx), but split not supported\n", addr,
	       vma->vm_start, vma->vm_end);
	return -EOPNOTSUPP;
}

static int obmm_vma_mremap(struct vm_area_struct *vma __always_unused)
{
	pr_warn("mremap not supported\n");
	return -EOPNOTSUPP;
}

static bool validate_update_info(const struct obmm_region *region,
				 const struct obmm_cmd_update_range *update_info,
				 bool cacheable)
{
	bool valid;

	if (!cacheable) {
		pr_err("Ownership operation is not applicable to o-sync mmap %d.\n",
		       region->regionid);
		return false;
	}
	if (!region->ownership_info) {
		pr_err("error updating ownership: ownership of memdev %d not initialized.\n",
		       region->regionid);
		return false;
	}

	valid = update_info->start < update_info->end &&
		IS_ALIGNED(update_info->start, PAGE_SIZE) &&
		IS_ALIGNED(update_info->end, PAGE_SIZE);
	if (!valid)
		pr_err("{pid=%d, start=%#llx end=%#llx is not a valid page range from memdev %d.\n",
		       current->pid, update_info->start, update_info->end, region->regionid);
	return valid;
}
static int obmm_vma_mprotect(struct vm_area_struct *vma __always_unused,
			     unsigned long start __always_unused, unsigned long end __always_unused,
			     unsigned long newflags __always_unused)
{
	pr_warn("mprotect not supported\n");
	return -EOPNOTSUPP;
}
static vm_fault_t obmm_vma_fault(struct vm_fault *vmf __always_unused)
{
	pr_warn("Unexpected fault\n");
	return VM_FAULT_SIGBUS;
}
static int obmm_vma_access(struct vm_area_struct *vma __always_unused,
			   unsigned long addr __always_unused, void *buf __always_unused,
			   int len __always_unused, int write __always_unused)
{
	pr_warn("access not supported\n");
	return -EOPNOTSUPP;
}
static const char *obmm_vma_name(struct vm_area_struct *vma __always_unused)
{
	return "OBMM_SHM";
}

static unsigned long obmm_pagesize(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct obmm_region *reg = (struct obmm_region *)filp->private_data;

	if (reg->mmap_granu == OBMM_MMAP_GRANU_PMD)
		return PMD_SIZE;
	else
		return PAGE_SIZE;
}

static const struct vm_operations_struct obmm_vm_ops = {
	.open = obmm_vma_open,
	.close = obmm_vma_close,
	.may_split = obmm_vma_may_split,
	.mremap = obmm_vma_mremap,
	.mprotect = obmm_vma_mprotect,
	.fault = obmm_vma_fault,
	.access = obmm_vma_access,
	.name = obmm_vma_name,
	.pagesize = obmm_pagesize,
};

static int obmm_shm_fops_open(struct inode *inode, struct file *file)
{
	struct obmm_region *reg;
	bool cacheable;

	reg = container_of(inode->i_cdev, struct obmm_region, cdevice);
	file->private_data = reg;

	pr_debug("obmm_shmdev open: mem_id=%d pid=%d f_mode=%#x f_flags=%#x\n", reg->regionid,
		 current->pid, file->f_mode, file->f_flags);

	cacheable = !(file->f_flags & O_SYNC);
	if (cacheable && !(reg->mem_cap & OBMM_MEM_ALLOW_CACHEABLE_MMAP)) {
		pr_err("Noncacheable region %d cannot be mmaped with cachable mode.\n",
		       reg->regionid);
		return -EPERM;
	}
	if (!cacheable && !(reg->mem_cap & OBMM_MEM_ALLOW_NONCACHEABLE_MMAP)) {
		pr_err("Cacheable region %d cannot be mmaped with noncachable mode.\n",
		       reg->regionid);
		return -EPERM;
	}
	if (try_get_obmm_region(reg) == NULL) {
		pr_err("obmm_shmdev open: The device is in creation or destruction process. Open failed.\n");
		return -EAGAIN;
	}

	pr_debug("obmm_shmdev open: mem_id=%d pid=%d completed.\n", reg->regionid, current->pid);

	return 0;
}

static int obmm_shm_fops_flush(struct file *file __always_unused, fl_owner_t owner __always_unused)
{
	return 0;
}

static int obmm_shm_fops_release(struct inode *inode __always_unused, struct file *file)
{
	struct obmm_region *reg = (struct obmm_region *)file->private_data;

	pr_debug("obmm_shmdev release: mem_id=%d pid=%d\n", reg->regionid, current->pid);
	put_obmm_region(reg);

	return 0;
}

static int map_obmm_region(struct vm_area_struct *vma, struct obmm_region *reg,
			   enum obmm_mmap_granu mmap_granu)
{
	struct obmm_export_region *e_reg;
	struct obmm_import_region *i_reg;

	pr_debug("mmap region %d: size=%#llx\n", reg->regionid, reg->mem_size);
	if (reg->type == OBMM_IMPORT_REGION) {
		i_reg = container_of(reg, struct obmm_import_region, region);
		return map_import_region(vma, i_reg, mmap_granu);
	}

	e_reg = container_of(reg, struct obmm_export_region, region);
	return map_export_region(vma, e_reg, mmap_granu);
}

/* Return page table protection bits.
 * @mem_state must be validated by caller.
 */
static pgprot_t mem_state_to_pgprot(unsigned long mem_state)
{
	pgprot_t pgprot;

	/* initialize pgprot to be normal memory pgprot with certain access rights */
	if ((mem_state & OBMM_SHM_MEM_ACCESS_MASK) == OBMM_SHM_MEM_READONLY) {
		pgprot = PAGE_READONLY;
	} else if ((mem_state & OBMM_SHM_MEM_ACCESS_MASK) == OBMM_SHM_MEM_READEXEC) {
		pgprot = PAGE_READONLY_EXEC;
	} else if ((mem_state & OBMM_SHM_MEM_ACCESS_MASK) == OBMM_SHM_MEM_READWRITE) {
		/*
		 * Use PAGE_SHARED (PTE_RDONLY | PTE_WRITE) and clear PTE_RDONLY
		 * to make the page immediately writable. This ensures:
		 * 1. pte_write() returns true (PTE_WRITE/PTE_DBM bit set)
		 * 2. Page is writable on both DBM and non-DBM platforms
		 * 3. generic_access_phys() can properly verify write permission
		 */
		pgprot = PAGE_SHARED;
		pgprot.pgprot &= ~PTE_RDONLY;
	} else {
		pgprot = PAGE_NONE;
	}

	/* modify cacheability attribute if necessary */
	if ((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_NORMAL_NC)
		pgprot = pgprot_writecombine(pgprot);
	else if ((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_DEVICE)
		pgprot = pgprot_noncached(pgprot);

	return pgprot;
}

static void print_mmap_param(const struct file *file, const struct vm_area_struct *vma)
{
	const struct obmm_region *reg = (struct obmm_region *)file->private_data;
	const char *vm_flags_desc, *f_flags_desc;

	pr_debug("obmm_shmdev mmap: mem_id=%d pid=%d vma=[%#lx, %#lx] pgoff=%#lx ", reg->regionid,
		 current->pid, vma->vm_start, vma->vm_end, vma->vm_pgoff);

	if (vma->vm_flags & VM_WRITE)
		vm_flags_desc = "W";
	else if ((vma->vm_flags & VM_READ) && (vma->vm_flags & VM_EXEC))
		vm_flags_desc = "RX";
	else if (vma->vm_flags & VM_READ)
		vm_flags_desc = "R";
	else
		vm_flags_desc = "N";

	if (file->f_flags & O_SYNC)
		f_flags_desc = "O_SYNC";
	else
		f_flags_desc = "not O_SYNC";

	pr_debug("vm_flags=%#lx(%s) f_flags=%#x(%s)\n", vma->vm_flags, vm_flags_desc, file->f_flags,
		 f_flags_desc);
}

static bool validate_perm(struct file *file, vm_flags_t vm_flags)
{
	if (((vm_flags & VM_READ) && !(file->f_mode & FMODE_READ)) ||
	    ((vm_flags & VM_WRITE) && !(file->f_mode & FMODE_WRITE)) ||
	    ((vm_flags & VM_EXEC) && !(file->f_mode & FMODE_READ))) {
		pr_err("%s false: vm_flags: %#lx, f_mode: %#x\n", __func__, vm_flags, file->f_mode);
		return false;
	}
	return true;
}

static int obmm_shm_fops_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct obmm_region *reg = (struct obmm_region *)file->private_data;
	unsigned long size, offset;
	uint8_t mem_state;
	enum obmm_mmap_mode old_mmap_mode;
	enum obmm_mmap_granu mmap_granu, init_mmap_granu;
	int ret;
	bool cacheable, o_sync;

	print_mmap_param(file, vma);
	if (!region_allow_mmap(reg)) {
		pr_err("mmap region %d: not allow to be mmaped\n", reg->regionid);
		return -EPERM;
	}

	if (!validate_perm(file, vma->vm_flags)) {
		pr_err("mmap region %d: invalid vma permission\n", reg->regionid);
		return -EPERM;
	}

	o_sync = file->f_flags & O_SYNC;
	size = vma->vm_end - vma->vm_start;
	offset = vma->vm_pgoff << PAGE_SHIFT;

	if (offset & OBMM_MMAP_FLAG_HUGETLB_PMD) {
		pr_debug("trying hugepage mmap\n");
		offset &= ~OBMM_MMAP_FLAG_HUGETLB_PMD;
		if (vma->vm_start % PMD_SIZE || vma->vm_end % PMD_SIZE) {
			pr_err("error running huge mmap for not pmd-aligned vma: %#lx-%#lx\n",
				vma->vm_start, vma->vm_end);
			return -EINVAL;
		}
		mmap_granu = OBMM_MMAP_GRANU_PMD;
	} else {
		mmap_granu = OBMM_MMAP_GRANU_PAGE;
	}
	init_mmap_granu = reg->mmap_granu;
	if (reg->mmap_granu == OBMM_MMAP_GRANU_NONE) {
		reg->mmap_granu = mmap_granu;
	} else if (reg->mmap_granu != mmap_granu) {
		pr_err("map with PAGE_SIZE and PMD_SIZE granu should not be mixed on the same region\n");
		ret = -EPERM;
		goto err_reset_mmap_granu;
	}

	vma->vm_pgoff = offset >> PAGE_SHIFT;

	if (offset >= reg->mem_size || size > reg->mem_size - offset) {
		pr_err("mmap region %d: offset:%#lx, size:%#lx over region size: %#llx",
		       reg->regionid, offset, size, reg->mem_size);
		ret = -EINVAL;
		goto err_reset_mmap_granu;
	}

	/*
	 * VM flags considerations
	 * Compared to legacy device memory, OBMM memory has many different properties:
	 *   1. does not have side-effects on access (VM_IO not set)
	 *   2. may be used for core dump output (VM_DONTDUMP not set)
	 * On the other hand, OBMM and traditional device memory do have some similarities:
	 *   3. the mapping cannot be inherited on process fork (VM_DONTCOPY set) for now
	 *   4. VMA merging and expanding makes no sense (VM_DONTEXPAND set)
	 *   5. the VMA should not be swapped out (VM_LOCKED set)
	 *   6. mappable import region does not has struct page; mappable export region haves struct
	 *      page, but cannot work as expected since its kernel linear mapping might be modified
	 *      (VM_PFNMAP set)
	 */
	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_LOCKED | VM_PFNMAP);
	cacheable = o_sync ? false : true;
	mem_state = get_vma_mem_state(vma->vm_flags, cacheable);

	/* initial VMA page prot used by the mapping process -- will be changed later */
	vma->vm_page_prot = mem_state_to_pgprot(mem_state);

	mutex_lock(&reg->state_mutex);
	old_mmap_mode = reg->mmap_mode;

	if ((o_sync && reg->mmap_mode == OBMM_MMAP_NORMAL) ||
	    (!o_sync && reg->mmap_mode == OBMM_MMAP_OSYNC)) {
		pr_err("region cannot be mapped to cc and nc at the same time");
		ret = -EPERM;
		goto err_mutex_unlock;
	}
	if (reg->mmap_mode == OBMM_MMAP_INIT)
		reg->mmap_mode = o_sync ? OBMM_MMAP_OSYNC : OBMM_MMAP_NORMAL;

	/* cc mmap */
	if (reg->mmap_mode == OBMM_MMAP_NORMAL) {
		if (mmap_granu == OBMM_MMAP_GRANU_PAGE) {
			ret = init_local_state_info(vma, mem_state);
			if (ret) {
				pr_err("init local state info failed: %pe\n", ERR_PTR(ret));
				goto reset_cur_osync;
			}
			/*
			 * initialize region-level ownership info if not done yet.
			 * once initialized, the OBMM ownership will persist until
			 * the memdev goes offline
			 */
			ret = init_ownership_info(reg);
			if (ret)
				goto err_release_local_state_info;
			/*
			 * after ownership_info initialized, mmap_granu should not be
			 * reset to OBMM_MMAP_GRANU_NONE.
			 */
			init_mmap_granu = reg->mmap_granu;
			ret = check_mmap_allowed(reg, vma, mem_state);
			if (ret)
				goto err_release_local_state_info;
		}

		ret = map_obmm_region(vma, reg, mmap_granu);
		if (ret) {
			pr_err("Failed to mmap region %d. ret=%pe\n", reg->regionid, ERR_PTR(ret));
			goto err_release_local_state_info;
		}
		if (mmap_granu == OBMM_MMAP_GRANU_PAGE)
			add_mapping_permission(reg, vma, mem_state);
	} else {
		/* cc-region with nc-mmap(o-sync) */
		ret = map_obmm_region(vma, reg, mmap_granu);
		if (ret) {
			pr_err("Failed to mmap region %d. ret=%pe\n", reg->regionid, ERR_PTR(ret));
			goto reset_cur_osync;
		}
	}
	reg->mmap_count++;
	mutex_unlock(&reg->state_mutex);
	/*
	 * since OBMM allows changing protection by pages and we will not split
	 * VMA in near future. Therefore a mismatch between PTE protection and
	 * VMA flags is inevitable. Our current approach is to avoid all
	 * possible faults to change the PTE protection on the fly. Here we
	 * just set the page protection to the most restrictive one to guard
	 * against unexpected access.
	 */
	vma->vm_page_prot = vm_get_page_prot(VM_NONE);
	if (!cacheable)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	vm_flags_clear(vma, VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE);

	vma->vm_ops = &obmm_vm_ops;

	pr_debug("obmm_shmdev mmap: mem_id=%d pid=%d vma=[%#lx, %#lx] mapped: mem_state=%#x.\n",
		 reg->regionid, current->pid, vma->vm_start, vma->vm_end, mem_state);

	return 0;

err_release_local_state_info:
	if (mmap_granu == OBMM_MMAP_GRANU_PAGE)
		release_local_state_info(vma);
reset_cur_osync:
	if (old_mmap_mode == OBMM_MMAP_INIT)
		reg->mmap_mode = OBMM_MMAP_INIT;
err_mutex_unlock:
	mutex_unlock(&reg->state_mutex);
err_reset_mmap_granu:
	reg->mmap_granu = init_mmap_granu;
	return ret;
}

/*
 * Verify whether mem_state is valid.
 */
static bool validate_state(uint8_t mem_state)
{
	if (mem_state & ~(OBMM_SHM_MEM_CACHE_MASK | OBMM_SHM_MEM_ACCESS_MASK)) {
		pr_err("Invalid mem_state: %#x", mem_state);
		return false;
	}

	/* validate cacheability field */
	if ((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_CACHE_RESV) {
		pr_err("Invalid mem_state: %#x -- reserved cacheability", mem_state);
		return false;
	}
	/* currently no need to validate access permission field */

	if (((mem_state & OBMM_SHM_MEM_ACCESS_MASK) == OBMM_SHM_MEM_READEXEC) &&
	    (((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_DEVICE) ||
	     (mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_NORMAL_NC)) {
		pr_err("Bad target mem_state configuration: NC memory cannot be executable\n");
		return false;
	}

	if (((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_NORMAL_NC) &&
	    ((mem_state & OBMM_SHM_MEM_ACCESS_MASK) != OBMM_SHM_MEM_NO_ACCESS)) {
		pr_err("Invalid access state transition: cannot set cacheable region to an accessible but non-cacheable state.\n");
		return false;
	}

	return true;
}

static bool validate_cache_ops(uint8_t cache_ops)
{
	if (cache_ops != OBMM_SHM_CACHE_NONE &&
	    cache_ops != OBMM_SHM_CACHE_INVAL &&
	    cache_ops != OBMM_SHM_CACHE_WB_INVAL) {
		pr_err("Invalid cache operations: 0x%x\n", cache_ops);
		return false;
	}
	return true;
}

static int update_pte_prot(pte_t *ptep, unsigned long addr __always_unused, void *data)
{
	pgprot_t *pgprot = (pgprot_t *)data;
	pte_t ptent_old, ptent_new;

	ptent_old = ptep_get(ptep);

	ptent_new = pfn_pte(pte_pfn(ptent_old), *pgprot);
	if (pte_special(ptent_old))
		ptent_new = pte_mkspecial(ptent_new);

	set_pte(ptep, ptent_new);
	return 0;
}

static void log_ownership_change(struct obmm_region *reg, uint64_t start, uint64_t end,
				 uint8_t mem_state, uint8_t cache_ops)
{
	pr_debug("obmm memory %d ownership change: pid=%d start=%#llx end=%#llx mem_state=%u cache_ops=%u\n",
		reg->regionid, current->pid, start, end, mem_state, cache_ops);
}

/* the caller holds mm mmap lock */
static long update_region_page_range(const struct obmm_cmd_update_range *update_info)
{
	int ret;
	pgprot_t pgprot;

	/* decide new page protection properties */
	pgprot = mem_state_to_pgprot(update_info->mem_state);

	/*
	 * we currently do not update VMA properties. Instead we manipulate the
	 * page table entries directly: VMA-level manipulation is not
	 * preferrable because the users want to have page-level control.
	 * Sub-VMA manipulations, which involves frequent merge and split,
	 * require efforts. But we just do not have enough time.
	 */

	pr_debug("changing pgtable pgprot to 0x%llx: pid=%d start=0x%llx end=0x%llx\n",
		 pgprot_val(pgprot), current->pid, update_info->start, update_info->end);
	/* not sure whether this part MUST be protected by the write lock */
	ret = apply_to_page_range(current->mm, update_info->start,
				  update_info->end - update_info->start, update_pte_prot, &pgprot);
	if (ret) {
		pr_err("failed to change pgprot to 0x%llx: pid=%d start=0x%llx end=0x%llx\n",
		       pgprot_val(pgprot), current->pid, update_info->start, update_info->end);
		return ret;
	}
	pr_debug("user pgtable updated\n");
	obmm_flush_tlb(current->mm);
	pr_debug("TLB flushed\n");

	return 0;
}

static bool validate_vma_attrs(struct vm_area_struct *vma, struct file *file,
			       const struct obmm_cmd_update_range *update_info)
{
	if (!vma) {
		pr_err("vma not found for update range: start=%#llx end=%#llx.\n",
		       update_info->start, update_info->end);
		return false;
	}
	if (vma->vm_file == NULL || file == NULL ||
	    vma->vm_file->private_data != file->private_data) {
		pr_err("VA range [%#llx, %#llx) is not a mapping of the target memdev.\n",
		       update_info->start, update_info->end);
		return false;
	}
	if (update_info->start < vma->vm_start || update_info->end > vma->vm_end) {
		pr_err("invalid update range: request [%#llx, %#llx), full range [%#lx, %#lx)\n",
		       update_info->start, update_info->end, vma->vm_start, vma->vm_end);
		return false;
	}
	return true;
}

struct scan_context {
	struct obmm_region *reg;
	struct obmm_local_state_info *local_state_info;
	unsigned long vma_start;
	uint8_t target_mem_state;
	uint8_t range_mem_state;
	unsigned long local_page_idx;
	unsigned long page_count;
};

static int do_scan_region_and_flush(struct scan_context *ctx, unsigned long region_page_idx_start,
				    unsigned long idx_offset_start, unsigned long idx_offset,
				    bool is_read)
{
	uint8_t cache_ops;
	unsigned long phys_offset, size;

	cache_ops = is_read ? OBMM_SHM_CACHE_INVAL : OBMM_SHM_CACHE_WB_INVAL;
	phys_offset = (region_page_idx_start + idx_offset_start) << PAGE_SHIFT;
	size = (idx_offset - idx_offset_start) << PAGE_SHIFT;
	return obmm_region_flush_range(ctx->reg, phys_offset, size, cache_ops);
}

/*
 * Scan the global permission count and flush the cache
 * for intervals where the read permission count is 1
 * and write permission count is 0.
 */
static int scan_region_and_flush(struct scan_context *ctx, bool is_read)
{
	unsigned long idx_offset, region_page_idx_start, idx_offset_start;
	struct obmm_ownership_info *info;
	int ret;
	uint32_t state_count, read_count, write_count;
	bool start_flag, stop_flag;

	info = ctx->reg->ownership_info;
	/* translate to region page idx */
	region_page_idx_start = ctx->local_page_idx + ctx->local_state_info->orig_pgoff;

	idx_offset_start = -1;
	for (idx_offset = 0; idx_offset < ctx->page_count; idx_offset++) {
		state_count = info->mem_state_arr[region_page_idx_start + idx_offset];
		read_count = GET_R_COUNTER(state_count);
		write_count = GET_W_COUNTER(state_count);

		if (is_read) {
			start_flag = (write_count == 0 && read_count == 1);
			stop_flag = (write_count != 0 || read_count != 1);
		} else {
			start_flag = (write_count == 1);
			stop_flag = (write_count != 1);
		}

		if (start_flag && idx_offset_start == -1) {
			idx_offset_start = idx_offset;
		} else if (stop_flag && idx_offset_start != -1) {
			/* flush the range [idx_offset_start, idx_offset) */
			ret = do_scan_region_and_flush(ctx, region_page_idx_start, idx_offset_start,
						       idx_offset, is_read);
			if (ret)
				return ret;
			idx_offset_start = -1;
		}
	}
	/* check if there is a range not flushed */
	if (idx_offset_start != -1) {
		ret = do_scan_region_and_flush(ctx, region_page_idx_start, idx_offset_start,
					       idx_offset, is_read);
		if (ret)
			return ret;
	}
	return 0;
}

static int do_scan_and_flush(struct scan_context *ctx)
{
	int ret;
	uint8_t cache_ops;
	unsigned long size, vm_start;

	cache_ops = infer_cache_ops(ctx->range_mem_state, ctx->target_mem_state);
	vm_start = ctx->vma_start + (ctx->local_page_idx << PAGE_SHIFT);
	size = (unsigned long)ctx->page_count << PAGE_SHIFT;

	log_ownership_change(ctx->reg, vm_start, vm_start + size, ctx->target_mem_state, cache_ops);
	if (cache_ops == OBMM_SHM_CACHE_NONE) {
		/* ignore none ops */
		ret = 0;
	} else if (cache_ops == OBMM_SHM_CACHE_WB_INVAL || cache_ops == OBMM_SHM_CACHE_WB_ONLY) {
		/* may need to split and flush */
		ret = scan_region_and_flush(ctx, false);
	} else {
		/* may need to split and flush */
		ret = scan_region_and_flush(ctx, true);
	}
	return ret;
}

/*
 * Scan pages in a range and flush pages which are not in use.
 * The caller holds region state_mutex lock.
 */
static int scan_and_flush(struct obmm_region *reg, struct vm_area_struct *vma,
			  const struct obmm_cmd_update_range *update_info)
{
	struct obmm_local_state_info *local_state_info;
	int idx_offset, page_count, local_page_idx_start, idx_offset_start;
	uint8_t mem_state_start, mem_state;
	struct scan_context ctx;
	int ret;

	page_count = (update_info->end - update_info->start) >> PAGE_SHIFT;

	local_state_info = (struct obmm_local_state_info *)vma->vm_private_data;
	local_page_idx_start = vma_addr_to_page_idx_local(vma, update_info->start);

	ctx.reg = reg;
	ctx.local_state_info = local_state_info;
	ctx.vma_start = vma->vm_start;
	ctx.target_mem_state = update_info->mem_state;

	idx_offset_start = 0;
	mem_state_start = local_state_info->local_mem_state_arr[local_page_idx_start];
	for (idx_offset = 1; idx_offset < page_count; idx_offset++) {
		mem_state =
			local_state_info->local_mem_state_arr[local_page_idx_start + idx_offset];
		if (mem_state == mem_state_start)
			continue;

		ctx.range_mem_state = mem_state_start;
		ctx.local_page_idx = local_page_idx_start + idx_offset_start;
		ctx.page_count = idx_offset - idx_offset_start;

		ret = do_scan_and_flush(&ctx);
		if (ret)
			return ret;

		idx_offset_start = idx_offset;
		mem_state_start = mem_state;
	}

	ctx.range_mem_state = mem_state_start;
	ctx.local_page_idx = local_page_idx_start + idx_offset_start;
	ctx.page_count = idx_offset - idx_offset_start;
	ret = do_scan_and_flush(&ctx);
	return ret;
}

static void print_update_param(const struct obmm_cmd_update_range *update_info)
{
	pr_debug("obmm_set_ownership: pid=%d va=[%#llx, %#llx) mem_state=%#x cache_ops=%#x\n",
		 current->pid, update_info->start, update_info->end, update_info->mem_state,
		 update_info->cache_ops);
}

static bool validate_ownership_perm(struct file *file,
				    const struct obmm_cmd_update_range *update_info)
{
	uint8_t access_param = update_info->mem_state & OBMM_SHM_MEM_ACCESS_MASK;
	vm_flags_t tmp_vmflags = VM_NONE;

	if (access_param == OBMM_SHM_MEM_READONLY)
		tmp_vmflags |= VM_READ;
	if (access_param == OBMM_SHM_MEM_READWRITE)
		tmp_vmflags |= (VM_READ | VM_WRITE);
	if (access_param == OBMM_SHM_MEM_READEXEC)
		tmp_vmflags |= (VM_READ | VM_EXEC);
	return validate_perm(file, tmp_vmflags);
}

static long obmm_shm_update_range(struct file *file,
				  const struct obmm_cmd_update_range *update_info)
{
	int ret;
	unsigned long phys_offset;
	struct obmm_region *reg = (struct obmm_region *)file->private_data;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct obmm_local_state_info *local_state_info;
	uint8_t cache_ops;
	bool cacheable;

	print_update_param(update_info);

	if (file->f_flags & O_SYNC)
		cacheable = false;
	else
		cacheable = true;
	/* quick validation without VMA info. */
	if (!validate_update_info(reg, update_info, cacheable))
		return -EINVAL;

	if (!validate_ownership_perm(file, update_info)) {
		pr_err("The target permission is not allowed for the vma.\n");
		return -EPERM;
	}

	if (!validate_state(update_info->mem_state))
		return -EINVAL;

	if (update_info->cache_ops != OBMM_SHM_CACHE_INFER) {
		/* validate cache operations */
		if (!validate_cache_ops(update_info->cache_ops))
			return -EINVAL;
	}

	mmap_read_lock(mm);

	vma = find_vma(mm, update_info->start);
	if (!validate_vma_attrs(vma, file, update_info)) {
		ret = -EFAULT;
		goto err_unlock;
	}

	local_state_info = (struct obmm_local_state_info *)vma->vm_private_data;

	mutex_lock(&reg->state_mutex);

	ret = check_modify_ownership_allowed(reg, vma, update_info);
	if (ret) {
		pr_err("check range (%llx-%llx) ownership failed: %d\n", update_info->start,
		       update_info->end, ret);
		goto err_mutex;
	}

	ret = update_region_page_range(update_info);
	if (ret)
		goto err_mutex;
	/*
	 * If the user specifies a cache operation, we perform the operation
	 * on the range specified by update_info. Otherwise,
	 * we dynamically calculate whether the cache operation is needed.
	 */
	if (update_info->cache_ops != OBMM_SHM_CACHE_INFER) {
		cache_ops = update_info->cache_ops;
		log_ownership_change(reg, update_info->start, update_info->end,
				     update_info->mem_state, cache_ops);
		/* conditionally flush L3 cache & ub controller packet queue */
		phys_offset = update_info->start - vma->vm_start +
			      (local_state_info->orig_pgoff << PAGE_SHIFT);
		ret = obmm_region_flush_range(reg, phys_offset,
					      update_info->end - update_info->start, cache_ops);
	} else {
		ret = scan_and_flush(reg, vma, update_info);
	}

	if (ret) {
		/* original ownership has been lost. */
		pr_err("ownership update: failed to flush cache, ret=%pe. not recoverable.\n",
		       ERR_PTR(ret));
		ret = -ENOTRECOVERABLE;
		goto err_mutex;
	}
	update_ownership(reg, vma, update_info);

	mutex_unlock(&reg->state_mutex);
	mmap_read_unlock(mm);

	pr_debug("obmm_set_ownership: completed.\n");
	return 0;

err_mutex:
	mutex_unlock(&reg->state_mutex);
err_unlock:
	mmap_read_unlock(mm);
	return ret;
}

static long obmm_shm_fops_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;

	switch (cmd) {
	case OBMM_SHMDEV_UPDATE_RANGE: {
		struct obmm_cmd_update_range cmd_update_range;

		ret = (long)copy_from_user(&cmd_update_range, (void __user *)arg,
					   sizeof(struct obmm_cmd_update_range));
		if (ret) {
			pr_err("failed to load update_range argument");
			return -EFAULT;
		}

		ret = obmm_shm_update_range(file, &cmd_update_range);
	} break;
	default:
		ret = -ENOTTY;
	}
	return ret;
}

const struct file_operations obmm_shm_fops = { .owner = THIS_MODULE,
					       .unlocked_ioctl = obmm_shm_fops_ioctl,
					       .mmap = obmm_shm_fops_mmap,
					       .get_unmapped_area = thp_get_unmapped_area,
					       .open = obmm_shm_fops_open,
					       .flush = obmm_shm_fops_flush,
					       .release = obmm_shm_fops_release };

static void obmm_shm_dev_release(struct device *dev)
{
	struct obmm_region *reg = container_of(dev, struct obmm_region, device);

	atomic_set(&reg->device_released, 1);
	module_put(THIS_MODULE);
}

void wait_until_dev_released(struct obmm_region *reg)
{
	while (atomic_read(&reg->device_released) == 0)
		cpu_relax();
}

int obmm_shm_dev_add(struct obmm_region *reg)
{
	int ret;
	dev_t devt;

	if (!try_module_get(THIS_MODULE)) {
		pr_err("Module is dying. Reject all memory requests\n");
		return -EPERM;
	}

	reg->mmap_count = 0;
	reg->mmap_mode = OBMM_MMAP_INIT;

	devt = MKDEV(MAJOR(obmm_devt), reg->regionid);
	cdev_init(&reg->cdevice, &obmm_shm_fops);
	reg->cdevice.owner = THIS_MODULE;
	reg->device.devt = devt;
	reg->device.release = obmm_shm_dev_release;
	reg->device.groups = obmm_region_get_attr_groups(reg);
	reg->device.parent = obmm_shm_rootdev;
	device_initialize(&reg->device);

	ret = dev_set_name(&reg->device, "obmm_shmdev%d", reg->regionid);
	if (ret) {
		pr_err("Failed to set name for shmdev %d. ret=%pe\n", reg->regionid, ERR_PTR(ret));
		goto err_put_dev;
	}

	ret = cdev_device_add(&reg->cdevice, &reg->device);
	if (ret) {
		pr_err("Failed to add shm device %d. ret=%pe\n", reg->regionid, ERR_PTR(ret));
		goto err_put_dev;
	}

	atomic_set(&reg->device_released, 0);

	return 0;

	/* NOTE: If the device is properly initialized, the refcount of module
	 * should be maintained by device kobject (and the associated
	 * obmm_shm_dev_release function). The refcount of region is always
	 * recovered by kobject-triggered release function.
	 */
err_put_dev:
	put_device(&reg->device);
	return ret;
}

void obmm_shm_dev_del(struct obmm_region *reg)
{
	cdev_device_del(&reg->cdevice, &reg->device);
	put_device(&reg->device);
}

int obmm_shm_dev_init(void)
{
	int ret;

	pr_info("shmdev: root device initialization started\n");
	ret = alloc_chrdev_region(&obmm_devt, OBMM_MIN_VALID_REGIONID, OBMM_REGIONID_MAX_COUNT,
				  obmm_shm_region_name);
	if (ret) {
		pr_err("Failed to allocate char device ID. ret=%pe\n", ERR_PTR(ret));
		goto err_reg_alloc;
	}

	obmm_shm_rootdev = root_device_register(obmm_shm_rootdev_name);
	if (IS_ERR_OR_NULL(obmm_shm_rootdev)) {
		pr_err("error register obmm root device\n");
		ret = -ENOMEM;
		goto err_rootdev;
	}

	pr_info("shmdev: root device initialization completed\n");
	return 0;
err_rootdev:
	unregister_chrdev_region(obmm_devt, OBMM_REGIONID_MAX_COUNT);
err_reg_alloc:
	return ret;
}

void obmm_shm_dev_exit(void)
{
	pr_info("shmdev: root device starts shutting down\n");
	root_device_unregister(obmm_shm_rootdev);
	unregister_chrdev_region(obmm_devt, OBMM_REGIONID_MAX_COUNT);
	pr_info("shmdev: root device shut down completed\n");
}
