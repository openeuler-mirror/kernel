// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <asm/tlbflush.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pagewalk.h>
#include <linux/pgtable.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "obmm_cache.h"
#include "obmm_sysfs.h"
#include "obmm_export_region_ops.h"
#include "obmm_import.h"
#include "obmm_ownership.h"
#include "obmm_shm_dev.h"

#include <linux/mm_inline.h>

static dev_t obmm_devt;

static const char *obmm_shm_region_name = "OBMM_SHMDEV";
static const char *obmm_shm_rootdev_name = "obmm";
static struct device *obmm_shm_rootdev;

/* VMA operations for obmm-mmaped VMA */
static void obmm_vma_open(struct vm_area_struct *vma)
{
	struct obmm_region *reg = vma->vm_file->private_data;

	/* atomic to avoid deadlock: update_range holds state_mutex when calling split_vma */
	atomic_inc(&reg->mmap_count);
}

static void obmm_vma_close(struct vm_area_struct *vma)
{
	struct obmm_region *reg = vma->vm_file->private_data;
	uint8_t access = vm_flags_to_access(vma->vm_flags);
	unsigned long region_pgoff = vma->vm_pgoff;
	unsigned long npages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	uint8_t cache_ops;
	int ret;

	mutex_lock(&reg->state_mutex);

	cache_ops = update_vma_perm_count(reg, region_pgoff, npages, access, OBMM_SHM_MEM_NO_ACCESS);

	if (cache_ops != OBMM_SHM_CACHE_NONE && reg->mmap_mode == OBMM_MMAP_NORMAL) {
		ret = obmm_region_flush_range(reg, region_pgoff << PAGE_SHIFT,
					      npages << PAGE_SHIFT, cache_ops);
		if (ret)
			pr_err("vma close: cache flush failed: %d\n", ret);
	}

	if (atomic_dec_and_test(&reg->mmap_count))
		reg->mmap_mode = OBMM_MMAP_INIT;

	mutex_unlock(&reg->state_mutex);
}

static int obmm_vma_may_split(struct vm_area_struct *vma, unsigned long addr)
{
	struct obmm_region *reg = vma->vm_file->private_data;

	if (!obmm_is_aligned(reg, addr)) {
		pr_err("mmap split must be aligned: addr=%#lx\n", addr);
		return -EINVAL;
	}
	return 0;
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

	if (update_info->start >= update_info->end) {
		pr_err("invalid range: start=%#llx end=%#llx\n",
		       update_info->start, update_info->end);
		return false;
	}

	if (!obmm_is_aligned(region, update_info->start) ||
	    !obmm_is_aligned(region, update_info->end)) {
		pr_err("ownership update must be aligned: pid=%d start=%#llx end=%#llx\n",
		       current->pid, update_info->start, update_info->end);
		return false;
	}

	return true;
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

/*
 * Walk the page table for @addr and extract the PFN.
 * Handles both PTE entries and PMD leaf (huge page) entries.
 * Caller must hold mmap_read_lock (or mmap_write_lock) so that the page
 * table entries cannot be torn or freed concurrently.
 */
static int obmm_lookup_pfn(struct mm_struct *mm, unsigned long addr,
			   unsigned long *pfn)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return -EINVAL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		return -EINVAL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		return -EINVAL;

	pmd = pmd_offset(pud, addr);

	/* PMD leaf (huge page): extract PFN directly */
	if (pmd_leaf(*pmd)) {
		if (!pmd_present(*pmd))
			return -EINVAL;
		*pfn = pmd_pfn(*pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
		return 0;
	}

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return -EINVAL;

	/* Regular PTE: follow_pte handles PTE-level lock and mapping */
	if (follow_pte(mm, addr, &ptep, &ptl))
		return -EINVAL;
	*pfn = pte_pfn(ptep_get(ptep));
	pte_unmap_unlock(ptep, ptl);
	return 0;
}

/* Custom access handler for ptrace/GDB on PFNMAP VMAs */
static int obmm_vma_access(struct vm_area_struct *vma, unsigned long addr,
			   void *buf, int len, int write)
{
	struct obmm_region *reg = vma->vm_file->private_data;
	unsigned long pfn, prot;
	void *kaddr;
	bool is_vmap;
	int offset = offset_in_page(addr);
	int ret = -EINVAL;

	pr_debug("addr=%#lx len=%d write=%d region=%d type=%s\n",
		 addr, len, write, reg->regionid,
		 reg->type == OBMM_EXPORT_REGION ? "export" : "import");

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))
		return -EINVAL;

	/* Check permission from vm_flags */
	if (!(vma->vm_flags & (VM_READ | VM_WRITE)))
		return -EINVAL;
	if (write && !(vma->vm_flags & VM_WRITE))
		return -EINVAL;

	/* Get PFN from page table walk */
	if (obmm_lookup_pfn(vma->vm_mm, addr, &pfn))
		return -EINVAL;

	/* Derive prot from vma->vm_page_prot, adjust for kernel access */
	prot = pgprot_val(vma->vm_page_prot);
	prot &= ~(PTE_USER | PTE_NG);
	prot |= (PTE_PXN | PTE_UXN);

	/* Map one page */
	len = min(len, (int)(PAGE_SIZE - offset));

	if (reg->type == OBMM_EXPORT_REGION) {
		struct page *page;

		if (!pfn_valid(pfn))
			return -EINVAL;
		page = pfn_to_page(pfn);
		kaddr = vmap(&page, 1, VM_MAP, __pgprot(prot));
		is_vmap = true;
	} else {
		resource_size_t phys_addr = (resource_size_t)pfn << PAGE_SHIFT;

		kaddr = (__force void *)ioremap_prot(phys_addr, PAGE_SIZE, prot);
		is_vmap = false;
	}
	if (!kaddr)
		return -ENOMEM;

	if (write)
		ret = copy_mc_to_kernel(kaddr + offset, buf, len) ? -EFAULT : len;
	else
		ret = copy_mc_to_kernel(buf, kaddr + offset, len) ? -EFAULT : len;

	if (is_vmap)
		vunmap(kaddr);
	else
		iounmap((__force void __iomem *)kaddr);
	return ret;
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
		/* Clear PTE_RDONLY for immediate write access on ARM64 */
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
	const struct obmm_region *reg = (const struct obmm_region *)file->private_data;
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
	uint8_t access;
	int ret;
	bool cacheable, o_sync;

	print_mmap_param(file, vma);

	if (!(vma->vm_flags & VM_MAYSHARE)) {
		pr_err("mmap region %d: MAP_PRIVATE is not supported, use MAP_SHARED\n",
		       reg->regionid);
		return -EINVAL;
	}

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

		if (!IS_ALIGNED(vma->vm_start, PMD_SIZE) ||
		    !IS_ALIGNED(vma->vm_end, PMD_SIZE)) {
			pr_err("PMD mmap vma not PMD-aligned: start=%#lx end=%#lx\n",
			       vma->vm_start, vma->vm_end);
			return -EINVAL;
		}

		if (!IS_ALIGNED(offset, PMD_SIZE)) {
			pr_err("PMD mmap offset not PMD-aligned: offset=%#lx\n", offset);
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

	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_LOCKED | VM_PFNMAP);
	cacheable = !o_sync;
	mem_state = vm_flags_to_mem_state(vma->vm_flags, cacheable);
	pr_debug("VMA init mem_state: vma_flags=%#lx, cacheable=%d, mem_state=%#x\n",
		 vma->vm_flags, cacheable, mem_state);

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
		ret = init_ownership_info(reg);
		if (ret)
			goto reset_cur_osync;

		ret = map_obmm_region(vma, reg, mmap_granu);
		if (ret) {
			pr_err("Failed to mmap region %d. ret=%pe\n", reg->regionid, ERR_PTR(ret));
			goto reset_cur_osync;
		}

		access = vm_flags_to_access(vma->vm_flags);
		update_vma_perm_count(reg, vma->vm_pgoff, size >> PAGE_SHIFT,
				      OBMM_SHM_MEM_NO_ACCESS, access);
	} else {
		/* cc-region with nc-mmap(o-sync) */
		ret = map_obmm_region(vma, reg, mmap_granu);
		if (ret) {
			pr_err("Failed to mmap region %d. ret=%pe\n", reg->regionid, ERR_PTR(ret));
			goto reset_cur_osync;
		}
	}
	atomic_inc(&reg->mmap_count);
	mutex_unlock(&reg->state_mutex);

	vma->vm_ops = &obmm_vm_ops;

	pr_debug("obmm_shmdev mmap: mem_id=%d pid=%d vma=[%#lx, %#lx] mapped: mem_state=%#x.\n",
		 reg->regionid, current->pid, vma->vm_start, vma->vm_end, mem_state);

	return 0;

reset_cur_osync:
	if (old_mmap_mode == OBMM_MMAP_INIT)
		reg->mmap_mode = OBMM_MMAP_INIT;
err_mutex_unlock:
	mutex_unlock(&reg->state_mutex);
err_reset_mmap_granu:
	reg->mmap_granu = init_mmap_granu;
	return ret;
}

static bool validate_state(uint8_t mem_state)
{
	if (mem_state & ~(OBMM_SHM_MEM_CACHE_MASK | OBMM_SHM_MEM_ACCESS_MASK)) {
		pr_err("Invalid mem_state: %#x", mem_state);
		return false;
	}

	if ((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_CACHE_RESV) {
		pr_err("Invalid mem_state: %#x -- reserved cacheability", mem_state);
		return false;
	}

	if (((mem_state & OBMM_SHM_MEM_ACCESS_MASK) == OBMM_SHM_MEM_READEXEC) &&
	    ((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_DEVICE ||
	     (mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_NORMAL_NC)) {
		pr_err("NC memory cannot be executable\n");
		return false;
	}

	if ((mem_state & OBMM_SHM_MEM_CACHE_MASK) == OBMM_SHM_MEM_NORMAL_NC &&
	    (mem_state & OBMM_SHM_MEM_ACCESS_MASK) != OBMM_SHM_MEM_NO_ACCESS) {
		pr_err("Cannot set cacheable region to accessible but non-cacheable state\n");
		return false;
	}

	return true;
}

struct update_prot_info {
	pgprot_t newprot;
};

static int update_pmd_entry(pmd_t *pmd, unsigned long addr,
			    unsigned long next __always_unused, struct mm_walk *walk)
{
	struct update_prot_info *info = walk->private;
	pgprot_t newprot = info->newprot;
	struct mm_struct *mm = walk->mm;
	spinlock_t *ptl;
	pmd_t old_pmd, new_pmd;

	if (pmd_none(*pmd))
		return 0;

	if (pmd_leaf(*pmd)) {
		ptl = pmd_lock(mm, pmd);
		old_pmd = *pmd;
		if (pmd_leaf(old_pmd)) {
			new_pmd = pfn_pmd(pmd_pfn(old_pmd), newprot);
			new_pmd = pmd_mkspecial(pmd_mkhuge(new_pmd));
			__set_pte((pte_t *)pmd, pmd_pte(new_pmd));
		}
		spin_unlock(ptl);
		/* Skip PTE-level walk and split_huge_pmd for PFN-mapped huge pages */
		walk->action = ACTION_CONTINUE;
		return 0;
	}

	/* Continue to PTE-level walk */
	return 0;
}

static int update_pte_entry(pte_t *pte, unsigned long addr __always_unused,
			    unsigned long next __always_unused, struct mm_walk *walk)
{
	struct update_prot_info *info = walk->private;
	pgprot_t newprot = info->newprot;
	pte_t old_pte, new_pte;

	old_pte = ptep_get(pte);
	if (pte_none(old_pte))
		return 0;

	new_pte = pfn_pte(pte_pfn(old_pte), newprot);
	if (pte_special(old_pte))
		new_pte = pte_mkspecial(new_pte);

	__set_pte(pte, new_pte);
	return 0;
}

/*
 * Bypass VM_PFNMAP skip in walk_page_test -- OBMM PFN mappings
 * have no struct page but do need page table permission updates.
 */
static int obmm_walk_test(unsigned long start __always_unused,
			  unsigned long end __always_unused, struct mm_walk *walk __always_unused)
{
	return 0;
}

static int update_vma_page_range(struct vm_area_struct *vma, uint8_t mem_state)
{
	pgprot_t pgprot = mem_state_to_pgprot(mem_state);
	struct update_prot_info info = { .newprot = pgprot };
	struct mm_struct *mm = vma->vm_mm;
	unsigned long start = vma->vm_start;
	unsigned long end = vma->vm_end;
	struct mm_walk_ops walk_ops = {
		.test_walk = obmm_walk_test,
		.pmd_entry = update_pmd_entry,
		.pte_entry = update_pte_entry,
	};

	return walk_page_range(mm, start, end, &walk_ops, &info);
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

/* Mask of vm_flags that ownership update is allowed to modify */
#define OBMM_UPDATE_VM_FLAGS_MASK (VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE)

static long obmm_shm_update_range(struct file *file,
				  const struct obmm_cmd_update_range *update_info)
{
	struct obmm_region *reg = file->private_data;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	uint8_t old_access, new_access;
	vm_flags_t new_vm_flags, old_vm_flags;
	unsigned long cursor, region_pgoff, npages, modified_end;
	unsigned long region_offset, length;
	uint8_t cache_ops, flush_op, old_mem_state, cache_bits;
	bool cacheable;
	int ret;

	VMA_ITERATOR(vmi, mm, update_info->start);

	print_update_param(update_info);

	cacheable = !(file->f_flags & O_SYNC);

	if (!validate_update_info(reg, update_info, cacheable))
		return -EINVAL;
	if (!validate_ownership_perm(file, update_info))
		return -EPERM;
	if (!validate_state(update_info->mem_state))
		return -EINVAL;
	if (update_info->cache_ops != OBMM_SHM_CACHE_INFER &&
	    !obmm_is_valid_cache_ops(update_info->cache_ops))
		return -EINVAL;

	new_access = update_info->mem_state & OBMM_SHM_MEM_ACCESS_MASK;
	new_vm_flags = access_to_vm_flags(new_access);
	cache_bits = update_info->mem_state & OBMM_SHM_MEM_CACHE_MASK;

	mmap_write_lock(mm);
	mutex_lock(&reg->state_mutex);

	/*
	 * Phase 1: Single traversal - split, update, and flush per VMA
	 *
	 * We process each VMA in a single pass:
	 * 1. Validate continuity and ownership
	 * 2. Split VMA at range boundaries if needed
	 * 3. Update ownership counters and vm_flags
	 * 4. Execute cache flush for this VMA
	 *
	 * Rollback tracks modified_end to know which VMAs need restoration.
	 */
	modified_end = update_info->start;
	cursor = update_info->start;

	for_each_vma_range(vmi, vma, update_info->end) {
		/* Check VMA continuity */
		if (vma->vm_start > cursor) {
			pr_err("VMA gap detected: expected start=%#lx, actual=%#lx\n",
			       cursor, vma->vm_start);
			ret = -EFAULT;
			goto rollback;
		}
		/* Check VMA belongs to this region */
		if (vma->vm_ops != &obmm_vm_ops ||
		    !vma->vm_file ||
		    vma->vm_file->private_data != reg) {
			pr_err("VMA does not belong to this region: vma=[%#lx, %#lx)\n",
			       vma->vm_start, vma->vm_end);
			ret = -EFAULT;
			goto rollback;
		}

		/* Split at start boundary if needed */
		if (vma->vm_start < cursor) {
			ret = split_vma(&vmi, vma, cursor, 1);
			if (ret) {
				pr_err("Failed to split VMA at start boundary: addr=%#lx, ret=%d\n",
				       cursor, ret);
				goto rollback;
			}
		}
		/* Split at end boundary if needed */
		if (vma->vm_end > update_info->end) {
			ret = split_vma(&vmi, vma, update_info->end, 0);
			if (ret) {
				pr_err("Failed to split VMA at end boundary: addr=%#llx, ret=%d\n",
				       update_info->end, ret);
				goto rollback;
			}
		}

		/*
		 * Mark this VMA as being modified BEFORE we modify it.
		 * This ensures rollback includes this VMA even if subsequent
		 * operations (counter update, flags change, cache flush) fail.
		 */
		modified_end = vma->vm_end;

		old_access = vm_flags_to_access(vma->vm_flags);
		region_pgoff = vma->vm_pgoff;
		npages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
		region_offset = region_pgoff << PAGE_SHIFT;
		length = npages << PAGE_SHIFT;

		/*
		 * Temporarily stash vm_flags in vm_private_data for rollback.
		 * This is safe because OBMM VMAs don't use vm_private_data.
		 */
		vma->vm_private_data = (void *)(uintptr_t)vma->vm_flags;

		cache_ops = update_vma_perm_count(reg, region_pgoff, npages,
						  old_access, new_access);

		vm_flags_clear(vma, OBMM_UPDATE_VM_FLAGS_MASK);
		vm_flags_set(vma, new_vm_flags & OBMM_UPDATE_VM_FLAGS_MASK);
		vma->vm_page_prot = mem_state_to_pgprot(update_info->mem_state);

		/* Determine flush operation for this VMA */
		if (update_info->cache_ops != OBMM_SHM_CACHE_INFER)
			flush_op = update_info->cache_ops;  /* User-specified */
		else if (cache_ops != OBMM_SHM_CACHE_NONE &&
			 reg->mmap_mode == OBMM_MMAP_NORMAL)
			flush_op = cache_ops;  /* INFER: per-VMA precise result */
		else
			flush_op = OBMM_SHM_CACHE_NONE;

		/* Execute cache flush immediately for this VMA */
		if (flush_op != OBMM_SHM_CACHE_NONE) {
			ret = obmm_region_flush_range(reg, region_offset, length, flush_op);
			if (ret)
				goto rollback;
		}

		/* Update page tables for this VMA */
		ret = update_vma_page_range(vma, update_info->mem_state);
		if (ret) {
			pr_err("Failed to update page tables: vma=[%#lx, %#lx) mem_state=%#x ret=%d\n",
			       vma->vm_start, vma->vm_end, update_info->mem_state, ret);
			goto rollback;
		}

		cursor = vma->vm_end;
	}

	/* Check if VMAs cover the entire requested range */
	if (cursor < update_info->end) {
		pr_err("VMAs do not cover requested range: expected_end=%#llx actual_end=%#lx\n",
		       update_info->end, cursor);
		ret = -EFAULT;
		goto rollback;
	}

	obmm_flush_tlb(mm);

	mutex_unlock(&reg->state_mutex);
	mmap_write_unlock(mm);
	return 0;

rollback:
	pr_debug("Rolling back ownership update: region=%d range=[%#llx, %#llx) modified_end=%#lx\n",
		 reg->regionid, update_info->start, update_info->end, modified_end);
	/* Restore only the VMAs we actually modified (up to modified_end) */
	cursor = update_info->start;
	while (cursor < modified_end) {
		vma = find_vma(mm, cursor);
		if (WARN_ON(!vma || vma->vm_start > cursor))
			break;
		old_vm_flags = (vm_flags_t)(uintptr_t)vma->vm_private_data;
		old_access = vm_flags_to_access(old_vm_flags);
		region_pgoff = vma->vm_pgoff;
		npages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

		/* Restore counters */
		update_vma_perm_count(reg, region_pgoff, npages, new_access, old_access);

		/* Restore vm_flags */
		vm_flags_clear(vma, OBMM_UPDATE_VM_FLAGS_MASK);
		vm_flags_set(vma, old_vm_flags & OBMM_UPDATE_VM_FLAGS_MASK);

		/* Restore vm_page_prot */
		old_mem_state = old_access | cache_bits;
		vma->vm_page_prot = mem_state_to_pgprot(old_mem_state);

		/*
		 * Restore page tables.
		 * Note: If failure occurred before page table update (e.g., cache flush
		 * failed), this operation is redundant but harmless - it simply sets
		 * the page tables to their original values.
		 */
		update_vma_page_range(vma, old_mem_state);

		cursor = vma->vm_end;
	}

	obmm_flush_tlb(mm);

	mutex_unlock(&reg->state_mutex);
	mmap_write_unlock(mm);
	return ret;
}

static long obmm_shm_fops_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case OBMM_SHMDEV_UPDATE_RANGE: {
		struct obmm_cmd_update_range cmd_update_range;

		if (copy_from_user(&cmd_update_range, (void __user *)arg,
				   sizeof(cmd_update_range))) {
			pr_err("failed to load update_range argument\n");
			return -EFAULT;
		}

		return obmm_shm_update_range(file, &cmd_update_range);
	}
	default:
		pr_err("unknown ioctl command: %#x\n", cmd);
		return -ENOTTY;
	}
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

	atomic_set(&reg->mmap_count, 0);
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
