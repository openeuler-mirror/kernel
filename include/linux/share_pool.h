/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_SHARE_POOL_H
#define LINUX_SHARE_POOL_H

#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/notifier.h>
#include <linux/vmalloc.h>
#include <linux/printk.h>
#include <linux/hashtable.h>
#include <linux/numa.h>
#include <linux/jump_label.h>

#define SP_HUGEPAGE		(1 << 0)
#define SP_HUGEPAGE_ONLY	(1 << 1)
#define SP_DVPP			(1 << 2)
#define SP_SPEC_NODE_ID		(1 << 3)
#define SP_PROT_RO		(1 << 16)
/*
 * SP_PROT_FOCUS should used with SP_PROT_RO,
 * to alloc a memory within sharepool ro memory.
 */
#define SP_PROT_FOCUS		(1 << 17)

#define DEVICE_ID_BITS		4UL
#define DEVICE_ID_MASK		((1UL << DEVICE_ID_BITS) - 1UL)
#define DEVICE_ID_SHIFT		32UL
#define NODE_ID_BITS		NODES_SHIFT
#define NODE_ID_MASK		((1UL << NODE_ID_BITS) - 1UL)
#define NODE_ID_SHIFT		(DEVICE_ID_SHIFT + DEVICE_ID_BITS)

#define SP_FLAG_MASK		(SP_HUGEPAGE | SP_HUGEPAGE_ONLY | SP_DVPP | \
				 SP_SPEC_NODE_ID | SP_PROT_RO | SP_PROT_FOCUS | \
				(DEVICE_ID_MASK << DEVICE_ID_SHIFT) | \
				(NODE_ID_MASK << NODE_ID_SHIFT))

#define sp_flags_device_id(flags) (((flags) >> DEVICE_ID_SHIFT) & DEVICE_ID_MASK)
#define sp_flags_node_id(flags) (((flags) >> NODE_ID_SHIFT) & NODE_ID_MASK)

#define SPG_ID_NONE	(-1)	/* not associated with sp_group, only for specified thread */
#define SPG_ID_DEFAULT	0	/* use the spg id of current thread */
#define SPG_ID_MIN	1	/* valid id should be >= 1 */
#define SPG_ID_MAX	99999
#define SPG_ID_AUTO_MIN 100000
#define SPG_ID_AUTO_MAX 199999
#define SPG_ID_AUTO     200000  /* generate group id automatically */
#define SPG_ID_LOCAL_MIN	200001
#define SPG_ID_LOCAL_MAX	299999
#define SPG_ID_LOCAL		300000 /* generate group id in local range */

#define MAX_DEVID 8	/* the max num of Da-vinci devices */

extern struct static_key_false share_pool_enabled_key;

struct sp_walk_data {
	struct page **pages;
	unsigned int page_count;
	unsigned long uva_aligned;
	unsigned long page_size;
	bool is_hugepage;
	bool is_page_type_set;
	pmd_t *pmd;
};

#define MAP_SHARE_POOL			0x200000

#define MMAP_TOP_4G_SIZE		0x100000000UL

/* 8T - 64G size */
#define MMAP_SHARE_POOL_NORMAL_SIZE	0x7F000000000UL
/* 64G */
#define MMAP_SHARE_POOL_RO_SIZE		0x1000000000UL
/* 8T size*/
#define MMAP_SHARE_POOL_DVPP_SIZE	0x80000000000UL
/* 16G size */
#define MMAP_SHARE_POOL_16G_SIZE	0x400000000UL
/* skip 8T for stack */
#define MMAP_SHARE_POOL_SKIP		0x80000000000UL
#define MMAP_SHARE_POOL_END		(TASK_SIZE - MMAP_SHARE_POOL_SKIP)
#define MMAP_SHARE_POLL_DVPP_END	(MMAP_SHARE_POOL_END)
/* MMAP_SHARE_POOL_DVPP_START should be align to 16G */
#define MMAP_SHARE_POOL_DVPP_START	(MMAP_SHARE_POLL_DVPP_END - MMAP_SHARE_POOL_DVPP_SIZE)
#define MMAP_SHARE_POOL_RO_END		(MMAP_SHARE_POOL_DVPP_START)
#define MMAP_SHARE_POOL_RO_START	(MMAP_SHARE_POOL_RO_END - MMAP_SHARE_POOL_RO_SIZE)
#define MMAP_SHARE_POOL_NORMAL_END	(MMAP_SHARE_POOL_RO_START)
#define MMAP_SHARE_POOL_NORMAL_START	(MMAP_SHARE_POOL_NORMAL_END - MMAP_SHARE_POOL_NORMAL_SIZE)
#define MMAP_SHARE_POOL_START		(MMAP_SHARE_POOL_NORMAL_START)

#define MMAP_SHARE_POOL_DYNAMIC_DVPP_BASE	0x100000000000ULL
#define MMAP_SHARE_POOL_DYNAMIC_DVPP_END	(MMAP_SHARE_POOL_DYNAMIC_DVPP_BASE + \
						MMAP_SHARE_POOL_16G_SIZE * 64)

#ifdef CONFIG_SHARE_POOL

static inline void sp_init_mm(struct mm_struct *mm)
{
	mm->sp_group_master = NULL;
}

/*
 * Those interfaces are exported for modules
 */
extern int mg_sp_group_add_task(int tgid, unsigned long prot, int spg_id);
extern int mg_sp_group_id_by_pid(int tgid, int *spg_ids, int *num);

extern void *mg_sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id);
extern void *mg_sp_alloc_nodemask(unsigned long size, unsigned long sp_flags, int spg_id,
		nodemask_t nodemask);
extern int mg_sp_free(unsigned long addr, int id);

extern void *mg_sp_make_share_k2u(unsigned long kva, unsigned long size,
			unsigned long sp_flags, int tgid, int spg_id);
extern void *mg_sp_make_share_u2k(unsigned long uva, unsigned long size, int tgid);
extern int mg_sp_unshare(unsigned long va, unsigned long size, int spg_id);

extern int mg_sp_walk_page_range(unsigned long uva, unsigned long size,
	struct task_struct *tsk, struct sp_walk_data *sp_walk_data);

extern void mg_sp_walk_page_free(struct sp_walk_data *sp_walk_data);

extern bool mg_sp_config_dvpp_range(size_t start, size_t size, int device_id, int tgid);

extern bool mg_is_sharepool_addr(unsigned long addr);

extern int mg_sp_id_of_current(void);

extern void sp_area_drop(struct vm_area_struct *vma);
extern void sp_mm_clean(struct mm_struct *mm);
vm_fault_t sharepool_no_page(struct mm_struct *mm,
			     struct vm_area_struct *vma,
			     struct address_space *mapping, pgoff_t idx,
			     unsigned long address, pte_t *ptep, unsigned int flags);
extern bool sp_check_addr(unsigned long addr);
extern bool sp_check_mmap_addr(unsigned long addr, unsigned long flags);
extern int sp_node_id(struct vm_area_struct *vma);

static inline bool sp_is_enabled(void)
{
	return static_branch_likely(&share_pool_enabled_key);
}

static inline void sp_area_work_around(struct vm_unmapped_area_info *info)
{
	if (sp_is_enabled())
		info->high_limit = min(info->high_limit, MMAP_SHARE_POOL_START);
}

static inline bool sp_check_vm_share_pool(unsigned long vm_flags)
{
	if (sp_is_enabled() && (vm_flags & VM_SHARE_POOL))
		return true;

	return false;
}

#else /* CONFIG_SHARE_POOL */

static inline int mg_sp_group_add_task(int tgid, unsigned long prot, int spg_id)
{
	return -EPERM;
}

static inline void sp_mm_clean(struct mm_struct *mm)
{
}

static inline int mg_sp_group_id_by_pid(int tgid, int *spg_ids, int *num)
{
	return -EPERM;
}

static inline void *mg_sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id)
{
	return NULL;
}

static inline int mg_sp_free(unsigned long addr, int id)
{
	return -EPERM;
}

static inline void *mg_sp_make_share_k2u(unsigned long kva, unsigned long size,
			unsigned long sp_flags, int tgid, int spg_id)
{
	return NULL;
}

static inline void *mg_sp_make_share_u2k(unsigned long uva, unsigned long size, int tgid)
{
	return NULL;
}

static inline int mg_sp_unshare(unsigned long va, unsigned long size, int id)
{
	return -EPERM;
}

static inline int mg_sp_id_of_current(void)
{
	return -EPERM;
}

static inline void sp_init_mm(struct mm_struct *mm)
{
}

static inline void sp_area_drop(struct vm_area_struct *vma)
{
}

static inline int mg_sp_walk_page_range(unsigned long uva, unsigned long size,
	struct task_struct *tsk, struct sp_walk_data *sp_walk_data)
{
	return 0;
}

static inline void mg_sp_walk_page_free(struct sp_walk_data *sp_walk_data)
{
}

static inline bool mg_sp_config_dvpp_range(size_t start, size_t size, int device_id, int tgid)
{
	return false;
}

static inline bool mg_is_sharepool_addr(unsigned long addr)
{
	return false;
}

static inline void spa_overview_show(struct seq_file *seq)
{
}

static inline void spg_overview_show(struct seq_file *seq)
{
}

static inline bool sp_is_enabled(void)
{
	return false;
}

static inline void sp_area_work_around(struct vm_unmapped_area_info *info)
{
}

static inline bool sp_check_vm_share_pool(unsigned long vm_flags)
{
	return false;
}

static inline bool is_vm_huge_special(struct vm_area_struct *vma)
{
	return false;
}

static inline bool sp_check_addr(unsigned long addr)
{
	return false;
}

static inline bool sp_check_mmap_addr(unsigned long addr, unsigned long flags)
{
	return false;
}

static inline vm_fault_t sharepool_no_page(struct mm_struct *mm,
			struct vm_area_struct *vma,
			struct address_space *mapping, pgoff_t idx,
			unsigned long address, pte_t *ptep, unsigned int flags)
{
	return VM_FAULT_SIGBUS;
}

static inline int sp_node_id(struct vm_area_struct *vma)
{
	return numa_node_id();
}

#endif /* !CONFIG_SHARE_POOL */

#endif /* LINUX_SHARE_POOL_H */
