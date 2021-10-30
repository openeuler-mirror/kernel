#ifndef LINUX_SHARE_POOL_H
#define LINUX_SHARE_POOL_H

#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/notifier.h>
#include <linux/vmalloc.h>
#include <linux/printk.h>

#define SP_HUGEPAGE		(1 << 0)
#define SP_HUGEPAGE_ONLY	(1 << 1)
#define SP_DVPP			(1 << 2)

#define SPG_ID_NONE	-1	/* not associated with sp_group, only for specified thread */
#define SPG_ID_DEFAULT	0	/* use the spg id of current thread */
#define SPG_ID_MIN	1	/* valid id should be >= 1 */
#define SPG_ID_MAX	99999
#define SPG_ID_AUTO_MIN 100000
#define SPG_ID_AUTO_MAX 199999
#define SPG_ID_AUTO     200000  /* generate group id automatically */
#define SPG_ID_DVPP_PASS_THROUGH_MIN	800000
#define SPG_ID_DVPP_PASS_THROUGH_MAX	899999
#define SPG_ID_DVPP_PASS_THROUGH	900000

#define MAX_DEVID 1	/* the max num of Da-vinci devices */

/* to align the pointer to the (next) PMD boundary */
#define PMD_ALIGN(addr)		ALIGN(addr, PMD_SIZE)

/* test whether an address (unsigned long or pointer) is aligned to PMD_SIZE */
#define PMD_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PMD_SIZE)

extern int sysctl_share_pool_hugepage_enable;

extern int sysctl_ac_mode;

extern int sysctl_sp_debug_mode;

extern int enable_ascend_share_pool;

/* Processes in the same sp_group can share memory.
 * Memory layout for share pool:
 *
 * |-------------------- 8T -------------------|---|------ 8T ------------|
 * |		Device 0	   |  Device 1 |...|                      |
 * |----------------------------------------------------------------------|
 * |- 16G -|- 16G -|- 16G -|- 16G -|     |     |   |                      |
 * | DVPP GROUP0   | DVPP GROUP1   | ... | ... |...|  sp normal memory    |
 * | svm   |  sp   |  svm  |  sp   |     |     |   |                      |
 * |----------------------------------------------------------------------|
 *
 * The host SVM feature reserves 8T virtual memory by mmap, and due to the
 * restriction of DVPP, while SVM and share pool will both allocate memory
 * for DVPP, the memory have to be in the same 32G range.
 *
 * Share pool reserves 16T memory, with 8T for normal uses and 8T for DVPP.
 * Within this 8T DVPP memory, SVM will call sp_config_dvpp_range() to
 * tell us which 16G memory range is reserved for share pool .
 *
 * In some scenarios where there is no host SVM feature, share pool uses
 * the default memory setting for DVPP.
 */
struct sp_group {
	int		 id;
	struct file	 *file;
	struct file	 *file_hugetlb;
	/* list head of processes */
	struct list_head procs;
	/* list of sp_area */
	struct list_head spa_list;
	/* number of sp_area */
	atomic_t	 spa_num;
	/* total size of all sp_area from sp_alloc and k2u(spg) */
	atomic64_t	 size;
	/* record the number of hugepage allocation failures */
	int		 hugepage_failures;
	/* is_alive == false means it's being destroyed */
	bool		 is_alive;
	/* we define the creator process of a sp_group as owner */
	struct task_struct *owner;
	/* dvpp_multi_spaces == true means multiple dvpp 16G spaces are set */
	bool		 dvpp_multi_spaces;
	unsigned long	 dvpp_va_start;
	unsigned long	 dvpp_size;
	atomic_t	 use_count;
};

struct sp_walk_data {
	struct page **pages;
	unsigned int page_count;
	unsigned long uva_aligned;
	unsigned long page_size;
	bool is_hugepage;
};

#ifdef CONFIG_ASCEND_SHARE_POOL

#define MAP_SHARE_POOL			0x100000

#define MMAP_TOP_4G_SIZE		0x100000000UL

/* 8T size */
#define MMAP_SHARE_POOL_NORMAL_SIZE	0x80000000000UL
/* 8T size*/
#define MMAP_SHARE_POOL_DVPP_SIZE	0x80000000000UL
/* 16G size */
#define MMAP_SHARE_POOL_16G_SIZE	0x400000000UL
#define MMAP_SHARE_POOL_SIZE		(MMAP_SHARE_POOL_NORMAL_SIZE + MMAP_SHARE_POOL_DVPP_SIZE)
/* align to 2M hugepage size, and MMAP_SHARE_POOL_TOP_16G_START should be align to 16G */
#define MMAP_SHARE_POOL_END		((TASK_SIZE - MMAP_SHARE_POOL_DVPP_SIZE) & ~((1 << 21) - 1))
#define MMAP_SHARE_POOL_START		(MMAP_SHARE_POOL_END - MMAP_SHARE_POOL_SIZE)
#define MMAP_SHARE_POOL_16G_START	(MMAP_SHARE_POOL_END - MMAP_SHARE_POOL_DVPP_SIZE)

static inline void sp_init_mm(struct mm_struct *mm)
{
	mm->sp_group = NULL;
	INIT_LIST_HEAD(&mm->sp_node);
	mm->sp_stat_id = 0;
}

extern int sp_group_add_task(int pid, int spg_id);
extern void sp_group_exit(struct mm_struct *mm);
extern void sp_group_post_exit(struct mm_struct *mm);
extern int sp_group_id_by_pid(int pid);
extern int sp_group_walk(int spg_id, void *data, int (*func)(struct mm_struct *mm, void *));
extern int proc_sp_group_state(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task);

extern void *sp_alloc(unsigned long size, unsigned long sp_flags, int sp_id);
extern int sp_free(unsigned long addr);
extern void *sp_make_share_k2u(unsigned long kva, unsigned long size,
			unsigned long sp_flags, int pid, int spg_id);
extern void *sp_make_share_u2k(unsigned long uva, unsigned long size, int pid);
extern int sp_unshare(unsigned long va, unsigned long size, int pid, int spg_id);

extern void sp_area_drop(struct vm_area_struct *vma);

extern int sp_walk_page_range(unsigned long uva, unsigned long size,
			      struct task_struct *tsk, struct sp_walk_data *sp_walk_data);
extern void sp_walk_page_free(struct sp_walk_data *sp_walk_data);

extern int sp_register_notifier(struct notifier_block *nb);
extern int sp_unregister_notifier(struct notifier_block *nb);
extern bool sp_config_dvpp_range(size_t start, size_t size, int device_id, int pid);
extern bool is_sharepool_addr(unsigned long addr);
extern void proc_sharepool_init(void);

static inline struct task_struct *sp_get_task(struct mm_struct *mm)
{
	if (enable_ascend_share_pool)
		return mm->owner;
	else
		return current;
}

static inline bool sp_check_hugepage(struct page *p)
{
	if (enable_ascend_share_pool && PageHuge(p))
		return true;

	return false;
}

static inline bool sp_is_enabled(void)
{
	return enable_ascend_share_pool ? true : false;
}

static inline bool sp_check_vm_huge_page(unsigned long flags)
{
	if (enable_ascend_share_pool && (flags & VM_HUGE_PAGES))
		return true;

	return false;
}

static inline void sp_area_work_around(struct vm_unmapped_area_info *info)
{
	if (enable_ascend_share_pool)
		info->high_limit = min(info->high_limit, MMAP_SHARE_POOL_START);
}

extern struct page *sp_alloc_pages(struct vm_struct *area, gfp_t mask,
						 unsigned int page_order, int node);

static inline void sp_free_pages(struct page *page, struct vm_struct *area)
{
	if (PageHuge(page))
		put_page(page);
	else
		__free_pages(page, area->page_order);
}

static inline bool sp_check_vm_share_pool(unsigned long vm_flags)
{
	if (enable_ascend_share_pool && (vm_flags & VM_SHARE_POOL))
		return true;

	return false;
}

static inline bool is_vm_huge_special(struct vm_area_struct *vma)
{
	return !!(enable_ascend_share_pool && (vma->vm_flags & VM_HUGE_SPECIAL));
}

static inline bool sp_mmap_check(unsigned long flags)
{
	if (enable_ascend_share_pool && (flags & MAP_SHARE_POOL))
		return true;

	return false;
}

static inline void sp_dump_stack(void)
{
	if (sysctl_sp_debug_mode)
		dump_stack();
}

vm_fault_t sharepool_no_page(struct mm_struct *mm,
			struct vm_area_struct *vma,
			struct address_space *mapping, pgoff_t idx,
			unsigned long address, pte_t *ptep, unsigned int flags);

#else

static inline int sp_group_add_task(int pid, int spg_id)
{
	return -EPERM;
}

static inline void sp_group_exit(struct mm_struct *mm)
{
}

static inline void sp_group_post_exit(struct mm_struct *mm)
{
}

static inline int sp_group_id_by_pid(int pid)
{
	return -EPERM;
}

static inline  int proc_sp_group_state(struct seq_file *m, struct pid_namespace *ns,
			       struct pid *pid, struct task_struct *task)
{
	return -EPERM;
}

static inline void *sp_alloc(unsigned long size, unsigned long sp_flags, int sp_id)
{
	return NULL;
}

static inline int sp_free(unsigned long addr)
{
	return -EPERM;
}

static inline void *sp_make_share_k2u(unsigned long kva, unsigned long size,
				      unsigned long sp_flags, int pid, int spg_id)
{
	return NULL;
}

static inline void *sp_make_share_u2k(unsigned long uva, unsigned long size, int pid)
{
	return NULL;
}
static inline int sp_unshare(unsigned long va, unsigned long size, int pid, int spg_id)
{
	return -EPERM;
}

static inline void sp_init_mm(struct mm_struct *mm)
{
}

static inline void sp_area_drop(struct vm_area_struct *vma)
{
}

static inline int sp_walk_page_range(unsigned long uva, unsigned long size,
				     struct task_struct *tsk, struct sp_walk_data *sp_walk_data)
{
	return 0;
}

static inline void sp_walk_page_free(struct sp_walk_data *sp_walk_data)
{
}
static inline int sp_register_notifier(struct notifier_block *nb)
{
	return -EPERM;
}

static inline int sp_unregister_notifier(struct notifier_block *nb)
{
	return -EPERM;
}
static inline bool sp_config_dvpp_range(size_t start, size_t size, int device_id, int pid)
{
	return false;
}

static inline bool is_sharepool_addr(unsigned long addr)
{
	return false;
}

static inline void proc_sharepool_init(void)
{
}

static inline struct task_struct  *sp_get_task(struct mm_struct *mm)
{
	return current;
}
static inline bool sp_check_hugepage(struct page *p)
{
	return false;
}

static inline bool sp_is_enabled(void)
{
	return false;
}

static inline bool sp_check_vm_huge_page(unsigned long flags)
{
	return false;
}

static inline void sp_area_work_around(struct vm_unmapped_area_info *info)
{
}

static inline struct page *sp_alloc_pages(void *area, gfp_t mask,
					  unsigned int page_order, int node)
{
	return NULL;
}

static inline void sp_free_pages(struct page *page, struct vm_struct *area)
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

static inline bool sp_mmap_check(unsigned long flags)
{
	return false;
}

static inline void sp_dump_stack(void)
{
}
#endif

#endif /* LINUX_SHARE_POOL_H */
