/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMAN_H
#define _LINUX_MMAN_H

#include <linux/mm.h>
#include <linux/percpu_counter.h>

#include <linux/atomic.h>
#include <uapi/linux/mman.h>

#ifdef CONFIG_COHERENT_DEVICE
#define CHECKNODE_BITS  48
#define CHECKNODE_MASK	(~((_AC(1, UL) << CHECKNODE_BITS) - 1))
static inline void set_vm_checknode(vm_flags_t *vm_flags, unsigned long flags)
{
	if (is_set_cdmmask())
		*vm_flags |= VM_CHECKNODE | ((((flags >> MAP_HUGE_SHIFT) &
			MAP_HUGE_MASK) << CHECKNODE_BITS) & CHECKNODE_MASK);
}
#else
#define CHECKNODE_BITS	(0)
static inline void set_vm_checknode(vm_flags_t *vm_flags, unsigned long flags)
{}
#endif

extern int enable_mmap_dvpp;
/*
 * Enable MAP_32BIT for Ascend Platform
 */
#ifdef CONFIG_ASCEND_DVPP_MMAP

#define MAP_DVPP	0x200

#define DVPP_MMAP_SIZE	(0x100000000UL)
#define DVPP_MMAP_BASE (TASK_SIZE - DVPP_MMAP_SIZE)

static inline int dvpp_mmap_check(unsigned long addr, unsigned long len,
								unsigned long flags)
{
	if (enable_mmap_dvpp && (flags & MAP_DVPP) &&
		(addr < DVPP_MMAP_BASE + DVPP_MMAP_SIZE) &&
			(addr > DVPP_MMAP_BASE))
		return -EINVAL;
	else
		return 0;
}

static inline void dvpp_mmap_get_area(struct vm_unmapped_area_info *info,
									unsigned long flags)
{
	if (flags & MAP_DVPP) {
		info->low_limit = DVPP_MMAP_BASE;
		info->high_limit = DVPP_MMAP_BASE + DVPP_MMAP_SIZE;
	} else {
		info->low_limit = max(info->low_limit, TASK_UNMAPPED_BASE);
		info->high_limit = min(info->high_limit, DVPP_MMAP_BASE);
	}
}

static inline int dvpp_mmap_zone(unsigned long addr)
{
	if (addr >= DVPP_MMAP_BASE)
		return 1;
	else
		return 0;
}
#else

#define MAP_DVPP (0)

static inline int dvpp_mmap_check(unsigned long addr, unsigned long len,
								unsigned long flags)
{
	return 0;
}

static inline void dvpp_mmap_get_area(struct vm_unmapped_area_info *info,
									unsigned long flags)
{
}

static inline int dvpp_mmap_zone(unsigned long addr) { return 0; }

#define DVPP_MMAP_BASE (0)

#define DVPP_MMAP_SIZE (0)

#endif

/*
 * Arrange for legacy / undefined architecture specific flags to be
 * ignored by mmap handling code.
 */
#ifndef MAP_32BIT
#define MAP_32BIT 0
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB 0
#endif
#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB 0
#endif
#ifndef MAP_UNINITIALIZED
#define MAP_UNINITIALIZED 0
#endif
#ifndef MAP_SYNC
#define MAP_SYNC 0
#endif

/*
 * The historical set of flags that all mmap implementations implicitly
 * support when a ->mmap_validate() op is not provided in file_operations.
 */
#define LEGACY_MAP_MASK (MAP_SHARED \
		| MAP_PRIVATE \
		| MAP_FIXED \
		| MAP_ANONYMOUS \
		| MAP_DENYWRITE \
		| MAP_EXECUTABLE \
		| MAP_UNINITIALIZED \
		| MAP_GROWSDOWN \
		| MAP_LOCKED \
		| MAP_NORESERVE \
		| MAP_POPULATE \
		| MAP_NONBLOCK \
		| MAP_STACK \
		| MAP_HUGETLB \
		| MAP_32BIT \
		| MAP_HUGE_2MB \
		| MAP_HUGE_1GB)

extern int sysctl_overcommit_memory;
extern int sysctl_overcommit_ratio;
extern unsigned long sysctl_overcommit_kbytes;
extern struct percpu_counter vm_committed_as;

#ifdef CONFIG_SMP
extern s32 vm_committed_as_batch;
extern void mm_compute_batch(int overcommit_policy);
#else
#define vm_committed_as_batch 0
static inline void mm_compute_batch(int overcommit_policy)
{
}
#endif

unsigned long vm_memory_committed(void);

static inline void vm_acct_memory(long pages)
{
	percpu_counter_add_batch(&vm_committed_as, pages, vm_committed_as_batch);
}

static inline void vm_unacct_memory(long pages)
{
	vm_acct_memory(-pages);
}

/*
 * Allow architectures to handle additional protection and flag bits. The
 * overriding macros must be defined in the arch-specific asm/mman.h file.
 */

#ifndef arch_calc_vm_prot_bits
#define arch_calc_vm_prot_bits(prot, pkey) 0
#endif

#ifndef arch_calc_vm_flag_bits
#define arch_calc_vm_flag_bits(flags) 0
#endif

#ifndef arch_vm_get_page_prot
#define arch_vm_get_page_prot(vm_flags) __pgprot(0)
#endif

#ifndef arch_validate_prot
/*
 * This is called from mprotect().  PROT_GROWSDOWN and PROT_GROWSUP have
 * already been masked out.
 *
 * Returns true if the prot flags are valid
 */
static inline bool arch_validate_prot(unsigned long prot, unsigned long addr)
{
	return (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM)) == 0;
}
#define arch_validate_prot arch_validate_prot
#endif

#ifndef arch_validate_flags
/*
 * This is called from mmap() and mprotect() with the updated vma->vm_flags.
 *
 * Returns true if the VM_* flags are valid.
 */
static inline bool arch_validate_flags(unsigned long flags)
{
	return true;
}
#define arch_validate_flags arch_validate_flags
#endif

/*
 * Optimisation macro.  It is equivalent to:
 *      (x & bit1) ? bit2 : 0
 * but this version is faster.
 * ("bit1" and "bit2" must be single bits)
 */
#define _calc_vm_trans(x, bit1, bit2) \
  ((!(bit1) || !(bit2)) ? 0 : \
  ((bit1) <= (bit2) ? ((x) & (bit1)) * ((bit2) / (bit1)) \
   : ((x) & (bit1)) / ((bit1) / (bit2))))

/*
 * Combine the mmap "prot" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_prot_bits(unsigned long prot, unsigned long pkey)
{
	return _calc_vm_trans(prot, PROT_READ,  VM_READ ) |
	       _calc_vm_trans(prot, PROT_WRITE, VM_WRITE) |
	       _calc_vm_trans(prot, PROT_EXEC,  VM_EXEC) |
	       arch_calc_vm_prot_bits(prot, pkey);
}

/*
 * Combine the mmap "flags" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_flag_bits(unsigned long flags)
{
	return _calc_vm_trans(flags, MAP_GROWSDOWN,  VM_GROWSDOWN ) |
	       _calc_vm_trans(flags, MAP_DENYWRITE,  VM_DENYWRITE ) |
	       _calc_vm_trans(flags, MAP_LOCKED,     VM_LOCKED    ) |
	       _calc_vm_trans(flags, MAP_SYNC,	     VM_SYNC      ) |
	       arch_calc_vm_flag_bits(flags);
}

unsigned long vm_commit_limit(void);
#endif /* _LINUX_MMAN_H */
