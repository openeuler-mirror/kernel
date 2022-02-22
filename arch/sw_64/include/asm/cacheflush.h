/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_CACHEFLUSH_H
#define _ASM_SW64_CACHEFLUSH_H

#include <linux/mm.h>
#include <asm/hw_init.h>

/* Caches aren't brain-dead on the sw64. */
#define flush_cache_all()			do { } while (0)
#define flush_cache_mm(mm)			do { } while (0)
#define flush_cache_dup_mm(mm)			do { } while (0)
#define flush_cache_range(vma, start, end)	do { } while (0)
#define flush_cache_page(vma, vmaddr, pfn)	do { } while (0)
#define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE	0
#define flush_dcache_page(page)			do { } while (0)
#define flush_dcache_mmap_lock(mapping)		do { } while (0)
#define flush_dcache_mmap_unlock(mapping)	do { } while (0)
#define flush_cache_vmap(start, end)		do { } while (0)
#define flush_cache_vunmap(start, end)		do { } while (0)

/* Note that the following two definitions are _highly_ dependent
 * on the contexts in which they are used in the kernel.  I personally
 * think it is criminal how loosely defined these macros are.
 */

/* We need to flush the kernel's icache after loading modules.  The
 * only other use of this macro is in load_aout_interp which is not
 * used on sw64.

 * Note that this definition should *not* be used for userspace
 * icache flushing.  While functional, it is _way_ overkill.  The
 * icache is tagged with ASNs and it suffices to allocate a new ASN
 * for the process.
 */
#ifndef CONFIG_SMP
static inline void
flush_icache_range(unsigned long start, unsigned long end)
{
	if (icache_is_vivt_no_ictag())
		imb();
}
#define flush_icache_range flush_icache_range
#else
extern void smp_imb(void);
static inline void
flush_icache_range(unsigned long start, unsigned long end)
{
	if (icache_is_vivt_no_ictag())
		smp_imb();
}
#define flush_icache_range flush_icache_range
#endif

/* We need to flush the userspace icache after setting breakpoints in
 * ptrace.

 * Instead of indiscriminately using imb, take advantage of the fact
 * that icache entries are tagged with the ASN and load a new mm context.
 */
/* ??? Ought to use this in arch/sw_64/kernel/signal.c too.  */

#ifndef CONFIG_SMP
#include <linux/sched.h>

extern void __load_new_mm_context(struct mm_struct *);
static inline void
flush_icache_user_page(struct vm_area_struct *vma, struct page *page,
			unsigned long addr, int len)
{
	if ((vma->vm_flags & VM_EXEC) && icache_is_vivt_no_ictag())
		imb();
}
#define flush_icache_user_page flush_icache_user_page
#else
extern void flush_icache_user_page(struct vm_area_struct *vma,
				    struct page *page,
				    unsigned long addr, int len);
#define flush_icache_user_page flush_icache_user_page
#endif

/* This is used only in __do_fault and do_swap_page.  */
#define flush_icache_page(vma, page) \
	flush_icache_user_page((vma), (page), 0, 0)

#define copy_to_user_page(vma, page, vaddr, dst, src, len) \
do {	\
	memcpy(dst, src, len); \
	flush_icache_user_page(vma, page, vaddr, len); \
} while (0)
#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
	memcpy(dst, src, len)

#include <asm-generic/cacheflush.h>

#endif /* _ASM_SW64_CACHEFLUSH_H */
