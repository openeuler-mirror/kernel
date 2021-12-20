// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2019 FUJITSU LIMITED

#include <linux/smp.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_ARM64_TLBI_IPI
struct tlb_args {
	struct vm_area_struct *ta_vma;
	unsigned long ta_start;
	unsigned long ta_end;
	unsigned long ta_stride;
	bool ta_last_level;
};

int disable_tlbflush_is;

static int __init disable_tlbflush_is_setup(char *str)
{
	disable_tlbflush_is = 1;

	return 0;
}
__setup("disable_tlbflush_is", disable_tlbflush_is_setup);
#endif

static inline void __flush_tlb_mm(struct mm_struct *mm)
{
	unsigned long asid = __TLBI_VADDR(0, ASID(mm));

	dsb(ishst);
	__tlbi(aside1is, asid);
	__tlbi_user(aside1is, asid);
	dsb(ish);
}

#ifdef CONFIG_ARM64_TLBI_IPI
static inline void ipi_flush_tlb_mm(void *arg)
{
	struct mm_struct *mm = arg;

	local_flush_tlb_mm(mm);
}
#endif

void flush_tlb_mm(struct mm_struct *mm)
{
#ifdef CONFIG_ARM64_TLBI_IPI
	if (unlikely(disable_tlbflush_is))
		on_each_cpu_mask(mm_cpumask(mm), ipi_flush_tlb_mm,
				 (void *)mm, true);
	else
		__flush_tlb_mm(mm);
#else
	__flush_tlb_mm(mm);
#endif
}

static inline void __flush_tlb_page_nosync(unsigned long addr)
{
	dsb(ishst);
	__tlbi(vale1is, addr);
	__tlbi_user(vale1is, addr);
}

static inline void __local_flush_tlb_page_nosync(unsigned long addr)
{
	dsb(nshst);
	__tlbi(vale1, addr);
	__tlbi_user(vale1, addr);
	dsb(nsh);
}

static inline void ipi_flush_tlb_page_nosync(void *arg)
{
	unsigned long addr = *(unsigned long *)arg;

	__local_flush_tlb_page_nosync(addr);
}

void flush_tlb_page_nosync(struct vm_area_struct *vma, unsigned long uaddr)
{
	unsigned long addr = __TLBI_VADDR(uaddr, ASID(vma->vm_mm));

#ifdef CONFIG_ARM64_TLBI_IPI
	if (unlikely(disable_tlbflush_is))
		on_each_cpu_mask(mm_cpumask(vma->vm_mm),
				ipi_flush_tlb_page_nosync, &addr, true);
	else
		__flush_tlb_page_nosync(addr);
#else
	__flush_tlb_page_nosync(addr);
#endif
}

static inline void ___flush_tlb_range(unsigned long start, unsigned long end,
				     unsigned long stride, bool last_level)
{
	unsigned long addr;

	dsb(ishst);
	for (addr = start; addr < end; addr += stride) {
		if (last_level) {
			__tlbi(vale1is, addr);
			__tlbi_user(vale1is, addr);
		} else {
			__tlbi(vae1is, addr);
			__tlbi_user(vae1is, addr);
		}
	}
	dsb(ish);
}

static inline void __local_flush_tlb_range(unsigned long addr, bool last_level)
{
	dsb(nshst);
	if (last_level) {
		__tlbi(vale1, addr);
		__tlbi_user(vale1, addr);
	} else {
		__tlbi(vae1, addr);
		__tlbi_user(vae1, addr);
	}
	dsb(nsh);
}

#ifdef CONFIG_ARM64_TLBI_IPI
static inline void ipi_flush_tlb_range(void *arg)
{
	struct tlb_args *ta = (struct tlb_args *)arg;
	unsigned long addr;

	for (addr = ta->ta_start; addr < ta->ta_end; addr += ta->ta_stride)
		__local_flush_tlb_range(addr, ta->ta_last_level);
}
#endif

void __flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
		unsigned long end, unsigned long stride, bool last_level)
{
	unsigned long asid = ASID(vma->vm_mm);

	start = round_down(start, stride);
	end = round_up(end, stride);

	if ((end - start) >= (MAX_TLBI_OPS * stride)) {
		flush_tlb_mm(vma->vm_mm);
		return;
	}

	/* Convert the stride into units of 4k */
	stride >>= 12;

	start = __TLBI_VADDR(start, asid);
	end = __TLBI_VADDR(end, asid);


#ifdef CONFIG_ARM64_TLBI_IPI
	if (unlikely(disable_tlbflush_is)) {
		struct tlb_args ta = {
			.ta_start	= start,
			.ta_end		= end,
			.ta_stride	= stride,
			.ta_last_level	= last_level,
		};

		on_each_cpu_mask(mm_cpumask(vma->vm_mm), ipi_flush_tlb_range,
					    &ta, true);
	} else
		___flush_tlb_range(start, end, stride, last_level);
#else
	___flush_tlb_range(start, end, stride, last_level);
#endif
}
