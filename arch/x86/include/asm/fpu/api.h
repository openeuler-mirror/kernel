/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 1994 Linus Torvalds
 *
 * Pentium III FXSR, SSE support
 * General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 * x86-64 work by Andi Kleen 2002
 */

#ifndef _ASM_X86_FPU_API_H
#define _ASM_X86_FPU_API_H
#include <linux/bottom_half.h>

/*
 * Use kernel_fpu_begin/end() if you intend to use FPU in kernel context. It
 * disables preemption so be careful if you intend to use it for long periods
 * of time.
 * If you intend to use the FPU in softirq you need to check first with
 * irq_fpu_usable() if it is possible.
 */
extern void kernel_fpu_begin(void);
extern void kernel_fpu_end(void);
extern bool irq_fpu_usable(void);

#if defined(CONFIG_X86_HYGON_LMC_SSE2_ON) || \
	defined(CONFIG_X86_HYGON_LMC_AVX2_ON)
extern int kernel_fpu_begin_nonatomic_mask(void);
extern void kernel_fpu_end_nonatomic(void);

/* Code that is unaware of kernel_fpu_begin_nonatomic_mask() can use this */
static inline int kernel_fpu_begin_nonatomic(void)
{
	return kernel_fpu_begin_nonatomic_mask();
}

/*
 * It means we call kernel_fpu_end after kernel_fpu_begin_nonatomic
 * func, but before kernel_fpu_end_nonatomic
 */
static inline void check_using_kernel_fpu(void)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
		WARN_ON_ONCE(test_thread_flag(TIF_USING_FPU_NONATOMIC));
}

#else
static inline void check_using_kernel_fpu(void) { }

#endif

/*
 * Query the presence of one or more xfeatures. Works on any legacy CPU as well.
 *
 * If 'feature_name' is set then put a human-readable description of
 * the feature there as well - this can be used to print error (or success)
 * messages.
 */
extern int cpu_has_xfeatures(u64 xfeatures_mask, const char **feature_name);

#endif /* _ASM_X86_FPU_API_H */
