/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/asm-sw64/processor.h
 *
 * Copyright (C) 1994 Linus Torvalds
 */

#ifndef _ASM_SW64_PROCESSOR_H
#define _ASM_SW64_PROCESSOR_H

#include <linux/personality.h>	/* for ADDR_LIMIT_32BIT */

/*
 * Returns current instruction pointer ("program counter").
 */
#define current_text_addr() \
	({ void *__pc; __asm__ ("br %0, .+4" : "=r"(__pc)); __pc; })

/*
 * SW64 does have an arch_pick_mmap_layout()
 */
#define HAVE_ARCH_PICK_MMAP_LAYOUT 1

/*
 * We have a 52-bit user address space: 4PB user VM...
 */
#define TASK_SIZE (0x10000000000000UL)
#define UNMAPPED_BASE (TASK_SIZE >> 6)
#define STACK_TOP \
	(current->personality & ADDR_LIMIT_32BIT ? 0x80000000 : 0x00120000000UL)

#define STACK_TOP_MAX	0x00120000000UL

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE \
	((current->personality & ADDR_LIMIT_32BIT) ? 0x40000000 : UNMAPPED_BASE)

typedef struct {
	unsigned long seg;
} mm_segment_t;

struct context_fpregs {
	unsigned long f0[4];
	unsigned long f1[4];
	unsigned long f2[4];
	unsigned long f3[4];
	unsigned long f4[4];
	unsigned long f5[4];
	unsigned long f6[4];
	unsigned long f7[4];
	unsigned long f8[4];
	unsigned long f9[4];
	unsigned long f10[4];
	unsigned long f11[4];
	unsigned long f12[4];
	unsigned long f13[4];
	unsigned long f14[4];
	unsigned long f15[4];
	unsigned long f16[4];
	unsigned long f17[4];
	unsigned long f18[4];
	unsigned long f19[4];
	unsigned long f20[4];
	unsigned long f21[4];
	unsigned long f22[4];
	unsigned long f23[4];
	unsigned long f24[4];
	unsigned long f25[4];
	unsigned long f26[4];
	unsigned long f27[4];
	unsigned long f28[4];
	unsigned long f29[4];
	unsigned long f30[4];
} __aligned(32);	/* 256 bits aligned for simd */

struct thread_struct {
	struct context_fpregs ctx_fp;
	unsigned long fpcr;
};
#define INIT_THREAD  { }

/* Return saved PC of a blocked thread.  */
struct task_struct;
extern unsigned long thread_saved_pc(struct task_struct *);

/* Do necessary setup to start up a newly executed thread.  */
struct pt_regs;
extern void start_thread(struct pt_regs *, unsigned long, unsigned long);

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);

unsigned long get_wchan(struct task_struct *p);

#define KSTK_EIP(tsk) (task_pt_regs(tsk)->pc)

#define KSTK_ESP(tsk) \
	((tsk) == current ? rdusp() : task_thread_info(tsk)->pcb.usp)

#define cpu_relax()	barrier()

#define ARCH_HAS_PREFETCH
#define ARCH_HAS_PREFETCHW
#define ARCH_HAS_SPINLOCK_PREFETCH

#ifndef CONFIG_SMP
/* Nothing to prefetch. */
#define spin_lock_prefetch(lock)	do { } while (0)
#endif

static inline void prefetch(const void *ptr)
{
	__builtin_prefetch(ptr, 0, 3);
}

static inline void prefetchw(const void *ptr)
{
	__builtin_prefetch(ptr, 1, 3);
}

#ifdef CONFIG_SMP
static inline void spin_lock_prefetch(const void *ptr)
{
	__builtin_prefetch(ptr, 1, 3);
}
#endif

#endif /* _ASM_SW64_PROCESSOR_H */
