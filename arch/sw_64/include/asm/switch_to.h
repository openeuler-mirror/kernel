/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SWITCH_TO_H
#define _ASM_SW64_SWITCH_TO_H

#include<linux/sched.h>

extern void __fpstate_save(struct task_struct *save_to);
extern void __fpstate_restore(struct task_struct *restore_from);
extern struct task_struct *__switch_to(unsigned long pcb,
		struct task_struct *prev, struct task_struct *next);
extern void restore_da_match_after_sched(void);

static inline void fpstate_save(struct task_struct *task)
{
	if (likely(!(task->flags & PF_KTHREAD)))
		__fpstate_save(task);
}

static inline void fpstate_restore(struct task_struct *task)
{
	if (likely(!(task->flags & PF_KTHREAD)))
		__fpstate_restore(task);
}

static inline void __switch_to_aux(struct task_struct *prev,
				   struct task_struct *next)
{
	fpstate_save(prev);
	fpstate_restore(next);
}


#define switch_to(prev, next, last)					\
do {									\
	struct task_struct *__prev = (prev);				\
	struct task_struct *__next = (next);				\
	__u64 __nextpcb = virt_to_phys(&task_thread_info(__next)->pcb);	\
	__switch_to_aux(__prev, __next);				\
	(last) = __switch_to(__nextpcb, __prev, __next);		\
	check_mmu_context();						\
} while (0)


/* TODO: finish_arch_switch has been removed from arch-independent code. */

/*
 * finish_arch_switch will be called after switch_to
 */
#define finish_arch_post_lock_switch()					\
do {									\
	restore_da_match_after_sched();					\
} while (0)


#endif /* _ASM_SW64_SWITCH_TO_H */
