/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SWITCH_TO_H
#define _ASM_SW64_SWITCH_TO_H

struct task_struct;
extern struct task_struct *__switch_to(unsigned long, struct task_struct *);
extern void restore_da_match_after_sched(void);
#define switch_to(P, N, L)						\
do {									\
	(L) = __switch_to(virt_to_phys(&task_thread_info(N)->pcb), (P));\
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
