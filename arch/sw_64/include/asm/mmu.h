/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_MMU_H
#define _ASM_SW64_MMU_H

/* The sw64 MMU context is one "unsigned long" bitmap per CPU*/
typedef struct {
	unsigned long asid[NR_CPUS];
	void *vdso;
} mm_context_t;

static inline void clear_asid(mm_context_t *mm_context)
{
	memset(mm_context->asid, 0, sizeof(mm_context->asid[0]) * nr_cpu_ids);
}
#endif /* _ASM_SW64_MMU_H */
