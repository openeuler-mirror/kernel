/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 ARM Ltd.
 */
#ifndef __ASM_NMI_H
#define __ASM_NMI_H

#ifndef __ASSEMBLER__

#include <linux/cpumask.h>

extern bool arm64_supports_nmi(void);
extern void arm64_send_nmi(cpumask_t *mask);

void set_smp_dynamic_ipi(int ipi);
void dynamic_ipi_setup(int cpu);
void dynamic_ipi_teardown(int cpu);

#endif /* !__ASSEMBLER__ */

static __always_inline void _allint_clear(void)
{
	asm volatile(__msr_s(SYS_ALLINT_CLR, "xzr"));
}

static __always_inline void _allint_set(void)
{
	asm volatile(__msr_s(SYS_ALLINT_SET, "xzr"));
}

#endif
