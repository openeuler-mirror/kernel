/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SPECIAL_INSNS_H
#define _ASM_SW64_SPECIAL_INSNS_H

enum amask_enum {
	AMASK_BWX = (1UL << 0),
	AMASK_FIX = (1UL << 1),
	AMASK_CIX = (1UL << 2),
	AMASK_MAX = (1UL << 8),
	AMASK_PRECISE_TRAP = (1UL << 9),
};

#define amask(mask)						\
({								\
	unsigned long __amask, __input = (mask);		\
	__asm__ ("mov %1, %0" : "=r"(__amask) : "rI"(__input));	\
	__amask;						\
})

#endif /* _ASM_SW64_SPECIAL_INSNS_H */
