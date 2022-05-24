/*
 * Based on arch/arm/include/asm/exception.h
 *
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_EXCEPTION_H
#define __ASM_EXCEPTION_H

#include <asm/esr.h>

#include <linux/interrupt.h>

#define __exception	__attribute__((section(".exception.text")))
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
#define __exception_irq_entry	__irq_entry
#else
#define __exception_irq_entry	__exception
#endif

static inline u32 disr_to_esr(u64 disr)
{
	unsigned int esr = ESR_ELx_EC_SERROR << ESR_ELx_EC_SHIFT;

	if ((disr & DISR_EL1_IDS) == 0)
		esr |= (disr & DISR_EL1_ESR_MASK);
	else
		esr |= (disr & ESR_ELx_ISS_MASK);

	return esr;
}

#ifdef CONFIG_UCE_KERNEL_RECOVERY
/* Need set task state when trigger uce */
#define KR_SET_TASK_STATE	0x00000001

struct uce_kernel_recovery_info {
	int (*fn)(void);
	const char *name;
	unsigned long addr;
	unsigned long size;
	unsigned int flags;
};

extern int copy_page_cow_sea_fallback(void);
extern int copy_generic_read_sea_fallback(void);
extern int copy_from_user_sea_fallback(void);
extern int get_user_sea_fallback(void);
extern int memcpy_mc_sea_fallback(void);
#endif

#endif	/* __ASM_EXCEPTION_H */
