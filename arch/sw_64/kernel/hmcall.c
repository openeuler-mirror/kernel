// SPDX-License-Identifier: GPL-2.0
/*
 * arch/sw_64/kernel/hmcall.c
 *
 * Copyright (C) 2022 WXIAT
 * Author: He Sheng
 */

#include <asm/hmcall.h>
#include <asm/page.h>

#define A0(func)	(((HMC_##func & 0xFF) >> 6) & 0x1)
#define A1(func)	((((HMC_##func & 0xFF)>>6) & 0x2) >> 1)
#define A2(func)	((HMC_##func & 0x3F) << 7)

#define T(func)		((A0(func) ^ A1(func)) & 0x1)
#define B0(func)	((T(func) | A0(func)) << 13)
#define B1(func)	(((~T(func) & 1) | A1(func)) << 14)

#define PRI_BASE	0x10000UL

#define HMCALL_ENTRY(func)	(PRI_BASE | B1(func) | B0(func) | A2(func))


static inline void fixup_rdtp(void)
{
	unsigned int *entry = __va(HMCALL_ENTRY(rdtp));

	entry[0] = 0x181ffec7;	/* pri_rcsr $0, CSR__TID */
	entry[1] = 0x1ee00000;	/* pri_ret $23 */
}

static inline void fixup_wrtp(void)
{
	unsigned int *entry = __va(HMCALL_ENTRY(wrtp));

	entry[0] = 0x1a1fffc7;	/* pri_wcsr $16, CSR__TID */
	entry[1] = 0x1ee00000;	/* pri_ret $23 */
}

void __init fixup_hmcall(void)
{
#if defined(CONFIG_SUBARCH_C3A) || defined(CONFIG_SUBARCH_C3B)
	fixup_rdtp();
	fixup_wrtp();
#endif
}

#undef A0
#undef A1
#undef A2
#undef T
#undef B0
#undef B1
