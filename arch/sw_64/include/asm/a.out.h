/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_A_OUT_H
#define _ASM_SW64_A_OUT_H

#include <uapi/asm/a.out.h>

/* Assume that start addresses below 4G belong to a TASO application.
 * Unfortunately, there is no proper bit in the exec header to check.
 * Worse, we have to notice the start address before swapping to use
 * /sbin/loader, which of course is _not_ a TASO application.
 */
#define SET_AOUT_PERSONALITY(BFPM, EX) \
	set_personality(((BFPM->taso || EX.ah.entry < 0x100000000L \
			? ADDR_LIMIT_32BIT : 0) | PER_OSF4))

#endif /* _ASM_SW64_A_OUT_H */
