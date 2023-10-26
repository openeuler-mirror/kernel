/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__ASM_MMAN_H
#define _UAPI__ASM_MMAN_H

#include <asm-generic/mman.h>

#define PROT_BTI	0x10		/* BTI guarded page */
#define PROT_MTE	0x20		/* Normal Tagged mapping */
#define PROT_PBHA_BIT0	0x40		/* PBHA 59 bit */

#endif /* ! _UAPI__ASM_MMAN_H */
