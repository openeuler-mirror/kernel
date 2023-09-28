/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_UNWIND_HINTS_H
#define __ASM_UNWIND_HINTS_H

#include <linux/objtool.h>

#include "orc_types.h"

#ifdef __ASSEMBLY__

.macro UNWIND_HINT_EMPTY
	UNWIND_HINT sp_reg=ORC_REG_UNDEFINED type=UNWIND_HINT_TYPE_CALL end=1
.endm

.macro UNWIND_HINT_FUNC sp_offset=0
	UNWIND_HINT sp_reg=ORC_REG_SP sp_offset=\sp_offset type=UNWIND_HINT_TYPE_CALL
.endm

.macro UNWIND_HINT_REGS base=ORC_REG_SP offset=0
	UNWIND_HINT sp_reg=\base sp_offset=\offset type=UNWIND_HINT_TYPE_REGS
.endm

#endif /* __ASSEMBLY__ */

#endif /* __ASM_UNWIND_HINTS_H */
