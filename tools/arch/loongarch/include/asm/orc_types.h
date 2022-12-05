/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */

#ifndef _ASM_ORC_TYPES_H
#define _ASM_ORC_TYPES_H

#include <linux/types.h>
#include <linux/compiler.h>

/*
 * The ORC_REG_* registers are base registers which are used to find other
 * registers on the stack.
 *
 * ORC_REG_PREV_SP, also known as DWARF Call Frame Address (CFA), is the
 * address of the previous frame: the caller's SP before it called the current
 * function.
 *
 * ORC_REG_UNDEFINED means the corresponding register's value didn't change in
 * the current frame.
 *
 * The most commonly used base registers are SP and FP -- which the previous SP
 * is usually based on -- and PREV_SP and UNDEFINED -- which the previous FP is
 * usually based on.
 */
#define ORC_REG_UNDEFINED		0
#define ORC_REG_PREV_SP			1
#define ORC_REG_SP			2
#define ORC_REG_FP			3
#define ORC_REG_MAX			15

#define UNWIND_HINT_TYPE_SAVE		4
#define UNWIND_HINT_TYPE_RESTORE	5

#ifndef __ASSEMBLY__
/*
 * This struct is more or less a vastly simplified version of the DWARF Call
 * Frame Information standard.  It contains only the necessary parts of DWARF
 * CFI, simplified for ease of access by the in-kernel unwinder.  It tells the
 * unwinder how to find the previous SP and FP (and sometimes entry regs) on
 * the stack for a given code address.  Each instance of the struct corresponds
 * to one or more code locations.
 */
struct orc_entry {
	signed short	sp_offset;
	signed short	fp_offset;
	signed short    ra_offset;
	unsigned int	sp_reg:4;
	unsigned int	fp_reg:4;
	unsigned int	ra_reg:4;
	unsigned int	type:2;
	unsigned int	end:1;
	unsigned int	unused:1;
};

#endif /* __ASSEMBLY__ */

#endif /* _ASM_ORC_TYPES_H */
