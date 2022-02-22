// SPDX-License-Identifier: GPL-2.0
/*
 * Mapping of DWARF debug register numbers into register names.
 *
 * Copyright (C) 2010 Will Deacon, ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <dwarf-regs.h>
#include <linux/ptrace.h> /* for struct user_pt_regs */
#include <linux/stringify.h>
#include "util.h"

struct pt_regs_dwarfnum {
	const char *name;
	unsigned int dwarfnum;
};

#define REG_DWARFNUM_NAME(r, num) {.name = r, .dwarfnum = num}
#define REG_DWARFNUM_END {.name = NULL, .dwarfnum = 0}

static const struct pt_regs_dwarfnum regdwarfnum_table[] = {
	REG_DWARFNUM_NAME("%v0", 0),
	REG_DWARFNUM_NAME("%t0", 1),
	REG_DWARFNUM_NAME("%t1", 2),
	REG_DWARFNUM_NAME("%t2", 3),
	REG_DWARFNUM_NAME("%t3", 4),
	REG_DWARFNUM_NAME("%t4", 5),
	REG_DWARFNUM_NAME("%t5", 6),
	REG_DWARFNUM_NAME("%t6", 7),
	REG_DWARFNUM_NAME("%t7", 8),
	REG_DWARFNUM_NAME("%s0", 9),
	REG_DWARFNUM_NAME("%s1", 10),
	REG_DWARFNUM_NAME("%s2", 11),
	REG_DWARFNUM_NAME("%s3", 12),
	REG_DWARFNUM_NAME("%s4", 13),
	REG_DWARFNUM_NAME("%s5", 14),
	REG_DWARFNUM_NAME("%s6", 15),
	REG_DWARFNUM_NAME("%a0", 16),
	REG_DWARFNUM_NAME("%a1", 17),
	REG_DWARFNUM_NAME("%a2", 18),
	REG_DWARFNUM_NAME("%a3", 19),
	REG_DWARFNUM_NAME("%a4", 20),
	REG_DWARFNUM_NAME("%a5", 21),
	REG_DWARFNUM_NAME("%t8", 22),
	REG_DWARFNUM_NAME("%t9", 23),
	REG_DWARFNUM_NAME("%t10", 24),
	REG_DWARFNUM_NAME("%t11", 25),
	REG_DWARFNUM_NAME("%ra", 26),
	REG_DWARFNUM_NAME("%pv", 27),
	REG_DWARFNUM_NAME("%at", 28),
	REG_DWARFNUM_NAME("%gp", 29),
	REG_DWARFNUM_NAME("%sp", 30),
	REG_DWARFNUM_NAME("%zero", 31),
	REG_DWARFNUM_END,
};

/**
 * get_arch_regstr() - lookup register name from it's DWARF register number
 * @n:	the DWARF register number
 *
 * get_arch_regstr() returns the name of the register in struct
 * regdwarfnum_table from it's DWARF register number. If the register is not
 * found in the table, this returns NULL;
 */
const char *get_arch_regstr(unsigned int n)
{
	const struct pt_regs_dwarfnum *roff;

	for (roff = regdwarfnum_table; roff->name != NULL; roff++)
		if (roff->dwarfnum == n)
			return roff->name;
	return NULL;
}

int regs_query_register_offset(const char *name)
{
	const struct pt_regs_dwarfnum *roff;

	for (roff = regdwarfnum_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->dwarfnum;
	return -EINVAL;
}
