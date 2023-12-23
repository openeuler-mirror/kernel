/* SPDX-License-Identifier: GPL-2.0 */
/*
 * livepatch.h - arm-specific Kernel Live Patching Core
 *
 * Copyright (C) 2018  Huawei Technologies Co., Ltd.
 * Copyright (C) 2023  Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ASM_ARM_LIVEPATCH_H
#define _ASM_ARM_LIVEPATCH_H

#ifdef CONFIG_LIVEPATCH_WO_FTRACE

#ifdef CONFIG_ARM_MODULE_PLTS
#define LJMP_INSN_SIZE	3
#else
#define LJMP_INSN_SIZE	1
#endif /* CONFIG_ARM_MODULE_PLTS */

#define KLP_ARM_BREAKPOINT_INSTRUCTION		0xe7f001f9

struct arch_klp_data {
	u32 old_insns[LJMP_INSN_SIZE];
	/*
	 * Saved opcode at the entry of the old func (which maybe replaced
	 * with breakpoint).
	 */
	u32 saved_opcode;
};

#define KLP_MAX_REPLACE_SIZE sizeof_field(struct arch_klp_data, old_insns)

struct klp_func;

/* kernel livepatch instruction barrier */
#define klp_smp_isb()  isb()
int arch_klp_patch_func(struct klp_func *func);
void arch_klp_unpatch_func(struct klp_func *func);
long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func);
bool arch_check_jump_insn(unsigned long func_addr);
int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data);
int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func);
void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func);
int arch_klp_module_check_calltrace(void *data);

#endif /* CONFIG_LIVEPATCH_WO_FTRACE */

#endif /* _ASM_ARM_LIVEPATCH_H */
