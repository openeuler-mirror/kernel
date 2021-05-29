/* SPDX-License-Identifier: GPL-2.0 */
/*
 * livepatch.h - arm-specific Kernel Live Patching Core
 *
 * Copyright (C) 2018  Huawei Technologies Co., Ltd.
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

#include <linux/module.h>

struct klp_patch;
struct klp_func;

/* kernel livepatch instruction barrier */
#define klp_smp_isb()  isb()

int arch_klp_patch_func(struct klp_func *func);
void arch_klp_unpatch_func(struct klp_func *func);

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
int klp_check_calltrace(struct klp_patch *patch, int enable);
#endif

#endif /* _ASM_ARM_LIVEPATCH_H */
