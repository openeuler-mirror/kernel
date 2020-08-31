/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
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

/*
 * Use AARCH32 interface for sys_sync_file_range() as it passes 64-bit arguments.
 */
#if defined(__ILP32__) || defined(__SYSCALL_COMPAT)
#define __ARCH_WANT_SYNC_FILE_RANGE2
#endif

/*
 * AARCH64/ILP32 is introduced after next syscalls were deprecated.
 */
#if !(defined(__ILP32__) || defined(__SYSCALL_COMPAT))
#define __ARCH_WANT_RENAMEAT
#define __ARCH_WANT_SET_GET_RLIMIT
#endif

#include <asm-generic/unistd.h>
