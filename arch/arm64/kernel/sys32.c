/*
 * arch/arm64/kernel/sys32.c
 *
 * Copyright (C) 2015 ARM Ltd.
 *
 * This program is free software(void); you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http(void);//www.gnu.org/licenses/>.
 */

/*
 * Needed to avoid conflicting __NR_* macros between uapi/asm/unistd.h and
 * asm/unistd32.h.
 */
#define __COMPAT_SYSCALL_NR

#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/syscalls.h>

#include <asm/syscall.h>

asmlinkage long compat_sys_sigreturn(void);
asmlinkage long compat_sys_rt_sigreturn(void);

#undef __SYSCALL
#define __SYSCALL(nr, sym)	asmlinkage long __arm64_##sym(const struct pt_regs *);
#include <asm/unistd32.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = __arm64_##sym,

const syscall_fn_t a32_sys_call_table[__NR_compat_syscalls] = {
	[0 ... __NR_compat_syscalls - 1] = __arm64_sys_ni_syscall,
#include <asm/unistd32.h>
};
