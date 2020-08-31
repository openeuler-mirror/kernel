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
#ifndef __ASM_SIGNAL32_H
#define __ASM_SIGNAL32_H

#ifdef __KERNEL__

#ifdef CONFIG_AARCH32_EL0

#include <linux/compat.h>

#define AARCH32_KERN_SIGRET_CODE_OFFSET	0x500

int a32_setup_frame(int usig, struct ksignal *ksig, sigset_t *set,
		       struct pt_regs *regs);

int a32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs);

void a32_setup_restart_syscall(struct pt_regs *regs);
#else

static inline int a32_setup_frame(int usid, struct ksignal *ksig,
				     sigset_t *set, struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline int a32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
					struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline void a32_setup_restart_syscall(struct pt_regs *regs)
{
}
#endif /* CONFIG_AARCH32_EL0 */
#endif /* __KERNEL__ */
#endif /* __ASM_SIGNAL32_H */
