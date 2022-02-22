/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_UCONTEXT_H
#define _ASM_SW64_UCONTEXT_H

struct ucontext {
	unsigned long		uc_flags;
	struct ucontext		*uc_link;
	old_sigset_t		uc_old_sigmask;
	stack_t			uc_stack;
	struct sigcontext	uc_mcontext;
	sigset_t		uc_sigmask;	/* mask last for extensibility */
};

#endif /* _ASM_SW64_UCONTEXT_H */
