/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SIGNAL_H
#define _ASM_SW64_SIGNAL_H

#include <uapi/asm/signal.h>

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef unsigned long old_sigset_t;		/* at least 32 bits */

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

struct odd_sigaction {
	__sighandler_t	sa_handler;
	old_sigset_t	sa_mask;
	int		sa_flags;
};

#include <asm/sigcontext.h>
#endif
