// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/sw_64/kernel/signal.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  1997-11-02  Modified for POSIX.1b signals by Richard Henderson
 */

#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/tracehook.h>
#include <linux/syscalls.h>

#include <asm/ucontext.h>
#include <asm/vdso.h>
#include <asm/switch_to.h>

#include "proto.h"


#define DEBUG_SIG 0

#define _BLOCKABLE (~(sigmask(SIGKILL) | sigmask(SIGSTOP)))

SYSCALL_DEFINE2(odd_sigprocmask, int, how, unsigned long, newmask)
{
	sigset_t oldmask;
	sigset_t mask;
	unsigned long res;

	siginitset(&mask, newmask & _BLOCKABLE);
	res = sigprocmask(how, &mask, &oldmask);
	if (!res) {
		force_successful_syscall_return();
		res = oldmask.sig[0];
	}
	return res;
}

SYSCALL_DEFINE3(odd_sigaction, int, sig,
		const struct odd_sigaction __user *, act,
		struct odd_sigaction __user *, oact)
{
	struct k_sigaction new_ka, old_ka;
	old_sigset_t mask;
	int ret;

	if (act) {
		if (!access_ok(act, sizeof(*act)) ||
		    __get_user(new_ka.sa.sa_handler, &act->sa_handler) ||
		    __get_user(new_ka.sa.sa_flags, &act->sa_flags) ||
		    __get_user(mask, &act->sa_mask))
			return -EFAULT;
		siginitset(&new_ka.sa.sa_mask, mask);
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		if (!access_ok(oact, sizeof(*oact)) ||
		    __put_user(old_ka.sa.sa_handler, &oact->sa_handler) ||
		    __put_user(old_ka.sa.sa_flags, &oact->sa_flags) ||
		    __put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask))
			return -EFAULT;
	}

	return ret;
}

/*
 * Do a signal return; undo the signal stack.
 */

#if _NSIG_WORDS > 1
# error "Non SA_SIGINFO frame needs rearranging"
#endif

struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
};

/*
 * If this changes, userland unwinders that Know Things about our signal
 * frame will break.  Do not undertake lightly.  It also implies an ABI
 * change wrt the size of siginfo_t, which may cause some pain.
 */
extern char compile_time_assert
	[offsetof(struct rt_sigframe, uc.uc_mcontext) == 176 ? 1 : -1];

static long
restore_sigcontext(struct sigcontext __user *sc, struct pt_regs *regs)
{
	unsigned long usp;
	long err = __get_user(regs->pc, &sc->sc_pc);

	current->restart_block.fn = do_no_restart_syscall;

	err |= __get_user(regs->r0, sc->sc_regs+0);
	err |= __get_user(regs->r1, sc->sc_regs+1);
	err |= __get_user(regs->r2, sc->sc_regs+2);
	err |= __get_user(regs->r3, sc->sc_regs+3);
	err |= __get_user(regs->r4, sc->sc_regs+4);
	err |= __get_user(regs->r5, sc->sc_regs+5);
	err |= __get_user(regs->r6, sc->sc_regs+6);
	err |= __get_user(regs->r7, sc->sc_regs+7);
	err |= __get_user(regs->r8, sc->sc_regs+8);
	err |= __get_user(regs->r9, sc->sc_regs+9);
	err |= __get_user(regs->r10, sc->sc_regs+10);
	err |= __get_user(regs->r11, sc->sc_regs+11);
	err |= __get_user(regs->r12, sc->sc_regs+12);
	err |= __get_user(regs->r13, sc->sc_regs+13);
	err |= __get_user(regs->r14, sc->sc_regs+14);
	err |= __get_user(regs->r15, sc->sc_regs+15);
	err |= __get_user(regs->r16, sc->sc_regs+16);
	err |= __get_user(regs->r17, sc->sc_regs+17);
	err |= __get_user(regs->r18, sc->sc_regs+18);
	err |= __get_user(regs->r19, sc->sc_regs+19);
	err |= __get_user(regs->r20, sc->sc_regs+20);
	err |= __get_user(regs->r21, sc->sc_regs+21);
	err |= __get_user(regs->r22, sc->sc_regs+22);
	err |= __get_user(regs->r23, sc->sc_regs+23);
	err |= __get_user(regs->r24, sc->sc_regs+24);
	err |= __get_user(regs->r25, sc->sc_regs+25);
	err |= __get_user(regs->r26, sc->sc_regs+26);
	err |= __get_user(regs->r27, sc->sc_regs+27);
	err |= __get_user(regs->r28, sc->sc_regs+28);
	err |= __get_user(regs->gp, sc->sc_regs+29);
	err |= __get_user(usp, sc->sc_regs+30);
	wrusp(usp);
	/* simd-fp */
	err |= __copy_from_user(&current->thread.fpstate, &sc->sc_fpregs,
				offsetof(struct user_fpsimd_state, fpcr));
	err |= __get_user(current->thread.fpstate.fpcr, &sc->sc_fpcr);

	if (likely(!err))
		__fpstate_restore(current);

	return err;
}

/*
 * Note that this syscall is also used by setcontext(3) to install
 * a given sigcontext.  This because it's impossible to set *all*
 * registers and transfer control from userland.
 */

asmlinkage void
do_sigreturn(struct sigcontext __user *sc)
{
	struct pt_regs *regs = current_pt_regs();
	sigset_t set;

	/* Verify that it's a good sigcontext before using it */
	if (!access_ok(sc, sizeof(*sc)))
		goto give_sigsegv;
	if (__get_user(set.sig[0], &sc->sc_mask))
		goto give_sigsegv;

	set_current_blocked(&set);

	if (restore_sigcontext(sc, regs))
		goto give_sigsegv;

	return;

give_sigsegv:
	force_sig(SIGSEGV);
}

asmlinkage void
do_rt_sigreturn(struct rt_sigframe __user *frame)
{
	struct pt_regs *regs = current_pt_regs();
	sigset_t set;

	/* Verify that it's a good ucontext_t before using it */
	if (!access_ok(&frame->uc, sizeof(frame->uc)))
		goto give_sigsegv;
	if (__copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set)))
		goto give_sigsegv;

	set_current_blocked(&set);

	if (restore_sigcontext(&frame->uc.uc_mcontext, regs))
		goto give_sigsegv;

	if (restore_altstack(&frame->uc.uc_stack))
		goto give_sigsegv;

	return;

give_sigsegv:
	force_sig(SIGSEGV);
}


/*
 * Set up a signal frame.
 */

static inline void __user *
get_sigframe(struct ksignal *ksig, unsigned long sp, size_t frame_size)
{
	return (void __user *)((sigsp(sp, ksig) - frame_size) & -32ul);
}

static long
setup_sigcontext(struct sigcontext __user *sc, struct pt_regs *regs,
		 unsigned long mask, unsigned long sp)
{
	long err = 0;

	err |= __put_user(on_sig_stack((unsigned long)sc), &sc->sc_onstack);
	err |= __put_user(mask, &sc->sc_mask);
	err |= __put_user(regs->pc, &sc->sc_pc);
	err |= __put_user(8, &sc->sc_ps);

	err |= __put_user(regs->r0, sc->sc_regs+0);
	err |= __put_user(regs->r1, sc->sc_regs+1);
	err |= __put_user(regs->r2, sc->sc_regs+2);
	err |= __put_user(regs->r3, sc->sc_regs+3);
	err |= __put_user(regs->r4, sc->sc_regs+4);
	err |= __put_user(regs->r5, sc->sc_regs+5);
	err |= __put_user(regs->r6, sc->sc_regs+6);
	err |= __put_user(regs->r7, sc->sc_regs+7);
	err |= __put_user(regs->r8, sc->sc_regs+8);
	err |= __put_user(regs->r9, sc->sc_regs+9);
	err |= __put_user(regs->r10, sc->sc_regs+10);
	err |= __put_user(regs->r11, sc->sc_regs+11);
	err |= __put_user(regs->r12, sc->sc_regs+12);
	err |= __put_user(regs->r13, sc->sc_regs+13);
	err |= __put_user(regs->r14, sc->sc_regs+14);
	err |= __put_user(regs->r15, sc->sc_regs+15);
	err |= __put_user(regs->r16, sc->sc_regs+16);
	err |= __put_user(regs->r17, sc->sc_regs+17);
	err |= __put_user(regs->r18, sc->sc_regs+18);
	err |= __put_user(regs->r19, sc->sc_regs+19);
	err |= __put_user(regs->r20, sc->sc_regs+20);
	err |= __put_user(regs->r21, sc->sc_regs+21);
	err |= __put_user(regs->r22, sc->sc_regs+22);
	err |= __put_user(regs->r23, sc->sc_regs+23);
	err |= __put_user(regs->r24, sc->sc_regs+24);
	err |= __put_user(regs->r25, sc->sc_regs+25);
	err |= __put_user(regs->r26, sc->sc_regs+26);
	err |= __put_user(regs->r27, sc->sc_regs+27);
	err |= __put_user(regs->r28, sc->sc_regs+28);
	err |= __put_user(regs->gp, sc->sc_regs+29);
	err |= __put_user(sp, sc->sc_regs+30);
	err |= __put_user(0, sc->sc_regs+31);
	/* simd-fp */
	__fpstate_save(current);
	err |= __copy_to_user(&sc->sc_fpregs, &current->thread.fpstate,
				offsetof(struct user_fpsimd_state, fpcr));
	err |= __put_user(current->thread.fpstate.fpcr, &sc->sc_fpcr);

	return err;
}

static int
setup_rt_frame(struct ksignal *ksig, sigset_t *set, struct pt_regs *regs)
{
	unsigned long oldsp, r26, err = 0;
	struct rt_sigframe __user *frame;

	oldsp = rdusp();
	frame = get_sigframe(ksig, oldsp, sizeof(*frame));
	if (!access_ok(frame, sizeof(*frame)))
		return -EFAULT;

	if (ksig->ka.sa.sa_flags & SA_SIGINFO)
		err |= copy_siginfo_to_user(&frame->info, &ksig->info);

	/* Create the ucontext.  */
	err |= __put_user(0, &frame->uc.uc_flags);
	err |= __put_user(0, &frame->uc.uc_link);
	err |= __put_user(set->sig[0], &frame->uc.uc_old_sigmask);
	err |= __save_altstack(&frame->uc.uc_stack, oldsp);
	err |= setup_sigcontext(&frame->uc.uc_mcontext, regs,
			set->sig[0], oldsp);
	err |= __copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set));
	if (err)
		return -EFAULT;

	/* Set up to return from userspace.  If provided, use a stub
	 * already in userspace.
	 */
	r26 = VDSO_SYMBOL(current->mm->context.vdso, rt_sigreturn);

	/* "Return" to the handler */
	regs->r26 = r26;
	regs->r27 = regs->pc = (unsigned long) ksig->ka.sa.sa_handler;
	regs->r16 = ksig->sig;                    /* a0: signal number */
	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		/* a1: siginfo pointer, a2: ucontext pointer */
		regs->r17 = (unsigned long) &frame->info;
		regs->r18 = (unsigned long) &frame->uc;
	} else {
		/* a1: exception code, a2: sigcontext pointer */
		regs->r17 = 0;
		regs->r18 = (unsigned long) &frame->uc.uc_mcontext;
	}
	wrusp((unsigned long) frame);

#if DEBUG_SIG
	printk("SIG deliver (%s:%d): sp=%p pc=%p ra=%p\n",
			current->comm, current->pid, frame, regs->pc, regs->r26);
#endif

	return 0;
}

/*
 * OK, we're invoking a handler.
 */
static inline void
handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
	sigset_t *oldset = sigmask_to_save();
	int ret;

	ret = setup_rt_frame(ksig, oldset, regs);

	signal_setup_done(ret, ksig, 0);
}

static inline void
syscall_restart(unsigned long r0, unsigned long r19,
		struct pt_regs *regs, struct k_sigaction *ka)
{
	switch (regs->r0) {
	case ERESTARTSYS:
		if (!(ka->sa.sa_flags & SA_RESTART)) {
			regs->r0 = EINTR;
			break;
		}
		/* else: fallthrough */
	case ERESTARTNOINTR:
		regs->r0 = r0;	/* reset v0 and a3 and replay syscall */
		regs->r19 = r19;
		regs->pc -= 4;
		break;
	case ERESTART_RESTARTBLOCK:
		regs->r0 = EINTR;
		break;
	case ERESTARTNOHAND:
		regs->r0 = EINTR;
		break;
	}
}


/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 *
 * Note that we go through the signals twice: once to check the signals that
 * the kernel can handle, and then we build all the user-level signal handling
 * stack-frames in one go after that.
 *
 * "r0" and "r19" are the registers we need to restore for system call
 * restart. "r0" is also used as an indicator whether we can restart at
 * all (if we get here from anything but a syscall return, it will be 0)
 */
static void
do_signal(struct pt_regs *regs, unsigned long r0, unsigned long r19)
{
	struct ksignal ksig;

	/* This lets the debugger run, ... */
	if (get_signal(&ksig)) {
		/* Whee!  Actually deliver the signal.  */
		if (r0)
			syscall_restart(r0, r19, regs, &ksig.ka);
		handle_signal(&ksig, regs);
	} else {
		if (r0) {
			switch (regs->r0) {
			case ERESTARTNOHAND:
			case ERESTARTSYS:
			case ERESTARTNOINTR:
				/* Reset v0 and a3 and replay syscall.  */
				regs->r0 = r0;
				regs->r19 = r19;
				regs->pc -= 4;
				break;
			case ERESTART_RESTARTBLOCK:
				/* Set v0 to the restart_syscall and replay */
				regs->r0 = __NR_restart_syscall;
				regs->pc -= 4;
				break;
			}
		}
		restore_saved_sigmask();
	}
}

void
do_work_pending(struct pt_regs *regs, unsigned long thread_flags,
		unsigned long r0, unsigned long r19)
{
	do {
		if (thread_flags & _TIF_NEED_RESCHED) {
			schedule();
		} else {
			local_irq_enable();

			if (thread_flags & _TIF_UPROBE)
				uprobe_notify_resume(regs);

			if (thread_flags & _TIF_SIGPENDING) {
				do_signal(regs, r0, r19);
				r0 = 0;
			} else {
				clear_thread_flag(TIF_NOTIFY_RESUME);
				tracehook_notify_resume(regs);
			}
		}
		local_irq_disable();
		thread_flags = current_thread_info()->flags;
	} while (thread_flags & _TIF_WORK_MASK);
}
