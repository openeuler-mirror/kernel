/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2018 Cavium Networks.
 */

#ifndef __ASM_SIGNAL_COMMON_H
#define __ASM_SIGNAL_COMMON_H

#include <linux/uaccess.h>
#include <asm/fpsimd.h>
#include <asm/traps.h>

#define EXTRA_CONTEXT_SIZE round_up(sizeof(struct extra_context), 16)
#define TERMINATOR_SIZE round_up(sizeof(struct _aarch64_ctx), 16)
#define SIGCONTEXT_RESERVED_SIZE sizeof(((struct sigcontext *)0)->__reserved)
#define RT_SIGFRAME_RESERVED_OFFSET \
		offsetof(struct rt_sigframe, uc.uc_mcontext.__reserved)

/*
 * Sanity limit on the approximate maximum size of signal frame we'll
 * try to generate.  Stack alignment padding and the frame record are
 * not taken into account.  This limit is not a guarantee and is
 * NOT ABI.
 */
#define SIGFRAME_MAXSZ SZ_64K

struct rt_sigframe_user_layout {
	struct rt_sigframe __user *sigframe;
	struct frame_record __user *next_frame;

	unsigned long size;	/* size of allocated sigframe data */
	unsigned long limit;	/* largest allowed size */

	unsigned long fpsimd_offset;
	unsigned long esr_offset;
	unsigned long sve_offset;
	unsigned long tpidr2_offset;
	unsigned long za_offset;
	unsigned long zt_offset;
	unsigned long extra_offset;
	unsigned long end_offset;
};

struct user_ctxs {
	struct fpsimd_context __user *fpsimd;
	u32 fpsimd_size;
	struct sve_context __user *sve;
	u32 sve_size;
	struct tpidr2_context __user *tpidr2;
	u32 tpidr2_size;
	struct za_context __user *za;
	u32 za_size;
	struct zt_context __user *zt;
	u32 zt_size;
};

struct frame_record {
	u64 fp;
	u64 lr;
};

void __user *apply_user_offset(struct rt_sigframe_user_layout const *user,
			       unsigned long offset);

int setup_sigframe_layout(struct rt_sigframe_user_layout *user, bool add_all);
int setup_extra_context(char __user *sfp, unsigned long sf_size,
			char __user *exprap);
int __parse_user_sigcontext(struct user_ctxs *user,
				   struct sigcontext __user const *sc,
				   void __user const *sigframe_base);
#define parse_user_sigcontext(user, sf)					\
	__parse_user_sigcontext(user, &(sf)->uc.uc_mcontext, sf)

int preserve_fpsimd_context(struct fpsimd_context __user *ctx);
int restore_fpsimd_context(struct user_ctxs *user);

#ifdef CONFIG_ARM64_SVE
int preserve_sve_context(struct sve_context __user *ctx);
int restore_sve_fpsimd_context(struct user_ctxs *user);
#else /* ! CONFIG_ARM64_SVE */

/* Turn any non-optimised out attempts to use these into a link error: */
extern int preserve_sve_context(void __user *ctx);
extern int restore_sve_fpsimd_context(struct user_ctxs *user);

#endif /* ! CONFIG_ARM64_SVE */


#ifdef CONFIG_ARM64_SME
int preserve_tpidr2_context(struct tpidr2_context __user *ctx);
int restore_tpidr2_context(struct user_ctxs *user);
int preserve_za_context(struct za_context __user *ctx);
int restore_za_context(struct user_ctxs *user);
int preserve_zt_context(struct zt_context __user *ctx);
int restore_zt_context(struct user_ctxs *user);
#else /* ! CONFIG_ARM64_SME */

/* Turn any non-optimised out attempts to use these into a link error: */
extern int preserve_tpidr2_context(void __user *ctx);
extern int restore_tpidr2_context(struct user_ctxs *user);
extern int preserve_za_context(void __user *ctx);
extern int restore_za_context(struct user_ctxs *user);
extern int preserve_zt_context(void __user *ctx);
extern int restore_zt_context(struct user_ctxs *user);

#endif /* ! CONFIG_ARM64_SME */

int sigframe_alloc(struct rt_sigframe_user_layout *user,
		   unsigned long *offset, size_t size);
int sigframe_alloc_end(struct rt_sigframe_user_layout *user);

void __setup_return(struct pt_regs *regs, struct k_sigaction *ka,
		    struct rt_sigframe_user_layout *user, int usig);

static void init_user_layout(struct rt_sigframe_user_layout *user)
{
	const size_t reserved_size =
		sizeof(user->sigframe->uc.uc_mcontext.__reserved);

	memset(user, 0, sizeof(*user));
	user->size = offsetof(struct rt_sigframe, uc.uc_mcontext.__reserved);

	user->limit = user->size + reserved_size;

	user->limit -= TERMINATOR_SIZE;
	user->limit -= EXTRA_CONTEXT_SIZE;
	/* Reserve space for extension and terminator ^ */
}

static size_t sigframe_size(struct rt_sigframe_user_layout const *user)
{
	return round_up(max(user->size, sizeof(struct rt_sigframe)), 16);
}

static int get_sigframe(struct rt_sigframe_user_layout *user,
			 struct ksignal *ksig, struct pt_regs *regs)
{
	unsigned long sp, sp_top;
	int err;

	init_user_layout(user);
	err = setup_sigframe_layout(user, false);
	if (err)
		return err;

	sp = sp_top = sigsp(regs->sp, ksig);

	sp = round_down(sp - sizeof(struct frame_record), 16);
	user->next_frame = (struct frame_record __user *)sp;

	sp = round_down(sp, 16) - sigframe_size(user);
	user->sigframe = (void __user *)sp;

	/*
	 * Check that we can actually write to the signal frame.
	 */
	if (!access_ok(VERIFY_WRITE, user->sigframe, sp_top - sp))
		return -EFAULT;

	return 0;
}

static int restore_sigframe(struct pt_regs *regs,
			    struct rt_sigframe __user *sf)
{
	sigset_t set;
	int i, err;
	struct user_ctxs user;

	err = __copy_from_user(&set, &sf->uc.uc_sigmask, sizeof(set));
	if (err == 0)
		set_current_blocked(&set);

	for (i = 0; i < 31; i++)
		__get_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i],
				 err);
	__get_user_error(regs->sp, &sf->uc.uc_mcontext.sp, err);
	__get_user_error(regs->pc, &sf->uc.uc_mcontext.pc, err);
	__get_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err);

	/*
	 * Avoid sys_rt_sigreturn() restarting.
	 */
	forget_syscall(regs);

	err |= !valid_user_regs(&regs->user_regs, current);
	if (err == 0)
		err = parse_user_sigcontext(&user, sf);

	if (err == 0 && system_supports_fpsimd()) {
		if (!user.fpsimd)
			return -EINVAL;

		if (user.sve)
			err = restore_sve_fpsimd_context(&user);
		else
			err = restore_fpsimd_context(&user);
	}

	if (err == 0 && system_supports_tpidr2() && user.tpidr2)
		err = restore_tpidr2_context(&user);

	if (err == 0 && system_supports_sme() && user.za)
		err = restore_za_context(&user);

	if (err == 0 && system_supports_sme2() && user.zt)
		err = restore_zt_context(&user);

	return err;
}

static int setup_sigframe(struct rt_sigframe_user_layout *user,
			  struct pt_regs *regs, sigset_t *set)
{
	int i, err = 0;
	struct rt_sigframe __user *sf = user->sigframe;

	/* set up the stack frame for unwinding */
	__put_user_error(regs->regs[29], &user->next_frame->fp, err);
	__put_user_error(regs->regs[30], &user->next_frame->lr, err);

	for (i = 0; i < 31; i++)
		__put_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i],
				 err);
	__put_user_error(regs->sp, &sf->uc.uc_mcontext.sp, err);
	__put_user_error(regs->pc, &sf->uc.uc_mcontext.pc, err);
	__put_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err);

	__put_user_error(current->thread.fault_address, &sf->uc.uc_mcontext.fault_address, err);

	err |= __copy_to_user(&sf->uc.uc_sigmask, set, sizeof(*set));

	if (err == 0 && system_supports_fpsimd()) {
		struct fpsimd_context __user *fpsimd_ctx =
			apply_user_offset(user, user->fpsimd_offset);
		err |= preserve_fpsimd_context(fpsimd_ctx);
	}

	/* fault information, if valid */
	if (err == 0 && user->esr_offset) {
		struct esr_context __user *esr_ctx =
			apply_user_offset(user, user->esr_offset);

		__put_user_error(ESR_MAGIC, &esr_ctx->head.magic, err);
		__put_user_error(sizeof(*esr_ctx), &esr_ctx->head.size, err);
		__put_user_error(current->thread.fault_code, &esr_ctx->esr, err);
	}

	/* Scalable Vector Extension state (including streaming), if present */
	if ((system_supports_sve() || system_supports_sme()) &&
	    err == 0 && user->sve_offset) {
		struct sve_context __user *sve_ctx =
			apply_user_offset(user, user->sve_offset);
		err |= preserve_sve_context(sve_ctx);
	}

	/* TPIDR2 if supported */
	if (system_supports_tpidr2() && err == 0) {
		struct tpidr2_context __user *tpidr2_ctx =
			apply_user_offset(user, user->tpidr2_offset);
		err |= preserve_tpidr2_context(tpidr2_ctx);
	}

	/* ZA state if present */
	if (system_supports_sme() && err == 0 && user->za_offset) {
		struct za_context __user *za_ctx =
			apply_user_offset(user, user->za_offset);
		err |= preserve_za_context(za_ctx);
	}

	/* ZT state if present */
	if (system_supports_sme2() && err == 0 && user->zt_offset) {
		struct zt_context __user *zt_ctx =
			apply_user_offset(user, user->zt_offset);
		err |= preserve_zt_context(zt_ctx);
	}

	if (err == 0 && user->extra_offset) {
		char __user *sfp = (char __user *)user->sigframe;
		char __user *userp =
			apply_user_offset(user, user->extra_offset);

		struct extra_context __user *extra;
		struct _aarch64_ctx __user *end;
		u64 extra_datap;
		u32 extra_size;

		extra = (struct extra_context __user *)userp;
		userp += EXTRA_CONTEXT_SIZE;

		end = (struct _aarch64_ctx __user *)userp;
		userp += TERMINATOR_SIZE;

		/*
		 * extra_datap is just written to the signal frame.
		 * The value gets cast back to a void __user *
		 * during sigreturn.
		 */
		extra_datap = (__force u64)userp;
		extra_size = sfp + round_up(user->size, 16) - userp;

		__put_user_error(EXTRA_MAGIC, &extra->head.magic, err);
		__put_user_error(EXTRA_CONTEXT_SIZE, &extra->head.size, err);
		__put_user_error(extra_datap, &extra->datap, err);
		__put_user_error(extra_size, &extra->size, err);

		/* Add the terminator */
		__put_user_error(0, &end->magic, err);
		__put_user_error(0, &end->size, err);
	}

	/* set the "end" magic */
	if (err == 0) {
		struct _aarch64_ctx __user *end =
			apply_user_offset(user, user->end_offset);

		__put_user_error(0, &end->magic, err);
		__put_user_error(0, &end->size, err);
	}

	return err;
}

static long __sys_rt_sigreturn(struct pt_regs *regs)
{
	struct rt_sigframe __user *frame;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	/*
	 * Since we stacked the signal on a 128-bit boundary, then 'sp' should
	 * be word aligned here.
	 */
	if (regs->sp & 15)
		goto badframe;

	frame = (struct rt_sigframe __user *)regs->sp;

	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;

	if (restore_sigframe(regs, frame))
		goto badframe;

	if (restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	return regs->regs[0];

badframe:
	arm64_notify_segfault(regs->sp);
	return 0;
}

static int __setup_rt_frame(int usig, struct ksignal *ksig,
				sigset_t *set, struct pt_regs *regs)
{
	struct rt_sigframe_user_layout user;
	struct rt_sigframe __user *frame;
	int err = 0;

	fpsimd_signal_preserve_current_state();

	if (get_sigframe(&user, ksig, regs))
		return 1;

	frame = user.sigframe;

	__put_user_error(0, &frame->uc.uc_flags, err);
	__put_user_error((typeof(frame->uc.uc_link)) 0,
			  &frame->uc.uc_link, err);

	err |= __save_altstack(&frame->uc.uc_stack, regs->sp);
	err |= setup_sigframe(&user, regs, set);
	if (err == 0) {
		setup_return(regs, &ksig->ka, &user, usig);
		if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
			err |= copy_siginfo_to_user(&frame->info, &ksig->info);
			regs->regs[1] = (unsigned long)&frame->info;
			regs->regs[2] = (unsigned long)&frame->uc;
		}
	}

	return err;
}

#endif /* __ASM_SIGNAL_COMMON_H */
