/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Kernel FPU state switching for scheduling.
 *
 * This is a two-stage process:
 *
 *  - switch_kernel_fpu_prepare() saves the old kernel fpu state.
 *    This is done within the context of the old process.
 *
 *  - switch_kernel_fpu_finish() restore new kernel fpu state.
 *
 * The kernel FPU context is only stored/restored for a user task in kernel
 * mode and PF_KTHREAD is used to distinguish between kernel and user threads.
 */
#if defined(CONFIG_X86_HYGON_LMC_SSE2_ON) ||                                   \
	defined(CONFIG_X86_HYGON_LMC_AVX2_ON)
extern void save_fpregs_to_fpkernelstate(struct fpu *kfpu);
extern unsigned long get_fpu_registers_pos(struct fpu *fpu, unsigned int off);
static inline void switch_kernel_fpu_prepare(struct task_struct *prev, int cpu)
{
	struct fpu *old_fpu = &prev->thread.fpu;

	if (!test_thread_flag(TIF_USING_FPU_NONATOMIC))
		return;

	if (static_cpu_has(X86_FEATURE_FPU) && !(prev->flags & PF_KTHREAD))
		save_fpregs_to_fpkernelstate(old_fpu);
}

/* Internal helper for switch_kernel_fpu_finish() and signal frame setup */
static inline void fpregs_restore_kernelregs(struct fpu *kfpu)
{
	kernel_fpu_states_restore(NULL, (void *)get_fpu_registers_pos(kfpu, MAX_FPU_CTX_SIZE),
						MAX_FPU_CTX_SIZE);
}

/* Loading of the complete FPU state immediately. */
static inline void switch_kernel_fpu_finish(struct task_struct *next)
{
	struct fpu *new_fpu = &next->thread.fpu;

	if (next->flags & PF_KTHREAD)
		return;

	if (cpu_feature_enabled(X86_FEATURE_FPU) &&
	    test_ti_thread_flag((struct thread_info *)next,
				TIF_USING_FPU_NONATOMIC))
		fpregs_restore_kernelregs(new_fpu);
}
#else
static inline void switch_kernel_fpu_prepare(struct task_struct *prev, int cpu)
{
}
static inline void switch_kernel_fpu_finish(struct task_struct *next)
{
}

#endif
