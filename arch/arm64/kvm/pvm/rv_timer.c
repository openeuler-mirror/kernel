// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: wanghaibin <wanghaibin.wang@huawei.com>
 */

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/uaccess.h>

#include <clocksource/arm_arch_timer.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>

#include <kvm/arm_vgic.h>
#include <kvm/arm_arch_timer.h>
#include <kvm/arm_rv_timer.h>

#include "../vgic/vgic.h"
#include "pvm.h"

#define CREATE_TRACE_POINTS
#include "trace_rv.h"

static u64 kvm_counter_compute_delta(struct rv_timer_context *timer_ctx,
				     u64 val);
static void kvm_rv_timer_update_irq(struct kvm_vcpu *vcpu, bool new_level,
				    struct rv_timer_context *timer_ctx);
static bool kvm_rv_timer_should_fire(struct rv_timer_context *timer_ctx);
static void rv_timer_emulate(struct rv_timer_context *ctx);
static bool kvm_rv_timer_irq_can_fire(struct rv_timer_context *timer_ctx);
static void kvm_rv_timer_write(struct kvm_vcpu *vcpu,
			       struct rv_timer_context *timer,
			       enum kvm_arch_timer_regs treg,
			       u64 val);
static u64 kvm_rv_timer_read(struct kvm_vcpu *vcpu,
			     struct rv_timer_context *timer,
			     enum kvm_arch_timer_regs treg);

static struct timecounter *timecounter;

static const u8 default_ppi[] = {
	/* The single context exposes the virtual timer ABI and default PPI. */
	[RVTIMER_VTIMER]  = 27,
};

/*
 * Also called from the PVM hyp counter fast path with interrupts masked.
 * Keep this reader and its counter/offset callees non-sleeping and safe
 * in that context; do not add locking or tracing without auditing callers.
 */
static u64 rv_counter_read(void)
{
	/*
	 * Use the architected clocksource selected by the L1 timer driver.
	 * In the current PVM L1 this is CNTVCT, with the required access
	 * ordering and any architected counter workarounds applied.
	 */
	return timecounter->cc->read(timecounter->cc);
}

static void rv_timer_set_offset(struct rv_timer_context *ctxt, u64 offset)
{
	WRITE_ONCE(*ctxt->offset.vm_offset, offset);
}

static u64 rv_timer_get_offset(struct rv_timer_context *ctxt)
{
	u64 offset = 0;

	if (!ctxt)
		return 0;

	if (ctxt->offset.vm_offset)
		offset += READ_ONCE(*ctxt->offset.vm_offset);

	return offset;
}

static u64 kvm_rv_timer_compute_delta(struct rv_timer_context *timer_ctx);

/*
 * Only the virtual timer is implemented. Physical timer accesses are
 * compatibility aliases of this same state, not an independent timer.
 * Userspace enumerates the virtual timer state for save and restore.
 */
static enum kvm_rv_timers rv_timer_id(enum kvm_arch_timers tmr)
{
	switch (tmr) {
	case TIMER_VTIMER:
	case TIMER_PTIMER:
		return RVTIMER_VTIMER;
	default:
		WARN_ON_ONCE(1);
		return RVTIMER_VTIMER;
	}
}

static int nr_timers(struct kvm_vcpu *vcpu)
{
	return NR_KVM_RVTIMERS;
}

static void soft_timer_start(struct hrtimer *hrt, u64 ns)
{
	hrtimer_start(hrt, ktime_add_ns(ktime_get(), ns),
		      HRTIMER_MODE_ABS_HARD);
}

static void soft_timer_cancel(struct hrtimer *hrt)
{
	hrtimer_cancel(hrt);
}

static bool vcpu_has_wfit_active(struct kvm_vcpu *vcpu)
{
	return (cpus_have_final_cap(ARM64_HAS_WFXT) &&
		vcpu_get_flag(vcpu, IN_WFIT));
}

static u64 wfit_delay_ns(struct kvm_vcpu *vcpu)
{
	u64 val = vcpu_get_reg(vcpu, kvm_vcpu_sys_get_rt(vcpu));
	struct rv_timer_context *ctx;

	ctx = vcpu_rv_vtimer(vcpu);

	return kvm_counter_compute_delta(ctx, val);
}

u32 rv_timer_get_ctl(struct rv_timer_context *ctxt)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch (rv_timer_ctx_index(ctxt)) {
	case RVTIMER_VTIMER:
		return __vcpu_sys_reg(vcpu, CNTV_CTL_EL0);

	default:
		WARN_ON(1);
		return 0;
	}
}

u64 rv_timer_get_cval(struct rv_timer_context *ctxt)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch (rv_timer_ctx_index(ctxt)) {
	case RVTIMER_VTIMER:
		return __vcpu_sys_reg(vcpu, CNTV_CVAL_EL0);

	default:
		WARN_ON(1);
		return 0;
	}
}

static u64 read_rv_timer_ctl(struct rv_timer_context *timer)
{
	/*
	 * Set ISTATUS bit if it's expired.
	 * Note that according to ARMv8 ARM Issue A.k, ISTATUS bit is
	 * UNKNOWN when ENABLE bit is 0, so we chose to set ISTATUS bit
	 * regardless of ENABLE bit for our implementation convenience.
	 */
	u32 ctl = rv_timer_get_ctl(timer);

	if (!kvm_rv_timer_compute_delta(timer))
		ctl |= ARCH_TIMER_CTRL_IT_STAT;

	return ctl;
}

static void rv_timer_set_ctl(struct rv_timer_context *ctxt, u32 ctl)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch (rv_timer_ctx_index(ctxt)) {
	case RVTIMER_VTIMER:
		__vcpu_sys_reg(vcpu, CNTV_CTL_EL0) = ctl;
		break;

	default:
		WARN_ON(1);
	}
}

static void rv_timer_set_cval(struct rv_timer_context *ctxt, u64 cval)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch (rv_timer_ctx_index(ctxt)) {
	case RVTIMER_VTIMER:
		__vcpu_sys_reg(vcpu, CNTV_CVAL_EL0) = cval;
		break;
	default:
		WARN_ON(1);
	}
}

static enum hrtimer_restart kvm_hrtimer_expire(struct hrtimer *hrt)
{
	struct rv_timer_context *ctx;
	struct kvm_vcpu *vcpu;
	u64 ns;

	ctx = container_of(hrt, struct rv_timer_context, hrtimer);
	vcpu = ctx->vcpu;

	trace_kvm_rv_timer_hrtimer_expire(ctx);

	/*
	 * Check that the timer has really expired from the guest's
	 * PoV (NTP on the host may have forced it to expire
	 * early). If not ready, schedule for a later time.
	 */
	ns = kvm_rv_timer_compute_delta(ctx);
	if (unlikely(ns)) {
		hrtimer_forward_now(hrt, ns_to_ktime(ns));
		return HRTIMER_RESTART;
	}

	kvm_rv_timer_update_irq(vcpu, true, ctx);
	return HRTIMER_NORESTART;
}

int kvm_cpu_has_pending_rv_timer(struct kvm_vcpu *vcpu)
{
	return vcpu_has_wfit_active(vcpu) && wfit_delay_ns(vcpu) == 0;
}

static void kvm_rv_timer_unblocking(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);

	soft_timer_cancel(&timer->bg_timer);
}

void kvm_rv_timer_vcpu_load(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);
	struct rv_timer_context *ctx = vcpu_rv_vtimer(vcpu);

	if (unlikely(!timer->enabled))
		return;

	kvm_rv_timer_unblocking(vcpu);

	/*
	 * Update the timer output so that it is likely to match the
	 * state we're about to restore. If the timer expires between
	 * this point and the register restoration, we'll take the
	 * interrupt anyway.
	 */
	kvm_rv_timer_update_irq(vcpu,
				kvm_rv_timer_should_fire(ctx),
				ctx);

	rv_timer_emulate(ctx);

	trace_kvm_rv_timer_load_state(ctx);
}

/*
 * Returns the earliest expiration time in ns among guest timers.
 * Note that it will return 0 if none of timers can fire.
 */
static u64 kvm_rv_timer_earliest_exp(struct kvm_vcpu *vcpu)
{
	u64 min_delta = ULLONG_MAX;
	int i;

	for (i = 0; i < nr_timers(vcpu); i++) {
		struct rv_timer_context *ctx = &vcpu_to_pvm(vcpu)->timer_cpu.timers[i];

		if (kvm_rv_timer_irq_can_fire(ctx))
			min_delta = min(min_delta, kvm_rv_timer_compute_delta(ctx));
	}

	if (vcpu_has_wfit_active(vcpu))
		min_delta = min(min_delta, wfit_delay_ns(vcpu));

	/* If none of timers can fire, then return 0 */
	if (min_delta == ULLONG_MAX)
		return 0;

	return min_delta;
}

static enum hrtimer_restart kvm_bg_timer_expire(struct hrtimer *hrt)
{
	struct rv_timer_cpu *timer;
	struct kvm_vcpu *vcpu;
	u64 ns;

	timer = container_of(hrt, struct rv_timer_cpu, bg_timer);
	vcpu = &container_of(timer, struct kvm_pvm_vcpu, timer_cpu)->vcpu;

	/*
	 * Check that the timer has really expired from the guest's
	 * PoV (NTP on the host may have forced it to expire
	 * early). If we should have slept longer, restart it.
	 */
	ns = kvm_rv_timer_earliest_exp(vcpu);
	if (unlikely(ns)) {
		hrtimer_forward_now(hrt, ns_to_ktime(ns));
		return HRTIMER_RESTART;
	}

	kvm_vcpu_wake_up(vcpu);
	return HRTIMER_NORESTART;
}

/*
 * Schedule the background timer before calling kvm_vcpu_halt, so that this
 * thread is removed from its waitqueue and made runnable when there's a timer
 * interrupt to handle.
 */
static void kvm_rv_timer_blocking(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);
	struct rv_timer_context *ctx = vcpu_rv_vtimer(vcpu);

	/*
	 * If no timers are capable of raising interrupts (disabled or
	 * masked), then there's no more work for us to do.
	 */
	if (!kvm_rv_timer_irq_can_fire(ctx) &&
	    !vcpu_has_wfit_active(vcpu))
		return;

	/*
	 * At least one guest timer will expire. Schedule a background timer.
	 * Set the earliest expiration time among the guest timers.
	 */
	soft_timer_start(&timer->bg_timer, kvm_rv_timer_earliest_exp(vcpu));
}

void kvm_rv_timer_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);
	struct rv_timer_context *ctx = vcpu_rv_vtimer(vcpu);

	if (unlikely(!timer->enabled))
		return;

	trace_kvm_rv_timer_put_state(ctx);

	/*
	 * Cancel soft timer emulation, because the only case where we
	 * need it after a vcpu_put is in the context of a sleeping VCPU, and
	 * in that case we already factor in the deadline for the virtual
	 * timer when scheduling the bg_timer.
	 *
	 * In any case, we re-schedule the hrtimer for the virtual timer when
	 * coming back to the VCPU thread in kvm_timer_vcpu_load().
	 */
	soft_timer_cancel(&ctx->hrtimer);

	if (kvm_vcpu_is_blocking(vcpu))
		kvm_rv_timer_blocking(vcpu);
}

int kvm_rv_timer_set_reg(struct kvm_vcpu *vcpu, u64 regid, u64 value)
{
	struct rv_timer_context *timer = vcpu_rv_vtimer(vcpu);

	switch (regid) {
	case KVM_REG_ARM_TIMER_CTL:
	case KVM_REG_ARM_PTIMER_CTL:
		kvm_rv_timer_write(vcpu, timer, TIMER_REG_CTL, value);
		break;
	case KVM_REG_ARM_TIMER_CNT:
	case KVM_REG_ARM_PTIMER_CNT:
		rv_timer_set_offset(timer, rv_counter_read() - value);
		break;
	case KVM_REG_ARM_TIMER_CVAL:
	case KVM_REG_ARM_PTIMER_CVAL:
		kvm_rv_timer_write(vcpu, timer, TIMER_REG_CVAL, value);
		break;

	default:
		return -1;
	}

	return 0;
}

u64 kvm_rv_timer_get_reg(struct kvm_vcpu *vcpu, u64 regid)
{
	switch (regid) {
	case KVM_REG_ARM_TIMER_CTL:
	case KVM_REG_ARM_PTIMER_CTL:
		return kvm_rv_timer_read(vcpu,
					 vcpu_rv_vtimer(vcpu), TIMER_REG_CTL);
	case KVM_REG_ARM_TIMER_CNT:
	case KVM_REG_ARM_PTIMER_CNT:
		return kvm_rv_timer_read(vcpu,
					 vcpu_rv_vtimer(vcpu), TIMER_REG_CNT);
	case KVM_REG_ARM_TIMER_CVAL:
	case KVM_REG_ARM_PTIMER_CVAL:
		return kvm_rv_timer_read(vcpu,
					 vcpu_rv_vtimer(vcpu), TIMER_REG_CVAL);
	}
	return (u64)-1;
}

static inline bool userspace_irqchip(struct kvm *kvm)
{
	return unlikely(!irqchip_in_kernel(kvm));
}

static u64 kvm_counter_compute_delta(struct rv_timer_context *timer_ctx,
				     u64 val)
{
	u64 now = rv_counter_read() - rv_timer_get_offset(timer_ctx);

	if (now < val) {
		u64 ns;

		ns = cyclecounter_cyc2ns(timecounter->cc,
					 val - now,
					 timecounter->mask,
					 &timer_ctx->ns_frac);
		return ns;
	}

	return 0;
}

static u64 kvm_rv_timer_compute_delta(struct rv_timer_context *timer_ctx)
{
	return kvm_counter_compute_delta(timer_ctx, rv_timer_get_cval(timer_ctx));
}

static void kvm_rv_timer_update_irq(struct kvm_vcpu *vcpu, bool new_level,
				    struct rv_timer_context *timer_ctx)
{
	int ret;

	timer_ctx->irq.level = new_level;

	trace_kvm_rv_timer_update_irq(vcpu->vcpu_id, rv_timer_irq(timer_ctx),
				      timer_ctx->irq.level);

	if (!userspace_irqchip(vcpu->kvm)) {
		ret = kvm_vgic_inject_irq(vcpu->kvm, vcpu->vcpu_id,
					  rv_timer_irq(timer_ctx),
					  timer_ctx->irq.level,
					  timer_ctx);

		WARN_ON(ret);
	}
}

static bool kvm_rv_timer_irq_can_fire(struct rv_timer_context *timer_ctx)
{
	return timer_ctx &&
		((rv_timer_get_ctl(timer_ctx) &
		  (ARCH_TIMER_CTRL_IT_MASK | ARCH_TIMER_CTRL_ENABLE)) == ARCH_TIMER_CTRL_ENABLE);
}

static bool kvm_rv_timer_should_fire(struct rv_timer_context *timer_ctx)
{
	u64 cval, now;

	if (!timer_ctx)
		return false;

	if (!kvm_rv_timer_irq_can_fire(timer_ctx))
		return false;

	cval = rv_timer_get_cval(timer_ctx);
	now = rv_counter_read() - rv_timer_get_offset(timer_ctx);

	return cval <= now;
}

/* Only called for a fully emulated timer */
static void rv_timer_emulate(struct rv_timer_context *ctx)
{
	bool should_fire = kvm_rv_timer_should_fire(ctx);

	trace_kvm_rv_timer_emulate(ctx, should_fire);

	if (should_fire != ctx->irq.level)
		kvm_rv_timer_update_irq(ctx->vcpu, should_fire, ctx);

	/*
	 * If the timer can fire now, we don't need to have a soft timer
	 * scheduled for the future.  If the timer cannot fire at all,
	 * then we also don't need a soft timer.
	 */
	if (should_fire || !kvm_rv_timer_irq_can_fire(ctx))
		return;

	soft_timer_start(&ctx->hrtimer, kvm_rv_timer_compute_delta(ctx));
}

static u64 kvm_rv_timer_read(struct kvm_vcpu *vcpu,
			     struct rv_timer_context *timer,
			     enum kvm_arch_timer_regs treg)
{
	u64 val;

	switch (treg) {
	case TIMER_REG_TVAL:
		val = rv_timer_get_cval(timer) - rv_counter_read() + rv_timer_get_offset(timer);
		val = lower_32_bits(val);
		break;

	case TIMER_REG_CTL:
		val = read_rv_timer_ctl(timer);
		break;

	case TIMER_REG_CVAL:
		val = rv_timer_get_cval(timer);
		break;

	case TIMER_REG_CNT:
		val = rv_counter_read() - rv_timer_get_offset(timer);
		break;

	default:
		WARN_ON_ONCE(1);
		return 0;
	}

	return val;
}

u64 kvm_rv_timer_read_sysreg(struct kvm_vcpu *vcpu,
			     enum kvm_arch_timers tmr,
			     enum kvm_arch_timer_regs treg)
{
	struct rv_timer_context *timer;

	timer = vcpu_get_rv_timer(vcpu, rv_timer_id(tmr));

	return kvm_rv_timer_read(vcpu, timer, treg);
}

static void kvm_rv_timer_write(struct kvm_vcpu *vcpu,
			       struct rv_timer_context *timer,
			       enum kvm_arch_timer_regs treg,
			       u64 val)
{
	switch (treg) {
	case TIMER_REG_TVAL:
		rv_timer_set_cval(timer, rv_counter_read() -
				  rv_timer_get_offset(timer) + (s32)val);
		break;

	case TIMER_REG_CTL:
		rv_timer_set_ctl(timer, val & ~ARCH_TIMER_CTRL_IT_STAT);
		break;

	case TIMER_REG_CVAL:
		rv_timer_set_cval(timer, val);
		break;

	default:
		WARN_ON_ONCE(1);
		return;
	}
}

void kvm_rv_timer_write_sysreg(struct kvm_vcpu *vcpu,
			       enum kvm_arch_timers tmr,
			       enum kvm_arch_timer_regs treg,
			       u64 val)
{
	struct rv_timer_context *timer;

	timer = vcpu_get_rv_timer(vcpu, rv_timer_id(tmr));

	soft_timer_cancel(&timer->hrtimer);
	kvm_rv_timer_write(vcpu, timer, treg, val);
	rv_timer_emulate(timer);
}

int kvm_rv_timer_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);
	struct rv_timer_context *ctx = vcpu_rv_vtimer(vcpu);

	soft_timer_cancel(&timer->bg_timer);
	soft_timer_cancel(&ctx->hrtimer);

	/*
	 * The bits in CNTV_CTL are architecturally reset to UNKNOWN for ARMv8
	 * and to 0 for ARMv7.  We provide an implementation that always
	 * resets the timer to be disabled and unmasked and is compliant with
	 * the ARMv7 architecture.
	 */
	for (int i = 0; i < nr_timers(vcpu); i++)
		rv_timer_set_ctl(vcpu_get_rv_timer(vcpu, i), 0);

	if (timer->enabled) {
		for (int i = 0; i < nr_timers(vcpu); i++)
			kvm_rv_timer_update_irq(vcpu, false,
						vcpu_get_rv_timer(vcpu, i));
	}

	return 0;
}

int kvm_rv_timer_enable(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);

	if (timer->enabled)
		return 0;
	if (!kvm_has_gicv3(vcpu->kvm))
		return -EINVAL;

	for (int i = 0; i < nr_timers(vcpu); i++) {
		struct rv_timer_context *ctx;
		int irq;

		ctx = vcpu_get_rv_timer(vcpu, i);
		irq = rv_timer_irq(ctx);

		if (kvm_vgic_set_owner(vcpu, irq, ctx))
			return -EINVAL;
	}

	timer->enabled = true;

	return 0;
}

void kvm_rv_timer_vcpu_terminate(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);

	soft_timer_cancel(&timer->bg_timer);
	soft_timer_cancel(&vcpu_rv_vtimer(vcpu)->hrtimer);
}

static void rv_timer_context_init(struct kvm_vcpu *vcpu, int timerid)
{
	struct rv_timer_context *ctxt = vcpu_get_rv_timer(vcpu, timerid);
	struct kvm *kvm = vcpu->kvm;

	ctxt->vcpu = vcpu;
	ctxt->offset.vm_offset = &kvm_to_pvm(kvm)->timer_data.offset;

	hrtimer_init(&ctxt->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_HARD);
	ctxt->hrtimer.function = kvm_hrtimer_expire;
}

void kvm_rv_timer_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct rv_timer_cpu *timer = vcpu_rv_timer(vcpu);

	for (int i = 0; i < NR_KVM_RVTIMERS; i++)
		rv_timer_context_init(vcpu, i);

	hrtimer_init(&timer->bg_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_HARD);
	timer->bg_timer.function = kvm_bg_timer_expire;
}

void kvm_rv_timer_init_vm(struct kvm *kvm)
{
	/* All vCPUs share one counter epoch, initialized only once. */
	kvm_to_pvm(kvm)->timer_data.offset = rv_counter_read();

	for (int i = 0; i < NR_KVM_RVTIMERS; i++)
		kvm_to_pvm(kvm)->timer_data.ppi[i] = default_ppi[i];
}

int __init kvm_rv_timer_hyp_init(void)
{
	struct arch_timer_kvm_info *info;

	info = arch_timer_get_kvm_info();
	timecounter = &info->timecounter;

	if (!timecounter->cc) {
		kvm_err("pvm: uninitialized timer timecounter\n");
		return -ENODEV;
	}

	return 0;
}
