// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/kvm_host.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/cacheops.h>
#include <asm/cpu-info.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/inst.h>
#include "kvmcpu.h"
#include "trace.h"
#include "kvm_compat.h"

/*
 * ktime_to_tick() - Scale ktime_t to a 64-bit stable timer.
 *
 * Caches the dynamic nanosecond bias in vcpu->arch.timer_dyn_bias.
 */
static u64 ktime_to_tick(struct kvm_vcpu *vcpu, ktime_t now)
{
	s64 now_ns, periods;
	u64 delta;

	now_ns = ktime_to_ns(now);
	delta = now_ns + vcpu->arch.timer_dyn_bias;

	if (delta >= vcpu->arch.timer_period) {
		/* If delta is out of safe range the bias needs adjusting */
		periods = div64_s64(now_ns, vcpu->arch.timer_period);
		vcpu->arch.timer_dyn_bias = -periods * vcpu->arch.timer_period;
		/* Recalculate delta with new bias */
		delta = now_ns + vcpu->arch.timer_dyn_bias;
	}

	/*
	 * We've ensured that:
	 *   delta < timer_period
	 */
	return div_u64(delta * vcpu->arch.timer_mhz, MNSEC_PER_SEC);
}

/**
 * kvm_resume_hrtimer() - Resume hrtimer, updating expiry.
 * @vcpu:	Virtual CPU.
 * @now:	ktime at point of resume.
 * @stable_timer:	stable timer at point of resume.
 *
 * Resumes the timer and updates the timer expiry based on @now and @count.
 */
static void kvm_resume_hrtimer(struct kvm_vcpu *vcpu, ktime_t now, u64 stable_timer)
{
	u64 delta;
	ktime_t expire;

	/* Stable timer decreased to zero or
	 * initialize to zero, set 4 second timer
	*/
	delta = div_u64(stable_timer * MNSEC_PER_SEC, vcpu->arch.timer_mhz);
	expire = ktime_add_ns(now, delta);

	/* Update hrtimer to use new timeout */
	hrtimer_cancel(&vcpu->arch.swtimer);
	hrtimer_start(&vcpu->arch.swtimer, expire, HRTIMER_MODE_ABS_PINNED);
}

/**
 * kvm_init_timer() - Initialise stable timer.
 * @vcpu:	Virtual CPU.
 * @timer_hz:	Frequency of timer.
 *
 * Initialise the timer to the specified frequency, zero it, and set it going if
 * it's enabled.
 */
void kvm_init_timer(struct kvm_vcpu *vcpu, unsigned long timer_hz)
{
	ktime_t now;
	unsigned long ticks;
	struct loongarch_csrs *csr = vcpu->arch.csr;

	vcpu->arch.timer_mhz = timer_hz >> 20;
	vcpu->arch.timer_period = div_u64((u64)MNSEC_PER_SEC * IOCSR_TIMER_MASK, vcpu->arch.timer_mhz);
	vcpu->arch.timer_dyn_bias = 0;

	/* Starting at 0 */
	ticks = 0;
	now = ktime_get();
	vcpu->arch.timer_bias = ticks - ktime_to_tick(vcpu, now);
	vcpu->arch.timer_bias &= IOCSR_TIMER_MASK;

	kvm_write_sw_gcsr(csr, KVM_CSR_TVAL, ticks);
}

/**
 * kvm_count_timeout() - Push timer forward on timeout.
 * @vcpu:	Virtual CPU.
 *
 * Handle an hrtimer event by push the hrtimer forward a period.
 *
 * Returns:	The hrtimer_restart value to return to the hrtimer subsystem.
 */
enum hrtimer_restart kvm_count_timeout(struct kvm_vcpu *vcpu)
{
	unsigned long timer_cfg;

	/* Add the Count period to the current expiry time */
	timer_cfg = kvm_read_sw_gcsr(vcpu->arch.csr, KVM_CSR_TCFG);
	if (timer_cfg & KVM_TCFG_PERIOD) {
		hrtimer_add_expires_ns(&vcpu->arch.swtimer, timer_cfg & KVM_TCFG_VAL);
		return HRTIMER_RESTART;
	} else
		return HRTIMER_NORESTART;
}

/*
 * kvm_restore_timer() - Restore timer state.
 * @vcpu:       Virtual CPU.
 *
 * Restore soft timer state from saved context.
 */
void kvm_restore_timer(struct kvm_vcpu *vcpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	ktime_t saved_ktime, now;
	u64 stable_timer, new_timertick = 0;
	u64 delta = 0;
	int expired = 0;
	unsigned long timer_cfg;

	/*
	 * Set guest stable timer cfg csr
	 */
	timer_cfg = kvm_read_sw_gcsr(csr, KVM_CSR_TCFG);
	kvm_restore_hw_gcsr(csr, KVM_CSR_ESTAT);
	if (!(timer_cfg & KVM_TCFG_EN)) {
		kvm_restore_hw_gcsr(csr, KVM_CSR_TCFG);
		kvm_restore_hw_gcsr(csr, KVM_CSR_TVAL);
		return;
	}

	now = ktime_get();
	saved_ktime = vcpu->arch.stable_ktime_saved;
	stable_timer = kvm_read_sw_gcsr(csr, KVM_CSR_TVAL);

	/*hrtimer not expire */
	delta = ktime_to_tick(vcpu, ktime_sub(now, saved_ktime));
	if (delta >= stable_timer)
		expired = 1;

	if (expired) {
		if (timer_cfg & KVM_TCFG_PERIOD) {
			new_timertick = (delta - stable_timer) % (timer_cfg & KVM_TCFG_VAL);
		} else {
			new_timertick = 1;
		}
	} else {
		new_timertick = stable_timer - delta;
	}

	new_timertick &= KVM_TCFG_VAL;
	kvm_write_gcsr_timercfg(timer_cfg);
	kvm_write_gcsr_timertick(new_timertick);
	if (expired)
		_kvm_queue_irq(vcpu, LARCH_INT_TIMER);
}

/*
 * kvm_acquire_timer() - Switch to hard timer state.
 * @vcpu:       Virtual CPU.
 *
 * Restore hard timer state on top of existing soft timer state if possible.
 *
 * Since hard timer won't remain active over preemption, preemption should be
 * disabled by the caller.
 */
void kvm_acquire_timer(struct kvm_vcpu *vcpu)
{
	unsigned long flags, guestcfg;

	guestcfg = kvm_read_csr_gcfg();
	if (!(guestcfg & KVM_GCFG_TIT))
		return;

	/* enable guest access to hard timer */
	kvm_write_csr_gcfg(guestcfg & ~KVM_GCFG_TIT);

	/*
	 * Freeze the soft-timer and sync the guest stable timer with it. We do
	 * this with interrupts disabled to avoid latency.
	 */
	local_irq_save(flags);
	hrtimer_cancel(&vcpu->arch.swtimer);
	local_irq_restore(flags);
}


/*
 * _kvm_save_timer() - Switch to software emulation of guest timer.
 * @vcpu:       Virtual CPU.
 *
 * Save guest timer state and switch to software emulation of guest
 * timer. The hard timer must already be in use, so preemption should be
 * disabled.
 */
static ktime_t _kvm_save_timer(struct kvm_vcpu *vcpu, u64 *stable_timer)
{
	u64 end_stable_timer;
	ktime_t before_time;

	before_time = ktime_get();

	/*
	 * Record a final stable timer which we will transfer to the soft-timer.
	 */
	end_stable_timer = kvm_read_gcsr_timertick();
	*stable_timer = end_stable_timer;

	kvm_resume_hrtimer(vcpu, before_time, end_stable_timer);
	return before_time;
}

/*
 * kvm_save_timer() - Save guest timer state.
 * @vcpu:       Virtual CPU.
 *
 * Save guest timer state and switch to soft guest timer if hard timer was in
 * use.
 */
void kvm_save_timer(struct kvm_vcpu *vcpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	unsigned long guestcfg;
	u64 stable_timer = 0;
	ktime_t save_ktime;

	preempt_disable();
	guestcfg = kvm_read_csr_gcfg();
	if (!(guestcfg & KVM_GCFG_TIT)) {
		/* disable guest use of hard timer */
		kvm_write_csr_gcfg(guestcfg | KVM_GCFG_TIT);

		/* save hard timer state */
		kvm_save_hw_gcsr(csr, KVM_CSR_TCFG);
		if (kvm_read_sw_gcsr(csr, KVM_CSR_TCFG) & KVM_TCFG_EN) {
			save_ktime = _kvm_save_timer(vcpu, &stable_timer);
			kvm_write_sw_gcsr(csr, KVM_CSR_TVAL, stable_timer);
			vcpu->arch.stable_ktime_saved = save_ktime;
			if (stable_timer == IOCSR_TIMER_MASK)
				_kvm_queue_irq(vcpu, LARCH_INT_TIMER);
		} else {
			kvm_save_hw_gcsr(csr, KVM_CSR_TVAL);
		}
	}

	/* save timer-related state to VCPU context */
	kvm_save_hw_gcsr(csr, KVM_CSR_ESTAT);
	preempt_enable();
}

void kvm_reset_timer(struct kvm_vcpu *vcpu)
{
	kvm_write_gcsr_timercfg(0);
	kvm_write_sw_gcsr(vcpu->arch.csr, KVM_CSR_TCFG, 0);
	hrtimer_cancel(&vcpu->arch.swtimer);
}
