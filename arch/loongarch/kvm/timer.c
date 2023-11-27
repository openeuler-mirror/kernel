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

/*
 * ktime_to_tick() - Scale ktime_t to timer tick value.
 */
static inline u64 ktime_to_tick(struct kvm_vcpu *vcpu, ktime_t now)
{
	u64 delta;

	delta = ktime_to_ns(now);
	return div_u64(delta * vcpu->arch.timer_mhz, MNSEC_PER_SEC);
}

static inline u64 tick_to_ns(struct kvm_vcpu *vcpu, u64 tick)
{
	return div_u64(tick * MNSEC_PER_SEC, vcpu->arch.timer_mhz);
}

/*
 * Push timer forward on timeout.
 * Handle an hrtimer event by push the hrtimer forward a period.
 */
static enum hrtimer_restart kvm_count_timeout(struct kvm_vcpu *vcpu)
{
	unsigned long cfg, period;

	/* Add periodic tick to current expire time */
	cfg = kvm_read_sw_gcsr(vcpu->arch.csr, LOONGARCH_CSR_TCFG);
	if (cfg & CSR_TCFG_PERIOD) {
		period = tick_to_ns(vcpu, cfg & CSR_TCFG_VAL);
		hrtimer_add_expires_ns(&vcpu->arch.swtimer, period);
		return HRTIMER_RESTART;
	} else
		return HRTIMER_NORESTART;
}

/* low level hrtimer wake routine */
enum hrtimer_restart kvm_swtimer_wakeup(struct hrtimer *timer)
{
	struct kvm_vcpu *vcpu;

	vcpu = container_of(timer, struct kvm_vcpu, arch.swtimer);
	_kvm_queue_irq(vcpu, LARCH_INT_TIMER);
	rcuwait_wake_up(&vcpu->wait);
	return kvm_count_timeout(vcpu);
}

/*
 * Initialise the timer to the specified frequency, zero it
 */
void kvm_init_timer(struct kvm_vcpu *vcpu, unsigned long timer_hz)
{
	vcpu->arch.timer_mhz = timer_hz >> 20;

	/* Starting at 0 */
	kvm_write_sw_gcsr(vcpu->arch.csr, LOONGARCH_CSR_TVAL, 0);
}

/*
 * Restore soft timer state from saved context.
 */
void kvm_restore_timer(struct kvm_vcpu *vcpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	ktime_t expire, now;
	unsigned long cfg, delta, period;
	unsigned long ticks, estat;

	/*
	 * Set guest stable timer cfg csr
	 */
	cfg = kvm_read_sw_gcsr(csr, LOONGARCH_CSR_TCFG);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_ESTAT);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TCFG);
	if (!(cfg & CSR_TCFG_EN)) {
		/* guest timer is disabled, just restore timer registers */
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TVAL);
		return;
	}

	/*
	 * Freeze the soft-timer and sync the guest stable timer with it. We do
	 * this with interrupts disabled to avoid latency.
	 */
	hrtimer_cancel(&vcpu->arch.swtimer);

	/*
	 * From LoongArch Reference Manual Volume 1 Chapter 7.6.2
	 * If oneshot timer is fired, CSR TVAL will be -1, there are two
	 * conditions:
	 *  a) timer is fired during exiting to host
	 *  b) timer is fired and vm is handling timer irq, host should not
	 *     inject timer irq to avoid spurious timer interrupt
	 */
	ticks = kvm_read_sw_gcsr(csr, LOONGARCH_CSR_TVAL);
	estat = kvm_read_sw_gcsr(csr, LOONGARCH_CSR_ESTAT);
	if (!(cfg & CSR_TCFG_PERIOD) && (ticks > cfg)) {
		/*
		 * Writing 0 to LOONGARCH_CSR_TVAL will inject timer irq
		 * and set CSR TVAL with -1
		 *
		 * Writing CSR_TINTCLR_TI to LOONGARCH_CSR_TINTCLR will clear
		 * timer interrupt, and set CSR TVAL keeps unchanged with -1,
		 * it avoids spurious timer interrupt
		 */
		kvm_write_gcsr_timertick(0);
		if ((estat & CPU_TIMER) == 0)
			kvm_gcsr_write(CSR_TINTCLR_TI, LOONGARCH_CSR_TINTCLR);
		return;
	}

	/*
	 * set remainder tick value if not expired
	 */
	now = ktime_get();
	expire = vcpu->arch.expire;
	delta = 0;
	if (ktime_before(now, expire))
		delta = ktime_to_tick(vcpu, ktime_sub(expire, now));
	else if (cfg & CSR_TCFG_PERIOD) {
		period = cfg & CSR_TCFG_VAL;
		delta = ktime_to_tick(vcpu, ktime_sub(now, expire));
		delta = period - (delta % period);

		/*
		 * inject timer here though sw timer should inject timer
		 * interrupt async already
		 */
		_kvm_queue_irq(vcpu, LARCH_INT_TIMER);
	}

	kvm_write_gcsr_timertick(delta);
}

/*
 * Save guest timer state and switch to software emulation of guest
 * timer. The hard timer must already be in use, so preemption should be
 * disabled.
 */
static void _kvm_save_timer(struct kvm_vcpu *vcpu)
{
	unsigned long ticks, delta, cfg;
	ktime_t expire;
	struct loongarch_csrs *csr = vcpu->arch.csr;

	ticks = kvm_read_sw_gcsr(csr, LOONGARCH_CSR_TVAL);
	cfg = kvm_read_sw_gcsr(csr, LOONGARCH_CSR_TCFG);

	/*
	 * From LoongArch Reference Manual Volume 1 Chapter 7.6.2
	 * If period timer is fired, CSR TVAL will be reloaded from CSR TCFG
	 * If oneshot timer is fired, CSR TVAL will be -1
	 * Here judge one shot timer fired by checking whether TVAL is larger
	 * than TCFG
	 */
	if (ticks < cfg) {
		/*
		 * Update hrtimer to use new timeout
		 * HRTIMER_MODE_PINNED is suggested since vcpu may run in
		 * the same physical cpu in next time
		 */
		delta = tick_to_ns(vcpu, ticks);
		expire = ktime_add_ns(ktime_get(), delta);
		vcpu->arch.expire = expire;
		hrtimer_start(&vcpu->arch.swtimer, expire, HRTIMER_MODE_ABS_PINNED);
	} else if (vcpu->arch.blocking) {
		/*
		 * Inject timer interrupt so that hall polling can dectect and exit
		 * kvm_queue_irq is not enough, hrtimer had better be used since vcpu
		 * is halt-polling and scheduled out already
		 */
		expire = ktime_add_ns(ktime_get(), 10);  // 10ns is enough here
		vcpu->arch.expire = expire;
		hrtimer_start(&vcpu->arch.swtimer, expire, HRTIMER_MODE_ABS_PINNED);
	}
}

/*
 * Save guest timer state and switch to soft guest timer if hard timer was in
 * use.
 */
void kvm_save_timer(struct kvm_vcpu *vcpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	preempt_disable();

	/* save hard timer state */
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TCFG);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TVAL);
	if (kvm_read_sw_gcsr(csr, LOONGARCH_CSR_TCFG) & CSR_TCFG_EN)
		_kvm_save_timer(vcpu);

	/* save timer-related state to vCPU context */
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_ESTAT);
	preempt_enable();
}

void kvm_reset_timer(struct kvm_vcpu *vcpu)
{
	kvm_write_gcsr_timercfg(0);
	kvm_write_sw_gcsr(vcpu->arch.csr, LOONGARCH_CSR_TCFG, 0);
	hrtimer_cancel(&vcpu->arch.swtimer);
}
