// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/kvm_host.h>
#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

#include <asm/kvm_tmi.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_coproc.h>

typedef int (*exit_handler_fn)(struct kvm_vcpu *vcpu);

static void update_arch_timer_irq_lines(struct kvm_vcpu *vcpu, bool unmask_ctl)
{
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	run = tec->tec_run;
	__vcpu_sys_reg(vcpu, CNTV_CTL_EL0) = run->tec_exit.cntv_ctl;
	__vcpu_sys_reg(vcpu, CNTV_CVAL_EL0) = run->tec_exit.cntv_cval;
	__vcpu_sys_reg(vcpu, CNTP_CTL_EL0) = run->tec_exit.cntp_ctl;
	__vcpu_sys_reg(vcpu, CNTP_CVAL_EL0) = run->tec_exit.cntp_cval;

	/* Because the timer mask is tainted by TMM, we don't know the
	 * true intent of the guest. Here, we assume mask is always
	 * cleared during WFI.
	 */
	if (unmask_ctl) {
		__vcpu_sys_reg(vcpu, CNTV_CTL_EL0) &= ~ARCH_TIMER_CTRL_IT_MASK;
		__vcpu_sys_reg(vcpu, CNTP_CTL_EL0) &= ~ARCH_TIMER_CTRL_IT_MASK;
	}

	kvm_cvm_timers_update(vcpu);
}

static int tec_exit_reason_notimpl(struct kvm_vcpu *vcpu)
{
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	run = tec->tec_run;
	pr_err("[vcpu %d] Unhandled exit reason from cvm (ESR: %#llx)\n",
		vcpu->vcpu_id, run->tec_exit.esr);
	return -ENXIO;
}

/* The process is the same as kvm_handle_wfx,
 * except the tracing and updating operation for pc,
 * we copy kvm_handle_wfx process here
 * to avoid changing kvm_handle_wfx function.
 */
static int tec_exit_wfx(struct kvm_vcpu *vcpu)
{
	u64 esr = kvm_vcpu_get_esr(vcpu);

	if (esr & ESR_ELx_WFx_ISS_WFE)
		vcpu->stat.wfe_exit_stat++;
	else
		vcpu->stat.wfi_exit_stat++;

	if (esr & ESR_ELx_WFx_ISS_WFxT) {
		if (esr & ESR_ELx_WFx_ISS_RV) {
			u64 val, now;

			now = kvm_arm_timer_get_reg(vcpu, KVM_REG_ARM_TIMER_CNT);
			val = vcpu_get_reg(vcpu, kvm_vcpu_sys_get_rt(vcpu));

			if (now >= val)
				goto out;
		} else {
			/* Treat WFxT as WFx if RN is invalid */
			esr &= ~ESR_ELx_WFx_ISS_WFxT;
		}
	}

	if (esr & ESR_ELx_WFx_ISS_WFE) {
		kvm_vcpu_on_spin(vcpu, vcpu_mode_priv(vcpu));
	} else {
		vcpu->arch.pvsched.pv_unhalted = false;
		if (esr & ESR_ELx_WFx_ISS_WFxT)
			vcpu->arch.flags |= KVM_ARM64_WFIT;
		kvm_vcpu_block(vcpu);
		vcpu->arch.flags &= ~KVM_ARM64_WFIT;
		kvm_clear_request(KVM_REQ_UNHALT, vcpu);
	}

out:
	return 1;
}

static int tec_exit_sys_reg(struct kvm_vcpu *vcpu)
{
	int ret;
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;
	unsigned long esr = kvm_vcpu_get_esr(vcpu);
	int rt = kvm_vcpu_sys_get_rt(vcpu);
	bool is_write = !(esr & 1);

	run = tec->tec_run;
	if (is_write)
		vcpu_set_reg(vcpu, rt, run->tec_exit.gprs[0]);

	ret = kvm_handle_sys_reg(vcpu);

	if (ret >= 0 && !is_write)
		run->tec_entry.gprs[0] = vcpu_get_reg(vcpu, rt);

	return ret;
}

static int tec_exit_sync_dabt(struct kvm_vcpu *vcpu)
{
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	run = tec->tec_run;
	if (kvm_vcpu_dabt_iswrite(vcpu) && kvm_vcpu_dabt_isvalid(vcpu)) {
		vcpu_set_reg(vcpu, kvm_vcpu_dabt_get_rd(vcpu),
			run->tec_exit.gprs[0]);
	}
	return kvm_handle_guest_abort(vcpu);
}

static int tec_exit_sync_iabt(struct kvm_vcpu *vcpu)
{
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	run = tec->tec_run;
	pr_err("[vcpu %d] Unhandled instruction abort (ESR: %#llx).\n",
		vcpu->vcpu_id, run->tec_exit.esr);

	return -ENXIO;
}

static exit_handler_fn tec_exit_handlers[] = {
	[0 ... ESR_ELx_EC_MAX] = tec_exit_reason_notimpl,
	[ESR_ELx_EC_WFx]	   = tec_exit_wfx,
	[ESR_ELx_EC_SYS64]	   = tec_exit_sys_reg,
	[ESR_ELx_EC_DABT_LOW]  = tec_exit_sync_dabt,
	[ESR_ELx_EC_IABT_LOW]  = tec_exit_sync_iabt
};

static int tec_exit_psci(struct kvm_vcpu *vcpu)
{
	int i;
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	run = tec->tec_run;
	for (i = 0; i < TEC_EXIT_NR_GPRS; ++i)
		vcpu_set_reg(vcpu, i, run->tec_exit.gprs[i]);

	return kvm_psci_call(vcpu);
}

static int tec_exit_host_call(struct kvm_vcpu *vcpu)
{
	int ret, i;
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	run = tec->tec_run;
	vcpu->stat.hvc_exit_stat++;

	for (i = 0; i < TEC_EXIT_NR_GPRS; ++i)
		vcpu_set_reg(vcpu, i, run->tec_exit.gprs[i]);

	ret = kvm_hvc_call_handler(vcpu);

	if (ret < 0) {
		vcpu_set_reg(vcpu, 0, ~0UL);
		ret = 1;
	}
	for (i = 0; i < TEC_EXIT_NR_GPRS; ++i)
		run->tec_entry.gprs[i] = vcpu_get_reg(vcpu, i);

	return ret;
}

/*
 * Return > 0 to return to guest, < 0 on error, 0(and set exit_reason) on
 * proper exit to userspace
 */

int handle_cvm_exit(struct kvm_vcpu *vcpu, int tec_run_ret)
{
	unsigned long status;
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;
	u8 esr_ec;
	bool is_wfx;

	run = tec->tec_run;
	esr_ec = ESR_ELx_EC(run->tec_exit.esr);
	status = TMI_RETURN_STATUS(tec_run_ret);

	if (status == TMI_ERROR_CVM_POWEROFF) {
		vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_SHUTDOWN;
		return 0;
	}

	if (status == TMI_ERROR_CVM_STATE) {
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		return 0;
	}

	if (tec_run_ret)
		return -ENXIO;

	vcpu->arch.fault.esr_el2 = run->tec_exit.esr;
	vcpu->arch.fault.far_el2 = run->tec_exit.far;
	vcpu->arch.fault.hpfar_el2 = run->tec_exit.hpfar;

	is_wfx = (run->tec_exit.exit_reason == TMI_EXIT_SYNC) && (esr_ec == ESR_ELx_EC_WFx);
	update_arch_timer_irq_lines(vcpu, is_wfx);

	run->tec_entry.flags = 0;

	switch (run->tec_exit.exit_reason) {
	case TMI_EXIT_FIQ:
	case TMI_EXIT_IRQ:
		return 1;
	case TMI_EXIT_PSCI:
		return tec_exit_psci(vcpu);
	case TMI_EXIT_SYNC:
		return tec_exit_handlers[esr_ec](vcpu);
	case TMI_EXIT_HOST_CALL:
		return tec_exit_host_call(vcpu);
	}

	kvm_pr_unimpl("Unsupported exit reason : 0x%llx\n",
		run->tec_exit.exit_reason);
	return 0;
}
