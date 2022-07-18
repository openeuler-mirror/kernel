// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 - os kernal
 * Author: fire3 <fire3@example.com> yangzh <yangzh@gmail.com>
 * linhn <linhn@example.com>
 */
#include <asm/hmcall.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_timer.h>
#include <linux/kvm.h>

int handle_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
		int exception_index, struct hcall_args *hargs)
{
	switch (exception_index) {
	case SW64_KVM_EXIT_IO:
		return io_mem_abort(vcpu, run, hargs);
	case SW64_KVM_EXIT_HALT:
		vcpu->arch.halted = 1;
		kvm_vcpu_block(vcpu);
		return 1;
	case SW64_KVM_EXIT_SHUTDOWN:
		vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_SHUTDOWN;
		return 0;
	case SW64_KVM_EXIT_RESTART:
		vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_RESET;
		return 0;
	case SW64_KVM_EXIT_TIMER:
		set_timer(vcpu, hargs->arg0);
		return 1;
	case SW64_KVM_EXIT_IPI:
		vcpu_send_ipi(vcpu, hargs->arg0);
		return 1;
#ifdef CONFIG_KVM_MEMHOTPLUG
	case SW64_KVM_EXIT_MEMHOTPLUG:
		vcpu_mem_hotplug(vcpu, hargs->arg0);
		return 1;
#endif
	case SW64_KVM_EXIT_FATAL_ERROR:
		printk("Guest fatal error: Reason=[%lx], EXC_PC=[%lx], DVA=[%lx]", hargs->arg0, hargs->arg1, hargs->arg2);
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = hargs->arg0;
		return 0;
	}

	return 1;
}
