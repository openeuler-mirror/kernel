// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 - os kernal
 * Author: fire3 <fire3@example.com> yangzh <yangzh@gmail.com>
 * linhn <linhn@example.com>
 */

#include <linux/errno.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/mman.h>
#include <linux/sched/signal.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>

#include <asm/kvm_timer.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/barrier.h>
#include "trace.h"

#include "../kernel/pci_impl.h"

#define GUEST_RESET_PC		0xfff0000000011002
static unsigned long shtclock_offset;

static unsigned long core4_get_new_vpn_context(struct kvm_vcpu *vcpu, long cpu)
{
	unsigned long vpn = last_vpn(cpu);
	unsigned long next = vpn + 1;

	if ((vpn & VPN_MASK) >= VPN_MASK) {
		tbivpn(-1, 0, 0);
		next = (vpn & ~VPN_MASK) + VPN_FIRST_VERSION + 1; /* bypass 0 */
	}
	last_vpn(cpu) = next;
	return next;
}

static void core4_update_vpn(struct kvm_vcpu *vcpu, unsigned long vpn)
{
	vcpu->arch.vcb.vpcr = vpn << 44;
	vcpu->arch.vcb.dtb_vpcr = vpn;
}

int kvm_core4_init_vm(struct kvm *kvm)
{
	return kvm_alloc_addtional_stage_pgd(kvm);
}

void kvm_core4_destroy_vm(struct kvm *kvm)
{
	int i;

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (kvm->vcpus[i]) {
			kvm_arch_vcpu_free(kvm->vcpus[i]);
			kvm->vcpus[i] = NULL;
		}
	}
	atomic_set(&kvm->online_vcpus, 0);
}

int kvm_core4_vcpu_reset(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.has_run_once)
		apt_unmap_vm(vcpu->kvm);

	hrtimer_cancel(&vcpu->arch.hrt);
	vcpu->arch.vcb.soft_cid = vcpu->vcpu_id;
	vcpu->arch.vcb.vcpu_irq_disabled = 1;
	vcpu->arch.pcpu_id = -1; /* force flush tlb for the first time */
	vcpu->arch.power_off = 0;
	memset(&vcpu->arch.irqs_pending, 0, sizeof(vcpu->arch.irqs_pending));

	return 0;
}

/*
 * Return > 0 to return to guest, < 0 on error, 0 (and set exit_reason) on
 * proper exit to userspace.
 */
int kvm_core4_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret;
	struct vcpucb *vcb = &(vcpu->arch.vcb);
	struct hcall_args hargs;
	int irq;
	bool more;
	sigset_t sigsaved;

#ifdef CONFIG_PERF_EVENTS
	vcpu_load(vcpu);
#endif
	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	if (run->exit_reason == KVM_EXIT_MMIO)
		kvm_handle_mmio_return(vcpu, run);

	run->exit_reason = KVM_EXIT_UNKNOWN;
	ret = 1;
	while (ret > 0) {
		/*
		 * Check conditions before entering the guest
		 */
		cond_resched();

		preempt_disable();
		local_irq_disable();

		if (signal_pending(current)) {
			ret = -EINTR;
			run->exit_reason = KVM_EXIT_INTR;
			vcpu->stat.signal_exits++;
		}

		if (ret <= 0) {
			local_irq_enable();
			preempt_enable();
			continue;
		}

		memset(&hargs, 0, sizeof(hargs));

		clear_vcpu_irq(vcpu);

		if (vcpu->arch.restart == 1) {
			/* handle reset vCPU */
			vcpu->arch.regs.pc = GUEST_RESET_PC;
			vcpu->arch.restart = 0;
		}

		irq = interrupt_pending(vcpu, &more);
		if (irq < SWVM_IRQS)
			try_deliver_interrupt(vcpu, irq, more);

		vcpu->arch.halted = 0;

		sw64_kvm_switch_vpn(vcpu);
		check_vcpu_requests(vcpu);
		guest_enter_irqoff();

		/* update aptp before the guest runs */
		imemb();
		write_csr_imb((unsigned long)vcpu->kvm->arch.pgd, CSR_APTP);

		/* Enter the guest */
		trace_kvm_sw64_entry(vcpu->vcpu_id, vcpu->arch.regs.pc);
		vcpu->mode = IN_GUEST_MODE;

		ret = __sw64_vcpu_run(__pa(vcb), &(vcpu->arch.regs), &hargs);

		/* Back from guest */
		vcpu->mode = OUTSIDE_GUEST_MODE;

		vcpu->stat.exits++;
		local_irq_enable();
		guest_exit_irqoff();

		trace_kvm_sw64_exit(ret, vcpu->arch.regs.pc);

		preempt_enable();

		/* ret = 0 indicate interrupt in guest mode, ret > 0 indicate hcall */
		ret = handle_exit(vcpu, run, ret, &hargs);
		update_vcpu_stat_time(&vcpu->stat);
	}

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

#ifdef CONFIG_PERF_EVENTS
	vcpu_put(vcpu);
#endif
	return ret;
}

static void kvm_core4_vcpu_free(struct kvm_vcpu *vcpu)
{
	kvm_mmu_free_memory_caches(vcpu);
}

static long kvm_core4_get_vcb(struct file *filp, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;

	if (vcpu->arch.migration_mark)
		vcpu->arch.shtclock = read_csr(CSR_SHTCLOCK)
			+ vcpu->arch.vcb.shtclock_offset;
	if (copy_to_user((void __user *)arg, &(vcpu->arch.vcb), sizeof(struct vcpucb)))
		return -EINVAL;

	return 0;
}

static long kvm_core4_set_vcb(struct file *filp, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	struct vcpucb *kvm_vcb;

	kvm_vcb = memdup_user((void __user *)arg, sizeof(*kvm_vcb));
	memcpy(&(vcpu->arch.vcb), kvm_vcb, sizeof(struct vcpucb));

	if (vcpu->arch.migration_mark) {
		/* synchronize the longtime of source and destination */
		if (vcpu->arch.vcb.soft_cid == 0)
			shtclock_offset = vcpu->arch.shtclock - read_csr(CSR_SHTCLOCK);
		vcpu->arch.vcb.shtclock_offset = shtclock_offset;
		set_timer(vcpu, 200000000);
		vcpu->arch.migration_mark = 0;
	}
	return 0;
}

static struct kvm_sw64_ops core4_sw64_ops __ro_after_init = {
	.get_new_vpn_context = core4_get_new_vpn_context,
	.update_vpn = core4_update_vpn,
	.init_vm = kvm_core4_init_vm,
	.destroy_vm = kvm_core4_destroy_vm,
	.commit_memory_region = kvm_core4_commit_memory_region,
	.flush_shadow_memslot = kvm_core4_flush_shadow_memslot,
	.flush_shadow_all = kvm_core4_flush_shadow_all,
	.vcpu_reset = kvm_core4_vcpu_reset,
	.vcpu_run = kvm_core4_vcpu_ioctl_run,
	.vcpu_free = kvm_core4_vcpu_free,
	.get_vcb = kvm_core4_get_vcb,
	.set_vcb = kvm_core4_set_vcb,
};

static int __init kvm_core4_init(void)
{
	int i, ret;

	for (i = 0; i < NR_CPUS; i++)
		last_vpn(i) = VPN_FIRST_VERSION;

	ret = kvm_init(&core4_sw64_ops, sizeof(struct kvm_vcpu), 0, THIS_MODULE);

	if (ret)
		return ret;

	return 0;
}

static void __exit kvm_core4_exit(void)
{
	kvm_exit();
}

module_init(kvm_core4_init);
module_exit(kvm_core4_exit);
