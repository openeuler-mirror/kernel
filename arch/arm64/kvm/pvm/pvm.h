/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 - Huawei LLC
 * Author: Kunkun Jiang <Jiangkunkun@huawei.com>
 */
#ifndef __ARM64_KVM_PVM_H
#define __ARM64_KVM_PVM_H

#include <linux/kvm_host.h>

#include <kvm/arm_rv_timer.h>

struct kvm_pvm_mmu;

struct kvm_pvm {
	struct kvm kvm;
	struct rv_timer_vm_data timer_data;
	struct kvm_pvm_mmu **suser_mmus;
	size_t suser_mmus_size;
	size_t suser_mmus_next;
	unsigned int mmus_per_vcpu;
	/*
	 * Kernel contexts form a VM-wide pool. vCPUs with matching translation
	 * regimes share a context; different regimes use independent roots.
	 * Each vCPU pins the context matching its current guest controls.
	 */
	struct kvm_pvm_mmu **skern_mmus;
	size_t skern_mmus_size;
	size_t skern_mmus_next;
	unsigned long invalidate_seq;
	unsigned int invalidating;
	phys_addr_t kern_pgd_phys;
	struct page *kern_pgd_page;
};

struct kvm_pvm_vcpu {
	struct kvm_vcpu vcpu;
	struct kvm_pvm_mmu *suser_mmu;
	struct rv_timer_cpu timer_cpu;
	struct kvm_pvm_mmu *skern_mmu;
	/* Opcode handed from hyp to host for the current UNKNOWN exit. */
	u32 trapped_insn;
	bool trapped_insn_valid;
};

static inline struct kvm_pvm *kvm_to_pvm(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_pvm, kvm);
}

static inline struct kvm_pvm_vcpu *vcpu_to_pvm(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct kvm_pvm_vcpu, vcpu);
}

#define vcpu_rv_timer(v)	(&vcpu_to_pvm(v)->timer_cpu)
#define vcpu_get_rv_timer(v, t)	(&vcpu_rv_timer(v)->timers[(t)])
#define vcpu_rv_vtimer(v)	(&vcpu_rv_timer(v)->timers[RVTIMER_VTIMER])

#define rv_timer_vm_data(ctx)		(&kvm_to_pvm((ctx)->vcpu->kvm)->timer_data)

#define rv_timer_ctx_index(ctx)	((ctx) - vcpu_rv_timer((ctx)->vcpu)->timers)
#define rv_timer_irq(ctx)	(rv_timer_vm_data(ctx)->ppi[rv_timer_ctx_index(ctx)])

int kvm_pvm_emulate_sysreg(struct kvm_vcpu *vcpu, u32 insn);
int kvm_pvm_emulate_dc_by_va(struct kvm_vcpu *vcpu, u32 insn);
int kvm_pvm_emulate_at(struct kvm_vcpu *vcpu, u32 insn);
int kvm_pvm_recover_mmio(struct kvm_vcpu *vcpu);
int kvm_pvm_read_guest_insn(struct kvm_vcpu *vcpu, u32 *insn);

void kvm_pvm_emulate_eret(struct kvm_vcpu *vcpu);
int kvm_pvm_inject_sync(struct kvm_vcpu *vcpu, u64 esr_el1);

#endif /* __ARM64_KVM_PVM_H */
