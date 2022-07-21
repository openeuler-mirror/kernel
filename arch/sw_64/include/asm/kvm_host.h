/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_KVM_HOST_H
#define _ASM_SW64_KVM_HOST_H

#include <linux/types.h>
#include <linux/hardirq.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/preempt.h>
#include <linux/msi.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/ratelimit.h>
#include <linux/err.h>
#include <linux/bitmap.h>
#include <linux/compiler.h>
#include <asm/signal.h>
#include <asm/vcpu.h>

#include <generated/autoconf.h>
#include <asm/ptrace.h>

#include <asm/kvm_mmio.h>

#define KVM_MAX_VCPUS 64
#define KVM_USER_MEM_SLOTS 64

#define KVM_HALT_POLL_NS_DEFAULT 0
#define KVM_IRQCHIP_NUM_PINS     256
/* KVM Hugepage definitions for sw64 */
#define KVM_NR_PAGE_SIZES   3
#define KVM_HPAGE_GFN_SHIFT(x)  (((x) - 1) * 9)
#define KVM_HPAGE_SHIFT(x)  (PAGE_SHIFT + KVM_HPAGE_GFN_SHIFT(x))
#define KVM_HPAGE_SIZE(x)   (1UL << KVM_HPAGE_SHIFT(x))
#define KVM_HPAGE_MASK(x)   (~(KVM_HPAGE_SIZE(x) - 1))
#define KVM_PAGES_PER_HPAGE(x)  (KVM_HPAGE_SIZE(x) / PAGE_SIZE)

struct kvm_arch_memory_slot {
	unsigned long host_phys_addr;
	bool valid;
};

struct kvm_arch {
	unsigned long host_phys_addr;
	unsigned long size;

	/* segment table */
	unsigned long *seg_pgd;
};


struct kvm_vcpu_arch {
	struct kvm_regs regs __attribute__((__aligned__(32)));
	struct vcpucb vcb;
	struct task_struct *tsk;
	unsigned int pcpu_id; /* current running pcpu id */

	/* Virtual clock device */
	struct hrtimer hrt;
	unsigned long timer_next_event;
	int first_run;
	int halted;
	int stopped;
	int restart;

	/* Pending virtual interrupts */
	DECLARE_BITMAP(irqs_pending, SWVM_IRQS);
	unsigned long vpnc[NR_CPUS];

	/* WAIT executed */
	int wait;

	/* vcpu power-off state */
	bool power_off;

	/* Don't run the guest (internal implementation need) */
	bool pause;

	struct kvm_decode mmio_decode;
};

struct vmem_info {
	unsigned long start;
	size_t size;
	atomic_t refcnt;
};

struct kvm_vm_stat {
	u32 remote_tlb_flush;
};

struct kvm_vcpu_stat {
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_wakeup;
	u64 halt_poll_invalid;
};

#ifdef CONFIG_KVM_MEMHOTPLUG
void vcpu_mem_hotplug(struct kvm_vcpu *vcpu, unsigned long start_addr);
#endif
int handle_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
		int exception_index, struct hcall_args *hargs);
void vcpu_send_ipi(struct kvm_vcpu *vcpu, int target_vcpuid);
static inline void kvm_arch_hardware_disable(void) {}
static inline void kvm_arch_sync_events(struct kvm *kvm) {}
static inline void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu) {}
static inline void kvm_arch_free_memslot(struct kvm *kvm,
		struct kvm_memory_slot *slot) {}
static inline void kvm_arch_memslots_updated(struct kvm *kvm, u64 gen) {}
static inline void kvm_arch_flush_shadow_all(struct kvm *kvm) {}
static inline void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
		struct kvm_memory_slot *slot) {}
static inline void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_vcpu_block_finish(struct kvm_vcpu *vcpu) {}

#endif  /* _ASM_SW64_KVM_HOST_H */
