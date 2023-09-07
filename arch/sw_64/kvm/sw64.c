// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/mman.h>
#include <linux/sched/signal.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/msi.h>
#include <asm/kvm_timer.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/barrier.h>
#include <asm/core.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

#include "../kernel/pci_impl.h"

bool set_msi_flag;

#define DFX_STAT(n, x, ...) \
	{ n, offsetof(struct kvm_vcpu_stat, x), DFX_STAT_U64, ## __VA_ARGS__ }

struct kvm_sw64_ops *kvm_sw64_ops __read_mostly;
EXPORT_SYMBOL_GPL(kvm_sw64_ops);

int vcpu_interrupt_line(struct kvm_vcpu *vcpu, int number, bool level)
{
	set_bit(number, (vcpu->arch.irqs_pending));
	kvm_vcpu_kick(vcpu);
	return 0;
}

int kvm_arch_check_processor_compat(void *opaque)
{
	return 0;
}

int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e, struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	unsigned int vcid;
	unsigned int vcpu_idx;
	struct kvm_vcpu *vcpu = NULL;
	int irq = e->msi.data & 0xff;

	vcid = (e->msi.address_lo & VT_MSIX_ADDR_DEST_ID_MASK) >> VT_MSIX_ADDR_DEST_ID_SHIFT;
	vcpu_idx = vcid & 0x1f;
	vcpu = kvm_get_vcpu(kvm, vcpu_idx);

	if (!vcpu)
		return -EINVAL;

	return vcpu_interrupt_line(vcpu, irq, true);
}

void sw64_kvm_switch_vpn(struct kvm_vcpu *vcpu)
{
	unsigned long vpn;
	unsigned long vpnc;
	long cpu = smp_processor_id();

	vpn = last_vpn(cpu);
	vpnc = vcpu->arch.vpnc[cpu];

	if ((vpnc ^ vpn) & ~VPN_MASK) {
		/* vpnc and cpu vpn not in the same version, get new vpnc and vpn */
		vpnc = kvm_sw64_ops->get_new_vpn_context(vcpu, cpu);
		vcpu->arch.vpnc[cpu] = vpnc;
	}

	vpn = vpnc & VPN_MASK;

	/* Always update vpn */
	/* Just setup vcb, hardware CSR will be changed later in HMcode */
	kvm_sw64_ops->update_vpn(vcpu, vpn);

	/*
	 * If vcpu migrate to a new physical cpu, the new physical cpu may keep
	 * old tlb entries for this vcpu's vpn, upn in the old tlb entries and
	 * current vcpu's upn may not in the same version.
	 * For now, we don't know the vcpu's upn version and the current version.
	 * If we keep track of the vcpu's upn version, the TLB-flush could be less.
	 * To be safe and correct, flush all tlb entries of current vpn for now.
	 */

	if (vcpu->arch.pcpu_id != cpu) {
		tbivpn(0, 0, vpn);
		vcpu->arch.pcpu_id = cpu;
		vcpu->cpu = cpu;
	}
}

void check_vcpu_requests(struct kvm_vcpu *vcpu)
{
	unsigned long vpn;
	long cpu = smp_processor_id();

	if (kvm_request_pending(vcpu)) {
		if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
			vpn = vcpu->arch.vpnc[cpu] & VPN_MASK;
			tbivpn(0, 0, vpn);
		}
	}
}

struct kvm_stats_debugfs_item debugfs_entries[] = {
	VCPU_STAT("exits", exits),
	VCPU_STAT("io_exits", io_exits),
	VCPU_STAT("mmio_exits", mmio_exits),
	VCPU_STAT("migration_set_dirty", migration_set_dirty),
	VCPU_STAT("shutdown_exits", shutdown_exits),
	VCPU_STAT("restart_exits", restart_exits),
	VCPU_STAT("ipi_exits", ipi_exits),
	VCPU_STAT("timer_exits", timer_exits),
	VCPU_STAT("debug_exits", debug_exits),
#ifdef CONFIG_KVM_MEMHOTPLUG
	VCPU_STAT("memhotplug_exits", memhotplug_exits),
#endif
	VCPU_STAT("fatal_error_exits", fatal_error_exits),
	VCPU_STAT("halt_exits", halt_exits),
	VCPU_STAT("halt_successful_poll", halt_successful_poll),
	VCPU_STAT("halt_attempted_poll", halt_attempted_poll),
	VCPU_STAT("halt_wakeup", halt_wakeup),
	VCPU_STAT("halt_poll_invalid", halt_poll_invalid),
	VCPU_STAT("signal_exits", signal_exits),
	{ "vcpu_stat", 0, KVM_STAT_DFX },
	{ NULL }
};

struct dfx_kvm_stats_debugfs_item dfx_debugfs_entries[] = {
	DFX_STAT("pid", pid),
	DFX_STAT("exits", exits),
	DFX_STAT("io_exits", io_exits),
	DFX_STAT("mmio_exits", mmio_exits),
	DFX_STAT("migration_set_dirty", migration_set_dirty),
	DFX_STAT("shutdown_exits", shutdown_exits),
	DFX_STAT("restart_exits", restart_exits),
	DFX_STAT("ipi_exits", ipi_exits),
	DFX_STAT("timer_exits", timer_exits),
	DFX_STAT("debug_exits", debug_exits),
	DFX_STAT("fatal_error_exits", fatal_error_exits),
	DFX_STAT("halt_exits", halt_exits),
	DFX_STAT("halt_successful_poll", halt_successful_poll),
	DFX_STAT("halt_attempted_poll", halt_attempted_poll),
	DFX_STAT("halt_wakeup", halt_wakeup),
	DFX_STAT("halt_poll_invalid", halt_poll_invalid),
	DFX_STAT("signal_exits", signal_exits),
	DFX_STAT("steal", steal),
	DFX_STAT("st_max", st_max),
	DFX_STAT("utime", utime),
	DFX_STAT("stime", stime),
	DFX_STAT("gtime", gtime),
	{ NULL }
};

int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	return ((!bitmap_empty(vcpu->arch.irqs_pending, SWVM_IRQS) || !vcpu->arch.halted)
			&& !vcpu->arch.power_off);
}

int kvm_arch_hardware_enable(void)
{
	return 0;
}

void kvm_arch_hardware_unsetup(void)
{
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return false;
}

bool kvm_arch_has_vcpu_debugfs(void)
{
	return false;
}

int kvm_arch_create_vcpu_debugfs(struct kvm_vcpu *vcpu)
{
	return 0;
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r = 0;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_SYNC_MMU:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	default:
		r = 0;
	}

	return r;
}

void kvm_arch_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
}

void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn_offset,
		unsigned long mask)
{
	if (kvm_sw64_ops->mmu_enable_log_dirty_pt_masked)
		kvm_sw64_ops->mmu_enable_log_dirty_pt_masked(kvm, slot, gfn_offset, mask);
}

int kvm_sw64_pending_timer(struct kvm_vcpu *vcpu)
{
	return test_bit(SW64_KVM_IRQ_TIMER, &vcpu->arch.irqs_pending);
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return kvm_sw64_pending_timer(vcpu);
}

int kvm_arch_hardware_setup(void *opaque)
{
	return 0;
}

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	if (type)
		return -EINVAL;

	if (kvm_sw64_ops->init_vm)
		return kvm_sw64_ops->init_vm(kvm);

	return 0;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	if (kvm_sw64_ops->destroy_vm)
		return kvm_sw64_ops->destroy_vm(kvm);
}

long kvm_arch_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
		unsigned long npages)
{
	return 0;
}

#ifdef CONFIG_KVM_MEMHOTPLUG
static void setup_segment_table(struct kvm *kvm,
	struct kvm_memory_slot *memslot, unsigned long addr, size_t size)
{
	unsigned long *seg_pgd = kvm->arch.seg_pgd;
	unsigned long num_of_entry;
	unsigned long base_hpa = addr;
	unsigned long i;

	num_of_entry = round_up(size, 1 << 30) >> 30;

	for (i = 0; i < num_of_entry; i++) {
		*seg_pgd = base_hpa + (i << 30);
		seg_pgd++;
	}

}
#endif

int kvm_arch_prepare_memory_region(struct kvm *kvm,
		struct kvm_memory_slot *memslot,
		const struct kvm_userspace_memory_region *mem,
		enum kvm_mr_change change)
{
	if (kvm_sw64_ops->prepare_memory_region)
		return kvm_sw64_ops->prepare_memory_region(kvm, memslot,
					mem, change);

	return 0;
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	hrtimer_cancel(&vcpu->arch.hrt);

	if (kvm_sw64_ops->vcpu_free)
		kvm_sw64_ops->vcpu_free(vcpu);

	kfree(vcpu);
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_free(vcpu);
}

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	/* Set up the timer for Guest */
	pr_info("vcpu: [%d], regs addr = %#lx, vcpucb = %#lx\n", vcpu->vcpu_id,
			(unsigned long)&vcpu->arch.regs, (unsigned long)&vcpu->arch.vcb);
	vcpu->arch.vtimer_freq = cpuid(GET_CPU_FREQ, 0) * 1000UL * 1000UL;
	hrtimer_init(&vcpu->arch.hrt, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	vcpu->arch.hrt.function = clockdev_fn;
	vcpu->arch.tsk = current;

	vcpu->arch.vcb.soft_cid = vcpu->vcpu_id;
	vcpu->arch.vcb.vcpu_irq_disabled = 1;
	vcpu->arch.pcpu_id = -1; /* force flush tlb for the first time */

	return 0;
}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	return 0;
}

int kvm_arch_vcpu_reset(struct kvm_vcpu *vcpu)
{
	if (kvm_sw64_ops->vcpu_reset)
		return kvm_sw64_ops->vcpu_reset(vcpu);

	return 0;
}

int kvm_set_routing_entry(struct kvm *kvm,
		struct kvm_kernel_irq_routing_entry *e,
		const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;

	switch (ue->type) {
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		e->msi.flags = ue->flags;
		e->msi.devid = ue->u.msi.devid;
		set_msi_flag = true;
		break;
	default:
		goto out;
	}
	r = 0;
out:
	return r;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
		struct kvm_translation *tr)
{
	return -EINVAL; /* not implemented yet */
}

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	return 0;
}

void kvm_arch_vcpu_stat_reset(struct kvm_vcpu_stat *vcpu_stat)
{
	vcpu_stat->st_max = 0;
}

static void update_steal_time(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_SCHED_INFO
	u64 delta;

	delta = current->sched_info.run_delay - vcpu->stat.steal;
	vcpu->stat.steal = current->sched_info.run_delay;
	vcpu->stat.st_max = max(vcpu->stat.st_max, delta);
#endif
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	vcpu->cpu = cpu;
	update_steal_time(vcpu);
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	/*
	 * The arch-generic KVM code expects the cpu field of a vcpu to be -1
	 * if the vcpu is no longer assigned to a cpu.  This is used for the
	 * optimized make_all_cpus_request path.
	 */
	vcpu->cpu = -1;
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
		struct kvm_mp_state *mp_state)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
		struct kvm_mp_state *mp_state)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	memcpy(&(vcpu->arch.regs), regs, sizeof(struct kvm_regs));
	return 0;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	memcpy(regs, &(vcpu->arch.regs), sizeof(struct kvm_regs));
	return 0;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
						struct kvm_guest_debug *dbg)
{
	return 0;
}

void update_vcpu_stat_time(struct kvm_vcpu_stat *vcpu_stat)
{
	vcpu_stat->utime = current->utime;
	vcpu_stat->stime = current->stime;
	vcpu_stat->gtime = current->gtime;
}

/*
 * Return > 0 to return to guest, < 0 on error, 0 (and set exit_reason) on
 * proper exit to userspace.
 */
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	return kvm_sw64_ops->vcpu_run(vcpu, run);
}

long kvm_arch_vcpu_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	int r;

	switch (ioctl) {
	case KVM_SW64_VCPU_INIT:
		r = kvm_arch_vcpu_reset(vcpu);
		break;
	case KVM_SW64_GET_VCB:
		r = kvm_sw64_ops->get_vcb(filp, arg);
		break;
	case KVM_SW64_SET_VCB:
		r = kvm_sw64_ops->set_vcb(filp, arg);
		break;
	default:
		r =  -EINVAL;
	}

	return r;
}

long kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm __maybe_unused = filp->private_data;
	long r;

	switch (ioctl) {
	case KVM_CREATE_IRQCHIP: {
		struct kvm_irq_routing_entry routing;

		r = -EINVAL;
		memset(&routing, 0, sizeof(routing));
		r = kvm_set_irq_routing(kvm, &routing, 0, 0);
		break;
	}
	default:
		r = -ENOIOCTLCMD;
	}
	return r;
}

int kvm_arch_init(void *opaque)
{
	int r;
	struct kvm_sw64_ops *ops = opaque;

	if (kvm_sw64_ops) {
		printk(KERN_ERR "kvm: already loaded the other module\n");
		r = -EEXIST;
		goto out;
	}

	kvm_sw64_ops = ops;
	kvm_sw64_perf_init();

	return 0;
out:
	return r;
}

void kvm_arch_exit(void)
{
	kvm_sw64_ops = NULL;
	kvm_sw64_perf_teardown();
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	return -ENOIOCTLCMD;
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOIOCTLCMD;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

void kvm_arch_flush_shadow_memslot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	if (kvm_sw64_ops->flush_shadow_memslot)
		kvm_sw64_ops->flush_shadow_memslot(kvm, slot);
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	if (kvm_sw64_ops->flush_shadow_all)
		kvm_sw64_ops->flush_shadow_all(kvm);
}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					struct kvm_memory_slot *memslot)
{
	/* Let implementation handle TLB/GVA invalidation */
	kvm_arch_flush_shadow_memslot(kvm, memslot);
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
		const struct kvm_userspace_memory_region *mem,
		struct kvm_memory_slot *old,
		const struct kvm_memory_slot *new,
		enum kvm_mr_change change)
{
	kvm_sw64_ops->commit_memory_region(kvm, mem, old, new, change);
}

int kvm_dev_ioctl_check_extension(long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_IOEVENTFD:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	default:
		r = 0;
	}

	return r;
}

#ifdef CONFIG_KVM_MEMHOTPLUG
void vcpu_mem_hotplug(struct kvm_vcpu *vcpu, unsigned long start_addr)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *slot;
	unsigned long start_pfn = start_addr >> PAGE_SHIFT;

	kvm_for_each_memslot(slot, kvm_memslots(kvm)) {
		if (start_pfn == slot->base_gfn) {
			unsigned long *seg_pgd;
			unsigned long num_of_entry = slot->npages >> 17;
			unsigned long base_hpa = slot->arch.host_phys_addr;
			unsigned long i;

			seg_pgd = kvm->arch.seg_pgd + (start_pfn >> 17);
			for (i = 0; i < num_of_entry; i++) {
				*seg_pgd = base_hpa + (i << 30);
				seg_pgd++;
			}
		}
	}
}
#endif

void vcpu_send_ipi(struct kvm_vcpu *vcpu, int target_vcpuid, int type)
{
	struct kvm_vcpu *target_vcpu = kvm_get_vcpu(vcpu->kvm, target_vcpuid);

	if (type == II_RESET)
		target_vcpu->arch.restart = 1;

	if (target_vcpu != NULL)
		vcpu_interrupt_line(target_vcpu, 1, 1);
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level,
		bool line_status)
{
	u32 irq = irq_level->irq;
	unsigned int irq_num;
	struct kvm_vcpu *vcpu = NULL;
	bool level = irq_level->level;

	irq_num = irq;
	/* target core for Intx is core0 */
	vcpu = kvm_get_vcpu(kvm, 0);
	if (!vcpu)
		return -EINVAL;

	return vcpu_interrupt_line(vcpu, irq_num, level);
}

