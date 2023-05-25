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
#include <linux/sched.h>
#include <linux/msi.h>
#include <asm/kvm_timer.h>
#include <asm/kvm_emulate.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

#include "../kernel/pci_impl.h"
#include "vmem.c"

bool set_msi_flag;
static unsigned long longtime_offset;

#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_NUMA)
extern bool bind_vcpu_enabled;
#endif
#define last_vpn(cpu)	(cpu_data[cpu].last_vpn)

#ifdef CONFIG_SUBARCH_C3B
#define WIDTH_HARDWARE_VPN	8
#endif

#define VPN_FIRST_VERSION	(1UL << WIDTH_HARDWARE_VPN)
#define HARDWARE_VPN_MASK	((1UL << WIDTH_HARDWARE_VPN) - 1)
#define VPN_SHIFT		(64 - WIDTH_HARDWARE_VPN)

#define VCPU_STAT(n, x, ...) \
	{ n, offsetof(struct kvm_vcpu, stat.x), KVM_STAT_VCPU, ##  __VA_ARGS__ }
#define VM_STAT(n, x, ...) \
	{ n, offsetof(struct kvm, stat.x), KVM_STAT_VM, ## __VA_ARGS__ }
#define DFX_STAT(n, x, ...) \
	{ n, offsetof(struct kvm_vcpu_stat, x), DFX_STAT_U64, ## __VA_ARGS__ }

static DEFINE_PER_CPU(struct kvm_vcpu *, kvm_running_vcpu);

static void kvm_set_running_vcpu(struct kvm_vcpu *vcpu)
{
	__this_cpu_write(kvm_running_vcpu, vcpu);
}

int vcpu_interrupt_line(struct kvm_vcpu *vcpu, int number, bool level)
{
	set_bit(number, (vcpu->arch.irqs_pending));
	kvm_vcpu_kick(vcpu);
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

extern int __sw64_vcpu_run(unsigned long vcb_pa,
			   struct kvm_regs *regs, struct hcall_args *args);

#ifdef CONFIG_KVM_MEMHOTPLUG
static u64 get_vpcr_memhp(u64 seg_base, u64 vpn)
{
	return seg_base | ((vpn & HARDWARE_VPN_MASK) << 44);
}
#else
static u64 get_vpcr(u64 hpa_base, u64 mem_size, u64 vpn)
{
	return (hpa_base >> 23) | ((mem_size >> 23) << 16)
				| ((vpn & HARDWARE_VPN_MASK) << 44);
}
#endif

static unsigned long __get_new_vpn_context(struct kvm_vcpu *vcpu, long cpu)
{
	unsigned long vpn = last_vpn(cpu);
	unsigned long next = vpn + 1;

	if ((vpn & HARDWARE_VPN_MASK) >= HARDWARE_VPN_MASK) {
		tbia();
		next = (vpn & ~HARDWARE_VPN_MASK) + VPN_FIRST_VERSION + 1; /* bypass 0 */
	}
	last_vpn(cpu) = next;
	return next;
}

static void sw64_kvm_switch_vpn(struct kvm_vcpu *vcpu)
{
	unsigned long vpn;
	unsigned long vpnc;
	long cpu = smp_processor_id();

	vpn = last_vpn(cpu);
	vpnc = vcpu->arch.vpnc[cpu];

	if ((vpnc ^ vpn) & ~HARDWARE_VPN_MASK) {
		/* vpnc and cpu vpn not in the same version, get new vpnc and vpn */
		vpnc = __get_new_vpn_context(vcpu, cpu);
		vcpu->arch.vpnc[cpu] = vpnc;
	}

	vpn = vpnc & HARDWARE_VPN_MASK;

	/* Always update vpn */
	/* Just setup vcb, hardware CSR will be changed later in HMcode */
	vcpu->arch.vcb.vpcr = ((vcpu->arch.vcb.vpcr) & (~(HARDWARE_VPN_MASK << 44))) | (vpn << 44);
	vcpu->arch.vcb.dtb_pcr = ((vcpu->arch.vcb.dtb_pcr) & (~(HARDWARE_VPN_MASK << VPN_SHIFT))) | (vpn << VPN_SHIFT);

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

static void check_vcpu_requests(struct kvm_vcpu *vcpu)
{
	unsigned long vpn;
	long cpu = smp_processor_id();

	if (kvm_request_pending(vcpu)) {
		if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
			vpn = vcpu->arch.vpnc[cpu] & HARDWARE_VPN_MASK;
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

int kvm_arch_check_processor_compat(void *opaque)
{
	return 0;
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

/*
 * kvm_mark_migration write the mark on every vcpucbs of the kvm, which tells
 * the system to do migration while the mark is on, and flush all vcpu's tlbs
 * at the beginning of the migration.
 */
void kvm_mark_migration(struct kvm *kvm, int mark)
{
	struct kvm_vcpu *vcpu;
	int cpu;

	kvm_for_each_vcpu(cpu, vcpu, kvm)
		vcpu->arch.vcb.migration_mark = mark << 2;

	kvm_flush_remote_tlbs(kvm);
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
		const struct kvm_userspace_memory_region *mem,
		struct kvm_memory_slot *old,
		const struct kvm_memory_slot *new,
		enum kvm_mr_change change)
{
	/*
	 * At this point memslot has been committed and there is an
	 * allocated dirty_bitmap[], dirty pages will be be tracked while the
	 * memory slot is write protected.
	 */

	/* If dirty logging has been stopped, do nothing for now. */
	if ((change != KVM_MR_DELETE)
			&& (old->flags & KVM_MEM_LOG_DIRTY_PAGES)
			&& (!(new->flags & KVM_MEM_LOG_DIRTY_PAGES))) {
		kvm_mark_migration(kvm, 0);
		return;
	}

	/* If it's the first time dirty logging, flush all vcpu tlbs. */
	if ((change == KVM_MR_FLAGS_ONLY)
			&& (!(old->flags & KVM_MEM_LOG_DIRTY_PAGES))
			&& (new->flags & KVM_MEM_LOG_DIRTY_PAGES))
		kvm_mark_migration(kvm, 1);
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r = 0;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_IMMEDIATE_EXIT:
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

void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn_offset,
		unsigned long mask)
{
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

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	hrtimer_cancel(&vcpu->arch.hrt);
}

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
#ifdef CONFIG_KVM_MEMHOTPLUG
	unsigned long *seg_pgd;

	if (kvm->arch.seg_pgd != NULL) {
		kvm_err("kvm_arch already initialized?\n");
		return -EINVAL;
	}

	seg_pgd = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
	if (!seg_pgd)
		return -ENOMEM;

	kvm->arch.seg_pgd = seg_pgd;
#endif

	return 0;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	int i;
#ifdef CONFIG_KVM_MEMHOTPLUG
	void *seg_pgd = NULL;

	if (kvm->arch.seg_pgd) {
		seg_pgd = READ_ONCE(kvm->arch.seg_pgd);
		kvm->arch.seg_pgd = NULL;
	}

	if (seg_pgd)
		free_pages_exact(seg_pgd, PAGE_SIZE);
#endif

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (kvm->vcpus[i]) {
			kvm_vcpu_destroy(kvm->vcpus[i]);
			kvm->vcpus[i] = NULL;
		}
	}

	atomic_set(&kvm->online_vcpus, 0);
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
	unsigned int num_of_entry = size >> 30;
	unsigned long base_hpa = addr >> 30;
	int i;

	for (i = 0; i < num_of_entry; i++) {
		*seg_pgd = base_hpa + i;
		seg_pgd++;
	}
}
#endif

int kvm_arch_prepare_memory_region(struct kvm *kvm,
		struct kvm_memory_slot *memslot,
		const struct kvm_userspace_memory_region *mem,
		enum kvm_mr_change change)
{
	unsigned long addr;
	struct file *vm_file;
	struct vm_area_struct *vma;
	struct vmem_info *info;
	unsigned long ret;
	size_t size;

	if (change == KVM_MR_FLAGS_ONLY || change == KVM_MR_DELETE)
		return 0;

	if (test_bit(IO_MARK_BIT, &(mem->guest_phys_addr)))
		return 0;

	if (test_bit(IO_MARK_BIT + 1, &(mem->guest_phys_addr)))
		return 0;

#ifndef CONFIG_KVM_MEMHOTPLUG
	if (mem->guest_phys_addr) {
		pr_info("%s, No KVM MEMHOTPLUG support!\n", __func__);
		return 0;
	}
#endif

	if (!sw64_kvm_pool)
		return -ENOMEM;

	pr_info("%s: %#llx %#llx, user addr: %#llx\n", __func__,
			mem->guest_phys_addr, mem->memory_size, mem->userspace_addr);

	vma = find_vma(current->mm, mem->userspace_addr);
	if (!vma)
		return -ENOMEM;
	vm_file = vma->vm_file;

	if (!vm_file) {
		info = kzalloc(sizeof(struct vmem_info), GFP_KERNEL);

		size = round_up(mem->memory_size, 8 << 20);
		addr = gen_pool_alloc(sw64_kvm_pool, size);
		if (!addr)
			return -ENOMEM;
		vm_munmap(mem->userspace_addr, mem->memory_size);
		ret = vm_mmap(vm_file, mem->userspace_addr, mem->memory_size,
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_FIXED, 0);
		if ((long)ret < 0)
			return ret;

		vma = find_vma(current->mm, mem->userspace_addr);
		if (!vma)
			return -ENOMEM;

#ifdef CONFIG_KVM_MEMHOTPLUG
		if (memslot->base_gfn == 0x0UL) {
			setup_segment_table(kvm, memslot, addr, size);
			kvm->arch.host_phys_addr = (u64)addr;
			memslot->arch.host_phys_addr = addr;
		} else {
			/* used for memory hotplug */
			memslot->arch.host_phys_addr = addr;
			memslot->arch.valid = false;
		}
#endif

		info->start = addr;
		info->size = size;
		vma->vm_private_data = (void *) info;

		vma->vm_ops = &vmem_vm_ops;
		vma->vm_ops->open(vma);

		ret = vmem_vm_insert_page(vma);
		if ((int)ret < 0)
			return ret;
	} else {
		info = vm_file->private_data;
		addr = info->start;
	}

	pr_info("guest phys addr = %#lx, size = %#lx\n",
			addr, vma->vm_end - vma->vm_start);

#ifndef CONFIG_KVM_MEMHOTPLUG
	kvm->arch.host_phys_addr = (u64)addr;
	kvm->arch.size = round_up(mem->memory_size, 8 << 20);
#endif

	memset(__va(addr), 0, 0x2000000);

	return 0;
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

	/* For guest kernel "sys_call HMC_whami", indicate virtual cpu id */
	vcpu->arch.vcb.whami = vcpu->vcpu_id;
	vcpu->arch.vcb.vcpu_irq_disabled = 1;
	vcpu->arch.pcpu_id = -1; /* force flush tlb for the first time */

	return 0;
}

int kvm_arch_vcpu_reset(struct kvm_vcpu *vcpu)
{
	unsigned long addr = vcpu->kvm->arch.host_phys_addr;

	hrtimer_cancel(&vcpu->arch.hrt);
	vcpu->arch.vcb.whami = vcpu->vcpu_id;
	vcpu->arch.vcb.vcpu_irq_disabled = 1;
	vcpu->arch.pcpu_id = -1; /* force flush tlb for the first time */
	vcpu->arch.power_off = 0;
	memset(&vcpu->arch.irqs_pending, 0, sizeof(vcpu->arch.irqs_pending));

	if (vcpu->vcpu_id == 0)
		memset(__va(addr), 0, 0x2000000);

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
	kvm_set_running_vcpu(vcpu);
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
	kvm_set_running_vcpu(NULL);
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

void _debug_printk_vcpu(struct kvm_vcpu *vcpu)
{
	unsigned long pc = vcpu->arch.regs.pc;
	unsigned long offset = vcpu->kvm->arch.host_phys_addr;
	unsigned int *pc_phys = __va((pc & 0x7fffffffUL) + offset);
	unsigned int insn;
	int opc, ra, disp16;

	insn = *pc_phys;
	opc = (insn >> 26) & 0x3f;
	ra = (insn >> 21) & 0x1f;
	disp16 = insn & 0xffff;

	if (opc == 0x06 && disp16 == 0x1000) /* RD_F */
		pr_info("vcpu exit: pc = %#lx (%px), insn[%x] : rd_f r%d [%#lx]\n",
				pc, pc_phys, insn, ra, vcpu_get_reg(vcpu, ra));
}

static void update_vcpu_stat_time(struct kvm_vcpu_stat *vcpu_stat)
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
	int ret;
	struct kvm_run *run = vcpu->run;
	struct vcpucb *vcb = &(vcpu->arch.vcb);
	struct hcall_args hargs;
	int irq;
	bool more;
	sigset_t sigsaved;

	if (run->immediate_exit)
		return -EINTR;

	/* Set guest vcb */
	/* vpn will update later when vcpu is running */
	if (vcpu->arch.vcb.vpcr == 0) {
#ifndef CONFIG_KVM_MEMHOTPLUG
		vcpu->arch.vcb.vpcr
			= get_vpcr(vcpu->kvm->arch.host_phys_addr, vcpu->kvm->arch.size, 0);

#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_NUMA)
		if (unlikely(bind_vcpu_enabled)) {
			int nid;
			unsigned long end;

			end = vcpu->kvm->arch.host_phys_addr + vcpu->kvm->arch.size;
			nid = pfn_to_nid(PHYS_PFN(vcpu->kvm->arch.host_phys_addr));
			if (pfn_to_nid(PHYS_PFN(end)) == nid)
				set_cpus_allowed_ptr(vcpu->arch.tsk, cpumask_of_node(nid));
		}
#endif
#else /* !CONFIG_KVM_MEMHOTPLUG */
		unsigned long seg_base = virt_to_phys(vcpu->kvm->arch.seg_pgd);

		vcpu->arch.vcb.vpcr = get_vpcr_memhp(seg_base, 0);
#endif /* CONFIG_KVM_MEMHOTPLUG */
		vcpu->arch.vcb.upcr = 0x7;
	}

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
		/* Check conditions before entering the guest */
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
		irq = interrupt_pending(vcpu, &more);
		if (irq < SWVM_IRQS)
			try_deliver_interrupt(vcpu, irq, more);

		vcpu->arch.halted = 0;

		sw64_kvm_switch_vpn(vcpu);
		check_vcpu_requests(vcpu);
		guest_enter_irqoff();

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

long kvm_arch_vcpu_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	unsigned long result;
	struct kvm_vcpu *vcpu = filp->private_data;
	struct vcpucb *kvm_vcb;

	switch (ioctl) {
	case KVM_SW64_VCPU_INIT:
		return kvm_arch_vcpu_reset(vcpu);
	case KVM_SW64_GET_VCB:
		if (vcpu->arch.vcb.migration_mark) {
			result = sw64_io_read(0, LONG_TIME)
					+ vcpu->arch.vcb.guest_longtime_offset;
			vcpu->arch.vcb.guest_longtime = result;
			vcpu->arch.vcb.guest_irqs_pending = vcpu->arch.irqs_pending[0];
		}

		if (copy_to_user((void __user *)arg, &(vcpu->arch.vcb), sizeof(struct vcpucb)))
			return -EINVAL;
		break;
	case KVM_SW64_SET_VCB:
		kvm_vcb = memdup_user((void __user *)arg, sizeof(*kvm_vcb));
		memcpy(&(vcpu->arch.vcb), kvm_vcb, sizeof(struct vcpucb));

		if (vcpu->arch.vcb.migration_mark) {
			/* updated vpcr needed by destination vm */
			vcpu->arch.vcb.vpcr
				= get_vpcr(vcpu->kvm->arch.host_phys_addr, vcpu->kvm->arch.size, 0);

			/* synchronize the longtime of source and destination */
			if (vcpu->arch.vcb.whami == 0) {
				result = sw64_io_read(0, LONG_TIME);
				vcpu->arch.vcb.guest_longtime_offset = vcpu->arch.vcb.guest_longtime - result;
				longtime_offset = vcpu->arch.vcb.guest_longtime_offset;
			} else
				vcpu->arch.vcb.guest_longtime_offset = longtime_offset;

			set_timer(vcpu, 200000000);
			vcpu->arch.vcb.migration_mark = 0;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
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
	kvm_sw64_perf_init();
	return 0;
}

void kvm_arch_exit(void)
{
	kvm_sw64_perf_teardown();
}

void kvm_arch_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					struct kvm_memory_slot *memslot)
{
	kvm_flush_remote_tlbs(kvm);
}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	return 0;
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
			int i;

			seg_pgd = kvm->arch.seg_pgd + (start_pfn >> 17);
			for (i = 0; i < num_of_entry; i++) {
				*seg_pgd = (base_hpa >> 30) + i;
				seg_pgd++;
			}
		}
	}
}
#endif

void vcpu_send_ipi(struct kvm_vcpu *vcpu, int target_vcpuid)
{
	struct kvm_vcpu *target_vcpu = kvm_get_vcpu(vcpu->kvm, target_vcpuid);

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

static int __init kvm_sw64_init(void)
{
	int i, ret;

	ret = vmem_init();
	if (ret)
		return ret;

	for (i = 0; i < NR_CPUS; i++)
		last_vpn(i) = VPN_FIRST_VERSION;

	ret = kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);
	if (ret) {
		vmem_exit();
		return ret;
	}
	return 0;
}

static void __exit kvm_sw64_exit(void)
{
	kvm_exit();
	vmem_exit();
}

module_init(kvm_sw64_init);
module_exit(kvm_sw64_exit);
