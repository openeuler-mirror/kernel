// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 - os kernal
 * Author: fire3 <fire3@example.com> yangzh <yangzh@gmail.com>
 * linhn <linhn@example.com>
 */

#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/mman.h>
#include <linux/sched/signal.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>

#include <asm/debug.h>
#include <asm/kvm_timer.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/barrier.h>
#include "trace.h"

#include "../kernel/pci_impl.h"
#include "vmem.c"


__read_mostly bool bind_vcpu_enabled;

#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_NUMA)
struct dentry *bindvcpu;

static int __init bind_vcpu_init(void)
{
	if (!sw64_debugfs_dir)
		return -ENODEV;
	bindvcpu = debugfs_create_bool("bind_vcpu", 0644,
			sw64_debugfs_dir, &bind_vcpu_enabled);
	if (IS_ERR(bindvcpu))
		return PTR_ERR(bindvcpu);
	return 0;
}

static void bind_vcpu_exit(void)
{
	bind_vcpu_enabled = false;
	debugfs_remove(bindvcpu);
}
#else
static int __init bind_vcpu_init(void)
{
	return 0;
}

static void bind_vcpu_exit(void) { }

#endif

#define GUEST_RESET_PC		0xffffffff80011100

static unsigned long longtime_offset;

#ifdef CONFIG_KVM_MEMHOTPLUG
static u64 get_vpcr_memhp(u64 seg_base, u64 vpn)
{
	return seg_base | ((vpn & VPN_MASK) << 44);
}
#else
static u64 get_vpcr(u64 hpa_base, u64 mem_size, u64 vpn)
{
	return (hpa_base >> 23) | ((mem_size >> 23) << 16)
		| ((vpn & VPN_MASK) << 44);
}
#endif

static unsigned long core3_get_new_vpn_context(struct kvm_vcpu *vcpu, long cpu)
{
	unsigned long vpn = last_vpn(cpu);
	unsigned long next = vpn + 1;

	if ((vpn & VPN_MASK) >= VPN_MASK) {
		tbia();
		next = (vpn & ~VPN_MASK) + VPN_FIRST_VERSION + 1; /* bypass 0 */
	}
	last_vpn(cpu) = next;
	return next;
}

static void core3_update_vpn(struct kvm_vcpu *vcpu, unsigned long vpn)
{
	vcpu->arch.vcb.vpcr = ((vcpu->arch.vcb.vpcr) & (~(VPN_MASK << 44))) | (vpn << 44);
	vcpu->arch.vcb.dtb_vpcr = ((vcpu->arch.vcb.dtb_vpcr) & (~(VPN_MASK << VPN_SHIFT))) | (vpn << VPN_SHIFT);
}

int kvm_core3_init_vm(struct kvm *kvm)
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

void kvm_core3_destroy_vm(struct kvm *kvm)
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
		if (kvm->vcpus[i])
			kvm_vcpu_destroy(kvm->vcpus[i]);
	}
	atomic_set(&kvm->online_vcpus, 0);
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

int kvm_core3_prepare_memory_region(struct kvm *kvm,
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

		size = round_up(mem->memory_size, 8<<20);
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
	kvm->arch.size = round_up(mem->memory_size, 8<<20);
#endif
	memset(__va(addr), 0, 0x2000000);

	return 0;
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

void kvm_core3_commit_memory_region(struct kvm *kvm,
		const struct kvm_userspace_memory_region *mem,
		const struct kvm_memory_slot *old,
		const struct kvm_memory_slot *new,
		enum kvm_mr_change change)
{
	/*
	 * At this point memslot has been committed and there is an
	 * allocated dirty_bitmap[], dirty pages will be tracked while the
	 * memory slot is write protected.
	 */

	/* If dirty logging has been stopped, do nothing for now. */
	if ((change != KVM_MR_DELETE) && (old->flags & KVM_MEM_LOG_DIRTY_PAGES)
		&& (!(new->flags & KVM_MEM_LOG_DIRTY_PAGES))) {
		kvm_mark_migration(kvm, 0);
		return;
	}

	/* If it's the first time dirty logging, flush all vcpu tlbs. */
	if ((change == KVM_MR_FLAGS_ONLY) && (!(old->flags & KVM_MEM_LOG_DIRTY_PAGES))
		&& (new->flags & KVM_MEM_LOG_DIRTY_PAGES))
		kvm_mark_migration(kvm, 1);
}

int kvm_core3_vcpu_reset(struct kvm_vcpu *vcpu)
{
	unsigned long addr = vcpu->kvm->arch.host_phys_addr;

	hrtimer_cancel(&vcpu->arch.hrt);
	vcpu->arch.vcb.soft_cid = vcpu->vcpu_id;
	vcpu->arch.vcb.vcpu_irq_disabled = 1;
	vcpu->arch.pcpu_id = -1; /* force flush tlb for the first time */
	vcpu->arch.power_off = 0;
	memset(&vcpu->arch.irqs_pending, 0, sizeof(vcpu->arch.irqs_pending));

	if (vcpu->vcpu_id == 0)
		memset(__va(addr), 0, 0x2000000);

	return 0;
}

/*
 * Return > 0 to return to guest, < 0 on error, 0 (and set exit_reason) on
 * proper exit to userspace.
 */
int kvm_core3_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret;
	struct vcpucb *vcb = &(vcpu->arch.vcb);
	struct hcall_args hargs;
	int irq;
	bool more;
	sigset_t sigsaved;

	/* Set guest vcb */
	/* vpn will update later when vcpu is running */
	if (vcpu->arch.vcb.vpcr == 0) {
#ifndef CONFIG_KVM_MEMHOTPLUG
		vcpu->arch.vcb.vpcr
			= get_vpcr(vcpu->kvm->arch.host_phys_addr, vcpu->kvm->arch.size, 0);
		if (unlikely(bind_vcpu_enabled)) {
			int nid;
			unsigned long end;

			end = vcpu->kvm->arch.host_phys_addr + vcpu->kvm->arch.size;
			nid = pfn_to_nid(PHYS_PFN(vcpu->kvm->arch.host_phys_addr));
			if (pfn_to_nid(PHYS_PFN(end)) == nid)
				set_cpus_allowed_ptr(vcpu->arch.tsk, cpumask_of_node(nid));
		}
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

static long kvm_core3_get_vcb(struct file *filp, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;

	if (vcpu->arch.vcb.migration_mark) {
		unsigned long result = sw64_io_read(0, LONG_TIME)
			+ vcpu->arch.vcb.guest_longtime_offset;
		vcpu->arch.vcb.guest_longtime = result;
		vcpu->arch.vcb.guest_irqs_pending = vcpu->arch.irqs_pending[0];
	}

	if (copy_to_user((void __user *)arg, &(vcpu->arch.vcb), sizeof(struct vcpucb)))
		return -EINVAL;

	return 0;
}

static long kvm_core3_set_vcb(struct file *filp, unsigned long arg)
{
	unsigned long result;
	struct kvm_vcpu *vcpu = filp->private_data;
	struct vcpucb *kvm_vcb;

	kvm_vcb = memdup_user((void __user *)arg, sizeof(*kvm_vcb));
	memcpy(&(vcpu->arch.vcb), kvm_vcb, sizeof(struct vcpucb));

	if (vcpu->arch.vcb.migration_mark) {
		/* updated vpcr needed by destination vm */
		vcpu->arch.vcb.vpcr
			= get_vpcr(vcpu->kvm->arch.host_phys_addr, vcpu->kvm->arch.size, 0);

		/* synchronize the longtime of source and destination */
		if (vcpu->arch.vcb.soft_cid == 0) {
			result = sw64_io_read(0, LONG_TIME);
			vcpu->arch.vcb.guest_longtime_offset = vcpu->arch.vcb.guest_longtime - result;
			longtime_offset = vcpu->arch.vcb.guest_longtime_offset;
		} else
			vcpu->arch.vcb.guest_longtime_offset = longtime_offset;

		set_timer(vcpu, 200000000);
		vcpu->arch.vcb.migration_mark = 0;
	}

	return 0;
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

static struct kvm_sw64_ops core3_sw64_ops __ro_after_init = {
	.get_new_vpn_context = core3_get_new_vpn_context,
	.update_vpn = core3_update_vpn,
	.init_vm = kvm_core3_init_vm,
	.destroy_vm = kvm_core3_destroy_vm,
	.prepare_memory_region = kvm_core3_prepare_memory_region,
	.commit_memory_region = kvm_core3_commit_memory_region,
	.vcpu_reset = kvm_core3_vcpu_reset,
	.vcpu_run = kvm_core3_vcpu_ioctl_run,
	.get_vcb = kvm_core3_get_vcb,
	.set_vcb = kvm_core3_set_vcb,
};

static int __init kvm_core3_init(void)
{
	int i, ret;

	bind_vcpu_init();

	ret = vmem_init();
	if (unlikely(ret))
		goto out;

	for (i = 0; i < NR_CPUS; i++)
		last_vpn(i) = VPN_FIRST_VERSION;

	ret = kvm_init(&core3_sw64_ops, sizeof(struct kvm_vcpu), 0, THIS_MODULE);

	if (likely(!ret))
		return 0;

	vmem_exit();
out:
	bind_vcpu_exit();
	return ret;
}

static void __exit kvm_core3_exit(void)
{
	kvm_exit();
	vmem_exit();
	bind_vcpu_exit();
}

module_init(kvm_core3_init);
module_exit(kvm_core3_exit);
