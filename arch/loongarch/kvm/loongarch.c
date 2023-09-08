// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/mod_devicetable.h>
#include <linux/kvm.h>
#include <linux/debugfs.h>
#include <linux/pid.h>
#include <linux/kvm_host.h>
#include <linux/sched/stat.h>
#include <asm/fpu.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/cpufeature.h>
#include "kvmcpu.h"
#include <asm/setup.h>
#include <asm/time.h>
#include <asm/paravirt.h>

#include "intc/ls3a_ipi.h"
#include "intc/ls7a_irq.h"
#include "intc/ls3a_ext_irq.h"
#include "kvm_compat.h"
#include "kvmcsr.h"

/*
 * Define loongarch kvm version.
 * Add version number when qemu/kvm interface changed
 */
#define KVM_LOONGARCH_VERSION 1
#define CREATE_TRACE_POINTS
#include "trace.h"
struct kvm_stats_debugfs_item vcpu_debugfs_entries[] = {
	VCPU_STAT("idle", idle_exits),
	VCPU_STAT("signal", signal_exits),
	VCPU_STAT("interrupt", int_exits),
	VCPU_STAT("rdcsr_cpu_feature", rdcsr_cpu_feature_exits),
	VCPU_STAT("rdcsr_misc_func", rdcsr_misc_func_exits),
	VCPU_STAT("rdcsr_ipi_access", rdcsr_ipi_access_exits),
	VCPU_STAT("cpucfg", cpucfg_exits),
	VCPU_STAT("huge_dec", huge_dec_exits),
	VCPU_STAT("huge_thp", huge_thp_exits),
	VCPU_STAT("huge_adj", huge_adjust_exits),
	VCPU_STAT("huge_set", huge_set_exits),
	VCPU_STAT("huge_merg", huge_merge_exits),
	VCPU_STAT("halt_successful_poll", halt_successful_poll),
	VCPU_STAT("halt_attempted_poll", halt_attempted_poll),
	VCPU_STAT("halt_poll_invalid", halt_poll_invalid),
	VCPU_STAT("halt_wakeup", halt_wakeup),
	VCPU_STAT("tlbmiss_ld", excep_exits[KVM_EXCCODE_TLBL]),
	VCPU_STAT("tlbmiss_st", excep_exits[KVM_EXCCODE_TLBS]),
       	VCPU_STAT("tlb_ifetch", excep_exits[KVM_EXCCODE_TLBI]),	
	VCPU_STAT("tlbmod", excep_exits[KVM_EXCCODE_TLBM]),	
	VCPU_STAT("tlbri", excep_exits[KVM_EXCCODE_TLBRI]),	
	VCPU_STAT("tlbxi", excep_exits[KVM_EXCCODE_TLBXI]),	
	VCPU_STAT("fp_dis", excep_exits[KVM_EXCCODE_FPDIS]),
	VCPU_STAT("lsx_dis", excep_exits[KVM_EXCCODE_LSXDIS]),
	VCPU_STAT("lasx_dis", excep_exits[KVM_EXCCODE_LASXDIS]),
	VCPU_STAT("fpe", excep_exits[KVM_EXCCODE_FPE]),	
	VCPU_STAT("watch", excep_exits[KVM_EXCCODE_WATCH]),	
	VCPU_STAT("gspr", excep_exits[KVM_EXCCODE_GSPR]),	
	VCPU_STAT("gcm", excep_exits[KVM_EXCCODE_GCM]),	
	VCPU_STAT("hc", excep_exits[KVM_EXCCODE_HYP]),	
	{NULL}
};

struct kvm_stats_debugfs_item debugfs_entries[] = {
	VM_STAT("remote_tlb_flush", remote_tlb_flush),
	VM_STAT("pip_read_exits", pip_read_exits),
	VM_STAT("pip_write_exits", pip_write_exits),
	VM_STAT("vm_ioctl_irq_line", vm_ioctl_irq_line),
	VM_STAT("ls7a_ioapic_update", ls7a_ioapic_update),
	VM_STAT("ls7a_ioapic_set_irq", ls7a_ioapic_set_irq),
	VM_STAT("ls7a_msi_irq", ls7a_msi_irq),
	VM_STAT("ioapic_reg_write", ioapic_reg_write),
	VM_STAT("ioapic_reg_read", ioapic_reg_read),
	VM_STAT("set_ls7a_ioapic", set_ls7a_ioapic),
	VM_STAT("get_ls7a_ioapic", get_ls7a_ioapic),
	VM_STAT("set_ls3a_ext_irq", set_ls3a_ext_irq),
	VM_STAT("get_ls3a_ext_irq", get_ls3a_ext_irq),
	VM_STAT("ls3a_ext_irq", trigger_ls3a_ext_irq),
	{NULL}
};

bool kvm_trace_guest_mode_change;
static struct kvm_context __percpu *vmcs;

int kvm_guest_mode_change_trace_reg(void)
{
	kvm_trace_guest_mode_change = 1;
	return 0;
}

void kvm_guest_mode_change_trace_unreg(void)
{
	kvm_trace_guest_mode_change = 0;
}

/*
 * XXXKYMA: We are simulatoring a processor that has the WII bit set in
 * Config7, so we are "runnable" if interrupts are pending
 */
int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	return !!(vcpu->arch.irq_pending);
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return false;
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}

#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
void kvm_update_stolen_time(struct kvm_vcpu *vcpu)
{
	struct kvm_host_map map;
	struct kvm_steal_time *st;
	int ret = 0;

	if (vcpu->arch.st.guest_addr == 0)
		return;

	ret = kvm_map_gfn(vcpu, vcpu->arch.st.guest_addr >> PAGE_SHIFT,
				&map, &vcpu->arch.st.cache, false);
	if (ret) {
		kvm_info("%s ret:%d\n", __func__, ret);
		return;
	}
	st = map.hva + offset_in_page(vcpu->arch.st.guest_addr);
	if (st->version & 1)
		st->version += 1; /* first time write, random junk */
	st->version += 1;
	smp_wmb();
	st->steal += current->sched_info.run_delay -
		vcpu->arch.st.last_steal;
	vcpu->arch.st.last_steal = current->sched_info.run_delay;
	smp_wmb();
	st->version += 1;

	kvm_unmap_gfn(vcpu, &map, &vcpu->arch.st.cache, true, false);
}

bool _kvm_pvtime_supported(void)
{
	return !!sched_info_on();
}

int _kvm_pvtime_set_attr(struct kvm_vcpu *vcpu,
				struct kvm_device_attr *attr)
{
	u64 __user *user = (u64 __user *)attr->addr;
	struct kvm *kvm = vcpu->kvm;
	u64 ipa;
	int ret = 0;
	int idx;

	if (!_kvm_pvtime_supported() ||
		attr->attr != KVM_LARCH_VCPU_PVTIME_IPA)
		return -ENXIO;

	if (get_user(ipa, user))
		return -EFAULT;
	if (!IS_ALIGNED(ipa, 64))
		return -EINVAL;

	/* Check the address is in a valid memslot */
	idx = srcu_read_lock(&kvm->srcu);
	if (kvm_is_error_hva(gfn_to_hva(kvm, ipa >> PAGE_SHIFT)))
		ret = -EINVAL;
	srcu_read_unlock(&kvm->srcu, idx);

	if (!ret)
		vcpu->arch.st.guest_addr = ipa;

	return ret;
}

int _kvm_pvtime_get_attr(struct kvm_vcpu *vcpu,
				struct kvm_device_attr *attr)
{
	u64 __user *user = (u64 __user *)attr->addr;
	u64 ipa;

	if (!_kvm_pvtime_supported() ||
		attr->attr != KVM_LARCH_VCPU_PVTIME_IPA)
		return -ENXIO;

	ipa = vcpu->arch.st.guest_addr;

	if (put_user(ipa, user))
		return -EFAULT;

	return 0;
}

int _kvm_pvtime_has_attr(struct kvm_vcpu *vcpu,
				struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_LARCH_VCPU_PVTIME_IPA:
		if (_kvm_pvtime_supported())
			return 0;
	}

	return -ENXIO;
}
#endif

int kvm_arch_hardware_enable(void)
{
	unsigned long gcfg = 0;

	/* First init gtlbc, gcfg, gstat, gintc. All guest use the same config */
	kvm_clear_csr_gtlbc(KVM_GTLBC_USETGID | KVM_GTLBC_TOTI);
	kvm_write_csr_gcfg(0);
	kvm_write_csr_gstat(0);
	kvm_write_csr_gintc(0);

	/*
	 * Enable virtualization features granting guest direct control of
	 * certain features:
	 * GCI=2:       Trap on init or unimplement cache instruction.
	 * TORU=0:      Trap on Root Unimplement.
	 * CACTRL=1:    Root control cache.
	 * TOP=0:       Trap on Previlege.
	 * TOE=0:       Trap on Exception.
	 * TIT=0:       Trap on Timer.
	 */
	gcfg |= KVM_GCFG_GCI_SECURE;
	gcfg |= KVM_GCFG_MATC_ROOT;
	gcfg |= KVM_GCFG_TIT;
	kvm_write_csr_gcfg(gcfg);
	kvm_flush_tlb_all();

	/* Enable using TGID  */
	kvm_set_csr_gtlbc(KVM_GTLBC_USETGID);
	kvm_debug("gtlbc:%llx gintc:%llx gstat:%llx gcfg:%llx",
			kvm_read_csr_gtlbc(), kvm_read_csr_gintc(),
			kvm_read_csr_gstat(), kvm_read_csr_gcfg());
	return 0;
}

void kvm_arch_hardware_disable(void)
{
	kvm_clear_csr_gtlbc(KVM_GTLBC_USETGID | KVM_GTLBC_TOTI);
	kvm_write_csr_gcfg(0);
	kvm_write_csr_gstat(0);
	kvm_write_csr_gintc(0);

	/* Flush any remaining guest TLB entries */
	kvm_flush_tlb_all();
}

int kvm_arch_hardware_setup(void *opaque)
{
	return 0;
}

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	/* Allocate page table to map GPA -> RPA */
	kvm->arch.gpa_mm.pgd = kvm_pgd_alloc();
	if (!kvm->arch.gpa_mm.pgd)
		return -ENOMEM;

	kvm->arch.cpucfg_lasx = (read_cpucfg(LOONGARCH_CPUCFG2) &
					  CPUCFG2_LASX);

	_kvm_init_iocsr(kvm);
	kvm->arch.vmcs = vmcs;

	return 0;
}

static void kvm_free_vcpus(struct kvm *kvm)
{
	unsigned int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvm_vcpu_destroy(vcpu);
		kvm->vcpus[i] = NULL;
	}

	atomic_set(&kvm->online_vcpus, 0);
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	kvm_destroy_ls3a_ipi(kvm);
	kvm_destroy_ls7a_ioapic(kvm);
	kvm_destroy_ls3a_ext_irq(kvm);
	kvm_free_vcpus(kvm);
	_kvm_destroy_mm(kvm);
}

long kvm_arch_dev_ioctl(struct file *filp, unsigned int ioctl,
			unsigned long arg)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
			    unsigned long npages)
{
	return 0;
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				   struct kvm_memory_slot *memslot,
				   const struct kvm_userspace_memory_region *mem,
				   enum kvm_mr_change change)
{
	return 0;
}

static void _kvm_new_vpid(unsigned long cpu, struct kvm_vcpu *vcpu)
{
	struct kvm_context *context;
	unsigned long vpid;

	context = per_cpu_ptr(vcpu->kvm->arch.vmcs, cpu);
	vpid = context->vpid_cache;
	if (!(++vpid & context->gid_mask)) {
		if (!vpid)              /* fix version if needed */
			vpid = context->gid_fisrt_ver;

		++vpid;         /* vpid 0 reserved for root */

		/* start new vpid cycle */
		kvm_flush_tlb_all();
	}

	context->vpid_cache = vpid;
	vcpu->arch.vpid[cpu] = vpid;
}

/* Returns 1 if the guest TLB may be clobbered */
static int _kvm_check_requests(struct kvm_vcpu *vcpu, int cpu)
{
	int ret = 0;
	int i;

	if (!kvm_request_pending(vcpu))
		return 0;

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		/* Drop all vpids for this VCPU */
		for_each_possible_cpu(i)
			vcpu->arch.vpid[i] = 0;
		/* This will clobber guest TLB contents too */
		ret = 1;
	}

	return ret;
}

static void _kvm_update_vmid(struct kvm_vcpu *vcpu, int cpu)
{
	struct kvm_context *context;
	bool migrated;
	unsigned int gstinfo_gidmask, gstinfo_gid = 0;

	/*
	 * Are we entering guest context on a different CPU to last time?
	 * If so, the VCPU's guest TLB state on this CPU may be stale.
	 */
	context = per_cpu_ptr(vcpu->kvm->arch.vmcs, cpu);
	migrated = (vcpu->arch.last_exec_cpu != cpu);
	vcpu->arch.last_exec_cpu = cpu;

	/*
	 * Check if our vpid is of an older version and thus invalid.
	 *
	 * We also discard the stored vpid if we've executed on
	 * another CPU, as the guest mappings may have changed without
	 * hypervisor knowledge.
	 */
	gstinfo_gidmask = context->gid_mask << KVM_GSTAT_GID_SHIFT;
	if (migrated ||
			(vcpu->arch.vpid[cpu] ^ context->vpid_cache) &
			context->gid_ver_mask) {
		_kvm_new_vpid(cpu, vcpu);
		trace_kvm_vpid_change(vcpu, vcpu->arch.vpid[cpu]);
	}
	gstinfo_gid = (vcpu->arch.vpid[cpu] & context->gid_mask) <<
		KVM_GSTAT_GID_SHIFT;

	/* Restore GSTAT(0x50).vpid */
	kvm_change_csr_gstat(gstinfo_gidmask, gstinfo_gid);
}

/*
 * Return value is in the form (errcode<<2 | RESUME_FLAG_HOST | RESUME_FLAG_NV)
 */
static int _kvm_handle_exit(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	unsigned long exst = vcpu->arch.host_estat;
	u32 intr = exst & 0x1fff; /* ignore NMI */
	u32 exccode = (exst & KVM_ESTAT_EXC) >> KVM_ESTAT_EXC_SHIFT;
	u32 __user *opc = (u32 __user *) vcpu->arch.pc;
	int ret = RESUME_GUEST, cpu;

	vcpu->mode = OUTSIDE_GUEST_MODE;

	/* Set a default exit reason */
	run->exit_reason = KVM_EXIT_UNKNOWN;
	run->ready_for_interrupt_injection = 1;

	/*
	 * Set the appropriate status bits based on host CPU features,
	 * before we hit the scheduler
	 */

	local_irq_enable();

	kvm_debug("%s: exst: %lx, PC: %p, kvm_run: %p, kvm_vcpu: %p\n",
			__func__, exst, opc, run, vcpu);
	trace_kvm_exit(vcpu, exccode);
	if (exccode) {
		vcpu->stat.excep_exits[exccode]++;
		ret = _kvm_handle_fault(vcpu, exccode);
	} else {
		WARN(!intr, "suspicious vm exiting");
		++vcpu->stat.int_exits;

		if (need_resched())
			cond_resched();

		ret = RESUME_GUEST;
	}

#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	if (kvm_check_request(KVM_REQ_RECORD_STEAL, vcpu))
		kvm_update_stolen_time(vcpu);
#endif

	cond_resched();

	local_irq_disable();

	if (ret == RESUME_GUEST)
		kvm_acquire_timer(vcpu);

	if (!(ret & RESUME_HOST)) {
		_kvm_deliver_intr(vcpu);
		/* Only check for signals if not already exiting to userspace */
		if (signal_pending(current)) {
			run->exit_reason = KVM_EXIT_INTR;
			ret = (-EINTR << 2) | RESUME_HOST;
			++vcpu->stat.signal_exits;
			trace_kvm_exit(vcpu, KVM_TRACE_EXIT_SIGNAL);
		}
	}

	if (ret == RESUME_GUEST) {
		trace_kvm_reenter(vcpu);

		/*
		 * Make sure the read of VCPU requests in vcpu_reenter()
		 * callback is not reordered ahead of the write to vcpu->mode,
		 * or we could miss a TLB flush request while the requester sees
		 * the VCPU as outside of guest mode and not needing an IPI.
		 */
		smp_store_mb(vcpu->mode, IN_GUEST_MODE);

		cpu = smp_processor_id();
		_kvm_check_requests(vcpu, cpu);
		_kvm_update_vmid(vcpu, cpu);

		/*
		 * If FPU / LSX are enabled (i.e. the guest's FPU / LSX context
		 * is live), restore FCSR0.
		 */
		if (_kvm_guest_has_fpu(&vcpu->arch) &&
		    kvm_read_csr_euen() & (KVM_EUEN_FPEN | KVM_EUEN_LSXEN)) {
			kvm_restore_fcsr(vcpu);
		}
	}

	return ret;
}

static void _kvm_vcpu_init(struct kvm_vcpu *vcpu)
{
	int i;
	unsigned long timer_hz;
	struct loongarch_csrs *csr = vcpu->arch.csr;

	for_each_possible_cpu(i)
		vcpu->arch.vpid[i] = 0;

	hrtimer_init(&vcpu->arch.swtimer, CLOCK_MONOTONIC,
			HRTIMER_MODE_ABS_PINNED);
	vcpu->arch.swtimer.function = kvm_swtimer_wakeup;
	vcpu->arch.fpu_enabled = true;
	vcpu->arch.lsx_enabled = true;

	/*
	 * Initialize guest register state to valid architectural reset state.
	 */
	timer_hz = calc_const_freq();
	kvm_init_timer(vcpu, timer_hz);

	/* Set Initialize mode for GUEST */
	kvm_write_sw_gcsr(csr, KVM_CSR_CRMD, KVM_CRMD_DA);

	/* Set cpuid */
	kvm_write_sw_gcsr(csr, KVM_CSR_TMID, vcpu->vcpu_id);

	/* start with no pending virtual guest interrupts */
	csr->csrs[KVM_CSR_GINTC] = 0;
}

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	vcpu->arch.host_eentry = kvm_csr_readq(KVM_CSR_EENTRY);
	vcpu->arch.guest_eentry = (unsigned long)kvm_exception_entry;
	vcpu->arch.vcpu_run = kvm_enter_guest;
	vcpu->arch.handle_exit = _kvm_handle_exit;
	vcpu->arch.host_ecfg = (kvm_read_csr_ecfg() & KVM_ECFG_VS);

	/*
	 * kvm all exceptions share one exception entry, and host <-> guest switch
	 * also switch excfg.VS field, keep host excfg.VS info here
	 */
	vcpu->arch.csr = kzalloc(sizeof(struct loongarch_csrs), GFP_KERNEL);
	if (!vcpu->arch.csr) {
		return -ENOMEM;
	}

	/* Init */
	vcpu->arch.last_sched_cpu = -1;
	vcpu->arch.last_exec_cpu = -1;
	_kvm_vcpu_init(vcpu);
	return 0;
}

static void _kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	int cpu;
	struct kvm_context *context;

	/*
	 * If the VCPU is freed and reused as another VCPU, we don't want the
	 * matching pointer wrongly hanging around in last_vcpu.
	 */
	for_each_possible_cpu(cpu) {
		context = per_cpu_ptr(vcpu->kvm->arch.vmcs, cpu);
		if (context->last_vcpu == vcpu)
			context->last_vcpu = NULL;
	}
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	struct gfn_to_pfn_cache *cache = &vcpu->arch.st.cache;

	_kvm_vcpu_uninit(vcpu);

	hrtimer_cancel(&vcpu->arch.swtimer);
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_page_cache);
	if (vcpu->arch.st.guest_addr)
		kvm_release_pfn(cache->pfn, cache->dirty, cache);
	kfree(vcpu->arch.csr);
}
#define KVM_GUESTDBG_VALID_MASK (KVM_GUESTDBG_ENABLE | \
		KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_SINGLESTEP)
int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	int ret = 0;

	if (dbg->control & ~KVM_GUESTDBG_VALID_MASK) {
		ret = -EINVAL;
		goto out;
	}
	if (dbg->control & KVM_GUESTDBG_ENABLE) {
		vcpu->guest_debug = dbg->control;
		/* No hardware breakpoint */
	} else {
		vcpu->guest_debug = 0;
	}
out:
	return ret;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	int r = -EINTR;
	int cpu;
	struct kvm_run *run = vcpu->run;

	vcpu_load(vcpu);

	kvm_sigset_activate(vcpu);

	if (vcpu->mmio_needed) {
		if (!vcpu->mmio_is_write)
			_kvm_complete_mmio_read(vcpu, run);
		vcpu->mmio_needed = 0;
	} else if (vcpu->arch.is_hypcall) {
		/* set return value for hypercall v0 register */
		vcpu->arch.gprs[KVM_REG_A0] = run->hypercall.ret;
		vcpu->arch.is_hypcall = 0;
	}

	if (run->exit_reason == KVM_EXIT_LOONGARCH_IOCSR) {
		if (!run->iocsr_io.is_write)
			_kvm_complete_iocsr_read(vcpu, run);
	}

	/* clear exit_reason */
	run->exit_reason = KVM_EXIT_UNKNOWN;
	if (run->immediate_exit)
		goto out;

	lose_fpu(1);

#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	if (kvm_check_request(KVM_REQ_RECORD_STEAL, vcpu))
		kvm_update_stolen_time(vcpu);
#endif
	local_irq_disable();
	guest_enter_irqoff();
	trace_kvm_enter(vcpu);

	/*
	 * Make sure the read of VCPU requests in vcpu_run() callback is not
	 * reordered ahead of the write to vcpu->mode, or we could miss a TLB
	 * flush request while the requester sees the VCPU as outside of guest
	 * mode and not needing an IPI.
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	cpu = smp_processor_id();
	kvm_acquire_timer(vcpu);
	/* Check if we have any exceptions/interrupts pending */
	_kvm_deliver_intr(vcpu);

	_kvm_check_requests(vcpu, cpu);
	_kvm_update_vmid(vcpu, cpu);
	r = kvm_enter_guest(run, vcpu);

	trace_kvm_out(vcpu);
	guest_exit_irqoff();
	local_irq_enable();

out:
	kvm_sigset_deactivate(vcpu);

	vcpu_put(vcpu);
	return r;
}

int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu,
			     struct kvm_loongarch_interrupt *irq)
{
	int intr = (int)irq->irq;

	if (intr < 0) {
		_kvm_dequeue_irq(vcpu, -intr);
		return 0;
	}

	_kvm_queue_irq(vcpu, intr);
	kvm_vcpu_kick(vcpu);
	return 0;
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

/**
 * kvm_migrate_count() - Migrate timer.
 * @vcpu:       Virtual CPU.
 *
 * Migrate hrtimer to the current CPU by cancelling and restarting it
 * if it was running prior to being cancelled.
 *
 * Must be called when the VCPU is migrated to a different CPU to ensure that
 * timer expiry during guest execution interrupts the guest and causes the
 * interrupt to be delivered in a timely manner.
 */
static void kvm_migrate_count(struct kvm_vcpu *vcpu)
{
	if (hrtimer_cancel(&vcpu->arch.swtimer))
		hrtimer_restart(&vcpu->arch.swtimer);
}

static int _kvm_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct kvm_context *context;
	struct loongarch_csrs *csr = vcpu->arch.csr;
	bool migrated, all;

	/*
	 * Have we migrated to a different CPU?
	 * If so, any old guest TLB state may be stale.
	 */
	migrated = (vcpu->arch.last_sched_cpu != cpu);

	/*
	 * Was this the last VCPU to run on this CPU?
	 * If not, any old guest state from this VCPU will have been clobbered.
	 */
	context = per_cpu_ptr(vcpu->kvm->arch.vmcs, cpu);
	all = migrated || (context->last_vcpu != vcpu);
	context->last_vcpu = vcpu;

	/*
	 * Restore timer state regardless
	 */
	kvm_restore_timer(vcpu);

	/* Control guest page CCA attribute */
	kvm_change_csr_gcfg(KVM_GCFG_MATC_MASK, KVM_GCFG_MATC_ROOT);
	/* Restore hardware perf csr */
	kvm_restore_hw_perf(vcpu);

#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	kvm_make_request(KVM_REQ_RECORD_STEAL, vcpu);
#endif
	/* Don't bother restoring registers multiple times unless necessary */
	if (!all)
		return 0;

	kvm_write_csr_gcntc((ulong)vcpu->kvm->arch.stablecounter_gftoffset);
	/*
	 * Restore guest CSR registers
	 */
	kvm_restore_hw_gcsr(csr, KVM_CSR_CRMD);
	kvm_restore_hw_gcsr(csr, KVM_CSR_PRMD);
	kvm_restore_hw_gcsr(csr, KVM_CSR_EUEN);
	kvm_restore_hw_gcsr(csr, KVM_CSR_MISC);
	kvm_restore_hw_gcsr(csr, KVM_CSR_ECFG);
	kvm_restore_hw_gcsr(csr, KVM_CSR_ERA);
	kvm_restore_hw_gcsr(csr, KVM_CSR_BADV);
	kvm_restore_hw_gcsr(csr, KVM_CSR_BADI);
	kvm_restore_hw_gcsr(csr, KVM_CSR_EENTRY);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBIDX);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBEHI);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBELO0);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBELO1);
	kvm_restore_hw_gcsr(csr, KVM_CSR_ASID);
	kvm_restore_hw_gcsr(csr, KVM_CSR_PGDL);
	kvm_restore_hw_gcsr(csr, KVM_CSR_PGDH);
	kvm_restore_hw_gcsr(csr, KVM_CSR_PWCTL0);
	kvm_restore_hw_gcsr(csr, KVM_CSR_PWCTL1);
	kvm_restore_hw_gcsr(csr, KVM_CSR_STLBPGSIZE);
	kvm_restore_hw_gcsr(csr, KVM_CSR_RVACFG);
	kvm_restore_hw_gcsr(csr, KVM_CSR_CPUID);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS0);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS1);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS2);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS3);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS4);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS5);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS6);
	kvm_restore_hw_gcsr(csr, KVM_CSR_KS7);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TMID);
	kvm_restore_hw_gcsr(csr, KVM_CSR_CNTC);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBRENTRY);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBRBADV);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBRERA);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBRSAVE);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBRELO0);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBRELO1);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBREHI);
	kvm_restore_hw_gcsr(csr, KVM_CSR_TLBRPRMD);
	kvm_restore_hw_gcsr(csr, KVM_CSR_DMWIN0);
	kvm_restore_hw_gcsr(csr, KVM_CSR_DMWIN1);
	kvm_restore_hw_gcsr(csr, KVM_CSR_DMWIN2);
	kvm_restore_hw_gcsr(csr, KVM_CSR_DMWIN3);
	kvm_restore_hw_gcsr(csr, KVM_CSR_LLBCTL);

	/* restore Root.Guestexcept from unused Guest guestexcept register */
	kvm_write_csr_gintc(csr->csrs[KVM_CSR_GINTC]);

	/*
	 * We should clear linked load bit to break interrupted atomics. This
	 * prevents a SC on the next VCPU from succeeding by matching a LL on
	 * the previous VCPU.
	 */
	if (vcpu->kvm->created_vcpus > 1)
		kvm_set_gcsr_llbctl(KVM_LLBCTL_WCLLB);

	return 0;
}

/* Restore ASID once we are scheduled back after preemption */
void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	unsigned long flags;

	local_irq_save(flags);
	vcpu->cpu = cpu;
	if (vcpu->arch.last_sched_cpu != cpu) {
		kvm_debug("[%d->%d]KVM VCPU[%d] switch\n",
				vcpu->arch.last_sched_cpu, cpu, vcpu->vcpu_id);
		/*
		 * Migrate the timer interrupt to the current CPU so that it
		 * always interrupts the guest and synchronously triggers a
		 * guest timer interrupt.
		 */
		kvm_migrate_count(vcpu);
	}

	/* restore guest state to registers */
	_kvm_vcpu_load(vcpu, cpu);
	local_irq_restore(flags);
}

static int _kvm_vcpu_put(struct kvm_vcpu *vcpu, int cpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	kvm_lose_fpu(vcpu);
	kvm_lose_hw_perf(vcpu);

	kvm_save_hw_gcsr(csr, KVM_CSR_CRMD);
	kvm_save_hw_gcsr(csr, KVM_CSR_PRMD);
	kvm_save_hw_gcsr(csr, KVM_CSR_EUEN);
	kvm_save_hw_gcsr(csr, KVM_CSR_MISC);
	kvm_save_hw_gcsr(csr, KVM_CSR_ECFG);
	kvm_save_hw_gcsr(csr, KVM_CSR_ERA);
	kvm_save_hw_gcsr(csr, KVM_CSR_BADV);
	kvm_save_hw_gcsr(csr, KVM_CSR_BADI);
	kvm_save_hw_gcsr(csr, KVM_CSR_EENTRY);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBIDX);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBEHI);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBELO0);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBELO1);
	kvm_save_hw_gcsr(csr, KVM_CSR_ASID);
	kvm_save_hw_gcsr(csr, KVM_CSR_PGDL);
	kvm_save_hw_gcsr(csr, KVM_CSR_PGDH);
	kvm_save_hw_gcsr(csr, KVM_CSR_PGD);
	kvm_save_hw_gcsr(csr, KVM_CSR_PWCTL0);
	kvm_save_hw_gcsr(csr, KVM_CSR_PWCTL1);
	kvm_save_hw_gcsr(csr, KVM_CSR_STLBPGSIZE);
	kvm_save_hw_gcsr(csr, KVM_CSR_RVACFG);
	kvm_save_hw_gcsr(csr, KVM_CSR_CPUID);
	kvm_save_hw_gcsr(csr, KVM_CSR_PRCFG1);
	kvm_save_hw_gcsr(csr, KVM_CSR_PRCFG2);
	kvm_save_hw_gcsr(csr, KVM_CSR_PRCFG3);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS0);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS1);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS2);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS3);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS4);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS5);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS6);
	kvm_save_hw_gcsr(csr, KVM_CSR_KS7);
	kvm_save_hw_gcsr(csr, KVM_CSR_TMID);
	kvm_save_hw_gcsr(csr, KVM_CSR_CNTC);
	kvm_save_hw_gcsr(csr, KVM_CSR_LLBCTL);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBRENTRY);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBRBADV);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBRERA);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBRSAVE);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBRELO0);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBRELO1);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBREHI);
	kvm_save_hw_gcsr(csr, KVM_CSR_TLBRPRMD);
	kvm_save_hw_gcsr(csr, KVM_CSR_DMWIN0);
	kvm_save_hw_gcsr(csr, KVM_CSR_DMWIN1);
	kvm_save_hw_gcsr(csr, KVM_CSR_DMWIN2);
	kvm_save_hw_gcsr(csr, KVM_CSR_DMWIN3);

	/* save Root.Guestexcept in unused Guest guestexcept register */
	kvm_save_timer(vcpu);
	csr->csrs[KVM_CSR_GINTC] = kvm_read_csr_gintc();
	return 0;
}

/* ASID can change if another task is scheduled during preemption */
void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	int cpu;

	local_irq_save(flags);
	cpu = smp_processor_id();
	vcpu->arch.last_sched_cpu = cpu;
	vcpu->cpu = -1;

	/* save guest state in registers */
	_kvm_vcpu_put(vcpu, cpu);
	local_irq_restore(flags);
}

static int _kvm_get_one_reg(struct kvm_vcpu *vcpu,
		const struct kvm_one_reg *reg, s64 *v)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	int reg_idx, ret;

	if ((reg->id & KVM_IOC_CSRID(0)) == KVM_IOC_CSRID(0)) {
		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		ret = _kvm_getcsr(vcpu, reg_idx, v, 0);
		if (ret == 0)
			return ret;
	}

	switch (reg->id) {
	case KVM_REG_LOONGARCH_COUNTER:
		*v = drdtime() + vcpu->kvm->arch.stablecounter_gftoffset;
		break;
	default:
		if ((reg->id & KVM_REG_LOONGARCH_MASK) != KVM_REG_LOONGARCH_CSR)
			return -EINVAL;

		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		if (reg_idx < CSR_ALL_SIZE)
			*v = kvm_read_sw_gcsr(csr, reg_idx);
		else
			return -EINVAL;
	}
	return 0;
}

static int _kvm_set_one_reg(struct kvm_vcpu *vcpu,
		const struct kvm_one_reg *reg,
		s64 v)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	int ret = 0;
	unsigned long flags;
	u64 val;
	int reg_idx;

	val = v;
	if ((reg->id & KVM_IOC_CSRID(0)) == KVM_IOC_CSRID(0)) {
		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		ret = _kvm_setcsr(vcpu, reg_idx, &val, 0);
		if (ret == 0)
			return ret;
	}

	switch (reg->id) {
	case KVM_REG_LOONGARCH_COUNTER:
		local_irq_save(flags);
		/*
		 * gftoffset is relative with board, not vcpu
		 * only set for the first time for smp system
		 */
		if (vcpu->vcpu_id == 0)
			vcpu->kvm->arch.stablecounter_gftoffset = (signed long)(v - drdtime());
		kvm_write_csr_gcntc((ulong)vcpu->kvm->arch.stablecounter_gftoffset);
		local_irq_restore(flags);
		break;
	case KVM_REG_LOONGARCH_VCPU_RESET:
		kvm_reset_timer(vcpu);
		if (vcpu->vcpu_id == 0)
			kvm_setup_ls3a_extirq(vcpu->kvm);
		memset(&vcpu->arch.irq_pending, 0, sizeof(vcpu->arch.irq_pending));
		memset(&vcpu->arch.irq_clear, 0, sizeof(vcpu->arch.irq_clear));

		/* disable pv timer when cpu resetting */
		vcpu->arch.st.guest_addr = 0;
		break;
	default:
		if ((reg->id & KVM_REG_LOONGARCH_MASK) != KVM_REG_LOONGARCH_CSR)
			return -EINVAL;

		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		if (reg_idx < CSR_ALL_SIZE)
			kvm_write_sw_gcsr(csr, reg_idx, v);
		else
			return -EINVAL;
	}
	return ret;
}

static int _kvm_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	int ret;
	s64 v;

	ret = _kvm_get_one_reg(vcpu, reg, &v);
	if (ret)
		return ret;

	ret = -EINVAL;
	if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64) {
		u64 __user *uaddr64 = (u64 __user *)(long)reg->addr;

		ret = put_user(v, uaddr64);
	} else if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32) {
		u32 __user *uaddr32 = (u32 __user *)(long)reg->addr;
		u32 v32 = (u32)v;

		ret = put_user(v32, uaddr32);
	}

	return ret;
}

static int _kvm_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	s64 v;
	int ret;

	ret = -EINVAL;
	if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64) {
		u64 __user *uaddr64 = (u64 __user *)(long)reg->addr;
		ret = get_user(v, uaddr64);
	} else if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32) {
		u32 __user *uaddr32 = (u32 __user *)(long)reg->addr;
		s32 v32;

		ret = get_user(v32, uaddr32);
		v = (s64)v32;
	}

	if (ret)
		return -EFAULT;

	return _kvm_set_one_reg(vcpu, reg, v);
}

static int kvm_vcpu_ioctl_enable_cap(struct kvm_vcpu *vcpu,
				     struct kvm_enable_cap *cap)
{
	int r = 0;

	if (!kvm_vm_ioctl_check_extension(vcpu->kvm, cap->cap))
		return -EINVAL;
	if (cap->flags)
		return -EINVAL;
	if (cap->args[0])
		return -EINVAL;

	switch (cap->cap) {
	case KVM_CAP_LOONGARCH_FPU:
	case KVM_CAP_LOONGARCH_LSX:
		break;
	default:
		r = -EINVAL;
		break;
	}

	return r;
}

long kvm_arch_vcpu_async_ioctl(struct file *filp, unsigned int ioctl,
			       unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;

	if (ioctl == KVM_INTERRUPT) {
		struct kvm_loongarch_interrupt irq;

		if (copy_from_user(&irq, argp, sizeof(irq)))
			return -EFAULT;
		kvm_debug("[%d] %s: irq: %d\n", vcpu->vcpu_id, __func__,
			  irq.irq);

		return kvm_vcpu_ioctl_interrupt(vcpu, &irq);
	}

	return -ENOIOCTLCMD;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level,
			  bool line_status)
{
	u32 irq = irq_level->irq;
	unsigned int irq_type, vcpu_idx, irq_num, ret;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	bool level = irq_level->level;
	unsigned long flags;

	irq_type = (irq >> KVM_LOONGSON_IRQ_TYPE_SHIFT) & KVM_LOONGSON_IRQ_TYPE_MASK;
	vcpu_idx = (irq >> KVM_LOONGSON_IRQ_VCPU_SHIFT) & KVM_LOONGSON_IRQ_VCPU_MASK;
	irq_num = (irq >> KVM_LOONGSON_IRQ_NUM_SHIFT) & KVM_LOONGSON_IRQ_NUM_MASK;

	switch (irq_type) {
	case KVM_LOONGSON_IRQ_TYPE_IOAPIC:
		if (!ls7a_ioapic_in_kernel(kvm))
			return -ENXIO;

		if (vcpu_idx >= nrcpus)
			return -EINVAL;

		ls7a_ioapic_lock(ls7a_ioapic_irqchip(kvm), &flags);
		ret = kvm_ls7a_ioapic_set_irq(kvm, irq_num, level);
		ls7a_ioapic_unlock(ls7a_ioapic_irqchip(kvm), &flags);
		return ret;
	}
	kvm->stat.vm_ioctl_irq_line++;

	return -EINVAL;
}

static int kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct loongarch_kvm_irqchip *chip)
{
	int r, dlen;

	r = 0;
	dlen = chip->len - sizeof(struct loongarch_kvm_irqchip);
	switch (chip->chip_id) {
	case KVM_IRQCHIP_LS7A_IOAPIC:
		if (dlen != sizeof(struct kvm_ls7a_ioapic_state)) {
			kvm_err("get ls7a state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_get_ls7a_ioapic(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_GIPI:
		if (dlen != sizeof(gipiState)) {
			kvm_err("get gipi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_get_ls3a_ipi(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_HT_IRQ:
	case KVM_IRQCHIP_LS3A_ROUTE:
		break;
	case KVM_IRQCHIP_LS3A_EXTIRQ:
		if (dlen != sizeof(struct kvm_loongarch_ls3a_extirq_state)) {
			kvm_err("get extioi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_get_ls3a_extirq(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_IPMASK:
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
dlen_err:
	r = -EINVAL;
	return r;
}

static int kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct loongarch_kvm_irqchip *chip)
{
	int r, dlen;

	r = 0;
	dlen = chip->len - sizeof(struct loongarch_kvm_irqchip);
	switch (chip->chip_id) {
	case KVM_IRQCHIP_LS7A_IOAPIC:
		if (dlen != sizeof(struct kvm_ls7a_ioapic_state)) {
			kvm_err("set ls7a state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_set_ls7a_ioapic(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_GIPI:
		if (dlen != sizeof(gipiState)) {
			kvm_err("set gipi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_set_ls3a_ipi(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_HT_IRQ:
	case KVM_IRQCHIP_LS3A_ROUTE:
		break;
	case KVM_IRQCHIP_LS3A_EXTIRQ:
		if (dlen != sizeof(struct kvm_loongarch_ls3a_extirq_state)) {
			kvm_err("set extioi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_set_ls3a_extirq(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_IPMASK:
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
dlen_err:
	r = -EINVAL;
	return r;
}

/*
 * Read or write a bunch of msrs. All parameters are kernel addresses.
 *
 * @return number of msrs set successfully.
 */
static int _kvm_csr_io(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs,
		struct kvm_csr_entry *entries,
		int (*do_csr)(struct kvm_vcpu *vcpu,
			unsigned index, u64 *data, int force))
{
	int i;

	for (i = 0; i < msrs->ncsrs; ++i)
		if (do_csr(vcpu, entries[i].index, &entries[i].data, 1))
			break;

	return i;
}

static int kvm_csr_io(struct kvm_vcpu *vcpu, struct kvm_msrs __user *user_msrs,
		int (*do_csr)(struct kvm_vcpu *vcpu,
			unsigned index, u64 *data, int force))
{
	struct kvm_msrs msrs;
	struct kvm_csr_entry *entries;
	int r, n;
	unsigned size;

	r = -EFAULT;
	if (copy_from_user(&msrs, user_msrs, sizeof msrs))
		goto out;

	r = -E2BIG;
	if (msrs.ncsrs >= CSR_ALL_SIZE)
		goto out;

	size = sizeof(struct kvm_csr_entry) * msrs.ncsrs;
	entries = memdup_user(user_msrs->entries, size);
	if (IS_ERR(entries)) {
		r = PTR_ERR(entries);
		goto out;
	}

	r = n = _kvm_csr_io(vcpu, &msrs, entries, do_csr);
	if (r < 0)
		goto out_free;

	r = -EFAULT;
	if (copy_to_user(user_msrs->entries, entries, size))
		goto out_free;

	r = n;

out_free:
	kfree(entries);
out:
	return r;
}

static int _kvm_vcpu_set_attr(struct kvm_vcpu *vcpu,
				struct kvm_device_attr *attr)
{
	int ret = -ENXIO;

	switch (attr->group) {
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	case KVM_LARCH_VCPU_PVTIME_CTRL:
		ret = _kvm_pvtime_set_attr(vcpu, attr);
		break;
#endif
	default:
		ret = -ENXIO;
		break;
	}

	return ret;
}

static int _kvm_vcpu_get_attr(struct kvm_vcpu *vcpu,
				struct kvm_device_attr *attr)
{
	int ret = -ENXIO;

	switch (attr->group) {
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	case KVM_LARCH_VCPU_PVTIME_CTRL:
		ret = _kvm_pvtime_get_attr(vcpu, attr);
		break;
#endif
	default:
		ret = -ENXIO;
		break;
	}

	return ret;
}

static int _kvm_vcpu_has_attr(struct kvm_vcpu *vcpu,
				struct kvm_device_attr *attr)
{
	int ret = -ENXIO;

	switch (attr->group) {
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	case KVM_LARCH_VCPU_PVTIME_CTRL:
		ret = _kvm_pvtime_has_attr(vcpu, attr);
		break;
#endif
	default:
		ret = -ENXIO;
		break;
	}

	return ret;
}

long kvm_arch_vcpu_ioctl(struct file *filp, unsigned int ioctl,
			 unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	struct kvm_device_attr attr;
	long r;

	vcpu_load(vcpu);

	switch (ioctl) {
	case KVM_SET_ONE_REG:
	case KVM_GET_ONE_REG: {
		struct kvm_one_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, argp, sizeof(reg)))
			break;
		if (ioctl == KVM_SET_ONE_REG)
			r = _kvm_set_reg(vcpu, &reg);
		else
			r = _kvm_get_reg(vcpu, &reg);
		break;
	}
	case KVM_ENABLE_CAP: {
		struct kvm_enable_cap cap;

		r = -EFAULT;
		if (copy_from_user(&cap, argp, sizeof(cap)))
			break;
		r = kvm_vcpu_ioctl_enable_cap(vcpu, &cap);
		break;
	}
	case KVM_CHECK_EXTENSION: {
		unsigned int ext;
		if (copy_from_user(&ext, argp, sizeof(ext)))
			return -EFAULT;
		switch (ext) {
		case KVM_CAP_LOONGARCH_FPU:
			r = !!cpu_has_fpu;
			break;
		case KVM_CAP_LOONGARCH_LSX:
			r = !!cpu_has_lsx;
			break;
		default:
			break;
		}
		break;
	}

	case KVM_LOONGARCH_GET_VCPU_STATE:
	{
		int i;
		struct  kvm_loongarch_vcpu_state vcpu_state;
		r = -EFAULT;

		vcpu_state.online_vcpus = vcpu->kvm->arch.online_vcpus;
		vcpu_state.is_migrate = 1;
		for (i = 0; i < 4; i++)
			vcpu_state.core_ext_ioisr[i] = vcpu->arch.core_ext_ioisr[i];

		vcpu_state.irq_pending =  vcpu->arch.irq_pending;
		vcpu_state.irq_clear =  vcpu->arch.irq_clear;

		if (copy_to_user(argp, &vcpu_state, sizeof(struct kvm_loongarch_vcpu_state)))
			break;
		r = 0;
		break;
	}

	case KVM_LOONGARCH_SET_VCPU_STATE:
	{
		int i;
		struct  kvm_loongarch_vcpu_state vcpu_state;
		r = -EFAULT;

		if (copy_from_user(&vcpu_state, argp, sizeof(struct kvm_loongarch_vcpu_state)))
			return -EFAULT;

		vcpu->kvm->arch.online_vcpus = vcpu_state.online_vcpus;
		vcpu->kvm->arch.is_migrate = vcpu_state.is_migrate;
		for (i = 0; i < 4; i++)
			 vcpu->arch.core_ext_ioisr[i] = vcpu_state.core_ext_ioisr[i];

		vcpu->arch.irq_pending = vcpu_state.irq_pending;
		vcpu->arch.irq_clear = vcpu_state.irq_clear;
		r = 0;
		break;
	}
	case KVM_GET_MSRS: {
		r = kvm_csr_io(vcpu, argp, _kvm_getcsr);
		break;
	}
	case KVM_SET_MSRS: {
		r = kvm_csr_io(vcpu, argp, _kvm_setcsr);
		break;
	}
	case KVM_SET_DEVICE_ATTR: {
		r = -EFAULT;
		if (copy_from_user(&attr, argp, sizeof(attr)))
			break;
		r = _kvm_vcpu_set_attr(vcpu, &attr);
		break;
	}
	case KVM_GET_DEVICE_ATTR: {
		r = -EFAULT;
		if (copy_from_user(&attr, argp, sizeof(attr)))
			break;
		r = _kvm_vcpu_get_attr(vcpu, &attr);
		break;
	}
	case KVM_HAS_DEVICE_ATTR: {
		r = -EFAULT;
		if (copy_from_user(&attr, argp, sizeof(attr)))
			break;
		r = _kvm_vcpu_has_attr(vcpu, &attr);
		break;
	}
	default:
		r = -ENOIOCTLCMD;
	}

	vcpu_put(vcpu);
	return r;
}

long kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;

	switch (ioctl) {
	case KVM_CREATE_IRQCHIP:
	{
		mutex_lock(&kvm->lock);
		r = -EEXIST;
		if (kvm->arch.v_ioapic)
			goto create_irqchip_unlock;

		r = kvm_create_ls7a_ioapic(kvm);
		if (r < 0)
			goto create_irqchip_unlock;
		r = kvm_create_ls3a_ipi(kvm);
		if (r < 0) {
			mutex_lock(&kvm->slots_lock);
			kvm_destroy_ls7a_ioapic(kvm);
			mutex_unlock(&kvm->slots_lock);
			goto create_irqchip_unlock;
		}
		r = kvm_create_ls3a_ext_irq(kvm);
		if (r < 0) {
			mutex_lock(&kvm->slots_lock);
			kvm_destroy_ls3a_ipi(kvm);
			kvm_destroy_ls7a_ioapic(kvm);
			mutex_unlock(&kvm->slots_lock);
		}
		irqchip_debug_init(kvm);
		/* Write kvm->irq_routing before kvm->arch.vpic.  */
		smp_wmb();
create_irqchip_unlock:
		mutex_unlock(&kvm->lock);
		break;
	}
	case KVM_GET_IRQCHIP: {
		struct loongarch_kvm_irqchip *kchip;
		struct loongarch_kvm_irqchip uchip;
		if (copy_from_user(&uchip, argp, sizeof(struct loongarch_kvm_irqchip)))
			goto out;
		kchip = memdup_user(argp, uchip.len);
		if (IS_ERR(kchip)) {
			r = PTR_ERR(kchip);
			goto out;
		}

		r = -ENXIO;
		if (!ls7a_ioapic_in_kernel(kvm))
			goto get_irqchip_out;
		r = kvm_vm_ioctl_get_irqchip(kvm, kchip);
		if (r)
			goto get_irqchip_out;
		if (copy_to_user(argp, kchip, kchip->len))
			goto get_irqchip_out;
		r = 0;
get_irqchip_out:
		kfree(kchip);
		break;
	}
	case KVM_SET_IRQCHIP: {
		struct loongarch_kvm_irqchip *kchip;
		struct loongarch_kvm_irqchip uchip;
		if (copy_from_user(&uchip, argp, sizeof(struct loongarch_kvm_irqchip)))
			goto out;

		kchip = memdup_user(argp, uchip.len);
		if (IS_ERR(kchip)) {
			r = PTR_ERR(kchip);
			goto out;
		}

		r = -ENXIO;
		if (!ls7a_ioapic_in_kernel(kvm))
			goto set_irqchip_out;
		r = kvm_vm_ioctl_set_irqchip(kvm, kchip);
		if (r)
			goto set_irqchip_out;
		r = 0;
set_irqchip_out:
		kfree(kchip);
		break;
	}
	case KVM_LOONGARCH_GET_IOCSR:
	{
		r = _kvm_get_iocsr(kvm, argp);
		break;
	}
	case KVM_LOONGARCH_SET_IOCSR:
	{
		r = _kvm_set_iocsr(kvm, argp);
		break;
	}
	case KVM_LOONGARCH_SET_CPUCFG:
	{
		r = 0;
		if (copy_from_user(&kvm->arch.cpucfgs, argp, sizeof(struct kvm_cpucfg)))
			r = -EFAULT;
		break;
	}
	case KVM_LOONGARCH_GET_CPUCFG:
	{
		r = 0;
		if (copy_to_user(argp, &kvm->arch.cpucfgs, sizeof(struct kvm_cpucfg)))
		   r = -EFAULT;
		break;
	}
	default:
		r = -ENOIOCTLCMD;
	}
out:

	return r;
}

int kvm_arch_init(void *opaque)
{
	struct kvm_context *context;
	unsigned long vpid_mask;
	int cpu;

	vmcs = alloc_percpu(struct kvm_context);
	if (!vmcs) {
		printk(KERN_ERR "kvm: failed to allocate percpu kvm_context\n");
		return -ENOMEM;
	}

	vpid_mask = kvm_read_csr_gstat();
	vpid_mask = (vpid_mask & KVM_GSTAT_GIDBIT) >> KVM_GSTAT_GIDBIT_SHIFT;
	if (vpid_mask)
		vpid_mask = GENMASK(vpid_mask - 1, 0);

	for_each_possible_cpu(cpu) {
		context = per_cpu_ptr(vmcs, cpu);
		context->gid_mask = vpid_mask;
		context->gid_ver_mask = ~context->gid_mask;
		context->gid_fisrt_ver = context->gid_mask + 1;
		context->vpid_cache = context->gid_mask + 1;
		context->last_vcpu = NULL;
	}

	_kvm_init_fault();
	return 0;
}

void kvm_arch_exit(void)
{
	free_percpu(vmcs);
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
	int i = 0;

	/* no need vcpu_load and vcpu_put */
	fpu->fcsr = vcpu->arch.fpu.fcsr;
	fpu->fcc = vcpu->arch.fpu.fcc;
	for (i = 0; i < NUM_FPU_REGS; i++)
		memcpy(&fpu->fpr[i], &vcpu->arch.fpu.fpr[i], FPU_REG_WIDTH / 64);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	int i = 0;

	/* no need vcpu_load and vcpu_put */
	vcpu->arch.fpu.fcsr = fpu->fcsr;
	vcpu->arch.fpu.fcc = fpu->fcc;
	for (i = 0; i < NUM_FPU_REGS; i++)
		memcpy(&vcpu->arch.fpu.fpr[i], &fpu->fpr[i], FPU_REG_WIDTH / 64);

	return 0;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_ONE_REG:
	case KVM_CAP_ENABLE_CAP:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_SYNC_MMU:
#ifdef CONFIG_HAVE_LS_KVM_MSI
	case KVM_CAP_SIGNAL_MSI:
#endif
	case KVM_CAP_IMMEDIATE_EXIT:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		r = num_online_cpus();
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	case KVM_CAP_MAX_VCPU_ID:
		r = KVM_MAX_VCPU_ID;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	case KVM_CAP_LOONGARCH_FPU:
		/* We don't handle systems with inconsistent cpu_has_fpu */
		r = !!cpu_has_fpu;
		break;
	case KVM_CAP_LOONGARCH_LSX:
		/*
		 * We don't support LSX vector partitioning yet:
		 * 1) It would require explicit support which can't be tested
		 *    yet due to lack of support in current hardware.
		 * 2) It extends the state that would need to be saved/restored
		 *    by e.g. QEMU for migration.
		 *
		 * When vector partitioning hardware becomes available, support
		 * could be added by requiring a flag when enabling
		 * KVM_CAP_LOONGARCH_LSX capability to indicate that userland knows
		 * to save/restore the appropriate extra state.
		 */
		r = cpu_has_lsx;
		break;
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_IOEVENTFD:
		/* we wouldn't be here unless cpu_has_lvz */
		r = 1;
		break;
	case KVM_CAP_LOONGARCH_VZ:
		/* get user defined kvm version */
		r = KVM_LOONGARCH_VERSION;
		break;
	default:
		r = 0;
		break;
	}
	return r;
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return _kvm_pending_timer(vcpu) ||
		kvm_read_hw_gcsr(KVM_CSR_ESTAT) &
			(1 << (KVM_INT_TIMER - KVM_INT_START));
}

int kvm_arch_vcpu_dump_regs(struct kvm_vcpu *vcpu)
{
	int i;
	struct loongarch_csrs *csr;

	if (!vcpu)
		return -1;

	kvm_debug("VCPU Register Dump:\n");
	kvm_debug("\tpc = 0x%08lx\n", vcpu->arch.pc);
	kvm_debug("\texceptions: %08lx\n", vcpu->arch.irq_pending);

	for (i = 0; i < 32; i += 4) {
		kvm_debug("\tgpr%02d: %08lx %08lx %08lx %08lx\n", i,
		       vcpu->arch.gprs[i],
		       vcpu->arch.gprs[i + 1],
		       vcpu->arch.gprs[i + 2], vcpu->arch.gprs[i + 3]);
	}

	csr = vcpu->arch.csr;
	kvm_debug("\tCRMOD: 0x%08llx, exst: 0x%08llx\n",
		  kvm_read_hw_gcsr(KVM_CSR_CRMD),
		  kvm_read_hw_gcsr(KVM_CSR_ESTAT));

	kvm_debug("\tERA: 0x%08llx\n", kvm_read_hw_gcsr(KVM_CSR_ERA));

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu_load(vcpu);

	for (i = 1; i < ARRAY_SIZE(vcpu->arch.gprs); i++)
		vcpu->arch.gprs[i] = regs->gpr[i];
	vcpu->arch.gprs[0] = 0; /* zero is special, and cannot be set. */
	vcpu->arch.pc = regs->pc;

	vcpu_put(vcpu);
	return 0;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu_load(vcpu);

	for (i = 0; i < ARRAY_SIZE(vcpu->arch.gprs); i++)
		regs->gpr[i] = vcpu->arch.gprs[i];

	regs->pc = vcpu->arch.pc;

	vcpu_put(vcpu);
	return 0;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				  struct kvm_translation *tr)
{
	return 0;
}

/* Enable FPU for guest and restore context */
void kvm_own_fpu(struct kvm_vcpu *vcpu)
{
	unsigned long sr;

	preempt_disable();

	sr = kvm_read_hw_gcsr(KVM_CSR_EUEN);

	/*
	 * If LSX state is already live, it is undefined how it interacts with
	 * FR=0 FPU state, and we don't want to hit reserved instruction
	 * exceptions trying to save the LSX state later when CU=1 && FR=1, so
	 * play it safe and save it first.
	 *
	 * In theory we shouldn't ever hit this case since kvm_lose_fpu() should
	 * get called when guest CU1 is set, however we can't trust the guest
	 * not to clobber the status register directly via the commpage.
	 */
	if (cpu_has_lsx && sr & KVM_EUEN_FPEN &&
	    vcpu->arch.aux_inuse & (KVM_LARCH_LSX | KVM_LARCH_LASX))
		kvm_lose_fpu(vcpu);

	/*
	 * Enable FPU for guest
	 * We set FR and FRE according to guest context
	 */
	kvm_set_csr_euen(KVM_EUEN_FPEN);

	/* If guest FPU state not active, restore it now */
	if (!(vcpu->arch.aux_inuse & KVM_LARCH_FPU)) {
		kvm_restore_fpu(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_FPU;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE, KVM_TRACE_AUX_FPU);
	} else {
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_ENABLE, KVM_TRACE_AUX_FPU);
	}

	preempt_enable();
}

#ifdef CONFIG_CPU_HAS_LSX
/* Enable LSX for guest and restore context */
void kvm_own_lsx(struct kvm_vcpu *vcpu)
{
	preempt_disable();

	/*
	 * Enable FP if enabled in guest, since we're restoring FP context
	 * anyway.
	 */
	if (_kvm_guest_has_fpu(&vcpu->arch)) {

		kvm_set_csr_euen(KVM_EUEN_FPEN);
	}

	/* Enable LSX for guest */
	kvm_set_csr_euen(KVM_EUEN_LSXEN);

	switch (vcpu->arch.aux_inuse & (KVM_LARCH_FPU |
			 KVM_LARCH_LSX | KVM_LARCH_LASX)) {
		case KVM_LARCH_FPU:
			/*
			 * Guest FPU state already loaded,
			 * only restore upper LSX state
			 */
			kvm_restore_lsx_upper(vcpu);
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
			trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE,
						KVM_TRACE_AUX_LSX);
			break;
		case 0:
			/* Neither FP or LSX already active,
			 * restore full LSX state
			 */
			kvm_restore_lsx(vcpu);
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
			if (_kvm_guest_has_fpu(&vcpu->arch))
				vcpu->arch.aux_inuse |= KVM_LARCH_FPU;
			trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE,
					KVM_TRACE_AUX_FPU_LSX);
		break;
	default:
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_ENABLE, KVM_TRACE_AUX_LSX);
		break;
	}

	preempt_enable();
}
#endif

#ifdef CONFIG_CPU_HAS_LASX
/* Enable LASX for guest and restore context */
void kvm_own_lasx(struct kvm_vcpu *vcpu)
{
	preempt_disable();

	/*
	 * Enable FP if enabled in guest, since we're restoring FP context
	 * anyway.
	 */
	if (_kvm_guest_has_lsx(&vcpu->arch)) {
		/* Enable LSX for guest */
		kvm_set_csr_euen(KVM_EUEN_LSXEN);
	}

	/*
	 * Enable FPU if enabled in guest, since we're restoring FPU context
	 * anyway. We set FR and FRE according to guest context.
	 */
	if (_kvm_guest_has_fpu(&vcpu->arch)) {
		kvm_set_csr_euen(KVM_EUEN_FPEN);
	}

	/* Enable LASX for guest */
	kvm_set_csr_euen(KVM_EUEN_LASXEN);

	switch (vcpu->arch.aux_inuse & (KVM_LARCH_FPU |
			 KVM_LARCH_LSX | KVM_LARCH_LASX)) {
	case (KVM_LARCH_LSX | KVM_LARCH_FPU):
	case KVM_LARCH_LSX:
		/*
		 * Guest LSX state already loaded, only restore upper LASX state
		 */
		kvm_restore_lasx_upper(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_LASX;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE, KVM_TRACE_AUX_LASX);
		break;
	case KVM_LARCH_FPU:
		/*
		 * Guest FP state already loaded, only restore 64~256 LASX state
		 */
		kvm_restore_lsx_upper(vcpu);
		kvm_restore_lasx_upper(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_LASX;
		if (_kvm_guest_has_lsx(&vcpu->arch))
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE, KVM_TRACE_AUX_LASX);
		break;
	case 0:
		/* Neither FP or LSX already active, restore full LASX state */
		kvm_restore_lasx(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_LASX;
		if (_kvm_guest_has_lsx(&vcpu->arch))
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
		if (_kvm_guest_has_fpu(&vcpu->arch))
			vcpu->arch.aux_inuse |= KVM_LARCH_FPU;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE,
			      KVM_TRACE_AUX_FPU_LSX_LASX);
		break;
	default:
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_ENABLE, KVM_TRACE_AUX_LASX);
		break;
	}

	preempt_enable();
}
#endif

/* Save and disable FPU & LSX & LASX */
void kvm_lose_fpu(struct kvm_vcpu *vcpu)
{
	preempt_disable();
	if (cpu_has_lasx && (vcpu->arch.aux_inuse & KVM_LARCH_LASX)) {

#ifdef CONFIG_CPU_HAS_LASX
		kvm_save_lasx(vcpu);
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_SAVE, KVM_TRACE_AUX_FPU_LSX_LASX);

		/* Disable LASX & MAS & FPU */
		disable_lasx();
		disable_lsx();
#endif

		if (vcpu->arch.aux_inuse & KVM_LARCH_FPU) {
			kvm_clear_csr_euen(KVM_EUEN_FPEN);
		}
		vcpu->arch.aux_inuse &= ~(KVM_LARCH_FPU |
					 KVM_LARCH_LSX | KVM_LARCH_LASX);
	} else if (cpu_has_lsx && vcpu->arch.aux_inuse & KVM_LARCH_LSX) {

#ifdef CONFIG_CPU_HAS_LASX
		kvm_save_lsx(vcpu);
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_SAVE, KVM_TRACE_AUX_FPU_LSX);

		/* Disable LSX & FPU */
		disable_lsx();
#endif

		if (vcpu->arch.aux_inuse & KVM_LARCH_FPU) {
			kvm_clear_csr_euen(KVM_EUEN_FPEN);
		}
		vcpu->arch.aux_inuse &= ~(KVM_LARCH_FPU | KVM_LARCH_LSX);
	} else if (vcpu->arch.aux_inuse & KVM_LARCH_FPU) {

		kvm_save_fpu(vcpu);
		vcpu->arch.aux_inuse &= ~KVM_LARCH_FPU;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_SAVE, KVM_TRACE_AUX_FPU);

		/* Disable FPU */
		kvm_clear_csr_euen(KVM_EUEN_FPEN);
	}
	preempt_enable();
}

void kvm_lose_hw_perf(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.aux_inuse & KVM_LARCH_PERF) {
		struct loongarch_csrs *csr = vcpu->arch.csr;
		/* save guest pmu csr */
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCTRL0);
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCNTR0);
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCTRL1);
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCNTR1);
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCTRL2);
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCNTR2);
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCTRL3);
		kvm_save_hw_gcsr(csr, KVM_CSR_PERFCNTR3);
		if (((kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL0) |
			kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL1) |
			kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL2) |
			kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL3))
			& KVM_PMU_PLV_ENABLE) == 0)
			vcpu->arch.aux_inuse &= ~KVM_LARCH_PERF;
		/* config host pmu csr */
		kvm_write_csr_gcfg(kvm_read_csr_gcfg() & ~KVM_GCFG_GPERF);
		/* TODO: pmu csr used by host and guest at the same time */
		kvm_write_csr_perfctrl0(0);
		kvm_write_csr_perfcntr0(0);
		kvm_write_csr_perfctrl1(0);
		kvm_write_csr_perfcntr1(0);
		kvm_write_csr_perfctrl2(0);
		kvm_write_csr_perfcntr2(0);
		kvm_write_csr_perfctrl3(0);
		kvm_write_csr_perfcntr3(0);
	}
}

void kvm_restore_hw_perf(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.aux_inuse & KVM_LARCH_PERF) {
		struct loongarch_csrs *csr = vcpu->arch.csr;
		/* enable guest pmu */
		kvm_write_csr_gcfg(kvm_read_csr_gcfg() | KVM_GCFG_GPERF);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCTRL0);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCNTR0);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCTRL1);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCNTR1);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCTRL2);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCNTR2);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCTRL3);
		kvm_restore_hw_gcsr(csr, KVM_CSR_PERFCNTR3);
	}
}

static int __init kvm_loongarch_init(void)
{
	int ret;

	if (!cpu_has_lvz)
		return  0;

	ret = kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);

	if (ret)
		return ret;

	return 0;
}

static void __exit kvm_loongarch_exit(void)
{
	kvm_exit();
}

module_init(kvm_loongarch_init);
module_exit(kvm_loongarch_exit);

static const struct cpu_feature loongarch_kvm_feature[] = {
	{ .feature = cpu_feature(LOONGARCH_LVZ) },
	{},
};
MODULE_DEVICE_TABLE(cpu, loongarch_kvm_feature);

EXPORT_TRACEPOINT_SYMBOL(kvm_exit);
