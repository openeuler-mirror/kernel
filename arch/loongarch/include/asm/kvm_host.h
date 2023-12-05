/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef __LOONGARCH_KVM_HOST_H__
#define __LOONGARCH_KVM_HOST_H__

#include <linux/cpumask.h>
#include <linux/mutex.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/kvm.h>
#include <linux/kvm_types.h>
#include <linux/threads.h>
#include <linux/spinlock.h>
#include <asm/inst.h>

/* Loongarch KVM register ids */
#define LOONGARCH_CSR_32(_R, _S)					\
	(KVM_REG_LOONGARCH_CSR | KVM_REG_SIZE_U32 | (8 * (_R) + (_S)))

#define LOONGARCH_CSR_64(_R, _S)					\
	(KVM_REG_LOONGARCH_CSR | KVM_REG_SIZE_U64 | (8 * (_R) + (_S)))

#define KVM_IOC_CSRID(id)	LOONGARCH_CSR_64(id, 0)
#define KVM_GET_IOC_CSRIDX(id)	((id & KVM_CSR_IDX_MASK) >> 3)

#define LOONGSON_VIRT_REG_BASE	0x1f000000
#define KVM_MAX_VCPUS		256
#define KVM_USER_MEM_SLOTS	256
/* memory slots that does not exposed to userspace */
#define KVM_PRIVATE_MEM_SLOTS	0

#define KVM_HALT_POLL_NS_DEFAULT 500000

#define KVM_REQ_RECORD_STEAL	KVM_ARCH_REQ(1)
#define KVM_INVALID_ADDR		0xdeadbeef
#define KVM_HVA_ERR_BAD			(-1UL)
#define KVM_HVA_ERR_RO_BAD		(-2UL)
static inline bool kvm_is_error_hva(unsigned long addr)
{
	return IS_ERR_VALUE(addr);
}

struct kvm_vm_stat {
	ulong remote_tlb_flush;
	u64 vm_ioctl_irq_line;
	u64 ls7a_ioapic_update;
	u64 ls7a_ioapic_set_irq;
	u64 ioapic_reg_write;
	u64 ioapic_reg_read;
	u64 set_ls7a_ioapic;
	u64 get_ls7a_ioapic;
	u64 set_ls3a_ext_irq;
	u64 get_ls3a_ext_irq;
	u64 trigger_ls3a_ext_irq;
	u64 pip_read_exits;
	u64 pip_write_exits;
	u64 ls7a_msi_irq;
};
struct kvm_vcpu_stat {
	u64 excep_exits[EXCCODE_INT_START];
	u64 idle_exits;
	u64 signal_exits;
	u64 int_exits;
	u64 rdcsr_cpu_feature_exits;
	u64 rdcsr_misc_func_exits;
	u64 rdcsr_ipi_access_exits;
	u64 cpucfg_exits;
	u64 huge_dec_exits;
	u64 huge_thp_exits;
	u64 huge_adjust_exits;
	u64 huge_set_exits;
	u64 huge_merge_exits;
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
};

#define KVM_MEMSLOT_DISABLE_THP		(1UL << 17)
struct kvm_arch_memory_slot {
	unsigned int flags;
};

enum {
	IOCSR_FEATURES,
	IOCSR_VENDOR,
	IOCSR_CPUNAME,
	IOCSR_NODECNT,
	IOCSR_MISC_FUNC,
	IOCSR_MAX
};

struct kvm_context {
	unsigned long gid_mask;
	unsigned long gid_ver_mask;
	unsigned long gid_fisrt_ver;
	unsigned long vpid_cache;
	struct kvm_vcpu *last_vcpu;
};

struct kvm_arch {
	/* Guest physical mm */
	struct mm_struct gpa_mm;
	/* Mask of CPUs needing GPA ASID flush */
	cpumask_t asid_flush_mask;

	unsigned char online_vcpus;
	unsigned char is_migrate;
	s64 stablecounter_gftoffset;
	u32 cpucfg_lasx;
	struct ls7a_kvm_ioapic *v_ioapic;
	struct ls3a_kvm_ipi *v_gipi;
	struct ls3a_kvm_routerirq *v_routerirq;
	struct ls3a_kvm_extirq *v_extirq;
	spinlock_t iocsr_lock;
	struct kvm_iocsr_entry iocsr[IOCSR_MAX];
	struct kvm_cpucfg cpucfgs;
	struct kvm_context __percpu *vmcs;
};


#define LOONGARCH_CSRS	0x100
#define CSR_UCWIN_BASE	0x100
#define CSR_UCWIN_SIZE	0x10
#define CSR_DMWIN_BASE	0x180
#define CSR_DMWIN_SIZE	0x4
#define CSR_PERF_BASE	0x200
#define CSR_PERF_SIZE	0x8
#define CSR_DEBUG_BASE	0x500
#define CSR_DEBUG_SIZE	0x3
#define CSR_ALL_SIZE	0x800

struct loongarch_csrs {
	unsigned long csrs[CSR_ALL_SIZE];
};

/* Resume Flags */
#define RESUME_FLAG_DR		(1<<0)	/* Reload guest nonvolatile state? */
#define RESUME_FLAG_HOST	(1<<1)	/* Resume host? */

#define RESUME_GUEST		0
#define RESUME_GUEST_DR		RESUME_FLAG_DR
#define RESUME_HOST		RESUME_FLAG_HOST

enum emulation_result {
	EMULATE_DONE,		/* no further processing */
	EMULATE_DO_MMIO,	/* kvm_run filled with MMIO request */
	EMULATE_FAIL,		/* can't emulate this instruction */
	EMULATE_WAIT,		/* WAIT instruction */
	EMULATE_PRIV_FAIL,
	EMULATE_EXCEPT,		/* A guest exception has been generated */
	EMULATE_PV_HYPERCALL,	/* HYPCALL instruction */
	EMULATE_DEBUG,		/* Emulate guest kernel debug */
	EMULATE_DO_IOCSR,	/* handle IOCSR request */
};

#define KVM_LARCH_FPU		(0x1 << 0)
#define KVM_LARCH_LSX		(0x1 << 1)
#define KVM_LARCH_LASX		(0x1 << 2)
#define KVM_LARCH_DATA_HWBP	(0x1 << 3)
#define KVM_LARCH_INST_HWBP	(0x1 << 4)
#define KVM_LARCH_HWBP		(KVM_LARCH_DATA_HWBP | KVM_LARCH_INST_HWBP)
#define KVM_LARCH_RESET		(0x1 << 5)
#define KVM_LARCH_PERF		(0x1 << 6)

struct kvm_vcpu_arch {
	unsigned long guest_eentry;
	unsigned long host_eentry;
	int (*vcpu_run)(struct kvm_run *run, struct kvm_vcpu *vcpu);
	int (*handle_exit)(struct kvm_run *run, struct kvm_vcpu *vcpu);

	/* Host registers preserved across guest mode execution */
	unsigned long host_stack;
	unsigned long host_gp;
	unsigned long host_pgd;
	unsigned long host_pgdhi;
	unsigned long host_entryhi;

	/* Host CSR registers used when handling exits from guest */
	unsigned long badv;
	unsigned long host_estat;
	unsigned long badi;
	unsigned long host_ecfg;
	unsigned long host_percpu;

	u32 is_hypcall;
	/* GPRS */
	unsigned long gprs[32];
	unsigned long pc;

	/* FPU State */
	struct loongarch_fpu fpu FPU_ALIGN;
	/* Which auxiliary state is loaded (KVM_LOONGARCH_AUX_*) */
	unsigned int aux_inuse;

	/* CSR State */
	struct loongarch_csrs *csr;

	/* GPR used as IO source/target */
	u32 io_gpr;

	struct hrtimer swtimer;
	/* Count timer control KVM register */
	u32 count_ctl;

	/* Bitmask of exceptions that are pending */
	unsigned long irq_pending;
	/* Bitmask of pending exceptions to be cleared */
	unsigned long irq_clear;

	/* Cache some mmu pages needed inside spinlock regions */
	struct kvm_mmu_memory_cache mmu_page_cache;

	/* vcpu's vpid is different on each host cpu in an smp system */
	u64 vpid[NR_CPUS];

	/* Frequency of stable timer in Hz */
	u64 timer_mhz;
	ktime_t expire;

	u64 core_ext_ioisr[4];

	/* Last CPU the VCPU state was loaded on */
	int last_sched_cpu;
	/* Last CPU the VCPU actually executed guest code on */
	int last_exec_cpu;

	u8 fpu_enabled;
	u8 lsx_enabled;
	/* paravirt steal time */
	struct {
		u64 guest_addr;
		u64 last_steal;
		struct gfn_to_pfn_cache cache;
	} st;
	struct kvm_guest_debug_arch guest_debug;
	/* save host pmu csr */
	u64 perf_ctrl[4];
	u64 perf_cntr[4];

	int blocking;
};

static inline unsigned long readl_sw_gcsr(struct loongarch_csrs *csr, int reg)
{
	return csr->csrs[reg];
}

static inline void writel_sw_gcsr(struct loongarch_csrs *csr, int reg,
		unsigned long val)
{
	csr->csrs[reg] = val;
}

/* Helpers */
static inline bool _kvm_guest_has_fpu(struct kvm_vcpu_arch *arch)
{
	return cpu_has_fpu && arch->fpu_enabled;
}


static inline bool _kvm_guest_has_lsx(struct kvm_vcpu_arch *arch)
{
	return cpu_has_lsx && arch->lsx_enabled;
}

bool _kvm_guest_has_lasx(struct kvm_vcpu *vcpu);
void _kvm_init_fault(void);

/* Debug: dump vcpu state */
int kvm_arch_vcpu_dump_regs(struct kvm_vcpu *vcpu);

/* MMU handling */
int kvm_handle_mm_fault(struct kvm_vcpu *vcpu, unsigned long badv, bool write);
void kvm_flush_tlb_all(void);
void _kvm_destroy_mm(struct kvm *kvm);
pgd_t *kvm_pgd_alloc(void);
void kvm_mmu_free_memory_caches(struct kvm_vcpu *vcpu);

enum _kvm_fault_result {
	KVM_LOONGARCH_MAPPED = 0,
	KVM_LOONGARCH_GVA,
	KVM_LOONGARCH_GPA,
	KVM_LOONGARCH_TLB,
	KVM_LOONGARCH_TLBINV,
	KVM_LOONGARCH_TLBMOD,
};

#define KVM_ARCH_WANT_MMU_NOTIFIER
int kvm_unmap_hva_range(struct kvm *kvm,
			unsigned long start, unsigned long end, bool blockable);
int kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte);
int kvm_age_hva(struct kvm *kvm, unsigned long start, unsigned long end);
int kvm_test_age_hva(struct kvm *kvm, unsigned long hva);

static inline void update_pc(struct kvm_vcpu_arch *arch)
{
	arch->pc += 4;
}

/**
 * kvm_is_ifetch_fault() - Find whether a TLBL exception is due to ifetch fault.
 * @vcpu:	Virtual CPU.
 *
 * Returns:	Whether the TLBL exception was likely due to an instruction
 *		fetch fault rather than a data load fault.
 */
static inline bool kvm_is_ifetch_fault(struct kvm_vcpu_arch *arch)
{
	if (arch->pc == arch->badv)
		return true;

	return false;
}

/* Misc */
static inline void kvm_arch_hardware_unsetup(void) {}
static inline void kvm_arch_sync_events(struct kvm *kvm) {}
static inline void kvm_arch_free_memslot(struct kvm *kvm,
		struct kvm_memory_slot *slot) {}
static inline void kvm_arch_memslots_updated(struct kvm *kvm, u64 gen) {}
static inline void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu) {}
static inline void kvm_arch_vcpu_block_finish(struct kvm_vcpu *vcpu) {}

extern int kvm_enter_guest(struct kvm_run *run, struct kvm_vcpu *vcpu);
extern void kvm_exception_entry(void);
#endif /* __LOONGARCH_KVM_HOST_H__ */
