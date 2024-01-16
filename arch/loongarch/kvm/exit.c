// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/cacheops.h>
#include <asm/cmpxchg.h>
#include <asm/fpu.h>
#include <asm/inst.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/time.h>
#include <asm/tlb.h>
#include <asm/numa.h>
#include "kvmcpu.h"
#include <linux/kvm_host.h>
#include "trace.h"
#include "kvm_compat.h"
#include "kvmcsr.h"
#include "intc/ls3a_ext_irq.h"

/*
 * Loongarch KVM callback handling for not implemented guest exiting
 */
static int _kvm_fault_ni(struct kvm_vcpu *vcpu)
{
	unsigned long estat, badv;
	unsigned int exccode, inst;

	/*
	 *  Fetch the instruction.
	 */
	badv = vcpu->arch.badv;
	estat = vcpu->arch.host_estat;
	exccode = (estat & KVM_ESTAT_EXC) >> KVM_ESTAT_EXC_SHIFT;
	inst = vcpu->arch.badi;
	kvm_err("Exccode: %d PC=%#lx inst=0x%08x BadVaddr=%#lx estat=%#llx\n",
		exccode, vcpu->arch.pc, inst, badv, kvm_read_gcsr_estat());
	kvm_arch_vcpu_dump_regs(vcpu);
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	return RESUME_HOST;
}

static int _kvm_handle_csr(struct kvm_vcpu *vcpu, union loongarch_instruction inst)
{
	enum emulation_result er = EMULATE_DONE;
	unsigned int rd, rj, csrid;
	unsigned long csr_mask;
	unsigned long val = 0;

	/*
	 * CSR value mask imm
	 * rj = 0 means csrrd
	 * rj = 1 means csrwr
	 * rj != 0,1 means csrxchg
	 */
	rd = inst.reg2csr_format.rd;
	rj = inst.reg2csr_format.rj;
	csrid = inst.reg2csr_format.csr;

	/* Process CSR ops */
	if (rj == 0) {
		/* process csrrd */
		val = _kvm_emu_read_csr(vcpu, csrid);
		if (er != EMULATE_FAIL)
			vcpu->arch.gprs[rd] = val;
	} else if (rj == 1) {
		/* process csrwr */
		val = vcpu->arch.gprs[rd];
		_kvm_emu_write_csr(vcpu, csrid, val);
	} else {
		/* process csrxchg */
		val = vcpu->arch.gprs[rd];
		csr_mask = vcpu->arch.gprs[rj];
		_kvm_emu_xchg_csr(vcpu, csrid, csr_mask, val);
	}

	return er;
}

static int _kvm_emu_cache(struct kvm_vcpu *vcpu, union loongarch_instruction inst)
{
	return EMULATE_DONE;
}

static int _kvm_trap_handle_gspr(struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	struct kvm_run *run = vcpu->run;
	union loongarch_instruction inst;
	unsigned long curr_pc;
	int rd, rj;
	unsigned int index;

	/*
	 *  Fetch the instruction.
	 */
	inst.word = vcpu->arch.badi;
	curr_pc = vcpu->arch.pc;
	update_pc(&vcpu->arch);

	er = EMULATE_FAIL;
	switch (((inst.word >> 24) & 0xff)) {
	case 0x0:
		/* cpucfg GSPR */
		if (inst.reg2_format.opcode == 0x1B) {
			rd = inst.reg2_format.rd;
			rj = inst.reg2_format.rj;
			++vcpu->stat.cpucfg_exits;
			index = vcpu->arch.gprs[rj];
			vcpu->arch.gprs[rd] = vcpu->kvm->arch.cpucfgs.cpucfg[index];
			if (vcpu->arch.gprs[rd] == 0) {
				/*
				 * Fallback to get host cpucfg info, this is just for
				 * compatible with older qemu.
				 */
				vcpu->arch.gprs[rd] = read_cpucfg(index);
				/* Nested KVM is not supported */
				if (index == 2)
					vcpu->arch.gprs[rd] &= ~CPUCFG2_LVZP;
			}
			er = EMULATE_DONE;
		}
		break;
	case 0x4:
		/* csr GSPR */
		er = _kvm_handle_csr(vcpu, inst);
		break;
	case 0x6:
		/* iocsr,cache,idle GSPR */
		switch (((inst.word >> 22) & 0x3ff)) {
		case 0x18:
			/* cache GSPR */
			er = _kvm_emu_cache(vcpu, inst);
			trace_kvm_exit(vcpu, KVM_TRACE_EXIT_CACHE);
			break;
		case 0x19:
			/* iocsr/idle GSPR */
			switch (((inst.word >> 15) & 0x1ffff)) {
			case 0xc90:
				/* iocsr GSPR */
				er = _kvm_emu_iocsr(inst, run, vcpu);
				break;
			case 0xc91:
				/* idle GSPR */
				er = _kvm_emu_idle(vcpu);
				break;
			default:
				er = EMULATE_FAIL;
				break;
			}
			break;
		default:
			er = EMULATE_FAIL;
			break;
		}
		break;
	default:
		er = EMULATE_FAIL;
		break;
	}

	/* Rollback PC only if emulation was unsuccessful */
	if (er == EMULATE_FAIL) {
		kvm_err("[%#lx]%s: unsupported gspr instruction 0x%08x\n",
			curr_pc, __func__, inst.word);

		kvm_arch_vcpu_dump_regs(vcpu);
		vcpu->arch.pc = curr_pc;
	}
	return er;
}

static int _kvm_check_hypcall(struct kvm_vcpu *vcpu)
{
	enum emulation_result ret;
	union loongarch_instruction inst;
	unsigned long curr_pc;
	unsigned int code;

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */
	inst.word = vcpu->arch.badi;
	code = inst.reg0i15_format.immediate;
	curr_pc = vcpu->arch.pc;
	update_pc(&vcpu->arch);

	ret = EMULATE_DONE;
	switch (code) {
	case KVM_HC_CODE_SERVICE:
		ret = EMULATE_PV_HYPERCALL;
		break;
	case KVM_HC_CODE_SWDBG:
		/*
		 * Only SWDBG(SoftWare DeBug) could stop vm
		 * code other than 0 is ignored.
		 */
		ret = EMULATE_DEBUG;
		break;
	default:
		kvm_info("[%#lx] HYPCALL %#03x unsupported\n", vcpu->arch.pc, code);
		break;
	}

	if (ret == EMULATE_DEBUG)
		vcpu->arch.pc = curr_pc;

	return ret;
}

/* Execute cpucfg instruction will tirggerGSPR,
 * Also the access to unimplemented csrs 0x15
 * 0x16, 0x50~0x53, 0x80, 0x81, 0x90~0x95, 0x98
 * 0xc0~0xff, 0x100~0x109, 0x500~0x502,
 * cache_op, idle_op iocsr ops the same
 */
static int _kvm_handle_gspr(struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	vcpu->arch.is_hypcall = 0;

	er = _kvm_trap_handle_gspr(vcpu);

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		vcpu->run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else if (er == EMULATE_DO_IOCSR) {
		vcpu->run->exit_reason = KVM_EXIT_LOONGARCH_IOCSR;
		ret = RESUME_HOST;
	} else {
		kvm_err("%s internal error\n", __func__);
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

static int _kvm_handle_hypcall(struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	vcpu->arch.is_hypcall = 0;
	er = _kvm_check_hypcall(vcpu);

	if (er == EMULATE_PV_HYPERCALL)
		ret = _kvm_handle_pv_hcall(vcpu);
	else if (er == EMULATE_DEBUG) {
		vcpu->run->exit_reason = KVM_EXIT_DEBUG;
		ret = RESUME_HOST;
	} else
		ret = RESUME_GUEST;

	return ret;
}

static int _kvm_handle_gcm(struct kvm_vcpu *vcpu)
{
	int ret, subcode;

	vcpu->arch.is_hypcall = 0;
	ret = RESUME_GUEST;
	subcode = (vcpu->arch.host_estat & KVM_ESTAT_ESUBCODE) >> KVM_ESTAT_ESUBCODE_SHIFT;
	if ((subcode != EXCSUBCODE_GCSC) && (subcode != EXCSUBCODE_GCHC)) {
		kvm_err("%s internal error\n", __func__);
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}

	return ret;
}

/**
 * _kvm_handle_fpu_disabled() - Guest used fpu however it is disabled at host
 * @vcpu:	Virtual CPU context.
 *
 * Handle when the guest attempts to use fpu which hasn't been allowed
 * by the root context.
 */
static int _kvm_handle_fpu_disabled(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	/*
	 * If guest FPU not present, the FPU operation should have been
	 * treated as a reserved instruction!
	 * If FPU already in use, we shouldn't get this at all.
	 */
	if (WARN_ON(!_kvm_guest_has_fpu(&vcpu->arch) ||
				vcpu->arch.aux_inuse & KVM_LARCH_FPU)) {
		kvm_err("%s internal error\n", __func__);
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		return RESUME_HOST;
	}

	kvm_own_fpu(vcpu);
	return RESUME_GUEST;
}

/**
 * _kvm_handle_lsx_disabled() - Guest used LSX while disabled in root.
 * @vcpu:	Virtual CPU context.
 *
 * Handle when the guest attempts to use LSX when it is disabled in the root
 * context.
 */
static int _kvm_handle_lsx_disabled(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	/*
	 * If LSX not present or not exposed to guest, the LSX operation
	 * should have been treated as a reserved instruction!
	 * If LSX already in use, we shouldn't get this at all.
	 */
	if (!_kvm_guest_has_lsx(&vcpu->arch) ||
	    !(kvm_read_gcsr_euen() & KVM_EUEN_LSXEN) ||
	    vcpu->arch.aux_inuse & KVM_LARCH_LSX) {
		kvm_err("%s internal error, lsx %d guest euen %llx aux %x",
			__func__, _kvm_guest_has_lsx(&vcpu->arch),
			kvm_read_gcsr_euen(), vcpu->arch.aux_inuse);
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		return RESUME_HOST;
	}

#ifdef CONFIG_CPU_HAS_LSX
	kvm_own_lsx(vcpu);
#endif
	return RESUME_GUEST;
}

bool _kvm_guest_has_lasx(struct kvm_vcpu *vcpu)
{
	return cpu_has_lasx && vcpu->arch.lsx_enabled && vcpu->kvm->arch.cpucfg_lasx;
}

/**
 * _kvm_handle_lasx_disabled() - Guest used LASX while disabled in root.
 * @vcpu:	Virtual CPU context.
 *
 * Handle when the guest attempts to use LASX when it is disabled in the root
 * context.
 */
static int _kvm_handle_lasx_disabled(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	/*
	 * If LASX not present or not exposed to guest, the LASX operation
	 * should have been treated as a reserved instruction!
	 * If LASX already in use, we shouldn't get this at all.
	 */
	if (!_kvm_guest_has_lasx(vcpu) ||
	    !(kvm_read_gcsr_euen() & KVM_EUEN_LSXEN) ||
	    !(kvm_read_gcsr_euen() & KVM_EUEN_LASXEN) ||
	    vcpu->arch.aux_inuse & KVM_LARCH_LASX) {
		kvm_err("%s internal error, lasx %d guest euen %llx aux %x",
			__func__, _kvm_guest_has_lasx(vcpu),
			kvm_read_gcsr_euen(), vcpu->arch.aux_inuse);
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		return RESUME_HOST;
	}

#ifdef CONFIG_CPU_HAS_LASX
	kvm_own_lasx(vcpu);
#endif
	return RESUME_GUEST;
}


static int _kvm_handle_read_fault(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	ulong badv = vcpu->arch.badv;
	union loongarch_instruction inst;
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	if (kvm_handle_mm_fault(vcpu, badv, false)) {
		/* A code fetch fault doesn't count as an MMIO */
		if (kvm_is_ifetch_fault(&vcpu->arch)) {
			kvm_err("%s ifetch error addr:%lx\n", __func__, badv);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			return RESUME_HOST;
		}

		/* Treat as MMIO */
		inst.word =  vcpu->arch.badi;
		er = _kvm_emu_mmio_read(vcpu, inst);
		if (er == EMULATE_FAIL) {
			kvm_err("Guest Emulate Load failed: PC: %#lx, BadVaddr: %#lx\n",
				vcpu->arch.pc, badv);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		}
	}

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

static int _kvm_handle_write_fault(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	ulong badv = vcpu->arch.badv;
	union loongarch_instruction inst;
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	if (kvm_handle_mm_fault(vcpu, badv, true)) {

		/* Treat as MMIO */
		inst.word =  vcpu->arch.badi;
		er = _kvm_emu_mmio_write(vcpu, inst);
		if (er == EMULATE_FAIL) {
			kvm_err("Guest Emulate Store failed: PC:  %#lx, BadVaddr: %#lx\n",
				vcpu->arch.pc, badv);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		}
	}

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

static int _kvm_handle_debug(struct kvm_vcpu *vcpu)
{
	uint32_t fwps, mwps;

	fwps = kvm_csr_readq(KVM_CSR_FWPS);
	mwps = kvm_csr_readq(KVM_CSR_MWPS);
	if (fwps & 0xff)
		kvm_csr_writeq(fwps, KVM_CSR_FWPS);
	if (mwps & 0xff)
		kvm_csr_writeq(mwps, KVM_CSR_MWPS);
	vcpu->run->debug.arch.exception = KVM_EXCCODE_WATCH;
	vcpu->run->debug.arch.fwps = fwps;
	vcpu->run->debug.arch.mwps = mwps;
	vcpu->run->exit_reason = KVM_EXIT_DEBUG;
	return RESUME_HOST;
}

static exit_handle_fn _kvm_fault_tables[KVM_INT_START] = {
	[KVM_EXCCODE_TLBL]		= _kvm_handle_read_fault,
	[KVM_EXCCODE_TLBS]		= _kvm_handle_write_fault,
	[KVM_EXCCODE_TLBI]		= _kvm_handle_read_fault,
	[KVM_EXCCODE_TLBM]		= _kvm_handle_write_fault,
	[KVM_EXCCODE_TLBRI]		= _kvm_handle_read_fault,
	[KVM_EXCCODE_TLBXI]		= _kvm_handle_read_fault,
	[KVM_EXCCODE_FPDIS]		= _kvm_handle_fpu_disabled,
	[KVM_EXCCODE_LSXDIS]	= _kvm_handle_lsx_disabled,
	[KVM_EXCCODE_LASXDIS]	= _kvm_handle_lasx_disabled,
	[KVM_EXCCODE_WATCH]		= _kvm_handle_debug,
	[KVM_EXCCODE_GSPR]		= _kvm_handle_gspr,
	[KVM_EXCCODE_HYP]		= _kvm_handle_hypcall,
	[KVM_EXCCODE_GCM]		= _kvm_handle_gcm,
};

int _kvm_handle_fault(struct kvm_vcpu *vcpu, int fault)
{
	return _kvm_fault_tables[fault](vcpu);
}

void _kvm_init_fault(void)
{
	int i;

	for (i = 0; i < KVM_INT_START; i++)
		if (!_kvm_fault_tables[i])
			_kvm_fault_tables[i] = _kvm_fault_ni;
}
