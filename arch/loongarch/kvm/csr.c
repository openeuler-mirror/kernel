// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/kvm_host.h>
#include <asm/inst.h>
#include <asm/numa.h>
#include "kvmcpu.h"
#include "intc/ls3a_ipi.h"
#include "intc/ls3a_ext_irq.h"
#include "kvm_compat.h"
#include "kvmcsr.h"
#include "irq.h"

unsigned long _kvm_emu_read_csr(struct kvm_vcpu *vcpu, int csrid)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	unsigned long val = 0;

	switch (csrid) {
	case KVM_CSR_ERRCTL:
		return kvm_read_sw_gcsr(csr, KVM_CSR_ERRCTL);
	case KVM_CSR_ERRINFO1:
		return kvm_read_sw_gcsr(csr, KVM_CSR_ERRINFO1);
	case KVM_CSR_ERRINFO2:
		return kvm_read_sw_gcsr(csr, KVM_CSR_ERRINFO2);
	case KVM_CSR_MERRENTRY:
		return kvm_read_sw_gcsr(csr, KVM_CSR_MERRENTRY);
	case KVM_CSR_MERRERA:
		return kvm_read_sw_gcsr(csr, KVM_CSR_MERRERA);
	case KVM_CSR_ERRSAVE:
		return kvm_read_sw_gcsr(csr, KVM_CSR_ERRSAVE);
	/* read sw csr when not config pmu to guest */
	case KVM_CSR_PERFCTRL0:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL0);
	case KVM_CSR_PERFCTRL1:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL1);
	case KVM_CSR_PERFCTRL2:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL2);
	case KVM_CSR_PERFCTRL3:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCTRL3);
	case KVM_CSR_PERFCNTR0:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCNTR0);
	case KVM_CSR_PERFCNTR1:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCNTR1);
	case KVM_CSR_PERFCNTR2:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCNTR2);
	case KVM_CSR_PERFCNTR3:
		return kvm_read_sw_gcsr(csr, KVM_CSR_PERFCNTR3);
	default:
		break;
	}

	val = 0;
	if (csrid < 4096)
		val = kvm_read_sw_gcsr(csr, csrid);
	else
		pr_warn_once("Unsupport csrread 0x%x with pc %lx\n",
			csrid, vcpu->arch.pc);
	return val;
}

void _kvm_emu_write_csr(struct kvm_vcpu *vcpu, int csrid,
	unsigned long val)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	switch (csrid) {
	case KVM_CSR_ERRCTL:
		return kvm_write_sw_gcsr(csr, KVM_CSR_ERRCTL, val);
	case KVM_CSR_ERRINFO1:
		return kvm_write_sw_gcsr(csr, KVM_CSR_ERRINFO1, val);
	case KVM_CSR_ERRINFO2:
		return kvm_write_sw_gcsr(csr, KVM_CSR_ERRINFO2, val);
	case KVM_CSR_MERRENTRY:
		return kvm_write_sw_gcsr(csr, KVM_CSR_MERRENTRY, val);
	case KVM_CSR_MERRERA:
		return kvm_write_sw_gcsr(csr, KVM_CSR_MERRERA, val);
	case KVM_CSR_ERRSAVE:
		return kvm_write_sw_gcsr(csr, KVM_CSR_ERRSAVE, val);
	default:
		break;
	}

	/* give pmu register to guest when config perfctrl */
	switch (csrid) {
	case KVM_CSR_PERFCTRL0:
		if (val & KVM_PMU_PLV_ENABLE) {
			kvm_write_csr_gcfg(kvm_read_csr_gcfg() | KVM_GCFG_GPERF);
			kvm_write_hw_gcsr(csr, KVM_CSR_PERFCTRL0, val | KVM_PERFCTRL_GMOD);
			vcpu->arch.aux_inuse |= KVM_LARCH_PERF;
		} else {
			kvm_write_sw_gcsr(csr, KVM_CSR_PERFCTRL0, val);
		}
		return;
	case KVM_CSR_PERFCTRL1:
		if (val & KVM_PMU_PLV_ENABLE) {
			kvm_write_csr_gcfg(kvm_read_csr_gcfg() | KVM_GCFG_GPERF);
			kvm_write_hw_gcsr(csr, KVM_CSR_PERFCTRL1, val | KVM_PERFCTRL_GMOD);
			vcpu->arch.aux_inuse |= KVM_LARCH_PERF;
		} else {
			kvm_write_sw_gcsr(csr, KVM_CSR_PERFCTRL1, val);
		}
		return;
	case KVM_CSR_PERFCTRL2:
		if (val & KVM_PMU_PLV_ENABLE) {
			kvm_write_csr_gcfg(kvm_read_csr_gcfg() | KVM_GCFG_GPERF);
			kvm_write_hw_gcsr(csr, KVM_CSR_PERFCTRL2, val | KVM_PERFCTRL_GMOD);
			vcpu->arch.aux_inuse |= KVM_LARCH_PERF;
		} else {
			kvm_write_sw_gcsr(csr, KVM_CSR_PERFCTRL2, val);
		}
		return;
	case KVM_CSR_PERFCTRL3:
		if (val & KVM_PMU_PLV_ENABLE) {
			kvm_write_csr_gcfg(kvm_read_csr_gcfg() | KVM_GCFG_GPERF);
			kvm_write_hw_gcsr(csr, KVM_CSR_PERFCTRL3, val | KVM_PERFCTRL_GMOD);
			vcpu->arch.aux_inuse |= KVM_LARCH_PERF;
		} else {
			kvm_write_sw_gcsr(csr, KVM_CSR_PERFCTRL3, val);
		}
		return;
	default:
		break;
	}

	/* write sw pmu csr if not config ctrl */
	switch (csrid) {
	case KVM_CSR_PERFCNTR0:
		return kvm_write_sw_gcsr(csr, KVM_CSR_PERFCNTR0, val);
	case KVM_CSR_PERFCNTR1:
		return kvm_write_sw_gcsr(csr, KVM_CSR_PERFCNTR1, val);
	case KVM_CSR_PERFCNTR2:
		return kvm_write_sw_gcsr(csr, KVM_CSR_PERFCNTR2, val);
	case KVM_CSR_PERFCNTR3:
		return kvm_write_sw_gcsr(csr, KVM_CSR_PERFCNTR3, val);
	default:
		break;
	}

	if (csrid < 4096)
		kvm_write_sw_gcsr(csr, csrid, val);
	else
		pr_warn_once("Unsupport csrwrite 0x%x with pc %lx\n",
				csrid, vcpu->arch.pc);
}

void _kvm_emu_xchg_csr(struct kvm_vcpu *vcpu, int csrid,
	unsigned long csr_mask, unsigned long val)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	switch (csrid) {
	case KVM_CSR_IMPCTL1:
		return kvm_change_sw_gcsr(csr, KVM_CSR_IMPCTL1, csr_mask, val);
	case KVM_CSR_ERRCTL:
		return kvm_change_sw_gcsr(csr, KVM_CSR_ERRCTL, csr_mask, val);
	case KVM_CSR_ERRINFO1:
		return kvm_change_sw_gcsr(csr, KVM_CSR_ERRINFO1, csr_mask, val);
	case KVM_CSR_ERRINFO2:
		return kvm_change_sw_gcsr(csr, KVM_CSR_ERRINFO2, csr_mask, val);
	case KVM_CSR_MERRENTRY:
		return kvm_change_sw_gcsr(csr, KVM_CSR_MERRENTRY, csr_mask, val);
	case KVM_CSR_MERRERA:
		return kvm_change_sw_gcsr(csr, KVM_CSR_MERRERA, csr_mask, val);
	case KVM_CSR_ERRSAVE:
		return kvm_change_sw_gcsr(csr, KVM_CSR_ERRSAVE, csr_mask, val);
	default:
		break;
	}

	if (csrid < 4096) {
		unsigned long orig;

		orig = kvm_read_sw_gcsr(csr, csrid);
		orig &= ~csr_mask;
		orig |= val & csr_mask;
		kvm_write_sw_gcsr(csr, csrid, orig);
	}
	pr_warn_once("Unsupport csrxchg 0x%x with pc %lx\n",
				csrid, vcpu->arch.pc);
}

int _kvm_getcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	switch (id) {
	case KVM_CSR_CRMD:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_CRMD);
		return 0;
	case KVM_CSR_PRMD:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PRMD);
		return 0;
	case KVM_CSR_EUEN:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_EUEN);
		return 0;
	case KVM_CSR_MISC:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_MISC);
		return 0;
	case KVM_CSR_ECFG:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_ECFG);
		return 0;
	case KVM_CSR_ESTAT:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_ESTAT);
		return 0;
	case KVM_CSR_ERA:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_ERA);
		return 0;
	case KVM_CSR_BADV:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_BADV);
		return 0;
	case KVM_CSR_BADI:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_BADI);
		return 0;
	case KVM_CSR_EENTRY:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_EENTRY);
		return 0;
	case KVM_CSR_TLBIDX:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBIDX);
		return 0;
	case KVM_CSR_TLBEHI:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBEHI);
		return 0;
	case KVM_CSR_TLBELO0:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBELO0);
		return 0;
	case KVM_CSR_TLBELO1:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBELO1);
		return 0;
	case KVM_CSR_ASID:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_ASID);
		return 0;
	case KVM_CSR_PGDL:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PGDL);
		return 0;
	case KVM_CSR_PGDH:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PGDH);
		return 0;
	case KVM_CSR_PWCTL0:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PWCTL0);
		return 0;
	case KVM_CSR_PWCTL1:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PWCTL1);
		return 0;
	case KVM_CSR_STLBPGSIZE:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_STLBPGSIZE);
		return 0;
	case KVM_CSR_RVACFG:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_RVACFG);
		return 0;
	case KVM_CSR_CPUID:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_CPUID);
		return 0;
	case KVM_CSR_PRCFG1:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PRCFG1);
		return 0;
	case KVM_CSR_PRCFG2:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PRCFG2);
		return 0;
	case KVM_CSR_PRCFG3:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_PRCFG3);
		return 0;
	case KVM_CSR_KS0:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS0);
		return 0;
	case KVM_CSR_KS1:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS1);
		return 0;
	case KVM_CSR_KS2:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS2);
		return 0;
	case KVM_CSR_KS3:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS3);
		return 0;
	case KVM_CSR_KS4:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS4);
		return 0;
	case KVM_CSR_KS5:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS5);
		return 0;
	case KVM_CSR_KS6:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS6);
		return 0;
	case KVM_CSR_KS7:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_KS7);
		return 0;
	case KVM_CSR_TMID:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TMID);
		return 0;
	case KVM_CSR_TCFG:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TCFG);
		return 0;
	case KVM_CSR_TVAL:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TVAL);
		return 0;
	case KVM_CSR_CNTC:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_CNTC);
		return 0;
	case KVM_CSR_LLBCTL:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_LLBCTL);
		return 0;
	case KVM_CSR_TLBRENTRY:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBRENTRY);
		return 0;
	case KVM_CSR_TLBRBADV:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBRBADV);
		return 0;
	case KVM_CSR_TLBRERA:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBRERA);
		return 0;
	case KVM_CSR_TLBRSAVE:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBRSAVE);
		return 0;
	case KVM_CSR_TLBRELO0:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBRELO0);
		return 0;
	case KVM_CSR_TLBRELO1:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBRELO1);
		return 0;
	case KVM_CSR_TLBREHI:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBREHI);
		return 0;
	case KVM_CSR_TLBRPRMD:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_TLBRPRMD);
		return 0;
	case KVM_CSR_DMWIN0:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_DMWIN0);
		return 0;
	case KVM_CSR_DMWIN1:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_DMWIN1);
		return 0;
	case KVM_CSR_DMWIN2:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_DMWIN2);
		return 0;
	case KVM_CSR_DMWIN3:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_DMWIN3);
		return 0;
	case KVM_CSR_MWPS:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_MWPS);
		return 0;
	case KVM_CSR_FWPS:
		*v = (long)kvm_read_hw_gcsr(KVM_CSR_FWPS);
		return 0;
	default:
		break;
	}

	switch (id) {
	case KVM_CSR_IMPCTL1:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_IMPCTL1);
		return 0;
	case KVM_CSR_IMPCTL2:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_IMPCTL2);
		return 0;
	case KVM_CSR_ERRCTL:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_ERRCTL);
		return 0;
	case KVM_CSR_ERRINFO1:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_ERRINFO1);
		return 0;
	case KVM_CSR_ERRINFO2:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_ERRINFO2);
		return 0;
	case KVM_CSR_MERRENTRY:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_MERRENTRY);
		return 0;
	case KVM_CSR_MERRERA:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_MERRERA);
		return 0;
	case KVM_CSR_ERRSAVE:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_ERRSAVE);
		return 0;
	case KVM_CSR_CTAG:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_CTAG);
		return 0;
	case KVM_CSR_DEBUG:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_DEBUG);
		return 0;
	case KVM_CSR_DERA:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_DERA);
		return 0;
	case KVM_CSR_DESAVE:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_DESAVE);
		return 0;
	case KVM_CSR_TINTCLR:
		*v = kvm_read_sw_gcsr(csr, KVM_CSR_TINTCLR);
		return 0;
	}

	if (force && (id < CSR_ALL_SIZE)) {
		*v = kvm_read_sw_gcsr(csr, id);
		return 0;
	}

	return -1;
}

int _kvm_setcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	int ret;

	switch (id) {
	case KVM_CSR_CRMD:
		kvm_write_hw_gcsr(csr, KVM_CSR_CRMD, *v);
		return 0;
	case KVM_CSR_PRMD:
		kvm_write_hw_gcsr(csr, KVM_CSR_PRMD, *v);
		return 0;
	case KVM_CSR_EUEN:
		kvm_write_hw_gcsr(csr, KVM_CSR_EUEN, *v);
		return 0;
	case KVM_CSR_MISC:
		kvm_write_hw_gcsr(csr, KVM_CSR_MISC, *v);
		return 0;
	case KVM_CSR_ECFG:
		kvm_write_hw_gcsr(csr, KVM_CSR_ECFG, *v);
		return 0;
	case KVM_CSR_ESTAT:
		kvm_write_hw_gcsr(csr, KVM_CSR_ESTAT, *v);
		return 0;
	case KVM_CSR_ERA:
		kvm_write_hw_gcsr(csr, KVM_CSR_ERA, *v);
		return 0;
	case KVM_CSR_BADV:
		kvm_write_hw_gcsr(csr, KVM_CSR_BADV, *v);
		return 0;
	case KVM_CSR_BADI:
		kvm_write_hw_gcsr(csr, KVM_CSR_BADI, *v);
		return 0;
	case KVM_CSR_EENTRY:
		kvm_write_hw_gcsr(csr, KVM_CSR_EENTRY, *v);
		return 0;
	case KVM_CSR_TLBIDX:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBIDX, *v);
		return 0k;
	case KVM_CSR_TLBEHI:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBEHI, *v);
		return 0;
	case KVM_CSR_TLBELO0:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBELO0, *v);
		return 0;
	case KVM_CSR_TLBELO1:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBELO1, *v);
		return 0;
	case KVM_CSR_ASID:
		kvm_write_hw_gcsr(csr, KVM_CSR_ASID, *v);
		return 0;
	case KVM_CSR_PGDL:
		kvm_write_hw_gcsr(csr, KVM_CSR_PGDL, *v);
		return 0;
	case KVM_CSR_PGDH:
		kvm_write_hw_gcsr(csr, KVM_CSR_PGDH, *v);
		return 0;
	case KVM_CSR_PWCTL0:
		kvm_write_hw_gcsr(csr, KVM_CSR_PWCTL0, *v);
		return 0;
	case KVM_CSR_PWCTL1:
		kvm_write_hw_gcsr(csr, KVM_CSR_PWCTL1, *v);
		return 0;
	case KVM_CSR_STLBPGSIZE:
		kvm_write_hw_gcsr(csr, KVM_CSR_STLBPGSIZE, *v);
		return 0;
	case KVM_CSR_RVACFG:
		kvm_write_hw_gcsr(csr, KVM_CSR_RVACFG, *v);
		return 0;
	case KVM_CSR_CPUID:
		kvm_write_hw_gcsr(csr, KVM_CSR_CPUID, *v);
		return 0;
	case KVM_CSR_PRCFG1:
		kvm_write_hw_gcsr(csr, KVM_CSR_PRCFG1, *v);
		return 0;
	case KVM_CSR_PRCFG2:
		kvm_write_hw_gcsr(csr, KVM_CSR_PRCFG2, *v);
		return 0;
	case KVM_CSR_PRCFG3:
		kvm_write_hw_gcsr(csr, KVM_CSR_PRCFG3, *v);
		return 0;
	case KVM_CSR_KS0:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS0, *v);
		return 0;
	case KVM_CSR_KS1:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS1, *v);
		return 0;
	case KVM_CSR_KS2:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS2, *v);
		return 0;
	case KVM_CSR_KS3:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS3, *v);
		return 0;
	case KVM_CSR_KS4:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS4, *v);
		return 0;
	case KVM_CSR_KS5:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS5, *v);
		return 0;
	case KVM_CSR_KS6:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS6, *v);
		return 0;
	case KVM_CSR_KS7:
		kvm_write_hw_gcsr(csr, KVM_CSR_KS7, *v);
		return 0;
	case KVM_CSR_TMID:
		kvm_write_hw_gcsr(csr, KVM_CSR_TMID, *v);
		return 0;
	case KVM_CSR_TCFG:
		kvm_write_hw_gcsr(csr, KVM_CSR_TCFG, *v);
		return 0;
	case KVM_CSR_TVAL:
		kvm_write_hw_gcsr(csr, KVM_CSR_TVAL, *v);
		return 0;
	case KVM_CSR_CNTC:
		kvm_write_hw_gcsr(csr, KVM_CSR_CNTC, *v);
		return 0;
	case KVM_CSR_LLBCTL:
		kvm_write_hw_gcsr(csr, KVM_CSR_LLBCTL, *v);
		return 0;
	case KVM_CSR_TLBRENTRY:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBRENTRY, *v);
		return 0;
	case KVM_CSR_TLBRBADV:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBRBADV, *v);
		return 0;
	case KVM_CSR_TLBRERA:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBRERA, *v);
		return 0;
	case KVM_CSR_TLBRSAVE:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBRSAVE, *v);
		return 0;
	case KVM_CSR_TLBRELO0:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBRELO0, *v);
		return 0;
	case KVM_CSR_TLBRELO1:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBRELO1, *v);
		return 0;
	case KVM_CSR_TLBREHI:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBREHI, *v);
		return 0;
	case KVM_CSR_TLBRPRMD:
		kvm_write_hw_gcsr(csr, KVM_CSR_TLBRPRMD, *v);
		return 0;
	case KVM_CSR_DMWIN0:
		kvm_write_hw_gcsr(csr, KVM_CSR_DMWIN0, *v);
		return 0;
	case KVM_CSR_DMWIN1:
		kvm_write_hw_gcsr(csr, KVM_CSR_DMWIN1, *v);
		return 0;
	case KVM_CSR_DMWIN2:
		kvm_write_hw_gcsr(csr, KVM_CSR_DMWIN2, *v);
		return 0;
	case KVM_CSR_DMWIN3:
		kvm_write_hw_gcsr(csr, KVM_CSR_DMWIN3, *v);
		return 0;
	case KVM_CSR_MWPS:
		kvm_write_hw_gcsr(csr, KVM_CSR_MWPS, *v);
		return 0;
	case KVM_CSR_FWPS:
		kvm_write_hw_gcsr(csr, KVM_CSR_FWPS, *v);
		return 0;
	default:
		break;
	}

	switch (id) {
	case KVM_CSR_IMPCTL1:
		kvm_write_sw_gcsr(csr, KVM_CSR_IMPCTL1, *v);
		return 0;
	case KVM_CSR_IMPCTL2:
		kvm_write_sw_gcsr(csr, KVM_CSR_IMPCTL2, *v);
		return 0;
	case KVM_CSR_ERRCTL:
		kvm_write_sw_gcsr(csr, KVM_CSR_ERRCTL, *v);
		return 0;
	case KVM_CSR_ERRINFO1:
		kvm_write_sw_gcsr(csr, KVM_CSR_ERRINFO1, *v);
		return 0;
	case KVM_CSR_ERRINFO2:
		kvm_write_sw_gcsr(csr, KVM_CSR_ERRINFO2, *v);
		return 0;
	case KVM_CSR_MERRENTRY:
		kvm_write_sw_gcsr(csr, KVM_CSR_MERRENTRY, *v);
		return 0;
	case KVM_CSR_MERRERA:
		kvm_write_sw_gcsr(csr, KVM_CSR_MERRERA, *v);
		return 0;
	case KVM_CSR_ERRSAVE:
		kvm_write_sw_gcsr(csr, KVM_CSR_ERRSAVE, *v);
		return 0;
	case KVM_CSR_CTAG:
		kvm_write_sw_gcsr(csr, KVM_CSR_CTAG, *v);
		return 0;
	case KVM_CSR_DEBUG:
		kvm_write_sw_gcsr(csr, KVM_CSR_DEBUG, *v);
		return 0;
	case KVM_CSR_DERA:
		kvm_write_sw_gcsr(csr, KVM_CSR_DERA, *v);
		return 0;
	case KVM_CSR_DESAVE:
		kvm_write_sw_gcsr(csr, KVM_CSR_DESAVE, *v);
		return 0;
	case KVM_CSR_PRCFG1:
		kvm_write_sw_gcsr(csr, KVM_CSR_PRCFG1, *v);
		return 0;
	case KVM_CSR_PRCFG2:
		kvm_write_sw_gcsr(csr, KVM_CSR_PRCFG2, *v);
		return 0;
	case KVM_CSR_PRCFG3:
		kvm_write_sw_gcsr(csr, KVM_CSR_PRCFG3, *v);
		return 0;
	case KVM_CSR_PGD:
		kvm_write_sw_gcsr(csr, KVM_CSR_PGD, *v);
		return 0;
	case KVM_CSR_TINTCLR:
		kvm_write_sw_gcsr(csr, KVM_CSR_TINTCLR, *v);
		return 0;
	default:
		break;
	}

	ret = -1;
	switch (id) {
	case KVM_CSR_ESTAT:
		kvm_write_gcsr_estat(*v);
		/* estat IP0~IP7 inject through guestexcept */
		kvm_write_csr_gintc(((*v) >> 2)  & 0xff);
		ret = 0;
		break;
	default:
		if (force && (id < CSR_ALL_SIZE)) {
			kvm_set_sw_gcsr(csr, id, *v);
			ret = 0;
		}
		break;
	}

	return ret;
}

struct kvm_iocsr {
	u32 start, end;
	int (*get)(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr, u64 *res);
	int (*set)(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr, u64 val);
};

static struct kvm_iocsr_entry *_kvm_find_iocsr(struct kvm *kvm, u32 addr)
{
	int i = 0;

	for (i = 0; i < IOCSR_MAX; i++) {
		if (addr == kvm->arch.iocsr[i].addr)
			return &kvm->arch.iocsr[i];
	}

	return NULL;
}

static int kvm_iocsr_common_get(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 *res)
{
	int r = EMULATE_FAIL;
	struct kvm_iocsr_entry *entry;

	spin_lock(&vcpu->kvm->arch.iocsr_lock);
	entry = _kvm_find_iocsr(vcpu->kvm, addr);
	if (entry) {
		r = EMULATE_DONE;
		*res = entry->data;
	}
	spin_unlock(&vcpu->kvm->arch.iocsr_lock);
	return r;
}

static int kvm_iocsr_common_set(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 val)
{
	int r = EMULATE_FAIL;
	struct kvm_iocsr_entry *entry;

	spin_lock(&vcpu->kvm->arch.iocsr_lock);
	entry = _kvm_find_iocsr(vcpu->kvm, addr);
	if (entry) {
		r = EMULATE_DONE;
		entry->data = val;
	}
	spin_unlock(&vcpu->kvm->arch.iocsr_lock);
	return r;
}

static int kvm_misc_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	return kvm_iocsr_common_set(run, vcpu, addr, val);
}

static int kvm_ipi_get(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 *res)
{
	int ret;

	++vcpu->stat.rdcsr_ipi_access_exits;
	run->mmio.phys_addr = KVM_IPI_REG_ADDRESS(vcpu->vcpu_id, (addr & 0xff));
	ret = kvm_io_bus_read(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, res);
	if (ret) {
		run->mmio.is_write = 0;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 0;
		return EMULATE_DO_MMIO;
	}
	return EMULATE_DONE;
}

static int kvm_extioi_isr_get(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 *res)
{
	int ret;

	run->mmio.phys_addr =  EXTIOI_PERCORE_ADDR(vcpu->vcpu_id, (addr & 0xff));
	ret = kvm_io_bus_read(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, res);
	if (ret) {
		run->mmio.is_write = 0;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 0;
		return EMULATE_FAIL;
	}

	return EMULATE_DONE;
}

static int kvm_ipi_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	int ret;

	run->mmio.phys_addr = KVM_IPI_REG_ADDRESS(vcpu->vcpu_id, (addr & 0xff));
	ret = kvm_io_bus_write(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, &val);
	if (ret < 0) {
		run->mmio.is_write = 1;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 1;
		return EMULATE_DO_MMIO;
	}

	return EMULATE_DONE;
}

static int kvm_extioi_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	int ret;

	if ((addr & 0x1f00) == KVM_IOCSR_EXTIOI_ISR_BASE)
		run->mmio.phys_addr =  EXTIOI_PERCORE_ADDR(vcpu->vcpu_id, (addr & 0xff));
	else
		run->mmio.phys_addr = EXTIOI_ADDR((addr & 0x1fff));

	ret = kvm_io_bus_write(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, &val);
	if (ret < 0) {
		memcpy(run->mmio.data, &val, run->mmio.len);
		run->mmio.is_write = 1;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 1;
		return EMULATE_DO_MMIO;
	}

	return EMULATE_DONE;
}

static int kvm_nop_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	return EMULATE_DONE;
}

/* we put these iocsrs with access frequency, from high to low */
static struct kvm_iocsr kvm_iocsrs[] = {
	/* extioi iocsr */
	{KVM_IOCSR_EXTIOI_EN_BASE, KVM_IOCSR_EXTIOI_EN_BASE + 0x100,
		NULL, kvm_extioi_set},
	{KVM_IOCSR_EXTIOI_NODEMAP_BASE, KVM_IOCSR_EXTIOI_NODEMAP_BASE+0x28,
		NULL, kvm_extioi_set},
	{KVM_IOCSR_EXTIOI_ROUTE_BASE, KVM_IOCSR_EXTIOI_ROUTE_BASE + 0x100,
		NULL, kvm_extioi_set},
	{KVM_IOCSR_EXTIOI_ISR_BASE, KVM_IOCSR_EXTIOI_ISR_BASE + 0x1c,
		kvm_extioi_isr_get, kvm_extioi_set},

	{KVM_IOCSR_IPI_STATUS, KVM_IOCSR_IPI_STATUS + 0x40,
		kvm_ipi_get, kvm_ipi_set},
	{KVM_IOCSR_IPI_SEND, KVM_IOCSR_IPI_SEND + 0x1,
		NULL, kvm_ipi_set},
	{KVM_IOCSR_MBUF_SEND, KVM_IOCSR_MBUF_SEND + 0x1,
		NULL, kvm_ipi_set},

	{KVM_IOCSR_FEATURES, KVM_IOCSR_FEATURES + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{KVM_IOCSR_VENDOR, KVM_IOCSR_VENDOR + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{KVM_IOCSR_CPUNAME, KVM_IOCSR_CPUNAME + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{KVM_IOCSR_NODECNT, KVM_IOCSR_NODECNT + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{KVM_IOCSR_MISC_FUNC, KVM_IOCSR_MISC_FUNC + 0x1,
		kvm_iocsr_common_get, kvm_misc_set},
};

static int _kvm_emu_iocsr_read(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 *res)
{
	enum emulation_result er = EMULATE_FAIL;
	int i = 0;
	struct kvm_iocsr *iocsr = NULL;

	if (!irqchip_in_kernel(vcpu->kvm)) {
		run->iocsr_io.len = run->mmio.len;
		run->iocsr_io.phys_addr = addr;
		run->iocsr_io.is_write = 0;
		return EMULATE_DO_IOCSR;
	}
	for (i = 0; i < sizeof(kvm_iocsrs) / sizeof(struct kvm_iocsr); i++) {
		iocsr = &kvm_iocsrs[i];
		if (addr >= iocsr->start && addr < iocsr->end) {
			if (iocsr->get)
				er = iocsr->get(run, vcpu, addr, res);
		}
	}

	if (er != EMULATE_DONE)
		kvm_debug("%s iocsr 0x%x not support in kvm\n", __func__, addr);

	return er;
}

static int _kvm_emu_iocsr_write(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 val)
{
	enum emulation_result er = EMULATE_FAIL;
	int i = 0;
	struct kvm_iocsr *iocsr = NULL;

	if (!irqchip_in_kernel(vcpu->kvm)) {
		run->iocsr_io.len = run->mmio.len;
		memcpy(run->iocsr_io.data, &val, run->iocsr_io.len);
		run->iocsr_io.phys_addr = addr;
		run->iocsr_io.is_write = 1;
		return EMULATE_DO_IOCSR;
	}
	for (i = 0; i < sizeof(kvm_iocsrs) / sizeof(struct kvm_iocsr); i++) {
		iocsr = &kvm_iocsrs[i];
		if (addr >= iocsr->start && addr < iocsr->end) {
			if (iocsr->set)
				er = iocsr->set(run, vcpu, addr, val);
		}
	}
	if (er != EMULATE_DONE)
		kvm_debug("%s iocsr 0x%x not support in kvm\n", __func__, addr);

	return er;
}

/* all iocsr operation should in kvm, no mmio */
int _kvm_emu_iocsr(union loongarch_instruction inst,
		struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	u32 rd, rj, opcode;
	u32 val;
	u64 res = 0;
	int ret;

	/*
	 * Each IOCSR with different opcode
	 */
	rd = inst.reg2_format.rd;
	rj = inst.reg2_format.rj;
	opcode = inst.reg2_format.opcode;
	val = vcpu->arch.gprs[rj];
	res = vcpu->arch.gprs[rd];
	/* LoongArch is Little endian */
	switch (opcode) {
	case iocsrrdb_op:
		run->mmio.len = 1;
		ret = _kvm_emu_iocsr_read(run, vcpu, val, &res);
		vcpu->arch.gprs[rd] = (u8) res;
		break;
	case iocsrrdh_op:
		run->mmio.len = 2;
		ret = _kvm_emu_iocsr_read(run, vcpu, val, &res);
		vcpu->arch.gprs[rd] = (u16) res;
		break;
	case iocsrrdw_op:
		run->mmio.len = 4;
		ret = _kvm_emu_iocsr_read(run, vcpu, val, &res);
		vcpu->arch.gprs[rd] = (u32) res;
		break;
	case iocsrrdd_op:
		run->mmio.len = 8;
		ret = _kvm_emu_iocsr_read(run, vcpu, val, &res);
		vcpu->arch.gprs[rd] = res;
		break;
	case iocsrwrb_op:
		run->mmio.len = 1;
		ret = _kvm_emu_iocsr_write(run, vcpu, val, (u8)res);
		break;
	case iocsrwrh_op:
		run->mmio.len = 2;
		ret = _kvm_emu_iocsr_write(run, vcpu, val, (u16)res);
		break;
	case iocsrwrw_op:
		run->mmio.len = 4;
		ret = _kvm_emu_iocsr_write(run, vcpu, val, (u32)res);
		break;
	case iocsrwrd_op:
		run->mmio.len = 8;
		ret = _kvm_emu_iocsr_write(run, vcpu, val, res);
		break;
	default:
		ret = EMULATE_FAIL;
		break;
	}

	if (ret == EMULATE_DO_IOCSR)
		vcpu->arch.io_gpr = rd;

	return ret;
}

int _kvm_complete_iocsr_read(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	unsigned long *gpr = &vcpu->arch.gprs[vcpu->arch.io_gpr];
	enum emulation_result er = EMULATE_DONE;

	switch (run->iocsr_io.len) {
	case 8:
		*gpr = *(s64 *)run->iocsr_io.data;
		break;
	case 4:
		*gpr = *(int *)run->iocsr_io.data;
		break;
	case 2:
		*gpr = *(short *)run->iocsr_io.data;
		break;
	case 1:
		*gpr = *(char *) run->iocsr_io.data;
		break;
	default:
		kvm_err("Bad IOCSR length: %d,addr is 0x%lx",
				run->iocsr_io.len, vcpu->arch.badv);
		er = EMULATE_FAIL;
		break;
	}

	return er;
}

int _kvm_get_iocsr(struct kvm *kvm, struct kvm_iocsr_entry *__user argp)
{
	struct kvm_iocsr_entry *entry, tmp;
	int r = -EFAULT;

	if (copy_from_user(&tmp, argp, sizeof(tmp)))
		goto out;

	spin_lock(&kvm->arch.iocsr_lock);
	entry = _kvm_find_iocsr(kvm, tmp.addr);
	if (entry != NULL)
		tmp.data = entry->data;
	spin_unlock(&kvm->arch.iocsr_lock);

	if (entry)
		r = copy_to_user(argp, &tmp, sizeof(tmp));

out:
	return r;
}

int _kvm_set_iocsr(struct kvm *kvm, struct kvm_iocsr_entry *__user argp)
{
	struct kvm_iocsr_entry *entry, tmp;
	int r = -EFAULT;

	if (copy_from_user(&tmp, argp, sizeof(tmp)))
		goto out;

	spin_lock(&kvm->arch.iocsr_lock);
	entry = _kvm_find_iocsr(kvm, tmp.addr);
	if (entry != NULL) {
		r = 0;
		entry->data = tmp.data;
	}
	spin_unlock(&kvm->arch.iocsr_lock);

out:
	return r;
}

static struct kvm_iocsr_entry iocsr_array[IOCSR_MAX] = {
	{KVM_IOCSR_FEATURES, .data = KVM_IOCSRF_NODECNT|KVM_IOCSRF_MSI
		|KVM_IOCSRF_EXTIOI|KVM_IOCSRF_CSRIPI|KVM_IOCSRF_VM},
	{KVM_IOCSR_VENDOR, .data = 0x6e6f73676e6f6f4c}, /* Loongson */
	{KVM_IOCSR_CPUNAME, .data = 0x303030354133},	/* 3A5000 */
	{KVM_IOCSR_NODECNT, .data = 0x4},
	{KVM_IOCSR_MISC_FUNC, .data = 0x0},
};

int _kvm_init_iocsr(struct kvm *kvm)
{
	int i = 0;

	spin_lock_init(&kvm->arch.iocsr_lock);
	for (i = 0; i < IOCSR_MAX; i++) {
		kvm->arch.iocsr[i].addr = iocsr_array[i].addr;
		kvm->arch.iocsr[i].data = iocsr_array[i].data;
	}
	return 0;
}
