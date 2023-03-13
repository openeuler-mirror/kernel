/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef __LOONGARCH_KVM_CSR_H__
#define __LOONGARCH_KVM_CSR_H__
#include <asm/kvm_host.h>
#include "kvmcpu.h"
#include <linux/uaccess.h>
#include <linux/kvm_host.h>

#define kvm_read_hw_gcsr(id)			kvm_gcsr_read(id)
#define kvm_write_hw_gcsr(csr, id, val)		kvm_gcsr_write(val, id)

int _kvm_getcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force);
int _kvm_setcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force);
unsigned long _kvm_emu_read_csr(struct kvm_vcpu *vcpu, int csrid);
void _kvm_emu_write_csr(struct kvm_vcpu *vcpu, int csrid, unsigned long val);
void _kvm_emu_xchg_csr(struct kvm_vcpu *vcpu, int csrid,
	unsigned long csr_mask, unsigned long val);
int _kvm_emu_iocsr(larch_inst inst, struct kvm_run *run, struct kvm_vcpu *vcpu);

static inline void kvm_save_hw_gcsr(struct loongarch_csrs *csr, u32 gid)
{
	csr->csrs[gid] = kvm_gcsr_read(gid);
}

static inline void kvm_restore_hw_gcsr(struct loongarch_csrs *csr, u32 gid)
{
	kvm_gcsr_write(csr->csrs[gid], gid);
}

static inline unsigned long kvm_read_sw_gcsr(struct loongarch_csrs *csr, u32 gid)
{
	return csr->csrs[gid];
}

static inline void kvm_write_sw_gcsr(struct loongarch_csrs *csr, u32 gid, unsigned long val)
{
	csr->csrs[gid] = val;
}

static inline void kvm_set_sw_gcsr(struct loongarch_csrs *csr, u32 gid, unsigned long val)
{
	csr->csrs[gid] |= val;
}

static inline void kvm_change_sw_gcsr(struct loongarch_csrs *csr, u32 gid, unsigned mask,
	unsigned long val)
{
	unsigned long _mask = mask;
	csr->csrs[gid] &= ~_mask;
	csr->csrs[gid] |= val & _mask;
}


#define GET_HW_GCSR(id, csrid, v)				\
	do {							\
		if (csrid == id) {				\
			*v = (long)kvm_read_hw_gcsr(csrid);	\
			return 0;				\
		}						\
	} while (0)

#define GET_SW_GCSR(csr, id, csrid, v)				\
	do {							\
		if (csrid == id) {				\
			*v = kvm_read_sw_gcsr(csr, id);		\
			return 0;				\
		}						\
	} while (0)

#define SET_HW_GCSR(csr, id, csrid, v)				\
	do {							\
		if (csrid == id) {				\
			kvm_write_hw_gcsr(csr, csrid, *v);	\
			return 0;				\
		}						\
	} while (0)

#define SET_SW_GCSR(csr, id, csrid, v)				\
	do {							\
		if (csrid == id) {				\
			kvm_write_sw_gcsr(csr, csrid, *v);	\
			return 0;				\
		}						\
	} while (0)

int _kvm_init_iocsr(struct kvm *kvm);
int _kvm_set_iocsr(struct kvm *kvm, struct kvm_iocsr_entry *__user argp);
int _kvm_get_iocsr(struct kvm *kvm, struct kvm_iocsr_entry *__user argp);

#define KVM_PMU_PLV_ENABLE      (KVM_PERFCTRL_PLV0 |            \
					KVM_PERFCTRL_PLV1 |     \
					KVM_PERFCTRL_PLV2 |     \
					KVM_PERFCTRL_PLV3)

#define CASE_WRITE_HW_PMU(vcpu, csr, id, csrid, v)                                              \
	do {                                                                                    \
		if (csrid == id) {                                                              \
			if (v & KVM_PMU_PLV_ENABLE) {                                           \
				kvm_write_csr_gcfg(kvm_read_csr_gcfg() | KVM_GCFG_GPERF);       \
				kvm_write_hw_gcsr(csr, csrid, v | KVM_PERFCTRL_GMOD);           \
				vcpu->arch.aux_inuse |= KVM_LARCH_PERF;                         \
				return ;                                                        \
			} else {                                                                \
				kvm_write_sw_gcsr(csr, csrid, v);                               \
				return;                                                         \
			}                                                                       \
		}                                                                               \
	} while (0)

#endif	/* __LOONGARCH_KVM_CSR_H__ */
