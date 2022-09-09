/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_VCPU_H
#define  _ASM_SW64_VCPU_H

#ifndef __ASSEMBLY__

struct vcpucb {
	unsigned long go_flag;
	unsigned long pcbb;
	unsigned long ksp;
	unsigned long usp;
	unsigned long kgp;
	unsigned long ent_arith;
	unsigned long ent_if;
	unsigned long ent_int;
	unsigned long ent_mm;
	unsigned long ent_sys;
	unsigned long ent_una;
	unsigned long stack_pc;
	unsigned long new_a0;
	unsigned long new_a1;
	unsigned long new_a2;
	unsigned long whami;
	unsigned long csr_save;
	unsigned long wakeup_magic;
	unsigned long host_vcpucb;
	unsigned long upcr;
	unsigned long vpcr;
	unsigned long dtb_pcr;
	unsigned long guest_ksp;
	unsigned long guest_usp;
	unsigned long vcpu_irq_disabled;
	unsigned long vcpu_irq;
	unsigned long ptbr;
	unsigned long tid;
	unsigned long int_stat1;
	unsigned long int_stat2;
	unsigned long int_stat3;
	unsigned long reset_entry;
	unsigned long pvcpu;
	unsigned long exit_reason;
	unsigned long ipaddr;
	unsigned long vcpu_irq_vector;
};

#endif  /* __ASSEMBLY__ */
#endif  /* _ASM_SW64_VCPU_H */
