// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/linkage.h>
#include <asm/stackframe.h>
#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/regdef.h>
#include "kvm_compat.h"

#define RESUME_HOST	(1 << 1)

#define GGPR_OFFSET(x)	(KVM_ARCH_GGPR + 8*x)
#define PT_GPR_OFFSET(x)	(PT_R0 + 8*x)

	.text

.macro kvm_save_guest_gprs base
	.irp n,1,2,3,4,5,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	KVM_LONG_S	$r\n, \base, GGPR_OFFSET(\n)
	.endr
.endm

.macro kvm_restore_guest_gprs base
	.irp n,1,2,3,4,5,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	KVM_LONG_L	$r\n, \base, GGPR_OFFSET(\n)
	.endr
.endm

.macro kvm_save_host_gpr base
	.irp n,1,2,3,22,23,24,25,26,27,28,29,30,31
	KVM_LONG_S	$r\n, \base, PT_GPR_OFFSET(\n)
	.endr
.endm

.macro kvm_restore_host_gpr base
	.irp n,1,2,3,22,23,24,25,26,27,28,29,30,31
	KVM_LONG_L	$r\n, \base, PT_GPR_OFFSET(\n)
	.endr
.endm

/*
 * prepare switch to guest
 * @param:
 *  KVM_ARCH: kvm_vcpu_arch, don't touch it until 'ertn'
 *  GPRNUM: KVM_ARCH gpr number
 *  tmp, tmp1: temp register
 */
.macro kvm_switch_to_guest KVM_ARCH GPRNUM tmp tmp1
	/* set host excfg.VS=0, all exceptions share one exception entry */
	csrrd	\tmp, KVM_CSR_ECFG
	bstrins.w	\tmp, zero, (KVM_ECFG_VS_SHIFT + KVM_ECFG_VS_WIDTH - 1), KVM_ECFG_VS_SHIFT
	csrwr	\tmp, KVM_CSR_ECFG

	/* Load up the new EENTRY */
	KVM_LONG_L	\tmp, \KVM_ARCH, KVM_ARCH_GEENTRY
	csrwr		\tmp, KVM_CSR_EENTRY

	/* Set Guest ERA */
	KVM_LONG_L	\tmp, \KVM_ARCH, KVM_ARCH_GPC
	csrwr		\tmp, KVM_CSR_ERA

	/* Save host PGDL */
	csrrd	\tmp, KVM_CSR_PGDL
	KVM_LONG_S	\tmp, \KVM_ARCH, KVM_ARCH_HPGD

	/* Switch to kvm */
	KVM_LONG_L	\tmp1, \KVM_ARCH, KVM_VCPU_KVM - KVM_VCPU_ARCH

	/* Load guest PGDL */
	lu12i.w \tmp, KVM_GPGD
	srli.w \tmp, \tmp, 12
	ldx.d  \tmp, \tmp1, \tmp
	csrwr	\tmp, KVM_CSR_PGDL

	/* Mix GID and RID */
	csrrd	\tmp1, KVM_CSR_GSTAT
	bstrpick.w	\tmp1, \tmp1, (KVM_GSTAT_GID_SHIFT + KVM_GSTAT_GID_WIDTH - 1), KVM_GSTAT_GID_SHIFT
	csrrd	\tmp, KVM_CSR_GTLBC
	bstrins.w	\tmp, \tmp1, (KVM_GTLBC_TGID_SHIFT + KVM_GTLBC_TGID_WIDTH - 1), KVM_GTLBC_TGID_SHIFT
	csrwr	\tmp, KVM_CSR_GTLBC

	/*
	 * Switch to guest:
	 *  GSTAT.PGM = 1, ERRCTL.ISERR = 0, TLBRPRMD.ISTLBR = 0
	 *  ertn
	 */

	/* Prepare enable Intr before enter guest */
	ori	\tmp, zero, KVM_PRMD_PIE
	csrxchg	\tmp, \tmp, KVM_CSR_PRMD

	/* Set PVM bit to setup ertn to guest context */
	ori	\tmp, zero, KVM_GSTAT_PVM
	csrxchg	\tmp, \tmp, KVM_CSR_GSTAT

	/* Load Guest gprs */
	kvm_restore_guest_gprs	\KVM_ARCH

	/* Load KVM_ARCH register */
	KVM_LONG_L	\KVM_ARCH, \KVM_ARCH, GGPR_OFFSET(\GPRNUM)

	ertn
.endm

#ifndef	EXCPTION_ENTRY
#define EXCPTION_ENTRY(name)	\
	.globl name ASM_NL	\
	.p2align	12;	\
	name:			\
		.cfi_startproc;
#endif
#ifndef	EXCPTION_ENDPROC
#define EXCPTION_ENDPROC(name)	\
	.cfi_endproc;			\
	SYM_END(name, SYM_T_FUNC)
#endif

/* load kvm_vcpu to a2 and store a1 for free use */
EXCPTION_ENTRY(kvm_exception_entry)
	csrwr	a2, KVM_TEMP_KS
	csrrd	a2, KVM_VCPU_KS
	KVM_LONG_ADDI	a2, a2, KVM_VCPU_ARCH

	/* After save gprs, free to use any gpr */
	kvm_save_guest_gprs	a2
	/* Save guest a2 */
	csrrd	t0, KVM_TEMP_KS
	KVM_LONG_S	t0, a2, GGPR_OFFSET(REG_A2)

	b	kvm_exit_entry
EXCPTION_ENDPROC(kvm_exception_entry)

/* a2: kvm_vcpu_arch, a1 is free to use */
SYM_FUNC_START(kvm_exit_entry)
	csrrd	s1, KVM_VCPU_KS
	KVM_LONG_L	s0, s1, KVM_VCPU_RUN

	csrrd		t0, KVM_CSR_ESTAT
	KVM_LONG_S	t0, a2, KVM_ARCH_HESTAT
	csrrd		t0, KVM_CSR_ERA
	KVM_LONG_S	t0, a2, KVM_ARCH_GPC
	csrrd		t0, KVM_CSR_BADV
	KVM_LONG_S	t0, a2, KVM_ARCH_HBADV
	csrrd		t0, KVM_CSR_BADI
	KVM_LONG_S	t0, a2, KVM_ARCH_HBADI

	/* Restore host excfg.VS */
	csrrd		t0, KVM_CSR_ECFG
	KVM_LONG_L	t1, a2, KVM_ARCH_HECFG
	or		t0, t0, t1
	csrwr		t0, KVM_CSR_ECFG

	/* Restore host eentry */
	KVM_LONG_L	t0, a2, KVM_ARCH_HEENTRY
	csrwr		t0, KVM_CSR_EENTRY

#if defined(CONFIG_CPU_HAS_FPU)
	/* Save FPU context */
	csrrd	t0, KVM_CSR_EUEN
	ori	t1, zero, KVM_EUEN_FPEN | KVM_EUEN_LSXEN | KVM_EUEN_LASXEN
	and	t2, t0, t1
	beqz	t2, 1f
	movfcsr2gr	t3, fcsr0
	INT_S	t3,	a2, VCPU_FCSR0

	movcf2gr	t3, $fcc0
	or		t2, t3, zero
	movcf2gr	t3, $fcc1
	bstrins.d	t2, t3, 0xf, 0x8
	movcf2gr	t3, $fcc2
	bstrins.d	t2, t3, 0x17, 0x10
	movcf2gr	t3, $fcc3
	bstrins.d	t2, t3, 0x1f, 0x18
	movcf2gr	t3, $fcc4
	bstrins.d	t2, t3, 0x27, 0x20
	movcf2gr	t3, $fcc5
	bstrins.d	t2, t3, 0x2f, 0x28
	movcf2gr	t3, $fcc6
	bstrins.d	t2, t3, 0x37, 0x30
	movcf2gr	t3, $fcc7
	bstrins.d	t2, t3, 0x3f, 0x38
	KVM_LONG_S	t2, a2, VCPU_FCC
	movgr2fcsr	fcsr0, zero
1:
#endif

	KVM_LONG_L	t0, a2, KVM_ARCH_HPGD
	csrwr	t0, KVM_CSR_PGDL

	/* Disable PVM bit for keeping from into guest */
	ori	t0, zero, KVM_GSTAT_PVM
	csrxchg	zero, t0, KVM_CSR_GSTAT

	/* Clear GTLBC.TGID field */
	csrrd	t0, KVM_CSR_GTLBC
	bstrins.w	t0, zero, KVM_GTLBC_TGID_SHIFT + KVM_GTLBC_TGID_WIDTH - 1, KVM_GTLBC_TGID_SHIFT
	csrwr	t0, KVM_CSR_GTLBC

	/* Enable Address Map mode */
	ori	t0, zero, (1 << KVM_CRMD_DACM_SHIFT)|(1 << KVM_CRMD_DACF_SHIFT) | KVM_CRMD_PG |PLV_KERN
	csrwr	t0, KVM_CSR_CRMD

	KVM_LONG_L	tp, a2, KVM_ARCH_HGP
	KVM_LONG_L	sp, a2, KVM_ARCH_HSTACK
	/* restore per cpu register */
	KVM_LONG_L	$r21, a2, KVM_ARCH_HPERCPU

	KVM_LONG_ADDI	sp, sp, -PT_SIZE

	/* Prepare handle exception */
	or		a0, s0, zero
	or		a1, s1, zero
	KVM_LONG_L	t8, a2, KVM_ARCH_HANDLE_EXIT
	jirl		ra,t8, 0

	ori	t0, zero, KVM_CRMD_IE
	csrxchg	zero, t0, KVM_CSR_CRMD
	or	a2, s1, zero
	KVM_LONG_ADDI	a2, a2, KVM_VCPU_ARCH

	andi	t0, a0, RESUME_HOST
	bnez	t0, ret_to_host
	INT_S	zero, a2, KVM_ARCH_ISHYPCALL

ret_to_guest:
	/* Save per cpu register again, maybe switched to another cpu */
	KVM_LONG_S	$r21, a2, KVM_ARCH_HPERCPU

	/* Save kvm_vcpu to kscratch */
	csrwr	s1, KVM_VCPU_KS
	kvm_switch_to_guest a2 REG_A2 t0 t1

ret_to_host:
	KVM_LONG_L  a2, a2, KVM_ARCH_HSTACK
	addi.d  a2, a2, -PT_SIZE
	srai.w  a3, a0, 2
	or      a0, a3, zero
	kvm_restore_host_gpr    a2
	jirl    zero, ra, 0
SYM_FUNC_END(kvm_exit_entry)

/*
 * int kvm_enter_guest(struct kvm_run *run, struct kvm_vcpu *vcpu)
 *
 * @register_param:
 *  a0: kvm_run* run
 *  a1: kvm_vcpu* vcpu
 */
SYM_FUNC_START(kvm_enter_guest)
	/* allocate space in stack bottom */
	KVM_LONG_ADDI	a2, sp, -PT_SIZE

	/* save host gprs */
	kvm_save_host_gpr a2

	/* save host crmd,prmd csr to stack */
	csrrd		a3, KVM_CSR_CRMD
	KVM_LONG_S	a3, a2, PT_CRMD
	csrrd		a3, KVM_CSR_PRMD
	KVM_LONG_S	a3, a2, PT_PRMD

	KVM_LONG_ADDI	a2, a1, KVM_VCPU_ARCH
	KVM_LONG_S	sp, a2, KVM_ARCH_HSTACK
	KVM_LONG_S	tp, a2, KVM_ARCH_HGP
	/* Save per cpu register */
	KVM_LONG_S	$r21, a2, KVM_ARCH_HPERCPU

	/* Save kvm_vcpu to kscratch */
	csrwr	a1, KVM_VCPU_KS

	kvm_switch_to_guest	a2 REG_A2 t0 t1

SYM_FUNC_END(kvm_enter_guest)

SYM_FUNC_START(__kvm_save_fpu)
	fpu_save_double a0 t1
	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_save_fpu)

SYM_FUNC_START(__kvm_restore_fpu)
	fpu_restore_double a0 t1
	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_restore_fpu)

SYM_FUNC_START(__kvm_restore_fcsr)
	fpu_restore_csr a0 t1
	fpu_restore_cc  a0 t1 t2

	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_restore_fcsr)

#ifdef CONFIG_CPU_HAS_LSX
SYM_FUNC_START(__kvm_save_lsx)
	lsx_save_data a0 t1

	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_save_lsx)

SYM_FUNC_START(__kvm_restore_lsx)
	lsx_restore_data a0 t1

	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_restore_lsx)

SYM_FUNC_START(__kvm_restore_lsx_upper)
	lsx_restore_all_upper a0 t0 t1

	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_restore_lsx_upper)
#endif

#ifdef CONFIG_CPU_HAS_LASX
SYM_FUNC_START(__kvm_save_lasx)
	lasx_save_data a0 t7

	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_save_lasx)

SYM_FUNC_START(__kvm_restore_lasx)
	lasx_restore_data a0 t7

	jirl    zero, ra, 0
SYM_FUNC_END(__kvm_restore_lasx)
#endif

