/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_H

#include <linux/tracepoint.h>
#include "kvm_compat.h"
#include "kvmcsr.h"

#undef	TRACE_SYSTEM
#define TRACE_SYSTEM kvm
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace

/*
 * arch/loongarch/kvm/loongarch.c
 */
extern bool kvm_trace_guest_mode_change;
int kvm_guest_mode_change_trace_reg(void);
void kvm_guest_mode_change_trace_unreg(void);

/*
 * Tracepoints for VM enters
 */
DECLARE_EVENT_CLASS(kvm_transition,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu),
	TP_STRUCT__entry(
		__field(unsigned long, pc)
	),

	TP_fast_assign(
		__entry->pc = vcpu->arch.pc;
	),

	TP_printk("PC: 0x%08lx",
		  __entry->pc)
);

DEFINE_EVENT(kvm_transition, kvm_enter,
	     TP_PROTO(struct kvm_vcpu *vcpu),
	     TP_ARGS(vcpu));

DEFINE_EVENT(kvm_transition, kvm_reenter,
	     TP_PROTO(struct kvm_vcpu *vcpu),
	     TP_ARGS(vcpu));

DEFINE_EVENT(kvm_transition, kvm_out,
	     TP_PROTO(struct kvm_vcpu *vcpu),
	     TP_ARGS(vcpu));

/* The first 32 exit reasons correspond to Cause.ExcCode */
#define KVM_TRACE_EXIT_INT	0
#define KVM_TRACE_EXIT_TLBLD	(KVM_EXCCODE_TLBL)
#define KVM_TRACE_EXIT_TLBST	(KVM_EXCCODE_TLBS)
#define KVM_TRACE_EXIT_TLBI	(KVM_EXCCODE_TLBI)
#define KVM_TRACE_EXIT_TLBMOD	(KVM_EXCCODE_TLBM)
#define KVM_TRACE_EXIT_TLBRI	(KVM_EXCCODE_TLBRI)
#define KVM_TRACE_EXIT_TLBXI	(KVM_EXCCODE_TLBXI)
#define KVM_TRACE_EXIT_TLBPE	(KVM_EXCCODE_TLBPE)
#define KVM_TRACE_EXIT_ADDE	(KVM_EXCCODE_ADE)
#define KVM_TRACE_EXIT_UNALIGN	(KVM_EXCCODE_ALE)
#define KVM_TRACE_EXIT_ODB	(KVM_EXCCODE_OOB)
#define KVM_TRACE_EXIT_SYSCALL	(KVM_EXCCODE_SYS)
#define KVM_TRACE_EXIT_BP	(KVM_EXCCODE_BP)
#define KVM_TRACE_EXIT_INE	(KVM_EXCCODE_INE)
#define KVM_TRACE_EXIT_IPE	(KVM_EXCCODE_IPE)
#define KVM_TRACE_EXIT_FPDIS	(KVM_EXCCODE_FPDIS)
#define KVM_TRACE_EXIT_LSXDIS	(KVM_EXCCODE_LSXDIS)
#define KVM_TRACE_EXIT_LASXDIS	(KVM_EXCCODE_LASXDIS)
#define KVM_TRACE_EXIT_FPE	(KVM_EXCCODE_FPE)
#define KVM_TRACE_EXIT_WATCH	(KVM_EXCCODE_WATCH)
#define KVM_TRACE_EXIT_GSPR	(KVM_EXCCODE_GSPR)
#define KVM_TRACE_EXIT_HC	(KVM_EXCCODE_HYP)
#define KVM_TRACE_EXIT_GCM	(KVM_EXCCODE_GCM)

/* Further exit reasons */
#define KVM_TRACE_EXIT_IDLE	64
#define KVM_TRACE_EXIT_CACHE	65
#define KVM_TRACE_EXIT_SIGNAL	66

/* Tracepoints for VM exits */
#define kvm_trace_symbol_exit_types				\
	{ KVM_TRACE_EXIT_INT,		"Interrupt" },		\
	{ KVM_TRACE_EXIT_TLBLD,		"TLB (LD)" },		\
	{ KVM_TRACE_EXIT_TLBST,		"TLB (ST)" },		\
	{ KVM_TRACE_EXIT_TLBI,		"TLB Ifetch" },		\
	{ KVM_TRACE_EXIT_TLBMOD,	"TLB Mod" },		\
	{ KVM_TRACE_EXIT_TLBRI,		"TLB RI" },		\
	{ KVM_TRACE_EXIT_TLBXI,		"TLB XI" },		\
	{ KVM_TRACE_EXIT_TLBPE,		"TLB Previlege Error" },\
	{ KVM_TRACE_EXIT_ADDE,		"Address Error" },	\
	{ KVM_TRACE_EXIT_UNALIGN,	"Address unalign" },	\
	{ KVM_TRACE_EXIT_ODB,		"Out boundary" },	\
	{ KVM_TRACE_EXIT_SYSCALL,	"System Call" },	\
	{ KVM_TRACE_EXIT_BP,		"Breakpoint" },		\
	{ KVM_TRACE_EXIT_INE,		"Reserved Inst" },	\
	{ KVM_TRACE_EXIT_IPE,		"Inst prev error" },	\
	{ KVM_TRACE_EXIT_FPDIS,		"FPU disable" },	\
	{ KVM_TRACE_EXIT_LSXDIS,	"LSX disable" },	\
	{ KVM_TRACE_EXIT_LASXDIS,	"LASX disable" },	\
	{ KVM_TRACE_EXIT_FPE,		"FPE" },		\
	{ KVM_TRACE_EXIT_WATCH,		"DEBUG" },		\
	{ KVM_TRACE_EXIT_GSPR,		"GSPR" },		\
	{ KVM_TRACE_EXIT_HC,		"Hypercall" },		\
	{ KVM_TRACE_EXIT_GCM,		"CSR Mod" },		\
	{ KVM_TRACE_EXIT_IDLE,		"IDLE" },		\
	{ KVM_TRACE_EXIT_CACHE,		"CACHE" },		\
	{ KVM_TRACE_EXIT_SIGNAL,	"Signal" }

TRACE_EVENT(kvm_exit,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned int reason),
	    TP_ARGS(vcpu, reason),
	    TP_STRUCT__entry(
			__field(unsigned long, pc)
			__field(unsigned int, reason)
	    ),

	    TP_fast_assign(
			__entry->pc = vcpu->arch.pc;
			__entry->reason = reason;
	    ),

	    TP_printk("[%s]PC: 0x%08lx",
		      __print_symbolic(__entry->reason,
				       kvm_trace_symbol_exit_types),
		      __entry->pc)
);

#define KVM_TRACE_AUX_RESTORE		0
#define KVM_TRACE_AUX_SAVE		1
#define KVM_TRACE_AUX_ENABLE		2
#define KVM_TRACE_AUX_DISABLE		3
#define KVM_TRACE_AUX_DISCARD		4

#define KVM_TRACE_AUX_FPU		1
#define KVM_TRACE_AUX_LSX		2
#define KVM_TRACE_AUX_FPU_LSX		3
#define KVM_TRACE_AUX_LASX		4
#define KVM_TRACE_AUX_FPU_LSX_LASX	7

#define kvm_trace_symbol_aux_op			\
	{ KVM_TRACE_AUX_RESTORE, "restore" },	\
	{ KVM_TRACE_AUX_SAVE,    "save" },	\
	{ KVM_TRACE_AUX_ENABLE,  "enable" },	\
	{ KVM_TRACE_AUX_DISABLE, "disable" },	\
	{ KVM_TRACE_AUX_DISCARD, "discard" }

#define kvm_trace_symbol_aux_state		\
	{ KVM_TRACE_AUX_FPU,     "FPU" },	\
	{ KVM_TRACE_AUX_LSX,     "LSX" },	\
	{ KVM_TRACE_AUX_LASX,    "LASX" },	\
	{ KVM_TRACE_AUX_FPU_LSX, "FPU & LSX" }, \
	{ KVM_TRACE_AUX_FPU_LSX_LASX, "FPU & LSX & LASX" }

TRACE_EVENT(kvm_aux,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned int op,
		     unsigned int state),
	    TP_ARGS(vcpu, op, state),
	    TP_STRUCT__entry(
			__field(unsigned long, pc)
			__field(u8, op)
			__field(u8, state)
	    ),

	    TP_fast_assign(
			__entry->pc = vcpu->arch.pc;
			__entry->op = op;
			__entry->state = state;
	    ),

	    TP_printk("%s %s PC: 0x%08lx",
		      __print_symbolic(__entry->op,
				       kvm_trace_symbol_aux_op),
		      __print_symbolic(__entry->state,
				       kvm_trace_symbol_aux_state),
		      __entry->pc)
);

TRACE_EVENT(kvm_vpid_change,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned long vpid),
	    TP_ARGS(vcpu, vpid),
	    TP_STRUCT__entry(
			__field(unsigned long, vpid)
	    ),

	    TP_fast_assign(
			__entry->vpid = vpid;
	    ),

	    TP_printk("vpid: 0x%08lx",
		      __entry->vpid)
);

#endif /* _TRACE_KVM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
