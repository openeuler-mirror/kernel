/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_LOONGARCH_KVM_PARA_H
#define _ASM_LOONGARCH_KVM_PARA_H

#include <uapi/asm/kvm_para.h>

#define KVM_HYPERCALL ".word 0x002b8000"

/*
 * Hypcall code field
 */
#define KVM_HC_CODE_SERIVCE     0x0
#define KVM_HC_CODE_SWDBG       0x5
/*
 *	function id
 *	0x00000 ~ 0xfffff      Standard Hypervisor Calls
 */
#define KVM_HC_FUNC_FEATURE	0x0
#define KVM_HC_FUNC_NOTIFY	0x1
#define KVM_HC_FUNC_IPI		0x2
/*
 * LoongArch support PV feature list
 */
#define KVM_FEATURE_STEAL_TIME	0
#define KVM_FEATURE_MULTI_IPI	1
/*
 * LoongArch hypcall return code
 */
#define KVM_RET_SUC	1
#define KVM_RET_NOT_SUPPORTED	-1

/*
 * Hypercalls interface for KVM.
 *
 * a0: function identifier
 * a1-a6: args
 * Return value will be placed in v0.
 * Up to 6 arguments are passed in a1, a2, a3, a4, a5, a6.
 */
static inline long kvm_hypercall0(u64 fid)
{
	register long ret asm("v0");
	register unsigned long fun asm("a0") = fid;

	__asm__ __volatile__(
		KVM_HYPERCALL
		: "=r" (ret)
		: "r" (fun)
		: "memory"
	);

	return ret;
}

static inline long kvm_hypercall1(u64 fid, unsigned long arg0)
{
	register long ret asm("v0");
	register unsigned long fun asm("a0") = fid;
	register unsigned long a1 asm("a1") = arg0;

	__asm__ __volatile__(
		KVM_HYPERCALL
		: "=r" (ret)
		: "r" (fun), "r" (a1)
		: "memory"
	);

	return ret;
}

static inline long kvm_hypercall2(u64 fid,
					unsigned long arg0, unsigned long arg1)
{
	register long ret asm("v0");
	register unsigned long fun asm("a0") = fid;
	register unsigned long a1 asm("a1") = arg0;
	register unsigned long a2 asm("a2") = arg1;

	__asm__ __volatile__(
		KVM_HYPERCALL
		: "=r" (ret)
		: "r" (fun), "r" (a1), "r" (a2)
		: "memory"
	);

	return ret;
}

static inline long kvm_hypercall3(u64 fid,
	unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	register long ret asm("v0");
	register unsigned long fun asm("a0") = fid;
	register unsigned long a1 asm("a1") = arg0;
	register unsigned long a2 asm("a2") = arg1;
	register unsigned long a3 asm("a3") = arg2;

	__asm__ __volatile__(
		KVM_HYPERCALL
		: "=r" (ret)
		: "r" (fun), "r" (a1), "r" (a2), "r" (a3)
		: "memory"
	);

	return ret;
}

static inline long kvm_hypercall4(u64 fid,
	unsigned long arg0, unsigned long arg1, unsigned long arg2,
	unsigned long arg3)
{
	register long ret asm("v0");
	register unsigned long fun asm("a0") = fid;
	register unsigned long a1 asm("a1") = arg0;
	register unsigned long a2 asm("a2") = arg1;
	register unsigned long a3 asm("a3") = arg2;
	register unsigned long a4 asm("a4") = arg3;

	__asm__ __volatile__(
		KVM_HYPERCALL
		: "=r" (ret)
		: "i"(fun), "r" (a1), "r" (a2), "r" (a3), "r" (a4)
		: "memory"
	);

	return ret;
}

static inline long kvm_hypercall5(u64 fid,
	unsigned long arg0, unsigned long arg1, unsigned long arg2,
	unsigned long arg3, unsigned long arg4)
{
	register long ret asm("v0");
	register unsigned long fun asm("a0") = fid;
	register unsigned long a1 asm("a1") = arg0;
	register unsigned long a2 asm("a2") = arg1;
	register unsigned long a3 asm("a3") = arg2;
	register unsigned long a4 asm("a4") = arg3;
	register unsigned long a5 asm("a5") = arg4;

	__asm__ __volatile__(
		KVM_HYPERCALL
		: "=r" (ret)
		: "i"(fun), "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5)
		: "memory"
	);

	return ret;
}

static inline long kvm_hypercall6(u64 fid,
	unsigned long arg0, unsigned long arg1, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	register long ret asm("v0");
	register unsigned long fun asm("a0") = fid;
	register unsigned long a1 asm("a1") = arg0;
	register unsigned long a2 asm("a2") = arg1;
	register unsigned long a3 asm("a3") = arg2;
	register unsigned long a4 asm("a4") = arg3;
	register unsigned long a5 asm("a5") = arg4;
	register unsigned long a6 asm("a6") = arg5;

	__asm__ __volatile__(
		KVM_HYPERCALL
		: "=r" (ret)
		: "i"(fun), "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6)
		: "memory"
	);

	return ret;
}

static inline bool kvm_check_and_clear_guest_paused(void)
{
	return false;
}

static inline unsigned int kvm_arch_para_features(void)
{
	return 0;
}

static inline unsigned int kvm_arch_para_hints(void)
{
	return 0;
}

#endif /* _ASM_LOONGARCH_KVM_PARA_H */
