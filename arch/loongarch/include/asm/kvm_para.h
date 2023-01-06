/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_LOONGARCH_KVM_PARA_H
#define _ASM_LOONGARCH_KVM_PARA_H

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
