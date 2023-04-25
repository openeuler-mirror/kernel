/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_LOONGARCH_PARAVIRT_H
#define _ASM_LOONGARCH_PARAVIRT_H
#include <asm/kvm_para.h>

#ifdef CONFIG_PARAVIRT
static inline bool kvm_para_available(void)
{
	return true;
}
struct static_key;
extern struct static_key paravirt_steal_enabled;
extern struct static_key paravirt_steal_rq_enabled;

struct pv_time_ops {
	unsigned long long (*steal_clock)(int cpu);
};
struct kvm_steal_time {
	__u64 steal;
	__u32 version;
	__u32 flags;
	__u32 pad[12];
};
extern struct pv_time_ops pv_time_ops;

static inline u64 paravirt_steal_clock(int cpu)
{
	return pv_time_ops.steal_clock(cpu);
}

static inline bool pv_feature_support(int feature)
{
	return kvm_hypercall1(KVM_HC_FUNC_FEATURE, feature) == KVM_RET_SUC;
}
static inline void pv_notify_host(int feature, unsigned long data)
{
	kvm_hypercall2(KVM_HC_FUNC_NOTIFY, feature, data);
}

int __init pv_time_init(void);
int __init pv_ipi_init(void);
#else
static inline bool kvm_para_available(void)
{
	return false;
}

static inline int pv_time_init(void)
{
	return 0;
}

static inline int pv_ipi_init(void)
{
	return 0;
}
#endif
#endif /* _ASM_LOONGARCH_PARAVIRT_H */
