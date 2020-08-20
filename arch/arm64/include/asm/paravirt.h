/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_PARAVIRT_H
#define _ASM_ARM64_PARAVIRT_H

#ifdef CONFIG_PARAVIRT
struct static_key;
extern struct static_key paravirt_steal_enabled;
extern struct static_key paravirt_steal_rq_enabled;

struct pv_time_ops {
	unsigned long long (*steal_clock)(int cpu);
};

struct pv_sched_ops {
	bool (*vcpu_is_preempted)(int cpu);
};

struct paravirt_patch_template {
	struct pv_time_ops time;
	struct pv_sched_ops sched;
};

extern struct paravirt_patch_template pv_ops;

static inline u64 paravirt_steal_clock(int cpu)
{
	return pv_ops.time.steal_clock(cpu);
}

__visible bool __native_vcpu_is_preempted(int cpu);
static inline bool pv_vcpu_is_preempted(int cpu)
{
	return pv_ops.sched.vcpu_is_preempted(cpu);
}

#endif

#endif
