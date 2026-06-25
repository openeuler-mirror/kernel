/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_PARAVIRT_H
#define _ASM_ARM64_PARAVIRT_H

#ifdef CONFIG_PARAVIRT
#include <linux/static_call_types.h>

struct static_key;
extern struct static_key paravirt_steal_enabled;
extern struct static_key paravirt_steal_rq_enabled;

u64 dummy_steal_clock(int cpu);

DECLARE_STATIC_CALL(pv_steal_clock, dummy_steal_clock);

static inline u64 paravirt_steal_clock(int cpu)
{
	return static_call(pv_steal_clock)(cpu);
}

int __init pv_time_init(void);

#ifdef CONFIG_VIRT_VTIMER_PV_STATUS
void dummy_set_pvtimer_status(bool active);

DECLARE_STATIC_CALL(pvtimer_status_set, dummy_set_pvtimer_status);

static inline void paravirt_set_pvtimer_active(bool active)
{
	return static_call(pvtimer_status_set)(active);
}

int __init pvtimer_status_init(void);
#endif

#ifdef CONFIG_VIRT_TIMER_EARLY_INJECT
u64 dummy_get_timer_early_inject_ns(void);

DECLARE_STATIC_CALL(pv_timer_early_inject, dummy_get_timer_early_inject_ns);

static inline u64 paravirt_get_timer_early_inject_ns(void)
{
	return static_call(pv_timer_early_inject)();
}

int __init timer_early_inject_init(void);
#else
static inline u64 paravirt_get_timer_early_inject_ns(void)
{
	return 0;
}

#define timer_early_inject_init() do {} while (0)
#endif

#ifdef CONFIG_PARAVIRT_SCHED
int __init pv_sched_init(void);

__visible bool __native_vcpu_is_preempted(int cpu);
DECLARE_STATIC_CALL(pv_vcpu_preempted, __native_vcpu_is_preempted);

static inline bool pv_vcpu_is_preempted(int cpu)
{
	return static_call(pv_vcpu_preempted)(cpu);
}
#endif /* CONFIG_PARAVIRT_SCHED */

#else

#define pv_time_init() do {} while (0)
#ifdef CONFIG_VIRT_VTIMER_PV_STATUS
#define pvtimer_status_init() do {} while (0)
#endif
#define timer_early_inject_init() do {} while (0)
#define pv_sched_init() do {} while (0)

#endif // CONFIG_PARAVIRT

#endif
