// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#include <linux/spinlock.h>
#include <asm/paravirt.h>

#ifdef CONFIG_PARAVIRT_SCHED
#include <linux/static_call.h>

__visible bool __native_vcpu_is_preempted(int cpu)
{
	return false;
}

DEFINE_STATIC_CALL(pv_vcpu_preempted, __native_vcpu_is_preempted);
#endif /* CONFIG_PARAVIRT_SCHED */

#ifdef CONFIG_PARAVIRT_SPINLOCKS
bool pv_is_native_spin_unlock(void)
{
	return pv_ops.lock.queued_spin_unlock == __native_queued_spin_unlock;
}
#endif /* CONFIG_PARAVIRT_SPINLOCKS */
