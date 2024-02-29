// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#ifdef CONFIG_PARAVIRT_SCHED
#include <linux/static_call.h>
#include <linux/spinlock.h>
#include <asm/paravirt.h>

__visible bool __native_vcpu_is_preempted(int cpu)
{
	return false;
}

DEFINE_STATIC_CALL(pv_vcpu_preempted, __native_vcpu_is_preempted);
#endif /* CONFIG_PARAVIRT_SCHED */
