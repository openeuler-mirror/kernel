// SPDX-License-Identifier: GPL-2.0
/*
 * Paravirt types for ARM64
 *
 * Copyright (C) 2024 Huawei Technologies Co., Ltd
 */

#include <linux/spinlock.h>
#include <asm/qspinlock.h>
#include <asm/paravirt_types.h>

static void pv_nop_wait(u8 *ptr, u8 val)
{
}

static void pv_nop_kick(int cpu)
{
}

void __native_queued_spin_unlock(struct qspinlock *lock)
{
	native_queued_spin_unlock(lock);
}
EXPORT_SYMBOL(__native_queued_spin_unlock);

/*
 * Default pv_ops.lock with native implementations.
 * Will be overridden by pv_qspinlock_init() when PV spinlock is enabled.
 */
struct paravirt_patch_template pv_ops = {
	.lock = {
		.queued_spin_lock_slowpath	= native_queued_spin_lock_slowpath,
		.queued_spin_unlock		= __native_queued_spin_unlock,
		.wait				= pv_nop_wait,
		.kick				= pv_nop_kick,
	},
};
EXPORT_SYMBOL(pv_ops);
