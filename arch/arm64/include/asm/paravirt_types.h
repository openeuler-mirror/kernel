/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_PARAVIRT_TYPES_H
#define _ASM_ARM64_PARAVIRT_TYPES_H

#include <linux/types.h>

struct qspinlock;

struct pv_lock_ops {
	void (*queued_spin_lock_slowpath)(struct qspinlock *lock, u32 val);
	void (*queued_spin_unlock)(struct qspinlock *lock);

	void (*wait)(u8 *ptr, u8 val);
	void (*kick)(int cpu);
};

/* This contains all the paravirt structures */
struct paravirt_patch_template {
	struct pv_lock_ops	lock;
} __no_randomize_layout;

extern struct paravirt_patch_template pv_ops;

void __native_queued_spin_unlock(struct qspinlock *lock);

#endif /* _ASM_ARM64_PARAVIRT_TYPES_H */
