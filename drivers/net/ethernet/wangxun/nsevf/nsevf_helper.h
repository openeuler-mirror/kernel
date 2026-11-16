/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_HELPER_H_
#define _NSEVF_HELPER_H_

#include "nsevf_alloc.h"

/* prototype */
inline void nsevf_destroy_spinlock_d(struct nsevf_spinlock *sp);
inline void nsevf_acquire_spinlock_d(struct nsevf_spinlock *sp);
inline void nsevf_release_spinlock_d(struct nsevf_spinlock *sp);

/**
 * nsevf_init_spinlock_d - OS specific spinlock init for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
static inline void nsevf_init_spinlock_d(struct nsevf_spinlock *sp)
{
	mutex_init((struct mutex *)sp);
}

/**
 * nsevf_acquire_spinlock_d - OS specific spinlock acquire for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void nsevf_acquire_spinlock_d(struct nsevf_spinlock *sp)
{
	mutex_lock((struct mutex *)sp);
}

/**
 * nsevf_release_spinlock_d - OS specific spinlock release for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void nsevf_release_spinlock_d(struct nsevf_spinlock *sp)
{
	mutex_unlock((struct mutex *)sp);
}

/**
 * nsevf_destroy_spinlock_d - OS specific spinlock destroy for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void nsevf_destroy_spinlock_d(struct nsevf_spinlock *sp)
{
	mutex_destroy((struct mutex *)sp);
}
#endif /* _NSEVF_HELPER_H_ */
