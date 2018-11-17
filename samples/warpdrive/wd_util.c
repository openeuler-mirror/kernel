// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include "wd_util.h"

void wd_spinlock(struct wd_lock *lock)
{
	while (__atomic_test_and_set(&lock->lock, __ATOMIC_ACQUIRE))
		while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED))
			;
}

void wd_unspinlock(struct wd_lock *lock)
{
	__atomic_clear(&lock->lock, __ATOMIC_RELEASE);
}
