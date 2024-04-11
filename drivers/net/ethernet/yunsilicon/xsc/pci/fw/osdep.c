// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <asm/byteorder.h>
#include "common/xsc_core.h"

void xsc_lock_init(struct xsc_lock *lock)
{
	spin_lock_init(&lock->lock);
}

void xsc_acquire_lock(struct xsc_lock *lock, unsigned long *oflags)
{
	unsigned long flags;

	spin_lock_irqsave(&lock->lock, flags);
	*oflags = flags;
}

void xsc_release_lock(struct xsc_lock *lock, unsigned long flags)
{
	spin_unlock_irqrestore(&lock->lock, flags);
}

void xsc_mmiowb(void)
{
	mmiowb();
}

void xsc_wmb(void)
{
	/* mem barrier for xsc operation */
	wmb();
}

void xsc_msleep(int timeout)
{
	msleep(timeout);
}

void xsc_udelay(int timeout)
{
	udelay(timeout);
}

