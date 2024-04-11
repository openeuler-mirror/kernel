/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef OSDEP_H
#define OSDEP_H

#include "common/xsc_core.h"

#define xsc_print printk

void xsc_msleep(int timeout);

void xsc_udelay(int timeout);

void xsc_lock_init(struct xsc_lock *lock);

void xsc_acquire_lock(struct xsc_lock *lock, unsigned long *flags);

void xsc_release_lock(struct xsc_lock *lock, unsigned long flags);

void xsc_mmiowb(void);

void xsc_wmb(void);

void *xsc_malloc(unsigned int size);

void xsc_free(void *addr);

#endif

