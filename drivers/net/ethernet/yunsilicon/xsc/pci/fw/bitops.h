/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef BITOPS_H
#define BITOPS_H

#include <linux/bitops.h>
#include <linux/bitmap.h>

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset);

#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)

#define clear_bit(bit, bitmap) __clear_bit(bit, bitmap)

static inline void xsc_clear_bit(int bit, long *bitmap)
{
	clear_bit(bit, bitmap);
}

static inline int xsc_test_bit(int bit, long *bitmap)
{
	return test_bit(bit, bitmap);
}

static inline int xsc_test_and_set_bit(int bit, long *bitmap)
{
	return test_and_set_bit(bit, bitmap);
}

static inline void xsc_set_bit(int bit, long *bitmap)
{
	set_bit(bit, bitmap);
}

#endif

