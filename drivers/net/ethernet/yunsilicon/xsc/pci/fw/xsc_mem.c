// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"

void *xsc_malloc(unsigned int size)
{
	return kmalloc(size, GFP_ATOMIC);
}

void xsc_free(void *addr)
{
	kfree(addr);
}

