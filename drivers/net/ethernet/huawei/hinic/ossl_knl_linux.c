// SPDX-License-Identifier: GPL-2.0
/* Huawei HiNIC PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <linux/pci_regs.h>

#include "ossl_knl_linux.h"

void add_to_timer(struct timer_list *timer, long period)
{
	if (!timer)
		return;

	add_timer(timer);
}

void stop_timer(struct timer_list *timer)
{
}

void delete_timer(struct timer_list *timer)
{
	if (!timer)
		return;

	del_timer_sync(timer);
}

int local_atoi(const char *name)
{
	int val = 0;

	for (;; name++) {
		switch (*name) {
		case '0' ... '9':
			val = 10 * val + (*name - '0');
			break;
		default:
			return val;
		}
	}
}
