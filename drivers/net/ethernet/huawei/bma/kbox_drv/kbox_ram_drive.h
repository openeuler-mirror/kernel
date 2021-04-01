/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _KBOX_RAM_DRIVE_H_
#define _KBOX_RAM_DRIVE_H_

#include <linux/types.h>
#include <linux/atomic.h>

struct kbox_dev_s {
	atomic_t au_count;

	struct kbox_pci_dev_s *kbox_pci_dev;
};

int kbox_drive_init(void);
void kbox_drive_cleanup(void);

#endif
