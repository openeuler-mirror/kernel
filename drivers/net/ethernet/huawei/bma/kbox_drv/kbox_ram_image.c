// SPDX-License-Identifier: GPL-2.0
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

#include "kbox_include.h"
#include "kbox_main.h"
#include "kbox_ram_image.h"

void __iomem *kbox_get_section_addr(enum kbox_section_e  kbox_section)
{
	void __iomem *kbox_addr = kbox_get_base_addr();
	unsigned long kbox_len = kbox_get_io_len();

	if (!kbox_addr || kbox_len == 0) {
		KBOX_MSG("get kbox_addr or kbox_len failed!\n");
		return NULL;
	}

	switch (kbox_section) {
	case KBOX_SECTION_KERNEL:
		return kbox_addr;

	case KBOX_SECTION_PANIC:
		return kbox_addr + SECTION_KERNEL_LEN;

	case KBOX_SECTION_THREAD:
		return kbox_addr + SECTION_KERNEL_LEN + SECTION_PANIC_LEN;

	case KBOX_SECTION_PRINTK1:
		return kbox_addr + (kbox_len - (2 * SECTION_PRINTK_LEN) -
				    SECTION_USER_LEN);

	case KBOX_SECTION_PRINTK2:
		return kbox_addr + (kbox_len - SECTION_PRINTK_LEN -
				    SECTION_USER_LEN);

	case KBOX_SECTION_USER:
		return kbox_addr + (kbox_len - SECTION_USER_LEN);

	case KBOX_SECTION_ALL:
		return kbox_addr;

	default:
		KBOX_MSG("input kbox_section error!\n");
		return NULL;
	}
}

unsigned long kbox_get_section_len(enum kbox_section_e  kbox_section)
{
	unsigned long kbox_len = kbox_get_io_len();

	if (kbox_len == 0) {
		KBOX_MSG("get kbox_len failed!\n");
		return 0;
	}

	switch (kbox_section) {
	case KBOX_SECTION_KERNEL:
		return SECTION_KERNEL_LEN;

	case KBOX_SECTION_PANIC:
		return SECTION_PANIC_LEN;

	case KBOX_SECTION_THREAD:
		return (kbox_len - (2 * SECTION_PRINTK_LEN) -
			SECTION_USER_LEN - SECTION_KERNEL_LEN -
			SECTION_PANIC_LEN);

	case KBOX_SECTION_PRINTK1:
	case KBOX_SECTION_PRINTK2:
		return SECTION_PRINTK_LEN;

	case KBOX_SECTION_USER:
		return SECTION_USER_LEN;

	case KBOX_SECTION_ALL:
		return kbox_len;

	default:
		KBOX_MSG("input kbox_section error!\n");
		return 0;
	}
}

unsigned long kbox_get_section_phy_addr(enum kbox_section_e  kbox_section)
{
	unsigned long kbox_phy_addr = kbox_get_base_phy_addr();
	unsigned long kbox_len = kbox_get_io_len();

	if (kbox_phy_addr == 0 || kbox_len == 0) {
		KBOX_MSG("get kbox_phy_addr or kbox_len failed!\n");
		return 0;
	}

	switch (kbox_section) {
	case KBOX_SECTION_KERNEL:
		return kbox_phy_addr;

	case KBOX_SECTION_PANIC:
		return kbox_phy_addr + SECTION_KERNEL_LEN;

	case KBOX_SECTION_THREAD:
		return kbox_phy_addr + SECTION_KERNEL_LEN + SECTION_PANIC_LEN;

	case KBOX_SECTION_PRINTK1:
		return kbox_phy_addr + (kbox_len - (2 * SECTION_PRINTK_LEN) -
					SECTION_USER_LEN);

	case KBOX_SECTION_PRINTK2:
		return kbox_phy_addr + (kbox_len - SECTION_PRINTK_LEN -
					SECTION_USER_LEN);

	case KBOX_SECTION_USER:
		return kbox_phy_addr + (kbox_len - SECTION_USER_LEN);

	case KBOX_SECTION_ALL:
		return kbox_phy_addr;

	default:
		KBOX_MSG("input kbox_section error!\n");
		return 0;
	}
}
