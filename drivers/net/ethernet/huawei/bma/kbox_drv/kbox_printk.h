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

#ifndef _KBOX_PRINTK_H_
#define _KBOX_PRINTK_H_
#include "kbox_ram_image.h"

struct printk_ctrl_block_tmp_s {
	int printk_region;
	enum kbox_section_e section;
	unsigned int start;
	unsigned int end;
	unsigned int valid_len;/* valid length of printk section */
};

int  kbox_printk_init(int kbox_proc_exist);
void kbox_output_printk_info(void);
int  kbox_dump_printk_info(const char *fmt, ...);
void kbox_printk_exit(void);

#endif
