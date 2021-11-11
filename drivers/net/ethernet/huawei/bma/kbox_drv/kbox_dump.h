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

#ifndef _KBOX_DUMP_H_
#define _KBOX_DUMP_H_

#define DUMPSTATE_MCE_RESET 1
#define DUMPSTATE_OPPS_RESET 2
#define DUMPSTATE_PANIC_RESET 3

enum kbox_error_type_e {
	KBOX_MCE_EVENT = 1,
	KBOX_OPPS_EVENT,
	KBOX_PANIC_EVENT
};

int kbox_dump_thread_info(const char *fmt, ...);
void kbox_dump_event(enum kbox_error_type_e type, unsigned long event,
		     const char *msg);

#endif
