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

#include <linux/spinlock.h>
#include <linux/utsname.h>		/* system_utsname */
#include <linux/rtc.h>		/* struct rtc_time */
#include "kbox_include.h"
#include "kbox_main.h"
#include "kbox_printk.h"
#include "kbox_ram_image.h"
#include "kbox_ram_op.h"
#include "kbox_dump.h"
#include "kbox_panic.h"

#ifdef CONFIG_X86
#include "kbox_mce.h"
#endif

#define THREAD_TMP_BUF_SIZE 256

static DEFINE_SPINLOCK(g_dump_lock);

static const char g_day_in_month[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

#define LEAPS_THRU_END_OF(y) ((y) / 4 - (y) / 100 + (y) / 400)
#define LEAP_YEAR(year) \
	((!((year) % 4) && ((year) % 100)) || !((year) % 400))
#define MONTH_DAYS(month, year) \
	(g_day_in_month[(month)] + (int)(LEAP_YEAR(year) && (month == 1)))

static void kbox_show_kernel_version(void)
{
	(void)kbox_dump_painc_info
		("\nOS : %s,\nRelease : %s,\nVersion : %s,\n",
		 init_uts_ns.name.sysname,
		 init_uts_ns.name.release,
		 init_uts_ns.name.version);
	(void)kbox_dump_painc_info
		("Machine : %s,\nNodename : %s\n",
		 init_uts_ns.name.machine,
		 init_uts_ns.name.nodename);
}

static void kbox_show_version(void)
{
	(void)kbox_dump_painc_info("\nKBOX_VERSION         : %s\n",
				   KBOX_VERSION);
}

static void kbox_show_time_stamps(void)
{
	struct rtc_time rtc_time_val = { };
	struct timespec64 uptime;

	ktime_get_coarse_real_ts64(&uptime);
	rtc_time64_to_tm(uptime.tv_sec, &rtc_time_val);

	(void)kbox_dump_painc_info
		("Current time         : %04d-%02d-%02d %02d:%02d:%02d\n",
		 rtc_time_val.tm_year + 1900, rtc_time_val.tm_mon + 1,
		 rtc_time_val.tm_mday, rtc_time_val.tm_hour,
		 rtc_time_val.tm_min, rtc_time_val.tm_sec);
}

void kbox_dump_event(enum kbox_error_type_e type, unsigned long event,
		     const char *msg)
{
	if (!spin_trylock(&g_dump_lock))
		return;

	(void)kbox_dump_painc_info("\n====kbox begin dumping...====\n");

	switch (type) {
#ifdef CONFIG_X86
	case KBOX_MCE_EVENT:

		kbox_handle_mce_dump(msg);

		break;
#endif

	case KBOX_OPPS_EVENT:

		break;
	case KBOX_PANIC_EVENT:
		if (kbox_handle_panic_dump(msg) == KBOX_FALSE)
			goto end;

		break;
	default:
		break;
	}

	kbox_show_kernel_version();

	kbox_show_version();

	kbox_show_time_stamps();

	(void)kbox_dump_painc_info("\n====kbox end dump====\n");

	kbox_output_syslog_info();
	kbox_output_printk_info();

end:
	spin_unlock(&g_dump_lock);
}
