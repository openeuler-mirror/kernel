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

#include <asm/types.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/err.h>
#include "kbox_include.h"
#include "kbox_panic.h"
#include "kbox_ram_op.h"

#ifdef CONFIG_X86
#include <asm/msr.h>
#endif

#define PANIC_TMP_BUF_SIZE 256

static int g_panic_init_ok = KBOX_FALSE;

static char *g_panic_info_buf_tmp;
static char *g_panic_info_buf;

static unsigned int g_panic_info_start;

static unsigned int g_panic_info_end;

static unsigned int g_panic_info_len;

static DEFINE_SPINLOCK(g_panic_buf_lock);

static void kbox_emit_syslog_char(const char c)
{
	if (unlikely(!g_panic_info_buf))
		return;

	*(g_panic_info_buf + (g_panic_info_end % SLOT_LENGTH)) = c;
	g_panic_info_end++;

	if (g_panic_info_end > SLOT_LENGTH)
		g_panic_info_start++;

	if (g_panic_info_len < SLOT_LENGTH)
		g_panic_info_len++;
}

static int kbox_duplicate_syslog_info(const char *syslog_buf,
				      unsigned int buf_len)
{
	unsigned int idx = 0;
	unsigned long flags = 0;

	if (!syslog_buf)
		return 0;

	spin_lock_irqsave(&g_panic_buf_lock, flags);

	for (idx = 0; idx < buf_len; idx++)
		kbox_emit_syslog_char(*syslog_buf++);

	spin_unlock_irqrestore(&g_panic_buf_lock, flags);

	return buf_len;
}

int kbox_dump_painc_info(const char *fmt, ...)
{
	va_list args;
	int num = 0;
	char tmp_buf[PANIC_TMP_BUF_SIZE] = { };

	va_start(args, fmt);

	num = vsnprintf(tmp_buf, sizeof(tmp_buf) - 1, fmt, args);
	if (num >= 0)
		(void)kbox_duplicate_syslog_info(tmp_buf, num);

	va_end(args);

	return num;
}

void kbox_output_syslog_info(void)
{
	unsigned int start_tmp = 0;
	unsigned int end_tmp = 0;
	unsigned int len_tmp = 0;
	unsigned long flags = 0;

	if (unlikely
	    (!g_panic_info_buf || !g_panic_info_buf_tmp))
		return;

	spin_lock_irqsave(&g_panic_buf_lock, flags);
	if (g_panic_info_len == 0) {
		spin_unlock_irqrestore(&g_panic_buf_lock, flags);
		return;
	}

	start_tmp = (g_panic_info_start % SLOT_LENGTH);
	end_tmp = ((g_panic_info_end - 1) % SLOT_LENGTH);
	len_tmp = g_panic_info_len;

	if (start_tmp > end_tmp) {
		memcpy(g_panic_info_buf_tmp,
		       (g_panic_info_buf + start_tmp),
			len_tmp - start_tmp);
		memcpy((g_panic_info_buf_tmp + len_tmp - start_tmp),
		       g_panic_info_buf,
			end_tmp + 1);
	} else {
		memcpy(g_panic_info_buf_tmp,
		       (char *)(g_panic_info_buf + start_tmp),
			len_tmp);
	}

	spin_unlock_irqrestore(&g_panic_buf_lock, flags);

	(void)kbox_write_panic_info(g_panic_info_buf_tmp, len_tmp);
}

int kbox_panic_init(void)
{
	int ret = KBOX_TRUE;

	g_panic_info_buf = kmalloc(SLOT_LENGTH, GFP_KERNEL);
	if (!g_panic_info_buf) {
		KBOX_MSG("kmalloc g_panic_info_buf fail!\n");
		ret = -ENOMEM;
		goto fail;
	}

	memset(g_panic_info_buf, 0, SLOT_LENGTH);

	g_panic_info_buf_tmp = kmalloc(SLOT_LENGTH, GFP_KERNEL);
	if (!g_panic_info_buf_tmp) {
		KBOX_MSG("kmalloc g_panic_info_buf_tmp fail!\n");
		ret = -ENOMEM;
		goto fail;
	}

	memset(g_panic_info_buf_tmp, 0, SLOT_LENGTH);

	g_panic_init_ok = KBOX_TRUE;

	return ret;
fail:

	kfree(g_panic_info_buf);
	g_panic_info_buf = NULL;

	kfree(g_panic_info_buf_tmp);
	g_panic_info_buf_tmp = NULL;

	return ret;
}

void kbox_panic_exit(void)
{
	if (g_panic_init_ok != KBOX_TRUE)
		return;

	kfree(g_panic_info_buf);
	g_panic_info_buf = NULL;

	kfree(g_panic_info_buf_tmp);
	g_panic_info_buf_tmp = NULL;
}

int kbox_handle_panic_dump(const char *msg)
{
	if (msg)
		(void)kbox_dump_painc_info("panic string: %s\n", msg);

	return KBOX_TRUE;
}
