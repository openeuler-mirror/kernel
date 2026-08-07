/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DEBUG_H_
#define __VS_DEBUG_H_

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define MAX_DC_INTR_EVENT_SIZE 128

enum vs_debug_intr_partition {
	VS_DEBUG_INTR_FE0 = 0,
	VS_DEBUG_INTR_FE1 = 1,
	VS_DEBUG_INTR_BE = 2,
};

int vs_egt_debug_file_create(struct file **fp);
void vs_egt_debug_file_close(struct file **fp);
int vs_egt_debug_reset(struct file **fp);
void vs_egt_debug_dump_capture(struct file *fp, u32 addr, u32 value, bool is_read);
void vs_egt_debug_dump_interrupt(struct file *fp, const char *event,
				enum vs_debug_intr_partition part,
				bool multi_dest, u8 intr_dest);

#endif /* __VS_VIRTUAL_H_ */
