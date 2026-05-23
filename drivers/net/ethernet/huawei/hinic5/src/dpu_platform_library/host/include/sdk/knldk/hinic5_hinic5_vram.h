/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hinic5_vram.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HINIC5_VRAM
#define HINIC5_HINIC5_VRAM

#include <linux/pci.h>
#include <linux/pm.h>

#include "mpu_inband_cmd_defs.h"

typedef int (*hiudk_flush_fn)(void *priv_data);
typedef struct hiudk_dev_flush_infos {
	void *lld_dev;
	hiudk_flush_fn flush_ops;

	/* private: Internal use */
	int ret;
} hiudk_dev_flush_infos;

typedef struct hiudk_async_ctrl {
	spinlock_t lock; /* spinlock protecting the hiudk_async_ctrl data structure */

	hiudk_dev_flush_infos flush_infos[CMD_MAX_MAX_PF_NUM];
} hiudk_async_ctrl;

int hinic5_wait_for_devices_flush(struct notifier_block *nb, unsigned long action, void *data);
int hiudk5_register_flush_fn(void *lld_dev, hiudk_flush_fn fn);
int hiudk5_unregister_flush_fn(void *lld_dev);
int hisdk5_hinic5_vram_init(void);
void hisdk5_hinic5_vram_deinit(void);

#endif