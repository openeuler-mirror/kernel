/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _FUC_HOTPLUG_H_
#define _FUC_HOTPLUG_H_
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/err.h>
#include <linux/msi.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <linux/dinghai/log.h>

#define FUC_HP_EVENT_ID 44
#define BUF_SIZE 0x1000

#define FUC_HP_BAR_MSG_OFFSET (0x2000)
#define FUC_HP_VENDOR_ID (0x1cf2)
#define FUC_HP_DEVICE_ID (0x8044)
#define FUC_HP_IOREMAP_SIZE (0x3000)

#define FUC_HP_POLLING_SPAN 100
#define FUC_HP_TIMEOUT_TH 3000

struct func_sel {
	unsigned int cmd;
	int (*ioctl_func)(unsigned long long arg);
};

extern int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in,
				       struct zxdh_msg_recviver_mem *result);
extern int get_fuc_hp_ret(void);
extern int reset_fuc_hp_ret(void);
#endif
