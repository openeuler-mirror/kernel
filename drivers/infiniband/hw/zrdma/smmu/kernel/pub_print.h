/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef PUB_PRINT_H
#define PUB_PRINT_H

#if defined(__KERNEL__)
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>
#include <linux/inetdevice.h>
#include <linux/io.h>
#include <linux/irqdomain.h>
#include <linux/irq.h>
#include <linux/of.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ethtool.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/fsl_devices.h>
#include <linux/mii.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/if_arp.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/cpumask.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/mman.h>
#include <linux/atomic.h>
#include <linux/smp.h>
#include <linux/kernel.h>
#else
#include <string.h>
#include <stdarg.h>
#endif
#include "cmdk.h"

#define PM_DEBUG ((u8)0x01)
#define PM_INFO ((u8)0x02)
#define PM_WARN ((u8)0x04)
#define PM_ERROR ((u8)0x08)
#define PM_FATAL ((u8)0x10)
#define DEFAULT_LEVEL ((u8)0x1E)

#define MAX_LEVEL_MASK ((u8)0x1F)

#define MAX_LEVEL_TYPE ((u8)0x05)
#define INVALID_MODULE_ID 0xFF

#define MAX_MDL_NAME_LEN 24
#define MAX_MODULE_ID ((u8)0x80)
#define MAX_MDL_PRINT_BUF_LEN 512

#define PM_FLAG_ON 1
#define PM_FLAG_OFF 0

extern u8 g_ucBySelfId;

#define PUB_PRINTF printk

#endif /* PUB_PRINT_H */
