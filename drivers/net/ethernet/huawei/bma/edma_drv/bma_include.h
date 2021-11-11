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

#ifndef _BMA_INCLUDE_H_
#define _BMA_INCLUDE_H_

#include <linux/slab.h>
#include <asm/ioctls.h>
#include <linux/capability.h>
#include <linux/uaccess.h>	/* copy_*_user */
#include <linux/delay.h>	/* udelay */
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>	/*tasklet */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/sched.h>

#define UNUSED(x) (x = x)
#define KBOX_FALSE (-1)
#define KBOX_TRUE 0

#define KBOX_IOC_MAGIC (0xB2)

#define DEFAULT_MAX_RECV_MSG_NUMS   32
#define MAX_RECV_MSG_NUMS 1024

#define STRFICATION(R) #R
#define MICRO_TO_STR(R) STRFICATION(R)

enum {
	DLOG_ERROR = 0,
	DLOG_DEBUG = 1,
};

enum {
	DEV_CLOSE = 0,
	DEV_OPEN = 1,
	DEV_OPEN_STATUS_REQ = 0xf0,
	DEV_OPEN_STATUS_ANS
};

struct bma_user_s {
	struct list_head link;

	u32 type;
	u32 sub_type;
	u8 user_id;

	u8 dma_transfer:1, support_int:1;

	u8 reserve1[2];
	u32 seq;
	u16 cur_recvmsg_nums;
	u16 max_recvmsg_nums;
};

struct bma_priv_data_veth_s {
	struct pci_dev *pdev;

	unsigned long veth_swap_phy_addr;
	void __iomem *veth_swap_addr;
	unsigned long veth_swap_len;
};

struct bma_priv_data_s {
	struct bma_user_s user;
	/* spinlock for recv msg list */
	spinlock_t recv_msg_lock;
	struct list_head recv_msgs;
	struct file *file;
	wait_queue_head_t wait;

	union {
		struct bma_priv_data_veth_s veth;
	} specific;
};

#if defined(timer_setup) && defined(from_timer)
#define HAVE_TIMER_SETUP
#endif

void __iomem *kbox_get_base_addr(void);
unsigned long kbox_get_io_len(void);
unsigned long kbox_get_base_phy_addr(void);
int edma_param_set_debug(const char *buf, const struct kernel_param *kp);

#define GET_SYS_SECONDS(t) do \
	{\
		struct timespec64 uptime;\
		ktime_get_coarse_real_ts64(&uptime);\
		t = uptime.tv_sec;\
	} while (0)

#define SECONDS_PER_DAY (24 * 3600)
#define SECONDS_PER_HOUR (3600)
#define SECONDS_PER_MINUTE (60)

#endif
