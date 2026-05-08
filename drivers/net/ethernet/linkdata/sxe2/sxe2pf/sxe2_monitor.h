/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_monitor.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_MONITOR_H__
#define __SXE2_MONITOR_H__

#include <linux/types.h>

#define SXE2_NORMAL_TIMER_PERIOD (2 * HZ)

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

enum sxe2_monitor_task_state {
	SXE2_MONITOR_WORK_INITED,

	SXE2_MONITOR_WORK_SCHED,
	SXE2_MONITOR_WORK_DISABLED,
};

struct sxe2_monitor_context {
	struct timer_list timer;
	unsigned long period;
	unsigned long state;
	struct work_struct work;

	/* in order to protect the data */
	spinlock_t lock;
};

enum sxe2_link_get_speed {
	SXE2_LINK_SPEED_UNKNOWN = 0,
	SXE2_LINK_SPEED_10G = 10000,
	SXE2_LINK_SPEED_25G = 25000,
	SXE2_LINK_SPEED_50G = 50000,
	SXE2_LINK_SPEED_100G = 100000,
	SXE2_LINK_SPEED_AUTO = 200000,
};

enum sxe2_speed_cap {
	LINK_SPEED_UNKNOWN,
	LINK_SPEED_1G = 0x1,
	LINK_SPEED_10G = 0x2,
	LINK_SPEED_25G = 0x4,
	LINK_SPEED_50G = 0x8,
	LINK_SPEED_100G = 0x10,
};

enum sxe2_link_get_status {
	SXE2_LINK_DOWN = 0,
	SXE2_LINK_UP = 1,
	SXE2_LINK_ERROR = 15,
};

struct sxe2_mac_sync_entry {
	struct list_head list_entry;
	u8 mac_addr[ETH_ALEN];
};

struct sxe2_cmd_link_context {
	u32 fec;
	u32 current_link_speed;
	bool tx_fc;
	bool rx_fc;

	/* in order to protect the data */
	struct mutex link_status_lock;
};

void sxe2_monitor_init(struct sxe2_adapter *adapter);

void sxe2_monitor_work_schedule(struct sxe2_adapter *adapter);

void sxe2_work_cb(struct work_struct *work);

void sxe2_monitor_stop(struct sxe2_adapter *adapter);

void sxe2_monitor_start(struct sxe2_adapter *adapter);

s32 sxe2_monitor_create(void);

void sxe2_monitor_destroy(void);

int sxe2_sync_mac_add(struct net_device *netdev, const u8 *addr);

int sxe2_unsync_mac_add(struct net_device *netdev, const u8 *addr);

#if defined(SXE2_HARDWARE_ASIC)
u32 sxe2_get_link_speed(struct sxe2_adapter *adapter);

bool sxe2_get_pf_link_status(struct sxe2_adapter *adapter);
#endif
#endif
