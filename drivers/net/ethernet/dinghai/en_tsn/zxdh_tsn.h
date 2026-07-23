/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_TSN_H__
#define __ZXDH_TSN_H__
#include <linux/types.h>
#include <linux/hrtimer.h>
#include <linux/spinlock.h>
#include <linux/dinghai/driver.h>

#define TSN_PORT_RAM_NUM (2)
#define TSN_PORT_RAM_MAX (TSN_PORT_RAM_NUM - 1)
#define TSN_PORT_GCL_NUM (250)
#define TSN_PORT_GCL_EXT_NUM (6)
#define TSN_PORT_GCL_MAX (TSN_PORT_GCL_NUM + TSN_PORT_GCL_EXT_NUM - 1)
#define TSN_PORT_QUEUE_NUM (8)
#define TSN_PORT_QUEUE_MAX (TSN_PORT_QUEUE_NUM - 1)
#define TSN_PORT_PORT_ID_NUM (4)
#define TSN_PORT_PORT_ID_MAX (TSN_PORT_PORT_ID_NUM - 1)
#define TSN_PORT_PORT_ID_DEF (15)
#define TSN_PORT_TIMER_ID_NUM (4)
#define TSN_PORT_TIMER_ID_MAX (TSN_PORT_TIMER_ID_NUM - 1)

#define TSN_PORT_GATE_ENABLE (1)
#define TSN_PORT_GATE_DISABLE (0)
#define TSN_PORT_INIT_ENABLE (1)
#define TSN_PORT_INIT_DISABLE (0)
#define TSN_PORT_CHANGE_ENABLE (1)
#define TSN_PORT_CHANGE_DISABLE (0)

#define TSN_PORT_GATE_IDLE (0)
#define TSN_PORT_GATE_RUNNING (1)
#define TSN_PORT_GATE_CHANGING (2)
#define TSN_PORT_GATE_PENDING (3)

#define TSN_CYCLE_TIME_MIN (500000)
#define TSN_CYCLE_TIME_MAX (4000000000)
#define TSN_INTERVAL_TIME_MIN (1000)
#define TSN_INTERVAL_TIME_MAX (16000000)

struct zxdh_tsn_port_id {
	u32 port_id;
};

struct zxdh_tsn_timer_id {
	u32 timer_id;
};

struct zxdh_tsn_qbv_cap {
	u64 ct_min;
	u64 ct_max;
	u32 it_min;
	u32 it_max;
	u32 gcl_num;
};

struct zxdh_tsn_qbv_entry {
	u32 gate_state;
	u32 time_interval;
};

struct zxdh_tsn_qbv_basic {
	u64 base_time;
	u64 cycle_time;
	u32 maxsdu[TSN_PORT_QUEUE_NUM];
	u32 guard_band_time[TSN_PORT_QUEUE_NUM];
	u32 control_list_length;
	struct zxdh_tsn_qbv_entry control_list[TSN_PORT_GCL_NUM];
};

struct zxdh_tsn_qbv_conf {
	u32 enable;
	struct zxdh_tsn_qbv_basic admin;
};

struct zxdh_tsn_qbv_status {
	u64 current_time;
	u32 current_status;
	struct zxdh_tsn_qbv_basic oper;
};

struct zxdh_tsn_private {
	u32 phy_port_id;
	u64 pci_ioremap_addr;
	u64 tsn_reg_base_addr;

	struct zxdh_tsn_port_id tsn_port_id;
	struct zxdh_tsn_qbv_cap tsn_qbv_cap;
	struct zxdh_tsn_qbv_conf tsn_qbv_conf[TSN_PORT_RAM_NUM];
	struct hrtimer tsn_qbv_change_timer;

	spinlock_t tsn_spin_lock;
};

s32 zxdh_tsn_init(struct dh_core_dev *dh_dev);
void zxdh_tsn_exit(struct dh_core_dev *dh_dev);

#endif /* __ZXDH_TSN_H__ */
