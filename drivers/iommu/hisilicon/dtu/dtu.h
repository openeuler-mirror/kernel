/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu logical-layer definitions.
 */

#ifndef __UMMU_DTU_H__
#define __UMMU_DTU_H__

#include <linux/device.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/ummu_core.h>

#include "dtu_comm.h"
#include "dtu_addr_window.h"

#define UB_DTU_DRV_NAME	"ub_dtu"

/* command queue disabled after unrecoverable error */
enum dtu_cmd_state {
	DTU_STATE_CMD_DISABLE,
};

#define dtu_err(_udev, fmt, ...) \
	dev_err((_udev)->dev, fmt, ##__VA_ARGS__)
#define dtu_dbg(_udev, fmt, ...) \
	dev_dbg((_udev)->dev, fmt, ##__VA_ARGS__)

/* Mapped window record — one per successful map_pages */
struct ub_dtu_win {
	unsigned long		iova;
	phys_addr_t		pa;
	size_t			size;
	u8			win_id;
	struct list_head	node;
};

/* Per-master (IO device) private data */
struct ub_dtu_master {
	struct ub_dtu_logic_dev	*logic_dtu;
};

/* Global logic DTU singleton — aggregates N physical dies */
struct ub_dtu_logic_dev {
	struct ummu_core_device	core_dev;
	struct ub_dtu_device	*agent_device;
	struct list_head	dev_list;
	struct mutex		dev_mutex;
	u32			dtu_cnt;
	struct dtu_win_mgr	mgr;
};

/* Per-IOMMU-domain DTU private context */
struct ub_dtu_logic_domain {
	struct ummu_base_domain		base_domain;
	struct ub_dtu_logic_dev		*logic_dtu;
	struct mutex			domain_lock;
	struct list_head		win_list;
};

/* Called by ummu_main at probe / remove time */
int  ub_dtu_probe(struct device *dev);
void ub_dtu_remove(struct device *dev);

#endif /* __UMMU_DTU_H__ */
