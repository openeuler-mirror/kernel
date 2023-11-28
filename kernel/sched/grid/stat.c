// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for QOS-aware smart grid Scheduling
 *
 * Copyright (C) 2023-2024 Huawei Technologies Co., Ltd
 *
 * Author: Wang Shaobo <bobo.shaobowang@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/sched/grid_qos.h>
#include "internal.h"

static int qos_stat_set_class_level(struct sched_grid_qos_stat *qos_stat, int level)
{
	if (qos_stat == NULL || level >= SCHED_GRID_QOS_TASK_LEVEL_MAX)
		return -EINVAL;

	qos_stat->class_lvl = level;
	return 0;
}

void qos_stat_init(struct sched_grid_qos_stat *stat)
{
	if (stat == NULL)
		return;

	stat->sample[SCHED_GRID_QOS_IPS_INDEX].name = "ips";
	stat->sample[SCHED_GRID_QOS_IPS_INDEX].index = SCHED_GRID_QOS_IPS_INDEX;
	stat->sample[SCHED_GRID_QOS_MEMBOUND_RATIO_INDEX].name = "membound_ratio";
	stat->sample[SCHED_GRID_QOS_MEMBOUND_RATIO_INDEX].index =
		SCHED_GRID_QOS_MEMBOUND_RATIO_INDEX;
	stat->sample[SCHED_GRID_QOS_MEMBANDWIDTH_INDEX].name = "memband_width";
	stat->sample[SCHED_GRID_QOS_MEMBANDWIDTH_INDEX].index =
		SCHED_GRID_QOS_MEMBANDWIDTH_INDEX;

	stat->set_class_lvl = qos_stat_set_class_level;
	stat->class_lvl = SCHED_GRID_QOS_TASK_LEVEL_DEFAULT;
}
