/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_STATS_H__
#define __UBASE_STATS_H__

#include <ub/ubase/ubase_comm_stats.h>

struct ubase_query_mac_stats_cmd {
	__le16 port_id;
	u8 resv[6];
	__le64 stats_val[];
};

struct ubase_die_node {
	struct list_head	list;
	u16			chip_id;
	u16			die_id;
	u16			ref_cnt;
	u64			port_bitmap;
	u32			period[UBASE_MAX_PORT_NUM];
};

int __ubase_get_eth_port_stats(struct ubase_dev *udev,
			       struct ubase_eth_mac_stats *data);
int ubase_update_eth_stats_trylock(struct ubase_dev *udev);
void ubase_update_activate_stats(struct ubase_dev *udev, bool activate,
				 int result);
int __ubase_perf_stats(struct ubase_dev *udev, u64 port_bitmap, u32 period,
		       struct ubase_perf_stats_result *data, u32 data_size);
int ubase_die_list_init(struct ubase_dev *udev);
void ubase_die_list_uninit(struct ubase_dev *udev);

#endif /* __UBASE_STATS_H__ */
