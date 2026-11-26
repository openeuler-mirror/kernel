/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#ifndef __UB_CMD_H__
#define __UB_CMD_H__
#include <linux/bitmap.h>

#include "ub_common.h"

struct ucdev_list_node {
	u32 chip_id;
	u32 die_id;
	u64 port_bitmap;
	struct list_head dev_list;
	struct list_head list;
};

struct ubctl_port_link_info {
	time64_t time;
	u32 link_status;
};

struct ubctl_link_status {
	struct ubctl_port_link_info info;
	struct list_head list;
};

struct ubctl_port_link_list {
	u32 port;
	u32 port_type;
	u32 size;
	u32 link_up_num;
	u32 link_down_num;
	struct ubctl_link_status link_info_list;
	struct list_head port_link_list;
};

#define UBCTL_MAX_PORTS 32
/*
 * struct ubctl_port_info - port information structure
 *
 * @valid:            1 if valid, 0 if invalid/not found.
 * @port_type_bitmap: bitmap for port types.
 *                    bitn=1: portn is ub type.
 *                    bitn=0: portn is uboe type.
 * @port_id_bitmap:   bitmap for port presence.
 *                    bitn=1: portn exists.
 *                    bitn=0: portn does not exist.
 */
struct ubctl_port_info {
	u8 valid;
	unsigned long port_type_bitmap;
	unsigned long port_id_bitmap;
};

struct ubctl_func_dispatch *ubctl_get_query_func(struct ubctl_dev *ucdev,
						 u32 rpc_cmd);
int ubctl_port_link_status_init(struct auxiliary_device *adev, struct ubctl_dev *ucdev);
void ubctl_port_link_status_uninit(struct auxiliary_device *adev);
int ubctl_handle_link_status_event(void *dev, void *data, u32 len);
int ubctl_check_port_type(struct ubctl_dev *ucdev, struct ubctl_query_cmd_param *query_cmd_param,
			  u32 expect_port_type);
int ubctl_check_port_type_from_bitmap(struct ubctl_dev *ucdev,
				      struct ubctl_query_cmd_param *query_cmd_param,
				      u32 expect_port_type);
struct ucdev_list_node *ubctl_find_ucdev_list_node(u32 die_id, u32 chip_id);
struct ubctl_port_info ubctl_get_port_info(u32 die_id, u32 chip_id);
#endif
