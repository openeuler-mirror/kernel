// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/list.h>

#include "ub_cmd.h"

struct ubctl_port_info ubctl_get_port_info(u32 die_id, u32 chip_id)
{
	struct ucdev_list_node *devnode = ubctl_find_ucdev_list_node(die_id, chip_id);
	struct ubctl_port_link_list *list_node = NULL;
	struct ubctl_port_info port_info;

	memset(&port_info, 0, sizeof(port_info));
	if (!devnode)
		return port_info;

	list_for_each_entry(list_node, &devnode->dev_list, port_link_list) {
		set_bit(list_node->port, &port_info.port_id_bitmap);
		if (list_node->port_type)
			set_bit(list_node->port, &port_info.port_type_bitmap);
	}
	port_info.valid = 1;
	return port_info;
}
EXPORT_SYMBOL(ubctl_get_port_info);
