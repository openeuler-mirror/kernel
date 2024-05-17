/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore netdev head file
 * Author: Chen Wen
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14: Create file
 */

#ifndef UBCORE_NETDEV_H
#define UBCORE_NETDEV_H

#include <urma/ubcore_types.h>

int ubcore_check_port_state(struct ubcore_device *dev);
void ubcore_fill_port_netdev(struct ubcore_device *dev,
	struct net_device *ndev, uint8_t *port_list, uint8_t *port_cnt);

int ubcore_sip_table_init(struct ubcore_sip_table *sip_table, uint32_t size);
void ubcore_sip_table_uninit(struct ubcore_sip_table *sip_table);

uint32_t ubcore_sip_idx_alloc(struct ubcore_sip_table *sip_table);
int ubcore_sip_idx_free(struct ubcore_sip_table *sip_table, uint32_t idx);

int ubcore_add_sip_entry(struct ubcore_sip_table *sip_table, struct ubcore_sip_info *sip,
	uint32_t idx);
int ubcore_del_sip_entry(struct ubcore_sip_table *sip_table, uint32_t idx);
int ubcore_lookup_sip_idx(struct ubcore_sip_table *sip_table, struct ubcore_sip_info *sip,
	uint32_t *idx);
int ubcore_update_sip_entry(struct ubcore_sip_table *sip_table, struct ubcore_sip_info *new_sip,
	uint32_t *sip_idx, struct ubcore_sip_info *old_sip);
struct ubcore_device *ubcore_lookup_tpf_by_sip_addr(union ubcore_net_addr_union *addr);
int ubcore_notify_uvs_add_sip(struct ubcore_device *dev,
	const struct ubcore_sip_info *sip, uint32_t index);
int ubcore_notify_uvs_del_sip(struct ubcore_device *dev,
	const struct ubcore_sip_info *sip, uint32_t index);

struct ubcore_sip_info *ubcore_lookup_sip_info_without_lock(
	struct ubcore_sip_table *sip_table, uint32_t idx);
struct ubcore_nlmsg *ubcore_new_sip_req_msg(struct ubcore_device *dev,
	struct ubcore_sip_info *sip_info, uint32_t index);
#endif
