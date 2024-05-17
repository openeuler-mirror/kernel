/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Description: ubcore main header
 * Author: Zhao Yusu
 * Create: 2024-02-27
 * Note:
 * History: 2024-02-27: Introduce ubcore version API
 */

#ifndef UBCORE_MAIN_H
#define UBCORE_MAIN_H

#include "ubcore_msg.h"

#define UBCORE_VERSION0 0x0
#define UBCORE_VERSION UBCORE_VERSION0
#define UBCORE_INVALID_VERSION 0xffffffff
#define UBCORE_SUPPORT_VERION_NUM 1
#define UBCORE_CAP 0x0

bool ubcore_negotiated(void);
uint32_t ubcore_get_version(void);
void ubcore_set_version(uint32_t version);
uint32_t ubcore_get_cap(void);
void ubcore_set_cap(uint32_t cap);
uint32_t *ubcore_get_support_versions(void);
int ubcore_negotiate_version(struct ubcore_msg_nego_ver_req *req, uint32_t *ver, uint32_t *cap);
int ubcore_recv_net_addr_update(struct ubcore_device *tpf_dev, struct ubcore_req_host *req);
int ubcore_send_eid_update_req(struct ubcore_device *dev, enum ubcore_net_addr_op op,
	union ubcore_eid *eid, uint32_t eid_idx, uint32_t *upi);
int ubcore_recv_eid_update_req(struct ubcore_device *tpf_dev, struct ubcore_req_host *req);

int ubcore_update_net_addr(struct ubcore_device *dev, struct net_device *netdev,
	struct ubcore_net_addr *netaddr, enum ubcore_net_addr_op op, bool async);
#endif
