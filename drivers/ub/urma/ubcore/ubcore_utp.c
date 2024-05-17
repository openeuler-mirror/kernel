// SPDX-License-Identifier: GPL-2.0
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
 * Description: ubcore utp implementation
 * Author: Ji Lei
 * Create: 2023-08-03
 * Note:
 * History: 2023-08-03: Create file
 */

#include <linux/slab.h>
#include "ubcore_log.h"
#include "ubcore_hash_table.h"
#include "ubcore_utp.h"

static int utp_get_active_mtu(struct ubcore_device *dev, uint8_t port_num,
	enum ubcore_mtu *mtu)
{
	struct ubcore_device_status st = { 0 };

	if (port_num >= dev->attr.port_cnt || dev->ops == NULL ||
		dev->ops->query_device_status == NULL || port_num >= UBCORE_MAX_PORT_CNT) {
		ubcore_log_err("Invalid parameter");
		return -1;
	}
	if (dev->ops->query_device_status(dev, &st) != 0) {
		ubcore_log_err("Failed to query query_device_status for port %hhu", port_num);
		return -1;
	}
	if (st.port_status[port_num].state != UBCORE_PORT_ACTIVE) {
		ubcore_log_err("Port %d is not active", port_num);
		return -1;
	}
	*mtu = st.port_status[port_num].active_mtu;
	return 0;
}

struct ubcore_utp *ubcore_create_utp(struct ubcore_device *dev, struct ubcore_utp_cfg *cfg)
{
	struct ubcore_utp *utp;
	enum ubcore_mtu mtu;
	int ret;

	if (dev->ops == NULL || dev->ops->create_utp == NULL)
		return NULL;

	if (((int32_t)cfg->mtu) == 0) {
		ret = utp_get_active_mtu(dev, (uint8_t)cfg->port_id, &mtu);
		if (ret < 0) {
			ubcore_log_warn("Failed to get active mtu, use default 1024");
			mtu = UBCORE_MTU_1024;
		}
		cfg->mtu = mtu;
		ubcore_log_info("Global cfg not config, device mtu is %d", (int32_t)cfg->mtu);
	}

	ubcore_log_info("Utp mtu config to %u", (uint32_t)cfg->mtu);

	utp = dev->ops->create_utp(dev, cfg, NULL);
	if (utp == NULL) {
		ubcore_log_err("Failed to create utp");
		return NULL;
	}
	utp->ub_dev = dev;
	utp->utp_cfg = *cfg;
	atomic_set(&utp->use_cnt, 1);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_UTP], &utp->hnode, utp->utpn);
	if (ret != 0) {
		(void)dev->ops->destroy_utp(utp);
		utp = NULL;
		ubcore_log_err("Failed to add utp to the utp table");
		return utp;
	}

	ubcore_log_info("Success to create utp, utp_idx %u", utp->utpn);
	return utp;
}

int ubcore_destroy_utp(struct ubcore_utp *utp)
{
	struct ubcore_device *dev = utp->ub_dev;
	uint32_t utp_idx = utp->utpn;
	int ret;

	if (dev->ops == NULL || dev->ops->destroy_utp == NULL)
		return -EINVAL;

	if (atomic_dec_return(&utp->use_cnt) > 0) {
		ubcore_log_err("utp in use");
		return -EBUSY;
	}

	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_UTP], &utp->hnode);

	ret = dev->ops->destroy_utp(utp);
	if (ret != 0) {
		(void)ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_UTP], &utp->hnode, utp->utpn);
		/* inc utp use cnt? */
		ubcore_log_err("Failed to destroy utp");
		return ret;
	}

	ubcore_log_info("Success to destroy utp, utp_idx %u", utp_idx);
	return ret;
}

struct ubcore_utp *ubcore_find_utp(struct ubcore_device *dev, uint32_t idx)
{
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_UTP], idx, &idx);
}
