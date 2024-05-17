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
#include "ubcore_device.h"
#include "ubcore_utp.h"

int utp_get_active_mtu(struct ubcore_device *dev, uint8_t port_num,
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

static void ubcore_utp_kref_release(struct kref *ref_cnt)
{
	struct ubcore_utp *utp = container_of(ref_cnt, struct ubcore_utp, ref_cnt);

	complete(&utp->comp);
}

void ubcore_utp_kref_put(struct ubcore_utp *utp)
{
	(void)kref_put(&utp->ref_cnt, ubcore_utp_kref_release);
}

void ubcore_utp_get(void *obj)
{
	struct ubcore_utp *utp = obj;

	kref_get(&utp->ref_cnt);
}

struct ubcore_utp *ubcore_create_utp(struct ubcore_device *dev, struct ubcore_utp_cfg *cfg)
{
	struct ubcore_utp *utp;
	int ret;

	if (dev->ops == NULL || dev->ops->create_utp == NULL)
		return NULL;

	ubcore_log_info("Utp mtu config to %u", (uint32_t)cfg->mtu);

	utp = dev->ops->create_utp(dev, cfg, NULL);
	if (utp == NULL) {
		ubcore_log_err("Failed to create utp");
		return NULL;
	}
	utp->ub_dev = dev;
	utp->utp_cfg = *cfg;
	atomic_set(&utp->use_cnt, 0);
	kref_init(&utp->ref_cnt);
	init_completion(&utp->comp);

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

	ubcore_utp_kref_put(utp);
	wait_for_completion(&utp->comp);
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

struct ubcore_utp *ubcore_find_get_utp(struct ubcore_device *dev, uint32_t idx)
{
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_UTP], idx, &idx);
}

struct ubcore_utp *ubcore_find_remove_utp(struct ubcore_device *dev, uint32_t idx)
{
	struct ubcore_utp *utp;

	spin_lock(&dev->ht[UBCORE_HT_UTP].lock);
	if (&dev->ht[UBCORE_HT_UTP].head == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_UTP].lock);
		return NULL;
	}
	utp = ubcore_hash_table_lookup_nolock(&dev->ht[UBCORE_HT_UTP], idx, &idx);
	if (utp == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_UTP].lock);
		return NULL;
	}
	if (atomic_read(&utp->use_cnt) > 0) {
		spin_unlock(&dev->ht[UBCORE_HT_UTP].lock);
		ubcore_log_err("Failed to remove utp");
		return NULL;
	}
	ubcore_hash_table_remove_nolock(&dev->ht[UBCORE_HT_UTP], &utp->hnode);
	spin_unlock(&dev->ht[UBCORE_HT_UTP].lock);

	return utp;
}
