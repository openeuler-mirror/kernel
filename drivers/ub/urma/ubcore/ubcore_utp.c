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

static void ubcore_destroy_utp(struct ubcore_utp *utp)
{
	struct ubcore_device *dev = utp->ub_dev;
	uint32_t utp_idx = utp->utpn;
	int ret;

	if (dev->ops == NULL || dev->ops->destroy_utp == NULL)
		return;

	ret = dev->ops->destroy_utp(utp);
	if (ret != 0) {
		ubcore_log_err("Failed to destroy utp:%u", utp_idx);
		return;
	}
}

static void ubcore_utp_kref_release(struct kref *ref_cnt)
{
	struct ubcore_utp *utp = container_of(ref_cnt, struct ubcore_utp, ref_cnt);

	ubcore_destroy_utp(utp);
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

static void ubcore_utp_kref_get(struct ubcore_utp *utp)
{
	kref_get(&utp->ref_cnt);
}

static int ubcore_find_add_utp(struct ubcore_hash_table *ht, struct ubcore_utp *utp)
{
	struct hlist_node *hnode = &utp->hnode;
	uint32_t hash = utp->utpn;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return -EINVAL;
	}
	if (ubcore_hash_table_lookup_nolock(ht, hash, ubcore_ht_key(ht, hnode)) != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}
	ubcore_hash_table_add_nolock(ht, hnode, hash);
	ubcore_utp_kref_get(utp);
	spin_unlock(&ht->lock);
	return 0;
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
	kref_init(&utp->ref_cnt);

	ret = ubcore_find_add_utp(&dev->ht[UBCORE_HT_UTP], utp);
	if (ret != 0) {
		ubcore_utp_kref_put(utp);
		ubcore_log_err("Failed to add utp to the utp table");
		return NULL;
	}
	return utp;
}

struct ubcore_utp *ubcore_find_utp(struct ubcore_device *dev, uint32_t idx)
{
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_UTP], idx, &idx);
}

struct ubcore_utp *ubcore_find_get_utp(struct ubcore_device *dev, uint32_t idx)
{
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_UTP], idx, &idx);
}

void ubcore_find_remove_utp(struct ubcore_device *dev, uint32_t idx)
{
	struct ubcore_utp *utp;

	spin_lock(&dev->ht[UBCORE_HT_UTP].lock);
	if (&dev->ht[UBCORE_HT_UTP].head == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_UTP].lock);
		return;
	}
	utp = ubcore_hash_table_lookup_nolock(&dev->ht[UBCORE_HT_UTP], idx, &idx);
	if (utp == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_UTP].lock);
		return;
	}
	ubcore_hash_table_remove_nolock(&dev->ht[UBCORE_HT_UTP], &utp->hnode);
	ubcore_utp_kref_put(utp);
	spin_unlock(&dev->ht[UBCORE_HT_UTP].lock);
}
