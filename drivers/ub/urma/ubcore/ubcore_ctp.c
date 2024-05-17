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
 * Description: ubcore ctp implementation
 * Author: Xu Zhicong
 * Create: 2023-10-12
 * Note:
 * History: 2023-10-12: Create file
 */

#include <linux/slab.h>
#include "ubcore_log.h"
#include "ubcore_hash_table.h"
#include "ubcore_ctp.h"

struct ubcore_ctp *ubcore_create_ctp(struct ubcore_device *dev, struct ubcore_ctp_cfg *cfg)
{
	struct ubcore_ctp *ctp;
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->create_ctp == NULL)
		return NULL;

	ctp = dev->ops->create_ctp(dev, cfg, NULL);
	if (ctp == NULL) {
		ubcore_log_err("Failed to create ctp");
		return NULL;
	}
	ctp->ub_dev = dev;
	ctp->ctp_cfg = *cfg;
	atomic_set(&ctp->use_cnt, 0);
	kref_init(&ctp->ref_cnt);
	init_completion(&ctp->comp);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_CTP], &ctp->hnode, ctp->ctpn);
	if (ret != 0) {
		(void)dev->ops->destroy_ctp(ctp);
		ctp = NULL;
		ubcore_log_err("Failed to add ctp to the ctp table");
		return ctp;
	}

	ubcore_log_info("Success to create ctp, ctp_idx %u", ctp->ctpn);
	return ctp;
}

static void ubcore_ctp_kref_release(struct kref *ref_cnt)
{
	struct ubcore_ctp *ctp = container_of(ref_cnt, struct ubcore_ctp, ref_cnt);

	complete(&ctp->comp);
}

void ubcore_ctp_kref_put(struct ubcore_ctp *ctp)
{
	(void)kref_put(&ctp->ref_cnt, ubcore_ctp_kref_release);
}

void ubcore_ctp_get(void *obj)
{
	struct ubcore_ctp *ctp = obj;

	kref_get(&ctp->ref_cnt);
}

int ubcore_destroy_ctp(struct ubcore_ctp *ctp)
{
	struct ubcore_device *dev = ctp->ub_dev;
	uint32_t ctp_idx = ctp->ctpn;
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->destroy_ctp == NULL)
		return -EINVAL;

	ubcore_ctp_kref_put(ctp);
	wait_for_completion(&ctp->comp);
	ret = dev->ops->destroy_ctp(ctp);
	if (ret != 0) {
		(void)ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_CTP], &ctp->hnode, ctp->ctpn);
		/* inc ctp use cnt? */
		ubcore_log_err("Failed to destroy ctp");
		return ret;
	}

	ubcore_log_info("Success to destroy ctp, ctp_idx %u", ctp_idx);
	return ret;
}

struct ubcore_ctp *ubcore_find_ctp(struct ubcore_device *dev, uint32_t idx)
{
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_CTP], idx, &idx);
}

struct ubcore_ctp *ubcore_find_get_ctp(struct ubcore_device *dev, uint32_t idx)
{
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_CTP], idx, &idx);
}

struct ubcore_ctp *ubcore_find_remove_ctp(struct ubcore_device *dev, uint32_t idx)
{
	struct ubcore_ctp *ctp;

	spin_lock(&dev->ht[UBCORE_HT_CTP].lock);
	if (&dev->ht[UBCORE_HT_CTP].head == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_CTP].lock);
		return NULL;
	}
	ctp = ubcore_hash_table_lookup_nolock(&dev->ht[UBCORE_HT_CTP], idx, &idx);
	if (ctp == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_CTP].lock);
		return NULL;
	}
	if (atomic_read(&ctp->use_cnt) > 0) {
		spin_unlock(&dev->ht[UBCORE_HT_CTP].lock);
		ubcore_log_err("Failed to remove ctp");
		return NULL;
	}
	ubcore_hash_table_remove_nolock(&dev->ht[UBCORE_HT_CTP], &ctp->hnode);
	spin_unlock(&dev->ht[UBCORE_HT_CTP].lock);

	return ctp;
}
