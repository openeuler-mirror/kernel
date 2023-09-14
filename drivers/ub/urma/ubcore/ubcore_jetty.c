// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Description: ubcore jetty kernel module
 * Author: Ouyang Changchun
 * Create: 2021-11-25
 * Note:
 * History: 2021-11-25: create file
 * History: 2022-07-28: Yan Fangfang move jetty implementation here
 */

#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/poll.h>
#include "ubcore_log.h"
#include <urma/ubcore_types.h>
#include <urma/ubcore_uapi.h>
#include "ubcore_priv.h"

static uint32_t ubcore_get_eq_id(const struct ubcore_device *dev)
{
	uint32_t eq_id = 0;
	int cpu;

	if (dev->num_comp_vectors > 0) {
		cpu = get_cpu();
		eq_id = (uint32_t)(cpu % dev->num_comp_vectors);
		put_cpu();
	}
	return eq_id;
}

static int check_and_fill_jfc_attr(struct ubcore_jfc_cfg *cfg, const struct ubcore_jfc_cfg *user)
{
	if (cfg->depth < user->depth)
		return -1;

	/* store the immutable and skip the driver updated depth */
	cfg->flag = user->flag;
	cfg->jfc_context = user->jfc_context;
	return 0;
}

struct ubcore_jfc *ubcore_create_jfc(struct ubcore_device *dev, const struct ubcore_jfc_cfg *cfg,
				     ubcore_comp_callback_t jfce_handler,
				     ubcore_event_callback_t jfae_handler,
				     struct ubcore_udata *udata)
{
	struct ubcore_jfc *jfc;
	uint32_t eq_id;

	if (dev == NULL || cfg == NULL || dev->ops->create_jfc == NULL ||
	    dev->ops->destroy_jfc == NULL)
		return NULL;

	eq_id = ubcore_get_eq_id(dev);

	((struct ubcore_jfc_cfg *)cfg)->eq_id = eq_id;
	jfc = dev->ops->create_jfc(dev, cfg, udata);
	if (jfc == NULL) {
		ubcore_log_err("failed to create jfc.\n");
		return NULL;
	}

	if (check_and_fill_jfc_attr(&jfc->jfc_cfg, cfg) != 0) {
		(void)dev->ops->destroy_jfc(jfc);
		ubcore_log_err("jfc cfg is not qualified.\n");
		return NULL;
	}
	jfc->jfc_cfg.eq_id = eq_id;
	jfc->jfce_handler = jfce_handler;
	jfc->jfae_handler = jfae_handler;
	jfc->ub_dev = dev;
	jfc->uctx = ubcore_get_uctx(udata);
	atomic_set(&jfc->use_cnt, 0);

	if (ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFC], &jfc->hnode, jfc->id) != 0) {
		(void)dev->ops->destroy_jfc(jfc);
		ubcore_log_err("Failed to add jfc.\n");
		return NULL;
	}
	return jfc;
}
EXPORT_SYMBOL(ubcore_create_jfc);

int ubcore_modify_jfc(struct ubcore_jfc *jfc, const struct ubcore_jfc_attr *attr,
		      struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops->modify_jfc == NULL)
		return -EINVAL;

	jfc_id = jfc->id;
	dev = jfc->ub_dev;

	ret = dev->ops->modify_jfc(jfc, attr, udata);
	if (ret < 0)
		ubcore_log_err("UBEP failed to modify jfc, jfc_id:%u.\n", jfc_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jfc);

int ubcore_delete_jfc(struct ubcore_jfc *jfc)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops->destroy_jfc == NULL)
		return -1;

	if (WARN_ON_ONCE(atomic_read(&jfc->use_cnt)))
		return -EBUSY;

	jfc_id = jfc->id;
	dev = jfc->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFC], &jfc->hnode);
	ret = dev->ops->destroy_jfc(jfc);
	if (ret < 0)
		ubcore_log_err("UBEP failed to destroy jfc, jfc_id:%u.\n", jfc_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfc);
