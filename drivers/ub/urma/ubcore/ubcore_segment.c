// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: ubcore segment
 * Author: Qian Guoxin, Ouyang Changchun
 * Create: 2022-07-28
 * Note:
 * History: 2022-07-28: Yan Fangfang move segment implementation here
 */

#include "ubcore_log.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_priv.h"
#include "ubcore_hash_table.h"
#include "ubcore_tp.h"
#include "ubcore_tp_table.h"

struct ubcore_key_id *ubcore_alloc_key_id(struct ubcore_device *dev, struct ubcore_udata *udata)
{
	struct ubcore_key_id *key;

	if (dev == NULL || dev->ops->alloc_key_id == NULL || dev->ops->free_key_id == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return NULL;
	}

	key = dev->ops->alloc_key_id(dev, udata);
	if (key == NULL) {
		ubcore_log_err("failed to alloc key id.\n");
		return NULL;
	}
	key->ub_dev = dev;
	key->uctx = ubcore_get_uctx(udata);
	atomic_set(&key->use_cnt, 0);
	return key;
}
EXPORT_SYMBOL(ubcore_alloc_key_id);

int ubcore_free_key_id(struct ubcore_key_id *key)
{
	struct ubcore_device *dev;

	if (key == NULL || key->ub_dev == NULL || key->ub_dev->ops->free_key_id == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}
	dev = key->ub_dev;

	if (WARN_ON_ONCE(atomic_read(&key->use_cnt)))
		return -EBUSY;

	return dev->ops->free_key_id(key);
}
EXPORT_SYMBOL(ubcore_free_key_id);
