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

struct ubcore_target_seg *ubcore_register_seg(struct ubcore_device *dev,
					      const struct ubcore_seg_cfg *cfg,
					      struct ubcore_udata *udata)
{
	struct ubcore_target_seg *tseg;

	if (dev == NULL || cfg == NULL || dev->ops->register_seg == NULL ||
	    dev->ops->unregister_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return NULL;
	}

	if ((cfg->flag.bs.access & (UBCORE_ACCESS_REMOTE_WRITE | UBCORE_ACCESS_REMOTE_ATOMIC)) &&
	    !(cfg->flag.bs.access & UBCORE_ACCESS_LOCAL_WRITE)) {
		ubcore_log_err(
			"Local write must be set when either remote write or remote atomic is declared.\n");
		return NULL;
	}

	tseg = dev->ops->register_seg(dev, cfg, udata);
	if (tseg == NULL) {
		ubcore_log_err("UBEP failed to register segment with va:%llu\n", cfg->va);
		return NULL;
	}

	tseg->ub_dev = dev;
	tseg->uctx = ubcore_get_uctx(udata);
	tseg->seg.len = cfg->len;
	tseg->seg.ubva.va = cfg->va;
	tseg->keyid = cfg->keyid;

	(void)memcpy(tseg->seg.ubva.eid.raw, dev->attr.eid.raw, UBCORE_EID_SIZE);
	(void)memcpy(&tseg->seg.attr, &cfg->flag, sizeof(union ubcore_reg_seg_flag));
	atomic_set(&tseg->use_cnt, 0);
	if (tseg->keyid != NULL)
		atomic_inc(&tseg->keyid->use_cnt);

	return tseg;
}
EXPORT_SYMBOL(ubcore_register_seg);

int ubcore_unregister_seg(struct ubcore_target_seg *tseg)
{
	struct ubcore_device *dev;
	int ret;

	if (tseg == NULL || tseg->ub_dev == NULL || tseg->ub_dev->ops->unregister_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}
	dev = tseg->ub_dev;

	if (tseg->keyid != NULL)
		atomic_dec(&tseg->keyid->use_cnt);

	ret = dev->ops->unregister_seg(tseg);
	return ret;
}
EXPORT_SYMBOL(ubcore_unregister_seg);

struct ubcore_target_seg *ubcore_import_seg(struct ubcore_device *dev,
					    const struct ubcore_target_seg_cfg *cfg,
					    struct ubcore_udata *udata)
{
	struct ubcore_target_seg *tseg;

	if (dev == NULL || cfg == NULL || dev->ops->import_seg == NULL ||
	    dev->ops->unimport_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return NULL;
	}

	tseg = dev->ops->import_seg(dev, cfg, udata);
	if (tseg == NULL) {
		ubcore_log_err("UBEP failed to import segment with va:%llu\n", cfg->seg.ubva.va);
		return NULL;
	}
	tseg->ub_dev = dev;
	tseg->uctx = ubcore_get_uctx(udata);
	tseg->seg = cfg->seg;
	atomic_set(&tseg->use_cnt, 0);

	return tseg;
}
EXPORT_SYMBOL(ubcore_import_seg);

int ubcore_unimport_seg(struct ubcore_target_seg *tseg)
{
	struct ubcore_device *dev;

	if (tseg == NULL || tseg->ub_dev == NULL || tseg->ub_dev->ops->unimport_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}
	dev = tseg->ub_dev;

	return dev->ops->unimport_seg(tseg);
}
EXPORT_SYMBOL(ubcore_unimport_seg);
