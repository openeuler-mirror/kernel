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

struct ubcore_token_id *ubcore_alloc_token_id(struct ubcore_device *dev,
	struct ubcore_udata *udata)
{
	struct ubcore_token_id *token_id;

	if (dev == NULL || dev->ops == NULL || dev->ops->alloc_token_id == NULL ||
		dev->ops->free_token_id == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return NULL;
	}

	token_id = dev->ops->alloc_token_id(dev, udata);
	if (token_id == NULL) {
		ubcore_log_err("failed to alloc token_id id.\n");
		return NULL;
	}
	token_id->ub_dev = dev;
	token_id->uctx = ubcore_get_uctx(udata);
	atomic_set(&token_id->use_cnt, 0);
	return token_id;
}
EXPORT_SYMBOL(ubcore_alloc_token_id);

int ubcore_free_token_id(struct ubcore_token_id *token_id)
{
	struct ubcore_device *dev;

	if (token_id == NULL || token_id->ub_dev == NULL || token_id->ub_dev->ops == NULL ||
		token_id->ub_dev->ops->free_token_id == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	dev = token_id->ub_dev;

	if (atomic_read(&token_id->use_cnt)) {
		ubcore_log_err("The token_id is still being used");
		return -EBUSY;
	}
	return dev->ops->free_token_id(token_id);
}
EXPORT_SYMBOL(ubcore_free_token_id);

static int ubcore_check_ops_register_seg(struct ubcore_device *dev, struct ubcore_seg_cfg *cfg)
{
	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->register_seg == NULL ||
	    dev->ops->unregister_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}
	return 0;
}

struct ubcore_target_seg *ubcore_register_seg(struct ubcore_device *dev,
					      struct ubcore_seg_cfg *cfg,
					      struct ubcore_udata *udata)
{
	bool alloc_token_id = false;
	struct ubcore_seg_cfg tmp_cfg;
	struct ubcore_target_seg *tseg;

	if (ubcore_check_ops_register_seg(dev, cfg) != 0)
		return NULL;

	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
		((cfg->flag.bs.token_id_valid == UBCORE_TOKEN_ID_VALID && cfg->token_id == NULL) ||
		(cfg->flag.bs.token_id_valid == UBCORE_TOKEN_ID_INVALID &&
			cfg->token_id != NULL))) {
		ubcore_log_err("invalid parameter of token_id.\n");
		return NULL;
	}

	if ((cfg->flag.bs.access & (UBCORE_ACCESS_REMOTE_WRITE | UBCORE_ACCESS_REMOTE_ATOMIC)) &&
	    !(cfg->flag.bs.access & UBCORE_ACCESS_LOCAL_WRITE)) {
		ubcore_log_err(
			"Local write must be set when either remote write or remote atomic is declared.\n");
		return NULL;
	}
	if (cfg->eid_index >= dev->eid_table.eid_cnt) {
		ubcore_log_warn("eid_index:%u >= eid_table cnt:%u.\n",
			cfg->eid_index, dev->eid_table.eid_cnt);
		return NULL;
	}

	if (udata == NULL && cfg->flag.bs.token_id_valid == UBCORE_TOKEN_ID_INVALID &&
		dev->transport_type == UBCORE_TRANSPORT_UB)
		alloc_token_id = true;

	tmp_cfg = *cfg;
	if (alloc_token_id == true) {
		tmp_cfg.token_id = ubcore_alloc_token_id(dev, NULL);
		if (tmp_cfg.token_id == NULL) {
			ubcore_log_err("alloc token id failed.\n");
			return NULL;
		}
	}

	tseg = dev->ops->register_seg(dev, &tmp_cfg, udata);
	if (tseg == NULL) {
		ubcore_log_err("UBEP failed to register segment.\n");
		if (alloc_token_id == true)
			(void)ubcore_free_token_id(tmp_cfg.token_id);
		return NULL;
	}

	tseg->ub_dev = dev;
	tseg->uctx = ubcore_get_uctx(udata);
	tseg->seg.len = tmp_cfg.len;
	tseg->seg.ubva.va = tmp_cfg.va;
	tseg->token_id = tmp_cfg.token_id;

	(void)memcpy(tseg->seg.ubva.eid.raw, dev->eid_table.eid_entries[cfg->eid_index].eid.raw,
		UBCORE_EID_SIZE);
	(void)memcpy(&tseg->seg.attr, &cfg->flag, sizeof(union ubcore_reg_seg_flag));
	tseg->seg.attr.bs.user_token_id = tmp_cfg.flag.bs.token_id_valid;
	atomic_set(&tseg->use_cnt, 0);
	if (tseg->token_id != NULL)
		atomic_inc(&tseg->token_id->use_cnt);

	return tseg;
}
EXPORT_SYMBOL(ubcore_register_seg);

int ubcore_unregister_seg(struct ubcore_target_seg *tseg)
{
	struct ubcore_token_id *token_id = NULL;
	bool free_token_id = false;
	struct ubcore_device *dev;
	int ret;

	if (tseg == NULL || tseg->ub_dev == NULL || tseg->ub_dev->ops == NULL ||
		tseg->ub_dev->ops->unregister_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	dev = tseg->ub_dev;

	if (tseg->token_id != NULL)
		atomic_dec(&tseg->token_id->use_cnt);

	if (tseg->seg.attr.bs.user_token_id == UBCORE_TOKEN_ID_INVALID &&
		dev->transport_type == UBCORE_TRANSPORT_UB &&
		tseg->token_id != NULL && tseg->uctx == NULL) {
		free_token_id = true;
		token_id = tseg->token_id;
	}

	ret = dev->ops->unregister_seg(tseg);

	if (free_token_id == true && token_id != NULL)
		(void)ubcore_free_token_id(token_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_unregister_seg);

struct ubcore_target_seg *ubcore_import_seg(struct ubcore_device *dev,
					    struct ubcore_target_seg_cfg *cfg,
					    struct ubcore_udata *udata)
{
	struct ubcore_target_seg *tseg;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->import_seg == NULL ||
	    dev->ops->unimport_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return NULL;
	}

	tseg = dev->ops->import_seg(dev, cfg, udata);
	if (tseg == NULL) {
		ubcore_log_err("UBEP failed to import segment with va\n");
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

	if (tseg == NULL || tseg->ub_dev == NULL || tseg->ub_dev->ops == NULL ||
		tseg->ub_dev->ops->unimport_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	dev = tseg->ub_dev;

	return dev->ops->unimport_seg(tseg);
}
EXPORT_SYMBOL(ubcore_unimport_seg);
