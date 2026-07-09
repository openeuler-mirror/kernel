// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore segment
 * Author: Qian Guoxin, Ouyang Changchun
 * Create: 2022-07-28
 * Note:
 * History: 2022-07-28: Yan Fangfang move segment implementation here
 */

#include "ubcore_device.h"
#include "ubcore_log.h"
#include "ubcore_priv.h"
#include "ubcore_hash_table.h"
#include "ubcore_tp.h"
#include "ubcore_tp_table.h"
#include "ub/urma/ubcore_perf.h"

struct ubcore_token_id *ubcore_alloc_token_id(struct ubcore_device *dev,
					      union ubcore_token_id_flag flag,
					      struct ubcore_udata *udata)
{
	struct ubcore_token_id *token_id;

	UBCORE_PERF_TRACE_BEGIN(PERF_CORE_ALLOC_TOKEN_ID);

	if (flag.bs.pa == 1 && udata != NULL) {
		ubcore_log_err("invalid parameter of pa.\n");
		UBCORE_PERF_TRACE_END(PERF_CORE_ALLOC_TOKEN_ID);
		return ERR_PTR(-EINVAL);
	}

	if (dev == NULL || dev->ops == NULL ||
	    dev->ops->alloc_token_id == NULL ||
	    dev->ops->free_token_id == NULL) {
		UBCORE_PERF_TRACE_END(PERF_CORE_ALLOC_TOKEN_ID);
		return ERR_PTR(-EINVAL);
	}

	UBCORE_PERF_TRACE_BEGIN(PERF_UB_ALLOC_TOKEN_ID);
	token_id = dev->ops->alloc_token_id(dev, flag, udata);
	UBCORE_PERF_TRACE_END(PERF_UB_ALLOC_TOKEN_ID);

	if (IS_ERR_OR_NULL(token_id)) {
		ubcore_log_err("[DRV]:failed to alloc token_id id,dev_name is %s.\n",
			dev->dev_name);
		UBCORE_PERF_TRACE_END(PERF_CORE_ALLOC_TOKEN_ID);
		return UBCORE_CHECK_RETURN_ERR_PTR(token_id, UBCORE_DRV_ERRNO);
	}
	token_id->flag = flag;
	token_id->ub_dev = dev;
	token_id->uctx = ubcore_get_uctx(udata);
	atomic_set(&token_id->use_cnt, 0);
	ubcore_log_info("[ALLOC_TOKEN_ID]:device_name is %s, token_id is %u",
		dev->dev_name, token_id->token_id);
	UBCORE_PERF_TRACE_END(PERF_CORE_ALLOC_TOKEN_ID);
	return token_id;
}
EXPORT_SYMBOL(ubcore_alloc_token_id);

int ubcore_free_token_id(struct ubcore_token_id *token_id)
{
	struct ubcore_device *dev;
	uint32_t id;
	int ret = 0;

	UBCORE_PERF_TRACE_BEGIN(PERF_CORE_FREE_TOKEN_ID);

	if (token_id == NULL || token_id->ub_dev == NULL ||
	    token_id->ub_dev->ops == NULL ||
	    token_id->ub_dev->ops->free_token_id == NULL) {
		ubcore_log_err("invalid parameter.\n");
		UBCORE_PERF_TRACE_END(PERF_CORE_FREE_TOKEN_ID);
		return -EINVAL;
	}
	dev = token_id->ub_dev;

	int use_cnt = atomic_read(&token_id->use_cnt);
	if (atomic_read(&token_id->use_cnt)) {
		ubcore_log_err("The token_id is still being used, use_cnt is %d",
			       use_cnt);
		UBCORE_PERF_TRACE_END(PERF_CORE_FREE_TOKEN_ID);
		return -EBUSY;
	}
	id = token_id->token_id;
	UBCORE_PERF_TRACE_BEGIN(PERF_UB_FREE_TOKEN_ID);
	ret = dev->ops->free_token_id(token_id);
	UBCORE_PERF_TRACE_END(PERF_UB_FREE_TOKEN_ID);
	if (ret != 0) {
		ubcore_log_err("[DRV]Failed to free_token_id, ret is %d", ret);
		UBCORE_PERF_TRACE_END(PERF_CORE_FREE_TOKEN_ID);
		return ret;
	}
	ubcore_log_info("[FREE_TOKEN_ID] Free_token_id is %u.", id);
	UBCORE_PERF_TRACE_END(PERF_CORE_FREE_TOKEN_ID);
	return ret;
}
EXPORT_SYMBOL(ubcore_free_token_id);

static bool ubcore_check_register_seg_access(struct ubcore_seg_cfg *cfg)
{
	if ((cfg->flag.bs.access & UBCORE_ACCESS_LOCAL_ONLY) &&
		(cfg->flag.bs.access & (UBCORE_ACCESS_READ |
		UBCORE_ACCESS_WRITE |
		UBCORE_ACCESS_ATOMIC))) {
		ubcore_log_err(
			"Local only access is not allowed to config with other accesses.\n");
		return false;
	}
	if ((cfg->flag.bs.access & UBCORE_ACCESS_WRITE) &&
		!(cfg->flag.bs.access & UBCORE_ACCESS_READ)) {
		ubcore_log_err(
			"Write access should be config with read access.\n");
		return false;
	}
	if ((cfg->flag.bs.access & UBCORE_ACCESS_ATOMIC) &&
		!((cfg->flag.bs.access & UBCORE_ACCESS_READ) &&
		(cfg->flag.bs.access & UBCORE_ACCESS_WRITE))) {
		ubcore_log_err(
			"Atomic access should be config with read and write access.\n");
		return false;
	}
	return true;
}

static int ubcore_check_register_seg_para(struct ubcore_device *dev,
					  struct ubcore_seg_cfg *cfg,
					  struct ubcore_udata *udata)
{
	if (dev == NULL || cfg == NULL || dev->ops == NULL ||
	    dev->ops->register_seg == NULL ||
	    dev->ops->unregister_seg == NULL ||
	    IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}

	if (ubcore_is_bonding_dev(dev))
		return 0;

	if (!ubcore_check_register_seg_access(cfg))
		return -EINVAL;

	if (cfg->flag.bs.pa == 1 && udata != NULL) {
		ubcore_log_err("invalid parameter of pa.\n");
		return -1;
	}

	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
	    ((cfg->flag.bs.token_id_valid == UBCORE_TOKEN_ID_VALID &&
	      cfg->token_id == NULL) ||
	     (cfg->flag.bs.token_id_valid == UBCORE_TOKEN_ID_INVALID &&
	      cfg->token_id != NULL))) {
		ubcore_log_err("invalid parameter of token_id.\n");
		return -1;
	}

	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
	    cfg->flag.bs.token_id_valid == UBCORE_TOKEN_ID_VALID &&
	    cfg->token_id->flag.bs.pa != cfg->flag.bs.pa) {
		ubcore_log_err("invalid parameter of token_id pa.\n");
		return -1;
	}

	if (cfg->eid_index >= dev->eid_table.eid_cnt) {
		ubcore_log_warn("eid_index:%u >= eid_table cnt:%u.\n",
				cfg->eid_index, dev->eid_table.eid_cnt);
		return -1;
	}
	return 0;
}

struct ubcore_target_seg *ubcore_register_seg(struct ubcore_device *dev,
					      struct ubcore_seg_cfg *cfg,
					      struct ubcore_udata *udata)
{
	union ubcore_token_id_flag flag = { 0 };
	bool alloc_token_id = false;
	struct ubcore_seg_cfg tmp_cfg;
	struct ubcore_target_seg *tseg;
	uint32_t perf_register_seg_type;

	UBCORE_PERF_TRACE_BEGIN(PERF_CORE_REGISTER_SEG);

	if (ubcore_check_register_seg_para(dev, cfg, udata) != 0) {
		UBCORE_PERF_TRACE_END(PERF_CORE_REGISTER_SEG);
		return ERR_PTR(-EINVAL);
	}

	if (udata == NULL &&
	    cfg->flag.bs.token_id_valid == UBCORE_TOKEN_ID_INVALID &&
	    dev->transport_type == UBCORE_TRANSPORT_UB)
		alloc_token_id = true;

	tmp_cfg = *cfg;
	if (alloc_token_id == true) {
		flag.bs.pa = cfg->flag.bs.pa;
		tmp_cfg.token_id = ubcore_alloc_token_id(dev, flag, NULL);
		if (IS_ERR_OR_NULL(tmp_cfg.token_id)) {
			UBCORE_PERF_TRACE_END(PERF_CORE_REGISTER_SEG);
			return (void *)tmp_cfg.token_id;
		}
	}

	if (ubcore_is_bonding_dev(dev))
		perf_register_seg_type = PERF_AGG_REGISTER_SEG;
	else
		perf_register_seg_type = PERF_UB_REGISTER_SEG;

	UBCORE_PERF_TRACE_BEGIN(perf_register_seg_type);
	tseg = dev->ops->register_seg(dev, &tmp_cfg, udata);
	UBCORE_PERF_TRACE_END(perf_register_seg_type);

	if (IS_ERR_OR_NULL(tseg)) {
		ubcore_log_err("[DRV]failed to register segment,dev name is %s.\n",
			       dev->dev_name);
		if (alloc_token_id == true)
			(void)ubcore_free_token_id(tmp_cfg.token_id);
		UBCORE_PERF_TRACE_END(PERF_CORE_REGISTER_SEG);
		return UBCORE_CHECK_RETURN_ERR_PTR(tseg, UBCORE_DRV_ERRNO);
	}

	tseg->ub_dev = dev;
	tseg->uctx = ubcore_get_uctx(udata);
	tseg->seg.len = tmp_cfg.len;
	tseg->seg.ubva.va = tmp_cfg.va;
	tseg->token_id = tmp_cfg.token_id;

	(void)memcpy(tseg->seg.ubva.eid.raw,
		     dev->eid_table.eid_entries[cfg->eid_index].eid.raw,
		     UBCORE_EID_SIZE);
	(void)memcpy(&tseg->seg.attr, &cfg->flag,
		     sizeof(union ubcore_reg_seg_flag));
	tseg->seg.attr.bs.user_token_id = tmp_cfg.flag.bs.token_id_valid;
	atomic_set(&tseg->use_cnt, 0);
	if (tseg->token_id != NULL)
		atomic_inc(&tseg->token_id->use_cnt);
	ubcore_log_info("[REGISTER SEG]Register seg,dev_name is %s.",
		dev->dev_name);

	UBCORE_PERF_TRACE_END(PERF_CORE_REGISTER_SEG);
	return tseg;
}
EXPORT_SYMBOL(ubcore_register_seg);

int ubcore_unregister_seg(struct ubcore_target_seg *tseg)
{
	struct ubcore_token_id *token_id = NULL;
	bool free_token_id = false;
	struct ubcore_device *dev;
	int ret;
	uint32_t perf_unregister_seg_type;

	UBCORE_PERF_TRACE_BEGIN(PERF_CORE_UNREGISTER_SEG);

	if (tseg == NULL || tseg->ub_dev == NULL || tseg->ub_dev->ops == NULL ||
	    tseg->ub_dev->ops->unregister_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		UBCORE_PERF_TRACE_END(PERF_CORE_UNREGISTER_SEG);
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

	if (ubcore_is_bonding_dev(dev))
		perf_unregister_seg_type = PERF_AGG_UNREGISTER_SEG;
	else
		perf_unregister_seg_type = PERF_UB_UNREGISTER_SEG;

	UBCORE_PERF_TRACE_BEGIN(perf_unregister_seg_type);
	ret = dev->ops->unregister_seg(tseg);
	UBCORE_PERF_TRACE_END(perf_unregister_seg_type);
	if (ret != 0) {
		ubcore_log_err("[DRV]failed to unregister segment,dev name is %s, ret is %d.\n",
			dev->dev_name, ret);
		UBCORE_PERF_TRACE_END(PERF_CORE_UNREGISTER_SEG);
		return ret;
	}

	if (free_token_id == true && token_id != NULL)
		(void)ubcore_free_token_id(token_id);

	ubcore_log_info("[REGISTER SEG]Register seg,dev_name is %s.",
		dev->dev_name);
	UBCORE_PERF_TRACE_END(PERF_CORE_UNREGISTER_SEG);
	return ret;
}
EXPORT_SYMBOL(ubcore_unregister_seg);

struct ubcore_target_seg *ubcore_import_seg(struct ubcore_device *dev,
					    struct ubcore_target_seg_cfg *cfg,
					    struct ubcore_udata *udata)
{
	struct ubcore_target_seg *tseg;
	uint32_t perf_import_seg_type;

	UBCORE_PERF_TRACE_BEGIN(PERF_CORE_IMPORT_SEG);

	if (dev == NULL || cfg == NULL || dev->ops == NULL ||
	    dev->ops->import_seg == NULL || dev->ops->unimport_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		UBCORE_PERF_TRACE_END(PERF_CORE_IMPORT_SEG);
		return ERR_PTR(-EINVAL);
	}

	if (ubcore_is_bonding_dev(dev))
		perf_import_seg_type = PERF_AGG_IMPORT_SEG;
	else
		perf_import_seg_type = PERF_UB_IMPORT_SEG;

	UBCORE_PERF_TRACE_BEGIN(perf_import_seg_type);
	tseg = dev->ops->import_seg(dev, cfg, udata);
	UBCORE_PERF_TRACE_END(perf_import_seg_type);

	if (IS_ERR_OR_NULL(tseg)) {
		ubcore_log_err("[DRV] failed to import segment with va\n");
		UBCORE_PERF_TRACE_END(PERF_CORE_IMPORT_SEG);
		return UBCORE_CHECK_RETURN_ERR_PTR(tseg, UBCORE_DRV_ERRNO);
	}
	tseg->ub_dev = dev;
	tseg->uctx = ubcore_get_uctx(udata);
	tseg->seg = cfg->seg;
	atomic_set(&tseg->use_cnt, 0);
	ubcore_log_info("[IMPORT SEG] Import seg, dev_name is %s", dev->dev_name);
	UBCORE_PERF_TRACE_END(PERF_CORE_IMPORT_SEG);
	return tseg;
}
EXPORT_SYMBOL(ubcore_import_seg);

int ubcore_unimport_seg(struct ubcore_target_seg *tseg)
{
	struct ubcore_device *dev;
	int ret;
	uint32_t perf_unimport_seg_type;

	UBCORE_PERF_TRACE_BEGIN(PERF_CORE_UNIMPORT_SEG);

	if (tseg == NULL || tseg->ub_dev == NULL || tseg->ub_dev->ops == NULL ||
	    tseg->ub_dev->ops->unimport_seg == NULL) {
		ubcore_log_err("invalid parameter.\n");
		UBCORE_PERF_TRACE_END(PERF_CORE_UNIMPORT_SEG);
		return -EINVAL;
	}
	dev = tseg->ub_dev;

	if (ubcore_is_bonding_dev(dev))
		perf_unimport_seg_type = PERF_AGG_UNIMPORT_SEG;
	else
		perf_unimport_seg_type = PERF_UB_UNIMPORT_SEG;

	UBCORE_PERF_TRACE_BEGIN(perf_unimport_seg_type);
	ret = dev->ops->unimport_seg(tseg);
	UBCORE_PERF_TRACE_END(perf_unimport_seg_type);

	if (ret != 0) {
		ubcore_log_err("[DRV] Failed to unimport seg, dev_name is %s, ret is %d.",
			       dev->dev_name, ret);
		UBCORE_PERF_TRACE_END(PERF_CORE_UNIMPORT_SEG);
		return ret;
	}
	ubcore_log_info("[UNIMPORT SEG] Unimport seg, dev_name is %s.",
			dev->dev_name);
	UBCORE_PERF_TRACE_END(PERF_CORE_UNIMPORT_SEG);
	return ret;
}
EXPORT_SYMBOL(ubcore_unimport_seg);
