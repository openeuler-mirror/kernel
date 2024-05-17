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
 * Description: ubcore tpg implementation
 * Author: Yan Fangfang
 * Create: 2023-07-17
 * Note:
 * History: 2023-07-17: Create file
 */

#include <linux/slab.h>
#include "ubcore_log.h"
#include "ubcore_hash_table.h"
#include "ubcore_tp.h"
#include "ubcore_tpg.h"

struct ubcore_tpg *ubcore_create_tpg(struct ubcore_device *dev, struct ubcore_tpg_cfg *cfg)
{
	struct ubcore_tpg *tpg;
	uint32_t i;
	int ret;

	if (dev->ops == NULL || dev->ops->create_tpg == NULL)
		return NULL;

	tpg = dev->ops->create_tpg(dev, cfg, NULL);
	if (tpg == NULL) {
		ubcore_log_err("Failed to create tpg");
		return NULL;
	}
	tpg->ub_dev = dev;
	tpg->tpg_cfg = *cfg;
	for (i = 0; i < cfg->tp_cnt; i++)
		tpg->tp_list[i] = NULL;
	atomic_set(&tpg->use_cnt, 1);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_TPG], &tpg->hnode, tpg->tpgn);
	if (ret != 0) {
		(void)dev->ops->destroy_tpg(tpg);
		tpg = NULL;
		ubcore_log_err("Failed to add tpg to the tpg table");
	}
	return tpg;
}

int ubcore_destroy_tpg(struct ubcore_tpg *tpg)
{
	struct ubcore_device *dev = tpg->ub_dev;
	int ret;

	if (dev->ops == NULL || dev->ops->destroy_tpg == NULL)
		return -EINVAL;

	if (atomic_dec_return(&tpg->use_cnt) > 0) {
		ubcore_log_err("tpg in use");
		return -EBUSY;
	}

	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_TPG], &tpg->hnode);

	ret = dev->ops->destroy_tpg(tpg);
	if (ret != 0) {
		(void)ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_TPG], &tpg->hnode, tpg->tpgn);
		/* inc tpg use cnt? */
		ubcore_log_err("Failed to destroy tpg");
	}

	return ret;
}

struct ubcore_tpg *ubcore_find_tpg(struct ubcore_device *dev, uint32_t tpgn)
{
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_TPG], tpgn, &tpgn);
}

static void ubcore_set_tp_init_flag(union ubcore_tp_flag *flag, union ubcore_tp_cfg_flag in)
{
	flag->bs.target = in.bs.target;
	flag->bs.loopback = in.bs.loopback;
	flag->bs.ack_resp = in.bs.ack_resp;
	flag->bs.bonding = in.bs.bonding;
	flag->bs.dca_enable = in.bs.dca_enable;
}

/* todonext: merge with the function in tp.c */
static void ubcore_store_tp_init_cfg(struct ubcore_tpg *tpg, struct ubcore_tp *tp,
	struct ubcore_device *dev, const struct ubcore_tp_cfg *cfg)
{
	ubcore_set_tp_init_flag(&tp->flag, cfg->flag);
	tp->local_jetty = cfg->local_jetty;
	tp->peer_jetty = cfg->peer_jetty;
	tp->trans_mode = cfg->trans_mode;
	tp->retry_num = cfg->retry_num;
	tp->ack_timeout = cfg->ack_timeout;
	tp->retry_factor = cfg->retry_factor;
	tp->dscp = cfg->dscp;
	tp->oor_cnt = cfg->oor_cnt;

	tp->ub_dev = dev;
	tp->state = UBCORE_TP_STATE_RESET;
	tp->tpg = tpg;
	tp->priv = NULL;
	atomic_set(&tp->use_cnt, 1);
}

int ubcore_create_multi_tp(struct ubcore_device *dev, struct ubcore_tpg *tpg,
	struct ubcore_tp_cfg *cfg)
{
	struct ubcore_tp *tp[UBCORE_MAX_TP_CNT_IN_GRP];
	uint32_t tp_cnt = tpg->tpg_cfg.tp_cnt;
	uint32_t i;
	int ret;

	if (dev->ops == NULL || dev->ops->create_multi_tp == NULL ||
		dev->ops->destroy_multi_tp == NULL)
		return -EINVAL;

	ret = dev->ops->create_multi_tp(dev, tp_cnt, cfg, NULL, tp);
	if (ret != (int)tp_cnt) {
		if (ret > 0)
			(void)dev->ops->destroy_multi_tp(ret, tp);
		ubcore_log_err("Failed to create multi tp");
		return -ENOSPC;
	}

	/* add tp to tpg */
	for (i = 0; i < tp_cnt; i++) {
		if (tp[i] == NULL) {
			ubcore_log_warn("create multi tp, buf tp is null_ptr");
			continue;
		}
		ubcore_store_tp_init_cfg(tpg, tp[i], dev, &cfg[i]);
		tpg->tp_list[i] = tp[i];
	}

	return 0;
}

uint32_t ubcore_destroy_multi_tp(struct ubcore_device *dev, struct ubcore_tpg *tpg)
{
	struct ubcore_tp *tp[UBCORE_MAX_TP_CNT_IN_GRP];
	uint32_t tp_cnt = tpg->tpg_cfg.tp_cnt;
	int ret;
	int i;

	if (dev->ops == NULL || dev->ops->destroy_multi_tp == NULL)
		return 0;

	for (i = 0; i < (int)tp_cnt; i++)
		tp[i] = tpg->tp_list[i];

	/* todonext: modify to error, and reset first */
	ret = dev->ops->destroy_multi_tp(tp_cnt, tp);
	if (ret != (int)tp_cnt)
		ubcore_log_err("Failed to destroy multi tp %d", ret);

	for (i = 0; (i < ret) && (i < UBCORE_MAX_TP_CNT_IN_GRP); i++)
		tpg->tp_list[i] = NULL;

	return (ret > 0 ? (uint32_t)ret : 0);
}

uint32_t ubcore_modify_tp_in_tpg(struct ubcore_device *dev, struct ubcore_tpg *tpg,
	struct ubcore_tp_attr *attr, union ubcore_tp_attr_mask *mask, struct ubcore_tp **failed_tp)
{
	int ret;
	int i;

	if (dev->ops == NULL || dev->ops->modify_multi_tp == NULL)
		return 0;

	ret = dev->ops->modify_multi_tp(tpg->tpg_cfg.tp_cnt, tpg->tp_list, attr, mask, failed_tp);
	if (ret != (int)tpg->tpg_cfg.tp_cnt)
		ubcore_log_err("Failed to modify multi tp %d and tpgn %u ", ret, tpg->tpgn);

	for (i = 0; (i < ret && i < UBCORE_MAX_TP_CNT_IN_GRP); i++)
		ubcore_modify_tp_attr(tpg->tp_list[i], &attr[i], mask[i]);

	return (ret > 0 ? (uint32_t)ret : 0);
}

struct ubcore_tp *ubcore_find_tp_in_tpg(struct ubcore_tpg *tpg, uint32_t tpn)
{
	uint32_t i;

	for (i = 0; i < tpg->tpg_cfg.tp_cnt; i++) {
		if (tpg->tp_list[i] == NULL || tpg->tp_list[i]->tpn != tpn)
			continue;

		return tpg->tp_list[i];
	}

	return NULL;
}
