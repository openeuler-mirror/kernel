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

	if (dev->ops == NULL || dev->ops->create_tpg == NULL)
		return ERR_PTR(-EINVAL);

	tpg = dev->ops->create_tpg(dev, cfg, NULL);
	if (IS_ERR_OR_NULL(tpg)) {
		ubcore_log_err("Failed to create tpg");
		if (tpg == NULL)
			return ERR_PTR(-ENOEXEC);
		return tpg;
	}
	tpg->ub_dev = dev;
	tpg->tpg_cfg = *cfg;
	for (i = 0; i < cfg->tp_cnt; i++)
		tpg->tp_list[i] = NULL;

	kref_init(&tpg->ref_cnt);
	mutex_init(&tpg->mutex);

	return tpg;
}

void ubcore_tpg_get(void *obj)
{
	struct ubcore_tpg *tpg = obj;

	kref_get(&tpg->ref_cnt);
}

static void ubcore_destroy_tpg(struct ubcore_tpg *tpg)
{
	struct ubcore_device *dev = tpg->ub_dev;
	int ret;

	if (dev->ops == NULL || dev->ops->destroy_tpg == NULL)
		return;

	ret = dev->ops->destroy_tpg(tpg);
	if (ret != 0)
		ubcore_log_err("destrory tpg err:%d", ret);
}

static void ubcore_tpg_kref_release(struct kref *ref_cnt)
{
	struct ubcore_tpg *tpg = container_of(ref_cnt, struct ubcore_tpg, ref_cnt);

	ubcore_destroy_tpg(tpg);
}

void ubcore_tpg_kref_put(struct ubcore_tpg *tpg)
{
	(void)kref_put(&tpg->ref_cnt, ubcore_tpg_kref_release);
}

void ubcore_tpg_kref_get(struct ubcore_tpg *tpg)
{
	kref_get(&tpg->ref_cnt);
}

struct ubcore_tpg *ubcore_find_get_tpg(struct ubcore_device *dev, uint32_t tpgn)
{
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_TPG], tpgn, &tpgn);
}

int ubcore_find_remove_tpg(struct ubcore_device *dev, uint32_t tpgn)
{
	struct ubcore_tpg *tpg;

	spin_lock(&dev->ht[UBCORE_HT_TPG].lock);
	if (&dev->ht[UBCORE_HT_TPG].head == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_TPG].lock);
		return -1;
	}
	tpg = ubcore_hash_table_lookup_nolock(&dev->ht[UBCORE_HT_TPG], tpgn, &tpgn);
	if (tpg == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_TPG].lock);
		return -1;
	}
	ubcore_hash_table_remove_nolock(&dev->ht[UBCORE_HT_TPG], &tpg->hnode);
	ubcore_tpg_kref_put(tpg);
	spin_unlock(&dev->ht[UBCORE_HT_TPG].lock);
	return 0;
}

int ubcore_add_tp(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	return ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_TP],
		&tp->hnode, tp->tpn);
}

struct ubcore_tp *ubcore_find_get_tp(struct ubcore_device *dev, uint32_t tpn)
{
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_TP], tpn, &tpn);
}

struct ubcore_tp *ubcore_find_remove_tp_node(struct ubcore_device *dev, uint32_t tpn)
{
	struct ubcore_tp *tp;

	spin_lock(&dev->ht[UBCORE_HT_TP].lock);
	if (&dev->ht[UBCORE_HT_TP].head == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_TP].lock);
		return NULL;
	}
	tp = ubcore_hash_table_lookup_nolock(&dev->ht[UBCORE_HT_TP], tpn, &tpn);
	if (tp == NULL) {
		spin_unlock(&dev->ht[UBCORE_HT_TP].lock);
		return NULL;
	}

	if (atomic_dec_return(&tp->use_cnt) > 0) {
		spin_unlock(&dev->ht[UBCORE_HT_TP].lock);
		ubcore_log_warn("Failed to remove tp:%u and use cnt:%u",
			tp->tpn, (uint32_t)atomic_read(&tp->use_cnt));
		return NULL;
	}
	ubcore_hash_table_remove_nolock(&dev->ht[UBCORE_HT_TP], &tp->hnode);
	spin_unlock(&dev->ht[UBCORE_HT_TP].lock);

	return tp;
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
	struct ubcore_tp *tp[UBCORE_MAX_TP_CNT_IN_GRP] = {0};
	uint32_t tp_cnt = tpg->tpg_cfg.tp_cnt;
	int created_tp_cnt;
	uint32_t i;
	uint32_t j;
	int ret;

	if (dev->ops == NULL || dev->ops->create_multi_tp == NULL ||
		dev->ops->destroy_multi_tp == NULL)
		return -EINVAL;

	created_tp_cnt = dev->ops->create_multi_tp(dev, tp_cnt, cfg, NULL, tp);
	if (created_tp_cnt != (int)tp_cnt) {
		if (created_tp_cnt > 0)
			(void)dev->ops->destroy_multi_tp(created_tp_cnt, tp);
		ubcore_log_err("Failed to create multi tp");
		return -ENOSPC;
	}

	/* add tp to tpg */
	for (i = 0; i < tp_cnt; i++) {
		struct ubcore_tp *single_tp = tp[i];

		if (single_tp == NULL) {
			ubcore_log_warn("create multi tp, buf tp is null_ptr");
			continue;
		}
		kref_init(&single_tp->ref_cnt);
		init_completion(&single_tp->comp);
		ubcore_store_tp_init_cfg(tpg, single_tp, dev, &cfg[i]);
		tpg->tp_list[i] = single_tp;

		ret = ubcore_add_tp(dev, single_tp);
		if (ret != 0) {
			ubcore_log_err("Failed to add tp:%u to the tp table and tpg:%u, dev:%s",
				single_tp->tpn, tpg->tpgn, dev->dev_name);
			for (j = 0; j < i; j++)
				(void)ubcore_find_remove_tp_node(dev, tp[j]->tpn);

			(void)dev->ops->destroy_multi_tp(created_tp_cnt, tp);
			ubcore_log_err("Failed to create multi tp");
			return -EPERM;
		}
		ubcore_log_debug("success to add tp:%u to the tp table and tpg:%u, dev:%s",
				single_tp->tpn, tpg->tpgn, dev->dev_name);
	}

	return 0;
}

uint32_t ubcore_destroy_multi_tp_from_index(struct ubcore_device *dev, struct ubcore_tpg *tpg,
	uint32_t from_index)
{
	struct ubcore_tp *tp[UBCORE_MAX_TP_CNT_IN_GRP];
	uint32_t tp_cnt = tpg->tpg_cfg.tp_cnt - from_index;
	struct ubcore_tp *single_tp;
	int ret;
	int i;

	if (dev->ops == NULL || dev->ops->destroy_multi_tp == NULL)
		return 0;

	mutex_lock(&tpg->mutex);
	for (i = 0; i < (int)tp_cnt; i++) {
		tp[i] = tpg->tp_list[i + (int)from_index];
		tpg->tp_list[i + (int)from_index] = NULL;
		ubcore_log_info("tp set null %d", i + (int)from_index);
	}
	mutex_unlock(&tpg->mutex);

	for (i = 0; i < (int)tp_cnt; i++) {
		ubcore_tp_kref_put(tp[i]);
		wait_for_completion(&tp[i]->comp);

		single_tp = ubcore_find_remove_tp_node(dev, tp[i]->tpn);
		if (single_tp == NULL)
			ubcore_log_err("failed to find tp with tpn %u and tpgn %u, dev:%s",
				tp[i]->tpn, tp[i]->tpg->tpgn, dev->dev_name);
	}

	/* todonext: modify to error, and reset first */
	ret = dev->ops->destroy_multi_tp(tp_cnt, tp);
	if (ret != (int)tp_cnt)
		ubcore_log_err("Failed to destroy multi tp %d", ret);

	return (ret > 0 ? (uint32_t)ret : 0);
}

uint32_t ubcore_destroy_multi_tp(struct ubcore_device *dev, struct ubcore_tpg *tpg)
{
	return ubcore_destroy_multi_tp_from_index(dev, tpg, 0);
}

uint32_t ubcore_modify_tp_in_tpg(struct ubcore_device *dev, struct ubcore_tpg *tpg,
	struct ubcore_tp_attr *attr, union ubcore_tp_attr_mask *mask, struct ubcore_tp **failed_tp)
{
	int ret;
	int i;

	if (dev->ops == NULL || dev->ops->modify_multi_tp == NULL)
		return 0;

	mutex_lock(&tpg->mutex);
	for (i = 0; i < (int)tpg->tpg_cfg.tp_cnt; i++)
		ubcore_tp_get(tpg->tp_list[i]);
	mutex_unlock(&tpg->mutex);

	ret = dev->ops->modify_multi_tp(tpg->tpg_cfg.tp_cnt, tpg->tp_list, attr, mask, failed_tp);
	if (ret != (int)tpg->tpg_cfg.tp_cnt)
		ubcore_log_err("Failed to modify multi tp %d and tpgn %u ", ret, tpg->tpgn);

	for (i = 0; (i < ret && i < UBCORE_MAX_TP_CNT_IN_GRP); i++)
		ubcore_modify_tp_attr(tpg->tp_list[i], &attr[i], mask[i]);

	for (i = 0; i < (int)tpg->tpg_cfg.tp_cnt; i++)
		ubcore_tp_kref_put(tpg->tp_list[i]);
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

struct ubcore_tp *ubcore_find_get_tp_in_tpg(struct ubcore_tpg *tpg, uint32_t tpn)
{
	uint32_t i;

	mutex_lock(&tpg->mutex);
	for (i = 0; i < tpg->tpg_cfg.tp_cnt; i++) {
		if (tpg->tp_list[i] == NULL || tpg->tp_list[i]->tpn != tpn)
			continue;

		ubcore_tp_get(tpg->tp_list[i]);
		mutex_unlock(&tpg->mutex);

		return tpg->tp_list[i];
	}
	mutex_unlock(&tpg->mutex);

	return NULL;
}

int ubcore_find_add_tpg(struct ubcore_device *dev, struct ubcore_tpg *tpg)
{
	struct ubcore_hash_table *ht = &dev->ht[UBCORE_HT_TPG];

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return -EINVAL;
	}

	if (ubcore_hash_table_lookup_nolock(ht, tpg->tpgn, &tpg->tpgn) != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}
	ubcore_hash_table_add_nolock(ht, &tpg->hnode, tpg->tpgn);
	ubcore_tpg_kref_get(tpg);
	spin_unlock(&ht->lock);
	return 0;
}
