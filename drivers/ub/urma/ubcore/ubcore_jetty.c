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
#include "ubcore_hash_table.h"
#include "ubcore_tp.h"
#include "ubcore_tp_table.h"
#include "ubcore_vtp.h"
#include "ubcore_tpg.h"

struct ubcore_jfc *ubcore_find_jfc(struct ubcore_device *dev, uint32_t jfc_id)
{
	if (dev == NULL) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JFC], jfc_id, &jfc_id);
}
EXPORT_SYMBOL(ubcore_find_jfc);

struct ubcore_jfs *ubcore_find_jfs(struct ubcore_device *dev, uint32_t jfs_id)
{
	if (dev == NULL) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JFS], jfs_id, &jfs_id);
}
EXPORT_SYMBOL(ubcore_find_jfs);

struct ubcore_jfr *ubcore_find_jfr(struct ubcore_device *dev, uint32_t jfr_id)
{
	if (dev == NULL) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JFR], jfr_id, &jfr_id);
}
EXPORT_SYMBOL(ubcore_find_jfr);

static int check_and_fill_jfc_attr(struct ubcore_jfc_cfg *cfg, struct ubcore_jfc_cfg *user)
{
	if (cfg->depth < user->depth)
		return -1;

	/* store the immutable and skip the driver updated depth */
	cfg->flag = user->flag;
	cfg->jfc_context = user->jfc_context;
	return 0;
}

struct ubcore_jfc *ubcore_create_jfc(struct ubcore_device *dev, struct ubcore_jfc_cfg *cfg,
	ubcore_comp_callback_t jfce_handler, ubcore_event_callback_t jfae_handler,
	struct ubcore_udata *udata)
{
	struct ubcore_jfc *jfc;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->create_jfc == NULL ||
		dev->ops->destroy_jfc == NULL)
		return NULL;

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

int ubcore_modify_jfc(struct ubcore_jfc *jfc, struct ubcore_jfc_attr *attr,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
		jfc->ub_dev->ops->modify_jfc == NULL)
		return -EINVAL;

	jfc_id = jfc->id;
	dev = jfc->ub_dev;

	ret = dev->ops->modify_jfc(jfc, attr, udata);
	if (ret != 0)
		ubcore_log_err("UBEP failed to modify jfc, jfc_id:%u.\n", jfc_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jfc);

int ubcore_delete_jfc(struct ubcore_jfc *jfc)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
		jfc->ub_dev->ops->destroy_jfc == NULL)
		return -1;

	if (atomic_read(&jfc->use_cnt)) {
		ubcore_log_err("The jfc is still being used");
		return -EBUSY;
	}

	jfc_id = jfc->id;
	dev = jfc->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFC], &jfc->hnode);
	ret = dev->ops->destroy_jfc(jfc);
	if (ret != 0) {
		ubcore_log_err("UBEP failed to destroy jfc, jfc_id:%u.\n", jfc_id);
		goto rollback;
	}

	return ret;

rollback:
	(void)ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFC], &jfc->hnode, jfc->id);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfc);

static int check_jfs_cfg(struct ubcore_device *dev, struct ubcore_jfs_cfg *cfg)
{
	if (cfg->depth == 0 || cfg->depth > dev->attr.dev_cap.max_jfs_depth) {
		ubcore_log_err("Invalid parameter, depth:%u, max_depth:%u.\n",
			cfg->depth, dev->attr.dev_cap.max_jfs_depth);
		return -EINVAL;
	}
	if (cfg->max_inline_data != 0 && cfg->max_inline_data >
		dev->attr.dev_cap.max_jfs_inline_size) {
		ubcore_log_err("Invalid parameter, inline_data:%u, max_inline_len:%u.\n",
			cfg->max_inline_data, dev->attr.dev_cap.max_jfs_inline_size);
		return -EINVAL;
	}
	if (cfg->max_sge > dev->attr.dev_cap.max_jfs_sge) {
		ubcore_log_err("Invalid parameter, sge:%hhu, max_sge:%u.\n",
			cfg->max_sge, dev->attr.dev_cap.max_jfs_sge);
		return -EINVAL;
	}
	if (cfg->max_rsge > dev->attr.dev_cap.max_jfs_rsge) {
		ubcore_log_err("Invalid parameter, rsge:%hhu, max_rsge:%u.\n",
			cfg->max_rsge, dev->attr.dev_cap.max_jfs_rsge);
		return -EINVAL;
	}
	return 0;
}

static int check_and_fill_jfs_attr(struct ubcore_jfs_cfg *cfg, struct ubcore_jfs_cfg *user)
{
	if (cfg->depth < user->depth || cfg->max_sge < user->max_sge ||
		cfg->max_rsge < user->max_rsge || cfg->max_inline_data < user->max_inline_data)
		return -1;

	/* store the immutable and skip the driver updated attributes including depth,
	 * max_sge and max_inline_data
	 */
	cfg->flag = user->flag;
	cfg->eid_index = user->eid_index;
	cfg->priority = user->priority;
	cfg->rnr_retry = user->rnr_retry;
	cfg->err_timeout = user->err_timeout;
	cfg->trans_mode = user->trans_mode;
	cfg->jfs_context = user->jfs_context;
	cfg->jfc = user->jfc;
	return 0;
}

struct ubcore_jfs *ubcore_create_jfs(struct ubcore_device *dev, struct ubcore_jfs_cfg *cfg,
	ubcore_event_callback_t jfae_handler, struct ubcore_udata *udata)
{
	struct ubcore_jfs *jfs;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->create_jfs == NULL ||
		dev->ops->destroy_jfs == NULL)
		return NULL;

	if (((uint16_t)cfg->trans_mode & dev->attr.dev_cap.trans_mode) == 0) {
		ubcore_log_err("jfs cfg is not supported.\n");
		return NULL;
	}
	if (check_jfs_cfg(dev, cfg) != 0)
		return NULL;

	jfs = dev->ops->create_jfs(dev, cfg, udata);
	if (jfs == NULL) {
		ubcore_log_err("failed to create jfs.\n");
		return NULL;
	}

	/* Prevent ubcore private data from being modified */
	if (check_and_fill_jfs_attr(&jfs->jfs_cfg, cfg) != 0) {
		(void)dev->ops->destroy_jfs(jfs);
		ubcore_log_err("jfs cfg is not qualified.\n");
		return NULL;
	}
	jfs->ub_dev = dev;
	jfs->uctx = ubcore_get_uctx(udata);
	jfs->jfae_handler = jfae_handler;
	if (ubcore_jfs_need_advise(jfs)) {
		jfs->tptable = ubcore_create_tptable();
		if (jfs->tptable == NULL) {
			(void)dev->ops->destroy_jfs(jfs);
			ubcore_log_err("Failed to create tp table in the jfs.\n");
			return NULL;
		}
	}
	atomic_set(&jfs->use_cnt, 0);

	if (ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFS], &jfs->hnode, jfs->id) != 0) {
		ubcore_destroy_tptable(&jfs->tptable);
		(void)dev->ops->destroy_jfs(jfs);
		ubcore_log_err("Failed to add jfs.\n");
		return NULL;
	}

	atomic_inc(&cfg->jfc->use_cnt);
	return jfs;
}
EXPORT_SYMBOL(ubcore_create_jfs);

int ubcore_modify_jfs(struct ubcore_jfs *jfs, struct ubcore_jfs_attr *attr,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfs_id;
	int ret;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->modify_jfs == NULL)
		return -EINVAL;

	jfs_id = jfs->id;
	dev = jfs->ub_dev;
	ret = dev->ops->modify_jfs(jfs, attr, udata);
	if (ret != 0)
		ubcore_log_err("UBEP failed to modify jfs, jfs_id:%u.\n", jfs_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jfs);

int ubcore_query_jfs(struct ubcore_jfs *jfs, struct ubcore_jfs_cfg *cfg,
	struct ubcore_jfs_attr *attr)
{
	struct ubcore_device *dev;
	uint32_t jfs_id;
	int ret;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL
		|| jfs->ub_dev->ops->query_jfs == NULL)
		return -EINVAL;

	jfs_id = jfs->id;
	dev = jfs->ub_dev;
	ret = dev->ops->query_jfs(jfs, cfg, attr);
	if (ret != 0)
		ubcore_log_err("UBEP failed to query jfs, jfs_id:%u.\n", jfs_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_query_jfs);

int ubcore_delete_jfs(struct ubcore_jfs *jfs)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *jfc;
	uint32_t jfs_id;
	int ret;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->destroy_jfs == NULL)
		return -EINVAL;

	jfc = jfs->jfs_cfg.jfc;
	jfs_id = jfs->id;
	dev = jfs->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFS], &jfs->hnode);
	ubcore_destroy_tptable(&jfs->tptable);
	ret = dev->ops->destroy_jfs(jfs);
	if (ret != 0) {
		ubcore_log_err("UBEP failed to destroy jfs, jfs_id:%u.\n", jfs_id);
		goto rollback;
	} else {
		atomic_dec(&jfc->use_cnt);
	}

	return ret;

rollback:
	if (ubcore_jfs_need_advise(jfs))
		jfs->tptable = ubcore_create_tptable();
	(void)ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFS], &jfs->hnode, jfs->id);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfs);

int ubcore_flush_jfs(struct ubcore_jfs *jfs, int cr_cnt, struct ubcore_cr *cr)
{
	struct ubcore_ops *dev_ops;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->flush_jfs == NULL || cr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jfs->ub_dev->ops;
	return dev_ops->flush_jfs(jfs, cr_cnt, cr);
}
EXPORT_SYMBOL(ubcore_flush_jfs);

static int check_and_fill_jfr_attr(struct ubcore_jfr_cfg *cfg, struct ubcore_jfr_cfg *user)
{
	if (cfg->depth < user->depth || cfg->max_sge < user->max_sge)
		return -1;

	/* store the immutable and skip the driver updated attributes including depth, max_sge */
	cfg->eid_index = user->eid_index;
	cfg->flag = user->flag;
	cfg->min_rnr_timer = user->min_rnr_timer;
	cfg->trans_mode = user->trans_mode;
	cfg->token_value = user->token_value;
	cfg->jfr_context = user->jfr_context;
	cfg->jfc = user->jfc;
	return 0;
}

struct ubcore_jfr *ubcore_create_jfr(struct ubcore_device *dev, struct ubcore_jfr_cfg *cfg,
	ubcore_event_callback_t jfae_handler, struct ubcore_udata *udata)
{
	struct ubcore_jfr *jfr;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->create_jfr == NULL ||
	    dev->ops->destroy_jfr == NULL)
		return NULL;

	jfr = dev->ops->create_jfr(dev, cfg, udata);
	if (jfr == NULL) {
		ubcore_log_err("failed to create jfr.\n");
		return NULL;
	}

	if (check_and_fill_jfr_attr(&jfr->jfr_cfg, cfg) != 0) {
		ubcore_log_err("jfr cfg is not qualified.\n");
		(void)dev->ops->destroy_jfr(jfr);
		return NULL;
	}
	jfr->ub_dev = dev;
	jfr->uctx = ubcore_get_uctx(udata);
	jfr->jfae_handler = jfae_handler;
	if (ubcore_jfr_need_advise(jfr)) {
		jfr->tptable = ubcore_create_tptable();
		if (jfr->tptable == NULL) {
			(void)dev->ops->destroy_jfr(jfr);
			ubcore_log_err("Failed to create tp table in the jfr.\n");
			return NULL;
		}
	}
	atomic_set(&jfr->use_cnt, 0);

	if (ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFR], &jfr->hnode, jfr->id) != 0) {
		ubcore_destroy_tptable(&jfr->tptable);
		(void)dev->ops->destroy_jfr(jfr);
		ubcore_log_err("Failed to add jfr.\n");
		return NULL;
	}

	atomic_inc(&cfg->jfc->use_cnt);
	return jfr;
}
EXPORT_SYMBOL(ubcore_create_jfr);

int ubcore_modify_jfr(struct ubcore_jfr *jfr, struct ubcore_jfr_attr *attr,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfr_id;
	int ret;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->modify_jfr == NULL)
		return -EINVAL;

	jfr_id = jfr->id;
	dev = jfr->ub_dev;
	ret = dev->ops->modify_jfr(jfr, attr, udata);
	if (ret != 0)
		ubcore_log_err("UBEP failed to modify jfr, jfr_id:%u.\n", jfr_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jfr);

int ubcore_query_jfr(struct ubcore_jfr *jfr, struct ubcore_jfr_cfg *cfg,
	struct ubcore_jfr_attr *attr)
{
	struct ubcore_device *dev;
	uint32_t jfr_id;
	int ret;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->query_jfr == NULL)
		return -EINVAL;

	jfr_id = jfr->id;
	dev = jfr->ub_dev;
	ret = dev->ops->query_jfr(jfr, cfg, attr);
	if (ret != 0)
		ubcore_log_err("UBEP failed to query jfr, jfr_id:%u.\n", jfr_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_query_jfr);

int ubcore_delete_jfr(struct ubcore_jfr *jfr)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *jfc;
	uint32_t jfr_id;
	int ret;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->destroy_jfr == NULL)
		return -EINVAL;

	if (atomic_read(&jfr->use_cnt)) {
		ubcore_log_err("The jfr is still being used");
		return -EBUSY;
	}

	jfc = jfr->jfr_cfg.jfc;
	jfr_id = jfr->id;
	dev = jfr->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFR], &jfr->hnode);
	ubcore_destroy_tptable(&jfr->tptable);
	ret = dev->ops->destroy_jfr(jfr);
	if (ret != 0) {
		ubcore_log_err("UBEP failed to destroy jfr, jfr_id:%u.\n", jfr_id);
		goto rollback;
	} else {
		atomic_dec(&jfc->use_cnt);
	}

	return ret;

rollback:
	if (ubcore_jfr_need_advise(jfr))
		jfr->tptable = ubcore_create_tptable();
	(void)ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFR], &jfr->hnode, jfr->id);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfr);

struct ubcore_tjetty *ubcore_import_jfr(struct ubcore_device *dev,
	struct ubcore_tjetty_cfg *cfg, struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param;
	struct ubcore_tjetty *tjfr;

	if (!ubcore_have_tp_ops(dev) || dev->ops->import_jetty == NULL ||
		dev->ops->unimport_jfr == NULL || cfg == NULL ||
		dev->attr.dev_cap.max_eid_cnt < cfg->eid_index)
		return NULL;

	tjfr = dev->ops->import_jfr(dev, cfg, udata);
	if (tjfr == NULL) {
		ubcore_log_err("UBEP failed to import jfr, jfr_id:%u.\n", cfg->id.id);
		return NULL;
	}
	tjfr->cfg = *cfg;
	tjfr->ub_dev = dev;
	tjfr->uctx = ubcore_get_uctx(udata);
	atomic_set(&tjfr->use_cnt, 0);
	mutex_init(&tjfr->lock);

	/* create rm tp if the remote eid is not connected */
	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
		(cfg->trans_mode == UBCORE_TP_RM || cfg->trans_mode == UBCORE_TP_UM)) {
		ubcore_set_vtp_param(dev, NULL, cfg, &vtp_param);
		mutex_lock(&tjfr->lock);
		tjfr->vtpn = ubcore_connect_vtp(dev, &vtp_param);
		if (tjfr->vtpn == NULL) {
			mutex_unlock(&tjfr->lock);
			mutex_destroy(&tjfr->lock);
			(void)dev->ops->unimport_jfr(tjfr);
			ubcore_log_err("Failed to setup tp connection.\n");
			return NULL;
		}
		mutex_unlock(&tjfr->lock);
	} else {
		tjfr->vtpn = NULL;
	}
	tjfr->tp = NULL;
	return tjfr;
}
EXPORT_SYMBOL(ubcore_import_jfr);

int ubcore_unimport_jfr(struct ubcore_tjetty *tjfr)
{
	struct ubcore_device *dev;
	int ret;

	if (tjfr == NULL || tjfr->ub_dev == NULL || tjfr->ub_dev->ops == NULL ||
		tjfr->ub_dev->ops->unimport_jfr == NULL ||
		!ubcore_have_tp_ops(tjfr->ub_dev))
		return -EINVAL;

	dev = tjfr->ub_dev;
	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
		(tjfr->cfg.trans_mode == UBCORE_TP_RM || tjfr->cfg.trans_mode == UBCORE_TP_UM) &&
		tjfr->vtpn != NULL) {
		mutex_lock(&tjfr->lock);
		ret = ubcore_disconnect_vtp(tjfr->vtpn);
		if (ret != 0) {
			ubcore_log_err("Failed to disconnect vtp.\n");
			mutex_unlock(&tjfr->lock);
			return ret;
		}
		tjfr->vtpn = NULL;
		mutex_unlock(&tjfr->lock);
	}
	mutex_destroy(&tjfr->lock);
	return dev->ops->unimport_jfr(tjfr);
}
EXPORT_SYMBOL(ubcore_unimport_jfr);

static int check_and_fill_jetty_attr(struct ubcore_jetty_cfg *cfg, struct ubcore_jetty_cfg *user)
{
	if (cfg->jfs_depth < user->jfs_depth || cfg->max_send_sge < user->max_send_sge ||
		cfg->max_send_rsge < user->max_send_rsge ||
		cfg->max_inline_data < user->max_inline_data) {
		ubcore_log_err("send attributes are not qualified.\n");
		return -1;
	}
	if (cfg->jfr_depth < user->jfr_depth || cfg->max_recv_sge < user->max_recv_sge) {
		ubcore_log_err("recv attributes are not qualified.\n");
		return -1;
	}
	/* store the immutable and skip the driver updated send and recv attributes */
	cfg->eid_index = user->eid_index;
	cfg->flag = user->flag;
	cfg->send_jfc = user->send_jfc;
	cfg->recv_jfc = user->recv_jfc;
	cfg->jfr = user->jfr;
	cfg->priority = user->priority;
	cfg->rnr_retry = user->rnr_retry;
	cfg->err_timeout = user->err_timeout;
	cfg->min_rnr_timer = user->min_rnr_timer;
	cfg->trans_mode = user->trans_mode;
	cfg->jetty_context = user->jetty_context;
	cfg->token_value = user->token_value;
	return 0;
}

static int check_jetty_cfg(struct ubcore_device *dev, struct ubcore_jetty_cfg *cfg)
{
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err("Invalid parameter, trans_mode: %d.\n", (int)cfg->trans_mode);
		return -1;
	}

	if (cfg->send_jfc == NULL || cfg->recv_jfc == NULL) {
		ubcore_log_err("jfc is null.\n");
		return -1;
	}

	if (cfg->flag.bs.share_jfr == 0 && dev->transport_type == UBCORE_TRANSPORT_UB) {
		ubcore_log_err("UB dev should use share jfr");
		return -1;
	}
	if (cfg->flag.bs.share_jfr != 0 &&
		(cfg->jfr == NULL || cfg->jfr->jfr_cfg.trans_mode != cfg->trans_mode)) {
		ubcore_log_err("jfr is null or trans_mode invalid with shared jfr flag.\n");
		return -1;
	}
	return 0;
}

static int check_jetty_cfg_with_jetty_grp(struct ubcore_jetty_cfg *cfg)
{
	if (cfg->jetty_grp == NULL)
		return 0;

	if (cfg->trans_mode != UBCORE_TP_RM)
		return -1;
	if (cfg->token_value.token != cfg->jetty_grp->jetty_grp_cfg.token_value.token)
		return -1;

	if (cfg->flag.bs.share_jfr == 1 && (cfg->jfr == NULL ||
		cfg->token_value.token != cfg->jfr->jfr_cfg.token_value.token ||
		cfg->jetty_grp->jetty_grp_cfg.flag.bs.token_policy !=
		cfg->jfr->jfr_cfg.flag.bs.token_policy ||
		cfg->jfr->jfr_cfg.trans_mode != UBCORE_TP_RM))
		return -1;

	return 0;
}

static int check_jetty_check_dev_cap(struct ubcore_device *dev, struct ubcore_jetty_cfg *cfg)
{
	struct ubcore_device_cap *cap = &dev->attr.dev_cap;

	if (cfg->jetty_grp != NULL) {
		mutex_lock(&cfg->jetty_grp->lock);
		if (cfg->jetty_grp->jetty_cnt >= cap->max_jetty_in_jetty_grp) {
			mutex_unlock(&cfg->jetty_grp->lock);
			ubcore_log_err("jetty_grp jetty cnt:%u, max_jetty in grp:%u.\n",
				cfg->jetty_grp->jetty_cnt, cap->max_jetty_in_jetty_grp);
			return -1;
		}
		mutex_unlock(&cfg->jetty_grp->lock);
	}

	if (cfg->jfs_depth == 0 || cfg->jfs_depth > cap->max_jfs_depth) {
		ubcore_log_err("Invalid parameter, jfs_depth:%u, max_jfs_depth: %u.\n",
			cfg->jfs_depth, cap->max_jfs_depth);
		return -EINVAL;
	}
	if (cfg->max_inline_data != 0 && cfg->max_inline_data > cap->max_jfs_inline_size) {
		ubcore_log_err("Invalid parameter, inline_data:%u, max_jfs_inline_len: %u.\n",
			cfg->max_inline_data, cap->max_jfs_inline_size);
		return -EINVAL;
	}
	if (cfg->max_send_sge > cap->max_jfs_sge) {
		ubcore_log_err("Invalid parameter, jfs_sge:%hhu, max_jfs_sge:%u.\n",
			cfg->max_send_sge, cap->max_jfs_sge);
		return -EINVAL;
	}
	if (cfg->max_send_rsge > cap->max_jfs_rsge) {
		ubcore_log_err("Invalid parameter, jfs_rsge:%hhu, max_jfs_rsge:%u.\n",
			cfg->max_send_rsge, cap->max_jfs_rsge);
		return -EINVAL;
	}

	if (cfg->flag.bs.share_jfr == 0) {
		if (cfg->jfr_depth == 0 || cfg->jfr_depth > cap->max_jfr_depth) {
			ubcore_log_err("Invalid parameter, jfr_depth:%u, max_jfr_depth: %u.\n",
				cfg->jfr_depth, cap->max_jfr_depth);
			return -EINVAL;
		}
		if (cfg->max_recv_sge > cap->max_jfr_sge) {
			ubcore_log_err("Invalid parameter, jfr_sge:%hhu, max_jfr_sge:%u.\n",
				cfg->max_recv_sge, cap->max_jfr_sge);
			return -EINVAL;
		}
	}

	return 0;
}

static int ubcore_add_jetty_to_jetty_grp(struct ubcore_jetty *jetty,
	struct ubcore_jetty_group *jetty_grp)
{
	uint32_t max_jetty_in_grp;
	uint32_t i;

	max_jetty_in_grp = jetty->ub_dev->attr.dev_cap.max_jetty_in_jetty_grp;
	mutex_lock(&jetty_grp->lock);
	for (i = 0; i < max_jetty_in_grp; i++) {
		if (jetty_grp->jetty[i] == NULL) {
			jetty_grp->jetty[i] = jetty;
			jetty_grp->jetty_cnt++;
			mutex_unlock(&jetty_grp->lock);
			return 0;
		}
	}
	mutex_unlock(&jetty_grp->lock);
	ubcore_log_err("failed to add jetty to jetty_grp.\n");
	return -1;
}

static int ubcore_remove_jetty_from_jetty_grp(struct ubcore_jetty *jetty,
	struct ubcore_jetty_group *jetty_grp)
{
	uint32_t max_jetty_in_grp;
	uint32_t i;

	if (jetty == NULL || jetty_grp == NULL)
		return 0;

	max_jetty_in_grp = jetty->ub_dev->attr.dev_cap.max_jetty_in_jetty_grp;
	mutex_lock(&jetty_grp->lock);
	for (i = 0; i < max_jetty_in_grp; i++) {
		if (jetty_grp->jetty[i] == jetty) {
			jetty_grp->jetty[i] = NULL;
			jetty_grp->jetty_cnt--;
			mutex_unlock(&jetty_grp->lock);
			return 0;
		}
	}
	mutex_unlock(&jetty_grp->lock);
	ubcore_log_err("failed to delete jetty to jetty_grp.\n");
	return -1;
}

struct ubcore_jetty *ubcore_create_jetty(struct ubcore_device *dev, struct ubcore_jetty_cfg *cfg,
	ubcore_event_callback_t jfae_handler, struct ubcore_udata *udata)
{
	struct ubcore_jetty *jetty;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->create_jetty == NULL ||
		dev->ops->destroy_jetty == NULL)
		return NULL;

	if (check_jetty_cfg(dev, cfg) != 0) {
		ubcore_log_err("failed to check jetty cfg.\n");
		return NULL;
	}

	if (check_jetty_cfg_with_jetty_grp(cfg) != 0) {
		ubcore_log_err("failed to check jetty cfg.\n");
		return NULL;
	}

	if (check_jetty_check_dev_cap(dev, cfg) != 0) {
		ubcore_log_err("failed to check jetty cfg.\n");
		return NULL;
	}

	jetty = dev->ops->create_jetty(dev, cfg, udata);
	if (jetty == NULL) {
		ubcore_log_err("failed to create jetty.\n");
		return NULL;
	}

	jetty->ub_dev = dev;
	if (cfg->jetty_grp != NULL &&
		ubcore_add_jetty_to_jetty_grp(jetty,
			(struct ubcore_jetty_group *)cfg->jetty_grp) != 0) {
		ubcore_log_err("jetty cfg is not qualified.\n");
		goto destroy_jetty;
	}

	if (check_and_fill_jetty_attr(&jetty->jetty_cfg, cfg) != 0) {
		ubcore_log_err("jetty cfg is not qualified.\n");
		goto delete_jetty_to_grp;
	}

	jetty->uctx = ubcore_get_uctx(udata);
	jetty->jfae_handler = jfae_handler;
	if (ubcore_jetty_need_advise(jetty) || jetty->jetty_cfg.trans_mode == UBCORE_TP_RC) {
		jetty->tptable = ubcore_create_tptable();
		if (jetty->tptable == NULL) {
			ubcore_log_err("Failed to create tp table in the jetty.\n");
			goto delete_jetty_to_grp;
		}
	} else {
		jetty->tptable = NULL; /* To prevent kernel-mode drivers, malloc is not empty */
	}
	atomic_set(&jetty->use_cnt, 0);

	if (ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JETTY], &jetty->hnode, jetty->id) != 0) {
		ubcore_log_err("Failed to add jetty.\n");
		goto destroy_tptable;
	}

	atomic_inc(&cfg->send_jfc->use_cnt);
	atomic_inc(&cfg->recv_jfc->use_cnt);

	if (cfg->jfr)
		atomic_inc(&cfg->jfr->use_cnt);

	return jetty;
destroy_tptable:
	ubcore_destroy_tptable(&jetty->tptable);
delete_jetty_to_grp:
	(void)ubcore_remove_jetty_from_jetty_grp(
		jetty, (struct ubcore_jetty_group *)cfg->jetty_grp);
destroy_jetty:
	(void)dev->ops->destroy_jetty(jetty);
	return NULL;
}
EXPORT_SYMBOL(ubcore_create_jetty);

int ubcore_modify_jetty(struct ubcore_jetty *jetty, struct ubcore_jetty_attr *attr,
	struct ubcore_udata *udata)
{
	uint32_t jetty_id;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->modify_jetty == NULL ||
		attr == NULL)
		return -EINVAL;

	jetty_id = jetty->id;

	ret = jetty->ub_dev->ops->modify_jetty(jetty, attr, udata);
	if (ret != 0)
		ubcore_log_err("UBEP failed to modify jetty, jetty_id:%u.\n", jetty_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jetty);

int ubcore_query_jetty(struct ubcore_jetty *jetty, struct ubcore_jetty_cfg *cfg,
	struct ubcore_jetty_attr *attr)
{
	struct ubcore_device *dev;
	uint32_t jetty_id;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->query_jetty == NULL)
		return -EINVAL;

	jetty_id = jetty->id;
	dev = jetty->ub_dev;
	ret = dev->ops->query_jetty(jetty, cfg, attr);
	if (ret != 0)
		ubcore_log_err("UBEP failed to query jetty, jetty_id:%u.\n", jetty_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_query_jetty);

int ubcore_delete_jetty(struct ubcore_jetty *jetty)
{
	struct ubcore_jetty_group *jetty_grp;
	struct ubcore_jfc *send_jfc;
	struct ubcore_jfc *recv_jfc;
	struct ubcore_device *dev;
	struct ubcore_jfr *jfr;
	uint32_t jetty_id;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->destroy_jetty == NULL)
		return -1;

	if ((jetty->ub_dev->transport_type == UBCORE_TRANSPORT_UB &&
		jetty->jetty_cfg.trans_mode == UBCORE_TP_RC && jetty->remote_jetty != NULL) ||
		atomic_read(&jetty->use_cnt) > 0) {
		ubcore_log_err("Failed to delete jetty in RC mode because it has remote jetty");
		return -1;
	}

	jetty_grp = jetty->jetty_cfg.jetty_grp;
	send_jfc = jetty->jetty_cfg.send_jfc;
	recv_jfc = jetty->jetty_cfg.recv_jfc;
	jfr = jetty->jetty_cfg.jfr;
	jetty_id = jetty->id;
	dev = jetty->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JETTY], &jetty->hnode);
	ubcore_destroy_tptable(&jetty->tptable);

	if (jetty->ub_dev->transport_type == UBCORE_TRANSPORT_UB && jetty->remote_jetty != NULL) {
		mutex_lock(&jetty->remote_jetty->lock);
		(void)ubcore_disconnect_vtp(jetty->remote_jetty->vtpn);
		jetty->remote_jetty->vtpn = NULL;
		mutex_unlock(&jetty->remote_jetty->lock);
		atomic_dec(&jetty->remote_jetty->use_cnt);
		/* The tjetty object will release remote jetty resources */
		jetty->remote_jetty = NULL;
		ubcore_log_warn("jetty->remote_jetty != NULL and it has been handled");
	}

	if (jetty_grp != NULL)
		(void)ubcore_remove_jetty_from_jetty_grp(jetty, jetty_grp);
	ret = dev->ops->destroy_jetty(jetty);
	if (ret != 0) {
		ubcore_log_err("UBEP failed to destroy jetty, jetty_id:%u.\n", jetty_id);
		goto rollback;
	} else {
		if (send_jfc)
			atomic_dec(&send_jfc->use_cnt);
		if (recv_jfc)
			atomic_dec(&recv_jfc->use_cnt);
		if (jfr)
			atomic_dec(&jfr->use_cnt);
	}
	return ret;

rollback:
	if (jetty_grp != NULL)
		(void)ubcore_add_jetty_to_jetty_grp(jetty, jetty_grp);
	if (ubcore_jetty_need_advise(jetty) || jetty->jetty_cfg.trans_mode == UBCORE_TP_RC)
		jetty->tptable = ubcore_create_tptable();
	(void)ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JETTY], &jetty->hnode, jetty->id);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jetty);

int ubcore_flush_jetty(struct ubcore_jetty *jetty, int cr_cnt, struct ubcore_cr *cr)
{
	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->flush_jetty == NULL || cr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	return jetty->ub_dev->ops->flush_jetty(jetty, cr_cnt, cr);
}
EXPORT_SYMBOL(ubcore_flush_jetty);

struct ubcore_tjetty *ubcore_import_jetty(struct ubcore_device *dev,
	struct ubcore_tjetty_cfg *cfg, struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param;
	struct ubcore_tjetty *tjetty;

	if (!ubcore_have_tp_ops(dev) || dev->ops->import_jetty == NULL ||
		dev->ops->unimport_jetty == NULL || cfg == NULL ||
		dev->attr.dev_cap.max_eid_cnt < cfg->eid_index)
		return NULL;

	tjetty = dev->ops->import_jetty(dev, cfg, udata);
	if (tjetty == NULL) {
		ubcore_log_err("UBEP failed to import jetty, jetty_id:%u.\n", cfg->id.id);
		return NULL;
	}
	tjetty->cfg = *cfg;
	tjetty->ub_dev = dev;
	tjetty->uctx = ubcore_get_uctx(udata);

	atomic_set(&tjetty->use_cnt, 0);
	mutex_init(&tjetty->lock);

	/* create rm tp if the remote eid is not connected */
	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
		(cfg->trans_mode == UBCORE_TP_RM || cfg->trans_mode == UBCORE_TP_UM)) {
		ubcore_set_vtp_param(dev, NULL, cfg, &vtp_param);
		mutex_lock(&tjetty->lock);
		tjetty->vtpn = ubcore_connect_vtp(dev, &vtp_param);
		if (tjetty->vtpn == NULL) {
			mutex_unlock(&tjetty->lock);
			mutex_destroy(&tjetty->lock);
			(void)dev->ops->unimport_jetty(tjetty);
			ubcore_log_err("Failed to setup tp connection.\n");
			return NULL;
		}
		mutex_unlock(&tjetty->lock);
	} else {
		tjetty->tp = NULL;
	}

	return tjetty;
}
EXPORT_SYMBOL(ubcore_import_jetty);

int ubcore_unimport_jetty(struct ubcore_tjetty *tjetty)
{
	struct ubcore_device *dev;
	int ret;

	if (tjetty == NULL || tjetty->ub_dev == NULL || tjetty->ub_dev->ops == NULL ||
		tjetty->ub_dev->ops->unimport_jetty == NULL || !ubcore_have_tp_ops(tjetty->ub_dev))
		return -EINVAL;

	dev = tjetty->ub_dev;

	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
		(tjetty->cfg.trans_mode == UBCORE_TP_RM ||
			tjetty->cfg.trans_mode == UBCORE_TP_UM) &&
		tjetty->vtpn != NULL) {
		mutex_lock(&tjetty->lock);
		ret = ubcore_disconnect_vtp(tjetty->vtpn);
		if (ret != 0) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Failed to disconnect vtp.\n");
			return ret;
		}
		tjetty->vtpn = NULL;
		mutex_unlock(&tjetty->lock);
	}

	if (tjetty->cfg.trans_mode == UBCORE_TP_RC && atomic_read(&tjetty->use_cnt))
		return -EBUSY;

	mutex_destroy(&tjetty->lock);

	return dev->ops->unimport_jetty(tjetty);
}
EXPORT_SYMBOL(ubcore_unimport_jetty);

static int ubcore_advice_jfs_tjfr(struct ubcore_tp_advice *advice, struct ubcore_jfs *jfs,
				  struct ubcore_tjetty *tjfr)
{
	(void)memset(advice, 0, sizeof(struct ubcore_tp_advice));
	advice->meta.ht = ubcore_get_tptable(jfs->tptable);
	if (advice->meta.ht == NULL) {
		ubcore_log_err("tp table has already been destroyed");
		return -1;
	}

	advice->ta.type = UBCORE_TA_JFS_TJFR;
	advice->ta.jfs = jfs;
	advice->ta.tjetty_id = tjfr->cfg.id;

	ubcore_init_tp_key_jetty_id(&advice->meta.key, &tjfr->cfg.id);
	advice->meta.hash = ubcore_get_jetty_hash(&tjfr->cfg.id);
	return 0;
}

static int ubcore_advice_jetty_tjetty(struct ubcore_tp_advice *advice, struct ubcore_jetty *jetty,
				      struct ubcore_tjetty *tjetty)
{
	(void)memset(advice, 0, sizeof(struct ubcore_tp_advice));
	advice->meta.ht = ubcore_get_tptable(jetty->tptable);
	if (advice->meta.ht == NULL) {
		ubcore_log_err("tp table has already been destroyed");
		return -1;
	}

	advice->ta.type = UBCORE_TA_JETTY_TJETTY;
	advice->ta.jetty = jetty;
	advice->ta.tjetty_id = tjetty->cfg.id;

	ubcore_init_tp_key_jetty_id(&advice->meta.key, &tjetty->cfg.id);
	advice->meta.hash = ubcore_get_jetty_hash(&tjetty->cfg.id);
	return 0;
}

static inline void ubcore_put_advice(struct ubcore_tp_advice *advice)
{
	ubcore_put_tptable(advice->meta.ht);
}

int ubcore_advise_jfr(struct ubcore_jfs *jfs, struct ubcore_tjetty *tjfr,
		      struct ubcore_udata *udata)
{
	struct ubcore_tp_advice advice;
	int ret;

	if (jfs == NULL || tjfr == NULL || !ubcore_have_tp_ops(jfs->ub_dev)) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}

	if (jfs->ub_dev->transport_type == UBCORE_TRANSPORT_UB)
		return 0;

	if (!ubcore_jfs_tjfr_need_advise(jfs, tjfr)) {
		ubcore_log_err("The transport mode is not rm.\n");
		return -1;
	}

	ret = ubcore_advice_jfs_tjfr(&advice, jfs, tjfr);
	if (ret != 0)
		return ret;

	ret = ubcore_advise_tp(jfs->ub_dev, &tjfr->cfg.id.eid, &advice, udata);
	ubcore_put_advice(&advice);
	return ret;
}
EXPORT_SYMBOL(ubcore_advise_jfr);

int ubcore_unadvise_jfr(struct ubcore_jfs *jfs, struct ubcore_tjetty *tjfr)
{
	struct ubcore_tp_advice advice;
	int ret;

	if (jfs == NULL || tjfr == NULL || !ubcore_have_tp_ops(jfs->ub_dev)) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}

	if (jfs->ub_dev->transport_type == UBCORE_TRANSPORT_UB)
		return 0;

	if (!ubcore_jfs_tjfr_need_advise(jfs, tjfr)) {
		ubcore_log_err("The transport mode is not rm.\n");
		return -1;
	}

	ret = ubcore_advice_jfs_tjfr(&advice, jfs, tjfr);
	if (ret != 0)
		return ret;

	ret = ubcore_unadvise_tp(jfs->ub_dev, &advice);
	ubcore_put_advice(&advice);
	return ret;
}
EXPORT_SYMBOL(ubcore_unadvise_jfr);

int ubcore_advise_jetty(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
			struct ubcore_udata *udata)
{
	struct ubcore_tp_advice advice;
	int ret;

	if (jetty == NULL || tjetty == NULL || !ubcore_have_tp_ops(jetty->ub_dev)) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}

	if (jetty->ub_dev->transport_type == UBCORE_TRANSPORT_UB)
		return 0;

	if (!ubcore_jetty_tjetty_need_advise(jetty, tjetty)) {
		ubcore_log_err("The transport mode is not rm.\n");
		return -1;
	}

	ret = ubcore_advice_jetty_tjetty(&advice, jetty, tjetty);
	if (ret != 0)
		return ret;

	/* alpha version, IB transport type and RM tp mode */
	ret = ubcore_advise_tp(jetty->ub_dev, &tjetty->cfg.id.eid, &advice, udata);
	ubcore_put_advice(&advice);
	return ret;
}
EXPORT_SYMBOL(ubcore_advise_jetty);

int ubcore_unadvise_jetty(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty)
{
	struct ubcore_tp_advice advice;
	int ret;

	if (jetty == NULL || tjetty == NULL || !ubcore_have_tp_ops(jetty->ub_dev)) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}

	if (jetty->ub_dev->transport_type == UBCORE_TRANSPORT_UB)
		return 0;

	if (!ubcore_jetty_tjetty_need_advise(jetty, tjetty)) {
		ubcore_log_err("The transport mode is not rm.\n");
		return -1;
	}

	ret = ubcore_advice_jetty_tjetty(&advice, jetty, tjetty);
	if (ret != 0)
		return ret;

	ret = ubcore_unadvise_tp(jetty->ub_dev, &advice);
	ubcore_put_advice(&advice);
	return ret;
}
EXPORT_SYMBOL(ubcore_unadvise_jetty);

static int ubcore_inner_bind_jetty(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
								struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param;
	struct ubcore_tp_advice advice;
	struct ubcore_device *dev;
	int ret;

	dev = jetty->ub_dev;
	if (dev == NULL) {
		ubcore_log_err("Invalid parameter with dev null_ptr.\n");
		return -1;
	}

	if (dev->attr.dev_cap.max_eid_cnt < tjetty->cfg.eid_index) {
		ubcore_log_err("eid_index:%u is beyond the max_eid_cnt:%u.\n",
			tjetty->cfg.eid_index, dev->attr.dev_cap.max_eid_cnt);
		return -EINVAL;
	}

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		struct ubcore_vtpn *vtpn;
		/* IB devices don't need to call bind_jetty and unbind_jetty */
		if (dev->ops == NULL || dev->ops->bind_jetty == NULL ||
			dev->ops->unbind_jetty == NULL) {
			ubcore_log_err("Failed to bind jetty, no ops->bind_jetty\n");
			return -1;
		}

		ret = dev->ops->bind_jetty(jetty, tjetty, udata);
		if (ret != 0) {
			ubcore_log_err("Failed to bind jetty");
			return ret;
		}
		atomic_inc(&jetty->use_cnt);

		ubcore_set_vtp_param(dev, jetty, &tjetty->cfg, &vtp_param);
		mutex_lock(&tjetty->lock);
		vtpn = ubcore_connect_vtp(dev, &vtp_param);
		if (vtpn == NULL) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Failed to setup vtp connection.\n");
			ret = -1;
			goto unbind;
		}
		tjetty->vtpn = vtpn;
		mutex_unlock(&tjetty->lock);
	} else if (dev->transport_type == UBCORE_TRANSPORT_IB) {
		ret = ubcore_advice_jetty_tjetty(&advice, jetty, tjetty);
		if (ret != 0)
			return ret;

		ret = ubcore_bind_tp(jetty, tjetty, &advice, udata);
		ubcore_put_advice(&advice);
		if (ret != 0) {
			ubcore_log_err("Failed to setup tp connection.\n");
			return ret;
		}
	}
	ubcore_log_info("jetty: %u bind tjetty: %u\n", jetty->id, tjetty->cfg.id.id);
	jetty->remote_jetty = tjetty;
	atomic_inc(&tjetty->use_cnt);
	return 0;

unbind:
	if (dev->ops->bind_jetty != NULL && dev->ops->unbind_jetty != NULL) {
		(void)dev->ops->unbind_jetty(jetty);
		atomic_dec(&jetty->use_cnt);
	}

	return ret;
}

int ubcore_bind_jetty(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
		      struct ubcore_udata *udata)
{
	if (jetty == NULL || tjetty == NULL || !ubcore_have_tp_ops(jetty->ub_dev)) {
		ubcore_log_err("invalid parameter.\n");
		return -1;
	}
	if ((jetty->jetty_cfg.trans_mode != UBCORE_TP_RC) ||
		(tjetty->cfg.trans_mode != UBCORE_TP_RC)) {
		ubcore_log_err("trans mode is not rc type.\n");
		return -1;
	}
	if (jetty->remote_jetty == tjetty) {
		ubcore_log_info("bind reentry, jetty: %u bind tjetty: %u\n",
			jetty->id, tjetty->cfg.id.id);
		return 0;
	}
	if (jetty->remote_jetty != NULL) {
		ubcore_log_err("The same jetty, different tjetty, prevent duplicate bind.\n");
		return -1;
	}

	if (tjetty->vtpn != NULL) {
		ubcore_log_err("The tjetty, has already connect vtpn, prevent duplicate bind.\n");
		return -1;
	}

	return ubcore_inner_bind_jetty(jetty, tjetty, udata);
}
EXPORT_SYMBOL(ubcore_bind_jetty);

int ubcore_unbind_jetty(struct ubcore_jetty *jetty)
{
	struct ubcore_tp_advice advice;
	struct ubcore_tjetty *tjetty;
	struct ubcore_device *dev;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	tjetty = jetty->remote_jetty;
	if ((jetty->jetty_cfg.trans_mode != UBCORE_TP_RC) ||
		tjetty == NULL || (tjetty->cfg.trans_mode != UBCORE_TP_RC)) {
		ubcore_log_err("trans mode is not rc type.\n");
		return -EINVAL;
	}

	dev = jetty->ub_dev;

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		if (tjetty->vtpn != NULL) {
			mutex_lock(&tjetty->lock);
			ret = ubcore_disconnect_vtp(tjetty->vtpn);
			if (ret != 0) {
				mutex_unlock(&tjetty->lock);
				ubcore_log_err("Failed to disconnect vtp.\n");
				return ret;
			}
			tjetty->vtpn = NULL;
			mutex_unlock(&tjetty->lock);
		}
	} else if (dev->transport_type == UBCORE_TRANSPORT_IB) {
		ret = ubcore_advice_jetty_tjetty(&advice, jetty, tjetty);
		if (ret != 0)
			return ret;

		ret = ubcore_unbind_tp(jetty, tjetty, &advice);
		ubcore_put_advice(&advice);
		if (ret != 0) {
			ubcore_log_err("Failed to destroy jetty tp.\n");
			return ret;
		}
	}
	ubcore_log_info("jetty: %u unbind tjetty: %u\n", jetty->id, tjetty->cfg.id.id);

	/* IB devices don't need to call bind_jetty and unbind_jetty */
	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		if (dev->ops == NULL || dev->ops->bind_jetty == NULL ||
			dev->ops->unbind_jetty == NULL) {
			ubcore_log_err("Failed to unbind jetty, no ops->unbind_jetty\n");
			return -1;
		}
		ret = dev->ops->unbind_jetty(jetty);
		if (ret != 0) {
			ubcore_log_err("Failed to unbind jetty");
			return ret;
		}
		atomic_dec(&jetty->use_cnt);
	}

	atomic_dec(&tjetty->use_cnt);
	jetty->remote_jetty = NULL;
	return 0;
}
EXPORT_SYMBOL(ubcore_unbind_jetty);

struct ubcore_jetty *ubcore_find_jetty(struct ubcore_device *dev, uint32_t jetty_id)
{
	if (dev == NULL) {
		ubcore_log_err("invalid parameter.\n");
		return NULL;
	}

	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JETTY], jetty_id, &jetty_id);
}
EXPORT_SYMBOL(ubcore_find_jetty);

struct ubcore_jetty_group *ubcore_create_jetty_grp(struct ubcore_device *dev,
	struct ubcore_jetty_grp_cfg *cfg, ubcore_event_callback_t jfae_handler,
	struct ubcore_udata *udata)
{
	struct ubcore_jetty_group *jetty_grp;
	uint32_t max_jetty_in_jetty_grp;
	uint32_t i;

	if (dev == NULL || cfg == NULL || udata == NULL || dev->ops == NULL ||
		dev->ops->create_jetty_grp == NULL || dev->ops->delete_jetty_grp == NULL)
		return NULL;

	max_jetty_in_jetty_grp = dev->attr.dev_cap.max_jetty_in_jetty_grp;
	if (max_jetty_in_jetty_grp == 0 || max_jetty_in_jetty_grp > UBCORE_MAX_JETTY_IN_JETTY_GRP) {
		ubcore_log_err("max_jetty_in_jetty_grp %u is err, range is 1 to %u.\n",
			max_jetty_in_jetty_grp, UBCORE_MAX_JETTY_IN_JETTY_GRP);
		return NULL;
	}

	jetty_grp = dev->ops->create_jetty_grp(dev, (struct ubcore_jetty_grp_cfg *)cfg, udata);
	if (jetty_grp == NULL) {
		ubcore_log_err("failed to create jetty_grp.\n");
		return NULL;
	}

	jetty_grp->jetty = kzalloc(
		sizeof(struct ubcore_jetty *) * max_jetty_in_jetty_grp, GFP_KERNEL);
	if (jetty_grp->jetty == NULL) {
		(void)dev->ops->delete_jetty_grp(jetty_grp);
		ubcore_log_err("Failed to alloc jetty array.\n");
		return NULL;
	}

	jetty_grp->ub_dev = dev;
	jetty_grp->jetty_grp_cfg = *cfg;
	jetty_grp->jfae_handler = jfae_handler;
	jetty_grp->uctx = ubcore_get_uctx(udata);
	mutex_init(&jetty_grp->lock);
	jetty_grp->jetty_cnt = 0;
	for (i = 0; i < dev->attr.dev_cap.max_jetty_in_jetty_grp; i++)
		jetty_grp->jetty[i] = NULL;

	return jetty_grp;
}
EXPORT_SYMBOL(ubcore_create_jetty_grp);

int ubcore_delete_jetty_grp(struct ubcore_jetty_group *jetty_grp)
{
	struct ubcore_device *dev;
	uint32_t jetty_grp_id;
	int ret;

	if (jetty_grp == NULL || jetty_grp->ub_dev == NULL || jetty_grp->ub_dev->ops == NULL ||
		jetty_grp->ub_dev->ops->delete_jetty_grp == NULL)
		return -EINVAL;

	jetty_grp_id = jetty_grp->id;
	dev = jetty_grp->ub_dev;

	mutex_lock(&jetty_grp->lock);
	if (jetty_grp->jetty_cnt > 0) {
		mutex_unlock(&jetty_grp->lock);
		ubcore_log_err("jetty_grp->jetty_cnt: %u.\n", jetty_grp->jetty_cnt);
		return -EBUSY;
	}
	if (jetty_grp->jetty != NULL) {
		kfree(jetty_grp->jetty);
		jetty_grp->jetty = NULL;
	}
	mutex_unlock(&jetty_grp->lock);
	mutex_destroy(&jetty_grp->lock);

	ret = dev->ops->delete_jetty_grp(jetty_grp);
	if (ret != 0)
		ubcore_log_err(
			"UBEP failed to destroy jetty_grp, jetty_grp_id:%u.\n", jetty_grp_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jetty_grp);
