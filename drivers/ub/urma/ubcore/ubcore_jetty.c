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

static int check_and_fill_jfs_attr(struct ubcore_jfs_cfg *cfg, const struct ubcore_jfs_cfg *user)
{
	if (cfg->depth < user->depth || cfg->max_sge < user->max_sge ||
	    cfg->max_rsge < user->max_rsge || cfg->max_inline_data < user->max_inline_data)
		return -1;

	/* store the immutable and skip the driver updated attributes including depth,
	 * max_sge and max_inline_data
	 */
	cfg->flag = user->flag;
	cfg->priority = user->priority;
	cfg->retry_cnt = user->retry_cnt;
	cfg->rnr_retry = user->rnr_retry;
	cfg->err_timeout = user->err_timeout;
	cfg->trans_mode = user->trans_mode;
	cfg->jfs_context = user->jfs_context;
	cfg->jfc = user->jfc;
	return 0;
}

struct ubcore_jfs *ubcore_create_jfs(struct ubcore_device *dev, const struct ubcore_jfs_cfg *cfg,
				     ubcore_event_callback_t jfae_handler,
				     struct ubcore_udata *udata)
{
	struct ubcore_jfs *jfs;

	if (dev == NULL || cfg == NULL || dev->ops->create_jfs == NULL ||
	    dev->ops->destroy_jfs == NULL)
		return NULL;

	if (((uint16_t)cfg->trans_mode & dev->attr.dev_cap.trans_mode) == 0) {
		ubcore_log_err("jfs cfg is not supported.\n");
		return NULL;
	}

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

	atomic_set(&jfs->use_cnt, 0);

	if (ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFS], &jfs->hnode, jfs->id) != 0) {
		(void)dev->ops->destroy_jfs(jfs);
		ubcore_log_err("Failed to add jfs.\n");
		return NULL;
	}

	atomic_inc(&cfg->jfc->use_cnt);
	return jfs;
}
EXPORT_SYMBOL(ubcore_create_jfs);

int ubcore_modify_jfs(struct ubcore_jfs *jfs, const struct ubcore_jfs_attr *attr,
		      struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfs_id;
	int ret;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops->modify_jfs == NULL)
		return -EINVAL;

	jfs_id = jfs->id;
	dev = jfs->ub_dev;
	ret = dev->ops->modify_jfs(jfs, attr, udata);
	if (ret < 0)
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

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops->query_jfs == NULL)
		return -EINVAL;

	jfs_id = jfs->id;
	dev = jfs->ub_dev;
	ret = dev->ops->query_jfs(jfs, cfg, attr);
	if (ret < 0)
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

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops->destroy_jfs == NULL)
		return -EINVAL;

	jfc = jfs->jfs_cfg.jfc;
	jfs_id = jfs->id;
	dev = jfs->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFS], &jfs->hnode);
	ret = dev->ops->destroy_jfs(jfs);
	if (ret < 0)
		ubcore_log_err("UBEP failed to destroy jfs, jfs_id:%u.\n", jfs_id);
	else
		atomic_dec(&jfc->use_cnt);

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

static int check_and_fill_jfr_attr(struct ubcore_jfr_cfg *cfg, const struct ubcore_jfr_cfg *user)
{
	if (cfg->depth < user->depth || cfg->max_sge < user->max_sge)
		return -1;

	/* store the immutable and skip the driver updated attributes including depth, max_sge */
	cfg->flag = user->flag;
	cfg->min_rnr_timer = user->min_rnr_timer;
	cfg->trans_mode = user->trans_mode;
	cfg->ukey = user->ukey;
	cfg->jfr_context = user->jfr_context;
	cfg->jfc = user->jfc;
	return 0;
}

struct ubcore_jfr *ubcore_create_jfr(struct ubcore_device *dev, const struct ubcore_jfr_cfg *cfg,
				     ubcore_event_callback_t jfae_handler,
				     struct ubcore_udata *udata)
{
	struct ubcore_jfr *jfr;

	if (dev == NULL || cfg == NULL || dev->ops->create_jfr == NULL ||
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

	atomic_inc(&cfg->jfc->use_cnt);
	return jfr;
}
EXPORT_SYMBOL(ubcore_create_jfr);

int ubcore_modify_jfr(struct ubcore_jfr *jfr, const struct ubcore_jfr_attr *attr,
		      struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfr_id;
	int ret;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops->modify_jfr == NULL)
		return -EINVAL;

	jfr_id = jfr->id;
	dev = jfr->ub_dev;
	ret = dev->ops->modify_jfr(jfr, attr, udata);
	if (ret < 0)
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

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops->query_jfr == NULL)
		return -EINVAL;

	jfr_id = jfr->id;
	dev = jfr->ub_dev;
	ret = dev->ops->query_jfr(jfr, cfg, attr);
	if (ret < 0)
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

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops->destroy_jfr == NULL)
		return -EINVAL;

	if (WARN_ON_ONCE(atomic_read(&jfr->use_cnt)))
		return -EBUSY;

	jfc = jfr->jfr_cfg.jfc;
	jfr_id = jfr->id;
	dev = jfr->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFR], &jfr->hnode);
	ret = dev->ops->destroy_jfr(jfr);
	if (ret < 0)
		ubcore_log_err("UBEP failed to destroy jfr, jfr_id:%u.\n", jfr_id);
	else
		atomic_dec(&jfc->use_cnt);

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfr);

static int check_and_fill_jetty_attr(struct ubcore_jetty_cfg *cfg,
				     const struct ubcore_jetty_cfg *user)
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
	cfg->flag = user->flag;
	cfg->send_jfc = user->send_jfc;
	cfg->recv_jfc = user->recv_jfc;
	cfg->jfr = user->jfr;
	cfg->priority = user->priority;
	cfg->retry_cnt = user->retry_cnt;
	cfg->rnr_retry = user->rnr_retry;
	cfg->err_timeout = user->err_timeout;
	cfg->min_rnr_timer = user->min_rnr_timer;
	cfg->trans_mode = user->trans_mode;
	cfg->jetty_context = user->jetty_context;
	cfg->ukey = user->ukey;
	return 0;
}

struct ubcore_jetty *ubcore_create_jetty(struct ubcore_device *dev,
					 const struct ubcore_jetty_cfg *cfg,
					 ubcore_event_callback_t jfae_handler,
					 struct ubcore_udata *udata)
{
	struct ubcore_jetty *jetty;

	if (dev == NULL || cfg == NULL || dev->ops->create_jetty == NULL ||
	    dev->ops->destroy_jetty == NULL)
		return NULL;

	jetty = dev->ops->create_jetty(dev, cfg, udata);
	if (jetty == NULL) {
		ubcore_log_err("failed to create jetty.\n");
		return NULL;
	}
	if (check_and_fill_jetty_attr(&jetty->jetty_cfg, cfg) != 0) {
		ubcore_log_err("jetty cfg is not qualified.\n");
		(void)dev->ops->destroy_jetty(jetty);
		return NULL;
	}
	jetty->ub_dev = dev;
	jetty->uctx = ubcore_get_uctx(udata);
	jetty->jfae_handler = jfae_handler;
	atomic_set(&jetty->use_cnt, 0);

	if (ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JETTY], &jetty->hnode, jetty->id) != 0) {
		ubcore_destroy_tptable(&jetty->tptable);
		(void)dev->ops->destroy_jetty(jetty);
		ubcore_log_err("Failed to add jetty.\n");
	}

	atomic_inc(&cfg->send_jfc->use_cnt);
	atomic_inc(&cfg->recv_jfc->use_cnt);
	if (cfg->jfr)
		atomic_inc(&cfg->jfr->use_cnt);
	return jetty;
}
EXPORT_SYMBOL(ubcore_create_jetty);

int ubcore_modify_jetty(struct ubcore_jetty *jetty, const struct ubcore_jetty_attr *attr,
			struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jetty_id;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops->modify_jetty == NULL ||
	    attr == NULL)
		return -EINVAL;

	jetty_id = jetty->id;
	dev = jetty->ub_dev;

	ret = dev->ops->modify_jetty(jetty, attr, udata);
	if (ret < 0)
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

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops->query_jetty == NULL)
		return -EINVAL;

	jetty_id = jetty->id;
	dev = jetty->ub_dev;
	ret = dev->ops->query_jetty(jetty, cfg, attr);
	if (ret < 0)
		ubcore_log_err("UBEP failed to query jetty, jetty_id:%u.\n", jetty_id);

	return ret;
}
EXPORT_SYMBOL(ubcore_query_jetty);

int ubcore_delete_jetty(struct ubcore_jetty *jetty)
{
	struct ubcore_jfc *send_jfc;
	struct ubcore_jfc *recv_jfc;
	struct ubcore_device *dev;
	struct ubcore_jfr *jfr;
	uint32_t jetty_id;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops->destroy_jetty == NULL)
		return -1;

	send_jfc = jetty->jetty_cfg.send_jfc;
	recv_jfc = jetty->jetty_cfg.recv_jfc;
	jfr = jetty->jetty_cfg.jfr;
	jetty_id = jetty->id;
	dev = jetty->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JETTY], &jetty->hnode);
	ret = dev->ops->destroy_jetty(jetty);
	if (ret < 0) {
		ubcore_log_err("UBEP failed to destroy jetty, jetty_id:%u.\n", jetty_id);
	} else {
		if (send_jfc)
			atomic_dec(&send_jfc->use_cnt);
		if (recv_jfc)
			atomic_dec(&recv_jfc->use_cnt);
		if (jfr)
			atomic_dec(&jfr->use_cnt);
	}
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jetty);

int ubcore_flush_jetty(struct ubcore_jetty *jetty, int cr_cnt, struct ubcore_cr *cr)
{
	struct ubcore_ops *dev_ops;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
	    jetty->ub_dev->ops->flush_jetty == NULL || cr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jetty->ub_dev->ops;
	return dev_ops->flush_jetty(jetty, cr_cnt, cr);
}
EXPORT_SYMBOL(ubcore_flush_jetty);
