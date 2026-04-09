// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
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
#include <linux/random.h>
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include <ub/urma/ubcore_jetty.h>
#include "ubcore_connect_adapter.h"
#include "ubcore_connect_bonding.h"
#include "ubcore_log.h"
#include "ubcore_priv.h"
#include "ubcore_hash_table.h"
#include "ubcore_tp.h"
#include "ubcore_tp_table.h"
#include "ubcore_vtp.h"
#include "ubcore_device.h"
#include "ubcore_opt.h"

const struct ubcore_opt_map_t g_ubcore_jfc_opt_table[] = {
	/* opt, mask, target, offset, size */
	/* ---- CFG ---- */
	{ UBCORE_JFC_DEPTH,         UBCORE_CFG_MASK,     TARGET_CFG,
		offsetof(struct ubcore_jfc_cfg, depth),        4 },

	{ UBCORE_JFC_CEQN,          UBCORE_CFG_MASK,      TARGET_CFG,
		offsetof(struct ubcore_jfc_cfg, ceqn),         4 },

	{ UBCORE_JFC_FLAG,          UBCORE_CFG_MASK,      TARGET_CFG,
		offsetof(struct ubcore_jfc_cfg, flag),         4 },

	{ UBCORE_JFC_BIND_JFCE,     UBCORE_CFG_MASK,      TARGET_CFG,
		offsetof(struct ubcore_jfc_cfg, jfc_context),   8 },

	{ UBCORE_JFC_USER_CTX,      UBCORE_CFG_MASK,      TARGET_NO_STORE, 0, 8},
	/* ---- OPT ---- */
	{ UBCORE_JFC_CQE_BASE_ADDR, UBCORE_JFC_CQE_BASE_ADDR_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfc_opt, urma_jfc_cqe_base_addr), 8 },

	{ UBCORE_JFC_ID,            UBCORE_JFC_ID_MASK,        TARGET_OPT,
		offsetof(struct ubcore_jfc_opt, urma_jfc_id),   4 },

	{ UBCORE_JFC_DB_ADDR,       UBCORE_JFC_DB_ADDR_MASK,   TARGET_OPT,
		offsetof(struct ubcore_jfc_opt, urma_jfc_db_addr), 8 },

	{ UBCORE_JFC_DB_STATUS,     UBCORE_JFC_DB_STATUS_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfc_opt, urma_jfc_db_status), 1 },

	{ UBCORE_JFC_PI,            UBCORE_JFC_PI_MASK,        TARGET_OPT,
		offsetof(struct ubcore_jfc_opt, urma_jfc_pi),   2 },

	{ UBCORE_JFC_PI_TYPE,       UBCORE_JFC_PI_TYPE_MASK,   TARGET_OPT,
		offsetof(struct ubcore_jfc_opt, urma_jfc_pi_type), 2 },

	{ UBCORE_JFC_CI,            UBCORE_JFC_CI_MASK,        TARGET_OPT,
		offsetof(struct ubcore_jfc_opt, urma_jfc_ci),   2 },
};

const size_t g_ubcore_jfc_opt_map_count = ARRAY_SIZE(g_ubcore_jfc_opt_table);

const struct ubcore_opt_map_t g_ubcore_jfr_opt_table[] = {
	/* opt, mask, target, offset, size */

	{ UBCORE_JFR_DEPTH,         UBCORE_CFG_MASK,     TARGET_CFG,
		offsetof(struct ubcore_jfr_cfg, depth),        4 },

	{ UBCORE_JFR_FLAG,          UBCORE_CFG_MASK,      TARGET_CFG,
		offsetof(struct ubcore_jfr_cfg, flag),         4 },

	{ UBCORE_JFR_TRANS_MODE,    UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jfr_cfg, trans_mode),         4 },

	{ UBCORE_JFR_MAX_SGE,       UBCORE_CFG_MASK,  TARGET_CFG,
		offsetof(struct ubcore_jfr_cfg, max_sge),     1 },

	{ UBCORE_JFR_MIN_RNR_TIMER, UBCORE_CFG_MASK,  TARGET_CFG,
		offsetof(struct ubcore_jfr_cfg, min_rnr_timer),     1 },

	{ UBCORE_JFR_BIND_JFC,      UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jfr_cfg, jfc), 8 },

	{ UBCORE_JFR_TOKEN_VALUE,   UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jfr_cfg, token_value), 4 },

	{ UBCORE_JFR_USER_CTX,      UBCORE_CFG_MASK, TARGET_NO_STORE, 0, 8},
	/* ---- OPT ---- */

	{ UBCORE_JFR_RQE_BASE_ADDR, UBCORE_JFR_RQE_BASE_ADDR_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfr_opt, urma_jfr_rqe_base_addr), 8 },

	{ UBCORE_JFR_ID,            UBCORE_JFR_ID_MASK,        TARGET_OPT,
		offsetof(struct ubcore_jfr_opt, urma_jfr_id),   4 },

	{ UBCORE_JFR_DB_ADDR,       UBCORE_JFR_DB_ADDR_MASK,   TARGET_OPT,
		offsetof(struct ubcore_jfr_opt, urma_jfr_db_addr), 8 },

	{ UBCORE_JFR_DB_STATUS,     UBCORE_JFR_DB_STATUS_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfr_opt, urma_jfr_db_status), 1 },

	{ UBCORE_JFR_PI,            UBCORE_JFR_PI_MASK,        TARGET_OPT,
		offsetof(struct ubcore_jfr_opt, urma_jfr_pi),   2 },

	{ UBCORE_JFR_PI_TYPE,       UBCORE_JFR_PI_TYPE_MASK,   TARGET_OPT,
		offsetof(struct ubcore_jfr_opt, urma_jfr_pi_type), 2 },

	{ UBCORE_JFR_CI,            UBCORE_JFR_CI_MASK,        TARGET_OPT,
		offsetof(struct ubcore_jfr_opt, urma_jfr_ci),   2 },
};
const size_t g_ubcore_jfr_opt_map_count = ARRAY_SIZE(g_ubcore_jfr_opt_table);

const struct ubcore_opt_map_t g_ubcore_jfs_opt_table[] = {
	/* opt, mask, target, offset, size */
	{ UBCORE_JFS_DEPTH,         UBCORE_CFG_MASK,     TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, depth),        4 },

	{ UBCORE_JFS_FLAG,          UBCORE_CFG_MASK,      TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, flag),         4 },

	{ UBCORE_JFS_TRANS_MODE,    UBCORE_CFG_MASK, TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, trans_mode),         4 },

	{ UBCORE_JFS_PRIORITY,    UBCORE_CFG_MASK, TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, priority),         1 },

	{ UBCORE_JFS_MAX_SGE,       UBCORE_CFG_MASK,  TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, max_sge),     1 },

	{ UBCORE_JFS_MAX_RSGE,       UBCORE_CFG_MASK,  TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, max_rsge),     1 },

	{ UBCORE_JFS_MAX_INLINE_DATA,       UBCORE_CFG_MASK,  TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, max_inline_data),     4 },

	{ UBCORE_JFS_RNR_RETRY,       UBCORE_CFG_MASK,  TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, rnr_retry),     1 },

	{ UBCORE_JFS_ERR_TIMEOUT,       UBCORE_CFG_MASK,  TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, err_timeout),     1 },

	{ UBCORE_JFS_BIND_JFC,      UBCORE_CFG_MASK, TARGET_CFG,
	  offsetof(struct ubcore_jfs_cfg, jfc), 8 },

	{ UBCORE_JFS_USER_CTX,      UBCORE_CFG_MASK, TARGET_NO_STORE, 0, 0},
	/* ---- OPT ---- */
	{ UBCORE_JFS_SQE_BASE_ADDR, UBCORE_JFS_SQE_BASE_ADDR_MASK, TARGET_OPT,
	  offsetof(struct ubcore_jfs_opt, urma_jfs_sqe_base_addr), 8 },

	{ UBCORE_JFS_ID,            UBCORE_JFS_ID_MASK,        TARGET_OPT,
	  offsetof(struct ubcore_jfs_opt, urma_jfs_id),   4 },

	{ UBCORE_JFS_DB_ADDR,       UBCORE_JFS_DB_ADDR_MASK,   TARGET_OPT,
	  offsetof(struct ubcore_jfs_opt, urma_jfs_db_addr), 8 },

	{ UBCORE_JFS_DB_STATUS,     UBCORE_JFS_DB_STATUS_MASK, TARGET_OPT,
	  offsetof(struct ubcore_jfs_opt, urma_jfs_db_status), 1 },

	{ UBCORE_JFS_PI,            UBCORE_JFS_PI_MASK,        TARGET_OPT,
	  offsetof(struct ubcore_jfs_opt, urma_jfs_pi),   2 },

	{ UBCORE_JFS_PI_TYPE,       UBCORE_JFS_PI_TYPE_MASK,   TARGET_OPT,
	  offsetof(struct ubcore_jfs_opt, urma_jfs_pi_type), 2 },

	{ UBCORE_JFS_CI,            UBCORE_JFS_CI_MASK,        TARGET_OPT,
	  offsetof(struct ubcore_jfs_opt, urma_jfs_ci),   2 },
};
const size_t g_ubcore_jfs_opt_map_count = ARRAY_SIZE(g_ubcore_jfs_opt_table);

const struct ubcore_opt_map_t g_ubcore_jetty_opt_table[] = {
	/* opt, mask, target, offset, size */
	{ UBCORE_JETTY_ID,       UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, id), 4 },
	{ UBCORE_JETTY_FLAG,     UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, flag), 4 },
	{ UBCORE_JETTY_BIND_RX_JFC, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, recv_jfc), 8 },
	{ UBCORE_JETTY_BIND_JFR, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, jfr), 8 },
	{ UBCORE_JETTY_BIND_JTG, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, jetty_grp), 8 },
	{ UBCORE_JFS_DEPTH,      UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, jfs_depth), 4 },
	{ UBCORE_JFS_TRANS_MODE, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, trans_mode), 4 },
	{ UBCORE_JFS_PRIORITY,   UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, priority), 1 },
	{ UBCORE_JFS_MAX_SGE,    UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, max_send_sge), 1 },
	{ UBCORE_JFS_MAX_RSGE,   UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, max_send_rsge), 1 },
	{ UBCORE_JFS_MAX_INLINE_DATA, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, max_inline_data), 4 },
	{ UBCORE_JFS_RNR_RETRY, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, rnr_retry), 1 },
	{ UBCORE_JFS_ERR_TIMEOUT, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, err_timeout), 1 },
	{ UBCORE_JFS_BIND_JFC, UBCORE_CFG_MASK, TARGET_CFG,
		offsetof(struct ubcore_jetty_cfg, send_jfc), 8 },
	{ UBCORE_JFS_USER_CTX, UBCORE_CFG_MASK, TARGET_NO_STORE, 0, 0},
	{ UBCORE_JFS_SQE_BASE_ADDR, UBCORE_JFS_SQE_BASE_ADDR_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfs_opt, urma_jfs_sqe_base_addr), 8 },
	{ UBCORE_JFS_DB_ADDR, UBCORE_JFS_DB_ADDR_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfs_opt, urma_jfs_db_addr), 8 },
	{ UBCORE_JFS_DB_STATUS, UBCORE_JFS_DB_STATUS_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfs_opt, urma_jfs_db_status), 1 },
	{ UBCORE_JFS_PI, UBCORE_JFS_PI_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfs_opt, urma_jfs_pi), 2 },
	{ UBCORE_JFS_PI_TYPE, UBCORE_JFS_PI_TYPE_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfs_opt, urma_jfs_pi_type), 2 },
	{ UBCORE_JFS_CI, UBCORE_JFS_CI_MASK, TARGET_OPT,
		offsetof(struct ubcore_jfs_opt, urma_jfs_ci), 2 },
};

const size_t g_ubcore_jetty_opt_map_count = ARRAY_SIZE(g_ubcore_jetty_opt_table);

static void ubcore_jfs_kref_release(struct kref *ref_cnt)
{
	struct ubcore_jfs *jfs =
		container_of(ref_cnt, struct ubcore_jfs, ref_cnt);

	complete(&jfs->comp);
}

void ubcore_put_jfs(struct ubcore_jfs *jfs)
{
	if (jfs)
		(void)kref_put(&jfs->ref_cnt, ubcore_jfs_kref_release);
}

void ubcore_jfs_get(void *obj)
{
	struct ubcore_jfs *jfs = obj;

	kref_get(&jfs->ref_cnt);
}

static void ubcore_jfr_kref_release(struct kref *ref_cnt)
{
	struct ubcore_jfr *jfr =
		container_of(ref_cnt, struct ubcore_jfr, ref_cnt);

	complete(&jfr->comp);
}

void ubcore_put_jfr(struct ubcore_jfr *jfr)
{
	if (jfr)
		(void)kref_put(&jfr->ref_cnt, ubcore_jfr_kref_release);
}

void ubcore_jfr_get(void *obj)
{
	struct ubcore_jfr *jfr = obj;

	kref_get(&jfr->ref_cnt);
}

static void ubcore_jetty_kref_release(struct kref *ref_cnt)
{
	struct ubcore_jetty *jetty =
		container_of(ref_cnt, struct ubcore_jetty, ref_cnt);

	complete(&jetty->comp);
}

void ubcore_put_jetty(struct ubcore_jetty *jetty)
{
	if (jetty)
		(void)kref_put(&jetty->ref_cnt, ubcore_jetty_kref_release);
}

void ubcore_jetty_get(void *obj)
{
	struct ubcore_jetty *jetty = obj;

	kref_get(&jetty->ref_cnt);
}

struct ubcore_jfc *ubcore_find_jfc(struct ubcore_device *dev, uint32_t jfc_id)
{
	if (!dev) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JFC], jfc_id,
					&jfc_id);
}
EXPORT_SYMBOL(ubcore_find_jfc);

struct ubcore_jfs *ubcore_find_jfs(struct ubcore_device *dev, uint32_t jfs_id)
{
	if (!dev) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JFS], jfs_id,
					&jfs_id);
}
EXPORT_SYMBOL(ubcore_find_jfs);

struct ubcore_jfr *ubcore_find_jfr(struct ubcore_device *dev, uint32_t jfr_id)
{
	if (!dev) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JFR], jfr_id,
					&jfr_id);
}
EXPORT_SYMBOL(ubcore_find_jfr);

static int check_and_fill_jfc_attr(struct ubcore_jfc_cfg *cfg,
				   struct ubcore_jfc_cfg *user)
{
	if (cfg->depth < user->depth)
		return -EINVAL;

	/* store the immutable and skip the driver updated depth */
	cfg->flag = user->flag;
	cfg->jfc_context = user->jfc_context;
	return 0;
}

int ubcore_check_opt_valid(void *opt_mask_addr, const struct ubcore_opt_map_t *table,
	size_t table_cnt, uint64_t opt, uint32_t len)
{
	size_t i;

	for (i = 0; i < table_cnt; i++) {
		if (table[i].opt == opt) {
			if (table[i].size != len) {
				ubcore_log_err("invalid opt len, opt is %llu", opt);
				return -EINVAL;
			}
			if (table[i].tgt == TARGET_OPT && opt_mask_addr != NULL) {
				uint64_t *mask_ptr = (uint64_t *)opt_mask_addr;
				*mask_ptr |= table[i].mask;
			}
			return 0;
		}
	}
	return 0;
}

int ubcore_set_options_common(const struct ubcore_opt_map_t *table,
	size_t table_cnt, uint64_t opt, void *buf, uint32_t len,
	void *cfg_base, void *opt_base)
{
	size_t i;
	void *target_base;
	void *field;

	for (i = 0; i < table_cnt; i++) {
		if (table[i].opt == opt) {
			if (table[i].tgt == TARGET_OPT)
				target_base = opt_base;
			else if (table[i].tgt == TARGET_CFG)
				target_base = cfg_base;
			else
				return 0;

			field = (char *)target_base + table[i].offset;
			memcpy(field, buf, len);
			return 0;
		}
	}
	return -EINVAL;
}

struct ubcore_jfc *ubcore_create_jfc(struct ubcore_device *dev,
				     struct ubcore_jfc_cfg *cfg,
				     ubcore_comp_callback_t jfce_handler,
				     ubcore_event_callback_t jfae_handler,
				     struct ubcore_udata *udata)
{
	struct ubcore_jfc *jfc;
	int ret;

	if (!dev || !cfg || !dev->ops ||
		!dev->ops->create_jfc || !dev->ops->destroy_jfc)
		return ERR_PTR(-EINVAL);

	jfc = dev->ops->create_jfc(dev, cfg, udata);
	if (IS_ERR_OR_NULL(jfc)) {
		ubcore_log_err("failed to create jfc, dev_name: %s.\n", dev->dev_name);
		return UBCORE_CHECK_RETURN_ERR_PTR(jfc, UBCORE_DRV_ERRNO);
	}

	if (check_and_fill_jfc_attr(&jfc->jfc_cfg, cfg) != 0) {
		(void)dev->ops->destroy_jfc(jfc);
		ubcore_log_err("jfc cfg is not qualified.\n");
		return ERR_PTR(-EINVAL);
	}
	jfc->jfce_handler = jfce_handler;
	jfc->jfae_handler = jfae_handler;
	jfc->ub_dev = dev;
	jfc->uctx = ubcore_get_uctx(udata);
	atomic_set(&jfc->use_cnt, 0);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFC], &jfc->hnode,
					 jfc->id);
	if (ret != 0) {
		(void)dev->ops->destroy_jfc(jfc);
		return ERR_PTR(ret);
	}
	jfc->jfc_opt.is_actived = true;
	ubcore_log_info("[JFC CREATE] Created JFC: id: %u, dev_name: %s.",
		jfc->id, dev->dev_name);
	return jfc;
}
EXPORT_SYMBOL(ubcore_create_jfc);

int ubcore_modify_jfc(struct ubcore_jfc *jfc, struct ubcore_jfc_attr *attr,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (!jfc || !attr || !jfc->ub_dev ||
		!jfc->ub_dev->ops || !jfc->ub_dev->ops->modify_jfc)
		return -EINVAL;

	jfc_id = jfc->id;
	dev = jfc->ub_dev;

	ret = dev->ops->modify_jfc(jfc, attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to modify jfc, jfc_id:%u, ret: %d.\n",
			       jfc_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jfc);

int ubcore_delete_jfc(struct ubcore_jfc *jfc)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (!jfc || !jfc->ub_dev || !jfc->ub_dev->ops ||
	    !jfc->ub_dev->ops->destroy_jfc)
		return -EINVAL;

	if (jfc->jfc_opt.is_actived == false) {
		ubcore_log_err("Failed to delete jfc, because status is still activated.\n");
		return -EINVAL;
	}

	if (atomic_read(&jfc->use_cnt)) {
		ubcore_log_err("The jfc is still being used, use_cnt is %d",
			       atomic_read(&jfc->use_cnt));
		return -EBUSY;
	}

	jfc_id = jfc->id;
	dev = jfc->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFC], &jfc->hnode);
	ret = dev->ops->destroy_jfc(jfc);
	if (ret != 0) {
		ubcore_log_err(
			"[DRV] failed to destroy jfc, dev_name: %s, jfc_id: %u, ret: %d\n",
			dev->dev_name, jfc_id, ret);
		return ret;
	}
	ubcore_log_info("[JFC DELETE] Deleted JFC: id: %u, dev_name: %s.",
			jfc->id, dev->dev_name);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfc);

int ubcore_delete_jfc_batch(struct ubcore_jfc **jfc_arr, int jfc_num,
			    int *bad_jfc_index)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_jfc *jfc = NULL;
	uint32_t jfc_id;
	uint32_t i;
	int ret;

	if (!jfc_arr || jfc_num <= 0 || !bad_jfc_index) {
		ubcore_log_err("Invalid parameter.");
		return -EINVAL;
	}

	for (i = 0; i < jfc_num; ++i) {
		jfc = jfc_arr[i];
		if (!jfc || !jfc->ub_dev ||
		    !jfc->ub_dev->ops ||
		    !jfc->ub_dev->ops->destroy_jfc_batch) {
			*bad_jfc_index = 0;
			ubcore_log_err("Invalid parameter, index is %d", i);
			return -EINVAL;
		}

		if (atomic_read(&jfc->use_cnt)) {
			ubcore_log_err(
				"The jfc is still being used, index is %u", i);
			ubcore_log_debug("jfc->use_cnt is %d",
					 atomic_read(&jfc->use_cnt));
			*bad_jfc_index = 0;
			return -EBUSY;
		}
	}

	for (i = 0; i < jfc_num; ++i) {
		jfc = jfc_arr[i];
		jfc_id = jfc->id;
		dev = jfc->ub_dev;
		ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFC], &jfc->hnode);
	}

	ret = dev->ops->destroy_jfc_batch(jfc_arr, jfc_num, bad_jfc_index);
	if (ret != 0) {
		ubcore_log_err(
			"driver failed to destroy jfc batch, index: %d, ret: %d.\n",
			*bad_jfc_index, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfc_batch);

int ubcore_alloc_jfc(struct ubcore_device *dev, struct ubcore_jfc_cfg *cfg,
	ubcore_comp_callback_t jfce_handler, ubcore_event_callback_t jfae_handler,
	struct ubcore_jfc **jfc, struct ubcore_udata *udata)
{
	int ret;
	int free_ret = 0;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->alloc_jfc == NULL ||
		dev->ops->free_jfc == NULL || jfc == NULL)
		return -EINVAL;

	ret = dev->ops->alloc_jfc(dev, cfg, jfc, udata);
	if (ret != 0) {
		ubcore_log_err("failed to alloc jfc, ret is %d.\n", ret);
		return ret;
	}

	if (check_and_fill_jfc_attr(&(*jfc)->jfc_cfg, cfg) != 0) {
		free_ret = dev->ops->free_jfc(*jfc, udata);
		ubcore_log_err("jfc cfg is not qualified,ret is %d.\n", free_ret);
		return -EINVAL;
	}
	(*jfc)->jfce_handler = jfce_handler;
	(*jfc)->jfae_handler = jfae_handler;
	(*jfc)->ub_dev = dev;
	(*jfc)->uctx = ubcore_get_uctx(udata);
	atomic_set(&(*jfc)->use_cnt, 0);

	(*jfc)->jfc_opt.is_actived = false;
	return ret;
}
EXPORT_SYMBOL(ubcore_alloc_jfc);


int ubcore_free_jfc(struct ubcore_jfc *jfc, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
		jfc->ub_dev->ops->free_jfc == NULL)
		return -EINVAL;

	if (jfc->jfc_opt.is_actived == true) {
		ubcore_log_err("The jfc is still activated, please deactivate first.");
		return -EINVAL;
	}

	if (atomic_read(&jfc->use_cnt)) {
		ubcore_log_err("The jfc is still being used, use_cnt is %d",
			atomic_read(&jfc->use_cnt));
		return -EBUSY;
	}

	jfc_id = jfc->id;
	dev = jfc->ub_dev;
	ret = dev->ops->free_jfc(jfc, udata);
	if (ret != 0) {
		ubcore_log_err("failed to free jfc, ret: %d, jfc_id:%u.\n",
		    ret, jfc_id);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_free_jfc);

int ubcore_set_jfc_opt(struct ubcore_jfc *jfc, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || opt == 0 || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
		jfc->ub_dev->ops->set_jfc_opt == NULL || buf == NULL)
		return -EINVAL;
	jfc_id = jfc->id;
	dev = jfc->ub_dev;
	ret = ubcore_check_opt_valid(&jfc->jfc_opt.jfc_opt_mask.value, g_ubcore_jfc_opt_table,
		g_ubcore_jfc_opt_map_count, opt, len);
	if (ret != 0) {
		ubcore_log_err("invalid opt.\n");
		return ret;
	}
	ret = dev->ops->set_jfc_opt(jfc, opt, buf, len, udata); /*no need copy_from_user */
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to set_jfc_opt, jfc_id:%u, ret %d.\n",
			jfc_id, ret);
		return ret;
	}

	ret = ubcore_set_options_common(g_ubcore_jfc_opt_table,
		g_ubcore_jfc_opt_map_count, opt, buf, len,
		&jfc->jfc_cfg, &jfc->jfc_opt);
	if (ret != 0)
		ubcore_log_err("failed to set opt, jfc_id:%u, ret is %d.\n", jfc_id, ret);
	return ret;
}
EXPORT_SYMBOL(ubcore_set_jfc_opt);

int ubcore_get_jfc_opt(struct ubcore_jfc *jfc, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || opt == 0 || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
		jfc->ub_dev->ops->get_jfc_opt == NULL || buf == NULL)
		return -EINVAL;

	ret = ubcore_check_opt_valid(&jfc->jfc_opt.jfc_opt_mask.value, g_ubcore_jfc_opt_table,
		g_ubcore_jfc_opt_map_count, opt, len);
	if (ret != 0) {
		ubcore_log_err("invalid opt.\n");
		return ret;
	}

	jfc_id = jfc->id;
	dev = jfc->ub_dev;
	ret = dev->ops->get_jfc_opt(jfc, opt, buf, len, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_jfc_opt, jfc_id:%u, ret: %d.\n",
			jfc_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_jfc_opt);


int ubcore_active_jfc(struct ubcore_jfc *jfc, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
		jfc->ub_dev->ops->active_jfc == NULL)
		return -EINVAL;

	if (jfc->jfc_opt.is_actived) {
		ubcore_log_err("jfc has activated.\n");
		return -EINVAL;
	}

	jfc_id = jfc->id;
	dev = jfc->ub_dev;

	ret = dev->ops->active_jfc(jfc, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to active jfc, jfc_id:%u, ret: %d.\n",
			jfc_id, ret);
		return ret;
	}
	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFC], &jfc->hnode, jfc->id);
	if (ret != 0) {
		(void)dev->ops->deactive_jfc(jfc, udata);
		ubcore_log_err("Failed to add jfc to hash_table, ret is %d.\n", ret);
		return ret;
	}
	jfc->jfc_opt.is_actived = true;
	return ret;
}
EXPORT_SYMBOL(ubcore_active_jfc);

int ubcore_deactive_jfc(struct ubcore_jfc *jfc, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	uint32_t jfc_id;
	int ret;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
		jfc->ub_dev->ops->deactive_jfc == NULL)
		return -EINVAL;

	if (!jfc->jfc_opt.is_actived) {
		ubcore_log_err("jfc has deactived.\n");
		return -EINVAL;
	}

	jfc_id = jfc->id;
	dev = jfc->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFC], &jfc->hnode);
	ret = dev->ops->deactive_jfc(jfc, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to deactivate jfc, jfc_id:%u, ret: %d.\n",
			jfc_id, ret);
		return ret;
	}
	jfc->jfc_opt.is_actived = false;
	return ret;
}
EXPORT_SYMBOL(ubcore_deactive_jfc);

static int check_jfs_cfg(struct ubcore_device *dev, struct ubcore_jfs_cfg *cfg)
{
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err("Invalid parameter, trans_mode: %d.\n",
			       (int)cfg->trans_mode);
		return -EINVAL;
	}

	if (cfg->depth == 0 || cfg->depth > dev->attr.dev_cap.max_jfs_depth) {
		ubcore_log_err("Invalid parameter, depth:%u, max_depth:%u.\n",
			       cfg->depth, dev->attr.dev_cap.max_jfs_depth);
		return -EINVAL;
	}
	if (cfg->max_inline_data != 0 &&
	    cfg->max_inline_data > dev->attr.dev_cap.max_jfs_inline_size) {
		ubcore_log_err(
			"Invalid parameter, inline_data:%u, max_inline_len:%u.\n",
			cfg->max_inline_data,
			dev->attr.dev_cap.max_jfs_inline_size);
		return -EINVAL;
	}
	if (cfg->max_sge > dev->attr.dev_cap.max_jfs_sge) {
		ubcore_log_err("Invalid parameter, sge:%u, max_sge:%u.\n",
			       cfg->max_sge, dev->attr.dev_cap.max_jfs_sge);
		return -EINVAL;
	}
	if (cfg->max_rsge > dev->attr.dev_cap.max_jfs_rsge) {
		ubcore_log_err("Invalid parameter, rsge:%u, max_rsge:%u.\n",
			       cfg->max_rsge, dev->attr.dev_cap.max_jfs_rsge);
		return -EINVAL;
	}
	return 0;
}

static int check_and_fill_jfs_attr(struct ubcore_jfs_cfg *cfg,
				   struct ubcore_jfs_cfg *user)
{
	if (cfg->depth < user->depth || cfg->max_sge < user->max_sge ||
	    cfg->max_rsge < user->max_rsge ||
	    cfg->max_inline_data < user->max_inline_data)
		return -EINVAL;

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

struct ubcore_jfs *ubcore_create_jfs(struct ubcore_device *dev,
				     struct ubcore_jfs_cfg *cfg,
				     ubcore_event_callback_t jfae_handler,
				     struct ubcore_udata *udata)
{
	struct ubcore_jfs *jfs;
	int ret;

	if (!dev || !dev->ops || !dev->ops->create_jfs ||
	    !dev->ops->destroy_jfs || !cfg || !cfg->jfc ||
	    !ubcore_eid_valid(dev, cfg->eid_index, udata))
		return ERR_PTR(-EINVAL);

	if (((uint16_t)cfg->trans_mode & dev->attr.dev_cap.trans_mode) == 0)
		return ERR_PTR(-EINVAL);

	if (check_jfs_cfg(dev, cfg) != 0)
		return ERR_PTR(-EINVAL);

	jfs = dev->ops->create_jfs(dev, cfg, udata);
	if (IS_ERR_OR_NULL(jfs)) {
		ubcore_log_err("[Drv]failed to create jfs, device: %s.\n", dev->dev_name);
		return UBCORE_CHECK_RETURN_ERR_PTR(jfs, UBCORE_DRV_ERRNO);
	}

	/* Prevent ubcore private data from being modified */
	if (check_and_fill_jfs_attr(&jfs->jfs_cfg, cfg) != 0) {
		(void)dev->ops->destroy_jfs(jfs);
		ubcore_log_err("jfs cfg is not qualified.\n");
		return ERR_PTR(-EINVAL);
	}
	jfs->ub_dev = dev;
	jfs->uctx = ubcore_get_uctx(udata);
	jfs->jfae_handler = jfae_handler;
	jfs->jfs_id.eid = dev->eid_table.eid_entries[cfg->eid_index].eid;
	atomic_set(&jfs->use_cnt, 0);
	kref_init(&jfs->ref_cnt);
	init_completion(&jfs->comp);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFS], &jfs->hnode,
					 jfs->jfs_id.id);
	if (ret != 0) {
		ubcore_destroy_tptable(&jfs->tptable);
		(void)dev->ops->destroy_jfs(jfs);
		return ERR_PTR(ret);
	}
	ubcore_log_info("[JFS CREATE] Created JFS: id: %u, dev_name: %s, eid_idx: %u.\n",
		jfs->jfs_id.id, dev->dev_name, jfs->jfs_cfg.eid_index);
	jfs->jfs_opt.is_actived = true;
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

	if (!jfs || !attr || !jfs->ub_dev ||
		!jfs->ub_dev->ops || !jfs->ub_dev->ops->modify_jfs)
		return -EINVAL;

	jfs_id = jfs->jfs_id.id;
	dev = jfs->ub_dev;
	ret = dev->ops->modify_jfs(jfs, attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to modify jfs, jfs_id:%u, ret: %d.\n",
				   jfs_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jfs);

int ubcore_query_jfs(struct ubcore_jfs *jfs, struct ubcore_jfs_cfg *cfg,
		     struct ubcore_jfs_attr *attr)
{
	struct ubcore_device *dev;
	uint32_t jfs_id;
	int ret;

	if (!jfs || !cfg || !attr || !jfs->ub_dev ||
		!jfs->ub_dev->ops || !jfs->ub_dev->ops->query_jfs)
		return -EINVAL;

	jfs_id = jfs->jfs_id.id;
	dev = jfs->ub_dev;
	ret = dev->ops->query_jfs(jfs, cfg, attr);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to query jfs, jfs_id:%u, ret: %d.\n",
				   jfs_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_query_jfs);

int ubcore_delete_jfs(struct ubcore_jfs *jfs)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *jfc;
	uint32_t jfs_id;
	int ret;

	if (!jfs || !jfs->ub_dev || !jfs->ub_dev->ops ||
	    !jfs->ub_dev->ops->destroy_jfs)
		return -EINVAL;

	if (jfs->jfs_opt.is_actived == false) {
		ubcore_log_err("Failed to delete jfs, because status is still activated");
		return -EINVAL;
	}

	jfc = jfs->jfs_cfg.jfc;
	jfs_id = jfs->jfs_id.id;
	dev = jfs->ub_dev;

	(void)ubcore_hash_table_check_remove(&dev->ht[UBCORE_HT_JFS],
					     &jfs->hnode);
	ubcore_destroy_tptable(&jfs->tptable);

	ubcore_put_jfs(jfs);
	wait_for_completion(&jfs->comp);

	ret = dev->ops->destroy_jfs(jfs);
	if (ret != 0) {
		ubcore_log_err("[DRV] Failed to destroy jfs, dev_name: %s, eid_idx: %u, jfs_id: %u.\n",
			dev->dev_name, jfs->jfs_cfg.eid_index, jfs_id);
		kref_init(&jfs->ref_cnt);
		return ret;
	}
	ubcore_log_info("[JFS DELETE] Delete jfs: dev_name: %s, eid_idx: %u, jfs_id: %u.\n",
		dev->dev_name, jfs->jfs_cfg.eid_index, jfs_id);
	atomic_dec(&jfc->use_cnt);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfs);

int ubcore_delete_jfs_batch(struct ubcore_jfs **jfs_arr, int jfs_num,
			    int *bad_jfs_index)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_jfc **jfc = NULL;
	struct ubcore_jfs *jfs = NULL;
	int bad_index = 0;
	uint32_t jfs_id;
	uint32_t i;
	int ret;

	if (!jfs_arr || jfs_num <= 0 || !bad_jfs_index) {
		ubcore_log_err("Invalid parameter.");
		return -EINVAL;
	}

	for (i = 0; i < jfs_num; ++i) {
		jfs = jfs_arr[i];
		if (!jfs || !jfs->ub_dev ||
			!jfs->ub_dev->ops ||
			!jfs->ub_dev->ops->destroy_jfs_batch) {
			*bad_jfs_index = 0;
			ubcore_log_err("Invalid parameter, index is %d", i);
			return -EINVAL;
		}
	}

	jfc = kcalloc(jfs_num, sizeof(struct ubcore_jfc *), GFP_KERNEL);
	if (!jfc) {
		*bad_jfs_index = 0;
		return -ENOMEM;
	}

	for (i = 0; i < jfs_num; ++i) {
		jfs = jfs_arr[i];
		jfc[i] = jfs->jfs_cfg.jfc;
		jfs_id = jfs->jfs_id.id;
		dev = jfs->ub_dev;
		(void)ubcore_hash_table_check_remove(&dev->ht[UBCORE_HT_JFS],
						     &jfs->hnode);
		ubcore_destroy_tptable(&jfs->tptable);

		ubcore_put_jfs(jfs);
		wait_for_completion(&jfs->comp);
	}

	ret = dev->ops->destroy_jfs_batch(jfs_arr, jfs_num, bad_jfs_index);
	bad_index = jfs_num;
	if (ret != 0) {
		ubcore_log_err(
			"driver failed to destroy jfs batch, index: %d.\n",
			*bad_jfs_index);
		if (ret == -EINVAL)
			bad_index = 0;
		else
			bad_index = *bad_jfs_index;
		if (bad_index >= jfs_num) {
			ubcore_log_err(
				"driver return bad_jfs_index %d out of range, jfs_num is %d.\n",
				*bad_jfs_index, jfs_num);
			*bad_jfs_index = 0;
			bad_index = jfs_num;
			ret = -EFAULT;
		}
		for (i = bad_index; i < jfs_num; ++i)
			kref_init(&jfs_arr[i]->ref_cnt);
	}

	for (i = 0; i < bad_index; ++i) {
		atomic_dec(&jfc[i]->use_cnt);
		ubcore_log_info("jfc->use_cnt is: %d.\n",
				atomic_read(&jfc[i]->use_cnt));
	}

	kfree(jfc);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfs_batch);

int ubcore_flush_jfs(struct ubcore_jfs *jfs, int cr_cnt, struct ubcore_cr *cr)
{
	struct ubcore_ops *dev_ops;

	if (!jfs || !jfs->ub_dev || !jfs->ub_dev->ops ||
	    !jfs->ub_dev->ops->flush_jfs || !cr) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jfs->ub_dev->ops;
	return dev_ops->flush_jfs(jfs, cr_cnt, cr);
}
EXPORT_SYMBOL(ubcore_flush_jfs);

static int check_and_fill_jfr_attr(struct ubcore_jfr_cfg *cfg,
				   struct ubcore_jfr_cfg *user)
{
	if (cfg->depth < user->depth || cfg->max_sge < user->max_sge)
		return -EINVAL;

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

int ubcore_alloc_jfs(struct ubcore_device *dev, struct ubcore_jfs_cfg *cfg,
	ubcore_event_callback_t jfae_handler, struct ubcore_jfs **jfs, struct ubcore_udata *udata)
{
	int ret;
	int free_ret = 0;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->alloc_jfs == NULL ||
		dev->ops->free_jfs == NULL || jfs == NULL || cfg->jfc == NULL ||
		!ubcore_eid_valid(dev, cfg->eid_index, udata))
		return -EINVAL;

	ret = dev->ops->alloc_jfs(dev, cfg, jfs, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]failed to alloc jfs, ret is %d.\n", ret);
		return ret;
	}

	if (check_and_fill_jfs_attr(&(*jfs)->jfs_cfg, cfg) != 0) {
		free_ret = dev->ops->free_jfs(*jfs, udata);
		ubcore_log_err("jfs cfg is not qualified, ret is %d.\n", free_ret);
		return -EINVAL;
	}
	(*jfs)->ub_dev = dev;
	(*jfs)->uctx = ubcore_get_uctx(udata);
	(*jfs)->jfae_handler = jfae_handler;
	(*jfs)->jfs_id.eid = dev->eid_table.eid_entries[cfg->eid_index].eid;

	atomic_set(&(*jfs)->use_cnt, 0);
	kref_init(&(*jfs)->ref_cnt);
	init_completion(&(*jfs)->comp);

	(*jfs)->jfs_opt.is_actived = false;
	atomic_inc(&cfg->jfc->use_cnt);
	return ret;
}
EXPORT_SYMBOL(ubcore_alloc_jfs);

int ubcore_free_jfs(struct ubcore_jfs *jfs, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *jfc;
	uint32_t jfs_id;
	int ret;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->free_jfs == NULL)
		return -EINVAL;

	if (jfs->jfs_opt.is_actived == true) {
		ubcore_log_err("The jfs is still activated , please deactivate first.");
		return -EINVAL;
	}
	if (atomic_read(&jfs->use_cnt)) {
		ubcore_log_err("The jfs is still being used, use_cnt is %d",
			atomic_read(&jfs->use_cnt));
		return -EBUSY;
	}

	dev = jfs->ub_dev;
	jfs_id = jfs->jfs_opt.urma_jfs_id;
	jfc = jfs->jfs_cfg.jfc;
	ret = dev->ops->free_jfs(jfs, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to free jfs, ret: %d, jfs_id: %u.\n",
			ret, jfs_id);
		return ret;
	}

	atomic_dec(&jfc->use_cnt);
	return ret;
}
EXPORT_SYMBOL(ubcore_free_jfs);

int ubcore_set_jfs_opt(struct ubcore_jfs *jfs, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *old_jfc;
	struct ubcore_jfc *new_jfc;
	int ret;

	if (jfs == NULL || opt == 0 || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->set_jfs_opt == NULL || buf == NULL)
		return -EINVAL;

	ret = ubcore_check_opt_valid(&jfs->jfs_opt.jfs_opt_mask.value, g_ubcore_jfs_opt_table,
		g_ubcore_jfs_opt_map_count, opt, len);
	if (ret != 0) {
		ubcore_log_err("invalid opt.\n");
		return ret;
	}

	dev = jfs->ub_dev;
	ret = dev->ops->set_jfs_opt(jfs, opt, buf, len, udata); /* need copy_from_user */
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to set_jfs_opt, jfs_id:%u, ret %d.\n",
			jfs->jfs_opt.urma_jfs_id, ret);
		return ret;
	}
	if (opt == UBCORE_JFS_BIND_JFC) {
		old_jfc = jfs->jfs_cfg.jfc;
		if (old_jfc)
			atomic_dec(&old_jfc->use_cnt);
	}

	ret = ubcore_set_options_common(g_ubcore_jfs_opt_table, g_ubcore_jfs_opt_map_count,
		opt, buf, len, &jfs->jfs_cfg, &jfs->jfs_opt);
	if (ret != 0) {
		if (opt == UBCORE_JFS_BIND_JFC && old_jfc)
			atomic_inc(&old_jfc->use_cnt);

		ubcore_log_err("failed to set opt of ubcore_jfs, jfs_id:%u, ret is %d.\n",
			jfs->jfs_opt.urma_jfs_id, ret);
		return ret;
	}

	if (opt == UBCORE_JFS_BIND_JFC) {
		new_jfc = jfs->jfs_cfg.jfc;
		if (new_jfc)
			atomic_inc(&new_jfc->use_cnt);
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_set_jfs_opt);

int ubcore_get_jfs_opt(struct ubcore_jfs *jfs, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	if (jfs == NULL || opt == 0 || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->get_jfs_opt == NULL || buf == NULL)
		return -EINVAL;

	dev = jfs->ub_dev;
	ret = dev->ops->get_jfs_opt(jfs, opt, buf, len, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_jfs_opt, jfs_id:%u, ret: %d.\n",
			jfs->jfs_opt.urma_jfs_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_jfs_opt);

int ubcore_active_jfs(struct ubcore_jfs *jfs, struct ubcore_udata *udata)
{
	struct ubcore_device *dev = jfs->ub_dev;
	int ret;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->active_jfs == NULL || jfs->jfs_cfg.jfc == NULL)
		return -EINVAL;

	if (((uint16_t)jfs->jfs_cfg.trans_mode & dev->attr.dev_cap.trans_mode) == 0) {
		ubcore_log_err("jfs cfg is not supported.\n");
		return -EINVAL;
	}

	if (check_jfs_cfg(dev, &jfs->jfs_cfg) != 0)
		return -EINVAL;

	if (jfs->jfs_opt.is_actived) {
		ubcore_log_err("jfs has activated.\n");
		return -EINVAL;
	}

	if (jfs->jfs_cfg.jfc->jfc_opt.is_actived == false) {
		ubcore_log_err("jfc in jfs has not activated.\n");
		return -EINVAL;
	}

	ret = dev->ops->active_jfs(jfs, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to active jfs, ret: %d, jfs_id: %u.\n",
			ret, jfs->jfs_opt.urma_jfs_id);
		return ret;
	}
	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFS], &jfs->hnode, jfs->jfs_id.id);
	if (ret != 0) {
		(void)dev->ops->deactive_jfs(jfs, udata);
		ubcore_log_err("Failed to add jfs, ret: %d.\n", ret);
		return ret;
	}
	jfs->jfs_opt.is_actived = true;

	return ret;
}
EXPORT_SYMBOL(ubcore_active_jfs);

int ubcore_deactive_jfs(struct ubcore_jfs *jfs, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
		jfs->ub_dev->ops->deactive_jfs == NULL)
		return -EINVAL;

	if (!jfs->jfs_opt.is_actived) {
		ubcore_log_err("jfs has deactived.\n");
		return -EINVAL;
	}

	dev = jfs->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFS], &jfs->hnode);
	ret = dev->ops->deactive_jfs(jfs, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to deactivate jfs, jfs_id:%u, ret: %d.\n",
			jfs->jfs_opt.urma_jfs_id, ret);
		return ret;
	}
	jfs->jfs_opt.is_actived = false;
	return ret;
}
EXPORT_SYMBOL(ubcore_deactive_jfs);

static int ubcore_check_jfr_cfg(struct ubcore_jfr_cfg *cfg)
{
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err("Invalid parameter, trans_mode: %d.\n",
				   (int)cfg->trans_mode);
		return -EINVAL;
	}

	return 0;
}

struct ubcore_jfr *ubcore_create_jfr(struct ubcore_device *dev,
					 struct ubcore_jfr_cfg *cfg,
					 ubcore_event_callback_t jfae_handler,
					 struct ubcore_udata *udata)
{
	struct ubcore_jfr *jfr;
	int ret;

	if (!dev || !dev->ops || !dev->ops->create_jfr ||
	    !dev->ops->destroy_jfr || !cfg || !cfg->jfc ||
	    !ubcore_eid_valid(dev, cfg->eid_index, udata))
		return ERR_PTR(-EINVAL);

	if (ubcore_check_jfr_cfg(cfg) != 0)
		return ERR_PTR(-EINVAL);

	jfr = dev->ops->create_jfr(dev, cfg, udata);
	if (IS_ERR_OR_NULL(jfr)) {
		ubcore_log_err("[DRV]failed to create jfr,device: %s.\n", dev->dev_name);
		return UBCORE_CHECK_RETURN_ERR_PTR(jfr, UBCORE_DRV_ERRNO);
	}

	if (check_and_fill_jfr_attr(&jfr->jfr_cfg, cfg) != 0) {
		ubcore_log_err("jfr cfg is not qualified.\n");
		(void)dev->ops->destroy_jfr(jfr);
		return ERR_PTR(-EINVAL);
	}
	jfr->ub_dev = dev;
	jfr->uctx = ubcore_get_uctx(udata);
	jfr->jfae_handler = jfae_handler;
	jfr->jfr_id.eid = dev->eid_table.eid_entries[cfg->eid_index].eid;
	atomic_set(&jfr->use_cnt, 0);
	kref_init(&jfr->ref_cnt);
	init_completion(&jfr->comp);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFR], &jfr->hnode,
					 jfr->jfr_id.id);
	if (ret != 0) {
		ubcore_destroy_tptable(&jfr->tptable);
		(void)dev->ops->destroy_jfr(jfr);
		return ERR_PTR(ret);
	}
	ubcore_log_info("[JFR CREATE] Created JFR: id: %u,device: %s,eid_idx: %u.\n",
		jfr->jfr_id.id, dev->dev_name, jfr->jfr_cfg.eid_index);
	jfr->jfr_opt.is_actived = true;
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

	if (!jfr || !attr || !jfr->ub_dev ||
		!jfr->ub_dev->ops || !jfr->ub_dev->ops->modify_jfr)
		return -EINVAL;

	jfr_id = jfr->jfr_id.id;
	dev = jfr->ub_dev;
	ret = dev->ops->modify_jfr(jfr, attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to modify jfr, jfr_id:%u.\n",
				   jfr_id);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jfr);

int ubcore_query_jfr(struct ubcore_jfr *jfr, struct ubcore_jfr_cfg *cfg,
			 struct ubcore_jfr_attr *attr)
{
	struct ubcore_device *dev;
	uint32_t jfr_id;
	int ret;

	if (!jfr || !cfg || !attr || !jfr->ub_dev ||
	    !jfr->ub_dev->ops || !jfr->ub_dev->ops->query_jfr)
		return -EINVAL;

	jfr_id = jfr->jfr_id.id;
	dev = jfr->ub_dev;
	ret = dev->ops->query_jfr(jfr, cfg, attr);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to query jfr, jfr_id: %u, ret: %d.\n",
			       jfr_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_query_jfr);

int ubcore_delete_jfr(struct ubcore_jfr *jfr)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *jfc;
	uint32_t jfr_id;
	int ret;

	if (!jfr || !jfr->ub_dev || !jfr->ub_dev->ops ||
		!jfr->ub_dev->ops->destroy_jfr)
		return -EINVAL;

	if (jfr->jfr_opt.is_actived == false) {
		ubcore_log_err("Failed to delete jfr, because status is still activated");
		return -EINVAL;
	}

	if (atomic_read(&jfr->use_cnt)) {
		ubcore_log_err("The jfr is still being used");
		return -EBUSY;
	}

	jfc = jfr->jfr_cfg.jfc;
	jfr_id = jfr->jfr_id.id;
	dev = jfr->ub_dev;

	(void)ubcore_hash_table_check_remove(&dev->ht[UBCORE_HT_JFR],
					     &jfr->hnode);
	ubcore_destroy_tptable(&jfr->tptable);

	ubcore_put_jfr(jfr);
	wait_for_completion(&jfr->comp);

	ret = dev->ops->destroy_jfr(jfr);
	if (ret != 0) {
		ubcore_log_err(
			"[DRV] failed to destroy jfr, dev_name: %s, eid_idx: %u, jfr_id: %u, ret:%u\n",
			dev->dev_name, jfr->jfr_cfg.eid_index, jfr_id, ret);
		kref_init(&jfr->ref_cnt);
		return ret;
	}

	atomic_dec(&jfc->use_cnt);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfr);

int ubcore_delete_jfr_batch(struct ubcore_jfr **jfr_arr, int jfr_num,
			    int *bad_jfr_index)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_jfc **jfc = NULL;
	struct ubcore_jfr *jfr = NULL;
	int bad_index = 0;
	uint32_t jfr_id;
	uint32_t i;
	int ret;

	if (!jfr_arr || jfr_num <= 0 || !bad_jfr_index) {
		ubcore_log_err("Invalid parameter.");
		return -EINVAL;
	}

	jfc = kcalloc(jfr_num, sizeof(struct ubcore_jfc *), GFP_KERNEL);
	if (!jfc) {
		*bad_jfr_index = 0;
		return -ENOMEM;
	}

	for (i = 0; i < jfr_num; ++i) {
		jfr = jfr_arr[i];
		jfc[i] = jfr->jfr_cfg.jfc;
		if (!jfr || !jfr->ub_dev ||
			!jfr->ub_dev->ops ||
			!jfr->ub_dev->ops->destroy_jfr_batch) {
			*bad_jfr_index = 0;
			ubcore_log_err("Invalid parameter, index is %d", i);
			return -EINVAL;
		}

		if (atomic_read(&jfr->use_cnt)) {
			ubcore_log_err(
				"The jfr is still being used, index is %u", i);
			ubcore_log_debug("jfr->use_cnt is %d",
					 atomic_read(&jfr->use_cnt));
			*bad_jfr_index = 0;
			return -EBUSY;
		}
	}

	for (i = 0; i < jfr_num; ++i) {
		jfr = jfr_arr[i];
		jfr_id = jfr->jfr_id.id;
		dev = jfr->ub_dev;
		(void)ubcore_hash_table_check_remove(&dev->ht[UBCORE_HT_JFR],
						     &jfr->hnode);
		ubcore_destroy_tptable(&jfr->tptable);

		ubcore_put_jfr(jfr);
		wait_for_completion(&jfr->comp);
	}

	ret = dev->ops->destroy_jfr_batch(jfr_arr, jfr_num, bad_jfr_index);
	bad_index = jfr_num;
	if (ret != 0) {
		ubcore_log_err(
			"driver failed to destroy jfr batch, index: %d.\n",
			*bad_jfr_index);
		if (ret == -EINVAL)
			bad_index = 0;
		else
			bad_index = *bad_jfr_index;
		if (bad_index >= jfr_num) {
			ubcore_log_err(
				"driver return bad_jfr_index %d out of range, jfr_num is %d.\n",
				*bad_jfr_index, jfr_num);
			*bad_jfr_index = 0;
			bad_index = jfr_num;
			ret = -EFAULT;
		}
		for (i = bad_index; i < jfr_num; ++i)
			kref_init(&jfr_arr[i]->ref_cnt);
	}

	for (i = 0; i < bad_index; ++i) {
		atomic_dec(&jfc[i]->use_cnt);
		ubcore_log_info("jfc->use_cnt is: %d.\n",
				atomic_read(&jfc[i]->use_cnt));
	}

	kfree(jfc);
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jfr_batch);

struct ubcore_tjetty *ubcore_import_jfr(struct ubcore_device *dev,
					struct ubcore_tjetty_cfg *cfg,
					struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_vtpn *vtpn = NULL;
	struct ubcore_tjetty *tjfr;

	if (!ubcore_have_ops(dev) || !dev->ops->unimport_jfr ||
	    !cfg || dev->attr.dev_cap.max_eid_cnt <= cfg->eid_index)
		return ERR_PTR(-EINVAL);

	if (ubcore_check_ctrlplane_compat(dev->ops->import_jfr))
		return ubcore_import_jfr_compat(dev, cfg, udata);

	if (ubcore_is_bonding_dev(dev)) {
		if (ubcore_connect_exchange_udata_when_import_jetty(
			    cfg, udata, true, dev) != 0) {
			return ERR_PTR(-ENOEXEC);
		}
	}

	tjfr = dev->ops->import_jfr(dev, cfg, udata);
	if (IS_ERR_OR_NULL(tjfr)) {
		ubcore_log_err("Failed to import jfr, dev_name is %s,jfr_id:%u.\n",
			dev->dev_name, cfg->id.id);
		return UBCORE_CHECK_RETURN_ERR_PTR(tjfr, UBCORE_DRV_ERRNO);
	}
	tjfr->cfg = *cfg;
	tjfr->ub_dev = dev;
	tjfr->uctx = ubcore_get_uctx(udata);
	atomic_set(&tjfr->use_cnt, 0);
	mutex_init(&tjfr->lock);

	/* create rm tp if the remote eid is not connected */
	if (!ubcore_is_bonding_dev(dev) &&
	    dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (cfg->trans_mode == UBCORE_TP_RM ||
	     cfg->trans_mode == UBCORE_TP_UM)) {
		ubcore_set_vtp_param(dev, NULL, cfg, &vtp_param);
		mutex_lock(&tjfr->lock);
		vtpn = ubcore_connect_vtp(dev, &vtp_param);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjfr->lock);
			mutex_destroy(&tjfr->lock);
			(void)dev->ops->unimport_jfr(tjfr);
			ubcore_log_err("Failed to setup tp connection.\n");
			if (!vtpn)
				return ERR_PTR(-ECONNREFUSED);
			return (void *)vtpn;
		}
		tjfr->vtpn = vtpn;
		mutex_unlock(&tjfr->lock);
	} else {
		tjfr->vtpn = NULL;
	}
	tjfr->tp = NULL;
	ubcore_log_info("[JFR IMPORT] Import TJFR: id: %u,device: %s,eid_idx: %u.\n",
		cfg->id.id, dev->dev_name, tjfr->cfg.eid_index);
	return tjfr;
}
EXPORT_SYMBOL(ubcore_import_jfr);

struct ubcore_tjetty *
ubcore_import_jfr_ex(struct ubcore_device *dev, struct ubcore_tjetty_cfg *cfg,
		     struct ubcore_active_tp_cfg *active_tp_cfg,
		     struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_vtpn *vtpn = NULL;
	struct ubcore_tjetty *tjfr;

	if (!dev || !dev->ops ||
	    !dev->ops->import_jfr_ex || !dev->ops->unimport_jfr ||
	    !cfg || !active_tp_cfg ||
	    dev->attr.dev_cap.max_eid_cnt <= cfg->eid_index)
		return ERR_PTR(-EINVAL);

	tjfr = dev->ops->import_jfr_ex(dev, cfg, active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(tjfr)) {
		ubcore_log_err("[DRV] failed to import jfr ex, dev_name: %s, jfr_id:%u.\n",
			dev->dev_name, cfg->id.id);
		return UBCORE_CHECK_RETURN_ERR_PTR(tjfr, UBCORE_DRV_ERRNO);
	}
	tjfr->cfg = *cfg;
	tjfr->ub_dev = dev;
	tjfr->uctx = ubcore_get_uctx(udata);
	atomic_set(&tjfr->use_cnt, 0);
	mutex_init(&tjfr->lock);

	/* create rm tp if the remote eid is not connected */
	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (cfg->trans_mode == UBCORE_TP_RM ||
	     cfg->trans_mode == UBCORE_TP_UM)) {
		ubcore_set_vtp_param(dev, NULL, cfg, &vtp_param);
		mutex_lock(&tjfr->lock);
		vtpn = ubcore_connect_vtp_ctrlplane(dev, &vtp_param,
							active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjfr->lock);
			mutex_destroy(&tjfr->lock);
			(void)dev->ops->unimport_jfr(tjfr);
			ubcore_log_err("Failed to setup tp connection.\n");
			if (!vtpn)
				return ERR_PTR(-ECONNREFUSED);
			return (void *)vtpn;
		}
		tjfr->vtpn = vtpn;
		mutex_unlock(&tjfr->lock);
	} else {
		tjfr->vtpn = NULL;
	}
	tjfr->tp = NULL;
	ubcore_log_info("[JFR IMPORT EX] Import TJFR EX: id: %u,device: %s,eid_idx: %u.\n",
		cfg->id.id, dev->dev_name, tjfr->cfg.eid_index);
	return tjfr;
}
EXPORT_SYMBOL(ubcore_import_jfr_ex);

int ubcore_unimport_jfr(struct ubcore_tjetty *tjfr)
{
	uint32_t tjfr_id = tjfr->cfg.id.id;
	struct ubcore_device *dev;
	int ret;

	if (!tjfr || !tjfr->ub_dev || !tjfr->ub_dev->ops ||
	    !tjfr->ub_dev->ops->unimport_jfr ||
	    !ubcore_have_ops(tjfr->ub_dev))
		return -EINVAL;

	dev = tjfr->ub_dev;
	if (!ubcore_is_bonding_dev(dev) &&
	    dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (tjfr->cfg.trans_mode == UBCORE_TP_RM ||
	     tjfr->cfg.trans_mode == UBCORE_TP_UM) &&
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
	ret = dev->ops->unimport_jfr(tjfr);
	if (ret != 0) {
		ubcore_log_err("[DRV] Failed to unimport jfr, dev_name: %s, eid_idx: %u, tjfr_id: %u.\n",
			dev->dev_name, tjfr->cfg.eid_index, tjfr_id);
		return ret;
	}
	ubcore_log_info("[JFR UNIMPORT] Unimport TJFR EX: id: %u, dev_name: %s, eid_idx: %u.\n",
		tjfr_id, dev->dev_name, tjfr->cfg.eid_index);
	return ret;
}
EXPORT_SYMBOL(ubcore_unimport_jfr);

static int check_and_fill_jetty_attr(struct ubcore_jetty_cfg *cfg,
				     struct ubcore_jetty_cfg *user)
{
	if (cfg->jfs_depth < user->jfs_depth ||
	    cfg->max_send_sge < user->max_send_sge ||
	    cfg->max_send_rsge < user->max_send_rsge ||
	    cfg->max_inline_data < user->max_inline_data) {
		ubcore_log_err("send attributes are not qualified.\n");
		return -EINVAL;
	}
	if (cfg->jfr_depth < user->jfr_depth ||
	    cfg->max_recv_sge < user->max_recv_sge) {
		ubcore_log_err("recv attributes are not qualified.\n");
		return -EINVAL;
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

static int check_jetty_cfg(struct ubcore_device *dev,
			   struct ubcore_jetty_cfg *cfg)
{
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err("Invalid parameter, trans_mode: %d.\n",
			       (int)cfg->trans_mode);
		return -EINVAL;
	}

	if (!cfg->send_jfc || !cfg->recv_jfc) {
		ubcore_log_err("jfc is null.\n");
		return -EINVAL;
	}

	if (cfg->flag.bs.share_jfr == 0 &&
	    dev->transport_type == UBCORE_TRANSPORT_UB) {
		ubcore_log_err("UB dev should use share jfr");
		return -EINVAL;
	}
	if (cfg->flag.bs.share_jfr != 0 &&
	    (cfg->jfr == NULL ||
	     cfg->jfr->jfr_cfg.trans_mode != cfg->trans_mode ||
	     cfg->jfr->jfr_cfg.flag.bs.order_type != cfg->flag.bs.order_type)) {
		ubcore_log_err(
			"jfr is null or trans_mode invalid with shared jfr flag.\n");
		return -EINVAL;
	}
	return 0;
}

int ubcore_alloc_jfr(struct ubcore_device *dev, struct ubcore_jfr_cfg *cfg,
	ubcore_event_callback_t jfae_handler, struct ubcore_jfr **jfr, struct ubcore_udata *udata)
{
	int ret;
	int free_ret = 0;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->alloc_jfr == NULL ||
		dev->ops->free_jfr == NULL || jfr == NULL || cfg->jfc == NULL ||
		!ubcore_eid_valid(dev, cfg->eid_index, udata))
		return -EINVAL;

	ret = dev->ops->alloc_jfr(dev, cfg, jfr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to alloc jfr, ret is %d.\n", ret);
		return ret;
	}

	if (check_and_fill_jfr_attr(&(*jfr)->jfr_cfg, cfg) != 0) {
		free_ret = dev->ops->free_jfr(*jfr, udata);
		ubcore_log_err("jfr cfg is not qualified,ret is %d.\n", free_ret);
		return -EINVAL;
	}
	(*jfr)->ub_dev = dev;
	(*jfr)->uctx = ubcore_get_uctx(udata);
	(*jfr)->jfae_handler = jfae_handler;
	(*jfr)->jfr_id.eid = dev->eid_table.eid_entries[cfg->eid_index].eid;

	atomic_set(&(*jfr)->use_cnt, 0);
	kref_init(&(*jfr)->ref_cnt);
	init_completion(&(*jfr)->comp);

	(*jfr)->jfr_opt.is_actived = false;
	atomic_inc(&cfg->jfc->use_cnt);
	return ret;
}
EXPORT_SYMBOL(ubcore_alloc_jfr);

int ubcore_free_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *jfc;
	uint32_t jfr_id;
	int ret;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->free_jfr == NULL)
		return -EINVAL;

	if (jfr->jfr_opt.is_actived == true) {
		ubcore_log_err("The jfc is still activated.");
		return -EINVAL;
	}

	if (atomic_read(&jfr->use_cnt)) {
		ubcore_log_err("The jfr is still being used, use_cnt is %d",
			atomic_read(&jfr->use_cnt));
		return -EBUSY;
	}

	dev = jfr->ub_dev;
	jfr_id = jfr->jfr_opt.urma_jfr_id;
	jfc = jfr->jfr_cfg.jfc;
	ret = dev->ops->free_jfr(jfr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to free jfr, ret: %d.\n", ret);
		return ret;
	}

	atomic_dec(&jfc->use_cnt);
	return ret;
}
EXPORT_SYMBOL(ubcore_free_jfr);

int ubcore_set_jfr_opt(struct ubcore_jfr *jfr, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	struct ubcore_jfc *old_jfc;
	struct ubcore_jfc *new_jfc;
	int ret;

	if (jfr == NULL || opt == 0 || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->set_jfr_opt == NULL || buf == NULL)
		return -EINVAL;
	ret = ubcore_check_opt_valid(&jfr->jfr_opt.jfr_opt_mask.value,
		g_ubcore_jfr_opt_table,
		g_ubcore_jfr_opt_map_count, opt, len);
	if (ret != 0) {
		ubcore_log_err("invalid opt.\n");
		return ret;
	}
	dev = jfr->ub_dev;
	ret = dev->ops->set_jfr_opt(jfr, opt, buf, len, udata); /*no need copy_from_user */
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to set_jfr_opt, jfr_id:%u, ret %d.\n",
			jfr->jfr_opt.urma_jfr_id, ret);
		return ret;
	}

	if (opt == UBCORE_JFR_BIND_JFC) {
		old_jfc = jfr->jfr_cfg.jfc;
		if (old_jfc)
			atomic_dec(&old_jfc->use_cnt);
	}
	ret = ubcore_set_options_common(g_ubcore_jfr_opt_table,
		g_ubcore_jfr_opt_map_count, opt, buf, len, &jfr->jfr_cfg,
		&jfr->jfr_opt);
	if (ret != 0) {
		if (opt == UBCORE_JFR_BIND_JFC && old_jfc)
			atomic_inc(&old_jfc->use_cnt);

		ubcore_log_err("failed to set opt of ubcore_jfr, jfr_id:%u, ret is %d.\n",
			jfr->jfr_opt.urma_jfr_id, ret);
		return ret;
	}

	if (opt == UBCORE_JFR_BIND_JFC) {
		new_jfc = jfr->jfr_cfg.jfc;
		if (new_jfc)
			atomic_inc(&new_jfc->use_cnt);
	}
	return ret;
}
EXPORT_SYMBOL(ubcore_set_jfr_opt);

int ubcore_get_jfr_opt(struct ubcore_jfr *jfr, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	if (jfr == NULL || opt == 0 || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->get_jfr_opt == NULL || buf == NULL)
		return -EINVAL;

	ret = ubcore_check_opt_valid(&jfr->jfr_opt.jfr_opt_mask.value, g_ubcore_jfr_opt_table,
		g_ubcore_jfr_opt_map_count, opt, len);
	if (ret != 0) {
		ubcore_log_err("invalid opt.\n");
		return ret;
	}

	dev = jfr->ub_dev;
	ret = dev->ops->get_jfr_opt(jfr, opt, buf, len, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_jfr_opt, jfr_id:%u, ret %d.\n",
			jfr->jfr_opt.urma_jfr_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_jfr_opt);

int ubcore_active_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata)
{
	struct ubcore_device *dev = jfr->ub_dev;
	int ret;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->active_jfr == NULL || jfr->jfr_cfg.jfc == NULL)
		return -EINVAL;

	if (ubcore_check_jfr_cfg(&jfr->jfr_cfg) != 0)
		return -EINVAL;

	if (jfr->jfr_opt.is_actived) {
		ubcore_log_err("jfr has activated.\n");
		return -EINVAL;
	}

	if (jfr->jfr_cfg.jfc->jfc_opt.is_actived == false) {
		ubcore_log_err("jfc in jfr has not activated.\n");
		return -EINVAL;
	}

	ret = dev->ops->active_jfr(jfr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to active jfr, jfr_id:%u, ret: %d.\n",
			jfr->jfr_opt.urma_jfr_id, ret);
		return ret;
	}
	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JFR], &jfr->hnode, jfr->jfr_id.id);
	if (ret != 0) {
		(void)dev->ops->deactive_jfr(jfr, udata);
		ubcore_log_err("Failed to add jfr, ret: %d.\n", ret);
		return ret;
	}
	jfr->jfr_opt.is_actived = true;
	return ret;
}
EXPORT_SYMBOL(ubcore_active_jfr);

int ubcore_deactive_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
		jfr->ub_dev->ops->deactive_jfr == NULL)
		return -EINVAL;

	if (!jfr->jfr_opt.is_actived) {
		ubcore_log_err("jfr has deactivated.\n");
		return -EINVAL;
	}

	dev = jfr->ub_dev;
	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_JFR], &jfr->hnode);
	ret = dev->ops->deactive_jfr(jfr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to deactivate jfr, jfr_id:%u, ret: %d.\n",
			jfr->jfr_opt.urma_jfr_id, ret);
		return ret;
	}
	jfr->jfr_opt.is_actived = false;
	return ret;
}
EXPORT_SYMBOL(ubcore_deactive_jfr);

static int check_jetty_cfg_with_jetty_grp(struct ubcore_jetty_cfg *cfg)
{
	if (!cfg->jetty_grp)
		return 0;

	if (cfg->trans_mode != UBCORE_TP_RM)
		return -EINVAL;
	if (cfg->token_value.token !=
	    cfg->jetty_grp->jetty_grp_cfg.token_value.token)
		return -EINVAL;

	if (cfg->flag.bs.share_jfr == 1 &&
	    (cfg->jfr == NULL ||
	     cfg->token_value.token != cfg->jfr->jfr_cfg.token_value.token ||
	     cfg->jetty_grp->jetty_grp_cfg.flag.bs.token_policy !=
		     cfg->jfr->jfr_cfg.flag.bs.token_policy ||
	     cfg->jfr->jfr_cfg.trans_mode != UBCORE_TP_RM))
		return -EINVAL;

	return 0;
}

static int check_jetty_check_dev_cap(struct ubcore_device *dev,
				     struct ubcore_jetty_cfg *cfg)
{
	struct ubcore_device_cap *cap = &dev->attr.dev_cap;

	if (cfg->jetty_grp) {
		mutex_lock(&cfg->jetty_grp->lock);
		if (cfg->jetty_grp->jetty_cnt >= cap->max_jetty_in_jetty_grp) {
			mutex_unlock(&cfg->jetty_grp->lock);
			ubcore_log_err(
				"jetty_grp jetty cnt:%u, max_jetty in grp:%u.\n",
				cfg->jetty_grp->jetty_cnt,
				cap->max_jetty_in_jetty_grp);
			return -EINVAL;
		}
		mutex_unlock(&cfg->jetty_grp->lock);
	}

	if (cfg->jfs_depth == 0 || cfg->jfs_depth > cap->max_jfs_depth) {
		ubcore_log_err(
			"Invalid parameter, jfs_depth:%u, max_jfs_depth: %u.\n",
			cfg->jfs_depth, cap->max_jfs_depth);
		return -EINVAL;
	}
	if (cfg->max_inline_data != 0 &&
	    cfg->max_inline_data > cap->max_jfs_inline_size) {
		ubcore_log_err(
			"Invalid parameter, inline_data:%u, max_jfs_inline_len: %u.\n",
			cfg->max_inline_data, cap->max_jfs_inline_size);
		return -EINVAL;
	}
	if (cfg->max_send_sge > cap->max_jfs_sge) {
		ubcore_log_err(
			"Invalid parameter, jfs_sge:%u, max_jfs_sge:%u.\n",
			cfg->max_send_sge, cap->max_jfs_sge);
		return -EINVAL;
	}
	if (cfg->max_send_rsge > cap->max_jfs_rsge) {
		ubcore_log_err(
			"Invalid parameter, jfs_rsge:%u, max_jfs_rsge:%u.\n",
			cfg->max_send_rsge, cap->max_jfs_rsge);
		return -EINVAL;
	}

	if (cfg->flag.bs.share_jfr == 0) {
		if (cfg->jfr_depth == 0 ||
		    cfg->jfr_depth > cap->max_jfr_depth) {
			ubcore_log_err(
				"Invalid parameter, jfr_depth:%u, max_jfr_depth: %u.\n",
				cfg->jfr_depth, cap->max_jfr_depth);
			return -EINVAL;
		}
		if (cfg->max_recv_sge > cap->max_jfr_sge) {
			ubcore_log_err(
				"Invalid parameter, jfr_sge:%u, max_jfr_sge:%u.\n",
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
		if (!jetty_grp->jetty[i]) {
			jetty_grp->jetty[i] = jetty;
			jetty_grp->jetty_cnt++;
			mutex_unlock(&jetty_grp->lock);
			return 0;
		}
	}
	mutex_unlock(&jetty_grp->lock);
	ubcore_log_err("failed to add jetty to jetty_grp.\n");
	return -EINVAL;
}

static int
ubcore_remove_jetty_from_jetty_grp(struct ubcore_jetty *jetty,
				   struct ubcore_jetty_group *jetty_grp)
{
	uint32_t max_jetty_in_grp;
	uint32_t i;

	if (!jetty || !jetty_grp)
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
	return -EINVAL;
}

static int ubcore_jetty_pre_check(struct ubcore_device *dev,
				  struct ubcore_jetty_cfg *cfg)
{
	do {
		if (check_jetty_cfg(dev, cfg) != 0) {
			ubcore_log_err("failed to check jetty cfg.\n");
			break;
		}

		if (check_jetty_cfg_with_jetty_grp(cfg) != 0) {
			ubcore_log_err("failed to check jetty cfg.\n");
			break;
		}

		if (check_jetty_check_dev_cap(dev, cfg) != 0) {
			ubcore_log_err("failed to check jetty cfg.\n");
			break;
		}
		return 0;
	} while (0);
	return -EINVAL;
}

struct ubcore_jetty *ubcore_create_jetty(struct ubcore_device *dev,
					 struct ubcore_jetty_cfg *cfg,
					 ubcore_event_callback_t jfae_handler,
					 struct ubcore_udata *udata)
{
	struct ubcore_jetty *jetty;
	int ret;

	if (!dev || !cfg || !dev->ops ||
	    !dev->ops->create_jetty || !dev->ops->destroy_jetty ||
	    !ubcore_eid_valid(dev, cfg->eid_index, udata))
		return ERR_PTR(-EINVAL);

	if (ubcore_jetty_pre_check(dev, cfg) != 0)
		return ERR_PTR(-EINVAL);

	jetty = dev->ops->create_jetty(dev, cfg, udata);
	if (IS_ERR_OR_NULL(jetty)) {
		ubcore_log_err("[DRV]failed to create jetty.\n");
		return UBCORE_CHECK_RETURN_ERR_PTR(jetty, UBCORE_DRV_ERRNO);
	}

	jetty->ub_dev = dev;
	if (cfg->jetty_grp &&
	    ubcore_add_jetty_to_jetty_grp(
		    jetty, (struct ubcore_jetty_group *)cfg->jetty_grp) != 0) {
		ret = -EPERM;
		goto destroy_jetty;
	}

	if (check_and_fill_jetty_attr(&jetty->jetty_cfg, cfg) != 0) {
		ret = -EINVAL;
		goto delete_jetty_to_grp;
	}

	jetty->uctx = ubcore_get_uctx(udata);
	jetty->jfae_handler = jfae_handler;
	jetty->jetty_id.eid = dev->eid_table.eid_entries[cfg->eid_index].eid;
	if (jetty->jetty_cfg.trans_mode == UBCORE_TP_RC) {
		jetty->tptable = ubcore_create_tptable();
		if (!jetty->tptable) {
			ubcore_log_err(
				"Failed to create tp table in the jetty.\n");
			ret = -ENOMEM;
			goto delete_jetty_to_grp;
		}
	} else {
		jetty->tptable =
			NULL; /* To prevent kernel-mode drivers, malloc is not empty */
	}
	atomic_set(&jetty->use_cnt, 0);
	kref_init(&jetty->ref_cnt);
	init_completion(&jetty->comp);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JETTY],
		&jetty->hnode, jetty->jetty_id.id);
	if (ret != 0) {
		ubcore_log_err("Failed to add jetty.\n");
		goto destroy_tptable;
	}

	atomic_inc(&cfg->send_jfc->use_cnt);
	atomic_inc(&cfg->recv_jfc->use_cnt);

	if (cfg->jfr)
		atomic_inc(&cfg->jfr->use_cnt);

	ubcore_log_info("[JETTY CREATE] Created JETTY: id: %u, dev_name: %s, eid_idx: %u.\n",
		jetty->jetty_cfg.id, dev->dev_name, jetty->jetty_cfg.eid_index);
	jetty->jetty_opt.is_actived = true;
	return jetty;
destroy_tptable:
	ubcore_destroy_tptable(&jetty->tptable);
delete_jetty_to_grp:
	(void)ubcore_remove_jetty_from_jetty_grp(
		jetty, (struct ubcore_jetty_group *)cfg->jetty_grp);
destroy_jetty:
	(void)dev->ops->destroy_jetty(jetty);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(ubcore_create_jetty);

int ubcore_modify_jetty(struct ubcore_jetty *jetty,
			struct ubcore_jetty_attr *attr,
			struct ubcore_udata *udata)
{
	uint32_t jetty_id;
	int ret;

	if (!jetty || !attr || !jetty->ub_dev ||
	    !jetty->ub_dev->ops ||
	    !jetty->ub_dev->ops->modify_jetty)
		return -EINVAL;

	jetty_id = jetty->jetty_id.id;

	ret = jetty->ub_dev->ops->modify_jetty(jetty, attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to modify jetty, id:%u, ret: %d.\n",
			       jetty_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_modify_jetty);

int ubcore_query_jetty(struct ubcore_jetty *jetty, struct ubcore_jetty_cfg *cfg,
		       struct ubcore_jetty_attr *attr)
{
	struct ubcore_device *dev;
	uint32_t jetty_id;
	int ret;

	if (!jetty || !cfg || !attr ||
	    !jetty->ub_dev || !jetty->ub_dev->ops ||
	    !jetty->ub_dev->ops->query_jetty)
		return -EINVAL;

	jetty_id = jetty->jetty_id.id;
	dev = jetty->ub_dev;
	ret = dev->ops->query_jetty(jetty, cfg, attr);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to query jetty, id:%u, ret: %d.\n",
			       jetty_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_query_jetty);

static int ubcore_check_jetty_attr(struct ubcore_jetty *jetty)
{
	if (!jetty || !jetty->ub_dev ||
	    !jetty->ub_dev->ops ||
	    !jetty->ub_dev->ops->destroy_jetty)
		return -EINVAL;

	if ((jetty->ub_dev->transport_type == UBCORE_TRANSPORT_UB &&
	     jetty->jetty_cfg.trans_mode == UBCORE_TP_RC &&
	     jetty->remote_jetty != NULL) ||
	    atomic_read(&jetty->use_cnt) > 0) {
		ubcore_log_err(
			"Failed to delete jetty in RC mode because it has remote jetty");
		return -EINVAL;
	}

	return 0;
}

int ubcore_delete_jetty(struct ubcore_jetty *jetty)
{
	struct ubcore_jetty_group *jetty_grp;
	struct ubcore_jfc *send_jfc;
	struct ubcore_jfc *recv_jfc;
	struct ubcore_device *dev;
	struct ubcore_jfr *jfr;
	uint32_t jetty_id;
	int ret;

	if (ubcore_check_jetty_attr(jetty) != 0)
		return -EINVAL;

	if (jetty->jetty_opt.is_actived == false) {
		ubcore_log_err("Failed to delete deactivated jetty.");
		return -EINVAL;
	}

	jetty_grp = jetty->jetty_cfg.jetty_grp;
	send_jfc = jetty->jetty_cfg.send_jfc;
	recv_jfc = jetty->jetty_cfg.recv_jfc;
	jfr = jetty->jetty_cfg.jfr;
	jetty_id = jetty->jetty_id.id;
	dev = jetty->ub_dev;

	(void)ubcore_hash_table_check_remove(&dev->ht[UBCORE_HT_JETTY],
					     &jetty->hnode);
	ubcore_destroy_tptable(&jetty->tptable);

	if (jetty->ub_dev->transport_type == UBCORE_TRANSPORT_UB &&
	    jetty->remote_jetty != NULL) {
		mutex_lock(&jetty->remote_jetty->lock);
		(void)ubcore_disconnect_vtp(jetty->remote_jetty->vtpn);
		jetty->remote_jetty->vtpn = NULL;
		mutex_unlock(&jetty->remote_jetty->lock);
		atomic_dec(&jetty->remote_jetty->use_cnt);
		/* The tjetty object will release remote jetty resources */
		jetty->remote_jetty = NULL;
		ubcore_log_warn(
			"jetty->remote_jetty != NULL and it has been handled");
	}

	ubcore_put_jetty(jetty);
	wait_for_completion(&jetty->comp);

	if (jetty_grp) {
		(void)ubcore_remove_jetty_from_jetty_grp(jetty, jetty_grp);
		jetty->jetty_cfg.jetty_grp = NULL;
	}
	ret = dev->ops->destroy_jetty(jetty);
	if (ret != 0) {
		ubcore_log_err("[DRV]failed to destroy jetty, id: %u, dev_name: %s, eid_idx: %u, ret: %d.\n",
			jetty_id, dev->dev_name, jetty->jetty_cfg.eid_index, ret);
		kref_init(&jetty->ref_cnt);
		return ret;
	}

	if (send_jfc)
		atomic_dec(&send_jfc->use_cnt);
	if (recv_jfc)
		atomic_dec(&recv_jfc->use_cnt);
	if (jfr)
		atomic_dec(&jfr->use_cnt);

	ubcore_log_info("[JETTY DELETE] Delete JETTY: id: %u, dev_name: %s, eid_idx: %u.\n",
		jetty_id, dev->dev_name, jetty->jetty_cfg.eid_index);

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jetty);

int ubcore_delete_jetty_batch(struct ubcore_jetty **jetty_arr, int jetty_num,
			      int *bad_jetty_index)
{
	struct ubcore_jetty_group *jetty_grp;
	struct ubcore_jfc **send_jfc = NULL;
	struct ubcore_jfc **recv_jfc = NULL;
	struct ubcore_jetty *jetty = NULL;
	struct ubcore_jfr **jfr = NULL;
	struct ubcore_device *dev;
	int bad_index = 0;
	uint32_t jetty_id;
	int ret;
	int i;

	if (!jetty_arr || jetty_num <= 0 || !bad_jetty_index) {
		ubcore_log_err("Invalid parameter.");
		return -EINVAL;
	}

	for (i = 0; i < jetty_num; ++i) {
		jetty = jetty_arr[i];
		if (ubcore_check_jetty_attr(jetty) != 0) {
			*bad_jetty_index = 0;
			return -EINVAL;
		}
	}
	send_jfc = kcalloc(jetty_num, sizeof(struct ubcore_jfc *), GFP_KERNEL);
	if (!send_jfc) {
		*bad_jetty_index = 0;
		return -ENOMEM;
	}
	recv_jfc = kcalloc(jetty_num, sizeof(struct ubcore_jfc *), GFP_KERNEL);
	if (!recv_jfc) {
		kfree(send_jfc);
		*bad_jetty_index = 0;
		return -ENOMEM;
	}
	jfr = kcalloc(jetty_num, sizeof(struct ubcore_jfr *), GFP_KERNEL);
	if (!jfr) {
		kfree(recv_jfc);
		kfree(send_jfc);
		*bad_jetty_index = 0;
		return -ENOMEM;
	}

	for (i = 0; i < jetty_num; ++i) {
		jetty = jetty_arr[i];
		jetty_grp = jetty->jetty_cfg.jetty_grp;
		send_jfc[i] = jetty->jetty_cfg.send_jfc;
		recv_jfc[i] = jetty->jetty_cfg.recv_jfc;
		jfr[i] = jetty->jetty_cfg.jfr;
		jetty_id = jetty->jetty_id.id;
		dev = jetty->ub_dev;

		(void)ubcore_hash_table_check_remove(&dev->ht[UBCORE_HT_JETTY],
						     &jetty->hnode);
		ubcore_destroy_tptable(&jetty->tptable);

		if (jetty->ub_dev->transport_type == UBCORE_TRANSPORT_UB &&
		    jetty->remote_jetty != NULL) {
			mutex_lock(&jetty->remote_jetty->lock);
			(void)ubcore_disconnect_vtp(jetty->remote_jetty->vtpn);
			jetty->remote_jetty->vtpn = NULL;
			mutex_unlock(&jetty->remote_jetty->lock);
			atomic_dec(&jetty->remote_jetty->use_cnt);
			/* The tjetty object will release remote jetty resources */
			jetty->remote_jetty = NULL;
			ubcore_log_warn(
				"jetty->remote_jetty != NULL and it has been handled");
		}

		ubcore_put_jetty(jetty);
		wait_for_completion(&jetty->comp);

		if (jetty_grp) {
			(void)ubcore_remove_jetty_from_jetty_grp(jetty,
								 jetty_grp);
			jetty->jetty_cfg.jetty_grp = NULL;
		}
	}

	ret = dev->ops->destroy_jetty_batch(jetty_arr, jetty_num,
					    bad_jetty_index);
	bad_index = jetty_num;
	if (ret != 0) {
		ubcore_log_err(
			"driver failed to destroy jetty batch, index: %d.\n",
			*bad_jetty_index);
		if (ret == -EINVAL)
			bad_index = 0;
		else
			bad_index = *bad_jetty_index;
		if (bad_index >= jetty_num) {
			ubcore_log_err(
				"driver return bad_jetty_index %d out of range, jetty_num is %d.\n",
				*bad_jetty_index, jetty_num);
			*bad_jetty_index = 0;
			bad_index = jetty_num;
			ret = -EFAULT;
		}
		for (i = bad_index; i < jetty_num; ++i)
			kref_init(&jetty_arr[i]->ref_cnt);
	}

	/* Do not dereference jetty in jetty_arr, as it might be released */
	for (i = 0; i < bad_index; ++i) {
		if (send_jfc[i])
			atomic_dec(&send_jfc[i]->use_cnt);
		if (recv_jfc[i])
			atomic_dec(&recv_jfc[i]->use_cnt);
		if (jfr[i])
			atomic_dec(&jfr[i]->use_cnt);
	}

	kfree(jfr);
	kfree(recv_jfc);
	kfree(send_jfc);

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jetty_batch);

int ubcore_flush_jetty(struct ubcore_jetty *jetty, int cr_cnt,
		       struct ubcore_cr *cr)
{
	if (!jetty || !jetty->ub_dev ||
	    !jetty->ub_dev->ops ||
	    !jetty->ub_dev->ops->flush_jetty || !cr) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	return jetty->ub_dev->ops->flush_jetty(jetty, cr_cnt, cr);
}
EXPORT_SYMBOL(ubcore_flush_jetty);

struct ubcore_tjetty *ubcore_import_jetty(struct ubcore_device *dev,
					  struct ubcore_tjetty_cfg *cfg,
					  struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_vtpn *vtpn = NULL;
	struct ubcore_tjetty *tjetty;

	if (!ubcore_have_ops(dev) || !dev->ops->unimport_jetty ||
	    cfg == NULL || dev->attr.dev_cap.max_eid_cnt <= cfg->eid_index)
		return ERR_PTR(-EINVAL);

	if (ubcore_check_ctrlplane_compat(dev->ops->import_jetty))
		return ubcore_import_jetty_compat(dev, cfg, udata);

	if (ubcore_is_bonding_dev(dev)) {
		if (ubcore_connect_exchange_udata_when_import_jetty(
			    cfg, udata, false, dev) != 0) {
			return ERR_PTR(-ENOEXEC);
		}
	}

	tjetty = dev->ops->import_jetty(dev, cfg, udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		ubcore_log_err("[DRV] failed to import jetty,dev_name: %s, eid_idx: %u, jetty_id: %u.\n",
			       dev->dev_name, cfg->eid_index, cfg->id.id);
		return UBCORE_CHECK_RETURN_ERR_PTR(tjetty, UBCORE_DRV_ERRNO);
	}
	tjetty->cfg = *cfg;
	tjetty->ub_dev = dev;
	tjetty->uctx = ubcore_get_uctx(udata);

	atomic_set(&tjetty->use_cnt, 0);
	mutex_init(&tjetty->lock);

	/* create rm tp if the remote eid is not connected */
	if (!ubcore_is_bonding_dev(dev) &&
	    dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (cfg->trans_mode == UBCORE_TP_RM ||
	     cfg->trans_mode == UBCORE_TP_UM ||
	     is_create_rc_shared_tp(cfg->trans_mode, cfg->flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp))) {
		ubcore_set_vtp_param(dev, NULL, cfg, &vtp_param);
		mutex_lock(&tjetty->lock);
		vtpn = ubcore_connect_vtp(dev, &vtp_param);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjetty->lock);
			mutex_destroy(&tjetty->lock);
			(void)dev->ops->unimport_jetty(tjetty);
			ubcore_log_err("Failed to setup tp connection.\n");
			if (!vtpn)
				return ERR_PTR(-ECONNREFUSED);
			return (void *)vtpn;
		}
		tjetty->vtpn = vtpn;
		mutex_unlock(&tjetty->lock);
	} else {
		tjetty->tp = NULL;
	}
	ubcore_log_info("[JETTY IMPORT] Import JETTY: id: %u, dev_name: %s, eid_idx: %u.\n",
			cfg->id.id, dev->dev_name, cfg->eid_index);
	return tjetty;
}
EXPORT_SYMBOL(ubcore_import_jetty);

struct ubcore_tjetty *
ubcore_import_jetty_ex(struct ubcore_device *dev, struct ubcore_tjetty_cfg *cfg,
		       struct ubcore_active_tp_cfg *active_tp_cfg,
		       struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_vtpn *vtpn = NULL;
	struct ubcore_tjetty *tjetty;

	if (!dev || !dev->ops ||
	    !dev->ops->import_jetty_ex ||
	    !dev->ops->unimport_jetty || !cfg ||
	    !active_tp_cfg || dev->attr.dev_cap.max_eid_cnt <= cfg->eid_index)
		return ERR_PTR(-EINVAL);

	tjetty = dev->ops->import_jetty_ex(dev, cfg, active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		ubcore_log_err("[DRV] failed to import jetty, dev_name: %s, eid_idx: %u, jetty_id:%u.\n",
			dev->dev_name, cfg->eid_index, cfg->id.id);
		return UBCORE_CHECK_RETURN_ERR_PTR(tjetty, UBCORE_DRV_ERRNO);
	}
	tjetty->cfg = *cfg;
	tjetty->ub_dev = dev;
	tjetty->uctx = ubcore_get_uctx(udata);

	atomic_set(&tjetty->use_cnt, 0);
	mutex_init(&tjetty->lock);

	/* create rm tp if the remote eid is not connected */
	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (cfg->trans_mode == UBCORE_TP_RM ||
	     cfg->trans_mode == UBCORE_TP_UM ||
	     is_create_rc_shared_tp(cfg->trans_mode, cfg->flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp))) {
		ubcore_set_vtp_param(dev, NULL, cfg, &vtp_param);
		mutex_lock(&tjetty->lock);
		vtpn = ubcore_connect_vtp_ctrlplane(dev, &vtp_param,
							active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjetty->lock);
			mutex_destroy(&tjetty->lock);
			(void)dev->ops->unimport_jetty(tjetty);
			ubcore_log_err("Failed to setup tp connection.\n");
			if (!vtpn)
				return ERR_PTR(-ECONNREFUSED);
			return (void *)vtpn;
		}
		tjetty->vtpn = vtpn;
		mutex_unlock(&tjetty->lock);
	} else {
		tjetty->tp = NULL;
	}
	ubcore_log_info("[JETTY IMPORT EX] Import JETTY Ex: id: %u, dev_name: %s, eid_idx: %u.\n",
				cfg->id.id, dev->dev_name, cfg->eid_index);
	return tjetty;
}
EXPORT_SYMBOL(ubcore_import_jetty_ex);

int ubcore_unimport_jetty(struct ubcore_tjetty *tjetty)
{
	struct ubcore_device *dev;
	uint32_t jetty_id = tjetty->cfg.id.id;
	uint32_t eid_idx = tjetty->cfg.eid_index;
	int ret;

	if (!tjetty || !tjetty->ub_dev || !tjetty->ub_dev->ops ||
	    !tjetty->ub_dev->ops->unimport_jetty ||
	    !ubcore_have_ops(tjetty->ub_dev))
		return -EINVAL;

	dev = tjetty->ub_dev;

	if (!ubcore_is_bonding_dev(dev) &&
	    dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (tjetty->cfg.trans_mode == UBCORE_TP_RM ||
	     tjetty->cfg.trans_mode == UBCORE_TP_UM ||
	     is_create_rc_shared_tp(tjetty->cfg.trans_mode,
				    tjetty->cfg.flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp)) &&
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

	if (tjetty->cfg.trans_mode == UBCORE_TP_RC &&
	    atomic_read(&tjetty->use_cnt))
		return -EBUSY;

	mutex_destroy(&tjetty->lock);

	ret = dev->ops->unimport_jetty(tjetty);
	if (ret != 0) {
		ubcore_log_err("[DRV] Failed to unimport_jetty, dev_name:%s, eid_idx:%u, id:%u, ret: %d.",
			dev->dev_name, eid_idx, jetty_id, ret);
		return ret;
	}
	ubcore_log_info("[JETTY UNIMPORT] Unimport JETTY Ex: id: %u, dev_name: %s, eid_idx: %u.\n",
			jetty_id, dev->dev_name, eid_idx);
	return ret;
}
EXPORT_SYMBOL(ubcore_unimport_jetty);

static int ubcore_inner_bind_ub_jetty(struct ubcore_jetty *jetty,
				      struct ubcore_tjetty *tjetty,
				      struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_device *dev;
	struct ubcore_vtpn *vtpn;
	int ret;

	dev = jetty->ub_dev;

	if (!dev->ops || !dev->ops->unbind_jetty) {
		ubcore_log_err("Failed to bind jetty, no ops->bind_jetty\n");
		return -EINVAL;
	}

	if (ubcore_check_ctrlplane_compat(dev->ops->bind_jetty))
		return ubcore_bind_jetty_compat(jetty, tjetty, udata);

	ret = dev->ops->bind_jetty(jetty, tjetty, udata);
	if (ret != 0) {
		ubcore_log_err("Failed to bind jetty");
		return ret;
	}
	atomic_inc(&jetty->use_cnt);

	if (!is_create_rc_shared_tp(jetty->jetty_cfg.trans_mode,
				    jetty->jetty_cfg.flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp)) {
		ubcore_set_vtp_param(dev, jetty, &tjetty->cfg, &vtp_param);
		mutex_lock(&tjetty->lock);

		if (tjetty->vtpn) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Duplicate bind\n");
			ret = -EEXIST;
			goto unbind;
		}
		vtpn = ubcore_connect_vtp(dev, &vtp_param);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Failed to setup vtp connection.\n");
			ret = -1;
			if (vtpn)
				ret = PTR_ERR(vtpn);
			goto unbind;
		}
		tjetty->vtpn = vtpn;
		mutex_unlock(&tjetty->lock);
	}
	return 0;

unbind:
	if (dev->ops->bind_jetty && dev->ops->unbind_jetty) {
		(void)dev->ops->unbind_jetty(jetty);
		atomic_dec(&jetty->use_cnt);
	}
	return ret;
}

static int ubcore_inner_bind_jetty(struct ubcore_jetty *jetty,
				   struct ubcore_tjetty *tjetty,
				   struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	dev = jetty->ub_dev;
	if (!dev) {
		ubcore_log_err("Invalid parameter with dev null_ptr.\n");
		return -EINVAL;
	}

	if (dev->attr.dev_cap.max_eid_cnt <= tjetty->cfg.eid_index) {
		ubcore_log_err("eid_index:%u is beyond the max_eid_cnt:%u.\n",
			       tjetty->cfg.eid_index,
			       dev->attr.dev_cap.max_eid_cnt);
		return -EINVAL;
	}

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		ret = ubcore_inner_bind_ub_jetty(jetty, tjetty, udata);
		if (ret != 0)
			return ret;
	} else {
		atomic_inc(&jetty->use_cnt);
	}
	ubcore_log_info_rl("jetty: %u bind tjetty: %u\n", jetty->jetty_id.id,
			   tjetty->cfg.id.id);
	jetty->remote_jetty = tjetty;
	atomic_inc(&tjetty->use_cnt);
	return 0;
}

int ubcore_bind_jetty(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
		      struct ubcore_udata *udata)
{
	if (!jetty || !tjetty ||
	    !ubcore_have_ops(jetty->ub_dev)) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	if ((jetty->jetty_cfg.trans_mode != UBCORE_TP_RC) ||
	    (tjetty->cfg.trans_mode != UBCORE_TP_RC)) {
		ubcore_log_err("trans mode is not rc type.\n");
		return -EINVAL;
	}
	if (jetty->remote_jetty == tjetty) {
		ubcore_log_info("bind reentry, jetty: %u bind tjetty: %u\n",
				jetty->jetty_id.id, tjetty->cfg.id.id);
		return 0;
	}
	if (jetty->remote_jetty) {
		ubcore_log_err(
			"The same jetty, different tjetty, prevent duplicate bind.\n");
		return -EINVAL;
	}

	if (tjetty->vtpn &&
	    (!is_create_rc_shared_tp(tjetty->cfg.trans_mode,
				     tjetty->cfg.flag.bs.order_type,
				     tjetty->cfg.flag.bs.share_tp))) {
		ubcore_log_err(
			"The tjetty, has already connect vtpn, prevent duplicate bind.\n");
		return -EINVAL;
	}

	return ubcore_inner_bind_jetty(jetty, tjetty, udata);
}
EXPORT_SYMBOL(ubcore_bind_jetty);

static bool
ubcore_check_tp_handle_available(struct ubcore_device *dev,
				 struct ubcore_active_tp_cfg *active_tp_cfg)
{
	struct ubcore_vtpn *vtpn;

	vtpn = ubcore_find_get_vtpn_ctrlplane(dev, active_tp_cfg);
	if (vtpn) {
		ubcore_log_err(
			"Invalid operation with tp_handle: %llu already used.\n",
			active_tp_cfg->tp_handle.value);
		ubcore_vtpn_kref_put(vtpn);
		return false;
	}
	return true;
}

static int ubcore_inner_bind_ub_jetty_ctrlplane(
	struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
	struct ubcore_active_tp_cfg *active_tp_cfg, struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_device *dev;
	struct ubcore_vtpn *vtpn;
	int ret;

	dev = jetty->ub_dev;
	if (!dev->ops || !dev->ops->bind_jetty_ex ||
	    !dev->ops->unbind_jetty) {
		ubcore_log_err(
			"Failed to bind jetty, no ops->bind_jetty_ex.\n");
		return -EINVAL;
	}

	if (!ubcore_check_tp_handle_available(dev, active_tp_cfg)) {
		ubcore_log_err("Invalid tp_handle: %llu.\n",
			       active_tp_cfg->tp_handle.value);
		return -EINVAL;
	}

	ret = dev->ops->bind_jetty_ex(jetty, tjetty, active_tp_cfg, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to bind jetty, ret: %d.\n", ret);
		return ret;
	}
	atomic_inc(&jetty->use_cnt);

	if (!is_create_rc_shared_tp(jetty->jetty_cfg.trans_mode,
				    jetty->jetty_cfg.flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp)) {
		ubcore_set_vtp_param(dev, jetty, &tjetty->cfg, &vtp_param);
		mutex_lock(&tjetty->lock);

		if (tjetty->vtpn) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Duplicate bind\n");
			ret = -EEXIST;
			goto unbind;
		}
		vtpn = ubcore_connect_vtp_ctrlplane(dev, &vtp_param,
							active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Failed to setup vtp connection.\n");
			ret = vtpn == NULL ?
				-UBCORE_DRV_ERRNO : PTR_ERR(vtpn);
			goto unbind;
		}
		tjetty->vtpn = vtpn;
		mutex_unlock(&tjetty->lock);
	}
	return 0;

unbind:
	if (dev->ops->bind_jetty_ex && dev->ops->unbind_jetty) {
		(void)dev->ops->unbind_jetty(jetty);
		atomic_dec(&jetty->use_cnt);
	}
	return ret;
}

static int ubcore_inner_bind_jetty_ctrlplane(
	struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
	struct ubcore_active_tp_cfg *active_tp_cfg, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	dev = jetty->ub_dev;
	if (dev->attr.dev_cap.max_eid_cnt <= tjetty->cfg.eid_index) {
		ubcore_log_err("eid_index:%u is beyond the max_eid_cnt:%u.\n",
			       tjetty->cfg.eid_index,
			       dev->attr.dev_cap.max_eid_cnt);
		return -EINVAL;
	}

	if (dev->transport_type != UBCORE_TRANSPORT_UB) {
		ubcore_log_err("Invalid transport_type: %d.\n",
			       dev->transport_type);
		return -EINVAL;
	}

	ret = ubcore_inner_bind_ub_jetty_ctrlplane(jetty, tjetty, active_tp_cfg,
						   udata);
	if (ret != 0)
		return ret;

	ubcore_log_info_rl("jetty: %u bind tjetty: %u\n", jetty->jetty_id.id,
			   tjetty->cfg.id.id);
	jetty->remote_jetty = tjetty;
	atomic_inc(&tjetty->use_cnt);
	return 0;
}

int ubcore_bind_jetty_ex(struct ubcore_jetty *jetty,
			 struct ubcore_tjetty *tjetty,
			 struct ubcore_active_tp_cfg *active_tp_cfg,
			 struct ubcore_udata *udata)
{
	if (!jetty || !tjetty || !jetty->ub_dev ||
	    !jetty->ub_dev->ops || !active_tp_cfg) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	if ((jetty->jetty_cfg.trans_mode != UBCORE_TP_RC) ||
	    (tjetty->cfg.trans_mode != UBCORE_TP_RC)) {
		ubcore_log_err("trans mode is not rc type.\n");
		return -EINVAL;
	}
	if (jetty->remote_jetty == tjetty) {
		ubcore_log_info("bind reentry, jetty: %u bind tjetty: %u.\n",
				jetty->jetty_id.id, tjetty->cfg.id.id);
		return 0;
	}
	if (jetty->remote_jetty) {
		ubcore_log_err(
			"The same jetty, different tjetty, prevent duplicate bind.\n");
		return -EINVAL;
	}

	if (tjetty->vtpn &&
	    (!is_create_rc_shared_tp(tjetty->cfg.trans_mode,
				     tjetty->cfg.flag.bs.order_type,
				     tjetty->cfg.flag.bs.share_tp))) {
		ubcore_log_err(
			"The tjetty, has already connect vtpn, prevent duplicate bind.\n");
		return -EINVAL;
	}

	return ubcore_inner_bind_jetty_ctrlplane(jetty, tjetty, active_tp_cfg,
						 udata);
}
EXPORT_SYMBOL(ubcore_bind_jetty_ex);

static int ubcore_inner_unbind_ub_jetty(struct ubcore_jetty *jetty,
					struct ubcore_tjetty *tjetty)
{
	int ret;

	if (tjetty->vtpn) {
		if (!is_create_rc_shared_tp(jetty->jetty_cfg.trans_mode,
					    jetty->jetty_cfg.flag.bs.order_type,
					    tjetty->cfg.flag.bs.share_tp)) {
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
	}
	return 0;
}

int ubcore_unbind_jetty(struct ubcore_jetty *jetty)
{
	struct ubcore_tjetty *tjetty;
	struct ubcore_device *dev;
	int ret;

	if (!jetty || !jetty->ub_dev) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	tjetty = jetty->remote_jetty;
	if ((jetty->jetty_cfg.trans_mode != UBCORE_TP_RC) || !tjetty ||
	    (tjetty->cfg.trans_mode != UBCORE_TP_RC)) {
		ubcore_log_err("trans mode is not rc type.\n");
		return -EINVAL;
	}

	dev = jetty->ub_dev;

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		ret = ubcore_inner_unbind_ub_jetty(jetty, tjetty);
		if (ret != 0)
			return ret;
	}

	ubcore_log_info_rl("jetty: %u unbind tjetty: %u\n", jetty->jetty_id.id,
			   tjetty->cfg.id.id);

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		if (!dev->ops || !dev->ops->unbind_jetty) {
			ubcore_log_err(
				"Failed to unbind jetty, no ops->unbind_jetty\n");
			return -EINVAL;
		}
		ret = dev->ops->unbind_jetty(jetty);
		if (ret != 0) {
			ubcore_log_err("[DRV_ERROR]Failed to unbind jetty, ret: %d.\n", ret);
			return ret;
		}
	}

	jetty->remote_jetty = NULL;
	atomic_dec(&tjetty->use_cnt);
	atomic_dec(&jetty->use_cnt);
	return 0;
}
EXPORT_SYMBOL(ubcore_unbind_jetty);

struct ubcore_jetty *ubcore_find_jetty(struct ubcore_device *dev,
				       uint32_t jetty_id)
{
	if (!dev) {
		ubcore_log_err("invalid parameter.\n");
		return NULL;
	}

	return ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_JETTY], jetty_id,
					&jetty_id);
}
EXPORT_SYMBOL(ubcore_find_jetty);

struct ubcore_jetty_group *ubcore_create_jetty_grp(
	struct ubcore_device *dev, struct ubcore_jetty_grp_cfg *cfg,
	ubcore_event_callback_t jfae_handler, struct ubcore_udata *udata)
{
	struct ubcore_jetty_group *jetty_grp;
	uint32_t max_jetty_in_jetty_grp;
	uint32_t i;

	if (!dev || !cfg || !dev->ops ||
	    !dev->ops->create_jetty_grp ||
	    !dev->ops->delete_jetty_grp ||
	    !ubcore_eid_valid(dev, cfg->eid_index, udata))
		return ERR_PTR(-EINVAL);

	max_jetty_in_jetty_grp = dev->attr.dev_cap.max_jetty_in_jetty_grp;
	if (max_jetty_in_jetty_grp == 0 ||
	    max_jetty_in_jetty_grp > UBCORE_MAX_JETTY_IN_JETTY_GRP) {
		ubcore_log_err(
			"max_jetty_in_jetty_grp %u is err, range is 1 to %u.\n",
			max_jetty_in_jetty_grp, UBCORE_MAX_JETTY_IN_JETTY_GRP);
		return ERR_PTR(-EINVAL);
	}

	jetty_grp = dev->ops->create_jetty_grp(
		dev, (struct ubcore_jetty_grp_cfg *)cfg, udata);
	if (IS_ERR_OR_NULL(jetty_grp)) {
		ubcore_log_err("failed to create jetty_grp.\n");
		return UBCORE_CHECK_RETURN_ERR_PTR(jetty_grp, UBCORE_DRV_ERRNO);
	}

	jetty_grp->jetty =
		kzalloc(sizeof(struct ubcore_jetty *) * max_jetty_in_jetty_grp,
			GFP_KERNEL);
	if (!jetty_grp->jetty) {
		(void)dev->ops->delete_jetty_grp(jetty_grp);
		ubcore_log_err("Failed to alloc jetty array.\n");
		return ERR_PTR(-ENOMEM);
	}

	jetty_grp->ub_dev = dev;
	jetty_grp->jetty_grp_cfg = *cfg;
	jetty_grp->jfae_handler = jfae_handler;
	jetty_grp->uctx = ubcore_get_uctx(udata);
	jetty_grp->jetty_grp_id.eid =
		dev->eid_table.eid_entries[cfg->eid_index].eid;
	mutex_init(&jetty_grp->lock);
	jetty_grp->jetty_cnt = 0;
	for (i = 0; i < max_jetty_in_jetty_grp; i++)
		jetty_grp->jetty[i] = NULL;

	return jetty_grp;
}
EXPORT_SYMBOL(ubcore_create_jetty_grp);

int ubcore_delete_jetty_grp(struct ubcore_jetty_group *jetty_grp)
{
	struct ubcore_device *dev;
	uint32_t jetty_grp_id;
	int ret;

	if (!jetty_grp || !jetty_grp->ub_dev ||
	    !jetty_grp->ub_dev->ops ||
	    !jetty_grp->ub_dev->ops->delete_jetty_grp)
		return -EINVAL;

	jetty_grp_id = jetty_grp->jetty_grp_id.id;
	dev = jetty_grp->ub_dev;

	mutex_lock(&jetty_grp->lock);
	if (jetty_grp->jetty_cnt > 0) {
		mutex_unlock(&jetty_grp->lock);
		ubcore_log_err("jetty_grp->jetty_cnt: %u.\n",
			       jetty_grp->jetty_cnt);
		return -EBUSY;
	}
	kfree(jetty_grp->jetty);
	jetty_grp->jetty = NULL;
	mutex_unlock(&jetty_grp->lock);
	mutex_destroy(&jetty_grp->lock);

	ret = dev->ops->delete_jetty_grp(jetty_grp);
	if (ret != 0) {
		ubcore_log_err(
			"[DRV_ERROR]Failed to destroy jetty_grp, id:%ul, ret: %d.\n",
			jetty_grp_id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_jetty_grp);

struct ubcore_tjetty *ubcore_import_jetty_async(struct ubcore_device *dev,
						struct ubcore_tjetty_cfg *cfg,
						int timeout,
						struct ubcore_import_cb *cb,
						struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_vtpn *vtpn = NULL;
	struct ubcore_tjetty *tjetty;
	struct ubcore_vtpn_cb_para para = { 0 };

	if (!ubcore_have_ops(dev) || !dev->ops->import_jetty ||
	    !dev->ops->unimport_jetty || !cfg ||
	    dev->attr.dev_cap.max_eid_cnt <= cfg->eid_index || !cb)
		return ERR_PTR(-EINVAL);

	tjetty = dev->ops->import_jetty(dev, cfg, udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		ubcore_log_err(
			"UBEP failed to import jetty async, jetty_id:%u.\n",
			cfg->id.id);
		return UBCORE_CHECK_RETURN_ERR_PTR(tjetty, UBCORE_DRV_ERRNO);
	}
	tjetty->cfg = *cfg;
	tjetty->ub_dev = dev;
	tjetty->uctx = ubcore_get_uctx(udata);

	atomic_set(&tjetty->use_cnt, 0);
	mutex_init(&tjetty->lock);

	para.type = UBCORE_IMPORT_JETTY_VTPN;
	para.tjetty = tjetty;
	para.import_cb = cb;

	/* create rm tp if the remote eid is not connected */
	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (cfg->trans_mode == UBCORE_TP_RM ||
	     cfg->trans_mode == UBCORE_TP_UM ||
	     is_create_rc_shared_tp(cfg->trans_mode, cfg->flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp))) {
		ubcore_set_vtp_param(dev, NULL, cfg, &vtp_param);
		mutex_lock(&tjetty->lock);
		vtpn = ubcore_connect_vtp_async(dev, &vtp_param, timeout,
						&para);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjetty->lock);
			mutex_destroy(&tjetty->lock);
			(void)dev->ops->unimport_jetty(tjetty);
			ubcore_log_err(
				"Failed to setup asynchronous tp connection.\n");
			if (!vtpn)
				return ERR_PTR(-ECONNREFUSED);
			return (void *)vtpn;
		}
		tjetty->vtpn = vtpn;
		mutex_unlock(&tjetty->lock);
	} else {
		tjetty->tp = NULL;
		cb->callback(tjetty, 0, cb->user_arg);
		kfree(cb);
	}

	return tjetty;
}
EXPORT_SYMBOL(ubcore_import_jetty_async);

int ubcore_unimport_jetty_async(struct ubcore_tjetty *tjetty, int timeout,
				struct ubcore_unimport_cb *cb)
{
	struct ubcore_device *dev;
	struct ubcore_vtpn_cb_para para = { 0 };
	int ret;

	if (!tjetty || !tjetty->ub_dev ||
	    !tjetty->ub_dev->ops ||
	    !tjetty->ub_dev->ops->unimport_jetty ||
	    !ubcore_have_ops(tjetty->ub_dev))
		return -EINVAL;

	dev = tjetty->ub_dev;
	para.type = UBCORE_UNIMPORT_JETTY_VTPN;
	para.unimport_cb = cb;

	if (dev->transport_type == UBCORE_TRANSPORT_UB &&
	    (tjetty->cfg.trans_mode == UBCORE_TP_RM ||
	     tjetty->cfg.trans_mode == UBCORE_TP_UM ||
	     is_create_rc_shared_tp(tjetty->cfg.trans_mode,
				    tjetty->cfg.flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp)) &&
	    tjetty->vtpn != NULL) {
		mutex_lock(&tjetty->lock);
		ret = ubcore_disconnect_vtp_async(tjetty->vtpn, timeout, &para);
		if (ret != 0) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Failed to disconnect vtp.\n");
			return ret;
		}

		tjetty->vtpn = NULL;
		mutex_unlock(&tjetty->lock);
	}

	if (tjetty->cfg.trans_mode == UBCORE_TP_RC &&
	    atomic_read(&tjetty->use_cnt))
		return -EBUSY;

	mutex_destroy(&tjetty->lock);

	return dev->ops->unimport_jetty(tjetty);
}
EXPORT_SYMBOL(ubcore_unimport_jetty_async);

static int ubcore_inner_bind_ub_jetty_async(struct ubcore_jetty *jetty,
					    struct ubcore_tjetty *tjetty,
					    int timeout,
					    struct ubcore_bind_cb *cb,
					    struct ubcore_udata *udata)
{
	struct ubcore_vtp_param vtp_param = { 0 };
	struct ubcore_device *dev;
	struct ubcore_vtpn *vtpn;
	struct ubcore_vtpn_cb_para para = { 0 };
	int ret;

	dev = jetty->ub_dev;

	if (!dev->ops || !dev->ops->bind_jetty ||
	    !dev->ops->unbind_jetty) {
		ubcore_log_err(
			"Failed to bind jetty async, no bind/unbind ops\n");
		return -EINVAL;
	}

	ret = dev->ops->bind_jetty(jetty, tjetty, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to bind jetty async, ret: %d.\n",
			ret);
		return ret;
	}
	atomic_inc(&jetty->use_cnt);

	para.type = UBCORE_BIND_JETTY_VTPN;
	para.tjetty = tjetty;
	para.jetty = jetty;
	para.bind_cb = cb;

	if (!is_create_rc_shared_tp(jetty->jetty_cfg.trans_mode,
				    jetty->jetty_cfg.flag.bs.order_type,
				    tjetty->cfg.flag.bs.share_tp)) {
		ubcore_set_vtp_param(dev, jetty, &tjetty->cfg, &vtp_param);
		mutex_lock(&tjetty->lock);

		if (tjetty->vtpn) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Duplicate bind\n");
			ret = -EEXIST;
			goto unbind;
		}
		vtpn = ubcore_connect_vtp_async(dev, &vtp_param, timeout,
						&para);
		if (IS_ERR_OR_NULL(vtpn)) {
			mutex_unlock(&tjetty->lock);
			ubcore_log_err("Failed to setup vtp connection.\n");
			ret = -1;
			if (vtpn)
				ret = PTR_ERR(vtpn);
			goto unbind;
		}
		tjetty->vtpn = vtpn;
		mutex_unlock(&tjetty->lock);
	} else {
		if (cb) {
			cb->callback(jetty, tjetty, 0, cb->user_arg);
			kfree(cb);
		}
	}
	return 0;

unbind:
	if (dev->ops->bind_jetty && dev->ops->unbind_jetty) {
		(void)dev->ops->unbind_jetty(jetty);
		atomic_dec(&jetty->use_cnt);
	}
	return ret;
}

static int ubcore_inner_bind_jetty_async(struct ubcore_jetty *jetty,
					 struct ubcore_tjetty *tjetty,
					 int timeout, struct ubcore_bind_cb *cb,
					 struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	dev = jetty->ub_dev;
	if (!dev) {
		ubcore_log_err("Invalid parameter with dev null_ptr.\n");
		return -EINVAL;
	}

	if (dev->attr.dev_cap.max_eid_cnt <= tjetty->cfg.eid_index) {
		ubcore_log_err("eid_index:%u is beyond the max_eid_cnt:%u.\n",
			       tjetty->cfg.eid_index,
			       dev->attr.dev_cap.max_eid_cnt);
		return -EINVAL;
	}

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		ret = ubcore_inner_bind_ub_jetty_async(jetty, tjetty, timeout,
						       cb, udata);
		if (ret != 0)
			return ret;
	}
	ubcore_log_info_rl("jetty: %u bind tjetty async: %u\n",
			   jetty->jetty_id.id, tjetty->cfg.id.id);
	jetty->remote_jetty = tjetty;
	atomic_inc(&tjetty->use_cnt);
	return 0;
}

int ubcore_bind_jetty_async(struct ubcore_jetty *jetty,
			    struct ubcore_tjetty *tjetty, int timeout,
			    struct ubcore_bind_cb *cb,
			    struct ubcore_udata *udata)
{
	if (!jetty || !tjetty || !cb ||
	    !ubcore_have_ops(jetty->ub_dev)) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	if ((jetty->jetty_cfg.trans_mode != UBCORE_TP_RC) ||
	    (tjetty->cfg.trans_mode != UBCORE_TP_RC)) {
		ubcore_log_err("trans mode is not rc type.\n");
		return -EINVAL;
	}
	if (jetty->remote_jetty == tjetty) {
		ubcore_log_info("bind reentry, jetty: %u bind tjetty: %u\n",
				jetty->jetty_id.id, tjetty->cfg.id.id);
		if (cb) {
			cb->callback(jetty, tjetty, 0, cb->user_arg);
			kfree(cb);
		}
		return 0;
	}
	if (jetty->remote_jetty) {
		ubcore_log_err(
			"The same jetty, different tjetty, prevent duplicate bind.\n");
		return -EINVAL;
	}
	if (tjetty->vtpn &&
	    (!is_create_rc_shared_tp(tjetty->cfg.trans_mode,
				     tjetty->cfg.flag.bs.order_type,
				     tjetty->cfg.flag.bs.share_tp))) {
		ubcore_log_err(
			"The tjetty, has already connect vtpn, prevent duplicate bind.\n");
		return -EINVAL;
	}

	return ubcore_inner_bind_jetty_async(jetty, tjetty, timeout, cb, udata);
}
EXPORT_SYMBOL(ubcore_bind_jetty_async);

static int ubcore_inner_unbind_ub_jetty_async(struct ubcore_jetty *jetty,
					      struct ubcore_tjetty *tjetty,
					      int timeout,
					      struct ubcore_unbind_cb *cb)
{
	struct ubcore_vtpn_cb_para para = { 0 };
	int ret;

	para.type = UBCORE_UNBIND_JETTY_VTPN;
	para.unbind_cb = cb;
	if (tjetty->vtpn) {
		if (!is_create_rc_shared_tp(jetty->jetty_cfg.trans_mode,
					    jetty->jetty_cfg.flag.bs.order_type,
					    tjetty->cfg.flag.bs.share_tp)) {
			mutex_lock(&tjetty->lock);
			ret = ubcore_disconnect_vtp_async(tjetty->vtpn, timeout,
							  &para);
			if (ret != 0) {
				mutex_unlock(&tjetty->lock);
				ubcore_log_err("Failed to disconnect vtp.\n");
				return ret;
			}
			tjetty->vtpn = NULL;
			mutex_unlock(&tjetty->lock);
		}
	}
	return 0;
}

int ubcore_unbind_jetty_async(struct ubcore_jetty *jetty, int timeout,
			      struct ubcore_unbind_cb *cb)
{
	struct ubcore_tjetty *tjetty;
	struct ubcore_device *dev;
	int ret;

	if (!jetty || !jetty->ub_dev) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	tjetty = jetty->remote_jetty;
	if ((jetty->jetty_cfg.trans_mode != UBCORE_TP_RC) || !tjetty ||
	    (tjetty->cfg.trans_mode != UBCORE_TP_RC)) {
		ubcore_log_err("trans mode is not rc type.\n");
		return -EINVAL;
	}

	dev = jetty->ub_dev;

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		ret = ubcore_inner_unbind_ub_jetty_async(jetty, tjetty, timeout,
							 cb);
		if (ret != 0)
			return ret;
	}

	ubcore_log_info_rl("jetty: %u unbind tjetty async: %u\n",
			   jetty->jetty_id.id, tjetty->cfg.id.id);

	if (dev->transport_type == UBCORE_TRANSPORT_UB) {
		if (!dev->ops || !dev->ops->bind_jetty ||
		    !dev->ops->unbind_jetty) {
			ubcore_log_err(
				"Failed to unbind jetty, no ops->unbind_jetty\n");
			return -EINVAL;
		}
		ret = dev->ops->unbind_jetty(jetty);
		if (ret != 0) {
			ubcore_log_err("[DRV_ERROR]Failed to unbind jetty, ret: %d.\n",
				ret);
			return ret;
		}
	}

	jetty->remote_jetty = NULL;
	atomic_dec(&tjetty->use_cnt);
	atomic_dec(&jetty->use_cnt);
	return 0;
}
EXPORT_SYMBOL(ubcore_unbind_jetty_async);

int ubcore_alloc_jetty(struct ubcore_device *dev, struct ubcore_jetty_cfg *cfg,
	ubcore_event_callback_t jfae_handler,
	struct ubcore_jetty **jetty, struct ubcore_udata *udata)
{
	int ret;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->alloc_jetty == NULL ||
		dev->ops->free_jetty == NULL || !ubcore_eid_valid(dev, cfg->eid_index, udata))
		return -EINVAL;

	ret = dev->ops->alloc_jetty(dev, cfg, jetty, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to alloc jetty, ret %d.\n", ret);
		return ret;
	}

	if (jetty == NULL || *jetty == NULL) {
		ubcore_log_err("alloc_jetty returns success but jetty is NULL.\n");
		return -EFAULT;
	}

	(*jetty)->ub_dev = dev;

	if (check_and_fill_jetty_attr(&(*jetty)->jetty_cfg, cfg) != 0) {
		ubcore_log_err("jetty cfg is not qualified.\n");
		ret = -EINVAL;
		goto destroy_jetty;
	}

	(*jetty)->uctx = ubcore_get_uctx(udata);
	(*jetty)->jfae_handler = jfae_handler;
	(*jetty)->jetty_id.eid = dev->eid_table.eid_entries[cfg->eid_index].eid;
	if ((*jetty)->jetty_cfg.trans_mode == UBCORE_TP_RC) {
		(*jetty)->tptable = ubcore_create_tptable();
		if ((*jetty)->tptable == NULL) {
			ubcore_log_err("Failed to create tp table in the jetty.\n");
			ret = -ENOMEM;
			goto destroy_jetty;
		}
	} else {
		(*jetty)->tptable = NULL; /* To prevent kernel-mode drivers, malloc is not empty */
	}
	atomic_set(&(*jetty)->use_cnt, 0);
	kref_init(&(*jetty)->ref_cnt);
	init_completion(&(*jetty)->comp);

	atomic_inc(&cfg->send_jfc->use_cnt);
	atomic_inc(&cfg->recv_jfc->use_cnt);

	if (cfg->jfr)
		atomic_inc(&cfg->jfr->use_cnt);

	(*jetty)->jetty_opt.is_actived = false;
	return ret;

destroy_jetty:
	(void)dev->ops->free_jetty(*jetty, udata);
	return ret;
}
EXPORT_SYMBOL(ubcore_alloc_jetty);

int ubcore_free_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata)
{
	struct ubcore_jetty_group *jetty_grp;
	struct ubcore_jfc *send_jfc;
	struct ubcore_jfc *recv_jfc;
	struct ubcore_device *dev;
	struct ubcore_jfr *jfr;
	uint32_t jetty_id;
	int ret;

	if (ubcore_check_jetty_attr(jetty) != 0)
		return -EINVAL;

	if (jetty->jetty_opt.is_actived == true) {
		ubcore_log_err("The jetty is still activated, please deactivate first.");
		return -EINVAL;
	}

	jetty_grp = jetty->jetty_cfg.jetty_grp;
	send_jfc = jetty->jetty_cfg.send_jfc;
	recv_jfc = jetty->jetty_cfg.recv_jfc;
	jfr = jetty->jetty_cfg.jfr;
	jetty_id = jetty->jetty_id.id;
	dev = jetty->ub_dev;

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

	ubcore_put_jetty(jetty);
	wait_for_completion(&jetty->comp);

	if (jetty_grp != NULL) {
		(void)ubcore_remove_jetty_from_jetty_grp(jetty, jetty_grp);
		jetty->jetty_cfg.jetty_grp = NULL;
	}
	ret = dev->ops->free_jetty(jetty, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to destroy jetty, ret: %d, jetty_id:%u.\n",
			ret, jetty_id);
		kref_init(&jetty->ref_cnt);
		return ret;
	}

	if (send_jfc)
		atomic_dec(&send_jfc->use_cnt);
	if (recv_jfc)
		atomic_dec(&recv_jfc->use_cnt);
	if (jfr)
		atomic_dec(&jfr->use_cnt);

	return ret;
}
EXPORT_SYMBOL(ubcore_free_jetty);

static void ubcore_jetty_opt_put_old(struct ubcore_jetty *jetty, uint64_t opt)
{
	switch (opt) {
	case UBCORE_JETTY_BIND_RX_JFC: {
		struct ubcore_jfc *recv_jfc = jetty->jetty_cfg.recv_jfc;

		if (recv_jfc)
			atomic_dec(&recv_jfc->use_cnt);
		break;
	}
	case UBCORE_JETTY_BIND_JFR: {
		struct ubcore_jfr *jfr = jetty->jetty_cfg.jfr;

		if (jfr)
			atomic_dec(&jfr->use_cnt);
		break;
	}
	case UBCORE_JFS_BIND_JFC: {
		struct ubcore_jfc *send_jfc = jetty->jetty_cfg.send_jfc;

		if (send_jfc)
			atomic_dec(&send_jfc->use_cnt);
		break;
	}
	case UBCORE_JETTY_BIND_JTG: {
		struct ubcore_jetty_group *jetty_grp = jetty->jetty_cfg.jetty_grp;

		if (jetty_grp)
			(void)ubcore_remove_jetty_from_jetty_grp(jetty, jetty_grp);
		break;
	}
	default:
		break;
	}
}

static void ubcore_jetty_opt_rollback_old(struct ubcore_jetty *jetty, uint64_t opt)
{
	switch (opt) {
	case UBCORE_JETTY_BIND_RX_JFC: {
		struct ubcore_jfc *recv_jfc = jetty->jetty_cfg.recv_jfc;

		if (recv_jfc)
			atomic_inc(&recv_jfc->use_cnt);
		break;
	}
	case UBCORE_JETTY_BIND_JFR: {
		struct ubcore_jfr *jfr = jetty->jetty_cfg.jfr;

		if (jfr)
			atomic_inc(&jfr->use_cnt);
		break;
	}
	case UBCORE_JFS_BIND_JFC: {
		struct ubcore_jfc *send_jfc = jetty->jetty_cfg.send_jfc;

		if (send_jfc)
			atomic_inc(&send_jfc->use_cnt);
		break;
	}
	case UBCORE_JETTY_BIND_JTG: {
		struct ubcore_jetty_group *jetty_grp = jetty->jetty_cfg.jetty_grp;

		if (jetty_grp)
			(void)ubcore_add_jetty_to_jetty_grp(jetty, jetty_grp);
		break;
	}
	default:
		break;
	}
}

static void ubcore_jetty_opt_get_new(struct ubcore_jetty *jetty, uint64_t opt)
{
	switch (opt) {
	case UBCORE_JETTY_BIND_RX_JFC: {
		struct ubcore_jfc *recv_jfc = jetty->jetty_cfg.recv_jfc;

		if (recv_jfc)
			atomic_inc(&recv_jfc->use_cnt);
		break;
	}
	case UBCORE_JETTY_BIND_JFR: {
		struct ubcore_jfr *jfr = jetty->jetty_cfg.jfr;

		if (jfr)
			atomic_inc(&jfr->use_cnt);
		break;
	}
	case UBCORE_JFS_BIND_JFC: {
		struct ubcore_jfc *send_jfc = jetty->jetty_cfg.send_jfc;

		if (send_jfc)
			atomic_inc(&send_jfc->use_cnt);
		break;
	}
	case UBCORE_JETTY_BIND_JTG: {
		struct ubcore_jetty_group *jetty_grp = jetty->jetty_cfg.jetty_grp;

		if (jetty_grp)
			(void)ubcore_add_jetty_to_jetty_grp(jetty, jetty_grp);
		break;
	}
	default:
		break;
	}
}

int ubcore_set_jetty_opt(struct ubcore_jetty *jetty, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	if (jetty == NULL || opt == 0 || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->set_jetty_opt == NULL || buf == NULL)
		return -EINVAL;

	ret = ubcore_check_opt_valid(NULL, g_ubcore_jetty_opt_table,
		g_ubcore_jetty_opt_map_count, opt, len);
	if (ret != 0) {
		ubcore_log_err("invalid opt.\n");
		return ret;
	}

	ubcore_jetty_opt_put_old(jetty, opt);
	dev = jetty->ub_dev;
	ret = dev->ops->set_jetty_opt(jetty, opt, buf, len, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to set_jetty_opt, id:%u, ret %d, opt %llu.\n",
			jetty->jetty_id.id, ret, opt);
		return ret;
	}
	ret = ubcore_set_options_common(g_ubcore_jetty_opt_table,
		g_ubcore_jetty_opt_map_count, opt, buf, len,
		&jetty->jetty_cfg, &jetty->jetty_opt.jfs_opt);
	if (ret != 0) {
		ubcore_log_err("ubcore_set_options_common failed, jetty_id:%u, ret %d, opt %llu.\n",
			jetty->jetty_id.id, ret, opt);
		ubcore_jetty_opt_rollback_old(jetty, opt);
		return ret;
	}
	ubcore_jetty_opt_get_new(jetty, opt);
	return ret;
}
EXPORT_SYMBOL(ubcore_set_jetty_opt);

int ubcore_get_jetty_opt(struct ubcore_jetty *jetty, uint64_t opt, void *buf, uint32_t len,
	struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	if (jetty == NULL || opt == 0 || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->get_jetty_opt == NULL || buf == NULL)
		return -EINVAL;

	ret = ubcore_check_opt_valid(NULL, g_ubcore_jetty_opt_table,
		g_ubcore_jetty_opt_map_count, opt, len);
	if (ret != 0) {
		ubcore_log_err("invalid opt.\n");
		return ret;
	}

	dev = jetty->ub_dev;
	ret = dev->ops->get_jetty_opt(jetty, opt, buf, len, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_jetty_opt, id:%u, ret is %d.\n",
			jetty->jetty_id.id, ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_jetty_opt);

int ubcore_active_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata)
{
	struct ubcore_device *dev = jetty->ub_dev;
	struct ubcore_jetty_cfg *cfg = &jetty->jetty_cfg;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->active_jetty == NULL ||
		jetty->ub_dev->ops->deactive_jetty == NULL)
		return -EINVAL;

	if (ubcore_jetty_pre_check(dev, cfg) != 0)
		return -EINVAL;

	if (jetty->jetty_cfg.jfr->jfr_opt.is_actived == false ||
		jetty->jetty_cfg.recv_jfc->jfc_opt.is_actived == false) {
		ubcore_log_err("jetty's jfr or jfc is not activated.\n");
		return -EINVAL;
	}

	ret = dev->ops->active_jetty(jetty, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to activate jetty, id:%u, ret: %d.\n",
			jetty->jetty_id.id, ret);
		return ret;
	}
	if (cfg->jetty_grp != NULL && ubcore_add_jetty_to_jetty_grp(jetty,
			(struct ubcore_jetty_group *)cfg->jetty_grp) != 0) {
		ubcore_log_err("jetty cfg is not qualified.\n");
		ret = -EPERM;
		goto destroy_jetty;
	}

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_JETTY],
		&jetty->hnode, jetty->jetty_id.id);
	if (ret != 0) {
		ubcore_log_err("Failed to add jetty, ret: %d.\n", ret);
		goto delete_jetty_to_grp;
	}
	jetty->jetty_opt.is_actived = true;

	return ret;

delete_jetty_to_grp:
	(void)ubcore_remove_jetty_from_jetty_grp(
		jetty, (struct ubcore_jetty_group *)cfg->jetty_grp);
destroy_jetty:
	(void)dev->ops->deactive_jetty(jetty, udata);
	return ret;
}
EXPORT_SYMBOL(ubcore_active_jetty);

int ubcore_deactive_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata)
{
	struct ubcore_device *dev;
	int ret;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
		jetty->ub_dev->ops->deactive_jetty == NULL)
		return -EINVAL;

	if (!jetty->jetty_opt.is_actived) {
		ubcore_log_err("jetty has deactived.\n");
		return -EINVAL;
	}

	dev = jetty->ub_dev;
	ret = ubcore_hash_table_check_remove(&dev->ht[UBCORE_HT_JETTY], &jetty->hnode);
	ubcore_log_info("remove jetty from hashtable, ret: %d.", ret);
	ret = dev->ops->deactive_jetty(jetty, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to deactivate jetty, id:%u, ret: %d.\n",
			jetty->jetty_id.id, ret);
		return ret;
	}
	jetty->jetty_opt.is_actived = false;
	return ret;
}
EXPORT_SYMBOL(ubcore_deactive_jetty);

struct ubcore_jfs *ubcore_find_get_jfs(struct ubcore_device *dev, uint32_t jfs_id)
{
	if (dev == NULL) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_JFS], jfs_id, &jfs_id);
}
EXPORT_SYMBOL(ubcore_find_get_jfs);

struct ubcore_jfr *ubcore_find_get_jfr(struct ubcore_device *dev, uint32_t jfr_id)
{
	if (dev == NULL) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_JFR], jfr_id, &jfr_id);
}

struct ubcore_jetty *ubcore_find_get_jetty(struct ubcore_device *dev, uint32_t jetty_id)
{
	if (dev == NULL) {
		ubcore_log_err("dev is NULL\n");
		return NULL;
	}
	return ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_JETTY], jetty_id, &jetty_id);
}
