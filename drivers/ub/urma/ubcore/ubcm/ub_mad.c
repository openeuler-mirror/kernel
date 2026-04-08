// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ub_mad implementation
 * Author: Chen Yutao
 * Create: 2025-01-10
 * Note:
 * History: 2025-01-10: create file
 */

#include <linux/list.h>
#include <linux/jhash.h>
#include <ub/urma/ubcore_uapi.h>
#include <ub/urma/ubcore_api.h>
#include "ubcore_tp.h"
#include "ubcore_log.h"
#include "ub_mad_priv.h"
#include "ubcore_log.h"
#include "ubcore_topo_info.h"

// udma jetty id starts from 1 currently
#define WK_JETTY_ID_INITIALIZER                  \
	{                                            \
		UBMAD_WK_JETTY_ID_0, UBMAD_WK_JETTY_ID_1 \
	}
static const uint32_t g_ubmad_wk_jetty_id[UBMAD_WK_JETTY_NUM] =
	WK_JETTY_ID_INITIALIZER;

static struct list_head g_ubmad_device_list;
static DEFINE_SPINLOCK(g_ubmad_device_list_lock);

static struct list_head g_ubmad_agent_list;
static DEFINE_SPINLOCK(g_ubmad_agent_list_lock);
static DEFINE_MUTEX(g_ubc_eid_lock);

/* forward declaration */
// device
static int
ubmad_create_device_priv_resources(struct ubmad_device_priv *dev_priv);
static void
ubmad_destroy_device_priv_resources(struct ubmad_device_priv *dev_priv);
static struct ubmad_device_priv *
ubmad_get_device_priv_lockless(struct ubcore_device *device);

/* common */
struct ubmad_bitmap *ubmad_create_bitmap(uint32_t bitmap_size)
{
	struct ubmad_bitmap *bitmap;

	bitmap = kcalloc(1, sizeof(struct ubmad_bitmap), GFP_KERNEL);
	if (IS_ERR_OR_NULL(bitmap))
		return ERR_PTR(-ENOMEM);
	bitmap->size = bitmap_size;
	bitmap->bits = kcalloc(BITS_TO_LONGS(bitmap_size),
			       sizeof(unsigned long), GFP_KERNEL);
	if (IS_ERR_OR_NULL(bitmap->bits)) {
		kfree(bitmap);
		return ERR_PTR(-ENOMEM);
	}
	spin_lock_init(&bitmap->lock);
	return bitmap;
}

void ubmad_destroy_bitmap(struct ubmad_bitmap *bitmap)
{
	if (bitmap->bits != NULL)
		kfree(bitmap->bits);
	kfree(bitmap);
}

uint32_t ubmad_bitmap_get_id(struct ubmad_bitmap *bitmap)
{
	uint32_t id;

	spin_lock(&bitmap->lock);
	id = find_first_zero_bit(bitmap->bits, bitmap->size);
	if (id >= bitmap->size) {
		spin_unlock(&bitmap->lock);
		ubcore_log_err("bitmap find zero bit failed\n");
		return id;
	}
	set_bit(id, bitmap->bits);
	spin_unlock(&bitmap->lock);
	return id;
}

int ubmad_bitmap_put_id(struct ubmad_bitmap *bitmap, uint32_t id)
{
	spin_lock(&bitmap->lock);
	if (id >= bitmap->size) {
		spin_unlock(&bitmap->lock);
		ubcore_log_err("invalid id %u\n", id);
		return -EINVAL;
	}
	clear_bit(id, bitmap->bits);
	spin_unlock(&bitmap->lock);
	return 0;
}

bool ubmad_bitmap_test_id(struct ubmad_bitmap *bitmap, uint32_t id)
{
	bool result;

	spin_lock(&bitmap->lock);
	if (id >= bitmap->size) {
		spin_unlock(&bitmap->lock);
		ubcore_log_err("invalid id %u\n", id);
		return false;
	}
	result = test_bit(id, bitmap->bits) == 0;
	set_bit(id, bitmap->bits);
	spin_unlock(&bitmap->lock);

	return result;
}

int ubmad_bitmap_set_id(struct ubmad_bitmap *bitmap, uint32_t id)
{
	spin_lock(&bitmap->lock);
	if (id >= bitmap->size) {
		spin_unlock(&bitmap->lock);
		ubcore_log_err("invalid id %u\n", id);
		return -1;
	}

	set_bit(id, bitmap->bits);
	spin_unlock(&bitmap->lock);
	return 0;
}

/* ubcore event ops */
// re-create dev resources when add eid after open dev
static void ubmad_event_cb(struct ubcore_event *event,
			   struct ubcore_event_handler *handler)
{
	switch (event->event_type) {
	case UBCORE_EVENT_EID_CHANGE:
		ubcore_log_info("No need to handle eid event.\n");
		break;
	default:
		ubcore_log_err("Invalid event_type: %d, dev_name: %s.\n",
			     event->event_type, event->ub_dev->dev_name);
		break;
	}
}

static int ubmad_check_eid_in_dev(struct ubcore_device *dev,
				  struct ubcore_eid_info *eid_info)
{
	int i;

	if (IS_ERR_OR_NULL(eid_info) || IS_ERR_OR_NULL(dev->eid_table.eid_entries))
		return -1;

	spin_lock(&dev->eid_table.lock);
	for (i = 0; i < dev->eid_table.eid_cnt; i++) {
		if (memcmp(&dev->eid_table.eid_entries[i].eid, &eid_info->eid,
			   sizeof(union ubcore_eid)) == 0 &&
		    dev->eid_table.eid_entries[i].eid_index ==
			    eid_info->eid_index) {
			spin_unlock(&dev->eid_table.lock);
			return 0;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	return -1;
}

static int
ubmad_update_device_priv_resources(struct ubmad_device_priv *dev_priv,
				   struct ubcore_eid_info *eid_info)
{
	int ret;

	if (memcmp(&dev_priv->eid_info.eid, &eid_info->eid,
		   sizeof(union ubcore_eid)) == 0 &&
	    dev_priv->eid_info.eid_index == eid_info->eid_index) {
		ubcore_log_warn(
			"eid_info is not changed, no need to update rsrc\n");
		return 0;
	}
	ubmad_destroy_device_priv_resources(dev_priv);
	dev_priv->has_create_jetty_rsrc = false;

	(void)memcpy(&dev_priv->eid_info.eid, &eid_info->eid,
		     sizeof(union ubcore_eid));
	dev_priv->eid_info.eid_index = eid_info->eid_index;
	ret = ubmad_create_device_priv_resources(dev_priv);
	if (ret != 0) {
		ubcore_log_err("Failed to create device resources, ret: %d.\n",
			     ret);
		return ret;
	}
	dev_priv->has_create_jetty_rsrc = true;
	ubcore_log_info(
		"Success to update priv resources: dev: %s eid_idx %d, eid: " EID_FMT,
		dev_priv->device->dev_name, dev_priv->eid_info.eid_index,
		EID_ARGS(dev_priv->eid_info.eid));
	return 0;
}

static int ubmad_ubc_eid_ops_inner(struct ubcore_device *dev,
				   struct ubcore_eid_info *eid_info,
				   enum ubcore_mgmt_event_type event_type)
{
	struct ubmad_device_priv *dev_priv;
	unsigned long flag;
	int ret;

	spin_lock_irqsave(&g_ubmad_device_list_lock, flag);
	dev_priv = ubmad_get_device_priv_lockless(dev);
	spin_unlock_irqrestore(&g_ubmad_device_list_lock, flag);
	if (IS_ERR_OR_NULL(dev_priv)) {
		ubcore_log_err("Failed to get dev_priv, dev_name: %s\n",
			     dev->dev_name);
		return -1;
	}
	switch (event_type) {
	case UBCORE_MGMT_EVENT_EID_ADD:
		if (dev_priv->has_create_jetty_rsrc) {
			ret = ubmad_update_device_priv_resources(dev_priv,
								 eid_info);
			if (ret != 0)
				ubcore_log_err(
					"Failed to update device resources, ret: %d.\n",
					ret);
		} else {
			(void)memcpy(&dev_priv->eid_info.eid, &eid_info->eid,
				     sizeof(union ubcore_eid));
			dev_priv->eid_info.eid_index = eid_info->eid_index;
			ret = ubmad_create_device_priv_resources(dev_priv);
			if (ret != 0)
				ubcore_log_err(
					"Failed to create device resources, ret: %d.\n",
					ret);
			else
				dev_priv->has_create_jetty_rsrc = true;
		}
		break;
	case UBCORE_MGMT_EVENT_EID_RMV:
		ubmad_destroy_device_priv_resources(dev_priv);
		dev_priv->has_create_jetty_rsrc = false;
		ret = 0;
		break;
	default:
		ubcore_log_err("Invali event_type: %d.\n", event_type);
		ret = -EINVAL;
	}
	ubcore_log_info("Finish to handle new eid, ret: %d, event_type: %d.\n",
		      ret, (int)event_type);
	ubmad_put_device_priv(dev_priv);
	return ret;
}

// re-create dev resources when dispatch management event
static int ubmad_ubc_eid_ops(struct ubcore_device *dev,
			     struct ubcore_eid_info *eid_info,
			     enum ubcore_mgmt_event_type event_type)
{
	union ubcore_eid main_primary_eid = {0};
	int ret;

	mutex_lock(&g_ubc_eid_lock);
	if (ubmad_check_eid_in_dev(dev, eid_info) != 0) {
		mutex_unlock(&g_ubc_eid_lock);
		ubcore_log_err("Eid is not in dev, dev_name: %s, eid: " EID_FMT
			     ", eid_index: %u.\n",
			     dev->dev_name, EID_ARGS(eid_info->eid),
			     eid_info->eid_index);
		return -1;
	}

	ret = ubcore_get_main_primary_eid(&eid_info->eid, &main_primary_eid);
	if (ret != 0) {
		mutex_unlock(&g_ubc_eid_lock);
		ubcore_log_err("Invalid eid "EID_FMT".\n", EID_ARGS(eid_info->eid));
		return -1;
	}

	if (memcmp(&eid_info->eid, &main_primary_eid,
		sizeof(union ubcore_eid)) != 0) {
		mutex_unlock(&g_ubc_eid_lock);
		ubcore_log_warn("No need to operate current eid "EID_FMT".\n",
			EID_ARGS(eid_info->eid));
		return 0;
	}

	ret = ubmad_ubc_eid_ops_inner(dev, eid_info, event_type);
	if (ret != 0) {
		mutex_unlock(&g_ubc_eid_lock);
		ubcore_log_err("Failed to handle eid_ops_called, ret: %d.\n",
			     ret);
		return ret;
	}
	mutex_unlock(&g_ubc_eid_lock);
	return 0;
}

/* jetty ops */
static struct ubcore_jfc *ubmad_create_jfc_s(struct ubcore_device *device)
{
	struct ubcore_jfc_cfg jfc_cfg = { 0 };
	struct ubcore_jfc *jfc = NULL;
	int rearm_ret;

	jfc_cfg.depth = UBMAD_JFS_DEPTH;
	jfc = ubcore_create_jfc(device, &jfc_cfg, ubmad_jfce_handler_s, NULL,
				NULL);
	if (IS_ERR_OR_NULL(jfc)) {
		ubcore_log_err("create jfc_s failed\n");
		return jfc;
	}

	rearm_ret = ubcore_rearm_jfc(jfc, false);
	if (rearm_ret != 0) {
		ubcore_log_err("rearm jfc_s failed. ret %d\n", rearm_ret);
		return NULL;
	}

	return jfc;
}

static struct ubcore_jfc *ubmad_create_jfc_r(struct ubcore_device *device)
{
	struct ubcore_jfc_cfg jfc_cfg = { 0 };
	struct ubcore_jfc *jfc = NULL;
	int rearm_ret;

	jfc_cfg.depth = UBMAD_JFR_DEPTH;
	jfc = ubcore_create_jfc(device, &jfc_cfg, ubmad_jfce_handler_r, NULL,
				NULL);
	if (IS_ERR_OR_NULL(jfc)) {
		ubcore_log_err("create jfc_r failed\n");
		return jfc;
	}

	rearm_ret = ubcore_rearm_jfc(jfc, false);
	if (rearm_ret != 0) {
		ubcore_log_err("rearm jfc_r failed. ret %d\n", rearm_ret);
		return NULL;
	}

	return jfc;
}

static struct ubcore_jfr *ubmad_create_jfr(struct ubmad_device_priv *dev_priv,
					   struct ubcore_jfc *jfc_r)
{
	struct ubcore_jfr_cfg jfr_cfg = { 0 };

	jfr_cfg.id = 0U;
	jfr_cfg.depth = UBMAD_JFR_DEPTH;
	jfr_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	jfr_cfg.trans_mode = UBCORE_TP_UM;
	jfr_cfg.eid_index = dev_priv->eid_info.eid_index;
	jfr_cfg.max_sge = UBMAD_JFR_MAX_SGE_NUM;
	jfr_cfg.jfc = jfc_r;

	return ubcore_create_jfr(dev_priv->device, &jfr_cfg, NULL, NULL);
}

static int ubmad_jetty_set_priority(struct ubmad_device_priv *dev_priv,
		  struct ubcore_jetty_cfg *jetty_cfg)
{
	struct ubcore_device_attr attr = {0};
	int set_priority_ret = 0;
	int ret = 0;
	int i;

	ret = ubcore_query_device_attr(dev_priv->device, &attr);
	if (ret == 0) {
		for (i = 0; i < UBCORE_MAX_PRIORITY_CNT; ++i) {
			/* No priority supports utp currently, so rtp priority used */
			if (attr.dev_cap.priority_info[i].tp_type.bs.rtp == 1) {
				jetty_cfg->priority = i;
				ubcore_log_info(
					"ubmad create jetty set priority : %d, tp_type : ctp\n", i);
				set_priority_ret = 1;
				break;
			}
		}
		if (set_priority_ret == 0) {
			ubcore_log_err("set priority default value : 0\n");
			return -EINVAL;
		}
	} else {
		ubcore_log_err("Failed to ubcore get dev_attr!\n");
		return -EINVAL;
	}
	return 0;
}

static struct ubcore_jetty *
ubmad_create_jetty(struct ubmad_device_priv *dev_priv, struct ubcore_jfc *jfc_s,
		   struct ubcore_jfc *jfc_r, struct ubcore_jfr *jfr,
		   uint32_t jetty_id)
{
	struct ubcore_jetty_cfg jetty_cfg = { 0 };
	int ret = 0;

	jetty_cfg.id = jetty_id;
	jetty_cfg.flag.bs.share_jfr = 1;
	jetty_cfg.trans_mode = UBCORE_TP_UM;
	jetty_cfg.eid_index = dev_priv->eid_info.eid_index;
	jetty_cfg.jfs_depth = UBMAD_JFS_DEPTH;
	jetty_cfg.priority = 0;
	ret = ubmad_jetty_set_priority(dev_priv, &jetty_cfg);
	if (ret)
		ubcore_log_info("ubmad create jetty set priority : 0\n");
	jetty_cfg.max_send_sge = UBMAD_JFS_MAX_SGE_NUM;
	jetty_cfg.max_send_rsge = UBMAD_JFS_MAX_SGE_NUM;
	jetty_cfg.jfr_depth = UBMAD_JFR_DEPTH;
	jetty_cfg.max_recv_sge = UBMAD_JFR_MAX_SGE_NUM;
	jetty_cfg.send_jfc = jfc_s;
	jetty_cfg.recv_jfc = jfc_r;
	jetty_cfg.jfr = jfr;
	jetty_cfg.err_timeout = UBMAD_JETTY_ERR_TIMEOUT;

	return ubcore_create_jetty(dev_priv->device, &jetty_cfg, NULL, NULL);
}

static struct ubmad_tjetty *
ubmad_get_tjetty_lockless(struct ubmad_jetty_resource *rsrc, uint32_t hash,
			  union ubcore_eid *dst_eid)
{
	struct ubmad_tjetty *tjetty;
	struct hlist_node *next;

	hlist_for_each_entry_safe(tjetty, next, &rsrc->tjetty_hlist[hash],
				  node) {
		if (memcmp(&tjetty->tjetty->cfg.id.eid, dst_eid,
			   sizeof(union ubcore_eid)) == 0) {
			kref_get(&tjetty->kref);
			return tjetty;
		}
	}
	return NULL;
}

struct ubmad_tjetty *ubmad_get_tjetty(union ubcore_eid *dst_eid,
				      struct ubmad_jetty_resource *rsrc)
{
	unsigned long flag;
	uint32_t hash = jhash(dst_eid, sizeof(union ubcore_eid), 0) %
			UBMAD_MAX_TJETTY_NUM;
	struct ubmad_tjetty *tjetty = NULL;

	spin_lock_irqsave(&rsrc->tjetty_hlist_lock, flag);
	tjetty = ubmad_get_tjetty_lockless(rsrc, hash, dst_eid);
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);

	return tjetty;
}

static void ubmad_release_tjetty(struct kref *kref)
{
	struct ubmad_tjetty *tjetty =
		container_of(kref, struct ubmad_tjetty, kref);
	int ret;

	ubmad_uninit_msn_mgr(&tjetty->msn_mgr);

	ret = ubcore_unimport_jetty(tjetty->tjetty);
	if (ret != 0)
		ubcore_log_err("Failed to unimport jetty, ret: %d.\n", ret);
	kfree(tjetty);
}

void ubmad_put_tjetty(struct ubmad_tjetty *tjetty)
{
	kref_put(&tjetty->kref, ubmad_release_tjetty);
}

static int ubmad_fill_get_tp_cfg(struct ubcore_device *dev,
				 struct ubcore_get_tp_cfg *get_tp_cfg,
				 struct ubcore_tjetty_cfg *cfg)
{
	uint32_t eid_index = cfg->eid_index;

	get_tp_cfg->flag.bs.ctp = 0;
	get_tp_cfg->flag.bs.rtp = 0;
	get_tp_cfg->flag.bs.utp = 1;

	get_tp_cfg->trans_mode = cfg->trans_mode;

	spin_lock(&dev->eid_table.lock);
	if (eid_index >= dev->eid_table.eid_cnt ||
	    dev->eid_table.eid_entries == NULL ||
	    dev->eid_table.eid_entries[eid_index].valid == false) {
		spin_unlock(&dev->eid_table.lock);
		ubcore_log_err("Invalid parameter, eid_index: %u.\n",
			       eid_index);
		return -EINVAL;
	}
	/* Need to adapt bonding primary eid */
	get_tp_cfg->local_eid = dev->eid_table.eid_entries[eid_index].eid;
	spin_unlock(&dev->eid_table.lock);
	get_tp_cfg->peer_eid = cfg->id.eid;

	return 0;
}

static struct ubcore_tjetty *
ubmad_import_jetty_compat(struct ubcore_device *dev,
			  struct ubcore_tjetty_cfg *cfg,
			  struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct ubcore_get_tp_cfg get_tp_cfg = { 0 };
	struct ubcore_tp_info tp_list = { 0 };
	struct ubcore_tjetty *tjetty = NULL;
	uint32_t tp_cnt = 1;
	int ret;

	if (!ubcore_have_tp_ctrlplane_ops(dev) ||
	    dev->ops->unimport_jfr == NULL || cfg == NULL ||
	    dev->attr.dev_cap.max_eid_cnt <= cfg->eid_index)
		return ERR_PTR(-EINVAL);

	if (ubmad_fill_get_tp_cfg(dev, &get_tp_cfg, cfg) != 0)
		return NULL;

	ret = ubcore_get_tp_list(dev, &get_tp_cfg, &tp_cnt, &tp_list, NULL);
	if (ret != 0 || tp_cnt != 1) {
		ubcore_log_err("Failed to get tp list, ret: %d, tp_cnt: %u.\n",
			       ret, tp_cnt);
		return NULL;
	}
	active_tp_cfg.tp_handle = tp_list.tp_handle;
	ubcore_log_info("Finish to get tp, tpid: %u, tp_cnt: %u, leid: " EID_FMT
			", deid: " EID_FMT ".\n",
			(uint32_t)tp_list.tp_handle.bs.tpid,
			(uint32_t)tp_list.tp_handle.bs.tp_cnt,
			EID_ARGS(get_tp_cfg.local_eid),
			EID_ARGS(get_tp_cfg.peer_eid));

	tjetty = ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(tjetty))
		ubcore_log_err("Failed to import jetty ex.\n");

	return tjetty;
}

/* need to put twice to release tjetty.
 * First put for kref_get() is called by user after finish using tjetty locally.
 * Second put for kref_init() is in ubmad_unimport_jetty().
 */
struct ubmad_tjetty *ubmad_import_jetty(struct ubcore_device *device,
					struct ubmad_jetty_resource *rsrc,
					union ubcore_eid *dst_eid)
{
	unsigned long flag;
	uint32_t hash = jhash(dst_eid, sizeof(union ubcore_eid), 0) %
			UBMAD_MAX_TJETTY_NUM;
	struct ubmad_tjetty *tjetty = NULL, *new_tjetty = NULL;
	struct ubcore_tjetty *new_target = NULL;
	struct ubcore_tjetty_cfg tjetty_cfg = { 0 };

	/* get first */
	spin_lock_irqsave(&rsrc->tjetty_hlist_lock, flag);
	tjetty = ubmad_get_tjetty_lockless(rsrc, hash, dst_eid); // put by user
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);
	if (!IS_ERR_OR_NULL(tjetty)) {
		ubcore_log_info("tjetty0 already imported. eid " EID_FMT "\n",
			      EID_ARGS(*dst_eid));
		return tjetty;
	}

	/* not exist, import then */
	new_tjetty = kzalloc(sizeof(struct ubmad_tjetty), GFP_KERNEL);
	if (IS_ERR_OR_NULL(new_tjetty))
		return ERR_PTR(-ENOMEM);
	kref_init(&new_tjetty->kref); // put in ubmad_unimport_jetty()

	tjetty_cfg.id.id = rsrc->jetty_id;
	tjetty_cfg.id.eid = *dst_eid;
	tjetty_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	tjetty_cfg.trans_mode = UBCORE_TP_UM;
	tjetty_cfg.type = UBCORE_JETTY;
	tjetty_cfg.eid_index = rsrc->jetty->jetty_cfg.eid_index;
	new_target = ubmad_import_jetty_compat(device, &tjetty_cfg, NULL);
	if (IS_ERR_OR_NULL(new_target)) {
		ubcore_log_err("import tjetty: %u failed. eid " EID_FMT "\n",
			     rsrc->jetty_id, EID_ARGS(*dst_eid));
		goto free;
	}
	new_tjetty->tjetty = new_target;

	ubmad_init_msn_mgr(&new_tjetty->msn_mgr);

	spin_lock_irqsave(&rsrc->tjetty_hlist_lock, flag);
	/* get again in case of concurrence */
	tjetty = ubmad_get_tjetty_lockless(rsrc, hash, dst_eid); // put by user
	if (!IS_ERR_OR_NULL(tjetty)) {
		spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);
		ubcore_log_info(
			"tjetty0 already imported. dev_name: %s, deid " EID_FMT
			".\n",
			device->dev_name, EID_ARGS(*dst_eid));
		goto uninit_msn_mgr;
	}

	/* still not exist, use new_tjetty */
	// kref_get for new imported tjetty to unify put logics with tjetty got from hlist
	kref_get(&new_tjetty->kref);

	// add to hlist
	INIT_HLIST_NODE(&new_tjetty->node);
	hlist_add_head(&new_tjetty->node, &rsrc->tjetty_hlist[hash]);
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);

	ubcore_log_info(
		"import tjetty0 and add to hlist succeeded. dev_name: %s, deid " EID_FMT
		".\n",
		device->dev_name, EID_ARGS(*dst_eid));
	return new_tjetty;

uninit_msn_mgr:
	ubmad_uninit_msn_mgr(&new_tjetty->msn_mgr);
	ubcore_unimport_jetty(new_target);
free:
	kfree(new_tjetty);
	return tjetty;
}

static void ubmad_unimport_jetty(struct ubmad_tjetty *tjetty)
{
	ubmad_put_tjetty(tjetty); // second put for ubmad_import_jetty()
}

void ubmad_remove_tjetty(union ubcore_eid *seid,
			 struct ubmad_jetty_resource *rsrc)
{
	uint32_t hash =
		jhash(seid, sizeof(union ubcore_eid), 0) % UBMAD_MAX_TJETTY_NUM;
	struct ubmad_tjetty *tjetty;
	struct hlist_node *next;
	unsigned long flag;

	ubcore_log_info("Remove tjetty, leid: " EID_FMT ", reid: " EID_FMT ".\n",
		      EID_ARGS(rsrc->jetty->jetty_id.eid), EID_ARGS(*seid));
	spin_lock_irqsave(&rsrc->tjetty_hlist_lock, flag);
	hlist_for_each_entry_safe(tjetty, next, &rsrc->tjetty_hlist[hash],
				  node) {
		if (memcmp(&tjetty->tjetty->cfg.id.eid, seid,
			   sizeof(union ubcore_eid)) == 0) {
			hlist_del(&tjetty->node);
			ubmad_unimport_jetty(tjetty);
		}
	}
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);
}

/* seg ops */
static struct ubcore_target_seg *ubmad_register_seg(struct ubcore_device *dev,
						    uint32_t num_sge)
{
	void *seg_va = NULL;
	union ubcore_reg_seg_flag flag = { 0 };
	uint64_t seg_len = UBMAD_SGE_MAX_LEN * num_sge;
	struct ubcore_seg_cfg cfg = { 0 };
	struct ubcore_target_seg *ret;

	seg_va = kzalloc(seg_len, GFP_KERNEL);
	if (IS_ERR_OR_NULL(seg_va))
		return ERR_PTR(-ENOMEM);
	flag.bs.token_policy = UBCORE_TOKEN_NONE;
	flag.bs.cacheable = UBCORE_NON_CACHEABLE;
	flag.bs.access = UBCORE_ACCESS_LOCAL_ONLY;
	cfg.va = (uint64_t)seg_va;
	cfg.len = seg_len;
	cfg.flag = flag;

	ret = ubcore_register_seg(dev, &cfg, NULL);
	if (IS_ERR_OR_NULL(ret)) {
		ubcore_log_err("reg seg failed\n");
		goto free;
	}
	ubcore_log_info("Finish to register seg, va: 0x%llx, len: %llu", cfg.va,
		      seg_len);
	return ret;

free:
	kfree(seg_va);
	return ret;
}

static void ubmad_unregister_seg(struct ubcore_target_seg *seg)
{
	uint64_t va = seg->seg.ubva.va;

	(void)ubcore_unregister_seg(seg);
	kfree((void *)va);
}

static int ubmad_create_seg(struct ubmad_jetty_resource *rsrc,
			    struct ubcore_device *device)
{
	// send_seg
	rsrc->send_seg = ubmad_register_seg(device, UBMAD_SEND_SGE_NUM);
	if (IS_ERR_OR_NULL(rsrc->send_seg)) {
		ubcore_log_err("register send_seg failed.\n");
		return -1;
	}
	rsrc->send_seg_bitmap = ubmad_create_bitmap(UBMAD_SEND_SGE_NUM);
	if (IS_ERR_OR_NULL(rsrc->send_seg_bitmap)) {
		ubcore_log_err("alloc send_seg_bitmap failed\n");
		goto unreg_send_seg;
	}

	// recv_seg
	rsrc->recv_seg = ubmad_register_seg(device, UBMAD_RECV_SGE_NUM);
	if (IS_ERR_OR_NULL(rsrc->recv_seg)) {
		ubcore_log_err("register recv_seg failed\n");
		goto free_send_seg_bitmap;
	}
	rsrc->recv_seg_bitmap = ubmad_create_bitmap(UBMAD_RECV_SGE_NUM);
	if (IS_ERR_OR_NULL(rsrc->recv_seg_bitmap)) {
		ubcore_log_err("alloc recv_seg_bitmap failed\n");
		rsrc->recv_seg_bitmap = NULL;
		goto unreg_recv_seg;
	}

	return 0;

unreg_recv_seg:
	ubmad_unregister_seg(rsrc->recv_seg);
	rsrc->recv_seg = NULL;
free_send_seg_bitmap:
	ubmad_destroy_bitmap(rsrc->send_seg_bitmap);
	rsrc->send_seg_bitmap = NULL;
unreg_send_seg:
	ubmad_unregister_seg(rsrc->send_seg);
	rsrc->send_seg = NULL;
	return -1;
}

static void ubmad_destroy_seg(struct ubmad_jetty_resource *rsrc)
{
	ubmad_destroy_bitmap(rsrc->recv_seg_bitmap);
	rsrc->recv_seg_bitmap = NULL;
	ubmad_unregister_seg(rsrc->recv_seg);
	rsrc->recv_seg = NULL;

	ubmad_destroy_bitmap(rsrc->send_seg_bitmap);
	rsrc->send_seg_bitmap = NULL;
	ubmad_unregister_seg(rsrc->send_seg);
	rsrc->send_seg = NULL;
}

/* jetty rsrc */
static int ubmad_init_jetty_rsrc(struct ubmad_jetty_resource *rsrc,
				 struct ubmad_device_priv *dev_priv)
{
	struct ubcore_device *device = dev_priv->device;
	struct ubcore_jetty *jetty;
	struct ubcore_jfc *jfc_s;
	struct ubcore_jfc *jfc_r;
	struct ubcore_jfr *jfr;
	uint32_t idx;
	int ret;

	/* create jetty */
	jfc_s = ubmad_create_jfc_s(device);
	if (IS_ERR_OR_NULL(jfc_s)) {
		ubcore_log_err("fail to create jfc_s. dev_name: %s\n",
			     device->dev_name);
		return -1;
	}
	rsrc->jfc_s = jfc_s;

	jfc_r = ubmad_create_jfc_r(device);
	if (IS_ERR_OR_NULL(jfc_r)) {
		ubcore_log_err("fail to create jfc_r. dev_name: %s\n",
			     device->dev_name);
		ret = -1;
		goto del_jfc_s;
	}
	rsrc->jfc_r = jfc_r;

	jfr = ubmad_create_jfr(dev_priv, jfc_r);
	if (IS_ERR_OR_NULL(jfr)) {
		ubcore_log_err("fail to create jfr. dev_name: %s\n",
			     device->dev_name);
		ret = -1;
		goto del_jfc_r;
	}
	rsrc->jfr = jfr;

	jetty = ubmad_create_jetty(dev_priv, jfc_s, jfc_r, jfr, rsrc->jetty_id);
	if (IS_ERR_OR_NULL(jetty)) {
		ubcore_log_err("fail to create wk jetty. dev_name: %s, id: %u.\n",
			     device->dev_name, rsrc->jetty_id);
		ret = -1;
		goto del_jfr;
	}
	atomic_set(&rsrc->tx_in_queue, 0);

	ubcore_log_info("well-known jetty id %u eid " EID_FMT ", jfr id: %u.\n",
		      jetty->jetty_id.id, EID_ARGS(jetty->jetty_id.eid),
		      jfr->jfr_id.id);
	rsrc->jetty = jetty;

	/* create seg */
	ret = ubmad_create_seg(rsrc, device);
	if (ret != 0) {
		ubcore_log_err("create seg failed. device %s.\n",
			     device->dev_name);
		goto del_jetty;
	}

	/* first batch of post_recv */
	for (idx = 0; idx < UBMAD_JFR_DEPTH; idx++) {
		ret = ubmad_post_recv(rsrc);
		if (ret != 0) {
			ubcore_log_err(
				"No. %u post recv in the first batch failed. device %s ret %d\n",
				idx, device->dev_name, ret);
			goto destroy_seg;
		}
	}

	/* tjetty */
	for (idx = 0; idx < UBMAD_MAX_TJETTY_NUM; idx++)
		INIT_HLIST_HEAD(&rsrc->tjetty_hlist[idx]);
	spin_lock_init(&rsrc->tjetty_hlist_lock);

	/* reliable communication */
	ubmad_init_seid_hlist(rsrc);

	return 0;
destroy_seg:
	ubmad_destroy_seg(rsrc);
del_jetty:
	(void)ubcore_delete_jetty(jetty);
del_jfr:
	(void)ubcore_delete_jfr(jfr);
del_jfc_r:
	(void)ubcore_delete_jfc(jfc_r);
del_jfc_s:
	(void)ubcore_delete_jfc(jfc_s);
	return ret;
}

static void ubmad_delete_jetty(struct ubcore_jetty *jetty)
{
	uint32_t jetty_id = jetty->jetty_id.id;
	int ret;

	ret = ubcore_delete_jetty(jetty);
	if (ret != 0)
		ubcore_log_err("Failed to delete jetty, id: %u, ret: %d.\n",
			jetty_id, ret);
}

static void ubmad_delete_jfr(struct ubcore_jfr *jfr)
{
	uint32_t jfr_id = jfr->jfr_id.id;
	int ret;

	ret = ubcore_delete_jfr(jfr);
	if (ret != 0)
		ubcore_log_err("Failed to delete jfr, id: %u, ret: %d.\n",
			jfr_id, ret);
}

static void ubmad_delete_jfc(struct ubcore_jfc *jfc)
{
	uint32_t jfc_id = jfc->id;
	int ret;

	ret = ubcore_delete_jfc(jfc);
	if (ret != 0)
		ubcore_log_err("Failed to delete jfc, id: %u, ret: %d.\n",
			jfc_id, ret);
}

static void ubmad_uninit_jetty_rsrc(struct ubmad_jetty_resource *rsrc)
{
	struct ubmad_tjetty *tjetty;
	struct hlist_node *next;
	unsigned long flag;
	int i;

	/* reliable communication */
	ubmad_uninit_seid_hlist(rsrc);

	/* tjetty */
	spin_lock_irqsave(&rsrc->tjetty_hlist_lock, flag);
	for (i = 0; i < UBMAD_MAX_TJETTY_NUM; i++) {
		hlist_for_each_entry_safe(tjetty, next, &rsrc->tjetty_hlist[i],
					  node) {
			hlist_del(&tjetty->node);
			ubmad_unimport_jetty(tjetty);
		}
	}
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);

	ubmad_destroy_seg(rsrc);
	ubmad_delete_jetty(rsrc->jetty);
	rsrc->jetty = NULL;

	ubmad_delete_jfr(rsrc->jfr);
	rsrc->jfr = NULL;

	ubmad_delete_jfc(rsrc->jfc_r);
	rsrc->jfc_r = NULL;

	ubmad_delete_jfc(rsrc->jfc_s);
	rsrc->jfc_s = NULL;
}

static int ubmad_init_jetty_rsrc_array(struct ubmad_jetty_resource *rsrc_array,
				       struct ubmad_device_priv *dev_priv)
{
	int i, j;
	int ret;

	for (i = 0; i < UBMAD_WK_JETTY_NUM; i++) {
		rsrc_array[i].jetty_id = g_ubmad_wk_jetty_id[i];
		ret = ubmad_init_jetty_rsrc(&rsrc_array[i], dev_priv);
		if (ret != 0) {
			ubcore_log_err(
				"Failed to init jetty rsrc, index: %d, ret: %d.\n",
				i, ret);
			goto uninit_rsrc;
		}
	}
	ubcore_log_info("Finish to init jetty resource.\n");

	return 0;
uninit_rsrc:
	for (j = 0; j < i; j++)
		ubmad_uninit_jetty_rsrc(&rsrc_array[j]);
	return ret;
}

static void
ubmad_uninit_jetty_rsrc_array(struct ubmad_jetty_resource *rsrc_array)
{
	int i;

	for (i = 0; i < UBMAD_WK_JETTY_NUM; i++)
		ubmad_uninit_jetty_rsrc(&rsrc_array[i]);
}

struct ubmad_jetty_resource *
ubmad_get_jetty_rsrc_by_jfc_s(struct ubmad_device_priv *dev_priv,
			      struct ubcore_jfc *jfc_s)
{
	int i;

	/* No need to lock as dev_priv kref_put, so jetty resources are valid */
	for (i = 0; i < UBMAD_WK_JETTY_NUM; i++) {
		if (dev_priv->jetty_rsrc[i].jfc_s == jfc_s)
			return &dev_priv->jetty_rsrc[i];
	}

	return NULL;
}

struct ubmad_jetty_resource *
ubmad_get_jetty_rsrc_by_jfc_r(struct ubmad_device_priv *dev_priv,
			      struct ubcore_jfc *jfc_r)
{
	int i;

	/* No need to lock as dev_priv kref_put, so jetty resources are valid */
	for (i = 0; i < UBMAD_WK_JETTY_NUM; i++) {
		if (dev_priv->jetty_rsrc[i].jfc_r == jfc_r)
			return &dev_priv->jetty_rsrc[i];
	}

	return NULL;
}

/* device */
static int
ubmad_create_device_priv_resources(struct ubmad_device_priv *dev_priv)
{
	struct ubcore_device *device = dev_priv->device;
	struct ubcore_eid_info *eid_list = NULL;
	uint32_t cnt = 0;
	int ret;

	/* check */
	if (dev_priv->valid) {
		ubcore_log_warn("dev_priv rsrc already inited. dev_name: %s\n",
			      device->dev_name);
		return 0;
	}

	eid_list = ubcore_get_eid_list(device, &cnt);
	if (eid_list == NULL || cnt == 0) {
		ubcore_log_warn(
			"No eid_list in device: %s, do not create wk-jetty resource.\n",
			device->dev_name);
		return 0;
	}

	ret = ubmad_init_jetty_rsrc_array(dev_priv->jetty_rsrc, dev_priv);
	if (ret != 0) {
		ubcore_log_err("Failed to init jetty rsrc array, ret: %d.\n",
			     ret);
		return ret;
	}

	dev_priv->valid = true;
	return 0;
}

static void
ubmad_destroy_device_priv_resources(struct ubmad_device_priv *dev_priv)
{
	if (!dev_priv->valid) {
		ubcore_log_warn(
			"dev_priv rsrc not inited. No need to uninit. dev_name: %s\n",
			dev_priv->device->dev_name);
		return;
	}
	dev_priv->valid = false;

	ubmad_uninit_jetty_rsrc_array(dev_priv->jetty_rsrc);
}

static struct ubmad_device_priv *
ubmad_get_device_priv_lockless(struct ubcore_device *device)
{
	struct ubmad_device_priv *dev_priv, *next;

	list_for_each_entry_safe(dev_priv, next, &g_ubmad_device_list, node) {
		if (dev_priv->device == device) {
			kref_get(&dev_priv->kref);
			return dev_priv;
		}
	}
	return NULL;
}

struct ubmad_device_priv *ubmad_get_device_priv(struct ubcore_device *device)
{
	struct ubmad_device_priv *dev_priv;
	unsigned long flag;

	spin_lock_irqsave(&g_ubmad_device_list_lock, flag);
	dev_priv = ubmad_get_device_priv_lockless(device);
	spin_unlock_irqrestore(&g_ubmad_device_list_lock, flag);

	return dev_priv;
}

static void ubmad_release_device_priv(struct kref *kref)
{
	struct ubmad_device_priv *dev_priv =
		container_of(kref, struct ubmad_device_priv, kref);

	/* retransmission */
	drain_workqueue(dev_priv->rt_wq);
	destroy_workqueue(dev_priv->rt_wq);

	/* rsrc */
	ubmad_destroy_device_priv_resources(dev_priv);

	/* basic */
	ubcore_unregister_event_handler(dev_priv->device, &dev_priv->handler);
	kfree(dev_priv);
}

void ubmad_put_device_priv(struct ubmad_device_priv *dev_priv)
{
	kref_put(&dev_priv->kref, ubmad_release_device_priv);
}

// init dev_priv rsrc fail won't cause this func ret err
static int ubmad_open_device(struct ubcore_device *device)
{
	struct ubmad_device_priv *dev_priv;
	unsigned long flag;

	/* basic */
	dev_priv = kzalloc(sizeof(struct ubmad_device_priv), GFP_KERNEL);
	if (dev_priv == NULL)
		return -ENOMEM;
	kref_init(&dev_priv->kref);
	dev_priv->device = device;
	dev_priv->handler.event_callback = ubmad_event_cb;
	ubcore_register_event_handler(device, &dev_priv->handler);

	/* rsrc */
	if (ubmad_create_device_priv_resources(dev_priv) != 0) {
		// It could be due to eid not added. Wait for ubcore add eid event to init again.
		ubcore_log_warn("fail to create dev_priv rsrc. dev_name: %s\n",
			      device->dev_name);
	}

	/* reliable communication */
	dev_priv->rt_wq = alloc_workqueue("%s", 0, 0, "ubmad rt_wq");
	if (IS_ERR_OR_NULL(dev_priv->rt_wq)) {
		ubcore_log_err("create rt_wq failed. dev_name: %s\n",
			     device->dev_name);
		ubmad_destroy_device_priv_resources(dev_priv);
		ubcore_unregister_event_handler(dev_priv->device,
						&dev_priv->handler);
		kfree(dev_priv);
		return -1;
	}

	/* add to list */
	spin_lock_irqsave(&g_ubmad_device_list_lock, flag);
	list_add_tail(&dev_priv->node, &g_ubmad_device_list);
	spin_unlock_irqrestore(&g_ubmad_device_list_lock, flag);

	return 0;
}

static void ubmad_rsrc_notify_close(struct ubmad_jetty_resource *rsrc)
{
	struct ubmad_tjetty *tjetty;
	struct hlist_node *next;
	unsigned long flag;
	int i;

	if (IS_ERR_OR_NULL(rsrc->jetty) || IS_ERR_OR_NULL(rsrc->send_seg) ||
	    IS_ERR_OR_NULL(rsrc->send_seg_bitmap)) {
		ubcore_log_warn("Invalid parameter.\n");
		return;
	}

	spin_lock_irqsave(&rsrc->tjetty_hlist_lock, flag);
	for (i = 0; i < UBMAD_MAX_TJETTY_NUM; i++) {
		hlist_for_each_entry_safe(tjetty, next, &rsrc->tjetty_hlist[i],
					  node)
			ubmad_post_send_close_req(rsrc, tjetty->tjetty);
	}
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);
}

// send close request to all tjetty before remove kmod
static void ubmad_notify_close(struct ubcore_device *device)
{
	struct ubmad_device_priv *dev_priv;
	unsigned long flag;
	int i;

	spin_lock_irqsave(&g_ubmad_device_list_lock, flag);
	dev_priv = ubmad_get_device_priv_lockless(device);
	spin_unlock_irqrestore(&g_ubmad_device_list_lock, flag);
	if (dev_priv == NULL) {
		ubcore_log_err("Failed to get dev_priv, dev_name: %s\n",
			     device->dev_name);
		return;
	}

	for (i = 0; i < UBMAD_WK_JETTY_NUM; i++)
		ubmad_rsrc_notify_close(&dev_priv->jetty_rsrc[i]);

	ubmad_put_device_priv(dev_priv);
}

static int ubmad_close_device(struct ubcore_device *device)
{
	struct ubmad_device_priv *dev_priv;
	unsigned long flag;

	/* remove from list */
	spin_lock_irqsave(&g_ubmad_device_list_lock, flag);
	dev_priv = ubmad_get_device_priv_lockless(device);
	if (dev_priv == NULL) {
		spin_unlock_irqrestore(&g_ubmad_device_list_lock, flag);
		ubcore_log_err("Failed to get dev_priv, dev_name: %s\n",
			     device->dev_name);
		return -ENODEV;
	}
	list_del(&dev_priv->node);
	spin_unlock_irqrestore(&g_ubmad_device_list_lock, flag);
	ubmad_put_device_priv(dev_priv); // put for get above

	/* left triggered by put */
	ubmad_put_device_priv(
		dev_priv); // put for kref_init() in ubmad_open_device()
	return 0;
}

static int ubmad_add_device(struct ubcore_device *device)
{
	/* Use main device, do not use namespace logic device */
	int ret;

	ret = ubmad_open_device(device);
	if (ret != 0) {
		ubcore_log_err(
			"fail to open mad device, dev_name: %s, ret: %d.\n",
			device->dev_name, ret);
		return ret;
	}

	return 0;
}

static void ubmad_remove_device(struct ubcore_device *device, void *client_ctx)
{
	int ret;

	ubmad_notify_close(device);

	ret = ubmad_close_device(device);
	if (ret != 0)
		ubcore_log_err("Failed to close ubmad device, dev_name: %s.\n",
			     device->dev_name);
}

static struct ubcore_client g_ubmad_client = {
	.list_node = LIST_HEAD_INIT(g_ubmad_client.list_node),
	.client_name = "ubmad",
	.add = ubmad_add_device,
	.remove = ubmad_remove_device
};

int ubmad_init(void)
{
	int ret;

	INIT_LIST_HEAD(&g_ubmad_device_list);
	INIT_LIST_HEAD(&g_ubmad_agent_list);

	ret = ubcore_register_client(&g_ubmad_client);
	if (ret != 0) {
		ubcore_log_err("Failed to register ub_mad client, ret: %d.\n",
			     ret);
		return ret;
	}

	ubcore_register_cm_eid_ops(ubmad_ubc_eid_ops);

	return 0;
}

void ubmad_uninit(void)
{
	ubcore_unregister_client(&g_ubmad_client);
}

/* agent ops */
static struct ubmad_agent_priv *
ubmad_get_agent_priv_lockless(struct ubcore_device *device)
{
	struct ubmad_agent_priv *agent_priv, *next;

	list_for_each_entry_safe(agent_priv, next, &g_ubmad_agent_list, node) {
		if (agent_priv->agent.device == device) {
			kref_get(&agent_priv->kref);
			return agent_priv;
		}
	}

	return NULL;
}

struct ubmad_agent_priv *ubmad_get_agent_priv(struct ubcore_device *device)
{
	struct ubmad_agent_priv *agent_priv;
	unsigned long flag;

	spin_lock_irqsave(&g_ubmad_agent_list_lock, flag);
	agent_priv = ubmad_get_agent_priv_lockless(device);
	spin_unlock_irqrestore(&g_ubmad_agent_list_lock, flag);

	return agent_priv;
}

static void ubmad_release_agent_priv(struct kref *kref)
{
	struct ubmad_agent_priv *agent_priv =
		container_of(kref, struct ubmad_agent_priv, kref);

	drain_workqueue(agent_priv->jfce_wq_s);
	destroy_workqueue(agent_priv->jfce_wq_s);
	drain_workqueue(agent_priv->jfce_wq_r);
	destroy_workqueue(agent_priv->jfce_wq_r);

	kfree(agent_priv);
}

void ubmad_put_agent_priv(struct ubmad_agent_priv *agent_priv)
{
	kref_put(&agent_priv->kref, ubmad_release_agent_priv);
}

struct ubmad_agent *ubmad_register_agent(struct ubcore_device *device,
					 ubmad_send_handler send_handler,
					 ubmad_recv_handler recv_handler,
					 void *usr_ctx)
{
	struct ubmad_agent *agent;
	struct ubmad_agent_priv *agent_priv;
	unsigned long flag;

	/* check inputs */
	if (IS_ERR_OR_NULL(device)) {
		ubcore_log_err("device nullptr\n");
		return ERR_PTR(-EINVAL);
	}
	if (IS_ERR_OR_NULL(send_handler))
		ubcore_log_warn("send_handler null\n");
	if (IS_ERR_OR_NULL(recv_handler))
		ubcore_log_warn("recv_handler null\n");

	/* create agent_priv */
	agent_priv = kzalloc(sizeof(struct ubmad_agent_priv), GFP_KERNEL);
	if (IS_ERR_OR_NULL(agent_priv))
		return ERR_PTR(-ENOMEM);
	kref_init(&agent_priv->kref);

	agent_priv->jfce_wq_s = alloc_workqueue("%s", 0, 0, "ubmad jfce_wq_s");
	if (IS_ERR_OR_NULL(agent_priv->jfce_wq_s)) {
		ubcore_log_err("alloc agent_priv workqueue_s failed.\n");
		goto err_alloc_wq_s;
	}
	agent_priv->jfce_wq_r = alloc_workqueue("%s", 0, 0, "ubmad jfce_wq_r");
	if (IS_ERR_OR_NULL(agent_priv->jfce_wq_r)) {
		ubcore_log_err("alloc agent_priv workqueue_r failed.\n");
		goto err_alloc_wq_r;
	}

	/* init agent */
	agent = &agent_priv->agent;
	agent->device = device;
	agent->send_handler = send_handler;
	agent->recv_handler = recv_handler;
	agent->usr_ctx = usr_ctx;

	/* add to list */
	INIT_LIST_HEAD(&agent_priv->node);
	spin_lock_irqsave(&g_ubmad_agent_list_lock, flag);
	list_add_tail(&agent_priv->node, &g_ubmad_agent_list);
	spin_unlock_irqrestore(&g_ubmad_agent_list_lock, flag);

	return agent;

err_alloc_wq_r:
	if (agent_priv->jfce_wq_s && !IS_ERR(agent_priv->jfce_wq_s))
		destroy_workqueue(agent_priv->jfce_wq_s);

err_alloc_wq_s:
	kfree(agent_priv);
	return ERR_PTR(-ENOMEM);
}

int ubmad_unregister_agent(struct ubmad_agent *agent)
{
	unsigned long flag;
	struct ubmad_agent_priv *agent_priv;

	if (IS_ERR_OR_NULL(agent)) {
		ubcore_log_err("agent nullptr\n");
		return -EINVAL;
	}

	/* remove from list */
	agent_priv = container_of(agent, struct ubmad_agent_priv, agent);
	spin_lock_irqsave(&g_ubmad_agent_list_lock, flag);
	list_del(&agent_priv->node);
	spin_unlock_irqrestore(&g_ubmad_agent_list_lock, flag);

	ubmad_put_agent_priv(agent_priv); // put for kref_init()

	return 0;
}
