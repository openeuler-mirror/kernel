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
#include <linux/atomic.h>
#include <linux/completion.h>
#include <ub/urma/ubcore_uapi.h>
#include <ub/urma/ubcore_api.h>
#include "ubcore_tp.h"
#include "ubcore_log.h"
#include "ub_mad_priv.h"
#include "ubcore_log.h"
#include "ubcore_main_ue_eid.h"
#include "ubcore_priv.h"

static struct list_head g_ubmad_device_list;
static DEFINE_SPINLOCK(g_ubmad_device_list_lock);

static DEFINE_MUTEX(g_ubc_eid_lock);

/*
 * Deferred agent release: the last agent kref is often dropped by the
 * agent's own work handler (an in-flight work when unregistering), where
 * draining/destroying its own wq would self-deadlock. See
 * ubmad_release_agent_priv().
 */
static struct workqueue_struct *g_ubmad_release_wq;
static atomic_t g_ubmad_agent_cnt = ATOMIC_INIT(0);
static DECLARE_COMPLETION(g_ubmad_agents_released);

/* forward declaration */
// device
static int
ubmad_create_device_priv_agent_resources(struct ubmad_agent_priv *agent_priv);
static void
ubmad_destroy_device_priv_agent_resources(struct ubmad_agent_priv *agent_priv,
	bool need_uninit_msn);
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

static int ubmad_get_eid_info_by_eid(struct ubcore_device *dev,
				     const union ubcore_eid *eid,
				     struct ubcore_eid_info *eid_info)
{
	int i;

	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(eid) ||
	    IS_ERR_OR_NULL(eid_info) || IS_ERR_OR_NULL(dev->eid_table.eid_entries))
		return -EINVAL;

	spin_lock(&dev->eid_table.lock);
	for (i = 0; i < dev->eid_table.eid_cnt; i++) {
		if (!dev->eid_table.eid_entries[i].valid)
			continue;

		if (memcmp(&dev->eid_table.eid_entries[i].eid, eid,
			   sizeof(union ubcore_eid)) == 0) {
			eid_info->eid = dev->eid_table.eid_entries[i].eid;
			eid_info->eid_index =
				dev->eid_table.eid_entries[i].eid_index;
			spin_unlock(&dev->eid_table.lock);
			return 0;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	return -ENOENT;
}

static int ubmad_find_main_eid_from_dev(struct ubcore_device *device,
					 struct ubcore_eid_info *eid_info)
{
	struct ubcore_eid_info *eid_list = NULL;
	union ubcore_eid main_ue_eid;
	uint32_t cnt = 0;
	uint32_t i;
	int ret = -ENOENT;

	eid_list = ubcore_get_eid_list(device, &cnt);
	if (eid_list == NULL || cnt == 0)
		return -ENOENT;

	for (i = 0; i < cnt; i++) {
		int lookup_ret;

		lookup_ret = ubcore_lookup_main_ue_eid(&eid_list[i].eid,
						       &main_ue_eid);
		if (lookup_ret != 0)
			continue;
		if (memcmp(&eid_list[i].eid, &main_ue_eid,
			   sizeof(union ubcore_eid)) != 0)
			continue;
		*eid_info = eid_list[i];
		ret = 0;
		break;
	}

	ubcore_free_eid_list(eid_list);
	return ret;
}

static int ubmad_update_device_priv_agent_resources(struct ubmad_agent_priv *agent_priv,
				   struct ubcore_eid_info *eid_info)
{
	int ret;

	if (agent_priv->valid &&
	    memcmp(&agent_priv->eid_info.eid, &eid_info->eid,
		   sizeof(union ubcore_eid)) == 0 &&
	    agent_priv->eid_info.eid_index == eid_info->eid_index) {
		ubcore_log_warn_rl(
			"eid_info is not changed, no need to update rsrc\n");
		return 0;
	}
	/* without draining: defer tjetty release to uninit msn */
	ubmad_destroy_device_priv_agent_resources(agent_priv, false);

	(void)memcpy(&agent_priv->eid_info.eid, &eid_info->eid,
		     sizeof(union ubcore_eid));
	agent_priv->eid_info.eid_index = eid_info->eid_index;
	ret = ubmad_create_device_priv_agent_resources(agent_priv);
	if (ret != 0) {
		ubcore_log_err("Failed to create agent resources, ret: %d.\n",
				     ret);
		return ret;
	}

	ubcore_log_info(
		"Success to update priv resources: dev: %s eid_idx %d, eid: " EID_FMT,
		agent_priv->agent.device->dev_name, agent_priv->eid_info.eid_index,
		EID_ARGS(agent_priv->eid_info.eid));
	return 0;
}

/* reconcile agent resources when eid change */
static int ubmad_reconcile_agent_resources(struct ubmad_device_priv *dev_priv,
				struct ubcore_eid_info *eid_info,
				enum ubcore_mgmt_event_type event_type)
{
	struct ubmad_agent_priv *agent_priv, *next;
	int ret = 0;

	list_for_each_entry_safe(agent_priv, next, &dev_priv->agent_list, node) {
		switch (event_type) {
		case UBCORE_MGMT_EVENT_EID_ADD:
			ret = ubmad_update_device_priv_agent_resources(agent_priv, eid_info);
			if (ret != 0)
				ubcore_log_err(
					"Failed to update agent resources, ret: %d.\n",
					ret);
			break;
		case UBCORE_MGMT_EVENT_EID_RMV:
			ubmad_destroy_device_priv_agent_resources(agent_priv, false);
			break;
		default:
			ubcore_log_err("Invalid event_type: %d.\n", event_type);
			return -EINVAL;
		}
		}
	return ret;
}

static int ubmad_ubc_eid_ops_inner(struct ubcore_device *dev,
				   struct ubcore_eid_info *eid_info,
				   enum ubcore_mgmt_event_type event_type)
{
	struct ubmad_device_priv *dev_priv;
	unsigned long flag;
	int ret;

	/* add device list lock */
	spin_lock_irqsave(&g_ubmad_device_list_lock, flag);
	dev_priv = ubmad_get_device_priv_lockless(dev);
	spin_unlock_irqrestore(&g_ubmad_device_list_lock, flag);
	if (IS_ERR_OR_NULL(dev_priv)) {
		ubcore_log_err("Failed to get dev_priv, dev_name: %s\n",
			     dev->dev_name);
		return -1;
	}

	/* 1、eid add event, create agent resources */
	ret = ubmad_reconcile_agent_resources(dev_priv, eid_info, event_type);
	if (ret != 0) {
		ubcore_log_err("Failed to reconcile agent resources, ret: %d.\n",
			     ret);
		ubmad_put_device_priv(dev_priv);
		return ret;
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

	ret = ubcore_lookup_main_ue_eid(&eid_info->eid, &main_primary_eid);
	if (ret != 0) {
		mutex_unlock(&g_ubc_eid_lock);
		ubcore_log_err_rl("Invalid eid "EID_FMT".\n", EID_ARGS(eid_info->eid));
		return -1;
	}

	if (memcmp(&eid_info->eid, &main_primary_eid,
		sizeof(union ubcore_eid)) != 0) {
		mutex_unlock(&g_ubc_eid_lock);
		ubcore_log_warn_rl("No need to operate current eid "EID_FMT".\n",
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

static void ubmad_on_main_ue_eid_event(
	const union ubcore_eid *main_ue_eid,
	enum ubcore_main_ue_eid_event_type event_type)
{
	struct ubcore_device *dev;
	struct ubcore_eid_info eid_info = { 0 };
	enum ubcore_mgmt_event_type mgmt_event_type;
	int ret;

	switch (event_type) {
	case UBCORE_MAIN_UE_EID_FIRST_ADD:
		mgmt_event_type = UBCORE_MGMT_EVENT_EID_ADD;
		break;
	case UBCORE_MAIN_UE_EID_LAST_DEL:
		mgmt_event_type = UBCORE_MGMT_EVENT_EID_RMV;
		break;
	default:
		return;
	}

	dev = ubcore_get_device_by_eid((union ubcore_eid *)main_ue_eid,
				       UBCORE_TRANSPORT_UB);
	if (dev == NULL)
		return;

	ret = ubmad_get_eid_info_by_eid(dev, main_ue_eid, &eid_info);
	if (ret != 0) {
		ubcore_put_device(dev);
		return;
	}

	mutex_lock(&g_ubc_eid_lock);
	ret = ubmad_ubc_eid_ops_inner(dev, &eid_info, mgmt_event_type);
	mutex_unlock(&g_ubc_eid_lock);
	if (ret != 0)
		ubcore_log_err("Failed to handle main ue eid event, eid " EID_FMT
			       ", event_type: %d, ret: %d.\n",
			       EID_ARGS(*main_ue_eid), event_type, ret);
	ubcore_put_device(dev);
}

/* jetty ops */
static struct ubcore_jfc *ubmad_create_jfc_s(struct ubcore_device *device,
					 uint32_t depth)
{
	struct ubcore_jfc_cfg jfc_cfg = { 0 };
	struct ubcore_jfc *jfc = NULL;
	int rearm_ret;

	jfc_cfg.depth = depth;
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

static struct ubcore_jfc *ubmad_create_jfc_r(struct ubcore_device *device,
					 uint32_t depth)
{
	struct ubcore_jfc_cfg jfc_cfg = { 0 };
	struct ubcore_jfc *jfc = NULL;
	int rearm_ret;

	jfc_cfg.depth = depth;
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

static struct ubcore_jfr *ubmad_create_jfr(struct ubmad_agent_priv *agent_priv,
					   struct ubcore_jfc *jfc_r,
					   uint32_t depth)
{
	struct ubcore_jfr_cfg jfr_cfg = { 0 };

	jfr_cfg.id = 0U;
	jfr_cfg.depth = depth;
	jfr_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	jfr_cfg.trans_mode = UBCORE_TP_UM;
	jfr_cfg.eid_index = agent_priv->eid_info.eid_index;
	jfr_cfg.max_sge = UBMAD_JFR_MAX_SGE_NUM;
	jfr_cfg.jfc = jfc_r;

	return ubcore_create_jfr(agent_priv->agent.device, &jfr_cfg, NULL, NULL);
}

static int ubmad_jetty_set_priority(struct ubmad_device_priv *dev_priv,
		  struct ubcore_jetty_cfg *jetty_cfg)
{
	struct ubcore_device_attr attr = {0};
	int ret = 0;
	int i;

	ret = ubcore_query_device_attr(dev_priv->device, &attr);
	if (ret != 0) {
		ubcore_log_err("Failed to ubcore get dev_attr!\n");
		return -EINVAL;
	}

	for (i = 0; i < UBCORE_MAX_PRIORITY_CNT; ++i) {
		if (attr.dev_cap.priority_info[i].tp_type.bs.utp == 1) {
			jetty_cfg->priority = i;
			ubcore_log_info(
				"ubmad create jetty set priority: %d, tp_type: utp\n", i);
			return 0;
		}
	}
	/* Fall back to RTP for legacy environments where no UTP SL is provisioned. */
	for (i = 0; i < UBCORE_MAX_PRIORITY_CNT; ++i) {
		if (attr.dev_cap.priority_info[i].tp_type.bs.rtp == 1) {
			jetty_cfg->priority = i;
			ubcore_log_info(
				"ubmad create jetty set priority: %d, tp_type: rtp\n", i);
			return 0;
		}
	}

	ubcore_log_err("set priority default value: 0\n");
	return -EINVAL;
}

static struct ubcore_jetty *
ubmad_create_jetty(struct ubmad_agent_priv *agent_priv, struct ubcore_jfc *jfc_s,
		   struct ubcore_jfc *jfc_r, struct ubcore_jfr *jfr,
		   struct ubmad_jetty_cfg *cfg)
{
	struct ubcore_jetty_cfg jetty_cfg = { 0 };
	int ret = 0;

	jetty_cfg.id = cfg->jetty_id;
	jetty_cfg.flag.bs.share_jfr = 1;
	jetty_cfg.trans_mode = UBCORE_TP_UM;
	jetty_cfg.eid_index = agent_priv->eid_info.eid_index;
	jetty_cfg.jfs_depth = cfg->send_sge_num;
	jetty_cfg.priority = 0;
	ret = ubmad_jetty_set_priority(agent_priv->dev_priv, &jetty_cfg);
	if (ret)
		ubcore_log_info("ubmad create jetty set priority : 0\n");
	jetty_cfg.max_send_sge = UBMAD_JFS_MAX_SGE_NUM;
	jetty_cfg.max_send_rsge = UBMAD_JFS_MAX_SGE_NUM;
	jetty_cfg.jfr_depth = cfg->recv_sge_num;
	jetty_cfg.max_recv_sge = UBMAD_JFR_MAX_SGE_NUM;
	jetty_cfg.send_jfc = jfc_s;
	jetty_cfg.recv_jfc = jfc_r;
	jetty_cfg.jfr = jfr;
	jetty_cfg.err_timeout = UBMAD_JETTY_ERR_TIMEOUT;

	return ubcore_create_jetty(agent_priv->agent.device, &jetty_cfg, NULL,
				   NULL);
}

struct ubmad_tjetty *
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

static void ubmad_tjetty_release_work_handler(struct work_struct *work)
{
	struct ubmad_tjetty *tjetty =
		container_of(work, struct ubmad_tjetty, release_work);
	int ret;
	struct ubmad_ini_rtbuffer *ini_rtbuffer;
	struct ubmad_tgt_hash_node *tgt_hash_node;
	struct hlist_node *next;
	unsigned long flag;
	uint32_t idx;

	/* kref is zero, no concurrent access to ini_rt_hlist. */
	for (idx = 0; idx < UBMAD_INI_RTBUFFER_SIZE; idx++) {
		hlist_for_each_entry_safe(ini_rtbuffer, next,
					  &tjetty->ini_rt_hlist[idx], node) {
			hlist_del(&ini_rtbuffer->node);
			vfree(ini_rtbuffer);
		}
	}

	spin_lock_irqsave(&tjetty->tgt_hash_lock, flag);
	for (idx = 0; idx < UBMAD_TGT_HASH_SIZE; idx++) {
		hlist_for_each_entry_safe(tgt_hash_node, next,
					  &tjetty->tgt_hash_hlist[idx], node) {
			hlist_del(&tgt_hash_node->node);
			kfree(tgt_hash_node);
		}
	}
	spin_unlock_irqrestore(&tjetty->tgt_hash_lock, flag);

	ubmad_uninit_msn_mgr(&tjetty->recv_msn_mgr);
	ubmad_uninit_msn_mgr(&tjetty->msn_mgr);

	ret = ubcore_unimport_jetty(tjetty->tjetty);
	if (ret != 0)
		ubcore_log_err("Failed to unimport jetty, ret: %d.\n", ret);
	ubcore_put_device(tjetty->ub_dev); // get in ubmad_import_jetty()
	vfree(tjetty);
}

/*
 * The last put may come from any context (rt_work, poster, recv work).
 * Running the teardown inline there would either self-deadlock (the msn
 * cleanup cancels the calling rt_work). Defer to g_ubmad_release_wq
 */
static void ubmad_release_tjetty(struct kref *kref)
{
	struct ubmad_tjetty *tjetty =
		container_of(kref, struct ubmad_tjetty, kref);

	if (queue_work(g_ubmad_release_wq, &tjetty->release_work) == 0) {
		/* should not happen: release work is queued only once */
		ubcore_log_err_rl("Failed to queue tjetty release work.\n");
	}
}

void ubmad_put_tjetty(struct ubmad_tjetty *tjetty)
{
	kref_put(&tjetty->kref, ubmad_release_tjetty);
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
	new_tjetty = vzalloc(sizeof(struct ubmad_tjetty));
	if (IS_ERR_OR_NULL(new_tjetty))
		return ERR_PTR(-ENOMEM);
	kref_init(&new_tjetty->kref); // put in ubmad_unimport_jetty()
	INIT_WORK(&new_tjetty->release_work, ubmad_tjetty_release_work_handler);
	new_tjetty->ub_dev = device;

	tjetty_cfg.id.id = rsrc->cfg.jetty_id;
	tjetty_cfg.id.eid = *dst_eid;
	tjetty_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	tjetty_cfg.trans_mode = UBCORE_TP_UM;
	tjetty_cfg.type = UBCORE_JETTY;
	tjetty_cfg.eid_index = rsrc->jetty->jetty_cfg.eid_index;
	tjetty_cfg.tp_type = UBCORE_UTP;
	new_target = ubcore_import_jetty(device, &tjetty_cfg, NULL);
	if (IS_ERR_OR_NULL(new_target)) {
		ubcore_log_err("import tjetty: %u failed. eid " EID_FMT "\n",
			     rsrc->cfg.jetty_id, EID_ARGS(*dst_eid));
		goto free;
	}
	new_tjetty->tjetty = new_target;

	int idx;

	for (idx = 0; idx < UBMAD_INI_RTBUFFER_SIZE; idx++)
		INIT_HLIST_HEAD(&new_tjetty->ini_rt_hlist[idx]);
	spin_lock_init(&new_tjetty->ini_rt_spinlock);
	for (idx = 0; idx < UBMAD_TGT_HASH_SIZE; idx++)
		INIT_HLIST_HEAD(&new_tjetty->tgt_hash_hlist[idx]);
	for (idx = 0; idx < UBMAD_TGT_RTBUFFER_SIZE; idx++)
		new_tjetty->tgt_rt_buffer[idx].msn = 0;
	spin_lock_init(&new_tjetty->tgt_hash_lock);
	atomic64_set(&new_tjetty->tgt_idx_gen, 1);
	new_tjetty->rsrc = rsrc;

	ubmad_init_msn_mgr(&new_tjetty->msn_mgr);
	ubmad_init_msn_mgr(&new_tjetty->recv_msn_mgr);

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
	/* Hold the device because need wait tjetty_release_work finish */
	ubcore_get_device(device);

	// add to hlist
	INIT_HLIST_NODE(&new_tjetty->node);
	hlist_add_head(&new_tjetty->node, &rsrc->tjetty_hlist[hash]);
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);

	ubcore_log_info_rl(
		"import tjetty0 and add to hlist succeeded. dev_name: %s, deid " EID_FMT
		".\n",
		device->dev_name, EID_ARGS(*dst_eid));
	return new_tjetty;

uninit_msn_mgr:
	ubmad_uninit_msn_mgr(&new_tjetty->recv_msn_mgr);
	ubmad_uninit_msn_mgr(&new_tjetty->msn_mgr);
	ubcore_unimport_jetty(new_target);
free:
	vfree(new_tjetty);
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
						    uint32_t num_sge, uint32_t sge_size)
{
	void *seg_va = NULL;
	union ubcore_reg_seg_flag flag = { 0 };
	uint64_t seg_len = (uint64_t)sge_size * num_sge;
	struct ubcore_seg_cfg cfg = { 0 };
	struct ubcore_target_seg *ret;

#ifdef MIRROR_ENABLE
	struct page *pages;
	uint32_t order;
#endif

	if (seg_len == 0) {
		ubcore_log_err("Invalid seg len, sge_size: %u, num_sge: %u.\n",
			     sge_size, num_sge);
		return ERR_PTR(-EINVAL);
	}

#ifdef MIRROR_ENABLE
	ubcore_log_info("enable mirror memory.\n");
	/* order is rounded up to power of two pages, may exceed seg_len */
	order = get_order(seg_len);
	pages = alloc_pages_node(dev_to_node(dev->dev.parent),
			GFP_HIGHUSER_MOVABLE | __GFP_ZERO | __GFP_COMP, order);
	if (!pages) {
		ubcore_log_err_rl("Failed to alloc %llu bytes (order=%u).\n",
				seg_len, order);
		return ERR_PTR(-ENOMEM);
	}
	seg_va = page_address(pages);
	if (!seg_va) {
		ubcore_log_err_rl("page_address return null.\n");
		ret = ERR_PTR(-EFAULT);
		goto free;
	}
#else
	seg_va = vzalloc(seg_len);
	if (IS_ERR_OR_NULL(seg_va))
		return ERR_PTR(-ENOMEM);
#endif
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
#ifdef MIRROR_ENABLE
	if (pages)
		__free_pages(pages, order);
#else
	vfree(seg_va);
#endif
	return ret;
}

static void ubmad_unregister_seg(struct ubcore_target_seg *seg)
{
	uint64_t va = seg->seg.ubva.va;
#ifdef MIRROR_ENABLE
	uint64_t len = seg->seg.len;
#endif

	(void)ubcore_unregister_seg(seg);

#ifdef MIRROR_ENABLE
	free_pages((unsigned long)va, get_order(len));
#else
	vfree((void *)va);
#endif
}

static int ubmad_create_seg(struct ubmad_jetty_resource *rsrc,
			    struct ubcore_device *device)
{
	// send_seg
	rsrc->send_seg = ubmad_register_seg(device, rsrc->cfg.send_sge_num,
								rsrc->cfg.sge_size);
	if (IS_ERR_OR_NULL(rsrc->send_seg)) {
		ubcore_log_err("register send_seg failed.\n");
		return -1;
	}
	rsrc->send_seg_bitmap = ubmad_create_bitmap(rsrc->cfg.send_sge_num);
	if (IS_ERR_OR_NULL(rsrc->send_seg_bitmap)) {
		ubcore_log_err("alloc send_seg_bitmap failed\n");
		goto unreg_send_seg;
	}

	// recv_seg
	rsrc->recv_seg = ubmad_register_seg(device, rsrc->cfg.recv_sge_num,
								rsrc->cfg.sge_size);
	if (IS_ERR_OR_NULL(rsrc->recv_seg)) {
		ubcore_log_err("register recv_seg failed\n");
		goto free_send_seg_bitmap;
	}
	rsrc->recv_seg_bitmap = ubmad_create_bitmap(rsrc->cfg.recv_sge_num);
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
				 struct ubmad_agent_priv *agent_priv)
{
	struct ubcore_device *device = agent_priv->agent.device;
	struct ubcore_jetty *jetty;
	struct ubcore_jfc *jfc_s;
	struct ubcore_jfc *jfc_r;
	struct ubcore_jfr *jfr;
	uint32_t idx;
	int ret;

	/* create jetty */
	jfc_s = ubmad_create_jfc_s(device, rsrc->cfg.send_sge_num);
	if (IS_ERR_OR_NULL(jfc_s)) {
		ubcore_log_err("fail to create jfc_s. dev_name: %s\n",
			     device->dev_name);
		return -1;
	}
	rsrc->jfc_s = jfc_s;

	jfc_r = ubmad_create_jfc_r(device, rsrc->cfg.recv_sge_num);
	if (IS_ERR_OR_NULL(jfc_r)) {
		ubcore_log_err("fail to create jfc_r. dev_name: %s\n",
			     device->dev_name);
		ret = -1;
		goto del_jfc_s;
	}
	rsrc->jfc_r = jfc_r;

	jfr = ubmad_create_jfr(agent_priv, jfc_r, rsrc->cfg.recv_sge_num);
	if (IS_ERR_OR_NULL(jfr)) {
		ubcore_log_err("fail to create jfr. dev_name: %s\n",
			     device->dev_name);
		ret = -1;
		goto del_jfc_r;
	}
	rsrc->jfr = jfr;

	jetty = ubmad_create_jetty(agent_priv, jfc_s, jfc_r, jfr, &rsrc->cfg);
	if (IS_ERR_OR_NULL(jetty)) {
		ubcore_log_err("fail to create wk jetty. dev_name: %s, id: %u.\n",
			     device->dev_name, rsrc->cfg.jetty_id);
		ret = -1;
		goto del_jfr;
	}
	atomic_set(&rsrc->tx_in_queue, 0);

	ubcore_log_info("jetty id %u eid " EID_FMT ", jfr id: %u.\n",
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

	/* tjetty */
	for (idx = 0; idx < UBMAD_MAX_TJETTY_NUM; idx++)
		INIT_HLIST_HEAD(&rsrc->tjetty_hlist[idx]);
	spin_lock_init(&rsrc->tjetty_hlist_lock);

	/* first batch of post_recv */
	for (idx = 0; idx < rsrc->cfg.recv_sge_num; idx++) {
		ret = ubmad_post_recv(rsrc);
		if (ret != 0) {
			ubcore_log_err(
				"No. %u post recv in the first batch failed. device %s ret %d\n",
				idx, device->dev_name, ret);
			goto destroy_seg;
		}
	}

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

static void ubmad_uninit_jetty_rsrc(struct ubmad_jetty_resource *rsrc,
				     bool need_uninit_msn)
{
	struct ubmad_tjetty *tjetty;
	struct hlist_node *next;
	struct hlist_head rm_tjetty_list;
	unsigned long flag;
	int i;

	/* like remove tjetty, detach to avoid sleep in lock
		because of cancel_delayed_work */
	INIT_HLIST_HEAD(&rm_tjetty_list);
	spin_lock_irqsave(&rsrc->tjetty_hlist_lock, flag);
	for (i = 0; i < UBMAD_MAX_TJETTY_NUM; i++) {
		hlist_for_each_entry_safe(tjetty, next, &rsrc->tjetty_hlist[i],
					  node) {
			hlist_del(&tjetty->node);
			hlist_add_head(&tjetty->node, &rm_tjetty_list);
		}
	}
	spin_unlock_irqrestore(&rsrc->tjetty_hlist_lock, flag);

	hlist_for_each_entry_safe(tjetty, next, &rm_tjetty_list, node) {
		if (need_uninit_msn)
			ubmad_uninit_msn_mgr(&tjetty->msn_mgr);
		ubmad_unimport_jetty(tjetty);
	}

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

/* device */
static int ubmad_create_device_priv_agent_resources(struct ubmad_agent_priv *agent_priv)
{
	struct ubcore_device *device = agent_priv->agent.device;
	struct ubcore_eid_info *eid_list = NULL;
	uint32_t cnt = 0;
	int i, j;
	int ret;

	/* check */
	if (agent_priv->valid) {
		ubcore_log_warn("agent_priv rsrc already inited. dev_name: %s\n",
			      device->dev_name);
		return 0;
	}

	eid_list = ubcore_get_eid_list(device, &cnt);
	if (eid_list == NULL || cnt == 0) {
		ubcore_log_warn(
			"No eid_list in device: %s, do not create wk-jetty resource.\n",
			device->dev_name);
		return -ENODEV;
	}
	ubcore_free_eid_list(eid_list);

	for (i = 0; i < agent_priv->rsrc_num; i++) {
		ret = ubmad_init_jetty_rsrc(&agent_priv->rsrc[i], agent_priv);
		if (ret != 0) {
			ubcore_log_err(
				"Failed to init jetty rsrc, index: %d, ret: %d.\n",
				i, ret);
			goto uninit_rsrc;
		}
	}

	agent_priv->valid = true;
	ubcore_log_info("Finish to init agent jetty resource, dev_name: %s.\n",
			agent_priv->agent.device->dev_name);
	return 0;

uninit_rsrc:
	for (j = 0; j < i; j++)
		ubmad_uninit_jetty_rsrc(&agent_priv->rsrc[j], true);
	return ret;
}

static void ubmad_destroy_device_priv_agent_resources(
	struct ubmad_agent_priv *agent_priv, bool need_uninit_msn)
{
	int i;

	if (!agent_priv->valid)
		return;

	agent_priv->valid = false;

	for (i = 0; i < agent_priv->rsrc_num; i++)
		ubmad_uninit_jetty_rsrc(&agent_priv->rsrc[i], need_uninit_msn);
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

	/* rsrc is free in release agent priv */
	if (!list_empty(&dev_priv->agent_list))
		ubcore_log_err_rl(
			"agent list is not empty when release dev, dev_name: %s.\n",
			dev_priv->device->dev_name);

	/* basic */
	ubcore_unregister_event_handler(dev_priv->device, &dev_priv->handler);
	ubcore_put_device(dev_priv->device); // get in ubmad_open_device()
	kfree(dev_priv);
}

void ubmad_put_device_priv(struct ubmad_device_priv *dev_priv)
{
	kref_put(&dev_priv->kref, ubmad_release_device_priv);
}

/*	device only binds the agent list,  resources are created
	when agent registers or main ue eid event comes */
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

	/* hold ubcore device until dev_priv released: agent rsrc destroy is
	 * free by g_ubmad_release_wq and may run after remove callbacks,
	 * ubcore_unregister_device() need wait it. */
	ubcore_get_device(device);

	dev_priv->handler.event_callback = ubmad_event_cb;
	ubcore_register_event_handler(device, &dev_priv->handler);

	/* agent list */
	INIT_LIST_HEAD(&dev_priv->agent_list);
	spin_lock_init(&dev_priv->agent_list_lock);

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

	/* agent release is deferred, see ubmad_release_agent_priv() */
	atomic_set(&g_ubmad_agent_cnt, 0);
	reinit_completion(&g_ubmad_agents_released);
	g_ubmad_release_wq = alloc_workqueue("%s",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 0, "ubmad release_wq");
	if (IS_ERR_OR_NULL(g_ubmad_release_wq)) {
		ubcore_log_err("Failed to alloc ubmad release workqueue.\n");
		return -ENOMEM;
	}

	ret = ubcore_register_main_ue_eid_event_cb(ubmad_on_main_ue_eid_event);
	if (ret != 0) {
		ubcore_log_err("Failed to register main ue eid event cb, ret: %d.\n",
			       ret);
		goto destroy_release_wq;
	}

	ret = ubcore_register_client(&g_ubmad_client);
	if (ret != 0) {
		ubcore_log_err("Failed to register ub_mad client, ret: %d.\n",
			     ret);
		(void)ubcore_unregister_main_ue_eid_event_cb(
			ubmad_on_main_ue_eid_event);
		goto destroy_release_wq;
	}

	ubcore_register_cm_eid_ops(ubmad_ubc_eid_ops);

	return 0;

destroy_release_wq:
	destroy_workqueue(g_ubmad_release_wq);
	g_ubmad_release_wq = NULL;
	return ret;
}

void ubmad_uninit(void)
{
	(void)ubcore_unregister_main_ue_eid_event_cb(ubmad_on_main_ue_eid_event);
	ubcore_unregister_client(&g_ubmad_client);

	/*
	 * Agents are unregistered by their owners (ubcm) before ubmad_uninit(),
	 * but the final kref may still be held by an in-flight work, and the
	 * release is deferred to g_ubmad_release_wq. Wait until all agents are
	 * fully released, otherwise a late put could queue_work() on a freed
	 * release wq (and run module text being unloaded).
	 */
	if (atomic_read(&g_ubmad_agent_cnt) != 0)
		wait_for_completion(&g_ubmad_agents_released);
	destroy_workqueue(g_ubmad_release_wq);
	g_ubmad_release_wq = NULL;
}

static void ubmad_agent_release_work_handler(struct work_struct *work)
{
	struct ubmad_agent_priv *agent_priv =
		container_of(work, struct ubmad_agent_priv, release_work);

	/* if do this by init failed, some rsrc maybe null, add null check */
	/* jfce work may queue conn work and retransmit work, drain jfce first */
	if (!IS_ERR_OR_NULL(agent_priv->jfce_wq_s)) {
		drain_workqueue(agent_priv->jfce_wq_s);
		destroy_workqueue(agent_priv->jfce_wq_s);
	}
	if (!IS_ERR_OR_NULL(agent_priv->jfce_wq_r)) {
		drain_workqueue(agent_priv->jfce_wq_r);
		destroy_workqueue(agent_priv->jfce_wq_r);
	}

	/* connection */
	if (!IS_ERR_OR_NULL(agent_priv->conn_wq)) {
		drain_workqueue(agent_priv->conn_wq);
		destroy_workqueue(agent_priv->conn_wq);
	}

	/* rt_work is delayed work, drain maybe not null,
		destroy rt wq after destroy rsrc */
	if (!IS_ERR_OR_NULL(agent_priv->rt_wq))
		drain_workqueue(agent_priv->rt_wq);

	/* has drain rt_wq, no in-flight work, so the tjetty msn cleanup inline */
	ubmad_destroy_device_priv_agent_resources(agent_priv, true);

	if (!IS_ERR_OR_NULL(agent_priv->rt_wq))
		destroy_workqueue(agent_priv->rt_wq);

	if (!IS_ERR_OR_NULL(agent_priv->rsrc))
		kvfree(agent_priv->rsrc); // kvcalloc in ubmad_register_agent()

	/* ensure kfree agent list after agent workqueue task complete */
	ubmad_put_device_priv(agent_priv->dev_priv);
	kfree(agent_priv);

	/* all agents released, wake up ubmad_uninit() */
	if (atomic_dec_and_test(&g_ubmad_agent_cnt))
		complete(&g_ubmad_agents_released);
}

static void ubmad_release_agent_priv(struct kref *kref)
{
	struct ubmad_agent_priv *agent_priv =
		container_of(kref, struct ubmad_agent_priv, kref);

	/*
	 * The last kref is often dropped by the agent's own work handler
	 * Draining or destroying that wq in its own work context self-deadlocks,
	 * so defer release to g_ubmad_release_wq instead.
	 */
	INIT_WORK(&agent_priv->release_work, ubmad_agent_release_work_handler);
	if (queue_work(g_ubmad_release_wq, &agent_priv->release_work) == 0) {
		/* should not happen: release work is queued only once */
		ubcore_log_err("Failed to queue agent release work.\n");
	}
}

void ubmad_get_agent_priv(struct ubmad_agent_priv *agent_priv)
{
	kref_get(&agent_priv->kref);
}

void ubmad_put_agent_priv(struct ubmad_agent_priv *agent_priv)
{
	kref_put(&agent_priv->kref, ubmad_release_agent_priv);
}

static int add_agent_list_and_try_init_jetty_rsrc(struct ubcore_device *device,
					struct ubmad_device_priv *dev_priv,
					struct ubmad_agent_priv *agent_priv)
{
	struct ubcore_eid_info eid_info = { 0 };
	unsigned long flag;
	int ret = 0;

	/* add agent to agent list */
	INIT_LIST_HEAD(&agent_priv->node);
	mutex_lock(&g_ubc_eid_lock);
	spin_lock_irqsave(&dev_priv->agent_list_lock, flag);
	list_add_tail(&agent_priv->node, &dev_priv->agent_list);
	spin_unlock_irqrestore(&dev_priv->agent_list_lock, flag);

	if (ubmad_find_main_eid_from_dev(device, &eid_info) == 0) {
		(void)memcpy(&agent_priv->eid_info.eid, &eid_info.eid,
			     sizeof(union ubcore_eid));
		agent_priv->eid_info.eid_index = eid_info.eid_index;
		ret = ubmad_create_device_priv_agent_resources(agent_priv);
		if (ret != 0) {
			ubcore_log_err(
				"Failed to create agent resources, dev_name: %s, ret: %d.\n",
				device->dev_name, ret);
			(void)memset(&agent_priv->eid_info, 0,
				     sizeof(agent_priv->eid_info));
			goto del_agent_list;
		}
	}
	mutex_unlock(&g_ubc_eid_lock);
	return ret;

del_agent_list:
	spin_lock_irqsave(&dev_priv->agent_list_lock, flag);
	list_del(&agent_priv->node);
	spin_unlock_irqrestore(&dev_priv->agent_list_lock, flag);
	mutex_unlock(&g_ubc_eid_lock);

	return ret;
}

static int ubmad_check_agent_cfg(const struct ubmad_agent_cfg *cfg)
{
	const struct ubmad_jetty_cfg *jetty_cfg;
	uint32_t i, j;

	if (IS_ERR_OR_NULL(cfg) || IS_ERR_OR_NULL(cfg->jetty_cfg)) {
		ubcore_log_err("invalid agent cfg or jetty_cfg.\n");
		return -EINVAL;
	}
	if (cfg->jetty_num == 0) {
		ubcore_log_err("invalid jetty_num: %u.\n", cfg->jetty_num);
		return -EINVAL;
	}

	for (i = 0; i < cfg->jetty_num; i++) {
		jetty_cfg = &cfg->jetty_cfg[i];
		if (jetty_cfg->jetty_id == 0 || jetty_cfg->sge_size == 0) {
			ubcore_log_err(
				"invalid jetty cfg, index: %u, jetty_id: %u, sge_size: %u.\n",
				i, jetty_cfg->jetty_id, jetty_cfg->sge_size);
			return -EINVAL;
		}

		if (jetty_cfg->send_sge_num <= 8 || jetty_cfg->recv_sge_num == 0) {
			ubcore_log_err(
				"invalid jetty cfg, index: %u, send_sge_num: %u, recv_sge_num: %u.\n",
				    i, jetty_cfg->send_sge_num, jetty_cfg->recv_sge_num);
			return -EINVAL;
		}
		/* check jetty id duplicate */
		for (j = 0; j < i; j++) {
			if (cfg->jetty_cfg[j].jetty_id == jetty_cfg->jetty_id) {
				ubcore_log_err("duplicate jetty id: %u, index: %u and %u.\n",
					       jetty_cfg->jetty_id, j, i);
				return -EINVAL;
			}
		}
	}

	return 0;
}

struct ubmad_agent *ubmad_register_agent(struct ubcore_device *device,
					const struct ubmad_agent_cfg *cfg,
					ubmad_send_handler send_handler,
					ubmad_recv_handler recv_handler,
					void *usr_ctx)
{
	struct ubmad_agent *agent;
	struct ubmad_agent_priv *agent_priv;
	struct ubmad_device_priv *dev_priv;
	int i, ret;

	/* check inputs */
	if (IS_ERR_OR_NULL(device)) {
		ubcore_log_err("device nullptr\n");
		return ERR_PTR(-EINVAL);
	}

	ret = ubmad_check_agent_cfg(cfg);
	if (ret != 0) {
		ubcore_log_err("invalid agent cfg, ret: %d.\n", ret);
		return ERR_PTR(-EINVAL);
	}

	if (IS_ERR_OR_NULL(send_handler))
		ubcore_log_warn("send_handler null\n");
	if (IS_ERR_OR_NULL(recv_handler))
		ubcore_log_warn("recv_handler null\n");

	/* hold dev_priv ref, put in ubmad_agent_release_work_handler() */
	dev_priv = ubmad_get_device_priv(device);
	if (IS_ERR_OR_NULL(dev_priv)) {
		ubcore_log_err("Failed to get dev_priv, dev_name: %s\n",
			       device->dev_name);
		return ERR_PTR(-ENODEV);
	}

	/* create agent_priv */
	agent_priv = kzalloc(sizeof(struct ubmad_agent_priv), GFP_KERNEL);
	if (IS_ERR_OR_NULL(agent_priv)) {
		ubcore_log_err("alloc agent_priv failed.\n");
		ret = -ENOMEM;
		goto put_device_priv;
	}

	/* init agent_priv*/
	kref_init(&agent_priv->kref);
	agent_priv->dev_priv = dev_priv;
	/* agent sum,wait all agent release complete g_ubmad_release_wq */
	if (atomic_inc_return(&g_ubmad_agent_cnt) == 1)
		reinit_completion(&g_ubmad_agents_released);
	/* alloc workqueue */
	agent_priv->jfce_wq_s = alloc_workqueue("%s",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 0, "ubmad jfce_wq_s");
	if (IS_ERR_OR_NULL(agent_priv->jfce_wq_s)) {
		ubcore_log_err("alloc agent_priv workqueue_s failed.\n");
		ret = -ENOMEM;
		goto put_agent;
	}
	agent_priv->jfce_wq_r = alloc_workqueue("%s",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 0, "ubmad jfce_wq_r");
	if (IS_ERR_OR_NULL(agent_priv->jfce_wq_r)) {
		ubcore_log_err("alloc agent_priv workqueue_r failed.\n");
		ret = -ENOMEM;
		goto put_agent;
	}
	agent_priv->rt_wq = alloc_workqueue("%s",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 0, "ubmad rt_wq");
	if (IS_ERR_OR_NULL(agent_priv->rt_wq)) {
		ubcore_log_err("alloc agent_priv rt_wq failed.\n");
		ret = -ENOMEM;
		goto put_agent;
	}
	agent_priv->conn_wq = alloc_workqueue("%s",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 0, "ubmad conn_wq");
	if (IS_ERR_OR_NULL(agent_priv->conn_wq)) {
		ubcore_log_err("alloc agent_priv conn_wq failed.\n");
		ret = -ENOMEM;
		goto put_agent;
	}
	/* alloc jetty rsrc */
	agent_priv->rsrc_num = cfg->jetty_num;
	agent_priv->rsrc = kvcalloc(cfg->jetty_num,
				    sizeof(struct ubmad_jetty_resource),
				    GFP_KERNEL);
	if (IS_ERR_OR_NULL(agent_priv->rsrc)) {
		ubcore_log_err("alloc agent rsrc failed, jetty_num: %u.\n",
			       cfg->jetty_num);
		ret = -ENOMEM;
		goto put_agent;
	}

	/* restore jetty cfg, used by init jetty rsrc */
	for (i = 0; i < cfg->jetty_num; i++)
		agent_priv->rsrc[i].cfg = cfg->jetty_cfg[i];

	/* init agent */
	agent = &agent_priv->agent;
	agent->device = device;
	agent->send_handler = send_handler;
	agent->recv_handler = recv_handler;
	agent->usr_ctx = usr_ctx;

	/* try to init jetty rsrc if eid exists */
	ret = add_agent_list_and_try_init_jetty_rsrc(device, dev_priv, agent_priv);
	if (ret != 0) {
		ubcore_log_err("Failed to init jetty rsrc, dev_name: %s, ret: %d.\n",
			       device->dev_name, ret);
		goto put_agent;
	}

	ubcore_log_info("Success to register agent, dev_name: %s, rsrc_num: %u.\n",
			device->dev_name, agent_priv->rsrc_num);
	return agent;

put_agent:
	ubmad_put_agent_priv(agent_priv); // put for kref_init()
	return ERR_PTR(ret);

put_device_priv:
	ubmad_put_device_priv(dev_priv);
	return ERR_PTR(ret);
}

int ubmad_unregister_agent(struct ubmad_agent *agent)
{
	struct ubmad_agent_priv *agent_priv;
	unsigned long flag;
	int i;

	if (IS_ERR_OR_NULL(agent)) {
		ubcore_log_err("agent nullptr\n");
		return -EINVAL;
	}

	/* remove from list */
	agent_priv = container_of(agent, struct ubmad_agent_priv, agent);

	mutex_lock(&g_ubc_eid_lock);
	/* send close request to all tjetty before remove kmod */
	if (agent_priv->valid) {
		for (i = 0; i < agent_priv->rsrc_num; i++)
			ubmad_rsrc_notify_close(&agent_priv->rsrc[i]);
	}

	/* remove agent list */
	spin_lock_irqsave(&agent_priv->dev_priv->agent_list_lock, flag);
	list_del(&agent_priv->node);
	spin_unlock_irqrestore(&agent_priv->dev_priv->agent_list_lock, flag);

	mutex_unlock(&g_ubc_eid_lock);

	ubmad_put_agent_priv(agent_priv); // put for kref_init()
	return 0;
}
