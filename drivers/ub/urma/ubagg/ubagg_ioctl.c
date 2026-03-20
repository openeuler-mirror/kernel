// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg kernel module
 * Author: Dongxu Li
 * Create: 2025-1-14
 * Note:
 * History: 2025-1-14: Create file
 */
#include <linux/module.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/kref.h>

#include <ub/urma/ubcore_api.h>
#include <ub/urma/ubcore_uapi.h>
#include <ub/urma/ubcore_types.h>
#include "ubagg_log.h"
#include "ubagg_ioctl.h"
#include "ubagg_jetty.h"
#include "ubagg_seg.h"
#include "ubagg_bitmap.h"
#include "ubagg_hash_table.h"

#define UBAGG_DEVICE_MAX_EID_CNT 128
#define UBAGG_MAX_BONDING_DEV_NUM 1024
#define BITMAP_OFFSET 1025

static LIST_HEAD(g_ubagg_dev_list);
static DEFINE_SPINLOCK(g_ubagg_dev_list_lock);

struct seg_info_req {
	struct ubcore_ubva ubva;
	uint64_t len;
	uint32_t token_id;
};

struct jetty_info_req {
	struct ubcore_jetty_id jetty_id;
	bool is_jfr;
};

static struct ubagg_ht_param g_ubagg_ht_params[] = {
	[UBAGG_HT_SEGMENT_HT] = { UBAGG_BITMAP_SIZE,
				  sizeof(struct ubagg_seg_hash_node) -
					  sizeof(struct hlist_node),
				  sizeof(struct ubcore_target_seg),
				  sizeof(uint32_t) },
	[UBAGG_HT_JETTY_HT] = { UBAGG_BITMAP_SIZE,
				sizeof(struct ubagg_jetty_hash_node) -
					sizeof(struct hlist_node),
				sizeof(struct ubcore_jetty), sizeof(uint32_t) },
	[UBAGG_HT_JFR_HT] = { UBAGG_BITMAP_SIZE,
			      sizeof(struct ubagg_jfr_hash_node) -
				      sizeof(struct hlist_node),
			      sizeof(struct ubcore_jfr), sizeof(uint32_t) },
};

static void ubagg_dev_release(struct kref *kref)
{
	struct ubagg_device *dev = container_of(kref, struct ubagg_device, ref);

	kfree(dev);
}

void ubagg_dev_ref_get(struct ubagg_device *dev)
{
	kref_get(&dev->ref);
}

void ubagg_dev_ref_put(struct ubagg_device *dev)
{
	kref_put(&dev->ref, ubagg_dev_release);
}

struct ubagg_dev_name_eid_arr {
	char master_dev_name[UBAGG_MAX_DEV_NAME_LEN];
	char agg_eid[EID_LEN];
};
static struct ubagg_dev_name_eid_arr
	g_name_eid_arr[UBAGG_MAX_BONDING_DEV_NUM] = { 0 };
static DEFINE_MUTEX(g_name_eid_arr_lock);

static bool ubagg_dev_exists(char *dev_name)
{
	struct ubagg_device *dev;

	list_for_each_entry(dev, &g_ubagg_dev_list, list_node) {
		if (strncmp(dev_name, dev->master_dev_name,
			    UBAGG_MAX_DEV_NAME_LEN) == 0)
			return true;
	}
	return false;
}

static struct ubagg_device *ubagg_find_dev_by_name(char *dev_name)
{
	struct ubagg_device *dev;

	spin_lock(&g_ubagg_dev_list_lock);
	list_for_each_entry(dev, &g_ubagg_dev_list, list_node) {
		if (strncmp(dev_name, dev->master_dev_name,
			    UBAGG_MAX_DEV_NAME_LEN) == 0) {
			spin_unlock(&g_ubagg_dev_list_lock);
			return dev;
		}
	}
	spin_unlock(&g_ubagg_dev_list_lock);
	return NULL;
}

static bool is_agg_dev_valid(struct ubagg_topo_agg_dev *agg_dev)
{
	struct ubagg_topo_agg_dev empty_dev = {0};

	return (memcmp(agg_dev, &empty_dev, sizeof(struct ubagg_topo_agg_dev)) == 0) ? false : true;
}

static bool is_eid_valid(const char *eid)
{
	int i;

	for (i = 0; i < EID_LEN; i++) {
		if (eid[i] != 0)
			return true;
	}
	return false;
}

static bool is_eid_match(const char *eid1, const char *eid2)
{
	return memcmp(eid1, eid2, EID_LEN) == 0;
}

static int query_eid_idx(struct ubcore_device *dev, union ubcore_eid *eid,
			 uint32_t *eid_idx)
{
	spin_lock(&dev->eid_table.lock);
	for (int32_t i = 0; i < dev->eid_table.eid_cnt; i++) {
		struct ubcore_eid_entry *eid_entity;

		eid_entity = &dev->eid_table.eid_entries[i];
		if (memcmp(eid, &eid_entity->eid, sizeof(*eid)) == 0) {
			*eid_idx = eid_entity->eid_index;
			spin_unlock(&dev->eid_table.lock);
			return 0;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	return -ENOENT;
}

static int get_physical_device(struct ubagg_device *ubagg_dev,
			       struct ubagg_physical_device_out *out,
			       union ubcore_eid *bonding_eid)
{
	struct ubagg_topo_map *topo_map;
	struct ubagg_topo_agg_dev *topo_agg_dev;
	int ret;

	topo_map = get_global_ubagg_map();
	if (topo_map == NULL) {
		ubagg_log_err("global topo map is NULL\n");
		return -EINVAL;
	}

	topo_agg_dev = find_cur_topo_agg_dev(topo_map, bonding_eid);
	if (topo_agg_dev == NULL) {
		ubagg_log_err("find cur node index failed\n");
		return -EINVAL;
	}

	out->physical_dev_num = IODIE_NUM;
	for (int i = 0; i < IODIE_NUM; i++) {
		struct ubagg_topo_ue *topo_ue;
		struct ubagg_physical_device *pdev;
		union ubcore_eid *primary_eid;
		struct ubcore_device *dev;

		topo_ue = &topo_agg_dev->ues[i];

		primary_eid = (union ubcore_eid *)&topo_ue->primary_eid;
		dev = ubcore_get_device_by_eid(primary_eid, UBCORE_TRANSPORT_UB);
		if (IS_ERR_OR_NULL(dev)) {
			ubagg_log_err("Failed to query primary dev, eid: "EID_FMT"\n",
				EID_RAW_ARGS(topo_ue->primary_eid));
			return -ENOENT;
		}

		pdev = &out->physical_devs[i];
		pdev->chip_id = topo_ue->chip_id;
		(void)memcpy(pdev->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);

		ret = query_eid_idx(dev, primary_eid, &pdev->primary_eid_idx);
		if (ret != 0) {
			ubagg_log_err("Failed to query primary eid information, eid: "
				EID_FMT"\n", EID_ARGS(*bonding_eid));
			pdev->primary_eid_idx = UINT32_MAX;
		}
		for (int j = 0; j < MAX_PORT_NUM; j++) {
			union ubcore_eid *port_eid;

			port_eid = (union ubcore_eid *)&topo_ue->port_eid[j];
			if (!is_eid_valid(port_eid->raw)) {
				pdev->port_eid_idx[j] = UINT32_MAX;
				continue;
			}
			ret = query_eid_idx(dev, port_eid, &pdev->port_eid_idx[j]);
			if (ret != 0) {
				ubagg_log_err("Failed to query port eid information, eid: "
					EID_FMT"\n", EID_ARGS(*bonding_eid));
				pdev->port_eid_idx[j] = UINT32_MAX;
				continue;
			}
		}
	}
	return 0;
}

static int ubagg_get_physical_device(struct ubcore_device *dev,
				  struct ubcore_user_ctl *user_ctl)
{
	struct ubagg_physical_device_out out = {0};
	struct ubagg_device *ubagg_dev;
	int ret;

	ubagg_dev = ubagg_find_dev_by_name(dev->dev_name);
	if (ubagg_dev == NULL) {
		ubagg_log_err("Bonding device not exist.");
		return -ENXIO;
	}

	if (get_physical_device(ubagg_dev, &out, &ubagg_dev->bonding_eid) != 0) {
		ubagg_log_err("Failed to get physical device:%s", dev->dev_name);
		return -ENXIO;
	}

	if (user_ctl->out.len < sizeof(struct ubagg_physical_device_out)) {
		ubagg_log_err(
			"ubagg user ctl has no enough space, buffer size:%u, needed size:%lu",
			user_ctl->out.len, sizeof(struct ubagg_physical_device_out));
		return -ENOSPC;
	}

	ret = copy_to_user((void __user *)user_ctl->out.addr,
			   (void *)&out, sizeof(out));
	if (ret != 0) {
		ubagg_log_err("copy to user fail, ret:%d", ret);
		return -EFAULT;
	}
	return 0;
}

static struct ubagg_topo_info_out *get_topo_info(void)
{
	struct ubagg_topo_info_out *out = NULL;
	struct ubagg_topo_map *topo_map = NULL;

	topo_map = get_global_ubagg_map();
	if (topo_map == NULL)
		return NULL;
	out = kzalloc(sizeof(struct ubagg_topo_info_out), GFP_KERNEL);
	if (out == NULL)
		return NULL;
	(void)memcpy(out->topo_info, topo_map->topo_infos,
		     sizeof(topo_map->topo_infos));
	out->node_num = topo_map->node_num;
	return out;
}

static int ubagg_get_topo_info(struct ubcore_device *dev,
			       struct ubcore_user_ctl *user_ctl)
{
	struct ubagg_topo_info_out *topo_info_out = NULL;
	int ret;

	topo_info_out = get_topo_info();
	if (!topo_info_out) {
		ubagg_log_err("ubagg dev topo info does not exist:%s",
			      dev->dev_name);
		return -ENXIO;
	}

	if (user_ctl->out.len < sizeof(struct ubagg_topo_info_out)) {
		ubagg_log_err(
			"ubagg user ctl has no enough space, buffer size:%u, needed size:%lu",
			user_ctl->out.len, sizeof(struct ubagg_topo_info_out));
		kfree(topo_info_out);
		return -ENOSPC;
	}

	ret = copy_to_user((void __user *)user_ctl->out.addr,
			   (void *)topo_info_out,
			   sizeof(struct ubagg_topo_info_out));
	if (ret != 0) {
		ubagg_log_err("copy to user fail, ret:%d", ret);
		kfree(topo_info_out);
		return -EFAULT;
	}
	kfree(topo_info_out);
	return 0;
}

static int ubagg_get_jfr_id(struct ubcore_device *dev,
			    struct ubcore_user_ctl *user_ctl)
{
	struct ubagg_device *ubagg_dev = to_ubagg_dev(dev);
	uint32_t id;
	int ret;

	if ((ubagg_dev == NULL) || (ubagg_dev->jfr_bitmap == NULL)) {
		ubagg_log_err("ubagg_dev->jfr_bitmap NULL");
		return -1;
	}
	id = ubagg_bitmap_alloc_idx(ubagg_dev->jfr_bitmap);
	ret = copy_to_user((void __user *)user_ctl->out.addr, (void *)&id,
			   sizeof(uint32_t));
	if (ret != 0) {
		ubagg_log_err("copy to user fail, ret:%d", ret);
		return -EFAULT;
	}
	return ret;
}

static int ubagg_get_jetty_id(struct ubcore_device *dev,
			      struct ubcore_user_ctl *user_ctl)
{
	struct ubagg_device *ubagg_dev = to_ubagg_dev(dev);
	uint32_t id;
	int ret;

	if ((ubagg_dev == NULL) || (ubagg_dev->jetty_bitmap == NULL)) {
		ubagg_log_err("ubagg_dev->jfr_bitmap NULL");
		return -EINVAL;
	}
	id = ubagg_bitmap_alloc_idx(ubagg_dev->jetty_bitmap);
	ret = copy_to_user((void __user *)user_ctl->out.addr, (void *)&id,
			   sizeof(uint32_t));
	if (ret != 0) {
		ubagg_log_err("copy to user fail, ret:%d", ret);
		return -EFAULT;
	}
	return ret;
}

static int ubagg_get_seg_info(struct ubcore_device *dev,
			      struct ubcore_user_ctl *user_ctl)
{
	struct ubagg_device *ubagg_dev = to_ubagg_dev(dev);
	struct ubagg_hash_table *ubagg_seg_ht = NULL;
	struct ubagg_seg_hash_node *tmp_seg = NULL;
	struct seg_info_req *req = NULL;

	if ((ubagg_dev == NULL) || (ubagg_dev->segment_bitmap == NULL)) {
		ubagg_log_err("ubagg_dev->segment_bitmap NULL");
		return -1;
	}

	if (user_ctl->uctx != NULL ||
	    user_ctl->in.addr == 0 ||
	    user_ctl->in.len != sizeof(struct seg_info_req)) {
		ubagg_log_err("Invalid user in");
		return -1;
	}
	req = (struct seg_info_req *)user_ctl->in.addr;

	ubagg_seg_ht = &ubagg_dev->ubagg_ht[UBAGG_HT_SEGMENT_HT];
	spin_lock(&ubagg_seg_ht->lock);
	tmp_seg = ubagg_hash_table_lookup_nolock(ubagg_seg_ht, req->token_id,
						 &req->token_id);
	if (tmp_seg == NULL) {
		spin_unlock(&ubagg_seg_ht->lock);
		ubagg_log_err("Failed to find seg.\n");
		return -1;
	}
	if (user_ctl->out.addr != 0 &&
	    user_ctl->out.len < sizeof(tmp_seg->ex_info.slaves)) {
		ubagg_log_err("Invalid user out");
		return -1;
	}
	memcpy((void *)user_ctl->out.addr, tmp_seg->ex_info.slaves,
	       sizeof(tmp_seg->ex_info.slaves));
	spin_unlock(&ubagg_seg_ht->lock);
	return 0;
}

static int ubagg_get_jetty_info(struct ubcore_device *dev,
				struct ubcore_user_ctl *user_ctl)
{
	struct ubagg_hash_table *ht = NULL;
	struct ubagg_device *ubagg_dev = to_ubagg_dev(dev);
	struct jetty_info_req *req = NULL;

	if ((ubagg_dev == NULL) || (ubagg_dev->segment_bitmap == NULL)) {
		ubagg_log_err("ubagg_dev->segment_bitmap NULL");
		return -1;
	}

	if (user_ctl->uctx != NULL ||
	    user_ctl->in.addr == 0 ||
	    user_ctl->in.len != sizeof(struct jetty_info_req)) {
		ubagg_log_err("Invalid user in");
		return -1;
	}
	req = (struct jetty_info_req *)user_ctl->in.addr;

	if (req->is_jfr) {
		struct ubagg_jfr_hash_node *tmp_jfr = NULL;

		ht = &ubagg_dev->ubagg_ht[UBAGG_HT_JFR_HT];
		spin_lock(&ht->lock);
		tmp_jfr = ubagg_hash_table_lookup_nolock(ht, req->jetty_id.id,
							 &req->jetty_id.id);
		if (tmp_jfr == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jfr, jetty_id:%u.\n",
				      req->jetty_id.id);
			return -1;
		}
		memcpy((void *)user_ctl->out.addr, &tmp_jfr->ex_info,
		       sizeof(tmp_jfr->ex_info));
		spin_unlock(&ht->lock);
	} else {
		struct ubagg_jetty_hash_node *tmp_jetty = NULL;

		ht = &ubagg_dev->ubagg_ht[UBAGG_HT_JETTY_HT];
		spin_lock(&ht->lock);
		tmp_jetty = ubagg_hash_table_lookup_nolock(ht, req->jetty_id.id,
							   &req->jetty_id.id);
		if (tmp_jetty == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jetty, jetty_id:%u.\n",
				      req->jetty_id.id);
			return -1;
		}
		memcpy((void *)user_ctl->out.addr, &tmp_jetty->ex_info,
		       sizeof(tmp_jetty->ex_info));
		spin_unlock(&ht->lock);
	}
	return 0;
}

int ubagg_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *user_ctl)
{
	int ret = 0;

	if (dev == NULL || user_ctl == NULL) {
		ubagg_log_err("Invalid parameter.\n");
		return -1;
	}

	switch (user_ctl->in.opcode) {
	case GET_PHYSICAL_DEVICE:
		ret = ubagg_get_physical_device(dev, user_ctl);
		break;
	case GET_TOPO_INFO:
		ret = ubagg_get_topo_info(dev, user_ctl);
		break;
	case GET_JFR_ID:
		ret = ubagg_get_jfr_id(dev, user_ctl);
		break;
	case GET_JETTY_ID:
		ret = ubagg_get_jetty_id(dev, user_ctl);
		break;
	case GET_SEG_INFO:
		ret = ubagg_get_seg_info(dev, user_ctl);
		break;
	case GET_JETTY_INFO:
		ret = ubagg_get_jetty_info(dev, user_ctl);
		break;
	default:
		ubagg_log_err("unsupported ubagg userctl opcde:%u",
			      user_ctl->in.opcode);
		ret = -ENXIO;
	}

	return ret;
}

int ubagg_config_device(struct ubcore_device *dev,
			struct ubcore_device_cfg *cfg)
{
	(void)dev;
	(void)cfg;
	return 0;
}

static struct ubcore_ucontext *
ubagg_alloc_ucontext(struct ubcore_device *dev, uint32_t eid_index,
		     struct ubcore_udrv_priv *udrv_data)
{
	(void)dev;
	(void)eid_index;
	(void)udrv_data;
	return kzalloc(sizeof(struct ubcore_ucontext), GFP_KERNEL);
}

static int ubagg_free_ucontext(struct ubcore_ucontext *uctx)
{
	kfree(uctx);
	return 0;
}

static int ubagg_query_device_attr(struct ubcore_device *dev,
				   struct ubcore_device_attr *attr)
{
	*attr = dev->attr;
	return 0;
}

struct ubcore_jfc *ubagg_create_jfc(struct ubcore_device *ub_dev,
				    struct ubcore_jfc_cfg *cfg,
				    struct ubcore_udata *udata)
{
	struct ubagg_device *ubagg_dev =
		ubagg_container_of(ub_dev, struct ubagg_device, ub_dev);
	struct ubagg_jfc *jfc;
	int id;

	if (ubagg_dev == NULL || ub_dev == NULL || cfg == NULL ||
	    udata == NULL || udata->uctx == NULL)
		return NULL;

	jfc = kzalloc(sizeof(struct ubagg_jfc), GFP_KERNEL);
	if (jfc == NULL)
		return NULL;
	jfc->base.jfc_cfg.depth = cfg->depth;
	spin_lock(&ubagg_dev->jfc_bitmap->lock);
	id = ubagg_bitmap_alloc_idx_from_offset_nolock(
		ubagg_dev->jfc_bitmap, ubagg_dev->jfc_bitmap->alloc_idx);
	if (id == -1) {
		spin_unlock(&ubagg_dev->jfc_bitmap->lock);
		ubagg_log_err("failed to alloc jfc_id");
		kfree(jfc);
		return NULL;
	}

	jfc->base.id = id;
	ubagg_dev->jfc_bitmap->alloc_idx =
		(jfc->base.id + 1) % UBAGG_BITMAP_MAX_SIZE;
	spin_unlock(&ubagg_dev->jfc_bitmap->lock);
	ubagg_log_info("ubagg jfc created successfully, id: %u.\n",
		       jfc->base.id);
	return &jfc->base;
}

int ubagg_destroy_jfc(struct ubcore_jfc *jfc)
{
	struct ubagg_device *ubagg_dev;
	struct ubagg_jfc *ubagg_jfc;
	int id;

	if (jfc == NULL || jfc->ub_dev == NULL)
		return -EINVAL;
	ubagg_dev = (struct ubagg_device *)jfc->ub_dev;
	ubagg_jfc = ubagg_container_of(jfc, struct ubagg_jfc, base);

	id = jfc->id;
	(void)ubagg_bitmap_free_idx(ubagg_dev->jfc_bitmap, id);
	kfree(ubagg_jfc);
	ubagg_log_info("ubagg jfc destroyed successfully, id: %u.\n", id);
	return 0;
}

struct ubcore_jfs *ubagg_create_jfs(struct ubcore_device *ub_dev,
				    struct ubcore_jfs_cfg *cfg,
				    struct ubcore_udata *udata)
{
	struct ubagg_device *ubagg_dev =
		ubagg_container_of(ub_dev, struct ubagg_device, ub_dev);
	struct ubagg_jfs *jfs;
	int id;

	if (ub_dev == NULL || cfg == NULL || udata == NULL ||
	    udata->uctx == NULL)
		return NULL;
	spin_lock(&ubagg_dev->jfs_bitmap->lock);
	id = ubagg_bitmap_alloc_idx_from_offset_nolock(
		ubagg_dev->jfs_bitmap, ubagg_dev->jfs_bitmap->alloc_idx);
	if (id == -1) {
		spin_unlock(&ubagg_dev->jfs_bitmap->lock);
		ubagg_log_err("failed to alloc jfs_id: id has been used up.\n");
		return NULL;
	}
	ubagg_dev->jfs_bitmap->alloc_idx = (id + 1) % UBAGG_BITMAP_MAX_SIZE;
	spin_unlock(&ubagg_dev->jfs_bitmap->lock);

	jfs = kzalloc(sizeof(struct ubagg_jfs), GFP_KERNEL);
	if (IS_ERR_OR_NULL(jfs)) {
		(void)ubagg_bitmap_free_idx(ubagg_dev->jfs_bitmap, id);
		return NULL;
	}

	jfs->base.jfs_cfg.depth = cfg->depth;
	jfs->base.jfs_cfg.max_sge = cfg->max_sge;
	jfs->base.jfs_cfg.max_rsge = cfg->max_rsge;
	jfs->base.jfs_cfg.max_inline_data = cfg->max_inline_data;
	jfs->base.jfs_cfg.trans_mode = cfg->trans_mode;
	jfs->base.jfs_id.id = id;

	ubagg_log_info("ubagg create jfs successfully, id: %u.\n",
		       jfs->base.jfs_id.id);
	return &jfs->base;
}

int ubagg_destroy_jfs(struct ubcore_jfs *jfs)
{
	struct ubagg_device *ubagg_dev;
	struct ubagg_jfs *ubagg_jfs;
	int id;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->uctx == NULL)
		return -EINVAL;
	ubagg_dev = (struct ubagg_device *)jfs->ub_dev;
	ubagg_jfs = ubagg_container_of(jfs, struct ubagg_jfs, base);
	id = jfs->jfs_id.id;
	(void)ubagg_bitmap_free_idx(ubagg_dev->jfs_bitmap, id);
	kfree(ubagg_jfs);
	ubagg_log_info("ubagg destroy jfs_ctx successfully, id: %u.\n", id);
	return 0;
}

struct ubcore_jfr *ubagg_create_jfr(struct ubcore_device *ub_dev,
				    struct ubcore_jfr_cfg *cfg,
				    struct ubcore_udata *udata)
{
	struct ubagg_device *ubagg_dev =
		ubagg_container_of(ub_dev, struct ubagg_device, ub_dev);
	struct ubagg_hash_table *ubagg_jfr_ht = NULL;
	struct ubagg_jfr_hash_node *tmp_jfr = NULL;
	struct ubagg_jfr_hash_node *jfr = NULL;
	int ret = 0;
	int id;

	if (ub_dev == NULL || cfg == NULL || udata == NULL ||
	    udata->uctx == NULL || cfg->id >= UBAGG_BITMAP_MAX_SIZE)
		return NULL;

	id = cfg->id;
	if (id == 0) {
		spin_lock(&ubagg_dev->jfr_bitmap->lock);
		id = ubagg_bitmap_alloc_idx_from_offset_nolock(
			ubagg_dev->jfr_bitmap,
			ubagg_dev->jfr_bitmap->alloc_idx);
		if (id == -1) {
			spin_unlock(&ubagg_dev->jfr_bitmap->lock);
			ubagg_log_err(
				"failed to alloc jfr_id: id has been used up.\n");
			return NULL;
		}
		ubagg_dev->jfr_bitmap->alloc_idx =
			(id + 1) % UBAGG_BITMAP_MAX_SIZE == 0 ?
				      BITMAP_OFFSET :
				      (id + 1) % UBAGG_BITMAP_MAX_SIZE;
		spin_unlock(&ubagg_dev->jfr_bitmap->lock);
	} else {
		if (ubagg_bitmap_use_id(ubagg_dev->jfr_bitmap, id) != 0) {
			ubagg_log_err(
				"failed to alloc jfr_id: id has been set.\n");
			return NULL;
		}
	}

	if (id == -1) {
		ubagg_log_err("failed to alloc jfr_id: id has been used up.\n");
		return NULL;
	}

	jfr = kzalloc(sizeof(struct ubagg_jfr_hash_node), GFP_KERNEL);
	if (jfr == NULL)
		goto FREE_ID;

	jfr->base.jfr_cfg.depth = cfg->depth;
	jfr->base.jfr_cfg.max_sge = cfg->max_sge;
	jfr->base.jfr_id.id = id;
	jfr->token_id = id;

	if (udata->udrv_data->in_addr != 0 &&
		udata->udrv_data->in_len > sizeof(struct ubagg_jetty_exchange_info)) {
		ubagg_log_err(
			"invalid udrv_data in_len.\n");
		goto FREE_JFR;
	}
	ret = copy_from_user(&jfr->ex_info,
			     (void __user *)udata->udrv_data->in_addr,
			     udata->udrv_data->in_len);
	if (ret != 0) {
		ubagg_log_err("ubagg fail to copy from user, ret:%d.\n", ret);
		goto FREE_JFR;
	}

	ubagg_jfr_ht = &ubagg_dev->ubagg_ht[UBAGG_HT_JFR_HT];
	spin_lock(&ubagg_jfr_ht->lock);
	tmp_jfr = ubagg_hash_table_lookup_nolock(ubagg_jfr_ht, id, &id);
	if (tmp_jfr != NULL) {
		ubagg_log_err("id:%u already exists.\n", id);
		// should remove it
		ubagg_hash_table_remove_nolock(ubagg_jfr_ht, &tmp_jfr->hnode);
		spin_unlock(&ubagg_jfr_ht->lock);
		kfree(tmp_jfr);
		goto FREE_JFR;
	}

	ubagg_hash_table_add_nolock(ubagg_jfr_ht, &jfr->hnode, id);
	spin_unlock(&ubagg_jfr_ht->lock);

	ubagg_log_info("ubagg create jfr_ctx successfully, id: %u.\n",
		       jfr->base.jfr_id.id);
	return &jfr->base;

FREE_JFR:
	kfree(jfr);
FREE_ID:
	(void)ubagg_bitmap_free_idx(ubagg_dev->jfr_bitmap, id);

	ubagg_log_err("ubagg fail to create jfr.\n");
	return NULL;
}

int ubagg_destroy_jfr(struct ubcore_jfr *jfr)
{
	struct ubagg_device *ubagg_dev;
	struct ubagg_jfr_hash_node *ubagg_jfr;
	int id;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->uctx == NULL)
		return -EINVAL;
	ubagg_dev = (struct ubagg_device *)jfr->ub_dev;
	ubagg_jfr = ubagg_container_of(jfr, struct ubagg_jfr_hash_node, base);
	id = jfr->jfr_id.id;
	ubagg_hash_table_remove(&ubagg_dev->ubagg_ht[UBAGG_HT_JFR_HT],
				&ubagg_jfr->hnode);
	(void)ubagg_bitmap_free_idx(ubagg_dev->jfr_bitmap, id);
	kfree(ubagg_jfr);
	ubagg_log_info("ubagg destroy jfr_ctx successfully, id: %u.\n", id);
	return 0;
}

struct ubcore_jetty *ubagg_create_jetty(struct ubcore_device *dev,
					struct ubcore_jetty_cfg *cfg,
					struct ubcore_udata *udata)
{
	struct ubagg_device *ubagg_dev =
		ubagg_container_of(dev, struct ubagg_device, ub_dev);
	struct ubagg_hash_table *ubagg_jetty_ht = NULL;
	struct ubagg_jetty_hash_node *tmp_jetty = NULL;
	struct ubagg_jetty_hash_node *jetty = NULL;
	int ret;
	int id;

	if (dev == NULL || cfg == NULL || udata == NULL ||
	    cfg->id >= UBAGG_BITMAP_MAX_SIZE)
		return NULL;

	id = cfg->id;
	if (id == 0) {
		spin_lock(&ubagg_dev->jetty_bitmap->lock);
		id = ubagg_bitmap_alloc_idx_from_offset_nolock(
			ubagg_dev->jetty_bitmap,
			ubagg_dev->jetty_bitmap->alloc_idx);
		ubagg_log_info("jetty alloc bitmap, idx = %d\n", id);
		if (id <= 0) {
			spin_unlock(&ubagg_dev->jetty_bitmap->lock);
			ubagg_log_err("failed to alloc jetty_id.\n");
			return NULL;
		}
		ubagg_dev->jetty_bitmap->alloc_idx =
			(id + 1) % UBAGG_BITMAP_MAX_SIZE == 0 ?
				      BITMAP_OFFSET :
				      (id + 1) % UBAGG_BITMAP_MAX_SIZE;
		spin_unlock(&ubagg_dev->jetty_bitmap->lock);
	} else {
		if (ubagg_bitmap_use_id(ubagg_dev->jetty_bitmap, id) != 0) {
			ubagg_log_err(
				"failed to alloc jetty_id: id has been set.\n");
			return NULL;
		}
	}

	if (id == -1) {
		ubagg_log_err(
			"failed to alloc jetty_id: id has been used up.\n");
		return NULL;
	}

	jetty = kzalloc(sizeof(struct ubagg_jetty_hash_node), GFP_KERNEL);
	if (jetty == NULL)
		goto FREE_ID;

	jetty->base.jetty_cfg = *cfg;
	jetty->base.jetty_id.id = id;
	jetty->token_id = id;
	if (udata->udrv_data->in_addr != 0 &&
		udata->udrv_data->in_len > sizeof(struct ubagg_jetty_exchange_info)) {
		ubagg_log_err(
			"invalid udrv_data in_len.\n");
		goto FREE_JETTY;
	}
	ret = copy_from_user(&jetty->ex_info,
			     (void __user *)udata->udrv_data->in_addr,
			     udata->udrv_data->in_len);
	if (ret != 0) {
		ubagg_log_err("ubagg fail to copy from user, ret:%d.\n", ret);
		goto FREE_JETTY;
	}

	ubagg_jetty_ht = &ubagg_dev->ubagg_ht[UBAGG_HT_JETTY_HT];
	spin_lock(&ubagg_jetty_ht->lock);
	tmp_jetty = ubagg_hash_table_lookup_nolock(ubagg_jetty_ht, id, &id);
	if (tmp_jetty != NULL) {
		ubagg_log_err("id:%u already exists.\n", id);
		// should remove it
		ubagg_hash_table_remove_nolock(ubagg_jetty_ht,
					       &tmp_jetty->hnode);
		spin_unlock(&ubagg_jetty_ht->lock);
		kfree(tmp_jetty);
		goto FREE_JETTY;
	}

	ubagg_hash_table_add_nolock(ubagg_jetty_ht, &jetty->hnode, id);
	spin_unlock(&ubagg_jetty_ht->lock);

	ubagg_log_info("ubagg create jetty_ctx successfully, jetty_id: %d\n",
		       jetty->base.jetty_id.id);
	return &jetty->base;

FREE_JETTY:
	kfree(jetty);
FREE_ID:
	(void)ubagg_bitmap_free_idx(ubagg_dev->jetty_bitmap, id);

	ubagg_log_err("ubagg fail to create jetty_ctx.\n");
	return NULL;
}

int ubagg_destroy_jetty(struct ubcore_jetty *jetty)
{
	struct ubagg_jetty_hash_node *ubagg_jetty;
	struct ubagg_device *ubagg_dev;
	int id;

	if (jetty == NULL)
		return -EINVAL;
	ubagg_dev = (struct ubagg_device *)jetty->ub_dev;
	ubagg_jetty =
		ubagg_container_of(jetty, struct ubagg_jetty_hash_node, base);
	id = jetty->jetty_id.id;
	ubagg_hash_table_remove(&ubagg_dev->ubagg_ht[UBAGG_HT_JETTY_HT],
				&ubagg_jetty->hnode);
	(void)ubagg_bitmap_free_idx(ubagg_dev->jetty_bitmap, id);
	kfree(ubagg_jetty);
	ubagg_log_info("ubagg destroy jetty successfully, id: %u.\n", id);
	return 0;
}

int ubagg_query_device_status(struct ubcore_device *dev,
			      struct ubcore_device_status *status)
{
	int i;

	for (i = 0; i < UBCORE_MAX_PORT_CNT; ++i) {
		status->port_status[i].state = UBCORE_PORT_ACTIVE;
		status->port_status[i].active_mtu = UBCORE_MTU_4096;
		status->port_status[i].active_speed = UBCORE_SP_400G;
		status->port_status[i].active_width = UBCORE_LINK_X16;
	}
	return 0;
}

static struct ubcore_ops g_ubagg_dev_ops = {
	.owner = THIS_MODULE,
	.driver_name = "ub_agg",
	.abi_version = 0,
	.user_ctl = ubagg_user_ctl,
	.config_device = ubagg_config_device,
	.alloc_ucontext = ubagg_alloc_ucontext,
	.free_ucontext = ubagg_free_ucontext,
	.query_device_attr = ubagg_query_device_attr,
	.register_seg = ubagg_register_seg,
	.unregister_seg = ubagg_unregister_seg,
	.import_seg = ubagg_import_seg,
	.unimport_seg = ubagg_unimport_seg,
	.create_jfs = ubagg_create_jfs,
	.destroy_jfs = ubagg_destroy_jfs,
	.create_jfr = ubagg_create_jfr,
	.destroy_jfr = ubagg_destroy_jfr,
	.create_jetty = ubagg_create_jetty,
	.destroy_jetty = ubagg_destroy_jetty,
	.create_jfc = ubagg_create_jfc,
	.destroy_jfc = ubagg_destroy_jfc,
	.import_jfr = ubagg_import_jfr,
	.unimport_jfr = ubagg_unimport_jfr,
	.import_jetty = ubagg_import_jetty,
	.unimport_jetty = ubagg_unimport_jetty,
	.query_device_status = ubagg_query_device_status,
};

static void ubagg_reserve_jetty_id(struct ubagg_device *dev)
{
	if (ubagg_bitmap_alloc_idx(dev->jfs_bitmap) != 0)
		ubagg_log_err("Failed to reserve jfs id = 0.\n");

	if (ubagg_bitmap_alloc_idx(dev->jfr_bitmap) != 0)
		ubagg_log_err("Failed to reserve jfr id = 0.\n");

	if (ubagg_bitmap_alloc_idx(dev->jetty_bitmap) != 0)
		ubagg_log_err("Failed to reserve jetty id = 0.\n");
}

static int alloc_ubagg_dev_bitmap(struct ubagg_device *ubagg_dev)
{
	ubagg_dev->jfc_bitmap = ubagg_bitmap_alloc(UBAGG_BITMAP_MAX_SIZE);
	if (ubagg_dev->jfc_bitmap == NULL) {
		ubagg_log_err("failed alloc jfc bitmap.\n");
		return -1;
	}
	ubagg_dev->jfs_bitmap = ubagg_bitmap_alloc(UBAGG_BITMAP_MAX_SIZE);
	if (ubagg_dev->jfs_bitmap == NULL) {
		ubagg_log_err("failed alloc jfs bitmap.\n");
		goto free_jfc_bitmap;
	}
	ubagg_dev->jfr_bitmap = ubagg_bitmap_alloc(UBAGG_BITMAP_MAX_SIZE);
	if (ubagg_dev->jfr_bitmap == NULL) {
		ubagg_log_err("failed alloc jfr bitmap.\n");
		goto free_jfs_bitmap;
	}
	ubagg_dev->jfr_bitmap->alloc_idx = BITMAP_OFFSET;
	ubagg_dev->jetty_bitmap = ubagg_bitmap_alloc(UBAGG_BITMAP_MAX_SIZE);
	if (ubagg_dev->jetty_bitmap == NULL) {
		ubagg_log_err("failed alloc jetty bitmap.\n");
		goto free_jfr_bitmap;
	}
	ubagg_dev->jetty_bitmap->alloc_idx = BITMAP_OFFSET;
	ubagg_dev->segment_bitmap = ubagg_bitmap_alloc(UBAGG_BITMAP_MAX_SIZE);
	if (ubagg_dev->segment_bitmap == NULL) {
		ubagg_log_err("failed alloc seg bitmap.\n");
		goto free_jetty_bitmap;
	}
	ubagg_reserve_jetty_id(ubagg_dev);

	return 0;
free_jetty_bitmap:
	if (ubagg_dev->jetty_bitmap != NULL) {
		kfree(ubagg_dev->jetty_bitmap);
		ubagg_dev->jetty_bitmap = NULL;
	}
free_jfr_bitmap:
	if (ubagg_dev->jfr_bitmap != NULL) {
		kfree(ubagg_dev->jfr_bitmap);
		ubagg_dev->jfr_bitmap = NULL;
	}
free_jfs_bitmap:
	if (ubagg_dev->jfs_bitmap != NULL) {
		kfree(ubagg_dev->jfs_bitmap);
		ubagg_dev->jfs_bitmap = NULL;
	}
free_jfc_bitmap:
	if (ubagg_dev->jfc_bitmap != NULL) {
		kfree(ubagg_dev->jfc_bitmap);
		ubagg_dev->jfc_bitmap = NULL;
	}
	return -1;
}

static void free_ubagg_dev_bitmap(struct ubagg_device *ubagg_dev)
{
	ubagg_bitmap_free(ubagg_dev->segment_bitmap);
	ubagg_bitmap_free(ubagg_dev->jetty_bitmap);
	ubagg_bitmap_free(ubagg_dev->jfr_bitmap);
	ubagg_bitmap_free(ubagg_dev->jfs_bitmap);
	ubagg_bitmap_free(ubagg_dev->jfc_bitmap);
	ubagg_dev->segment_bitmap = NULL;
	ubagg_dev->jetty_bitmap = NULL;
	ubagg_dev->jfr_bitmap = NULL;
	ubagg_dev->jfs_bitmap = NULL;
	ubagg_dev->jfc_bitmap = NULL;
}

static int update_dev_info(struct ubagg_topo_node *new_topo_info,
					struct ubagg_topo_node *old_topo_info)
{
	int dev_id;
	bool new_valid, old_valid;

	for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
		new_valid = is_agg_dev_valid(&new_topo_info->agg_devs[dev_id]);
		old_valid = is_agg_dev_valid(&old_topo_info->agg_devs[dev_id]);
		if (old_valid && new_valid) {
			/* if both dev are valid, return error */
			if (memcmp(&old_topo_info->agg_devs[dev_id],
				&new_topo_info->agg_devs[dev_id],
				sizeof(struct ubagg_topo_agg_dev)) != 0) {
				ubagg_log_err("dev %d is not the same\n", dev_id);
				return -1;
			}
		}
		if (!old_valid && new_valid) {
			/* if old dev is not valid, update it */
			(void)memcpy(&old_topo_info->agg_devs[dev_id],
				&new_topo_info->agg_devs[dev_id],
				sizeof(struct ubagg_topo_agg_dev));
		}
	}

	return 0;
}

static int update_link_info(struct ubagg_topo_node *new_topo_info,
				struct ubagg_topo_node *old_topo_info)
{
	int iodie_id, port_id, new_remote_port_id, old_remote_port_id;

	for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
		for (port_id = 0; port_id < MAX_PORT_NUM; ++port_id) {
			new_remote_port_id = new_topo_info->links[iodie_id][port_id].peer_port;
			old_remote_port_id = old_topo_info->links[iodie_id][port_id].peer_port;
			if (new_remote_port_id == UINT32_MAX) {
				/* if new link is not connected, skip it */
				continue;
			} else if (old_remote_port_id == UINT32_MAX) {
				/* if old link is not connected, update it */
				(void)memcpy(&old_topo_info->links[iodie_id][port_id],
					&new_topo_info->links[iodie_id][port_id],
					sizeof(struct ubagg_topo_link));
			} else {
				/* if old link is connected and new link is connected,
				   check if they are the same */
				if (memcmp(&old_topo_info->links[iodie_id][port_id],
						&new_topo_info->links[iodie_id][port_id],
						sizeof(struct ubagg_topo_link)) != 0) {
					ubagg_log_err("link is not the same, new: ");
					ubagg_log_err(
						"peer_node[%u]/peer_iodie[%u]/peer_port[%u], ",
						new_topo_info->links[iodie_id][port_id].peer_node,
						new_topo_info->links[iodie_id][port_id].peer_iodie,
						new_topo_info->links[iodie_id][port_id].peer_port);
					ubagg_log_err(
						"old: peer_node[%u]/peer_iodie[%u]/peer_port[%u]\n",
						old_topo_info->links[iodie_id][port_id].peer_node,
						old_topo_info->links[iodie_id][port_id].peer_iodie,
						old_topo_info->links[iodie_id][port_id].peer_port);
					return -1;
				}
			}
		}
	}
	return 0;
}

static int ubagg_update_topo_info(struct ubagg_topo_map *new_topo_map,
				  struct ubagg_topo_map *old_topo_map)
{
	struct ubagg_topo_node *new_node, *old_node;
	uint32_t i, j;

	if (!new_topo_map || !old_topo_map) {
		ubagg_log_err("Invalid topo map\n");
		return -EINVAL;
	}

	for (i = 0; i < new_topo_map->node_num; i++) {
		new_node = &new_topo_map->topo_infos[i];
		for (j = 0; j < old_topo_map->node_num; j++) {
			old_node = &old_topo_map->topo_infos[j];
			if (new_node->node_id == old_node->node_id) {
				if (update_link_info(new_node, old_node)) {
					ubagg_log_err("update link info fail.");
					return -EINVAL;
				}
				if (update_dev_info(new_node, old_node)) {
					ubagg_log_err("update dev info fail.");
					return -EINVAL;
				}
			}
		}
	}

	return 0;
}

static bool has_add_dev_by_agg_eid(const char *agg_eid)
{
	int i;

	if (agg_eid == NULL) {
		ubagg_log_err("agg_eid is NULL");
		return false;
	}
	mutex_lock(&g_name_eid_arr_lock);
	for (i = 0; i < UBAGG_MAX_BONDING_DEV_NUM; i++) {
		if (is_eid_match(agg_eid, g_name_eid_arr[i].agg_eid)) {
			mutex_unlock(&g_name_eid_arr_lock);
			return true;
		}
	}
	mutex_unlock(&g_name_eid_arr_lock);
	return false;
}

static void fill_add_dev_cfg(struct ubagg_topo_agg_dev *agg_dev,
			     struct ubagg_add_dev_by_uvs *arg)
{
	int i, j, k;

	(void)memcpy(&arg->agg_eid, agg_dev->agg_eid, EID_LEN);
	for (i = 0; i < IODIE_NUM; i++)
		(void)memcpy(&arg->slave_eid[i].primary_eid,
				 agg_dev->ues[i].primary_eid, EID_LEN);

	for (j = 0; j < IODIE_NUM; j++) {
		for (k = 0; k < MAX_PORT_NUM; k++)
			(void)memcpy(&arg->slave_eid[j].port_eid[k],
					 agg_dev->ues[j].port_eid[k],
					 EID_LEN);
	}
}

static void
set_ubagg_device_attr_by_ubcore_cap(struct ubcore_device *dev,
				    struct ubcore_device_cap *dev_cap)
{
	dev->attr.dev_cap = *dev_cap;
}

static int init_ubagg_dev(struct ubagg_device *ubagg_dev,
			  struct ubagg_add_dev_by_uvs *arg)
{
	struct ubcore_device *dev = NULL;
	int slave_dev_idx = 0;
	int i, j, k;

	// init ubagg device
	(void)memcpy(ubagg_dev->master_dev_name, arg->master_dev_name,
		     UBAGG_MAX_DEV_NAME_LEN);
	(void)memcpy(&ubagg_dev->bonding_eid, &arg->agg_eid,
		     sizeof(union ubcore_eid));
	ubagg_log_info("master dev name: %s, eid : " EID_FMT "\n",
		ubagg_dev->master_dev_name,
		EID_ARGS(arg->agg_eid));
	for (i = 0; i < IODIE_NUM; i++) {
		if (!is_eid_valid((char *)&arg->slave_eid[i].primary_eid.raw)) {
			ubagg_log_err("primary slave %d eid is invalid\n", i);
			continue;
		}

		dev = ubcore_get_device_by_eid(&arg->slave_eid[i].primary_eid,
					       UBCORE_TRANSPORT_UB);
		if (dev == NULL) {
			ubagg_log_err(
				"primary slave %d dev not exist, eid: " EID_FMT
				"\n",
				i, EID_ARGS(arg->slave_eid[i].primary_eid));
			return -1;
		}
		if (slave_dev_idx == 0)
			set_ubagg_device_attr_by_ubcore_cap(&ubagg_dev->ub_dev,
							    &dev->attr.dev_cap);

		(void)memcpy(ubagg_dev->slave_dev_name[slave_dev_idx],
			     dev->dev_name, UBAGG_MAX_DEV_NAME_LEN);
		slave_dev_idx++;
	}

	for (j = 0; j < IODIE_NUM; j++) {
		for (k = 0; k < MAX_PORT_NUM; k++) {
			if (!is_eid_valid(
				(char *)&arg->slave_eid[j].port_eid[k].raw)) {
				ubagg_log_err("port slave %d_%d eid is invalid\n", j, k);
				continue;
			}
			dev = ubcore_get_device_by_eid(
				&arg->slave_eid[j].port_eid[k],
				UBCORE_TRANSPORT_UB);
			if (dev == NULL) {
				ubagg_log_err(
					"port slave %d_%d dev not exist, eid: " EID_FMT
					"\n",
					j, k,
					EID_ARGS(
						arg->slave_eid[j].port_eid[k]));
				return -1;
			}
			if (slave_dev_idx == 0)
				set_ubagg_device_attr_by_ubcore_cap(
					&ubagg_dev->ub_dev, &dev->attr.dev_cap);

			(void)memcpy(ubagg_dev->slave_dev_name[slave_dev_idx],
				     dev->dev_name, UBAGG_MAX_DEV_NAME_LEN);
			slave_dev_idx++;
		}
	}

	if (slave_dev_idx == 0) {
		ubagg_log_err("slave devs is null\n");
		return -1;
	}

	ubagg_dev->slave_dev_num = slave_dev_idx;
	return 0;
}

static int init_ubagg_res(struct ubagg_device *ubagg_dev)
{
	int ret = 0;
	int i = 0;
	int j = 0;

	ret = alloc_ubagg_dev_bitmap(ubagg_dev);
	if (ret != 0) {
		ubagg_log_err("ubagg alloc bitmap fail\n");
		return ret;
	}

	for (i = 0; i < UBAGG_HT_MAX; i++) {
		ret = ubagg_hash_table_alloc(&ubagg_dev->ubagg_ht[i],
					     &g_ubagg_ht_params[i]);
		if (ret != 0) {
			ubagg_log_err("Fail to init hash map:%d.\n", i);
			goto FREE_HMAP;
		}
	}

	return 0;

FREE_HMAP:
	for (j = 0; j < i; j++)
		ubagg_hash_table_free(&ubagg_dev->ubagg_ht[j]);
	free_ubagg_dev_bitmap(ubagg_dev);

	return -ENOMEM;
}

static void uninit_ubagg_res(struct ubagg_device *ubagg_dev)
{
	int i = 0;

	free_ubagg_dev_bitmap(ubagg_dev);
	for (i = 0; i < UBAGG_HT_MAX; i++)
		ubagg_hash_table_free(&ubagg_dev->ubagg_ht[i]);
}

static int init_ubagg_ubcore_dev(struct ubagg_device *ubagg_dev,
				 struct ubagg_add_dev_by_uvs *arg)
{
	int ret = 0;

	(void)memcpy(ubagg_dev->ub_dev.dev_name, arg->master_dev_name,
		     UBAGG_MAX_DEV_NAME_LEN);
	ubagg_dev->ub_dev.ops = &g_ubagg_dev_ops;
	ubagg_dev->ub_dev.attr.tp_maintainer = false;
	ubagg_dev->ub_dev.attr.dev_cap.max_eid_cnt = UBAGG_DEVICE_MAX_EID_CNT;

	ret = ubcore_register_device(&ubagg_dev->ub_dev);
	if (ret != 0) {
		ubagg_log_err("ubcore register device fail, name:%s\n",
			      arg->master_dev_name);
		free_ubagg_dev_bitmap(ubagg_dev);
		ubagg_dev_ref_put(ubagg_dev);
		return ret;
	}

	ubagg_dev->ub_dev.eid_table.eid_entries[0].eid_index = 0;
	ubagg_dev->ub_dev.eid_table.eid_entries[0].net = &init_net;
	(void)memcpy(&ubagg_dev->ub_dev.eid_table.eid_entries[0].eid,
		     &arg->agg_eid, UBAGG_EID_SIZE);
	ubagg_dev->ub_dev.eid_table.eid_entries[0].valid = true;

	return 0;
}

static int add_dev_to_list(struct ubagg_device *ubagg_dev)
{
	struct ubagg_device *cur = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	list_for_each_entry(cur, &g_ubagg_dev_list, list_node) {
		if (strncmp(cur->ub_dev.dev_name, ubagg_dev->ub_dev.dev_name,
			    UBAGG_MAX_DEV_NAME_LEN) == 0) {
			spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
			return -EEXIST;
		}
	}
	list_add_tail(&ubagg_dev->list_node, &g_ubagg_dev_list);
	ubagg_dev_ref_get(ubagg_dev);
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
	return 0;
}

static void rmv_dev_from_list(struct ubagg_device *ubagg_dev)
{
	struct ubagg_device *cur = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	list_for_each_entry(cur, &g_ubagg_dev_list, list_node) {
		if (strncmp(cur->ub_dev.dev_name, ubagg_dev->ub_dev.dev_name,
			    UBAGG_MAX_DEV_NAME_LEN) == 0) {
			list_del(&cur->list_node);
			ubagg_dev_ref_put(ubagg_dev);
			spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
			ubagg_log_info("ubagg dev %s removed from list\n",
				ubagg_dev->ub_dev.dev_name);
			return;
		}
	}
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
}

static int add_dev_by_uvs(struct ubagg_add_dev_by_uvs *arg)
{
	struct ubagg_device *ubagg_dev = NULL;

	if (ubagg_dev_exists(arg->master_dev_name)) {
		ubagg_log_err("ubagg dev already exist, name:%s\n",
			      arg->master_dev_name);
		return -EEXIST;
	}

	ubagg_dev = kzalloc(sizeof(struct ubagg_device), GFP_KERNEL);
	if (ubagg_dev == NULL)
		return -ENOMEM;
	kref_init(&ubagg_dev->ref);

	if (init_ubagg_dev(ubagg_dev, arg) != 0) {
		ubagg_log_err("init ubagg dev fail, name:%s\n",
			      arg->master_dev_name);
		goto PUT_DEV;
	}

	if (init_ubagg_res(ubagg_dev) != 0) {
		ubagg_log_err("init ubagg res fail, name:%s\n",
			      arg->master_dev_name);
		goto PUT_DEV;
	}

	if (init_ubagg_ubcore_dev(ubagg_dev, arg) != 0) {
		ubagg_log_err("init ubagg ubcore fail, name:%s\n",
			      arg->master_dev_name);
		goto UNINIT_UBAGG_RES;
	}

	if (add_dev_to_list(ubagg_dev) != 0) {
		ubagg_log_err("add dev to list fail, name:%s\n",
			      arg->master_dev_name);
		goto UNINIT_UBCORE_DEV;
	}

	return 0;

UNINIT_UBCORE_DEV:
	ubcore_unregister_device(&ubagg_dev->ub_dev);
UNINIT_UBAGG_RES:
	uninit_ubagg_res(ubagg_dev);
PUT_DEV:
	ubagg_dev_ref_put(ubagg_dev);

	return -ENODEV;
}

static bool is_eid_empty(const char *eid)
{
	int i;

	for (i = 0; i < EID_LEN; i++) {
		if (eid[i] != 0)
			return false;
	}
	return true;
}

static void find_add_master_dev(const char *agg_eid, const char *name)
{
	int i;
	int empty_index = -1;

	mutex_lock(&g_name_eid_arr_lock);
	for (i = 0; i < UBAGG_MAX_BONDING_DEV_NUM; i++) {
		if (is_eid_empty(g_name_eid_arr[i].agg_eid)) {
			empty_index = i;
			break;
		}
	}
	if (empty_index == -1) {
		mutex_unlock(&g_name_eid_arr_lock);
		ubagg_log_err("g_name_eid_arr is full, max dev num is %d",
			      UBAGG_MAX_BONDING_DEV_NUM);
		return;
	}
	(void)memcpy(g_name_eid_arr[empty_index].agg_eid, agg_eid,
		     EID_LEN);
	(void)snprintf(g_name_eid_arr[empty_index].master_dev_name,
		       UBAGG_MAX_DEV_NAME_LEN, "%s", name);
	mutex_unlock(&g_name_eid_arr_lock);
}

static void print_topo_map(struct ubagg_topo_map *topo_map)
{
	int node_idx, dev_idx, iodie_idx, port_idx;
	struct ubagg_topo_node *node;

	if (!topo_map) {
		ubagg_log_err("topo_map is NULL\n");
		return;
	}

	ubagg_log_info(
		"========================== topo map start =============================\n");
	for (node_idx = 0; node_idx < topo_map->node_num; node_idx++) {
		node = &topo_map->topo_infos[node_idx];

		ubagg_log_info(
			"===================== node %u start(is_current:%d) =======================\n",
			node->node_id, node->is_current);

		/* print link table for this node */
		for (iodie_idx = 0; iodie_idx < IODIE_NUM; iodie_idx++) {
			for (port_idx = 0; port_idx < MAX_PORT_NUM; port_idx++) {
				ubagg_log_info("link[iodie_idx:%d][port_idx:%d] -> ",
					iodie_idx,
					port_idx);
				ubagg_log_info(
					"peer_node: %u, peer_iodie: %u, peer_port: %u\n",
					node->links[iodie_idx][port_idx].peer_node,
					node->links[iodie_idx][port_idx].peer_iodie,
					node->links[iodie_idx][port_idx].peer_port);
			}
		}

		/* print device list (only devices with valid agg_eid) */
		for (dev_idx = 0; dev_idx < DEV_NUM; dev_idx++) {
			if (!is_eid_valid(node->agg_devs[dev_idx].agg_eid))
				continue;

			ubagg_log_info("---- dev %d agg_eid: " EID_FMT "\n", dev_idx,
				EID_RAW_ARGS(node->agg_devs[dev_idx].agg_eid));

			for (iodie_idx = 0; iodie_idx < IODIE_NUM; iodie_idx++) {
				ubagg_log_info("------ chip_id[%d]: %u\n", iodie_idx,
					node->agg_devs[dev_idx].ues[iodie_idx].chip_id);

				ubagg_log_info("------ entity_id[%d]: %u\n", iodie_idx,
					node->agg_devs[dev_idx].ues[iodie_idx].entity_id);

				ubagg_log_info("------ primary_eid[%d]: " EID_FMT "\n", iodie_idx,
					EID_RAW_ARGS(
					node->agg_devs[dev_idx].ues[iodie_idx].primary_eid));

				for (port_idx = 0; port_idx < MAX_PORT_NUM; port_idx++) {
					ubagg_log_info("-------- port_eid[%d][%d]: " EID_FMT "\n",
					iodie_idx, port_idx,
					EID_RAW_ARGS(
					node->agg_devs[dev_idx].ues[
						iodie_idx].port_eid[port_idx]
					));
				}
			}
		}

		ubagg_log_info(
			"===================== node %d end =======================\n",
			node->node_id);
	}
	ubagg_log_info(
		"========================== topo map end =============================\n");
}

static int ubagg_cmd_set_topo_info(struct ubagg_cmd_hdr *hdr)
{
	struct ubagg_set_topo_info arg;
	struct ubagg_topo_map *new_topo_map;
	struct ubagg_topo_map *topo_map;
	int ret;

	if (hdr->args_len != sizeof(struct ubagg_set_topo_info)) {
		ubagg_log_err(
			"set topo info, args_len is invalid, args_len:%u\n",
			hdr->args_len);
		return -EINVAL;
	}

	ret = copy_from_user(&arg, (void __user *)hdr->args_addr,
			     hdr->args_len);
	if (ret != 0) {
		ubagg_log_err("copy_from_user fail.");
		return ret;
	}
	if (arg.in.topo == NULL || arg.in.topo_num == 0 ||
	    arg.in.topo_num > MAX_NODE_NUM) {
		ubagg_log_err("Invalid set_topo_info param\n");
		return -EINVAL;
	}
	topo_map = get_global_ubagg_map();
	if (topo_map == NULL) {
		topo_map = create_global_ubagg_topo_map(arg.in.topo,
							arg.in.topo_num);
		if (topo_map == NULL) {
			ubagg_log_err("Failed to create topo map\n");
			return -ENOMEM;
		}
	} else {
		// update topo_map
		new_topo_map = create_ubagg_topo_map_from_user(arg.in.topo,
							       arg.in.topo_num);
		if (ubagg_update_topo_info(new_topo_map, topo_map) != 0) {
			delete_ubagg_topo_map(new_topo_map);
			ubagg_log_err("Failed to update topo info\n");
			return -1;
		}
		delete_ubagg_topo_map(new_topo_map);
	}

	print_topo_map(topo_map);

	return 0;
}

void ubagg_delete_topo_map(void)
{
	delete_global_ubagg_topo_map();
}

static int ubagg_create_dev(struct ubagg_create_dev_arg *arg)
{
	struct ubagg_add_dev_by_uvs uvs_arg = {0};
	struct ubagg_topo_agg_dev *agg_dev;
	struct ubagg_topo_node *cur_node;
	struct ubagg_topo_map *topo_map;
	uint32_t dev_name_len = 0;
	int ret;
	int i;

	if (is_eid_empty(arg->in.agg_eid.raw)) {
		ubagg_log_err("agg_eid is empty\n");
		return -EINVAL;
	}

	dev_name_len = strnlen(arg->in.dev_name, UBAGG_MAX_DEV_NAME_LEN);
	if (dev_name_len == 0 || dev_name_len >= UBAGG_MAX_DEV_NAME_LEN) {
		ubagg_log_err("dev_name is invalid\n");
		return -EINVAL;
	}

	if (has_add_dev_by_agg_eid(arg->in.agg_eid.raw)) {
		ubagg_log_err("has add dev by aggr eid: " EID_FMT "\n",
				   EID_RAW_ARGS(arg->in.agg_eid.raw));
		return -EEXIST;
	}

	if (ubagg_dev_exists(arg->in.dev_name)) {
		ubagg_log_err("ubagg dev already exist, name:%s\n",
			      arg->in.dev_name);
		return -EEXIST;
	}

	topo_map = get_global_ubagg_map();
	if (topo_map == NULL) {
		ubagg_log_err("global topo map is NULL\n");
		return -EINVAL;
	}

	cur_node = find_cur_topo_node(topo_map);
	if (cur_node == NULL) {
		ubagg_log_err("find cur node index failed\n");
		return -EINVAL;
	}

	for (i = 0; i < DEV_NUM; i++)
		if (is_eid_match(cur_node->agg_devs[i].agg_eid, arg->in.agg_eid.raw)) {
			agg_dev = &(cur_node->agg_devs[i]);
			break;
		}

	if (agg_dev == NULL) {
		ubagg_log_err("eid: " EID_FMT " not found in current node\n",
					EID_RAW_ARGS(arg->in.agg_eid.raw));
		return -ENODEV;
	}

	(void)snprintf(uvs_arg.master_dev_name, UBAGG_MAX_DEV_NAME_LEN, "%s",
				arg->in.dev_name);

	fill_add_dev_cfg(agg_dev, &uvs_arg);

	ret = add_dev_by_uvs(&uvs_arg);
	if (ret != 0) {
		ubagg_log_err("add ubagg dev by uvs failed, ret:%d\n", ret);
		return ret;
	}

	find_add_master_dev(arg->in.agg_eid.raw, arg->in.dev_name);
	return 0;
}

static int ubagg_cmd_create_dev(struct ubagg_cmd_hdr *hdr)
{
	struct ubagg_create_dev_arg arg;
	int ret;

	if (hdr->args_len != sizeof(struct ubagg_create_dev_arg)) {
		ubagg_log_err("create dev, args_len invalid: %u\n",
				  hdr->args_len);
		return -EINVAL;
	}

	ret = copy_from_user(&arg, (void __user *)hdr->args_addr, hdr->args_len);
	if (ret != 0) {
		ubagg_log_err("copy_from_user fail.\n");
		return -EFAULT;
	}

	ret = ubagg_create_dev(&arg);
	if (ret != 0) {
		ubagg_log_err("ubagg_create_dev failed, ret:%d\n", ret);
		return ret;
	}

	return 0;
}

static int ubagg_find_name_by_agg_eid(const char *agg_eid, char *master_dev_name)
{
	int ret = -1;
	int i;

	if (!master_dev_name)
		return -EINVAL;

	mutex_lock(&g_name_eid_arr_lock);
	for (i = 0; i < UBAGG_MAX_BONDING_DEV_NUM; i++) {
		if (is_eid_match(agg_eid, g_name_eid_arr[i].agg_eid)) {
			(void)strscpy(master_dev_name, g_name_eid_arr[i].master_dev_name,
				UBAGG_MAX_DEV_NAME_LEN);
			ret = 0;
			break;
		}
	}
	mutex_unlock(&g_name_eid_arr_lock);

	if (ret != 0)
		master_dev_name[0] = '\0';

	return ret;
}

static void find_delete_master_dev(const char *agg_eid, const char *name)
{
	int i;

	if (agg_eid == NULL || name == NULL) {
		ubagg_log_err("agg_eid or name is NULL\n");
		return;
	}

	mutex_lock(&g_name_eid_arr_lock);
	for (i = 0; i < UBAGG_MAX_BONDING_DEV_NUM; i++) {
		if (is_eid_empty(g_name_eid_arr[i].agg_eid))
			continue;

		if (is_eid_match(agg_eid, g_name_eid_arr[i].agg_eid) &&
			strncmp(g_name_eid_arr[i].master_dev_name, name,
				UBAGG_MAX_DEV_NAME_LEN) == 0) {
			memset(g_name_eid_arr[i].agg_eid, 0, EID_LEN);
			memset(g_name_eid_arr[i].master_dev_name, 0,
				   UBAGG_MAX_DEV_NAME_LEN);
			mutex_unlock(&g_name_eid_arr_lock);
			return;
		}
	}
	mutex_unlock(&g_name_eid_arr_lock);

	ubagg_log_err("can not find to delete, bonding eid: " EID_FMT ", name:%s\n",
			  EID_RAW_ARGS(agg_eid), name);
}

static struct ubagg_device *ubagg_find_dev_by_agg_eid(const char *agg_eid)
{
	char master_dev_name[UBAGG_MAX_DEV_NAME_LEN] = {0};
	struct ubagg_device *dev;
	int ret;

	ret = ubagg_find_name_by_agg_eid(agg_eid, master_dev_name);
	if (ret != 0) {
		ubagg_log_err("no master dev name for bonding eid: " EID_FMT "\n",
					  EID_RAW_ARGS(agg_eid));
		return NULL;
	}

	dev = ubagg_find_dev_by_name(master_dev_name);
	if (dev == NULL) {
		ubagg_log_err("ubagg dev not exist by name:%s\n", master_dev_name);
		find_delete_master_dev(agg_eid, master_dev_name);
		return NULL;
	}

	return dev;
}

static int ubagg_delete_dev(const struct ubagg_delete_dev_arg *arg)
{
	struct ubagg_topo_agg_dev *agg_dev;
	struct ubagg_topo_node *cur_node;
	struct ubagg_topo_map *topo_map;
	struct ubagg_device *dev;
	int i;

	if (is_eid_empty(arg->in.agg_eid.raw)) {
		ubagg_log_err("agg_eid is empty\n");
		return -EINVAL;
	}

	if (!has_add_dev_by_agg_eid(arg->in.agg_eid.raw)) {
		ubagg_log_err("no ubagg dev by aggr eid: " EID_FMT "\n",
				   EID_RAW_ARGS(arg->in.agg_eid.raw));
		return -EEXIST;
	}

	topo_map = get_global_ubagg_map();
	if (topo_map == NULL) {
		ubagg_log_err("global topo map is NULL\n");
		return -EINVAL;
	}

	cur_node = find_cur_topo_node(topo_map);
	if (cur_node == NULL) {
		ubagg_log_err("find cur node index failed\n");
		return -EINVAL;
	}

	for (i = 0; i < DEV_NUM; i++)
		if (is_eid_match(cur_node->agg_devs[i].agg_eid, arg->in.agg_eid.raw)) {
			agg_dev = &(cur_node->agg_devs[i]);
			break;
		}

	if (agg_dev == NULL) {
		ubagg_log_err("eid: " EID_FMT " not found in current node\n",
					EID_RAW_ARGS(arg->in.agg_eid.raw));
		return -ENODEV;
	}

	dev = ubagg_find_dev_by_agg_eid(arg->in.agg_eid.raw);
	if (dev == NULL) {
		ubagg_log_err("ubagg dev not exist by agg eid: " EID_FMT "\n",
					EID_RAW_ARGS(arg->in.agg_eid.raw));
		return -ENODEV;
	}

	find_delete_master_dev(arg->in.agg_eid.raw, dev->master_dev_name);
	rmv_dev_from_list(dev);
	ubcore_unregister_device(&dev->ub_dev);
	uninit_ubagg_res(dev);

	ubagg_dev_ref_put(dev);

	return 0;
}

static int ubagg_cmd_delete_dev(struct ubagg_cmd_hdr *hdr)
{
	struct ubagg_delete_dev_arg arg;
	int ret;

	if (hdr->args_len != sizeof(struct ubagg_delete_dev_arg)) {
		ubagg_log_err("delete dev, args_len invalid: %u\n",
				  hdr->args_len);
		return -EINVAL;
	}

	ret = copy_from_user(&arg, (void __user *)hdr->args_addr, hdr->args_len);
	if (ret != 0) {
		ubagg_log_err("copy_from_user fail.\n");
		return -EFAULT;
	}

	ret = ubagg_delete_dev(&arg);
	if (ret != 0) {
		ubagg_log_err("ubagg_delete_dev failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static int ubagg_get_dev_name(struct ubagg_get_dev_name_arg *arg)
{
	struct ubcore_device *dev = NULL;

	if (is_eid_empty(arg->in.eid.raw)) {
		ubagg_log_err("Invalid get_dev_name param\n");
		return -EINVAL;
	}

	dev = ubcore_get_device_by_eid(&arg->in.eid, UBCORE_TRANSPORT_UB);
	if (dev == NULL) {
		ubagg_log_info("no ubcore dev for bonding eid: " EID_FMT "\n",
					  EID_RAW_ARGS(arg->in.eid.raw));
		return -ENODEV;
	}

	(void)strscpy(arg->out.dev_name, dev->dev_name, UBAGG_MAX_DEV_NAME_LEN);

	return 0;
}

static int ubagg_cmd_get_dev_name(struct ubagg_cmd_hdr *hdr)
{
	struct ubagg_get_dev_name_arg arg;
	int ret;

	if (hdr->args_len != sizeof(struct ubagg_get_dev_name_arg)) {
		ubagg_log_err("get dev name, args_len invalid: %u\n",
				  hdr->args_len);
		return -EINVAL;
	}

	ret = copy_from_user(&arg, (void __user *)hdr->args_addr, hdr->args_len);
	if (ret != 0) {
		ubagg_log_err("copy_from_user fail.\n");
		return -EFAULT;
	}

	ret = ubagg_get_dev_name(&arg);
	if (ret != 0) {
		ubagg_log_info("ubagg_get_dev_name failed: %d\n", ret);
		return ret;
	}

	ret = copy_to_user((void __user *)hdr->args_addr, &arg, hdr->args_len);
	if (ret != 0) {
		ubagg_log_err("copy_to_user fail.\n");
		return ret;
	}

	return 0;
}

long ubagg_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ubagg_cmd_hdr hdr;
	int ret = 0;

	if (cmd != UBAGG_CMD || !capable(CAP_NET_ADMIN)) {
		ubagg_log_err("bad ubagg ioctl cmd!");
		return -ENOIOCTLCMD;
	}

	ret = copy_from_user(&hdr, (void *)arg, sizeof(struct ubagg_cmd_hdr));
	if (ret != 0) {
		ubagg_log_err("copy from user fail, ret:%d", ret);
		return -EFAULT;
	}
	switch (hdr.command) {
	case UBAGG_CMD_ADD_DEV:
	case UBAGG_CMD_RMV_DEV:
		return 0;
	case UBAGG_CMD_SET_TOPO_INFO:
		return ubagg_cmd_set_topo_info(&hdr);
	case UBAGG_CMD_CREATE_DEV:
		return ubagg_cmd_create_dev(&hdr);
	case UBAGG_CMD_DELETE_DEV:
		return ubagg_cmd_delete_dev(&hdr);
	case UBAGG_CMD_GET_DEV_NAME:
		return ubagg_cmd_get_dev_name(&hdr);
	default:
		ubagg_log_err("Wrong command type:%u", hdr.command);
		return -EINVAL;
	}
}

void ubagg_clear_dev_list(void)
{
	struct ubagg_device *dev, *next = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	list_for_each_entry_safe(dev, next, &g_ubagg_dev_list, list_node) {
		list_del_init(&dev->list_node);
		ubcore_unregister_device(&dev->ub_dev);
		free_ubagg_dev_bitmap(dev);
		ubagg_dev_ref_put(dev);
		ubagg_dev_ref_put(dev);
	}
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
}
