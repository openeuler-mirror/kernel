// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore tp implementation
 * Author: Yan Fangfang
 * Create: 2022-08-25
 * Note:
 * History: 2022-08-25: Create file
 */

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/netevent.h>
#include <net/ip6_route.h>
#include <net/ipv6_stubs.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <ub/urma/ubcore_types.h>
#include "ub/urma/ubcore_perf.h"
#include "ubcore_tp.h"
#include "ubcore_priv.h"
#include "ubcore_log.h"
#include "ubcore_dmac.h"
#include "ubcore_hash_table.h"

int ubcore_check_tp_type_valid(enum ubcore_transport_mode trans_mode, uint32_t tp_mode)
{
	if ((trans_mode != UBCORE_TP_UM && tp_mode == UBCORE_UTP) ||
		(trans_mode == UBCORE_TP_UM && tp_mode == UBCORE_RTP)) {
		ubcore_log_err_rl("UTP/UM setting conflict, transmode=%d, tpmode=%d",
						trans_mode, tp_mode);
		return -1;
	}
	return 0;
}

static void ubcore_tpid_list_kref_release(struct kref *ref_cnt)
{
	struct ubcore_tpid_list *tpid_list =
		container_of(ref_cnt, struct ubcore_tpid_list, ref_cnt);

	complete(&tpid_list->comp);
}

void ubcore_tpid_list_kref_put(struct ubcore_tpid_list *tpid_list)
{
	if (tpid_list == NULL) {
		ubcore_log_err_rl("tpid_list is NULL");
		return;
	}
	(void)kref_put(&tpid_list->ref_cnt, ubcore_tpid_list_kref_release);
}

void ubcore_tpid_list_get(void *obj)
{
	struct ubcore_tpid_list *tpid_list = obj;
	kref_get(&tpid_list->ref_cnt);
}

static int ubcore_free_tpid_list(struct ubcore_tpid_list *tpid_list)
{
	struct ubcore_tpid_list_node *entry, *next;

	list_for_each_entry_safe(entry, next, &tpid_list->create_list, node) {
		list_del(&entry->node);
		kfree(entry);
	}

	ubcore_tpid_list_kref_put(tpid_list);
	wait_for_completion(&tpid_list->comp);
	mutex_destroy(&tpid_list->lock);

	kfree(tpid_list);

	return 0;
}

struct ubcore_tpid_list *ubcore_ht_find_get_tpid_list(struct ubcore_device *dev,
	struct ubcore_tpid_list_key *key)
{
	struct ubcore_hash_table *ht = NULL;
	uint32_t hash;

	ht = &dev->ht[UBCORE_HT_TPID_LIST];

	hash = ubcore_get_tpid_list_hash(ht, &key->local_eid);

	return ubcore_hash_table_lookup_get(ht, hash, &key->local_eid);
}

static int ubcore_find_add_tpid_list(struct ubcore_device *dev,
				      struct ubcore_tpid_list *new_tpid_list,
				      struct ubcore_tpid_list **exist_tpid_list,
				      struct ubcore_tpid_list_key *key)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	ht = &dev->ht[UBCORE_HT_TPID_LIST];

	hash = ubcore_get_tpid_list_hash(ht, &key->local_eid);

	spin_lock(&ht->lock);
	*exist_tpid_list = ubcore_hash_table_lookup_nolock_get(ht, hash, key);
	if (*exist_tpid_list != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}

	ubcore_hash_table_add_nolock(ht, &new_tpid_list->hnode, hash);
	ubcore_tpid_list_get(new_tpid_list);
	spin_unlock(&ht->lock);
	return 0;
}

static void ubcore_set_tpid_list_key(struct ubcore_device *dev,
					struct ubcore_get_tp_cfg *cfg,
					struct ubcore_tpid_list_key *tpid_list_key)
{
	tpid_list_key->local_eid = cfg->local_eid;
	tpid_list_key->peer_eid = cfg->peer_eid;
	tpid_list_key->trans_mode = cfg->trans_mode;
	memset(&tpid_list_key->local_cna, 0, sizeof(tpid_list_key->local_cna));
	memset(&tpid_list_key->peer_cna, 0, sizeof(tpid_list_key->peer_cna));

	if (cfg->flag.bs.rtp)
		tpid_list_key->tp_type = UBCORE_RTP;
	if (cfg->flag.bs.ctp) {
		tpid_list_key->trans_mode = UBCORE_TP_RM;
		tpid_list_key->tp_type = UBCORE_CTP;
	}
	if (cfg->flag.bs.utp)
		tpid_list_key->tp_type = UBCORE_UTP;

	if (cfg->flag.bs.uboe)
		tpid_list_key->link_type = UBCORE_LINK_UBOE;
	else
		tpid_list_key->link_type = UBCORE_LINK_ETHERNET;
}

int validate_get_tp_cfg(struct ubcore_get_tp_cfg *cfg)
{
	uint32_t tp_type;

	if (cfg->flag.bs.ctp) {
		tp_type = UBCORE_CTP;
		if (cfg->flag.bs.uboe) {
			ubcore_log_err_rl("Tp type ctp and uboe conflict.\n");
			return -EINVAL;
		}
	}
	if (cfg->flag.bs.rtp)
		tp_type = UBCORE_RTP;
	if (cfg->flag.bs.utp)
		tp_type = UBCORE_UTP;
	if (ubcore_check_tp_type_valid(cfg->trans_mode, tp_type) != 0)
		return -EINVAL;
	return 0;
}

static struct ubcore_tpid_list *ubcore_create_tpid_list(struct ubcore_device *dev,
						 struct ubcore_tpid_list_key *key)
{
	struct ubcore_tpid_list *new_tpid_list = NULL;

	new_tpid_list = kcalloc(1, sizeof(struct ubcore_tpid_list), GFP_KERNEL);
	if (IS_ERR_OR_NULL(new_tpid_list)) {
		ubcore_log_err("Failed to alloc tpid list.\n");
		return NULL;
	}

	kref_init(&new_tpid_list->ref_cnt);
	init_completion(&new_tpid_list->comp);
	mutex_init(&new_tpid_list->lock);
	new_tpid_list->ub_dev = dev;
	new_tpid_list->lk.local_eid  = key->local_eid;
	new_tpid_list->lk.peer_eid   = key->peer_eid;
	new_tpid_list->lk.trans_mode = key->trans_mode;
	new_tpid_list->lk.share_mode = key->share_mode;
	new_tpid_list->lk.tp_type    = key->tp_type;
	new_tpid_list->lk.link_type  = key->link_type;
	INIT_LIST_HEAD(&new_tpid_list->create_list);
	new_tpid_list->cnt = 0;

	return new_tpid_list;
}

static int init_state_for_tpid(struct ubcore_device *dev,
			       struct ubcore_tpid_list *tpid_list,
			       int begin, int end);

static int ubcore_update_tpid_list(struct ubcore_device *dev,
					   struct ubcore_tp_info *ops_tp_list,
					   struct ubcore_tpid_list *tpid_list,
					   uint32_t actual_total_tp_cnt,
					   struct ubcore_get_tp_cfg *cfg)
{
	int ret;
	uint32_t idx;
	uint32_t new_cnt = 0;
	struct ubcore_tpid_list_node *node, *tmp;
	LIST_HEAD(new_list);

	new_cnt = actual_total_tp_cnt - tpid_list->cnt;

	for (idx = tpid_list->cnt; idx < actual_total_tp_cnt; idx++) {
		node = kcalloc(1, sizeof(struct ubcore_tpid_list_node), GFP_KERNEL);
		if (node == NULL)
			goto err_free_new_list;
		node->tp_info = ops_tp_list[idx];
		node->tp_info.tp_handle.bs.trans_mode = cfg->trans_mode;
		node->tp_info.tp_handle.bs.ctp = cfg->flag.bs.ctp;
		node->tp_info.tp_handle.bs.rtp = cfg->flag.bs.rtp;
		node->tp_info.tp_handle.bs.utp = cfg->flag.bs.utp;
		node->tp_info.tp_handle.bs.uboe = cfg->flag.bs.uboe;
		list_add_tail(&node->node, &new_list);
	}

	list_splice_tail(&new_list, &tpid_list->create_list);
	tpid_list->cnt += new_cnt;

	ret = init_state_for_tpid(dev, tpid_list,
				  tpid_list->cnt - new_cnt, tpid_list->cnt);
	if (ret != 0) {
		tpid_list->cnt -= new_cnt;
		while (new_cnt-- > 0) {
			node = list_last_entry(&tpid_list->create_list,
				struct ubcore_tpid_list_node, node);
			list_del(&node->node);
			kfree(node);
		}
		ubcore_log_err_rl("Failed to init state for tpid list, ret = %d.\n", ret);
		return ret;
	}

	ubcore_log_info("Update tpid list success, cnt = %d.\n", tpid_list->cnt);
	return 0;

err_free_new_list:
	list_for_each_entry_safe(node, tmp, &new_list, node) {
		list_del(&node->node);
		kfree(node);
	}
	return -ENOMEM;
}

static int ubcore_get_tp_list_from_ops(struct ubcore_device *dev,
					struct ubcore_get_tp_cfg *cfg, uint32_t *tp_cnt,
					struct ubcore_tp_info *temp_buf,
					struct ubcore_udata *udata)
{
	int ret;
	uint32_t req_total_tp_cnt = 0;
	uint32_t actual_total_tp_cnt = 0;
	uint32_t req_group_tp_cnt = 0;
	uint32_t actual_group_tp_cnt = 0;
	uint32_t group_num = 1;
	uint32_t group_idx;

	if (temp_buf == NULL) {
		ubcore_log_err("tpid_list temp buf is null.\n");
		return -EINVAL;
	}

	req_total_tp_cnt = *tp_cnt;

	group_num = (req_total_tp_cnt + UBCORE_MAX_GET_TP_GROUP_CNT - 1) /
		UBCORE_MAX_GET_TP_GROUP_CNT;
	for (group_idx = 0; group_idx < group_num; group_idx++) {
		req_group_tp_cnt = (group_idx == group_num - 1) ?
			req_total_tp_cnt - group_idx * UBCORE_MAX_GET_TP_GROUP_CNT :
			UBCORE_MAX_GET_TP_GROUP_CNT;
		actual_group_tp_cnt = req_group_tp_cnt;
		cfg->flag.bs.group_id = group_idx;
		UBCORE_PERF_TRACE_BEGIN(PERF_UB_GET_TP_LIST);
		ret = dev->ops->get_tp_list(dev, cfg, &actual_group_tp_cnt,
			temp_buf + actual_total_tp_cnt, udata);
		UBCORE_PERF_TRACE_END(PERF_UB_GET_TP_LIST);
		if (ret != 0) {
			if (actual_total_tp_cnt > 0) {
				ubcore_log_info_rl("actual cnt < request cnt, end early.\n");
				ret = 0;
				break;
			}
			ubcore_log_err_rl("get tp list failed: total=%d idx=%d\n",
				req_total_tp_cnt, group_idx);
			ubcore_log_err_rl("req=%d actual=%d ret=%d.\n",
				req_group_tp_cnt, actual_group_tp_cnt, ret);
			return ret;
		}
		actual_total_tp_cnt += actual_group_tp_cnt;
		if (actual_group_tp_cnt < req_group_tp_cnt) {
			ubcore_log_info_rl("group_id = %d, actual %d < req %d, end early.\n",
				group_idx, actual_group_tp_cnt, req_group_tp_cnt);
			break;
		}
	}

	*tp_cnt = actual_total_tp_cnt;

	return ret;
}

static int ubcore_get_tp_list_helper(struct ubcore_device *dev, struct ubcore_get_tp_cfg *cfg,
	struct ubcore_tpid_list *tpid_list, struct ubcore_udata *udata,
	struct ubcore_tpid_list_key *tpid_list_key, struct ubcore_tp_info *new_tp_handle)
{
	int ret;
	uint32_t req_cnt = 0;
	uint32_t old_total_cnt;
	struct ubcore_tp_info *temp_buf = NULL;
	struct ubcore_tpid_list_node *new_node = NULL;

	old_total_cnt = tpid_list->cnt;
	req_cnt = old_total_cnt + 1;
	temp_buf = kcalloc(req_cnt, sizeof(struct ubcore_tp_info), GFP_KERNEL);
	if (temp_buf == NULL) {
		ubcore_log_err("Failed to alloc temp tpid_list buf.\n");
		return -ENOMEM;
	}

	ret = ubcore_get_tp_list_from_ops(dev, cfg, &req_cnt, temp_buf, udata);
	if (ret != 0) {
		ubcore_log_err_rl("Get tp list from ops failed, ret = %d.\n", ret);
		kfree(temp_buf);
		return -EINVAL;
	}

	ubcore_log_info_rl("Get tp list from ops success, cnt=%d, ret=%d.\n", req_cnt, ret);
	if (req_cnt > old_total_cnt) {
		ret = ubcore_update_tpid_list(dev, temp_buf, tpid_list, req_cnt, cfg);
		if (ret != 0) {
			ubcore_log_err_rl("Update tpid list failed, ret = %d.\n", ret);
			kfree(temp_buf);
			return -EINVAL;
		}
	} else {
		ubcore_log_err_rl("Tp_cnt is not increased, old_cnt: %u, new_cnt: %d.\n",
			old_total_cnt, req_cnt);
		kfree(temp_buf);
		return -EINVAL;
	}

	// get tp list from list last entry
	if (list_empty(&tpid_list->create_list)) {
		ubcore_log_err_rl("Tpid list head is empty after get tp list from ops.\n");
		kfree(temp_buf);
		return -EINVAL;
	}

	new_node = list_last_entry(&tpid_list->create_list, struct ubcore_tpid_list_node, node);
	*new_tp_handle = new_node->tp_info;
	kfree(temp_buf);
	return ret;
}

int ubcore_get_tp_list(struct ubcore_device *dev, struct ubcore_get_tp_cfg *cfg,
		       uint32_t *tp_cnt, struct ubcore_tp_info *tp_list,
		       struct ubcore_udata *udata)
{
	int idx, ret;
	uint32_t req_total_tp_cnt = 0;
	uint32_t actual_total_tp_cnt = 0;
	struct ubcore_tpid_cfg tpid_cfg = { 0 };
	union ubcore_tp_handle tp_handle;

	if (validate_get_tp_cfg(cfg) != 0)
		return -EINVAL;
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err_rl("Invalid parameter, trans_mode = %d.\n", (int)cfg->trans_mode);
		return -EINVAL;
	}

	req_total_tp_cnt = *tp_cnt;
	tpid_cfg.local_eid = cfg->local_eid;
	tpid_cfg.peer_eid = cfg->peer_eid;
	tpid_cfg.tp_mode = cfg->trans_mode;
	if (cfg->flag.bs.ctp)
		tpid_cfg.tp_type = UBCORE_CTP;
	if (cfg->flag.bs.rtp)
		tpid_cfg.tp_type = UBCORE_RTP;
	if (cfg->flag.bs.utp)
		tpid_cfg.tp_type = UBCORE_UTP;
	tpid_cfg.link_type = (cfg->flag.bs.uboe == 1) ? UBCORE_LINK_UBOE :
		UBCORE_LINK_ETHERNET;

	for (idx = 0; idx < req_total_tp_cnt; idx++) {
		ret = ubcore_create_tpid_priv(dev, &tpid_cfg, udata, &tp_handle);
		if (ret != 0) {
			if (actual_total_tp_cnt > 0) {
				ubcore_log_err_rl(
					"tpid num is insufficient, early end, actual_total_tp_cnt: %d.\n",
					actual_total_tp_cnt);
				goto success;
			}
			ubcore_log_err_rl("Failed to create tpid for tp_list.\n");
			return -ENOMEM;
		}
		tp_list[idx].tp_handle.value = tp_handle.value;
		actual_total_tp_cnt++;
	}

success:
	*tp_cnt = actual_total_tp_cnt;
	return 0;
}
EXPORT_SYMBOL(ubcore_get_tp_list);

static struct ubcore_tp_info *find_available_tp_id_nolock(struct ubcore_device *dev,
	struct ubcore_tpid_list *tpid_list)
{
	uint32_t tp_id;
	struct ubcore_tp_info *tp_info = NULL;
	struct ubcore_tpid_state *state = NULL;
	struct ubcore_tpid_list_node *entry;
	struct list_head *head;

	head = &tpid_list->create_list;
	if (list_empty(head))
		return NULL;

	list_for_each_entry(entry, head, node) {
		tp_info = &entry->tp_info;
		tp_id = tp_info->tp_handle.bs.tpid;
		ubcore_log_info_rl("tp_id=%u, cnt:%d.\n", tp_id,
							tpid_list->cnt);
		state = ubcore_find_get_tp_id_state_entry(dev, tp_id);
		if (state == NULL) {
			ubcore_log_err_rl("Failed to find state of tp_id = %u.\n", tp_id);
			continue;
		}
		ubcore_log_info_rl("tpid state: %d, alloced: %d.\n",
			state->tpid_status, state->alloced);
		mutex_lock(&state->lock);
		if (state->tpid_status != UBCORE_TPID_STATE_ERR && !state->alloced) {
			ubcore_log_info_rl("find available tp handle value: %llu.\n",
				tp_info->tp_handle.value);
			state->alloced = true;
			mutex_unlock(&state->lock);
			ubcore_tpid_state_kref_put(state);
			return tp_info;
		}
		mutex_unlock(&state->lock);
		ubcore_tpid_state_kref_put(state);
	}
	return NULL;
}

static struct ubcore_tp_info
*select_tpid(struct ubcore_device *dev, struct ubcore_tpid_list *tpid_list)
{
	struct ubcore_tp_info *tp_handle = NULL;

	ubcore_tpid_list_get(tpid_list);
	tp_handle = find_available_tp_id_nolock(dev, tpid_list);
	ubcore_tpid_list_kref_put(tpid_list);
	return tp_handle;
}

static struct ubcore_tpid_state
*make_tpid_state(struct ubcore_device *dev, struct ubcore_tpid_list *tpid_list,
				uint32_t tp_id, enum ubcore_tpid_status state)
{
	struct ubcore_tpid_state *entry = NULL;

	entry = kcalloc(1, sizeof(struct ubcore_tpid_state), GFP_KERNEL);
	if (entry == NULL) {
		ubcore_log_err_rl("Failed to alloc tpid state entry.\n");
		return NULL;
	}
	entry->ub_dev = dev;
	entry->tp_id = tp_id;
	entry->tpid_status = state;
	entry->alloced = false;
	entry->lk = tpid_list->lk;
	kref_init(&entry->ref_cnt);
	init_completion(&entry->comp);
	mutex_init(&entry->lock);
	return entry;
}

static int init_state_for_tpid(struct ubcore_device *dev,
	struct ubcore_tpid_list *tpid_list, int begin, int end)
{
	int ret;
	int i = 0;
	int rollback;
	uint32_t tpid;
	struct ubcore_tpid_list_node *entry;
	struct ubcore_tpid_state *state = NULL;

	list_for_each_entry(entry, &tpid_list->create_list, node) {
		if (i < begin) {
			i++;
			continue;
		}
		if (i >= end)
			break;
		tpid = entry->tp_info.tp_handle.bs.tpid;
		state = make_tpid_state(dev, tpid_list, tpid, UBCORE_TPID_STATE_RESET);
		if (state == NULL) {
			ubcore_log_err_rl("Failed to alloc tpid state entry.\n");
			ret = -ENOMEM;
			goto rollback;
		}
		ret = ubcore_find_add_tp_id_state_entry(dev, state);
		if (ret != 0) {
			ubcore_log_err_rl("Failed to add tpid state, tpid=%u, ret=%d.\n",
				tpid, ret);
			ubcore_tpid_state_kref_put(state);
			wait_for_completion(&state->comp);
			mutex_destroy(&state->lock);
			kfree(state);
			goto rollback;
		}
		ubcore_log_info_rl("init tpid state success, i=%d, tpid=%u, ret=%d.\n",
			i, tpid, ret);
		i++;
	}

	return 0;

rollback:
	rollback = 0;
	list_for_each_entry(entry, &tpid_list->create_list, node) {
		if (rollback < begin) {
			rollback++;
			continue;
		}
		if (rollback >= i)
			break;
		tpid = entry->tp_info.tp_handle.bs.tpid;
		state = ubcore_find_get_tp_id_state_entry(dev, tpid);
		if (state == NULL) {
			ubcore_log_err_rl("Failed to find state of tpid = %u.\n", tpid);
			break;
		}

		ubcore_tpid_state_kref_put(state);
		ubcore_remove_tp_id_state_entry(dev, state);
		ubcore_log_info_rl("delete tp id state in init state rollback.\n");
		rollback++;
	}
	return ret;
}

static int ubcore_query_select_tpid_list(struct ubcore_device *dev, struct ubcore_get_tp_cfg *cfg,
	struct ubcore_tp_info *selected_tpid, struct ubcore_udata *udata)
{
	int ret;
	uint32_t tp_id;
	struct ubcore_tpid_state *state = NULL;
	struct ubcore_tpid_list *old_tpid_list;
	struct ubcore_tpid_list *exist_tpid_list;
	struct ubcore_tpid_list_key tpid_list_key = {0};
	struct ubcore_tp_info *tp_selected = NULL;
	struct ubcore_tp_info new_tp_handle = {0};
	struct ubcore_tpid_list *tpid_list = NULL;

	if (validate_get_tp_cfg(cfg) != 0)
		return -EINVAL;
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err("Invalid parameter, trans_mode: %d.\n", (int)cfg->trans_mode);
		return -EINVAL;
	}
	ubcore_set_tpid_list_key(dev, cfg, &tpid_list_key);

	tpid_list = ubcore_ht_find_get_tpid_list(dev, &tpid_list_key);

	if (tpid_list == NULL) {
		tpid_list = ubcore_create_tpid_list(dev, &tpid_list_key);
		if (IS_ERR_OR_NULL(tpid_list)) {
			ubcore_log_err("failed to alloc new tpid list.\n");
			return -ENOMEM;
		}

		ret = ubcore_find_add_tpid_list(dev, tpid_list, &exist_tpid_list, &tpid_list_key);
		if (ret == -EEXIST && exist_tpid_list != NULL) {
			old_tpid_list = tpid_list;
			tpid_list = exist_tpid_list;
			(void)ubcore_free_tpid_list(old_tpid_list);
		}
	}

	mutex_lock(&tpid_list->lock);
	tp_selected = select_tpid(dev, tpid_list);
	if (!IS_ERR_OR_NULL(tp_selected)) {
		*selected_tpid = *tp_selected;
		mutex_unlock(&tpid_list->lock);
		ubcore_tpid_list_kref_put(tpid_list);
		return 0;
	}

	ret = ubcore_get_tp_list_helper(dev, cfg, tpid_list, udata,
			&tpid_list_key, &new_tp_handle);
	if (ret < 0) {
		ret = -ENOSPC;
		goto err_kref_put;
	}

	ubcore_log_info_rl("new_tp_handle handle value = %llu.\n", new_tp_handle.tp_handle.value);
	tp_id = new_tp_handle.tp_handle.bs.tpid;
	state = ubcore_find_get_tp_id_state_entry(dev, tp_id);
	if (state == NULL) {
		ubcore_log_err_rl("Failed to find state of tp_id = %u.\n", tp_id);
		ret = -ENOSPC;
		goto err_kref_put;
	}

	// if get from tp_list, state must be not ERR
	if (!state->alloced) {
		state->alloced = true;
		goto done;
	}
	ret = -1;
	ubcore_log_err("Unexpected failure updating tpid state: %d, ret=%d.\n",
		state->tpid_status, ret);
done:
	ubcore_tpid_state_kref_put(state);
	*selected_tpid = new_tp_handle;

err_kref_put:
	mutex_unlock(&tpid_list->lock);
	ubcore_tpid_list_kref_put(tpid_list);
	return ret;
}

int ubcore_create_tpid_priv(struct ubcore_device *dev, struct ubcore_tpid_cfg *cfg,
	struct ubcore_udata *udata, union ubcore_tp_handle *tp_handle)
{
	struct ubcore_get_tp_cfg get_cfg = {0};
	struct ubcore_tp_info selected = {0};
	int ret;

	if (dev == NULL || cfg == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -1;
	}

	ubcore_log_info_rl("Enter create tpid priv.\n");

	get_cfg.local_eid = cfg->local_eid;
	get_cfg.peer_eid = cfg->peer_eid;
	get_cfg.trans_mode = cfg->tp_mode;
	get_cfg.flag.bs.ctp = (cfg->tp_type == UBCORE_CTP);
	get_cfg.flag.bs.rtp = (cfg->tp_type == UBCORE_RTP);
	get_cfg.flag.bs.utp = (cfg->tp_type == UBCORE_UTP);
	get_cfg.flag.bs.uboe = (cfg->link_type != 0);

	if (validate_get_tp_cfg(&get_cfg) != 0)
		return -1;
	if (ubcore_check_trans_mode_valid(get_cfg.trans_mode) != true) {
		ubcore_log_err_rl("Invalid parameter, tp_mode: %d.\n", (int)cfg->tp_mode);
		return -1;
	}

	ret = ubcore_query_select_tpid_list(dev, &get_cfg, &selected, udata);
	if (ret != 0) {
		ubcore_log_err_rl("Failed to query/select tpid, ret = %d.\n", ret);
		return -1;
	}

	*tp_handle = selected.tp_handle;
	ubcore_log_info_rl("create tpid handle value = %llu.\n", selected.tp_handle.value);

	return 0;
}

struct ubcore_tpid *ubcore_create_tpid(struct ubcore_device *dev,
	struct ubcore_tpid_cfg *cfg, struct ubcore_udata *udata)
{
	union ubcore_tp_handle tp_handle = { 0 };
	struct ubcore_tpid *tpid = NULL;
	int ret;

	tpid = kzalloc(sizeof(*tpid), GFP_KERNEL);
	if (tpid == NULL)
		return NULL;

	ret = ubcore_create_tpid_priv(dev, cfg, udata, &tp_handle);
	if (ret != 0) {
		ubcore_log_err("Failed to create tpid, ret = %d.\n", ret);
		kfree(tpid);
		return NULL;
	}
	tpid->tp_handle = tp_handle;
	return tpid;
}
EXPORT_SYMBOL(ubcore_create_tpid);

int ubcore_query_tpid(struct ubcore_device *dev, uint32_t tpid, struct ubcore_tpid_attr *attr)
{
	struct ubcore_tpid_state *state = NULL;

	if (dev == NULL || attr == NULL)
		return -EINVAL;
	attr->mask = UBCORE_TPID_STATE;
	state = ubcore_find_get_tp_id_state_entry(dev, tpid);
	if (state == NULL) {
		ubcore_log_err("Failed to find tpid state, tpid = %u.\n", tpid);
		return -ENOENT;
	}
	mutex_lock(&state->lock);
	attr->state = state->tpid_status;
	mutex_unlock(&state->lock);
	ubcore_tpid_state_kref_put(state);
	return 0;
}
EXPORT_SYMBOL(ubcore_query_tpid);

int ubcore_delete_tpid_priv(struct ubcore_device *dev, uint32_t tpid_val)
{
	struct ubcore_tpid_state *state = NULL;
	struct ubcore_tpid_list *tpid_list = NULL;

	state = ubcore_find_get_tp_id_state_entry(dev, tpid_val);
	if (state == NULL) {
		ubcore_log_err_rl("Failed to find tpid state, tpid = %u.\n", tpid_val);
		return -EINVAL;
	}

	tpid_list = ubcore_ht_find_get_tpid_list(dev, &state->lk);
	if (tpid_list == NULL) {
		ubcore_log_err_rl("Failed to find tpid list in delete tpid.\n");
		ubcore_tpid_state_kref_put(state);
		return -EINVAL;
	}

	mutex_lock(&tpid_list->lock);
	state->alloced = false;
	mutex_unlock(&tpid_list->lock);

	ubcore_tpid_list_kref_put(tpid_list);
	ubcore_tpid_state_kref_put(state);
	return 0;
}

int ubcore_delete_tpid(struct ubcore_device *dev, struct ubcore_tpid *tpid)
{
	uint32_t tpid_val;

	if (dev == NULL || tpid == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	tpid_val = tpid->tp_handle.bs.tpid;
	kfree(tpid);
	return ubcore_delete_tpid_priv(dev, tpid_val);
}
EXPORT_SYMBOL(ubcore_delete_tpid);

int ubcore_modify_tpid(struct ubcore_device *dev, enum ubcore_tpid_status state,
	union ubcore_modify_tpid_cfg *cfg)
{
	int ret;
	uint32_t tp_id;
	struct ubcore_tpid_state *entry = NULL;
	enum ubcore_tpid_status old_state;

	if (!dev || cfg == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (state == UBCORE_TPID_STATE_RTS) {
		if (cfg->active_cfg == NULL) {
			ubcore_log_err("Invalid parameter for RTS state.\n");
			return -EINVAL;
		}
		tp_id = cfg->active_cfg->tp_handle.bs.tpid;
		entry = ubcore_find_get_tp_id_state_entry(dev, tp_id);
		if (entry == NULL) {
			ubcore_log_err_rl("Failed to find tpid state, tp_id = %u.\n", tp_id);
			return -EINVAL;
		}
		mutex_lock(&entry->lock);
		old_state = entry->tpid_status;
		if (old_state != UBCORE_TPID_STATE_RESET) {
			if (old_state != UBCORE_TPID_STATE_RTS)
				ubcore_log_err("Invalid state transition: %d -> RTS.\n", old_state);
			mutex_unlock(&entry->lock);
			ubcore_tpid_state_kref_put(entry);
			return (old_state == UBCORE_TPID_STATE_RTS) ? 0 : -EINVAL;
		}

		ret = ubcore_active_tp(dev, cfg->active_cfg);
		if (ret != 0) {
			mutex_unlock(&entry->lock);
			ubcore_tpid_state_kref_put(entry);
			return ret;
		}
		entry->tpid_status = state;
		mutex_unlock(&entry->lock);
		ubcore_tpid_state_kref_put(entry);
		return 0;
	}

	if (state == UBCORE_TPID_STATE_ERR) {
		if (cfg->deactive_cfg == NULL) {
			ubcore_log_err("Invalid parameter for ERR state.\n");
			return -EINVAL;
		}
		tp_id = cfg->deactive_cfg->tp_handle.bs.tpid;
		entry = ubcore_find_get_tp_id_state_entry(dev, tp_id);
		if (entry == NULL) {
			ubcore_log_err_rl("Failed to find tpid state, tp_id = %u.\n", tp_id);
			return -EINVAL;
		}
		mutex_lock(&entry->lock);
		old_state = entry->tpid_status;
		if (old_state != UBCORE_TPID_STATE_RTS) {
			ubcore_log_err("Invalid state transition: %d -> ERR.\n", old_state);
			mutex_unlock(&entry->lock);
			ubcore_tpid_state_kref_put(entry);
			return -EINVAL;
		}
		ret = ubcore_deactive_tp(dev, cfg->deactive_cfg->tp_handle,
			cfg->deactive_cfg->udata);
		if (ret != 0) {
			entry->tpid_status = UBCORE_TPID_STATE_ERR;
			mutex_unlock(&entry->lock);
			ubcore_tpid_state_kref_put(entry);
			return ret;
		}
		entry->tpid_status =
		(cfg->deactive_cfg->tp_handle.bs.rtp != 0) ?
		state : UBCORE_TPID_STATE_RESET;
		ubcore_log_info_rl("state transition: %d -> %d.\n", old_state, entry->tpid_status);
		mutex_unlock(&entry->lock);
		ubcore_tpid_state_kref_put(entry);
		return 0;
	}

	if (state == UBCORE_TPID_STATE_RESET) {
		if (cfg->flushdone_cfg == NULL) {
			ubcore_log_err("Invalid parameter for RESET state.\n");
			return -EINVAL;
		}
		tp_id = cfg->flushdone_cfg->tpid;
		entry = ubcore_find_get_tp_id_state_entry(dev, tp_id);
		if (entry == NULL) {
			ubcore_log_err_rl("Failed to find tpid state, tp_id = %u.\n", tp_id);
			return -EINVAL;
		}
		mutex_lock(&entry->lock);
		old_state = entry->tpid_status;
		if (old_state == UBCORE_TPID_STATE_RESET) {
			ubcore_log_warn_rl(
				"TPID %u state is already RESET, ignore flushdone event.\n",
				tp_id);
			mutex_unlock(&entry->lock);
			ubcore_tpid_state_kref_put(entry);
			return 0;
		}
		if (old_state != UBCORE_TPID_STATE_ERR) {
			ubcore_log_err_rl(
				"Invalid state transition: %d -> RESET, tp_id: %u.\n",
				old_state, tp_id);
			mutex_unlock(&entry->lock);
			ubcore_tpid_state_kref_put(entry);
			return -EINVAL;
		}
		entry->tpid_status = state;
		mutex_unlock(&entry->lock);
		ubcore_tpid_state_kref_put(entry);
		ubcore_log_info_rl("flush done completed.\n");
		return 0;
	}

	ubcore_log_err("Invalid state: %d.\n", state);
	return -EINVAL;
}

static void ubcore_tpid_state_kref_release(struct kref *ref_cnt)
{
	struct ubcore_tpid_state *tp_state_entry =
		container_of(ref_cnt, struct ubcore_tpid_state, ref_cnt);

	complete(&tp_state_entry->comp);
}

void ubcore_tpid_state_get(void *obj)
{
	struct ubcore_tpid_state *tp_state_entry = obj;

	if (tp_state_entry == NULL) {
		ubcore_log_err("tp_state_entry is NULL");
		return;
	}
	kref_get(&tp_state_entry->ref_cnt);
}

void ubcore_tpid_state_kref_put(struct ubcore_tpid_state *tp_state_entry)
{
	if (tp_state_entry == NULL) {
		ubcore_log_err("tp_state_entry is NULL");
		return;
	}
	(void)kref_put(&tp_state_entry->ref_cnt, ubcore_tpid_state_kref_release);
}

struct ubcore_tpid_state *ubcore_find_get_tp_id_state_entry(
	struct ubcore_device *dev, uint64_t tp_id)
{
	struct ubcore_hash_table *ht = NULL;
	uint32_t hash;

	ht = &dev->ht[UBCORE_HT_TPID_STATE];

	hash = ubcore_get_tpid_state_hash(ht, &tp_id);

	return ubcore_hash_table_lookup_get(ht, hash, &tp_id);
}

int ubcore_find_add_tp_id_state_entry(struct ubcore_device *dev,
	struct ubcore_tpid_state *new_tp_state_entry)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	ht = &dev->ht[UBCORE_HT_TPID_STATE];

	hash = ubcore_get_tpid_state_hash(ht, &new_tp_state_entry->tp_id);

	spin_lock(&ht->lock);
	if (ubcore_hash_table_lookup_nolock(ht, hash,
		ubcore_ht_key(ht, &new_tp_state_entry->hnode)) != NULL) {
		spin_unlock(&ht->lock);
		ubcore_log_warn("find tp_state_entry, hash: %u", hash);
		return -EEXIST;
	}

	ubcore_hash_table_add_nolock(ht, &new_tp_state_entry->hnode, hash);
	ubcore_tpid_state_get(new_tp_state_entry);
	spin_unlock(&ht->lock);
	return 0;
}

void ubcore_remove_tp_id_state_entry(struct ubcore_device *dev,
	struct ubcore_tpid_state *tp_state_entry)
{
	struct ubcore_hash_table *ht;

	ht = &dev->ht[UBCORE_HT_TPID_STATE];

	ubcore_hash_table_remove(ht, &tp_state_entry->hnode);
	/* Drop the hash-table and initial allocation references. */
	ubcore_tpid_state_kref_put(tp_state_entry);
	ubcore_tpid_state_kref_put(tp_state_entry);
	wait_for_completion(&tp_state_entry->comp);
	mutex_destroy(&tp_state_entry->lock);
	kfree(tp_state_entry);
}

int ubcore_set_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		       const uint8_t tp_attr_cnt, const uint32_t tp_attr_bitmap,
		       const struct ubcore_tp_attr_value *tp_attr,
		       struct ubcore_udata *udata)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->set_tp_attr == NULL ||
		tp_attr == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->set_tp_attr(dev, tp_handle, tp_attr_cnt, tp_attr_bitmap,
					tp_attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to set tp attr, ret: %d.\n",
					ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_set_tp_attr);

int ubcore_get_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		       uint8_t *tp_attr_cnt, uint32_t *tp_attr_bitmap,
		       struct ubcore_tp_attr_value *tp_attr,
		       struct ubcore_udata *udata)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_tp_attr == NULL ||
		tp_attr_cnt == NULL || tp_attr_bitmap == NULL || tp_attr == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_tp_attr(dev, tp_handle, tp_attr_cnt, tp_attr_bitmap,
					tp_attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get tp attr, ret: %d.\n",
					ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_tp_attr);

int ubcore_get_eid_by_ip(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr,
			 union ubcore_eid *eid)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_eid_by_ip == NULL ||
		net_addr == NULL || eid == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_eid_by_ip(dev, net_addr, eid);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_eid_by_ip, ret: %d.\n", ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_eid_by_ip);

int ubcore_get_ip_by_eid(struct ubcore_device *dev, const union ubcore_eid *eid,
				 struct ubcore_net_addr *net_addr)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_ip_by_eid == NULL ||
		net_addr == NULL || eid == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_ip_by_eid(dev, eid, net_addr);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_ip_by_eid, ret: %d.\n", ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_ip_by_eid);

int ubcore_get_smac(struct ubcore_device *dev, uint8_t *mac)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_smac == NULL || mac == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_smac(dev, mac);
	if (ret != 0) {
		ubcore_log_err("Failed to get smac, ret: %d.\n", ret);
		return ret;
	}
	ubcore_log_info_rl("Successfully got smac.\n");

	return ret;
}
EXPORT_SYMBOL(ubcore_get_smac);

int ubcore_get_dmac(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr, uint8_t *mac)
{
	int ret;

	if (dev == NULL || net_addr == NULL || mac == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (dev->ops->get_dmac == NULL)
		ret = ubcore_get_dmac_by_ip(dev, net_addr, mac);
	else
		ret = dev->ops->get_dmac(dev, net_addr, mac);

	if (ret != 0) {
		ubcore_log_err("Failed to get dmac, ret: %d.\n", ret);
		if (dev->ops->get_dmac)
			return ret;
	} else {
		ubcore_log_info_rl("Successfully got dmac.\n");
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_dmac);
