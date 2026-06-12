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
		ubcore_log_err("setting of UTP or UM is conflit with anther setting");
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
	unsigned int ref_cnt;

	if (tpid_list == NULL) {
		ubcore_log_err("tpid_list is NULL");
		return;
	}
	ref_cnt = kref_read(&tpid_list->ref_cnt);

	if (ref_cnt == 0)
		dump_stack();

	ubcore_log_info_rl("kref_put: ref_cnt is %u", ref_cnt);
	(void)kref_put(&tpid_list->ref_cnt, ubcore_tpid_list_kref_release);
}

void ubcore_tpid_list_get(void *obj)
{
	unsigned int ref_cnt;
	struct ubcore_tpid_list *tpid_list = obj;

	ref_cnt = kref_read(&tpid_list->ref_cnt);
	if (ref_cnt == 0)
		dump_stack();

	kref_get(&tpid_list->ref_cnt);
}

static int ubcore_free_tpid_list(struct ubcore_tpid_list *tpid_list)
{
	struct ubcore_tpid_list_node *entry, *next;

	if (tpid_list == NULL) {
		ubcore_log_err("tpid_list is NULL");
		return -EINVAL;
	}

	list_for_each_entry_safe(entry, next, &tpid_list->aware_list, node) {
		list_del(&entry->node);
		kfree(entry);
	}
	list_for_each_entry_safe(entry, next, &tpid_list->unaware_list, node) {
		list_del(&entry->node);
		kfree(entry);
	}

	ubcore_tpid_list_kref_put(tpid_list);
	wait_for_completion(&tpid_list->comp);
	mutex_destroy(&tpid_list->lock);
	mutex_destroy(&tpid_list->fetch_lock);

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
	*exist_tpid_list = ubcore_hash_table_lookup_nolock(ht, hash,
					ubcore_ht_key(ht, &new_tpid_list->hnode));
	if (*exist_tpid_list != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}

	ubcore_hash_table_add_nolock(ht, &new_tpid_list->hnode, hash);
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
			ubcore_log_err("Tp type ctp and uboe conflict.\n");
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

static int put_tp_list_from_tpid_list_entry(struct ubcore_device *dev,
					     struct ubcore_get_tp_cfg *cfg,
					     uint32_t *tp_cnt, struct ubcore_tp_info *tp_list,
					     struct ubcore_tpid_list *tpid_list,
					     enum ubcore_tpid_owner_type tp_owner_type)
{
	uint32_t req_cnt = *tp_cnt;
	uint32_t copy_cnt = 0;
	uint32_t tpid;
	struct ubcore_tpid_list_node *entry;
	struct ubcore_tpid_state *state = NULL;
	struct list_head *head;

	ubcore_log_info_rl("put tp_list from hash table, list_cnt = %d, req_cnt = %d.\n",
			tp_owner_type == UBCORE_TPID_OWNER_USER_AWARE ?
			tpid_list->acnt : tpid_list->ucnt, req_cnt);

	head = (tp_owner_type == UBCORE_TPID_OWNER_USER_AWARE) ?
		&tpid_list->aware_list : &tpid_list->unaware_list;

	mutex_lock(&tpid_list->lock);
	list_for_each_entry(entry, head, node) {
		if (copy_cnt >= req_cnt)
			break;
		tpid = entry->tp_info.tp_handle.bs.tpid;
		ubcore_log_info_rl("query tp id state, tpid = %u.\n", tpid);
		state = ubcore_find_get_tp_id_state_entry(dev, tpid);
		if (state == NULL) {
			ubcore_log_err_rl("Failed to find state of tpid = %u.\n", tpid);
			mutex_unlock(&tpid_list->lock);
			return -ENOSPC;
		}
		if (state->tpid_status != UBCORE_TPID_STATE_ERR) {
			tp_list[copy_cnt] = entry->tp_info;
			ubcore_log_info_rl("get tp_handle value: %lld success.\n",
				tp_list[copy_cnt].tp_handle.value);
			copy_cnt++;
		}
		ubcore_tpid_state_kref_put(state);
	}
	mutex_unlock(&tpid_list->lock);

	*tp_cnt = copy_cnt;

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
	mutex_init(&new_tpid_list->fetch_lock);
	new_tpid_list->ub_dev = dev;
	new_tpid_list->lk.local_eid  = key->local_eid;
	new_tpid_list->lk.peer_eid   = key->peer_eid;
	new_tpid_list->lk.trans_mode = key->trans_mode;
	new_tpid_list->lk.share_mode = key->share_mode;
	new_tpid_list->lk.tp_type    = key->tp_type;
	new_tpid_list->lk.link_type  = key->link_type;
	INIT_LIST_HEAD(&new_tpid_list->aware_list);
	INIT_LIST_HEAD(&new_tpid_list->unaware_list);
	new_tpid_list->acnt = 0;
	new_tpid_list->ucnt = 0;

	return new_tpid_list;
}

static int init_state_for_tpid(struct ubcore_device *dev,
			       struct ubcore_tpid_list *tpid_list,
			       int begin, int end, bool is_aware);

static int ubcore_update_unaware_tpid_list(struct ubcore_device *dev,
					   struct ubcore_tp_info *ops_tp_list,
					   struct ubcore_tpid_list *tpid_list,
					   struct ubcore_tpid_list_key *tpid_list_key,
					   uint32_t actual_total_tp_cnt,
					   struct ubcore_get_tp_cfg *cfg)
{
	int ret;
	uint32_t idx;
	uint32_t new_cnt = 0;

	struct ubcore_tpid_list_node *node;

	ubcore_log_info_rl("Enter update unaware tpid list.\n");

	new_cnt = actual_total_tp_cnt - tpid_list->acnt - tpid_list->ucnt;

	for (idx = tpid_list->acnt + tpid_list->ucnt; idx < actual_total_tp_cnt; idx++) {
		node = kcalloc(1, sizeof(struct ubcore_tpid_list_node), GFP_KERNEL);
		if (node == NULL)
			return -ENOMEM;
		node->tp_info = ops_tp_list[idx];
		node->tp_info.tp_handle.bs.trans_mode = cfg->trans_mode;
		node->tp_info.tp_handle.bs.ctp = cfg->flag.bs.ctp;
		node->tp_info.tp_handle.bs.rtp = cfg->flag.bs.rtp;
		node->tp_info.tp_handle.bs.utp = cfg->flag.bs.utp;
		node->tp_info.tp_handle.bs.uboe = cfg->flag.bs.uboe;
		list_add_tail(&node->node, &tpid_list->unaware_list);
	}

	tpid_list->ucnt += new_cnt;

	ubcore_log_info_rl("acnt: %d, ucnt: %d.\n", tpid_list->acnt, tpid_list->ucnt);

	ret = init_state_for_tpid(dev, tpid_list,
				  tpid_list->ucnt - new_cnt, tpid_list->ucnt, false);
	if (ret != 0)
		ubcore_log_err("Failed to init state for tpid list, ret = %d.\n", ret);
	return 0;
}

static int ubcore_update_aware_tpid_list(struct ubcore_device *dev,
					struct ubcore_tp_info *ops_tp_list,
					struct ubcore_tpid_list *tpid_list,
					struct ubcore_tpid_list_key *tpid_list_key,
					uint32_t actual_total_tp_cnt,
					struct ubcore_get_tp_cfg *cfg)
{
	int ret;
	uint32_t new_cnt;
	uint32_t idx;
	struct ubcore_tpid_list_node *node;

	ubcore_log_info_rl("Enter update aware tpid list.\n");

	new_cnt = actual_total_tp_cnt - tpid_list->acnt - tpid_list->ucnt;

	for (idx = tpid_list->acnt + tpid_list->ucnt; idx < actual_total_tp_cnt; idx++) {
		node = kcalloc(1, sizeof(struct ubcore_tpid_list_node), GFP_KERNEL);
		if (node == NULL)
			return -ENOMEM;
		node->tp_info = ops_tp_list[idx];
		node->tp_info.tp_handle.bs.trans_mode = cfg->trans_mode;
		node->tp_info.tp_handle.bs.ctp = cfg->flag.bs.ctp;
		node->tp_info.tp_handle.bs.rtp = cfg->flag.bs.rtp;
		node->tp_info.tp_handle.bs.utp = cfg->flag.bs.utp;
		node->tp_info.tp_handle.bs.uboe = cfg->flag.bs.uboe;
		list_add_tail(&node->node, &tpid_list->aware_list);
	}

	tpid_list->acnt += new_cnt;

	ubcore_log_info_rl("acnt: %d, ucnt: %d.\n", tpid_list->acnt, tpid_list->ucnt);

	ret = init_state_for_tpid(dev, tpid_list, tpid_list->acnt - new_cnt, tpid_list->acnt, true);
	if (ret != 0) {
		ubcore_log_err("Failed to init state for tpid list, ret = %d.\n", ret);
		return ret;
	}
	return 0;
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
		ret = dev->ops->get_tp_list(dev, cfg, &actual_group_tp_cnt,
			temp_buf + actual_total_tp_cnt, udata);
		if (ret != 0) {
			if (actual_total_tp_cnt > 0) {
				ubcore_log_info_rl("actual cnt < request cnt, end early.\n");
				ret = 0;
				break;
			}
			ubcore_log_err("get tp list failed: total=%d idx=%d\n",
				req_total_tp_cnt, group_idx);
			ubcore_log_err("req=%d actual=%d ret=%d.\n",
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
	uint32_t *tp_cnt, struct ubcore_tpid_list *tpid_list,
	struct ubcore_udata *udata, struct ubcore_tpid_list_key *tpid_list_key,
	struct ubcore_tp_info *tp_list, enum ubcore_tpid_owner_type tp_owner_type)
{
	int ret;
	uint32_t req_cnt = 0;
	uint32_t old_total_cnt;
	struct ubcore_tp_info *temp_buf = NULL;

	req_cnt = *tp_cnt;
	temp_buf = kcalloc(req_cnt, sizeof(struct ubcore_tp_info), GFP_KERNEL);
	if (temp_buf == NULL) {
		ubcore_log_err("Failed to alloc temp tpid_list buf.\n");
		return -ENOMEM;
	}

	mutex_lock(&tpid_list->lock);
	old_total_cnt = tpid_list->acnt + tpid_list->ucnt;
	ret = ubcore_get_tp_list_from_ops(dev, cfg, &req_cnt, temp_buf, udata);
	if (ret != 0) {
		ubcore_log_err("Get tp list from ops failed, ret = %d.\n", ret);
		kfree(temp_buf);
		mutex_unlock(&tpid_list->lock);
		return -EINVAL;
	}

	ubcore_log_info_rl("get tp list from ops success, cnt=%d, ret=%d.\n", req_cnt, ret);
	if (req_cnt > old_total_cnt) {
		if (tp_owner_type == UBCORE_TPID_OWNER_USER_AWARE)
			ret = ubcore_update_aware_tpid_list(dev, temp_buf, tpid_list,
				tpid_list_key, req_cnt, cfg);
		else
			ret = ubcore_update_unaware_tpid_list(dev, temp_buf, tpid_list,
				tpid_list_key, req_cnt, cfg);
		if (ret != 0) {
			ubcore_log_err("Update tpid list failed, ret = %d.\n", ret);
			kfree(temp_buf);
			mutex_unlock(&tpid_list->lock);
			return -EINVAL;
		}
	} else {
		ubcore_log_err("Tp_cnt decreased, old_cnt: %u, new_cnt: %d.\n",
			old_total_cnt, req_cnt);
	}
	mutex_unlock(&tpid_list->lock);

	ret = put_tp_list_from_tpid_list_entry(dev, cfg, tp_cnt, tp_list, tpid_list, tp_owner_type);
	if (ret != 0 || *tp_cnt == 0) {
		ubcore_log_err("copy tp_id_list to tp_list failed, ret=%d, cnt=%d.\n",
			ret, *tp_cnt);
		kfree(temp_buf);
		return ret;
	}

	kfree(temp_buf);
	return ret;
}

static int query_tpid_list_err_cnt(struct ubcore_device *dev, struct ubcore_tpid_list *tpid_list)
{
	uint32_t err_cnt = 0;
	uint64_t tp_id = 0;
	struct ubcore_tpid_list_node *entry;
	struct ubcore_tpid_state *state = NULL;

	if (tpid_list == NULL) {
		ubcore_log_err_rl("tpid list is null.\n");
		return -EINVAL;
	}

	if (list_empty(&tpid_list->aware_list) || tpid_list->acnt == 0) {
		ubcore_log_err_rl("tpid list aware list is empty.\n");
		return -EINVAL;
	}

	list_for_each_entry(entry, &tpid_list->aware_list, node) {
		tp_id = entry->tp_info.tp_handle.bs.tpid;
		state = ubcore_find_get_tp_id_state_entry(dev, tp_id);
		if (state == NULL) {
			ubcore_log_err_rl("Failed to find state of tp_id = %lld.\n", tp_id);
			continue;
		}
		if (state->tpid_status == UBCORE_TPID_STATE_ERR)
			err_cnt++;
		ubcore_tpid_state_kref_put(state);
	}
	return err_cnt;
}

int ubcore_get_tp_list(struct ubcore_device *dev, struct ubcore_get_tp_cfg *cfg,
		       uint32_t *tp_cnt, struct ubcore_tp_info *tp_list,
		       struct ubcore_udata *udata)
{
	int ret;
	int err_cnt = 0;
	uint32_t req_total_tp_cnt = 0;
	struct ubcore_tpid_list *old_tpid_list;
	struct ubcore_tpid_list *tpid_list = NULL;
	struct ubcore_tpid_list *exist_tpid_list;
	struct ubcore_tpid_list_key tpid_list_key = {0};

	if (validate_get_tp_cfg(cfg) != 0)
		return -EINVAL;
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err("Invalid parameter, trans_mode = %d.\n", (int)cfg->trans_mode);
		return -EINVAL;
	}

	UBCORE_PERF_TRACE_BEGIN(PERF_UB_GET_TP_LIST);
	ubcore_set_tpid_list_key(dev, cfg, &tpid_list_key);
	req_total_tp_cnt = *tp_cnt;
	tpid_list = ubcore_ht_find_get_tpid_list(dev, &tpid_list_key);
	if (tpid_list != NULL && !list_empty(&tpid_list->aware_list) && tpid_list->acnt > 0) {
		err_cnt = query_tpid_list_err_cnt(dev, tpid_list);
		if (tpid_list->acnt - err_cnt >= *tp_cnt) {
			ret = put_tp_list_from_tpid_list_entry(dev, cfg, tp_cnt, tp_list,
				tpid_list, UBCORE_TPID_OWNER_USER_AWARE);
			ubcore_tpid_list_kref_put(tpid_list);
			if (ret != 0) {
				ubcore_log_err("put tp list from tpid list failed.\n");
				UBCORE_PERF_TRACE_END(PERF_UB_GET_TP_LIST);
				return ret;
			}
			UBCORE_PERF_TRACE_END(PERF_UB_GET_TP_LIST);
			return 0;
		}
		req_total_tp_cnt += err_cnt + tpid_list->ucnt;
		ubcore_log_err("Cache insufficient: cached=%d, requested=%d, will refresh.\n",
			tpid_list->acnt, req_total_tp_cnt);
			goto get_tp_list_helper;
	}

	tpid_list = ubcore_create_tpid_list(dev, &tpid_list_key);
	if (tpid_list == NULL) {
		ubcore_log_err("failed to alloc new tpid list.\n");
		UBCORE_PERF_TRACE_END(PERF_UB_GET_TP_LIST);
		return -ENOMEM;
	}

	ret = ubcore_find_add_tpid_list(dev, tpid_list, &exist_tpid_list, &tpid_list_key);
	if (ret == -EEXIST && exist_tpid_list != NULL) {
		ubcore_log_info_rl("reuse tpid list.\n");
		old_tpid_list = tpid_list;
		tpid_list = exist_tpid_list;
		(void)ubcore_free_tpid_list(old_tpid_list);
	} else if (ret != 0) {
		ubcore_log_err("Failed to add tpid_list into hash table.\n");
		(void)ubcore_free_tpid_list(tpid_list);
		UBCORE_PERF_TRACE_END(PERF_UB_GET_TP_LIST);
		return ret;
	}

	req_total_tp_cnt += tpid_list->ucnt;

get_tp_list_helper:
	ret = ubcore_get_tp_list_helper(dev, cfg, &req_total_tp_cnt, tpid_list,
		udata, &tpid_list_key, tp_list, UBCORE_TPID_OWNER_USER_AWARE);
	UBCORE_PERF_TRACE_END(PERF_UB_GET_TP_LIST);
	if (ret != 0) {
		ubcore_log_err("get tp list helper failed.\n");
		return ret;
	}
	return ret;
}
EXPORT_SYMBOL(ubcore_get_tp_list);

static struct ubcore_tp_info *find_available_tp_id_nolock(struct ubcore_device *dev,
	struct ubcore_tpid_list *tp_id_list,
	bool is_aware)
{
	uint32_t tp_id;
	struct ubcore_tp_info *tp_info = NULL;
	struct ubcore_tpid_state *state = NULL;
	struct ubcore_tpid_list_node *entry;
	struct list_head *head;

	head = is_aware ? &tp_id_list->aware_list : &tp_id_list->unaware_list;
	if (list_empty(head))
		return NULL;

	list_for_each_entry(entry, head, node) {
		tp_info = &entry->tp_info;
		tp_id = tp_info->tp_handle.bs.tpid;
		ubcore_log_info_rl("tp_id=%u, acnt:%d, ucnt:%d.\n", tp_id,
			tp_id_list->acnt, tp_id_list->ucnt);
		state = ubcore_find_get_tp_id_state_entry(dev, tp_id);
		if (state == NULL) {
			ubcore_log_err_rl("Failed to find state of tp_id = %u.\n", tp_id);
			continue;
		}

		ubcore_log_info_rl("tpid state: %d, alloced: %d.\n",
			state->tpid_status, state->alloced);
		mutex_lock(&state->lock);
		if (state->tpid_status == UBCORE_TPID_STATE_RESET && !state->alloced) {
			ubcore_log_info_rl("find available tp handle value: %lld.\n",
				tp_info->tp_handle.value);
			state->alloced = true;
			state->tp_id_owner_type = is_aware ? UBCORE_TPID_OWNER_USER_AWARE :
				UBCORE_TPID_OWNER_USER_UNAWARE;
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
*select_tpid(struct ubcore_device *dev, struct ubcore_tpid_list *tpid_list, bool is_aware)
{
	struct ubcore_tp_info *tp_handle = NULL;
	struct list_head *head;

	if (tpid_list == NULL) {
		ubcore_log_err_rl("Invalid parameter, tpid list is null.\n");
		return NULL;
	}
	head = is_aware ? &tpid_list->aware_list : &tpid_list->unaware_list;
	if (list_empty(head)) {
		ubcore_log_err_rl("Invalid parameter, list head is null.\n");
		return NULL;
	}
	ubcore_tpid_list_get(tpid_list);
	tp_handle = find_available_tp_id_nolock(dev, tpid_list, is_aware);
	ubcore_tpid_list_kref_put(tpid_list);
	return tp_handle;
}

static struct ubcore_tpid_state
*make_tpid_state(struct ubcore_device *dev, uint32_t tp_id, enum ubcore_tpid_status state)
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
	kref_init(&entry->ref_cnt);
	init_completion(&entry->comp);
	mutex_init(&entry->lock);
	return entry;
}

static int init_state_for_tpid(struct ubcore_device *dev,
	struct ubcore_tpid_list *tpid_list, int begin,
	int end, bool is_aware)
{
	int ret;
	int i = 0;
	int rollback;
	uint32_t tpid;
	struct ubcore_tpid_list_node *entry;
	struct list_head *head;
	struct ubcore_tpid_state *state = NULL;

	head = is_aware ? &tpid_list->aware_list : &tpid_list->unaware_list;

	list_for_each_entry(entry, head, node) {
		if (i < begin) {
			i++;
			continue;
		}
		if (i >= end)
			break;
		tpid = entry->tp_info.tp_handle.bs.tpid;
		state = make_tpid_state(dev, tpid, UBCORE_TPID_STATE_RESET);
		ret = ubcore_find_add_tp_id_state_entry(dev, state);
		if (ret != 0) {
			ubcore_log_err_rl("Failed to add tpid state, tpid=%u, ret=%d.\n",
				tpid, ret);
			goto rollback;
		}
		ubcore_log_info_rl("init tpid state ok, i=%d, tpid=%u, ret=%d.\n",
			i, tpid, ret);
		i++;
	}

	return 0;

rollback:
	rollback = begin;
	list_for_each_entry(entry, head, node) {
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
		ubcore_remove_tp_id_state_entry(dev, state);
		ubcore_log_info_rl("delete tp id state.\n");
		rollback++;
	}
	return ret;
}

static int ubcore_query_select_tpid_list(struct ubcore_device *dev, struct ubcore_get_tp_cfg *cfg,
	struct ubcore_tpid_list *tpid_list, bool is_aware, struct ubcore_tp_info *selected_tpid,
	struct ubcore_udata *udata)
{
	int ret;
	int tp_owner_type;
	uint32_t fetch_cnt = 0;
	uint32_t old_cnt;
	uint32_t tp_id;
	struct ubcore_tpid_state *state = NULL;
	struct ubcore_tpid_list *old_tpid_list;
	struct ubcore_tpid_list *exist_tpid_list;
	struct ubcore_tpid_list_key tpid_list_key = {0};
	struct ubcore_tp_info *tp_selected = NULL;
	struct ubcore_tp_info *tp_list = NULL;

	if (validate_get_tp_cfg(cfg) != 0)
		return -EINVAL;
	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		ubcore_log_err("Invalid parameter, trans_mode: %d.\n", (int)cfg->trans_mode);
		return -EINVAL;
	}
	ubcore_set_tpid_list_key(dev, cfg, &tpid_list_key);

	tpid_list = ubcore_ht_find_get_tpid_list(dev, &tpid_list_key);

	if (tpid_list != NULL) {
		ubcore_log_info_rl("try to find tpid from tpid list.\n");
		mutex_lock(&tpid_list->lock);
		tp_selected = select_tpid(dev, tpid_list, is_aware);
		if (!IS_ERR_OR_NULL(tp_selected)) {
			*selected_tpid = *tp_selected;
			mutex_unlock(&tpid_list->lock);
			ubcore_tpid_list_kref_put(tpid_list);
			return 0;
		}
		mutex_unlock(&tpid_list->lock);
	}

	ubcore_log_info_rl("tpid not in tpid list, query ops.\n");
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
	} else if (ret != 0) {
		ubcore_log_err("Failed to add tpid_list into hash table.\n");
		(void)ubcore_free_tpid_list(tpid_list);
		return ret;
	}

	mutex_lock(&tpid_list->fetch_lock);

	tp_owner_type = is_aware ? (int)UBCORE_TPID_OWNER_USER_AWARE :
		(int)UBCORE_TPID_OWNER_USER_UNAWARE;
	fetch_cnt = tpid_list->acnt + tpid_list->ucnt + 1;
	tp_list = kcalloc(fetch_cnt, sizeof(struct ubcore_tp_info), GFP_KERNEL);
	if (tp_list == NULL) {
		ubcore_log_err("Failed to alloc tp_handle buffer.\n");
		mutex_unlock(&tpid_list->fetch_lock);
		return -ENOMEM;
	}

	old_cnt = is_aware ? tpid_list->acnt : tpid_list->ucnt;
	ret = ubcore_get_tp_list_helper(dev, cfg, &fetch_cnt, tpid_list, udata, &tpid_list_key,
		tp_list, tp_owner_type);
	if (ret < 0 || old_cnt == (is_aware ? tpid_list->acnt : tpid_list->ucnt)) {
		ubcore_log_err_rl("Failed to get tp list, ret = %d.\n", ret);
		ret =  -ENOSPC;
		goto err_free_tp_list;
	}

	tp_selected = &tp_list[fetch_cnt - 1];
	ubcore_log_info_rl("tp_selected handle value = %lld.\n", tp_selected->tp_handle.value);
	tp_id = tp_selected->tp_handle.bs.tpid;
	state = ubcore_find_get_tp_id_state_entry(dev, tp_id);
	if (state == NULL) {
		ubcore_log_err_rl("Failed to find state of tp_id = %u.\n", tp_id);
		ret = -ENOSPC;
		goto err_free_tp_list;
	}
	mutex_lock(&state->lock);
	if (!state->alloced) {
		state->alloced = true;
		state->tp_id_owner_type = is_aware ? UBCORE_TPID_OWNER_USER_AWARE :
			UBCORE_TPID_OWNER_USER_UNAWARE;
		goto done;
	}
	ret = -1;
	ubcore_log_err("Unexpected failure updating tpid state: %d, ret=%d.\n",
		state->tpid_status, ret);
done:
	mutex_unlock(&state->lock);
	ubcore_tpid_state_kref_put(state);
	*selected_tpid = *tp_selected;

err_free_tp_list:
	kfree(tp_list);
	mutex_unlock(&tpid_list->fetch_lock);
	return ret;
}

static struct ubcore_tp_info *get_managed_tpid_list(struct ubcore_device *dev,
	struct ubcore_get_tp_cfg *cfg, int tp_cnt, struct ubcore_udata *udata, bool is_aware)
{
	int ret;
	struct ubcore_tpid_list *tpid_list = NULL;
	struct ubcore_tp_info selected = {0};
	struct ubcore_tp_info *result = NULL;

	ret = ubcore_query_select_tpid_list(dev, cfg, tpid_list, is_aware, &selected, udata);
	if (ret != 0) {
		ubcore_log_err_rl("Failed to query/select tpid, ret = %d.\n", ret);
		return NULL;
	}

	result = kzalloc(sizeof(struct ubcore_tp_info), GFP_KERNEL);
	if (result == NULL)
		return NULL;

	ubcore_log_info_rl("create tpid handle value = %lld.\n", selected.tp_handle.value);
	*result = selected;
	return result;
}

struct ubcore_tpid *ubcore_create_tpid_priv(struct ubcore_device *dev,
	struct ubcore_tpid_cfg *cfg, struct ubcore_udata *udata, bool is_aware)
{
	struct ubcore_tpid *tpid;
	struct ubcore_tp_info *selected_tp;
	struct ubcore_get_tp_cfg get_cfg = {0};

	if (dev == NULL || cfg == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return NULL;
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
		return NULL;
	if (ubcore_check_trans_mode_valid(get_cfg.trans_mode) != true) {
		ubcore_log_err("Invalid parameter, tp_mode: %d.\n", (int)cfg->tp_mode);
		return NULL;
	}

	selected_tp = get_managed_tpid_list(dev, &get_cfg, 1, udata, is_aware);
	if (selected_tp == NULL) {
		ubcore_log_err_rl("Failed to get managed tpid list.\n");
		return NULL;
	}

	tpid = kzalloc(sizeof(struct ubcore_tpid), GFP_KERNEL);
	if (tpid == NULL)
		return NULL;
	tpid->tp_handle = selected_tp->tp_handle;

	return tpid;
}

struct ubcore_tpid *ubcore_create_tpid(struct ubcore_device *dev,
	struct ubcore_tpid_cfg *cfg, struct ubcore_udata *udata)
{
	return ubcore_create_tpid_priv(dev, cfg, udata, true);
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

	state = ubcore_find_get_tp_id_state_entry(dev, tpid_val);
	if (state == NULL) {
		ubcore_log_err_rl("Failed to find tpid state, tpid = %u.\n", tpid_val);
		return -EINVAL;
	}
	mutex_lock(&state->lock);
	state->alloced = false;
	state->tp_id_owner_type = UBCORE_TPID_OWNER_NONE;
	mutex_unlock(&state->lock);
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
		tp_id = cfg->flushdone_cfg->tpid;
		entry = ubcore_find_get_tp_id_state_entry(dev, tp_id);
		if (entry == NULL) {
			ubcore_log_err_rl("Failed to find tpid state, tp_id = %u.\n", tp_id);
			return -EINVAL;
		}
		mutex_lock(&entry->lock);
		old_state = entry->tpid_status;
		if (old_state != UBCORE_TPID_STATE_ERR) {
			ubcore_log_err("Invalid state transition: %d -> RESET.\n", old_state);
			mutex_unlock(&entry->lock);
			ubcore_tpid_state_kref_put(entry);
			return -EINVAL;
		}
		entry->tpid_status = state;
		mutex_unlock(&entry->lock);
		ubcore_tpid_state_kref_put(entry);
		ubcore_log_err("flush done completed.\n");
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
