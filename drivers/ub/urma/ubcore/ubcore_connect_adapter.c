// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore connect adapter implementation file
 * Author: Wang Hang
 * Create: 2025-06-19
 * Note:
 * History: 2025-06-19: create file
 */

#include <linux/delay.h>
#include <linux/random.h>
#include <ub/urma/ubcore_uapi.h>
#include "ub/urma/ubcore_perf.h"
#include "ubcore_log.h"
#include "net/ubcore_protocol.h"
#include "net/ubcore_comm.h"
#include "net/ubcore_session.h"
#include "ubcore_connect_adapter.h"
#include "ubcore_priv.h"
#include "ubcore_host_info.h"
#include "ubcore_hash_table.h"
#include "ubcore_workqueue.h"

enum msg_create_conn_result {
	CREATE_CONN_SUCCESS = 0,
	GET_TP_LIST_ERROR,
	MODIFY_TPID_ERROR,
	CREATE_CONN_FAIL,
	ESTABLISHED_TP_CHANNEL
};

struct session_data_create_conn {
	uint64_t peer_tp_handle;
	uint32_t rx_psn;
	int ret;
};

struct msg_create_conn_req {
	struct ubcore_get_tp_cfg get_tp_cfg;
	uint64_t tp_handle;
	uint32_t tx_psn;
/* Only for RC + RTP */
	uint32_t src_jetty_id;
	uint32_t dst_jetty_id;
/* Only for RM + RTP */
	uint64_t stag;
	uint64_t dtag;
	bool share_tp;
};

struct msg_create_conn_resp {
	uint64_t tp_handle;
	uint32_t tx_psn;
	int result; /* Refer to enum msg_create_conn_result */
};

struct msg_destroy_conn_req {
	union ubcore_tp_handle tp_handle;
	union ubcore_tp_handle peer_tp_handle;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t src_jetty_id;
	uint32_t dst_jetty_id;
	uint64_t stag;
	uint64_t dtag;
	enum ubcore_transport_mode trans_mode;
	int ht_id;
	uint32_t tp_type;
	uint32_t link_type;
	enum ubcore_tpid_share_mode share_mode;
};

struct msg_isref_conn_req {
	union ubcore_tp_handle tp_handle;
	union ubcore_tp_handle peer_tp_handle;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint64_t stag;
	uint64_t dtag;
	enum ubcore_transport_mode trans_mode;
	uint32_t tp_type;
	uint32_t link_type;
	enum ubcore_tpid_share_mode share_mode;
};

#define UBCORE_TPID_REUSE_WAIT_MIN_US 100
#define UBCORE_TPID_REUSE_WAIT_MAX_US 200
#define UBCORE_TPID_REUSE_MAX_WAIT_TIMES \
	(30 * 1000 * 1000 / UBCORE_TPID_REUSE_WAIT_MAX_US)
#define UBCORE_ENABLE_SHARED_CTP_DEFAULT false

/* Default as 30s */
uint32_t ubcore_conn_timeout = UBCORE_CONN_MAX_TIMEOUT;

uint32_t ubcore_get_conn_timeout(void)
{
	return ubcore_conn_timeout;
}

/* Default as off */
bool ubcore_enable_shared_ctp = UBCORE_ENABLE_SHARED_CTP_DEFAULT;

bool ubcore_get_enable_shared_ctp(void)
{
	return ubcore_enable_shared_ctp;
}

static void ubcore_lookup_host_info_local_and_peer(
	const union ubcore_eid *local_src_eid, union ubcore_eid *local_dst_eid,
	const union ubcore_eid *peer_src_eid, union ubcore_eid *peer_dst_eid,
	union ubcore_net_addr_union *local_cna,	union ubcore_net_addr_union *peer_cna)
{
	struct ubcore_host_info local_host_info;
	struct ubcore_host_info peer_host_info;

	int local_ret = ubcore_lookup_host_info(local_src_eid, &local_host_info);
	int peer_ret = ubcore_lookup_host_info(peer_src_eid, &peer_host_info);

	if (local_ret == 0 && peer_ret == 0) {
		*local_dst_eid = local_host_info.eid;
		*peer_dst_eid = peer_host_info.eid;
		if (local_cna != NULL && peer_cna != NULL) {
			*local_cna = local_host_info.cna;
			*peer_cna = peer_host_info.cna;
		}
		ubcore_log_info("local_host_eid=" EID_FMT " , peer_host_eid=" EID_FMT "\n",
			EID_ARGS(local_host_info.eid), EID_ARGS(peer_host_info.eid));
	}
	if (local_ret != 0)
		ubcore_log_warn_rl(
			"No result for local host eid, ret=%d, local_port_eid=" EID_FMT "\n",
			local_ret, EID_ARGS(*local_src_eid));
	if (peer_ret != 0)
		ubcore_log_warn_rl(
			"No result for peer host eid, ret=%d, peer_port_eid=" EID_FMT "\n",
			peer_ret, EID_ARGS(*peer_src_eid));
}

static int ubcore_fill_tpid_reuse_key(struct ubcore_tpid_reuse_key *key,
				 struct ubcore_get_tp_cfg *get_tp_cfg,
				 struct ubcore_tjetty_cfg *cfg,
				 union ubcore_net_addr_union *local_cna,
				 union ubcore_net_addr_union *peer_cna)
{
	if (key == NULL || get_tp_cfg == NULL || cfg == NULL)
		return -EINVAL;

	key->lk.local_eid = get_tp_cfg->local_eid;
	key->lk.peer_eid = get_tp_cfg->peer_eid;
	if (ubcore_get_enable_shared_ctp() &&
	    get_tp_cfg->flag.bs.ctp &&
	    cfg->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg->local_eid,
			&key->lk.local_eid, &get_tp_cfg->peer_eid, &key->lk.peer_eid,
			local_cna, peer_cna);
	}
	key->lk.trans_mode = cfg->trans_mode;
	key->lk.share_mode = cfg->flag.bs.share_tp ?
		UBCORE_TPID_SHARE_CONTAINER : UBCORE_TPID_SHARE_NONE;
	key->stag = cfg->stp_cfg.stag;
	key->dtag = cfg->stp_cfg.dtag;

	if (get_tp_cfg->flag.bs.rtp)
		key->lk.tp_type = UBCORE_RTP;
	if (get_tp_cfg->flag.bs.ctp)
		key->lk.tp_type = UBCORE_CTP;
	if (get_tp_cfg->flag.bs.utp)
		key->lk.tp_type = UBCORE_UTP;

	key->lk.link_type = (get_tp_cfg->flag.bs.uboe) ? UBCORE_LINK_UBOE : UBCORE_LINK_ETHERNET;
	memset(&key->lk.local_cna, 0, sizeof(key->lk.local_cna));
	memset(&key->lk.peer_cna, 0, sizeof(key->lk.peer_cna));
	return 0;
}

static int ubcore_fill_bind_tpid_reuse_key(struct ubcore_tpid_reuse_key *key,
				 struct ubcore_get_tp_cfg *get_tp_cfg,
				 struct ubcore_tjetty_cfg *cfg,
				 struct ubcore_jetty *sjetty,
				 union ubcore_net_addr_union *local_cna,
				 union ubcore_net_addr_union *peer_cna)
{
	if (key == NULL || get_tp_cfg == NULL || cfg == NULL)
		return -EINVAL;

	key->lk.local_eid = get_tp_cfg->local_eid;
	key->lk.peer_eid = get_tp_cfg->peer_eid;
	if (ubcore_get_enable_shared_ctp() &&
	    get_tp_cfg->flag.bs.ctp &&
	    cfg->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg->local_eid,
			&key->lk.local_eid, &get_tp_cfg->peer_eid, &key->lk.peer_eid,
			local_cna, peer_cna);
	}
	key->lk.trans_mode = cfg->trans_mode;
	key->lk.share_mode = cfg->flag.bs.share_tp ?
		UBCORE_TPID_SHARE_CONTAINER : UBCORE_TPID_SHARE_NONE;
	key->stag = sjetty->jetty_id.id;
	key->dtag = cfg->id.id;

	if (get_tp_cfg->flag.bs.rtp)
		key->lk.tp_type = UBCORE_RTP;
	if (get_tp_cfg->flag.bs.ctp)
		key->lk.tp_type = UBCORE_CTP;
	if (get_tp_cfg->flag.bs.utp)
		key->lk.tp_type = UBCORE_UTP;

	key->lk.link_type = (get_tp_cfg->flag.bs.uboe) ? UBCORE_LINK_UBOE : UBCORE_LINK_ETHERNET;
	memset(&key->lk.local_cna, 0, sizeof(key->lk.local_cna));
	memset(&key->lk.peer_cna, 0, sizeof(key->lk.peer_cna));
	return 0;
}

static int ubcore_fill_tpid_cfg(struct ubcore_tpid_cfg *tpid_cfg,
	struct ubcore_get_tp_cfg *get_tp_cfg)
{
	if (tpid_cfg == NULL || get_tp_cfg == NULL)
		return -EINVAL;

	tpid_cfg->local_eid = get_tp_cfg->local_eid;
	tpid_cfg->peer_eid = get_tp_cfg->peer_eid;
	if (ubcore_get_enable_shared_ctp() &&
	    get_tp_cfg->flag.bs.ctp &&
	    get_tp_cfg->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg->local_eid,
			&tpid_cfg->local_eid, &get_tp_cfg->peer_eid, &tpid_cfg->peer_eid,
			NULL, NULL);
	}
	tpid_cfg->tp_mode = get_tp_cfg->trans_mode;
	if (get_tp_cfg->flag.bs.ctp)
		tpid_cfg->tp_type = UBCORE_CTP;
	if (get_tp_cfg->flag.bs.rtp)
		tpid_cfg->tp_type = UBCORE_RTP;
	if (get_tp_cfg->flag.bs.utp)
		tpid_cfg->tp_type = UBCORE_UTP;
	tpid_cfg->link_type = (get_tp_cfg->flag.bs.uboe == 1) ? UBCORE_LINK_UBOE :
		UBCORE_LINK_ETHERNET;
	return 0;
}

static bool ubcore_net_addr_is_zero(const union ubcore_net_addr_union *addr)
{
	return addr->in6.subnet_prefix == 0 && addr->in6.interface_id == 0;
}

static void ubcore_fill_tpid_reuse_key_cna(struct ubcore_tpid_reuse_key *key,
					   union ubcore_net_addr_union local_cna,
					   union ubcore_net_addr_union peer_cna)
{
	memset(&key->lk.local_eid, 0, sizeof(key->lk.local_eid));
	memset(&key->lk.peer_eid, 0, sizeof(key->lk.peer_eid));
	key->lk.local_cna = local_cna;
	key->lk.peer_cna = peer_cna;
}

static void ubcore_tpid_reuse_kref_release(struct kref *ref_cnt)
{
	struct ubcore_tpid_reuse *entry =
		container_of(ref_cnt, struct ubcore_tpid_reuse, ref_cnt);

	complete(&entry->comp);
}

void ubcore_tpid_reuse_kref_put(struct ubcore_tpid_reuse *entry)
{
	if (entry == NULL)
		return;

	(void)kref_put(&entry->ref_cnt,
		       ubcore_tpid_reuse_kref_release);
}

static struct ubcore_tpid_reuse *
ubcore_create_tpid_reuse(struct ubcore_device *dev,
			       struct ubcore_tpid_reuse_key *key)
{
	struct ubcore_tpid_reuse *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return NULL;

	entry->ub_dev = dev;
	atomic_set(&entry->use_cnt, 0);
	kref_init(&entry->ref_cnt);
	init_completion(&entry->comp);
	entry->rk = *key;
	entry->reuse_state = UBCORE_TPID_REUSE_RESET;
	entry->tx_psn = get_random_u32();
	mutex_init(&entry->lock);

	return entry;
}

static struct ubcore_tpid_reuse *
ubcore_find_get_tpid_reuse(struct ubcore_device *dev,
				  struct ubcore_tpid_reuse_key *key)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	if (dev == NULL || key == NULL)
		return NULL;

	ht = &dev->ht[UBCORE_HT_TPID_REUSE];
	hash = ubcore_get_tpid_reuse_hash(ht, key);

	return ubcore_hash_table_lookup_get(ht, hash, key);
}


static int ubcore_find_add_tpid_reuse(struct ubcore_device *dev,
				struct ubcore_tpid_reuse *new_tpid_reuse,
				struct ubcore_tpid_reuse **exist_tpid_reuse,
				struct ubcore_tpid_reuse_key *key)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	ht = &dev->ht[UBCORE_HT_TPID_REUSE];
	hash = ubcore_get_tpid_reuse_hash(ht, key);

	spin_lock(&ht->lock);
	*exist_tpid_reuse = ubcore_hash_table_lookup_nolock_get(ht, hash, key);
	if (*exist_tpid_reuse != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}
	ubcore_hash_table_add_nolock(ht, &new_tpid_reuse->hnode, hash);
	spin_unlock(&ht->lock);
	return 0;
}

void ubcore_hash_table_rmv_tpid_reuse(struct ubcore_device *dev,
					     struct ubcore_tpid_reuse *entry)
{
	struct ubcore_hash_table *ht;

	ht = &dev->ht[UBCORE_HT_TPID_REUSE];

	ubcore_hash_table_remove(ht, &entry->hnode);
}

static int send_is_ref_req(struct ubcore_tpid_reuse *tpid_reuse)
{
	struct ubcore_comm_msg msg = { 0 };
	struct msg_isref_conn_req req = { 0 };
	int ret;

	req.local_eid = tpid_reuse->rk.lk.local_eid;
	req.peer_eid = tpid_reuse->rk.lk.peer_eid;
	req.trans_mode = tpid_reuse->rk.lk.trans_mode;
	req.stag = tpid_reuse->rk.stag;
	req.dtag = tpid_reuse->rk.dtag;

	req.tp_type = tpid_reuse->rk.lk.tp_type;
	req.link_type = tpid_reuse->rk.lk.link_type;
	req.share_mode = tpid_reuse->rk.lk.share_mode;

	msg.type = UBCORE_NET_ISREF_REQ;
	msg.len = (uint16_t)sizeof(struct msg_isref_conn_req);
	msg.session_id = 0;
	msg.data = &req;

	ret = ubcore_send_comm_msg_to(tpid_reuse->ub_dev, &msg, tpid_reuse->rk.lk.peer_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

static bool ubcore_is_loopback(struct ubcore_device *dev,
			       union ubcore_eid *peer_eid)
{
	uint32_t eid_idx;

	spin_lock(&dev->eid_table.lock);
	for (eid_idx = 0; eid_idx < dev->eid_table.eid_cnt; eid_idx++) {
		if (dev->eid_table.eid_entries[eid_idx].valid &&
			memcmp(peer_eid, &dev->eid_table.eid_entries[eid_idx].eid,
			sizeof(union ubcore_eid)) == 0) {
			spin_unlock(&dev->eid_table.lock);
			return true;
		}
	}
	spin_unlock(&dev->eid_table.lock);

	return false;
}

static inline void ubcore_tpid_reuse_dec_usecnt(struct ubcore_tpid_reuse *tpid_reuse)
{
	mutex_lock(&tpid_reuse->lock);
	atomic_dec(&tpid_reuse->use_cnt);
	mutex_unlock(&tpid_reuse->lock);
}

static inline void ubcore_tpid_reuse_inc_usecnt(struct ubcore_tpid_reuse *tpid_reuse)
{
	mutex_lock(&tpid_reuse->lock);
	atomic_inc(&tpid_reuse->use_cnt);
	mutex_unlock(&tpid_reuse->lock);
}

static struct ubcore_tpid_reuse *ubcore_reuse_tpid(struct ubcore_tpid_reuse *tpid_reuse)
{
	int i = 0;
	int ret = 0;

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
		if (!ubcore_is_loopback(tpid_reuse->ub_dev, &tpid_reuse->rk.lk.peer_eid) &&
			atomic_read(&tpid_reuse->use_cnt) == 0 &&
			tpid_reuse->is_ref == true) {
			ret = send_is_ref_req(tpid_reuse);
			if (ret != 0) {
				ubcore_log_err(
					"Failed to send is_ref req, ret = %d.\n", ret);
				mutex_unlock(&tpid_reuse->lock);
				ubcore_tpid_reuse_kref_put(tpid_reuse);
				return NULL;
			}
		}
		atomic_inc(&tpid_reuse->use_cnt);
		mutex_unlock(&tpid_reuse->lock);
		ubcore_log_info_rl("Success to reuse tpid_reuse:%u", tpid_reuse->tp_handle.bs.tpid);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return tpid_reuse;
	}

	for (i = 0; i < UBCORE_TPID_REUSE_MAX_WAIT_TIMES; i++) {
		if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
			if (!ubcore_is_loopback(tpid_reuse->ub_dev, &tpid_reuse->rk.lk.peer_eid) &&
				atomic_read(&tpid_reuse->use_cnt) == 0 &&
				tpid_reuse->is_ref == true) {
				ret = send_is_ref_req(tpid_reuse);
				if (ret != 0) {
					ubcore_log_err(
						"Failed to send is_ref req, ret = %d.\n", ret);
					mutex_unlock(&tpid_reuse->lock);
					ubcore_tpid_reuse_kref_put(tpid_reuse);
					return NULL;
				}
			}
			atomic_inc(&tpid_reuse->use_cnt);
			mutex_unlock(&tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(tpid_reuse);
			return tpid_reuse;
		} else if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_RESET) {
			mutex_unlock(&tpid_reuse->lock);
			usleep_range(UBCORE_TPID_REUSE_WAIT_MIN_US,
				UBCORE_TPID_REUSE_WAIT_MAX_US);
			mutex_lock(&tpid_reuse->lock);
		} else if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
			break;
		}
	}
	ubcore_log_err("failed to reuse tpid_reuse:%u, use_cnt:%d", tpid_reuse->tp_handle.bs.tpid,
			atomic_read(&tpid_reuse->use_cnt));
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	return NULL;
}

int ubcore_free_tpid_reuse(struct ubcore_tpid_reuse *tpid_reuse)
{
	int ret = 0;

	if (tpid_reuse == NULL || tpid_reuse->ub_dev == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to release tpid reuse, ret = %d.\n", ret);
		return ret;
	}

	if (atomic_read(&tpid_reuse->use_cnt) > 0) {
		ubcore_log_info_rl("tpid_reuse in use, tpid_reuse id = %u, tpid_reuse use_cnt = %d",
				tpid_reuse->tp_handle.bs.tpid, atomic_read(&tpid_reuse->use_cnt));
		return 0;
	}

	if (tpid_reuse->tp_handle_valid)	{
		ret = ubcore_delete_tpid_priv(tpid_reuse->ub_dev, tpid_reuse->tp_handle.bs.tpid);
		if (ret != 0)
			ubcore_log_err("Failed to delete tpid, ret = %d.\n", ret);
		tpid_reuse->tp_handle_valid = false;
	}

	ubcore_tpid_reuse_kref_put(tpid_reuse);
	wait_for_completion(&tpid_reuse->comp);
	mutex_destroy(&tpid_reuse->lock);

	kfree(tpid_reuse);
	return 0;
}

int ubcore_active_tp(struct ubcore_device *dev,
			    struct ubcore_active_tp_cfg *active_cfg)
{
	uint64_t start, duration;
	int ret;

	if (!dev || !dev->ops || !dev->ops->active_tp ||
	    active_cfg == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ubcore_log_info("Active tp, local tp_hdl: %llu, peer tp_hdl: %llu.\n",
			active_cfg->tp_handle.value,
			active_cfg->peer_tp_handle.value);

	UBCORE_PERF_TRACE_BEGIN(PERF_UB_ACTIVE_TP);
	start = ktime_get_ns();
	ret = dev->ops->active_tp(dev, active_cfg);
	duration = (ktime_get_ns() - start) / UBCORE_NS_TO_MS;
	UBCORE_PERF_TRACE_END(PERF_UB_ACTIVE_TP);
	if (ret != 0)
		ubcore_log_err(
			"Failed to active tp, ret: %d, local tpid: %u.\n", ret,
			(uint32_t)active_cfg->tp_handle.bs.tpid);

	if (duration > UBCORE_DRV_TP_THRESHOLD_MS)
		ubcore_log_info_rl("[DRV_INFO]active_tp target consumes: %llu.\n",
			duration);

	return ret;
}

int ubcore_deactive_tp(struct ubcore_device *dev,
				union ubcore_tp_handle tp_handle,
				struct ubcore_udata *udata)
{
	int ret;

	if (!dev || !dev->ops || !dev->ops->deactive_tp) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ubcore_log_info_rl("Deactivate tp, tp_handle:%lld.\n", tp_handle.value);

	UBCORE_PERF_TRACE_BEGIN(PERF_UB_DEACTIVE_TP);
	ret = dev->ops->deactive_tp(dev, tp_handle, udata);
	UBCORE_PERF_TRACE_END(PERF_UB_DEACTIVE_TP);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to deactivate tp, ret: %d.\n", ret);
		return ret;
	}

	return ret;
}

static struct ubcore_session *
create_session_for_create_connection(struct ubcore_device *dev)
{
	struct ubcore_session *session;
	struct session_data_create_conn *session_data;

	session_data =
		kzalloc(sizeof(struct session_data_create_conn), GFP_KERNEL);
	if (IS_ERR_OR_NULL(session_data)) {
		ubcore_log_err("Failed to alloc create user arg");
		return NULL;
	}

	session_data->ret = -1;

	session = ubcore_session_create(dev, session_data,
		ubcore_get_conn_timeout(), NULL, NULL);
	if (!session) {
		ubcore_log_err("Failed to alloc session for create connection");
		kfree(session_data);
		return NULL;
	}

	return session;
}

static int send_create_req(struct ubcore_device *dev, uint32_t session_id,
			   struct msg_create_conn_req *req)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_CREATE_REQ;
	msg.len = (uint16_t)sizeof(struct msg_create_conn_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubcore_send_comm_msg_to(dev, &msg, req->get_tp_cfg.peer_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg, dev_name is %s, peer_eid is "EID_FMT"\n",
			dev->dev_name, EID_ARGS(req->get_tp_cfg.peer_eid));
		return ret;
	}
	return 0;
}

static int send_create_resp(struct ubcore_device *dev, void *conn,
			    uint32_t session_id,
			    struct msg_create_conn_resp *resp)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_CREATE_RESP;
	msg.len = (uint16_t)sizeof(struct msg_create_conn_resp);
	msg.session_id = session_id;
	msg.data = resp;

	ret = ubcore_send_comm_msg(dev, &msg, conn);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

static int ubcore_add_ex_tp_info(struct ubcore_device *dev, uint64_t tp_handle)
{
	struct ubcore_ex_tp_info *ex_tp_info = NULL;
	uint32_t hash;
	int ret;

	ex_tp_info = kzalloc(sizeof(struct ubcore_ex_tp_info), GFP_KERNEL);
	if (!ex_tp_info)
		return -ENOMEM;
	ex_tp_info->tp_handle = tp_handle;
	kref_init(&ex_tp_info->ref_cnt);

	hash = ubcore_get_ex_tp_hash(&tp_handle);
	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_EX_TP],
					 &ex_tp_info->hnode, hash);
	if (ret != 0) {
		ubcore_log_err("Failed to add ex tp info, tp_handle: %llu.\n",
			       tp_handle);
		kfree(ex_tp_info);
	}

	return ret;
}

struct ubcore_ex_tp_info *
ubcore_find_remove_ex_tp_info(struct ubcore_device *dev, uint64_t tp_handle)
{
	struct ubcore_ex_tp_info *ex_tp_info = NULL;
	uint32_t hash;

	hash = ubcore_get_ex_tp_hash(&tp_handle);
	spin_lock(&dev->ht[UBCORE_HT_EX_TP].lock);
	if (!dev->ht[UBCORE_HT_EX_TP].head) {
		spin_unlock(&dev->ht[UBCORE_HT_EX_TP].lock);
		return NULL;
	}

	ex_tp_info = ubcore_hash_table_lookup_nolock(&dev->ht[UBCORE_HT_EX_TP],
						     hash, &tp_handle);
	if (!ex_tp_info) {
		spin_unlock(&dev->ht[UBCORE_HT_EX_TP].lock);
		ubcore_log_info("Do not find ex_tp_info, tp_handle: %llu.\n",
				tp_handle);
		return NULL;
	}
	ubcore_hash_table_remove_nolock(&dev->ht[UBCORE_HT_EX_TP],
					&ex_tp_info->hnode);
	spin_unlock(&dev->ht[UBCORE_HT_EX_TP].lock);

	return ex_tp_info;
}

int ubcore_exchange_tp_info(struct ubcore_device *dev,
				struct ubcore_get_tp_cfg *get_tp_cfg,
				struct ubcore_active_tp_cfg *active_tp_cfg,
				struct ubcore_tjetty_cfg *tjetty_cfg,
				struct ubcore_udata *udata)
{
	struct session_data_create_conn *session_data;
	struct msg_create_conn_req req = { 0 };
	struct ubcore_session *session;
	uint64_t *peer_tp_handle;
	uint64_t tp_handle;
	uint32_t *rx_psn;
	uint32_t tx_psn;
	int ret;

	if (!dev || !get_tp_cfg || !active_tp_cfg || !tjetty_cfg)
		return -EINVAL;

	peer_tp_handle = &active_tp_cfg->peer_tp_handle.value;
	tp_handle = active_tp_cfg->tp_handle.value;
	rx_psn = &active_tp_cfg->tp_attr.rx_psn;
	tx_psn = active_tp_cfg->tp_attr.tx_psn;

	if (ubcore_is_loopback(dev, &get_tp_cfg->peer_eid)) {
		*peer_tp_handle = tp_handle;
		*rx_psn = tx_psn;
		ubcore_log_info("Finish to handle loop back tp: %llu.\n", tp_handle);
		return 0;
	}

	session = create_session_for_create_connection(dev);
	if (!session) {
		return -ENOMEM;
	}

	req.get_tp_cfg = *get_tp_cfg;
	req.tp_handle = tp_handle;
	req.tx_psn = tx_psn;
	req.share_tp = (tjetty_cfg->flag.bs.share_tp == 1);
	req.stag = tjetty_cfg->stp_cfg.stag;
	req.dtag = tjetty_cfg->stp_cfg.dtag;

	ret = send_create_req(dev, ubcore_session_get_id(session), &req);
	if (ret != 0) {
		ubcore_session_complete(session);
		ubcore_session_ref_release(session);
		return ret;
	}

	ubcore_session_wait(session);
	session_data =
		(struct session_data_create_conn *)ubcore_session_get_data(
			session);
	ret = session_data->ret;
	if (ret != CREATE_CONN_SUCCESS && ret != ESTABLISHED_TP_CHANNEL) {
		ubcore_log_err("Failed to send create req message, ret: %d.\n",
			       ret);
		ubcore_session_ref_release(session);
		return ret;
	}
	*peer_tp_handle = session_data->peer_tp_handle;
	*rx_psn = session_data->rx_psn;
	ubcore_session_ref_release(session);
	/* ubcore_add_ex_tp_info result will not have effect on excange_tp_info result */
	return 0;
}
EXPORT_SYMBOL(ubcore_exchange_tp_info);

/* Only for RC + RTP */
int ubcore_exchange_tpid_info(struct ubcore_device *dev,
	struct ubcore_get_tp_cfg *cfg, struct ubcore_ex_tpid_info *info,
	struct ubcore_udata *udata)
{
	struct session_data_create_conn *session_data;
	struct msg_create_conn_req req = { 0 };
	struct ubcore_session *session;
	int ret;

	if (!dev || !cfg || !info) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (ubcore_is_loopback(dev, &cfg->peer_eid)) {
		info->peer_tp_handle = info->tp_handle;
		info->rx_psn = info->tx_psn;
		ubcore_log_info("Finish to handle loop back tp: %llu.\n",
			info->tp_handle);
		return 0;
	}

	session = create_session_for_create_connection(dev);
	if (!session) {
		return -ENOMEM;
	}

	req.get_tp_cfg = *cfg;
	req.tp_handle = info->tp_handle;
	req.tx_psn = info->tx_psn;
	req.src_jetty_id = info->local_jetty_id;
	req.dst_jetty_id = info->peer_jetty_id;
	ret = send_create_req(dev, ubcore_session_get_id(session), &req);
	if (ret != 0) {
		ubcore_log_err("Failed to send create req message");
		ubcore_session_complete(session);
		ubcore_session_ref_release(session);
		return ret;
	}

	ubcore_session_wait(session);
	session_data =
		(struct session_data_create_conn *)ubcore_session_get_data(
			session);
	ret = session_data->ret;
	if (ret != 0) {
		ubcore_log_err("Failed to send create req message, ret: %d.\n",
			       ret);
		ubcore_session_ref_release(session);
		return ret;
	}
	info->peer_tp_handle = session_data->peer_tp_handle;
	info->rx_psn = session_data->rx_psn;
	ubcore_session_ref_release(session);

	ret = ubcore_add_ex_tp_info(dev, info->tp_handle);
	ubcore_log_info("exchange tp_handle is %llu\n",
		(unsigned long long)info->tp_handle);
	/* ubcore_add_ex_tp_info result will not have effect on excange_tp_info result */
	if (ret != 0)
		ubcore_log_err("Failed to add ex tp info, ret: %d.\n", ret);
	return 0;
}

static inline uint32_t ubcore_get_tpid_hash(struct ubcore_tpid_key *key)
{
	return jhash(key, sizeof(struct ubcore_tpid_key), 0);
}

struct ubcore_tpid_ctx *ubcore_fget_tpid_ctx(
	struct ubcore_device *dev, struct ubcore_tpid_key *key)
{
	struct ubcore_tpid_ctx *ctx = NULL;
	uint32_t hash;

	hash = ubcore_get_tpid_hash(key);
	ctx = ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_RC_TP_ID],
		hash, key);
	ubcore_log_info("Find tpid_ctx result: %d, hash: %u.\n",
		(int)(ctx != NULL), hash);

	return ctx;
}

void ubcore_tpid_get(void *obj)
{
	struct ubcore_tpid_ctx *ctx = obj;

	kref_get(&ctx->ref);
}

static void ubcore_tpid_ctx_free(struct kref *ref)
{
	struct ubcore_tpid_ctx *ctx = container_of(ref,
		struct ubcore_tpid_ctx, ref);

	kfree(ctx);
}

static void ubcore_tpid_put(struct ubcore_tpid_ctx *ctx)
{
	kref_put(&ctx->ref, ubcore_tpid_ctx_free);
}

void ubcore_reuse_target_rtp_tpid(struct ubcore_device *dev,
	struct ubcore_tpid_ctx *ctx, struct ubcore_get_tp_cfg *cfg,
	struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_create_conn_resp resp = { 0 };
	int ret;

	if (cfg->flag.bs.rtp != 1 || cfg->trans_mode != UBCORE_TP_RC) {
		ubcore_log_err("Invalid operation.\n");
		ubcore_tpid_put(ctx);
		ret = -EINVAL;
		goto send_resp;
	}

	if (!ctx->is_init) {
		ubcore_log_err("Duplicate operation.\n");
		ubcore_tpid_put(ctx);
		ret = -EINVAL;
		goto send_resp;
	}

	/* Reuse */
	ubcore_log_info("Reuse tpid: %llu.\n", ctx->tp_handle);
	resp.tp_handle = ctx->tp_handle;
	resp.tx_psn = ctx->tx_psn;
	ret = CREATE_CONN_SUCCESS;

send_resp:
	resp.result = ret;
	if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
		ubcore_log_err("Failed to send create resp message.\n");
}

static inline void fill_tpid_ctx(struct ubcore_tpid_ctx *ctx,
	struct ubcore_tpid_key *key, struct ubcore_active_tp_cfg *cfg,
	bool is_init)
{
	ctx->tp_handle = cfg->tp_handle.value;
	ctx->peer_tp_handle = cfg->peer_tp_handle.value;
	kref_init(&ctx->ref);
	ctx->trans_mode = UBCORE_TP_RC;
	ctx->key = *key;
	ctx->tp_type = UBCORE_RTP;
	ctx->is_init = is_init;
	ctx->tx_psn = cfg->tp_attr.tx_psn;
	ctx->rx_psn = cfg->tp_attr.rx_psn;
}

void ubcore_fadd_target_tpid_ctx(struct ubcore_device *dev,
	struct ubcore_tpid_key *key, struct ubcore_active_tp_cfg *cfg,
	struct msg_create_conn_resp *resp)
{
	struct ubcore_tpid_ctx *add_ctx = NULL;
	struct ubcore_tpid_ctx *ctx = NULL;
	struct ubcore_hash_table *ht;
	uint32_t hash;

	hash = ubcore_get_tpid_hash(key);
	ht = &dev->ht[UBCORE_HT_RC_TP_ID];

	add_ctx = kzalloc(sizeof(struct ubcore_tpid_ctx), GFP_KERNEL);
	if (IS_ERR_OR_NULL(add_ctx))
		return;

	spin_lock(&ht->lock);
	ctx = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (ctx && ctx->is_init) {
		resp->tp_handle = ctx->tp_handle;
		spin_unlock(&ht->lock);
		ubcore_log_info("Find tpid in initiator, hash: %u.\n", hash);
		(void)ubcore_deactive_tp(dev, cfg->tp_handle, NULL);
		kfree(add_ctx);
		return;
	}
	if (ctx && !ctx->is_init) {
		spin_unlock(&ht->lock);
		ubcore_log_info("Find tpid in target, hash: %u.\n", hash);
		kfree(add_ctx);
		return;
	}

	fill_tpid_ctx(add_ctx, key, cfg, false);
	ubcore_log_info("add_ctx tp_handle is %llu, peer_tp_handle is %llu.",
		add_ctx->tp_handle, add_ctx->peer_tp_handle);
	add_ctx->tp_state = UBCORE_TP_ACTIVE;
	ubcore_hash_table_add_nolock(ht, &add_ctx->hnode, hash);
	spin_unlock(&ht->lock);
}

static int target_reuse_tpid(struct ubcore_device *dev, struct ubcore_tpid_reuse *tpid_reuse,
								struct msg_create_conn_req *req)
{
	struct ubcore_active_tp_cfg active_cfg = {0};
	union ubcore_modify_tpid_cfg modify_tpid_cfg = {
		.active_cfg = &active_cfg
	};
	int ret;
	int i;

	active_cfg.tp_handle.value = tpid_reuse->tp_handle.value;
	active_cfg.peer_tp_handle.value = req->tp_handle;
	active_cfg.tp_attr.rx_psn = req->tx_psn;
	active_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
		tpid_reuse->is_ref = true;
		mutex_unlock(&tpid_reuse->lock);
		return ESTABLISHED_TP_CHANNEL;
	}

	for (i = 0; i < UBCORE_TPID_REUSE_MAX_WAIT_TIMES; i++) {
		if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_RESET) {
			if (tpid_reuse->tp_handle.value != 0) {
				active_cfg.tp_handle.value = tpid_reuse->tp_handle.value;
				ret = ubcore_modify_tpid(dev, UBCORE_TPID_STATE_RTS,
										 &modify_tpid_cfg);
				if (ret != 0) {
					ubcore_log_err(
						"Failed to modify tpid:%u to RTS, ret:%d.\n",
						(uint32_t)active_cfg.tp_handle.bs.tpid, ret);
					tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
					mutex_unlock(&tpid_reuse->lock);
					return MODIFY_TPID_ERROR;
				}
				tpid_reuse->is_ref = true;
				mutex_unlock(&tpid_reuse->lock);
				return CREATE_CONN_SUCCESS;
			}
			mutex_unlock(&tpid_reuse->lock);
			usleep_range(UBCORE_TPID_REUSE_WAIT_MIN_US,
				UBCORE_TPID_REUSE_WAIT_MAX_US);
			mutex_lock(&tpid_reuse->lock);
		} else if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
			tpid_reuse->is_ref = true;
			mutex_unlock(&tpid_reuse->lock);
			return CREATE_CONN_SUCCESS;
		} else {
			mutex_unlock(&tpid_reuse->lock);
			return CREATE_CONN_FAIL;
		}
	}
	mutex_unlock(&tpid_reuse->lock);

	return CREATE_CONN_FAIL;
}

static void handle_create_req_with_tpid_reuse(struct ubcore_device *dev,
	struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_create_conn_req *req = (struct msg_create_conn_req *)msg->data;
	struct ubcore_get_tp_cfg get_tp_cfg = req->get_tp_cfg;
	struct ubcore_active_tp_cfg active_cfg = {0};
	struct ubcore_tpid_cfg tpid_cfg = { 0 };
	union ubcore_modify_tpid_cfg modify_tpid_cfg = {
		.active_cfg = &active_cfg
	};
	struct ubcore_tpid_reuse_key key = { 0 };
	struct ubcore_tpid_reuse *tpid_reuse = NULL;
	struct ubcore_tpid_reuse *exist_tpid_reuse = NULL;
	union ubcore_tp_handle tp_handle;
	struct msg_create_conn_resp resp = {0};
	uint32_t tx_psn;
	int ret;

	get_tp_cfg.local_eid = req->get_tp_cfg.peer_eid;
	get_tp_cfg.peer_eid = req->get_tp_cfg.local_eid;
	key.lk.local_eid = get_tp_cfg.local_eid;
	key.lk.peer_eid = get_tp_cfg.peer_eid;
	union ubcore_net_addr_union local_cna = {0};
	union ubcore_net_addr_union peer_cna = {0};

	if (ubcore_get_enable_shared_ctp() &&
	    get_tp_cfg.flag.bs.ctp &&
	    get_tp_cfg.trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg.local_eid,
			&key.lk.local_eid, &get_tp_cfg.peer_eid, &key.lk.peer_eid,
			&local_cna, &peer_cna);
	}
	key.lk.trans_mode = get_tp_cfg.trans_mode;
	key.stag = req->dtag;
	key.dtag = req->stag;

	if (get_tp_cfg.flag.bs.rtp)
		key.lk.tp_type = UBCORE_RTP;
	if (get_tp_cfg.flag.bs.ctp)
		key.lk.tp_type = UBCORE_CTP;
	if (get_tp_cfg.flag.bs.utp)
		key.lk.tp_type = UBCORE_UTP;

	key.lk.link_type = (get_tp_cfg.flag.bs.uboe) ? UBCORE_LINK_UBOE : UBCORE_LINK_ETHERNET;
	key.lk.share_mode = (req->share_tp) ? UBCORE_TPID_SHARE_CONTAINER : UBCORE_TPID_SHARE_NONE;

	ubcore_log_info_rl("Enter handle create req tpid reuse");

	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	if (tpid_reuse == NULL &&
	    ubcore_get_enable_shared_ctp() &&
	    key.lk.tp_type == UBCORE_CTP &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    !ubcore_net_addr_is_zero(&local_cna) &&
	    !ubcore_net_addr_is_zero(&peer_cna)) {
		ubcore_fill_tpid_reuse_key_cna(&key, local_cna, peer_cna);
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (create_req): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	}
	if (tpid_reuse != NULL) {
		ret = target_reuse_tpid(dev, tpid_reuse, req);
		resp.tp_handle = tpid_reuse->tp_handle.value;
		resp.tx_psn = tpid_reuse->tx_psn;
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		resp.result = ret;
		if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
			ubcore_log_err("Failed to send create resp message.\n");
		return;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		ret = GET_TP_LIST_ERROR;
		goto send_resp;
	}

	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		ubcore_log_info_rl("tpid_reuse exists.\n");
		ret = target_reuse_tpid(dev, exist_tpid_reuse, req);
		resp.tp_handle = exist_tpid_reuse->tp_handle.value;
		resp.tx_psn = exist_tpid_reuse->tx_psn;
		ubcore_tpid_reuse_kref_put(exist_tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		resp.result = ret;
		if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
			ubcore_log_err("Failed to send create resp message.\n");
		return;
	} else if (ret != 0) {
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		ret = GET_TP_LIST_ERROR;
		goto send_resp;
	}
	ret = ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid cfg, ret=%d", ret);
		ret = GET_TP_LIST_ERROR;
		ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		goto send_resp;
	}

	ret = ubcore_create_tpid_priv(dev, &tpid_cfg, NULL, &tp_handle);
	if (ret != 0) {
		ubcore_log_err("Failed to create tpid, ret=%d", ret);
		ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		ret = GET_TP_LIST_ERROR;
		goto send_resp;
	}
	ubcore_log_info_rl("return tpid value: %lld.\n", tp_handle.value);

	tx_psn = tpid_reuse->tx_psn;
	active_cfg.tp_handle.value = tp_handle.value;
	active_cfg.peer_tp_handle.value = req->tp_handle;
	active_cfg.tp_attr.rx_psn = req->tx_psn;
	active_cfg.tp_attr.tx_psn = tx_psn;

	ubcore_log_info("Rcv req, local eid " EID_FMT ", peer eid " EID_FMT
		", tphdl: %llu, p_tphdl: %llu, tx_psn: %u, rx_psn: %u.\n",
		EID_ARGS(tpid_cfg.local_eid),
		EID_ARGS(tpid_cfg.peer_eid), tp_handle.value,
		active_cfg.peer_tp_handle.value, tx_psn, req->tx_psn);

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->tp_handle.value = tp_handle.value;
	tpid_reuse->tp_handle_valid = true;
	ret = ubcore_modify_tpid(dev, UBCORE_TPID_STATE_RTS, &modify_tpid_cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to modify tpid:%u to RTS, ret:%d.\n",
				(uint32_t)active_cfg.tp_handle.bs.tpid, ret);
		tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
		mutex_unlock(&tpid_reuse->lock);
		ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		ret = MODIFY_TPID_ERROR;
		goto send_resp;
	}

	tpid_reuse->is_ref = true;
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	mutex_unlock(&tpid_reuse->lock);

	resp.tp_handle = tp_handle.value;
	resp.tx_psn = tx_psn;
	ret = CREATE_CONN_SUCCESS;

send_resp:
	resp.result = ret;
	if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
		ubcore_log_err("Failed to send create resp message.\n");
}

static void handle_create_resp(struct ubcore_device *dev, struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_create_conn_resp *resp = (struct msg_create_conn_resp *)msg->data;
	struct ubcore_session *session;
	struct session_data_create_conn *session_data;

	session = ubcore_session_find(msg->session_id);
	if (!session) {
		ubcore_log_err(
			"Failed to find session %u on handle create-resp",
			msg->session_id);
		return;
	}
	session_data = (struct session_data_create_conn *)ubcore_session_get_data(session);
	session_data->rx_psn = resp->tx_psn;
	session_data->peer_tp_handle = resp->tp_handle;
	session_data->ret = resp->result;
	ubcore_log_info("Create response result: %d.\n", resp->result);

	ubcore_session_complete(session);
	ubcore_session_ref_release(session);
}

static int send_destroy_req(struct ubcore_tpid_reuse *tpid_reuse)
{
	struct ubcore_comm_msg msg = { 0 };
	struct msg_destroy_conn_req req = { 0 };
	int ret;

	req.local_eid = tpid_reuse->rk.lk.local_eid;
	req.peer_eid = tpid_reuse->rk.lk.peer_eid;
	req.trans_mode = tpid_reuse->rk.lk.trans_mode;
	req.stag = tpid_reuse->rk.stag;
	req.dtag = tpid_reuse->rk.dtag;
	req.tp_type = tpid_reuse->rk.lk.tp_type;
	req.link_type = tpid_reuse->rk.lk.link_type;
	req.share_mode = tpid_reuse->rk.lk.share_mode;

	msg.type = UBCORE_NET_DESTROY_REQ;
	msg.len = (uint16_t)sizeof(struct msg_destroy_conn_req);
	msg.session_id = 0;
	msg.data = &req;

	ret = ubcore_send_comm_msg_to(tpid_reuse->ub_dev, &msg, tpid_reuse->rk.lk.peer_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}

	return 0;
}

int ubcore_disconnect_tpid_with_tpid_reuse(struct ubcore_tpid_reuse *tpid_reuse)
{
	struct ubcore_device *dev;
	struct ubcore_deactive_tp_cfg deactive_cfg = {0};
	union ubcore_modify_tpid_cfg cfg = {
		.deactive_cfg = &deactive_cfg
	};

	int ret = 0;

	if (tpid_reuse == NULL || tpid_reuse->ub_dev == NULL)
		return -EINVAL;

	dev = tpid_reuse->ub_dev;

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
		mutex_unlock(&tpid_reuse->lock);
		ubcore_log_warn("tpid_reuse already in ERROR state, skip disconnect.\n");
		return 0;
	}

	if (atomic_dec_return(&tpid_reuse->use_cnt) > 0) {
		mutex_unlock(&tpid_reuse->lock);
		return 0;
	}

	if (tpid_reuse->tp_handle.bs.rtp &&
		!ubcore_is_loopback(tpid_reuse->ub_dev, &tpid_reuse->rk.lk.peer_eid)) {
		ret = send_destroy_req(tpid_reuse);
		if (ret != 0) {
			ubcore_log_err("Failed to send destroy req message");
			/* Rollback use_cnt on failure */
			atomic_inc(&tpid_reuse->use_cnt);
			mutex_unlock(&tpid_reuse->lock);
			return ret;
		}
	}

	if (tpid_reuse->is_ref) {
		mutex_unlock(&tpid_reuse->lock);
		return 0;
	}

	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	cfg.deactive_cfg->tp_handle.value = tpid_reuse->tp_handle.value;
	cfg.deactive_cfg->udata = NULL;
	mutex_unlock(&tpid_reuse->lock);

	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);

	ret = ubcore_modify_tpid(dev, UBCORE_TPID_STATE_ERR, &cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to modify tpid to ERROR, ret: %d, tphdl: %llu.\n",
			ret, tpid_reuse->tp_handle.value);
	}

	ubcore_log_info_rl("disconnect tpid_reuse:%u, ret:%d, tpid_reuse_state:%u",
			   tpid_reuse->tp_handle.bs.tpid, ret, tpid_reuse->reuse_state);

	if (ret == 0)
		(void)ubcore_free_tpid_reuse(tpid_reuse);

	return ret;
}

int ubcore_adapter_layer_disconnect(struct ubcore_vtpn *vtpn)
{
	union ubcore_tp_handle tp_handle =
		(union ubcore_tp_handle)vtpn->tp_handle;
	union ubcore_eid peer_eid = vtpn->peer_eid;
	struct ubcore_device *dev = vtpn->ub_dev;
	struct ubcore_deactive_tp_cfg deactive_cfg = {0};
	union ubcore_modify_tpid_cfg cfg = {
		.deactive_cfg = &deactive_cfg
	};
	int ret;

	cfg.deactive_cfg->tp_handle.value = tp_handle.value;
	cfg.deactive_cfg->udata = NULL;
	ret = ubcore_modify_tpid(dev, UBCORE_TPID_STATE_ERR, &cfg);

	if (ret != 0) {
		ubcore_log_err("Failed to modify tpid to ERROR, ret: %d, tphdl: %llu.\n",
			ret, tp_handle.value);
		return ret;
	}

	if (ubcore_is_loopback(dev, &peer_eid)) {
		ubcore_log_info(
			"Loop-back, tp_handle: %llu,peer_tp_handle: %llu.\n",
			vtpn->tp_handle, vtpn->peer_tp_handle);
		return 0;
	}

	/* Only send destroy request for RM/RC TP */

	return 0;
}


static int send_destroy_stp_req(struct ubcore_device *dev,
				struct ubcore_rm_tp_key *key,
				union ubcore_tp_handle tp_handle)
{
	struct ubcore_comm_msg msg = { 0 };
	struct msg_destroy_conn_req req = { 0 };
	int ret;

	req.tp_handle = tp_handle;
	req.local_eid = key->local_eid;
	req.peer_eid = key->peer_eid;
	req.stag = key->stag;
	req.dtag = key->dtag;
	req.ht_id = UBCORE_HT_RM_TP_ID;

	msg.type = UBCORE_NET_DESTROY_REQ;
	msg.len = (uint16_t)sizeof(struct msg_destroy_conn_req);
	msg.session_id = 0;
	msg.data = &req;

	ret = ubcore_send_comm_msg_to(dev, &msg, key->peer_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

static int refput_for_deactive_rmstp(struct ubcore_hash_table *ht, uint32_t hash,
				struct ubcore_rm_tp_key *key)
{
	struct ubcore_rm_tp_info *tp_info = NULL;
	int ret = 0;

	spin_lock(&ht->lock);
	tp_info = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (IS_ERR_OR_NULL(tp_info)) {
		ubcore_log_err("[refput] Failed to find rm stp\n");
		ret = -RM_STP_ERROR;
		goto refput_out;
	}
	if (--tp_info->ref_cnt != 0) {
		ret = -RM_STP_ACTIVE;
		goto refput_out;
	}
	if (tp_info->is_refed) {
		ret = RM_STP_ACTIVE;
		goto refput_out;
	}
	ubcore_hash_table_remove_nolock(ht, &tp_info->hnode);
	spin_unlock(&ht->lock);
	kfree(tp_info);
	ret = RM_STP_CREATED;
	return ret;
refput_out:
	spin_unlock(&ht->lock);
	return ret;
}


static void ubcore_deactive_stp(struct work_struct *work)
{
	struct ubcore_deactive_stp_work *deactive_work =
		container_of(work, struct ubcore_deactive_stp_work, work);
	union ubcore_tp_handle tp_handle = deactive_work->tp_handle;
	struct ubcore_device *dev = deactive_work->dev;
	int ret = 0;

	if (deactive_work->uspace)
		ret = ubcore_deactive_tp(dev, tp_handle, &deactive_work->udata);
	else
		ret = ubcore_deactive_tp(dev, tp_handle, NULL);
	if (ret != 0)
		ubcore_log_err("Failed to queue deactivate tp\n");
	kfree(deactive_work);
}

int ubcore_adapter_layer_rm_stp_disconnect(struct ubcore_tjetty *tjetty)
{
	struct ubcore_vtpn *vtpn = tjetty->vtpn;
	union ubcore_tp_handle peer_tp_handle =
		(union ubcore_tp_handle)vtpn->peer_tp_handle;
	union ubcore_tp_handle tp_handle =
		(union ubcore_tp_handle)vtpn->tp_handle;
	struct ubcore_device *dev = vtpn->ub_dev;
	struct ubcore_hash_table *ht = &dev->ht[UBCORE_HT_RM_TP_ID];
	struct ubcore_share_tp_cfg *stp_cfg = &tjetty->cfg.stp_cfg;
	struct ubcore_deactive_stp_work *deactive_work;
	struct ubcore_rm_tp_key key = {0};
	struct ubcore_udata udata = {0};
	uint32_t hash;
	int ret;

	key.local_eid = vtpn->local_eid;
	key.peer_eid = vtpn->peer_eid;
	key.stag = stp_cfg->stag;
	key.dtag = stp_cfg->dtag;
	hash = ubcore_get_rm_tp_hash(&key);
	ret = refput_for_deactive_rmstp(ht, hash, &key);
	if (ret < 0)
		return ret;

	if (ret == RM_STP_CREATED) {
		deactive_work = kzalloc(sizeof(*deactive_work), GFP_KERNEL);
		if (IS_ERR_OR_NULL(deactive_work))
			return -ENOMEM;

		INIT_WORK(&deactive_work->work, ubcore_deactive_stp);
		deactive_work->dev = dev;
		deactive_work->tp_handle = tp_handle;
		deactive_work->udata = udata;
		deactive_work->uspace = vtpn->uspace;
		ret = ubcore_queue_work((int)UBCORE_DEACTIVE_SHARE_TP_WQ,
					&deactive_work->work);
		if (ret != 0) {
			kfree(&deactive_work->work);
			ubcore_log_err("Failed to queue deactivate tp\n");
			return ret;
		}
	}

	/* maybe unnecessary */
	if (ubcore_is_loopback(dev, &key.peer_eid)) {
		ubcore_log_info(
			"Loop-back, tp_handle: %llu,peer_tp_handle: %llu.\n",
			vtpn->tp_handle, vtpn->peer_tp_handle);
		return 0;
	}

	if (ubcore_check_ctrlplane_compat(dev->ops->import_jetty)) {
		ret = send_destroy_stp_req(dev, &key, peer_tp_handle);
		if (ret != 0)
			ubcore_log_err("Failed to send destroy req message");
	}
	return 0;
}

static void handle_destroy_req_with_tpid_reuse(struct ubcore_device *dev,
			       struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_destroy_conn_req *req =
		(struct msg_destroy_conn_req *)msg->data;
	struct ubcore_tpid_reuse_key key = { 0 };
	struct ubcore_deactive_tp_cfg deactive_cfg = {0};
	union ubcore_modify_tpid_cfg cfg = {
		.deactive_cfg = &deactive_cfg
	};
	struct ubcore_tpid_reuse *tpid_reuse;
	int ret;

	ubcore_log_info_rl("Enter handle req with tpid reuse.\n");

	key.lk.local_eid = req->peer_eid;
	key.lk.peer_eid = req->local_eid;
	union ubcore_net_addr_union destroy_local_cna = {0};
	union ubcore_net_addr_union destroy_peer_cna = {0};

	if (ubcore_get_enable_shared_ctp() &&
	    req->tp_type == UBCORE_CTP &&
	    req->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&req->peer_eid, &key.lk.local_eid,
			&req->local_eid, &key.lk.peer_eid, &destroy_local_cna, &destroy_peer_cna);
	}
	key.lk.trans_mode = req->trans_mode;
	key.lk.tp_type = req->tp_type;
	key.lk.link_type = req->link_type;
	key.lk.share_mode = req->share_mode;
	key.stag = req->dtag;
	key.dtag = req->stag;

	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	if (tpid_reuse == NULL &&
	    ubcore_get_enable_shared_ctp() &&
	    key.lk.tp_type == UBCORE_CTP &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    !ubcore_net_addr_is_zero(&destroy_local_cna) &&
	    !ubcore_net_addr_is_zero(&destroy_peer_cna)) {
		ubcore_fill_tpid_reuse_key_cna(&key, destroy_local_cna, destroy_peer_cna);
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (destroy_req): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	}
	if (tpid_reuse == NULL) {
		ubcore_log_err("tpid not found in tpid_reuse table in handle destroy req.\n");
		return;
	}

	mutex_lock(&tpid_reuse->lock);
	if (atomic_read(&tpid_reuse->use_cnt) > 0) {
		tpid_reuse->is_ref = false;
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}

	if (tpid_reuse->is_ref == false) {
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}

	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}

	tpid_reuse->is_ref = false;
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	cfg.deactive_cfg->tp_handle.value = tpid_reuse->tp_handle.value;
	cfg.deactive_cfg->udata = NULL;
	mutex_unlock(&tpid_reuse->lock);

	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);

	ret = ubcore_modify_tpid(dev, UBCORE_TPID_STATE_ERR, &cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to modify tpid to ERROR, ret: %d, tphdl: %llu.\n",
			ret, tpid_reuse->tp_handle.value);
	}

	ubcore_tpid_reuse_kref_put(tpid_reuse);
	if (ret == 0)
		(void)ubcore_free_tpid_reuse(tpid_reuse);
}

static void handle_isref_req(struct ubcore_device *dev,
			       struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_isref_conn_req *req =
		(struct msg_isref_conn_req *)msg->data;
	struct ubcore_tpid_reuse_key key = { 0 };
	struct ubcore_tpid_reuse *tpid_reuse;

	key.lk.local_eid = req->peer_eid;
	key.lk.peer_eid = req->local_eid;
	union ubcore_net_addr_union isref_local_cna = {0};
	union ubcore_net_addr_union isref_peer_cna = {0};

	if (ubcore_get_enable_shared_ctp() &&
	    req->tp_type == UBCORE_CTP &&
	    req->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&req->peer_eid,
			&key.lk.local_eid, &req->local_eid, &key.lk.peer_eid,
			&isref_local_cna, &isref_peer_cna);
	}
	key.lk.trans_mode = req->trans_mode;
	key.lk.tp_type = req->tp_type;
	key.lk.link_type = req->link_type;
	key.lk.share_mode = req->share_mode;
	key.stag = req->dtag;
	key.dtag = req->stag;

	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	if (tpid_reuse == NULL &&
	    ubcore_get_enable_shared_ctp() &&
	    key.lk.tp_type == UBCORE_CTP &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    !ubcore_net_addr_is_zero(&isref_local_cna) &&
	    !ubcore_net_addr_is_zero(&isref_peer_cna)) {
		ubcore_fill_tpid_reuse_key_cna(&key, isref_local_cna, isref_peer_cna);
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (isref_req): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	}
	if (tpid_reuse == NULL) {
		ubcore_log_err("tpid not found in tpid_reuse table.\n");
		return;
	}

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->is_ref = true;
	mutex_unlock(&tpid_reuse->lock);

	ubcore_tpid_reuse_kref_put(tpid_reuse);
}

/* Only for impoprt_jetty/jfr, thus only for RM/UM */
static int ubcore_fill_get_tp_cfg(struct ubcore_device *dev,
				  struct ubcore_get_tp_cfg *get_tp_cfg,
				  struct ubcore_tjetty_cfg *cfg)
{
	uint32_t eid_index = cfg->eid_index;

	if (cfg->tp_type == UBCORE_CTP)
		get_tp_cfg->flag.bs.ctp = 1;
	else if (cfg->tp_type == UBCORE_RTP)
		get_tp_cfg->flag.bs.rtp = 1;
	else
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
	get_tp_cfg->local_eid = dev->eid_table.eid_entries[eid_index].eid;
	spin_unlock(&dev->eid_table.lock);
	get_tp_cfg->peer_eid = cfg->id.eid;

	get_tp_cfg->stp_cfg = cfg->stp_cfg;

	return 0;
}

struct ubcore_tjetty *ubcore_import_jfr_compat(struct ubcore_device *dev,
					       struct ubcore_tjetty_cfg *cfg,
					       struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct ubcore_get_tp_cfg get_tp_cfg = { 0 };
	struct ubcore_tpid_cfg tpid_cfg = { 0 };
	struct ubcore_tpid_reuse_key key = { 0 };
	struct ubcore_tjetty *tjfr = NULL;
	struct ubcore_tpid_reuse *tpid_reuse = NULL;
	struct ubcore_tpid_reuse *exist_tpid_reuse = NULL;
	union ubcore_tp_handle tp_handle = { 0 };
	int ret;

	if (cfg->trans_mode != UBCORE_TP_RM &&
	    cfg->trans_mode != UBCORE_TP_UM) {
		ubcore_log_err("Invalid trans_mode %d.\n",
			       (int)cfg->trans_mode);
		return ERR_PTR(-EINVAL);
	}

	if (ubcore_fill_get_tp_cfg(dev, &get_tp_cfg, cfg) != 0)
		return NULL;

	union ubcore_net_addr_union jfr_local_cna = {0};
	union ubcore_net_addr_union jfr_peer_cna = {0};

	ret = ubcore_fill_tpid_reuse_key(&key, &get_tp_cfg, cfg,
				 &jfr_local_cna, &jfr_peer_cna);
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid reuse key, ret=%d", ret);
		return NULL;
	}
	ubcore_log_info_rl("try to get tpid reuse.\n");
	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	if (tpid_reuse == NULL &&
	    ubcore_get_enable_shared_ctp() &&
	    key.lk.tp_type == UBCORE_CTP &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    !ubcore_net_addr_is_zero(&jfr_local_cna) &&
	    !ubcore_net_addr_is_zero(&jfr_peer_cna)) {
		ubcore_fill_tpid_reuse_key_cna(&key, jfr_local_cna, jfr_peer_cna);
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (import_jfr): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	}
	if (tpid_reuse != NULL) {
		ubcore_log_info_rl("tpid reuse get. reuse tpid.\n");
		tpid_reuse = ubcore_reuse_tpid(tpid_reuse);
		if (tpid_reuse == NULL)
			return ERR_PTR(-EIO);
		active_tp_cfg.tp_handle = tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;
		tjfr = ubcore_import_jfr_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjfr))
			/* Rollback use_cnt since import failed */
			ubcore_tpid_reuse_dec_usecnt(tpid_reuse);
		return tjfr;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		return ERR_PTR(-ENOMEM);
	}

	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		exist_tpid_reuse =
			ubcore_reuse_tpid(exist_tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		if (exist_tpid_reuse == NULL)
			return ERR_PTR(-EIO);
		active_tp_cfg.tp_handle = exist_tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = exist_tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = exist_tpid_reuse->tx_psn;
		tjfr = ubcore_import_jfr_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjfr))
			/* Rollback use_cnt since import failed */
			ubcore_tpid_reuse_dec_usecnt(exist_tpid_reuse);
		return tjfr;
	} else if (ret != 0) {
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		return NULL;
	}

	ret = ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid cfg, ret=%d", ret);
		goto err_out;
	}

	ret = ubcore_create_tpid_priv(dev, &tpid_cfg, udata, &tp_handle);
	if (ret != 0) {
		ubcore_log_err("Failed to create tpid for reuse, ret: %d.\n", ret);
		goto err_out;
	}

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->tp_handle = tp_handle;
	tpid_reuse->tp_handle_valid = true;
	mutex_unlock(&tpid_reuse->lock);

	active_tp_cfg.tp_handle = tp_handle;
	active_tp_cfg.tpid_reuse = tpid_reuse;
	active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;

	if (cfg->trans_mode == UBCORE_TP_RM &&
		cfg->tp_type == UBCORE_RTP) {
		ret = ubcore_exchange_tp_info(dev, &get_tp_cfg,
				      &active_tp_cfg, cfg, udata);
		if (ret != 0) {
			ubcore_log_err("Exchange_tp_info Failed: dev_name is %s,local_tp_handle is %llu",
				dev->dev_name, tp_handle.value);
			ubcore_log_err("  local eid " EID_FMT ", peer eid " EID_FMT,
				EID_ARGS(tpid_cfg.local_eid),
				EID_ARGS(tpid_cfg.peer_eid));
			goto err_out;
		}
	}

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->peer_tp_handle = active_tp_cfg.peer_tp_handle;
	mutex_unlock(&tpid_reuse->lock);

	tjfr = ubcore_import_jfr_ex(dev, cfg, &active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(tjfr)) {
		ubcore_log_err("Failed to import jfr ex.\n");
		goto err_out;
	}

	mutex_lock(&tpid_reuse->lock);
	atomic_inc(&tpid_reuse->use_cnt);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	mutex_unlock(&tpid_reuse->lock);

	ubcore_log_info_rl("import jfr compat, tjetty->vtpn: %u.\n", tjfr->vtpn->vtpn);

	return tjfr;

err_out:
	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	mutex_unlock(&tpid_reuse->lock);
	(void)ubcore_free_tpid_reuse(tpid_reuse);
	return NULL;
}

struct ubcore_tjetty *ubcore_import_jetty_compat(struct ubcore_device *dev,
						 struct ubcore_tjetty_cfg *cfg,
						 struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct ubcore_get_tp_cfg get_tp_cfg = { 0 };
	struct ubcore_tpid_cfg tpid_cfg = { 0 };
	struct ubcore_tpid_reuse_key key = { 0 };
	struct ubcore_tjetty *tjetty = NULL;
	struct ubcore_tpid_reuse *tpid_reuse = NULL;
	struct ubcore_tpid_reuse *exist_tpid_reuse = NULL;
	union ubcore_tp_handle tp_handle = { 0 };
	int ret;

	if (cfg->trans_mode != UBCORE_TP_RM &&
	    cfg->trans_mode != UBCORE_TP_UM) {
		return ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
	}

	if (ubcore_fill_get_tp_cfg(dev, &get_tp_cfg, cfg) != 0)
		return NULL;

	union ubcore_net_addr_union jetty_local_cna = {0};
	union ubcore_net_addr_union jetty_peer_cna = {0};

	ret = ubcore_fill_tpid_reuse_key(&key, &get_tp_cfg, cfg,
				 &jetty_local_cna, &jetty_peer_cna);
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid reuse key, ret=%d", ret);
		return NULL;
	}

	ubcore_log_info_rl("try to get tpid reuse.\n");
	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);

	/*
	 * EID-level reuse missed; try to CNA-level reuse if both
	 * local and peer CNA are non-zero. The CNA key (peer_eid=0,
	 * local_cna/peer_cna set) is filled here so that even if the
	 * subsequent ubcore_find_get_tpid_reuse misses, the following
	 * ubcore_create_tpid_reuse will naturally create a CNA-level entry.
	 */
	if (tpid_reuse == NULL &&
	    ubcore_get_enable_shared_ctp() &&
	    key.lk.tp_type == UBCORE_CTP &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    !ubcore_net_addr_is_zero(&jetty_local_cna) &&
	    !ubcore_net_addr_is_zero(&jetty_peer_cna)) {
		ubcore_fill_tpid_reuse_key_cna(&key, jetty_local_cna, jetty_peer_cna);
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (import_jetty): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	}
	if (tpid_reuse != NULL) {
		ubcore_log_info_rl("tpid reuse get. reuse tpid.\n");
		tpid_reuse = ubcore_reuse_tpid(tpid_reuse);
		if (tpid_reuse == NULL)
			return ERR_PTR(-EIO);
		active_tp_cfg.tp_handle = tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;
		tjetty = ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjetty))
			/* Rollback use_cnt since import failed */
			ubcore_tpid_reuse_dec_usecnt(tpid_reuse);
		return tjetty;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		return ERR_PTR(-ENOMEM);
	}

	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		exist_tpid_reuse =
			ubcore_reuse_tpid(exist_tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		if (exist_tpid_reuse == NULL)
			return ERR_PTR(-EIO);
		active_tp_cfg.tp_handle = exist_tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = exist_tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = exist_tpid_reuse->tx_psn;
		tjetty = ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjetty))
			/* Rollback use_cnt since import failed */
			ubcore_tpid_reuse_dec_usecnt(exist_tpid_reuse);
		return tjetty;
	} else if (ret != 0) {
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		return NULL;
	}

	ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg);
	ret = ubcore_create_tpid_priv(dev, &tpid_cfg, udata, &tp_handle);
	if (ret != 0) {
		ubcore_log_err("Failed to create tpid for reuse, ret: %d.\n", ret);
		goto err_out;
	}

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->tp_handle = tp_handle;
	tpid_reuse->tp_handle_valid = true;
	mutex_unlock(&tpid_reuse->lock);

	active_tp_cfg.tp_handle = tp_handle;
	active_tp_cfg.tpid_reuse = tpid_reuse;
	active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;

	if (cfg->trans_mode == UBCORE_TP_RM &&
		cfg->tp_type == UBCORE_RTP) {
		ret = ubcore_exchange_tp_info(dev, &get_tp_cfg,
						&active_tp_cfg, cfg, udata);
		if (ret != 0) {
			ubcore_log_err("Exchange_tp_info Failed: dev_name is %s, local_tp_handle is %llu",
				dev->dev_name, tp_handle.value);
			ubcore_log_err("localeid " EID_FMT ", peereid " EID_FMT,
				EID_ARGS(tpid_cfg.local_eid),
				EID_ARGS(tpid_cfg.peer_eid));
			goto err_out;
		}
	}

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->peer_tp_handle = active_tp_cfg.peer_tp_handle;
	mutex_unlock(&tpid_reuse->lock);

	tjetty = ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		ubcore_log_err("Failed to import jetty ex.\n");
		goto err_out;
	}

	mutex_lock(&tpid_reuse->lock);
	atomic_inc(&tpid_reuse->use_cnt);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	mutex_unlock(&tpid_reuse->lock);

	ubcore_log_info_rl("import jetty compat, tjetty->vtpn: %u.\n", tjetty->vtpn->vtpn);

	return tjetty;

err_out:
	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	mutex_unlock(&tpid_reuse->lock);
	(void)ubcore_free_tpid_reuse(tpid_reuse);
	return NULL;
}

void ubcore_fadd_init_tpid_ctx(struct ubcore_device *dev,
	struct ubcore_tpid_key *key, struct ubcore_active_tp_cfg *cfg,
	struct ubcore_vtpn *vtpn)
{
	struct ubcore_tpid_ctx *add_ctx = NULL;
	struct ubcore_tpid_ctx *ctx = NULL;
	struct ubcore_hash_table *ht;
	uint32_t hash;

	hash = ubcore_get_tpid_hash(key);
	ht = &dev->ht[UBCORE_HT_RC_TP_ID];

	add_ctx = kzalloc(sizeof(struct ubcore_tpid_ctx), GFP_KERNEL);
	if (IS_ERR_OR_NULL(add_ctx))
		return;

	spin_lock(&ht->lock);
	ctx = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (ctx && ctx->is_init) {
		spin_unlock(&ht->lock);
		ubcore_log_warn("Find tpid in initiator, hash: %u.\n", hash);
		kfree(add_ctx);
		return;
	}
	if (ctx && !ctx->is_init) {
		ubcore_log_info("Find tpid in target, hash: %u.\n", hash);
		spin_unlock(&ht->lock);
		(void)ubcore_deactive_tp(dev, cfg->tp_handle, NULL);
		kfree(add_ctx);
		return;
	}

	fill_tpid_ctx(add_ctx, key, cfg, true);
	ubcore_log_info("add_ctx has tp_handle:%llu, peer_tp_handle:%llu.\n",
		add_ctx->tp_handle, add_ctx->peer_tp_handle);
	add_ctx->tp_state = UBCORE_TP_ENABLE;
	ubcore_hash_table_add_nolock(ht, &add_ctx->hnode, hash);
	spin_unlock(&ht->lock);
}


int ubcore_reuse_init_rtp_tpid(struct ubcore_jetty *jetty,
	struct ubcore_tjetty *tjetty, struct ubcore_tpid_ctx *ctx,
	struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	int ret;

	if (ctx->is_init) {
		ubcore_log_err("Invalid operation, tp_handle: %llu.\n",
			ctx->tp_handle);
		ubcore_tpid_put(ctx);
		return -EINVAL;
	}

	/* Reuse */
	active_tp_cfg.tp_handle.value = ctx->tp_handle;
	active_tp_cfg.peer_tp_handle.value = ctx->peer_tp_handle;
	active_tp_cfg.tp_attr.tx_psn = ctx->tx_psn;
	active_tp_cfg.tp_attr.rx_psn = ctx->rx_psn;
	active_tp_cfg.tag = 0;
	ubcore_log_info("tp_handle is %llu, peer_tp_handle is %llu.",
		ctx->tp_handle, ctx->peer_tp_handle);

	ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
	if (ret != 0) {
		ubcore_log_err("Failed to bind jetty in target, ret: %d.\n", ret);
		ubcore_tpid_put(ctx);
	}
	ubcore_tpid_get(ctx);
	return ret;
}

int ubcore_bind_jetty_reuse_compat(struct ubcore_jetty *jetty,
	struct ubcore_tjetty *tjetty, struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = {0};
	struct ubcore_get_tp_cfg get_tp_cfg = {0};
	struct ubcore_tpid_cfg tpid_cfg = { 0 };
	struct ubcore_device *dev = jetty->ub_dev;
	struct ubcore_tpid_reuse *tpid_reuse = NULL;
	struct ubcore_tpid_reuse *exist_tpid_reuse = NULL;
	struct ubcore_tpid_reuse_key key = { 0 };
	union ubcore_tp_handle tp_handle = {0};
	int ret;

	ret = ubcore_fill_get_tp_cfg(dev, &get_tp_cfg, &tjetty->cfg);
	if (ret != 0)
		return ret;

	union ubcore_net_addr_union bind_local_cna = {0};
	union ubcore_net_addr_union bind_peer_cna = {0};

	ret = ubcore_fill_bind_tpid_reuse_key(&key, &get_tp_cfg, &tjetty->cfg, jetty,
				      &bind_local_cna, &bind_peer_cna);
	if (ret != 0) {
		ubcore_log_err("Failed to fill bind tpid reuse key, ret=%d\n", ret);
		return ret;
	}
	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	if (tpid_reuse == NULL &&
	    ubcore_get_enable_shared_ctp() &&
	    key.lk.tp_type == UBCORE_CTP &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    !ubcore_net_addr_is_zero(&bind_local_cna) &&
	    !ubcore_net_addr_is_zero(&bind_peer_cna)) {
		ubcore_fill_tpid_reuse_key_cna(&key, bind_local_cna, bind_peer_cna);
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (bind_jetty): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	}
	if (tpid_reuse != NULL) {
		tpid_reuse = ubcore_reuse_tpid(tpid_reuse);
		if (tpid_reuse == NULL)
			return -EIO;
		active_tp_cfg.tp_handle = tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;
		ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
		if (ret != 0) {
			ubcore_log_err("Failed to bind jetty ex, ret: %d.\n", ret);
			return ret;
		}
		atomic_dec(&tjetty->use_cnt);
		return ret;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		return -ENOMEM;
	}

	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		exist_tpid_reuse =
			ubcore_reuse_tpid(exist_tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		if (exist_tpid_reuse == NULL)
			return -EIO;
		active_tp_cfg.tp_handle = exist_tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = exist_tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = exist_tpid_reuse->tx_psn;
		ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
		if (ret != 0) {
			ubcore_log_err("Failed to bind jetty ex, ret: %d.\n", ret);
			/* Rollback use_cnt since bind failed */
			ubcore_tpid_reuse_dec_usecnt(exist_tpid_reuse);
			return ret;
		}
		atomic_dec(&tjetty->use_cnt);
		return ret;
	} else if (ret != 0) {
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		return ret;
	}

	ret = ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid cfg, ret=%d\n", ret);
		goto err_out;
	}

	ret = ubcore_create_tpid_priv(dev, &tpid_cfg, udata, &tp_handle);
	if (ret != 0) {
		ubcore_log_err("Failed to create tpid for reuse, ret: %d.\n", ret);
		goto err_out;
	}

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->tp_handle = tp_handle;
	tpid_reuse->tp_handle_valid = true;
	mutex_unlock(&tpid_reuse->lock);

	active_tp_cfg.tp_handle = tp_handle;
	active_tp_cfg.tpid_reuse = tpid_reuse;
	active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;

	if (tjetty->cfg.tp_type == UBCORE_RTP) {
		tjetty->cfg.stp_cfg.stag = jetty->jetty_id.id;
		tjetty->cfg.stp_cfg.dtag = tjetty->cfg.id.id;
		ret = ubcore_exchange_tp_info(dev, &get_tp_cfg,
			&active_tp_cfg, &tjetty->cfg, udata);
		if (ret != 0) {
			ubcore_log_err("Failed to exchange tp info, ret: %d.\n", ret);
			goto err_out;
		}
		ubcore_log_info("Finish to exchange tp info.\n");
	}

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->peer_tp_handle = active_tp_cfg.peer_tp_handle;
	mutex_unlock(&tpid_reuse->lock);

	ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
	if (ret != 0) {
		ubcore_log_err("Failed to bind jetty ex, ret: %d.\n", ret);
		goto err_out;
	}
	atomic_dec(&tjetty->use_cnt);

	mutex_lock(&tpid_reuse->lock);
	atomic_inc(&tpid_reuse->use_cnt);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	mutex_unlock(&tpid_reuse->lock);

	return ret;

err_out:
	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	mutex_unlock(&tpid_reuse->lock);
	(void)ubcore_free_tpid_reuse(tpid_reuse);
	return ret;
}

void ubcore_exchange_init(void)
{
	ubcore_net_register_msg_handler(UBCORE_NET_CREATE_REQ,
					handle_create_req_with_tpid_reuse,
					sizeof(struct msg_create_conn_req));
	ubcore_net_register_msg_handler(UBCORE_NET_CREATE_RESP,
					handle_create_resp,
					sizeof(struct msg_create_conn_resp));
	ubcore_net_register_msg_handler(UBCORE_NET_DESTROY_REQ,
					handle_destroy_req_with_tpid_reuse,
					sizeof(struct msg_destroy_conn_req));
	ubcore_net_register_msg_handler(UBCORE_NET_ISREF_REQ,
					handle_isref_req,
					sizeof(struct msg_isref_conn_req));
}
