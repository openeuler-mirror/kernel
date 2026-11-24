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
#include <linux/module.h>
#include <linux/random.h>
#include <linux/string.h>
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
	ESTABLISHED_TP_CHANNEL,
	CREATE_CONN_RETRY,
	CREATE_CONN_REBUILD
};

/* The CM message structs are defined here because session_data_create_conn
 * embeds msg_create_conn_req by value and thus needs a complete type. They only
 * depend on external headers and do not nest.
 * ISREF is a request/response pair: struct msg_isref_conn_req from the source,
 * struct msg_isref_resp from the peer (always sent, result 0 or -EAGAIN).
 */
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
	/* Non-shared (NONE) path: per-connection token so identical-looking
	 * connections do not merge. Zero when sharing is enabled.
	 */
	uint32_t conn_id;
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
	uint32_t conn_id;
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
	uint32_t conn_id;
};

/* ISREF response: the peer always replies, with result 0 on success and
 * -EAGAIN when the entry is missing/mismatched/retired. The echoed req fields
 * let the source rebuild its key if it needs to rebuild the TP pair.
 */
struct msg_isref_resp {
	int result;
	/* echoed req fields (diagnostics); the source correlates by session_id. */
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint64_t stag;
	uint64_t dtag;
	enum ubcore_transport_mode trans_mode;
	uint32_t tp_type;
	uint32_t link_type;
	enum ubcore_tpid_share_mode share_mode;
	uint32_t conn_id;
};

struct session_data_create_conn {
	uint64_t peer_tp_handle;
	uint32_t rx_psn;
	int ret;

	/* Retransmit context: on CREATE_CONN_RETRY, handle_create_resp resends the
	 * original req from this data without waking the user process.
	 */
	struct ubcore_device *dev;
	struct msg_create_conn_req req;
	uint32_t retry_cnt;
};

#define UBCORE_ENABLE_SHARED_CTP_DEFAULT false

/* Max CREATE_RESP RETRY resends handled by handle_create_resp. The rebuild
 * retry budget for a failed ISREF is the outer UBCORE_CONN_RETRY_MAX (3).
 */
#define UBCORE_TPID_REUSE_RETRY_LIMIT 3

/* Default as 30s */
uint32_t ubcore_conn_timeout = UBCORE_CONN_MAX_TIMEOUT;

uint32_t ubcore_get_conn_timeout(void)
{
	return ubcore_conn_timeout;
}

/* Retained for sysfs/API compatibility. RM CNA sharing is controlled by
 * ubcore_share_mode and no longer depends on this legacy switch.
 */
bool ubcore_enable_shared_ctp = UBCORE_ENABLE_SHARED_CTP_DEFAULT;

bool ubcore_get_enable_shared_ctp(void)
{
	return ubcore_enable_shared_ctp;
}

/* TP reuse sharing granularity. This only selects the granularity; whether
 * sharing happens at all is decided by the userspace share_tp flag.
 * 0=NONE, 1=CONTAINER (RTP EID pair), 2=NODE (RTP by physical CNA pair),
 * 3=JETTY. A non-NONE value triggers the physical EID translation for RM.
 */
uint32_t ubcore_share_mode;

/* Adapter patch version, exposed via
 * /sys/module/ubcore/parameters/ubcore_adapter_ver so a ko build can be
 * identified at runtime.
 */
#define UBCORE_ADAPTER_VER "v20"
static char *ubcore_adapter_ver = UBCORE_ADAPTER_VER;
module_param(ubcore_adapter_ver, charp, 0444);
MODULE_PARM_DESC(ubcore_adapter_ver, "connect adapter patch version");

/* TP reuse diagnostics go through g_ubcore_log_level (no dedicated switch). */

/* Count-change trace; the tag marks the change point. */
void ubcore_tp_trace_cnt(const struct ubcore_tpid_reuse *entry, const char *tag)
{
	if (entry == NULL) {
		ubcore_log_debug("tp-trace|%s| entry=NULL\n", tag);
		return;
	}
	ubcore_log_debug("tp-trace|%s| tpid=%u use_cnt=%d ref_cnt=%d is_ref=%d state=%u\n",
		tag, entry->tp_handle.bs.tpid, atomic_read(&entry->use_cnt),
		kref_read(&entry->ref_cnt), entry->is_ref ? 1 : 0,
		(unsigned int)entry->reuse_state);
}

/* Dump the full reuse key so both ends can be compared field by field. */
void ubcore_tp_trace_key(const struct ubcore_tpid_reuse_key *key, const char *site)
{
	ubcore_log_debug(
		"tp-key|%s| leid=0x%llx:0x%llx peid=0x%llx:0x%llx tm=%d sm=%d tt=%d lt=%d stag=0x%llx dtag=0x%llx cid=%u lcna=0x%llx/0x%llx pcna=0x%llx/0x%llx\n",
		site,
		(unsigned long long)key->lk.local_eid.in6.subnet_prefix,
		(unsigned long long)key->lk.local_eid.in6.interface_id,
		(unsigned long long)key->lk.peer_eid.in6.subnet_prefix,
		(unsigned long long)key->lk.peer_eid.in6.interface_id,
		(int)key->lk.trans_mode, (int)key->lk.share_mode,
		(int)key->lk.tp_type, (int)key->lk.link_type,
		(unsigned long long)key->stag, (unsigned long long)key->dtag,
		key->conn_id,
		(unsigned long long)key->lk.local_cna.in6.subnet_prefix,
		(unsigned long long)key->lk.local_cna.in6.interface_id,
		(unsigned long long)key->lk.peer_cna.in6.subnet_prefix,
		(unsigned long long)key->lk.peer_cna.in6.interface_id);
}

static void ubcore_tp_trace_reuse_lookup(const char *site, const char *scope,
					 const char *result)
{
	ubcore_log_debug("tp-trace|reuse-lookup|site=%s|scope=%s|result=%s\n",
			site, scope, result);
}

static void ubcore_tp_link_log(const char *tag, const struct ubcore_tpid_reuse *e)
{
	ubcore_log_info("tp-link|%s|leid=" EID_FMT "|peid=" EID_FMT
			"|lcna=" EID_FMT "|pcna=" EID_FMT "|mode=%u|tpid=%u\n",
			tag, EID_ARGS(e->local_eid), EID_ARGS(e->peer_eid),
			EID_RAW_ARGS(e->rk.lk.local_cna.raw),
			EID_RAW_ARGS(e->rk.lk.peer_cna.raw),
			e->rk.lk.share_mode, e->tp_handle.bs.tpid);
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

	/* Translation diagnostics: log the input virtual EIDs and both lookup
	 * return codes (a non-zero return means the trie has no such EID).
	 */
	ubcore_log_debug("eid-translate: in local=" EID_FMT " peer=" EID_FMT
		" local_ret=%d peer_ret=%d\n",
		EID_ARGS(*local_src_eid), EID_ARGS(*peer_src_eid),
		local_ret, peer_ret);

	if (local_ret == 0 && peer_ret == 0) {
		if (local_cna != NULL && peer_cna != NULL) {
			*local_cna = local_host_info.cna;
			*peer_cna = peer_host_info.cna;
		}
		/* A lookup hit can contain incomplete metadata. Keep the original
		 * EID pair, but retain any CNA for the existing fallback path.
		 */
		if (!memchr_inv(local_host_info.eid.raw, 0, sizeof(local_host_info.eid.raw)) ||
		    !memchr_inv(peer_host_info.eid.raw, 0, sizeof(peer_host_info.eid.raw))) {
			ubcore_log_debug("tp-trace|eid-translate|skip:zero_host_eid\n");
			return;
		}
		if (local_dst_eid != NULL)
			*local_dst_eid = local_host_info.eid;
		if (peer_dst_eid != NULL)
			*peer_dst_eid = peer_host_info.eid;
		ubcore_log_debug("local_host_eid=" EID_FMT " , peer_host_eid=" EID_FMT "\n",
			EID_ARGS(local_host_info.eid), EID_ARGS(peer_host_info.eid));
	}
	if (local_ret != 0)
		ubcore_log_debug("tp-trace|eid-xlate|local miss, ret=%d\n", local_ret);
	if (peer_ret != 0)
		ubcore_log_debug("tp-trace|eid-xlate|peer miss, ret=%d\n", peer_ret);
}

/* Per-connection token for the non-shared (NONE) path. Only the source
 * generates it; the peer echoes it from the create request through the
 * destroy/isref messages. Shared modes keep conn_id == 0.
 */
static atomic_t ubcore_reuse_conn_id_gen = ATOMIC_INIT(0);

static uint32_t ubcore_new_conn_id(void)
{
	uint32_t id = (uint32_t)atomic_inc_return(&ubcore_reuse_conn_id_gen);

	/* 0 is reserved to mean "sharing enabled / no token". */
	if (id == 0)
		id = (uint32_t)atomic_inc_return(&ubcore_reuse_conn_id_gen);
	return id;
}

static enum ubcore_tpid_share_mode ubcore_effective_share_mode(bool share_tp)
{
	if (!share_tp || ubcore_share_mode == UBCORE_TPID_SHARE_NONE)
		return UBCORE_TPID_SHARE_NONE;
	return (enum ubcore_tpid_share_mode)ubcore_share_mode;
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
	key->lk.trans_mode = cfg->trans_mode;
	key->lk.share_mode = ubcore_effective_share_mode(cfg->flag.bs.share_tp);
	key->conn_id = (key->lk.share_mode == UBCORE_TPID_SHARE_NONE) ?
		ubcore_new_conn_id() : 0;
	memset(&key->lk.local_cna, 0, sizeof(key->lk.local_cna));
	memset(&key->lk.peer_cna, 0, sizeof(key->lk.peer_cna));

	/* When sharing is enabled and the transport is RM, translate the endpoint
	 * EIDs through the host-info table: for CTP the translated (host) EIDs go
	 * into the key, for RTP only the CNA pair is captured. Without injected
	 * host info the key keeps the virtual EIDs.
	 */
	if (key->lk.share_mode != UBCORE_TPID_SHARE_NONE &&
	    (get_tp_cfg->flag.bs.ctp || get_tp_cfg->flag.bs.rtp) &&
	    cfg->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg->local_eid,
			get_tp_cfg->flag.bs.ctp ? &key->lk.local_eid : NULL,
			&get_tp_cfg->peer_eid,
			get_tp_cfg->flag.bs.ctp ? &key->lk.peer_eid : NULL,
			local_cna, peer_cna);
	}
	key->stag = cfg->stp_cfg.stag;
	key->dtag = cfg->stp_cfg.dtag;

	if (get_tp_cfg->flag.bs.rtp)
		key->lk.tp_type = UBCORE_RTP;
	if (get_tp_cfg->flag.bs.ctp)
		key->lk.tp_type = UBCORE_CTP;
	if (get_tp_cfg->flag.bs.utp)
		key->lk.tp_type = UBCORE_UTP;

	key->lk.link_type = (get_tp_cfg->flag.bs.uboe) ? UBCORE_LINK_UBOE : UBCORE_LINK_ETHERNET;
	ubcore_tp_trace_key(key, "src-fill");
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
	key->lk.trans_mode = cfg->trans_mode;
	key->lk.share_mode = ubcore_effective_share_mode(cfg->flag.bs.share_tp);
	key->conn_id = (key->lk.share_mode == UBCORE_TPID_SHARE_NONE) ?
		ubcore_new_conn_id() : 0;
	memset(&key->lk.local_cna, 0, sizeof(key->lk.local_cna));
	memset(&key->lk.peer_cna, 0, sizeof(key->lk.peer_cna));

	/* Same host-info translation as ubcore_fill_tpid_reuse_key (RM only). */
	if (key->lk.share_mode != UBCORE_TPID_SHARE_NONE &&
	    (get_tp_cfg->flag.bs.ctp || get_tp_cfg->flag.bs.rtp) &&
	    cfg->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg->local_eid,
			get_tp_cfg->flag.bs.ctp ? &key->lk.local_eid : NULL,
			&get_tp_cfg->peer_eid,
			get_tp_cfg->flag.bs.ctp ? &key->lk.peer_eid : NULL,
			local_cna, peer_cna);
	}
	key->stag = sjetty->jetty_id.id;
	key->dtag = cfg->id.id;

	if (get_tp_cfg->flag.bs.rtp)
		key->lk.tp_type = UBCORE_RTP;
	if (get_tp_cfg->flag.bs.ctp)
		key->lk.tp_type = UBCORE_CTP;
	if (get_tp_cfg->flag.bs.utp)
		key->lk.tp_type = UBCORE_UTP;

	key->lk.link_type = (get_tp_cfg->flag.bs.uboe) ? UBCORE_LINK_UBOE : UBCORE_LINK_ETHERNET;
	return 0;
}

static int ubcore_fill_tpid_cfg(struct ubcore_tpid_cfg *tpid_cfg,
	struct ubcore_get_tp_cfg *get_tp_cfg, enum ubcore_tpid_share_mode share_mode)
{
	if (tpid_cfg == NULL || get_tp_cfg == NULL)
		return -EINVAL;

	tpid_cfg->local_eid = get_tp_cfg->local_eid;
	tpid_cfg->peer_eid = get_tp_cfg->peer_eid;

	/* Shared RM provider lists use the physical host EID pair for both CTP and
	 * RTP. RTP control messages still use the original endpoint EIDs because
	 * those messages route to the peer endpoint, not the provider list.
	 * Gated by the effective share mode (share_tp), not the raw kernel param:
	 * a non-shared (NONE) connection keeps its endpoint EIDs end to end.
	 */
	if (share_mode != UBCORE_TPID_SHARE_NONE &&
	    (get_tp_cfg->flag.bs.ctp || get_tp_cfg->flag.bs.rtp) &&
	    get_tp_cfg->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg->local_eid,
			&tpid_cfg->local_eid, &get_tp_cfg->peer_eid,
			&tpid_cfg->peer_eid, NULL, NULL);
	}
	ubcore_log_debug("tp-provider-cfg: tm=%d ctp=%u rtp=%u local=" EID_FMT
		" peer=" EID_FMT " -> local=" EID_FMT " peer=" EID_FMT "\n",
		(int)get_tp_cfg->trans_mode, get_tp_cfg->flag.bs.ctp,
		get_tp_cfg->flag.bs.rtp, EID_ARGS(get_tp_cfg->local_eid),
		EID_ARGS(get_tp_cfg->peer_eid), EID_ARGS(tpid_cfg->local_eid),
		EID_ARGS(tpid_cfg->peer_eid));
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

/* Build a CNA-level reuse key from the CNA pair supplied by the caller (host
 * info). No EID-to-IP lookup is performed: if either CNA is unknown the CNA
 * key is unusable and the caller keeps its original EID path.
 */
bool ubcore_fill_tpid_reuse_key_cna(struct ubcore_tpid_reuse_key *key,
	union ubcore_net_addr_union local_cna, union ubcore_net_addr_union peer_cna,
	struct ubcore_device *dev, const char *site)
{
	if (ubcore_net_addr_is_zero(&local_cna) ||
	    ubcore_net_addr_is_zero(&peer_cna)) {
		ubcore_log_debug("tp-trace|cna-resolve|%s|%s|miss|lc=" EID_FMT "|pc=" EID_FMT "\n",
			site, dev ? dev->dev_name : "null",
			EID_RAW_ARGS(local_cna.raw), EID_RAW_ARGS(peer_cna.raw));
		return false;
	}
	ubcore_log_debug("tp-trace|cna-resolve|%s|%s|ok|lc=" EID_FMT "|pc=" EID_FMT "\n",
		site, dev ? dev->dev_name : "null",
		EID_RAW_ARGS(local_cna.raw), EID_RAW_ARGS(peer_cna.raw));

	/* A CNA-level key carries no endpoint EIDs: matching/hash are by the
	 * physical CNA pair (plus stag/dtag/...), so two connections on the same
	 * CNA always build the identical key -- no per-EID divergence and thus no
	 * create-time race. The endpoint EIDs still needed to route the RTP
	 * isref/destroy control messages are kept on the entry itself
	 * (struct ubcore_tpid_reuse::local_eid/peer_eid), not in this key.
	 */
	memset(&key->lk.local_eid, 0, sizeof(key->lk.local_eid));
	memset(&key->lk.peer_eid, 0, sizeof(key->lk.peer_eid));
	key->lk.local_cna = local_cna;
	key->lk.peer_cna = peer_cna;
	return true;
}

static void ubcore_tpid_reuse_kref_release(struct kref *ref_cnt)
{
	struct ubcore_tpid_reuse *entry =
		container_of(ref_cnt, struct ubcore_tpid_reuse, ref_cnt);

	/* Last reference released: deactivate and delete the TP, then free the
	 * entry. The entry is always removed from the reuse hash before its base
	 * reference is dropped, so no lookup can race with this teardown.
	 */
	if (entry->tp_handle_valid) {
		struct ubcore_deactive_tp_cfg deactive_cfg = {0};
		union ubcore_modify_tpid_cfg cfg = { .deactive_cfg = &deactive_cfg };

		deactive_cfg.tp_handle.value = entry->tp_handle.value;
		(void)ubcore_modify_tpid(entry->ub_dev, UBCORE_TPID_STATE_ERR, &cfg);
		(void)ubcore_delete_tpid_priv(entry->ub_dev,
					      entry->tp_handle.bs.tpid);
		entry->tp_handle_valid = false;
	}
	mutex_destroy(&entry->lock);
	kfree(entry);
}

void ubcore_tpid_reuse_kref_put(struct ubcore_tpid_reuse *entry)
{
	if (entry == NULL)
		return;

	ubcore_log_debug("tp-trace|ref-put|%pS| tpid=%u ref_cnt=%d use_cnt=%d is_ref=%d state=%u\n",
			(void *)_RET_IP_, entry->tp_handle.bs.tpid,
			kref_read(&entry->ref_cnt), atomic_read(&entry->use_cnt),
			entry->is_ref ? 1 : 0, (unsigned int)entry->reuse_state);

	(void)kref_put(&entry->ref_cnt,
		       ubcore_tpid_reuse_kref_release);
}

void ubcore_tpid_reuse_get(void *obj)
{
	struct ubcore_tpid_reuse *entry = obj;

	kref_get(&entry->ref_cnt);
	ubcore_log_debug("tp-trace|ref-get|%pS| tpid=%u ref_cnt=%d use_cnt=%d is_ref=%d state=%u\n",
			(void *)_RET_IP_, entry->tp_handle.bs.tpid,
			kref_read(&entry->ref_cnt), atomic_read(&entry->use_cnt),
			entry->is_ref ? 1 : 0, (unsigned int)entry->reuse_state);
}

static struct ubcore_tpid_reuse *
ubcore_create_tpid_reuse(struct ubcore_device *dev,
			       struct ubcore_tpid_reuse_key *key,
			       const union ubcore_eid *local_eid,
			       const union ubcore_eid *peer_eid)
{
	struct ubcore_tpid_reuse *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return NULL;

	entry->ub_dev = dev;
	atomic_set(&entry->use_cnt, 0);
	kref_init(&entry->ref_cnt);
	entry->rk = *key;
	/* CNA-shared keys carry no EIDs; keep the real endpoint EIDs for the
	 * isref/destroy control-plane routing.
	 */
	entry->local_eid = *local_eid;
	entry->peer_eid = *peer_eid;
	ubcore_tp_trace_key(&entry->rk, "reuse-create");
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

	if (dev == NULL || key == NULL)
		return NULL;

	/* CNA sharing is expressed directly in the key (a CNA-level key carries no
	 * EIDs), so a plain exact-key lookup is enough -- no CNA scan needed.
	 */
	ht = &dev->ht[UBCORE_HT_TPID_REUSE];
	return ubcore_hash_table_lookup_get(ht, ubcore_get_tpid_reuse_hash(ht, key), key);
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
	ubcore_tpid_reuse_get(new_tpid_reuse);
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

static const char *ubcore_conn_result_str(int result)
{
	switch (result) {
	case CREATE_CONN_SUCCESS:
		return "SUCCESS";
	case GET_TP_LIST_ERROR:
		return "GET_TP_LIST";
	case MODIFY_TPID_ERROR:
		return "MODIFY_TPID";
	case CREATE_CONN_FAIL:
		return "FAIL";
	case ESTABLISHED_TP_CHANNEL:
		return "ESTABLISHED";
	case CREATE_CONN_RETRY:
		return "RETRY";
	case CREATE_CONN_REBUILD:
		return "REBUILD";
	default:
		return "UNKNOWN";
	}
}

/* One grep-able line per negotiation message on both tx and rx. It carries the
 * key fields of every REQ/RESP so the two ends can be aligned by sid/tp.
 */
static void ubcore_neg_msg_log(const char *dir, const char *dev_name,
			       const struct ubcore_comm_msg *msg)
{
	const void *p = msg->data;

	if (p == NULL)
		return;

	switch (msg->type) {
	case UBCORE_NET_CREATE_REQ: {
		const struct msg_create_conn_req *r = p;

		ubcore_log_info("neg|%s|CREATE_REQ|dev=%s|sid=%u|tm=%d|share=%d|"
				"cid=%u|tp=0x%llx|psn=%u|leid=" EID_FMT
				"|peid=" EID_FMT "\n",
				dir, dev_name, msg->session_id,
				(int)r->get_tp_cfg.trans_mode,
				(int)ubcore_effective_share_mode(r->share_tp),
				r->conn_id, (unsigned long long)r->tp_handle,
				r->tx_psn, EID_ARGS(r->get_tp_cfg.local_eid),
				EID_ARGS(r->get_tp_cfg.peer_eid));
		break;
	}
	case UBCORE_NET_CREATE_RESP: {
		const struct msg_create_conn_resp *r = p;

		ubcore_log_info("neg|%s|CREATE_RESP|dev=%s|sid=%u|tp=0x%llx|"
				"psn=%u|result=%d(%s)\n",
				dir, dev_name, msg->session_id,
				(unsigned long long)r->tp_handle, r->tx_psn,
				r->result, ubcore_conn_result_str(r->result));
		break;
	}
	case UBCORE_NET_ISREF_REQ: {
		const struct msg_isref_conn_req *r = p;

		ubcore_log_info("neg|%s|ISREF_REQ|dev=%s|tm=%d|share=%d|cid=%u|"
				"tp=0x%llx|ptp=0x%llx|leid=" EID_FMT
				"|peid=" EID_FMT "\n",
				dir, dev_name, (int)r->trans_mode,
				(int)r->share_mode, r->conn_id,
				(unsigned long long)r->tp_handle.value,
				(unsigned long long)r->peer_tp_handle.value,
				EID_ARGS(r->local_eid), EID_ARGS(r->peer_eid));
		break;
	}
	case UBCORE_NET_ISREF_RESP: {
		const struct msg_isref_resp *r = p;

		ubcore_log_info("neg|%s|ISREF_RESP|dev=%s|result=%d|tm=%d|"
				"share=%d|cid=%u|leid=" EID_FMT "|peid=" EID_FMT
				"\n",
				dir, dev_name, r->result, (int)r->trans_mode,
				(int)r->share_mode, r->conn_id,
				EID_ARGS(r->local_eid), EID_ARGS(r->peer_eid));
		break;
	}
	case UBCORE_NET_DESTROY_REQ: {
		const struct msg_destroy_conn_req *r = p;

		ubcore_log_info("neg|%s|DESTROY_REQ|dev=%s|tm=%d|share=%d|"
				"cid=%u|tp=0x%llx|ptp=0x%llx|leid=" EID_FMT
				"|peid=" EID_FMT "\n",
				dir, dev_name, (int)r->trans_mode,
				(int)r->share_mode, r->conn_id,
				(unsigned long long)r->tp_handle.value,
				(unsigned long long)r->peer_tp_handle.value,
				EID_ARGS(r->local_eid), EID_ARGS(r->peer_eid));
		break;
	}
	default:
		break;
	}
}

static struct ubcore_session *
create_session_for_create_connection(struct ubcore_device *dev);

/* Send an ISREF and wait for the peer's response. Success (0) means the peer
 * recorded is_ref; any other value (including timeout) means the caller must
 * rebuild the TP pair.
 */
static int send_is_ref_req(struct ubcore_tpid_reuse *tpid_reuse)
{
	struct session_data_create_conn *session_data;
	struct ubcore_session *session;
	struct ubcore_comm_msg msg = { 0 };
	struct msg_isref_conn_req req = { 0 };
	int ret;

	/* CTP does not establish a peer is_ref entry; a CNA key has zero EIDs. */
	if (tpid_reuse->rk.lk.tp_type == UBCORE_CTP)
		return 0;

	/* CNA-shared keys carry no EIDs; use the entry's routing EIDs. */
	req.local_eid = tpid_reuse->local_eid;
	req.peer_eid = tpid_reuse->peer_eid;
	req.trans_mode = tpid_reuse->rk.lk.trans_mode;
	req.stag = tpid_reuse->rk.stag;
	req.dtag = tpid_reuse->rk.dtag;

	req.tp_type = tpid_reuse->rk.lk.tp_type;
	req.link_type = tpid_reuse->rk.lk.link_type;
	req.share_mode = tpid_reuse->rk.lk.share_mode;
	req.conn_id = tpid_reuse->rk.conn_id;

	/* Carry the peer's local tp_handle so it can reject stale REQs. */
	req.tp_handle = tpid_reuse->peer_tp_handle;

	session = create_session_for_create_connection(tpid_reuse->ub_dev);
	if (session == NULL)
		return -ENOMEM;
	session_data = (struct session_data_create_conn *)
		ubcore_session_get_data(session);
	session_data->ret = -ETIMEDOUT;

	msg.type = UBCORE_NET_ISREF_REQ;
	msg.len = (uint16_t)sizeof(struct msg_isref_conn_req);
	msg.session_id = ubcore_session_get_id(session);
	msg.data = &req;

	ubcore_neg_msg_log("tx", tpid_reuse->ub_dev->dev_name, &msg);
	ret = ubcore_send_comm_msg_to(tpid_reuse->ub_dev, &msg,
				      tpid_reuse->peer_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send isref req, ret=%d", ret);
		ubcore_session_ref_release(session);
		return ret;
	}

	ubcore_session_wait(session);
	ret = session_data->ret;
	ubcore_session_ref_release(session);
	if (ret != 0)
		ubcore_log_err("isref not confirmed by peer, result: %d\n", ret);
	return ret;
}

/* Reply to an ISREF request; the resp echoes the req fields and carries the
 * requester's session_id so the source can wake its waiter.
 */
static int send_isref_resp(struct ubcore_device *dev, union ubcore_eid dst,
			   uint32_t session_id, struct msg_isref_resp *resp)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_ISREF_RESP;
	msg.len = (uint16_t)sizeof(struct msg_isref_resp);
	msg.session_id = session_id;
	msg.data = resp;

	ubcore_neg_msg_log("tx", dev->dev_name, &msg);
	/* Send toward the requester's EID; on loopback the send_to shortcut also
	 * works (the recv callback has conn == NULL there).
	 */
	ret = ubcore_send_comm_msg_to(dev, &msg, dst);
	if (ret != 0) {
		ubcore_log_err("Failed to send isref resp msg");
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

/* isref is fire-and-forget: on failure the peer replies UBCORE_NET_ISREF_RESP
 * and the source resends.
 */

static struct ubcore_tpid_reuse *ubcore_reuse_tpid(struct ubcore_tpid_reuse *tpid_reuse)
{
	bool drop_isref;
	int ret;
	int i;

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
		/* CTP has no peer control-plane exchange. CNA fallback entries
		 * intentionally carry zero EIDs, so an is_ref request would go to an
		 * invalid destination and make reuse wait until timeout.
		 */
		if (tpid_reuse->rk.lk.tp_type == UBCORE_CTP) {
			atomic_inc(&tpid_reuse->use_cnt);
			mutex_unlock(&tpid_reuse->lock);
			ubcore_log_info_rl("Success to reuse CTP tpid_reuse:%u",
					    tpid_reuse->tp_handle.bs.tpid);
			return tpid_reuse;
		}
		/* ISREF is a request/response sent only on the first local use
		 * (0 -> 1); the increment is under the lock so exactly one user
		 * performs the transition.
		 */
		if (atomic_inc_return(&tpid_reuse->use_cnt) > 1) {
			mutex_unlock(&tpid_reuse->lock);
			ubcore_log_info_rl("Reuse shared tpid_reuse:%u, use_cnt:%d",
					    tpid_reuse->tp_handle.bs.tpid,
					    atomic_read(&tpid_reuse->use_cnt));
			return tpid_reuse;
		}
		mutex_unlock(&tpid_reuse->lock);
		ret = send_is_ref_req(tpid_reuse);
		if (ret == 0) {
			ubcore_log_info_rl("Success to reuse tpid_reuse:%u",
					    tpid_reuse->tp_handle.bs.tpid);
			return tpid_reuse;
		}
		goto isref_fail;
	}

	for (i = 0; i < UBCORE_TPID_REUSE_MAX_WAIT_TIMES; i++) {
		if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
			if (tpid_reuse->rk.lk.tp_type == UBCORE_CTP) {
				atomic_inc(&tpid_reuse->use_cnt);
				mutex_unlock(&tpid_reuse->lock);
				ubcore_log_info_rl("Success to reuse CTP tpid_reuse:%u",
						    tpid_reuse->tp_handle.bs.tpid);
				return tpid_reuse;
			}
			if (atomic_inc_return(&tpid_reuse->use_cnt) > 1) {
				mutex_unlock(&tpid_reuse->lock);
				ubcore_log_info_rl("Reuse shared tpid_reuse:%u, use_cnt:%d",
						    tpid_reuse->tp_handle.bs.tpid,
						    atomic_read(&tpid_reuse->use_cnt));
				return tpid_reuse;
			}
			mutex_unlock(&tpid_reuse->lock);
			ret = send_is_ref_req(tpid_reuse);
			if (ret == 0) {
				ubcore_log_info_rl("Success to reuse tpid_reuse:%u",
						    tpid_reuse->tp_handle.bs.tpid);
				return tpid_reuse;
			}
			goto isref_fail;
		} else if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_RESET) {
			mutex_unlock(&tpid_reuse->lock);
			usleep_range(UBCORE_TPID_REUSE_WAIT_MIN_US,
				     UBCORE_TPID_REUSE_WAIT_MAX_US);
			mutex_lock(&tpid_reuse->lock);
		} else if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
			mutex_unlock(&tpid_reuse->lock);
			ubcore_log_err_rl(
				"tpid_reuse:%u state is ERROR, advise retry.\n",
				tpid_reuse->tp_handle.bs.tpid);
			ubcore_tpid_reuse_kref_put(tpid_reuse);
			return ERR_PTR(-EAGAIN);
		}
	}
	ubcore_log_err_rl("failed to reuse tpid_reuse:%u, use_cnt:%d, maybe wait timeout.\n",
			  tpid_reuse->tp_handle.bs.tpid, atomic_read(&tpid_reuse->use_cnt));
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tp_trace_cnt(tpid_reuse, "reuse-FAIL");
	mutex_lock(&tpid_reuse->lock);
	ubcore_tp_trace_key(&tpid_reuse->rk, "reuse-FAIL-key");
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	return ERR_PTR(-EAGAIN);

isref_fail:
	/* The peer did not confirm the reference (entry gone / tp mismatch /
	 * timeout). Detach this local entry; the outer compat retry will rebuild
	 * the TP pair through a fresh CREATE_REQ.
	 */
	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
		/* Already retired by a concurrent path; it owns the teardown. */
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);  /* lookup ref */
		return ERR_PTR(-EAGAIN);
	}
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	drop_isref = tpid_reuse->is_ref;
	if (drop_isref)
		tpid_reuse->is_ref = false;
	mutex_unlock(&tpid_reuse->lock);
	ubcore_hash_table_rmv_tpid_reuse(tpid_reuse->ub_dev, tpid_reuse);
	if (drop_isref)
		ubcore_tpid_reuse_kref_put(tpid_reuse);
	(void)ubcore_free_tpid_reuse(tpid_reuse);   /* base */
	ubcore_tpid_reuse_kref_put(tpid_reuse);     /* lookup ref */
	return ERR_PTR(-EAGAIN);
}

int ubcore_free_tpid_reuse(struct ubcore_tpid_reuse *tpid_reuse)
{
	if (tpid_reuse == NULL || tpid_reuse->ub_dev == NULL) {
		ubcore_log_err("Failed to release tpid reuse, invalid argument.\n");
		return -EINVAL;
	}

	/* Drop the base (table) reference. The entry and its TP are freed when
	 * the last user/isref reference is released; see kref_release.
	 */
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	return 0;
}

/* Clear the peer (isref) reference if set and report whether this caller must
 * drop the corresponding kref. Takes the entry lock.
 */
static bool ubcore_tpid_reuse_clear_isref(struct ubcore_tpid_reuse *e)
{
	bool drop;

	mutex_lock(&e->lock);
	drop = e->is_ref;
	if (drop)
		e->is_ref = false;
	mutex_unlock(&e->lock);
	return drop;
}

/* Lock-free second half of destroying a ready tpid_reuse: remove it from the
 * hash table, deactivate the hardware TP and free it. The caller must already
 * have set reuse_state/is_ref under the lock.
 */
static int ubcore_destroy_tpid_reuse(struct ubcore_device *dev,
				     struct ubcore_tpid_reuse *tpid_reuse)
{
	/* Detach from the reuse table and drop the base reference. The hardware
	 * TP is deactivated and its slot deleted when the last reference is
	 * released (see ubcore_tpid_reuse_kref_release), so users still holding
	 * the TP are not cut off.
	 */
	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
	(void)ubcore_free_tpid_reuse(tpid_reuse);
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

	ubcore_log_info("Active tp, local tp_hdl: %llu, peer tp_hdl: %llu, dev_name: %s.\n",
			active_cfg->tp_handle.value,
			active_cfg->peer_tp_handle.value,
			dev->dev_name);

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
		ubcore_log_warn_rl("[DRV_WARN]active_tp target consumes: %llu.\n",
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

static int send_create_req(struct ubcore_device *dev, uint32_t session_id,
			   struct msg_create_conn_req *req)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_CREATE_REQ;
	msg.len = (uint16_t)sizeof(struct msg_create_conn_req);
	msg.session_id = session_id;
	msg.data = req;

	ubcore_neg_msg_log("tx", dev->dev_name, &msg);
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

	ubcore_neg_msg_log("tx", dev->dev_name, &msg);
	ret = ubcore_send_comm_msg(dev, &msg, conn);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
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
	/* Sharing is decided by the userspace share_tp flag; ubcore_share_mode
	 * only selects the granularity.
	 */
	req.share_tp = (tjetty_cfg->flag.bs.share_tp == 1);
	req.stag = tjetty_cfg->stp_cfg.stag;
	req.dtag = tjetty_cfg->stp_cfg.dtag;
	req.conn_id = active_tp_cfg->tpid_reuse ?
		((struct ubcore_tpid_reuse *)active_tp_cfg->tpid_reuse)->rk.conn_id : 0;
	ubcore_log_debug("tp-trace|exch-create-req|tm=%d|ctp=%u|rtp=%u|stp=%u|cid=%u\n",
		(int)get_tp_cfg->trans_mode, get_tp_cfg->flag.bs.ctp,
		get_tp_cfg->flag.bs.rtp, req.share_tp, req.conn_id);

	/* Store the retransmit context in session_data so handle_create_resp can
	 * resend the original req on CREATE_CONN_RETRY without waking the user
	 * process.
	 */
	session_data = (struct session_data_create_conn *)ubcore_session_get_data(session);
	session_data->dev = dev;
	session_data->req = req;
	session_data->retry_cnt = 0;

	ret = send_create_req(dev, ubcore_session_get_id(session), &req);
	if (ret != 0) {
		ubcore_log_err("Failed to send create req, ret: %d\n", ret);
		ubcore_session_complete(session);
		ubcore_session_ref_release(session);
		return ret;
	}

	/* Wait once; the callback completes on success/real failure and resends
	 * internally on RETRY. The session's own timeout wakes the waiter.
	 */
	ubcore_session_wait(session);
	ret = session_data->ret;

	if (ret != CREATE_CONN_SUCCESS && ret != ESTABLISHED_TP_CHANNEL) {
		ubcore_log_err("Failed to create conn, result: %d\n", ret);
		ubcore_session_ref_release(session);
		return ret;
	}
	*peer_tp_handle = session_data->peer_tp_handle;
	*rx_psn = session_data->rx_psn;

	ubcore_session_ref_release(session);
	return 0;
}
EXPORT_SYMBOL(ubcore_exchange_tp_info);

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

/* Ensure a single local TP per tpid_reuse entry: return an existing one, become
 * the builder (tp_creating), or wait bounded for the current builder. The
 * active and responder paths may race here; tp_creating plus the entry lock
 * keep it to one TP and the loser drops its own TP.
 */
static int ubcore_tpid_reuse_ensure_tp(struct ubcore_device *dev,
	struct ubcore_tpid_reuse *tpid_reuse, struct ubcore_get_tp_cfg *get_tp_cfg,
	struct ubcore_udata *udata, union ubcore_tp_handle *tp_handle)
{
	struct ubcore_tpid_cfg tpid_cfg = { 0 };
	union ubcore_tp_handle new_handle = { 0 };
	bool gave_up = false;
	int ret, i;

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->tp_handle_valid) {
		*tp_handle = tpid_reuse->tp_handle;
		mutex_unlock(&tpid_reuse->lock);
		return 0;
	}
	if (!tpid_reuse->tp_creating) {
		tpid_reuse->tp_creating = true;
		mutex_unlock(&tpid_reuse->lock);
	} else {
		/* Another path is building; wait bounded for it. */
		mutex_unlock(&tpid_reuse->lock);
		gave_up = true;
		for (i = 0; i < UBCORE_TPID_REUSE_MAX_WAIT_TIMES; i++) {
			usleep_range(UBCORE_TPID_REUSE_WAIT_MIN_US,
				     UBCORE_TPID_REUSE_WAIT_MAX_US);
			mutex_lock(&tpid_reuse->lock);
			if (tpid_reuse->tp_handle_valid) {
				*tp_handle = tpid_reuse->tp_handle;
				mutex_unlock(&tpid_reuse->lock);
				return 0;
			}
			if (!tpid_reuse->tp_creating) {
				tpid_reuse->tp_creating = true;
				mutex_unlock(&tpid_reuse->lock);
				gave_up = false;
				break;
			}
			mutex_unlock(&tpid_reuse->lock);
		}
		if (gave_up) {
			ubcore_log_err("tpid_reuse ensure tp wait timeout\n");
			return -ETIMEDOUT;
		}
	}

	ret = ubcore_fill_tpid_cfg(&tpid_cfg, get_tp_cfg,
				   tpid_reuse->rk.lk.share_mode);
	if (ret == 0)
		ret = ubcore_create_tpid_priv(dev, &tpid_cfg, udata, &new_handle);

	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->tp_creating = false;
	if (ret != 0) {
		mutex_unlock(&tpid_reuse->lock);
		return ret;
	}
	if (tpid_reuse->tp_handle_valid) {
		/* Lost the race: drop the TP we just created and reuse the winner. */
		mutex_unlock(&tpid_reuse->lock);
		(void)ubcore_delete_tpid_priv(dev, new_handle.bs.tpid);
		mutex_lock(&tpid_reuse->lock);
		*tp_handle = tpid_reuse->tp_handle;
		mutex_unlock(&tpid_reuse->lock);
		return 0;
	}
	tpid_reuse->tp_handle = new_handle;
	tpid_reuse->tp_handle_valid = true;
	*tp_handle = new_handle;
	mutex_unlock(&tpid_reuse->lock);
	return 0;
}

static int target_reuse_tpid(struct ubcore_device *dev, struct ubcore_tpid_reuse *tpid_reuse,
								struct msg_create_conn_req *req)
{
	struct ubcore_active_tp_cfg active_cfg = {0};
	union ubcore_modify_tpid_cfg modify_tpid_cfg = {
		.active_cfg = &active_cfg
	};

	active_cfg.tp_handle.value = tpid_reuse->tp_handle.value;
	active_cfg.peer_tp_handle.value = req->tp_handle;
	active_cfg.tp_attr.rx_psn = req->tx_psn;
	active_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
		bool drop_isref;

		/* READY reuse sets is_ref and takes a kref. */
		if (!tpid_reuse->is_ref) {
			tpid_reuse->is_ref = true;
			ubcore_tpid_reuse_get(tpid_reuse);
			tpid_reuse->peer_tp_handle.value = req->tp_handle;
			ubcore_tp_trace_cnt(tpid_reuse, "peer-create-first(isref)");
			mutex_unlock(&tpid_reuse->lock);
			return ESTABLISHED_TP_CHANNEL;
		}

		/* is_ref already set. Reuse only when the local TP is still valid and
		 * the peer tpn matches the recorded pair (on loopback the peer tpn is
		 * our own tp_handle). Otherwise the peer rebuilt its TP or ours is
		 * gone: detach this entry from the reuse table and let the caller
		 * build a fresh one for the new pair. The old TP is released once its
		 * outstanding references are gone.
		 */
		if (tpid_reuse->tp_handle_valid &&
		    (req->tp_handle == tpid_reuse->peer_tp_handle.value ||
		     (ubcore_is_loopback(dev, &req->get_tp_cfg.peer_eid) &&
		      req->tp_handle == tpid_reuse->tp_handle.value))) {
			mutex_unlock(&tpid_reuse->lock);
			return ESTABLISHED_TP_CHANNEL;
		}

		drop_isref = tpid_reuse->is_ref;
		if (drop_isref)
			tpid_reuse->is_ref = false;
		tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
		mutex_unlock(&tpid_reuse->lock);

		/* Drop the isref reference (if any) and the base reference; the caller
		 * drops its lookup reference. Local users keep theirs and free the
		 * entry (and its TP) when the last one goes away.
		 */
		ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
		if (drop_isref)
			ubcore_tpid_reuse_kref_put(tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		return CREATE_CONN_REBUILD;
	}

	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_RESET) {
		struct ubcore_get_tp_cfg get_tp_cfg = req->get_tp_cfg;
		union ubcore_tp_handle tp_handle = { 0 };
		int cret;

		/* Entry is still being created/imported; an ISREF may already have
		 * set is_ref. Complete the link from the peer's req instead of
		 * returning CREATE_CONN_RETRY: a retry just re-enters the same
		 * window and never converges. This also covers two-sided
		 * simultaneous initiate.
		 */
		mutex_unlock(&tpid_reuse->lock);
		get_tp_cfg.local_eid = req->get_tp_cfg.peer_eid;
		get_tp_cfg.peer_eid = req->get_tp_cfg.local_eid;
		cret = ubcore_tpid_reuse_ensure_tp(dev, tpid_reuse, &get_tp_cfg,
						   NULL, &tp_handle);
		if (cret != 0) {
			mutex_lock(&tpid_reuse->lock);
			tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
			mutex_unlock(&tpid_reuse->lock);
			ubcore_log_err("peer-merge: ensure tp failed, ret=%d\n", cret);
			return GET_TP_LIST_ERROR;
		}

		mutex_lock(&tpid_reuse->lock);
		if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
			bool drop_isref = tpid_reuse->is_ref;

			/* The owner failed and removed the entry while we waited for
			 * ensure_tp. Do not resurrect an entry that is no longer in
			 * the hash; drop the peer reference if an ISREF took one.
			 */
			if (drop_isref)
				tpid_reuse->is_ref = false;
			mutex_unlock(&tpid_reuse->lock);
			if (drop_isref)
				ubcore_tpid_reuse_kref_put(tpid_reuse);
			ubcore_log_err_rl("peer-merge: entry removed while creating, retry\n");
			return CREATE_CONN_FAIL;
		}
		if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_READY) {
			if (!tpid_reuse->is_ref) {
				tpid_reuse->is_ref = true;
				ubcore_tpid_reuse_get(tpid_reuse);
			}
			mutex_unlock(&tpid_reuse->lock);
			ubcore_tp_trace_cnt(tpid_reuse, "peer-merge-READY");
			return ESTABLISHED_TP_CHANNEL;
		}
		active_cfg.tp_handle = tpid_reuse->tp_handle;
		active_cfg.peer_tp_handle.value = req->tp_handle;
		active_cfg.tp_attr.rx_psn = req->tx_psn;
		active_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;
		cret = ubcore_modify_tpid(dev, UBCORE_TPID_STATE_RTS, &modify_tpid_cfg);
		if (cret != 0) {
			tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
			mutex_unlock(&tpid_reuse->lock);
			ubcore_log_err("peer-merge: modify RTS failed, ret=%d\n", cret);
			return MODIFY_TPID_ERROR;
		}
		if (!tpid_reuse->is_ref) {
			tpid_reuse->is_ref = true;
			ubcore_tpid_reuse_get(tpid_reuse);
		}
		tpid_reuse->peer_tp_handle.value = req->tp_handle;
		tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
		ubcore_tp_trace_cnt(tpid_reuse, "peer-merge-RESET");
		mutex_unlock(&tpid_reuse->lock);
		return CREATE_CONN_SUCCESS;
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
	bool drop_isref;
	int ret;

	ubcore_neg_msg_log("rx", dev->dev_name, msg);
	get_tp_cfg.local_eid = req->get_tp_cfg.peer_eid;
	get_tp_cfg.peer_eid = req->get_tp_cfg.local_eid;
	key.lk.local_eid = get_tp_cfg.local_eid;
	key.lk.peer_eid = get_tp_cfg.peer_eid;
	union ubcore_net_addr_union local_cna = {0};
	union ubcore_net_addr_union peer_cna = {0};

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
	key.lk.share_mode = ubcore_effective_share_mode(req->share_tp);
	key.conn_id = req->conn_id;

	/* Same host-info translation as the source side so both ends build a
	 * symmetric key (RM only).
	 */
	if (key.lk.share_mode != UBCORE_TPID_SHARE_NONE &&
	    (get_tp_cfg.flag.bs.ctp || get_tp_cfg.flag.bs.rtp) &&
	    get_tp_cfg.trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&get_tp_cfg.local_eid,
			get_tp_cfg.flag.bs.ctp ? &key.lk.local_eid : NULL,
			&get_tp_cfg.peer_eid,
			get_tp_cfg.flag.bs.ctp ? &key.lk.peer_eid : NULL,
			&local_cna, &peer_cna);
	}

	ubcore_log_info_rl("Enter handle create req tpid reuse");

	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	ubcore_tp_trace_key(&key, "peer-create");
	if (tpid_reuse == NULL &&
	    key.lk.share_mode == UBCORE_TPID_SHARE_NODE &&
	    (key.lk.tp_type == UBCORE_CTP || key.lk.tp_type == UBCORE_RTP) &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    ubcore_fill_tpid_reuse_key_cna(&key, local_cna, peer_cna,
		dev, "create-req")) {
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("create-req", "cna",
			tpid_reuse == NULL ? "miss" : "hit");
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (create_req): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	} else {
		ubcore_tp_trace_reuse_lookup("create-req", "cna",
			tpid_reuse != NULL ? "skip:eid_hit" :
			key.lk.share_mode == UBCORE_TPID_SHARE_NONE ? "skip:share_mode_none" :
			key.lk.share_mode != UBCORE_TPID_SHARE_NODE ? "skip:share_mode_not_node" :
			key.lk.tp_type != UBCORE_CTP && key.lk.tp_type != UBCORE_RTP ?
				"skip:tp_type_not_reusable" :
			key.lk.trans_mode != UBCORE_TP_RM ? "skip:trans_mode_not_rm" :
			"skip:cna_unavailable");
	}
	if (tpid_reuse != NULL) {
		ret = target_reuse_tpid(dev, tpid_reuse, req);
		if (ret != CREATE_CONN_REBUILD) {
			resp.tp_handle = tpid_reuse->tp_handle.value;
			resp.tx_psn = tpid_reuse->tx_psn;
			if (ret == CREATE_CONN_SUCCESS ||
			    ret == ESTABLISHED_TP_CHANNEL)
				ubcore_tp_link_log("create-req", tpid_reuse);
			ubcore_tpid_reuse_kref_put(tpid_reuse);
			resp.result = ret;
			if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
				ubcore_log_err("Failed to send create resp message.\n");
			return;
		}
		/* Peer tpn changed: the old entry was detached; build a fresh one. */
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		tpid_reuse = NULL;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key,
					      &get_tp_cfg.local_eid, &get_tp_cfg.peer_eid);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		ret = GET_TP_LIST_ERROR;
		goto send_resp;
	}

	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		ret = target_reuse_tpid(dev, exist_tpid_reuse, req);
		if (ret == CREATE_CONN_REBUILD) {
			/* Existing entry detached for a new peer tpn; our fresh entry is
			 * not linked. Let the peer retry so the next request rebuilds it.
			 */
			ubcore_tpid_reuse_kref_put(exist_tpid_reuse);
			(void)ubcore_free_tpid_reuse(tpid_reuse);
			ret = CREATE_CONN_FAIL;
		} else {
			resp.tp_handle = exist_tpid_reuse->tp_handle.value;
			resp.tx_psn = exist_tpid_reuse->tx_psn;
			ubcore_tpid_reuse_kref_put(exist_tpid_reuse);
			(void)ubcore_free_tpid_reuse(tpid_reuse);
		}
		resp.result = ret;
		if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
			ubcore_log_err("Failed to send create resp message.\n");
		return;
	}

	ret = ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg,
				   ubcore_effective_share_mode(req->share_tp));
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid cfg, ret=%d", ret);
		ret = GET_TP_LIST_ERROR;
		drop_isref = ubcore_tpid_reuse_clear_isref(tpid_reuse);
		ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		if (drop_isref)
			ubcore_tpid_reuse_kref_put(tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		goto send_resp;
	}
	ubcore_log_debug("tp-trace|peer-create|tm=%d|ctp=%u|rtp=%u|stp=%u|cid=%u\n",
		(int)get_tp_cfg.trans_mode, get_tp_cfg.flag.bs.ctp,
		get_tp_cfg.flag.bs.rtp, req->share_tp, req->conn_id);

	ret = ubcore_tpid_reuse_ensure_tp(dev, tpid_reuse, &get_tp_cfg, NULL, &tp_handle);
	if (ret != 0) {
		ubcore_log_err("Failed to create tpid, ret=%d", ret);
		drop_isref = ubcore_tpid_reuse_clear_isref(tpid_reuse);
		ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		if (drop_isref)
			ubcore_tpid_reuse_kref_put(tpid_reuse);
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
	ret = ubcore_modify_tpid(dev, UBCORE_TPID_STATE_RTS, &modify_tpid_cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to modify tpid:%u to RTS, ret:%d.\n",
				(uint32_t)active_cfg.tp_handle.bs.tpid, ret);
		tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
		drop_isref = tpid_reuse->is_ref;
		if (drop_isref)
			tpid_reuse->is_ref = false;
		mutex_unlock(&tpid_reuse->lock);
		ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		if (drop_isref)
			ubcore_tpid_reuse_kref_put(tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		ret = MODIFY_TPID_ERROR;
		goto send_resp;
	}

	if (!tpid_reuse->is_ref) {
		tpid_reuse->is_ref = true;
		ubcore_tpid_reuse_get(tpid_reuse);
	}
	tpid_reuse->peer_tp_handle.value = req->tp_handle;
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tpid_reuse_kref_put(tpid_reuse);

	resp.tp_handle = tp_handle.value;
	resp.tx_psn = tx_psn;
	ret = CREATE_CONN_SUCCESS;
	ubcore_tp_link_log("create-req", tpid_reuse);

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
	int ret;

	ubcore_neg_msg_log("rx", dev->dev_name, msg);
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

	if (resp->result == CREATE_CONN_RETRY) {
		session_data->retry_cnt++;
		if (session_data->retry_cnt < UBCORE_TPID_REUSE_RETRY_LIMIT) {
			ubcore_log_info_rl("Create resp RETRY, resend req, retry: %u/%u\n",
					   session_data->retry_cnt, UBCORE_TPID_REUSE_RETRY_LIMIT);
			ret = send_create_req(session_data->dev, msg->session_id,
					      &session_data->req);
			if (ret != 0) {
				ubcore_log_err("Failed to resend create req, ret: %d\n", ret);
				session_data->ret = CREATE_CONN_FAIL;
				ubcore_session_complete(session);
			}
			ubcore_session_ref_release(session);
			return;
		}
		ubcore_log_err("Create resp RETRY limit reached, cnt: %u\n",
			       session_data->retry_cnt);
		session_data->ret = CREATE_CONN_FAIL;
		ubcore_session_complete(session);
		ubcore_session_ref_release(session);
		return;
	}
	ubcore_session_complete(session);
	ubcore_session_ref_release(session);
}

static int send_destroy_req(struct ubcore_tpid_reuse *tpid_reuse)
{
	struct ubcore_comm_msg msg = { 0 };
	struct msg_destroy_conn_req req = { 0 };
	int ret;

	/* CNA-shared keys carry no EIDs; use the entry's routing EIDs. */
	req.local_eid = tpid_reuse->local_eid;
	req.peer_eid = tpid_reuse->peer_eid;
	req.trans_mode = tpid_reuse->rk.lk.trans_mode;
	req.stag = tpid_reuse->rk.stag;
	req.dtag = tpid_reuse->rk.dtag;
	req.tp_type = tpid_reuse->rk.lk.tp_type;
	req.link_type = tpid_reuse->rk.lk.link_type;
	req.share_mode = tpid_reuse->rk.lk.share_mode;
	req.conn_id = tpid_reuse->rk.conn_id;

	msg.type = UBCORE_NET_DESTROY_REQ;
	msg.len = (uint16_t)sizeof(struct msg_destroy_conn_req);
	msg.session_id = 0;
	msg.data = &req;

	ubcore_neg_msg_log("tx", tpid_reuse->ub_dev->dev_name, &msg);
	ret = ubcore_send_comm_msg_to(tpid_reuse->ub_dev, &msg, tpid_reuse->peer_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}

	return 0;
}

int ubcore_disconnect_tpid_with_tpid_reuse(struct ubcore_tpid_reuse *tpid_reuse)
{
	struct ubcore_device *dev;
	bool drop_isref;
	int ret = 0;

	if (tpid_reuse == NULL || tpid_reuse->ub_dev == NULL)
		return -EINVAL;

	dev = tpid_reuse->ub_dev;

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
		mutex_unlock(&tpid_reuse->lock);
		/* Detached/retired entry: drop only this user's reference. Do not
		 * touch the entry afterwards; this may be the last reference.
		 */
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return 0;
	}

	if (atomic_dec_return(&tpid_reuse->use_cnt) > 0) {
		ubcore_tp_trace_cnt(tpid_reuse, "disconnect-dec(multi)");
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return 0;
	}

	ubcore_tp_trace_cnt(tpid_reuse, "disconnect-dec(last)");
	/* Hold a temporary reference across send/unlock/teardown: another path
	 * may already have dropped the base reference, so dropping the user
	 * reference below could be the last one.
	 */
	ubcore_tpid_reuse_get(tpid_reuse);

	if (tpid_reuse->tp_handle.bs.rtp &&
		!ubcore_is_loopback(tpid_reuse->ub_dev, &tpid_reuse->peer_eid)) {
		ret = send_destroy_req(tpid_reuse);
		if (ret != 0) {
			ubcore_log_err("Failed to send destroy req message");
			/* Retire under the lock so a concurrent lookup cannot revive
			 * the entry between unlock and removal.
			 */
			tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
			drop_isref = tpid_reuse->is_ref;
			if (drop_isref)
				tpid_reuse->is_ref = false;
			mutex_unlock(&tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(tpid_reuse);      /* user */
			if (drop_isref)
				ubcore_tpid_reuse_kref_put(tpid_reuse); /* isref */
			(void)ubcore_destroy_tpid_reuse(dev, tpid_reuse); /* base */
			ubcore_tpid_reuse_kref_put(tpid_reuse);      /* temp -> free */
			return 0;
		}
	}

	if (tpid_reuse->is_ref) {
		/* The peer still references our TP: keep the entry, drop only this
		 * user's reference and the temporary one.
		 */
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);  /* user */
		ubcore_tpid_reuse_kref_put(tpid_reuse);  /* temp */
		return 0;
	}

	/* Set reuse_state under the lock; the rest of the teardown runs in
	 * ubcore_destroy_tpid_reuse without it.
	 */
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tpid_reuse_kref_put(tpid_reuse);  /* user */
	(void)ubcore_destroy_tpid_reuse(dev, tpid_reuse);  /* base */
	ubcore_tpid_reuse_kref_put(tpid_reuse);  /* temp -> free */
	return 0;
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
			kfree(deactive_work);
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
	struct ubcore_tpid_reuse *tpid_reuse;

	ubcore_neg_msg_log("rx", dev->dev_name, msg);
	ubcore_log_info_rl("Enter handle req with tpid reuse.\n");

	key.lk.local_eid = req->peer_eid;
	key.lk.peer_eid = req->local_eid;
	union ubcore_net_addr_union destroy_local_cna = {0};
	union ubcore_net_addr_union destroy_peer_cna = {0};

	key.lk.trans_mode = req->trans_mode;
	key.lk.tp_type = req->tp_type;
	key.lk.link_type = req->link_type;
	key.lk.share_mode = req->share_mode;
	key.conn_id = req->conn_id;

	if (key.lk.share_mode != UBCORE_TPID_SHARE_NONE &&
	    (req->tp_type == UBCORE_CTP || req->tp_type == UBCORE_RTP) &&
	    req->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&req->peer_eid,
			req->tp_type == UBCORE_CTP ? &key.lk.local_eid : NULL,
			&req->local_eid,
			req->tp_type == UBCORE_CTP ? &key.lk.peer_eid : NULL,
			&destroy_local_cna, &destroy_peer_cna);
	}

	key.stag = req->dtag;
	key.dtag = req->stag;

	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	if (tpid_reuse == NULL &&
	    key.lk.share_mode == UBCORE_TPID_SHARE_NODE &&
	    (key.lk.tp_type == UBCORE_CTP || key.lk.tp_type == UBCORE_RTP) &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    ubcore_fill_tpid_reuse_key_cna(&key, destroy_local_cna, destroy_peer_cna,
		dev, "destroy-req")) {
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("destroy-req", "cna",
			tpid_reuse == NULL ? "miss" : "hit");
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (destroy_req): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	} else {
		ubcore_tp_trace_reuse_lookup("destroy-req", "cna",
			tpid_reuse != NULL ? "skip:eid_hit" :
			key.lk.share_mode == UBCORE_TPID_SHARE_NONE ? "skip:share_mode_none" :
			key.lk.share_mode != UBCORE_TPID_SHARE_NODE ? "skip:share_mode_not_node" :
			key.lk.tp_type != UBCORE_CTP && key.lk.tp_type != UBCORE_RTP ?
				"skip:tp_type_not_reusable" :
			key.lk.trans_mode != UBCORE_TP_RM ? "skip:trans_mode_not_rm" :
			"skip:cna_unavailable");
	}
	if (tpid_reuse == NULL) {
		ubcore_log_err("tpid not found in tpid_reuse table in handle destroy req.\n");
		return;
	}

	mutex_lock(&tpid_reuse->lock);
	if (tpid_reuse->is_ref == false) {
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}
	tpid_reuse->is_ref = false;
	/* Drop the reference taken when is_ref was set. */
	ubcore_tpid_reuse_kref_put(tpid_reuse);

	/* The peer released its reference, but if local users are still on this
	 * TP keep the entry serving them; the peer's own destroy_req (sent when
	 * its last user leaves) arrives later and converges the teardown. Do not
	 * deactivate a TP that is still in use.
	 */
	if (atomic_read(&tpid_reuse->use_cnt) > 0) {
		ubcore_tp_trace_cnt(tpid_reuse, "destroy-req(keep-inuse)");
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR ||
	    tpid_reuse->reuse_state == UBCORE_TPID_REUSE_RESET) {
		mutex_unlock(&tpid_reuse->lock);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}

	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	ubcore_tp_trace_cnt(tpid_reuse, "destroy-req(isref-clear)");
	mutex_unlock(&tpid_reuse->lock);

	/* Put the find_get reference before destroying; otherwise the free wait
	 * cannot reach ref_cnt 0 (the put would run after the wait).
	 */
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	(void)ubcore_destroy_tpid_reuse(dev, tpid_reuse);
}

static void handle_isref_req(struct ubcore_device *dev,
			       struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_isref_conn_req *req =
		(struct msg_isref_conn_req *)msg->data;
	struct ubcore_tpid_reuse_key key = { 0 };
	struct ubcore_tpid_reuse *tpid_reuse;
	/* The peer always replies: result 0 on success, -EAGAIN otherwise. */
	struct msg_isref_resp resp = {
		.result = 0,
		.local_eid = req->local_eid,
		.peer_eid = req->peer_eid,
		.stag = req->stag,
		.dtag = req->dtag,
		.trans_mode = req->trans_mode,
		.tp_type = req->tp_type,
		.link_type = req->link_type,
		.share_mode = req->share_mode,
		.conn_id = req->conn_id,
	};

	ubcore_neg_msg_log("rx", dev->dev_name, msg);
	key.lk.local_eid = req->peer_eid;
	key.lk.peer_eid = req->local_eid;
	union ubcore_net_addr_union isref_local_cna = {0};
	union ubcore_net_addr_union isref_peer_cna = {0};

	key.lk.trans_mode = req->trans_mode;
	key.lk.tp_type = req->tp_type;
	key.lk.link_type = req->link_type;
	key.lk.share_mode = req->share_mode;
	key.conn_id = req->conn_id;

	if (key.lk.share_mode != UBCORE_TPID_SHARE_NONE &&
	    (req->tp_type == UBCORE_CTP || req->tp_type == UBCORE_RTP) &&
	    req->trans_mode == UBCORE_TP_RM) {
		ubcore_lookup_host_info_local_and_peer(&req->peer_eid,
			req->tp_type == UBCORE_CTP ? &key.lk.local_eid : NULL,
			&req->local_eid,
			req->tp_type == UBCORE_CTP ? &key.lk.peer_eid : NULL,
			&isref_local_cna, &isref_peer_cna);
	}

	key.stag = req->dtag;
	key.dtag = req->stag;

	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	ubcore_tp_trace_key(&key, "peer-isref");
	if (tpid_reuse == NULL &&
	    key.lk.share_mode == UBCORE_TPID_SHARE_NODE &&
	    (key.lk.tp_type == UBCORE_CTP || key.lk.tp_type == UBCORE_RTP) &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    ubcore_fill_tpid_reuse_key_cna(&key, isref_local_cna, isref_peer_cna,
		dev, "isref-req")) {
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("isref-req", "cna",
			tpid_reuse == NULL ? "miss" : "hit");
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (isref_req): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	} else {
		ubcore_tp_trace_reuse_lookup("isref-req", "cna",
			tpid_reuse != NULL ? "skip:eid_hit" :
			key.lk.share_mode == UBCORE_TPID_SHARE_NONE ? "skip:share_mode_none" :
			key.lk.share_mode != UBCORE_TPID_SHARE_NODE ? "skip:share_mode_not_node" :
			key.lk.tp_type != UBCORE_CTP && key.lk.tp_type != UBCORE_RTP ?
				"skip:tp_type_not_reusable" :
			key.lk.trans_mode != UBCORE_TP_RM ? "skip:trans_mode_not_rm" :
			"skip:cna_unavailable");
	}
	if (tpid_reuse == NULL) {
		ubcore_log_err("tpid not found in tpid_reuse table.\n");
		ubcore_tp_trace_key(&key, "peer-isref-MISS");
		resp.result = -EAGAIN;
		(void)send_isref_resp(dev, req->local_eid, msg->session_id, &resp);
		return;
	}

	mutex_lock(&tpid_reuse->lock);
	/* The local TP may not exist yet while the entry is still RESET (the
	 * owner is between ensure_tp and READY). Tolerate ISREF during that
	 * window: only validate the tp_handle once it has been created, and skip
	 * the check on loopback where the peer handle equals our own.
	 */
	if (tpid_reuse->tp_handle_valid &&
	    req->tp_handle.value != 0 &&
	    req->tp_handle.value != tpid_reuse->tp_handle.value &&
	    !ubcore_is_loopback(dev, &req->peer_eid)) {
		mutex_unlock(&tpid_reuse->lock);
		ubcore_log_err("isref tp_id mismatch: req %llu vs table %llu\n",
			       req->tp_handle.value, tpid_reuse->tp_handle.value);
		ubcore_tp_trace_cnt(tpid_reuse, "isref-req(tp-mismatch)");
		resp.result = -EAGAIN;
		(void)send_isref_resp(dev, req->local_eid, msg->session_id, &resp);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}

	/* A retired/detached entry is out of the hash; do not take a new isref
	 * reference on it (nobody would release it). Let the source retry.
	 */
	if (tpid_reuse->reuse_state == UBCORE_TPID_REUSE_ERROR) {
		mutex_unlock(&tpid_reuse->lock);
		ubcore_log_info_rl("isref for retired tpid_reuse:%u, reply retry\n",
				   tpid_reuse->tp_handle.bs.tpid);
		resp.result = -EAGAIN;
		(void)send_isref_resp(dev, req->local_eid, msg->session_id, &resp);
		ubcore_tpid_reuse_kref_put(tpid_reuse);
		return;
	}

	if (!tpid_reuse->is_ref) {
		tpid_reuse->is_ref = true;
		ubcore_tpid_reuse_get(tpid_reuse);
		ubcore_tp_trace_cnt(tpid_reuse, "isref-req(isref)");
	}
	resp.result = 0;
	mutex_unlock(&tpid_reuse->lock);
	(void)send_isref_resp(dev, req->local_eid, msg->session_id, &resp);
	ubcore_tpid_reuse_kref_put(tpid_reuse);
}

/* Source-side handler for the ISREF response: wake the waiter that sent the
 * ISREF. On success (result 0) the reuse is confirmed; on -EAGAIN the caller
 * detaches the entry and lets the outer compat retry rebuild the TP pair.
 */
static void handle_isref_resp(struct ubcore_device *dev,
			      struct ubcore_comm_msg *msg, void *conn)
{
	struct session_data_create_conn *session_data;
	struct msg_isref_resp *resp = (struct msg_isref_resp *)msg->data;
	struct ubcore_session *session;

	ubcore_neg_msg_log("rx", dev->dev_name, msg);
	session = ubcore_session_find(msg->session_id);
	if (session == NULL) {
		ubcore_log_err("Failed to find session %u on isref resp\n",
			       msg->session_id);
		return;
	}
	session_data = (struct session_data_create_conn *)
		ubcore_session_get_data(session);
	session_data->ret = resp->result;
	ubcore_session_complete(session);
	ubcore_session_ref_release(session);
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
	bool drop_isref;
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
	/* NONE (baseline) skips the reuse lookup entirely. */
	if (key.lk.share_mode == UBCORE_TPID_SHARE_NONE) {
		ubcore_log_info_rl("share_mode NONE, skip reuse lookup (baseline)\n");
		tpid_reuse = NULL;
		ubcore_tp_trace_reuse_lookup("import-jfr", "eid", "skip");
	} else {
		ubcore_log_info_rl("try to get tpid reuse.\n");
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("import-jfr", "eid",
			tpid_reuse == NULL ? "miss" : "hit");
	}
	if (tpid_reuse == NULL &&
	    key.lk.share_mode == UBCORE_TPID_SHARE_NODE &&
	    (key.lk.tp_type == UBCORE_CTP || key.lk.tp_type == UBCORE_RTP) &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    ubcore_fill_tpid_reuse_key_cna(&key, jfr_local_cna, jfr_peer_cna,
		dev, "import-jfr")) {
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("import-jfr", "cna",
			tpid_reuse == NULL ? "miss" : "hit");
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (import_jfr): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	} else {
		ubcore_tp_trace_reuse_lookup("import-jfr", "cna",
			tpid_reuse != NULL ? "skip:eid_hit" :
			key.lk.share_mode == UBCORE_TPID_SHARE_NONE ? "skip:share_mode_none" :
			key.lk.share_mode != UBCORE_TPID_SHARE_NODE ? "skip:share_mode_not_node" :
			key.lk.tp_type != UBCORE_CTP && key.lk.tp_type != UBCORE_RTP ?
				"skip:tp_type_not_reusable" :
			key.lk.trans_mode != UBCORE_TP_RM ? "skip:trans_mode_not_rm" :
			"skip:cna_unavailable");
	}
	if (tpid_reuse != NULL) {
		tpid_reuse = ubcore_reuse_tpid(tpid_reuse);
		if (IS_ERR_OR_NULL(tpid_reuse))
			return (void *)tpid_reuse;
		active_tp_cfg.tp_handle = tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;
		tjfr = ubcore_import_jfr_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjfr)) {
			/* Roll back the use_cnt inc (under the lock) and the find_get
			 * reference (put outside it). kref_put must not run under the
			 * mutex (UAF risk).
			 */
			mutex_lock(&tpid_reuse->lock);
			atomic_dec(&tpid_reuse->use_cnt);
			mutex_unlock(&tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(tpid_reuse);
		}
		return tjfr;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key,
					      &get_tp_cfg.local_eid, &get_tp_cfg.peer_eid);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		return ERR_PTR(-ENOMEM);
	}

	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		exist_tpid_reuse =
			ubcore_reuse_tpid(exist_tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		if (IS_ERR_OR_NULL(exist_tpid_reuse))
			return (void *)exist_tpid_reuse;
		active_tp_cfg.tp_handle = exist_tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = exist_tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = exist_tpid_reuse->tx_psn;
		tjfr = ubcore_import_jfr_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjfr)) {
			/* Same rollback as above for the find_add reference. */
			mutex_lock(&exist_tpid_reuse->lock);
			atomic_dec(&exist_tpid_reuse->use_cnt);
			mutex_unlock(&exist_tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(exist_tpid_reuse);
		}
		return tjfr;
	}

	ret = ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg,
				   ubcore_effective_share_mode(cfg->flag.bs.share_tp));
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid cfg, ret=%d", ret);
		goto err_out;
	}

	ret = ubcore_tpid_reuse_ensure_tp(dev, tpid_reuse, &get_tp_cfg, udata,
					  &tp_handle);
	if (ret != 0) {
		/* Errors are printed in ubcore_tpid_reuse_ensure_tp(). */
		goto err_out;
	}

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
	ubcore_tpid_reuse_get(tpid_reuse);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	mutex_unlock(&tpid_reuse->lock);

	/* kref_put from find_add kref_get*/
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	ubcore_log_info_rl("import jfr compat, tjfr->vtpn: %u.\n", tjfr->vtpn->vtpn);

	return tjfr;

err_out:
	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	drop_isref = tpid_reuse->is_ref;
	if (drop_isref)
		tpid_reuse->is_ref = false;
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	if (drop_isref)
		ubcore_tpid_reuse_kref_put(tpid_reuse);
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
	bool drop_isref;
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

	/* NONE (baseline) skips the lookup and builds its own entry; find_add
	 * still merges an identical key.
	 */
	if (key.lk.share_mode == UBCORE_TPID_SHARE_NONE) {
		ubcore_log_info_rl("share_mode NONE, skip reuse lookup (baseline)\n");
		tpid_reuse = NULL;
		ubcore_tp_trace_reuse_lookup("import-jetty", "eid", "skip");
	} else {
		ubcore_log_info_rl("try to get tpid reuse.\n");
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("import-jetty", "eid",
			tpid_reuse == NULL ? "miss" : "hit");
	}

	/*
	 * Granularity of RTP sharing is selected by ubcore_share_mode:
	 *   1 = CONTAINER -> EID-pair only: the key keeps the endpoint EIDs and
	 *       its CNA fields stay zero, so only connections with an identical
	 *       (local_eid, peer_eid) pair reuse the same TP. The CNA fallback
	 *       below is skipped.
	 *   2 = NODE -> CNA: after the EID-pair lookup misses, fall back to the
	 *       physical CNA pair (local_cna/peer_cna from host info) so every
	 *       endpoint EID on the same device pair converges on one TP.
	 * The CNA key is filled here so that even if the CNA lookup also misses,
	 * the following ubcore_create_tpid_reuse naturally creates a CNA-level
	 * entry carrying the real CNA for later NODE sharing.
	 */
	if (tpid_reuse == NULL &&
	    key.lk.share_mode == UBCORE_TPID_SHARE_NODE &&
	    (key.lk.tp_type == UBCORE_CTP || key.lk.tp_type == UBCORE_RTP) &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    ubcore_fill_tpid_reuse_key_cna(&key, jetty_local_cna, jetty_peer_cna,
		dev, "import-jetty")) {
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("import-jetty", "cna",
			tpid_reuse == NULL ? "miss" : "hit");
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (import_jetty): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	} else {
		ubcore_tp_trace_reuse_lookup("import-jetty", "cna",
			tpid_reuse != NULL ? "skip:eid_hit" :
			key.lk.share_mode == UBCORE_TPID_SHARE_NONE ? "skip:share_mode_none" :
			key.lk.share_mode != UBCORE_TPID_SHARE_NODE ? "skip:share_mode_not_node" :
			key.lk.tp_type != UBCORE_CTP && key.lk.tp_type != UBCORE_RTP ?
				"skip:tp_type_not_reusable" :
			key.lk.trans_mode != UBCORE_TP_RM ? "skip:trans_mode_not_rm" :
			"skip:cna_unavailable");
	}
	if (tpid_reuse != NULL) {
		ubcore_log_info_rl("tpid reuse get. reuse tpid.\n");
		tpid_reuse = ubcore_reuse_tpid(tpid_reuse);
		if (IS_ERR_OR_NULL(tpid_reuse))
			return (void *)tpid_reuse;
		active_tp_cfg.tp_handle = tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;
		tjetty = ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjetty)) {
			/* Roll back the use_cnt inc (under the lock) and the find_get
			 * reference (put outside it). kref_put must not run under the
			 * mutex (UAF risk).
			 */
			mutex_lock(&tpid_reuse->lock);
			atomic_dec(&tpid_reuse->use_cnt);
			ubcore_tp_trace_cnt(tpid_reuse, "jetty-import-rollback");
			mutex_unlock(&tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(tpid_reuse);
		} else {
			ubcore_tp_trace_cnt(tpid_reuse, "jetty-import-reuse");
		}
		return tjetty;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key,
					      &get_tp_cfg.local_eid, &get_tp_cfg.peer_eid);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		return ERR_PTR(-ENOMEM);
	}

	/*if exist, exist_tpid_reuse kref inc and origin tpid_reuse do not inc,
	  else, tpid_reuse kref inc, finally need kref put*/
	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		exist_tpid_reuse =
			ubcore_reuse_tpid(exist_tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		if (IS_ERR_OR_NULL(exist_tpid_reuse))
			return (void *)exist_tpid_reuse;
		active_tp_cfg.tp_handle = exist_tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = exist_tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = exist_tpid_reuse->tx_psn;
		tjetty = ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
		if (IS_ERR_OR_NULL(tjetty)) {
			/* Same rollback as above for the find_add reference. */
			mutex_lock(&exist_tpid_reuse->lock);
			atomic_dec(&exist_tpid_reuse->use_cnt);
			ubcore_tp_trace_cnt(exist_tpid_reuse, "jetty-import-rollback");
			mutex_unlock(&exist_tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(exist_tpid_reuse);
		} else {
			ubcore_tp_trace_cnt(exist_tpid_reuse, "jetty-import-reuse");
		}
		return tjetty;
	}

	ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg,
			     ubcore_effective_share_mode(cfg->flag.bs.share_tp));
	ret = ubcore_tpid_reuse_ensure_tp(dev, tpid_reuse, &get_tp_cfg, udata, &tp_handle);
	if (ret != 0) {
		/* Errors are printed in ubcore_tpid_reuse_ensure_tp(). */
		goto err_out;
	}

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
	ubcore_tpid_reuse_get(tpid_reuse);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	ubcore_tp_trace_cnt(tpid_reuse, "jetty-import-new");
	mutex_unlock(&tpid_reuse->lock);

	/* kref_put from find_add kref_get*/
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	ubcore_log_info_rl("import jetty compat, tjetty->vtpn: %u.\n", tjetty->vtpn->vtpn);
	ubcore_tp_link_log("import-jetty", tpid_reuse);
	return tjetty;

err_out:
	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	drop_isref = tpid_reuse->is_ref;
	if (drop_isref)
		tpid_reuse->is_ref = false;
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tp_trace_cnt(tpid_reuse, "jetty-import-fail");
	/* Drop the find_add, isref and base references; the entry (and its TP)
	 * is freed when the last reference is released.
	 */
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	if (drop_isref)
		ubcore_tpid_reuse_kref_put(tpid_reuse);
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
	struct ubcore_tjetty_cfg cfg = { 0 };
	bool drop_isref;
	int ret;

	memcpy(&cfg, &tjetty->cfg, sizeof(tjetty->cfg));
	ret = ubcore_fill_get_tp_cfg(dev, &get_tp_cfg, &cfg);
	if (ret != 0)
		return ret;

	union ubcore_net_addr_union bind_local_cna = {0};
	union ubcore_net_addr_union bind_peer_cna = {0};

	ret = ubcore_fill_bind_tpid_reuse_key(&key, &get_tp_cfg, &cfg, jetty,
				      &bind_local_cna, &bind_peer_cna);
	if (ret != 0) {
		ubcore_log_err("Failed to fill bind tpid reuse key, ret=%d\n", ret);
		return ret;
	}
	tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
	if (tpid_reuse == NULL &&
	    key.lk.share_mode == UBCORE_TPID_SHARE_NODE &&
	    (key.lk.tp_type == UBCORE_CTP || key.lk.tp_type == UBCORE_RTP) &&
	    key.lk.trans_mode == UBCORE_TP_RM &&
	    ubcore_fill_tpid_reuse_key_cna(&key, bind_local_cna, bind_peer_cna,
		dev, "bind-jetty")) {
		tpid_reuse = ubcore_find_get_tpid_reuse(dev, &key);
		ubcore_tp_trace_reuse_lookup("bind-jetty", "cna",
			tpid_reuse == NULL ? "miss" : "hit");
		if (tpid_reuse != NULL)
			ubcore_log_debug("CNA reuse hit (bind_jetty): local_eid=" EID_FMT
				      " peer_eid=" EID_FMT "\n",
				EID_ARGS(key.lk.local_eid), EID_ARGS(key.lk.peer_eid));
	} else {
		ubcore_tp_trace_reuse_lookup("bind-jetty", "cna",
			tpid_reuse != NULL ? "skip:eid_hit" :
			key.lk.share_mode == UBCORE_TPID_SHARE_NONE ? "skip:share_mode_none" :
			key.lk.share_mode != UBCORE_TPID_SHARE_NODE ? "skip:share_mode_not_node" :
			key.lk.tp_type != UBCORE_CTP && key.lk.tp_type != UBCORE_RTP ?
				"skip:tp_type_not_reusable" :
			key.lk.trans_mode != UBCORE_TP_RM ? "skip:trans_mode_not_rm" :
			"skip:cna_unavailable");
	}
	if (tpid_reuse != NULL) {
		tpid_reuse = ubcore_reuse_tpid(tpid_reuse);
		/* NULL must not fall into PTR_ERR(): PTR_ERR(NULL) == 0 means success */
		if (IS_ERR_OR_NULL(tpid_reuse))
			return tpid_reuse == NULL ? -EIO : PTR_ERR(tpid_reuse);
		active_tp_cfg.tp_handle = tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;
		ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
		if (ret != 0) {
			ubcore_log_err("Failed to bind jetty ex, ret: %d.\n", ret);
			mutex_lock(&tpid_reuse->lock);
			atomic_dec(&tpid_reuse->use_cnt);
			mutex_unlock(&tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(tpid_reuse);
			return ret;
		}
		atomic_dec(&tjetty->use_cnt);
		return ret;
	}

	tpid_reuse = ubcore_create_tpid_reuse(dev, &key,
					      &get_tp_cfg.local_eid, &get_tp_cfg.peer_eid);
	if (IS_ERR_OR_NULL(tpid_reuse)) {
		ubcore_log_err("failed to alloc tpid_reuse!");
		return -ENOMEM;
	}

	ret = ubcore_find_add_tpid_reuse(dev, tpid_reuse, &exist_tpid_reuse, &key);
	if (ret == -EEXIST && exist_tpid_reuse != NULL) {
		exist_tpid_reuse =
			ubcore_reuse_tpid(exist_tpid_reuse);
		(void)ubcore_free_tpid_reuse(tpid_reuse);
		/* NULL must not fall into PTR_ERR(): PTR_ERR(NULL) == 0 means success */
		if (IS_ERR_OR_NULL(exist_tpid_reuse))
			return exist_tpid_reuse == NULL ? -EIO : PTR_ERR(exist_tpid_reuse);
		active_tp_cfg.tp_handle = exist_tpid_reuse->tp_handle;
		active_tp_cfg.tpid_reuse = exist_tpid_reuse;
		active_tp_cfg.tp_attr.tx_psn = exist_tpid_reuse->tx_psn;
		ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
		if (ret != 0) {
			ubcore_log_err("Failed to bind jetty ex, ret: %d.\n", ret);
			mutex_lock(&exist_tpid_reuse->lock);
			atomic_dec(&exist_tpid_reuse->use_cnt);
			mutex_unlock(&exist_tpid_reuse->lock);
			ubcore_tpid_reuse_kref_put(exist_tpid_reuse);
			return ret;
		}
		atomic_dec(&tjetty->use_cnt);
		return ret;
	}

	ret = ubcore_fill_tpid_cfg(&tpid_cfg, &get_tp_cfg,
				   ubcore_effective_share_mode(cfg.flag.bs.share_tp));
	if (ret != 0) {
		ubcore_log_err("Failed to fill tpid cfg, ret=%d\n", ret);
		goto err_out;
	}

	ret = ubcore_tpid_reuse_ensure_tp(dev, tpid_reuse, &get_tp_cfg, udata,
					  &tp_handle);
	if (ret != 0) {
		/* Errors are printed in ubcore_tpid_reuse_ensure_tp(). */
		goto err_out;
	}

	active_tp_cfg.tp_handle = tp_handle;
	active_tp_cfg.tpid_reuse = tpid_reuse;
	active_tp_cfg.tp_attr.tx_psn = tpid_reuse->tx_psn;

	if (tjetty->cfg.tp_type == UBCORE_RTP) {
		tjetty->cfg.stp_cfg.stag = jetty->jetty_id.id;
		tjetty->cfg.stp_cfg.dtag = tjetty->cfg.id.id;
		cfg.stp_cfg = tjetty->cfg.stp_cfg;
		ret = ubcore_exchange_tp_info(dev, &get_tp_cfg,
			&active_tp_cfg, &cfg, udata);
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
	ubcore_tpid_reuse_get(tpid_reuse);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_READY;
	mutex_unlock(&tpid_reuse->lock);

	/* kref_put from find_add kref_get*/
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	return ret;

err_out:
	ubcore_hash_table_rmv_tpid_reuse(dev, tpid_reuse);
	mutex_lock(&tpid_reuse->lock);
	tpid_reuse->reuse_state = UBCORE_TPID_REUSE_ERROR;
	drop_isref = tpid_reuse->is_ref;
	if (drop_isref)
		tpid_reuse->is_ref = false;
	mutex_unlock(&tpid_reuse->lock);
	ubcore_tpid_reuse_kref_put(tpid_reuse);
	if (drop_isref)
		ubcore_tpid_reuse_kref_put(tpid_reuse);
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
	ubcore_net_register_msg_handler(UBCORE_NET_ISREF_RESP,
					handle_isref_resp,
					sizeof(struct msg_isref_resp));
}
