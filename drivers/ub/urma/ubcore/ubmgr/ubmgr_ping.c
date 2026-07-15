// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubmgr ping implementation file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>

#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_log.h"
#include "ubcore_main_ue_eid.h"

#include "ubmgr_ping.h"

#define PING_WK_JETTY_ID 5
#define PING_SEND_DEPTH 1024
#define PING_RECV_DEPTH 1024
#define PING_MAX_MSG_SIZE 4096
#define PING_BUF_SIZE ((PING_RECV_DEPTH) * (PING_MAX_MSG_SIZE))
#define PING_CR_SIZE 16
#define PING_TJETTY_HASH_SIZE 1024

struct ubcore_client g_ping_client;

struct ubmgr_ping_ctx {
	void *buf;
	struct mutex init_mutex;
	struct ubcore_target_seg *seg;
	struct ubcore_jfc *send_jfc;
	struct ubcore_jfc *recv_jfc;
	struct ubcore_jfr *jfr;
	struct ubcore_jetty *jetty;
	struct workqueue_struct *wq;
	struct hlist_head tjetty_hlist[PING_TJETTY_HASH_SIZE];
	spinlock_t tjetty_lock;
	spinlock_t wq_lock;     /* protects wq pointer + queue_work */
	bool wq_stopped;        /* blocks queue_work during jetty teardown */
};

/* Hash func */
struct ubmgr_ping_tjetty_entry {
	struct ubcore_tjetty *tjetty;
	struct kref kref;
	struct hlist_node node;
};

static inline uint32_t __ping_tjetty_hash_fn(union ubcore_eid *dst_eid)
{
	return jhash(dst_eid, sizeof(union ubcore_eid), 0) %
	       PING_TJETTY_HASH_SIZE;
}

static struct ubmgr_ping_tjetty_entry *
__ping_tjetty_new_entry(struct ubcore_device *dev, union ubcore_eid *dst_eid,
			uint32_t eid_index, uint32_t remote_jetty_id)
{
	struct ubcore_tjetty_cfg cfg = {
		.id.eid = *dst_eid,
		.id.id = remote_jetty_id,
		.trans_mode = UBCORE_TP_RM,
		.type = UBCORE_JETTY,
		.tp_type = UBCORE_CTP,
		.eid_index = eid_index,
	};
	struct ubcore_tjetty *tjetty = NULL;

	tjetty = ubcore_import_jetty(dev, &cfg, NULL);
	if (IS_ERR_OR_NULL(tjetty))
		return ERR_CAST(tjetty);

	struct ubmgr_ping_tjetty_entry *entry = NULL;

	entry = kzalloc(sizeof(struct ubmgr_ping_tjetty_entry), GFP_KERNEL);
	if (entry == NULL)
		return ERR_PTR(-ENOMEM);

	entry->tjetty = tjetty;
	kref_init(&entry->kref);
	return entry;
}

void __ping_tjetty_free_entry(struct kref *kref)
{
	struct ubmgr_ping_tjetty_entry *entry =
		container_of(kref, struct ubmgr_ping_tjetty_entry, kref);

	ubcore_unimport_jetty(entry->tjetty);
}

static struct ubmgr_ping_tjetty_entry *
__ping_tjetty_find(struct hlist_head *bucket, union ubcore_eid *dst_eid,
			uint32_t remote_id)
{
	struct ubmgr_ping_tjetty_entry *entry = NULL;

	hlist_for_each_entry(entry, bucket, node) {
		if (memcmp(&entry->tjetty->cfg.id.eid, dst_eid,
			   sizeof(union ubcore_eid)) == 0 &&
			   entry->tjetty->cfg.id.id == remote_id) {
			kref_get(&entry->kref);
			return entry;
		}
	}
	return NULL;
}

static struct ubmgr_ping_tjetty_entry *
__ping_tjetty_add(struct hlist_head *bucket, union ubcore_eid *dst_eid,
		  struct ubmgr_ping_tjetty_entry *entry, uint32_t remote_id)
{
	struct ubmgr_ping_tjetty_entry *entry_exist;

	entry_exist = __ping_tjetty_find(bucket, dst_eid, remote_id);
	if (entry_exist)
		return entry_exist;

	hlist_add_head(&entry->node, bucket);
	return entry;
}

void __ping_tjetty_clear(struct hlist_head *bucket)
{
	struct ubmgr_ping_tjetty_entry *entry;
	struct hlist_node *tmp;

	hlist_for_each_entry_safe(entry, tmp, bucket, node) {
		hlist_del(&entry->node);
		__ping_tjetty_free_entry(&entry->kref);
		kfree(entry);
	}
}

static struct ubmgr_ping_tjetty_entry *
ping_tjetty_find_or_create(struct ubmgr_ping_ctx *ctx,
			   union ubcore_eid *dst_eid, uint32_t remote_id)
{
	uint32_t hash = __ping_tjetty_hash_fn(dst_eid);
	struct hlist_head *bucket = &ctx->tjetty_hlist[hash];
	struct ubmgr_ping_tjetty_entry *entry, *entry_added;
	unsigned long flag;

	spin_lock_irqsave(&ctx->tjetty_lock, flag);
	entry = __ping_tjetty_find(bucket, dst_eid, remote_id);
	spin_unlock_irqrestore(&ctx->tjetty_lock, flag);

	if (!IS_ERR_OR_NULL(entry)) {
		ubcore_log_info("Tjetty already imported. eid " EID_FMT "\n",
				EID_ARGS(*dst_eid));
		return entry;
	}

	entry = __ping_tjetty_new_entry(ctx->jetty->ub_dev, dst_eid,
					ctx->jetty->jetty_cfg.eid_index, remote_id);
	if (IS_ERR_OR_NULL(entry)) {
		ubcore_log_err("Failed to import tjetty. eid " EID_FMT "\n",
			       EID_ARGS(*dst_eid));
		return ERR_CAST(entry);
	}

	spin_lock_irqsave(&ctx->tjetty_lock, flag);
	entry_added = __ping_tjetty_add(bucket, dst_eid, entry, remote_id);
	spin_unlock_irqrestore(&ctx->tjetty_lock, flag);

	if (entry_added != entry) {
		ubcore_log_info("Tjetty already imported. deid:" EID_FMT ".\n",
				EID_ARGS(*dst_eid));
		__ping_tjetty_free_entry(&entry->kref);
		kfree(entry);
		return entry_added;
	}

	return entry;
}

static void ping_tjetty_put(struct ubmgr_ping_ctx *ctx,
			    struct ubmgr_ping_tjetty_entry *entry)
{
	unsigned long flag;
	bool last = false;

	spin_lock_irqsave(&ctx->tjetty_lock, flag);
	if (kref_read(&entry->kref) == 1) {
		hlist_del(&entry->node);
		last = true;
	}
	spin_unlock_irqrestore(&ctx->tjetty_lock, flag);

	kref_put(&entry->kref, __ping_tjetty_free_entry);
	if (last)
		kfree(entry);
}

static void ping_tjetty_clear(struct ubmgr_ping_ctx *ctx)
{
	for (int i = 0; i < PING_TJETTY_HASH_SIZE; i++)
		__ping_tjetty_clear(&ctx->tjetty_hlist[i]);
}

static void ping_tjetty_htable_init(struct ubmgr_ping_ctx *ctx)
{
	for (int i = 0; i < PING_TJETTY_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&ctx->tjetty_hlist[i]);
}

static int ping_find_eid_by_main_ue_eid(const union ubcore_eid *main_ue_eid,
					 struct ubcore_device *dev,
					 struct ubcore_eid_info *eid_info)
{
	int i;

	spin_lock(&dev->eid_table.lock);
	for (i = 0; i < dev->eid_table.eid_cnt; i++) {
		if (!dev->eid_table.eid_entries[i].valid)
			continue;

		if (memcmp(&dev->eid_table.eid_entries[i].eid, main_ue_eid,
			   UBCORE_EID_SIZE) == 0) {
			eid_info->eid = dev->eid_table.eid_entries[i].eid;
			eid_info->eid_index = dev->eid_table.eid_entries[i].eid_index;
			spin_unlock(&dev->eid_table.lock);
			return 0;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	return -EINVAL;
}

/* Workqueue func */
struct ubmgr_ping_work {
	struct work_struct work;
	struct ubcore_jfc *jfc;
	struct ubmgr_ping_ctx *ctx;
};

struct ubmgr_ping_resp_ctx {
	struct ubmgr_ping_tjetty_entry *entry;
	uint64_t sge_addr;
};

static void ping_refill_recv_wr(struct ubmgr_ping_ctx *ctx, uint64_t addr)
{
	int ret;

	struct ubcore_sge sge = {
		.addr = addr,
		.len = PING_MAX_MSG_SIZE,
		.tseg = ctx->seg,
	};
	struct ubcore_jfr_wr wr = {
		.src.sge = &sge,
		.src.num_sge = 1,
		.user_ctx = sge.addr,
	};
	struct ubcore_jfr_wr *bad_wr = NULL;

	ret = ubcore_post_jetty_recv_wr(ctx->jetty, &wr, &bad_wr);
	if (ret != 0)
		ubcore_log_err("Fail to refill recv wr, ret:%d\n", ret);
}

static void ping_wq_on_recved(struct ubmgr_ping_ctx *ctx, struct ubcore_cr *cr)
{
	int ret;

	if (cr->status != UBCORE_CR_SUCCESS) {
		ubcore_log_err("Rx status error. status %d, comp_len %u.\n",
			       cr->status, cr->completion_len);
		goto refill;
	}

	struct ubmgr_ping_tjetty_entry *entry;

	entry = ping_tjetty_find_or_create(ctx, &cr->remote_id.eid, cr->remote_id.id);
	if (IS_ERR_OR_NULL(entry)) {
		ubcore_log_err("Failed to get tjetty for remote_id\n");
		goto refill;
	}

	struct ubmgr_ping_resp_ctx *resp_ctx =
		kzalloc(sizeof(struct ubmgr_ping_resp_ctx), GFP_KERNEL);

	if (resp_ctx == NULL) {
		ping_tjetty_put(ctx, entry);
		goto refill;
	}
	resp_ctx->entry = entry;
	resp_ctx->sge_addr = cr->user_ctx;

	struct ubcore_sge sge = {
		.addr = cr->user_ctx,
		.len = min_t(uint32_t, cr->completion_len, PING_MAX_MSG_SIZE),
		.tseg = ctx->seg,
	};
	struct ubcore_jfs_wr wr = {
		.opcode = UBCORE_OPC_SEND_IMM,
		.flag.bs.complete_enable = 1,
		.user_ctx = (uint64_t)resp_ctx,
		.tjetty = entry->tjetty,
		.send.src.sge = &sge,
		.send.src.num_sge = 1,
		.send.imm_data = cr->imm_data,
	};

	struct ubcore_jfs_wr *bad_wr = NULL;

	ret = ubcore_post_jetty_send_wr(ctx->jetty, &wr, &bad_wr);
	if (ret != 0) {
		ping_tjetty_put(ctx, entry);
		ubcore_log_err("Fail to post send wr, ret:%d\n", ret);
		goto refill;
	}
	return;

refill:
	ping_refill_recv_wr(ctx, cr->user_ctx);
}

static void ping_wq_on_sended(struct ubmgr_ping_ctx *ctx, struct ubcore_cr *cr)
{
	if (cr->status != UBCORE_CR_SUCCESS)
		ubcore_log_err("Tx status error. status %d, comp_len %u.\n",
			       cr->status, cr->completion_len);

	if (cr->status == UBCORE_CR_WR_FLUSH_ERR_DONE || cr->user_ctx == 0) {
		ubcore_log_err("Send WR flushed or cr user_ctx is NULL.\n");
		return;
	}

	struct ubmgr_ping_resp_ctx *resp_ctx = (struct ubmgr_ping_resp_ctx *)cr->user_ctx;

	ping_tjetty_put(ctx, resp_ctx->entry);
	ping_refill_recv_wr(ctx, resp_ctx->sge_addr);
	kfree(resp_ctx);
}

static void ping_recv_work_handler(struct work_struct *w)
{
	struct ubmgr_ping_work *work =
		container_of(w, struct ubmgr_ping_work, work);
	struct ubmgr_ping_ctx *ctx = work->ctx;
	struct ubcore_jfc *jfc = work->jfc;
	int ret;

	struct ubcore_cr cr = { 0 };
	int cr_cnt = 0;

	do {
		cr_cnt = ubcore_poll_jfc(jfc, 1, &cr);
		if (cr_cnt < 0) {
			ubcore_log_err(
				"Failed to poll jfc, jfc_id: %u, ret: %d.\n",
				jfc->id, cr_cnt);
			break;
		} else if (cr_cnt == 0)
			break;

		ping_wq_on_recved(ctx, &cr);
	} while (cr_cnt > 0);

	ret = ubcore_rearm_jfc(jfc, false);
	if (ret != 0)
		ubcore_log_err("Failed to rearm jfc, jfc_id: %u, ret: %d.\n",
			       jfc->id, ret);

	kfree(work);
}

static void ping_send_work_handler(struct work_struct *w)
{
	struct ubmgr_ping_work *work =
		container_of(w, struct ubmgr_ping_work, work);
	struct ubmgr_ping_ctx *ctx = work->ctx;
	struct ubcore_jfc *jfc = work->jfc;
	int ret;

	struct ubcore_cr cr = { 0 };
	int cr_cnt = 0;

	do {
		cr_cnt = ubcore_poll_jfc(jfc, 1, &cr);
		if (cr_cnt < 0) {
			ubcore_log_err(
				"Failed to poll jfc, jfc_id: %u, ret: %d.\n",
				jfc->id, cr_cnt);
			break;
		} else if (cr_cnt == 0)
			break;

		ping_wq_on_sended(ctx, &cr);
	} while (cr_cnt > 0);

	ret = ubcore_rearm_jfc(jfc, false);
	if (ret != 0)
		ubcore_log_err("Failed to rearm jfc, jfc_id: %u, ret: %d.\n",
			       jfc->id, ret);

	kfree(work);
}

static int ping_wq_queue_work(struct ubcore_jfc *jfc,
			      void (*handler)(struct work_struct *))
{
	struct ubmgr_ping_ctx *ctx;

	struct ubmgr_ping_work *pwork;
	unsigned long flags;

	ctx = ubcore_get_client_ctx_data(jfc->ub_dev, &g_ping_client);
	if (IS_ERR_OR_NULL(ctx))
		return -EINVAL;

	pwork = kzalloc(sizeof(struct ubmgr_ping_work), GFP_ATOMIC);
	if (pwork == NULL)
		return -ENOMEM;

	INIT_WORK(&pwork->work, handler);
	pwork->jfc = jfc;
	pwork->ctx = ctx;

	/*
	 * Hold wq_lock across state-check + queue_work so teardown cannot
	 * race between the check and queueing a new work item.
	 */
	spin_lock_irqsave(&ctx->wq_lock, flags);
	if (!ctx->wq || ctx->wq_stopped) {
		spin_unlock_irqrestore(&ctx->wq_lock, flags);
		kfree(pwork);
		return -ESHUTDOWN;
	}
	if (!queue_work(ctx->wq, &pwork->work)) {
		spin_unlock_irqrestore(&ctx->wq_lock, flags);
		kfree(pwork);
		return -EBUSY;
	}
	spin_unlock_irqrestore(&ctx->wq_lock, flags);
	return 0;
}

static void ping_recv_jfc_comp(struct ubcore_jfc *jfc)
{
	int ret;

	ret = ping_wq_queue_work(jfc, ping_recv_work_handler);
	if (ret != 0)
		ubcore_log_err("Failed to queue work for recv, ret:%d.\n", ret);
}

static void ping_send_jfc_comp(struct ubcore_jfc *jfc)
{
	int ret;

	ret = ping_wq_queue_work(jfc, ping_send_work_handler);
	if (ret != 0)
		ubcore_log_err("Failed to queue work for send, ret:%d.\n", ret);
}

static int ping_ctx_prefill_recv_wr(struct ubmgr_ping_ctx *ctx)
{
	int ret;

	for (uint32_t i = 0; i < PING_RECV_DEPTH; i++) {
		uint64_t addr = (uint64_t)(uintptr_t)(ctx->buf);
		struct ubcore_sge sge = {
			.addr = addr + i * PING_MAX_MSG_SIZE,
			.len = PING_MAX_MSG_SIZE,
			.tseg = ctx->seg,
		};
		struct ubcore_jfr_wr wr = {
			.src.sge = &sge,
			.src.num_sge = 1,
			.user_ctx = sge.addr,
		};
		struct ubcore_jfr_wr *bad_wr = NULL;

		ret = ubcore_post_jetty_recv_wr(ctx->jetty, &wr, &bad_wr);
		if (ret != 0) {
			ubcore_log_err("Fail to post recv wr, idx:%d, ret:%d\n",
				       i, ret);
			return ret;
		}
	}

	return 0;
}

static int ping_ctx_init_jetty(struct ubcore_device *dev,
			       struct ubmgr_ping_ctx *ctx, uint32_t eid_index)
{
	int ret;

	struct ubcore_seg_cfg seg_cfg = {
		.va = (uint64_t)(uintptr_t)(ctx->buf),
		.len = PING_BUF_SIZE,
		.eid_index = eid_index,
		.flag.bs.access = UBCORE_ACCESS_LOCAL_ONLY,
	};
	ctx->seg = ubcore_register_seg(dev, &seg_cfg, NULL);
	if (IS_ERR_OR_NULL(ctx->seg)) {
		ubcore_log_err("Fail to register ping seg, dev:%s\n",
			       dev->dev_name);
		return -EINVAL;
	}

	struct ubcore_jfc_cfg send_jfc_cfg = {
		.depth = PING_SEND_DEPTH,
	};
	ctx->send_jfc = ubcore_create_jfc(dev, &send_jfc_cfg,
					  ping_send_jfc_comp, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->send_jfc)) {
		ubcore_log_err("Fail to create ping send jfc, dev:%s\n",
			       dev->dev_name);
		ret = -EINVAL;
		goto unregister_seg;
	}

	ret = ubcore_rearm_jfc(ctx->send_jfc, false);
	if (ret != 0)
		ubcore_log_err(
			"Failed to rearm send jfc, jfc_id: %u, ret: %d.\n",
			ctx->send_jfc->id, ret);

	struct ubcore_jfc_cfg recv_jfc_cfg = {
		.depth = PING_RECV_DEPTH,
	};
	ctx->recv_jfc = ubcore_create_jfc(dev, &recv_jfc_cfg,
					  ping_recv_jfc_comp, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->recv_jfc)) {
		ubcore_log_err("Fail to create ping recv jfc, dev:%s\n",
			       dev->dev_name);
		ret = -EINVAL;
		goto delete_send_jfc;
	}

	ret = ubcore_rearm_jfc(ctx->recv_jfc, false);
	if (ret != 0)
		ubcore_log_err(
			"Failed to rearm recv jfc, jfc_id: %u, ret: %d.\n",
			ctx->recv_jfc->id, ret);

	struct ubcore_jfr_cfg jfr_cfg = {
		.depth = PING_RECV_DEPTH,
		.trans_mode = UBCORE_TP_RM,
		.eid_index = eid_index,
		.max_sge = 1,
		.jfc = ctx->recv_jfc,
	};
	ctx->jfr = ubcore_create_jfr(dev, &jfr_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jfr)) {
		ubcore_log_err("Fail to create ping jfr, dev:%s\n",
			       dev->dev_name);
		ret = -EINVAL;
		goto delete_recv_jfc;
	}

	struct ubcore_jetty_cfg jetty_cfg = {
		.id = PING_WK_JETTY_ID,
		.flag.bs.share_jfr = 1,
		.trans_mode = UBCORE_TP_RM,
		.eid_index = eid_index,
		.jfs_depth = PING_SEND_DEPTH,
		.priority = 6,
		.max_send_sge = 1,
		.max_send_rsge = 1,
		.send_jfc = ctx->send_jfc,
		.recv_jfc = ctx->recv_jfc,
		.jfr = ctx->jfr,
	};

	ctx->jetty = ubcore_create_jetty(dev, &jetty_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(ctx->jetty)) {
		ubcore_log_err("Fail to create ping wk jetty, dev:%s\n",
			       dev->dev_name);
		ret = -EINVAL;
		goto delete_jfr;
	}

	if (ping_ctx_prefill_recv_wr(ctx) != 0) {
		ret = -EINVAL;
		goto delete_jetty;
	}

	return 0;

delete_jetty:
	ubcore_delete_jetty(ctx->jetty);
	ctx->jetty = NULL;
delete_jfr:
	ubcore_delete_jfr(ctx->jfr);
	ctx->jfr = NULL;
delete_recv_jfc:
	ubcore_delete_jfc(ctx->recv_jfc);
	ctx->recv_jfc = NULL;
delete_send_jfc:
	ubcore_delete_jfc(ctx->send_jfc);
	ctx->send_jfc = NULL;
unregister_seg:
	ubcore_unregister_seg(ctx->seg);
	ctx->seg = NULL;
	return ret;
}

static void ping_ctx_uninit_jetty(struct ubmgr_ping_ctx *ctx)
{
	if (ctx->jetty != NULL) {
		ubcore_delete_jetty(ctx->jetty);
		ctx->jetty = NULL;
	}

	if (ctx->jfr != NULL) {
		ubcore_delete_jfr(ctx->jfr);
		ctx->jfr = NULL;
	}

	if (ctx->recv_jfc != NULL) {
		ubcore_delete_jfc(ctx->recv_jfc);
		ctx->recv_jfc = NULL;
	}

	if (ctx->send_jfc != NULL) {
		ubcore_delete_jfc(ctx->send_jfc);
		ctx->send_jfc = NULL;
	}

	if (ctx->seg != NULL) {
		ubcore_unregister_seg(ctx->seg);
		ctx->seg = NULL;
	}
}

static struct workqueue_struct *ping_stop_wq(struct ubmgr_ping_ctx *ctx,
					     bool detach)
{
	struct workqueue_struct *wq;
	unsigned long flags;

	/* Stop new ping work before draining in-flight handlers. */
	spin_lock_irqsave(&ctx->wq_lock, flags);
	wq = ctx->wq;
	ctx->wq_stopped = true;
	if (detach)
		ctx->wq = NULL;
	spin_unlock_irqrestore(&ctx->wq_lock, flags);

	if (wq != NULL)
		drain_workqueue(wq);

	return wq;
}

static void ping_start_wq(struct ubmgr_ping_ctx *ctx)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->wq_lock, flags);
	ctx->wq_stopped = false;
	spin_unlock_irqrestore(&ctx->wq_lock, flags);
}

static int ping_on_add_device(struct ubcore_device *dev)
{
	struct ubmgr_ping_ctx *ping_ctx;
	int ret;

	ping_ctx = vzalloc(sizeof(struct ubmgr_ping_ctx));
	if (ping_ctx == NULL)
		return -ENOMEM;

	ping_ctx->buf = vzalloc(PING_BUF_SIZE);
	if (ping_ctx->buf == NULL) {
		ret = -ENOMEM;
		goto free_ctx;
	}

	mutex_init(&ping_ctx->init_mutex);
	spin_lock_init(&ping_ctx->tjetty_lock);
	spin_lock_init(&ping_ctx->wq_lock);
	ping_tjetty_htable_init(ping_ctx);
	ping_ctx->wq = alloc_workqueue(
		"ping_wq", WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_FREEZABLE, 0);
	if (ping_ctx->wq == NULL) {
		ret = -ENOMEM;
		goto free_buf;
	}

	ubcore_set_client_ctx_data(dev, &g_ping_client, ping_ctx);
	return 0;

free_buf:
	vfree(ping_ctx->buf);
free_ctx:
	vfree(ping_ctx);
	return ret;
}

static void ping_on_remove_device(struct ubcore_device *dev, void *client_ctx)
{
	struct ubmgr_ping_ctx *ping_ctx = client_ctx;
	struct workqueue_struct *wq;

	if (ping_ctx == NULL)
		return;

	wq = ping_stop_wq(ping_ctx, true);

	ping_tjetty_clear(ping_ctx);
	ping_ctx_uninit_jetty(ping_ctx);

	if (wq != NULL)
		destroy_workqueue(wq);
	mutex_destroy(&ping_ctx->init_mutex);
	vfree(ping_ctx->buf);
	vfree(ping_ctx);
}

struct ubcore_client g_ping_client = {
	.list_node = LIST_HEAD_INIT(g_ping_client.list_node),
	.client_name = "ubmgr_ping",
	.add = ping_on_add_device,
	.remove = ping_on_remove_device,
	.stop = NULL,
};

static void ping_try_init_ctx(const union ubcore_eid *main_ue_eid,
			       struct ubcore_device *dev)
{
	struct ubmgr_ping_ctx *ping_ctx;
	int ret;

	ping_ctx = ubcore_get_client_ctx_data(dev, &g_ping_client);
	if (IS_ERR_OR_NULL(ping_ctx)) {
		ubcore_log_err("Failed to get ping client ctx, dev:%s\n",
			       dev->dev_name);
		return;
	}

	mutex_lock(&ping_ctx->init_mutex);
	if (ping_ctx->jetty != NULL) {
		mutex_unlock(&ping_ctx->init_mutex);
		return;
	}
	struct ubcore_eid_info eid_info = { 0 };

	if (ping_find_eid_by_main_ue_eid(main_ue_eid, dev, &eid_info) != 0) {
		ubcore_log_info(
			"Primary eid not found, init deferred, dev:%s\n",
			dev->dev_name);
		mutex_unlock(&ping_ctx->init_mutex);
		return;
	}

	ret = ping_ctx_init_jetty(dev, ping_ctx, eid_info.eid_index);
	if (ret != 0) {
		ubcore_log_err("Failed to init ping ctx, dev:%s, ret=%d\n",
			       dev->dev_name, ret);
	}
	mutex_unlock(&ping_ctx->init_mutex);
}

static void ping_try_uninit_ctx(struct ubcore_device *dev)
{
	struct ubmgr_ping_ctx *ping_ctx;

	ping_ctx = ubcore_get_client_ctx_data(dev, &g_ping_client);
	if (IS_ERR_OR_NULL(ping_ctx)) {
		ubcore_log_err("Failed to get ping client ctx, dev:%s\n",
			       dev->dev_name);
		return;
	}

	mutex_lock(&ping_ctx->init_mutex);
	if (ping_ctx->jetty == NULL) {
		mutex_unlock(&ping_ctx->init_mutex);
		return;
	}

	/* LAST_DEL tears down ping jetty resources until a later FIRST_ADD. */
	(void)ping_stop_wq(ping_ctx, false);
	ping_tjetty_clear(ping_ctx);
	ping_ctx_uninit_jetty(ping_ctx);
	ping_start_wq(ping_ctx);
	mutex_unlock(&ping_ctx->init_mutex);
}

static void ping_on_main_ue_eid_event(
	const union ubcore_eid *main_ue_eid,
	enum ubcore_main_ue_eid_event_type event_type)
{
	struct ubcore_device *dev;

	dev = ubcore_get_device_by_eid((union ubcore_eid *)main_ue_eid,
				       UBCORE_TRANSPORT_UB);
	if (dev == NULL)
		return;

	switch (event_type) {
	case UBCORE_MAIN_UE_EID_FIRST_ADD:
		ping_try_init_ctx(main_ue_eid, dev);
		break;
	case UBCORE_MAIN_UE_EID_LAST_DEL:
		ping_try_uninit_ctx(dev);
		break;
	default:
		break;
	}

	ubcore_put_device(dev);
}

int ubmgr_ping_init(void)
{
	int ret;

	ret = ubcore_register_main_ue_eid_event_cb(ping_on_main_ue_eid_event);
	if (ret != 0) {
		ubcore_log_err("Failed to register main ue eid event cb, ret=%d\n",
			       ret);
		return ret;
	}

	ret = ubcore_register_client(&g_ping_client);
	if (ret != 0) {
		ubcore_log_err("Failed to register ping client, ret=%d\n", ret);
		(void)ubcore_unregister_main_ue_eid_event_cb(ping_on_main_ue_eid_event);
		return ret;
	}

	return 0;
}

void ubmgr_ping_uninit(void)
{
	ubcore_unregister_client(&g_ping_client);
	(void)ubcore_unregister_main_ue_eid_event_cb(ping_on_main_ue_eid_event);
}
