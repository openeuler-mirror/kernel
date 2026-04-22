// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ub_mad datapath implementation
 * Author: Chen Yutao
 * Create: 2025-02-21
 * Note:
 * History: 2025-02-21: create file
 */

#include <linux/jiffies.h>
#include <linux/jhash.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_topo_info.h"
#include "net/ubcore_cm.h"
#include "ubcore_log.h"
#include "ub_mad_priv.h"

/** reliable communication **/
/* msn mgr */
void ubmad_init_msn_mgr(struct ubmad_msn_mgr *msn_mgr)
{
	uint32_t idx;

	for (idx = 0; idx < UBMAD_MSN_HLIST_SIZE; idx++)
		INIT_HLIST_HEAD(&msn_mgr->msn_hlist[idx]);
	spin_lock_init(&msn_mgr->msn_hlist_lock);
	atomic64_set(&msn_mgr->msn_gen, 0); // msn starts from 0
}

void ubmad_uninit_msn_mgr(struct ubmad_msn_mgr *msn_mgr)
{
	struct ubmad_msn_node *msn_node;
	struct hlist_node *next;
	unsigned long flag;
	uint32_t idx;

	spin_lock_irqsave(&msn_mgr->msn_hlist_lock, flag);
	for (idx = 0; idx < UBMAD_MSN_HLIST_SIZE; idx++) {
		hlist_for_each_entry_safe(msn_node, next,
					  &msn_mgr->msn_hlist[idx], node) {
			hlist_del(&msn_node->node);
			kfree(msn_node);
		}
	}
	spin_unlock_irqrestore(&msn_mgr->msn_hlist_lock, flag);
}

/* msn node */
static struct ubmad_msn_node *
ubmad_create_msn_node(uint64_t msn, struct ubmad_msn_mgr *msn_mgr)
{
	struct ubmad_msn_node *msn_node;
	unsigned long flag;
	uint32_t hash;

	msn_node = kzalloc(sizeof(struct ubmad_msn_node), GFP_KERNEL);
	if (IS_ERR_OR_NULL(msn_node))
		return ERR_PTR(-ENOMEM);

	msn_node->msn = msn;
	INIT_HLIST_NODE(&msn_node->node);

	hash = jhash(&msn, sizeof(uint64_t), 0) % UBMAD_MSN_HLIST_SIZE;
	spin_lock_irqsave(&msn_mgr->msn_hlist_lock, flag);
	hlist_add_head(&msn_node->node, &msn_mgr->msn_hlist[hash]);
	spin_unlock_irqrestore(&msn_mgr->msn_hlist_lock, flag);

	return msn_node;
}

static void ubmad_destroy_msn_node(struct ubmad_msn_node *msn_node,
				   struct ubmad_msn_mgr *msn_mgr)
{
	unsigned long flag;

	spin_lock_irqsave(&msn_mgr->msn_hlist_lock, flag);
	hlist_del(&msn_node->node);
	kfree(msn_node);
	spin_unlock_irqrestore(&msn_mgr->msn_hlist_lock, flag);
}

/* init retransmit buffer */
static struct ubmad_ini_rtbuffer *ubmad_create_ini_rtbuffer(
				struct ubmad_tjetty *tjetty, uint64_t msn)
{
	struct ubmad_ini_rtbuffer *ini_rt_buffer;
	unsigned long flag;
	uint32_t hash;

	ini_rt_buffer = kzalloc(sizeof(struct ubmad_ini_rtbuffer), GFP_KERNEL);
	if (IS_ERR_OR_NULL(ini_rt_buffer))
		return NULL;

	ini_rt_buffer->msn = msn;
	INIT_HLIST_NODE(&ini_rt_buffer->node);

	hash = jhash(&msn, sizeof(uint64_t), 0) % UBMAD_INI_RTBUFFER_SIZE;
	spin_lock_irqsave(&tjetty->ini_rt_spinlock, flag);
	hlist_add_head(&ini_rt_buffer->node, &tjetty->ini_rt_hlist[hash]);
	spin_unlock_irqrestore(&tjetty->ini_rt_spinlock, flag);

	return ini_rt_buffer;
}

static struct ubmad_ini_rtbuffer *ubmad_get_ini_rtbuffer(
					struct ubmad_tjetty *tjetty, uint64_t msn)
{
	struct ubmad_ini_rtbuffer *cur;
	unsigned long flag;
	struct hlist_node *next;
	uint32_t hash;

	hash = jhash(&msn, sizeof(uint64_t), 0) % UBMAD_INI_RTBUFFER_SIZE;
	spin_lock_irqsave(&tjetty->ini_rt_spinlock, flag);
	hlist_for_each_entry_safe(cur, next, &tjetty->ini_rt_hlist[hash], node) {
		if (cur->msn == msn) {
			spin_unlock_irqrestore(&tjetty->ini_rt_spinlock, flag);
			return cur;
		}
	}
	spin_unlock_irqrestore(&tjetty->ini_rt_spinlock, flag);
	return NULL;
}

static void ubmad_release_ini_rtbuffer(
					struct ubmad_tjetty *tjetty, uint64_t msn)
{
	struct ubmad_ini_rtbuffer *cur;
	unsigned long flag;
	struct hlist_node *next;
	uint32_t hash;

	hash = jhash(&msn, sizeof(uint64_t), 0) % UBMAD_INI_RTBUFFER_SIZE;
	spin_lock_irqsave(&tjetty->ini_rt_spinlock, flag);
	hlist_for_each_entry_safe(cur, next, &tjetty->ini_rt_hlist[hash], node) {
		if (cur->msn == msn) {
			hlist_del(&cur->node);
			kfree(cur);
			spin_unlock_irqrestore(&tjetty->ini_rt_spinlock, flag);
			return;
		}
	}
	spin_unlock_irqrestore(&tjetty->ini_rt_spinlock, flag);
	ubcore_log_err("Failed to release ini rtbuffer: already releasd.\n");
}

/* target retransmit buffer hash node */
static struct ubmad_tgt_hash_node *ubmad_create_tgt_hash_node(
				struct ubmad_tjetty *tjetty, uint64_t msn)
{
	struct ubmad_tgt_hash_node *tgt_hash_node;
	unsigned long flag;
	uint32_t hash;

	tgt_hash_node = kzalloc(sizeof(struct ubmad_tgt_hash_node), GFP_KERNEL);
	if (IS_ERR_OR_NULL(tgt_hash_node))
		return NULL;

	tgt_hash_node->msn = msn;
	tgt_hash_node->idx = atomic64_fetch_inc(&tjetty->tgt_idx_gen);

	INIT_HLIST_NODE(&tgt_hash_node->node);

	hash = jhash(&msn, sizeof(uint64_t), 0) % UBMAD_TGT_HASH_SIZE;
	spin_lock_irqsave(&tjetty->tgt_hash_lock, flag);
	hlist_add_head(&tgt_hash_node->node, &tjetty->tgt_hash_hlist[hash]);
	spin_unlock_irqrestore(&tjetty->tgt_hash_lock, flag);

	return tgt_hash_node;
}

static struct ubmad_tgt_hash_node *ubmad_get_tgt_hash_node(
					struct ubmad_tjetty *tjetty, uint64_t msn)
{
	struct ubmad_tgt_hash_node *cur;
	unsigned long flag;
	struct hlist_node *next;
	uint32_t hash;

	hash = jhash(&msn, sizeof(uint64_t), 0) % UBMAD_TGT_HASH_SIZE;
	spin_lock_irqsave(&tjetty->tgt_hash_lock, flag);
	hlist_for_each_entry_safe(cur, next, &tjetty->tgt_hash_hlist[hash], node) {
		if (cur->msn == msn) {
			spin_unlock_irqrestore(&tjetty->tgt_hash_lock, flag);
			return cur;
		}
	}
	spin_unlock_irqrestore(&tjetty->tgt_hash_lock, flag);
	return NULL;
}

static void ubmad_release_tgt_hash_node(
					struct ubmad_tjetty *tjetty, uint64_t msn)
{
	struct ubmad_tgt_hash_node *cur;
	unsigned long flag;
	struct hlist_node *next;
	uint32_t hash;

	hash = jhash(&msn, sizeof(uint64_t), 0) % UBMAD_TGT_HASH_SIZE;
	spin_lock_irqsave(&tjetty->tgt_hash_lock, flag);
	hlist_for_each_entry_safe(cur, next, &tjetty->tgt_hash_hlist[hash], node) {
		if (cur->msn == msn) {
			hlist_del(&cur->node);
			kfree(cur);
			spin_unlock_irqrestore(&tjetty->tgt_hash_lock, flag);
			return;
		}
	}
	spin_unlock_irqrestore(&tjetty->tgt_hash_lock, flag);
	ubcore_log_err("Failed to release tgt hash: already releasd.\n");
}

/* repost send conn data */
static int ubmad_repost_send_conn_data(struct ubmad_rt_work *rt_work)
{
	struct ubmad_jetty_resource *rsrc = rt_work->rsrc;
	union ubcore_eid dst = rt_work->dst;
	struct ubmad_tjetty *tjetty = ubmad_get_tjetty(&dst, rsrc);
	uint64_t msn = rt_work->msn;
	int ret = 0;

	if (IS_ERR_OR_NULL(tjetty))
		return -1;

	uint32_t sge_idx;
	uint64_t sge_addr;
	struct ubcore_jetty *jetty = rsrc->jetty;
	struct ubcore_sge sge = { 0 };
	struct ubcore_jfs_wr jfs_wr = { 0 };
	struct ubcore_jfs_wr *jfs_bad_wr = NULL;

	/* make segment */
	sge_idx = ubmad_bitmap_get_id(rsrc->send_seg_bitmap);
	if (sge_idx >= rsrc->send_seg_bitmap->size) {
		ubcore_log_err("get sge_idx failed\n");
		ubmad_put_tjetty(tjetty);
		return -1;
	}
	sge_addr = rsrc->send_seg->seg.ubva.va + UBMAD_SGE_MAX_LEN * sge_idx;

	/* make message */
	struct ubmad_ini_rtbuffer *rtbuffer = ubmad_get_ini_rtbuffer(tjetty, msn);

	if (IS_ERR_OR_NULL(rtbuffer)) {
		ubcore_log_err("Failed to get rtbuffer in repost.\n");
		goto repost_put_id;
	}
	memcpy((void *)sge_addr, rtbuffer->data, rtbuffer->payload_len);

	/* make work request */
	jfs_wr.opcode = UBCORE_OPC_SEND;
	jfs_wr.tjetty = tjetty->tjetty;
	sge.addr = sge_addr;
	sge.len = rtbuffer->payload_len;
	sge.tseg = rsrc->send_seg;
	jfs_wr.send.src.sge = &sge;
	jfs_wr.send.src.num_sge = 1;
	jfs_wr.user_ctx = sge_addr;
	jfs_wr.flag.bs.complete_enable = 1;

	if (atomic_fetch_add(1, &rsrc->tx_in_queue) >= UBMAD_TX_THREDSHOLD) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_err("Invalid threshold, tx_in_queue: %u.\n",
			     (uint32_t)atomic_read(&rsrc->tx_in_queue));
		ret = -1;
		goto repost_put_id;
	}
	ret = ubcore_post_jetty_send_wr(jetty, &jfs_wr, &jfs_bad_wr);
	if (ret != 0) {
		ubcore_log_err("ubcore post send failed. msn %llu eid " EID_FMT
			     "\n", msn, EID_ARGS(dst));
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		goto repost_put_id;
	}
	return 0;

repost_put_id:
	ubmad_put_tjetty(tjetty);
	(void)ubmad_bitmap_put_id(rsrc->send_seg_bitmap, sge_idx);
	return -1;
}

static int ubmad_try_repost_all_response(
						struct ubmad_jetty_resource *rsrc,
						union ubcore_eid *dst, uint64_t msn)
{
	struct ubmad_tjetty *tjetty = ubmad_get_tjetty(dst, rsrc);
	int ret = 0;

	if (IS_ERR_OR_NULL(tjetty))
		return -1;
	struct ubmad_tgt_hash_node *hash_node = ubmad_get_tgt_hash_node(
										tjetty, msn);

	if (IS_ERR_OR_NULL(hash_node)) {
		hash_node = ubmad_create_tgt_hash_node(tjetty, msn);
		ubmad_put_tjetty(tjetty);
		return -2;
	}
	int idx = (hash_node->idx & UBMAD_TGT_RTBUFFER_MASK);

	// msn + 1 means resp buffer overflow, direct pass req to adaptor
	if (tjetty->tgt_rt_buffer[idx].msn != msn) {
		if (tjetty->tgt_rt_buffer[idx].msn == msn + 1)
			ret = -2;
		ubmad_put_tjetty(tjetty);
		return ret;
	}

	uint32_t sge_idx;
	uint64_t sge_addr;
	struct ubcore_jetty *jetty = rsrc->jetty;
	struct ubcore_sge sge = { 0 };
	struct ubcore_jfs_wr jfs_wr = { 0 };
	struct ubcore_jfs_wr *jfs_bad_wr = NULL;

	/* make segment */
	sge_idx = ubmad_bitmap_get_id(rsrc->send_seg_bitmap);
	if (sge_idx >= rsrc->send_seg_bitmap->size) {
		ubcore_log_err("get sge_idx failed\n");
		return -1;
	}
	sge_addr = rsrc->send_seg->seg.ubva.va + UBMAD_SGE_MAX_LEN * sge_idx;

	/* make message */
	memcpy((void *)sge_addr, tjetty->tgt_rt_buffer[idx].data,
						tjetty->tgt_rt_buffer[idx].payload_len);

	/* make work request */
	jfs_wr.opcode = UBCORE_OPC_SEND;
	jfs_wr.tjetty = tjetty->tjetty;
	sge.addr = sge_addr;
	sge.len = tjetty->tgt_rt_buffer[idx].payload_len;
	sge.tseg = rsrc->send_seg;
	jfs_wr.send.src.sge = &sge;
	jfs_wr.send.src.num_sge = 1;
	jfs_wr.user_ctx = sge_addr;
	jfs_wr.flag.bs.complete_enable = 1;

	if (atomic_fetch_add(1, &rsrc->tx_in_queue) >= UBMAD_TX_THREDSHOLD) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_err("Invalid threshold, tx_in_queue: %u.\n",
			     (uint32_t)atomic_read(&rsrc->tx_in_queue));
		ret = -1;
		goto repost_resp_put_id;
	}
	ret = ubcore_post_jetty_send_wr(jetty, &jfs_wr, &jfs_bad_wr);
	if (ret != 0) {
		ubcore_log_err("ubcore post send failed. msn %llu eid " EID_FMT
			     "\n", msn, EID_ARGS(*dst));
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		goto repost_resp_put_id;
	}
	return 0;

repost_resp_put_id:
	(void)ubmad_bitmap_put_id(rsrc->send_seg_bitmap, sge_idx);
	return -1;
}

/* retransmission work */
static void ubmad_rt_work_handler(struct work_struct *work)
{
	struct delayed_work *delay_work =
		container_of(work, struct delayed_work, work);
	struct ubmad_rt_work *rt_work =
		container_of(delay_work, struct ubmad_rt_work, delay_work);

	struct ubmad_jetty_resource *rsrc = rt_work->rsrc;
	struct ubmad_msn_mgr *msn_mgr = rt_work->msn_mgr;
	union ubcore_eid *dst = &(rt_work->dst);

	unsigned long flag;
	struct ubmad_msn_node *cur;
	struct hlist_node *next;
	uint32_t hash = jhash(&rt_work->msn, sizeof(uint64_t), 0) %
			UBMAD_MSN_HLIST_SIZE;
	bool found = false;

	// try to find msn_node
	spin_lock_irqsave(&msn_mgr->msn_hlist_lock, flag);
	hlist_for_each_entry_safe(cur, next, &msn_mgr->msn_hlist[hash], node) {
		if (cur->msn == rt_work->msn) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&msn_mgr->msn_hlist_lock, flag);

	// found indicates not ack. Need to repost
	if (found) {
		rt_work->rt_cnt++;
		if (ubmad_repost_send_conn_data(rt_work) == 0 &&
				rt_work->rt_cnt <= UBMAD_MAX_RETRY_CNT) {
			if (queue_delayed_work(rt_work->rt_wq, &rt_work->delay_work,
						msecs_to_jiffies(1 << rt_work->rt_cnt)) != true) {
				ubcore_log_err("queue rt work failed\n");
				kfree(rt_work);
			}
			return;
		}
	}

	struct ubmad_tjetty *tjetty = ubmad_get_tjetty(dst, rsrc);

	if (!IS_ERR_OR_NULL(tjetty))
		ubmad_release_ini_rtbuffer(tjetty, rt_work->msn);

	ubcore_log_info_rl("Do not repost, found: %u, rt_work->rt_cnt: %u.\n",
		      (uint32_t)found, rt_work->rt_cnt);

	ubmad_put_tjetty(tjetty);
	kfree(rt_work);
}

struct ubmad_rt_work *ubmad_create_rt_work(struct workqueue_struct *rt_wq,
					   struct ubmad_msn_mgr *msn_mgr, uint64_t msn,
					   union ubcore_eid dst,
					   struct ubmad_jetty_resource *rsrc)
{
	struct ubmad_rt_work *rt_work;

	rt_work = kzalloc(sizeof(struct ubmad_rt_work),
			  GFP_KERNEL); // free in ubmad_rt_work_handler()
	if (IS_ERR_OR_NULL(rt_work))
		return ERR_PTR(-ENOMEM);
	rt_work->msn = msn;
	rt_work->msn_mgr = msn_mgr;
	rt_work->rsrc = rsrc;
	rt_work->dst = dst;
	rt_work->rt_wq = rt_wq;
	rt_work->rt_cnt = 1;

	INIT_DELAYED_WORK(&rt_work->delay_work, ubmad_rt_work_handler);
	if (queue_delayed_work(rt_wq, &rt_work->delay_work,
			       msecs_to_jiffies(2)) != true) {
		ubcore_log_err("queue rt work failed\n");
		kfree(rt_work);
		return NULL;
	}

	return rt_work;
}

/** post **/
// prepare msg to send
static int ubmad_prepare_msg(uint64_t sge_addr, struct ubmad_send_buf *send_buf,
			     uint32_t msn, struct ubcore_jetty *jetty,
			     struct ubmad_tjetty *tjetty)
{
	struct ubmad_msg *msg = (struct ubmad_msg *)sge_addr;

	if (sizeof(struct ubmad_msg) + send_buf->payload_len >
	    UBMAD_SGE_MAX_LEN) {
		ubcore_log_err(
			"msg header %lu + payload_len %u exceeds sge max length %u\n",
			sizeof(struct ubmad_msg), send_buf->payload_len,
			UBMAD_SGE_MAX_LEN);
		return -EINVAL;
	}

	msg->version = UBMAD_MSG_VERSION_0;
	msg->msn = msn;
	msg->msg_type = send_buf->msg_type;
	msg->payload_len = send_buf->payload_len;
	if (send_buf->msg_type == UBMAD_UBC_CONN_REQ ||
	    send_buf->msg_type == UBMAD_UBC_CONN_RESP ||
		send_buf->msg_type == UBMAD_UBC_SINGLE_REQ)
		// send_buf will be freed by cm. mad needs to memcpy user data to send sge.
		(void)memcpy((void *)msg->payload, send_buf->payload,
			     send_buf->payload_len);

	return 0;
}

static int ubmad_do_post_send_conn_data(struct ubcore_jetty *jetty,
					struct ubmad_tjetty *tjetty,
					struct ubcore_jfs_wr *jfs_wr,
					struct workqueue_struct *rt_wq,
					struct ubmad_jetty_resource *rsrc)
{
	uint64_t sge_addr = jfs_wr->send.src.sge->addr;
	uint32_t pld_len = jfs_wr->send.src.sge->len;
	struct ubmad_msg *msg = (struct ubmad_msg *)sge_addr;
	uint64_t msn = msg->msn;
	union ubcore_eid *dst_eid = &tjetty->tjetty->cfg.id.eid;

	struct ubmad_msn_node *msn_node;
	struct ubcore_jfs_wr *jfs_bad_wr = NULL;

	int ret;

	/* create msn_node before post to avoid recv ack before msn_node created and wrongly trigger
	 * fast retransmission.
	 */
	msn_node = ubmad_create_msn_node(msn, &tjetty->msn_mgr);
	if (IS_ERR_OR_NULL(msn_node)) {
		ubcore_log_err("create msn_node failed. msn %llu eid " EID_FMT
			     "\n",
			     msn, EID_ARGS(*dst_eid));
		return -1;
	}

	if (atomic_fetch_add(1, &rsrc->tx_in_queue) >= UBMAD_TX_THREDSHOLD) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_err("Invalid threshold, tx_in_queue: %u.\n",
			     (uint32_t)atomic_read(&rsrc->tx_in_queue));
		ret = -1;
		goto destroy_msn_node;
	}
	ret = ubcore_post_jetty_send_wr(jetty, jfs_wr, &jfs_bad_wr);
	if (ret != 0) {
		ubcore_log_err("ubcore post send failed. msn %llu eid " EID_FMT
			     "\n",
			     msn, EID_ARGS(*dst_eid));
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		goto destroy_msn_node;
	}

	struct ubmad_rt_work *rt_work = ubmad_create_rt_work(rt_wq,
			&tjetty->msn_mgr, msn, tjetty->tjetty->cfg.id.eid, rsrc);

	if (IS_ERR_OR_NULL(rt_work))
		ubcore_log_err("Failed to create the first rt_work. msn %llu.\n", msn);
	else if (pld_len <= UBMAD_RTBUFFER_PKTSIZE) {
		struct ubmad_ini_rtbuffer *rtbuffer = ubmad_create_ini_rtbuffer(tjetty, msn);

		if (IS_ERR_OR_NULL(rtbuffer))
			ubcore_log_err("Failed to create rtbuffer.\n");
		else {
			rtbuffer->payload_len = pld_len;
			memcpy(rtbuffer->data, (void *)sge_addr, pld_len);
		}
	} else
		ubcore_log_err("Failed to create rtbuffer, packet size too large.\n");

	ubcore_log_info_rl("send conn data successfully. msn %llu eid " EID_FMT "\n",
		      msn, EID_ARGS(*dst_eid));
	return 0;

destroy_msn_node:
	ubmad_destroy_msn_node(msn_node, &tjetty->msn_mgr);
	return ret;
}

static int ubmad_do_post_send_conn_resp_data(struct ubcore_jetty *jetty,
					struct ubmad_tjetty *tjetty,
					struct ubcore_jfs_wr *jfs_wr,
					struct workqueue_struct *rt_wq,
					struct ubmad_jetty_resource *rsrc)
{
	uint64_t sge_addr = jfs_wr->send.src.sge->addr;
	uint32_t pld_len = jfs_wr->send.src.sge->len;
	struct ubmad_msg *msg = (struct ubmad_msg *)sge_addr;
	uint64_t msn = msg->msn;
	union ubcore_eid *dst_eid = &tjetty->tjetty->cfg.id.eid;
	struct ubcore_jfs_wr *jfs_bad_wr = NULL;
	int ret;

	if (atomic_fetch_add(1, &rsrc->tx_in_queue) >= UBMAD_TX_THREDSHOLD) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_err("Invalid threshold, tx_in_queue: %u.\n",
			     (uint32_t)atomic_read(&rsrc->tx_in_queue));
		return -1;
	}
	ret = ubcore_post_jetty_send_wr(jetty, jfs_wr, &jfs_bad_wr);
	if (ret != 0) {
		ubcore_log_err("ubcore post send failed. msn %llu eid " EID_FMT
			     "\n",
			     msn, EID_ARGS(*dst_eid));
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		return -1;
	}

	struct ubmad_tgt_hash_node *tgt_hash_node = ubmad_get_tgt_hash_node(tjetty, msn);

	if (IS_ERR_OR_NULL(tgt_hash_node)) {
		ubcore_log_err("get resp target hash node failed, msn %llu.\n", msn);
		return -1;
	}

	uint64_t hash_idx = (tgt_hash_node->idx & UBMAD_TGT_RTBUFFER_MASK);

	if (tjetty->tgt_rt_buffer[hash_idx].msn != msn && pld_len <= UBMAD_RTBUFFER_PKTSIZE) {
		ubmad_release_tgt_hash_node(tjetty, tjetty->tgt_rt_buffer[hash_idx].msn);
		tjetty->tgt_rt_buffer[hash_idx].msn = msn;
		tjetty->tgt_rt_buffer[hash_idx].payload_len = pld_len;
		memcpy(tjetty->tgt_rt_buffer[hash_idx].data, (void *)sge_addr, pld_len);
	}

	// set rt_buffer.msn to msn + 1 means direct pass req to adaptor
	if (pld_len > UBMAD_RTBUFFER_PKTSIZE)
		tjetty->tgt_rt_buffer[hash_idx].msn = msn + 1;

	ubcore_log_info_rl("send conn resp data successfully. msn %llu eid " EID_FMT "\n",
		      msn, EID_ARGS(*dst_eid));
	return 0;
}

static int ubmad_do_post_send_conn_single(struct ubcore_jetty *jetty,
					struct ubmad_tjetty *tjetty,
					struct ubcore_jfs_wr *jfs_wr,
					struct workqueue_struct *rt_wq,
					struct ubmad_jetty_resource *rsrc)
{
	uint64_t sge_addr = jfs_wr->send.src.sge->addr;
	struct ubmad_msg *msg = (struct ubmad_msg *)sge_addr;
	uint64_t msn = msg->msn;
	union ubcore_eid *dst_eid = &tjetty->tjetty->cfg.id.eid;
	struct ubcore_jfs_wr *jfs_bad_wr = NULL;
	int ret;

	if (atomic_fetch_add(1, &rsrc->tx_in_queue) >= UBMAD_TX_THREDSHOLD) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_err("Invalid threshold, tx_in_queue: %u.\n",
			     (uint32_t)atomic_read(&rsrc->tx_in_queue));
		return -1;
	}
	ret = ubcore_post_jetty_send_wr(jetty, jfs_wr, &jfs_bad_wr);
	if (ret != 0) {
		ubcore_log_err("ubcore post send failed. msn %llu eid " EID_FMT
			     "\n",
			     msn, EID_ARGS(*dst_eid));
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		return -1;
	}

	ubcore_log_info_rl("send conn single successfully. msn %llu eid " EID_FMT "\n",
		      msn, EID_ARGS(*dst_eid));
	return 0;
}

static int ubmad_do_post_send(struct ubmad_jetty_resource *rsrc,
			      struct ubmad_tjetty *tjetty,
			      struct ubmad_send_buf *send_buf, uint64_t msn,
			      struct workqueue_struct *rt_wq)
{
	uint32_t sge_idx;
	uint64_t sge_addr;
	struct ubcore_jetty *jetty = rsrc->jetty;
	struct ubmad_msg *msg;

	struct ubcore_sge sge = { 0 };
	struct ubcore_jfs_wr jfs_wr = { 0 };

	int ret;

	/* prepare */
	/* get sge
	 * data msg sge id put in ubmad_rt_work_handler().
	 * ack sge id put in ubmad_send_work_handler()
	 */
	sge_idx = ubmad_bitmap_get_id(rsrc->send_seg_bitmap);
	if (sge_idx >= rsrc->send_seg_bitmap->size) {
		ubcore_log_err("get sge_idx failed\n");
		return -1;
	}
	sge_addr = rsrc->send_seg->seg.ubva.va + UBMAD_SGE_MAX_LEN * sge_idx;

	// prepare msg, msg stored in sge
	ret = ubmad_prepare_msg(sge_addr, send_buf, msn, jetty, tjetty);
	if (ret != 0) {
		ubcore_log_err("prepare msg failed. ret %d payload_len %u\n", ret,
			     send_buf->payload_len);
		goto put_id;
	}

	// prepare wr
	jfs_wr.opcode = UBCORE_OPC_SEND;
	jfs_wr.tjetty = tjetty->tjetty;
	sge.addr = sge_addr;
	sge.len = send_buf->payload_len +
		  sizeof(struct ubmad_msg); // only need to send data len
	sge.tseg = rsrc->send_seg;
	jfs_wr.send.src.sge = &sge;
	jfs_wr.send.src.num_sge = 1;
	jfs_wr.user_ctx = sge_addr;
	jfs_wr.flag.bs.complete_enable = 1;

	/* post */
	msg = (struct ubmad_msg *)sge_addr;
	switch (msg->msg_type) {
	case UBMAD_UBC_CONN_REQ:
		ret = ubmad_do_post_send_conn_data(jetty, tjetty, &jfs_wr,
						   rt_wq, rsrc);
		break;
	case UBMAD_UBC_CONN_RESP:
		ret = ubmad_do_post_send_conn_resp_data(jetty, tjetty, &jfs_wr,
						   rt_wq, rsrc);
		break;
	case UBMAD_UBC_SINGLE_REQ:
		ret = ubmad_do_post_send_conn_single(jetty, tjetty, &jfs_wr,
						   rt_wq, rsrc);
		break;
	default:
		ubcore_log_err("invalid msg_type %d\n", msg->msg_type);
		ret = -EINVAL;
	}
	if (ret != 0) {
		ubcore_log_err("post send failed. msg type %d ret %d\n",
			     msg->msg_type, ret);
		goto put_id;
	}

	return 0;

put_id:
	(void)ubmad_bitmap_put_id(rsrc->send_seg_bitmap, sge_idx);
	return ret;
}

// for UBMAD_CONN_DATA, UBMAD_AUTHN_DATA
static void ubmad_jetty_work_handler(struct work_struct *work)
{
	struct ubmad_jetty_work *jetty_work = container_of(work, struct ubmad_jetty_work, work);
	struct ubmad_tjetty *wk_tjetty;
	int ret;

	wk_tjetty = ubmad_import_jetty(jetty_work->dev_priv->device, jetty_work->rsrc,
		&jetty_work->dst_primary_eid);
	if (IS_ERR_OR_NULL(wk_tjetty)) {
		ubcore_log_err("import jetty failed. eid " EID_FMT "\n",
			     EID_ARGS(jetty_work->dst_primary_eid));
		goto put_device_priv;
	}
	/* post send */
	ret = ubmad_do_post_send(
		jetty_work->rsrc, wk_tjetty, jetty_work->send_buf,
		jetty_work->send_buf->session_id,
		jetty_work->dev_priv->rt_wq);
	if (ret != 0)
		ubcore_log_err("do post send failed, ret: %d\n", ret);

	ubmad_put_tjetty(wk_tjetty);

put_device_priv:
	ubmad_put_device_priv(jetty_work->dev_priv);
	kfree(jetty_work->send_buf);
	kfree(jetty_work);
}

int ubmad_post_send(struct ubcore_device *device,
		    struct ubmad_send_buf *send_buf,
		    struct ubmad_send_buf **bad_send_buf)
{
	struct ubmad_device_priv *dev_priv = NULL;
	struct ubmad_jetty_resource *rsrc;
	union ubcore_eid dst_primary_eid = { 0 };
	struct ubmad_jetty_work *jetty_work;
	struct ubmad_send_buf *jetty_send_buf;
	int ret;

	dev_priv = ubmad_get_device_priv(device); // put in ubmad_jetty_work_handler()
	if (IS_ERR_OR_NULL(dev_priv)) {
		ubcore_log_err("Failed to get dev_priv, dev_name: %s.\n",
			     device->dev_name);
		return -1;
	}
	if (!dev_priv->valid) {
		ubcore_log_err("dev_priv rsrc not inited. dev_name: %s.\n",
			     device->dev_name);
		ret = -1;
		goto put_device_priv;
	}

	switch (send_buf->msg_type) {
	case UBMAD_UBC_CONN_REQ:
		rsrc = &dev_priv->jetty_rsrc[0];
		break;
	case UBMAD_UBC_CONN_RESP:
		rsrc = &dev_priv->jetty_rsrc[0];
		break;
	case UBMAD_UBC_SINGLE_REQ:
		rsrc = &dev_priv->jetty_rsrc[0];
		break;
	case UBMAD_AUTHN_DATA:
		rsrc = &dev_priv->jetty_rsrc[1];
		break;
	default:
		ubcore_log_err("Invalid msg_type: %d.\n",
			     (int)send_buf->msg_type);
		ret = -EINVAL;
		goto put_device_priv;
	}

	/* import well-known jetty */
	// unimport in ubmad_uninit_jetty_rsrc()
	ret = ubcore_get_main_primary_eid(&send_buf->dst_eid, &dst_primary_eid);
	if (ret != 0) {
		ubcore_log_err("get primary eid failed\n");
		goto put_device_priv;
	}

	jetty_work = kcalloc(1, sizeof(struct ubmad_jetty_work), GFP_KERNEL);
	if (IS_ERR_OR_NULL(jetty_work)) {
		ret = -ENOMEM;
		goto put_device_priv;
	}
	jetty_send_buf = kcalloc(1, sizeof(struct ubmad_send_buf) + send_buf->payload_len,
		GFP_KERNEL);
	if (IS_ERR_OR_NULL(jetty_send_buf)) {
		ret = -ENOMEM;
		kfree(jetty_work);
		goto put_device_priv;
	}
	(void)memcpy(jetty_send_buf, send_buf,
		sizeof(struct ubmad_send_buf) + send_buf->payload_len);

	jetty_work->dev_priv = dev_priv;
	jetty_work->rsrc = rsrc;
	jetty_work->dst_primary_eid = dst_primary_eid;
	jetty_work->send_buf = jetty_send_buf;

	INIT_WORK(&jetty_work->work, ubmad_jetty_work_handler);
	ret = queue_work(dev_priv->conn_wq, &jetty_work->work);
	if (!ret) {
		ubcore_log_err("queue work failed. ret %d\n", ret);
		kfree(jetty_send_buf);
		kfree(jetty_work);
		goto put_device_priv;
	}
	return 0;

put_device_priv:
	ubmad_put_device_priv(dev_priv);
	return ret;
}

void ubmad_post_send_close_req(struct ubmad_jetty_resource *rsrc,
			       struct ubcore_tjetty *tjetty)
{
	struct ubcore_jfs_wr *jfs_bad_wr = NULL;
	struct ubcore_jfs_wr jfs_wr = { 0 };
	struct ubcore_sge sge = { 0 };
	struct ubmad_msg *msg;
	uint64_t sge_addr;
	uint32_t sge_idx;
	int ret;

	if (atomic_fetch_add(1, &rsrc->tx_in_queue) >= UBMAD_TX_THREDSHOLD) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_err("Invalid threshold, tx_in_queue: %u.\n",
			     (uint32_t)atomic_read(&rsrc->tx_in_queue));
		return;
	}

	sge_idx = ubmad_bitmap_get_id(rsrc->send_seg_bitmap);
	if (sge_idx >= rsrc->send_seg_bitmap->size) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_err("Failed to get sge_idx: %u.\n", sge_idx);
		return;
	}

	sge_addr = rsrc->send_seg->seg.ubva.va + UBMAD_SGE_MAX_LEN * sge_idx;
	msg = (struct ubmad_msg *)sge_addr;
	msg->version = UBMAD_MSG_VERSION_0;
	msg->msg_type = UBMAD_CLOSE_REQ;
	msg->payload_len = 0;
	msg->msn = 0; // UBMAD_CLOSE_REQ is unreliable, msn does not work

	sge.addr = sge_addr;
	sge.len = (uint32_t)sizeof(struct ubmad_msg);
	sge.tseg = rsrc->send_seg;
	jfs_wr.opcode = UBCORE_OPC_SEND;
	jfs_wr.tjetty = tjetty;
	jfs_wr.send.src.sge = &sge;
	jfs_wr.send.src.num_sge = 1;

	ret = ubcore_post_jetty_send_wr(rsrc->jetty, &jfs_wr, &jfs_bad_wr);
	if (ret != 0) {
		atomic_fetch_sub(1, &rsrc->tx_in_queue);
		ubcore_log_warn(
			"Failed to send close request, ret: %d, jetty_id: %u.\n",
			ret, rsrc->jetty->jetty_id.id);
	}
}

/*
 * 1. fill up jfr in ubmad_open_device() for first post_send of each jetty0 pair.
 * 2. supplement one consumed wqe to jfr after poll jfc_r in ubmad_jfce_handler_r().
 * 3. this function is private and in ubmad range.
 */
int ubmad_post_recv(struct ubmad_jetty_resource *rsrc)
{
	uint32_t sge_idx;
	uint64_t sge_addr;
	struct ubcore_sge sge = { 0 };
	struct ubcore_jfr_wr jfr_wr = { 0 };
	struct ubcore_jfr_wr *jfr_bad_wr = NULL;
	int ret;

	sge_idx = ubmad_bitmap_get_id(
		rsrc->recv_seg_bitmap); // put in ubmad_recv_work_handler()
	if (sge_idx >= rsrc->recv_seg_bitmap->size) {
		ubcore_log_err("get sge_idx failed\n");
		return -1;
	}
	sge_addr = rsrc->recv_seg->seg.ubva.va + UBMAD_SGE_MAX_LEN * sge_idx;

	sge.addr = sge_addr;
	sge.len = UBMAD_SGE_MAX_LEN;
	sge.tseg = rsrc->recv_seg;
	jfr_wr.src.sge = &sge;
	jfr_wr.src.num_sge = 1;
	jfr_wr.user_ctx = sge_addr;
	ret = ubcore_post_jetty_recv_wr(rsrc->jetty, &jfr_wr, &jfr_bad_wr);
	if (ret != 0) {
		ubcore_log_err("ubcore post recv failed. ret %d\n", ret);
		return ret;
	}

	return 0;
}

/** poll **/
/* process msg after recv */
static int ubmad_cm_process_msg(struct ubcore_cr *cr,
				union ubcore_eid *local_eid,
				struct ubmad_msg *msg,
				struct ubmad_agent_priv *agent_priv)
{
	struct ubmad_recv_cr recv_cr = { 0 };

	recv_cr.cr = cr;
	recv_cr.local_eid = *local_eid;
	/* only UBMAD_UBC_CONN_REQ valid for recv_handler */
	recv_cr.msg_type = UBMAD_UBC_CONN_REQ;
	recv_cr.payload = (uint64_t)msg->payload;
	recv_cr.payload_len = msg->payload_len;

	if (agent_priv->agent.recv_handler != NULL &&
	    agent_priv->agent.recv_handler(&agent_priv->agent, &recv_cr) != 0) {
		ubcore_log_err("recv_handler exec failed\n");
		return -1;
	}

	return 0;
}

static int ubmad_process_conn_data(struct ubcore_cr *cr,
				   struct ubmad_jetty_resource *rsrc,
				   struct ubmad_device_priv *dev_priv,
				   struct ubmad_agent_priv *agent_priv)
{
	struct ubmad_msg *msg = (struct ubmad_msg *)cr->user_ctx;
	union ubcore_eid *seid = &cr->remote_id.eid;
	int ret = 0;

	ubcore_log_info_rl(
		"Finish to recv request. msn %llu, seid " EID_FMT
		"\n", msg->msn, EID_ARGS(*seid));

	ret = ubmad_try_repost_all_response(rsrc, seid, msg->msn);

	if (ret == -1) {
		ubcore_log_err("try to repost response failed, msn = %llu, seid"
						EID_FMT "\n", msg->msn, EID_ARGS(*seid));
		return ret;
	}

	if (ret == 0)
		return ret;

	ret = ubmad_cm_process_msg(cr, &rsrc->jetty->jetty_id.eid, msg,
				   agent_priv);
	if (ret != 0)
		ubcore_log_err("cm process msg failed. msn %llu, seid " EID_FMT
			     "\n", msg->msn, EID_ARGS(*seid));
	return ret;
}

static int ubmad_process_conn_resp(struct ubcore_cr *cr,
				   struct ubmad_jetty_resource *rsrc,
				   struct ubmad_device_priv *dev_priv,
				   struct ubmad_agent_priv *agent_priv)
{
	struct ubmad_msg *msg = (struct ubmad_msg *)cr->user_ctx;
	union ubcore_eid *seid = &cr->remote_id.eid;
	struct ubmad_tjetty *tjetty;
	int ret;
	struct ubmad_msn_mgr *msn_mgr;
	unsigned long flag;
	struct ubmad_msn_node *cur;
	struct hlist_node *next;
	uint32_t hash =
		jhash(&msg->msn, sizeof(uint64_t), 0) % UBMAD_MSN_HLIST_SIZE;

	tjetty = ubmad_get_tjetty(seid, rsrc); // put below
	if (IS_ERR_OR_NULL(tjetty)) {
		ubcore_log_err("get tjetty failed. eid " EID_FMT "\n",
			     EID_ARGS(*seid));
		return -EINVAL;
	}

	// try to remove msn_node from msn_hlist
	msn_mgr = &tjetty->msn_mgr;
	spin_lock_irqsave(&msn_mgr->msn_hlist_lock, flag);
	hlist_for_each_entry_safe(cur, next, &msn_mgr->msn_hlist[hash], node) {
		if (cur->msn == msg->msn) {
			hlist_del(&cur->node);
			kfree(cur);
			spin_unlock_irqrestore(&msn_mgr->msn_hlist_lock, flag);
			goto effective_resp;
		}
	}
	spin_unlock_irqrestore(&msn_mgr->msn_hlist_lock, flag);
	ubmad_put_tjetty(tjetty);

	// msn_node not in msn_hlist, indicates already removed by previous ack with same msn
	ubcore_log_info_rl("redundant ack. msn %llu seid " EID_FMT "\n", msg->msn,
		      EID_ARGS(*seid));
	return -1;

effective_resp:
	ret = ubmad_cm_process_msg(cr, &rsrc->jetty->jetty_id.eid, msg,
				   agent_priv);

	ubmad_put_tjetty(tjetty);
	ubcore_log_info_rl("recv conn resp. msn %llu seid " EID_FMT "\n", msg->msn,
		      EID_ARGS(*seid));
	return ret;
}

static int ubmad_process_conn_single(struct ubcore_cr *cr,
				   struct ubmad_jetty_resource *rsrc,
				   struct ubmad_device_priv *dev_priv,
				   struct ubmad_agent_priv *agent_priv)
{
	struct ubmad_msg *msg = (struct ubmad_msg *)cr->user_ctx;
	union ubcore_eid *seid = &cr->remote_id.eid;
	struct ubmad_tjetty *tjetty;

	tjetty = ubmad_get_tjetty(seid, rsrc); // put below
	if (IS_ERR_OR_NULL(tjetty)) {
		ubcore_log_err("get tjetty failed. eid " EID_FMT "\n",
			     EID_ARGS(*seid));
		return -EINVAL;
	}

	int ret = ubmad_cm_process_msg(cr, &rsrc->jetty->jetty_id.eid, msg,
				   agent_priv);

	ubmad_put_tjetty(tjetty);
	ubcore_log_info_rl("recv conn single. msn %llu seid " EID_FMT "\n", msg->msn,
		      EID_ARGS(*seid));
	return ret;
}

static inline void ubmad_process_close_req(struct ubcore_cr *cr,
					   struct ubmad_jetty_resource *rsrc)
{
	ubmad_remove_tjetty(&cr->remote_id.eid, rsrc);

	ubcore_log_info_rl("Finish to process close request, remote eid: " EID_FMT
		      ", remote id: %u.\n",
		      EID_ARGS(cr->remote_id.eid), cr->remote_id.id);
}

static int ubmad_process_msg(struct ubcore_cr *cr,
			     struct ubmad_jetty_resource *rsrc,
			     struct ubmad_device_priv *dev_priv,
			     struct ubmad_agent_priv *agent_priv)
{
	struct ubmad_msg *msg = (struct ubmad_msg *)cr->user_ctx;
	int ret = 0;

	if (cr->completion_len < sizeof(struct ubmad_msg)) {
		ubcore_log_err(
			"even header is incomplete. completion_len %u < header size %lu\n",
			cr->completion_len, sizeof(struct ubmad_msg));
		return -EINVAL;
	}
	if (cr->completion_len != sizeof(struct ubmad_msg) + msg->payload_len) {
		ubcore_log_err(
			"completion_len not right. completion_len %u != header %lu + payload len %u\n",
			cr->completion_len, sizeof(struct ubmad_msg),
			msg->payload_len);
		return -EINVAL;
	}

	switch (msg->msg_type) {
	case UBMAD_UBC_CONN_REQ:
		ret = ubmad_process_conn_data(cr, rsrc, dev_priv, agent_priv);
		break;
	case UBMAD_UBC_CONN_RESP:
		ret = ubmad_process_conn_resp(cr, rsrc, dev_priv, agent_priv);
		break;
	case UBMAD_UBC_SINGLE_REQ:
		ret = ubmad_process_conn_single(cr, rsrc, dev_priv, agent_priv);
		break;
	case UBMAD_CLOSE_REQ:
		ubmad_process_close_req(cr, rsrc);
		break;
	default:
		ubcore_log_err("Invalid msg_type: %u.\n", msg->msg_type);
		ret = -EINVAL;
	}

	return ret;
}

/* send_ops for ubcore connection manager */
// for UBMAD_UBC_CONN_DATA
int ubmad_ubc_send(struct ubcore_device *device,
		   struct ubcore_cm_send_buf *send_buf)
{
	struct ubmad_send_buf *bad_send_buf = NULL;
	struct ubmad_device_priv *dev_priv;
	int ret;

	if (device == NULL || send_buf == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	if (send_buf->msg_type != UBMAD_UBC_CONN_REQ &&
		send_buf->msg_type != UBMAD_UBC_CONN_RESP &&
		send_buf->msg_type != UBMAD_UBC_SINGLE_REQ &&
		send_buf->msg_type != UBMAD_CLOSE_REQ) {
		ubcore_log_err("Invalid message type: %u.\n", send_buf->msg_type);
		return -EINVAL;
	}

	dev_priv = ubmad_get_device_priv(device);
	if (IS_ERR_OR_NULL(dev_priv)) {
		ubcore_log_err("Failed to get dev_priv, dev_name: %s\n",
			     device->dev_name);
		return -1;
	}

	send_buf->src_eid = dev_priv->eid_info.eid;
	ubmad_put_device_priv(dev_priv);

	ubcore_log_info_rl("ubc dev: %s, s_eid: " EID_FMT ", d_eid: " EID_FMT " ",
		      device->dev_name, EID_ARGS(send_buf->src_eid),
		      EID_ARGS(send_buf->dst_eid));

	ret = ubmad_post_send(device, (struct ubmad_send_buf *)send_buf,
			      &bad_send_buf);
	if (ret != 0)
		ubcore_log_err("Failed to send message, ret: %d, length: %u.\n",
			     ret, send_buf->payload_len);

	return ret;
}

/* jfce work handler */
// polling here only indicates if send successfully
static void ubmad_send_work_handler(struct ubmad_device_priv *dev_priv,
				    struct ubmad_jfce_work *jfce_work)
{
	struct ubmad_jetty_resource *rsrc;
	struct ubmad_msg *msg;
	uint32_t sge_idx;
	int ret;
	int cr_cnt;
	struct ubcore_cr cr = {0};
	struct ubmad_agent_priv *agent_priv = jfce_work->agent_priv;
	struct ubcore_jfc *jfc = jfce_work->jfc;
	struct ubmad_send_cr send_cr = {0};

	cr_cnt = 0;

	rsrc = ubmad_get_jetty_rsrc_by_jfc_s(dev_priv, jfc);
	if (IS_ERR_OR_NULL(rsrc)) {
		ubcore_log_err("Failed to match jfc for send.\n");
		return;
	}

	do {
		cr_cnt = ubcore_poll_jfc(jfc, 1, &cr);
		if (cr_cnt < 0) {
			ubcore_log_err("cr_cnt %d < 0\n", cr_cnt);
			break;
		}
		if (cr_cnt == 0)
			break;

		/* cr_cnt == 1 */
		atomic_dec(&rsrc->tx_in_queue);
		if (cr.status == UBCORE_CR_SUCCESS) {
			send_cr.cr = &cr;
			if (agent_priv->agent.send_handler != NULL &&
			    agent_priv->agent.send_handler(&agent_priv->agent,
							   &send_cr) != 0)
				ubcore_log_err("send handler failed. cr_cnt %d\n",
					     cr_cnt);
		}

		// put ack msg sge id
		if (cr.user_ctx < rsrc->send_seg->seg.ubva.va) {
			ubcore_log_err(
				"invalid cr.user_ctx. sge addr should not < seg addr\n");
		} else {
			msg = (struct ubmad_msg *)cr.user_ctx;
			sge_idx = (cr.user_ctx - rsrc->send_seg->seg.ubva.va) /
				  UBMAD_SGE_MAX_LEN;
			ubmad_bitmap_put_id(
				rsrc->send_seg_bitmap,
				sge_idx); // get in ubmad_do_post_send()
		}
		if (cr.status != UBCORE_CR_SUCCESS && cr.status != UBCORE_CR_ACK_TIMEOUT_ERR) {
			ubcore_log_err_rl(
				"Tx status error. cr_cnt %d, status %d, comp_len %u, user_ctx: 0x%llx.\n",
				cr_cnt, cr.status, cr.completion_len,
				cr.user_ctx);
			break;
		}
	} while (cr_cnt > 0);

	ret = ubcore_rearm_jfc(jfc, false);
	ubcore_log_info_rl("Rearm send jfc, jfc_id: %u, ret: %d.\n", jfc->id, ret);
}

// polling here indicates if recv msg
static void ubmad_recv_work_handler(struct ubmad_device_priv *dev_priv,
				    struct ubmad_jfce_work *jfce_work)
{
	struct ubcore_jfc *jfc = jfce_work->jfc;
	struct ubmad_jetty_resource *rsrc;
	struct ubcore_cr cr = {0};
	uint32_t sge_idx;
	int ret;
	int cr_cnt;

	cr_cnt = 0;

	rsrc = ubmad_get_jetty_rsrc_by_jfc_r(dev_priv, jfc);
	if (IS_ERR_OR_NULL(rsrc)) {
		ubcore_log_err("Failed to match jfc for recv.\n");
		return;
	}

	do {
		cr_cnt = ubcore_poll_jfc(jfc, 1, &cr);
		if (cr_cnt < 0) {
			ubcore_log_err("cr_cnt %d < 0\n", cr_cnt);
			break;
		}
		if (cr_cnt == 0)
			break;

		/* cr_cnt == 1 */
		if (cr.status == UBCORE_CR_SUCCESS) {
			if (ubmad_process_msg(&cr, rsrc, dev_priv,
					      jfce_work->agent_priv) != 0)
				ubcore_log_err("process msg failed\n");
		}

		// put sge id
		if (cr.user_ctx < rsrc->recv_seg->seg.ubva.va) {
			ubcore_log_err(
				"invalid cr.user_ctx. sge addr should not < seg addr\n");
		} else {
			sge_idx = (cr.user_ctx - rsrc->recv_seg->seg.ubva.va) /
				  UBMAD_SGE_MAX_LEN;
			// get in ubmad_post_recv()
			ubmad_bitmap_put_id(rsrc->recv_seg_bitmap, sge_idx);
		}

		// supplement one consumed wqe
		if (ubmad_post_recv(rsrc) != 0)
			ubcore_log_err("post recv in jfce handler failed.\n");

		if (cr.status != UBCORE_CR_SUCCESS) {
			ubcore_log_err(
				"Rx status error. cr_cnt %d, status %d, comp_len %u, user_ctx: 0x%llx.\n",
				cr_cnt, cr.status, cr.completion_len,
				cr.user_ctx);
			break;
		}
	} while (cr_cnt > 0);

	ret = ubcore_rearm_jfc(jfc, false);
	ubcore_log_info_rl("Rearm recv jfc, jfc_id: %u, ret: %d.\n", jfc->id, ret);
}

// continue from ubmad_jfce_handler()
static void ubmad_jfce_work_handler(struct work_struct *work)
{
	struct ubmad_jfce_work *jfce_work =
		container_of(work, struct ubmad_jfce_work, work);
	struct ubcore_device *dev = jfce_work->jfc->ub_dev;
	struct ubmad_device_priv *dev_priv = NULL;

	dev_priv = ubmad_get_device_priv(dev); // put below
	if (IS_ERR_OR_NULL(dev_priv)) {
		ubcore_log_err("fail to get dev_priv, dev_name: %s.\n",
			     dev->dev_name);
		goto put_agent_priv;
	}
	if (!dev_priv->valid) {
		ubcore_log_err_rl("dev_priv rsrc not inited. dev_name: %s.\n",
				dev->dev_name);
		goto put_device_priv;
	}

	switch (jfce_work->type) {
	case UBMAD_SEND_WORK:
		ubmad_send_work_handler(dev_priv, jfce_work);
		break;
	case UBMAD_RECV_WORK:
		ubmad_recv_work_handler(dev_priv, jfce_work);
		break;
	default:
		ubcore_log_err("unknown work type %d\n", jfce_work->type);
	}

put_device_priv:
	ubmad_put_device_priv(dev_priv); // get above
put_agent_priv:
	ubmad_put_agent_priv(
		jfce_work->agent_priv); // get in ubmad_jfce_handler()
	kfree(jfce_work); // alloc in ubmad_jfce_handler()
}

/* jfce handler */
// see ubmad_jfce_work_handler() then
static void ubmad_jfce_handler(struct ubcore_jfc *jfc,
			       enum ubmad_jfce_work_type type)
{
	struct ubmad_agent_priv *agent_priv = NULL;
	struct ubmad_jfce_work *jfce_work;
	int ret;

	agent_priv = ubmad_get_agent_priv(
		jfc->ub_dev); // put in ubmad_jfce_work_handler()
	if (IS_ERR_OR_NULL(agent_priv)) {
		ubcore_log_err("Failed to get agent_priv, dev_name: %s.\n",
			     jfc->ub_dev->dev_name);
		return;
	}
	ubcore_log_info_rl("Start to handle jfce, type: %d, jfc_id: %u.\n", type, jfc->id);

	// free in ubmad_jfce_work_handler()
	jfce_work = kzalloc(sizeof(struct ubmad_jfce_work), GFP_ATOMIC);
	if (IS_ERR_OR_NULL(jfce_work))
		goto put_agent_priv;
	jfce_work->type = type;
	jfce_work->jfc = jfc;
	jfce_work->agent_priv = agent_priv;

	INIT_WORK(&jfce_work->work, ubmad_jfce_work_handler);
	switch (jfce_work->type) {
	case UBMAD_SEND_WORK:
		ret = queue_work(agent_priv->jfce_wq_s, &jfce_work->work);
		break;
	case UBMAD_RECV_WORK:
		ret = queue_work(agent_priv->jfce_wq_r, &jfce_work->work);
		break;
	default:
		ret = 0;
		ubcore_log_err("wrong jfce_wrok->type:%d\n", jfce_work->type);
	}
	if (!ret) {
		ubcore_log_err("queue work failed. ret %d\n", ret);
		goto free_work;
	}
	return;

free_work:
	kfree(jfce_work);
put_agent_priv:
	ubmad_put_agent_priv(agent_priv);
}

void ubmad_jfce_handler_s(struct ubcore_jfc *jfc)
{
	ubmad_jfce_handler(jfc, UBMAD_SEND_WORK);
}

void ubmad_jfce_handler_r(struct ubcore_jfc *jfc)
{
	ubmad_jfce_handler(jfc, UBMAD_RECV_WORK);
}
