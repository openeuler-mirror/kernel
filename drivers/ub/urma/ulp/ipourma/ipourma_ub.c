// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: ipourma underlay datapath implementaion
 */

#include <net/dst.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/smp.h>
#include <linux/jiffies.h>
#include "ipourma_res.h"
#include "ipourma_main.h"
#include "ipourma_utils.h"
#include "ipourma_err.h"
#include "ub/urma/ubcore_uapi.h"
#include "ipourma_ub.h"

void ipourma_build_seg_cfg(struct ubcore_seg_cfg *cfg,
			   uint64_t va, uint64_t len)
{
	union ubcore_reg_seg_flag flag = {
		.bs.token_policy = UBCORE_TOKEN_NONE,
		.bs.cacheable = UBCORE_NON_CACHEABLE,
		.bs.access = UBCORE_ACCESS_LOCAL_ONLY,
	};
	cfg->va = va;
	cfg->len = len;
	cfg->flag = flag;
}

static int ipourma_prepare_tx_data(struct ubcore_device *urma_dev,
					struct ipourma_dev_priv *priv,
					struct ipourma_tx_buf *tx_req)
{
	struct sk_buff *skb = tx_req->skb;
	struct ubcore_seg_cfg cfg = {0};
	u32 offset = 1, i, j;
	u32 linear_len = skb_headlen(skb);

	pr_skb_head_plus_linear(skb, "Register tx seg");
	if (unlikely(linear_len > priv->tx_buf_size)) {
		priv->runtime_stats.tx_stats.linear_len_oversize++;
		netdev_dbg(priv->dev, "%s: linear len %u, tx buffer size %u\n",
					ipourma_err_desc(IPOURMA_UNSUPPORTED_LINEAR_DATA_LEN),
					linear_len, priv->tx_buf_size);
		return IPOURMA_UNSUPPORTED_LINEAR_DATA_LEN;
	}
	if (likely(linear_len > 0))
		memcpy(tx_req->buf_aligned, skb->data, linear_len);
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		void *vaddr = skb_frag_address(frag);
		unsigned int frag_len = skb_frag_size(frag);

		ipourma_build_seg_cfg(&cfg, (u64)vaddr, frag_len);
		tx_req->seg[i + offset] = ubcore_register_seg(urma_dev, &cfg, NULL);
		if (IS_ERR_OR_NULL(tx_req->seg[i + offset]))
			goto partial_reg_out;
	}
	return IPOURMA_OK;

partial_reg_out:
	for (j = 1; j < i + offset; j++) {
		if (IS_ERR_OR_NULL(tx_req->seg[j]))
			continue;
		ubcore_unregister_seg(tx_req->seg[j]);
	}
	return IPOURMA_REGISTER_SEG_FAILED;
}

static int ipourma_setup_sges(struct ipourma_dev_priv *priv,
	struct ipourma_tx_buf *tx_req)
{
	int i, offset = 0;
	struct sk_buff *skb = tx_req->skb;
	skb_frag_t *frags = skb_shinfo(skb)->frags;
	int nr_frags = skb_shinfo(skb)->nr_frags;

	if (skb_headlen(skb)) {
		tx_req->tx_sge[0].len = skb_headlen(skb);
		offset++;
	}
	for (i = 0; i < nr_frags; i++) {
		tx_req->tx_sge[i + offset].addr = tx_req->seg[i + offset]->seg.ubva.va;
		tx_req->tx_sge[i + offset].len = skb_frag_size(&frags[i]);
		tx_req->tx_sge[i + offset].tseg = tx_req->seg[i + offset];
	}

	return (nr_frags + offset);
}

static inline uint32_t hash_eids(union ubcore_eid *src_eid,
				 union ubcore_eid *dst_eid,
				 uint32_t hash_seed)
{
	/* 2 * UBCORE_EID_SIZE / sizeof(uint32_t) */
	u32 num_u32 = UBCORE_EID_SIZE >> 1;
	u32 key[UBCORE_EID_SIZE >> 1];

	memcpy(key, src_eid, UBCORE_EID_SIZE);
	memcpy(key + (num_u32 >> 1), dst_eid, UBCORE_EID_SIZE);

	return jhash2((const u32 *)key, num_u32, hash_seed);
}

static inline void ipourma_build_tjetty_cfg(struct ubcore_tjetty_cfg *tjetty_cfg,
	union ubcore_eid *dst_eid, uint32_t jetty_id, uint32_t eid_idx, uint32_t ctp_en)
{
	tjetty_cfg->id.eid = *dst_eid;
	tjetty_cfg->id.id = jetty_id;
	tjetty_cfg->flag.bs.token_policy = UBCORE_TOKEN_NONE;
	tjetty_cfg->tp_type = ctp_en ? UBCORE_CTP : UBCORE_UTP;
	tjetty_cfg->trans_mode = ctp_en ? UBCORE_TP_RM : UBCORE_TP_UM;
	tjetty_cfg->type = UBCORE_JETTY;
	tjetty_cfg->eid_index = eid_idx;
}

static struct ubcore_tjetty *ipourma_import_jetty(struct net_device *dev,
	union ubcore_eid *dst_eid, uint32_t jetty_id)
{
	u32 eid_index = jetty_id - IPOURMA_WELL_KNOWN_JETTY_ID;
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct ubcore_device *urma_dev = priv->urma_dev;
	struct ubcore_tjetty_cfg tjetty_cfg = { 0 };
	struct ubcore_tjetty *tjetty;
	uint32_t ctp_en;

	ctp_en = urma_dev->attr.dev_cap.feature.bs.ctp_en;

	ipourma_build_tjetty_cfg(&tjetty_cfg, dst_eid, jetty_id, eid_index, ctp_en);
	tjetty = ubcore_import_jetty(urma_dev, &tjetty_cfg, NULL);
	if (IS_ERR_OR_NULL(tjetty)) {
		netdev_dbg(dev, "%s: dst EID = 0x%llx-0x%llx\n",
					ipourma_err_desc(IPOURMA_IMPORT_JETTY_FAILED),
					dst_eid->in6.subnet_prefix,
					dst_eid->in6.interface_id);
		return NULL;
	}

	return tjetty;
}

static inline void ipourma_renew_tjetty_node(struct ipourma_tjetty_lru *tjetty_lru,
					  struct ipourma_tjetty_hash_node *tjetty_node)
{
	list_del(&tjetty_node->lru_list);
	list_add(&tjetty_node->lru_list, &tjetty_lru->list);
	tjetty_node->last_jiffies = get_jiffies_64();
}

static struct ipourma_tjetty_hash_node *ipourma_locate_tjetty_node(
					struct ipourma_tjetty_lru *tjetty_lru,
					union ubcore_eid *src_eid,
					union ubcore_eid *dst_eid,
					bool lock_free)
{
	struct ipourma_tjetty_hmap *tjetty_hmap = &tjetty_lru->tjetty_hmap;
	uint32_t hash_key = hash_eids(src_eid, dst_eid, tjetty_hmap->hash_seed);
	struct ipourma_tjetty_hash_node *tjetty_node = NULL;

	hash_key = hash_key & (IPOURMA_TJETTY_HMAP_SIZE - 1);
	if (!lock_free)
		spin_lock(&tjetty_lru->lock);
	hlist_for_each_entry(tjetty_node, &tjetty_hmap->buckets[hash_key], hlist) {
		if (ipourma_are_eids_equal(&tjetty_node->key[0], src_eid) &&
		    ipourma_are_eids_equal(&tjetty_node->key[1], dst_eid)) {
			pr_debug("dst_eid hit in hmap\n");
			ipourma_renew_tjetty_node(tjetty_lru, tjetty_node);
			break;
		}
	}
	if (!lock_free)
		spin_unlock(&tjetty_lru->lock);

	return tjetty_node;
}

static void ipourma_insert_tjetty_node(struct ipourma_tjetty_lru *tjetty_lru,
					struct ipourma_tjetty_hash_node *tjetty_node)
{
	struct ipourma_tjetty_hmap *tjetty_hmap = &tjetty_lru->tjetty_hmap;
	uint32_t hash_seed = tjetty_hmap->hash_seed;
	/* newly imported jetty has been checked before the calling of insert function */
	uint32_t hash_key = hash_eids(&tjetty_node->key[0], &tjetty_node->key[1], hash_seed);

	hash_key = hash_key & (IPOURMA_TJETTY_HMAP_SIZE - 1);
	spin_lock(&tjetty_lru->lock);
	hlist_add_head(&tjetty_node->hlist, &tjetty_hmap->buckets[hash_key]);
	list_add(&tjetty_node->lru_list, &tjetty_lru->list);
	tjetty_lru->count++;
	tjetty_node->last_jiffies = get_jiffies_64();
	spin_unlock(&tjetty_lru->lock);
}

static inline void ipourma_delete_tjetty_node(struct ipourma_tjetty_hash_node *tjetty_node)
{
	hlist_del(&tjetty_node->hlist);
	queue_work(tjetty_node->tjetty_lru->tjetty_wq, &tjetty_node->unimport_work);
}

static void ipourma_lru_del_tail(struct ipourma_tjetty_lru *tjetty_lru, bool lock_free)
{
	struct ipourma_tjetty_hash_node *tjetty_node = NULL;

	if (!lock_free)
		spin_lock(&tjetty_lru->lock);

	if (likely(!list_empty(&tjetty_lru->list))) {
		tjetty_node = list_last_entry(&tjetty_lru->list,
						struct ipourma_tjetty_hash_node,
						lru_list);
		list_del(&tjetty_node->lru_list);
		ipourma_delete_tjetty_node(tjetty_node);
		tjetty_lru->count--;
	}

	if (!lock_free)
		spin_unlock(&tjetty_lru->lock);
}

void ipourma_lru_clear(struct ipourma_tjetty_lru *tjetty_lru)
{
	spin_lock(&tjetty_lru->lock);
	while (tjetty_lru->count > 0)
		ipourma_lru_del_tail(tjetty_lru, true);
	spin_unlock(&tjetty_lru->lock);
}

static void ipourma_lru_update(struct ipourma_tjetty_lru *tjetty_lru,
				struct ipourma_tjetty_hash_node *tjetty_node)
{
	spin_lock(&tjetty_lru->lock);
	while (tjetty_lru->count > tjetty_lru->tjetty_capacity)
		ipourma_lru_del_tail(tjetty_lru, true);
	spin_unlock(&tjetty_lru->lock);
}

static void tjetty_aging_callback(struct work_struct *work)
{
	struct delayed_work *tjetty_aging_work = container_of(work,
							      struct delayed_work,
							      work);
	struct ipourma_tjetty_lru *tjetty_lru = container_of(tjetty_aging_work,
							     struct ipourma_tjetty_lru,
							     tjetty_aging_work);
	struct ipourma_tjetty_hash_node *tjetty_node = NULL;
	u64 now_jiffies = 0;
	u32 delay_s = 0;

	if (!spin_trylock(&tjetty_lru->lock)) {
		schedule_delayed_work(tjetty_aging_work,
			msecs_to_jiffies(IPOURMA_TJETTY_CB_S * MSEC_PER_SEC));
		return;
	}
	delay_s = tjetty_lru->tjetty_aging_interval_s;
	now_jiffies = get_jiffies_64();
	while (tjetty_lru->count > 0) {
		tjetty_node = list_last_entry(&tjetty_lru->list,
					struct ipourma_tjetty_hash_node,
					lru_list);
		if (now_jiffies - tjetty_node->last_jiffies
			< (u64)tjetty_lru->tjetty_aging_timeout_s * HZ)
			break;
		list_del(&tjetty_node->lru_list);
		ipourma_delete_tjetty_node(tjetty_node);
		tjetty_lru->count--;
	}
	spin_unlock(&tjetty_lru->lock);
	schedule_delayed_work(tjetty_aging_work, msecs_to_jiffies(delay_s * MSEC_PER_SEC));
}

void ipourma_init_tjetty_aging_work(struct ipourma_tjetty_lru *tjetty_lru)
{
	struct delayed_work *work = &tjetty_lru->tjetty_aging_work;
	unsigned long flags;

	spin_lock_irqsave(&tjetty_lru->lock, flags);
	tjetty_lru->tjetty_aging_interval_s = IPOURMA_TJETTY_CB_S;
	tjetty_lru->tjetty_aging_timeout_s = IPOURMA_TJETTY_TIMEOUT_S;
	INIT_DELAYED_WORK(work, tjetty_aging_callback);
	schedule_delayed_work(work,
		msecs_to_jiffies((u32)tjetty_lru->tjetty_aging_interval_s * MSEC_PER_SEC));
	spin_unlock_irqrestore(&tjetty_lru->lock, flags);
}

static void ipourma_unimport_tjetty_cb(struct work_struct *work)
{
	struct ipourma_tjetty_hash_node *tjetty_node = NULL;

	tjetty_node = container_of(work, struct ipourma_tjetty_hash_node, unimport_work);
	ubcore_unimport_jetty(tjetty_node->tjetty);
	kfree(tjetty_node);
}

static struct ubcore_tjetty *ipourma_import_new_tjetty(
	struct ipourma_dev_priv *priv, struct ipourma_tx_buf *tx_req)
{
	if (IS_ERR_OR_NULL(priv) || IS_ERR_OR_NULL(tx_req))
		goto nullptr_err;
	u32 eid_index = tx_req->eid_index;
	union ubcore_eid src_eid = priv->eid_info[eid_index].eid;
	union ubcore_eid dst_eid = tx_req->dst_eid;
	struct ipourma_tjetty_hash_node *tjetty_node = NULL;
	u32 jetty_id = eid_index + IPOURMA_WELL_KNOWN_JETTY_ID;

	tjetty_node = kzalloc(sizeof(struct ipourma_tjetty_hash_node), GFP_KERNEL);
	if (IS_ERR_OR_NULL(tjetty_node)) {
		netdev_dbg(priv->dev, "%s\n",
				ipourma_err_desc(IPOURMA_TJETTY_NODE_ALLOC_FAILED));
		goto tjetty_node_zalloc_failed;
	}

	tjetty_node->key[0] = src_eid;
	tjetty_node->key[1] = dst_eid;
	tjetty_node->tjetty_lru = &priv->tjetty_lru;
	INIT_WORK(&tjetty_node->unimport_work, ipourma_unimport_tjetty_cb);
	tjetty_node->tjetty = ipourma_import_jetty(priv->dev, &dst_eid, jetty_id);
	if (IS_ERR_OR_NULL(tjetty_node->tjetty))
		goto ipourma_import_jetty_failed;

	ipourma_insert_tjetty_node(&priv->tjetty_lru, tjetty_node);
	ipourma_lru_update(&priv->tjetty_lru, tjetty_node);
	return tjetty_node->tjetty;
nullptr_err:
	return NULL;
ipourma_import_jetty_failed:
	kfree(tjetty_node);
tjetty_node_zalloc_failed:
	return NULL;
}

static void ipourma_advance_tx_tail(struct ipourma_dev_priv *priv,
	struct ipourma_tx_buf *tx_req)
{
	u32 i = 0, eid_idx = tx_req->eid_index;
	unsigned long flags;

	spin_lock_irqsave(&priv->tx_ring_locks[eid_idx], flags);
	tx_req->tx_buf_in_use = 0;
	for (i = priv->tx_tail[eid_idx] % ipourma_tx_ring_size;
		priv->tx_tail[eid_idx] != priv->tx_head[eid_idx];
		i = (i + 1) % ipourma_tx_ring_size) {
		if (priv->tx_ring[eid_idx][i].tx_buf_in_use == 1)
			break;
		priv->tx_tail[eid_idx]++;
	}
	if (unlikely(priv->tx_ring_is_full[eid_idx] &&
		test_bit(IPOURMA_DEV_ADMIN_UP, &priv->flags)) &&
		priv->tx_head[eid_idx] - priv->tx_tail[eid_idx] <= (ipourma_tx_ring_size >> 1)) {
		priv->tx_ring_is_full[eid_idx] = false;
		atomic_sub(1, &priv->tx_ring_blocked);
		if (atomic_read(&priv->tx_ring_blocked) == 0)
			netif_wake_queue(priv->dev);
	}
	spin_unlock_irqrestore(&priv->tx_ring_locks[eid_idx], flags);
}

static int ipourma_update_wr(struct net_device *dev, struct ipourma_tx_buf *tx_req)
{
	struct ipourma_tjetty_hash_node *tjetty_node = NULL;
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct ubcore_tjetty *tjetty_new = NULL;
	union ubcore_eid *src_eid, *dst_eid;

	if (IS_ERR_OR_NULL(tx_req->tjetty)) {
		src_eid = &priv->eid_info[tx_req->eid_index].eid;
		dst_eid = &tx_req->dst_eid;
		tjetty_node = ipourma_locate_tjetty_node(&priv->tjetty_lru,
								src_eid, dst_eid, false);
		if (IS_ERR_OR_NULL(tjetty_node)) {
			priv->runtime_stats.tx_stats.num_import_jetty_real++;
			tjetty_new = ipourma_import_new_tjetty(priv, tx_req);
			if (IS_ERR_OR_NULL(tjetty_new)) {
				ipourma_advance_tx_tail(priv, tx_req);
				priv->runtime_stats.tx_stats.import_jetty_failed++;
				return IPOURMA_TJETTY_NODE_ALLOC_FAILED;
			}
		} else {
			tjetty_new = tjetty_node->tjetty;
			priv->runtime_stats.tx_stats.num_import_jetty_bypass++;
		}
		tx_req->tx_wr.tjetty = tjetty_new;
	} else {
		tx_req->tx_wr.tjetty = tx_req->tjetty;
		priv->runtime_stats.tx_stats.num_tjetty_hash_hit++;
	}

	tx_req->tx_wr.send.src.num_sge = (u32)ipourma_setup_sges(priv, tx_req);
	return 0;
}

void ipourma_post_send(struct work_struct *work)
{
	struct ipourma_tx_buf *tx_req = container_of(work, struct ipourma_tx_buf, work);
	struct ipourma_dev_priv *priv = tx_req->priv;
	int ret;
	struct ubcore_jfs_wr *jfs_bad_wr = NULL;

	priv->runtime_stats.tx_stats.post_send_start++;
	pr_debug("post_send start, idx %u, jetty %u\n", tx_req->idx, tx_req->eid_index);
	ret = ipourma_prepare_tx_data(priv->urma_dev, priv, tx_req);
	if (ret != IPOURMA_OK)
		goto free_skb_out;
	ret = ipourma_update_wr(priv->dev, tx_req);
	if (unlikely(ret != 0))
		goto free_skb_out;
	ret = ubcore_post_jetty_send_wr(priv->jetty[tx_req->eid_index],
								&tx_req->tx_wr, &jfs_bad_wr);
	if (unlikely(ret != 0)) {
		priv->runtime_stats.tx_stats.send_wr_failed++;
		netdev_dbg(priv->dev, "%s: error code = %d\n",
					ipourma_err_desc(IPOURMA_POST_SEND_FAILED), ret);
		goto free_skb_out;
	}
	priv->runtime_stats.tx_stats.pass_to_ub++;
	pr_debug("post_send finish, idx %u, jetty %u\n", tx_req->idx, tx_req->eid_index);
	return;
free_skb_out:
	if (!IS_ERR_OR_NULL(tx_req->skb))
		dev_kfree_skb_any(tx_req->skb);
	tx_req->skb = NULL;
	ipourma_advance_tx_tail(priv, tx_req);
}

static inline int ipourma_get_eid_index(struct net_device *dev, union ubcore_eid *eid)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	for (u32 i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
		if (!eid_is_empty(&priv->eid_info[i].eid)
				&& ipourma_are_eids_equal(&priv->eid_info[i].eid, eid))
			return i;
	}
	return -IPOURMA_SRC_IP_ADDR_EID_MISMATCH;
}

int ipourma_check_skb(struct net_device *dev, struct sk_buff *skb)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	if (unlikely(skb_is_gso(skb) == true)) {
		/**
		 *  upper layer expects ipourma to do the GSO,
		 *  while ipourma or urma device doesn't support GSO
		 */
		priv->runtime_stats.tx_stats.gso_not_support++;
		netdev_dbg(dev, "%s: gso_size = %d\n",
					ipourma_err_desc(IPOURMA_NOT_SUPPORT_GSO),
					skb_shinfo(skb)->gso_size);
		return IPOURMA_NOT_SUPPORT_GSO;
	}
	if (unlikely(skb->len > priv->urma_mtu)) {
		/**
		 *  the overall length of linear & nonlinear should not
		 *  exceed the urma mtu when using send operation over CTP
		 *  ubcore doesn't define a CTP mode, use UBCORE_TP_RM for now
		 */
		if ((priv->urma_op_mode == UBCORE_OPC_SEND) &&
			(priv->urma_transport_mode == UBCORE_TP_RM)) {
			priv->runtime_stats.tx_stats.packet_size_error++;
			netdev_dbg(dev, "%s: skb len = %u\n",
						ipourma_err_desc(IPOURMA_GIANT_PACKET),
						skb->len);
			return IPOURMA_GIANT_PACKET;
		}
	}
	if (unlikely(skb_shinfo(skb)->nr_frags + 1 > priv->max_send_sge)) {
		/* try to linearize firstly */
		skb_linearize(skb);
		if (skb_shinfo(skb)->nr_frags + 1 > priv->max_send_sge) {
			priv->runtime_stats.tx_stats.frag_error++;
			netdev_dbg(dev, "%s: skb nr_frags = %d, max_send_sge = %d\n",
						ipourma_err_desc(IPOURMA_TOO_MANY_FRAGS),
						skb_shinfo(skb)->nr_frags, priv->max_send_sge);
			return IPOURMA_TOO_MANY_FRAGS;
		}
	}

	return IPOURMA_OK;
}

int ipourma_register_rx_segments(struct net_device *dev,
	struct ubcore_seg_cfg *cfg, struct ipourma_rx_buf *rx_req)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	u32 blk_idx;
	u32 i;

	blk_idx = rx_req->idx * priv->skb_buf_size / ipourma_register_seg_size;

	for (i = 0; i < IPOURMA_MAX_RX_SGES; i++) {
		rx_req->seg[i] = priv->ipourma_ub_rx_seg[rx_req->eid_index][blk_idx];
		/* FIME: deal with partial failures */
		if (IS_ERR_OR_NULL(rx_req->seg[i])) {
			priv->runtime_stats.rx_stats.register_seg_failed++;
			netdev_warn(dev, "%s\n",
						ipourma_err_desc(IPOURMA_REGISTER_SEG_FAILED));
			return IPOURMA_REGISTER_SEG_FAILED;
		}
	}

	return IPOURMA_OK;
}

static inline int ipourma_add_header(struct sk_buff *skb)
{
	struct ipourma_header *header;
	size_t header_size = sizeof(struct ipourma_header);

	/* For now, addresses are not used */
	header = skb_push(skb, header_size);
	header->proto = skb->protocol;

	return header_size;
}

int ipourma_xmit(struct net_device *dev, struct sk_buff *skb,
		 union ubcore_eid *src_eid, union ubcore_eid *dst_eid)
{
	struct ipourma_tjetty_hash_node *tjetty_node = NULL;
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct ipourma_tx_buf *tx_req;
	int ret = IPOURMA_OK;
	u32 eid_idx;
	u32 tx_idx;

	ipourma_add_header(skb);
	ret = ipourma_get_eid_index(dev, src_eid);
	if (unlikely(ret == -IPOURMA_SRC_IP_ADDR_EID_MISMATCH)) {
		priv->runtime_stats.tx_stats.ip_eid_not_equal++;
		netdev_dbg(dev, "%s:IP=0x%llx-0x%llx\n",
			ipourma_err_desc(IPOURMA_SRC_IP_ADDR_EID_MISMATCH),
			src_eid->in6.subnet_prefix,
			src_eid->in6.interface_id);
		return IPOURMA_SRC_IP_ADDR_EID_MISMATCH;
	}
	eid_idx = (u32)ret;
	ret = IPOURMA_OK;
	if (spin_trylock(&priv->tjetty_lru.lock)) {
		tjetty_node = ipourma_locate_tjetty_node(&priv->tjetty_lru, src_eid, dst_eid, true);
		spin_unlock(&priv->tjetty_lru.lock);
	}

	// enqueue the skb
	spin_lock(&priv->tx_ring_locks[eid_idx]);
	if (priv->tx_ring_is_full[eid_idx]) {
		spin_unlock(&priv->tx_ring_locks[eid_idx]);
		priv->runtime_stats.tx_stats.tx_ring_full++;
		return IPOURMA_TX_RING_FULL;
	}
	tx_idx = priv->tx_head[eid_idx] % ipourma_tx_ring_size;
	tx_req = &priv->tx_ring[eid_idx][tx_idx];
	tx_req->tx_buf_in_use = 1;
	if ((priv->tx_head[eid_idx] - priv->tx_tail[eid_idx]) == ipourma_tx_ring_size - 1) {
		/* tx ring is full, notify the upper layer */
		priv->tx_ring_is_full[eid_idx] = true;
		atomic_add(1, &priv->tx_ring_blocked);
		netif_stop_queue(dev);
		netdev_dbg(dev, "%s: head = %u, tail = %u\n",
					ipourma_err_desc(IPOURMA_TX_RING_FULL),
					priv->tx_head[eid_idx], priv->tx_tail[eid_idx]);
	}
	priv->tx_head[eid_idx]++;
	spin_unlock(&priv->tx_ring_locks[eid_idx]);
	tx_req->skb = skb;
	tx_req->dst_eid = *dst_eid;
	tx_req->eid_index = eid_idx;
	tx_req->tjetty = IS_ERR_OR_NULL(tjetty_node) ? NULL : tjetty_node->tjetty;

	/* take the ownership of skb */
	skb_orphan(skb);
	skb_dst_drop(skb);
	pr_debug("queue work, idx %u\n", tx_idx);
	if (!IS_ERR_OR_NULL(tx_req->tjetty)) {
		priv->runtime_stats.tx_stats.post_send_bypass++;
		ipourma_post_send(&(tx_req->work));
	} else {
		priv->runtime_stats.tx_stats.post_send_enque++;
		queue_work(priv->tx_wq, &(tx_req->work));
	}

	return ret;
}

static struct sk_buff *ipourma_alloc_rx_skb(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct sk_buff *skb;

	skb = alloc_skb(priv->skb_buf_size, GFP_KERNEL);
	if (IS_ERR_OR_NULL(skb)) {
		priv->runtime_stats.rx_stats.alloc_skb_failed++;
		netdev_dbg(dev, "%s\n",
					ipourma_err_desc(IPOURMA_ALLOC_RX_SKB_FAILED));
		return NULL;
	}
	skb_push(skb, skb_headroom(skb));
	skb_trim(skb, 0);

	return skb;
}

static int ipourma_alloc_rx_buffer(struct net_device *dev, u32 eid_idx, u32 idx)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct ubcore_seg_cfg cfg = { 0 };
	struct sk_buff *skb_pass_up;
	u32 blk_idx, offset;

	skb_pass_up = ipourma_alloc_rx_skb(dev);
	if (IS_ERR_OR_NULL(skb_pass_up))
		return IPOURMA_ALLOC_RX_SKB_FAILED;

	blk_idx = idx * priv->skb_buf_size / ipourma_register_seg_size;
	offset = (idx * priv->skb_buf_size) % ipourma_register_seg_size;
	priv->rx_ring[eid_idx][idx].buf_aligned = priv->rx_buf_aligned[eid_idx][blk_idx] + offset;

	if (ipourma_register_rx_segments(dev, &cfg, &priv->rx_ring[eid_idx][idx])
			!= IPOURMA_OK) {
		dev_kfree_skb_any(skb_pass_up);
		return IPOURMA_REGISTER_SEG_FAILED;
	}

	priv->rx_ring[eid_idx][idx].skb_pass_up = skb_pass_up;
	pr_skb_head_plus_linear(skb_pass_up, "Alloced rx buffer skb_pass_up");

	return IPOURMA_OK;
}

int ipourma_urma_post_recv(struct net_device *dev, u32 eid_idx, u32 idx)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct ipourma_rx_buf *rx_buf = &priv->rx_ring[eid_idx][idx];
	int ret;
	struct ubcore_jfr_wr *jfr_bad_wr = NULL;

	rx_buf->rx_sge[0].tseg = rx_buf->seg[0];
	rx_buf->rx_sge[0].addr = (u64)rx_buf->buf_aligned;
	rx_buf->rx_sge[0].len = priv->urma_mtu;
	pr_debug("post_recv start, eid idx %u, idx %u\n", rx_buf->eid_index, rx_buf->idx);
	ret = ubcore_post_jetty_recv_wr(priv->jetty[eid_idx], &rx_buf->rx_wr, &jfr_bad_wr);
	if (unlikely(ret != 0)) {
		priv->runtime_stats.rx_stats.post_wr_failed++;
		netdev_dbg(dev, "%s:%d\n",
					ipourma_err_desc(IPOURMA_URMA_POST_RECV_FAILED), ret);
		dev_kfree_skb_any(rx_buf->skb_pass_up);
		rx_buf->skb_pass_up = NULL;
		return IPOURMA_URMA_POST_RECV_FAILED;
	}
	priv->runtime_stats.rx_stats.num_post_wr++;
	pr_debug("post_recv finish, eid idx %u, idx %u\n", rx_buf->eid_index, rx_buf->idx);
	return IPOURMA_OK;
}

static int ipourma_post_recv_by_eid(struct net_device *dev, u32 eid_idx)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	int ret = IPOURMA_OK;
	u32 i;

	for (i = 0; i < ipourma_rx_ring_size; i++) {
		if (ipourma_alloc_rx_buffer(dev, eid_idx, i) != IPOURMA_OK) {
			ret = IPOURMA_ALLOC_RX_SKB_FAILED;
			goto post_recv_failed;
		}

		if (ipourma_urma_post_recv(dev, eid_idx, i) != IPOURMA_OK) {
			ret = IPOURMA_URMA_POST_RECV_FAILED;
			goto post_recv_failed;
		}
	}
	return ret;

post_recv_failed:
	ipourma_uninit_rx_bufs(priv, eid_idx);
	return ret;
}

void ipourma_replenish_segments(struct work_struct *work)
{
	struct ipourma_rx_buf *rx_buf = container_of(work, struct ipourma_rx_buf, work);
	struct ipourma_dev_priv *priv = rx_buf->priv;

	priv->runtime_stats.rx_stats.replenish_deque++;

	/* if post failed, skb will be released as well */
	rx_buf->skb_pass_up = ipourma_alloc_rx_skb(priv->dev);
	if (IS_ERR_OR_NULL(rx_buf->skb_pass_up)) {
		netdev_dbg(priv->dev, "%s: idx = %u\n",
			ipourma_err_desc(IPOURMA_REPLENISH_RX_SEG_FAILED), rx_buf->idx);
		return;
	}
	if (test_bit(IPOURMA_DEV_ADMIN_UP, &priv->flags))
		ipourma_urma_post_recv(priv->dev, rx_buf->eid_index, rx_buf->idx);
}

int ipourma_urma_init_by_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	int ret;

	ret = ipourma_init_rings_by_eid(priv, eid_idx);
	if (ret != IPOURMA_OK)
		goto init_rings_by_eid_failed;

	ret = ipourma_init_urma_resources_by_eid(priv, eid_idx);
	if (ret != IPOURMA_OK)
		goto init_urma_res_by_eid_failed;

	ret = ipourma_post_recv_by_eid(priv->dev, eid_idx);
	if (ret != IPOURMA_OK)
		goto post_recv_by_eid_failed;

	return ret;
post_recv_by_eid_failed:
	ipourma_uninit_urma_resources_by_eid(priv, eid_idx);
init_urma_res_by_eid_failed:
	ipourma_uninit_rings_by_eid(priv, eid_idx);
init_rings_by_eid_failed:
	return ret;
}

static void ipourma_do_handle_tx_wc(struct net_device *dev,
	struct ipourma_dev_priv *priv, u32 eid_idx, u32 idx, struct ubcore_cr *cr)
{
	struct ipourma_tx_buf *tx_req = &priv->tx_ring[eid_idx][idx];

	if (unlikely(tx_req->tx_buf_in_use == 0))
		return;
	if (unlikely(cr->status == UBCORE_CR_SUCCESS)) {
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += tx_req->skb->len;
		netif_trans_update(dev);
	}
	dev_kfree_skb_any(tx_req->skb);
	tx_req->skb = NULL;
	ipourma_advance_tx_tail(priv, tx_req);
}

void ipourma_handle_tx_wc(struct net_device *dev,
			  struct ipourma_dev_priv *priv,
			  struct ubcore_cr *cr)
{
	u32 eid_idx, idx;

	if (cr->status >= IPOURMA_MAX_CR_STATUS) {
		priv->runtime_stats.tx_stats.cqe_err++;
		return;
	}

	priv->runtime_stats.tx_stats.cqe_stats[cr->status]++;
	if (likely(cr->status == UBCORE_CR_SUCCESS))
		priv->runtime_stats.tx_stats.cqe_success++;
	else
		priv->runtime_stats.tx_stats.cqe_err++;

	if (unlikely(cr->status == UBCORE_CR_WR_FLUSH_ERR_DONE)) {
		/* should not happen, user_ctx is invalid in this case */
		netdev_dbg(dev, "%s:%d\n",
				   ipourma_err_desc(IPOURMA_INCORRECT_CR_STATUS), cr->status);
		return;
	}
	if (unlikely(cr->status == UBCORE_CR_FLUSH_ERR))
		priv->runtime_stats.tx_stats.flush_jetty_success++;

	eid_idx = cr->local_id - IPOURMA_WELL_KNOWN_JETTY_ID;
	if (unlikely(cr->local_id < IPOURMA_WELL_KNOWN_JETTY_ID ||
		cr->local_id >= IPOURMA_MAX_EID_CNT + IPOURMA_WELL_KNOWN_JETTY_ID)) {
		netdev_dbg(dev, "%s:%u\n",
				   ipourma_err_desc(IPOURMA_INCORRECT_WQE_JETTY_IDX), eid_idx);
		return;
	}

	idx = cr->user_ctx;
	if (IS_ERR_OR_NULL(priv->tx_ring[eid_idx]) ||
		unlikely(idx >= ipourma_tx_ring_size)) {
		netdev_dbg(dev, "%s:eid_idx:%u idx:%u\n",
				   ipourma_err_desc(IPOURMA_INCORRECT_WQE_IDX), eid_idx, idx);
		return;
	}
	pr_debug("now cr status:%d\n", cr->status);
	ipourma_do_handle_tx_wc(dev, priv, eid_idx, idx, cr);
}

static void ipourma_do_handle_rx_wc(struct net_device *dev,
					struct ipourma_dev_priv *priv,
					u32 eid_idx, u32 idx,
					struct ubcore_cr *cr)
{
	struct ipourma_rx_buf *rx_req = &priv->rx_ring[eid_idx][idx];
	struct sk_buff *skb;
	u32 data_len;

	/* hold the skb & segments */
	skb = rx_req->skb_pass_up;
	rx_req->skb_pass_up = NULL;
	if (cr->completion_len > priv->tx_buf_size ||
		cr->completion_len <= (u32)sizeof(struct ipourma_header)) {
		dev_kfree_skb_any(skb);
		priv->runtime_stats.rx_stats.cr_len_err++;
		goto rx_wc_out;
	}
	data_len = cr->completion_len - (u32)sizeof(struct ipourma_header);

	skb->protocol = ((struct ipourma_header *)rx_req->buf_aligned)->proto;
	memcpy(skb->head, rx_req->buf_aligned + sizeof(struct ipourma_header), data_len);
	/* update the skb pointer */
	skb->data_len = 0;
	skb_trim(skb, 0);
	skb_put(skb, data_len);

	skb->pkt_type = PACKET_HOST;
	skb->dev = dev;
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;
	pr_debug("IPoURMA received packet's proto: 0x%x\n",
			 ntohs(skb->protocol));
	pr_skb_head_plus_linear(skb, "Skb passed to kernel stack");
	if (atomic_read(&skb->users.refs) == 1) {
		netif_rx(skb);
		priv->runtime_stats.rx_stats.pass_to_kernel++;
	}
rx_wc_out:
	priv->runtime_stats.rx_stats.replenish_enque++;
	queue_work(priv->rx_wq, &(rx_req->work));
}

void ipourma_handle_rx_wc(struct net_device *dev,
			  struct ipourma_dev_priv *priv,
			  struct ubcore_cr *cr)
{
	u32 eid_idx, idx;

	if (cr->status >= IPOURMA_MAX_CR_STATUS) {
		priv->runtime_stats.rx_stats.cqe_err++;
		return;
	}
	priv->runtime_stats.rx_stats.cqe_stats[cr->status]++;
	if (unlikely(cr->status != UBCORE_CR_SUCCESS)) {
		priv->runtime_stats.rx_stats.cqe_err++;
		netdev_dbg(dev, "%s:%d\n",
				   ipourma_err_desc(IPOURMA_INCORRECT_CR_STATUS), cr->status);
		return;
	}
	priv->runtime_stats.rx_stats.cqe_success++;
	eid_idx = cr->local_id - IPOURMA_WELL_KNOWN_JETTY_ID;
	if (unlikely(cr->local_id < IPOURMA_WELL_KNOWN_JETTY_ID ||
		cr->local_id >= IPOURMA_MAX_EID_CNT + IPOURMA_WELL_KNOWN_JETTY_ID)) {
		netdev_dbg(dev, "%s:%u\n",
				   ipourma_err_desc(IPOURMA_INCORRECT_WQE_JETTY_IDX), eid_idx);
		return;
	}
	idx = cr->user_ctx;
	if (IS_ERR_OR_NULL(priv->rx_ring[eid_idx]) ||
		unlikely(idx >= ipourma_rx_ring_size)) {
		netdev_dbg(dev, "%s:eid_idx:%u idx:%u\n",
				   ipourma_err_desc(IPOURMA_INCORRECT_WQE_IDX), eid_idx, idx);
		return;
	}
	ipourma_do_handle_rx_wc(dev, priv, eid_idx, idx, cr);
}

void ipourma_rx_cr_event(struct work_struct *work)
{
	struct ipourma_dev_priv *priv = container_of(work, struct ipourma_dev_priv, rx_cr_event);
	int done = 0, budget = IPOURMA_NAPI_RX_WEIGHT;
	int left, max_num, actual_num, i, ret;
	struct net_device *dev = priv->dev;

	priv->runtime_stats.rx_stats.rx_deque++;
	while (done < budget) {
		left = budget - done;
		/* DO NOT exceed the weight */
		max_num = min(IPOURMA_NAPI_RX_WEIGHT, left);
		actual_num = ubcore_poll_jfc(priv->rx_jfc, max_num, priv->rx_cr);
		/* actual_num may be < 0, but it's OK to break the loop a little later */
		if (unlikely(actual_num < 0)) {
			priv->runtime_stats.rx_stats.poll_jfc_failed++;
			netdev_dbg(dev, "%s:%d\n", ipourma_err_desc(IPOURMA_POLL_JFC_FAILED),
					actual_num);
			break;
		}
		priv->runtime_stats.rx_stats.poll_jfc_success++;
		for (i = 0; i < actual_num; i++) {
			ipourma_handle_rx_wc(dev, priv, &priv->rx_cr[i]);
			done++;
			priv->runtime_stats.rx_stats.cqe_recved++;
		}
		if (actual_num != max_num) {
			/* actual_num < 0 or no more crs to poll */
			break;
		}
	}
	ret = ubcore_rearm_jfc(priv->rx_jfc, false);
	if (unlikely(ret != 0)) {
		priv->runtime_stats.rx_stats.rearm_failed++;
		netdev_dbg(dev, "%s:%d\n",
					ipourma_err_desc(IPOURMA_REARM_JFC_FAILED), ret);
	} else
		priv->runtime_stats.rx_stats.rearm_success++;
}

void ipourma_handle_tx_cqe(struct ubcore_jfc *jfc)
{
	struct ipourma_dev_priv *priv = ubcore_get_client_ctx_data(
		jfc->ub_dev, &g_ipourma_ubcore_client);

	if (IS_ERR_OR_NULL(priv))
		return;
	priv->runtime_stats.tx_stats.cqe_notify++;
	napi_schedule(&priv->napi_send);
}

void ipourma_handle_rx_cqe(struct ubcore_jfc *jfc)
{
	struct ipourma_dev_priv *priv = ubcore_get_client_ctx_data(
		jfc->ub_dev, &g_ipourma_ubcore_client);

	if (IS_ERR_OR_NULL(priv))
		return;
	priv->runtime_stats.rx_stats.cqe_notify++;
	napi_schedule(&priv->napi_recv);
}

int ipourma_napi_tx_poll(struct napi_struct *napi, int budget)
{
	struct ipourma_dev_priv *priv =
		container_of(napi, struct ipourma_dev_priv, napi_send);
	struct net_device *dev = priv->dev;
	int actual_num, i, ret;

	priv->runtime_stats.tx_stats.num_napi_tx++;
	actual_num = ubcore_poll_jfc(priv->tx_jfc, IPOURMA_NAPI_TX_WEIGHT, priv->tx_cr);
	if (unlikely(actual_num < 0)) {
		priv->runtime_stats.tx_stats.poll_jfc_failed++;
		netdev_dbg(dev, "%s:%d\n", ipourma_err_desc(IPOURMA_POLL_JFC_FAILED),
					actual_num);
	} else
		priv->runtime_stats.tx_stats.poll_jfc_success++;
	for (i = 0; i < actual_num; i++) {
		priv->runtime_stats.tx_stats.cqe_recved++;
		ipourma_handle_tx_wc(dev, priv, &priv->tx_cr[i]);
	}

	if (actual_num < budget) {
		/* no more crs to poll */
		napi_complete(napi);
	}
	ret = ubcore_rearm_jfc(priv->tx_jfc, false);
	if (unlikely(ret != 0)) {
		priv->runtime_stats.tx_stats.rearm_failed++;
		netdev_dbg(dev, "%s:%d\n",
					ipourma_err_desc(IPOURMA_REARM_JFC_FAILED), ret);
	} else
		priv->runtime_stats.tx_stats.rearm_success++;

	/* used up the budget, return w/o calling napi_complete */
	return actual_num;
}

int ipourma_napi_rx_poll(struct napi_struct *napi, int budget)
{
	struct ipourma_dev_priv *priv =
		container_of(napi, struct ipourma_dev_priv, napi_recv);

	priv->runtime_stats.rx_stats.num_napi_rx++;
	priv->runtime_stats.rx_stats.rx_enque++;
	queue_work(priv->rx_wq, &(priv->rx_cr_event));
	napi_complete(napi);

	return 0;
}

static void ipourma_napi_add(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	netif_napi_add_weight(dev, &priv->napi_send, ipourma_napi_tx_poll,
						  IPOURMA_NAPI_TX_WEIGHT);
	netif_napi_add_weight(dev, &priv->napi_recv, ipourma_napi_rx_poll,
						  IPOURMA_NAPI_RX_WEIGHT);
}

static inline void ipourma_napi_del(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	netif_napi_del(&priv->napi_send);
	netif_napi_del(&priv->napi_recv);
}

int ipourma_urma_dev_init(struct net_device *dev)
{
	int ret;

	ipourma_napi_add(dev);
	ret = ipourma_init_rings(dev);
	if (ret != IPOURMA_OK)
		goto init_rings_failed;

	ret = ipourma_init_urma_resources(dev);
	if (ret != IPOURMA_OK)
		goto init_urma_res_failed;

	return ret;
init_urma_res_failed:
	ipourma_uninit_rings(dev);
init_rings_failed:
	ipourma_napi_del(dev);
	return ret;
}

void ipourma_urma_dev_uninit(struct net_device *dev)
{
	ipourma_uninit_tjetty_hmap(dev);
	ipourma_uninit_urma_resources(dev);
	ipourma_uninit_rings(dev);
	ipourma_napi_del(dev);
}
