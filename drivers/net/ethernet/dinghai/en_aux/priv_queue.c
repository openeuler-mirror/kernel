// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/zxdh_compat.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include "priv_queue.h"

static void poll_timer_callback(struct timer_list *this_timer)
{
	struct msgq_dev *msgq_dev = from_timer(msgq_dev, this_timer, poll_timer);
	struct msg_buff *this_msg_buff = NULL;
	u16 i = 0;
	u32 tx_timeouts = 0;

	if (!msgq_dev) {
		LOG_ERR("msgq_dev is NULL\n");
		return;
	}

	for (i = 0; i < MSGQ_MAX_MSG_BUFF_NUM; ++i) {
		if (msgq_dev->free_cnt == 0) {
			msgq_dev->timer_in_use = false;
			return;
		}
		this_msg_buff = &msgq_dev->msg_buff_ring[i];

		if (!this_msg_buff->using || !this_msg_buff->need_free)
			continue;

		if (this_msg_buff->timeout_cnt == 0) {
			*(this_msg_buff->data_len) = 0;
			this_msg_buff->data = NULL;
			msgq_dev->free_cnt--;
			tx_timeouts++;
			LOG_ERR("msg[%d] get callback out of time\n", i);
			this_msg_buff->using = false;
			continue;
		}
		this_msg_buff->timeout_cnt--;
	}

	u64_stats_update_begin(&msgq_dev->sq_priv->stats.syncp);
	msgq_dev->sq_priv->stats.tx_timeouts += tx_timeouts;
	u64_stats_update_end(&msgq_dev->sq_priv->stats.syncp);

	mod_timer(this_timer, jiffies + msecs_to_jiffies(TIMER_DELAY_US));
}

static u32 msgq_get_mergeable_buf_len(struct receive_queue *rq, struct ewma_pkt_len *avg_pkt_len)
{
	const size_t hdr_len = PRIV_HEADER_LEN;
	u32 len = 0;

	len = hdr_len +
	      clamp_t(u32, ewma_pkt_len_read(avg_pkt_len), rq->min_buf_len, PAGE_SIZE - hdr_len);

	return ALIGN(len, L1_CACHE_BYTES);
}

static s32 msgq_add_recvbuf_mergeable(struct receive_queue *rq, gfp_t gfp)
{
	struct page_frag *alloc_frag = &rq->alloc_frag;
	char *buf = NULL;
	void *ctx = NULL;
	s32 err = 0;
	u32 len = 0;
	u32 hole = 0;

	len = msgq_get_mergeable_buf_len(rq, &rq->mrg_avg_pkt_len);
	if (unlikely(!dh_skb_page_frag_refill(len, alloc_frag, gfp)))
		return -ENOMEM;

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	get_page(alloc_frag->page);
	alloc_frag->offset += len;
	hole = alloc_frag->size - alloc_frag->offset;
	if (hole < len) {
		len += hole;
		alloc_frag->offset += hole;
	}

	sg_init_one(rq->sg, buf, len);
	ctx = (void *)(unsigned long)len;
	err = zxdh_virtqueue_add_inbuf_ctx(rq->vq, rq->sg, 1, buf, ctx, gfp);
	if (err < 0)
		put_page(virt_to_head_page(buf));

	return err;
}

static bool msgq_try_fill_recv(struct receive_queue *rq, gfp_t gfp)
{
	s32 err = 0;
	bool oom = 0;
	unsigned long flags = 0;

	do {
		err = msgq_add_recvbuf_mergeable(rq, gfp);
		oom = err == -ENOMEM;
		if (err)
			break;
	} while (rq->vq->num_free);

	if (virtqueue_kick_prepare_packed(rq->vq) && zxdh_virtqueue_notify(rq->vq)) {
		flags = u64_stats_update_begin_irqsave(&rq->stats.syncp);
		rq->stats.kicks++;
		u64_stats_update_end_irqrestore(&rq->stats.syncp, flags);
	}

	return !oom;
}

u32 msgq_mergeable_min_buf_len(struct virtqueue *vq)
{
	const u32 hdr_len = PRIV_HEADER_LEN;
	u32 rq_size = zxdh_virtqueue_get_vring_size(vq);
	u32 min_buf_len = DIV_ROUND_UP(BUFF_LEN, rq_size);

	return max(max(min_buf_len, hdr_len) - hdr_len, (u32)GOOD_PACKET_LEN);
}

s32 msgq_privq_init(struct msgq_dev *msgq_dev, struct net_device *netdev)
{
	struct receive_queue *rq = msgq_dev->rq_priv;
	struct send_queue *sq = msgq_dev->sq_priv;

	rq->pages = NULL;
	rq->min_buf_len = msgq_mergeable_min_buf_len(rq->vq);

	netif_napi_add(netdev, &rq->napi, zxdh_msgq_poll);
	netif_napi_add_tx_weight(netdev, &sq->napi, NULL, NAPI_POLL_WEIGHT);
	sg_init_table(rq->sg, ARRAY_SIZE(rq->sg));
	ewma_pkt_len_init(&rq->mrg_avg_pkt_len);
	sg_init_table(sq->sg, ARRAY_SIZE(sq->sg));

	u64_stats_init(&rq->stats.syncp);
	u64_stats_init(&sq->stats.syncp);

	if (!msgq_try_fill_recv(rq, GFP_KERNEL)) {
		LOG_ERR("msgq_try_fill_recv failed\n");
		netif_napi_del(&msgq_dev->rq_priv->napi);
		netif_napi_del(&msgq_dev->sq_priv->napi);
		return MSGQ_RET_ERR_CHANNEL_NOT_READY;
	}

	msgq_dev->msgq_enable = true;
	virtnet_napi_enable(rq->vq, &rq->napi);
	LOG_DEBUG("success\n");
	return MSGQ_RET_OK;
}

s32 zxdh_msgq_init(struct zxdh_en_device *en_dev)
{
	struct msgq_dev *msgq_dev = NULL;
	s32 idx = 0;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	en_dev->msgq_dev = kzalloc(sizeof(struct msgq_dev), GFP_KERNEL);
	if (unlikely((en_dev->msgq_dev) == NULL)) {
		LOG_ERR("null pointer\n");
		return MSGQ_RET_ERR_NULL_PTR;
	}

	idx = en_dev->max_queue_pairs - ZXDH_PQ_PAIRS_NUM;
	msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	msgq_dev->sq_priv = &en_dev->sq[idx];
	msgq_dev->rq_priv = &en_dev->rq[idx];
	msgq_dev->msgq_vfid = (u16)VQM_VFID(en_dev->vport);
	msgq_dev->msgq_rqid = (u16)msgq_dev->rq_priv->vq->phy_index;

	dpp_vport_create_by_vqm_vfid(&pf_info, RISCV_COMMON_VFID);
	spin_lock_init(&msgq_dev->sn_lock);
	spin_lock_init(&msgq_dev->tx_lock);
	msgq_dev->mlock = kzalloc(sizeof(struct mutex), GFP_KERNEL);
	if (unlikely((msgq_dev->mlock) == NULL)) {
		LOG_ERR("null pointer\n");
		goto err_mutex;
	}
	mutex_init(msgq_dev->mlock);
	timer_setup(&msgq_dev->poll_timer, poll_timer_callback, 0);

	err = msgq_privq_init(msgq_dev, en_dev->netdev);
	ZXDH_CHECK_RET_GOTO_ERR(err, free_msgq, "msgq_privq_init failed: %d\n", err);
	return 0;

free_msgq:
	del_timer_sync(&msgq_dev->poll_timer);
	mutex_destroy(msgq_dev->mlock);
	ZXDH_FREE_PTR(msgq_dev->mlock);
err_mutex:
	ZXDH_FREE_PTR(msgq_dev);
	return err;
}

void msgq_privq_uninit(struct msgq_dev *msgq_dev)
{
	msgq_dev->msgq_enable = false;
	napi_disable(&msgq_dev->rq_priv->napi);
	netif_napi_del(&msgq_dev->rq_priv->napi);
	netif_napi_del(&msgq_dev->sq_priv->napi);
	del_timer_sync(&msgq_dev->poll_timer);
}

void zxdh_msgq_exit(struct zxdh_en_device *en_dev)
{
	struct msgq_dev *msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;

	if (!msgq_dev) {
		LOG_ERR("msgq_dev is null!\n");
		return;
	}

	msgq_privq_uninit(msgq_dev);
	mutex_destroy(msgq_dev->mlock);
	ZXDH_FREE_PTR(msgq_dev->mlock);
	ZXDH_FREE_PTR(msgq_dev);
	LOG_INFO("zxdh_msg_chan_pkt remove success\n");
}

void msgq_print_data(u8 *buf, u32 len, u8 flag)
{
	u32 print_len = 0;

	if (flag == MSGQ_PRINT_HDR)
		print_len = PRIV_HEADER_LEN;
	else if (flag == MSGQ_PRINT_128B)
		print_len = len > 128 ? 128 : len;
	else if (flag == MSGQ_PRINT_ALL)
		print_len = len;

	print_data(buf, print_len);
}

static s32 zxdh_msg_para_check(struct msgq_pkt_info *msg, struct reps_info *reps)
{
	if (unlikely((msg) == NULL) || unlikely((msg->addr) == NULL)) {
		LOG_ERR("null pointer\n");
		return MSGQ_RET_ERR_NULL_PTR;
	}

	if ((msg->len == 0) || (msg->len > MSGQ_MAX_ADDR_LEN)) {
		LOG_ERR("invalid data_len: %d\n", msg->len);
		goto free_addr;
	}

	if (msg->event_id >= MSG_MODULE_NUM) {
		LOG_ERR("invalid event_id\n");
		goto free_addr;
	}

	if (msg->no_reps)
		return MSGQ_RET_OK;

	if (unlikely((reps) == NULL) || unlikely((reps->addr) == NULL)) {
		LOG_ERR("null pointer\n");
		goto free_addr;
	}

	if (reps->len == 0) {
		LOG_ERR("invalid reps_len: %d\n", reps->len);
		goto free_addr;
	}

	return MSGQ_RET_OK;
free_addr:
	ZXDH_FREE_PTR(msg->addr);
	return MSGQ_RET_ERR_INVALID_PARA;
}

static s32 zxdh_sequence_num_get(struct msgq_dev *msgq_dev, u16 *sequence_num)
{
	u16 sn = 0;
	u16 loop = 0;

	spin_lock(&msgq_dev->sn_lock);
	sn = msgq_dev->sequence_num;

	for (loop = 0; loop < MSGQ_MAX_MSG_BUFF_NUM; loop++) {
		if (!msgq_dev->msg_buff_ring[sn].using) {
			*sequence_num = sn;
			msgq_dev->msg_buff_ring[sn].using = true;
			msgq_dev->msg_buff_ring[sn].valid = false;
			msgq_dev->free_cnt++;
			SEQUENCE_NUM_ADD(sn);
			break;
		}
		SEQUENCE_NUM_ADD(sn);
	}

	msgq_dev->sequence_num = sn;
	spin_unlock(&msgq_dev->sn_lock);

	if (loop == MSGQ_MAX_MSG_BUFF_NUM)
		return MSGQ_RET_ERR_CHAN_BUSY;

	return MSGQ_RET_OK;
}

static s32 page_send_cmd(struct send_queue *sq, u8 *buf, u16 buf_len, u8 print)
{
	u16 i = 0;
	s32 err = 0;
	u16 total_sg = 0;
	u16 last_buff_len = 0;

	if (print != 0) {
		LOG_DEBUG("send pkt start\n");
		msgq_print_data(buf, buf_len, print);
	}

	total_sg = buf_len / BUFF_LEN;
	last_buff_len = buf_len % BUFF_LEN;
	if (last_buff_len != 0)
		total_sg += 1;

	sg_init_table(sq->sg, total_sg);
	for (i = 0; i < total_sg; ++i) {
		if (i == (total_sg - 1)) {
			sg_set_buf(&sq->sg[i], buf + (i * BUFF_LEN),
				   ((last_buff_len != 0) ? (last_buff_len) : (BUFF_LEN)));
		} else {
			sg_set_buf(&sq->sg[i], buf + (i * BUFF_LEN), BUFF_LEN);
		}
	}

	err = zxdh_virtqueue_add_outbuf(sq->vq, sq->sg, total_sg, buf, GFP_ATOMIC);
	ZXDH_CHECK_RET_GOTO_ERR(err, free_addr, "zxdh_virtqueue_add_outbuf failed: %d\n", err);

	if (virtqueue_kick_prepare_packed(sq->vq) && zxdh_virtqueue_notify(sq->vq)) {
		u64_stats_update_begin(&sq->stats.syncp);
		sq->stats.kicks++;
		u64_stats_update_end(&sq->stats.syncp);
	}
	return err;

free_addr:
	return MSGQ_RET_ERR_VQ_BROKEN;
}

static s32 zxdh_msgq_pkt_send(struct msgq_dev *msgq_dev, struct msgq_pkt_info *pkt_info, u16 sn)
{
	struct priv_queues_net_hdr *hdr = (struct priv_queues_net_hdr *)pkt_info->addr;
	void *buf = NULL;
	u32 len = 0;

	if (spin_trylock(&msgq_dev->tx_lock)) {
		while ((buf = zxdh_virtqueue_get_buf(msgq_dev->sq_priv->vq, &len)) != NULL) {
			ZXDH_FREE_PTR(buf);
		};
		spin_unlock(&msgq_dev->tx_lock);
	}

	memset(hdr, 0, PRIV_HEADER_LEN);
	hdr->tx_port = TX_PORT_NP;
	hdr->pd_len = PRIV_HEADER_LEN / 2;
	hdr->pi_hdr.pi_type = DEFAULT_PI_TYPE;
	hdr->pi_hdr.pkt_type = CONTROL_MSG_TYPE;
	hdr->pi_hdr.vfid_dst = htons(RISCV_COMMON_VFID);
	hdr->pi_hdr.qid_dst = htons(RISCV_COMMON_QID);
	hdr->pi_hdr.vfid_src = htons(msgq_dev->msgq_vfid);
	hdr->pi_hdr.qid_src = htons(msgq_dev->msgq_rqid);
	hdr->pi_hdr.event_id = pkt_info->event_id;
	hdr->pi_hdr.sequence_num = sn;
	if (sn == NO_REPS_SEQUENCE_NUM)
		hdr->pi_hdr.msg_type = NO_REPS_MSG;
	if (msgq_dev->loopback) {
		hdr->pi_hdr.event_id = MODULE_MSGQ;
		hdr->pi_hdr.vfid_dst = hdr->pi_hdr.vfid_src;
		hdr->pi_hdr.qid_dst = hdr->pi_hdr.qid_src;
	}

	return page_send_cmd(msgq_dev->sq_priv, pkt_info->addr, pkt_info->len,
			     msgq_dev->print_flag);
}

s32 zxdh_msgq_send_cmd(struct msgq_dev *msgq_dev, struct msgq_pkt_info *pkt_info,
		       struct reps_info *reps)
{
	u16 sn = NO_REPS_SEQUENCE_NUM;
	u16 sync_poll_cnt = 0;
	s32 err = 0;
	s32 i = 0;
	u32 tx_timeouts = 0;
	u32 tx_errs = 0;

	err = zxdh_msg_para_check(pkt_info, reps);
	ZXDH_CHECK_RET_GOTO_ERR(err, tx_err, "zxdh_msg_para_check failed: %d\n", err);

	if (unlikely((msgq_dev) == NULL)) {
		LOG_ERR("null pointer\n");
		goto free_addr;
	}
	CHECK_CHANNEL_USABLE(msgq_dev, err);
	if (err)
		goto free_addr;

	if (!pkt_info->no_reps) {
		err = zxdh_sequence_num_get(msgq_dev, &sn);
		ZXDH_CHECK_RET_GOTO_ERR(err, free_addr, "zxdh_sequence_num_get failed: %d\n", err);
	}

	mutex_lock(msgq_dev->mlock);
	err = zxdh_msgq_pkt_send(msgq_dev, pkt_info, sn);
	mutex_unlock(msgq_dev->mlock);
	ZXDH_CHECK_RET_GOTO_ERR(err, free_addr, "zxdh_msgq_pkt_send failed: %d\n", err);

	if (pkt_info->no_reps)
		return MSGQ_RET_OK;

	msgq_dev->msg_buff_ring[sn].data = &reps->addr;
	msgq_dev->msg_buff_ring[sn].data_len = &reps->len;
	msgq_dev->msg_buff_ring[sn].timeout_cnt = pkt_info->timeout_us / TIMER_DELAY_US;
	if (!pkt_info->is_async) {
		sync_poll_cnt = pkt_info->timeout_us / 10;
		for (i = 0; i < sync_poll_cnt; ++i) {
			usleep_range(5, 10);
			if (!msgq_dev->msg_buff_ring[sn].using &&
			    msgq_dev->msg_buff_ring[sn].valid) {
				return MSGQ_RET_OK;
			}
		}
		err = MSGQ_RET_ERR_CALLBACK_OUT_OF_TIME;
		goto free_sn;
	} else {
		msgq_dev->msg_buff_ring[sn].need_free = true;
		if (!msgq_dev->timer_in_use) {
			mod_timer(&msgq_dev->poll_timer,
				  jiffies + usecs_to_jiffies(TIMER_DELAY_US));
			msgq_dev->timer_in_use = true;
		}
	}
	return MSGQ_RET_OK;

free_addr:
	ZXDH_FREE_PTR(pkt_info->addr);
tx_err:
	tx_errs++;
free_sn:
	if ((sn != NO_REPS_SEQUENCE_NUM) && (sn < MSGQ_MAX_MSG_BUFF_NUM)) {
		LOG_ERR("timeout, sn[%d] is free\n", sn);
		msgq_dev->msg_buff_ring[sn].using = false;
		tx_timeouts++;
		msgq_dev->free_cnt--;
	}
	u64_stats_update_begin(&msgq_dev->sq_priv->stats.syncp);
	msgq_dev->sq_priv->stats.xdp_tx_drops += tx_errs;
	msgq_dev->sq_priv->stats.tx_timeouts += tx_timeouts;
	u64_stats_update_end(&msgq_dev->sq_priv->stats.syncp);
	return err;
}

static void zxdh_swap_dst_and_src(u16 *dst, u16 *src)
{
	u16 temp = 0;

	temp = *dst;
	*dst = *src;
	*src = temp;
}

static s32 zxdh_pi_header_check(struct pi_header *hdr)
{
	if (hdr->pi_type != DEFAULT_PI_TYPE) {
		LOG_ERR("INVALID_PI_TYPE: %d\n", hdr->pi_type);
		return MSGQ_RET_ERR_CALLBACK_FAIL;
	}

	if (hdr->pkt_type != CONTROL_MSG_TYPE) {
		LOG_ERR("INVALID_PKT_TYPE: %d\n", hdr->pkt_type);
		return MSGQ_RET_ERR_CALLBACK_FAIL;
	}

	if (hdr->msg_type > NO_REPS_MSG) {
		LOG_ERR("INVALID_MSG_TYPE: %d\n", hdr->msg_type);
		return MSGQ_RET_ERR_CALLBACK_FAIL;
	}

	if (hdr->event_id >= MSG_MODULE_NUM) {
		LOG_ERR("INVALID_MSG_MODULE_ID: %d\n", hdr->event_id);
		return MSGQ_RET_ERR_CALLBACK_FAIL;
	}

	if (hdr->err_code != MSGQ_RET_OK) {
		LOG_ERR("MSG_ERR_CODE: %d\n", hdr->err_code);
		return MSGQ_RET_ERR_CALLBACK_FAIL;
	}

	return MSGQ_RET_OK;
}

static void rx_free_pages(struct msgq_dev *msgq_dev, void *buf, u32 len)
{
	if (msgq_dev->print_flag == MSGQ_PRINT_ALL) {
		print_data((u8 *)buf, len);
		LOG_DEBUG("buf: 0x%llx refcnt: %d\n", (u64)buf,
			  page_ref_count(virt_to_head_page(buf)));
	}
	put_page(virt_to_head_page(buf));
}

static s32 zxdh_response_msg_handle(struct msgq_dev *msgq_dev, struct virtnet_rq_stats *stats,
				    u16 num_buf, void *buf, u32 len)
{
	struct priv_queues_net_hdr *hdr = (struct priv_queues_net_hdr *)buf;
	u16 sn = hdr->pi_hdr.sequence_num;
	s32 err = MSGQ_RET_OK;
	struct msg_buff *tmp_buff = NULL;
	u32 max_len = 0;
	u32 pkt_len = 0;

	if (sn >= MSGQ_MAX_MSG_BUFF_NUM) {
		LOG_ERR("INVALID_SEQUENCE_NUM: %d\n", sn);
		err = MSGQ_RET_ERR;
		goto put_page;
	}

	tmp_buff = &msgq_dev->msg_buff_ring[sn];
	if (!tmp_buff->using) {
		LOG_ERR("buff[%d] is free\n", sn);
		err = MSGQ_RET_ERR_CALLBACK_OUT_OF_TIME;
		goto put_page;
	}

	if (unlikely((*tmp_buff->data) == NULL)) {
		LOG_ERR("null pointer\n");
		goto put_page;
	}

	max_len = *(tmp_buff->data_len);
	pkt_len = len - PRIV_HEADER_LEN;
	if (pkt_len > max_len) {
		LOG_ERR("buf_len: %d > tmp_buff->data_len: %d\n", pkt_len, max_len);
		err = MSGQ_RET_ERR_REPS_LEN_NOT_ENOUGH;
		goto put_page;
	}

	memcpy(*tmp_buff->data, (u8 *)buf + PRIV_HEADER_LEN, pkt_len);
	while (--num_buf != 0) {
		rx_free_pages(msgq_dev, buf, len);
		buf = zxdh_virtqueue_get_buf(msgq_dev->rq_priv->vq, &len);
		if (unlikely(!buf)) {
			LOG_ERR("msgq rx error: %dth buffers missing\n", num_buf);
			stats->drops++;
			err = MSGQ_RET_ERR_RX_INVALID_NUM_BUF;
			goto out;
		}

		if ((len + pkt_len) > max_len) {
			LOG_ERR("buf_len: %d > tmp_buff->data_len: %d\n", len + pkt_len, max_len);
			err = MSGQ_RET_ERR_REPS_LEN_NOT_ENOUGH;
			goto put_page;
		}

		stats->bytes += len;
		memcpy((*tmp_buff->data) + pkt_len, buf, len);
		pkt_len += len;
	}
	*(tmp_buff->data_len) = pkt_len;
	tmp_buff->valid = true;
	stats->xdp_drops--;

put_page:
	put_page(virt_to_head_page(buf));
out:
	if (tmp_buff) {
		tmp_buff->using = false;
		tmp_buff->data = NULL;
		msgq_dev->free_cnt--;
	}
	return err;
}

static s32 zxdh_callback_msg_handle(struct zxdh_en_device *en_dev, u8 *buf_addr, u32 buf_len)
{
	struct msgq_dev *msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	s32 err = BAR_MSG_ERR_MODULE_NOEXIST;
	u8 *reps_addr = NULL;
	u16 reps_len = MAX_PACKET_LEN;
	u16 hdr_len = PRIV_HEADER_LEN;
	struct priv_queues_net_hdr *hdr = NULL;

	hdr = (struct priv_queues_net_hdr *)buf_addr;
	if (hdr->pi_hdr.msg_type == NO_REPS_MSG) {
		return call_msg_recv_func_tbl(hdr->pi_hdr.event_id, buf_addr + hdr_len,
					      buf_len - hdr_len, NULL, 0, en_dev);
	}

	reps_addr = kzalloc(MSGQ_MAX_ADDR_LEN, GFP_ATOMIC);
	if (unlikely((reps_addr) == NULL)) {
		LOG_ERR("null pointer\n");
		return MSGQ_RET_ERR_NULL_PTR;
	}
	memcpy(reps_addr, buf_addr, hdr_len);
	hdr = (struct priv_queues_net_hdr *)reps_addr;

	if (hdr->pi_hdr.event_id < MSG_MODULE_NUM) {
		err = call_msg_recv_func_tbl(hdr->pi_hdr.event_id, buf_addr + hdr_len,
					     buf_len - hdr_len, reps_addr + hdr_len, &reps_len,
					     en_dev);
		hdr->pi_hdr.msg_type = ACK_MSG;
	}

	if (err == BAR_MSG_ERR_MODULE_NOEXIST) {
		hdr->pi_hdr.err_code = ERR_CODE_EVENT_UNREGIST;
	} else if ((err != MSGQ_RET_OK) || (reps_len > MAX_PACKET_LEN)) {
		LOG_ERR("get reps failed, reps_len:%d\n", reps_len);
		hdr->pi_hdr.err_code = ERR_CODE_EVENT_FAIL;
	}

	zxdh_swap_dst_and_src(&hdr->pi_hdr.vfid_dst, &hdr->pi_hdr.vfid_src);
	zxdh_swap_dst_and_src(&hdr->pi_hdr.qid_dst, &hdr->pi_hdr.qid_src);

	return page_send_cmd(msgq_dev->sq_priv, reps_addr, reps_len + hdr_len,
			     msgq_dev->print_flag);
}

static void msgq_receive_buf(struct zxdh_en_device *en_dev, struct receive_queue *rq, void *buf,
			     u32 len, void **ctx, struct virtnet_rq_stats *stats)
{
	struct priv_queues_net_hdr *hdr = (struct priv_queues_net_hdr *)buf;
	u16 num_buf = vqm16_to_cpu(en_dev, hdr->num_buffers);
	struct msgq_dev *msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	s32 err = MSGQ_RET_OK;
	u8 *tmp_addr = NULL;
	u32 tmp_addr_len = len;
	bool free_tmp_addr = false;

	if (msgq_dev->print_flag != 0) {
		LOG_DEBUG("receive pkt start, num_buf: %d\n", num_buf);
		msgq_print_data((u8 *)buf, len, msgq_dev->print_flag);
	}

	stats->xdp_drops++;
	err = zxdh_pi_header_check(&hdr->pi_hdr);
	ZXDH_CHECK_RET_GOTO_ERR(err, free_pages, "invalid pi_header\n");

	if (hdr->pi_hdr.msg_type == ACK_MSG) {
		err = zxdh_response_msg_handle(msgq_dev, stats, num_buf, buf, len);
		goto free_addr;
	} else if (num_buf == 1) {
		err = zxdh_callback_msg_handle(en_dev, (u8 *)buf, len);
	} else {
		tmp_addr = kzalloc(MSGQ_MAX_ADDR_LEN, GFP_ATOMIC);
		if (unlikely((tmp_addr) == NULL)) {
			LOG_ERR("null pointer\n");
			goto free_pages;
		}
		memcpy(tmp_addr, buf, tmp_addr_len);
		free_tmp_addr = true;
		while (--num_buf != 0) {
			rx_free_pages(msgq_dev, buf, len);
			buf = virtqueue_get_buf_ctx_packed(rq->vq, &len, ctx);
			if (unlikely(!buf)) {
				LOG_ERR("msgq rx error: %dth buffers missing\n", num_buf);
				stats->drops++;
				goto free_addr;
			}

			memcpy(tmp_addr + tmp_addr_len, buf, len);
			tmp_addr_len += len;
		}
		err = zxdh_callback_msg_handle(en_dev, tmp_addr, tmp_addr_len);
	}
	stats->xdp_drops--;

free_pages:
	put_page(virt_to_head_page(buf));
free_addr:
	if (free_tmp_addr)
		ZXDH_FREE_PTR(tmp_addr);
	stats->bytes += tmp_addr_len;
}

static s32 zxdh_msgq_receive(struct receive_queue *rq, s32 budget)
{
	struct zxdh_en_device *en_dev = rq->vq->en_dev;
	struct virtnet_rq_stats stats = {};
	u32 len = 0;
	void *buf = NULL;
	s32 i = 0;
	void *ctx = NULL;
	u64 *item = NULL;

	while (stats.packets < budget && (buf = virtqueue_get_buf_ctx_packed(rq->vq, &len, &ctx))) {
		msgq_receive_buf(en_dev, rq, buf, len, &ctx, &stats);
		stats.packets++;
	}

	if (rq->vq->num_free > min_t(u32, budget, zxdh_virtqueue_get_vring_size(rq->vq)) / 2) {
		if (!msgq_try_fill_recv(rq, GFP_ATOMIC))
			LOG_ERR("msgq_try_fill_recv failed\n");
	}

	u64_stats_update_begin(&rq->stats.syncp);
	for (i = 0; i < VIRTNET_RQ_STATS_LEN; i++) {
		size_t offset = virtnet_rq_stats_desc[i].offset;

		item = (u64 *)((u8 *)&rq->stats + offset);
		*item += *(u64 *)((u8 *)&stats + offset);
	}
	u64_stats_update_end(&rq->stats.syncp);

	return stats.packets;
}

static void msgq_poll_cleantx(struct receive_queue *rq)
{
	struct zxdh_en_device *en_dev = rq->vq->en_dev;
	struct msgq_dev *msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	struct send_queue *sq = msgq_dev->sq_priv;

	if (!sq->napi.weight)
		return;

	if (spin_trylock(&msgq_dev->tx_lock)) {
		zxdh_virtqueue_disable_cb(sq->vq);
		//free_old_xmit_bufs(sq);
		spin_unlock(&msgq_dev->tx_lock);
	}
}

int zxdh_msgq_poll(struct napi_struct *napi, int budget)
{
	struct receive_queue *rq = container_of(napi, struct receive_queue, napi);
	struct zxdh_en_device *en_dev = rq->vq->en_dev;
	struct msgq_dev *msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	u32 received = 0;

	if (msgq_dev->msgq_enable) {
		msgq_poll_cleantx(rq);
		received = zxdh_msgq_receive(rq, budget);
	}

	if (received < budget)
		virtqueue_napi_complete(napi, rq->vq, received);

	return received;
}
