// SPDX-License-Identifier: GPL-2.0
/* Huawei iBMA driver.
 * Copyright (c) 2019, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "virtual_cdev_eth_net.h"

static struct edma_eth_dev_s g_eth_edmaprivate;
static struct edma_packet_node_s g_edma_recv_packet_tmp = {0, NULL};
static struct edma_cut_packet_node_s *g_edma_send_cut_packet;
static unsigned int g_last_token = TK_START_END;
static unsigned int g_device_opened = CDEV_CLOSED;
static unsigned int g_last_number;
static unsigned int g_peer_not_ready;
static unsigned int g_read_pos;
static unsigned int g_delay_ms;
static int g_write_count;

static const int NO_SPACE_RETRY = 10;
static const int NO_SPACE_WAIT_MS = 2000;
static const int CUT_PKG_SLEEP_MS = 1;
static const int CUT_PKG_LIMIT_COUNT = 30;
static const int SEND_INT_PKG_COUNT = 50;

static int cdev_open(struct inode *inode_ptr, struct file *filp);
static int cdev_release(struct inode *inode_ptr, struct file *filp);
static unsigned int cdev_poll(struct file *file, poll_table *wait);
static ssize_t cdev_read(struct file *filp, char __user *data,
			 size_t count, loff_t *ppos);
static ssize_t cdev_write(struct file *filp, const char __user *data,
			  size_t count, loff_t *ppos);

#define IS_CDEV_IN_OPEN_STATE() (g_device_opened != CDEV_CLOSED)
#define SET_CDEV_OPEN_STATE(x) (g_device_opened = (x))

int debug = DLOG_ERROR;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug switch (0=close debug, 1=open debug)");

#define GET_PRIVATE_DATA(f) (((struct cdev_dev_s *)((f)->private_data))->priv)

const struct file_operations g_eth_edma_cdev_fops = {
	.owner = THIS_MODULE,
	.open = cdev_open,
	.release = cdev_release,
	.poll = cdev_poll,
	.read = cdev_read,
	.write = cdev_write,
};

void dump_global_info(void)
{
	struct edma_shmq_hd_s *pshmqhd_v = NULL;

	if (!debug)
		return;

	LOG(DLOG_DEBUG, "\r\n=================VETH INFO=================\r\n");

	pshmqhd_v = g_eth_edmaprivate.ptx_queue->pshmqhd_v;
	LOG(DLOG_DEBUG, "TX head/tail: %u/%u ------------",
	    pshmqhd_v->head, pshmqhd_v->tail);

	pshmqhd_v = g_eth_edmaprivate.prx_queue->pshmqhd_v;
	LOG(DLOG_DEBUG, "RX head/tail: %u/%u ------------",
	    pshmqhd_v->head, pshmqhd_v->tail);
}

static inline int edma_is_queue_ready(struct edma_rxtx_q_s *prxtx_queue)
{
	if (!prxtx_queue)
		return 0;

	return (prxtx_queue->pshmqhd_v->init == BSPVETH_SHMQUEUE_INITOK_V2);
}

static inline void edma_veth_host_addr_init(void *priv)
{
	struct bma_priv_data_s *edma_priv = (struct bma_priv_data_s *)priv;

	g_eth_edmaprivate.pshmpool_p =
			(u8 *)edma_priv->specific.veth.veth_swap_phy_addr;
	g_eth_edmaprivate.pshmpool_v =
			(u8 *)edma_priv->specific.veth.veth_swap_addr;
	g_eth_edmaprivate.shmpoolsize =
			(u32)edma_priv->specific.veth.veth_swap_len;
}

void edma_veth_free_tx_resources(struct edma_rxtx_q_s *ptx_queue)
{
	struct edma_bd_info_s *pbdinfobase_v = NULL;

	if (!ptx_queue || !ptx_queue->pbdinfobase_v)
		return;

	pbdinfobase_v = ptx_queue->pbdinfobase_v;
	ptx_queue->pbdinfobase_v = NULL;
	ptx_queue->pshmqhd_v = NULL;

	vfree(pbdinfobase_v);

	LOG(DLOG_DEBUG, "%s ok. count=%d", __func__, ptx_queue->count);
}

void edma_veth_free_all_tx_resources(struct edma_eth_dev_s *edma_eth)
{
	if (edma_eth && edma_eth->ptx_queue) {
		edma_veth_free_tx_resources(edma_eth->ptx_queue);
		kfree(edma_eth->ptx_queue);
		edma_eth->ptx_queue = NULL;
	}
}

int edma_veth_setup_tx_resources(struct edma_rxtx_q_s *ptx_queue)
{
	int size;

	ptx_queue->count = MAX_QUEUE_BDNUM;
	size = sizeof(struct edma_bd_info_s) * ptx_queue->count;

	ptx_queue->pbdinfobase_v = vmalloc(size);
	if (!ptx_queue->pbdinfobase_v) {
		LOG(DLOG_ERROR, "Failed to alloc memory for the TX queue.");
		return -ENOMEM;
	}

	memset(ptx_queue->pbdinfobase_v, 0, size);

	/* round up to nearest 4K */
	size = sizeof(struct edma_dma_shmbd_s) * ptx_queue->count;
	ptx_queue->size = ALIGN(size, ALIGN_MASK);

	ptx_queue->work_limit = BSPVETH_WORK_LIMIT;

	return 0;
}

int edma_veth_setup_all_tx_resources(struct edma_eth_dev_s *edma_eth)
{
	int err;
	u8 *shmq_head = NULL;
	u8 *shmq_head_p = NULL;
	struct edma_rxtx_q_s *tx_queue = NULL;

	tx_queue = (struct edma_rxtx_q_s *)
		   kmalloc(sizeof(struct edma_rxtx_q_s), GFP_KERNEL);
	if (!tx_queue) {
		LOG(DLOG_ERROR, "Failed to alloc TX queue.");
		return -ENOMEM;
	}

	memset(tx_queue, 0, sizeof(struct edma_rxtx_q_s));

	shmq_head = edma_eth->pshmpool_v + (MAX_SHAREQUEUE_SIZE * 0);
	shmq_head_p = edma_eth->pshmpool_p + (MAX_SHAREQUEUE_SIZE * 0);

	tx_queue->pshmqhd_v = (struct edma_shmq_hd_s *)shmq_head;
	tx_queue->pshmqhd_p = shmq_head_p;

	tx_queue->pshmbdbase_v = (struct edma_dma_shmbd_s *)
				 (shmq_head + BSPVETH_SHMBDBASE_OFFSET);
	tx_queue->pshmbdbase_p = shmq_head_p + BSPVETH_SHMBDBASE_OFFSET;

	tx_queue->pdmalbase_v = (struct edma_dmal_s *)
				(shmq_head + SHMDMAL_OFFSET);
	tx_queue->pdmalbase_p = (u8 *)(VETH_SHAREPOOL_BASE_INBMC +
				(MAX_SHAREQUEUE_SIZE * 0) + SHMDMAL_OFFSET);

	memset(tx_queue->pdmalbase_v, 0, MAX_SHMDMAL_SIZE);

	err = edma_veth_setup_tx_resources(tx_queue);
	if (err) {
		kfree(tx_queue);
		return err;
	}

	edma_eth->ptx_queue = tx_queue;

	return 0;
}

int edma_veth_setup_rx_resources(struct edma_rxtx_q_s *prx_queue)
{
	int size;

	prx_queue->count = MAX_QUEUE_BDNUM;
	size = sizeof(struct edma_bd_info_s) * prx_queue->count;

	prx_queue->pbdinfobase_v = vmalloc(size);
	if (!prx_queue->pbdinfobase_v) {
		LOG(DLOG_ERROR, "Failed to alloc memory for the RX queue.");
		return -ENOMEM;
	}

	memset(prx_queue->pbdinfobase_v, 0, size);

	/* Round up to nearest 4K */
	size = sizeof(struct edma_dma_shmbd_s) * prx_queue->count;
	prx_queue->size = ALIGN(size, ALIGN_MASK);

	prx_queue->work_limit = BSPVETH_WORK_LIMIT;

	return 0;
}

int edma_veth_setup_all_rx_resources(struct edma_eth_dev_s *edma_eth)
{
	int err;
	u8 *shmq_head = NULL;
	u8 *shmq_head_p = NULL;
	struct edma_rxtx_q_s *rx_queue = NULL;

	rx_queue = (struct edma_rxtx_q_s *)
		   kmalloc(sizeof(struct edma_rxtx_q_s), GFP_KERNEL);
	if (!rx_queue) {
		LOG(DLOG_ERROR, "Failed to alloc RX queue.");
		return -ENOMEM;
	}

	memset(rx_queue, 0, sizeof(struct edma_rxtx_q_s));

	shmq_head = edma_eth->pshmpool_v + MAX_SHAREQUEUE_SIZE;
	shmq_head_p = edma_eth->pshmpool_p + MAX_SHAREQUEUE_SIZE;
	rx_queue->pshmqhd_v = (struct edma_shmq_hd_s *)shmq_head;
	rx_queue->pshmqhd_p = shmq_head_p;

	rx_queue->pshmbdbase_v = (struct edma_dma_shmbd_s *)(shmq_head +
				  BSPVETH_SHMBDBASE_OFFSET);
	rx_queue->pshmbdbase_p = shmq_head_p + BSPVETH_SHMBDBASE_OFFSET;

	/* DMA address list (only used in host). */
	rx_queue->pdmalbase_v = (struct edma_dmal_s *)
				(shmq_head + SHMDMAL_OFFSET);
	rx_queue->pdmalbase_p = (u8 *)(VETH_SHAREPOOL_BASE_INBMC +
				MAX_SHAREQUEUE_SIZE + SHMDMAL_OFFSET);
	memset(rx_queue->pdmalbase_v, 0, MAX_SHMDMAL_SIZE);

	err = edma_veth_setup_rx_resources(rx_queue);
	if (err) {
		kfree(rx_queue);
		return err;
	}

	edma_eth->prx_queue = rx_queue;

	return 0;
}

void edma_veth_free_rx_resources(struct edma_rxtx_q_s *prx_queue)
{
	struct edma_bd_info_s *pbdinfobase_v = NULL;

	if (!prx_queue || !prx_queue->pbdinfobase_v)
		return;

	pbdinfobase_v = prx_queue->pbdinfobase_v;
	prx_queue->pbdinfobase_v = NULL;
	prx_queue->pshmqhd_v = NULL;

	/* Free all the Rx ring pages */
	vfree(pbdinfobase_v);

	LOG(DLOG_DEBUG, "%s ok. count=%d", __func__, prx_queue->count);
}

void edma_veth_free_all_rx_resources(struct edma_eth_dev_s *edma_eth)
{
	if (edma_eth && edma_eth->prx_queue) {
		edma_veth_free_rx_resources(edma_eth->prx_queue);
		kfree(edma_eth->prx_queue);
		edma_eth->prx_queue = NULL;
	}
}

int edma_veth_setup_all_rxtx_queue(struct edma_eth_dev_s *edma_eth)
{
	void *buf = NULL;
	unsigned int i;
	unsigned int j;

	dma_addr_t dmaaddr;
	struct edma_bd_info_s *pbdinfobase_v = NULL;

	struct edma_rxtx_q_s *ptx_queue = NULL;
	struct edma_rxtx_q_s *prx_queue = NULL;

	struct bma_priv_data_s *priv = NULL;
	struct device *dev = NULL;

	priv = (struct bma_priv_data_s *)edma_eth->edma_priv;
	dev = &priv->specific.veth.pdev->dev;

	ptx_queue = edma_eth->ptx_queue;
	prx_queue = edma_eth->prx_queue;

	edma_eth->pages_tx = 0;

	pbdinfobase_v = ptx_queue->pbdinfobase_v;

	for (i = 0; i < MAX_QUEUE_BDNUM; i++) {
		buf = kmalloc(NODE_SIZE, GFP_KERNEL | GFP_DMA);
		if (!buf) {
			for (j = 0; j < i; j++)
				kfree((void *)pbdinfobase_v[j].pdma_v);

			LOG(DLOG_ERROR, "Fail to alloc tx buf.");
			return -ENOMEM;
		}

		dmaaddr = dma_map_single(dev, buf, NODE_SIZE, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dmaaddr)) {
			LOG(DLOG_ERROR, "Failed to map tx DMA address.");
			kfree(buf);
			return -EIO;
		}

		memset(buf, 0xFF, NODE_SIZE);

		pbdinfobase_v[i].pdma_v = (u8 *)(buf);
		pbdinfobase_v[i].dma_p = dmaaddr;
		pbdinfobase_v[i].len = NODE_SIZE;
	}

	LOG(DLOG_DEBUG, "set tx done.");

	edma_eth->pages_rx = 0;

	pbdinfobase_v = prx_queue->pbdinfobase_v;

	for (i = 0; i < MAX_QUEUE_BDNUM; i++) {
		buf = kmalloc(NODE_SIZE, GFP_KERNEL | GFP_DMA);
		if (!buf) {
			for (j = 0; j < i; j++)
				kfree((void *)pbdinfobase_v[j].pdma_v);

			LOG(DLOG_ERROR, "Fail to alloc rx buf.");
			return -ENOMEM;
		}

		dmaaddr = dma_map_single(dev, buf, NODE_SIZE, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dmaaddr)) {
			LOG(DLOG_ERROR, "Failed to map rx DMA address.");
			kfree(buf);
			return -EIO;
		}

		memset(buf, 0xFF, NODE_SIZE);

		pbdinfobase_v[i].pdma_v = (u8 *)(buf);
		pbdinfobase_v[i].dma_p = dmaaddr;
		pbdinfobase_v[i].len = NODE_SIZE;
	}

	LOG(DLOG_DEBUG, "set rx done.");

	return 0;
}

void edma_veth_dump(void)
{
	struct edma_eth_dev_s *edma_eth = &g_eth_edmaprivate;
	struct edma_rxtx_q_s *ptx_queue = edma_eth->ptx_queue;
	struct edma_rxtx_q_s *prx_queue = edma_eth->prx_queue;
	struct edma_shmq_hd_s *pshmq_head = NULL;

	if (!debug)
		return;

	pshmq_head = prx_queue->pshmqhd_v;

	LOG(DLOG_DEBUG,
	    "RX host_head:%u, host_tail:%u, shm_head:%u, shm_tail:%u, ",
	    prx_queue->head, prx_queue->tail,
	    pshmq_head->head, pshmq_head->tail);
	LOG(DLOG_DEBUG, "count: %u, total: %u, init: %u.",
	    pshmq_head->count, pshmq_head->total, pshmq_head->init);

	pshmq_head = ptx_queue->pshmqhd_v;

	LOG(DLOG_DEBUG,
	    "TX host_head:%u, host_tail:%u, shm_head:%u, shm_tail:%u, ",
	    ptx_queue->head, ptx_queue->tail,
	    pshmq_head->head, pshmq_head->tail);
	LOG(DLOG_DEBUG, "count: %u, total: %u, init: %u.",
	    pshmq_head->count, pshmq_head->total, pshmq_head->init);
}

int edma_veth_setup_resource(struct edma_eth_dev_s *edma_eth)
{
	int err;

	err = edma_veth_setup_all_rx_resources(edma_eth);
	if (err < 0)
		return err;

	err = edma_veth_setup_all_tx_resources(edma_eth);
	if (err < 0)
		goto FREE_RX;

	err = edma_veth_setup_all_rxtx_queue(edma_eth);
	if (err < 0)
		goto FREE_TX;

	return 0;

FREE_TX:
	edma_veth_free_all_tx_resources(edma_eth);
FREE_RX:
	edma_veth_free_all_rx_resources(edma_eth);

	return err;
}

int edma_veth_free_rxtx_queue(struct edma_eth_dev_s *edma_eth)
{
	int i;
	struct edma_rxtx_q_s *ptx_queue = NULL;
	struct edma_rxtx_q_s *prx_queue = NULL;

	struct bma_priv_data_s *priv = NULL;
	struct device *dev = NULL;

	struct edma_bd_info_s *pbdinfobase_v = NULL;

	if (!edma_eth || !edma_eth->edma_priv)
		return 0;

	priv = (struct bma_priv_data_s *)edma_eth->edma_priv;
	dev = &priv->specific.veth.pdev->dev;

	ptx_queue = edma_eth->ptx_queue;
	prx_queue = edma_eth->prx_queue;

	pbdinfobase_v = ptx_queue->pbdinfobase_v;

	for (i = 0; i < MAX_QUEUE_BDNUM; i++) {
		dma_unmap_single(dev, pbdinfobase_v[i].dma_p,
				 NODE_SIZE, DMA_TO_DEVICE);
		kfree(pbdinfobase_v[i].pdma_v);
	}

	pbdinfobase_v = prx_queue->pbdinfobase_v;

	for (i = 0; i < MAX_QUEUE_BDNUM; i++) {
		dma_unmap_single(dev, pbdinfobase_v[i].dma_p,
				 NODE_SIZE, DMA_FROM_DEVICE);
		kfree(pbdinfobase_v[i].pdma_v);
	}

	return 0;
}

void edma_veth_free_resource(struct edma_eth_dev_s *edma_eth)
{
	edma_veth_free_rxtx_queue(edma_eth);
	LOG(DLOG_DEBUG, "edma_veth_free_rxtx_queue done.");

	edma_veth_free_all_rx_resources(edma_eth);
	LOG(DLOG_DEBUG, "edma_veth_free_all_rx_resources done.");

	edma_veth_free_all_tx_resources(edma_eth);
	LOG(DLOG_DEBUG, "edma_veth_free_all_tx_resources done.");
}

int edma_veth_send_one_pkt(struct edma_cut_packet_node_s *cut_packet_node)
{
	u32 head, tail, i;
	struct edma_bd_info_s *pbdinfo_v = NULL;
	struct edma_rxtx_q_s *ptx_queue = g_eth_edmaprivate.ptx_queue;
	struct bma_priv_data_s *priv = NULL;
	struct device *dev = NULL;

	if (!cut_packet_node || !ptx_queue || !ptx_queue->pshmbdbase_v) {
		LOG(DLOG_ERROR, "Invalid packet node.");
		return -EFAULT;
	}

	priv = (struct bma_priv_data_s *)(g_eth_edmaprivate.edma_priv);
	dev = &priv->specific.veth.pdev->dev;

	if (!bma_intf_is_link_ok()) {
		LOG(DLOG_ERROR, "EDMA link is not ready.");
		return -EIO;
	}

	for (i = 0; i < NO_SPACE_RETRY; i++) {
		head = ptx_queue->head;
		tail = ptx_queue->tail;

		LOG(DLOG_DEBUG, "TX queue, before: head/tail: %u/%u", head, tail);

		if (JUDGE_RING_QUEUE_SPACE(head, tail, 1))
			break;

		if (i == NO_SPACE_RETRY - 1) {
			LOG(DLOG_ERROR, "EDMA queue has no space.");
			return -EBUSY;
		}

		tasklet_hi_schedule(&g_eth_edmaprivate.dma_task);
		msleep(NO_SPACE_WAIT_MS);
	}

	ptx_queue->head = (head + 1) & BSPVETH_POINT_MASK;

	pbdinfo_v = ptx_queue->pbdinfobase_v + head;

	pbdinfo_v->len = NODE_TO_PACKET_SIZE(cut_packet_node);
	(void)memcpy(pbdinfo_v->pdma_v, cut_packet_node, pbdinfo_v->len);

	/* Force sync data from CPU to device. */
	dma_sync_single_for_device(dev, pbdinfo_v->dma_p,
				   pbdinfo_v->len, DMA_TO_DEVICE);

	LOG(DLOG_DEBUG, "TX queue, after: head/tail: %u -> %u\n",
	    ptx_queue->head, ptx_queue->tail);

	return 0;
}

static inline unsigned int edma_veth_get_ring_buf_count(unsigned int head,
							unsigned int tail,
							unsigned int size)
{
	return (tail + size - head) % size;
}

static inline void edma_veth_flush_ring_node(struct edma_packet_node_s *node,
					     unsigned int ring_len)
{
	unsigned int i;

	for (i = 0; i < ring_len; i++) {
		kfree(node[i].packet);
		node[i].packet = NULL;
	}
}

static int get_peer_queue_stress(struct edma_rxtx_q_s *queue)
{
	int stress;

	if (++g_write_count < RL_MAX_PACKET) {
		/* not enough packets, use the last delay. */
		return -1;
	}

	g_write_count = 0;

	/* check peer rx queue stress. */
	if (!queue || queue->pshmqhd_v->total == 0) {
		/* no rate limit allowed. */
		return 0;
	}

	stress = (int)((queue->pshmqhd_v->count * STRESS_FACTOR) /
			queue->pshmqhd_v->total);

	return stress;
}

static void do_queue_rate_limit(struct edma_rxtx_q_s *queue)
{
	unsigned long delay_jiffies;
	int stress = get_peer_queue_stress(queue);

	LOG(DLOG_DEBUG, "count: %u, total: %u, stress: %d",
	    queue->pshmqhd_v->count, queue->pshmqhd_v->total, stress);

	if (stress >= RL_STRESS_HIGH)
		g_delay_ms = RL_DELAY_MS_HIGH;
	else if (stress >= RL_STRESS_LOW)
		g_delay_ms = RL_DELAY_MS_LOW;
	else if (stress >= 0)
		g_delay_ms = 0;

	if (g_delay_ms) {
		delay_jiffies = msecs_to_jiffies(g_delay_ms);
		schedule_timeout_killable(delay_jiffies);
	}
}

static int edma_veth_cut_tx_packet_send(struct edma_eth_dev_s *eth_dev,
					const char __user *data, size_t len)
{
	int ret = 0;
	struct edma_cut_packet_node_s *tx_cut_pkt = g_edma_send_cut_packet;
	unsigned int length = len;
	unsigned int already_read_len = 0;
	unsigned int count = 0;

	if (!tx_cut_pkt)
		return -EFAULT;

	do_queue_rate_limit(eth_dev->ptx_queue);

	while (length > 0) {
		LOG(DLOG_DEBUG, "length: %u/%zu", length, len);

		if (length > BSPPACKET_MTU_MAX) {
			/* fragment. */
			if (copy_from_user(tx_cut_pkt->cut_packet,
					   data + already_read_len,
					   BSPPACKET_MTU_MAX)) {
				LOG(DLOG_DEBUG, "Failed to copy user data.");
				return -EFAULT;
			}
			tx_cut_pkt->number = count++;
			length = length - BSPPACKET_MTU_MAX;

			if (tx_cut_pkt->number == 0) {
				tx_cut_pkt->token = TK_START_PACKET;
				tx_cut_pkt->cut_packet_len = BSPPACKET_MTU_MAX;
			} else {
				tx_cut_pkt->token = TK_MIDDLE_PACKET;
				tx_cut_pkt->cut_packet_len = BSPPACKET_MTU_MAX;
			}
		} else {
			if (copy_from_user(tx_cut_pkt->cut_packet,
					   data + already_read_len, length)) {
				LOG(DLOG_DEBUG, "Failed to copy user data.");
				return -EFAULT;
			}
			tx_cut_pkt->number = count++;
			if (len > BSPPACKET_MTU_MAX)
				tx_cut_pkt->token = TK_END_PACKET;
			else
				tx_cut_pkt->token = TK_START_END;

			tx_cut_pkt->cut_packet_len = length;
			length = 0;
		}

		already_read_len += tx_cut_pkt->cut_packet_len;
		ret = edma_veth_send_one_pkt(tx_cut_pkt);
		if (ret < 0) {
			LOG(DLOG_DEBUG, "edma_veth_send_one_pkt failed, %d.",
			    ret);
			return ret;
		}
		if (length > 0 && count > CUT_PKG_LIMIT_COUNT) {
			LOG(DLOG_DEBUG, "middle pkg: %d, need sleep.",
				count);
			msleep(CUT_PKG_SLEEP_MS);
			/* send a interrupt to BMC for recv package */
			if (count % SEND_INT_PKG_COUNT == 0)
				tasklet_hi_schedule(&g_eth_edmaprivate.dma_task);
		}
	}

	LOG(DLOG_DEBUG, "send done, length: %u", length);

	return 0;
}

static int edma_veth_copy_full_packet(struct edma_eth_dev_s *eth_dev,
				      u8 *packet, u32 len)
{
	unsigned int count = 0;
	unsigned long flags = 0;
	u8 *ptr = NULL;

	LOG(DLOG_DEBUG, "Recv full packet, len %u.", len);

	ptr = kmalloc(len, GFP_ATOMIC);
	if (ptr) {
		/* lock the queue. */
		spin_lock_irqsave(&eth_dev->rx_queue_lock, flags);

		count = edma_veth_get_ring_buf_count(eth_dev->rx_packet_head,
						     eth_dev->rx_packet_tail,
						     MAX_RXTX_PACKET_LEN);
		if (count >= (MAX_RXTX_PACKET_LEN - 1)) {
			LOG(DLOG_DEBUG, "The rx queue is full.");
			spin_unlock_irqrestore(&eth_dev->rx_queue_lock, flags);
			kfree(ptr);
			return -EBUSY;
		}

		(void)memcpy(ptr, packet, len);
		eth_dev->rx_packet[eth_dev->rx_packet_tail].packet = ptr;
		eth_dev->rx_packet[eth_dev->rx_packet_tail].len = len;
		eth_dev->rx_packet_tail = (eth_dev->rx_packet_tail + 1) %
					   MAX_RXTX_PACKET_LEN;

		spin_unlock_irqrestore(&eth_dev->rx_queue_lock, flags);

		return 0;
	}

	return -ENOMEM;
}

static int edma_veth_cut_rx_packet_recv(struct edma_eth_dev_s *eth_dev,
					u8 *packet, u32 len)
{
	int ret = 0;
	struct edma_cut_packet_node_s *node =
	    (struct edma_cut_packet_node_s *)packet;
	struct edma_packet_node_s *g_packet = &g_edma_recv_packet_tmp;
	unsigned int copy_back = 0;

	if (node->cut_packet_len && len > NODE_TO_PACKET_SIZE(node))
		len = NODE_TO_PACKET_SIZE(node);

	LOG(DLOG_DEBUG,
	    "cut_packet_len: %u, token: %u/%u, number: %u, real length: %u.",
	    node->cut_packet_len, node->token, g_last_token, node->number, len);

	if (node->cut_packet_len > BSPPACKET_MTU_MAX ||
	    ((g_packet->len + node->cut_packet_len) > MAX_PACKET_LEN)) {
		LOG(DLOG_ERROR, "This packet is too long, packet length %u/%u",
		    node->cut_packet_len, g_packet->len);
		ret = -EINVAL;
		goto fail;
	}

	if (g_last_token == TK_START_END || g_last_token == TK_END_PACKET) {
		/* This should be a new packet. */
		if (node->token == TK_START_PACKET ||
		    node->token == TK_START_END) {
			(void)memcpy(g_packet->packet, node->cut_packet,
				     node->cut_packet_len);
			g_packet->len = node->cut_packet_len;

			if (node->token == TK_START_END) {
				/* A full packet, increase tail. */
				copy_back = 1;
			} else {
				LOG(DLOG_DEBUG,
				    "Add middle packet with length %u",
				    node->cut_packet_len);
			}
		} else {
			LOG(DLOG_ERROR, "The rx packet is out-of-order");
			LOG(DLOG_ERROR, "token: %d, len: %u, number: %u",
			    node->token, node->cut_packet_len, node->number);
			ret = -EINVAL;
			goto fail;
		}
	} else {
		/* Fragments, last token: TK_MIDDLE_PACKET/TK_START_PACKET. */
		if (g_last_number != (node->number - 1)) {
			LOG(DLOG_ERROR, "The number is not correct (%u/%u)",
			    g_last_number, node->number);
			ret = -EINVAL;
			goto fail;
		}

		if (node->token == TK_MIDDLE_PACKET) {
			(void)memcpy(g_packet->packet + g_packet->len,
				     node->cut_packet, node->cut_packet_len);
			g_packet->len = g_packet->len + node->cut_packet_len;
			LOG(DLOG_DEBUG, "Add middle packet with length %u",
			    node->cut_packet_len);
		} else if (node->token == TK_END_PACKET) {
			(void)memcpy(g_packet->packet + g_packet->len,
				     node->cut_packet, node->cut_packet_len);
			g_packet->len = g_packet->len + node->cut_packet_len;
			copy_back = 1;
		} else {
			LOG(DLOG_ERROR, "Unexpected token: %u", node->token);
			ret = -EINVAL;
			goto fail;
		}
	}

	if (copy_back) {
		ret = edma_veth_copy_full_packet(eth_dev, g_packet->packet,
						 g_packet->len);
		g_packet->len = 0;
	}

	g_last_token = node->token;
	g_last_number = node->number;

	LOG(DLOG_DEBUG, "rx_packet_head:%u, rx_packet_tail: %u",
	    eth_dev->rx_packet_head, eth_dev->rx_packet_tail);

	return copy_back;

fail:
	g_last_token = TK_START_END;
	g_last_number = 0;
	memset(g_packet->packet, 0, MAX_PACKET_LEN);
	g_packet->len = 0;

	return ret;
}

int edma_veth_recv_pkt(struct edma_rxtx_q_s *prx_queue,
		       struct bma_priv_data_s *priv)
{
	int ret = BSP_OK;

	u32 i, work_limit;
	u32 tail, head;

	struct edma_bd_info_s *prx_bdinfo_v = NULL;
	struct device *dev = NULL;

	u8 *packet = NULL;
	u32 len;
	u32 off;

	wait_queue_head_t *queue_head = NULL;
	u8 do_wake_up = 0;

	if (!priv)
		return BSP_OK;

	dev = &priv->specific.veth.pdev->dev;

	work_limit = prx_queue->work_limit;
	tail = prx_queue->tail;

	for (i = 0; i < work_limit; i++) {
		head = prx_queue->head;

		if (tail == head)
			break;

		LOG(DLOG_DEBUG, "===== enter ===== [%u/%u] ======", head, tail);
		prx_bdinfo_v = prx_queue->pbdinfobase_v + tail;

		len = prx_bdinfo_v->len;
		off = prx_bdinfo_v->off;
		packet = prx_bdinfo_v->pdma_v;

		LOG(DLOG_DEBUG, "off:%u, len: %u.", off, len);

		if (!IS_CDEV_IN_OPEN_STATE()) {
			LOG(DLOG_DEBUG,
			    "Local char device is not opened, drop packet");
			tail = BD_QUEUE_MASK(tail + 1);
			continue;
		}

		dma_sync_single_for_cpu(dev, prx_bdinfo_v->dma_p,
					len + off, DMA_FROM_DEVICE);

		if (off)
			packet += off;

		ret = edma_veth_cut_rx_packet_recv(&g_eth_edmaprivate,
						   packet, len);
		if (ret < 0)
			LOG(DLOG_DEBUG, "recv rx pkt fail, ret: %d", ret);
		else if (ret != 0)
			do_wake_up = 1;

		tail = BD_QUEUE_MASK(tail + 1);
	}

	prx_queue->tail = tail;
	head = prx_queue->head;

	if (tail != head) {
		/* check if more processing is needed. */
		return BSP_ERR_AGAIN;
	} else if (do_wake_up) {
		queue_head = (wait_queue_head_t *)bma_cdev_get_wait_queue(priv);
		/* finish reciving pkt, wake up the waiting process. */
		if (queue_head && waitqueue_active(queue_head)) {
			LOG(DLOG_DEBUG, "Wake up queue.");
			wake_up(queue_head);
		}
	}

	return BSP_OK;
}

void edma_task_do_packet_recv(unsigned long data)
{
	int ret = BSP_OK;
	struct edma_rxtx_q_s *prx_queue = NULL;
	struct bma_priv_data_s *priv = NULL;
	struct tasklet_struct *t = (struct tasklet_struct *)data;

	priv = (struct bma_priv_data_s *)g_eth_edmaprivate.edma_priv;
	prx_queue = g_eth_edmaprivate.prx_queue;

	if (prx_queue) {
		g_eth_edmaprivate.run_skb_RX_task++;

		ret = edma_veth_recv_pkt(prx_queue, priv);
	}

	if (ret == BSP_ERR_AGAIN)
		tasklet_hi_schedule(t);
}

static inline void edma_veth_reset_dma(int type)
{
	bma_intf_reset_dma(GET_DMA_DIRECTION(type));
}

int __dmacmp_err_deal_2(struct edma_rxtx_q_s *prxtx_queue, u32 type)
{
	prxtx_queue->dmacmperr = 0;
	prxtx_queue->start_dma = 0;

	(void)edma_veth_reset_dma(type);

	if (type == BSPVETH_RX) {
		LOG(DLOG_DEBUG,
		    "bmc->host dma time out, dma count:%d, work_limit:%d\n",
		    prxtx_queue->dmal_cnt,
		    prxtx_queue->work_limit);

		prxtx_queue->s.dma_failed++;
	} else {
		LOG(DLOG_DEBUG,
		    "host->bmc dma time out, dma count:%d, work_limit:%d\n",
		    prxtx_queue->dmal_cnt,
		    prxtx_queue->work_limit);

		prxtx_queue->s.dma_failed++;
	}

	if (prxtx_queue->dmal_cnt > 1)
		prxtx_queue->work_limit = (prxtx_queue->dmal_cnt >> 1);

	prxtx_queue->dma_overtime++;
	if (prxtx_queue->dma_overtime > BSPVETH_MAX_QUE_DEEP)
		return BSPVETH_DMA_BUSY;

	return BSP_OK;
}

int edma_veth_check_dma_status(struct edma_rxtx_q_s *prxtx_queue, u32 type)
{
	int i = 0;
	enum dma_direction_e dir = GET_DMA_DIRECTION(type);

	for (i = 0; i < BSPVETH_CHECK_DMA_STATUS_TIMES; i++) {
		if (bma_intf_check_dma_status(dir) == BSPVETH_DMA_OK)
			return BSP_OK;

		cpu_relax();

		if (i > DMA_STATUS_CHECK_DELAY_LIMIT)
			udelay(DMA_STATUS_CHECK_DELAY_MS);
	}

	prxtx_queue->s.dma_busy++;
	prxtx_queue->dmacmperr++;

	return BSPVETH_DMA_BUSY;
}

int __check_dmacmp_H_2(struct edma_rxtx_q_s *prxtx_queue, u32 type)
{
	u16 start_dma;
	u16 dmacmperr;
	u32 cnt = 0;
	u32 len = 0;
	u32 host_head = 0;
	u32 host_tail = 0;
	u32 shm_head = 0;
	u32 shm_tail = 0;
	s32 ret;
	struct edma_shmq_hd_s *pshmq_head = NULL;

	if (!prxtx_queue || !prxtx_queue->pshmqhd_v)
		return BSP_ERR_NULL_POINTER;

	start_dma = prxtx_queue->start_dma;
	if (!start_dma)
		return BSP_OK;

	pshmq_head = prxtx_queue->pshmqhd_v;
	dmacmperr = prxtx_queue->dmacmperr;

	if (dmacmperr > BSPVETH_WORK_LIMIT / DMACMP_ERR_FACTOR)
		return __dmacmp_err_deal_2(prxtx_queue, type);

	ret = edma_veth_check_dma_status(prxtx_queue, type);
	if (ret != BSP_OK)
		return ret;

	prxtx_queue->start_dma = 0;
	prxtx_queue->dma_overtime = 0;

	if (type == BSPVETH_RX) {
		cnt = prxtx_queue->dmal_cnt;
		len = prxtx_queue->dmal_byte;

		host_head = prxtx_queue->head;
		shm_tail = pshmq_head->tail;

		pshmq_head->tail = BD_QUEUE_MASK(shm_tail + cnt);
		prxtx_queue->head = BD_QUEUE_MASK(host_head + cnt);

		LOG(DLOG_DEBUG, "RX:host_head:%u, host_tail:%u, ",
		    prxtx_queue->head, prxtx_queue->tail);

		LOG(DLOG_DEBUG, "shm_head:%u, shm_tail:%u, inc: %u.",
		    pshmq_head->head, pshmq_head->tail, cnt);

		prxtx_queue->s.dmapkt += cnt;
		prxtx_queue->s.dmapktbyte += len;
	} else {
		cnt = prxtx_queue->dmal_cnt;
		len = prxtx_queue->dmal_byte;

		host_tail = prxtx_queue->tail;
		shm_head = pshmq_head->head;

		prxtx_queue->tail = BD_QUEUE_MASK(host_tail + cnt);
		pshmq_head->head = BD_QUEUE_MASK(shm_head + cnt);

		LOG(DLOG_DEBUG, "TX:host_head:%u, host_tail:%u, ",
		    prxtx_queue->head, prxtx_queue->tail);

		LOG(DLOG_DEBUG, "shm_head:%u, shm_tail:%u, inc: %u.",
		    pshmq_head->head, pshmq_head->tail, cnt);

		prxtx_queue->s.dmapkt += cnt;
		prxtx_queue->s.dmapktbyte += len;
	}

	tasklet_hi_schedule(&g_eth_edmaprivate.skb_task);

	(void)bma_intf_int_to_bmc(g_eth_edmaprivate.edma_priv);

	g_eth_edmaprivate.tobmc_int++;

	return BSP_OK;
}

int __checkspace_H_2(struct edma_rxtx_q_s *prxtx_queue, u32 type, u32 *pcnt)
{
	u32 host_head, host_tail;
	u32 shm_head, shm_tail;
	u32 shm_cnt, host_cnt, cnt_tmp, cnt;
	struct edma_shmq_hd_s *pshmq_head = NULL;

	if (!prxtx_queue || !prxtx_queue->pshmqhd_v)
		return -EFAULT;

	pshmq_head = prxtx_queue->pshmqhd_v;

	host_head = prxtx_queue->head;
	host_tail = prxtx_queue->tail;
	shm_head = pshmq_head->head;
	shm_tail = pshmq_head->tail;

	LOG(DLOG_DEBUG, "host_head:%u, host_tail:%u, shm_head:%u, shm_tail:%u.",
	    host_head, host_tail, shm_head, shm_tail);

	switch (type) {
	case BSPVETH_RX:
		if (shm_head == shm_tail) {
			prxtx_queue->s.shm_empty++;
			return BSP_ERR_NOT_TO_HANDLE;
		}

		if (!JUDGE_RING_QUEUE_SPACE(host_head, host_tail, 1))
			return -EFAULT;

		shm_cnt = GET_BD_RING_QUEUE_COUNT(shm_head, shm_tail);
		cnt_tmp = min(shm_cnt, prxtx_queue->work_limit);

		host_cnt = GET_BD_RING_QUEUE_SPACE(host_tail, host_head);
		cnt = min(cnt_tmp, host_cnt);

		LOG(DLOG_DEBUG,
		    "RX, host_cnt: %u, shm_cnt: %u, cnt_tmp: %u, cnt: %u",
		    host_cnt, shm_cnt, cnt_tmp, cnt);

		break;

	case BSPVETH_TX:
		if (host_tail == host_head) {
			prxtx_queue->s.q_empty++;
			return BSP_ERR_NOT_TO_HANDLE;
		}

		host_cnt = GET_BD_RING_QUEUE_COUNT(host_head, host_tail);
		cnt_tmp = min(host_cnt, prxtx_queue->work_limit);

		shm_cnt = GET_BD_RING_QUEUE_SPACE(shm_head, shm_tail);
		cnt = min(cnt_tmp, shm_cnt);

		LOG(DLOG_DEBUG,
		    "TX, host_cnt: %u, shm_cnt: %u, cnt_tmp: %u, cnt: %u",
		    host_cnt, shm_cnt, cnt_tmp, cnt);

		break;

	default:
		prxtx_queue->s.type_err++;
		return -EFAULT;
	}

	if (cnt > ((BSPVETH_DMABURST_MAX * DMABURST_FACTOR) /
				(DMABURST_FACTOR + 1)))
		prxtx_queue->s.dma_burst++;

	*pcnt = cnt;

	return BSP_OK;
}

int __make_dmalistbd_h2b_H_2(struct edma_rxtx_q_s *prxtx_queue, u32 cnt)
{
	u32 i = 0;
	u32 len = 0;
	u32 off = 0;
	struct edma_dmal_s *pdmalbase_v = NULL;
	struct edma_shmq_hd_s *pshmq_head = NULL;
	struct edma_bd_info_s *pbdinfobase_v = NULL;
	struct edma_dma_shmbd_s *pshmbdbase_v = NULL;

	unsigned long addr;

	u32 host_tail;
	u32 shm_head;

	if (!prxtx_queue)
		return -EFAULT;

	if (cnt == 0)
		return 0;

	pdmalbase_v = prxtx_queue->pdmalbase_v;
	pbdinfobase_v = prxtx_queue->pbdinfobase_v;
	pshmbdbase_v = prxtx_queue->pshmbdbase_v;

	pshmq_head = prxtx_queue->pshmqhd_v;

	host_tail = prxtx_queue->tail;
	shm_head = pshmq_head->head;

	for (i = 0; i < cnt; i++) {
		LOG(DLOG_DEBUG, "TX DMA, HOST: %u -> BMC: %u",
		    host_tail, shm_head);

		pdmalbase_v[i].chl = 0x1;

		addr = EDMA_ADDR_ALIGNED(pbdinfobase_v[host_tail].dma_p);
		off = EDMA_ADDR_OFFSET(addr);

		/* src: veth_send_one_pkt. */
		pdmalbase_v[i].slow = lower_32_bits(addr);
		pdmalbase_v[i].shi = upper_32_bits(addr);

		/* dst: bmc dma, in shared memory. */
		pdmalbase_v[i].dlow =
		    lower_32_bits(pshmbdbase_v[shm_head].dma_p);
		pdmalbase_v[i].dhi = 0;

		/* len: len + offset caused by alignment */
		pdmalbase_v[i].len = pbdinfobase_v[host_tail].len + off;

		LOG(DLOG_DEBUG,
		    "TX DMA %08x%08x -> %08x%08x, off: %u, len: %u.",
		    pdmalbase_v[i].shi, pdmalbase_v[i].slow,
		    pdmalbase_v[i].dhi, pdmalbase_v[i].dlow,
		    off, pbdinfobase_v[host_tail].len);

		pshmbdbase_v[shm_head].len = pbdinfobase_v[host_tail].len;
		pshmbdbase_v[shm_head].off = off;

		len += pdmalbase_v[i].len;

		/* ready for the next round. */
		host_tail = BD_QUEUE_MASK(host_tail + 1);
		shm_head = BD_QUEUE_MASK(shm_head + 1);
	}

	pdmalbase_v[i - 1].chl = 0x9;

	pdmalbase_v[i].chl = 0x7;
	pdmalbase_v[i].len = 0x0;
	pdmalbase_v[i].slow = lower_32_bits((u64)prxtx_queue->pdmalbase_p);
	pdmalbase_v[i].shi = upper_32_bits((u64)prxtx_queue->pdmalbase_p);
	pdmalbase_v[i].dlow = 0;
	pdmalbase_v[i].dhi = 0;

	prxtx_queue->dmal_cnt = cnt;
	prxtx_queue->dmal_byte = len;

	return 0;
}

int __make_dmalistbd_b2h_H_2(struct edma_rxtx_q_s *prxtx_queue, u32 cnt)
{
	u32 i;
	u32 len = 0;

	struct edma_dmal_s *pdmalbase_v = NULL;
	struct edma_shmq_hd_s *pshmq_head = NULL;
	struct edma_bd_info_s *pbdinfobase_v = NULL;
	struct edma_dma_shmbd_s *pshmbdbase_v = NULL;

	u32 host_head;
	u32 shm_tail;

	if (!prxtx_queue)
		return -EFAULT;

	if (cnt == 0)
		return -EFAULT;

	pdmalbase_v = prxtx_queue->pdmalbase_v;
	pbdinfobase_v = prxtx_queue->pbdinfobase_v;
	pshmbdbase_v = prxtx_queue->pshmbdbase_v;

	pshmq_head = prxtx_queue->pshmqhd_v;

	host_head = prxtx_queue->head;
	shm_tail = pshmq_head->tail;

	for (i = 0; i < cnt; i++) {
		LOG(DLOG_DEBUG, "RX DMA, BMC: %u -> HOST: %u",
		    shm_tail, host_head);

		pbdinfobase_v[host_head].off = pshmbdbase_v[shm_tail].off;
		pbdinfobase_v[host_head].len = pshmbdbase_v[shm_tail].len;

		pdmalbase_v[i].chl = 0x1;

		/* src: bmc set in shared memory. */
		pdmalbase_v[i].slow =
		    lower_32_bits(pshmbdbase_v[shm_tail].dma_p);
		pdmalbase_v[i].shi = 0;

		/* dst: edma_veth_setup_all_rxtx_queue. */
		pdmalbase_v[i].dlow =
		    lower_32_bits(pbdinfobase_v[host_head].dma_p);
		pdmalbase_v[i].dhi =
		    upper_32_bits(pbdinfobase_v[host_head].dma_p);

		pdmalbase_v[i].len = pshmbdbase_v[shm_tail].len +
				     pshmbdbase_v[shm_tail].off;

		LOG(DLOG_DEBUG,
		    "RX DMA %08x%08x -> %08x%08x, off: %u, len: %u, total: %u.",
		    pdmalbase_v[i].shi, pdmalbase_v[i].slow,
		    pdmalbase_v[i].dhi, pdmalbase_v[i].dlow,
		    pshmbdbase_v[shm_tail].off, pshmbdbase_v[shm_tail].len,
		    pdmalbase_v[i].len);

		len += pdmalbase_v[i].len;

		/* ready for the next round. */
		host_head = BD_QUEUE_MASK(host_head + 1);
		shm_tail = BD_QUEUE_MASK(shm_tail + 1);
	}

	pdmalbase_v[i - 1].chl = 0x9;

	pdmalbase_v[i].chl = 0x7;
	pdmalbase_v[i].len = 0x0;
	pdmalbase_v[i].slow = lower_32_bits((u64)prxtx_queue->pdmalbase_p);
	pdmalbase_v[i].shi = upper_32_bits((u64)prxtx_queue->pdmalbase_p);
	pdmalbase_v[i].dlow = 0;
	pdmalbase_v[i].dhi = 0;

	prxtx_queue->dmal_cnt = cnt;
	prxtx_queue->dmal_byte = len;

	return 0;
}

int __start_dmalist_H_2(struct edma_rxtx_q_s *prxtx_queue, u32 type, u32 cnt)
{
	int ret = BSP_OK;
	struct bma_dma_transfer_s dma_transfer = { 0 };
	struct edma_shmq_hd_s *pshmq_head = NULL;

	if (!prxtx_queue)
		return -1;

	pshmq_head = prxtx_queue->pshmqhd_v;

	LOG(DLOG_DEBUG, "before -> %u/%u/%u/%u.",
	    prxtx_queue->head, prxtx_queue->tail,
	    pshmq_head->head, pshmq_head->tail);

	if (type == BSPVETH_RX) {
		dma_transfer.dir = BMC_TO_HOST;
		ret = __make_dmalistbd_b2h_H_2(prxtx_queue, cnt);
	} else {
		dma_transfer.dir = HOST_TO_BMC;
		ret = __make_dmalistbd_h2b_H_2(prxtx_queue, cnt);
	}

	if (ret < 0)
		return ret;

	dma_transfer.type = DMA_LIST;
	dma_transfer.transfer.list.dma_addr =
	    (dma_addr_t)prxtx_queue->pdmalbase_p;

	ret = bma_intf_start_dma(g_eth_edmaprivate.edma_priv, &dma_transfer);
	LOG(DLOG_DEBUG, "after -> %u/%u/%u/%u, ret: %d",
	    prxtx_queue->head, prxtx_queue->tail,
	    pshmq_head->head, pshmq_head->tail,
	    ret);

	if (ret < 0)
		return ret;

	prxtx_queue->start_dma = 1;

	return BSP_OK;
}

int check_dma_queue_fault_2(struct edma_rxtx_q_s *prxtx_queue,
			    u32 type, u32 *pcnt)
{
	int ret;
	u32 cnt = 0;

	if (prxtx_queue->dma_overtime > BSPVETH_MAX_QUE_DEEP)
		return -EFAULT;

	ret = __check_dmacmp_H_2(prxtx_queue, type);
	if (ret != BSP_OK)
		return -EFAULT;

	ret = __checkspace_H_2(prxtx_queue, type, &cnt);
	if (ret != BSP_OK)
		return -EFAULT;

	if (CHECK_DMA_RXQ_FAULT(prxtx_queue, type, cnt)) {
		udelay(DMA_RXQ_FAULT_DELAY);

		prxtx_queue->dmal_cnt--;

		return -EFAULT;
	}

	*pcnt = cnt;

	return BSP_OK;
}

int __dma_rxtx_H_2(struct edma_rxtx_q_s *prxtx_queue, u32 type)
{
	int ret;
	u32 cnt = 0;

	if (!prxtx_queue || !prxtx_queue->pshmqhd_v)
		return -EFAULT;

	if (CHECK_DMA_QUEUE_EMPTY(type, prxtx_queue)) {
		LOG(DLOG_DEBUG, "Queue (type: %u) is empty.", type);
		return BSP_OK;
	}

	ret = check_dma_queue_fault_2(prxtx_queue, type, &cnt);
	if (ret != BSP_OK) {
		LOG(DLOG_DEBUG, "check_dma_queue_fault_2 (ret: %d).", ret);
		return -EFAULT;
	}

	if (cnt == 0)
		return BSP_OK;

	ret = __start_dmalist_H_2(prxtx_queue, type, cnt);
	if (ret != BSP_OK) {
		LOG(DLOG_DEBUG, "__start_dmalist_H_2 returns %d", ret);
		return -EFAULT;
	}

	if (cnt <= DMA_QUEUE_FAULT_LIMIT) {
		ret = __check_dmacmp_H_2(prxtx_queue, type);
		if (ret != BSP_OK) {
			LOG(DLOG_DEBUG, "__check_dmacmp_H_2 returns %d", ret);
			return -EFAULT;
		}
	}

	return BSP_OK;
}

inline int veth_dma_task_H_2(u32 type)
{
	struct edma_rxtx_q_s *prxtx_queue = NULL;

	if (type == BSPVETH_RX) {
		g_eth_edmaprivate.run_dma_RX_task++;
		prxtx_queue = g_eth_edmaprivate.prx_queue;
	} else {
		g_eth_edmaprivate.run_dma_TX_task++;
		prxtx_queue = g_eth_edmaprivate.ptx_queue;
	}

	if (prxtx_queue) {
		if (!edma_is_queue_ready(prxtx_queue)) {
			LOG(DLOG_DEBUG, "queue is not ready, init flag: %u.",
			    prxtx_queue->pshmqhd_v->init);
			return BSP_OK;
		}

		(void)__dma_rxtx_H_2(prxtx_queue, type);

		if (!CHECK_DMA_QUEUE_EMPTY(type, prxtx_queue))
			return BSP_ERR_AGAIN;
	}

	return BSP_OK;
}

void edma_task_do_data_transmit(unsigned long data)
{
	struct tasklet_struct *t = (struct tasklet_struct *)data;
	int txret, rxret;

	LOG(DLOG_DEBUG, "host_head/host_tail/shm_head/shm_tail - ");
	LOG(DLOG_DEBUG, "rx:%u/%u/%u/%u, tx:%u/%u/%u/%u.",
	    g_eth_edmaprivate.prx_queue->head,
	    g_eth_edmaprivate.prx_queue->tail,
	    g_eth_edmaprivate.prx_queue->pshmqhd_v->head,
	    g_eth_edmaprivate.prx_queue->pshmqhd_v->tail,
	    g_eth_edmaprivate.ptx_queue->head,
	    g_eth_edmaprivate.ptx_queue->tail,
	    g_eth_edmaprivate.ptx_queue->pshmqhd_v->head,
	    g_eth_edmaprivate.ptx_queue->pshmqhd_v->tail);

	txret = veth_dma_task_H_2(BSPVETH_TX);

	rxret = veth_dma_task_H_2(BSPVETH_RX);

	LOG(DLOG_DEBUG, "host_head/host_tail/shm_head/shm_tail - ");
	LOG(DLOG_DEBUG, "rx:%u/%u/%u/%u, tx:%u/%u/%u/%u.\n",
	    g_eth_edmaprivate.prx_queue->head,
	    g_eth_edmaprivate.prx_queue->tail,
	    g_eth_edmaprivate.prx_queue->pshmqhd_v->head,
	    g_eth_edmaprivate.prx_queue->pshmqhd_v->tail,
	    g_eth_edmaprivate.ptx_queue->head,
	    g_eth_edmaprivate.ptx_queue->tail,
	    g_eth_edmaprivate.ptx_queue->pshmqhd_v->head,
	    g_eth_edmaprivate.ptx_queue->pshmqhd_v->tail);

	if (txret == BSP_ERR_AGAIN || rxret == BSP_ERR_AGAIN) {
		/* restart transmission. */
		tasklet_hi_schedule(t);
	}
}

int edma_tasklet_setup(struct edma_eth_dev_s *dev, u8 **rx_buf,
		       struct edma_cut_packet_node_s **tx_cut_pkt_buf)
{
	u8 *rx_pkt_buf;
	struct edma_packet_node_s *rx_packet = NULL;
	struct edma_cut_packet_node_s *tx_cut_buf = NULL;
	size_t rx_size =
	    sizeof(struct edma_packet_node_s) * MAX_RXTX_PACKET_LEN;

	rx_pkt_buf = kmalloc(MAX_PACKET_LEN, GFP_KERNEL);
	if (!rx_pkt_buf)
		return -ENOMEM;

	tx_cut_buf = (struct edma_cut_packet_node_s *)
	    kmalloc(sizeof(*tx_cut_buf), GFP_KERNEL);
	if (!tx_cut_buf) {
		kfree(rx_pkt_buf);
		return -ENOMEM;
	}

	rx_packet = kmalloc(rx_size, GFP_KERNEL);
	if (!rx_packet) {
		kfree(rx_pkt_buf);
		kfree(tx_cut_buf);
		return -ENOMEM;
	}

	memset(rx_pkt_buf, 0, MAX_PACKET_LEN);
	memset(tx_cut_buf, 0, sizeof(*tx_cut_buf));
	memset(rx_packet, 0, rx_size);

	*rx_buf = rx_pkt_buf;
	*tx_cut_pkt_buf = tx_cut_buf;
	dev->rx_packet = rx_packet;

	spin_lock_init(&dev->rx_queue_lock);

	tasklet_init(&dev->skb_task,
		     edma_task_do_packet_recv,
		     (unsigned long)&dev->skb_task);

	tasklet_init(&dev->dma_task,
		     edma_task_do_data_transmit,
		     (unsigned long)&dev->dma_task);

	return 0;
}

void edma_tasklet_free(struct edma_eth_dev_s *dev, u8 **rx_buf,
		       struct edma_cut_packet_node_s **tx_cut_pkt_buf)
{
	if (!*rx_buf)
		return;

	/* stop task before releasing resource. */
	tasklet_kill(&dev->dma_task);
	tasklet_kill(&dev->skb_task);

	kfree(*rx_buf);
	kfree(*tx_cut_pkt_buf);

	/* flush the ring buf. */
	edma_veth_flush_ring_node(dev->rx_packet, MAX_RXTX_PACKET_LEN);
	kfree(dev->rx_packet);

	*rx_buf = NULL;
	*tx_cut_pkt_buf = NULL;
	dev->rx_packet = NULL;
}

static int edma_veth_int_handler(struct notifier_block *nb,
				 unsigned long ev, void *unuse)
{
	g_eth_edmaprivate.recv_int++;

	if (g_eth_edmaprivate.dma_task.func)
		tasklet_hi_schedule(&g_eth_edmaprivate.dma_task);

	return IRQ_HANDLED;
}

static struct notifier_block g_edma_veth_int_nb = {
	.notifier_call = edma_veth_int_handler,
};

static int comm_init_dev(struct edma_eth_dev_s *edma,
			 const struct file_operations *fops)
{
	struct cdev_dev_s *dev = &edma->cdev;
	int ret;

	dev->priv = edma->edma_priv;
	dev->dev.minor = MISC_DYNAMIC_MINOR;
	dev->dev.name = CDEV_VETH_NAME;
	dev->dev.fops = fops;

	ret = misc_register(&dev->dev);
	if (ret < 0) {
		LOG(DLOG_ERROR, "Failed to alloc major number, %d", ret);
		return ret;
	}

	return 0;
}

static inline void comm_cleanup_dev(struct edma_eth_dev_s *edma)
{
	struct cdev_dev_s *dev = &edma->cdev;

	misc_deregister(&dev->dev);
}

static int __init edma_cdev_init(void)
{
	int ret;

	g_write_count = 0;
	g_delay_ms = 0;
	g_last_number = 0;
	g_peer_not_ready = 0;

	LOG(DLOG_DEBUG, "Module init.");

	if (!bma_intf_check_edma_supported())
		return -ENXIO;

	(void)memset(&g_eth_edmaprivate, 0, sizeof(g_eth_edmaprivate));

	/* register EDMA sub-subyem. */
	ret = bma_intf_register_type(TYPE_VETH, 0, INTR_ENABLE,
				     &g_eth_edmaprivate.edma_priv);
	if (ret < 0) {
		LOG(DLOG_ERROR, "Failed to register EDMA interface.");
		goto failed;
	}

	/* initialize host DMA address. */
	edma_veth_host_addr_init(g_eth_edmaprivate.edma_priv);

	/* setup TX/RX resource */
	ret = edma_veth_setup_resource(&g_eth_edmaprivate);
	if (ret < 0) {
		LOG(DLOG_ERROR, "Failed to setup resource.");
		goto failed1;
	}

	/* setup resource for user packets. */
	ret = edma_tasklet_setup(&g_eth_edmaprivate,
				 &g_edma_recv_packet_tmp.packet,
				 &g_edma_send_cut_packet);
	if (ret < 0)
		goto failed2;

	/* register char device. */
	ret = comm_init_dev(&g_eth_edmaprivate, &g_eth_edma_cdev_fops);
	if (ret != 0) {
		LOG(DLOG_ERROR, "Failed to register cdev device.");
		goto failed3;
	}

	/* register EDMA INT notifier. */
	ret = bma_intf_register_int_notifier(&g_edma_veth_int_nb);
	if (ret < 0) {
		LOG(DLOG_ERROR, "Failed to register INT notifier.");
		goto failed4;
	}

	dump_global_info();

	GET_SYS_SECONDS(g_eth_edmaprivate.init_time);

	return 0;

failed4:
	comm_cleanup_dev(&g_eth_edmaprivate);
failed3:
	edma_tasklet_free(&g_eth_edmaprivate,
			  &g_edma_recv_packet_tmp.packet,
			  &g_edma_send_cut_packet);
failed2:
	edma_veth_free_resource(&g_eth_edmaprivate);
failed1:
	(void)bma_intf_unregister_type(&g_eth_edmaprivate.edma_priv);
failed:
	return ret;
}

static void __exit edma_cdev_exit(void)
{
	LOG(DLOG_DEBUG, "Module exit.");

	bma_intf_unregister_int_notifier(&g_edma_veth_int_nb);

	comm_cleanup_dev(&g_eth_edmaprivate);

	edma_tasklet_free(&g_eth_edmaprivate,
			  &g_edma_recv_packet_tmp.packet,
			  &g_edma_send_cut_packet);

	edma_veth_free_resource(&g_eth_edmaprivate);

	bma_intf_unregister_type(&g_eth_edmaprivate.edma_priv);
}

static inline int cdev_check_ring_recv(void)
{
	unsigned int count;

	count = edma_veth_get_ring_buf_count(g_eth_edmaprivate.rx_packet_head,
					     g_eth_edmaprivate.rx_packet_tail,
					     MAX_RXTX_PACKET_LEN);
	return (count > 0 ? 1 : 0);
}

static ssize_t cdev_copy_packet_to_user(struct edma_eth_dev_s *dev,
					char __user *data, size_t count)
{
	unsigned char *packet = NULL;
	unsigned char *start = NULL;
	unsigned int free_packet = 0;
	unsigned long flags = 0;
	ssize_t length = (ssize_t)count;
	ssize_t left;

	LOG(DLOG_DEBUG, "rx_packet_head:%u, rx_packet_tail: %u",
	    dev->rx_packet_head, dev->rx_packet_tail);

	spin_lock_irqsave(&dev->rx_queue_lock, flags);

	if (!cdev_check_ring_recv()) {
		spin_unlock_irqrestore(&dev->rx_queue_lock, flags);
		return -EAGAIN;
	}

	left = (ssize_t)(dev->rx_packet[dev->rx_packet_head].len) - g_read_pos;
	start = dev->rx_packet[dev->rx_packet_head].packet + g_read_pos;

	LOG(DLOG_DEBUG,
	    "User needs %zu bytes, pos: %u, total len: %u, left: %zd.",
	    count, g_read_pos, dev->rx_packet[dev->rx_packet_head].len, left);
	if (left <= 0) {
		/* No more data in this message, retry. */
		length = -EAGAIN;
		free_packet = 1;
	} else if (length > left) {
		/* A full message is returned. */
		length = left;
		free_packet = 1;
	} else {
		/* Update pos. */
		g_read_pos += length;
	}

	if (free_packet) {
		g_read_pos = 0;
		packet = dev->rx_packet[dev->rx_packet_head].packet;
		dev->rx_packet[dev->rx_packet_head].packet = NULL;
		dev->rx_packet_head = (dev->rx_packet_head + 1) %
				      MAX_RXTX_PACKET_LEN;
	}

	spin_unlock_irqrestore(&dev->rx_queue_lock, flags);

	if (length > 0 && copy_to_user(data, start, length)) {
		LOG(DLOG_DEBUG, "Failed to copy to user, skip this message.");
		length = -EFAULT;
		g_read_pos = 0;
	}

	LOG(DLOG_DEBUG,
	    "Copied bytes: %zd, pos: %d, buf len: %zu, free_packet: %d.",
	    length, g_read_pos, count, free_packet);

	if (packet) {
		/* Free the packet as needed. */
		kfree(packet);
	}

	return length;
}

int cdev_open(struct inode *inode_ptr, struct file *filp)
{
	struct cdev_dev_s *dev = &g_eth_edmaprivate.cdev;

	LOG(DLOG_DEBUG, "Open device.");

	if (!inode_ptr || !filp)
		return -EFAULT;

	/* only one instance is allowed. */
	if (IS_CDEV_IN_OPEN_STATE())
		return -EBUSY;

	LOG(DLOG_DEBUG, "Init flag, rx: %d, tx:%d",
	    g_eth_edmaprivate.prx_queue->pshmqhd_v->init,
	    g_eth_edmaprivate.ptx_queue->pshmqhd_v->init);

	/* save to private data. */
	filp->private_data = dev;
	SET_CDEV_OPEN_STATE(CDEV_OPENED);
	g_read_pos = 0;

	return 0;
}

int cdev_release(struct inode *inode_ptr, struct file *filp)
{
	LOG(DLOG_DEBUG, "Close device.");

	if (!filp)
		return 0;

	filp->private_data = NULL;

	SET_CDEV_OPEN_STATE(CDEV_CLOSED);

	return 0;
}

unsigned int cdev_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
	wait_queue_head_t *queue_head = NULL;

	if (!filp)
		return 0;

	edma_veth_dump();

	queue_head = (wait_queue_head_t *)
	    bma_cdev_get_wait_queue(GET_PRIVATE_DATA(filp));
	if (!queue_head)
		return 0;

	/* check or add to wait queue. */
	poll_wait(filp, queue_head, wait);

	if (!edma_is_queue_ready(g_eth_edmaprivate.prx_queue))
		return 0;

	if (cdev_check_ring_recv() > 0)
		mask = (POLLIN | POLLRDNORM);

	return mask;
}

ssize_t cdev_read(struct file *filp, char __user *data,
		  size_t count, loff_t *ppos)
{
	struct edma_eth_dev_s *dev = &g_eth_edmaprivate;
	ssize_t length = 0;

	if (!data || count >= MAX_PACKET_LEN)
		return -EFAULT;

	LOG(DLOG_DEBUG, "read begin, count: %zu, pos: %u.", count, g_read_pos);

	length = cdev_copy_packet_to_user(dev, data, count);

	LOG(DLOG_DEBUG, "read done, length: %zd, pos: %u.", length, g_read_pos);

	return length;
}

ssize_t cdev_write(struct file *filp, const char __user *data,
		   size_t count, loff_t *ppos)
{
	int ret = 0;
	struct edma_eth_dev_s *pdev = &g_eth_edmaprivate;

	if (!data || count <= 0 || count > MAX_PACKET_LEN)
		return -EINVAL;

	if (!edma_is_queue_ready(pdev->ptx_queue)) {
		if (g_peer_not_ready == 0 && pdev->ptx_queue) {
			LOG(DLOG_ERROR, "Peer rx queue is not ready (%u).",
			    pdev->ptx_queue->pshmqhd_v->init);
			g_peer_not_ready = 1;
		}
		return -EPERM;
	} else if (g_peer_not_ready) {
		LOG(DLOG_ERROR, "Peer rx queue becomes ready.");
		g_peer_not_ready = 0;
	}

	LOG(DLOG_DEBUG, "data length is %zu, pos: %u (%u/%u)",
	    count, g_read_pos,
	    pdev->ptx_queue->pshmqhd_v->count,
	    pdev->ptx_queue->pshmqhd_v->total);

	ret = edma_veth_cut_tx_packet_send(pdev, data, count);
	if (ret < 0) {
		LOG(DLOG_ERROR, "Failed to send packet, return code: %d.", ret);
	} else {
		tasklet_hi_schedule(&g_eth_edmaprivate.dma_task);
		ret = count;
	}

	return ret;
}

MODULE_VERSION(MICRO_TO_STR(CDEV_VETH_VERSION));
MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_DESCRIPTION("HUAWEI CDEV DRIVER");
MODULE_LICENSE("GPL");

module_init(edma_cdev_init);
module_exit(edma_cdev_exit);
