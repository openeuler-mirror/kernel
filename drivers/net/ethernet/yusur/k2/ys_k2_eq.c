// SPDX-License-Identifier: GPL-2.0
#include "ys_k2_core.h"

int ysk2_create_eq_ring(struct ysk2_port *k2port, u32 index, u32 size)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2port->ndev);
	struct ysk2_eq_ring *eq_ring;
	int ret;

	eq_ring = kzalloc(sizeof(*eq_ring), GFP_KERNEL);
	if (!eq_ring)
		return -ENOMEM;

	eq_ring->ring.k2port = k2port;
	ret = ysk2_alloc_ring(&eq_ring->ring, size, YSK2_EVENT_SIZE);
	if (ret)
		goto err_with_ring;

	eq_ring->ring.qid = ndev_priv->qbase + index;
	eq_ring->ring.hw_addr = k2port->k2nic->hw_addr +
				YSK2_CHN_EQ_BASE(eq_ring->ring.qid);

	k2port->qps[index].event_ring = eq_ring;

	return 0;

err_with_ring:
	kfree(eq_ring);

	return ret;
}

void ysk2_destroy_eq_ring(struct ysk2_eq_ring **ring_ptr)
{
	struct ysk2_eq_ring *eq_ring = *ring_ptr;
	*ring_ptr = NULL;

	ysk2_free_ring(&eq_ring->ring);
	kfree(eq_ring);
}

void ysk2_process_eq(struct ysk2_eq_ring *eq_ring)
{
	struct ysk2_port *k2port = eq_ring->ring.k2port;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2port->ndev);
	struct ysk2_cq_ring *cq_ring;
	u32 eq_index, eq_tail_ptr;
	struct ysk2_event *event;
	u16 qid;

	/* read head pointer from NIC */
	ysk2_read_head_ptr(&eq_ring->ring);
	eq_tail_ptr = eq_ring->ring.tail_ptr;
	eq_index = eq_tail_ptr & eq_ring->ring.size_mask;

	while (eq_ring->ring.head_ptr != eq_tail_ptr) {
		event = (struct ysk2_event *)eq_ring->ring.buf + eq_index;

		switch (le16_to_cpu(event->type)) {
		case YSK2_EVENT_TYPE_TX_CPL:
		case YSK2_EVENT_TYPE_RX_CPL:
			qid = le16_to_cpu(event->source);
			/* error qid event received */
			if (unlikely(qid != eq_ring->ring.qid)) {
				ys_net_err("eq[%d] unknown event source %d (index %d, type %d)",
					   eq_ring->ring.qid, qid, eq_index,
					   le16_to_cpu(event->type));
				print_hex_dump(KERN_ERR, "", DUMP_PREFIX_NONE,
					       16, 1, event, YSK2_EVENT_SIZE,
					       true);
				break;
			}

			if (event->type == YSK2_EVENT_TYPE_TX_CPL)
				cq_ring =
				k2port->qps[qid - ndev_priv->qbase].tx_cpl_ring;
			else
				cq_ring =
				k2port->qps[qid - ndev_priv->qbase].rx_cpl_ring;

			cq_ring->handler(cq_ring);

			break;
		default:
			ys_net_err("eq[%d] unknown event type %d (index %d)",
				   eq_ring->ring.qid, le16_to_cpu(event->type),
				   eq_index);
			print_hex_dump(KERN_ERR, "", DUMP_PREFIX_NONE, 16, 1,
				       event, YSK2_EVENT_SIZE, true);
			break;
		}

		eq_tail_ptr++;
		eq_index = eq_tail_ptr & eq_ring->ring.size_mask;
	}

	/* update eq tail */
	eq_ring->ring.tail_ptr = eq_tail_ptr;
	ysk2_write_tail_ptr(&eq_ring->ring);
}
