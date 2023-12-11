// SPDX-License-Identifier: GPL-2.0
#include "ys_k2_core.h"

static int ysk2_create_cq_ring(struct ysk2_port *k2port, u32 index, u32 size,
			       bool is_txcqring)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2port->ndev);
	struct ysk2_cq_ring *cq_ring;
	int ret;

	cq_ring = kzalloc(sizeof(*cq_ring), GFP_KERNEL);
	if (!cq_ring)
		return -ENOMEM;

	cq_ring->ring.k2port = k2port;
	ret = ysk2_alloc_ring(&cq_ring->ring, size, YSK2_CPL_SIZE);
	if (ret)
		goto err_with_ring;

	cq_ring->ring.qid = ndev_priv->qbase + index;
	cq_ring->ring.hw_addr = k2port->k2nic->hw_addr;
	if (is_txcqring) {
		cq_ring->ring.hw_addr += YSK2_CHN_TXCQ_BASE(cq_ring->ring.qid);
		cq_ring->src_ring = k2port->qps[index].tx_ring;
		k2port->qps[index].tx_cpl_ring = cq_ring;
	} else {
		cq_ring->ring.hw_addr += YSK2_CHN_RXCQ_BASE(cq_ring->ring.qid);
		cq_ring->src_ring = k2port->qps[index].rx_ring;
		k2port->qps[index].rx_cpl_ring = cq_ring;
	}

	return 0;

err_with_ring:
	kfree(cq_ring);

	return ret;
}

int ysk2_create_txcq_ring(struct ysk2_port *k2port, u32 index, u32 size)
{
	return ysk2_create_cq_ring(k2port, index, size, true);
}

int ysk2_create_rxcq_ring(struct ysk2_port *k2port, u32 index, u32 size)
{
	return ysk2_create_cq_ring(k2port, index, size, false);
}

void ysk2_destroy_cq_ring(struct ysk2_cq_ring **ring_ptr)
{
	struct ysk2_cq_ring *cq_ring = *ring_ptr;
	*ring_ptr = NULL;

	ysk2_free_ring(&cq_ring->ring);
	kfree(cq_ring);
}

void ysk2_cq_irq_handler(struct ysk2_cq_ring *cq_ring)
{
	ysk2_unarm_ring_irq(&cq_ring->ring);
	napi_schedule_irqoff(&cq_ring->napi);
}

int ysk2_napi_poll_cq(struct napi_struct *napi, int napi_budget)
{
	struct ysk2_cq_ring *cq_ring =
		container_of(napi, struct ysk2_cq_ring, napi);
	int done;

	if (cq_ring->src_ring->is_txring)
		done = ysk2_process_tx_cq(cq_ring, napi_budget);
	else
		done = ysk2_process_rx_cq(cq_ring, napi_budget);

	if (done == napi_budget)
		return done;

	napi_complete(napi);
	ysk2_arm_ring_irq(&cq_ring->ring);

	return done;
}
