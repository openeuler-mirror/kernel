// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth_common.h"
#include "xsc_eth_stats.h"
#include "xsc_eth_txrx.h"

void xsc_cq_notify_hw_rearm(struct xsc_cq *cq)
{
	union xsc_cq_doorbell db;

	ETH_DEBUG_LOG("cc = %d cqn = %d\n", cq->wq.cc, cq->xcq.cqn);

	db.val = 0;
	db.cq_next_cid = cpu_to_le32(cq->wq.cc);
	db.cq_id = cpu_to_le32(cq->xcq.cqn);
	db.arm = 0;

	/* ensure doorbell record is visible to device before ringing the doorbell */
	wmb();
	writel(db.val, REG_ADDR(cq->xdev, cq->xdev->regs.complete_db));
	if (cq->channel && cq->channel->stats)
		cq->channel->stats->arm++;
}

void xsc_cq_notify_hw(struct xsc_cq *cq)
{
	struct xsc_core_device *xdev  = cq->xdev;
	union xsc_cq_doorbell db;

	ETH_DEBUG_LOG("cc = %d cqn = %d\n", cq->wq.cc, cq->xcq.cqn);

	dma_wmb();

	db.val = 0;
	db.cq_next_cid = cpu_to_le32(cq->wq.cc);
	db.cq_id = cpu_to_le32(cq->xcq.cqn);

	writel(db.val, REG_ADDR(xdev, xdev->regs.complete_reg));
	if (cq->channel && cq->channel->stats)
		cq->channel->stats->noarm++;
}

static inline bool xsc_channel_no_affinity_change(struct xsc_channel *c)
{
	int current_cpu = smp_processor_id();

	return cpumask_test_cpu(current_cpu, c->aff_mask);
}

int xsc_eth_napi_poll(struct napi_struct *napi, int budget)
{
	struct xsc_channel *c = container_of(napi, struct xsc_channel, napi);
	struct xsc_rq *rq = &c->qp.rq[0];
	bool busy = false;
	int work_done = 0;
	int i;

	rcu_read_lock();

	clear_bit(XSC_CHANNEL_NAPI_SCHED, &c->flags);

	for (i = 0; i < c->num_tc; i++)
		busy |= xsc_poll_tx_cq(&c->qp.sq[i].cq, budget);

	/* budget=0 means: don't poll rx rings */
	if (likely(budget)) {
		work_done = xsc_poll_rx_cq(&rq->cq, budget);
		busy |= work_done == budget;
	}

	if (busy) {
		if (likely(xsc_channel_no_affinity_change(c))) {
			rcu_read_unlock();
			return budget;
		}
		c->stats->aff_change++;
		if (budget && work_done == budget)
			work_done--;
	}

	if (unlikely(!napi_complete_done(napi, work_done)))
		goto out;

	for (i = 0; i < c->num_tc; i++)
		xsc_cq_notify_hw_rearm(&c->qp.sq[i].cq);

	xsc_cq_notify_hw_rearm(&rq->cq);

out:
	rcu_read_unlock();
	return work_done;
}

