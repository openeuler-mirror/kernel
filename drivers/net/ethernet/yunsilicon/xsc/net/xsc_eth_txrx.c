// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth_common.h"
#include "xsc_eth_stats.h"
#include "xsc_eth_txrx.h"
#include "xsc_eth_dim.h"

void xsc_cq_notify_hw_rearm(struct xsc_cq *cq)
{
	ETH_DEBUG_LOG("cc = %d cqn = %d\n", cq->wq.cc, cq->xcq.cqn);
	xsc_arm_cq(cq->xdev, cq->xcq.cqn, cq->wq.cc, 0);
	if (cq->channel && cq->channel->stats)
		cq->channel->stats->arm++;
}

void xsc_cq_notify_hw(struct xsc_cq *cq)
{
	struct xsc_core_device *xdev  = cq->xdev;

	ETH_DEBUG_LOG("cc = %d cqn = %d\n", cq->wq.cc, cq->xcq.cqn);
	xsc_update_cq_ci(xdev, cq->xcq.cqn, cq->wq.cc);
	if (cq->channel && cq->channel->stats)
		cq->channel->stats->noarm++;
}

static inline bool xsc_channel_no_affinity_change(struct xsc_channel *c)
{
	int current_cpu = smp_processor_id();

	return cpumask_test_cpu(current_cpu, c->aff_mask);
}

enum hrtimer_restart xsc_dim_reduce_timer_fn(struct hrtimer *timer)
{
	struct xsc_dim_reduce_work *reduce = (struct xsc_dim_reduce_work *)timer;
	struct xsc_cq *cq = container_of(reduce, struct xsc_cq, cq_reduce);

	xsc_cq_notify_hw_rearm(cq);

	return HRTIMER_NORESTART;
}

int xsc_eth_napi_poll(struct napi_struct *napi, int budget)
{
	struct xsc_channel *c = container_of(napi, struct xsc_channel, napi);
	struct xsc_eth_params *params = &c->adapter->nic_param;
	struct xsc_rq *rq = &c->qp.rq[0];
	struct xsc_sq *sq = NULL;
	bool busy = false;
	int work_done = 0;
	int tx_budget = 0;
	int i;

	rcu_read_lock();

	clear_bit(XSC_CHANNEL_NAPI_SCHED, &c->flags);

	tx_budget = params->sq_size >> 2;
	for (i = 0; i < c->num_tc; i++)
		busy |= xsc_poll_tx_cq(&c->qp.sq[i].cq, tx_budget);

	/* budget=0 means: don't poll rx rings */
	if (likely(budget)) {
		work_done = xsc_poll_rx_cq(&rq->cq, budget);
		busy |= work_done == budget;
	}

	busy |= rq->post_wqes(rq, false);

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

	for (i = 0; i < c->num_tc; i++) {
		sq = &c->qp.sq[i];

		if (test_bit(XSC_ETH_SQ_STATE_AM, &sq->state)) {
			struct xsc_dim_reduce_work *reduce_sq = NULL;
			u32 dim_us_tx = params->tx_cq_moderation.usec;

			xsc_handle_tx_dim(sq);

			reduce_sq = &sq->cq.cq_reduce;
			if (hrtimer_is_queued(&reduce_sq->timer))
				continue;

			dim_us_tx = min_t(u32, sq->cq.xcq.dim_us, dim_us_tx);
			sq->stats->dim_us = dim_us_tx;
			if (dim_us_tx) {
				hrtimer_start(&reduce_sq->timer,
					      ns_to_ktime(dim_us_tx * NSEC_PER_USEC),
					      HRTIMER_MODE_REL_PINNED);
				continue;
			}
		}
		xsc_cq_notify_hw_rearm(&sq->cq);
	}

	if (test_bit(XSC_ETH_RQ_STATE_AM, &rq->state)) {
		struct xsc_dim_reduce_work *reduce = &rq->cq.cq_reduce;
		u32 dim_us = params->rx_cq_moderation.usec;

		xsc_handle_rx_dim(rq);

		if (c->stats->poll <= params->rx_dim_frames_low) {
			dim_us = 0;
			if (c->stats->poll == 0 && hrtimer_is_queued(&reduce->timer))
				goto out;
		} else {
			dim_us = min_t(u32, rq->cq.xcq.dim_us, dim_us);
		}
		rq->stats->dim_us = dim_us;

		if (dim_us) {
			if (hrtimer_is_queued(&reduce->timer))
				goto out;

			reduce->dim_us = dim_us;

			if (dim_us <= params->rx_dim_usecs_low) {
				udelay(dim_us);
				xsc_cq_notify_hw_rearm(&rq->cq);
			} else {
				hrtimer_start(&reduce->timer,
					      ns_to_ktime(dim_us * NSEC_PER_USEC),
					      HRTIMER_MODE_REL_PINNED);
			}
			goto out;
		}
	}

	xsc_cq_notify_hw_rearm(&rq->cq);

out:
	rcu_read_unlock();
	return work_done;
}

