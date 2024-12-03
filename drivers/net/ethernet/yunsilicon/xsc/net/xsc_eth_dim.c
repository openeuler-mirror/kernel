// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth_dim.h"
#include "xsc_queue.h"
#include "xsc_eth_stats.h"

xsc_dim_cq_moder_t xsc_get_def_tx_moderation(u8 cq_period_mode)
{
	xsc_dim_cq_moder_t moder;

	moder.cq_period_mode = cq_period_mode;
	moder.pkts = XSC_PARAMS_DEFAULT_TX_CQ_MODERATION_PKTS;
	moder.usec = XSC_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC;
	if (cq_period_mode == XSC_CQ_PERIOD_MODE_START_FROM_CQE)
		moder.usec = XSC_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC_FROM_CQE;

	return moder;
}

xsc_dim_cq_moder_t xsc_get_def_rx_moderation(u8 cq_period_mode)
{
	xsc_dim_cq_moder_t moder;

	moder.cq_period_mode = cq_period_mode;
	moder.pkts = XSC_PARAMS_DEFAULT_RX_CQ_MODERATION_PKTS;
	moder.usec = XSC_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC;

	return moder;
}

void xsc_set_tx_cq_mode_params(struct xsc_eth_params *params, u8 cq_period_mode)
{
	if (params->tx_dim_enabled)
		params->tx_cq_moderation = net_dim_get_tx_moderation(cq_period_mode,
								     XSC_DEF_TX_DIM_PROFILE_IDX);
	else
		params->tx_cq_moderation = xsc_get_def_tx_moderation(cq_period_mode);

	XSC_SET_PFLAG(params, XSC_PFLAG_TX_CQE_BASED_MODER,
		      params->tx_cq_moderation.cq_period_mode ==
		      XSC_CQ_PERIOD_MODE_START_FROM_CQE);
}

void xsc_set_rx_cq_mode_params(struct xsc_eth_params *params, u8 cq_period_mode)
{
	if (params->rx_dim_enabled) {
		params->rx_cq_moderation = net_dim_get_rx_moderation(cq_period_mode,
								     XSC_DEF_RX_DIM_PROFILE_IDX);
		if (cq_period_mode == XSC_CQ_PERIOD_MODE_START_FROM_EQE)
			params->rx_cq_moderation.usec =
						XSC_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC_FROM_EQE;
	} else {
		params->rx_cq_moderation = xsc_get_def_rx_moderation(cq_period_mode);
	}

	params->rx_dim_usecs_low = XSC_PARAMS_RX_DIM_USECS_LOW;
	params->rx_dim_frames_low = XSC_PARAMS_RX_DIM_FRAMES_LOW;

	XSC_SET_PFLAG(params, XSC_PFLAG_RX_CQE_BASED_MODER,
		      params->rx_cq_moderation.cq_period_mode ==
		      XSC_CQ_PERIOD_MODE_START_FROM_CQE);
}

void xsc_handle_tx_dim(struct xsc_sq *sq)
{
	xsc_dim_sample_t *sample = &sq->dim_obj.sample;

	if (unlikely(!test_bit(XSC_ETH_SQ_STATE_AM, &sq->state)))
		return;

	dim_update_sample(sq->cq.event_ctr, sample->pkt_ctr, sample->byte_ctr, sample);
	net_dim(&sq->dim_obj.dim, *sample);
}

void xsc_handle_rx_dim(struct xsc_rq *rq)
{
	xsc_dim_sample_t *sample = &rq->dim_obj.sample;

	if (unlikely(!test_bit(XSC_ETH_RQ_STATE_AM, &rq->state)))
		return;

	dim_update_sample(rq->cq.event_ctr, sample->pkt_ctr, sample->byte_ctr, sample);
	net_dim(&rq->dim_obj.dim, *sample);
}

static void xsc_complete_dim_work(xsc_dim_t *dim, xsc_dim_cq_moder_t moder,
				  struct xsc_core_device *dev, struct xsc_core_cq *xcq)
{
	xcq->dim_us = moder.usec;
	xcq->dim_pkts = moder.pkts;
	dim->state = XSC_DIM_START_MEASURE;
}

void xsc_rx_dim_work(struct work_struct *work)
{
	xsc_dim_t *dim = container_of(work, xsc_dim_t, work);
	struct xsc_dim *dim_obj = container_of(dim, struct xsc_dim, dim);
	struct xsc_rq *rq = container_of(dim_obj, struct xsc_rq, dim_obj);
	xsc_dim_cq_moder_t cur_moder =
		net_dim_get_rx_moderation(dim->mode, dim->profile_ix);

	xsc_complete_dim_work(dim, cur_moder, rq->cq.xdev, &rq->cq.xcq);
	rq->stats->dim_pkts = cur_moder.pkts;
}

void xsc_tx_dim_work(struct work_struct *work)
{
	xsc_dim_t *dim = container_of(work, xsc_dim_t, work);
	struct xsc_dim *dim_obj = container_of(dim, struct xsc_dim, dim);
	struct xsc_sq *sq = container_of(dim_obj, struct xsc_sq, dim_obj);
	xsc_dim_cq_moder_t cur_moder =
		net_dim_get_tx_moderation(dim->mode, dim->profile_ix);

	xsc_complete_dim_work(dim, cur_moder, sq->cq.xdev, &sq->cq.xcq);
	sq->stats->dim_pkts = cur_moder.pkts;
}

