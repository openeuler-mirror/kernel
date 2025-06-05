/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ETH_DIM_H
#define XSC_ETH_DIM_H

#include "xsc_eth_common.h"

#define XSC_DEF_RX_DIM_PROFILE_IDX	4
#define XSC_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC      0x1
#define XSC_PARAMS_DEFAULT_RX_CQ_MODERATION_PKTS      0x40
#define XSC_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC_FROM_CQE 0x2
#define XSC_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC_FROM_EQE 0x40

#define XSC_PARAMS_RX_DIM_USECS_LOW	8
#define XSC_PARAMS_RX_DIM_FRAMES_LOW	2

#define XSC_DEF_TX_DIM_PROFILE_IDX	4
#define XSC_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC      0x1
#define XSC_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC_FROM_CQE 0x2
#define XSC_PARAMS_DEFAULT_TX_CQ_MODERATION_PKTS      0x80
#define XSC_MAX_COAL_TIME		512
#define XSC_MAX_COAL_FRAMES		1024

#define XSC_DIM_START_MEASURE           DIM_START_MEASURE

enum {
	XSC_CQ_PERIOD_MODE_START_FROM_EQE = DIM_CQ_PERIOD_MODE_START_FROM_EQE,
	XSC_CQ_PERIOD_MODE_START_FROM_CQE = DIM_CQ_PERIOD_MODE_START_FROM_CQE,
	XSC_CQ_PERIOD_NUM_MODES
};

xsc_dim_cq_moder_t xsc_get_def_tx_moderation(u8 cq_period_mode);
xsc_dim_cq_moder_t xsc_get_def_rx_moderation(u8 cq_period_mode);
u8 xsc_to_net_dim_cq_period_mode(u8 cq_period_mode);
void xsc_set_tx_cq_mode_params(struct xsc_eth_params *params, u8 cq_period_mode);
void xsc_set_rx_cq_mode_params(struct xsc_eth_params *params, u8 cq_period_mode);

void xsc_tx_dim_work(struct work_struct *work);
void xsc_rx_dim_work(struct work_struct *work);

void xsc_handle_tx_dim(struct xsc_sq *sq);
void xsc_handle_rx_dim(struct xsc_rq *rq);

#endif /* XSC_ETH_DIM_H */
