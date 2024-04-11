/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_RXTX_H
#define XSC_RXTX_H

#include "xsc_eth.h"
#include "common/qp.h"
#include "xsc_eth_debug.h"

enum {
	XSC_ETH_WQE_NONE_CSUM,
	XSC_ETH_WQE_INNER_CSUM,
	XSC_ETH_WQE_OUTER_CSUM,
	XSC_ETH_WQE_INNER_AND_OUTER_CSUM,
};

#define ANDES_DRIVER

static inline u32 xsc_cqwq_get_size(struct xsc_cqwq *wq)
{
	return wq->fbc.sz_m1 + 1;
}

static inline struct xsc_cqe64 *xsc_cqwq_get_wqe(struct xsc_cqwq *wq, u32 ix)
{
	struct xsc_cqe64 *cqe = xsc_frag_buf_get_wqe(&wq->fbc, ix);

	ETH_DEBUG_LOG("cqe = %p\n", cqe);

	return cqe;
}

static inline struct xsc_cqe64 *xsc_cqwq_get_cqe(struct xsc_cqwq *wq)
{
	struct xsc_cqe64 *cqe;
	u8 cqe_ownership_bit;
	u8 sw_ownership_val;
	u32 ci = xsc_cqwq_get_ci(wq);

	cqe = xsc_cqwq_get_wqe(wq, ci);

	cqe_ownership_bit = cqe->owner & XSC_CQE_OWNER_MASK;
	sw_ownership_val = xsc_cqwq_get_wrap_cnt(wq) & 1;
	ETH_DEBUG_LOG("ci=%d, cqe_owner=%d, sw_owner=%d\n",
		      ci, cqe_ownership_bit, sw_ownership_val);

	if (cqe_ownership_bit != sw_ownership_val)
		return NULL;

	/* ensure cqe content is read after cqe ownership bit */
	dma_rmb();

	return cqe;
}

void xsc_free_tx_wqe(struct device *dev, struct xsc_sq *sq);
int xsc_eth_napi_poll(struct napi_struct *napi, int budget);
bool xsc_poll_tx_cq(struct xsc_cq *cq, int napi_budget);
int xsc_poll_rx_cq(struct xsc_cq *cq, int budget);
void xsc_eth_handle_rx_cqe(struct xsc_cqwq *cqwq,
			   struct xsc_rq *rq, struct xsc_cqe64 *cqe);
struct sk_buff *xsc_skb_from_cqe_linear(struct xsc_rq *rq,
					struct xsc_wqe_frag_info *wi, u32 cqe_bcnt, u8 has_pph);
struct sk_buff *xsc_skb_from_cqe_nonlinear(struct xsc_rq *rq,
					   struct xsc_wqe_frag_info *wi,
					   u32 cqe_bcnt, u8 has_pph);
bool xsc_eth_post_rx_wqes(struct xsc_rq *rq);
void xsc_cq_notify_hw(struct xsc_cq *cq);
void xsc_cq_notify_hw_rearm(struct xsc_cq *cq);
void xsc_eth_dealloc_rx_wqe(struct xsc_rq *rq, u16 ix);
netdev_tx_t xsc_eth_xmit_start(struct sk_buff *skb, struct net_device *netdev);

void xsc_page_release_dynamic(struct xsc_rq *rq,
			      struct xsc_dma_info *dma_info,
			      bool recycle);

#endif /* XSC_RXTX_H */
