/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_XSK_H_
#define _NSE_XSK_H_
#include "nse_txrx.h"
#include <net/xdp_sock_drv.h>

struct nse_vsi;

#ifdef CONFIG_XDP_SOCKETS
int nse_xsk_umem_setup(struct nse_vsi *vsi, struct xsk_buff_pool *umem,
		       u16 qid);
int nse_xsk_umem_query(struct nse_vsi *vsi, struct xdp_umem **umem, u16 qid);
int nse_clean_rx_irq_zc(struct nse_ring *rx_ring, int budget);
bool nse_clean_tx_irq_zc(struct nse_ring *xdp_ring);
int nse_clean_tx_irq_zc_on_hw_head(struct nse_ring *xdp_ring, u16 head,
				   struct nse_txcq_ring *cq_ring);
int nse_xsk_wakeup(struct net_device *netdev, u32 queue_id, u32 flags);
bool nse_alloc_rx_bufs_zc(struct nse_ring *rx_ring, int count);
bool nse_xsk_any_rx_ring_ena(struct nse_vsi *vsi);
void nse_xsk_clean_rx_ring(struct nse_ring *rx_ring);
void nse_xsk_clean_xdp_ring(struct nse_ring *xdp_ring);
#else
static inline int
nse_xsk_umem_setup(struct nse_vsi __always_unused *vsi,
		   struct xsk_buff_pool __always_unused *pool,
		   u16 __always_unused qid)
{
	return -EOPNOTSUPP;
}

static inline int
nse_xsk_umem_query(struct nse_vsi __always_unused *vsi,
		   struct xdp_umem __always_unused **umem,
		   u16 __always_unused qid)
{
	return -EOPNOTSUPP;
}

static inline int
nse_clean_rx_irq_zc(struct nse_ring __always_unused *rx_ring,
		    int __always_unused budget)
{
	return 0;
}

static inline bool
nse_clean_tx_irq_zc(struct nse_ring __always_unused *xdp_ring)
{
	return false;
}

static inline int nse_clean_tx_irq_zc_on_hw_head(struct nse_ring __always_unused *xdp_ring,
						 u16 head,
	struct nse_txcq_ring __always_unused *cq_ring)
{
	return 0;
}

static inline bool
nse_alloc_rx_bufs_zc(struct nse_ring __always_unused *rx_ring,
		     u16 __always_unused count)
{
	return false;
}

static inline bool nse_xsk_any_rx_ring_ena(struct nse_vsi __always_unused *vsi)
{
	return false;
}

static inline int
nse_xsk_wakeup(struct net_device __always_unused *netdev,
	       u32 __always_unused queue_id, u32 __always_unused flags)
{
	return -EOPNOTSUPP;
}

static inline void nse_xsk_clean_rx_ring(struct nse_ring *rx_ring) { }
static inline void nse_xsk_clean_xdp_ring(struct nse_ring *xdp_ring) { }
#endif /* CONFIG_XDP_SOCKETS */
#endif /* !_NSE_XSK_H_ */
