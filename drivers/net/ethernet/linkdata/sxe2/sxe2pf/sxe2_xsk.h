/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_xsk.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_XSK_H__
#define __SXE2_XSK_H__

#include "sxe2_compat.h"

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_BUFF_IN_XDP_H
#include <net/xdp.h>
#else
#include <linux/filter.h>
#endif
#endif
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#include <net/xdp_sock.h>
#endif
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#include <net/xdp_sock_drv.h>
#endif
#include <linux/bpf.h>
#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf_trace.h>
#endif

#include "sxe2.h"

#define SXE2_RX_BUF_WRITE 16

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
void sxe2_zca_free(struct zero_copy_allocator *alloc,
		   unsigned long handle_addr);

bool sxe2_alloc_rx_bufs_slow_zc(struct sxe2_queue *rxq, u16 count);
#else
bool sxe2_alloc_rx_bufs_zc(struct sxe2_queue *rxq, u16 count);
#endif

#ifdef HAVE_NETDEV_BPF_XSK_POOL
s32 sxe2_xsk_pool_setup(struct sxe2_vsi *vsi, struct xsk_buff_pool *pool,
			u16 qid);
#else
s32 sxe2_xsk_umem_setup(struct sxe2_vsi *vsi, struct xdp_umem *pool, u16 qid);
#endif
#endif

s32 sxe2_rx_irq_clean_zc(struct sxe2_queue *rxq, int budget);

bool sxe2_txq_irq_clean_zc(struct sxe2_queue *txq, s32 napi_budget);

void sxe2_xsk_clean_xdp_ring(struct sxe2_queue *xdp_ring);

void sxe2_xsk_clean_rx_ring(struct sxe2_queue *rx_ring);

static inline void sxe2_set_ring_xdp(struct sxe2_queue *q)
{
#ifdef HAVE_XDP_SUPPORT
	set_bit(SXE2_TX_FLAGS_Q_XDP, &q->flags);
#endif
}

static inline bool sxe2_xdp_is_enable(struct sxe2_vsi *vsi)
{
#ifdef HAVE_XDP_SUPPORT
	return !!READ_ONCE(vsi->xdp_prog);
#else
	return false;
#endif
}

static inline void sxe2_xdp_queue_cnt_set(struct sxe2_vsi *vsi, u16 count)
{
	vsi->num_xdp_txq = count;
	if (vsi->num_xdp_txq > SXE2_XDP_MAX_CNT)
		vsi->num_xdp_txq = SXE2_XDP_MAX_CNT;
}

static inline bool sxe2_queue_is_xdp(struct sxe2_queue *q)
{
	return (bool)test_bit(SXE2_TX_FLAGS_Q_XDP, &q->flags);
}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
struct xsk_buff_pool *sxe2_xsk_pool(struct sxe2_queue *ring);
#else
struct xdp_umem *sxe2_xsk_pool(struct sxe2_queue *ring);
#endif

#ifdef HAVE_NDO_XSK_WAKEUP
s32 sxe2_xsk_wakeup(struct net_device *netdev, u32 queue_id, u32 flags);
#else
s32 sxe2_xsk_async_xmit(struct net_device *netdev, u32 queue_id);
#endif

#endif
