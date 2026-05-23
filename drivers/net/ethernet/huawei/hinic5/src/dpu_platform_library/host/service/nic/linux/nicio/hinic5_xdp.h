/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_xdp.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_XDP_H
#define HINIC5_XDP_H

#include <net/xfrm.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/u64_stats_sync.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include "ossl_knl.h"
#ifdef HAVE_XDP_SUPPORT
#include <net/xdp.h>
#include <linux/bpf_trace.h>

#include "hinic5_nic_sq.h"
#include "hinic5_nic_rq.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"

#define HINIC5_XDP_PROCESSED 1

enum hinic5_xdp_pkt {
	// bpf_prog status
	HINIC5_XDP_PROG_EMPTY,
	// pkt action
	HINIC5_XDP_PKT_PASS,
	HINIC5_XDP_PKT_DROP,
	HINIC5_XDP_PKT_REDIRECT,
	HINIC5_XDP_PKT_TX,
};

int tx_map_xdpf(struct hinic5_nic_dev *nic_dev, struct hinic5_txq *txq, u16 pi,
		struct hinic5_sq_wqe_combo *wqe_combo);

void hinic5_prepare_xdp_sq_ctrl(struct hinic5_sq_wqe_combo *wqe_combo, u16 owner);

int hinic5_xdp_xmit_frame(struct hinic5_nic_dev *nic_dev, struct hinic5_txq *txq,
			  struct xdp_frame *xdpf);

int hinic5_xdp_xmit_frames(struct net_device *dev, int n, struct xdp_frame **frames,
			   u32 flags);
bool hinic5_xmit_xdp_buff(struct net_device *netdev, u16 q_id, struct xdp_buff *xdp);

struct xdp_frame *xdp_convert_to_frame(struct xdp_buff *xdp, struct hinic5_nic_dev *nic_dev);

int hinic5_run_xdp(struct hinic5_rxq *rxq, struct hinic5_cqe_info *cqe_info, struct xdp_buff *xdp);

struct sk_buff *hinic5_fetch_rx_buffer_xdp(struct hinic5_rxq *rxq, u32 pkt_len,
					   struct xdp_buff *xdp);

void hinic5_xdp_flush_if_needed(const struct hinic5_nic_dev *nic_dev);

bool hinic5_xdp_process_packet(struct hinic5_rxq *rxq, struct hinic5_cqe_info *cqe_info,
			       struct sk_buff **skb);
#endif
#endif
