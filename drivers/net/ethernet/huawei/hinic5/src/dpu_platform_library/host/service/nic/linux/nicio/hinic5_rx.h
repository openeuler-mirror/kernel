/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_rx.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_RX_H
#define HINIC5_RX_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/mm_types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/u64_stats_sync.h>

#include "ossl_knl.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_sq.h"
#include "hinic5_nic_rq.h"

/* performance: ci addr RTE_CACHE_SIZE(64B) alignment */
#define HINIC5_RX_HDR_SIZE			256
#define HINIC5_RX_BUFFER_WRITE			16

#define HINIC5_RX_TCP_PKT			0x3
#define HINIC5_RX_UDP_PKT			0x4
#define HINIC5_RX_SCTP_PKT			0x7

#define HINIC5_RX_IPV4_PKT			0
#define HINIC5_RX_IPV6_PKT			1
#define HINIC5_RX_INVALID_IP_TYPE		2

#define HINIC5_RX_PKT_FORMAT_NON_TUNNEL		0
#define HINIC5_RX_PKT_FORMAT_VXLAN		1

#define RXQ_STATS_INC(rxq, field)			\
do {							\
	u64_stats_update_begin(&(rxq)->rxq_stats.syncp);	\
	(rxq)->rxq_stats.field++;				\
	u64_stats_update_end(&(rxq)->rxq_stats.syncp);	\
} while (0)

#define HINIC5_GET_SGE_NUM(pkt_len, rxq)	\
		((u8)(((pkt_len) >> (rxq)->rx_buff_shift) + \
		      ((((pkt_len) & ((rxq)->buf_len - 1)) != 0) ? 1 : 0)))

/* rx cqe checksum err */
#define HINIC5_RX_CSUM_IP_CSUM_ERR	BIT(0)
#define HINIC5_RX_CSUM_TCP_CSUM_ERR	BIT(1)
#define HINIC5_RX_CSUM_UDP_CSUM_ERR	BIT(2)
#define HINIC5_RX_CSUM_IGMP_CSUM_ERR	BIT(3)
#define HINIC5_RX_CSUM_ICMPV4_CSUM_ERR	BIT(4)
#define HINIC5_RX_CSUM_ICMPV6_CSUM_ERR	BIT(5)
#define HINIC5_RX_CSUM_SCTP_CRC_ERR	BIT(6)
#define HINIC5_RX_CSUM_HW_CHECK_NONE	BIT(7)
#define HINIC5_RX_CSUM_IPSU_OTHER_ERR	BIT(8)

#define HINIC5_HEADER_DATA_UNIT 2
#define HINIC5_CQE_LEN 32
#define HINIC5_COMPACT_CQE_8B 8
#define HINIC5_COMPACT_CQE_16B 16

#define HINIC5_RQ_CQE_SEPARATE	0
#define HINIC5_RQ_CQE_INTEGRATE	1

#define HINIC5_RQ_CQE_USLEEP_LOW_BOUND  900
#define HINIC5_RQ_CQE_USLEEP_HIGH_BOUND 1000

/* flow bifurcation */
#define HINIC5_GROUP_NUMBER_MIN 1
#define HINIC5_GROUP_NUMBER_MAX 8

struct hinic5_rxq_stats {
	u64	packets;
	u64	bytes;
	u64	errors;
	u64	csum_errors;
	u64	other_errors;
	u64	dropped;
	u64	rx_buf_empty;

	u64	alloc_skb_err;
	u64	alloc_rx_buf_err;
	u64	restore_drop_sge;
	u64	pkt_mc;
#ifdef HAVE_XDP_SUPPORT
	u64	xdp_dropped;
	u64	xdp_redirected;
	u64	xdp_large_pkt;
#endif
#ifdef HAVE_NDO_GET_STATS64
	struct u64_stats_sync		syncp;
#else
	struct u64_stats_sync_empty	syncp;
#endif
};

struct hinic5_rx_info {
	dma_addr_t buf_dma_addr;

	struct hinic5_rq_cqe *cqe;
	struct hinic5_cqe_info *cqe_info;
	dma_addr_t cqe_dma;
	struct page *page;
#ifdef HAVE_PAGE_POOL_SUPPORT
	struct page_pool *page_pool;
#endif
	u32 page_offset;
	u32 rsvd1;
	struct hinic5_rq_wqe *rq_wqe;
	struct sk_buff *saved_skb;
	u32 skb_len;
	u32 rsvd2;
};

struct hinic5_rxq {
	struct net_device *netdev;

	u16 q_id;
	u16 rsvd1;
	u32 q_depth;
	u32 q_mask;

	u16 buf_len;
	u16 rsvd2;
	u32 rx_buff_shift;
	u32 dma_rx_buff_size;

	struct hinic5_rxq_stats	rxq_stats;
	u32 cons_idx;
	u32 delta;

	u32 irq_id;
	u16 msix_entry_idx;
#ifdef HAVE_XDP_SUPPORT
	u16 xdp_headroom_flag;
#else
	u16 rsvd3;
#endif

	struct hinic5_rx_info *rx_info;
	struct hinic5_io_queue *rq;
#ifdef HAVE_XDP_SUPPORT
	struct bpf_prog *xdp_prog;
	struct xdp_rxq_info xdp_rxq;
#endif

	struct hinic5_irq *irq_cfg;
	u16 next_to_alloc;
	u16 next_to_update;
	struct device *dev; /* device for DMA mapping */

	u64 status;
	dma_addr_t cqe_start_paddr;
	void *cqe_start_vaddr;

	u64 last_moder_packets;
	u64 last_moder_bytes;
	u8 last_coalesc_timer_cfg;
	u8 last_pending_limt;
	u16 restore_buf_num;
	u32 rsvd5;
	u64 rsvd6;

	u32 last_sw_pi;
	u32 last_sw_ci;

	u32 last_hw_ci;
	u8 rx_check_err_cnt;
	u8 rxq_print_times;
	u16 restore_pi;

	u64 last_packets;
} ____cacheline_aligned;

struct hinic5_dyna_rxq_res {
	u16 next_to_alloc;
	struct hinic5_rx_info *rx_info;
	struct hinic5_cqe_info *cqe_info;
	dma_addr_t cqe_start_paddr;
	void *cqe_start_vaddr;
#ifdef HAVE_PAGE_POOL_SUPPORT
	struct page_pool *page_pool;
#endif
};

struct hinic5_nic_dev;

int hinic5_alloc_rxqs(struct net_device *netdev);

void hinic5_free_rxqs(struct net_device *netdev);

int hinic5_alloc_rxqs_res(struct hinic5_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic5_dyna_rxq_res *rxqs_res);

void hinic5_free_rxqs_res(struct hinic5_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic5_dyna_rxq_res *rxqs_res);

void hinic5_remove_configure_rxqs(struct hinic5_nic_dev *nic_dev);

int hinic5_configure_rxqs(struct hinic5_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic5_dyna_rxq_res *rxqs_res);

int hinic5_rx_configure(struct net_device *netdev, u8 dcb_en);

void hinic5_rx_remove_configure(struct net_device *netdev);

int hinic5_rx_poll(struct hinic5_rxq *rxq, int budget);

void hinic5_rxq_get_stats(struct hinic5_rxq *rxq,
			  struct hinic5_rxq_stats *stats);

void hinic5_rxq_clean_stats(struct hinic5_rxq_stats *rxq_stats);

void hinic5_rxq_check_work_handler(struct work_struct *work);

void hinic5_rx_get_cqe_info(struct hinic5_rq_cqe *cqe,
			    struct hinic5_cqe_info *info, u8 cqe_mode, bool enable_pfe);

void hinic5_rx_get_compact_cqe_info(struct hinic5_rq_cqe *cqe,
				    struct hinic5_cqe_info *info, u8 cqe_mode, bool enable_pfe);

void hinic5_reuse_rx_page(struct hinic5_rxq *rxq,
			  struct hinic5_rx_info *old_rx_info);

struct sk_buff *hinic5_fetch_rx_buffer(struct hinic5_rxq *rxq,
				       const struct hinic5_cqe_info *cqe_info);

bool hinic5_rx_separate_cqe_done(struct hinic5_rxq *rxq, struct hinic5_rq_cqe **rx_cqe);

bool hinic5_rx_integrated_cqe_done(struct hinic5_rxq *rxq, struct hinic5_rq_cqe **rx_cqe);

#endif
