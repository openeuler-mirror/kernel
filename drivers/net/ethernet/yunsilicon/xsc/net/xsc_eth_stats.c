// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/types.h>
#include "common/xsc_cmd.h"

#include "xsc_eth_stats.h"
#include "xsc_eth.h"

static const struct counter_desc sw_stats_desc[] = {
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_inner_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_inner_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_unnecessary) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_none) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_succ) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_csum_partial) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_csum_partial_inner) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_queue_stopped) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_queue_dropped) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_xmit_more) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_cqes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_queue_wake) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_cqe_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_oversize_pkts_sw_drop) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, txdone_skb_null) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, txdone_skb_refcnt_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cqes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cqe_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_wqes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_wqe_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_oversize_pkts_sw_drop) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_oversize_pkts_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_buff_alloc_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_reuse) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_full) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_empty) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_busy) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_alloc) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_waive) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_ext) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_rdc) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_events) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_0) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_1_63) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_64_511) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_512_1023) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_1024) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_arm) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_noarm) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_aff_change) },
};

#define NUM_SW_COUNTERS			ARRAY_SIZE(sw_stats_desc)

static int xsc_grp_sw_get_num_stats(struct xsc_adapter *adapter)
{
	return NUM_SW_COUNTERS;
}

static int xsc_grp_sw_fill_strings(struct xsc_adapter *adapter, u8 *data, int idx)
{
	int i;

	for (i = 0; i < NUM_SW_COUNTERS; i++)
		strscpy(data + (idx++) * ETH_GSTRING_LEN,
			sw_stats_desc[i].format,
			sizeof(sw_stats_desc[i].format));
	return idx;
}

static int xsc_grp_sw_fill_stats(struct xsc_adapter *adapter, u64 *data, int idx)
{
	int i;

	for (i = 0; i < NUM_SW_COUNTERS; i++)
		data[idx++] = XSC_READ_CTR64_CPU(&adapter->stats->sw, sw_stats_desc, i);
	return idx;
}

void xsc_grp_sw_update_stats(struct xsc_adapter *adapter)
{
	struct xsc_sw_stats *s = &adapter->stats->sw;
	int max_tc = xsc_get_netdev_max_tc(adapter);
	int i;

	memset(s, 0, sizeof(*s));

	for (i = 0; i < xsc_get_netdev_max_channels(adapter); i++) {
		struct xsc_channel_stats *channel_stats =
			&adapter->stats->channel_stats[i];

		struct xsc_rq_stats *rq_stats = &channel_stats->rq;
		struct xsc_ch_stats *ch_stats = &channel_stats->ch;
		int j;

		s->rx_packets	+= rq_stats->packets;
		s->rx_bytes	+= rq_stats->bytes;
		s->rx_csum_unnecessary += rq_stats->csum_unnecessary;
		s->rx_csum_none	+= rq_stats->csum_none;
		s->rx_csum_err += rq_stats->csum_err;
		s->rx_csum_succ += rq_stats->csum_succ;
		s->rx_cqes	+= rq_stats->cqes;
		s->rx_cqe_err   += rq_stats->cqe_err;
		s->rx_wqes	+= rq_stats->wqes;
		s->rx_wqe_err   += rq_stats->wqe_err;
		s->rx_oversize_pkts_sw_drop += rq_stats->oversize_pkts_sw_drop;
		s->rx_oversize_pkts_err += rq_stats->oversize_pkts_err;
		s->rx_buff_alloc_err += rq_stats->buff_alloc_err;
		s->rx_cache_reuse += rq_stats->cache_reuse;
		s->rx_cache_full += rq_stats->cache_full;
		s->rx_cache_empty += rq_stats->cache_empty;
		s->rx_cache_busy += rq_stats->cache_busy;
		s->rx_cache_alloc += rq_stats->cache_alloc;
		s->rx_cache_waive += rq_stats->cache_waive;
		s->rx_cache_ext += rq_stats->cache_ext;
		s->rx_cache_rdc += rq_stats->cache_rdc;

		s->ch_events		+= ch_stats->events;
		s->ch_poll		+= ch_stats->poll;
		s->ch_poll_0		+= ch_stats->poll_0;
		s->ch_poll_1_63		+= ch_stats->poll_1_63;
		s->ch_poll_64_511	+= ch_stats->poll_64_511;
		s->ch_poll_512_1023	+= ch_stats->poll_512_1023;
		s->ch_poll_1024		+= ch_stats->poll_1024;
		s->ch_arm		+= ch_stats->arm;
		s->ch_noarm		+= ch_stats->noarm;
		s->ch_aff_change	+= ch_stats->aff_change;

		for (j = 0; j < max_tc; j++) {
			struct xsc_sq_stats *sq_stats = &channel_stats->sq[j];

			s->tx_packets		+= sq_stats->packets;
			s->tx_bytes		+= sq_stats->bytes;
			s->tx_tso_packets	+= sq_stats->tso_packets;
			s->tx_tso_bytes		+= sq_stats->tso_bytes;
			s->tx_tso_inner_packets	+= sq_stats->tso_inner_packets;
			s->tx_tso_inner_bytes	+= sq_stats->tso_inner_bytes;
			s->tx_csum_partial	+= sq_stats->csum_partial;
			s->tx_csum_partial_inner += sq_stats->csum_partial_inner;
			s->tx_csum_none		+= sq_stats->csum_none;
			s->tx_queue_stopped	+= sq_stats->stopped;
			s->tx_queue_dropped	+= sq_stats->dropped;
			s->tx_xmit_more		+= sq_stats->xmit_more;
			s->tx_cqes		+= sq_stats->cqes;
			s->tx_queue_wake	+= sq_stats->wake;
			s->tx_cqe_err		+= sq_stats->cqe_err;
			s->tx_oversize_pkts_sw_drop += sq_stats->oversize_pkts_sw_drop;
			s->txdone_skb_null += sq_stats->txdone_skb_null;
			s->txdone_skb_refcnt_err += sq_stats->txdone_skb_refcnt_err;
			s->skb_linear += sq_stats->skb_linear;
		}
	}
}

static const struct counter_desc rq_stats_desc[] = {
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, packets) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, bytes) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_unnecessary) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_none) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_succ) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cqes) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, wqe_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, oversize_pkts_sw_drop) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, oversize_pkts_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, buff_alloc_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_reuse) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_full) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_empty) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_busy) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_alloc) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_waive) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_ext) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_rdc) },
};

static const struct counter_desc sq_stats_desc[] = {
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, packets) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, bytes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_packets) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_bytes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_inner_packets) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_inner_bytes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, csum_partial) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, csum_partial_inner) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, csum_none) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, stopped) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, dropped) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, xmit_more) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, cqes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, wake) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, cqe_err) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, oversize_pkts_sw_drop) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, txdone_skb_null) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, txdone_skb_refcnt_err) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, skb_linear) },
};

static const struct counter_desc ch_stats_desc[] = {
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, events) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_0) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_1_63) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_64_511) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_512_1023) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_1024) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, arm) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, noarm) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, aff_change) },
};

#define NUM_RQ_STATS			ARRAY_SIZE(rq_stats_desc)
#define NUM_SQ_STATS			ARRAY_SIZE(sq_stats_desc)
#define NUM_CH_STATS			ARRAY_SIZE(ch_stats_desc)

static int xsc_grp_channels_get_num_stats(struct xsc_adapter *adapter)
{
	int max_nch = xsc_get_netdev_max_channels(adapter);
	int max_tc = xsc_get_netdev_max_tc(adapter);

	return (NUM_RQ_STATS * max_nch) +
	       (NUM_CH_STATS * max_nch) +
	       (NUM_SQ_STATS * max_nch * max_tc);
}

static int xsc_grp_channels_fill_strings(struct xsc_adapter *adapter, u8 *data,
					 int idx)
{
	int max_nch = xsc_get_netdev_max_channels(adapter);
	int max_tc = xsc_get_netdev_max_tc(adapter);
	int i, j, tc;

	for (i = 0; i < max_nch; i++)
		for (j = 0; j < NUM_CH_STATS; j++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN,
				ch_stats_desc[j].format, i);

	for (i = 0; i < max_nch; i++) {
		for (j = 0; j < NUM_RQ_STATS; j++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN,
				rq_stats_desc[j].format, i);
	}

	for (tc = 0; tc < max_tc; tc++)
		for (i = 0; i < max_nch; i++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				sprintf(data + (idx++) * ETH_GSTRING_LEN,
					sq_stats_desc[j].format,
					i + tc * max_nch);

	return idx;
}

static int xsc_grp_channels_fill_stats(struct xsc_adapter *adapter, u64 *data,
				       int idx)
{
	int max_nch = xsc_get_netdev_max_channels(adapter);
	int max_tc = xsc_get_netdev_max_tc(adapter);
	int i, j, tc;
	struct xsc_stats *stats = adapter->stats;

	for (i = 0; i < max_nch; i++)
		for (j = 0; j < NUM_CH_STATS; j++)
			data[idx++] =
				XSC_READ_CTR64_CPU(&stats->channel_stats[i].ch,
						   ch_stats_desc, j);

	for (i = 0; i < max_nch; i++) {
		for (j = 0; j < NUM_RQ_STATS; j++)
			data[idx++] =
				XSC_READ_CTR64_CPU(&stats->channel_stats[i].rq,
						   rq_stats_desc, j);
	}

	for (tc = 0; tc < max_tc; tc++)
		for (i = 0; i < max_nch; i++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				data[idx++] =
					XSC_READ_CTR64_CPU(&stats->channel_stats[i].sq[tc],
							   sq_stats_desc, j);

	return idx;
}

static const struct counter_desc hw_prio_stats_desc[] = {
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  0),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  1),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  2),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  3),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  4),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  5),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  6),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  7),
};

static const struct counter_desc hw_stats_desc[] = {
	/*by mac port*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  np_cnp_sent) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rp_cnp_handled) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  np_ecn_marked_roce_packets) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rp_cnp_ignored) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  tx_pause) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_pause) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_fcs_errors) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_discards) },

	/*by global*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_loopback_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_loopback_bytes) },
};

static int xsc_hw_get_num_stats(struct xsc_adapter *adapter)
{
	return ARRAY_SIZE(hw_prio_stats_desc) + ARRAY_SIZE(hw_stats_desc);
}

static int xsc_hw_fill_strings(struct xsc_adapter *adapter, u8 *data, int idx)
{
	int i;
	struct xsc_core_device *xdev;

	xdev = adapter->xdev;

	for (i = 0; i < ARRAY_SIZE(hw_prio_stats_desc); i++)
		strscpy(data + (idx++) * ETH_GSTRING_LEN,
			hw_prio_stats_desc[i].format,
			sizeof(hw_prio_stats_desc[i].format));

	for (i = 0; i < ARRAY_SIZE(hw_stats_desc); i++)
		strscpy(data + (idx++) * ETH_GSTRING_LEN,
			hw_stats_desc[i].format,
			sizeof(hw_stats_desc[i].format));

	return idx;
}

static int xsc_hw_fill_stats(struct xsc_adapter *adapter, u64 *data, int idx)
{
	struct xsc_prio_stats_mbox_in in;
	struct xsc_prio_stats_mbox_out out;
	struct xsc_hw_stats_mbox_in hw_in;
	struct xsc_hw_stats_mbox_out hw_out;
	struct xsc_core_device *xdev;
	int ret;
	u32 i;
	u64 val;

	xdev = adapter->xdev;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_QUERY_PRIO_STATS);
	in.pport = xdev->mac_port;

	ret = xsc_cmd_exec(adapter->xdev, (void *)&in, sizeof(struct xsc_prio_stats_mbox_in),
			   (void *)&out, sizeof(struct xsc_prio_stats_mbox_out));
	if (ret == 0 && out.hdr.status == 0) {
		for (i = 0; i < ARRAY_SIZE(hw_prio_stats_desc); i++) {
			val = XSC_READ_CTR64_CPU(&out.prio_stats, hw_prio_stats_desc, i);
						 data[idx++] = __be64_to_cpu(val);
		}
	}

	memset(&hw_in, 0, sizeof(hw_in));
	memset(&hw_out, 0, sizeof(hw_out));
	hw_in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_QUERY_HW_STATS);
	hw_in.mac_port = xdev->mac_port;
	hw_in.is_lag = 0;

	ret = xsc_cmd_exec(adapter->xdev, (void *)&hw_in, sizeof(struct xsc_hw_stats_mbox_in),
			   (void *)&hw_out, sizeof(struct xsc_hw_stats_mbox_out));
	if (ret == 0 && hw_out.hdr.status == 0) {
		for (i = 0; i < ARRAY_SIZE(hw_stats_desc); i++) {
			val = XSC_READ_CTR64_CPU(&hw_out.hw_stats, hw_stats_desc, i);
			data[idx++] = __be64_to_cpu(val);
		}
	}

	return idx;
}

/* The stats groups order is opposite to the update_stats() order calls */
const struct xsc_stats_grp xsc_stats_grps[] = {
	{
		.get_num_stats = xsc_grp_sw_get_num_stats,
		.fill_strings = xsc_grp_sw_fill_strings,
		.fill_stats = xsc_grp_sw_fill_stats,
		.update_stats = xsc_grp_sw_update_stats,
	},

	{
		.get_num_stats = xsc_grp_channels_get_num_stats,
		.fill_strings = xsc_grp_channels_fill_strings,
		.fill_stats = xsc_grp_channels_fill_stats,
	},

	{
		.get_num_stats = xsc_hw_get_num_stats,
		.fill_strings = xsc_hw_fill_strings,
		.fill_stats = xsc_hw_fill_stats,
	},
};

const int xsc_num_stats_grps = ARRAY_SIZE(xsc_stats_grps);

void xsc_fold_sw_stats64(struct xsc_adapter *adapter, struct rtnl_link_stats64 *s)
{
	int i, j;

	for (i = 0; i < xsc_get_netdev_max_channels(adapter); i++) {
		struct xsc_channel_stats *channel_stats = &adapter->stats->channel_stats[i];
		struct xsc_rq_stats *rq_stats = &channel_stats->rq;

		s->rx_packets   += rq_stats->packets;
		s->rx_bytes     += rq_stats->bytes;

		for (j = 0; j < xsc_get_netdev_max_tc(adapter); j++) {
			struct xsc_sq_stats *sq_stats = &channel_stats->sq[j];

			s->tx_packets    += sq_stats->packets;
			s->tx_bytes      += sq_stats->bytes;
			s->tx_dropped    += sq_stats->dropped;
		}
	}
}
