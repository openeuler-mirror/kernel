/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_EN_STATS_H
#define XSC_EN_STATS_H

#include "xsc_eth_common.h"

#define XSC_READ_CTR64_CPU(ptr, dsc, i) \
	(*(u64 *)((char *)(ptr) + (dsc)[i].offset))

#define ETH_GSTRING_LEN		32

#define XSC_DECLARE_STAT(type, fld)	""#fld, offsetof(type, fld)
#define XSC_DECLARE_RX_STAT(type, fld)	"rx%d_"#fld, offsetof(type, fld)
#define XSC_DECLARE_TX_STAT(type, fld)	"tx%d_"#fld, offsetof(type, fld)
#define XSC_DECLARE_CH_STAT(type, fld)	"ch%d_"#fld, offsetof(type, fld)

#define XSC_DECLARE_HW_PRIO_STAT_NAME(fld, prio)	(#fld "_prio"#prio)
#define XSC_DECLARE_HW_PRIO_STAT_OFFSET(type, fld, prio)	\
	(offsetof(type, fld) + (sizeof(type) * (prio)))
#define XSC_DECLARE_HW_PRIO_STAT(type, fld, prio)	\
	{XSC_DECLARE_HW_PRIO_STAT_NAME(fld, prio), \
	XSC_DECLARE_HW_PRIO_STAT_OFFSET(type, fld, prio)}

struct xsc_rq_stats {
	u64 packets;
	u64 bytes;
	u64 csum_unnecessary;
	u64 csum_none;
	u64 csum_err;
	u64 csum_succ;
	u64 cqes;
	u64 cqe_err;
	u64 wqes;
	u64 wqe_err;
	u64 oversize_pkts_sw_drop;
	u64 oversize_pkts_err;
	u64 buff_alloc_err;
	u64 cache_reuse;
	u64 cache_full;
	u64 cache_empty;
	u64 cache_busy;
	u64 cache_alloc;
	u64 cache_waive;
	u64 cache_ext;
	u64 cache_rdc;
};

struct xsc_sq_stats {
	/* commonly accessed in data path */
	u64 packets;
	u64 bytes;
	u64 tso_packets;
	u64 tso_bytes;
	u64 tso_inner_packets;
	u64 tso_inner_bytes;
	u64 csum_partial;
	u64 csum_partial_inner;
	/* less likely accessed in data path */
	u64 csum_none;
	u64 stopped;
	u64 dropped;
	u64 xmit_more;
	/* dirtied @completion */
	u64 cqes;
	u64 wake;
	u64 cqe_err;
	u64 oversize_pkts_sw_drop;
	u64 txdone_skb_null;
	u64 txdone_skb_refcnt_err;
	u64 skb_linear;
};

struct xsc_ch_stats {
	u64 events;
	u64 poll;
	u64 poll_0;
	u64 poll_1_63;
	u64 poll_64_511;
	u64 poll_512_1023;
	u64 poll_1024;
	u64 arm;
	u64 noarm;
	u64 aff_change;
} ____cacheline_aligned_in_smp;

struct xsc_adapter;
struct xsc_stats_grp {
	u16 update_stats_mask;
	int (*get_num_stats)(struct xsc_adapter *adapter);
	int (*fill_strings)(struct xsc_adapter *adapter, u8 *data, int idx);
	int (*fill_stats)(struct xsc_adapter *adapter, u64 *data, int idx);
	void (*update_stats)(struct xsc_adapter *adapter);
};

struct counter_desc {
	char		format[ETH_GSTRING_LEN];
	size_t		offset; /* Byte offset */
};

struct xsc_sw_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_tso_packets;
	u64 tx_tso_bytes;
	u64 tx_tso_inner_packets;
	u64 tx_tso_inner_bytes;
	u64 rx_csum_unnecessary;
	u64 rx_csum_none;
	u64 rx_csum_err;
	u64 rx_csum_succ;
	u64 tx_csum_none;
	u64 tx_csum_partial;
	u64 tx_csum_partial_inner;
	u64 tx_queue_stopped;
	u64 tx_queue_dropped;
	u64 tx_xmit_more;
	u64 tx_cqes;
	u64 tx_queue_wake;
	u64 tx_cqe_err;
	u64 tx_oversize_pkts_sw_drop;
	u64 txdone_skb_null;
	u64 txdone_skb_refcnt_err;
	u64 skb_linear;
	u64 rx_cqes;
	u64 rx_cqe_err;
	u64 rx_wqes;
	u64 rx_wqe_err;
	u64 rx_oversize_pkts_sw_drop;
	u64 rx_oversize_pkts_err;
	u64 rx_buff_alloc_err;
	u64 rx_cache_reuse;
	u64 rx_cache_full;
	u64 rx_cache_empty;
	u64 rx_cache_busy;
	u64 rx_cache_alloc;
	u64 rx_cache_waive;
	u64 rx_cache_ext;
	u64 rx_cache_rdc;
	u64 ch_events;
	u64 ch_poll;
	u64 ch_poll_0;
	u64 ch_poll_1_63;
	u64 ch_poll_64_511;
	u64 ch_poll_512_1023;
	u64 ch_poll_1024;
	u64 ch_arm;
	u64 ch_noarm;
	u64 ch_aff_change;
};

struct xsc_channel_stats {
	struct xsc_ch_stats ch;
	struct xsc_sq_stats sq[XSC_MAX_NUM_TC];
	struct xsc_rq_stats rq;
} ____cacheline_aligned_in_smp;

struct xsc_stats {
	struct xsc_sw_stats sw;
	struct xsc_channel_stats channel_stats[XSC_ETH_MAX_NUM_CHANNELS];
};

extern const struct xsc_stats_grp xsc_stats_grps[];
extern const int xsc_num_stats_grps;

void xsc_fold_sw_stats64(struct xsc_adapter *adapter, struct rtnl_link_stats64 *s);

#endif /* XSC_EN_STATS_H */
