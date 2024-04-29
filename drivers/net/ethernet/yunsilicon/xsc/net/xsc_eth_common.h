/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ETH_COMMON_H
#define XSC_ETH_COMMON_H

#include "xsc_queue.h"
#include "xsc_eth_compat.h"
#include "common/xsc_pph.h"
#include "common/xsc_hsi.h"

#define SW_MIN_MTU		64
#define SW_DEFAULT_MTU		1500
#define SW_MAX_MTU		9600

#define XSC_ETH_HW_MTU_SEND	9800		/*need to obtain from hardware*/
#define XSC_ETH_HW_MTU_RECV	9800		/*need to obtain from hardware*/
#define XSC_SW2HW_MTU(mtu)	((mtu) + 14 + 4)
#define XSC_SW2HW_FRAG_SIZE(mtu)	((mtu) + 14 + 8 + 4 + XSC_PPH_HEAD_LEN)
#define XSC_SW2HW_RX_PKT_LEN(mtu)	((mtu) + 14 + 256)

#define XSC_RX_MAX_HEAD			(256)
#define XSC_RX_HEADROOM			NET_SKB_PAD

#define XSC_QPN_SQN_STUB		1025
#define XSC_QPN_RQN_STUB		1024

#define XSC_LOG_INDIR_RQT_SIZE		0x8

#define XSC_INDIR_RQT_SIZE			BIT(XSC_LOG_INDIR_RQT_SIZE)
#ifdef XSC_RSS_SUPPORT
#define XSC_ETH_MIN_NUM_CHANNELS	2
#else
#define XSC_ETH_MIN_NUM_CHANNELS	1
#endif
#define XSC_ETH_MAX_NUM_CHANNELS	XSC_INDIR_RQT_SIZE

#define XSC_TX_NUM_TC			1
#define XSC_MAX_NUM_TC			8
#define XSC_ETH_MAX_TC_TOTAL		(XSC_ETH_MAX_NUM_CHANNELS * XSC_MAX_NUM_TC)
#define XSC_ETH_MAX_QP_NUM_PER_CH	(XSC_MAX_NUM_TC + 1)

#define XSC_SKB_FRAG_SZ(len)		(SKB_DATA_ALIGN(len) +	\
					SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#define XSC_MIN_SKB_FRAG_SZ		(XSC_SKB_FRAG_SZ(XSC_RX_HEADROOM))
#define XSC_LOG_MAX_RX_WQE_BULK	\
			(ilog2(PAGE_SIZE / roundup_pow_of_two(XSC_MIN_SKB_FRAG_SZ)))

#define XSC_MIN_LOG_RQ_SZ		(1 + XSC_LOG_MAX_RX_WQE_BULK)
#define XSC_DEF_LOG_RQ_SZ		0xa
#define XSC_MAX_LOG_RQ_SZ		0xd

#define XSC_MIN_LOG_SQ_SZ		0x6
#define XSC_DEF_LOG_SQ_SZ		0xa
#define XSC_MAX_LOG_SQ_SZ		0xd

#define XSC_SQ_ELE_NUM_DEF	BIT(XSC_DEF_LOG_SQ_SZ)
#define XSC_RQ_ELE_NUM_DEF	BIT(XSC_DEF_LOG_RQ_SZ)

#define XSC_RQCQ_ELE_NUM	XSC_RQ_ELE_NUM_DEF //number of rqcq entry
#define XSC_SQCQ_ELE_NUM	XSC_SQ_ELE_NUM_DEF //number of sqcq entry
#define XSC_RQ_ELE_NUM		XSC_RQ_ELE_NUM_DEF //ds number of a wqebb
#define XSC_SQ_ELE_NUM		XSC_SQ_ELE_NUM_DEF //DS number
#define XSC_EQ_ELE_NUM		XSC_SQ_ELE_NUM_DEF //number of eq entry???

#define XSC_RQCQ_ELE_SZ		32	//size of a rqcq entry
#define XSC_SQCQ_ELE_SZ		32	//size of a sqcq entry
#define XSC_RQ_ELE_SZ		XSC_RECV_WQE_BB
#define XSC_SQ_ELE_SZ		XSC_SEND_WQE_BB
#define XSC_EQ_ELE_SZ		8	//size of a eq entry

#define XSC_CQ_POLL_BUDGET	64
#define XSC_TX_POLL_BUDGET	128

#define XSC_MAX_BW_ALLOC	100 /* Max percentage of BW allocation */
#define XSC_MAX_PRIORITY	8
#define XSC_MAX_DSCP		64
#define XSC_MAX_BUFFER		8
#define XSC_DEFAULT_CABLE_LEN	7 /* 7 meters */

enum xsc_port_status {
	XSC_PORT_UP        = 1,
	XSC_PORT_DOWN      = 2,
};

/*all attributes of queue, MAYBE no use for some special queue*/

enum xsc_queue_type {
	XSC_QUEUE_TYPE_EQ = 0,
	XSC_QUEUE_TYPE_RQCQ,
	XSC_QUEUE_TYPE_SQCQ,
	XSC_QUEUE_TYPE_RQ,
	XSC_QUEUE_TYPE_SQ,
	XSC_QUEUE_TYPE_MAX,
};

struct xsc_queue_attr {
	u8  q_type;
	u32 ele_num;
	u32 ele_size;
	u8  ele_log_size;
	u8  q_log_size;
};

/*MUST set value before create queue*/
struct xsc_eth_eq_attr {
	struct xsc_queue_attr xsc_eq_attr;
};

struct xsc_eth_cq_attr {
	struct xsc_queue_attr xsc_cq_attr;
};

struct xsc_eth_rq_attr {
	struct xsc_queue_attr xsc_rq_attr;
};

struct xsc_eth_sq_attr {
	struct xsc_queue_attr xsc_sq_attr;
};

struct xsc_eth_qp_attr {
	struct xsc_queue_attr xsc_qp_attr;
};

struct xsc_eth_rx_wqe_cyc {
	DECLARE_FLEX_ARRAY(struct xsc_wqe_data_seg, data);
};

struct xsc_eq_param {
	struct xsc_queue_attr eq_attr;
};

struct xsc_cq_param {
	struct xsc_wq_param wq;
	struct cq_cmd {
		u8 abc[16];
	} cqc;
	struct xsc_queue_attr cq_attr;
};

struct xsc_rq_param {
	struct xsc_wq_param wq;
	struct xsc_queue_attr rq_attr;
	struct xsc_rq_frags_info frags_info;

};

struct xsc_sq_param {
	struct xsc_wq_param wq;
	struct xsc_queue_attr sq_attr;
};

struct xsc_qp_param {
	struct xsc_queue_attr qp_attr;
};

struct xsc_channel_param {
	struct xsc_cq_param rqcq_param;
	struct xsc_cq_param sqcq_param;
	struct xsc_rq_param rq_param;
	struct xsc_sq_param sq_param;
	struct xsc_qp_param qp_param;
};

struct xsc_eth_qp {
	u16 rq_num;
	u16 sq_num;
	struct xsc_rq rq[XSC_MAX_NUM_TC]; /*may be use one only*/
	struct xsc_sq sq[XSC_MAX_NUM_TC]; /*reserved to tc*/
};

enum channel_flags {
	XSC_CHANNEL_NAPI_SCHED = 1,
};

struct xsc_channel {
	/* data path */
	struct xsc_eth_qp  qp;
	struct napi_struct napi;
	u8	num_tc;
	int	chl_idx;

	/*relationship*/
	struct xsc_adapter *adapter;
	struct net_device *netdev;
	int	cpu;
	unsigned long	flags;

	/* data path - accessed per napi poll */
	const struct cpumask *aff_mask;
	struct irq_desc *irq_desc;
	struct xsc_ch_stats *stats;
	u8	rx_int;
} ____cacheline_aligned_in_smp;

enum xsc_eth_priv_flag {
	XSC_PFLAG_RX_NO_CSUM_COMPLETE,
	XSC_PFLAG_SNIFFER,
	XSC_PFLAG_DROPLESS_RQ,
	XSC_NUM_PFLAGS, /* Keep last */
};

#define XSC_SET_PFLAG(params, pflag, enable)			\
	do {							\
		if (enable)					\
			(params)->pflags |= BIT(pflag);		\
		else						\
			(params)->pflags &= ~(BIT(pflag));	\
	} while (0)

#define XSC_GET_PFLAG(params, pflag) (!!((params)->pflags & (BIT(pflag))))

struct xsc_eth_params {
	u16	num_channels;
	u16	max_num_ch;
	u8	num_tc;
	u32	mtu;
	u32	hard_mtu;
	u32	comp_vectors;
	u32	sq_size;
	u32	sq_max_size;
	u8	rq_wq_type;
	u32	rq_size;
	u32	rq_max_size;
	u32	rq_frags_size;

	u16	num_rl_txqs;
	u8	rx_cqe_compress_def;
	u8	tunneled_offload_en;
	u8	lro_en;
	u8	tx_min_inline_mode;
	u8	vlan_strip_disable;
	u8	scatter_fcs_en;
	u8	rx_dim_enabled;
	u8	tx_dim_enabled;
	u32	lro_timeout;
	u32	pflags;
};

struct xsc_eth_channels {
	struct xsc_channel *c;
	unsigned int num_chl;
	u32 rqn_base;
};

struct xsc_eth_redirect_rqt_param {
	u8 is_rss;
	union {
		u32 rqn; /* Direct RQN (Non-RSS) */
		struct {
			u8 hfunc;
			struct xsc_eth_channels *channels;
		} rss; /* RSS data */
	};
};

union xsc_send_doorbell {
	struct{
		s32  next_pid : 16;
		u32 qp_num : 15;
	};
	u32 send_data;
};

union xsc_recv_doorbell {
	struct{
		s32  next_pid : 13;
		u32 qp_num : 15;
	};
	u32 recv_data;
};

#endif /* XSC_ETH_COMMON_H */
