/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_trace.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#if !IS_ENABLED(CONFIG_TRACEPOINTS) || defined(__CHECKER__) || !defined(SXE2_DRIVER_TRACE)
#if !defined(_SXE2_TRACE_H_)
#define _SXE2_TRACE_H_

#define sxe2_trace(trace_name, args...)
#define sxe2_trace_enabled(trace_name) ((void)"" #trace_name, 0)
#endif
#else

#undef TRACE_SYSTEM
#define TRACE_SYSTEM sxe2

#if !defined(_SXE2_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _SXE2_TRACE_H_

#include "sxe2_irq.h"
#include "sxe2_queue.h"

#include <linux/tracepoint.h>

#define _SXE2_TRACE_NAME(trace_name) (trace_##sxe2##_##trace_name)
#define SXE2_TRACE_NAME(trace_name)  _SXE2_TRACE_NAME(trace_name)

#define sxe2_trace(trace_name, args...) SXE2_TRACE_NAME(trace_name)(args)

DECLARE_EVENT_CLASS(sxe2_irq_rxclean, TP_PROTO(struct sxe2_irq_data *irq_data, int total_clean),
		    TP_ARGS(irq_data, total_clean),
		    TP_STRUCT__entry(__string(irqname, irq_data->name) __field(int, total_clean)),
		    TP_fast_assign(__assign_str(irqname, irq_data->name);
				   __entry->total_clean = total_clean;),
		    TP_printk("irqname: %s total_clean: %d", __get_str(irqname),
			      __entry->total_clean));
#define DEFINE_IRQ_RXCLEAN_EVENT(name)                                      \
	DEFINE_EVENT(sxe2_irq_rxclean, name,                                    \
		TP_PROTO(struct sxe2_irq_data *irq_data, int total_clean), \
		TP_ARGS(irq_data, total_clean))
DEFINE_IRQ_RXCLEAN_EVENT(sxe2_irq_rxclean_begin);
DEFINE_IRQ_RXCLEAN_EVENT(sxe2_irq_rxclean_end);

TRACE_EVENT(sxe2_rxq_clean_begin, TP_PROTO(struct sxe2_queue *rxq), TP_ARGS(rxq),
	    TP_STRUCT__entry(__field(u16, idx_in_vsi)),
	    TP_fast_assign(__entry->idx_in_vsi = rxq->idx_in_vsi;),
	    TP_printk("rxq idx in vsi: %u", __entry->idx_in_vsi));
TRACE_EVENT(sxe2_rxq_clean_end, TP_PROTO(struct sxe2_queue *rxq, s32 clean), TP_ARGS(rxq, clean),
	    TP_STRUCT__entry(__field(u16, idx_in_vsi) __field(s32, clean)),
	    TP_fast_assign(__entry->idx_in_vsi = rxq->idx_in_vsi; __entry->clean = clean),
	    TP_printk("rxq idx in vsi: %u, clean: %d", __entry->idx_in_vsi, __entry->clean));

DECLARE_EVENT_CLASS(sxe2_pkt_clean, TP_PROTO(struct sxe2_queue *rxq), TP_ARGS(rxq),
		    TP_STRUCT__entry(__field(u16, idx_in_vsi) __field(u16, next_to_clean)),
		    TP_fast_assign(__entry->idx_in_vsi    = rxq->idx_in_vsi;
				   __entry->next_to_clean = rxq->next_to_clean;),
		    TP_printk("idx_in_vsi: %u next_to_clean: %u", __entry->idx_in_vsi,
			      __entry->next_to_clean));
#define DEFINE_PKT_CLEAN_EVENT(name) \
	DEFINE_EVENT(sxe2_pkt_clean, name, TP_PROTO(struct sxe2_queue *rxq), TP_ARGS(rxq))
DEFINE_PKT_CLEAN_EVENT(sxe2_rx_pkt_clean_begin);
DEFINE_PKT_CLEAN_EVENT(sxe2_rx_pkt_clean_end);

DECLARE_EVENT_CLASS(sxe2_xmit_template, TP_PROTO(struct sxe2_queue *queue, struct sk_buff *skb),
		    TP_ARGS(queue, skb),
		    TP_STRUCT__entry(__field(void *, queue) __field(void *, skb)
				    __string(devname, queue->netdev->name)),
		    TP_fast_assign(__entry->queue = queue; __entry->skb = skb;
				   __assign_str(devname, queue->netdev->name);),
		    TP_printk("netdev: %s skb: %pK queue: %pK", __get_str(devname), __entry->skb,
			      __entry->queue));

#define DEFINE_XMIT_TEMPLATE_OP_EVENT(name) \
	DEFINE_EVENT(sxe2_xmit_template, name,  \
		TP_PROTO(struct sxe2_queue *queue, struct sk_buff *skb), TP_ARGS(queue, skb))

DEFINE_XMIT_TEMPLATE_OP_EVENT(sxe2_queue_xmit);
DEFINE_XMIT_TEMPLATE_OP_EVENT(sxe2_queue_xmit_drop);

union sxe2_tx_data_desc;
struct sxe2_tx_buf;
DECLARE_EVENT_CLASS(sxe2_tx_clean_template,
		    TP_PROTO(struct sxe2_queue *txq,
			     union sxe2_tx_data_desc *tx_desc,
			     struct sxe2_tx_buf *tx_buf),
		    TP_ARGS(txq, tx_desc, tx_buf),
		    TP_STRUCT__entry(__field(void *, txq)
				     __field(void *, tx_desc)
				     __field(void *, tx_buf)
				     __string(devname, txq->netdev->name)),
		    TP_fast_assign(__entry->txq = txq;
				   __entry->tx_desc = tx_desc;
				   __entry->tx_buf = tx_buf;
				   __assign_str(devname, txq->netdev->name);),
		    TP_printk("netdev: %s txq_idx: %u txq: %p tx_desc: %p tx_buf %p",
			      __get_str(devname),
			      ((struct sxe2_queue *)__entry->txq)->idx_in_vsi, __entry->txq,
			      __entry->tx_desc, __entry->tx_buf)
);

#define DEFINE_TX_TEMPLATE_OP_EVENT(name) \
DEFINE_EVENT(sxe2_tx_clean_template, name, \
	TP_PROTO(struct sxe2_queue *txq, \
		union sxe2_tx_data_desc *tx_desc, \
		struct sxe2_tx_buf *tx_buf), \
	TP_ARGS(txq, tx_desc, tx_buf))

DEFINE_TX_TEMPLATE_OP_EVENT(sxe2_clean_tx_irq);
DEFINE_TX_TEMPLATE_OP_EVENT(sxe2_clean_tx_irq_unmap);
DEFINE_TX_TEMPLATE_OP_EVENT(sxe2_clean_tx_irq_unmap_eop);

DECLARE_EVENT_CLASS(sxe2_txts_template, TP_PROTO(struct sk_buff *skb, int idx), TP_ARGS(skb, idx),
		    TP_STRUCT__entry(__field(void *, skb) __field(int, idx)),
		    TP_fast_assign(__entry->skb = skb; __entry->idx = idx;),
		    TP_printk("skb %pK idx %d", __entry->skb, __entry->idx));

#define DEFINE_TX_TSTAMP_OP_EVENT(name)                                            \
	DEFINE_EVENT(sxe2_txts_template, name, TP_PROTO(struct sk_buff *skb, int idx), \
		TP_ARGS(skb, idx))

DEFINE_TX_TSTAMP_OP_EVENT(sxe2_txts_request);
DEFINE_TX_TSTAMP_OP_EVENT(sxe2_txts_hw_request);
DEFINE_TX_TSTAMP_OP_EVENT(sxe2_txts_hw_done);
DEFINE_TX_TSTAMP_OP_EVENT(sxe2_txts_complete);

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH CUR_DIR "/base/trace"
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE sxe2_trace
#include <trace/define_trace.h>
#endif
