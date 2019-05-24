/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2018-2019 Hisilicon Limited. */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM hns3

#if !defined(_HNS3_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _HNS3_TRACE_H_

#include <linux/tracepoint.h>

#define DESC_NR		(sizeof(struct hns3_desc) / sizeof(u32))

TRACE_EVENT(hns3_over_8bd,
	TP_PROTO(struct sk_buff *skb),
	TP_ARGS(skb),

	TP_STRUCT__entry(
		__field(unsigned int, headlen)
		__field(__u8, nr_frags)
		__field(unsigned short, gso_size)
		__array(__u32, size, MAX_SKB_FRAGS)
	),

	TP_fast_assign(
		__entry->headlen = skb_headlen(skb);
		__entry->nr_frags = skb_shinfo(skb)->nr_frags;
		__entry->gso_size = skb_shinfo(skb)->gso_size;
		hns3_shinfo_pack(skb_shinfo(skb), __entry->size);
	),

	TP_printk(
		"headlen: %u, nr_frags: %u, gso: %u frag size: %s",
		__entry->headlen, __entry->gso_size, __entry->nr_frags,
		__print_array(__entry->size, MAX_SKB_FRAGS, sizeof(__u32))
	)
);

TRACE_EVENT(hns3_tx_desc,
	TP_PROTO(struct hns3_enet_ring *ring),
	TP_ARGS(ring),

	TP_STRUCT__entry(
		__field(int, index)
		__field(int, ntu)
		__field(int, ntc)
		__field(dma_addr_t, desc_dma)
		__array(u32, desc, DESC_NR)
		__string(devname, ring->tqp->handle->kinfo.netdev->name)
	),

	TP_fast_assign(
		__entry->index = ring->tqp->tqp_index;
		__entry->ntu = ring->next_to_use;
		__entry->ntc = ring->next_to_clean;
		__entry->desc_dma = ring->desc_dma_addr,
		memcpy(__entry->desc, &ring->desc[ring->next_to_use],
		       sizeof(struct hns3_desc));
		__assign_str(devname, ring->tqp->handle->kinfo.netdev->name);
	),

	TP_printk(
		"%s-%d-%d/%d desc(0x%llx): %s",
		__get_str(devname), __entry->index, __entry->ntu,
		__entry->ntc, __entry->desc_dma,
		__print_array(__entry->desc, DESC_NR, sizeof(u32))
	)
);

TRACE_EVENT(hns3_rx_desc,
	TP_PROTO(struct hns3_enet_ring *ring),
	TP_ARGS(ring),

	TP_STRUCT__entry(
		__field(int, index)
		__field(int, ntu)
		__field(int, ntc)
		__field(dma_addr_t, desc_dma)
		__field(dma_addr_t, buf_dma)
		__array(u32, desc, DESC_NR)
		__string(devname, ring->tqp->handle->kinfo.netdev->name)
	),

	TP_fast_assign(
		__entry->index = ring->tqp->tqp_index;
		__entry->ntu = ring->next_to_use;
		__entry->ntc = ring->next_to_clean;
		__entry->desc_dma = ring->desc_dma_addr;
		__entry->buf_dma = ring->desc_cb[ring->next_to_clean].dma;
		memcpy(__entry->desc, &ring->desc[ring->next_to_clean],
		       sizeof(struct hns3_desc));
		__assign_str(devname, ring->tqp->handle->kinfo.netdev->name);
	),

	TP_printk(
		"%s-%d-%d/%d desc(0x%llx) buf(0x%llx): %s",
		__get_str(devname), __entry->index, __entry->ntu,
		__entry->ntc, __entry->desc_dma, __entry->buf_dma,
		__print_array(__entry->desc, DESC_NR, sizeof(u32))
	)
);

#endif /* _HNS3_TRACE_H_ */

/* This must be outside ifdef _HNS3_TRACE_H */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE hns3_trace
#include <trace/define_trace.h>
