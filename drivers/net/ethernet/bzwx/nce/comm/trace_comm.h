/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2020 - 2023, Chengdu BeiZhongWangXin Technology Co., Ltd. */

#define _NE6X_TRACE_NAME(trace_name) (trace_##ne6x##_##trace_name)
#define NE6X_TRACE_NAME(trace_name) _NE6X_TRACE_NAME(trace_name)

#define ne6x_trace(trace_name, args...) (NE6X_TRACE_NAME(trace_name) \
(args))

#define ne6x_trace_enabled(trace_name) (NE6X_TRACE_NAME(trace_name##_enabled) \
())

DECLARE_EVENT_CLASS(ne6x_tx_template,
		    TP_PROTO(struct ne6x_ring *ring, struct sk_buff *skb),
		    TP_ARGS(ring, skb),

		   TP_STRUCT__entry(__field(void *, ring)
				    __field(u32, len)
				    __field(u32, head_len)
				    __dynamic_array(unsigned char, data, skb_headlen(skb))
				    __string(devname, ring->netdev->name)
	),

		   TP_fast_assign(__entry->ring = ring;
				  __entry->len = skb->len;
				  __entry->head_len = skb_headlen(skb);
				  memcpy(__get_dynamic_array(data), skb->data,
					 skb_headlen(skb));
		   __assign_str(devname, ring->netdev->name);
	),

		   TP_printk("netdev: %s ring: %p  skb_len: %d skb_headlen:%d skb_head: %s",
			     __get_str(devname), __entry->ring, __entry->len,
			     __entry->head_len, __print_array(__get_dynamic_array(data),
			     __get_dynamic_array_len(data), 1))
	);

DEFINE_EVENT(ne6x_tx_template, ne6x_tx_skb,
	     TP_PROTO(struct ne6x_ring *ring, struct sk_buff *skb),
	     TP_ARGS(ring, skb)
);

DEFINE_EVENT(ne6x_tx_template, ne6x_tx_skb_jumbo,
	     TP_PROTO(struct ne6x_ring *ring, struct sk_buff *skb),
	     TP_ARGS(ring, skb)
);

DECLARE_EVENT_CLASS(ne6x_tx_desc_template,
		    TP_PROTO(struct ne6x_ring *ring, struct ne6x_tx_desc *desc),
		    TP_ARGS(ring, desc),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __field(u8, vp)
				     __field(u8, sop_valid)
				     __field(u8, eop_valid)
				     __field(u64, sop_cnt)
				     __field(u64, mop_cnt)
				     __field(u64, sop_addr)
				     __field(u64, mop_addr)
				     __string(devname, ring->netdev->name)
	),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
				   __entry->vp = desc->vp;
				   __entry->sop_valid = desc->sop_valid;
				   __entry->eop_valid = desc->eop_valid;
				   __entry->sop_cnt = desc->sop_cnt;
				   __entry->mop_cnt = desc->mop_cnt;
				   __entry->sop_addr = desc->buffer_sop_addr;
				   __entry->mop_addr = desc->buffer_mop_addr;
				   __assign_str(devname, ring->netdev->name);
	),

	TP_printk("netdev: %s ring: %p desc: %p vp: %d sop_valid:%d eop_valid: %d sop_cnt: %llu mop_cnt: %llu sop_addr: %llu mop_addr: %llu",
		  __get_str(devname), __entry->ring, __entry->desc,
		  __entry->vp, __entry->sop_valid, __entry->eop_valid,
		  __entry->sop_cnt, __entry->mop_cnt, __entry->sop_addr,
		  __entry->mop_addr)
	);

DEFINE_EVENT(ne6x_tx_desc_template, ne6x_tx_map_desc,
	     TP_PROTO(struct ne6x_ring *ring, struct ne6x_tx_desc *desc),
	     TP_ARGS(ring, desc)
);

DEFINE_EVENT(ne6x_tx_desc_template, ne6x_tx_map_jumbo_desc,
	     TP_PROTO(struct ne6x_ring *ring, struct ne6x_tx_desc *desc),
	     TP_ARGS(ring, desc)
);

DECLARE_EVENT_CLASS(ne6x_tx_tag_template,
		    TP_PROTO(struct ne6x_ring *ring, struct ne6x_tx_tag  *tx_tag),
		    TP_ARGS(ring, tx_tag),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(u8, pi)
				     __field(u8, vport)
				     __field(u16, vlan1)
				     __field(u16, vlan2)
				     __field(u16, mss)
				     __field(u16, tag_num)
				     __string(devname, ring->netdev->name)
	),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->pi = (tx_tag->tag_pi1 << 1) | tx_tag->tag_pi0;
				   __entry->vport = tx_tag->tag_vport;
				   __entry->vlan1 = tx_tag->tag_vlan1;
				   __entry->vlan2 = tx_tag->tag_vlan2;
				   __entry->mss = tx_tag->tag_mss;
				   __entry->tag_num = tx_tag->tag_num;
				   __assign_str(devname, ring->netdev->name);
	),

		    TP_printk("netdev: %s ring: %p pi: %d vport: %d vlan1:%d vlan2: %d mss: %d tag_num: %d",
			      __get_str(devname), __entry->ring, __entry->pi, __entry->vport,
			      __entry->vlan1, __entry->vlan2, __entry->mss, __entry->tag_num)
	);

DEFINE_EVENT(ne6x_tx_tag_template, ne6x_tx_map_tag,
	     TP_PROTO(struct ne6x_ring *ring, struct ne6x_tx_tag  *tx_tag),
	     TP_ARGS(ring, tx_tag)
);

DEFINE_EVENT(ne6x_tx_tag_template, ne6x_tx_map_jumbo_tag,
	     TP_PROTO(struct ne6x_ring *ring, struct ne6x_tx_tag  *tx_tag),
	     TP_ARGS(ring, tx_tag)
);

DECLARE_EVENT_CLASS(ne6x_rx_template,
		    TP_PROTO(struct ne6x_ring *ring, union ne6x_rx_desc *desc, struct sk_buff *skb),
		    TP_ARGS(ring, desc, skb),
		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __field(void *, skb)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
				   __entry->skb = skb;
				   __assign_str(devname, ring->netdev->name);),
		    TP_printk("netdev: %s ring: %p desc: %p skb %p",
			      __get_str(devname), __entry->ring,
			      __entry->desc, __entry->skb)
);

DECLARE_EVENT_CLASS(ne6x_rx_head_template,
		    TP_PROTO(struct ne6x_ring *ring, struct rx_hdr_info *rx_hdr),
		    TP_ARGS(ring, rx_hdr),
		    TP_STRUCT__entry(__field(void *, rx_hdr)
					__array(u8, headr, 12)
					__field(void *, ring)
					__string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->rx_hdr = rx_hdr;
				   memcpy(__entry->headr, rx_hdr, 12);
				   __assign_str(devname, ring->netdev->name);),
		    TP_printk("netdev: %s rx_hdr: %s",
			      __get_str(devname), __print_array(__entry->headr, 12, 1))
);

DEFINE_EVENT(ne6x_rx_head_template, ne6x_rx_hdr,
	     TP_PROTO(struct ne6x_ring *ring, struct rx_hdr_info *rx_hdr),
	     TP_ARGS(ring, rx_hdr)
);

DEFINE_EVENT(ne6x_rx_template, ne6x_clean_rx_irq,
	     TP_PROTO(struct ne6x_ring *ring, union ne6x_rx_desc *desc, struct sk_buff *skb),
	     TP_ARGS(ring, desc, skb)
);

DEFINE_EVENT(ne6x_rx_template, ne6x_clean_rx_irq_rx,
	     TP_PROTO(struct ne6x_ring *ring, union ne6x_rx_desc *desc, struct sk_buff *skb),
	     TP_ARGS(ring, desc, skb)
);

DECLARE_EVENT_CLASS(ne6x_xmit_template,
		    TP_PROTO(struct sk_buff *skb, struct ne6x_ring *ring),
		    TP_ARGS(skb, ring),
		    TP_STRUCT__entry(__field(void *, skb)
				     __field(void *, ring)
				     __string(devname, ring->netdev->name)),
		    TP_fast_assign(__entry->skb = skb;
				   __entry->ring = ring;
				   __assign_str(devname, ring->netdev->name);),
		    TP_printk("netdev: %s skb: %p ring: %p",
			      __get_str(devname), __entry->skb,
			      __entry->ring));

DEFINE_EVENT(ne6x_xmit_template, ne6x_xmit_frame_ring,
	     TP_PROTO(struct sk_buff *skb, struct ne6x_ring *ring),
	     TP_ARGS(skb, ring));

DEFINE_EVENT(ne6x_xmit_template, ne6x_xmit_frame_ring_drop,
	     TP_PROTO(struct sk_buff *skb, struct ne6x_ring *ring),
	     TP_ARGS(skb, ring));
