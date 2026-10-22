/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

/* This must be outside ifdef _UNIC_TRACE_H_ */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM unic

#if !defined(__UNIC_TRACE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __UNIC_TRACE_H__

#include <linux/tracepoint.h>

#define trace_tx_max_sqebb_num		8
#define trace_cqe_num			(sizeof(union unic_cqe) / sizeof(u32))
#define trace_sqebb_num(sqebb_num)	\
	(sizeof(struct unic_sqebb) * (sqebb_num) / sizeof(u32))

#define trace_nlmsghdr_arr_size		(sizeof(struct nlmsghdr) / sizeof(u32))
#define trace_ifaddrmsg_arr_size	(sizeof(struct ifaddrmsg) / sizeof(u32))
#define trace_attrbuf_arr_size		16

DECLARE_EVENT_CLASS(unic_cqe_template,
		    TP_PROTO(const struct net_device *netdev,
			     const struct unic_cq *cq, u16 pi, u16 ci,
			     u32 cqe_mask),
		    TP_ARGS(netdev, cq, pi, ci, cqe_mask),

		    TP_STRUCT__entry(__field(u32, jfcn)
				     __field(u32, cqe_mask)
				     __field(u16, pi)
				     __field(u16, ci)
				     __field(u32, cq_ci)
				     __field(u8, cqe_num)
				     __array(u32, cqe, trace_cqe_num)
				     __string(devname, netdev->name)
		    ),

		    TP_fast_assign(__entry->jfcn = cq->jfcn;
				   __entry->cqe_mask = cqe_mask;
				   __entry->pi = pi;
				   __entry->ci = ci;
				   __entry->cq_ci = cq->ci;
				   __entry->cqe_num = unic_get_cqe_size() / sizeof(u32);
				   memcpy(__entry->cqe,
					  &cq->cqe[cq->ci & __entry->cqe_mask],
					  unic_get_cqe_size());
				   __assign_str(devname, netdev->name);
		    ),

		    TP_printk("%s-%u-%u/%u cqe(%u): %s",
			      __get_str(devname), __entry->jfcn, __entry->pi,
			      __entry->ci, __entry->cq_ci,
			      __print_array(__entry->cqe, __entry->cqe_num,
					    sizeof(u32))
		    )
);

DEFINE_EVENT(unic_cqe_template, unic_tx_cqe,
	     TP_PROTO(const struct net_device *netdev, const struct unic_cq *cq,
		      u16 pi, u16 ci, u32 cqe_mask),
	     TP_ARGS(netdev, cq, pi, ci, cqe_mask));

DEFINE_EVENT(unic_cqe_template, unic_rx_cqe,
	     TP_PROTO(const struct net_device *netdev, const struct unic_cq *cq,
		      u16 pi, u16 ci, u32 cqe_mask),
	     TP_ARGS(netdev, cq, pi, ci, cqe_mask));

TRACE_EVENT(unic_tx_sqe,
	    TP_PROTO(struct unic_sq *sq, u16 sqebb_num, u16 sqebb_mask),
	    TP_ARGS(sq, sqebb_num, sqebb_mask),

	    TP_STRUCT__entry(__field(u32, jfcn)
			     __field(u16, pi)
			     __field(u16, ci)
			     __field(u16, buff_pi)
			     __field(u16, buff_ci)
			     __field(u16, sqebb_num)
			     __field(u16, real_pi)
			     __array(u32, sqebb, trace_sqebb_num(trace_tx_max_sqebb_num))
			     __string(devname, sq->netdev->name)
	    ),

	    TP_fast_assign(__entry->jfcn = sq->cq->jfcn;
			__entry->pi = sq->pi;
			__entry->ci = sq->ci;
			__entry->buff_pi = sq->tx_buff->pi;
			__entry->buff_ci = sq->tx_buff->ci;
			__entry->sqebb_num = sqebb_num;
			__entry->real_pi = sq->pi & sqebb_mask;
			if (__entry->real_pi + sqebb_num - 1 > sqebb_mask) {
				memcpy(__entry->sqebb, &sq->sqebb[__entry->real_pi],
				       (sqebb_mask - __entry->real_pi + 1) *
				       sizeof(struct unic_sqebb));
				memcpy(&__entry->sqebb[trace_sqebb_num(sqebb_mask -
				       __entry->real_pi + 1)],
				       &sq->sqebb[0],
				       (__entry->real_pi + sqebb_num - 1 - sqebb_mask) *
				       sizeof(struct unic_sqebb));
			} else {
				memcpy(__entry->sqebb, &sq->sqebb[__entry->real_pi],
				       sqebb_num * sizeof(struct unic_sqebb));
			}
			unic_mask_key_words(__entry->sqebb);
			__assign_str(devname, sq->netdev->name);
	    ),

	    TP_printk("%s-%u-%u/%u-%u/%u sqe: %s",
		      __get_str(devname), __entry->jfcn, __entry->pi,
		      __entry->ci, __entry->buff_pi, __entry->buff_ci,
		      __print_array(__entry->sqebb,
				    trace_sqebb_num(__entry->sqebb_num),
				    sizeof(u32))
	    )
);

TRACE_EVENT(unic_ip_req_skb,
	    TP_PROTO(const struct net_device *netdev, const struct sk_buff *skb,
		     const struct nlmsghdr *nh, const struct ifaddrmsg *info,
		     const char *attrbuf),
	    TP_ARGS(netdev, skb, nh, info, attrbuf),

	    TP_STRUCT__entry(__field(u32, len)
			     __array(u32, nl_hdr, trace_nlmsghdr_arr_size)
			     __array(u32, ifa_info, trace_ifaddrmsg_arr_size)
			     __array(u32, attrs_buf, trace_attrbuf_arr_size)
			     __string(devname, netdev->name)
	    ),

	    TP_fast_assign(__entry->len = skb->len;
			   memcpy(__entry->nl_hdr, nh, sizeof(struct nlmsghdr));
			   memcpy(__entry->ifa_info, info, sizeof(struct ifaddrmsg));
			   memcpy(__entry->attrs_buf, attrbuf,
				  sizeof(u32) * trace_attrbuf_arr_size);
			   __assign_str(devname, netdev->name);
	    ),

	    TP_printk("%s netlink: len=%u nl_hdr=%s ifa_info=%s attrs_buf=%s",
		      __get_str(devname), __entry->len,
		      __print_array(__entry->nl_hdr, trace_nlmsghdr_arr_size,
				    sizeof(u32)),
		      __print_array(__entry->ifa_info, trace_ifaddrmsg_arr_size,
				    sizeof(u32)),
		      __print_array(__entry->attrs_buf, trace_attrbuf_arr_size,
				    sizeof(u32))
	    )
);

TRACE_EVENT(unic_rq_ci_mismatch,
	    TP_PROTO(struct unic_rq *rq, const u32 start_rqe_idx),
	    TP_ARGS(rq, start_rqe_idx),

	    TP_STRUCT__entry(__field(u16, queue_index)
			     __field(u16, ci)
			     __field(u32, start_rqe_idx)
			     __string(devname, rq->netdev->name)
	    ),

	    TP_fast_assign(__entry->queue_index = rq->queue_index;
			   __entry->ci = rq->ci;
			   __entry->start_rqe_idx = start_rqe_idx;
			   __assign_str(devname, rq->netdev->name);
	    ),

	    TP_printk("%s rq_ci: queue_index=%u sw_rq_ci=%u hw_rq_ci=%u",
		      __get_str(devname), __entry->queue_index, __entry->ci,
		      __entry->start_rqe_idx
	    )
);

#endif /* __UNIC_TRACE_H__ */

/* This must be outside ifdef _UNIC_TRACE_H */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE unic_trace
#include <trace/define_trace.h>
