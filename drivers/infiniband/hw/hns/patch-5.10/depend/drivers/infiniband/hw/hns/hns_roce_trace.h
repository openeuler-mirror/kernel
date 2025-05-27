/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 Hisilicon Limited.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM hns_roce

#if !defined(__HNS_ROCE_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define __HNS_ROCE_TRACE_H

#include <linux/tracepoint.h>
#include "hns_roce_device.h"
#include "hns_roce_hw_v2.h"

DECLARE_EVENT_CLASS(flush_head_template,
		    TP_PROTO(unsigned long qpn, u32 pi,
			     enum hns_roce_trace_type type),
		    TP_ARGS(qpn, pi, type),

		    TP_STRUCT__entry(__field(unsigned long, qpn)
				     __field(u32, pi)
				     __field(enum hns_roce_trace_type, type)
		    ),

		    TP_fast_assign(__entry->qpn = qpn;
				   __entry->pi = pi;
				   __entry->type = type;
		    ),

		    TP_printk("%s 0x%lx flush head 0x%x.",
			      trace_type_to_str(__entry->type),
			      __entry->qpn, __entry->pi)
);

DEFINE_EVENT(flush_head_template, hns_sq_flush_cqe,
	     TP_PROTO(unsigned long qpn, u32 pi,
		      enum hns_roce_trace_type type),
	     TP_ARGS(qpn, pi, type));
DEFINE_EVENT(flush_head_template, hns_rq_flush_cqe,
	     TP_PROTO(unsigned long qpn, u32 pi,
		      enum hns_roce_trace_type type),
	     TP_ARGS(qpn, pi, type));

TRACE_EVENT(hns_ae_info,
	    TP_PROTO(int event_type, void *aeqe, unsigned int len),
	    TP_ARGS(event_type, aeqe, len),

	    TP_STRUCT__entry(__field(int, event_type)
			     __array(__le32, aeqe,
				     HNS_ROCE_V3_EQE_SIZE / sizeof(__le32))
			     __field(u32, len)
	    ),

	    TP_fast_assign(__entry->event_type = event_type;
			   __entry->len = len / sizeof(__le32);
			   memcpy(__entry->aeqe, aeqe, len);
	    ),

	    TP_printk("event %2d aeqe: %s", __entry->event_type,
		      __print_array(__entry->aeqe, __entry->len, sizeof(__le32)))
);

DECLARE_EVENT_CLASS(cmdq,
		    TP_PROTO(struct hns_roce_dev *hr_dev,
			     struct hns_roce_cmq_desc *desc),
		    TP_ARGS(hr_dev, desc),

		    TP_STRUCT__entry(__string(dev_name, dev_name(hr_dev->dev))
				     __field(u16, opcode)
				     __field(u16, flag)
				     __field(u16, retval)
				     __array(__le32, data, 6)
		    ),

		    TP_fast_assign(__assign_str(dev_name, dev_name(hr_dev->dev));
				   __entry->opcode = le16_to_cpu(desc->opcode);
				   __entry->flag = le16_to_cpu(desc->flag);
				   __entry->retval = le16_to_cpu(desc->retval);
				   memcpy(__entry->data, desc->data, 6 * sizeof(__le32));
		    ),

		    TP_printk("%s cmdq opcode:0x%x, flag:0x%x, retval:0x%x, data:%s\n",
			      __get_str(dev_name), __entry->opcode,
			      __entry->flag, __entry->retval,
			      __print_array(__entry->data, 6, sizeof(__le32)))
);

DEFINE_EVENT(cmdq, hns_cmdq_req,
	     TP_PROTO(struct hns_roce_dev *hr_dev,
		      struct hns_roce_cmq_desc *desc),
	     TP_ARGS(hr_dev, desc));
DEFINE_EVENT(cmdq, hns_cmdq_resp,
	     TP_PROTO(struct hns_roce_dev *hr_dev,
		      struct hns_roce_cmq_desc *desc),
	     TP_ARGS(hr_dev, desc));

#endif /* __HNS_ROCE_TRACE_H */

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE hns_roce_trace
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#include <trace/define_trace.h>
