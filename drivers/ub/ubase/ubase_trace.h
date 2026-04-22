/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

/* This must be outside ifdef UBASE_TRACE_H_ */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ubase

#if !defined(__UBASE_TRACE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __UBASE_TRACE_H__

#include <linux/tracepoint.h>

#define TRACE_TWO_BYTES_BITS		16
#define TRACE_THREE_BYTES_BITS		24
#define TRACE_CMDQ_DESC_SIZE	(sizeof(struct ubase_cmdq_desc) / sizeof(u32))

#define TRACE_DEV_NAME_MAX_LEN		16

#ifndef __UBASE_TRACE_INFO_STRUCT__
#define __UBASE_TRACE_INFO_STRUCT__
struct ubase_ctrlq_trace_info {
	u16	bus_ue_id;
	u8	num;
	u16	pi;
	u16	ci;
};
#endif

DECLARE_EVENT_CLASS(ubase_cmdq_template,
	TP_PROTO(const struct device *dev, int idx, u32 pi, u32 ci,
		 struct ubase_cmdq_desc *desc),
	TP_ARGS(dev, idx, pi, ci, desc),

	TP_STRUCT__entry(
		__field(int, idx)
		__field(u32, pi)
		__field(u32, ci)
		__array(u32, data, TRACE_CMDQ_DESC_SIZE)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->idx = idx;
		__entry->pi = pi;
		__entry->ci = ci;
		memcpy(&__entry->data, &desc[idx],
		       sizeof(u32) * TRACE_CMDQ_DESC_SIZE);
		if (dev) {
			snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				 "%s %s", dev_driver_string(dev), dev_name(dev));
		}
		ubase_mask_key_words((struct ubase_cmdq_desc *)&__entry->data,
				     desc[0].opcode, idx);
	),

	TP_printk(
		"%s %d-%u-%u data: %s", __get_str(devname),
		__entry->idx, __entry->pi, __entry->ci,
		__print_array(__entry->data, TRACE_CMDQ_DESC_SIZE, sizeof(u32))
	)
);

DEFINE_EVENT(ubase_cmdq_template, ubase_csq_tx,
	TP_PROTO(const struct device *dev, int idx, u32 pi, u32 ci,
		 struct ubase_cmdq_desc *desc),
	TP_ARGS(dev, idx, pi, ci, desc));

DEFINE_EVENT(ubase_cmdq_template, ubase_csq_rx,
	TP_PROTO(const struct device *dev, int idx, u32 pi, u32 ci,
		 struct ubase_cmdq_desc *desc),
	TP_ARGS(dev, idx, pi, ci, desc));

TRACE_EVENT(ubase_crq,
	TP_PROTO(const struct device *dev, int idx, u32 pi, u32 ci,
		 struct ubase_cmdq_desc *desc),
	TP_ARGS(dev, idx, pi, ci, desc),

	TP_STRUCT__entry(
		__field(int, idx)
		__field(u32, pi)
		__field(u32, ci)
		__array(u32, data, TRACE_CMDQ_DESC_SIZE)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->idx = idx;
		__entry->pi = pi;
		__entry->ci = ci;
		memcpy(&__entry->data, desc,
		       sizeof(u32) * TRACE_CMDQ_DESC_SIZE);
		if (dev) {
			snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				 "%s %s", dev_driver_string(dev), dev_name(dev));
		}
	),

	TP_printk(
		"%s %d-%u-%u data: %s", __get_str(devname),
		__entry->idx, __entry->pi, __entry->ci,
		__print_array(__entry->data, TRACE_CMDQ_DESC_SIZE, sizeof(u32))
	)
);

TRACE_EVENT(ubase_aeqe,
	TP_PROTO(struct device *dev, struct ubase_aeqe *aeqe,
		 struct ubase_eq *eq),
	TP_ARGS(dev, aeqe, eq),

	TP_STRUCT__entry(
		__field(u32, event_type)
		__field(u32, sub_type)
		__field(u32, owner)
		__field(u32, ci)
		__field(u32, queue_event_num)
		__field(u64, cmd_out_param)
		__field(u16, cmd_seq_num)
		__field(u8, cmd_status)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->event_type = aeqe->event_type;
		__entry->sub_type = aeqe->sub_type;
		__entry->owner = aeqe->owner;
		__entry->ci = eq->cons_index;
		__entry->queue_event_num = aeqe->event.queue_event.num;
		__entry->cmd_out_param = aeqe->event.cmd.out_param;
		__entry->cmd_seq_num = aeqe->event.cmd.seq_num;
		__entry->cmd_status = aeqe->event.cmd.status;
		if (dev) {
			snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				 "%s %s", dev_driver_string(dev), dev_name(dev));
		}
	),

	TP_printk(
		"%s %u-%u-%u-%u-%u-%llu-%u-%u", __get_str(devname),
		__entry->event_type, __entry->sub_type, __entry->owner,
		__entry->ci, __entry->queue_event_num, __entry->cmd_out_param,
		__entry->cmd_seq_num, __entry->cmd_status
	)
);

TRACE_EVENT(ubase_ceqe,
	TP_PROTO(struct device *dev, u32 jfcn, struct ubase_eq *eq),
	TP_ARGS(dev, jfcn, eq),

	TP_STRUCT__entry(
		__field(u32, jfcn)
		__field(u32, ci)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->jfcn = jfcn;
		__entry->ci = eq->cons_index;
		if (dev) {
			snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				 "%s %s", dev_driver_string(dev), dev_name(dev));
		}
	),

	TP_printk(
		"%s %u-%u", __get_str(devname), __entry->jfcn, __entry->ci
	)
);

DECLARE_EVENT_CLASS(ubase_ctrlq_template,
	TP_PROTO(const struct device *dev,
		 struct ubase_ctrlq_trace_info *trace_info,
		 const void *buf, u16 len),
	TP_ARGS(dev, trace_info, buf, len),

	TP_STRUCT__entry(
		__field(u16, bus_ue_id)
		__field(u16, bb_num)
		__field(u16, pi)
		__field(u16, ci)
		__dynamic_array(u8, data, len)
		__field(u16, len)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->bus_ue_id = trace_info->bus_ue_id;
		__entry->bb_num = trace_info->num;
		__entry->pi = trace_info->pi;
		__entry->ci = trace_info->ci;
		__entry->len = len;
		memcpy(__get_dynamic_array(data), buf, len);
		if (dev) {
			snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				 "%s %s", dev_driver_string(dev), dev_name(dev));
		}
	),

	TP_printk(
		"%s ue_id: %u %u-%u-%u data: %s", __get_str(devname),
		__entry->bus_ue_id, __entry->bb_num, __entry->pi, __entry->ci,
		__print_array(__get_dynamic_array(data), __entry->len, sizeof(__u8))
	)
);

DEFINE_EVENT(ubase_ctrlq_template, ubase_ctrlq_csq,
	TP_PROTO(const struct device *dev,
		 struct ubase_ctrlq_trace_info *trace_info,
		 const void *buf, u16 len),
	TP_ARGS(dev, trace_info, buf, len));

DEFINE_EVENT(ubase_ctrlq_template, ubase_ctrlq_crq,
	TP_PROTO(const struct device *dev,
		 struct ubase_ctrlq_trace_info *trace_info,
		 const void *buf, u16 len),
	TP_ARGS(dev, trace_info, buf, len));

DECLARE_EVENT_CLASS(ubase_ctrlq_ue_msg_template,
	TP_PROTO(const struct device *dev, u16 bus_ue_id, const void *buf, u16 len),
	TP_ARGS(dev, bus_ue_id, buf, len),

	TP_STRUCT__entry(
		__field(u16, bus_ue_id)
		__dynamic_array(u8, data, len)
		__field(u16, len)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->bus_ue_id = bus_ue_id;
		__entry->len = len;
		memcpy(__get_dynamic_array(data), buf, len);
		if (dev) {
			snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				 "%s %s", dev_driver_string(dev), dev_name(dev));
		}
	),

	TP_printk(
		"%s ue id: %u data: %s", __get_str(devname), __entry->bus_ue_id,
		__print_array(__get_dynamic_array(data), __entry->len, sizeof(__u8))
	)
);

DEFINE_EVENT(ubase_ctrlq_ue_msg_template, ubase_ue_req_callback,
	TP_PROTO(const struct device *dev, u16 bus_ue_id, const void *buf, u16 len),
	TP_ARGS(dev, bus_ue_id, buf, len));

DEFINE_EVENT(ubase_ctrlq_ue_msg_template, ubase_ue_resp_callback,
	TP_PROTO(const struct device *dev, u16 bus_ue_id, const void *buf, u16 len),
	TP_ARGS(dev, bus_ue_id, buf, len));

DEFINE_EVENT(ubase_ctrlq_ue_msg_template, ubase_send_mue2ue_resp,
	TP_PROTO(const struct device *dev, u16 bus_ue_id, const void *buf, u16 len),
	TP_ARGS(dev, bus_ue_id, buf, len));

DEFINE_EVENT(ubase_ctrlq_ue_msg_template, ubase_send_ue_req,
	TP_PROTO(const struct device *dev, u16 bus_ue_id, const void *buf, u16 len),
	TP_ARGS(dev, bus_ue_id, buf, len));
DEFINE_EVENT(ubase_ctrlq_ue_msg_template, ubase_parse_ue_msg,
	TP_PROTO(const struct device *dev, u16 bus_ue_id, const void *buf, u16 len),
	TP_ARGS(dev, bus_ue_id, buf, len));

DECLARE_EVENT_CLASS(ubase_free_mailbox_template,
	TP_PROTO(const struct device *dev, atomic_t *count, u16 seq_num),
	TP_ARGS(dev, count, seq_num),

	TP_STRUCT__entry(
		__field(int, count)
		__field(u16, seq_num)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->count = atomic_read(count);
		__entry->seq_num = seq_num;
		if (dev) {
			(void)snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				       "%s %s", dev_driver_string(dev),
				       dev_name(dev));
		}
	),

	TP_printk(
		"%s mailbox count: %d, seq_num: %d", __get_str(devname), __entry->count,
		__entry->seq_num
	)
);

DEFINE_EVENT(ubase_free_mailbox_template, ubase_free_mailbox_user,
	TP_PROTO(const struct device *dev, atomic_t *count, u16 seq_num),
	TP_ARGS(dev, count, seq_num));
DEFINE_EVENT(ubase_free_mailbox_template, ubase_free_mailbox_self,
	TP_PROTO(const struct device *dev, atomic_t *count, u16 seq_num),
	TP_ARGS(dev, count, seq_num));
DEFINE_EVENT(ubase_free_mailbox_template, ubase_alloc_mailbox_user,
	TP_PROTO(const struct device *dev, atomic_t *count, u16 seq_num),
	TP_ARGS(dev, count, seq_num));
DEFINE_EVENT(ubase_free_mailbox_template, ubase_add_mailbox_count,
	TP_PROTO(const struct device *dev, atomic_t *count, u16 seq_num),
	TP_ARGS(dev, count, seq_num));

TRACE_EVENT(ubase_misc_event_cause,
	TP_PROTO(struct device *dev, unsigned long event_cause),
	TP_ARGS(dev, event_cause),

	TP_STRUCT__entry(
		__field(unsigned long, event_cause)
		__dynamic_array(char, devname, TRACE_DEV_NAME_MAX_LEN)
	),

	TP_fast_assign(
		__entry->event_cause = event_cause;
		if (dev) {
			snprintf(__get_str(devname), TRACE_DEV_NAME_MAX_LEN,
				 "%s %s", dev_driver_string(dev), dev_name(dev));
		}
	),

	TP_printk("%s event_cause: 0x%lx", __get_str(devname), __entry->event_cause)
);

#endif /* __UBASE_TRACE_H__ */

/* This must be outside ifdef __UBASE_TRACE_H__ */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE ubase_trace
#include <trace/define_trace.h>
