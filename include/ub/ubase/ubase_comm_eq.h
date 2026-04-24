/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_EQ_H_
#define _UB_UBASE_COMM_EQ_H_

#include <linux/auxiliary_bus.h>
#include <linux/notifier.h>

enum ubase_drv_type {
	UBASE_DRV_UNIC,
	UBASE_DRV_UDMA,
	UBASE_DRV_CDMA,
	UBASE_DRV_FWCTL,
	UBASE_DRV_PMU,
	UBASE_DRV_UVB,
	UBASE_DRV_UBASEPROXY,
	UBASE_DRV_MAX,
};

enum ubase_subevent_jetty_type {
	UBASE_SUBEVENT_TYPE_JFS_CHECK_ERROR = 0x01,
	UBASE_SUBEVENT_TYPE_JFR_CHECK_ERROR,
	UBASE_SUBEVENT_TYPE_JFC_CHECK_ERROR,
	UBASE_SUBEVENT_TYPE_JETTY_GROUP_CHECK_ERROR
};

enum ubase_subevent_tp_type {
	UBASE_SUBEVENT_TYPE_TP_RETRY_ERROR = 0x01,
	UBASE_SUBEVENT_TYPE_TP_UNEXPECTED_OPCODE,
	UBASE_SUBEVENT_TYPE_TP_PSN_MSN_MISMATCH,
	UBASE_SUBEVENT_TYPE_TP_PORT_DOWN
};

enum ubase_subevent_ue_type {
	UBASE_SUBEVENT_TYPE_ENTITY_LEVEL_ERROR = 0x00
};

enum ubase_event_type {
	UBASE_EVENT_TYPE_RESERVED		= 0x00,
	UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR	= 0x01,
	UBASE_EVENT_TYPE_TP_LEVEL_ERROR		= 0x02,
	UBASE_EVENT_TYPE_ENTITY_LEVEL_ERROR	= 0x03,
	UBASE_EVENT_TYPE_TP_FLUSH_DONE		= 0x10,
	UBASE_EVENT_TYPE_ENTITY_FLUSH_DONE	= 0x11,
	UBASE_EVENT_TYPE_JFR_LIMIT_REACHED	= 0x12,
	UBASE_EVENT_TYPE_MB			= 0x13,
	UBASE_EVENT_TYPE_CHECK_TOKEN		= 0x14,
	UBASE_EVENT_TYPE_MAX
};

/**
 * struct ubase_event_nb - ubase event notification block
 * @drv_type: auxiliary device driver type
 * @event_type: event type
 * @nb: notifier block
 * @back: arbitrary registered pointer
 */
struct ubase_event_nb {
	int			drv_type; /* see ubase_drv_type */
	u8			event_type;
	struct notifier_block	nb;
	void			*back;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_aeqe - asynchronous event interrupt queue elements
 * @event_type: event type
 * @sub_type: sub event type
 * @rsv0: reserved bits
 * @owner: owner bit
 * @num: jfsn/jettyn/jfrn/jfcn/jtgn/tpn
 * @rsv1: reserved bits
 * @rsv2: reserved bits
 * @out_param: mailbox output parameter
 * @seq_num: mailbox sequence number
 * @status: mailbox status
 * @event: aeqe event information
 * @rsv: reserved bits
 */
struct ubase_aeqe {
	u32			event_type : 8;
	u32			sub_type : 8;
	u32			rsv0 : 15;
	u32			owner : 1;

	union {
		struct {
			u32	num : 20;
			u32	rsv0 : 12;
			u32	rsv1;
			u32	rsv2;
		} queue_event;

#pragma pack(push, 1)
		struct {
			u64	out_param;
			u16	seq_num;
			u8	status;
			u8	rsv0;
		} cmd;
#pragma pack(pop)
	} event;
	u32			rsv[12];
};

/**
 * struct ubase_aeq_notify_info - aeq notification information
 * @event_type: event type
 * @sub_type: sub event type
 * @aeqe: aeq elements
 */
struct ubase_aeq_notify_info {
	u8			event_type;
	u8			sub_type;
	struct ubase_aeqe	*aeqe;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

int ubase_event_register(struct auxiliary_device *adev,
			 struct ubase_event_nb *cb);
void ubase_event_unregister(struct auxiliary_device *adev,
			    struct ubase_event_nb *cb);
int ubase_comp_register(struct auxiliary_device *adev,
			int (*comp_handler)(struct notifier_block *nb,
					    unsigned long jfcn, void *data));
void ubase_comp_unregister(struct auxiliary_device *adev);

#endif /* _UBASE_COMM_EQ_H_ */
