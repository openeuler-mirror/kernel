/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __MSG_H__
#define __MSG_H__

#include "ubus.h"

extern bool msg_retry;

struct ub_link_header {
	u32 plen : 14;
	u32 rt : 2;
	u32 cfg : 4;
	u32 rsvd1 : 1;
	u32 vl : 4;
	u32 rsvd0 : 1;
	u32 crd_vl : 4;
	u32 ack : 1;
	u32 crd : 1;
};
#define UB_COMPACT_LINK_CFG 6

struct compact_network_header {
	/* DW0 */
	u32 dcna : 16;
	u32 scna : 16;
	/* DW1 */
#define NTH_NLP_WITH_TPH 0
#define NTH_NLP_WITHOUT_TPH 1
	u32 nth_nlp : 3;
	u32 mgmt : 1;
	u32 sl : 4;
	u32 lb : 8;
	u32 cc : 16;
};

/* message */
#define seid_high(eid) (((eid) >> 12) & 0xff)
#define seid_low(eid) ((eid) & 0xfff)
#define eid_gen(eid_h, eid_l) ((eid_h) << 12 | (eid_l))
#define msg_type(code) ((code) & 0x1)
#define msg_code(code) (((code) >> 1) & 0x7)
#define sub_msg_code(code) (((code) >> 4) & 0xf)
#define code_gen(msg, sub_msg, type) ((sub_msg) << 4 | ((msg) << 1 | (type)))
#define ubba_gen(ubba_h, ubba_l) ((u64)(ubba_h) << 32 | (ubba_l))

#define RETRY_COUNT 3
#define PLD_SIZE_MAX SZ_1K

enum ub_msg_type {
	MSG_REQ = 0,
	MSG_RSP = 1
};

enum ub_msg_code {
	UB_MSG_CODE_RAS = 0,
	UB_MSG_CODE_LINK = 1,
	UB_MSG_CODE_CFG = 2,
	UB_MSG_CODE_VDM = 3,
	UB_MSG_CODE_EXCH = 4,
	UB_MSG_CODE_SEC = 5,
	UB_MSG_CODE_POOL = 6,
	UB_MSG_CODE_MAX = 7
};

#define UB_MSG_CODE_NUM 8
#define UB_SUB_MSG_CODE_NUM 16

enum ub_sec_sub_msg_code {
	UB_TOKEN_CHECK_CFG = 2,
};

enum ub_exch_sub_msg_code {
	UB_OBTAIN_ENTITY_INFO = 2,
	UB_LINK_NEIGHBOR_QUERY = 7,
};

enum ub_pool_sub_msg_code {
	UB_BI_CREATE = 2,
	UB_BI_DESTROY = 3,
};

enum ub_vdm_sub_msg_code {
	UB_VENDOR_MSG = 0xf
};

enum ub_msg_rsp_status_code {
	UB_MSG_RSP_SUCCESS =		0x00,
	UB_MSG_RSP_CMD_EACCESS =	0x01,
	UB_MSG_RSP_CMD_ENODEV =		0x02,
	UB_MSG_RSP_CMD_CODE_ERR =	0x03,
	UB_MSG_RSP_CMD_LEN_ERR =	0x04,
	/* 0x05~0x1f reserved */
	UB_MSG_RSP_EXEC_ENOMEM =	0x20,
	UB_MSG_RSP_EXEC_EACCES =	0x21,
	UB_MSG_RSP_EXEC_EFAULT =	0x22,
	UB_MSG_RSP_EXEC_EBUSY =		0x23,
	UB_MSG_RSP_EXEC_EEXIST =	0x24,
	UB_MSG_RSP_EXEC_ENODEV =	0x25,
	UB_MSG_RSP_EXEC_EINVAL =	0x26,
	UB_MSG_RSP_EXEC_ENOEXEC =	0x27,
	/* 0x28~0xfe reserved */
	UB_MSG_RSP_UNKNOWN =		0xff
};

u8 err_to_msg_rsp(int err);

struct msg_extended_header {
	u32 plen : 12;
	u32 rsvd : 4;
	u32 rsp_status : 8;
	union {
		struct {
			u8 type : 1;
			u8 msg_code : 3;
			u8 sub_msg_code : 4;
		};
		u8 code;
	};
};

struct msg_pkt_header {
	/* DW0 */
	struct ub_link_header ulh;
	/* DW1-DW2 */
	struct compact_network_header nth;
	/* DW3 */
	u32 seid_h : 8;
	u32 upi : 16;
#define CTPH_NLP_UPI_40BITS_UEID 2
	u32 ctph_nlp : 4; /* tp header */
	u32 pad : 2;
#define CTPH_OPCODE_NOT_CNP 0
	u32 tp_opcode : 2;
	/* DW4 */
	u32 deid : 20;
	u32 seid_l : 12;
	/* DW5 */
	u32 src_tassn : 16;
	u32 taver : 3;
	u32 tk_vld : 1;
	u32 udf : 4;
#define TAH_OPCODE_MSG 0x10
	u32 ta_opcode : 8;
	/* DW6 */
	u32 msgq_id : 8;
	u32 rsvd0 : 24;
	/* DW7 */
	struct msg_extended_header msgetah;

	/* DW8~DW11 */
	char payload[];
};
#define MSG_PKT_HEADER_SIZE 32

#define MSG_CFG_PKT_SIZE 48 /* header 32bytes, pld 16bytes */

/**
 * struct msg_info - Collection of per message
 *
 * @ubc: This cfg request source ub bus controller
 * @uent: This cfg request target ub_entity
 * @req_packet: Request Message packet buffer
 * @req_pkt_size: Size of the request packet
 * @rsp_packet: Response Message packet buffer
 * @rsp_pkt_size: Size of the rsponse packet
 * @actual_rsp_size: Size of the actual rsponse packet
 *
 * vendor can define and parse structure in @req_packet and @rsp_packet
 */
struct msg_info {
	struct ub_entity *ubc;
	struct ub_entity *uent;
	void *req_packet;
	u16 req_pkt_size;
	void *rsp_packet;
	u16 rsp_pkt_size;
	u16 actual_rsp_size;
};
#define MSG_REQ_SIZE_OFFSET 16

enum message_tx_type {
	MESSAGE_TX_TYPE_MSG,
	MESSAGE_TX_TYPE_ENUM
};

#define msg_size_gen(req_size, rsp_size) ((u32)((req_size) << 16) | (rsp_size))

typedef void (*rx_msg_handler_t)(struct ub_bus_controller *ubc, void *pkt, u16 len);

/**
 * struct message_ops - message ops and capabilities
 * @sync_request: send message to target ub_entity and wait response
 * @send: send message to target ub_entity but not wait response
 * @response: send response message to target
 * @sync_enum: send enum message to target ub_entity and wait response
 * @vdm_rx_handler: send vdm response message to target
 * @owner: Driver module providing these ops
 */
struct message_ops {
	int (*sync_request)(struct message_device *mdev, struct msg_info *info,
			    u8 code);
	int (*response)(struct message_device *mdev, struct msg_info *info,
			u8 code);
	int (*sync_enum)(struct message_device *mdev, struct msg_info *info,
			 u8 cmd);
	int (*send)(struct message_device *mdev, struct msg_info *info,
		    u8 code);
	rx_msg_handler_t vdm_rx_handler;
	struct module *owner;
};

/**
 * struct message_device - Message core representation of one message-dev
 *                         hardware instance
 * @list:   Used by the message-core to keep a list of registered message-devs
 * @ops:    Message-ops for talking to this message-dev
 * @fwnode: Firmware representation of one message-dev
 */
struct message_device {
	struct list_head list;
	const struct message_ops *ops;
	struct fwnode_handle *fwnode;
};

/**
 * struct dev_message - Collection of per-device Message-dev data
 *
 * @mdev:   Message device this device is linked to
 * @priv:   Message Driver private data
 */
struct dev_message {
	struct message_device *mdev;
	void *priv;
};

static inline void message_info_init(struct msg_info *info, struct ub_entity *uent,
				     void *req, void *rsp, u32 size)
{
	if (uent) {
		info->ubc = uent->ubc->uent;
		info->uent = uent;
	}
	info->req_packet = req;
	info->rsp_packet = rsp;
	/* High 16bits for req size, low 16bits for rsp size */
	info->req_pkt_size = (u16)(size >> MSG_REQ_SIZE_OFFSET);
	info->rsp_pkt_size = (u16)size;
}

static inline void __message_device_set_ops(struct message_device *mdev,
					    const struct message_ops *ops)
{
	mdev->ops = ops;
}

#define message_device_set_ops(mdev, ops)                               \
do {                                                                    \
	struct message_ops *__ops = (struct message_ops *)(ops);        \
	__ops->owner = THIS_MODULE;                                     \
	__message_device_set_ops(mdev, __ops);                          \
} while (0)

static inline void message_device_set_fwnode(struct message_device *mdev,
					     struct fwnode_handle *fwnode)
{
	mdev->fwnode = fwnode;
}

void ub_msg_pkt_header_init(struct msg_pkt_header *header, struct ub_entity *uent,
			    u16 plen, u8 code, bool flag);

int message_device_register(struct message_device *mdev);
void message_device_unregister(struct message_device *mdev);
int message_probe_device(struct ub_entity *uent);
void message_remove_device(struct ub_entity *uent);
int message_sync_request(struct message_device *mdev, struct msg_info *info,
			 u8 code);
int message_send(struct message_device *mdev, struct msg_info *info,
		 u8 code);
int message_response(struct message_device *mdev, struct msg_info *info,
		     u8 code);
int message_sync_enum(struct message_device *mdev, struct msg_info *info,
		      u8 cmd);

struct ub_rx_msg_task {
	struct ub_bus_controller *ubc;
	void *pkt;
	u16 len;
	struct work_struct work;
};

struct workqueue_struct *get_rx_msg_wq(u8 msg_code);
int message_rx_handler(struct ub_bus_controller *ubc, void *pkt, u16 len);
int message_rx_init(void);
void message_rx_uninit(void);

#endif /* __MSG_H__ */
