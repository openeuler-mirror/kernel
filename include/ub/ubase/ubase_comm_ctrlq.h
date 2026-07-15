/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_CTRLQ_H_
#define _UB_UBASE_COMM_CTRLQ_H_

#include <linux/auxiliary_bus.h>
#include <linux/types.h>

#define UBASE_CTRLQ_MAX_DATA_SIZE	1000U

#define UBASE_CTRLQ_CSQ_BASEADDR_L_REG	0x18800
#define UBASE_CTRLQ_CSQ_BASEADDR_H_REG	0x18804
#define UBASE_CTRLQ_CSQ_DEPTH_REG	0x18808
#define UBASE_CTRLQ_CSQ_TAIL_REG	0x18810
#define UBASE_CTRLQ_CSQ_HEAD_REG	0x18814
#define UBASE_CTRLQ_CRQ_BASEADDR_L_REG	0x18818
#define UBASE_CTRLQ_CRQ_BASEADDR_H_REG	0x1881c
#define UBASE_CTRLQ_CRQ_DEPTH_REG	0x18820
#define UBASE_CTRLQ_CRQ_TAIL_REG	0x18824
#define UBASE_CTRLQ_CRQ_HEAD_REG	0x18828

#define UBASE_CTRLQ_HANDLE_UE_MSG	1

enum ubase_ctrlq_ser_ver {
	UBASE_CTRLQ_SER_VER_01 = 0x01,
};

enum ubase_ctrlq_ser_type {
	UBASE_CTRLQ_SER_TYPE_TP_ACL		= 0x01,
	UBASE_CTRLQ_SER_TYPE_DEV_REGISTER	= 0x02,
	UBASE_CTRLQ_SER_TYPE_IP_ACL		= 0x03,
	UBASE_CTRLQ_SER_TYPE_QOS		= 0x04,
	UBASE_CTRLQ_SER_TYPE_PORT		= 0x06,
};

enum ubase_ctrlq_opc_type_tp {
	UBASE_CTRLQ_OPC_CREATE_TP	= 0x11,
	UBASE_CTRLQ_OPC_DESTROY_TP	= 0x12,
	UBASE_CTRLQ_OPC_TP_FLUSH_DONE	= 0x14,
	UBASE_CTRLQ_OPC_CHECK_TP_ACTIVE	= 0x15,
	UBASE_CTRLQ_OPC_NOTIFY_BOND_IP	= 0x19,
	UBASE_CTRLQ_OPC_TPID_DEL_DONE	= 0x28,
};

enum ubase_ctrlq_opc_type_qos {
	UBASE_CTRLQ_OPC_QUERY_VL	= 0x01,
	UBASE_CTRLQ_OPC_QUERY_SL	= 0x02,
};

enum ubase_ctrlq_opc_type_ip {
	UBASE_CTRLQ_OPC_NOTIFY_IP	= 0x01,
	UBASE_CTRLQ_OPC_QUERY_IP	= 0x02,
};

enum ubase_ctrlq_opc_type_dev_register {
	UBASE_CTRLQ_OPC_UPDATE_SEID		= 0x02,
	UBASE_CTRLQ_OPC_UPDATE_UE_SEID_GUID	= 0x03,
	UBASE_CTRLQ_OPC_NOTIFY_RES_RATIO	= 0x13,
	UBASE_CTRLQ_OPC_CTRLQ_CTRL		= 0x14,
	UBASE_CTRLQ_OPC_UE_RESET_CTRL		= 0x15,
};

enum ubase_ctrlq_opc_type_port {
	UBASE_CTRLQ_OPC_BOND_PORT	= 0x01,
};

/**
 * struct ubase_ctrlq_msg - ubase ctrlq msg structure
 * @service_ver: ctrlq service version
 * @service_type: ctrlq service type
 * @opcode: ctrlq opcode
 * @need_resp: whether the message need a response
 * @is_resp: whether the message is a response
 * @is_async: whether the message is an asynchronous request
 * @resv: reserved bits
 * @resp_ret: the return value of response message
 * @resp_seq: response message sequence
 * @in_size: input data buffer size
 * @out_size: output data buffer size
 * @in: input data buffer
 * @out: output data buffer
 * @timeout: ctrlq msg timeout time, in ms
 */
struct ubase_ctrlq_msg {
	u32	service_ver; /* see ubase_ctrlq_ser_ver */
	u32	service_type; /* see ubase_ctrlq_ser_type */
	u8	opcode;
	u8	need_resp : 1;
	u8	is_resp   : 1;
	u8	is_async  : 1;
	u8	resv      : 5;
	u8	resp_ret; /* must set when the is_resp field is true. */
	u16	resp_seq; /* must set when the is_resp field is true. */
	u16	in_size;
	u16	out_size;
	void	*in;
	void	*out;
	u16	timeout; /* 0:use default timeout; otherwise, use the configured timeout*/

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_ctrlq_event_nb - ubase ctrlq event notification block structure
 * @service_type: ctrlq service type
 * @opcode: ctrlq crq opcode
 * @back: arbitrary registered pointer
 * @crq_handler: ctrlq crq handle function. adev: the struct member variable 'back',
 * service_ver: ctrlq service version, data: ctrlq crq msg data, len: ctrlq crq msg
 * length, seq: ctrlq crq msg sequence number.
 */
struct ubase_ctrlq_event_nb {
	u8	service_type;
	u8	opcode;
	void	*back;
	int	(*crq_handler)(struct auxiliary_device *adev, u8 service_ver,
			       void *data, u16 len, u16 seq);
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_ctrlq_ue_msg_nb - ubase ctrlq ue msg notification block structure
 * @service_type: ctrlq ue msg service type
 * @opcode: ctrlq ue msg opcode
 * @back: arbitrary registered pointer
 * @msg_handler: ctrlq ue msg handle function. adev: the struct member variable
 * 'back', data: ctrlq ue msg data, len: ctrlq ue msg data length.
 */
struct ubase_ctrlq_ue_msg_nb {
	u8	service_type;
	u8	opcode;
	void	*back;
	int	(*msg_handler)(struct auxiliary_device *adev, void *data, u16 len);

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_ctrlq_ue_msg_info - ubase ctrlq ue msg information structure
 * @service_ver: ctrlq ue msg service version
 * @bus_ue_id: bus ub entity id
 * @mbx_ue_id: mailbox ub entity id
 * @ret: result
 */
struct ubase_ctrlq_ue_msg_info {
	u8	service_ver;
	u8	mbx_ue_id;
	u16	bus_ue_id;
	int	ret;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

int ubase_ctrlq_send_msg(struct auxiliary_device *aux_dev,
			 struct ubase_ctrlq_msg *msg);
int ubase_ctrlq_register_crq_event(struct auxiliary_device *aux_dev,
				   struct ubase_ctrlq_event_nb *nb);
void ubase_ctrlq_unregister_crq_event(struct auxiliary_device *aux_dev,
				      u8 service_type, u8 opcode);
int ubase_ctrlq_register_ue_req_event(struct auxiliary_device *aux_dev,
				      struct ubase_ctrlq_ue_msg_nb *nb);
void ubase_ctrlq_unregister_ue_req_event(struct auxiliary_device *aux_dev,
					 u8 service_type, u8 opcode);
int ubase_ctrlq_register_ue_resp_event(struct auxiliary_device *aux_dev,
				       struct ubase_ctrlq_ue_msg_nb *nb);
void ubase_ctrlq_unregister_ue_resp_event(struct auxiliary_device *aux_dev,
					  u8 service_type, u8 opcode);
int ubase_ctrlq_send_mue2ue_resp(struct auxiliary_device *adev, void *data, u16 len,
				 u8 result);
int ubase_ctrlq_send_ue_req(struct auxiliary_device *adev, void *data, u16 len);
u16 ubase_ctrlq_ue_msg_header_len(void);
void ubase_ctrlq_parse_ue_msg(struct auxiliary_device *adev, void *data, u16 len,
			      struct ubase_ctrlq_ue_msg_info *info);
#endif /* _UB_UBASE_COMM_CTRLQ_H_ */
