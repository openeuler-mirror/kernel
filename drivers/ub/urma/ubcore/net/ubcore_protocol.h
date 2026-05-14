/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore protocol
 * Author: Wang Hang
 * Create: 2025-06-26
 *
 */

#ifndef NET_UBCORE_PROTOCOL_H
#define NET_UBCORE_PROTOCOL_H

#include <ub/urma/ubcore_uapi.h>

/* Compatible with uvs_msg_type_t */
enum ubcore_net_msg_type {
	UBCORE_NET_CREATE_REQ,
	UBCORE_NET_CREATE_RESP,
	UBCORE_NET_CREATE_ACK,
	UBCORE_NET_DESTROY_REQ,
	UBCORE_NET_DESTROY_RESP,
	UBCORE_NET_MSG_MAX,
};

#define MSG_HDR_SIZE offsetof(struct ubcore_comm_msg, data)

const char *__attribute_const__ msg_type_str(enum ubcore_net_msg_type type);

#define UNPACK(...) __VA_ARGS__
#define MSG_FMT "Msg[sid:%u %d.%s len:%u]"
#define MSG_ARG(m)                                                        \
	UNPACK(((m)->session_id), ((m)->type), (msg_type_str((m)->type)), \
	       ((m)->len))

/**
 * Register processing callbacks for specified message types
 * @param[in] type: Message type to handle
 * @param[in] handler: Callback function
 * @param[in] msg_len: Expected length (for validation), 0 means variable length
 */
int ubcore_net_register_msg_handler(enum ubcore_net_msg_type type,
				    ubcore_comm_msg_handler handler,
				    uint16_t msg_len);

/**
 * Distribute to registered handlers by message type
 */
void ubcore_net_handle_msg(struct ubcore_device *dev,
			   struct ubcore_comm_msg *msg, void *conn);

#endif /* NET_UBCORE_PROTOCOL_H */
