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

#include <ub/urma/ubcore_types.h>

/* Compatible with uvs_msg_type_t */
enum ubcore_net_msg_type {
	UBCORE_NET_CREATE_REQ,
	UBCORE_NET_CREATE_RESP,
	UBCORE_NET_CREATE_ACK,
	UBCORE_NET_DESTROY_REQ,
	UBCORE_NET_DESTROY_RESP,
	UBCORE_NET_BONDING_SEG_INFO_REQ,
	UBCORE_NET_BONDING_SEG_INFO_RESP,
	UBCORE_NET_BONDING_JETTY_INFO_REQ,
	UBCORE_NET_BONDING_JETTY_INFO_RESP,
	UBCORE_NET_BONDING_USER_MSG,
	UBCORE_NET_MSG_MAX,
};

/* Compatible with uvs_header_flag_t */
union ubcore_net_msg_flag {
	struct {
		uint16_t live_migrate : 1;
		uint16_t alpha : 1;
		uint16_t reserved : 14;
	} bs;
	uint16_t value;
};

/* Compatible with uvs_base_header_t */
struct ubcore_net_msg {
	uint8_t version;
	uint8_t type; // See enum ubcore_net_msg_type
	uint16_t len; // Total length of payload */
	uint32_t session_id; // Message sequence number, to index session
	uint16_t cap; // Capability, currently not used
	union ubcore_net_msg_flag flag; // Flag, for msg extension
	void *data;
};

#define MSG_HDR_SIZE offsetof(struct ubcore_net_msg, data)

const char *__attribute_const__ msg_type_str(enum ubcore_net_msg_type type);

#define UNPACK(...) __VA_ARGS__
#define MSG_FMT "Msg[sid:%u %d.%s len:%u]"
#define MSG_ARG(m)                                                        \
	UNPACK(((m)->session_id), ((m)->type), (msg_type_str((m)->type)), \
	       ((m)->len))

/**
 * Protocol message processing callback
 * @param[in] dev: Ubcore device.
 * @param[in] msg: Received message (guaranteed valid length)
 * @param[in] conn: Connector that received the message
 */
typedef void (*ubcore_net_msg_handler)(struct ubcore_device *dev,
				       struct ubcore_net_msg *msg, void *conn);

/**
 * Register processing callbacks for specified message types
 * @param[in] type: Message type to handle
 * @param[in] handler: Callback function
 * @param[in] msg_len: Expected length (for validation), 0 means variable length
 */
int ubcore_net_register_msg_handler(enum ubcore_net_msg_type type,
				    ubcore_net_msg_handler handler,
				    uint16_t msg_len);

/**
 * Distribute to registered handlers by message type
 */
void ubcore_net_handle_msg(struct ubcore_device *dev,
			   struct ubcore_net_msg *msg, void *conn);

#endif /* NET_UBCORE_PROTOCOL_H */
