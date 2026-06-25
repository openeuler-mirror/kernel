/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg bonding message dispatch header
 * Author: Wang Hang
 * Create: 2026-06-12
 * Note:
 * History: 2026-06-12: create file
 */

#ifndef UBAGG_MSG_H
#define UBAGG_MSG_H

#include <linux/types.h>
#include <ub/urma/ubcore_uapi.h>

#define UBAGG_BONDING_MSG_CUR_VERSION 0U

enum ubagg_comm_msg_type {
	UBAGG_COMM_MSG_SEG_INFO_REQ,
	UBAGG_COMM_MSG_SEG_INFO_RESP,
	UBAGG_COMM_MSG_JETTY_INFO_REQ,
	UBAGG_COMM_MSG_JETTY_INFO_RESP,
	UBAGG_COMM_MSG_FAILBACK_REQ,
	UBAGG_COMM_MSG_FAILBACK_RESP,
	UBAGG_COMM_MSG_MAX,
};

typedef void (*ubagg_msg_handler_t)(struct ubcore_device *dev,
				    struct ubcore_comm_msg *msg, void *conn);

struct ubagg_msg_desc {
	enum ubagg_comm_msg_type type;
	ubagg_msg_handler_t handler;
	uint16_t expected_len;
};

int ubagg_msg_init(void);
void ubagg_msg_uninit(void);

int ubagg_msg_register_handlers(const struct ubagg_msg_desc *msg_descs,
				uint32_t num_descs);
void ubagg_msg_unregister_handlers(const struct ubagg_msg_desc *msg_descs,
				   uint32_t num_descs);

#endif /* UBAGG_MSG_H */
