/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore comm (communication) module - endpoint abstraction
 * Author: Wang Hang
 * Create: 2025-06-26
 *
 */

#ifndef NET_UBCORE_COMM_H
#define NET_UBCORE_COMM_H

#include <ub/urma/ubcore_types.h>
#include "ubcore_protocol.h"

#define UBCORE_COMM_MSG_CUR_VERSION 0U

enum ubcore_comm_type {
	UBCORE_COMM_UBCM_WK_JETTY,
	UBCORE_COMM_SOCK,
};

struct ubcore_comm_endpoint;

/**
 * Message reception callback: Invoked when the endpoint receives a message
 * @ep: endpoint handle
 * @dev: ubcore dev
 * @msg: message
 * @conn: The connection handle is represented as sk_entry* or ubcore_eid*
 */
typedef void (*ubcore_comm_recv_cb)(struct ubcore_comm_endpoint *ep,
				   struct ubcore_device *dev,
				   struct ubcore_comm_msg *msg, void *conn);

/**
 * Endpoint operation set: Implemented and bound by specific transport (sock/ubcm)
 */
struct ubcore_comm_ops {
	/**
	 * Create an endpoint
	 * @ep: endpoint
	 * @cfg: Type related configuration, sock is (port, addr), ubcm is (dev, jety_id), etc
	 * @return: 0 successful, negative value failed
	 */
	int (*create)(struct ubcore_comm_endpoint *ep, void *cfg);

	void (*destroy)(struct ubcore_comm_endpoint *ep);

	/**
	 * reply message
	 * @ep: dst endpoint
	 * @dev: ubcore dev
	 * @conn: connect handle
	 * @msg: message
	 */
	int (*send)(struct ubcore_comm_endpoint *ep,
		    struct ubcore_device *dev,
		    void *conn, struct ubcore_comm_msg *msg);

	/**
	 * Send to the specified address
	 */
	int (*send_to)(struct ubcore_comm_endpoint *ep,
		       struct ubcore_device *dev,
		       union ubcore_eid addr,
		       struct ubcore_comm_msg *msg);
};

struct ubcore_comm_ubcm_cfg {
	struct ubcore_device *dev;
	uint32_t eid_index;
};

union ubcore_comm_cfg {
	struct ubcore_comm_ubcm_cfg ubcm;
};

struct ubcore_comm_endpoint {
	enum ubcore_comm_type type;
	const struct ubcore_comm_ops *ops;
	ubcore_comm_recv_cb recv_cb;
	void *priv;
	struct list_head list;
};

struct ubcore_comm_endpoint *ubcore_comm_create_endpoint(enum ubcore_comm_type type,
	union ubcore_comm_cfg *cfg, ubcore_comm_recv_cb recv_cb);

void ubcore_comm_destroy_endpoint(struct ubcore_comm_endpoint *ep);

int ubcore_comm_send(struct ubcore_comm_endpoint *ep,
		     struct ubcore_device *dev,
		     void *conn, struct ubcore_comm_msg *msg);

int ubcore_comm_send_to(struct ubcore_comm_endpoint *ep,
			struct ubcore_device *dev,
			union ubcore_eid addr,
			struct ubcore_comm_msg *msg);

struct ubcore_comm_endpoint *ubcore_comm_get_default_endpoint(void);

void ubcore_comm_set_default_endpoint(struct ubcore_comm_endpoint *ep);

struct ubcore_comm_endpoint *
ubcore_comm_create_default(enum ubcore_comm_type type,
			   union ubcore_comm_cfg *cfg);

extern uint32_t g_ubcore_connect_type;

void ubcore_comm_uninit(void);

#endif /* NET_UBCORE_COMM_H */
