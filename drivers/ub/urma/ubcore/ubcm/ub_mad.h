/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ub_mad header, only including Northbound API
 * Author: Chen Yutao
 * Create: 2025-01-10
 * Note:
 * History: 2025-01-10: Create file
 */

#ifndef UB_MAD_H
#define UB_MAD_H

#include "net/ubcore_cm.h"

/* agent */
#define UBMAD_SGE_MAX_LEN 2048 // cm data max len

enum ubmad_msg_type {
	UBMAD_CONN_DATA = 0,
	UBMAD_CONN_ACK,
	UBMAD_UBC_CONN_REQ = UBCORE_CM_CONN_REQ,
	UBMAD_UBC_CONN_RESP = UBCORE_CM_CONN_RESP,
	UBMAD_UBC_SINGLE_REQ = UBCORE_CM_SINGLE_REQ,
	UBMAD_AUTHN_DATA = 0x10,
	UBMAD_AUTHN_ACK,
	// cm send close request to all tjetty before remove kmod, one-way notification
	UBMAD_CLOSE_REQ = 0x20,
};

/* keep same with ubcore_cm_send_buf */
struct ubmad_send_buf {
	union ubcore_eid src_eid;
	union ubcore_eid dst_eid;

	enum ubmad_msg_type msg_type;
	uint32_t payload_len;
	uint64_t session_id;
	uint8_t payload[];
};

/* callbacks for cm in ubmad_jfce_handler */
struct ubmad_send_cr {
	struct ubcore_cr *cr;
};

/* keep same with ubcore_cm_recv_cr */
struct ubmad_recv_cr {
	struct ubcore_cr *cr;

	// remote eid see cr->remote_id.eid
	union ubcore_eid local_eid;

	enum ubmad_msg_type msg_type;
	uint64_t payload;
	uint32_t payload_len; // != cr->completion_len, latter including msg header size
};

struct ubmad_agent;
typedef int (*ubmad_send_handler)(struct ubmad_agent *agent,
	struct ubmad_send_cr *cr);
typedef int (*ubmad_recv_handler)(struct ubmad_agent *agent,
	struct ubmad_recv_cr *cr);
struct ubmad_agent {
	struct ubcore_device *device;
	ubmad_send_handler send_handler;
	ubmad_recv_handler recv_handler;
	void *usr_ctx;
};

int ubmad_init(void);
void ubmad_uninit(void);

struct ubmad_agent *ubmad_register_agent(struct ubcore_device *device,
	ubmad_send_handler send_handler,
	ubmad_recv_handler recv_handler,
	void *usr_ctx);
int ubmad_unregister_agent(struct ubmad_agent *agent);

int ubmad_post_send(struct ubcore_device *device,
	struct ubmad_send_buf *send_buf,
	struct ubmad_send_buf **bad_send_buf);
int ubmad_ubc_send(struct ubcore_device *device,
	struct ubcore_cm_send_buf *send_buf);

#endif /* UB_MAD_H */
