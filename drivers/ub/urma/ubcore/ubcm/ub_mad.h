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

/* CM agent: jetty id 1,2 */
#define UBMAD_CM_JETTY_ID_0 1U
#define UBMAD_CM_JETTY_ID_1 2U
/* H2D agent: jetty 80, unreliable */
#define UBMAD_H2D_JETTY_ID_0 80U

enum ubmad_msg_type {
	UBMAD_CONN_DATA = 0,
	UBMAD_CONN_ACK,
	UBMAD_UBC_CONN_REQ = UBCORE_CM_CONN_REQ,
	UBMAD_UBC_CONN_RESP = UBCORE_CM_CONN_RESP,
	UBMAD_UBC_SINGLE_REQ = UBCORE_CM_SINGLE_REQ,
	UBMAD_GEN_DATA = 0x10,
	UBMAD_GEN_ACK,
	UBMAD_GEN_RESP,
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

struct ubmad_jetty_cfg {
	uint32_t jetty_id; /* well-known jetty id */
	uint32_t sge_size; /* size of each sge buffer in the seg */
	uint32_t send_sge_num; /* send sge num in the seg, also jfs depth */
	uint32_t recv_sge_num; /* recv sge num in the seg, also jfr depth */
	uint32_t write_sge_num; /* write sge num, reserved for write path */
	uint32_t max_write_len; /* max write length, reserved for write path */
	bool reliable; /* reliable communication (ack & retransmit) or not */
};

/* agent cfg, describes the jetty resources owned by the agent */
struct ubmad_agent_cfg {
	const struct ubmad_jetty_cfg *jetty_cfg;
	uint32_t jetty_num;
};

int ubmad_init(void);
void ubmad_uninit(void);

struct ubmad_agent *ubmad_register_agent(struct ubcore_device *device,
	const struct ubmad_agent_cfg *cfg,
	ubmad_send_handler send_handler,
	ubmad_recv_handler recv_handler,
	void *usr_ctx);
int ubmad_unregister_agent(struct ubmad_agent *agent);

int ubmad_post_send(struct ubmad_agent *agent, uint32_t jetty_id,
	struct ubmad_send_buf *send_buf,
	struct ubmad_send_buf **bad_send_buf);
int ubmad_ubc_send(struct ubcore_device *device,
	struct ubcore_cm_send_buf *send_buf);

uint32_t ubmad_get_jetty_id_by_msg_type(uint32_t msg_type);

#endif /* UB_MAD_H */
