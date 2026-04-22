/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore connection manager header
 * Author: Wang Hang
 * Create: 2025-02-18
 * Note:
 * History: 2025-02-18: create file
 */

#ifndef UBCORE_CM_H
#define UBCORE_CM_H

#include <ub/urma/ubcore_types.h>
#include "ubcore_protocol.h"
#include "ubcore_comm.h"

typedef int (*ubcore_cm_eid_ops)(struct ubcore_device *dev,
				 struct ubcore_eid_info *eid_info,
				 enum ubcore_mgmt_event_type event_type);
void ubcore_register_cm_eid_ops(ubcore_cm_eid_ops eid_ops);

enum ubcore_cm_msg_type {
	UBCORE_CM_CONN_REQ = 2, /* Consistent with UBMAD_UBC_CONN_REQ */
	UBCORE_CM_CONN_RESP = 3, /* Consistent with UBMAD_UBC_CONN_RESP */
	UBCORE_CM_SINGLE_REQ = 4, /* Consistent with UBMAD_UBC_SINGLE_REQ */
	UBCORE_CM_MSG_NUM
};

struct ubcore_cm_send_buf {
	union ubcore_eid src_eid; /* [Optional] Initiator eid */
	union ubcore_eid dst_eid; /* [Mandatory] Target eid */
	uint32_t msg_type; /* [Mandatory] Refer to enum ubcore_cm_msg_type */
	uint32_t payload_len; /* [Mandatory] */
	uint64_t session_id;
	uint8_t payload[0]; /* [Mandatory] */
};

/**
 * send by ubcm well-known jetty
 * @param[in] dev: the ubcore_device handle;
 * @param[in] send_buf: buffer to send, net message should be payload of send_buf;
 * @return: 0 - Succeed to send; -EAGAIN - Try again later; Other value - Failed to send
 */
typedef int (*ubcore_cm_send)(struct ubcore_device *dev,
			      struct ubcore_cm_send_buf *send_buf);
void ubcore_register_cm_send_ops(ubcore_cm_send cm_send);

struct ubcore_cm_recv_cr {
	struct ubcore_cr *cr;

	/* remote eid see cr->remote_id.eid */
	union ubcore_eid local_eid;

	uint32_t msg_type; /* Refer to enum ubcore_cm_msg_type */
	uint64_t payload;
	uint32_t payload_len;
};
int ubcore_cm_recv(struct ubcore_device *dev,
		   struct ubcore_cm_recv_cr *recv_cr);

int ubcore_call_cm_eid_ops(struct ubcore_device *dev,
			   struct ubcore_eid_info *eid_info,
			   enum ubcore_mgmt_event_type event_type);

int ubcore_ubcm_send(struct ubcore_device *dev, void *conn,
		     struct ubcore_net_msg *msg);
int ubcore_ubcm_send_to(struct ubcore_device *dev, union ubcore_eid addr,
			struct ubcore_net_msg *msg);

void ubcore_cm_register_endpoint(struct ubcore_comm_endpoint *ep,
				 struct ubcore_device *dev,
				 uint32_t eid_index);
void ubcore_cm_unregister_endpoint(struct ubcore_comm_endpoint *ep);

#endif /* UBCORE_CM_H */
