/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore connect adapter header file
 * Author: Wang Hang
 * Create: 2025-06-19
 * Note:
 * History: 2025-06-19: create file
 */

#ifndef UBCORE_CONNECT_ADAPTER_H
#define UBCORE_CONNECT_ADAPTER_H

#include <ub/urma/ubcore_types.h>

struct ubcore_ex_tp_info {
	struct hlist_node hnode; /* key: tp_handle */
	uint64_t tp_handle;
	struct kref ref_cnt;
};

enum tp_status {
	UBCORE_TP_ENABLE,
	UBCORE_TP_ACTIVE,
	UBCORE_TP_DEACTIVE
};

struct ubcore_tpid_key {
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint64_t tag;
	uint32_t local_jetty_id;
	uint32_t peer_jetty_id;
};

/* Tpid will be added into UBCORE_HT_RC_TP_ID hash table
   after active_tp */
struct ubcore_tpid_ctx {
	struct hlist_node hnode;
	uint64_t tp_handle;
	uint64_t peer_tp_handle;
	struct kref ref;
	enum ubcore_transport_mode trans_mode;
	struct ubcore_tpid_key key;
	enum ubcore_tp_type tp_type;
	/* true: initiator tp_handle; false: target tp_handle */
	bool is_init;
	uint32_t tx_psn; /* optional */
	uint32_t rx_psn; /* optional */
	enum tp_status tp_state;
};

struct ubcore_ex_tpid_info {
	uint64_t tp_handle;
	uint64_t peer_tp_handle;
	uint32_t tx_psn;
	uint32_t rx_psn;
	uint32_t local_jetty_id;
	uint32_t peer_jetty_id;
};

extern uint32_t ubcore_conn_timeout;

struct ubcore_tjetty *ubcore_import_jfr_compat(struct ubcore_device *dev,
					       struct ubcore_tjetty_cfg *cfg,
					       struct ubcore_udata *udata);

struct ubcore_tjetty *ubcore_import_jetty_compat(struct ubcore_device *dev,
						 struct ubcore_tjetty_cfg *cfg,
						 struct ubcore_udata *udata);

int ubcore_bind_jetty_compat(struct ubcore_jetty *jetty,
			     struct ubcore_tjetty *tjetty,
			     struct ubcore_udata *udata);

int ubcore_adapter_layer_disconnect(struct ubcore_vtpn *vtpn);

int ubcore_adapter_layer_rm_stp_disconnect(struct ubcore_tjetty *tjetty);

void ubcore_exchange_init(void);

static inline bool ubcore_check_ctrlplane_compat(void *op_ptr)
{
	return (op_ptr == NULL);
}

void ubcore_tpid_get(void *obj);

struct ubcore_tpid_ctx *ubcore_fget_tpid_ctx(
	struct ubcore_device *dev, struct ubcore_tpid_key *key);

uint32_t ubcore_get_conn_timeout(void);

#endif
