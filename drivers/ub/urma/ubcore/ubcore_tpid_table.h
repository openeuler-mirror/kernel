/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore tpid reuse, tpid list, and tpid state table header
 * Author: Chen Zhengzhou
 * Create: 2026-06-04
 * Note:
 * History: 2026-06-04: Create file
 */

#ifndef UBCORE_TPID_TABLE_H
#define UBCORE_TPID_TABLE_H

#include <ub/urma/ubcore_types.h>

#define UBCORE_MAX_GET_TP_GROUP_CNT 32

enum ubcore_tpid_share_mode {
	UBCORE_TPID_SHARE_NONE = 0,      /* Not shared */
	UBCORE_TPID_SHARE_NODE,          /* Shared within node */
	UBCORE_TPID_SHARE_CONTAINER,     /* Shared within container */
	UBCORE_TPID_SHARE_JETTY,         /* Dedicated to one jetty */
	UBCORE_TPID_SHARE_CUSTOM,        /* User-defined sharing granularity */
};

enum ubcore_tpid_owner_type {
	UBCORE_TPID_OWNER_NONE = 0,
	UBCORE_TPID_OWNER_USER_AWARE,
	UBCORE_TPID_OWNER_USER_UNAWARE
};

enum ubcore_tpid_semantic {
	UBCORE_TPID_QUERY = 0,
	UBCORE_TPID_CREATE
};

enum ubcore_tpid_reuse_state {
	UBCORE_TPID_REUSE_RESET = 0,
	UBCORE_TPID_REUSE_READY,
	UBCORE_TPID_REUSE_ERROR
};

struct ubcore_tpid_list_node {
	struct list_head node;
	struct ubcore_tp_info tp_info;
};

struct ubcore_tpid_list_key {
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	enum ubcore_transport_mode trans_mode;
	enum ubcore_tpid_share_mode share_mode;
	uint32_t tp_type;                          // CTP/RTP/UTP
	uint32_t link_type;                        // UBOE or Not
};

struct ubcore_tpid_reuse_key {
	struct ubcore_tpid_list_key lk;
	uint64_t stag;
	uint64_t dtag;
};

struct ubcore_tpid_list {
	struct ubcore_device *ub_dev;
	struct hlist_node hnode;

	struct ubcore_tpid_list_key lk;

	struct list_head unaware_list;
	struct list_head aware_list;
	uint32_t acnt;
	uint32_t ucnt;
	uint32_t capacity;

	struct kref ref_cnt;
	struct completion comp;
	struct mutex lock;
	struct mutex fetch_lock;
};

struct ubcore_tpid_state {
	struct ubcore_device *ub_dev;

	struct hlist_node hnode;

	/* tp_id key start */
	uint64_t tp_id;
	/* tp_id key end */

	enum ubcore_tpid_status tpid_status;
	enum ubcore_tpid_owner_type tp_id_owner_type;
	bool alloced;
	uint32_t tx_psn;

	struct kref ref_cnt;
	struct completion comp;
	struct mutex lock;
};

struct ubcore_tpid_reuse {
	struct ubcore_device *ub_dev;

	struct hlist_node hnode;

	/* tp_state key start */
	struct ubcore_tpid_reuse_key rk;
	/* tp_state key end */

	/* value */
	union ubcore_tp_handle tp_handle;
	union ubcore_tp_handle peer_tp_handle;
	enum ubcore_tpid_reuse_state reuse_state;
	uint32_t tx_psn;

	bool is_ref;
	struct kref ref_cnt;
	atomic_t use_cnt;
	struct completion comp;
	struct mutex lock;
};

#endif
