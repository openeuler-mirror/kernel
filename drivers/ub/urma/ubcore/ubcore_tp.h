/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore tp header
 * Author: Yan Fangfang
 * Create: 2022-09-08
 * Note:
 * History: 2022-09-208: Create file
 */

#ifndef UBCORE_TP_H
#define UBCORE_TP_H

#include <ub/urma/ubcore_types.h>
#include "ubcore_tpid_table.h"

#define UBCORE_TP_ID_FETCH_NUM 1
#define UBCORE_TP_ID_BATCH_NUM 1
#define UBCORE_TP_ID_LIST_SIZE (64<<10)

struct ubcore_rm_tp_key {
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint64_t stag;
	uint64_t dtag;
};

struct ubcore_rm_tp_info {
	struct hlist_node hnode;
	uint64_t tp_handle;
	struct ubcore_rm_tp_key key;
	int ref_cnt;
	bool is_refed;
	atomic_t tp_state;
	uint32_t tx_psn;
	struct mutex lock;
};

enum {
	RM_STP_UNCREATED = 0,
	RM_STP_CREATED,
	RM_STP_ACTIVE,
	RM_STP_ERROR
};

struct ubcore_deactive_tp_cfg {
	union ubcore_tp_handle tp_handle;
	struct ubcore_udata *udata;
};

struct ubcore_flushdone_tp_cfg {
	uint32_t tpid;
};

union ubcore_modify_tpid_cfg {
	struct ubcore_active_tp_cfg *active_cfg;
	struct ubcore_deactive_tp_cfg *deactive_cfg;
	struct ubcore_flushdone_tp_cfg *flushdone_cfg;
};

struct ubcore_tp_id_list_param {
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	enum ubcore_transport_type transport_type;
};

struct ubcore_tpid_reuse_param {
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint64_t stag;
	uint64_t dtag;
};

static inline bool ubcore_have_ops(struct ubcore_device *dev)
{
	return (dev && dev->ops);
}

static inline bool ubcore_have_tp_ops(struct ubcore_device *dev)
{
	return (dev && dev->ops &&
		dev->ops->create_tp && dev->ops->modify_tp);
}

static inline bool ubcore_have_tp_ctrlplane_ops(struct ubcore_device *dev)
{
	return (dev && dev->ops &&
		dev->ops->get_tp_list && dev->ops->active_tp);
}

void ubcore_tpid_list_get(void *obj);
void ubcore_tpid_list_kref_put(struct ubcore_tpid_list *tpid_list);
struct ubcore_tpid_list *ubcore_ht_find_get_tpid_list(struct ubcore_device *dev,
	struct ubcore_tpid_list_key *key);

void ubcore_tpid_state_get(void *obj);
void ubcore_tpid_state_kref_put(struct ubcore_tpid_state *tp_state_entry);
struct ubcore_tpid_state *ubcore_find_get_tp_id_state_entry(struct ubcore_device *dev,
	uint64_t tp_id);
int ubcore_find_add_tp_id_state_entry(struct ubcore_device *dev,
	struct ubcore_tpid_state *new_tp_state_entry);
void ubcore_remove_tp_id_state_entry(struct ubcore_device *dev,
	struct ubcore_tpid_state *tp_state_entry);

int ubcore_create_tpid_priv(struct ubcore_device *dev, struct ubcore_tpid_cfg *cfg,
	struct ubcore_udata *udata, union ubcore_tp_handle *tp_handle);
int ubcore_delete_tpid_priv(struct ubcore_device *dev, uint32_t tpid);
int ubcore_modify_tpid(struct ubcore_device *dev, enum ubcore_tpid_status state,
	union ubcore_modify_tpid_cfg *cfg);
int ubcore_active_tp(struct ubcore_device *dev, struct ubcore_active_tp_cfg *active_cfg);
int ubcore_deactive_tp(struct ubcore_device *dev, union ubcore_tp_handle tp_handle,
	struct ubcore_udata *udata);
#endif
