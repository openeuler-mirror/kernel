/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore tp table header
 * Author: Yan Fangfang
 * Create: 2023-02-09
 * Note:
 * History: 2023-02-09: Create file
 */

#ifndef UBCORE_TP_TABLE_H
#define UBCORE_TP_TABLE_H

#include "ubcore_hash_table.h"
#include "ubcore_netlink.h"

enum ubcore_tp_key_type { UBCORE_TP_KEY_JETTY_ID, UBCORE_TP_KEY_TPN };

struct ubcore_tp_key {
	enum ubcore_tp_key_type key_type;
	union {
		struct ubcore_jetty_id jetty_id; /* for initiator tp towards target jfr or jetty */
		uint32_t tpn; /* for target tp */
	};
} __packed;

struct ubcore_tp_node {
	struct ubcore_tp_key key;
	struct ubcore_tp *tp;
	struct ubcore_ta ta;
	struct hlist_node hnode;
	struct mutex lock;
	struct kref ref_cnt;
	struct completion comp;
};

void ubcore_init_tp_key_jetty_id(struct ubcore_tp_key *key,
	const struct ubcore_jetty_id *jetty_id);

/* Return old tp node if key already exists */
struct ubcore_tp_node *ubcore_add_tp_node(struct ubcore_hash_table *ht, uint32_t hash,
					  const struct ubcore_tp_key *key, struct ubcore_tp *tp,
					  struct ubcore_ta *ta);
void ubcore_remove_tp_node(struct ubcore_hash_table *ht, struct ubcore_tp_node *tp_node);
/* Find and remove the tp from table only if it is unreferenced */
void ubcore_find_remove_tp(struct ubcore_hash_table *ht, uint32_t hash,
					const struct ubcore_tp_key *key);

struct ubcore_tp_node *ubcore_lookup_tpnode(struct ubcore_hash_table *ht, uint32_t hash,
					  const struct ubcore_tp_key *key);
void ubcore_tpnode_kref_put(struct ubcore_tp_node *tp_node);

/* TP table ops for devices that do not natively support RM */
struct ubcore_hash_table *ubcore_create_tptable(void);
void ubcore_destroy_tptable(struct ubcore_hash_table **pp_ht);
struct ubcore_hash_table *ubcore_get_tptable(struct ubcore_hash_table *ht);
void ubcore_put_tptable(struct ubcore_hash_table *ht);
#endif
