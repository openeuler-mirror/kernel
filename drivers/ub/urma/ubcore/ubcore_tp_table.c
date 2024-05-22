// SPDX-License-Identifier: GPL-2.0
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
 * Description: ubcore tp table implementation
 * Author: Yan Fangfang
 * Create: 2023-02-09
 * Note:
 * History: 2023-02-09: Create file
 */

#include <linux/slab.h>
#include "ubcore_log.h"
#include "ubcore_priv.h"
#include "ubcore_tp.h"
#include "ubcore_tp_table.h"

void ubcore_init_tp_key_jetty_id(struct ubcore_tp_key *key,
	const struct ubcore_jetty_id *jetty_id)
{
	memset(key, 0, sizeof(struct ubcore_tp_key));
	key->key_type = UBCORE_TP_KEY_JETTY_ID;
	key->jetty_id = *jetty_id;
}

void ubcore_remove_tp_node(struct ubcore_hash_table *ht, struct ubcore_tp_node *tp_node)
{
	if (tp_node == NULL)
		return;

	ubcore_hash_table_remove(ht, &tp_node->hnode);
	kfree(tp_node);
}


static void ubcore_tpnode_kref_release(struct kref *ref_cnt)
{
	struct ubcore_tp_node *tp_node = container_of(ref_cnt, struct ubcore_tp_node, ref_cnt);

	complete(&tp_node->comp);
}

void ubcore_tpnode_kref_put(struct ubcore_tp_node *tp_node)
{
	if (tp_node == NULL)
		return;

	(void)kref_put(&tp_node->ref_cnt, ubcore_tpnode_kref_release);
}

/* Find and remove the tp from table only if it is unreferenced */
void ubcore_find_remove_tp(struct ubcore_hash_table *ht, uint32_t hash,
					const struct ubcore_tp_key *key)
{
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp *tp = NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return;
	}
	tp_node = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (tp_node == NULL) {
		spin_unlock(&ht->lock);
		return;
	}
	hlist_del_init(&tp_node->hnode);
	spin_unlock(&ht->lock);

	ubcore_tpnode_kref_put(tp_node);
	wait_for_completion(&tp_node->comp);

	tp = tp_node->tp;
	mutex_destroy(&tp_node->lock);
	kfree(tp_node);
	(void)ubcore_destroy_tp(tp);
}

struct ubcore_hash_table *ubcore_create_tptable(void)
{
	struct ubcore_ht_param p = {
		.size = UBCORE_HASH_TABLE_SIZE,
		.node_offset = offsetof(struct ubcore_tp_node, hnode),
		.key_offset = offsetof(struct ubcore_tp_node, key),
		.key_size = (uint32_t)sizeof(struct ubcore_tp_key),
		.cmp_f = NULL,
		.free_f = NULL
	};
	struct ubcore_hash_table *htable;

	htable = kcalloc(1, sizeof(struct ubcore_hash_table), GFP_KERNEL);
	if (htable == NULL)
		return NULL;

	if (ubcore_hash_table_alloc(htable, &p) != 0) {
		kfree(htable);
		ubcore_log_err("Failed to calloc jfs tp hash table");
		return NULL;
	}
	return htable;
}

static void ubcore_free_tp_node(void *obj)
{
	struct ubcore_tp_node *tp_node = (struct ubcore_tp_node *)obj;

	ubcore_tpnode_kref_put(tp_node);
	wait_for_completion(&tp_node->comp);

	(void)ubcore_destroy_tp(tp_node->tp);
	kfree(tp_node);
}

static void ubcore_tptable_release(struct kref *kref)
{
	struct ubcore_hash_table *ht = container_of(kref, struct ubcore_hash_table, kref);

	kfree(ht);
}

void ubcore_destroy_tptable(struct ubcore_hash_table **pp_ht)
{
	struct ubcore_hash_table *ht;

	if (pp_ht == NULL || *pp_ht == NULL)
		return;

	ht = *pp_ht;
	*pp_ht = NULL;
	ubcore_hash_table_free_with_cb(ht, ubcore_free_tp_node);
	/* pair with kref_init */
	(void)kref_put(&ht->kref, ubcore_tptable_release);
}

struct ubcore_hash_table *ubcore_get_tptable(struct ubcore_hash_table *ht)
{
	if (ht == NULL)
		return NULL;

	kref_get(&ht->kref);
	return ht;
}

void ubcore_put_tptable(struct ubcore_hash_table *ht)
{
	if (ht == NULL)
		return;

	(void)kref_put(&ht->kref, ubcore_tptable_release);
}

struct ubcore_tp_node *ubcore_add_tp_node(struct ubcore_hash_table *ht, uint32_t hash,
					  const struct ubcore_tp_key *key, struct ubcore_tp *tp,
					  struct ubcore_ta *ta)
{
	struct ubcore_tp_node *new_tp_node;
	struct ubcore_tp_node *tp_node;

	new_tp_node = kzalloc(sizeof(struct ubcore_tp_node), GFP_KERNEL);
	if (new_tp_node == NULL)
		return NULL;

	new_tp_node->key = *key;
	new_tp_node->tp = tp;
	new_tp_node->ta = *ta;
	mutex_init(&new_tp_node->lock);
	kref_init(&new_tp_node->ref_cnt);
	init_completion(&new_tp_node->comp);

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		mutex_destroy(&new_tp_node->lock);
		kfree(new_tp_node);
		return NULL;
	}
	tp_node = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (tp_node != NULL) {
		kref_get(&tp_node->ref_cnt);
		spin_unlock(&ht->lock);
		mutex_destroy(&new_tp_node->lock);
		kfree(new_tp_node);
		return tp_node;
	}

	ubcore_hash_table_add_nolock(ht, &new_tp_node->hnode, hash);
	/* set private data for tp restore */
	tp->priv = new_tp_node;
	kref_get(&new_tp_node->ref_cnt);
	spin_unlock(&ht->lock);
	return new_tp_node;
}

struct ubcore_tp_node *ubcore_lookup_tpnode(struct ubcore_hash_table *ht, uint32_t hash,
	const struct ubcore_tp_key *key)
{
	struct ubcore_tp_node *tp_node = NULL;

	spin_lock(&ht->lock);
	tp_node = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (tp_node != NULL)
		kref_get(&tp_node->ref_cnt);
	spin_unlock(&ht->lock);
	return tp_node;
}
