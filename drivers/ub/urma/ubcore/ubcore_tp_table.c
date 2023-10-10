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

void ubcore_init_tp_key_jetty_id(struct ubcore_tp_key *key, const struct ubcore_jetty_id *jetty_id)
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

/* Find and remove the tp from table only if it is unreferenced */
struct ubcore_tp *ubcore_find_remove_tp(struct ubcore_hash_table *ht, uint32_t hash,
					const struct ubcore_tp_key *key)
{
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp *tp = NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return NULL;
	}
	tp_node = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (tp_node == NULL) {
		spin_unlock(&ht->lock);
		return NULL;
	}

	if (atomic_dec_return(&tp_node->tp->use_cnt) == 0) {
		tp = tp_node->tp;
		hlist_del(&tp_node->hnode);
		kfree(tp_node);
	}
	spin_unlock(&ht->lock);
	return tp;
}

struct ubcore_hash_table *ubcore_create_tptable(void)
{
	struct ubcore_ht_param p = { .size = UBCORE_HASH_TABLE_SIZE,
				     .node_offset = offsetof(struct ubcore_tp_node, hnode),
				     .key_offset = offsetof(struct ubcore_tp_node, key),
				     .key_size = sizeof(struct ubcore_tp_key),
				     .cmp_f = NULL,
				     .free_f = NULL };
	struct ubcore_hash_table *ht;

	ht = kcalloc(1, sizeof(struct ubcore_hash_table), GFP_KERNEL);
	if (ht == NULL)
		return NULL;

	if (ubcore_hash_table_alloc(ht, &p) != 0) {
		kfree(ht);
		ubcore_log_err("Failed to calloc jfs tp hash table");
		return NULL;
	}
	return ht;
}

static void ubcore_free_tp_node(void *obj)
{
	struct ubcore_tp_node *tp_node = (struct ubcore_tp_node *)obj;
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

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		kfree(new_tp_node);
		return NULL;
	}
	tp_node = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (tp_node != NULL) {
		spin_unlock(&ht->lock);
		kfree(new_tp_node);
		return tp_node;
	}

	ubcore_hash_table_add_nolock(ht, &new_tp_node->hnode, hash);
	/* set private data for tp restore */
	tp->priv = new_tp_node;
	spin_unlock(&ht->lock);
	return new_tp_node;
}

struct ubcore_tp_node *ubcore_add_tp_with_tpn(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	struct ubcore_tp_node *tp_node;
	int ret;

	tp_node = kzalloc(sizeof(struct ubcore_tp_node), GFP_KERNEL);
	if (tp_node == NULL)
		return NULL;

	tp_node->key.key_type = UBCORE_TP_KEY_TPN;
	tp_node->key.tpn = tp->tpn;
	tp_node->tp = tp;
	mutex_init(&tp_node->lock);

	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_TP], &tp_node->hnode, tp->tpn);
	if (ret != 0) {
		ubcore_log_err("Failed to add tp with tpn %u to tp table", tp->tpn);
		kfree(tp_node);
		return NULL;
	}
	/* set private data to find tp node fast */
	tp->priv = tp_node;
	return tp_node;
}

struct ubcore_tp *ubcore_remove_tp_with_tpn(struct ubcore_device *dev, uint32_t tpn)
{
	struct ubcore_tp_key key;

	memset(&key, 0, sizeof(struct ubcore_tp_key));
	key.key_type = UBCORE_TP_KEY_TPN;
	key.tpn = tpn;
	return ubcore_find_remove_tp(&dev->ht[UBCORE_HT_TP], tpn, &key);
}
