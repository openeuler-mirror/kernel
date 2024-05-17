// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: implement hash table ops
 * Author: Yan Fangfang
 * Create: 2022-08-03
 * Note:
 * History: 2022-08-03  Yan Fangfang  Add base code
 */

#include <linux/slab.h>
#include "ubcore_log.h"
#include "ubcore_hash_table.h"

int ubcore_hash_table_alloc(struct ubcore_hash_table *ht, const struct ubcore_ht_param *p)
{
	uint32_t i;

	if (p == NULL || p->size == 0)
		return -1;
	ht->p = *p;
	ht->head = kcalloc(p->size, sizeof(struct hlist_head), GFP_KERNEL);
	if (ht->head == NULL)
		return -ENOMEM;

	for (i = 0; i < p->size; i++)
		INIT_HLIST_HEAD(&ht->head[i]);

	spin_lock_init(&ht->lock);
	kref_init(&ht->kref);
	return 0;
}

void ubcore_hash_table_free_with_cb(struct ubcore_hash_table *ht, void (*free_cb)(void *))
{
	struct hlist_node *pos = NULL, *next = NULL;
	struct hlist_head *head;
	uint32_t i;
	void *obj;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return;
	}
	for (i = 0; i < ht->p.size; i++) {
		hlist_for_each_safe(pos, next, &ht->head[i]) {
			obj = ubcore_ht_obj(ht, pos);
			hlist_del(pos);
			if (free_cb != NULL)
				free_cb(obj);
			else if (ht->p.free_f != NULL)
				ht->p.free_f(obj);
			else
				kfree(obj);
		}
	}
	head = ht->head;
	ht->head = NULL;
	spin_unlock(&ht->lock);
	if (head != NULL)
		kfree(head);
}

void ubcore_hash_table_free(struct ubcore_hash_table *ht)
{
	ubcore_hash_table_free_with_cb(ht, NULL);
}

void ubcore_hash_table_add_nolock(struct ubcore_hash_table *ht, struct hlist_node *hnode,
				  uint32_t hash)
{
	INIT_HLIST_NODE(hnode);
	hlist_add_head(hnode, &ht->head[hash % ht->p.size]);
}

void ubcore_hash_table_add(struct ubcore_hash_table *ht, struct hlist_node *hnode, uint32_t hash)
{
	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return;
	}
	ubcore_hash_table_add_nolock(ht, hnode, hash);
	spin_unlock(&ht->lock);
}

void ubcore_hash_table_remove_nolock(struct ubcore_hash_table *ht, struct hlist_node *hnode)
{
	if (ht->head == NULL)
		return;

	hlist_del(hnode);
}

void ubcore_hash_table_remove(struct ubcore_hash_table *ht, struct hlist_node *hnode)
{
	spin_lock(&ht->lock);
	ubcore_hash_table_remove_nolock(ht, hnode);
	spin_unlock(&ht->lock);
}

void *ubcore_hash_table_lookup_nolock_get(struct ubcore_hash_table *ht, uint32_t hash,
										const void *key)
{
	struct hlist_node *pos = NULL;
	void *obj = NULL;

	hlist_for_each(pos, &ht->head[hash % ht->p.size]) {
		obj = ubcore_ht_obj(ht, pos);
		if (ht->p.cmp_f != NULL && ht->p.cmp_f(obj, key) == 0) {
			break;
		} else if (ht->p.key_size > 0 &&
			   memcmp(ubcore_ht_key(ht, pos), key, ht->p.key_size) == 0) {
			break;
		}
		obj = NULL;
	}
	if (ht->p.get_f != NULL && obj != NULL)
		ht->p.get_f(obj);

	return obj;
}

void *ubcore_hash_table_lookup_get(struct ubcore_hash_table *ht, uint32_t hash, const void *key)
{
	void *obj = NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return NULL;
	}
	obj = ubcore_hash_table_lookup_nolock_get(ht, hash, key);

	spin_unlock(&ht->lock);
	return obj;
}


void *ubcore_hash_table_lookup_nolock(struct ubcore_hash_table *ht, uint32_t hash, const void *key)
{
	struct hlist_node *pos = NULL;
	void *obj = NULL;

	hlist_for_each(pos, &ht->head[hash % ht->p.size]) {
		obj = ubcore_ht_obj(ht, pos);
		if (ht->p.cmp_f != NULL && ht->p.cmp_f(obj, key) == 0) {
			break;
		} else if (ht->p.key_size > 0 &&
			   memcmp(ubcore_ht_key(ht, pos), key, ht->p.key_size) == 0) {
			break;
		}
		obj = NULL;
	}
	return obj;
}

void *ubcore_hash_table_lookup(struct ubcore_hash_table *ht, uint32_t hash, const void *key)
{
	void *obj = NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return NULL;
	}
	obj = ubcore_hash_table_lookup_nolock(ht, hash, key);
	spin_unlock(&ht->lock);
	return obj;
}

/* Do not insert a new entry if an old entry with the same key exists */
int ubcore_hash_table_find_add(struct ubcore_hash_table *ht, struct hlist_node *hnode,
			       uint32_t hash)
{
	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return -EINVAL;
	}
	/* Old entry with the same key exists */
	if (ubcore_hash_table_lookup_nolock(ht, hash, ubcore_ht_key(ht, hnode)) != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}
	ubcore_hash_table_add_nolock(ht, hnode, hash);
	spin_unlock(&ht->lock);
	return 0;
}

void *ubcore_hash_table_find_remove(struct ubcore_hash_table *ht, uint32_t hash, const void *key)
{
	struct hlist_node *pos = NULL, *next = NULL;
	void *obj = NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return NULL;
	}
	hlist_for_each_safe(pos, next, &ht->head[hash % ht->p.size]) {
		obj = ubcore_ht_obj(ht, pos);
		if (ht->p.cmp_f != NULL && ht->p.cmp_f(obj, key) == 0) {
			hlist_del(pos);
			break;
		} else if (ht->p.key_size > 0 &&
			   memcmp(ubcore_ht_key(ht, pos), key, ht->p.key_size) == 0) {
			hlist_del(pos);
			break;
		}
		obj = NULL;
	}
	spin_unlock(&ht->lock);
	return obj;
}
