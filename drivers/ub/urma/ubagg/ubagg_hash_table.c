// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: implement hash table ops
 * Author: Yan Fangfang
 * Create: 2022-08-03
 * Note:
 * History: 2022-08-03  Yan Fangfang  Add base code
 */

#include <linux/slab.h>
#include "ubagg_hash_table.h"

int ubagg_hash_table_alloc(struct ubagg_hash_table *ht,
			   struct ubagg_ht_param *p)
{
	uint32_t i;

	if (!p || p->size == 0)
		return -EINVAL;

	ht->head = kcalloc(p->size, sizeof(struct hlist_head), GFP_KERNEL);
	if (!ht->head)
		return -ENOMEM;

	ht->p = *p;
	for (i = 0; i < p->size; i++)
		INIT_HLIST_HEAD(&ht->head[i]);

	spin_lock_init(&ht->lock);
	kref_init(&ht->kref);
	return 0;
}

void ubagg_hash_table_free(struct ubagg_hash_table *ht)
{
	struct hlist_node *pos = NULL, *next = NULL;
	struct hlist_head *head;
	uint32_t i;
	void *obj;

	if (ht == NULL || ht->head == NULL)
		return;

	spin_lock(&ht->lock);
	if (!ht->head) {
		spin_unlock(&ht->lock);
		return;
	}
	for (i = 0; i < ht->p.size; i++) {
		hlist_for_each_safe(pos, next, &ht->head[i]) {
			obj = ubagg_ht_obj(ht, pos);
			hlist_del(pos);
			spin_unlock(&ht->lock);
			kfree(obj);
			spin_lock(&ht->lock);
		}
	}
	head = ht->head;
	ht->head = NULL;
	spin_unlock(&ht->lock);
	kfree(head);
}

void ubagg_hash_table_add_nolock(struct ubagg_hash_table *ht,
				 struct hlist_node *hnode, uint32_t hash)
{
	INIT_HLIST_NODE(hnode);
	hlist_add_head(hnode, &ht->head[hash % ht->p.size]);
}

void ubagg_hash_table_remove_nolock(struct ubagg_hash_table *ht,
				    struct hlist_node *hnode)
{
	if (!ht->head)
		return;

	hlist_del_init(hnode);
}

void ubagg_hash_table_remove(struct ubagg_hash_table *ht,
			     struct hlist_node *hnode)
{
	spin_lock(&ht->lock);
	ubagg_hash_table_remove_nolock(ht, hnode);
	spin_unlock(&ht->lock);
}

void *ubagg_hash_table_lookup_nolock(struct ubagg_hash_table *ht, uint32_t hash,
				     const void *key)
{
	struct hlist_node *pos = NULL;
	void *obj = NULL;

	hlist_for_each(pos, &ht->head[hash % ht->p.size]) {
		obj = ubagg_ht_obj(ht, pos);
		if (ht->p.key_size > 0 &&
		    memcmp(ubagg_ht_key(ht, pos), key, ht->p.key_size) == 0) {
			break;
		}
		obj = NULL;
	}
	return obj;
}
