/* SPDX-License-Identifier: GPL-2.0 */
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
 * Description: define hash table ops
 * Author: Yan Fangfang
 * Create: 2022-08-03
 * Note:
 * History: 2022-08-03  Yan Fangfang  Add base code
 */

#ifndef UBCORE_HASH_TABLE_H
#define UBCORE_HASH_TABLE_H

#include <urma/ubcore_types.h>

static inline void *ubcore_ht_obj(const struct ubcore_hash_table *ht,
				  const struct hlist_node *hnode)
{
	return (char *)hnode - ht->p.node_offset;
}

static inline void *ubcore_ht_key(const struct ubcore_hash_table *ht,
				  const struct hlist_node *hnode)
{
	return ((char *)hnode - ht->p.node_offset) + ht->p.key_offset;
}
/* Init ht head, not calloc hash table itself */
int ubcore_hash_table_alloc(struct ubcore_hash_table *ht, const struct ubcore_ht_param *p);
/* Free ht head, not release hash table itself */
void ubcore_hash_table_free(struct ubcore_hash_table *ht);
void ubcore_hash_table_free_with_cb(struct ubcore_hash_table *ht, void (*free_cb)(void *));
void ubcore_hash_table_add(struct ubcore_hash_table *ht, struct hlist_node *hnode, uint32_t hash);
void ubcore_hash_table_add_nolock(struct ubcore_hash_table *ht, struct hlist_node *hnode,
	uint32_t hash);
void ubcore_hash_table_remove(struct ubcore_hash_table *ht, struct hlist_node *hnode);
int ubcore_hash_table_check_remove(struct ubcore_hash_table *ht, struct hlist_node *hnode);
void ubcore_hash_table_remove_nolock(struct ubcore_hash_table *ht, struct hlist_node *hnode);
void *ubcore_hash_table_lookup(struct ubcore_hash_table *ht, uint32_t hash, const void *key);
void *ubcore_hash_table_lookup_nolock(struct ubcore_hash_table *ht, uint32_t hash,
	const void *key);
void *ubcore_hash_table_lookup_get(struct ubcore_hash_table *ht, uint32_t hash, const void *key);
void *ubcore_hash_table_lookup_nolock_get(struct ubcore_hash_table *ht, uint32_t hash,
	const void *key);
void *ubcore_hash_table_find_remove(struct ubcore_hash_table *ht, uint32_t hash, const void *key);
/* Do not insert a new entry if an old entry with the same key exists */
int ubcore_hash_table_find_add(struct ubcore_hash_table *ht, struct hlist_node *hnode,
	uint32_t hash);
#endif
