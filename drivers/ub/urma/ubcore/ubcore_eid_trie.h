/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore EID trie
 */

#ifndef UBCORE_EID_TRIE_H
#define UBCORE_EID_TRIE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <ub/urma/ubcore_types.h>

/* Node structure for the Patricia Trie */
struct ubcore_eid_trie_node {
	struct rcu_head rcu;
	struct ubcore_eid_trie_node __rcu *child[2]; /* Left (0) and Right (1) */
	union ubcore_eid prefix;		/* The prefix stored at this node */
	union ubcore_eid value;			/* The mapped value (valid if is_leaf) */
	u8 prefix_len;				/* Length of the prefix (0-128) */
	bool is_leaf;				/* True if this node holds an actual key-value */
};

struct ubcore_eid_trie {
	struct ubcore_eid_trie_node __rcu *root;
	struct mutex lock;			/* Serializes writers */
};

#define EID_NODE_SZ (sizeof(struct ubcore_eid_trie_node))

/* --- Trie Operations --- */

int ubcore_eid_trie_lookup(struct ubcore_eid_trie *trie,
			   const union ubcore_eid *key,
			   union ubcore_eid *value_out);

int ubcore_eid_trie_insert(struct ubcore_eid_trie *trie,
			   const union ubcore_eid *key,
			   const union ubcore_eid *value);

int ubcore_eid_trie_delete(struct ubcore_eid_trie *trie,
			   const union ubcore_eid *key);

void ubcore_eid_trie_destroy(struct ubcore_eid_trie *trie);

#endif
