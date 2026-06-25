/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore host trie
 */

#ifndef UBCORE_HOST_TRIE_H
#define UBCORE_HOST_TRIE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <ub/urma/ubcore_types.h>

#include "ubcore_priv.h"

/* Node structure for the Patricia Trie */
struct ubcore_host_trie_node {
	struct rcu_head rcu;
	struct ubcore_host_trie_node __rcu *child[2]; /* Left (0) and Right (1) */
	union ubcore_eid prefix;		/* The prefix stored at this node */
	struct ubcore_host_info value;		/* The mapped value (valid if is_leaf) */
	u8 prefix_len;				/* Length of the prefix (0-128) */
	bool is_leaf;				/* True if this node holds an actual key-value */
};

struct ubcore_host_trie {
	struct ubcore_host_trie_node __rcu *root;
	struct mutex lock;			/* Serializes writers */
};

#define HOST_TRIE_NODE_SZ (sizeof(struct ubcore_host_trie_node))

/* --- Trie Operations --- */

int ubcore_host_trie_lookup(struct ubcore_host_trie *trie,
			    const union ubcore_eid *key,
			    struct ubcore_host_info *value_out);

int ubcore_host_trie_insert(struct ubcore_host_trie *trie,
			    const union ubcore_eid *key,
			    const struct ubcore_host_info *value);

int ubcore_host_trie_delete(struct ubcore_host_trie *trie,
			    const union ubcore_eid *key);

void ubcore_host_trie_destroy(struct ubcore_host_trie *trie);

#endif
