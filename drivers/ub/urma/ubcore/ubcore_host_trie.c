// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore host trie
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <ub/urma/ubcore_types.h>

#include "ubcore_host_trie.h"

/* --- Bit Manipulation Helpers --- */

/* Get the n-th bit (0-127) of an IPv6 address. 0 is the MSB. */
static inline int ubcore_eid_get_bit(const union ubcore_eid *addr, int n)
{
	return (addr->raw[n / 8] >> (7 - (n % 8))) & 1;
}

/* Find the first differing bit between two IPv6 addresses */
static int ubcore_eid_diff_bit(const union ubcore_eid *a,
			       const union ubcore_eid *b)
{
	int i, j;
	u8 xor;

	for (i = 0; i < 16; i++) {
		if (a->raw[i] != b->raw[i]) {
			xor = a->raw[i] ^ b->raw[i];
			for (j = 0; j < 8; j++) {
				if (xor & (1 << (7 - j)))
					return i * 8 + j;
			}
		}
	}
	return 128; /* Addresses are identical */
}

/* --- RCU Callback for safe memory reclamation --- */
static void ubcore_host_trie_node_rcu_free(struct rcu_head *head)
{
	struct ubcore_host_trie_node *node;

	node = container_of(head, struct ubcore_host_trie_node, rcu);
	kfree(node);
}

/* --- Trie Operations --- */

int ubcore_host_trie_lookup(struct ubcore_host_trie *trie,
			    const union ubcore_eid *key,
			    struct ubcore_host_info *value_out)
{
	struct ubcore_host_trie_node *node;
	int diff;

	rcu_read_lock();
	node = rcu_dereference(trie->root);

	while (node) {
		diff = ubcore_eid_diff_bit(key, &node->prefix);

		/* If key diverges before this node's prefix length, key is not in trie */
		if (diff < node->prefix_len) {
			rcu_read_unlock();
			return -ENOENT;
		}

		/* If it's an exact match (128 bits) and it's a leaf, we found it */
		if (node->is_leaf) {
			*value_out = node->value;
			rcu_read_unlock();
			return 0;
		}

		/* Traverse down based on the bit at the current prefix length */
		node = rcu_dereference(node->child[ubcore_eid_get_bit(key, node->prefix_len)]);
	}

	rcu_read_unlock();
	return -ENOENT;
}

int ubcore_host_trie_insert(struct ubcore_host_trie *trie,
			    const union ubcore_eid *key,
			    const struct ubcore_host_info *value)
{
	struct ubcore_host_trie_node *new_leaf, *node, *parent, *new_internal, *updated;
	int diff, bit, p_bit = 0, node_bit, new_bit;

	lockdep_assert_held(&trie->lock);

	/* Allocate new leaf node */
	new_leaf = kzalloc(HOST_TRIE_NODE_SZ, GFP_KERNEL);
	if (!new_leaf)
		return -ENOMEM;

	new_leaf->prefix = *key;
	new_leaf->prefix_len = 128;
	new_leaf->value = *value;
	new_leaf->is_leaf = true;

	parent = NULL;
	node = rcu_dereference_protected(trie->root, lockdep_is_held(&trie->lock));

	/* If trie is empty, set root */
	if (!node) {
		rcu_assign_pointer(trie->root, new_leaf);
		return 0;
	}

	/* Traverse to find insertion point */
	while (node) {
		diff = ubcore_eid_diff_bit(key, &node->prefix);

		/* Need to split here if divergence is within current node's prefix */
		if (diff < node->prefix_len)
			break;

		/* If exact match found, update value (RCU replace) */
		if (node->is_leaf) {
			updated = kzalloc(HOST_TRIE_NODE_SZ, GFP_KERNEL);
			if (!updated) {
				kfree(new_leaf);
				return -ENOMEM;
			}
			*updated = *node;
			updated->value = *value;

			if (parent)
				rcu_assign_pointer(parent->child[p_bit], updated);
			else
				rcu_assign_pointer(trie->root, updated);

			call_rcu(&node->rcu, ubcore_host_trie_node_rcu_free);
			kfree(new_leaf);
			return 0;
		}

		/* Descend */
		bit = ubcore_eid_get_bit(key, node->prefix_len);
		parent = node;
		p_bit = bit;
		node = rcu_dereference_protected(node->child[bit], lockdep_is_held(&trie->lock));
	}

	/* If we fell off the tree, attach to parent */
	if (!node) {
		rcu_assign_pointer(parent->child[p_bit], new_leaf);
		return 0;
	}

	/* We need to insert an internal node to split the divergence */
	new_internal = kzalloc(HOST_TRIE_NODE_SZ, GFP_KERNEL);
	if (!new_internal) {
		kfree(new_leaf);
		return -ENOMEM;
	}

	new_internal->prefix = *key; /* Can be node->prefix too; bits after diff don't matter */
	new_internal->prefix_len = diff;
	new_internal->is_leaf = false;

	node_bit = ubcore_eid_get_bit(&node->prefix, diff);
	new_bit = ubcore_eid_get_bit(key, diff);

	rcu_assign_pointer(new_internal->child[node_bit], node);
	rcu_assign_pointer(new_internal->child[new_bit], new_leaf);

	if (parent)
		rcu_assign_pointer(parent->child[p_bit], new_internal);
	else
		rcu_assign_pointer(trie->root, new_internal);

	return 0;
}

int ubcore_host_trie_delete(struct ubcore_host_trie *trie,
			    const union ubcore_eid *key)
{
	struct ubcore_host_trie_node *node, *parent, *gp, *sibling;
	int bit, p_bit = 0, gp_bit = 0, diff, sib_bit;

	lockdep_assert_held(&trie->lock);

	gp = NULL;
	parent = NULL;
	node = rcu_dereference_protected(trie->root, lockdep_is_held(&trie->lock));

	while (node) {
		diff = ubcore_eid_diff_bit(key, &node->prefix);

		if (diff < node->prefix_len)
			return -ENOENT; /* Key not in trie */

		if (node->is_leaf)
			break; /* Found the node to delete */

		bit = ubcore_eid_get_bit(key, node->prefix_len);
		gp = parent;
		gp_bit = p_bit;
		parent = node;
		p_bit = bit;
		node = rcu_dereference_protected(node->child[bit], lockdep_is_held(&trie->lock));
	}

	if (!node)
		return -ENOENT;

	/* If deleting root */
	if (!parent) {
		rcu_assign_pointer(trie->root, NULL);
		call_rcu(&node->rcu, ubcore_host_trie_node_rcu_free);
		return 0;
	}

	/*
	 * In an exact-match Patricia Trie, deleting a leaf means its parent
	 * internal node must also be removed, bypassing it with the leaf's sibling.
	 */
	sib_bit = p_bit ? 0 : 1;
	sibling = rcu_dereference_protected(parent->child[sib_bit],
		lockdep_is_held(&trie->lock));

	if (gp)
		rcu_assign_pointer(gp->child[gp_bit], sibling);
	else
		rcu_assign_pointer(trie->root, sibling);

	/* Schedule both the deleted leaf and its parent internal node for reclamation */
	call_rcu(&node->rcu, ubcore_host_trie_node_rcu_free);
	call_rcu(&parent->rcu, ubcore_host_trie_node_rcu_free);

	return 0;
}

static void ubcore_host_trie_reclaim(struct ubcore_host_trie_node *node)
{
	if (!node)
		return;
	ubcore_host_trie_reclaim(node->child[0]);
	ubcore_host_trie_reclaim(node->child[1]);
	kfree(node);
}

void ubcore_host_trie_destroy(struct ubcore_host_trie *trie)
{
	struct ubcore_host_trie_node *old_root;

	lockdep_assert_held(&trie->lock);

	/* Detach the tree: replace root with NULL */
	old_root = rcu_dereference_protected(trie->root, lockdep_is_held(&trie->lock));
	rcu_assign_pointer(trie->root, NULL);

	if (!old_root)
		return;

	/*
	 * Wait for all pre-existing RCU readers to exit their critical sections.
	 * After this returns, no CPU is holding a reference to any node in old_root.
	 */
	synchronize_rcu();

	/*
	 * Wait for any pending call_rcu() callbacks from previous
	 * insert/delete operations on this tree to finish executing.
	 * This prevents a pending callback from freeing a node after
	 * we free the entire tree in the next step.
	 */
	rcu_barrier();

	/* Safely free the detached tree. Exclusive access is now guaranteed. */
	ubcore_host_trie_reclaim(old_root);
}
