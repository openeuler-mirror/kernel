// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore main ue EID trie
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/srcu.h>
#include <ub/urma/ubcore_types.h>

#include "ubcore_main_ue_eid.h"

/* Node structure for the Patricia Trie */
struct ubcore_eid_trie_node {
	struct rcu_head rcu;
	struct ubcore_eid_trie_node __rcu *child[2]; /* Left (0) and Right (1) */
	union ubcore_eid prefix; /* The prefix stored at this node */
	union ubcore_eid value; /* The mapped value (valid if is_leaf) */
	u8 prefix_len; /* Length of the prefix (0-128) */
	bool is_leaf; /* True if this node holds an actual key-value */
};

struct ubcore_eid_trie {
	struct ubcore_eid_trie_node __rcu *root;
	struct mutex lock; /* Serializes writers */
};

struct ubcore_main_ue_eid_ref {
	struct hlist_node node;
	union ubcore_eid main_ue_eid;
	u32 refcnt;
};

struct ubcore_main_ue_eid_event_entry {
	struct list_head node;
	ubcore_main_ue_eid_event_cb_t cb;
};

#define EID_NODE_SZ (sizeof(struct ubcore_eid_trie_node))
#define MAIN_UE_EID_REF_HT_BITS 8

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
static void ubcore_eid_trie_node_rcu_free(struct rcu_head *head)
{
	struct ubcore_eid_trie_node *node;

	node = container_of(head, struct ubcore_eid_trie_node, rcu);
	kfree(node);
}

/* --- Trie Operations --- */

static int ubcore_eid_trie_lookup(struct ubcore_eid_trie *trie,
				  const union ubcore_eid *key,
				  union ubcore_eid *value_out)
{
	struct ubcore_eid_trie_node *node;
	int diff;
	// ubcore_log_err("Looking up EID " EID_FMT "\n", EID_ARGS(key));
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
		node = rcu_dereference(
			node->child[ubcore_eid_get_bit(key, node->prefix_len)]);
	}

	rcu_read_unlock();
	return -ENOENT;
}

static int ubcore_eid_trie_insert(struct ubcore_eid_trie *trie,
				  const union ubcore_eid *key,
				  const union ubcore_eid *value)
{
	struct ubcore_eid_trie_node *new_leaf, *node, *parent, *new_internal,
		*updated;
	int diff, bit, p_bit = 0, node_bit, new_bit;

	/* Allocate new leaf node */
	new_leaf = kzalloc(EID_NODE_SZ, GFP_KERNEL);
	if (!new_leaf) {
		return -ENOMEM;
	}
	new_leaf->prefix = *key;
	new_leaf->prefix_len = 128;
	new_leaf->value = *value;
	new_leaf->is_leaf = true;

	parent = NULL;
	node = rcu_dereference_protected(trie->root,
					 lockdep_is_held(&trie->lock));

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
			updated = kzalloc(EID_NODE_SZ, GFP_KERNEL);
			if (!updated) {
				kfree(new_leaf);
				return -ENOMEM;
			}
			*updated = *node;
			updated->value = *value;

			if (parent)
				rcu_assign_pointer(parent->child[p_bit],
						   updated);
			else
				rcu_assign_pointer(trie->root, updated);

			call_rcu(&node->rcu, ubcore_eid_trie_node_rcu_free);
			kfree(new_leaf);
			return 0;
		}

		/* Descend */
		bit = ubcore_eid_get_bit(key, node->prefix_len);
		parent = node;
		p_bit = bit;
		node = rcu_dereference_protected(node->child[bit],
						 lockdep_is_held(&trie->lock));
	}

	/* If we fell off the tree, attach to parent */
	if (!node) {
		rcu_assign_pointer(parent->child[p_bit], new_leaf);
		return 0;
	}

	/* We need to insert an internal node to split the divergence */
	new_internal = kzalloc(EID_NODE_SZ, GFP_KERNEL);
	if (!new_internal) {
		kfree(new_leaf);
		return -ENOMEM;
	}

	new_internal->prefix =
		*key; /* Can be node->prefix too; bits after diff don't matter */
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

static int ubcore_eid_trie_delete(struct ubcore_eid_trie *trie,
				  const union ubcore_eid *key)
{
	struct ubcore_eid_trie_node *node, *parent, *gp, *sibling;
	int bit, p_bit = 0, gp_bit = 0, diff, sib_bit;

	gp = NULL;
	parent = NULL;
	node = rcu_dereference_protected(trie->root,
					 lockdep_is_held(&trie->lock));

	while (node) {
		diff = ubcore_eid_diff_bit(key, &node->prefix);

		if (diff < node->prefix_len) {
			return -ENOENT; /* Key not in trie */
		}

		if (node->is_leaf)
			break; /* Found the node to delete */

		bit = ubcore_eid_get_bit(key, node->prefix_len);
		gp = parent;
		gp_bit = p_bit;
		parent = node;
		p_bit = bit;
		node = rcu_dereference_protected(node->child[bit],
						 lockdep_is_held(&trie->lock));
	}

	if (!node) {
		return -ENOENT;
	}

	/* If deleting root */
	if (!parent) {
		rcu_assign_pointer(trie->root, NULL);
		call_rcu(&node->rcu, ubcore_eid_trie_node_rcu_free);
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
	call_rcu(&node->rcu, ubcore_eid_trie_node_rcu_free);
	call_rcu(&parent->rcu, ubcore_eid_trie_node_rcu_free);

	return 0;
}

static void ubcore_eid_trie_reclaim(struct ubcore_eid_trie_node *node)
{
	if (!node)
		return;
	ubcore_eid_trie_reclaim(node->child[0]);
	ubcore_eid_trie_reclaim(node->child[1]);
	kfree(node);
}

void ubcore_eid_trie_destroy(struct ubcore_eid_trie *trie)
{
	struct ubcore_eid_trie_node *old_root;

	/* Detach the tree: replace root with NULL */
	old_root = rcu_dereference_protected(trie->root,
					     lockdep_is_held(&trie->lock));
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
	ubcore_eid_trie_reclaim(old_root);
}

static struct ubcore_eid_trie g_ubcore_eid_trie = {
	.root = RCU_INITIALIZER(NULL),
	.lock = __MUTEX_INITIALIZER(g_ubcore_eid_trie.lock)
};
static DEFINE_HASHTABLE(g_ubcore_main_ue_eid_ref_ht, MAIN_UE_EID_REF_HT_BITS);
static LIST_HEAD(g_ubcore_main_ue_eid_event_cb_list);
static DEFINE_MUTEX(g_ubcore_main_ue_eid_event_cb_lock);
DEFINE_STATIC_SRCU(g_ubcore_main_ue_eid_event_cb_srcu);

static bool ubcore_eid_is_zero(const union ubcore_eid *eid)
{
	u32 i;

	if (!eid)
		return true;

	for (i = 0; i < UBCORE_EID_SIZE; i++) {
		if (eid->raw[i] != 0)
			return false;
	}

	return true;
}

static bool ubcore_eid_is_same(const union ubcore_eid *lhs,
			       const union ubcore_eid *rhs)
{
	return memcmp(lhs, rhs, sizeof(*lhs)) == 0;
}

static u32 ubcore_main_ue_eid_hash(const union ubcore_eid *main_ue_eid)
{
	return jhash(main_ue_eid->raw, UBCORE_EID_SIZE, 0);
}

static struct ubcore_main_ue_eid_ref *
ubcore_find_main_ue_eid_ref(const union ubcore_eid *main_ue_eid)
{
	struct ubcore_main_ue_eid_ref *ref;
	u32 key = ubcore_main_ue_eid_hash(main_ue_eid);

	hash_for_each_possible(g_ubcore_main_ue_eid_ref_ht, ref, node, key) {
		if (ubcore_eid_is_same(&ref->main_ue_eid, main_ue_eid))
			return ref;
	}

	return NULL;
}

static int ubcore_get_main_ue_eid(struct ubcore_eid_trie *trie,
				  const union ubcore_eid *eid,
				  union ubcore_eid *main_ue_eid)
{
	return ubcore_eid_trie_lookup(trie, eid, main_ue_eid);
}

static int
ubcore_inc_main_ue_eid_ref_locked(const union ubcore_eid *main_ue_eid,
				  bool *is_first)
{
	struct ubcore_main_ue_eid_ref *ref;

	ref = ubcore_find_main_ue_eid_ref(main_ue_eid);
	if (ref) {
		ref->refcnt++;
		*is_first = false;
		return 0;
	}

	ref = kzalloc(sizeof(*ref), GFP_KERNEL);
	if (!ref)
		return -ENOMEM;

	ref->main_ue_eid = *main_ue_eid;
	ref->refcnt = 1;
	hash_add(g_ubcore_main_ue_eid_ref_ht, &ref->node,
		 ubcore_main_ue_eid_hash(main_ue_eid));
	*is_first = true;
	return 0;
}

static int
ubcore_dec_main_ue_eid_ref_locked(const union ubcore_eid *main_ue_eid,
				  bool *is_last)
{
	struct ubcore_main_ue_eid_ref *ref;

	ref = ubcore_find_main_ue_eid_ref(main_ue_eid);
	if (!ref || ref->refcnt == 0)
		return -ENOENT;

	ref->refcnt--;
	if (ref->refcnt != 0) {
		*is_last = false;
		return 0;
	}

	hash_del(&ref->node);
	kfree(ref);
	*is_last = true;
	return 0;
}

static struct ubcore_main_ue_eid_event_entry *
ubcore_find_main_ue_eid_event_cb_locked(ubcore_main_ue_eid_event_cb_t cb)
{
	struct ubcore_main_ue_eid_event_entry *entry;

	list_for_each_entry(entry, &g_ubcore_main_ue_eid_event_cb_list, node) {
		if (entry->cb == cb)
			return entry;
	}

	return NULL;
}

static void
ubcore_notify_main_ue_eid_event(const union ubcore_eid *main_ue_eid,
				enum ubcore_main_ue_eid_event_type event_type)
{
	struct ubcore_main_ue_eid_event_entry *entry;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&g_ubcore_main_ue_eid_event_cb_srcu);
	list_for_each_entry_srcu(entry, &g_ubcore_main_ue_eid_event_cb_list,
				 node,
				 srcu_read_lock_held(
					 &g_ubcore_main_ue_eid_event_cb_srcu))
		entry->cb(main_ue_eid, event_type);
	srcu_read_unlock(&g_ubcore_main_ue_eid_event_cb_srcu, srcu_idx);
}

int ubcore_insert_main_ue_eid(const union ubcore_eid *eid,
			      const union ubcore_eid *main_ue_eid)
{
	union ubcore_eid old_main_ue_eid;
	bool old_is_last = false;
	bool new_is_first = false;
	bool has_old = false;
	int ret;

	if (ubcore_eid_is_zero(eid))
		return -EINVAL;

	if (ubcore_eid_is_zero(main_ue_eid))
		return -EINVAL;

	mutex_lock(&g_ubcore_eid_trie.lock);

	ret = ubcore_get_main_ue_eid(&g_ubcore_eid_trie, eid, &old_main_ue_eid);
	if (ret == 0)
		has_old = true;
	else if (ret != -ENOENT)
		goto unlock;

	if (has_old && ubcore_eid_is_same(&old_main_ue_eid, main_ue_eid)) {
		ret = 0;
		goto unlock;
	}

	if (has_old) {
		ret = ubcore_dec_main_ue_eid_ref_locked(&old_main_ue_eid,
							&old_is_last);
		if (ret != 0)
			goto unlock;
	}

	ret = ubcore_inc_main_ue_eid_ref_locked(main_ue_eid, &new_is_first);
	if (ret != 0) {
		if (has_old) {
			bool rollback_first = false;

			(void)ubcore_inc_main_ue_eid_ref_locked(
				&old_main_ue_eid, &rollback_first);
		}
		goto unlock;
	}

	ret = ubcore_eid_trie_insert(&g_ubcore_eid_trie, eid, main_ue_eid);
	if (ret != 0) {
		bool rollback_first = false;
		bool rollback_last = false;

		(void)ubcore_dec_main_ue_eid_ref_locked(main_ue_eid,
							&rollback_last);
		if (has_old)
			(void)ubcore_inc_main_ue_eid_ref_locked(
				&old_main_ue_eid, &rollback_first);
		goto unlock;
	}

unlock:
	mutex_unlock(&g_ubcore_eid_trie.lock);

	if (ret == 0 && old_is_last)
		ubcore_notify_main_ue_eid_event(&old_main_ue_eid,
						UBCORE_MAIN_UE_EID_LAST_DEL);
	if (ret == 0 && new_is_first)
		ubcore_notify_main_ue_eid_event(main_ue_eid,
						UBCORE_MAIN_UE_EID_FIRST_ADD);

	return ret;
}

int ubcore_delete_main_ue_eid(const union ubcore_eid *eid)
{
	union ubcore_eid main_ue_eid;
	bool is_last = false;
	int ret;

	if (ubcore_eid_is_zero(eid))
		return -EINVAL;

	mutex_lock(&g_ubcore_eid_trie.lock);

	ret = ubcore_get_main_ue_eid(&g_ubcore_eid_trie, eid, &main_ue_eid);
	if (ret != 0)
		goto unlock;

	ret = ubcore_eid_trie_delete(&g_ubcore_eid_trie, eid);
	if (ret != 0)
		goto unlock;

	ret = ubcore_dec_main_ue_eid_ref_locked(&main_ue_eid, &is_last);

unlock:
	mutex_unlock(&g_ubcore_eid_trie.lock);

	if (ret == 0 && is_last)
		ubcore_notify_main_ue_eid_event(&main_ue_eid,
						UBCORE_MAIN_UE_EID_LAST_DEL);

	return ret;
}

int ubcore_lookup_main_ue_eid(const union ubcore_eid *eid,
			      union ubcore_eid *main_ue_eid)
{
	if (ubcore_eid_is_zero(eid))
		return -EINVAL;

	if (!main_ue_eid)
		return -EINVAL;

	return ubcore_eid_trie_lookup(&g_ubcore_eid_trie, eid, main_ue_eid);
}

int ubcore_register_main_ue_eid_event_cb(ubcore_main_ue_eid_event_cb_t cb)
{
	struct ubcore_main_ue_eid_event_entry *entry;

	if (!cb)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	INIT_LIST_HEAD(&entry->node);
	entry->cb = cb;

	mutex_lock(&g_ubcore_main_ue_eid_event_cb_lock);
	if (ubcore_find_main_ue_eid_event_cb_locked(cb)) {
		mutex_unlock(&g_ubcore_main_ue_eid_event_cb_lock);
		kfree(entry);
		return -EEXIST;
	}
	list_add_tail_rcu(&entry->node, &g_ubcore_main_ue_eid_event_cb_list);
	mutex_unlock(&g_ubcore_main_ue_eid_event_cb_lock);

	return 0;
}

int ubcore_unregister_main_ue_eid_event_cb(ubcore_main_ue_eid_event_cb_t cb)
{
	struct ubcore_main_ue_eid_event_entry *entry;

	if (!cb)
		return -EINVAL;

	mutex_lock(&g_ubcore_main_ue_eid_event_cb_lock);
	entry = ubcore_find_main_ue_eid_event_cb_locked(cb);
	if (!entry) {
		mutex_unlock(&g_ubcore_main_ue_eid_event_cb_lock);
		return -ENOENT;
	}
	list_del_rcu(&entry->node);
	mutex_unlock(&g_ubcore_main_ue_eid_event_cb_lock);

	synchronize_srcu(&g_ubcore_main_ue_eid_event_cb_srcu);
	kfree(entry);
	return 0;
}

void ubcore_flush_main_ue_eid(void)
{
	struct ubcore_main_ue_eid_ref *ref;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&g_ubcore_eid_trie.lock);
	ubcore_eid_trie_destroy(&g_ubcore_eid_trie);
	hash_for_each_safe(g_ubcore_main_ue_eid_ref_ht, bkt, tmp, ref, node) {
		hash_del(&ref->node);
		kfree(ref);
	}
	mutex_unlock(&g_ubcore_eid_trie.lock);
}
