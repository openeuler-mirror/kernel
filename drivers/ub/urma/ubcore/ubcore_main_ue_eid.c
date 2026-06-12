// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore main ue EID map
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

#include "ubcore_eid_trie.h"
#include "ubcore_main_ue_eid.h"

struct ubcore_main_ue_eid_ref {
	struct hlist_node node;
	union ubcore_eid main_ue_eid;
	u32 refcnt;
};

struct ubcore_main_ue_eid_event_entry {
	struct list_head node;
	ubcore_main_ue_eid_event_cb_t cb;
};

#define MAIN_UE_EID_REF_HT_BITS 8

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
				 &g_ubcore_main_ue_eid_event_cb_srcu)) {
		ubcore_main_ue_eid_event_cb_t cb;

		/*
		 * Safe RCU dereference to prevent Use-After-Free if
		 * unregistration happens concurrently
		 */
		cb = srcu_dereference(entry->cb, &g_ubcore_main_ue_eid_event_cb_srcu);
		if (cb)
			cb(main_ue_eid, event_type);
	}
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
	/* Notify callbacks inside the lock to guarantee event ordering */
	if (ret == 0 && old_is_last)
		ubcore_notify_main_ue_eid_event(&old_main_ue_eid,
						UBCORE_MAIN_UE_EID_LAST_DEL);
	if (ret == 0 && new_is_first)
		ubcore_notify_main_ue_eid_event(main_ue_eid,
						UBCORE_MAIN_UE_EID_FIRST_ADD);

	mutex_unlock(&g_ubcore_eid_trie.lock);

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
	/* Notify callbacks inside the lock to guarantee event ordering */
	if (ret == 0 && is_last)
		ubcore_notify_main_ue_eid_event(&main_ue_eid,
						UBCORE_MAIN_UE_EID_LAST_DEL);

	mutex_unlock(&g_ubcore_eid_trie.lock);

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

void ubcore_flush_main_ue_eid(void)
{
	struct ubcore_main_ue_eid_ref *ref;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&g_ubcore_eid_trie.lock);
	ubcore_eid_trie_destroy(&g_ubcore_eid_trie);
	hash_for_each_safe(g_ubcore_main_ue_eid_ref_ht, bkt, tmp, ref, node) {
		if (ref->refcnt > 0)
			ubcore_notify_main_ue_eid_event(&ref->main_ue_eid,
				UBCORE_MAIN_UE_EID_LAST_DEL);
		hash_del(&ref->node);
		kfree(ref);
	}
	mutex_unlock(&g_ubcore_eid_trie.lock);
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

	/*
	 * Wait for all pre-existing SRCU read-side critical sections to complete
	 * before freeing the entry. This guarantees no concurrent notifier is
	 * still actively holding/using this entry.
	 */
	synchronize_srcu(&g_ubcore_main_ue_eid_event_cb_srcu);
	kfree(entry);
	return 0;
}
