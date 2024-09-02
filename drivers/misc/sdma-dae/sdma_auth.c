// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/hashtable.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include "hisi_sdma.h"
#include "sdma_auth.h"

#define HISI_SDMA_AUTH_HASH_BUCKETS_BITS 10

struct hisi_sdma_sub_pid_hte {
	u32 pid;
	struct hlist_node pnode;
};

struct hisi_sdma_own_pid_hte {
	u32 pid;
	u32 pasid;
	struct hlist_node node;
	DECLARE_HASHTABLE(sdma_submitter_pid_ht, HISI_SDMA_AUTH_HASH_BUCKETS_BITS);
};

struct hisi_sdma_auth_ht {
	DECLARE_HASHTABLE(sdma_owner_pid_ht, HISI_SDMA_AUTH_HASH_BUCKETS_BITS);
	rwlock_t owner_pid_lock;
};

static struct hisi_sdma_auth_ht *g_authority;

int sdma_authority_hash_init(void)
{
	g_authority = kmalloc(sizeof(struct hisi_sdma_auth_ht), GFP_KERNEL);
	if (!g_authority)
		return -ENOMEM;

	hash_init(g_authority->sdma_owner_pid_ht);
	rwlock_init(&g_authority->owner_pid_lock);

	return 0;
}

static void entry_free_pid_ht(struct hisi_sdma_own_pid_hte *entry)
{
	struct hisi_sdma_sub_pid_hte *sub_entry;
	struct hlist_node *tmp;
	u32 bkt;

	hash_for_each_safe(entry->sdma_submitter_pid_ht, bkt, tmp, sub_entry, pnode) {
		hash_del(&sub_entry->pnode);
		kfree(sub_entry);
	}
	hash_del(&entry->node);
	kfree(entry);
}

void sdma_authority_ht_free(void)
{
	struct hisi_sdma_own_pid_hte *entry;
	struct hlist_node *tmp;
	u32 bkt;

	write_lock(&g_authority->owner_pid_lock);
	hash_for_each_safe(g_authority->sdma_owner_pid_ht, bkt, tmp, entry, node)
		entry_free_pid_ht(entry);

	write_unlock(&g_authority->owner_pid_lock);

	kfree(g_authority);
	g_authority = NULL;
}

static struct hisi_sdma_sub_pid_hte *sdma_search_submitter_pid(struct hisi_sdma_own_pid_hte *entry,
							       u32 submitter_pid)
{
	struct hisi_sdma_sub_pid_hte *sub_entry;

	hash_for_each_possible(entry->sdma_submitter_pid_ht, sub_entry, pnode, submitter_pid)
		if (sub_entry->pid == submitter_pid)
			return sub_entry;

	return NULL;
}

void sdma_free_authority_ht_with_pid(u32 pid)
{
	struct hisi_sdma_sub_pid_hte *sub_entry;
	struct hisi_sdma_own_pid_hte *entry;
	struct hlist_node *tmp;
	u32 bkt;

	write_lock(&g_authority->owner_pid_lock);
	hash_for_each_safe(g_authority->sdma_owner_pid_ht, bkt, tmp, entry, node) {
		if (entry->pid == pid)
			entry_free_pid_ht(entry);
		else {
			sub_entry = sdma_search_submitter_pid(entry, pid);
			if (sub_entry) {
				hash_del(&sub_entry->pnode);
				kfree(sub_entry);
			}
		}
	}
	write_unlock(&g_authority->owner_pid_lock);
}

static struct hisi_sdma_own_pid_hte *sdma_search_owner_pid_ht(u32 pid)
{
	struct hisi_sdma_own_pid_hte *entry;

	hash_for_each_possible(g_authority->sdma_owner_pid_ht, entry, node, pid)
		if (entry->pid == pid)
			return entry;

	return NULL;
}

static void sdma_clear_residual_auth_ht(struct hisi_sdma_own_pid_hte *entry, u32 *list, u32 pos,
					bool *stored_info)
{
	struct hisi_sdma_sub_pid_hte *sub_entry;
	u32 i = pos;

	while (i > 0) {
		i--;
		if (stored_info[i]) {
			sub_entry = sdma_search_submitter_pid(entry, list[i]);
			if (sub_entry) {
				hash_del(&sub_entry->pnode);
				kfree(sub_entry);
			}
		}
	}
}

static int sdma_add_authority_ht(struct hisi_sdma_own_pid_hte *entry, u32 count, u32 *list)
{
	struct hisi_sdma_sub_pid_hte *sub_entry;
	bool *stored;
	u32 i;

	stored = kcalloc(count, sizeof(bool), GFP_KERNEL);
	if (!stored)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		sub_entry = sdma_search_submitter_pid(entry, list[i]);
		if (sub_entry)
			continue;

		sub_entry = kzalloc(sizeof(struct hisi_sdma_sub_pid_hte), GFP_KERNEL);
		if (!sub_entry) {
			sdma_clear_residual_auth_ht(entry, list, i, stored);
			kfree(stored);
			return -ENOMEM;
		}

		sub_entry->pid = list[i];
		hash_add(entry->sdma_submitter_pid_ht, &sub_entry->pnode, sub_entry->pid);
		stored[i] = true;
	}

	kfree(stored);
	return 0;
}

static int sdma_create_authority_ht(u32 pid, u32 pasid, u32 num, u32 *list)
{
	struct hisi_sdma_own_pid_hte *entry;
	int ret;

	entry = kzalloc(sizeof(struct hisi_sdma_own_pid_hte), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->pid = pid;
	entry->pasid = pasid;
	hash_init(entry->sdma_submitter_pid_ht);
	ret = sdma_add_authority_ht(entry, num, list);
	hash_add(g_authority->sdma_owner_pid_ht, &entry->node, entry->pid);

	return ret;
}

int sdma_auth_add(u32 pasid, u32 num, u32 *pid_list)
{
	struct hisi_sdma_own_pid_hte *owner;
	u32 pid = (u32)current->tgid;
	int ret;

	write_lock(&g_authority->owner_pid_lock);
	owner = sdma_search_owner_pid_ht(pid);
	if (owner) {
		ret = sdma_add_authority_ht(owner, num, pid_list);
		if (ret < 0)
			pr_err("add_pid_ht failed\n");
	} else {
		ret = sdma_create_authority_ht(pid, pasid, num, pid_list);
		if (ret < 0)
			pr_err("create_pid_ht failed\n");
	}
	write_unlock(&g_authority->owner_pid_lock);

	return ret;
}

int sdma_check_authority(u32 pasid, u32 owner_pid, u32 submitter_pid, u32 *owner_pasid)
{
	struct hisi_sdma_sub_pid_hte *sub_entry;
	struct hisi_sdma_own_pid_hte *entry;

	if (owner_pid == submitter_pid) {
		*owner_pasid = pasid;
		return 0;
	}
	read_lock(&g_authority->owner_pid_lock);
	entry = sdma_search_owner_pid_ht(owner_pid);
	if (!entry) {
		pr_err("the owner_pid_ht[%u] not exist\n", owner_pid);
		read_unlock(&g_authority->owner_pid_lock);
		return -ENODATA;
	}
	sub_entry = sdma_search_submitter_pid(entry, submitter_pid);
	if (!sub_entry) {
		pr_err("the submitter[%u] not authorithed\n", submitter_pid);
		read_unlock(&g_authority->owner_pid_lock);
		return -ENODATA;
	}
	read_unlock(&g_authority->owner_pid_lock);

	*owner_pasid = entry->pasid;
	return 0;
}
