// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "ib_peer_mem.h"
#include <rdma/ib_verbs.h>
#include "ib_umem_ex.h"

static DEFINE_MUTEX(peer_memory_mutex);
static LIST_HEAD(peer_memory_list);

static void complete_peer(struct kref *kref);

/* Caller should be holding the peer client lock, ib_peer_client->lock */
static struct core_ticket *ib_peer_search_context(struct ib_peer_memory_client *ib_peer_client,
						  u64 key)
{
	struct core_ticket *core_ticket;

	list_for_each_entry(core_ticket, &ib_peer_client->core_ticket_list,
			    ticket_list) {
		if (core_ticket->key == key)
			return core_ticket;
	}

	return NULL;
}

static int ib_invalidate_peer_memory(void *reg_handle, u64 core_context)
{
	struct ib_peer_memory_client *ib_peer_client = reg_handle;
	struct invalidation_ctx *invalidation_ctx;
	struct core_ticket *core_ticket;
	int need_unlock = 1;

	mutex_lock(&ib_peer_client->lock);
	ib_peer_client->stats.num_free_callbacks += 1;
	core_ticket = ib_peer_search_context(ib_peer_client, core_context);
	if (!core_ticket)
		goto out;

	invalidation_ctx = (struct invalidation_ctx *)core_ticket->context;
	/* If context is not ready yet, mark it to be invalidated */
	if (!invalidation_ctx->func) {
		invalidation_ctx->peer_invalidated = 1;
		goto out;
	}
	invalidation_ctx->func(invalidation_ctx->cookie,
					invalidation_ctx->umem_ex, 0, 0);
	if (invalidation_ctx->inflight_invalidation) {
		/* init the completion to wait on before letting other thread to run */
		init_completion(&invalidation_ctx->comp);
		mutex_unlock(&ib_peer_client->lock);
		need_unlock = 0;
		wait_for_completion(&invalidation_ctx->comp);
	}

	kfree(invalidation_ctx);
out:
	if (need_unlock)
		mutex_unlock(&ib_peer_client->lock);

	return 0;
}

static int ib_peer_insert_context(struct ib_peer_memory_client *ib_peer_client,
				  void *context,
				  u64 *context_ticket)
{
	struct core_ticket *core_ticket = kzalloc(sizeof(*core_ticket), GFP_KERNEL);

	if (!core_ticket)
		return -ENOMEM;

	mutex_lock(&ib_peer_client->lock);
	core_ticket->key = ib_peer_client->last_ticket++;
	core_ticket->context = context;
	list_add_tail(&core_ticket->ticket_list,
		      &ib_peer_client->core_ticket_list);
	*context_ticket = core_ticket->key;
	mutex_unlock(&ib_peer_client->lock);

	return 0;
}

/*
 * Caller should be holding the peer client lock, specifically,
 * the caller should hold ib_peer_client->lock
 */
static int ib_peer_remove_context(struct ib_peer_memory_client *ib_peer_client,
				  u64 key)
{
	struct core_ticket *core_ticket;

	list_for_each_entry(core_ticket, &ib_peer_client->core_ticket_list,
			    ticket_list) {
		if (core_ticket->key == key) {
			list_del(&core_ticket->ticket_list);
			kfree(core_ticket);
			return 0;
		}
	}

	return 1;
}

/*
 * ib_peer_create_invalidation_ctx - creates invalidation context for a given umem
 * @ib_peer_mem: peer client to be used
 * @umem: umem struct belongs to that context
 * @invalidation_ctx: output context
 */
int ib_peer_create_invalidation_ctx(struct ib_peer_memory_client *ib_peer_mem,
				    struct ib_umem_ex *umem_ex,
				    struct invalidation_ctx **invalidation_ctx)
{
	int ret;
	struct invalidation_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ret = ib_peer_insert_context(ib_peer_mem, ctx,
				     &ctx->context_ticket);
	if (ret) {
		kfree(ctx);
		return ret;
	}

	ctx->umem_ex = umem_ex;
	umem_ex->invalidation_ctx = ctx;
	*invalidation_ctx = ctx;

	return 0;
}

/**
 * ** ib_peer_destroy_invalidation_ctx - destroy a given invalidation context
 * ** @ib_peer_mem: peer client to be used
 * ** @invalidation_ctx: context to be invalidated
 * **/
void ib_peer_destroy_invalidation_ctx(struct ib_peer_memory_client *ib_peer_mem,
				      struct invalidation_ctx *invalidation_ctx)
{
	int peer_callback;
	int inflight_invalidation;

	/* If we are under peer callback lock was already taken.*/
	if (!invalidation_ctx->peer_callback)
		mutex_lock(&ib_peer_mem->lock);
	ib_peer_remove_context(ib_peer_mem, invalidation_ctx->context_ticket);
	/* make sure to check inflight flag after took the lock and remove from tree.
	 * in addition, from that point using local variables for peer_callback and
	 * inflight_invalidation as after the complete invalidation_ctx can't be accessed
	 * any more as it may be freed by the callback.
	 */
	peer_callback = invalidation_ctx->peer_callback;
	inflight_invalidation = invalidation_ctx->inflight_invalidation;
	if (inflight_invalidation)
		complete(&invalidation_ctx->comp);

	/* On peer callback lock is handled externally */
	if (!peer_callback)
		mutex_unlock(&ib_peer_mem->lock);

	/* in case under callback context or callback is pending
	 * let it free the invalidation context
	 */
	if (!peer_callback && !inflight_invalidation)
		kfree(invalidation_ctx);
}

static int ib_memory_peer_check_mandatory(const struct peer_memory_client
						     *peer_client)
{
#define PEER_MEM_MANDATORY_FUNC(x) { offsetof(struct peer_memory_client, x), #x }
		static const struct {
			size_t offset;
			char  *name;
		} mandatory_table[] = {
			PEER_MEM_MANDATORY_FUNC(acquire),
			PEER_MEM_MANDATORY_FUNC(get_pages),
			PEER_MEM_MANDATORY_FUNC(put_pages),
			PEER_MEM_MANDATORY_FUNC(get_page_size),
			PEER_MEM_MANDATORY_FUNC(dma_map),
			PEER_MEM_MANDATORY_FUNC(dma_unmap)
		};
		int i;

		for (i = 0; i < ARRAY_SIZE(mandatory_table); ++i) {
			if (!*(void **)((void *)peer_client + mandatory_table[i].offset)) {
				pr_err("Peer memory %s is missing mandatory function %s\n",
				       peer_client->name, mandatory_table[i].name);
				return -EINVAL;
			}
		}

		return 0;
}

static void complete_peer(struct kref *kref)
{
	struct ib_peer_memory_client *ib_peer_client =
		container_of(kref, struct ib_peer_memory_client, ref);

	complete(&ib_peer_client->unload_comp);
}

void *ib_register_peer_memory_client(const struct peer_memory_client *peer_client,
				     invalidate_peer_memory *invalidate_callback)
{
	struct ib_peer_memory_client *ib_peer_client;

	if (ib_memory_peer_check_mandatory(peer_client))
		return NULL;

	ib_peer_client = kzalloc(sizeof(*ib_peer_client), GFP_KERNEL);
	if (!ib_peer_client)
		return NULL;

	INIT_LIST_HEAD(&ib_peer_client->core_ticket_list);
	mutex_init(&ib_peer_client->lock);
	init_completion(&ib_peer_client->unload_comp);
	kref_init(&ib_peer_client->ref);
	ib_peer_client->peer_mem = peer_client;

	/* Once peer supplied a non NULL callback it's an indication that
	 * invalidation support is required for any memory owning.
	 */
	if (invalidate_callback) {
		*invalidate_callback = ib_invalidate_peer_memory;
		ib_peer_client->invalidation_required = 1;
	}
	ib_peer_client->last_ticket = 1;

	mutex_lock(&peer_memory_mutex);
	list_add_tail(&ib_peer_client->core_peer_list, &peer_memory_list);
	mutex_unlock(&peer_memory_mutex);
	return ib_peer_client;
}
EXPORT_SYMBOL(ib_register_peer_memory_client);

void ib_unregister_peer_memory_client(void *reg_handle)
{
	struct ib_peer_memory_client *ib_peer_client = reg_handle;

	mutex_lock(&peer_memory_mutex);
	list_del(&ib_peer_client->core_peer_list);
	mutex_unlock(&peer_memory_mutex);

	kref_put(&ib_peer_client->ref, complete_peer);
	wait_for_completion(&ib_peer_client->unload_comp);
	kfree(ib_peer_client);
}
EXPORT_SYMBOL(ib_unregister_peer_memory_client);

struct ib_peer_memory_client *ib_get_peer_client(struct ib_ucontext *context, unsigned long addr,
						 size_t size, unsigned long peer_mem_flags,
						 void **peer_client_context)
{
	struct ib_peer_memory_client *ib_peer_client = NULL;

	int ret = 0;

	mutex_lock(&peer_memory_mutex);
	list_for_each_entry(ib_peer_client, &peer_memory_list, core_peer_list) {
		/* In case peer requires invalidation it can't own
		 * memory which doesn't support it
		 */
		if ((ib_peer_client->invalidation_required &&
		     (!(peer_mem_flags & IB_PEER_MEM_INVAL_SUPP))))
			continue;
		ret = ib_peer_client->peer_mem->acquire(addr, size, NULL, NULL,
						   peer_client_context);
		if (ret > 0)
			goto found;
	}

	ib_peer_client = NULL;

found:
	if (ib_peer_client)
		kref_get(&ib_peer_client->ref);

	mutex_unlock(&peer_memory_mutex);

	return ib_peer_client;
}
EXPORT_SYMBOL(ib_get_peer_client);

void ib_put_peer_client(struct ib_peer_memory_client *ib_peer_client,
			void *peer_client_context)
{
	if (ib_peer_client->peer_mem->release)
		ib_peer_client->peer_mem->release(peer_client_context);

	kref_put(&ib_peer_client->ref, complete_peer);
}
EXPORT_SYMBOL(ib_put_peer_client);

int ib_get_peer_private_data(struct ib_ucontext *context, u64 peer_id,
			     char *peer_name)
{
	pr_warn("predefine peer mem is not supported by now");
	return -1;
}
EXPORT_SYMBOL(ib_get_peer_private_data);

void ib_put_peer_private_data(struct ib_ucontext *context)
{
	pr_warn("predefine peer mem is not supported by now");
}
EXPORT_SYMBOL(ib_put_peer_private_data);
