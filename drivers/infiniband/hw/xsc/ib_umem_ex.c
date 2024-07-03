// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/sched/mm.h>

#ifndef MLX_PEER_SUPPORT
#include "ib_peer_mem.h"
#endif

#include <rdma/ib_verbs.h>
#include "ib_umem_ex.h"

#if defined(IB_CORE_UMEM_EX_V1)
#define get_mm(umem_ctx) ((umem_ctx)->mm)
#elif defined(IB_CORE_UMEM_EX_V2)
#define get_mm(umem_ctx) ((umem_ctx)->owning_mm)
#endif

#if defined(IB_CORE_UMEM_EX_V1) || defined(IB_CORE_UMEM_EX_V2)
static struct ib_umem_ex *peer_umem_get(struct ib_peer_memory_client *ib_peer_mem,
					struct ib_umem_ex *umem_ex, unsigned long addr,
					int dmasync, unsigned long peer_mem_flags)
{
	int ret;
	const struct peer_memory_client *peer_mem = ib_peer_mem->peer_mem;
	struct invalidation_ctx *invalidation_ctx = NULL;
	struct ib_umem *umem = (struct ib_umem *)umem_ex;

	umem_ex->ib_peer_mem = ib_peer_mem;
	if (peer_mem_flags & IB_PEER_MEM_INVAL_SUPP) {
		ret = ib_peer_create_invalidation_ctx(ib_peer_mem, umem_ex, &invalidation_ctx);
		if (ret)
			goto end;
	}

	/*
	 * We always request write permissions to the pages, to force breaking of any CoW
	 * during the registration of the MR. For read-only MRs we use the "force" flag to
	 * indicate that CoW breaking is required but the registration should not fail if
	 * referencing read-only areas.
	 */
	ret = peer_mem->get_pages(addr, umem->length,
				  1, !umem->writable,
				  &umem->sg_head,
				  umem_ex->peer_mem_client_context,
				  invalidation_ctx ?
				  invalidation_ctx->context_ticket : 0);
	if (ret)
		goto out;

	umem->page_shift = ilog2(peer_mem->get_page_size
				 (umem_ex->peer_mem_client_context));
	if (BIT(umem->page_shift) <= 0)
		goto put_pages;

	ret = peer_mem->dma_map(&umem->sg_head,
				umem_ex->peer_mem_client_context,
				umem->context->device->dma_device,
				dmasync,
				&umem->nmap);
	if (ret)
		goto put_pages;

	atomic64_add(umem->nmap, &ib_peer_mem->stats.num_reg_pages);
	atomic64_add(umem->nmap * BIT(umem->page_shift), &ib_peer_mem->stats.num_reg_bytes);
	atomic64_inc(&ib_peer_mem->stats.num_alloc_mrs);
	return umem_ex;

put_pages:
	peer_mem->put_pages(&umem->sg_head, umem_ex->peer_mem_client_context);
out:
	if (invalidation_ctx)
		ib_peer_destroy_invalidation_ctx(ib_peer_mem, invalidation_ctx);
end:
	ib_put_peer_client(ib_peer_mem, umem_ex->peer_mem_client_context);
	// renamed in different kernel
	mmdrop(get_mm(umem));
	kfree(umem_ex);
	return ERR_PTR(ret);
}
#endif

struct ib_umem_ex *ib_umem_ex(struct ib_umem *umem)
{
	struct ib_umem_ex *ret_umem;

	if (!umem)
		return ERR_PTR(-EINVAL);

#ifndef MLX_PEER_SUPPORT
	ret_umem =  kzalloc(sizeof(*ret_umem), GFP_KERNEL);
	if (!ret_umem)
		return ERR_PTR(-ENOMEM);

	ret_umem->umem = *umem;
	kfree(umem);
#else
	ret_umem = (struct ib_umem_ex *)umem;
#endif
	return ret_umem;
}

struct ib_umem_ex *ib_client_umem_get(struct ib_ucontext *context,
				      unsigned long addr,
				      size_t size, int access,
				      int dmasync, u8 *peer_exists)
{
#if defined(IB_CORE_UMEM_EX_V1) || defined(IB_CORE_UMEM_EX_V2)
	struct ib_peer_memory_client *peer_mem_client;
	struct ib_umem_ex *umem_ex;
	struct ib_umem *umem;

	/*
	 * If the combination of the addr and size requested for this memory
	 * region causes an integer overflow, return error.
	 */
	if (((addr + size) < addr) ||
	    PAGE_ALIGN(addr + size) < (addr + size))
		return ERR_PTR(-EINVAL);

	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	umem_ex = kzalloc(sizeof(*umem_ex), GFP_KERNEL);
	if (!umem_ex)
		return ERR_PTR(-ENOMEM);
	umem = &umem_ex->umem;

	umem->context    = context;
	umem->length     = size;
	umem->address    = addr;
	umem->writable   = ib_access_writable(access);
	get_mm(umem) = current->mm;

#if defined(IB_CORE_UMEM_EX_V1)
	umem->odp_data = NULL;
#endif

	mmgrab(get_mm(umem));

	peer_mem_client = ib_get_peer_client(context, addr, size,
					     IB_PEER_MEM_ALLOW | IB_PEER_MEM_INVAL_SUPP,
					     &umem_ex->peer_mem_client_context);
	if (peer_mem_client) {
		*peer_exists = 1;
		umem->hugetlb = 0;
		return peer_umem_get(peer_mem_client, umem_ex, addr, dmasync,
					IB_PEER_MEM_ALLOW | IB_PEER_MEM_INVAL_SUPP);
	}

	return ERR_PTR(-ENOMEM);
#else
	return NULL;
#endif
}

void ib_umem_ex_release(struct ib_umem_ex *umem_ex)
{
	struct ib_umem *umem = (struct ib_umem *)umem_ex;
#if defined(IB_CORE_UMEM_EX_V1) || defined(IB_CORE_UMEM_EX_V2)
	struct ib_peer_memory_client *ib_peer_mem = umem_ex->ib_peer_mem;
	const struct peer_memory_client *peer_mem;
	struct invalidation_ctx *invalidation_ctx;

	if (ib_peer_mem) {
		peer_mem = ib_peer_mem->peer_mem;
		invalidation_ctx = umem_ex->invalidation_ctx;

		if (invalidation_ctx)
			ib_peer_destroy_invalidation_ctx(ib_peer_mem, invalidation_ctx);

		peer_mem->dma_unmap(&umem->sg_head,
				umem_ex->peer_mem_client_context,
				umem->context->device->dma_device);
		peer_mem->put_pages(&umem->sg_head,
				umem_ex->peer_mem_client_context);
		atomic64_add(umem->nmap, &ib_peer_mem->stats.num_dereg_pages);
		atomic64_add(umem->nmap * BIT(umem->page_shift),
			     &ib_peer_mem->stats.num_dereg_bytes);
		atomic64_inc(&ib_peer_mem->stats.num_dealloc_mrs);
		ib_put_peer_client(ib_peer_mem, umem_ex->peer_mem_client_context);
		kfree(umem_ex);
	} else {
		// kernel ib umem release
		ib_umem_release(umem);
	}
#else
	ib_umem_release(umem);
#endif
}

int ib_client_umem_activate_invalidation_notifier(struct ib_umem_ex *umem_ex,
						  umem_invalidate_func_t func,
						  void *cookie)
{
#if defined(IB_CORE_UMEM_EX_V1) || defined(IB_CORE_UMEM_EX_V2)
	struct invalidation_ctx *invalidation_ctx = umem_ex->invalidation_ctx;
	int ret = 0;

	mutex_lock(&umem_ex->ib_peer_mem->lock);
	if (invalidation_ctx->peer_invalidated) {
		pr_err("ib_umem_activate_invalidation_notifier: pages were invalidated by peer\n");
		ret = -EINVAL;
		goto end;
	}
	invalidation_ctx->func = func;
	invalidation_ctx->cookie = cookie;
	/* from that point any pending invalidations can be called */
end:
	mutex_unlock(&umem_ex->ib_peer_mem->lock);
	return ret;
#else
	return 0;
#endif
}

