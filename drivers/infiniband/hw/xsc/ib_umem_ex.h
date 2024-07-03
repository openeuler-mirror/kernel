/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_IB_UMEM_EX_H
#define XSC_IB_UMEM_EX_H

#include <rdma/ib_umem.h>

struct ib_umem_ex;
struct invalidation_ctx;

// ib umem ex ib_umem add peer memory support
struct ib_umem_ex {
	struct ib_umem umem;
#ifndef MLX_PEER_SUPPORT
	struct ib_peer_memory_client *ib_peer_mem;
	struct invalidation_ctx *invalidation_ctx;
	void *peer_mem_client_context;
#endif
};

// expand ib_umem to ib_umem_ex by reallocate
struct ib_umem_ex *ib_umem_ex(struct ib_umem *umem);

#ifndef MLX_PEER_SUPPORT
typedef void (*umem_invalidate_func_t)(void *invalidation_cookie,
	struct ib_umem_ex *umem_ex, unsigned long addr, size_t size);

struct invalidation_ctx {
	struct ib_umem_ex *umem_ex;
	u64 context_ticket;
	umem_invalidate_func_t func;
	void *cookie;
	int peer_callback;
	int inflight_invalidation;
	int peer_invalidated;
	struct completion comp;
};
#endif

struct ib_umem_ex *ib_client_umem_get(struct ib_ucontext *context,
				      unsigned long addr, size_t size, int access,
				      int dmasync, u8 *peer_exists);

void ib_umem_ex_release(struct ib_umem_ex *umem_ex);

int ib_client_umem_activate_invalidation_notifier(struct ib_umem_ex *umem_ex,
						  umem_invalidate_func_t func,
						  void *cookie);
#endif
