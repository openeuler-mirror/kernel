/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * OBMM memory backends: refcounted objects attachable to a region shell.
 */
#ifndef OBMM_BACKEND_H
#define OBMM_BACKEND_H

#include <linux/refcount.h>
#include <linux/types.h>
#include "obmm_core.h"		/* struct obmm_region, resource handles */

/* Kernel-side creation specs; no uapi types or field encoding. */

/* uapi obmm_cmd_import fields; @remote/@preimport carry its flags. */
struct obmm_import_spec {
	u64 addr;
	u32 scna;
	u32 dcna;
	int numa_id;
	u8 base_dist;
	u8 seid[16];
	u8 deid[16];
	bool remote;
	bool preimport;
};

/* uapi obmm_cmd_export inputs; @vendor_info is a kernel buffer. */
struct obmm_export_pool_spec {
	u64 size[OBMM_MAX_LOCAL_NUMA_NODES];
	u32 node_count;
	int pxm_numa;
	u64 export_flags;
	u8 deid[16];
	void *vendor_info;
	u32 vendor_len;
};

/* uapi obmm_cmd_export_pid inputs; no flags, memory never mmapable. */
struct obmm_export_user_spec {
	int pid;
	void __user *user_va;
	u64 length;
	int pxm_numa;
	u8 deid[16];
	void *vendor_info;
	u32 vendor_len;
};

/* vendor_info ownership, both export specs: handed off at the creator call,
 * which consumes it on every path - stored in the backend (freed by destroy)
 * or freed on kzalloc failure; callers must not free or reuse it after.
 */

enum obmm_backend_type {
	OBMM_BACKEND_IMPORT,
	OBMM_BACKEND_EXPORT_POOLED,
	OBMM_BACKEND_EXPORT_USER,
};

struct obmm_backend;

/*
 * PTE install + cache maintenance + identity, per backend type. fault is
 * NULL only for a non-mmappable backend (mem_cap == 0), which the mmap
 * capability check rejects before a VMA can exist.
 *
 * Locks: query under the region's state_mutex, fault under the fault-gate
 * read lock, covers_pa under each pinned shell's state_mutex; flush_range
 * runs under state_mutex except in the switch windows and the backend
 * destroy after the last put, which run it unlocked.
 */
struct obmm_backend_ops {
	vm_fault_t (*fault)(struct obmm_backend *be, struct vm_fault *vmf,
			    bool is_pmd);
	/* validated ops only - never INFER (flush_cache_by_pa OOB hazard) */
	int (*flush_range)(struct obmm_backend *be, u64 off, u64 len,
			   u8 cache_ops);
	int (*query)(struct obmm_backend *be, struct obmm_ext_addr *out);
	/* @out: nullable; when set, backend-shaped detail for the range */
	bool (*covers_pa)(struct obmm_backend *be, u64 pa, u64 len,
			  struct obmm_ext_addr *out);
	int (*destroy)(struct obmm_backend *be);	/* freed regardless */
};

struct obmm_backend {
	refcount_t refcnt;		/* existence ref + attachment ref */
	enum obmm_backend_type type;
	u64 mem_size;
	u32 mem_cap;			/* OBMM_MEM_ALLOW_*_MMAP bits */
	u32 regionid;			/* cached at attach; immutable, so the
					 * spinlock-only by-PA walk needs no
					 * shell dereference
					 */
	const struct obmm_backend_ops *ops;
	struct obmm_region *shell;	/* state_mutex-guarded, NULL detached */
};

struct obmm_import_backend {
	struct obmm_backend base;
	u64 pa;
	u32 scna;
	u32 dcna;
	u8 seid[16];
	u8 deid[16];
	u8 base_dist;
	bool numa_remote:1;		/* classification from import flags */
	bool preimport:1;		/* classification from import flags */
	int numa_id;
	/* void * per obmm_preimport.h handle convention */
	void *preimport_handle;
	/* DIRECT_IMPORT_UBMEM resource, lifetime == backend; the MEMID leaf
	 * (memdev_res) is shell-owned and attach-managed, not here.
	 */
	struct ubmem_resource *ubmem_res;
};

/* Fields shared by both export variants; each allocates an sg_table and
 * runs setup_ummu, only the memory source differs.
 */
struct obmm_export_common {
	/* pool: memsegs merged; user: pinned pages */
	struct sg_table sgt;
	struct device *ummu_dev;	/* ummu_core_alloc_tdev return type */
	u32 tokenid;
	u64 uba;
	void *vendor_info;
	u32 vendor_len;
	u8 deid[16];
	int affinity;			/* pxm_numa as passed in */
	u64 node_mem_size[OBMM_MAX_LOCAL_NUMA_NODES];
	int node_count;
};

struct obmm_export_pool_backend {	/* EXPORT_POOLED */
	struct obmm_backend base;
	struct obmm_export_common exp;
	/* Per-node memseg lists, input to allocate_memory_contiguous/
	 * free_memory_contiguous/sg_alloc_table_from_memdesc.
	 */
	struct mem_description_pool desc;
};

struct obmm_export_user_backend {	/* EXPORT_USER */
	struct obmm_backend base;
	struct obmm_export_common exp;
	/* pid-path description; pages live in exp.sgt, no length field */
	int pid;
	void __user *user_va;
	int pinned;
	u64 start_time;
};

static inline struct obmm_import_backend *
obmm_backend_to_import(struct obmm_backend *be)
{
	return container_of(be, struct obmm_import_backend, base);
}

static inline struct obmm_export_pool_backend *
obmm_backend_to_export_pool(struct obmm_backend *be)
{
	return container_of(be, struct obmm_export_pool_backend, base);
}

static inline struct obmm_export_user_backend *
obmm_backend_to_export_user(struct obmm_backend *be)
{
	return container_of(be, struct obmm_export_user_backend, base);
}

/* container_of for BOTH export types; NULL for an import backend */
static inline struct obmm_export_common *
obmm_backend_to_export_common(struct obmm_backend *be)
{
	if (be->type == OBMM_BACKEND_EXPORT_POOLED)
		return &obmm_backend_to_export_pool(be)->exp;
	if (be->type == OBMM_BACKEND_EXPORT_USER)
		return &obmm_backend_to_export_user(be)->exp;
	return NULL;
}

/* Creation: each creator returns an object with refcnt == 1 (the existence
 * reference) or an ERR_PTR. @remote/@preimport are pre-validated in
 * obmm_import.c, so the creator switches only on booleans; the restricted
 * entry (full == false, switch target) rejects them with -EOPNOTSUPP.
 */
struct obmm_backend *
obmm_import_backend_create(const struct obmm_import_spec *spec,
			   u64 mem_size, bool full);
struct obmm_backend *
obmm_export_pool_backend_create(const struct obmm_export_pool_spec *spec,
				u64 mem_size);
struct obmm_backend *
obmm_export_user_backend_create(const struct obmm_export_user_spec *spec);

/* Attach/detach/put lifetime contract.
 *
 * attach (state_mutex held): takes the ATTACHMENT reference and, for import
 * backends, creates the MEMID_{regionid} iomem leaf. On failure it is
 * reference-neutral: no refcount_inc, no promised_cap change, no leaf.
 *
 * detach (state_mutex held): drops only the attachment reference and returns
 * the backend; the caller owns the EXISTENCE reference and must
 * obmm_backend_put it on success. A failed MEMID release sets *errp and must
 * never be followed by the put - destroy would free the parent resource under
 * the unreleased leaf, so the backend leaks loudly instead. errp non-NULL
 * propagates that errno, NULL logs; switch paths pass NULL deliberately.
 *
 * put drops one reference; at the last put it runs ops->destroy and returns
 * its result (the object is freed regardless).
 */
int obmm_backend_attach(struct obmm_region *reg, struct obmm_backend *be);
struct obmm_backend *obmm_backend_detach(struct obmm_region *reg, int *errp);
int obmm_backend_put(struct obmm_backend *be);

/* Creation-ioctl publish tail: attach_or_put + register + activate, with the
 * full shell unwind on failure (backend released with propagate == false,
 * uninit, device put). A failure returns the errno with everything torn
 * down; callers read their ioctl output off the backend first.
 */
int obmm_region_publish(struct obmm_region *reg, struct obmm_backend *be,
			const char *kind);

/* Unified detach + put release under the site's error policy: unimport and
 * unexport pass @propagate_detach_err true (a failed detach or destroy
 * aborts the teardown); creation-path unwinds pass false (warn-only, the
 * register error stands). Full matrix in obmm_backend.c.
 */
int obmm_region_release_backend(struct obmm_region *reg, bool propagate_detach_err);

#endif /* OBMM_BACKEND_H */
