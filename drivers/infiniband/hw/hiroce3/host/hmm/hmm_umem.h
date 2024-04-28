/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef HMM_UMEM_H
#define HMM_UMEM_H

#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/mmu_notifier.h>
#include <linux/kernel.h>

#ifdef ROCE_SERVICE
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#endif


#ifndef ROCE_SERVICE

enum rdma_remove_reason {
	/* Userspace requested uobject deletion. Call could fail */
	RDMA_REMOVE_DESTROY,
	/* Context deletion. This call should delete the actual object itself */
	RDMA_REMOVE_CLOSE,
	/* Driver is being hot-unplugged. This call should delete the actual object itself */
	RDMA_REMOVE_DRIVER_REMOVE,
	/* Context is being cleaned-up, but commit was just completed */
	RDMA_REMOVE_DURING_CLEANUP,
};

struct ib_uverbs_file;
struct ib_rdmacg_object {};
struct rb_root_cached_struct {
	struct rb_node *rb_root;
	struct rb_node *rb_leftmost;
};

struct ib_ucontext {
	struct device *device;
	struct ib_uverbs_file *ufile;
	int closing;

	/* locking the uobjects_list */
	struct mutex uobjects_lock;
	struct list_head uobjects;
	/* protects cleanup process from other actions */
	struct rw_semaphore cleanup_rwsem;
	enum rdma_remove_reason cleanup_reason;

	struct pid *tgid;
	struct rb_root_cached_struct umem_tree;
	/*
	 * Protects .umem_rbroot and tree, as well as odp_mrs_count and
	 * mmu notifiers registration.
	 */
	struct rw_semaphore umem_rwsem;
	void (*invalidate_range)(void *umem, unsigned long start, unsigned long end);

	struct mmu_notifier mn;
	atomic_t notifier_count;
	/* A list of umems that don't have private mmu notifier counters yet. */
	struct list_head no_private_counters;
	int odp_mrs_count;

	struct ib_rdmacg_object cg_obj;
};

struct ib_umem_odp;

struct hmm_umem *hmm_umem_get(struct device *device, unsigned long addr,
	size_t size, int access, int dmasync);

void hmm_umem_release(struct hmm_umem *hmem);

#endif

struct hmm_umem {
	struct ib_ucontext *context;
	size_t length;
	unsigned long address;
	int page_shift;
	int writable;
	int hugetlb;
	struct work_struct work;
	struct mm_struct *mm;
	unsigned long diff;
	struct ib_umem_odp *odp_data;
	struct sg_table sg_head;
	int nmap;
	int npages;
};


/* Returns the offset of the umem start relative to the first page. */
static inline int hmm_umem_offset(const struct hmm_umem *umem)
{
	return umem->address & ~PAGE_MASK;
}

/* Returns the first page of an ODP umem. */
static inline unsigned long hmm_umem_start(struct hmm_umem *umem)
{
	return umem->address - hmm_umem_offset(umem);
}

/* Returns the address of the page after the last one of an ODP umem. */
static inline unsigned long hmm_umem_end(const struct hmm_umem *umem)
{
	return ALIGN(umem->address + umem->length, BIT((unsigned int)umem->page_shift));
}

static inline size_t hmm_umem_num_pages(struct hmm_umem *umem)
{
	return (size_t)(((unsigned long)(hmm_umem_end(umem) -
		hmm_umem_start(umem))) >> (unsigned long)umem->page_shift);
}

u32 hmm_umem_page_count(struct hmm_umem *hmem);


#endif /* HMM_UMEM_H */
