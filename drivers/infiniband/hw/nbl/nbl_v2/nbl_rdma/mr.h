/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_MR_H
#define NBL_IB_MR_H

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>

#include "nbl_adapt.h"

#define NBL_DUMP_MRT_MSG_SIZE 100
#define NBL_MR_KEY_MASK 0xFF
#define NBL_MR_INDEX_SHIFT 8

#define NBL_PBL_KEY_MASK 0x7ff
#define NBL_PBL_KEY_BEGIN 1

enum nbl_mr_stat {
	NBL_MR_STAT_INVALID = 0,
	NBL_MR_STAT_FREE = 1,
	NBL_MR_STAT_VALID = 2,
	NBL_MR_STAT_MAX,
};

enum nbl_mr_type {
	NBL_MR_TYPE_MR = 0,
	NBL_MR_TYPE_MW1 = 1,
	NBL_MR_TYPE_MW2A = 2,
	NBL_MR_TYPE_MW2B = 3,
	NBL_MR_TYPE_MAX,
};

enum nbl_mr_rights {
	NBL_MR_RIGHTS_BIND = 1,
	NBL_MR_RIGHTS_ATOMIC = 2,
	NBL_MR_RIGHTS_RW = 4,
	NBL_MR_RIGHTS_RR = 8,
	NBL_MR_RIGHTS_LW = 16,
	NBL_MR_RIGHTS_LR = 32,
	NBL_MR_RIGHTS_MAX,
};

enum nbl_page_size {
	NBL_PAGE_SIZE_4K = 0,
	NBL_PAGE_SIZE_2M,
	NBL_PAGE_SIZE_1G,
	NBL_PAGE_SIZE_64K,
};

enum nbl_leaf_size {
	NBL_MR_NOT_ALLOCATE_PBLE = 0,
	NBL_MR_ALLOVATE_PBLE,
};

enum nbl_mr_inv_competence {
	NBL_MR_NOT_ALLOW_INV = 0,
	NBL_MR_ALLOW_INV,
};

enum nbl_mr_branch_type {
	NBL_MR_BRANCH_NORMAL = 0,
	NBL_MR_BRANCH_ZERO_COPY = 1,
};

struct reg_mr_cmd_req {
	__be32 stag;
	/* TBD */
};

struct nbl_pbl {
	struct list_head list;
	bool pbl_allocated : 1;
	u64 usr_base;
	struct nbl_pble_alloc pble_alloc;
	struct nbl_mr *mr;
};

struct nbl_mr {
	union {
		struct ib_mr ibmr;
		struct ib_mw ibmw;
	};
	struct ib_umem *region;
	u32 page_cnt;
	u64 page_sz;
	u64 pg_mask;
	u32 npages;
	u32 stag;
	u64 len;
	u64 pa;
	u32 pbl_key;
	struct nbl_pbl pbl;
	int access_flags; /* needed for rereg MR */
	bool allocated_region; /* whetehr to pin and dma userspace memory or not */
	bool nbl_peer;
	u32 sys_page_offset;
};

static inline struct nbl_mr *to_nbl_mr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct nbl_mr, ibmr);
}

u16 nbl_get_mr_access(struct nbl_device *nbldev, int access);

struct ib_mr *nbl_ib_reg_user_mr_dmabuf(struct ib_pd *pd, u64 start,
		u64 len, u64 virt, int fd, int access,
		struct ib_udata *udata);

struct ib_mr *nbl_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				 u64 iova, int access_flags,
				 struct ib_udata *udata);
int nbl_ib_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata);

struct ib_mr *nbl_ib_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			      u32 max_num_sg);
struct ib_mr *nbl_ib_get_dma_mr(struct ib_pd *pd, int access);
int nbl_ib_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata);
int nbl_ib_dealloc_mw(struct ib_mw *ibmw);
int nbl_ib_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_ents,
		     unsigned int *sg_offset);
void nbl_ib_mmap_free(struct rdma_user_mmap_entry *rdma_entry);
int nbl_ib_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma);
struct ib_mr *nbl_ib_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				   u64 length, u64 virt_addr,
				   int new_access_flags, struct ib_pd *new_pd,
				   struct ib_udata *udata);

#endif /* NBL_IB_MR_H */
