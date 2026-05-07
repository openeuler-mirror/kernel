/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_MR_H
#define NBL_IB_MR_H

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>

#include "nbl_adapt.h"

#define NBL_CQPSQ_MR_STAT GENMASK_ULL(47, 46)
#define NBL_CQPSQ_MR_RIGHTS GENMASK_ULL(43, 38)
#define NBL_CQPSQ_MR_TYPE GENMASK_ULL(45, 44)
#define NBL_CQPSQ_MR_IDX GENMASK_ULL(63, 40)
#define NBL_CQPSQ_MR_KEY GENMASK_ULL(7, 0)
#define NBL_CQPSQ_MR_PDN GENMASK_ULL(31, 8)
#define NBL_CQPSQ_MR_INV BIT_ULL(37)
#define NBL_CQPSQ_MR_LEAF_SIZE BIT_ULL(35)
#define NBL_CQPSQ_MR_HOST_PGSZ GENMASK_ULL(34, 33)
#define NBL_CQPSQ_MR_ADDR_TYPE BIT_ULL(32)
#define NBL_CQPSQ_MR_LEN GENMASK_ULL(63, 18)
#define NBL_CQPSQ_MR_VA GENMASK_ULL(63, 0)
#define NBL_CQPSQ_FIRST_PBL_ID GENMASK_ULL(27, 0)
#define NBL_CQPSQ_LAST_PBL_ID GENMASK_ULL(63, 36)

#define NBL_DUMP_MRT_MSG_SIZE 100

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
	struct nbl_pbl pbl;
	int access_flags; /* needed for rereg MR */
	u32 sys_page_offset;
};

#ifndef bits_per
static inline int __bits_per(unsigned long n)
{
	if (n < 2)
		return 1;
	if (is_power_of_2(n))
		return order_base_2(n) + 1;
	return order_base_2(n);
}

#define bits_per(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		((n) == 0 || (n) == 1)		\
			? 1 : ilog2(n) + 1	\
	) :					\
	__bits_per(n)				\
)
#endif

#ifndef count_trailing_zeros
static inline int count_trailing_zeros(unsigned long x)
{
#define COUNT_TRAILING_ZEROS_0 (-1)

	if (sizeof(x) == 4)
		return ffs(x);
	else
		return (x != 0) ? __ffs(x) : COUNT_TRAILING_ZEROS_0;
}
#endif

static inline struct nbl_mr *to_nbl_mr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct nbl_mr, ibmr);
}
u16 nbl_get_mr_access(struct nbl_device *nbldev, int access);
struct ib_mr *nbl_ib_reg_user_mr_dmabuf(struct ib_pd *pd, u64 start,
		u64 len, u64 virt, int fd, int access, struct ib_udata *udata);

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
