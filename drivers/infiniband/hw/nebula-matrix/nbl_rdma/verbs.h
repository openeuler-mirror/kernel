/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_VERBS_H
#define NBL_VERBS_H

#include "osdep.h"

struct nbl_cq_buf {
	struct nbl_dma_mem kmem_buf;
	struct nbl_cq_uk cq_uk;
	struct nbl_hw *hw;
	struct list_head list;
	struct work_struct work;
};

struct nbl_ib_cq_buf {
	struct nbl_frag_buf frag_buf;
	struct ib_umem *umem;
};

struct nbl_cq {
	struct ib_cq ibcq;
	struct nbl_sc_cq sc_cq;
	u32 cq_head;
	u32 cq_size; /* cqe num */
	u32 cq_num; /*rsrc index */
	u32 cq_pg_num; /* page num of memory for cq QUEUE*/
	bool user_mode; /*userspace or kernel create cq*/
	atomic_t armed;
	enum nbl_cmpl_notify last_notify;
	bool pa_continuous;
	struct nbl_dma_mem kmem;
	struct nbl_dma_mem kmem_shadow;
	struct completion free_cq;
	refcount_t refcnt;
	spinlock_t lock; /* for poll cq */
	struct nbl_cq_poll_info cur_cqe;
	struct nbl_ib_cq_buf buf;
	u32 pre_num;
	struct list_head wc_list; /* for qp err cqe poll */
	struct list_head pre_list; /* first put sw cqe here */
	bool ceq_suspend; /* suspend ceq report */
};

struct nbl_ib_wc {
	struct nbl_cq_poll_info info;
	struct list_head list;
	struct nbl_uk_qp *ukqp;
	bool is_sq;
};

#endif /* NBL_VERBS_H */
