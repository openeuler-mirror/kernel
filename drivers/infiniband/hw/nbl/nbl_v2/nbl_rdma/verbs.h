/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_VERBS_H
#define NBL_VERBS_H

#include "osdep.h"

struct nbl_cq_buf {
	struct nbl_cq_uk cq_uk;
	struct nbl_hw *hw;
	struct list_head list;
	struct work_struct work;
};

struct nbl_user_rsize {
	struct nbl_buf_desc bdes;
	struct list_head list;
};

struct nbl_cq {
	struct ib_cq ibcq;
	struct nbl_sc_cq sc_cq;
	u32 cq_num; /*rsrc index */
	bool user_mode; /*userspace or kernel create cq*/
	atomic_t armed;
	enum nbl_cmpl_notify last_notify;
	struct completion free_cq;
	refcount_t refcnt;
	spinlock_t lock; /* for poll cq */
	struct nbl_cq_poll_info cur_cqe;
	u8 sw_sel_cnt;
	u32 pre_num;
	struct list_head wc_list; /* for qp err cqe poll */
	struct list_head pre_list; /* first put sw cqe here */
	struct list_head resize_list;
	struct list_head u_resize_list; /* user mode resize use */
	u8 arm_seq_num;
	struct nbl_ucontext *uctx;
};

struct nbl_ib_wc {
	struct nbl_cq_poll_info info;
	struct list_head list;
	struct nbl_uk_qp *ukqp;
	bool is_sq;
};

struct nbl_ib_subq_buf {
	struct nbl_frag_buf frag_buf;
	struct ib_umem *umem;
	bool nbl_peer;
};

struct nbl_srq_subq {
	u8 subq_id;
	u8 page_mode;
	struct nbl_dma_mem mem;
	struct nbl_ib_subq_buf subq_buf;
	bool nxt_wqe_phase;
	bool sw_srq_pi_phase;
	/* only kernel subq need following attrs */
	u32 buf_size;
	u32 buf_quanta;
	u16 pi;
	u16 ci;
	bool has_pi;
	bool has_ci;
	u16 finish_wqe_count;
	u16 max_wqe;
	struct nbl_srq_subq *prevq;
	struct nbl_srq_subq *nextq;
};

struct nbl_srq {
	struct ib_srq ibsrq;
	spinlock_t lock;
	struct mutex mutex;
	u32 srqn;
	u32 wqe_ts;
	u32 cqn; /* XRC only */
	u32 xrcdn; /* XRC only */
	u32 max_wr;
	u32 max_wr_shift;
	u32 wqe_quanta;
	u32 max_sge;
	u32 subq_buf_quanta;
	u8 user_mode;
	u64 *wrid;
	struct nbl_srq_subq **subq_arr;
	/* only kernel subq need cur and tail ptr */
	struct nbl_srq_subq *cur_subq;
	struct nbl_srq_subq *tail_subq;
	struct nbl_dma_mem shdw; /* shaodw, va for RW shadow, pa for CQP */
	u64 __iomem *srq_db0;
	u64 __iomem *srq_db1;
	/* default is 16, when pi - ci <= this val, sw ring srq db */
	u16 hw_srq_ci_rth;
	refcount_t refcnt; /* for aeqe protect */
	struct completion free_srq;
	struct nbl_device *nbldev;
	/* seq_num identifies different srq using same srqn */
	u8 seq_num;
	/* db0 count, set to 0 when flip pi, knock db0 when this count less than 3 */
	u8 db0_count;
	/*init as 0, when switch to next subq, nxt_queue_num add 1 */
	u8 nxt_queue_num;
};

struct nbl_xrcd {
	struct ib_xrcd ibxrcd;
	u32 xrcdn;
};

#endif /* NBL_VERBS_H */
