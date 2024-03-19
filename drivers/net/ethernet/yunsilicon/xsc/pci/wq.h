/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_WQ_H__
#define __XSC_WQ_H__

#include "common/cq.h"
#include "common/qp.h"

struct xsc_wq_param {
	int		buf_numa_node;
	int		db_numa_node;
};

struct xsc_wq_ctrl {
	struct xsc_core_device	*xdev;
	struct xsc_frag_buf	buf;
	struct xsc_db		db;
};

struct xsc_wq_cyc {
	struct xsc_frag_buf_ctrl fbc;
	u16			sz;
	u16			wqe_ctr;
	u16			cur_sz;
};

struct xsc_cqwq {
	struct xsc_frag_buf_ctrl fbc;
	__be32			  *db;
	u32			  cc; /* consumer counter */
};

enum xsc_res_type {
	XSC_RES_UND	= 0,
	XSC_RES_RQ,
	XSC_RES_SQ,
	XSC_RES_MAX,
};

u32 xsc_wq_cyc_get_size(struct xsc_wq_cyc *wq);

int xsc_buf_alloc_node(struct xsc_core_device *dev, int size,
		       struct xsc_frag_buf *buf, int node);

/*api for eth driver*/
int xsc_eth_cqwq_create(struct xsc_core_device *xdev, struct xsc_wq_param *param,
			u8 q_log_size, u8 ele_log_size, struct xsc_cqwq *wq,
			struct xsc_wq_ctrl *wq_ctrl);

int xsc_eth_wq_cyc_create(struct xsc_core_device *xdev, struct xsc_wq_param *param,
			  u8 q_log_size, u8 ele_log_size, struct xsc_wq_cyc *wq,
			  struct xsc_wq_ctrl *wq_ctrl);
void xsc_eth_wq_destroy(struct xsc_wq_ctrl *wq_ctrl);

static inline void xsc_init_fbc_offset(struct xsc_buf_list *frags,
				       u8 log_stride, u8 log_sz,
				       u16 strides_offset,
				       struct xsc_frag_buf_ctrl *fbc)
{
	fbc->frags      = frags;
	fbc->log_stride = log_stride;
	fbc->log_sz     = log_sz;
	fbc->sz_m1	= (1 << fbc->log_sz) - 1;
	fbc->log_frag_strides = PAGE_SHIFT - fbc->log_stride;
	fbc->frag_sz_m1	= (1 << fbc->log_frag_strides) - 1;
	fbc->strides_offset = strides_offset;
}

static inline void xsc_init_fbc(struct xsc_buf_list *frags,
				u8 log_stride, u8 log_sz,
				struct xsc_frag_buf_ctrl *fbc)
{
	xsc_init_fbc_offset(frags, log_stride, log_sz, 0, fbc);
}

static inline void *xsc_frag_buf_get_wqe(struct xsc_frag_buf_ctrl *fbc,
					 u32 ix)
{
	unsigned int frag;

	ix  += fbc->strides_offset;
	frag = ix >> fbc->log_frag_strides;

	return fbc->frags[frag].buf + ((fbc->frag_sz_m1 & ix) << fbc->log_stride);
}

static inline u32
xsc_frag_buf_get_idx_last_contig_stride(struct xsc_frag_buf_ctrl *fbc, u32 ix)
{
	u32 last_frag_stride_idx = (ix + fbc->strides_offset) | fbc->frag_sz_m1;

	return min_t(u32, last_frag_stride_idx - fbc->strides_offset, fbc->sz_m1);
}

static inline int xsc_wq_cyc_missing(struct xsc_wq_cyc *wq)
{
	return wq->sz - wq->cur_sz;
}

static inline int xsc_wq_cyc_is_empty(struct xsc_wq_cyc *wq)
{
	return !wq->cur_sz;
}

static inline void xsc_wq_cyc_push(struct xsc_wq_cyc *wq)
{
	wq->wqe_ctr++;
	wq->cur_sz++;
}

static inline void xsc_wq_cyc_push_n(struct xsc_wq_cyc *wq, u8 n)
{
	wq->wqe_ctr += n;
	wq->cur_sz += n;
}

static inline void xsc_wq_cyc_pop(struct xsc_wq_cyc *wq)
{
	wq->cur_sz--;
}

static inline u16 xsc_wq_cyc_ctr2ix(struct xsc_wq_cyc *wq, u16 ctr)
{
	return ctr & wq->fbc.sz_m1;
}

static inline u16 xsc_wq_cyc_get_head(struct xsc_wq_cyc *wq)
{
	return xsc_wq_cyc_ctr2ix(wq, wq->wqe_ctr);
}

static inline u16 xsc_wq_cyc_get_tail(struct xsc_wq_cyc *wq)
{
	return xsc_wq_cyc_ctr2ix(wq, wq->wqe_ctr - wq->cur_sz);
}

static inline void *xsc_wq_cyc_get_wqe(struct xsc_wq_cyc *wq, u16 ix)
{
	return xsc_frag_buf_get_wqe(&wq->fbc, ix);
}

static inline u32 xsc_cqwq_ctr2ix(struct xsc_cqwq *wq, u32 ctr)
{
	return ctr & wq->fbc.sz_m1;
}

static inline u32 xsc_cqwq_get_ci(struct xsc_cqwq *wq)
{
	return xsc_cqwq_ctr2ix(wq, wq->cc);
}

static inline u32 xsc_cqwq_get_ctr_wrap_cnt(struct xsc_cqwq *wq, u32 ctr)
{
	return ctr >> wq->fbc.log_sz;
}

static inline u32 xsc_cqwq_get_wrap_cnt(struct xsc_cqwq *wq)
{
	return xsc_cqwq_get_ctr_wrap_cnt(wq, wq->cc);
}

static inline void xsc_cqwq_pop(struct xsc_cqwq *wq)
{
	wq->cc++;
}

#endif /* __XSC_WQ_H__ */
