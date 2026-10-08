/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_WR_H
#define NBL_IB_WR_H

#include <rdma/ib_verbs.h>
#include "nbl_adapt.h"
#include "qp.h"
#include "ah.h"
#include "pble.h"
#include "mr.h"
#include "mem.h"
#include "srq.h"

/* NOP WQE IS 1*64bytes */
#define NOP_WQE_QUANTA 1
#define SAFE_CLEAN_WQE_LENGTH 128
#define MAX_HW_SQ_CHUNK 2

#define NBL_SQ_RING_FREE_QUANTA(_ring)                                         \
	((_ring).size - NBL_SQ_RING_SED_QUANTA(_ring))

#define NBL_SQ_RING_SED_QUANTA(_ring)                                          \
	((((_ring).head + (_ring).size - (_ring).tail) % (_ring).size))

int _nbl_ib_post_send(struct ib_qp *ib_qp, const struct ib_send_wr *wr,
		      const struct ib_send_wr **bad_wr);
int _nbl_ib_post_send_v2(struct ib_qp *ib_qp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr);
int _nbl_ib_post_recv(struct ib_qp *ib_qp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr);
int _nbl_ib_post_recv_v2(struct ib_qp *ib_qp, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr);
int nbl_ib_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
				const struct ib_recv_wr **bad_wr);
static inline int nbl_ib_post_send_v2(struct ib_qp *ibqp,
				      const struct ib_send_wr *wr,
				      const struct ib_send_wr **bad_wr)
{
	return _nbl_ib_post_send_v2(ibqp, wr, bad_wr);
}

static inline int nbl_ib_post_send(struct ib_qp *ibqp,
				   const struct ib_send_wr *wr,
				   const struct ib_send_wr **bad_wr)
{
	return 0;
}

static inline int nbl_ib_post_recv_v2(struct ib_qp *ibqp,
				      const struct ib_recv_wr *wr,
				      const struct ib_recv_wr **bad_wr)
{
	return _nbl_ib_post_recv_v2(ibqp, wr, bad_wr);
}

static inline int nbl_ib_post_recv(struct ib_qp *ibqp,
				   const struct ib_recv_wr *wr,
				   const struct ib_recv_wr **bad_wr)
{
	return 0;
}
void nbl_set_sge_vld(void *wqe, int num_sge, bool vld);
void nbl_fill_32Byte_rsv_vld(__u32 sge_num, __u8 *wqe, bool wqe_vld,
			     __u8 cur_size);
int nbl_umr_post_send(struct ib_qp *ib_qp, struct ib_cqe *cqe,
	struct umr_wr *umrwr);
#endif /* NBL_IB_WR_H */
