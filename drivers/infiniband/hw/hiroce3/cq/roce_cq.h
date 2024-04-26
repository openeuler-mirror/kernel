/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_CQ_H
#define ROCE_CQ_H

#include <rdma/ib_verbs.h>
#include <linux/slab.h>

#include "hinic3_hw.h"
#include "hinic3_rdma.h"

#include "rdma_context_format.h"

#include "roce.h"
#include "roce_compat.h"
#include "roce_srq.h"
#include "roce_xrc.h"
#include "roce_user.h"
#include "hinic3_hmm.h"

#define ROCE_CQN_INVLD 0xFFFFFFFF

/* DB type of ARM_CQ */
enum {
	ROCE_CQ_DB_REQ_NOT_SOL = 1,
	ROCE_CQ_DB_REQ_NOT = 2
};

#define CQ_GPA_SIG_LEN 3
#define CQ_DW_TO_BYTE 4

/* the type of err cqe
 * IB compliant completion with error syndrome:
 *		0x01 - Local Length Error ()
 *		0x02 - Local QP Operation Error
 *		0x04 - Local Protection Error
 *		0x05 - Work Request Flushed Error
 *		0x06 - Memory Window Bind Error
 *		0x10 - Bad Response Error
 *		0x11 - Local Access Error
 *		0x12 - Remote Invalid Request Error
 *		0x13 - Remote Access Error
 *		0x14 - Remote Operation Error
 *		0x15 - Transport Retry Counter Exceeded
 *		0x16 - RNR Retry Counter Exceeded
 *		0x22 - Remote Aborted Error
 *		other - reserved
 * Syndrome is defined according to the InfiniBand Architecture Specification,
 * Volume 1. For a detailed explanation of the syndromes, refer to the Software
 * Transport Interface and Software Transport Verbs chapters of the IB specifica-tion.
 */
enum roce3_cqe_syndrome {
	ROCE_CQE_SYNDROME_LOCAL_LENGTH_ERR = 0x01,
	ROCE_CQE_SYNDROME_LOCAL_QP_OP_ERR = 0x02,
	ROCE_CQE_SYNDROME_LOCAL_PROT_ERR = 0x04,
	ROCE_CQE_SYNDROME_WR_FLUSH_ERR = 0x05,

	ROCE_CQE_SYNDROME_MW_BIND_ERR = 0x06,
	ROCE_CQE_SYNDROME_BAD_RESP_ERR = 0x10,

	ROCE_CQE_SYNDROME_LOCAL_ACCESS_ERR = 0x11,
	ROCE_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR = 0x12,
	ROCE_CQE_SYNDROME_REMOTE_ACCESS_ERR = 0x13,
	ROCE_CQE_SYNDROME_REMOTE_OP_ERR = 0x14,
	ROCE_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR = 0x15,

	ROCE_CQE_SYNDROME_RNR_RETRY_EXC_ERR = 0x16,

	ROCE_CQE_SYNDROME_REMOTE_ABORTED_ERR = 0x22,
	ROCE_CQE_SYNDROME_MAX = 0x23
};

/*
 * 1.Same type of operation as SQ WQE
 * 8'h00-Send
 * 8'h01-Send with Invalidate
 * 8'h02-Send with Immediate Data
 * 8'h03-reserved
 * 8'h04-RDMA Write
 * 8'h05-RDMA Write with Immediate Data
 * 8'h06-reserved
 * 8'h07-reserved
 * 8'h08-RDMA Read
 * 8'h09-reserved
 * 8'h0a-reserved
 * 8'h0b-reserved
 * 8'h0c-Atomic Compare & Swap
 * 8'h0d-Atomic Fetch & Add
 * 8'h0e-Atomic Masked Compare & Swap (Extended Atomic operation)
 * 8'h0f-Atomic Masked Fetch & Add (Extended Atomic operation)
 * 8'h10-Fast Register PMR
 * 8'h11-Local Invalidate
 * 8'h12-Bind Memory Window Type1/2
 * 8'h13-Local opreation(Extended for further local opreation)
 * other-Reserved
 * 2.Receive
 * 00000 - RDMA Write with Immediate
 * 00001 - Send
 * 00010 - Send with Immediate
 * 00011 - Send & Invalidate
 * 3.The following are general
 * 11110 Error coding
 * 10110 Resize coding
 */
enum roce3_cqe_send_opcode {
	ROCE_OPCODE_SEND = 0x0,
	ROCE_OPCODE_SEND_WITH_INV = 0x1,
	ROCE_OPCODE_SEND_WITH_IMM = 0x2,
	/* 0x3 reserved */

	ROCE_OPCODE_RDMA_WRITE = 0x4,
	ROCE_OPCODE_RDMA_WRITE_WITH_IMM = 0x5,
	/* 0x6 and 0x7 reserved */

	ROCE_OPCODE_RDMA_READ = 0x8,
	/* 0x9~0xb reserved */

	ROCE_OPCODE_ATOMIC_COMP_AND_SWP = 0xc,
	ROCE_OPCODE_ATOMIC_FETCH_AND_ADD = 0xd,
	ROCE_OPCODE_ATOMIC_MASKED_COMP_AND_SWP = 0xe,
	ROCE_OPCODE_ATOMIC_MASKED_FETCH_AND_ADD = 0xf,

	ROCE_OPCODE_FAST_REG_PMR = 0x10,
	ROCE_OPCODE_LOCAL_INV = 0x11,
	ROCE_OPCODE_BIND_TYPE2_MW = 0x12,
	ROCE_OPCODE_REG_SIG_MR = 0x13,

	ROCE_OPCODE_RESIZE_CQE = 0x16,
	ROCE_OPCODE_ERR = 0x1e,
	ROCE_OPCODE_CQE_UNUSED = 0x1f /* Be used in new CQ buf when reszie cq */
};

enum roce3_cqe_recv_opcode {
	ROCE_RECV_OPCODE_RDMA_WRITE_WITH_IMM = 0x0,
	ROCE_RECV_OPCODE_SEND = 0x1,
	ROCE_RECV_OPCODE_SEND_WITH_IMM = 0x2,
	ROCE_RECV_OPCODE_SEND_WITH_INV = 0x3
};

/* Define the state type of the CQ */
enum cq_state {
	ROCE_CQ_STATE_INVALID = 0x0,
	ROCE_CQ_STATE_ERR = 0x1,
	ROCE_CQ_STATE_OVERFLOW = 0x2,
	ROCE_CQ_STATE_VALID = 0xf,
	ROCE_CQ_STATE_MEM_INIT = 0xa /* Initial value of Host Memory */
};

#define ROCE_CQ_TIME_OUT_CHECK_VALUE 0xe
#define ROCE_CQ_STATE_CHECK_VALUE 0x0

#define ROCE_CQE_RQ_INLINE 1
#define ROCE_CQE_RQ_NORMAL 0
#define ROCE_CQE_SEND_COMP 1
#define ROCE_CQE_RECV_COMP 0

#define ATOMIC_DATA_LEN 8 /* Specified as 8B by protocol */

#define ROCE_CQE_INVALID_VALUE 0xff
#define ROCE_CQ_RESIZE_POLL_TIMES 100

/* roce Commands, bufs and data structures related to cq */
struct roce3_cq_query_outbuf {
	struct roce_cq_context cqc;
};

struct roce3_cq_buf {
	struct tag_cqm_buf *buf;	/* pointer to describe the buf structure b cqm */
	/* the mtt struct used by kernel mode and user mode to discribe buf */
	struct rdma_mtt mtt;
	int entry_size;		/* the size of cqe */
	int buf_size;		/* the size of cq_buf */
};

struct roce3_cq_resize_buf {
	struct roce3_cq_buf buf; /* the size of buf that was resized */
	int cqe;				 /* the number of resized cqe */
};

struct roce3_cq {
	struct ib_cq ibcq;
	struct tag_cqm_queue *cqm_cq;	/* Save the handle obtained from cqm */
	/* The address information of the software DB that stores the CI user mode/kernel mode */
	struct roce3_db db;
	__be32 *set_ci_db;	/* Kernel-mode software DB */
	u32 cons_index;		/* consumer pointer */

	u32 arm_sn;		/* the serial number of arm */
	/* Used to determine whether the arm command has been sent, to avoid repeated sending */
	int arm_flag;
	u32 cqn;
	unsigned int vector;			/* associated to the eq used */
	struct roce3_cq_buf buf;		/* pointer describing the buf structure of cqm */
	struct roce3_cq_resize_buf *resize_buf;	/* resize buf struction */

	spinlock_t lock;		/* Need to lock when operating cq */
	struct mutex resize_mutex;	/* resize the mutex of cq */
	struct ib_umem *umem;		/* record the information mapped by User-mode buf */
	/* record the information mapped by buf which the User-mode resized */
	struct ib_umem *resize_umem;

	struct list_head send_qp_list; /* send queue qp */
	struct list_head recv_qp_list; /* receive queue qp */

	int reset_notify_added;
	struct list_head reset_notify;

	void (*reset_flow_comp)(struct roce3_cq *cq);
};

/* cross ibcroce3_e_cq */
static inline struct roce3_cq *to_roce3_cq(const struct ib_cq *ibcq)
{
	return container_of(ibcq, struct roce3_cq, ibcq);
}

/* obroce3_roce_cq crossing cqm */
static inline struct roce3_cq *cqmobj_to_roce3_cq(const struct tag_cqm_object *object)
{
	struct tag_cqm_queue *cqm_cq;

	cqm_cq = container_of(object, struct tag_cqm_queue, object);
	return (struct roce3_cq *)cqm_cq->priv;
}

/* Used when destroy QP */
void roce3_cq_clean(struct roce3_cq *cq, u32 qpn, struct roce3_srq *srq);
void roce3_cq_async_event(struct roce3_device *rdev, struct roce3_cq *cq, int type);
void roce3_cq_clean_process(struct roce3_cq *cq, u32 qpn, struct roce3_srq *srq);
void roce3_cq_put_umem(struct roce3_device *rdev, struct roce3_cq_buf *buf, struct ib_umem **umem);

int roce3_cq_get_umem(struct roce3_device *rdev, struct ib_udata *udata, struct roce3_cq_buf *buf,
	struct ib_umem **umem, u64 buf_addr, int cqe);
int roce3_create_cq_common(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
	struct ib_udata *udata, struct roce3_cq *rcq, u32 index);

void *roce3_get_sw_cqe(struct roce3_cq *cq, unsigned int n);
void *roce3_get_cqe_from_buf(struct roce3_cq_buf *buf, unsigned int n);
void roce3_cq_set_ci(struct roce3_cq *cq);
void roce3_cq_buf_init(struct roce3_cq_buf *buf);
void *roce3_get_cqe(struct roce3_cq *cq, unsigned int n);
void roce_reset_flow_comp(struct roce3_cq *rcq);

void roce3_lock_cqs(struct roce3_cq *roce3_send_cq, struct roce3_cq *roce3_recv_cq)
		    __acquires(&roce3_send_cq->lock) __acquires(&roce3_recv_cq->lock);
void roce3_unlock_cqs(struct roce3_cq *roce3_send_cq, struct roce3_cq *roce3_recv_cq)
		      __releases(&roce3_send_cq->lock) __releases(&roce3_recv_cq->lock);

#endif // ROCE_CQ_H
