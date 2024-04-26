/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_SRQ_H
#define ROCE_SRQ_H

#include <linux/types.h>

#include <rdma/ib_verbs.h>

#include "hinic3_rdma.h"
#include "hinic3_cqm.h"

#include "roce.h"
#include "roce_pd.h"
#include "roce_db.h"

#include "rdma_context_format.h"

#define ROCE_SRQ_MAX_SGE 15
#define ROCE_SRQ_MID_SGE 7
#define ROCE_SRQ_MIN_SGE 3

#define ROCE_SRQN_INVLD 0XFFFFFFFF
#define ROCE_SRQ_CONTAINER_LWM_MASK 0xFFFF
#define ROCE_SRQ_CONTAINER_WARTH_MASK 0xF

#define MAX_SUPPORT_CONTAINER_MODE 3
#define DWORD_LEN 32
#define XRC_CQN_FIRST_LEN 10
#define XRC_CQN_SECOND_LEN 3
#define SRQ_GPA_SIG_LEN 3
/* (2^rq_wqebb_size)*16B => divide 16 means shift need to minus 4 */
#define SRQ_WQEBB_SIZE_CAL_SECTTOR 4
#define RDMA_PREFETCH_WQE_MAX 7
#define RDMA_PREFETCH_MTT_LEN_MAX 3
#define ROCE_WQE_BB_SIZE_MIN 64

/*
 *	Lbit:0 - The next SGE is present in the list
 *	Lbit:1 - The last SGE, no SGE is present in the list
 */
#define LAST_SGE_NO_PRESENT 0x80000000UL

/*
 *	Ebit:b0 - Normal format, without extension.
 *	Ebit:b1 - The pointer inside of SGE points to the next SGL.
 *	"Length" and "Key" fields are
 */
#define NORMAL_FMT_AND_NEXT_SGE_PRESENT 0x3FFFFFFFUL
#define NORMAL_FMT_AND_LAST_SGE_NO_PRESENT 0xBFFFFFFFUL

/**
 * container_mode:
 * mode: 0 -> container_size: 16
 * mode: 1 -> container_size: 8
 * mode: 2 -> container_size: 4
 * mode: 3 -> container_size: 2
 */
enum roce3_srq_mode {
	ROCE_SRQ_MODE_0 = 0,
	ROCE_SRQ_MODE_1,
	ROCE_SRQ_MODE_2,
	ROCE_SRQ_MODE_3
};

/**
 * CHIP container_mode:
 * chip mode: 0 -> Not container
 * chip mode: 1 -> container_size: 2
 * chip mode: 2 -> container_size: 4
 * chip mode: 3 -> container_size: 8
 * chip mode: 4 -> container_size: 16
 */
enum roce3_chip_srq_mode {
	ROCE_CHIP_SRQ_MODE_N = 0,
	ROCE_CHIP_SRQ_MODE_1,
	ROCE_CHIP_SRQ_MODE_2,
	ROCE_CHIP_SRQ_MODE_3,
	ROCE_CHIP_SRQ_MODE_4
};

enum roce3_srq_cont_num_mode {
	ROCE_SRQ_CONT_NUM_MODE3 = 2,
	ROCE_SRQ_CONT_NUM_MODE2 = 4,
	ROCE_SRQ_CONT_NUM_MODE1 = 8,
	ROCE_SRQ_CONT_NUM_MODE0 = 16
};

enum srq_state {
	ROCE_SRQ_STATE_INVALID = 0x0,
	ROCE_SRQ_STATE_ERR = 0x1,
	ROCE_SRQ_STATE_VALID = 0xf,
	ROCE_SRQ_STATE_MEM_INIT = 0xa
};

#define ROCE_SRQ_STATE_CHECK_VALUE 0x0

struct roce3_srq_query_outbuf {
	struct roce_srq_context srqc;
	u32 srq_ctr_vld;
	u32 srq_empty_ctr;
	u32 reserved[6];
};

struct roce3_wqe_srq_next_seg {
	u16 reserved1;
	__be16 pcnt; /* indicate the pi */
	u8 signature;
	u8 reserved2;
	__be16 next_wqe_index;
	u32 reserved3[2];
};

struct roce3_wqe_container_srq_next_seg {
	u32 next_gpa_h;

	struct {
		u32 rsvd : 11;
		u32 next_gpa_vd : 1;
		u32 next_gpa_h : 20; /* indicate the pi */
	} dw1;

	struct {
		u32 next_idx : 16;
		u32 rsvd : 16;
	} dw2;

	struct {
		u32 rsvd2 : 30;
		u32 link_flag : 1;
		u32 rsvd : 1;
	} dw3;

	struct {
		u32 osd_next_idx : 16;
		u32 osd_cur_idx : 16;
	} dw4;
};

#define ROCE_SRQ_SGE_LAST 1
#define ROCE_SRQ_SGE_NLAST 0

#define ROCE_SRQ_SGE_LKEY_NOEXT 0
#define ROCE_SRQ_SGE_LKEY_EXT 1

struct roce3_srq {
	struct ib_srq ibsrq; /* ibsrq */
	struct tag_cqm_queue *cqm_srq;

	u32 srqn;
	int max_depth;
	int max_gs;
	int wqe_shift;

	struct tag_cqm_buf *buf;
	struct roce3_db db;
	u64 *wrid;
	spinlock_t lock;
	int head;
	int tail;
	u16 wqe_ctr;
	u8 xrc_en;
	u8 rsvd;
	struct ib_umem *umem;
	struct rdma_mtt mtt;
	struct mutex mutex;
	u32 rqe_cnt_th;
	u8 container_flag;
	u8 container_size;
	u8 container_mode;
	u8 container_warn_th;

	int buf_sz;
};

static inline struct roce3_srq *to_roce3_srq(const struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct roce3_srq, ibsrq);
}

static inline struct roce3_srq *cqmobj_to_roce3_srq(const struct tag_cqm_object *object)
{
	struct tag_cqm_queue *cqm_srq;

	cqm_srq = container_of(object, struct tag_cqm_queue, object);
	return (struct roce3_srq *)cqm_srq->priv;
}

void roce3_free_srq_wqe(struct roce3_srq *srq, int wqe_index);
void roce3_srq_async_event(struct roce3_device *rdev, struct roce3_srq *srq, int type);
void *roce3_srq_get_wqe(struct roce3_srq *srq, int n);
u8 roce3_get_container_sz(u32 container_mode);
u8 roce3_calculate_cont_th(u32 srq_limit);
u8 roce3_srq_mode_chip_adapt(u8 cfg_mode);
u32 roce3_srq_max_avail_wr_set(struct roce3_srq *rsrq);

int roce3_create_srq_common(struct roce3_device *rdev, struct roce3_srq *rsrq, struct roce3_pd *pd,
	struct ib_srq_init_attr *init_attr, struct ib_udata *udata, u32 index);

#endif // ROCE_SRQ_H
