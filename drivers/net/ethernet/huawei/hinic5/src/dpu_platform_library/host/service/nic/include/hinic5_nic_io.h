/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_io.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_IO_H
#define HINIC5_NIC_IO_H

#include "hinic5_crm.h"
#include "hinic5_common.h"
#include "hinic5_wq.h"
#include "hinic5_nic_sq.h"
#include "hinic5_nic_rq.h"

#define HINIC5_MAX_TX_QUEUE_DEPTH	16384
#define HINIC5_MAX_RX_QUEUE_DEPTH	16384

#define HINIC5_MIN_QUEUE_DEPTH		128

#define HINIC5_SQ_WQEBB_SHIFT		4
#define HINIC5_RQ_WQEBB_SHIFT		3

#define HINIC5_SQ_WQEBB_SIZE		BIT(HINIC5_SQ_WQEBB_SHIFT)
#define HINIC5_CQE_SIZE_SHIFT		4

enum hinic5_rq_wqe_type {
	HINIC5_COMPACT_RQ_WQE,
	HINIC5_NORMAL_RQ_WQE,
	HINIC5_EXTEND_RQ_WQE,
};

#define HINIC5_SQ_COALESCE BIT(0)
#define HINIC5_RQ_COALESCE BIT(1)
#define HINIC5_SQ_RQ_COALESCE (HINIC5_SQ_COALESCE | HINIC5_RQ_COALESCE)

struct hinic5_io_queue {
	struct hinic5_wq wq;

	u64 head_addr;
	u64 tail_addr;

	union {
		u8 wqe_type; /* for rq */
		u8 owner; /* for sq */
	};
	u8			rsvd1;
	u16			rsvd2;

	u16 q_id;
	u16 msix_entry_idx;

	u8 __iomem *db_addr;
	void *cons_idx_addr;
} ____cacheline_aligned;

struct hinic5_nic_db {
	u32 db_info;
	u32 pi_hi;
};

struct hinic5_rq_ci_wb {
	union {
		struct {
			u16 cqe_num;
			u16 hw_ci;
		} bs;
		u32 value;
	} dw0;
};

/* *
 * @brief hinic5_get_sq_free_wqebbs - get send queue free wqebb
 * @param sq: send queue
 * @retval : number of free wqebb
 */
static inline u16 hinic5_get_sq_free_wqebbs(struct hinic5_io_queue *sq)
{
	return hinic5_wq_free_wqebbs(&sq->wq);
}

/* *
 * @brief hinic5_update_sq_local_ci - update send queue local consumer index
 * @param sq: send queue
 * @param wqe_cnt: number of wqebb
 */
static inline void hinic5_update_sq_local_ci(struct hinic5_io_queue *sq,
					     u16 wqebb_cnt)
{
	hinic5_wq_put_wqebbs(&sq->wq, wqebb_cnt);
}

/* *
 * @brief hinic5_get_sq_local_ci - get send queue local consumer index
 * @param sq: send queue
 * @retval : local consumer index
 */
static inline u16 hinic5_get_sq_local_ci(const struct hinic5_io_queue *sq)
{
	return WQ_MASK_IDX(&sq->wq, sq->wq.cons_idx);
}

/* *
 * @brief hinic5_get_sq_local_pi - get send queue local producer index
 * @param sq: send queue
 * @retval : local producer index
 */
static inline u16 hinic5_get_sq_local_pi(const struct hinic5_io_queue *sq)
{
	return WQ_MASK_IDX(&sq->wq, sq->wq.prod_idx);
}

/* *
 * @brief hinic5_get_sq_hw_ci - get send queue hardware consumer index
 * @param sq: send queue
 * @retval : hardware consumer index
 */
static inline u16 hinic5_get_sq_hw_ci(const struct hinic5_io_queue *sq)
{
	return WQ_MASK_IDX(&sq->wq,
			   hinic5_hw_cpu16(*(u16 *)sq->cons_idx_addr));
}

static inline u16 hinic5_get_rq_hw_ci(const struct hinic5_io_queue *rq)
{
	struct hinic5_rq_ci_wb rq_ci_wb;

	rq_ci_wb.dw0.value = hinic5_hw_cpu32(*(u32 *)rq->cons_idx_addr);

	return WQ_MASK_IDX(&rq->wq, rq_ci_wb.dw0.bs.hw_ci);
}

/* *
 * @brief hinic5_get_sq_one_wqebb - get send queue wqe with single wqebb
 * @param sq: send queue
 * @param pi: return current pi
 * @retval : wqe base address
 */
static inline void *hinic5_get_sq_one_wqebb(struct hinic5_io_queue *sq, u16 *pi)
{
	return hinic5_wq_get_one_wqebb(&sq->wq, pi);
}

static inline void *hinic5_get_sq_wqebbs(struct hinic5_io_queue *sq, u16 wqebb_cnt, u16 *pi)
{
	return hinic5_wq_get_wqebbs(&sq->wq, wqebb_cnt, pi);
}

/* *
 * @brief hinic5_get_sq_multi_wqebb - get send queue wqe with multiple wqebbs
 * @param sq: send queue
 * @param wqebb_cnt: wqebb counter
 * @param pi: return current pi
 * @param second_part_wqebbs_addr: second part wqebbs base address
 * @param first_part_wqebbs_num: number wqebbs of first part
 * @retval : first part wqebbs base address
 */
static inline void *hinic5_get_sq_multi_wqebbs(struct hinic5_io_queue *sq,
					       u16 wqebb_cnt, u16 *pi,
					       void **second_part_wqebbs_addr,
					       u16 *first_part_wqebbs_num)
{
	return hinic5_wq_get_multi_wqebbs(&sq->wq, wqebb_cnt, pi,
					  second_part_wqebbs_addr,
					  first_part_wqebbs_num);
}

/* *
 * @brief hinic5_get_and_update_sq_owner - get and update send queue owner bit
 * @param sq: send queue
 * @param curr_pi: current pi
 * @param wqebb_cnt: wqebb counter
 * @retval : owner bit
 */
static inline u16 hinic5_get_and_update_sq_owner(struct hinic5_io_queue *sq,
						 u16 curr_pi, u16 wqebb_cnt)
{
	u16 owner = sq->owner;

	if (unlikely(curr_pi + wqebb_cnt >= sq->wq.q_depth))
		sq->owner = (sq->owner != 0) ? 0 : 1;

	return owner;
}

/* *
 * @brief hinic5_get_sq_wqe_with_owner - get send queue wqe with owner
 * @param sq: send queue
 * @param wqebb_cnt: wqebb counter
 * @param pi: return current pi
 * @param owner: return owner bit
 * @param second_part_wqebbs_addr: second part wqebbs base address
 * @param first_part_wqebbs_num: number wqebbs of first part
 * @retval : first part wqebbs base address
 */
static inline void *hinic5_get_sq_wqe_with_owner(struct hinic5_io_queue *sq,
						 u16 wqebb_cnt, u16 *pi,
						 u16 *owner,
						 void **second_part_wqebbs_addr,
						 u16 *first_part_wqebbs_num)
{
	void *wqe = hinic5_wq_get_multi_wqebbs(&sq->wq, wqebb_cnt, pi,
					       second_part_wqebbs_addr,
					       first_part_wqebbs_num);

	*owner = sq->owner;
	if (unlikely(*pi + wqebb_cnt >= sq->wq.q_depth))
		sq->owner = (sq->owner != 0) ? 0 : 1;

	return wqe;
}

/* *
 * @brief hinic5_rollback_sq_wqebbs - rollback send queue wqe
 * @param sq: send queue
 * @param wqebb_cnt: wqebb counter
 * @param owner: owner bit
 */
static inline void hinic5_rollback_sq_wqebbs(struct hinic5_io_queue *sq,
					     u16 wqebb_cnt, u16 owner)
{
	if (owner != sq->owner)
		sq->owner = (u8)owner;
	sq->wq.prod_idx -= wqebb_cnt;
}

/* *
 * @brief hinic5_rq_wqe_addr - get receive queue wqe address by queue index
 * @param rq: receive queue
 * @param idx: wq index
 * @retval: wqe base address
 */
static inline void *hinic5_rq_wqe_addr(struct hinic5_io_queue *rq, u16 idx)
{
	return hinic5_wq_wqebb_addr(&rq->wq, idx);
}

/* *
 * @brief hinic5_update_rq_local_ci - update receive queue local consumer index
 * @param sq: receive queue
 * @param wqe_cnt: number of wqebb
 */
static inline void hinic5_update_rq_local_ci(struct hinic5_io_queue *rq,
					     u16 wqebb_cnt)
{
	hinic5_wq_put_wqebbs(&rq->wq, wqebb_cnt);
}

/* *
 * @brief hinic5_get_rq_local_ci - get receive queue local ci
 * @param rq: receive queue
 * @retval: receive queue local ci
 */
static inline u16 hinic5_get_rq_local_ci(const struct hinic5_io_queue *rq)
{
	return WQ_MASK_IDX(&rq->wq, rq->wq.cons_idx);
}

/* *
 * @brief hinic5_get_rq_local_pi - get receive queue local pi
 * @param rq: receive queue
 * @retval: receive queue local pi
 */
static inline u16 hinic5_get_rq_local_pi(const struct hinic5_io_queue *rq)
{
	return WQ_MASK_IDX(&rq->wq, rq->wq.prod_idx);
}

/* ******************** DB INFO ******************** */
#define DB_INFO_QID_SHIFT		0
#define DB_INFO_NON_FILTER_SHIFT	22
#define DB_INFO_CFLAG_SHIFT		23
#define DB_INFO_COS_SHIFT		24
#define DB_INFO_TYPE_SHIFT		27

#define DB_INFO_QID_MASK		0x1FFFU
#define DB_INFO_NON_FILTER_MASK		0x1U
#define DB_INFO_CFLAG_MASK		0x1U
#define DB_INFO_COS_MASK		0x7U
#define DB_INFO_TYPE_MASK		0x1FU
#define DB_INFO_SET(val, member)	\
		(((u32)(val) & DB_INFO_##member##_MASK) << \
		 DB_INFO_##member##_SHIFT)

#define DB_PI_LOW_MASK			0xFFU
#define DB_PI_HIGH_MASK			0xFFU
#define DB_PI_LOW(pi)			((pi) & DB_PI_LOW_MASK)
#define DB_PI_HI_SHIFT			8
#define DB_PI_HIGH(pi)		(((pi) >> DB_PI_HI_SHIFT) & DB_PI_HIGH_MASK)
#define DB_ADDR(queue, pi)	((u64 *)((queue)->db_addr) + (u16)DB_PI_LOW(pi))
#define SRC_TYPE			1

/* CFLAG_DATA_PATH */
#define SQ_CFLAG_DP			0U
#define RQ_CFLAG_DP			1U
/* *
 * @brief hinic5_write_db - write doorbell
 * @param queue: nic io queue
 * @param cos: cos index
 * @param cflag: 0--sq, 1--rq
 * @param pi: product index
 */
#ifndef __UEFI__
static inline void hinic5_write_db(struct hinic5_io_queue *queue, int cos,
				   u8 cflag, u16 pi)
{
	struct hinic5_nic_db db;

	db.db_info = DB_INFO_SET(SRC_TYPE, TYPE) | DB_INFO_SET(cflag, CFLAG) |
			DB_INFO_SET(cos, COS) | DB_INFO_SET(queue->q_id, QID);
	db.pi_hi = DB_PI_HIGH(pi);
	/* Data should be written to HW in Big Endian Format */
	db.db_info = hinic5_hw_be32(db.db_info);
	db.pi_hi = hinic5_hw_be32(db.pi_hi);

	wmb(); /* Write all before the doorbell */

	writeq(*((u64 *)&db), DB_ADDR(queue, pi));
}
#else
void hinic5_write_db(void *pcidev, struct hinic5_io_queue *queue, int cos,
		     u8 cflag, u16 pi);
#endif

struct hinic5_dyna_qp_params {
	u16	num_qps;
	u16	xdp_qps;
	u32	sq_depth;
	u32	rq_depth;

	struct hinic5_io_queue *sqs;
	struct hinic5_io_queue *rqs;
};

struct hinic5_qp_coalesce_info {
	union {
		struct {
			u8 rx_pending_limt;
			u8 rx_coalesce_timer_cfg;
			u8 tx_pending_limt;
			u8 tx_coalesce_timer_cfg;
		};

		struct {
			u8 pending_limt;
			u8 coalesce_timer_cfg;
		};
	};

	u64 pkt_rate_low;
	u8 rx_usecs_low;
	u8 rx_pending_limt_low;

	u64 pkt_rate_high;
	u8 rx_usecs_high;
	u8 rx_pending_limt_high;
};

enum hinic5_queue_type {
	HINIC5_SQ,
	HINIC5_RQ,
	HINIC5_MAX_QUEUE_TYPE
};

int hinic5_alloc_qps(void *hwdev, struct irq_info *qps_msix_arry,
		     struct hinic5_dyna_qp_params *qp_params);
void hinic5_free_qps(void *hwdev, struct hinic5_dyna_qp_params *qp_params);
int hinic5_init_qps(void *hwdev, struct hinic5_dyna_qp_params *qp_params);
void hinic5_deinit_qps(void *hwdev, struct hinic5_dyna_qp_params *qp_params);
int hinic5_init_nicio_res(void *hwdev, u16 usr_qps_num);
void hinic5_deinit_nicio_res(void *hwdev);
int hinic5_set_sq_rq_coalesce_cfg(void *hwdev, u32 q_id, u32 type,
				  struct hinic5_qp_coalesce_info *coal_info);
int hinic5_get_rq_wqe_type(void *hwdev);
void hinic5_nic_io_param_validate(void);

/* *
 * @brief hinic5_create_qps - create queue pairs
 * @param hwdev: device pointer to hwdev
 * @param num_qp: number of queue pairs
 * @param sq_depth: sq depth
 * @param rq_depth: rq depth
 * @param qps_msix_arry: msix info
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_create_qps(void *hwdev, u16 num_qp, u32 sq_depth, u32 rq_depth,
		      struct irq_info *qps_msix_arry);

/* *
 * @brief hinic5_destroy_qps - destroy queue pairs
 * @param hwdev: device pointer to hwdev
 */
void hinic5_destroy_qps(void *hwdev);

/* *
 * @brief hinic5_get_nic_queue - get nic queue
 * @param hwdev: device pointer to hwdev
 * @param q_id: queue index
 * @param q_type: queue type
 * @retval queue address
 */
void *hinic5_get_nic_queue(void *hwdev, u16 q_id, enum hinic5_queue_type q_type);

/* *
 * @brief hinic5_init_qp_ctxts - init queue pair context
 * @param hwdev: device pointer to hwdev
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_init_qp_ctxts(void *hwdev);

/* *
 * @brief hinic5_free_qp_ctxts - free queue pairs
 * @param hwdev: device pointer to hwdev
 */
void hinic5_free_qp_ctxts(void *hwdev);
#endif
