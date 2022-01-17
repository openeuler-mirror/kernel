/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_NIC_IO_H
#define SPNIC_NIC_IO_H

#include "sphw_crm.h"
#include "sphw_common.h"
#include "sphw_wq.h"

#define SPNIC_MAX_TX_QUEUE_DEPTH	65536
#define SPNIC_MAX_RX_QUEUE_DEPTH	16384

#define SPNIC_MIN_QUEUE_DEPTH		128

#define SPNIC_SQ_WQEBB_SHIFT		4
#define SPNIC_RQ_WQEBB_SHIFT		3

#define SPNIC_SQ_WQEBB_SIZE		BIT(SPNIC_SQ_WQEBB_SHIFT)
#define SPNIC_CQE_SIZE_SHIFT		4

enum spnic_rq_wqe_type {
	SPNIC_COMPACT_RQ_WQE,
	SPNIC_NORMAL_RQ_WQE,
	SPNIC_EXTEND_RQ_WQE,
};

struct spnic_io_queue {
	struct sphw_wq wq;
	union {
		u8 wqe_type;	/* for rq */
		u8 owner;	/* for sq */
	};

	u16 q_id;
	u16 msix_entry_idx;

	u8 __iomem *db_addr;

	union {
		struct {
			void *cons_idx_addr;
		} tx;

		struct {
			u16 *pi_virt_addr;
			dma_addr_t pi_dma_addr;
		} rx;
	};
} ____cacheline_aligned;

struct spnic_nic_db {
	u32 db_info;
	u32 pi_hi;
};

/* *
 * @brief spnic_get_sq_free_wqebbs - get send queue free wqebb
 * @param sq: send queue
 * @retval : number of free wqebb
 */
static inline u16 spnic_get_sq_free_wqebbs(struct spnic_io_queue *sq)
{
	return sphw_wq_free_wqebbs(&sq->wq);
}

/* *
 * @brief spnic_update_sq_local_ci - update send queue local consumer index
 * @param sq: send queue
 * @param wqe_cnt: number of wqebb
 */
static inline void spnic_update_sq_local_ci(struct spnic_io_queue *sq, u16 wqebb_cnt)
{
	sphw_wq_put_wqebbs(&sq->wq, wqebb_cnt);
}

/* *
 * @brief spnic_get_sq_local_ci - get send queue local consumer index
 * @param sq: send queue
 * @retval : local consumer index
 */
static inline u16 spnic_get_sq_local_ci(struct spnic_io_queue *sq)
{
	return WQ_MASK_IDX(&sq->wq, sq->wq.cons_idx);
}

/* *
 * @brief spnic_get_sq_local_pi - get send queue local producer index
 * @param sq: send queue
 * @retval : local producer index
 */
static inline u16 spnic_get_sq_local_pi(struct spnic_io_queue *sq)
{
	return WQ_MASK_IDX(&sq->wq, sq->wq.prod_idx);
}

/* *
 * @brief spnic_get_sq_hw_ci - get send queue hardware consumer index
 * @param sq: send queue
 * @retval : hardware consumer index
 */
static inline u16 spnic_get_sq_hw_ci(struct spnic_io_queue *sq)
{
	return WQ_MASK_IDX(&sq->wq, *(u16 *)sq->tx.cons_idx_addr);
}

/* *
 * @brief spnic_get_sq_one_wqebb - get send queue wqe with single wqebb
 * @param sq: send queue
 * @param pi: return current pi
 * @retval : wqe base address
 */
static inline void *spnic_get_sq_one_wqebb(struct spnic_io_queue *sq, u16 *pi)
{
	return sphw_wq_get_one_wqebb(&sq->wq, pi);
}

/* *
 * @brief spnic_get_sq_multi_wqebb - get send queue wqe with multiple wqebbs
 * @param sq: send queue
 * @param wqebb_cnt: wqebb counter
 * @param pi: return current pi
 * @param second_part_wqebbs_addr: second part wqebbs base address
 * @param first_part_wqebbs_num: number wqebbs of first part
 * @retval : first part wqebbs base address
 */
static inline void *spnic_get_sq_multi_wqebbs(struct spnic_io_queue *sq, u16 wqebb_cnt, u16 *pi,
					      void **second_part_wqebbs_addr,
					      u16 *first_part_wqebbs_num)
{
	return sphw_wq_get_multi_wqebbs(&sq->wq, wqebb_cnt, pi, second_part_wqebbs_addr,
					first_part_wqebbs_num);
}

/* *
 * @brief spnic_get_and_update_sq_owner - get and update send queue owner bit
 * @param sq: send queue
 * @param curr_pi: current pi
 * @param wqebb_cnt: wqebb counter
 * @retval : owner bit
 */
static inline u16 spnic_get_and_update_sq_owner(struct spnic_io_queue *sq,
						u16 curr_pi, u16 wqebb_cnt)
{
	u16 owner = sq->owner;

	if (unlikely(curr_pi + wqebb_cnt >= sq->wq.q_depth))
		sq->owner = !sq->owner;

	return owner;
}

/* *
 * @brief spnic_get_sq_wqe_with_owner - get send queue wqe with owner
 * @param sq: send queue
 * @param wqebb_cnt: wqebb counter
 * @param pi: return current pi
 * @param owner: return owner bit
 * @param second_part_wqebbs_addr: second part wqebbs base address
 * @param first_part_wqebbs_num: number wqebbs of first part
 * @retval : first part wqebbs base address
 */
static inline void *spnic_get_sq_wqe_with_owner(struct spnic_io_queue *sq,
						u16 wqebb_cnt, u16 *pi, u16 *owner,
						void **second_part_wqebbs_addr,
						u16 *first_part_wqebbs_num)
{
	void *wqe = sphw_wq_get_multi_wqebbs(&sq->wq, wqebb_cnt, pi, second_part_wqebbs_addr,
					     first_part_wqebbs_num);

	*owner = sq->owner;
	if (unlikely(*pi + wqebb_cnt >= sq->wq.q_depth))
		sq->owner = !sq->owner;

	return wqe;
}

/* *
 * @brief spnic_rollback_sq_wqebbs - rollback send queue wqe
 * @param sq: send queue
 * @param wqebb_cnt: wqebb counter
 * @param owner: owner bit
 */
static inline void spnic_rollback_sq_wqebbs(struct spnic_io_queue *sq, u16 wqebb_cnt, u16 owner)
{
	if (owner != sq->owner)
		sq->owner = owner;
	sq->wq.prod_idx -= wqebb_cnt;
}

/* *
 * @brief spnic_rq_wqe_addr - get receive queue wqe address by queue index
 * @param rq: receive queue
 * @param idx: wq index
 * @retval: wqe base address
 */
static inline void *spnic_rq_wqe_addr(struct spnic_io_queue *rq, u16 idx)
{
	return sphw_wq_wqebb_addr(&rq->wq, idx);
}

/* *
 * @brief spnic_update_rq_hw_pi - update receive queue hardware pi
 * @param rq: receive queue
 * @param pi: pi
 */
static inline void spnic_update_rq_hw_pi(struct spnic_io_queue *rq, u16 pi)
{
	*rq->rx.pi_virt_addr = cpu_to_be16((pi & rq->wq.idx_mask) << rq->wqe_type);
}

/* *
 * @brief spnic_update_rq_local_ci - update receive queue local consumer index
 * @param sq: receive queue
 * @param wqe_cnt: number of wqebb
 */
static inline void spnic_update_rq_local_ci(struct spnic_io_queue *rq, u16 wqebb_cnt)
{
	sphw_wq_put_wqebbs(&rq->wq, wqebb_cnt);
}

/* *
 * @brief spnic_get_rq_local_ci - get receive queue local ci
 * @param rq: receive queue
 * @retval: receive queue local ci
 */
static inline u16 spnic_get_rq_local_ci(struct spnic_io_queue *rq)
{
	return WQ_MASK_IDX(&rq->wq, rq->wq.cons_idx);
}

/* *
 * @brief spnic_get_rq_local_pi - get receive queue local pi
 * @param rq: receive queue
 * @retval: receive queue local pi
 */
static inline u16 spnic_get_rq_local_pi(struct spnic_io_queue *rq)
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
#define DB_ADDR(queue, pi)	((u64 *)((queue)->db_addr) + DB_PI_LOW(pi))
#define SRC_TYPE			1

/* CFLAG_DATA_PATH */
#define SQ_CFLAG_DP			0
#define RQ_CFLAG_DP			1
/* *
 * @brief spnic_write_db - write doorbell
 * @param queue: nic io queue
 * @param cos: cos index
 * @param cflag: 0--sq, 1--rq
 * @param pi: product index
 */
static inline void spnic_write_db(struct spnic_io_queue *queue, int cos, u8 cflag, u16 pi)
{
	struct spnic_nic_db db;

	db.db_info = DB_INFO_SET(SRC_TYPE, TYPE) | DB_INFO_SET(cflag, CFLAG) |
			DB_INFO_SET(cos, COS) | DB_INFO_SET(queue->q_id, QID);
	db.pi_hi = DB_PI_HIGH(pi);

	wmb(); /* Write all before the doorbell */

	writeq(*((u64 *)&db), DB_ADDR(queue, pi));
}

struct spnic_dyna_qp_params {
	u16	num_qps;
	u32	sq_depth;
	u32	rq_depth;

	struct spnic_io_queue *sqs;
	struct spnic_io_queue *rqs;
};

int spnic_alloc_qps(void *hwdev, struct irq_info *qps_msix_arry,
		    struct spnic_dyna_qp_params *qp_params);
void spnic_free_qps(void *hwdev, struct spnic_dyna_qp_params *qp_params);
int spnic_init_qps(void *hwdev, struct spnic_dyna_qp_params *qp_params);
void spnic_deinit_qps(void *hwdev, struct spnic_dyna_qp_params *qp_params);
int spnic_init_nicio_res(void *hwdev);
void spnic_deinit_nicio_res(void *hwdev);
#endif
