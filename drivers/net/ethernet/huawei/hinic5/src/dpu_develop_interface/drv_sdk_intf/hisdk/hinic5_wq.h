/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_wq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_WQ_H
#define HINIC5_WQ_H

#include <linux/types.h>

#include "hinic5_common.h"

/**
 * @brief struct hinic5_wq
 * @details Structure for describing work queue information; modifications need to be synchronized to user-space struct sdk_cmdq_info
 */
struct hinic5_wq {
	u16 cons_idx;		/**< Consumer index */
	u16 prod_idx;		/**< Producer index */

	u32 q_depth;		/**< Queue depth */
	u16 idx_mask;		/**< Queue index mask */
	u16 wqebb_size_shift;	/**< WQEBB shift */
	u16 rsvd1;
	u16 num_wq_pages;	/**< Number of wq pages */
	u32 wqebbs_per_page;	/**< Number of wqes per page */
	u16 wqebbs_per_page_shift;
	u16 wqebbs_per_page_mask;

	struct hinic5_dma_addr_align *wq_pages;	/* Pointer to DMA address alignment structure,
						 * used to describe wq page information
						 */

	dma_addr_t wq_block_paddr;	/**< WQ block physical address */
	u64 *wq_block_vaddr;	/**< WQ block virtual address */

	void *dev_hdl;		/**< Pointer to pcidev->dev or Handler */
	u32 wq_page_size;	/**< WQ page size */
	u16 wqebb_size;		/**< WQEBB size */
} ____cacheline_aligned;


/**
 * @brief Define a macro for calculating mask value of specific index in given queue
 * @param wq Queue object
 * @param idx Index value
 *
 * @return Returns calculated mask value
 */
#define WQ_MASK_IDX(wq, idx) (((u16)(idx)) & (wq)->idx_mask)
/**
 * @brief Calculate masked page based on work queue and page index
 * @param wq Work queue
 * @param pg_idx Page index
 *
 * @return Returns page index if page index is less than work queue page count, otherwise returns 0
 */
#define WQ_MASK_PAGE(wq, pg_idx) (((pg_idx) < (wq)->num_wq_pages) ? (pg_idx) : 0)
/**
 * @brief Calculate page index
 * @param wq Wait queue
 * @param idx Index
 *
 * @return Returns calculated page index
 */
#define WQ_PAGE_IDX(wq, idx) ((idx) >> (wq)->wqebbs_per_page_shift)
/**
 * @brief Calculate element offset in queue
 * @param wq Queue pointer
 * @param idx Element index
 *
 * @return Returns element offset in page
 */
#define WQ_OFFSET_IN_PAGE(wq, idx) ((idx) & (wq)->wqebbs_per_page_mask)
/**
 * @brief Get WQEBB address
 * @param wq Work queue
 * @param pg_idx Page index
 * @param idx_in_pg Index within page
 *
 * @return u8* Returns WQEBB address
 */
#define WQ_GET_WQEBB_ADDR(wq, pg_idx, idx_in_pg) \
	((u8 *)(wq)->wq_pages[(pg_idx)].align_vaddr + \
	 (((u64)(idx_in_pg)) << (wq)->wqebb_size_shift))
/**
 * @brief Check if queue is level 0
 * @param wq Queue pointer
 *
 * @return
 *      @retval true If queue is level 0
 *      @retval false If queue is not level 0
 */
#define WQ_IS_0_LEVEL_CLA(wq) ((wq)->num_wq_pages == 1)

/**
 * @brief free wq wqebb
 * @param wq: pointer of wq control struct
 *
 * @return free wqebb number
 */
static inline u16 hinic5_wq_free_wqebbs(struct hinic5_wq *wq)
{
	return (u16)(wq->q_depth
		    - ((wq->q_depth + wq->prod_idx - wq->cons_idx) & wq->idx_mask)
		    - 1);
}

/**
 * @brief check wq empty
 * @param wq: pointer of wq control struct
 *
 * @return true or false
 */
static inline bool hinic5_wq_is_empty(const struct hinic5_wq *wq)
{
	return WQ_MASK_IDX(wq, wq->prod_idx) == WQ_MASK_IDX(wq, wq->cons_idx);
}

/**
 * @brief get wq multi wqebbs
 * @param wq: pointer of wq control struct
 * @param wqebb_cnt: the number of wqebbs
 * @param pi: producer index
 *
 * @return first wqebb address
 **/
static inline void *hinic5_wq_get_wqebbs(struct hinic5_wq *wq, u16 wqebb_cnt, u16 *pi)
{
	*pi = WQ_MASK_IDX(wq, wq->prod_idx);
	wq->prod_idx += wqebb_cnt;

	return WQ_GET_WQEBB_ADDR(wq, WQ_PAGE_IDX(wq, *pi), WQ_OFFSET_IN_PAGE(wq, *pi));
}

/**
 * @brief get  wq  one wqebb
 * @param wq: pointer of wq control struct
 * @param pi: producer index
 **/
static inline void *hinic5_wq_get_one_wqebb(struct hinic5_wq *wq, u16 *pi)
{
	return hinic5_wq_get_wqebbs(wq, 1, pi);
}

/**
 * @brief get wq multi wqebbs
 * @param wq: pointer of wq control struct
 * @param num_wqebbs: the number of wqebbs
 * @param prod_idx: producer index
 * @param second_part_wqebbs_addr: second part wqebbs address
 * @param first_part_wqebbs_num: first part wqebbs address
 *
 * @return wqebbs address
 */
static inline void *hinic5_wq_get_multi_wqebbs(struct hinic5_wq *wq, u16 num_wqebbs,
					       u16 *prod_idx, void **second_part_wqebbs_addr,
					       u16 *first_part_wqebbs_num)
{
	u32 pg_idx, off_in_page;

	*prod_idx = WQ_MASK_IDX(wq, wq->prod_idx);
	wq->prod_idx += num_wqebbs;

	pg_idx = WQ_PAGE_IDX(wq, *prod_idx);
	off_in_page = WQ_OFFSET_IN_PAGE(wq, *prod_idx);

	if (off_in_page + num_wqebbs > wq->wqebbs_per_page) {
		/* wqe across wq page boundary */
		*second_part_wqebbs_addr = WQ_GET_WQEBB_ADDR(wq, WQ_MASK_PAGE(wq, pg_idx + 1), 0);
		*first_part_wqebbs_num = (u16)(wq->wqebbs_per_page - off_in_page);
	} else {
		*second_part_wqebbs_addr = NULL;
		*first_part_wqebbs_num = num_wqebbs;
	}

	return WQ_GET_WQEBB_ADDR(wq, pg_idx, off_in_page);
}

/**
 * @brief put  wq  wqebb
 * @param wq: pointer of wq control struct
 * @param num_wqebbs: number of wqebb
 */

static inline void hinic5_wq_put_wqebbs(struct hinic5_wq *wq, u16 num_wqebbs)
{
	wq->cons_idx += num_wqebbs;
}

/**
 * @brief get  wq  wqebb address
 * @param wq: pointer of wq control struct
 * @param idx: wqbb idx
 */

static inline void *hinic5_wq_wqebb_addr(struct hinic5_wq *wq, u16 idx)
{
	return WQ_GET_WQEBB_ADDR(wq, WQ_PAGE_IDX(wq, idx), WQ_OFFSET_IN_PAGE(wq, idx));
}

/**
 * @brief read one wqebb
 * @param wq: pointer of wq control struct
 * @param cons_idx: wqbb index
 *
 * @return wqe page address
 */
static inline void *hinic5_wq_read_one_wqebb(struct hinic5_wq *wq, u16 *cons_idx)
{
	*cons_idx = WQ_MASK_IDX(wq, wq->cons_idx);

	return hinic5_wq_wqebb_addr(wq, *cons_idx);
}

/**
 * @brief get the first wqe page address
 * @param wq: pointer of wq control struct
 *
 * @return wqe page address
 */
static inline u64 hinic5_wq_get_first_wqe_page_addr(struct hinic5_wq *wq)
{
	return wq->wq_pages[0].align_paddr;
}

/**
 * @brief reset wq  zero wq page data
 * @param wq: pointer of wq control struct
 */
static inline void hinic5_wq_reset(struct hinic5_wq *wq)
{
	u16 pg_idx;

	wq->cons_idx = 0;
	wq->prod_idx = 0;

	for (pg_idx = 0; pg_idx < wq->num_wq_pages; pg_idx++)
		memset(wq->wq_pages[pg_idx].align_vaddr, 0, wq->wq_page_size);
}

/**
 * @brief Initialize wq struct and allocate wq page
 * @param udkdev: device pointer to udkdev
 * @param wq: pointer of wq control struct
 * @param q_depth: wq depth
 * @param wqebb_size: the size of wqebb
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */
int hinic5_wq_create(void *hwdev, struct hinic5_wq *wq, u32 q_depth,
		     u16 wqebb_size);

/**
 * @brief Release wqe pages
 * @param udkdev: device pointer to udkdev
 * @param wq: pointer of wq control struct
 */
void hinic5_wq_destroy(struct hinic5_wq *wq);

#endif
