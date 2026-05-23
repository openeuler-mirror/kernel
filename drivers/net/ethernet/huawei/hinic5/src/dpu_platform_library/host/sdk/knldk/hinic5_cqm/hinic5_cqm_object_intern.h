/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_object_intern.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_OBJECT_INTERN_H
#define HINIC5_CQM_OBJECT_INTERN_H

#include "ossl_knl.h"
#include "hinic5_cqm_object.h"
#include "hinic5_cqm_bitmap_table.h"

#define HINIC5_CQM_CQ_DEPTH_MAX           32768
#define HINIC5_CQM_CQ_DEPTH_MIN           256

/* linkwqe */
#define HINIC5_CQM_LINK_WQE_CTRLSL_VALUE  2
#define HINIC5_CQM_LINK_WQE_LP_VALID      1
#define HINIC5_CQM_LINK_WQE_LP_INVALID    0
#define HINIC5_CQM_LINK_WQE_OWNER_VALID   1
#define HINIC5_CQM_LINK_WQE_OWNER_INVALID 0

#define HINIC5_CQM_ADDR_COMBINE(high_addr, low_addr) \
	((((dma_addr_t)(high_addr)) << 32) + ((dma_addr_t)(low_addr)))
#define HINIC5_CQM_ADDR_HI(addr) ((u32)((u64)(addr) >> 32))
#define HINIC5_CQM_ADDR_LW(addr) ((u32)((u64)(addr) & 0xffffffff))

#define HINIC5_CQM_QPC_LAYOUT_TABLE_SIZE  16

/* cla bitmap */
#define HINIC5_CQM_DYNAMIC_XID_LOW_BIT_MASK(lb_mode) \
		((~(lb_mode)) & HINIC5_CQM_XID_LOW_BITS_MASK)

#define HINIC5_CQM_DYNAMIC_XID_ALLOC_MODE(xid)   \
		(((xid) & HINIC5_CQM_DYNAMIC_XID_MASK) == HINIC5_CQM_DYNAMIC_XID_MASK)
#define HINIC5_CQM_DYNAMIC_XID_LB_MODE(xid)  \
		(((xid) >> HINIC5_CQM_XID_LB_MODE_SHIFT) & HINIC5_CQM_XID_LB_MODE_MASK)
#define HINIC5_CQM_DYNAMIC_XID_LOW_BITS(xid)  \
		(((xid) >> HINIC5_CQM_XID_LOW_BITS_SHIFT) & HINIC5_CQM_XID_LOW_BITS_MASK)
#define HINIC5_CQM_DYNAMIC_XID_SEARCH_MODE(xid)   \
		(((xid) >> HINIC5_CQM_XID_SEARCH_MODE_SHIFT) & HINIC5_CQM_XID_SEARCH_MODE_MASK)

#define HINIC5_CQM_BP_RANGE_VALID(start, end, min_index, max_index) \
		 (((start) >= (min_index)) && ((start) <= (max_index)) && \
		 ((end) >= (min_index)) && ((end) <= (max_index)) && ((start) != (end)))

struct tag_hinic5_cqm_qpc_layout_table_node {
	u32 type;
	u32 size;
	u32 offset;
	struct tag_hinic5_cqm_object *object;
};

struct tag_hinic5_cqm_qpc_mpt_info {
	struct tag_hinic5_cqm_qpc_mpt common;
	/* Different service has different QPC.
	 * The large QPC/mpt will occupy some continuous indexes in bitmap.
	 */
	u32 index_count;
	struct tag_hinic5_cqm_qpc_layout_table_node
		qpc_layout_table[HINIC5_CQM_QPC_LAYOUT_TABLE_SIZE];
};

struct tag_hinic5_cqm_nonrdma_qinfo {
	struct tag_hinic5_cqm_queue common;
	u32 wqe_size;
	/* Number of WQEs in each buffer (excluding link WQEs)
	 * For SRQ, the value is the number of WQEs contained in a container.
	 */
	u32 wqe_per_buf;
	u32 q_ctx_size;
	/* When different services use CTXs of different sizes,
	 * a large CTX occupies multiple consecutive indexes in the bitmap.
	 */
	u32 index_count;

	/* add for srq */
	u32 container_size;
};

struct tag_hinic5_cqm_rdma_qinfo {
	struct tag_hinic5_cqm_queue common;
	bool room_header_alloc;
	/* This field is used to temporarily record the new object_size during
	 * CQ resize.
	 */
	u32 new_object_size;
	u32 q_ctx_size;
	/* When different services use CTXs of different sizes,
	 * a large CTX occupies multiple consecutive indexes in the bitmap.
	 */
	u32 index_count;
};

struct tag_hinic5_cqm_rdma_table {
	struct tag_hinic5_cqm_mtt_rdmarc common;
	struct tag_hinic5_cqm_buf buf;
};

void hinic5_cqm_container_free(u8 *srq_head_container, u8 *srq_tail_container,
			       struct tag_hinic5_cqm_queue *common);
s32 hinic5_cqm_container_create(struct tag_hinic5_cqm_object *object,
				u8 **container_addr, bool link);
s32 hinic5_cqm_share_recv_queue_create(struct tag_hinic5_cqm_object *object);
void hinic5_cqm_share_recv_queue_delete(struct tag_hinic5_cqm_object *object);
s32 hinic5_cqm_qpc_mpt_create(struct tag_hinic5_cqm_object *object,
			      struct tag_hinic5_cqm_bitmap_range *bp_range);
void hinic5_cqm_qpc_mpt_delete(struct tag_hinic5_cqm_object *object);
s32 hinic5_cqm_nonrdma_queue_create(struct tag_hinic5_cqm_object *object);
void hinic5_cqm_nonrdma_queue_delete(struct tag_hinic5_cqm_object *object);
s32 hinic5_cqm_rdma_queue_create(struct tag_hinic5_cqm_object *object,
				 struct tag_hinic5_cqm_bitmap_range *bp_range);
void hinic5_cqm_rdma_queue_delete(struct tag_hinic5_cqm_object *object);
s32 hinic5_cqm_rdma_table_create(struct tag_hinic5_cqm_object *object);
void hinic5_cqm_rdma_table_delete(struct tag_hinic5_cqm_object *object);
u8 *hinic5_cqm_rdma_table_offset_addr(struct tag_hinic5_cqm_object *object,
				      u32 offset, dma_addr_t *paddr);

#endif /* HINIC5_CQM_OBJECT_INTERN_H */
