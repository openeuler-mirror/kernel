/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2-abi.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_ABI_STRUCT_H__
#define __SXE2_ABI_STRUCT_H__

#include <linux/types.h>

struct sxe2_create_ah_resp {
	__u32 ah_id;
	__u8 rsvd[4];
};

struct sxe2_modify_qp_req {
	__u8 sq_flush;
	__u8 rq_flush;
	__u8 llwqe_enable;
	__u8 new_page_alloc;
	__u32 llwqe_page_index;
};

struct sxe2_modify_qp_resp {
	__u8 rd_fence_rate;
	__u8 rsvd[3];
	__u32 db_mmap_size;
	__u32 db_page_id;
	__u32 rsvd1;
	__u64 db_mmap_offset;
};

struct sxe2_create_qp_req {
	__u32 sq_depth;
	__u32 rq_depth;
	__u8 sq_shift;
	__u8 rq_shift;
	__u8 rsvd[6];
	__u64 user_wqe_bufs;
	__u64 doorbell_note;
	__u64 user_compl_ctx;
};
struct sxe2_create_qp_resp {
	__u32 qpn;
	__u32 qp_caps;
};

struct sxe2_create_cq_req {
	__aligned_u64 user_cq_buf;
	__aligned_u64 user_cq_db_note;
};

struct sxe2_create_cq_resp {
	__u32 cq_id;
	__u32 ncqe;
};

struct sxe2_alloc_pd_resp {
	__u32 pd_id;
	__u8 rsvd[4];
};

struct sxe2_create_srq_req {
	__aligned_u64 user_srq_buf;
	__aligned_u64 user_srq_db_note;
	__aligned_u64 srq_cmpl_ctx;
	__u32 srq_buf_size;
	__u32 srq_size;
	__u32 max_wr_cal;
};

struct sxe2_create_srq_resp {
	__u32 srq_id;
};

#endif
