/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2016 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef HNS_ABI_USER_H
#define HNS_ABI_USER_H

#include <linux/types.h>

enum hns_roce_create_cq_create_flags {
	HNS_ROCE_CREATE_CQ_FLAGS_POE_MODE = 1 << 0,
	HNS_ROCE_CREATE_CQ_FLAGS_WRITE_WITH_NOTIFY = 1 << 1,
};

struct hns_roce_ib_create_cq {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__u32 cqe_size;
	__u32 reserved;
	__aligned_u64 create_flags; /* Use enum hns_roce_create_cq_create_flags */
	__u8 poe_channel;
	__u8 notify_mode;
	__u16 notify_idx;
	__u16 rsv[2];
};

enum hns_roce_cq_cap_flags {
	HNS_ROCE_CQ_FLAG_RECORD_DB = 1 << 0,
	HNS_ROCE_CQ_FLAG_POE_EN = 1 << 2,
	HNS_ROCE_CQ_FLAG_NOTIFY_EN = 1 << 3,
};

struct hns_roce_ib_create_cq_resp {
	__aligned_u64 cqn; /* Only 32 bits used, 64 for compat */
	__aligned_u64 cap_flags;
};

enum hns_roce_srq_cap_flags {
	HNS_ROCE_SRQ_CAP_RECORD_DB = 1 << 0,
};

enum hns_roce_srq_cap_flags_resp {
	HNS_ROCE_RSP_SRQ_CAP_RECORD_DB = 1 << 0,
};

struct hns_roce_ib_create_srq {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__aligned_u64 que_addr;
	__u32 req_cap_flags; /* Use enum hns_roce_srq_cap_flags */
	__u32 reserved;
};

struct hns_roce_ib_create_srq_resp {
	__u32	srqn;
	__u32   cap_flags; /* Use enum hns_roce_srq_cap_flags */
};

enum hns_roce_create_qp_comp_mask {
	HNS_ROCE_CREATE_QP_MASK_CREATE_FLAGS = 1 << 0,
	HNS_ROCE_CREATE_QP_MASK_CONGEST_TYPE = 1 << 1,
};

enum hns_roce_create_qp_flags {
	HNS_ROCE_CREATE_QP_FLAGS_STARS_MODE = 1 << 0,
};

enum hns_roce_congest_type_flags {
	HNS_ROCE_CREATE_QP_FLAGS_DCQCN = 1 << 0,
	HNS_ROCE_CREATE_QP_FLAGS_LDCP = 1 << 1,
	HNS_ROCE_CREATE_QP_FLAGS_HC3 = 1 << 2,
	HNS_ROCE_CREATE_QP_FLAGS_DIP = 1 << 3,
};

struct hns_roce_ib_create_qp {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__u8    log_sq_bb_count;
	__u8    log_sq_stride;
	__u8    sq_no_prefetch;
	__u8    reserved[4];
	__u8    pageshift;
	__aligned_u64 sdb_addr;
	__aligned_u64 comp_mask; /* Use enum hns_roce_create_qp_comp_mask */
	__aligned_u64 create_flags; /* Use enum hns_roce_create_qp_flags */
	__aligned_u64 congest_type_flags;
};

enum hns_roce_qp_cap_flags {
	HNS_ROCE_QP_CAP_RQ_RECORD_DB = 1 << 0,
	HNS_ROCE_QP_CAP_SQ_RECORD_DB = 1 << 1,
	HNS_ROCE_QP_CAP_OWNER_DB = 1 << 2,
	HNS_ROCE_QP_CAP_SVE_DIRECT_WQE = 1 << 3,
	HNS_ROCE_QP_CAP_DYNAMIC_CTX_ATTACH = 1 << 4,
	HNS_ROCE_QP_CAP_DIRECT_WQE = 1 << 5,
	HNS_ROCE_QP_CAP_DYNAMIC_CTX_DETACH = 1 << 6,
	HNS_ROCE_QP_CAP_STARS_SQ_MODE = 1 << 7,
	HNS_ROCE_QP_CAP_WRITE_WITH_NOTIFY = 1 << 8,
};

struct hns_roce_ib_create_qp_resp {
	__aligned_u64 cap_flags; /* Use enum hns_roce_qp_cap_flags */
	__aligned_u64 dwqe_mmap_key;
};

struct hns_roce_ib_create_ah_resp {
	__u8    priority;
	__u8    tc_mode;
	__u8    dmac[6];
};

struct hns_roce_ib_modify_qp_resp {
	__u8	tc_mode;
	__u8	priority;
	__u8	reserved[6];
	__u32	dcan;
	__u32	rsv2;
};

enum {
	HNS_ROCE_EXSGE_FLAGS = 1 << 0,
	HNS_ROCE_RQ_INLINE_FLAGS = 1 << 1,
	HNS_ROCE_CQE_INLINE_FLAGS = 1 << 2,
	HNS_ROCE_UCTX_CONFIG_DCA = 1 << 3,
	HNS_ROCE_UCTX_DYN_QP_PGSZ = 1 << 4,
};

enum {
	HNS_ROCE_RSP_EXSGE_FLAGS = 1 << 0,
	HNS_ROCE_RSP_RQ_INLINE_FLAGS = 1 << 1,
	HNS_ROCE_RSP_CQE_INLINE_FLAGS = 1 << 2,
	HNS_ROCE_UCTX_RSP_DCA_FLAGS = HNS_ROCE_UCTX_CONFIG_DCA,
	HNS_ROCE_UCTX_RSP_DYN_QP_PGSZ = HNS_ROCE_UCTX_DYN_QP_PGSZ,
};

struct hns_roce_ib_alloc_ucontext_resp {
	__u32	qp_tab_size;
	__u32	cqe_size;
	__u32   srq_tab_size;
	__u32   reserved;
	__u32	config;
	__u32	max_inline_data;
	__u8	mac_type;
	__u8	congest_type;
	__u8	rsv1[6];
	__u32	dca_qps;
	__u32	dca_mmap_size;
	__aligned_u64 dca_mmap_key;
	__aligned_u64 reset_mmap_key;
};

enum hns_roce_uctx_comp_mask {
	HNS_ROCE_ALLOC_UCTX_COMP_DCA_MAX_QPS = 1 << 0,
};

struct hns_roce_ib_alloc_ucontext {
	__u32 config;
	__u32 comp; /* use hns_roce_uctx_comp_mask */
	__u32 dca_max_qps;
	__u32 reserved;
};

struct hns_roce_ib_alloc_pd_resp {
	__u32 pdn;
};

#define UVERBS_ID_NS_MASK 0xF000
#define UVERBS_ID_NS_SHIFT 12

enum hns_ib_objects {
	HNS_IB_OBJECT_DCA_MEM = (1U << UVERBS_ID_NS_SHIFT),
};

enum hns_ib_dca_mem_methods {
	HNS_IB_METHOD_DCA_MEM_REG = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_METHOD_DCA_MEM_DEREG,
	HNS_IB_METHOD_DCA_MEM_SHRINK,
	HNS_IB_METHOD_DCA_MEM_ATTACH,
	HNS_IB_METHOD_DCA_MEM_DETACH,
	HNS_IB_METHOD_DCA_MEM_QUERY,
};

enum hns_ib_dca_mem_reg_attrs {
	HNS_IB_ATTR_DCA_MEM_REG_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_REG_FLAGS,
	HNS_IB_ATTR_DCA_MEM_REG_LEN,
	HNS_IB_ATTR_DCA_MEM_REG_ADDR,
	HNS_IB_ATTR_DCA_MEM_REG_KEY,
};

enum hns_ib_dca_mem_dereg_attrs {
	HNS_IB_ATTR_DCA_MEM_DEREG_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

enum hns_ib_dca_mem_shrink_attrs {
	HNS_IB_ATTR_DCA_MEM_SHRINK_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_SHRINK_RESERVED_SIZE,
	HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_KEY,
	HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_MEMS,
};

enum hns_ib_dca_mem_attach_attrs {
	HNS_IB_ATTR_DCA_MEM_ATTACH_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_ATTACH_SQ_OFFSET,
	HNS_IB_ATTR_DCA_MEM_ATTACH_SGE_OFFSET,
	HNS_IB_ATTR_DCA_MEM_ATTACH_RQ_OFFSET,
	HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_FLAGS,
	HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_PAGES,
};

enum hns_ib_dca_mem_detach_attrs {
	HNS_IB_ATTR_DCA_MEM_DETACH_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_DETACH_SQ_INDEX,
};

enum hns_ib_dca_mem_query_attrs {
	HNS_IB_ATTR_DCA_MEM_QUERY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_QUERY_PAGE_INDEX,
	HNS_IB_ATTR_DCA_MEM_QUERY_OUT_KEY,
	HNS_IB_ATTR_DCA_MEM_QUERY_OUT_OFFSET,
	HNS_IB_ATTR_DCA_MEM_QUERY_OUT_PAGE_COUNT,
};

#define HNS_IB_INVALID_ID 0XFFFF
struct hns_roce_ib_hw_id {
	__u16 chip_id;
	__u16 die_id;
	__u16 func_id;
	__u16 reserved;
};

struct hns_roce_ib_query_device_resp {
	__u32   comp_mask;
	__u32   len;
	struct hns_roce_ib_hw_id hw_id;
};
#endif /* HNS_ABI_USER_H */
