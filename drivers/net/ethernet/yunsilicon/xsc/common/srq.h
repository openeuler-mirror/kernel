/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_SRQ_H
#define XSC_SRQ_H

#define XSC_MAX_SRQ_NUM 8192

enum {
	XSC_SRQ_FLAG_ERR    = (1 << 0),
	XSC_SRQ_FLAG_WQ_SIG = (1 << 1),
	XSC_SRQ_FLAG_RNDV   = (1 << 2),
};

enum xsc_nvmf_offload_type {
	XSC_NVMF_WRITE_OFFLOAD			= 1,
	XSC_NVMF_READ_OFFLOAD			= 2,
	XSC_NVMF_READ_WRITE_OFFLOAD		= 3,
	XSC_NVMF_READ_WRITE_FLUSH_OFFLOAD	= 4,
};

struct xsc_nvmf_attr {
	enum xsc_nvmf_offload_type	type;
	u8				passthrough_sqe_rw_service_en;
	u8				log_max_namespace;
	u32				cmd_unknown_namespace_cnt;
	u32				ioccsz;
	u8				icdoff;
	u8				log_max_io_size;
	u8				nvme_memory_log_page_size;
	u8				staging_buffer_log_page_size;
	u16				staging_buffer_number_of_pages;
	u8				staging_buffer_page_offset;
	u32				nvme_queue_size;
	u64				*staging_buffer_pas;
};

struct xsc_srq_attr {
	u32 type;
	u32 flags;
	u32 log_size;
	u32 wqe_shift;
	u32 log_page_size;
	u32 wqe_cnt;
	u32 srqn;
	u32 xrcd;
	u32 page_offset;
	u32 cqn;
	u32 pd;
	u32 lwm;
	u32 user_index;
	u64 db_record;
	__be64 *pas;
	struct ib_umem *umem;
	u32 tm_log_list_size;
	u32 tm_next_tag;
	u32 tm_hw_phase_cnt;
	u32 tm_sw_phase_cnt;
	u16 uid;
	struct xsc_nvmf_attr nvmf;
};

struct xsc_srq_qp_node {
	struct list_head	entry;
	u32			qp_id;
	struct ib_qp		*ibqp;
};

struct xsc_srq_cache_wr {
	int wr_num;
	int max_wr_num;
	struct ib_recv_wr *head_wr;
	struct ib_recv_wr *tail_wr;
};

struct xsc_core_srq {
	u32 srqn;
	int max;
	size_t max_gs;
	size_t max_avail_gather;
	int wqe_shift;
	void (*event)(struct xsc_core_srq *srq, enum xsc_event e);

	/* protect ctrl list */
	spinlock_t		lock;
	struct list_head	ctrl_list;
	u16 uid;

	struct list_head	srq_qp_list;
	struct xsc_srq_cache_wr *cache_wr;
};

#endif /* XSC_SRQ_H */
