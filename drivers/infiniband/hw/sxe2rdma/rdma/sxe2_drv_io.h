/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_io.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DRV_IO_H__
#define __SXE2_DRV_IO_H__

#define SXE2_CQE_QTYPE_RQ  0
#define SXE2_CQE_QTYPE_SQ  1

#define SXE2_MAX_FRAGCNT	      16
#define SXE2_QP_WQE_MIN_SIZE	      32
#define SXE2_QP_WQE_MAX_SIZE	      256
#define SXE2_QP_WQE_MIN_QUANTA	      1
#define SXE2_QP_MAX_INLINE_PER_QUANTA 31

#define SXE2_INLINE_VALID_S 7

#define SXE2_WQEALLOC_WQE_DESC_INDEX GENMASK(31, 20)
#define SXE2_WQE_OPCODE		     GENMASK_ULL(37, 32)
#define SXE2_WQE_ADDSGECNT	     GENMASK_ULL(41, 38)
#define SXE2_WQE_VALID		     BIT_ULL(63)
#define SXE2_WQE_FRAG_VALID	     BIT_ULL(63)

#define SXE2_CQE_VALID	BIT_ULL(63)
#define SXE2_CQE_WQEIDX GENMASK_ULL(46, 32)

#define SXE2_SET_FIELD(origin, mask, val) ((origin) |= FIELD_PREP(mask, val))

#define SXE2_SRQE_BUSY 1
#define SXE2_SRQE_FREE 0

#define SXE2_WQE_QUANTA_ODD_NUMBER 0x1

enum sxe2_disp_id {
	SXE2_RDMA_SEND	       = 0,
	SXE2_RDMA_SEND_INLINE  = 1,
	SXE2_RDMA_WRITE	       = 2,
	SXE2_RDMA_WRITE_INLINE = 3,
	SXE2_RDMA_READ	       = 4,
	SXE2_RDMA_LOCAL_INV    = 5,
	SXE2_RDMA_FAST_REG_MR  = 6,
	SXE2_RDMA_MAX_ID
};

enum sxe2_cq_err {
	SXE2_CQ_OK    = 0,
	SXE2_CQ_NOENT = -2,
};

enum { SXE2_CQ_SET_CI = 0,
		SXE2_CQ_ARM_DB = 1,
};

enum { SXE2_QP_RQ_PI = 0,
		SXE2_QP_SQ_CI = 3,
};

enum { SXE2_CQ_DB_REQ_SOLICITED	  = 1 << 31,
		SXE2_CQ_DB_REQ_NOSOLICITED = 0 << 31 };

struct sxe2_post_send {
	struct ib_sge *sg_list;
	u32 num_sges;
	u32 qkey;
	u32 dest_qp;
	u32 ah_id;
};

struct sxe2_rdma_write {
	struct ib_sge *lo_sg_list;
	struct ib_sge rem_addr;
	u32 num_lo_sges;
};

struct sxe2_rdma_read {
	struct ib_sge *lo_sg_list;
	struct ib_sge rem_addr;
	u32 num_lo_sges;
};

struct sxe2_local_invalidate {
	u32 target_stag;
};

struct sxe2_flush_mem_region {
	u64 remote_tagged_offset;
	u32 remote_stag;
	u32 length;
	u8 selectivity;
	u8 placement_type;
};

struct sxe2_fast_reg_mr {
	u64 va_or_offset;
	u64 pbl_index;
	u64 len : 46;
	u64 rsv1 : 18;
	u64 mr_key : 8;
	u64 mr_idx : 24;
	u64 op : 6;
	u64 log_entity_size : 5;
	u64 rsv2 : 1;
	u64 rsv3 : 2;
	u64 rsv4 : 2;
	u64 access_right : 5;
	u64 va_based_flag : 1;
	u64 pbl_mode : 2;
	u64 push_wqe : 1;
	u64 rsv5 : 3;
	u64 read_fence : 1;
	u64 local_fence : 1;
	u64 signaled_completion : 1;
	u64 wqe_valid : 1;
};

struct sxe2_quanta {
	u64 buffer[4];
};

struct sxe2_wr_info {
	u64 wr_id;
	u8 op_type;
	u8 l4len;
	bool signaled : 1;
	bool read_fence : 1;
	bool local_fence : 1;
	bool inline_data : 1;
	bool imm_data_valid : 1;
	bool push_wqe : 1;
	bool report_rtt : 1;
	bool udp_hdr : 1;
	bool defer_flag : 1;
	bool read_inv_stag : 1;
	bool post_wqe : 1;
	u32 imm_data;
	u32 rkey_to_inv;
	union {
		struct sxe2_post_send send;
		struct sxe2_rdma_write rdma_write;
		struct sxe2_rdma_read rdma_read;
		struct sxe2_local_invalidate local_inval;
		struct sxe2_fast_reg_mr fastreg_mr;
	} op_info;
	enum sxe2_disp_id funid;
};

struct sxe2_rq_info {
	u64 wr_id;
	struct ib_sge *sg_list;
	u32 num_sges;
};

struct sxe2_imme_data {
	u64 imme_data;
};

struct sxe2_frag_data {
	u64 tag_offset;
	union {
		struct {
			u64 stag : 32;
			u64 frag_len : 31;
			u64 frag_valid : 1;
		} field;
		u64 val;
	} offset8;
};

union sxe2_dqpn_data {
	struct {
		u64 dest_qkey : 32;
		u64 dest_qpn : 24;
		u64 rsv0 : 8;
	} field;
	u64 val;
};

struct sxe2_bindmw_info {
	u64 mw_va_base;
	union {
		struct {
			u64 mw_key : 32;
			u64 mr_key : 32;
		} field;
		u64 val;
	} offset8;
	union {
		struct {
			u64 mw_len : 46;
			u64 rsv0 : 18;
		} field;
		u64 val;
	} offset16;
};

union sxe2_send_hdr {
	struct {
		u64 remote_inv_rkey : 32;
		u64 op : 6;
		u64 addfragcnt : 4;
		u64 rsvd1 : 4;
		u64 report_rtt : 1;
		u64 imme_data_flag : 1;
		u64 rsvd2 : 8;
		u64 push_wqe : 1;
		u64 inline_data_flag : 1;
		u64 rsvd3 : 1;
		u64 rsvd4 : 1;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_send_inline_hdr {
	struct {
		u64 remote_inv_rkey : 32;
		u64 op : 6;
		u64 rsvd1 : 8;
		u64 report_rtt : 1;
		u64 imme_data_flag : 1;
		u64 inline_data_len : 8;
		u64 push_wqe : 1;
		u64 inline_data_flag : 1;
		u64 rsvd2 : 2;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_write_hdr {
	struct {
		u64 remote_key : 32;
		u64 op : 6;
		u64 addfragcnt : 4;
		u64 rsvd1 : 4;
		u64 report_rtt : 1;
		u64 imme_data_flag : 1;
		u64 rsvd2 : 8;
		u64 push_wqe : 1;
		u64 inline_data_flag : 1;
		u64 rsvd3 : 2;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_write_inline_hdr {
	struct {
		u64 remote_key : 32;
		u64 op : 6;
		u64 rsvd1 : 8;
		u64 report_rtt : 1;
		u64 imme_data_flag : 1;
		u64 inline_data_len : 8;
		u64 push_wqe : 1;
		u64 inline_data_flag : 1;
		u64 rsvd2 : 2;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_read_hdr {
	struct {
		u64 remote_key : 32;
		u64 op : 6;
		u64 addfragcnt : 4;
		u64 rsvd1 : 4;
		u64 report_rtt : 1;
		u64 rsvd2 : 1;
		u64 rsvd3 : 8;
		u64 push_wqe : 1;
		u64 rsvd4 : 3;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_bindmw_hdr {
	struct {
		u64 rsvd0 : 32;
		u64 op : 6;
		u64 rsvd1 : 10;
		u64 access : 5;
		u64 va_base_flag : 1;
		u64 mw_type : 1;
		u64 rsvd2 : 1;
		u64 push_wqe : 1;
		u64 rsvd3 : 3;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_inval_hdr {
	struct {
		u64 rsvd0 : 32;
		u64 op : 6;
		u64 rsvd1 : 18;
		u64 push_wqe : 1;
		u64 rsvd3 : 3;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_fregmr_hdr {
	struct {
		u64 consumer_key : 8;
		u64 mr_index : 24;
		u64 op : 6;
		u64 log_entity_size : 5;
		u64 rsvd1 : 5;
		u64 access : 5;
		u64 va_base_flag : 1;
		u64 pbl_mode : 2;
		u64 push_wqe : 1;
		u64 rsvd3 : 3;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_rq_hdr {
	struct {
		u64 rsv0 : 38;
		u64 addfragcnt : 4;
		u64 rsv1 : 21;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

union sxe2_nop_hdr {
	struct {
		u64 rsv0 : 32;
		u64 op : 6;
		u64 addfragcnt : 4;
		u64 rsv1 : 14;
		u64 push_wqe : 1;
		u64 rsv2 : 3;
		u64 read_fence : 1;
		u64 local_fence : 1;
		u64 signaled_completion : 1;
		u64 wqe_valid : 1;
	} field;
	u64 val;
};

enum sxe2_qp_wqe_size {
	SXE2_WQE_SIZE_32  = 32,
	SXE2_WQE_SIZE_64  = 64,
	SXE2_WQE_SIZE_96  = 96,
	SXE2_WQE_SIZE_128 = 128,
	SXE2_WQE_SIZE_256 = 256,
};

typedef int (*rdma_disp_func)(struct sxe2_qp_common *qp,
			      struct sxe2_wr_info *wr_info, bool post_sq);
int sxe2_hw_send(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
		 bool post_sq);
int sxe2_hw_inline_send(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
			bool post_sq);
int sxe2_hw_rdma_write(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
		       bool post_sq);
int sxe2_hw_inline_rdma_write(struct sxe2_qp_common *qp,
			      struct sxe2_wr_info *wr_info, bool post_sq);
int sxe2_hw_rdma_read(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
		      bool post_sq);
int sxe2_hw_mw_bind(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
		    bool post_sq);
int sxe2_hw_local_invalidate(struct sxe2_qp_common *qp,
			     struct sxe2_wr_info *wr_info, bool post_sq);
int sxe2_hw_mr_fast_register(struct sxe2_qp_common *qp,
			     struct sxe2_wr_info *wr_info, bool post_sq);
int sxe2_kpoll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *entry);
int sxe2_kpost_recv(struct ib_qp *ibqp, const struct ib_recv_wr *ib_wr,
		    const struct ib_recv_wr **bad_wr);
int sxe2_kpost_send(struct ib_qp *ibqp, const struct ib_send_wr *ib_wr,
		    const struct ib_send_wr **bad_wr);
int sxe2_kreq_notify_cq(struct ib_cq *ibcq,
			enum ib_cq_notify_flags notify_flags);
int sxe2_kpost_srq_recv(struct ib_srq *ib_srq, const struct ib_recv_wr *ib_wr,
			const struct ib_recv_wr **bad_wr);
int sxe2_generated_cmpls(struct sxe2_rdma_cq *rdma_cq,
			 struct sxe2_cqe_info *out_cqeinfo);

#endif
