/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2022 WangXun Corporation */
#ifndef NSER_USER_H
#define NSER_USER_H

#define nser_handle void *
#define nser_adapter_handle nser_handle
#define nser_qp_handle nser_handle
#define nser_cq_handle nser_handle
#define nser_pd_id nser_handle
#define nser_stag_handle nser_handle
#define nser_stag_index u32
#define nser_stag u32
#define nser_stag_key u8
#define nser_tagged_offset u64
#define nser_access_privileges u32
#define nser_physical_fragment u64
#define nser_address_list u64 *
#define nser_sgl struct nser_sge *

#define	NSER_MAX_MR_SIZE       0x200000000000ULL

#define NSER_ACCESS_FLAGS_LOCALREAD		0x01
#define NSER_ACCESS_FLAGS_LOCALWRITE		0x02
#define NSER_ACCESS_FLAGS_REMOTEREAD_ONLY	0x04
#define NSER_ACCESS_FLAGS_REMOTEREAD		0x05
#define NSER_ACCESS_FLAGS_REMOTEWRITE_ONLY	0x08
#define NSER_ACCESS_FLAGS_REMOTEWRITE		0x0a
#define NSER_ACCESS_FLAGS_BIND_WINDOW		0x10
#define NSER_ACCESS_FLAGS_ZERO_BASED		0x20
#define NSER_ACCESS_FLAGS_ALL			0x3f

#define NSER_OP_TYPE_RDMA_WRITE			0x00
#define NSER_OP_TYPE_RDMA_READ			0x01
#define NSER_OP_TYPE_SEND			0x03
#define NSER_OP_TYPE_SEND_INV			0x04
#define NSER_OP_TYPE_SEND_SOL			0x05
#define NSER_OP_TYPE_SEND_SOL_INV		0x06
#define NSER_OP_TYPE_RDMA_WRITE_SOL		0x0d
#define NSER_OP_TYPE_BIND_MW			0x08
#define NSER_OP_TYPE_FAST_REG_NSMR		0x09
#define NSER_OP_TYPE_INV_STAG			0x0a
#define NSER_OP_TYPE_RDMA_READ_INV_STAG	0x0b
#define NSER_OP_TYPE_NOP			0x0c
#define NSER_OP_TYPE_ATOMIC_FETCH_AND_ADD	0x0f
#define NSER_OP_TYPE_ATOMIC_COMPARE_AND_SWAP	0x11
#define NSER_OP_TYPE_ATOMIC_WRITE		0x12
#define NSER_OP_TYPE_REC	0x3e
#define NSER_OP_TYPE_REC_IMM	0x3f

#define NSER_FLUSH_MAJOR_ERR	0

enum nser_device_caps_const {
	NSER_WQE_SIZE =			4,
	NSER_CQP_WQE_SIZE =			8,
	NSER_CQE_SIZE =			4,
	NSER_EXTENDED_CQE_SIZE =		8,
	NSER_AEQE_SIZE =			2,
	NSER_CEQE_SIZE =			1,
	NSER_CQP_CTX_SIZE =			8,
	NSER_CQP_RSVD_SIZE =                    4,
	NSER_SHADOW_AREA_SIZE =		8,
	NSER_QP_SHADOW_AREA_SIZE =		16,
	NSER_GATHER_STATS_BUF_SIZE =		1024,
	NSER_MIN_IW_QP_ID =			0,
	NSER_QUERY_FPM_BUF_SIZE =		208,
	NSER_COMMIT_FPM_BUF_SIZE =		208,
	NSER_MAX_IW_QP_ID =			262143,
	NSER_MIN_CEQID =			0,
	NSER_MAX_CEQID =			1023,
	NSER_CEQ_MAX_COUNT =			NSER_MAX_CEQID + 1,
	NSER_MIN_CQID =			0,
	NSER_MAX_CQID =			524287,
	NSER_MIN_AEQ_ENTRIES =			1,
	NSER_MAX_AEQ_ENTRIES =			524287,
	NSER_MIN_CEQ_ENTRIES =			1,
	NSER_MAX_CEQ_ENTRIES =			262143,
	NSER_MIN_CQ_SIZE =			1,
	NSER_MAX_CQ_SIZE =			524287,
	NSER_DB_ID_ZERO =			0,
	NSER_MAX_OUTBOUND_MSG_SIZE =		1073741824,
	NSER_MAX_INBOUND_MSG_SIZE =		2147483648,
	NSER_MAX_PUSH_PAGE_COUNT =		1024,
	NSER_MAX_PE_ENA_VF_COUNT =		32,
	//NSER_MAX_VF_FPM_ID =			47,
	NSER_MAX_VF_FPM_ID =			36,
	NSER_MAX_SQ_PAYLOAD_SIZE =		2145386496,
	NSER_MAX_INLINE_DATA_SIZE =		192,
	NSER_MAX_WQ_ENTRIES =			32768,
	NSER_Q2_BUF_SIZE =			256,
	NSER_QP_CTX_SIZE =			256,
	NSER_MAX_PDS =				262144,
};

enum nser_addressing_type {
	NSER_ADDR_TYPE_ZERO_BASED = 0,
	NSER_ADDR_TYPE_VA_BASED   = 1,
};

enum nser_flush_opcode {
	FLUSH_INVALID = 0,
	FLUSH_PROT_ERR,
	FLUSH_GENERAL_ERR,
	FLUSH_REM_ACCESS_ERR,
	FLUSH_LOC_QP_OP_ERR,
	FLUSH_REM_OP_ERR,
	FLUSH_LOC_LEN_ERR,
	FLUSH_FATAL_ERR,
	FLUSH_RETRY_EXC_ERR,
	FLUSH_MW_BIND_ERR,
	FLUSH_REM_INV_REQ_ERR,
};

#define EC_RDMA_READ_WHILE_ORD_ZERO      0x0205
#define EC_IB_REMOTE_OP_ERROR            0x020e
#define EC_IB_REMOTE_ACCESS_ERR          0x020d
#define EC_INVALID_AH_ENTRY              0x0406
#define EC_AH_PD_MISMATCH                0x0407
#define EC_IBSEND_EXCEED_RQE             0x0306
#define EC_WQE_FLUSHED                   0x0002
#define EC_ERR_RETRY_EXCEED              0x50A
#define EC_RNR_RETRY_EXCEED              0x50B
#define AE_INVALID_ARP_ENTRY             0x401

#define EC_RDMA_READ_WHILE_ORD_ZERO      0x0205
#define EC_IBREQ_UNSUPORT_OPCODE         0x0300
#define EC_IBREQ_BAD_PADCNT              0x0301
#define EC_IBREQ_PYLD_PMTU_ERR           0x0302
#define EC_IBREAD_PYLD_NONEZERO          0x0303
#define EC_IBWRITE_DMALEN_ERR            0x0304
#define EC_IBREAD_DMALEN_ERR             0x0305
#define EC_IBWRITE_DMALEN_PYLD_MISMATCH  0x0307
#define EC_IBREQ_OPCODE_SEQ_ERR          0x0308
#define EC_RDRSP_DMALEN_PYLD_MISMATCH    0x0316
#define EC_RDRSP_BAD_PADCNT              0x0317
#define EC_RDRSP_PYLD_PMTU_ERR           0x0318

#define EC_REQ_BAD_RESP                  0x0319

#define EC_AMP_UNALLOCATED_STAG          0x0102
#define EC_AMP_INVALID_STAG              0x0103
#define EC_AMP_BAD_QP                    0x0104
#define EC_AMP_BAD_PD                    0x0105
#define EC_AMP_BAD_STAG_KEY              0x0106
#define EC_AMP_BAD_STAG_INDEX            0x0107
#define EC_AMP_BOUNDS_VIOLATION          0x0108
#define EC_AMP_RIGHTS_VIOLATION          0x0109
#define EC_AMP_TO_WRAP                   0x010a
#define EC_PRIV_OP_DENIED                0x010c
#define EC_STAG_ZERO_INVALID             0x0206

enum nser_cmpl_status {
	NSER_COMPL_STATUS_SUCCESS = 0,
	NSER_COMPL_STATUS_FLUSHED,
	NSER_COMPL_STATUS_INVALID_WQE,
	NSER_COMPL_STATUS_QP_CATASTROPHIC,
	NSER_COMPL_STATUS_REMOTE_TERMINATION,
	NSER_COMPL_STATUS_INVALID_STAG,
	NSER_COMPL_STATUS_BASE_BOUND_VIOLATION,
	NSER_COMPL_STATUS_ACCESS_VIOLATION,
	NSER_COMPL_STATUS_INVALID_PD_ID,
	NSER_COMPL_STATUS_WRAP_ERROR,
	NSER_COMPL_STATUS_STAG_INVALID_PDID,
	NSER_COMPL_STATUS_RDMA_READ_ZERO_ORD,
	NSER_COMPL_STATUS_QP_NOT_PRIVLEDGED,
	NSER_COMPL_STATUS_STAG_NOT_INVALID,
	NSER_COMPL_STATUS_INVALID_PHYS_BUF_SIZE,
	NSER_COMPL_STATUS_INVALID_PHYS_BUF_ENTRY,
	NSER_COMPL_STATUS_INVALID_FBO,
	NSER_COMPL_STATUS_INVALID_LEN,
	NSER_COMPL_STATUS_INVALID_ACCESS,
	NSER_COMPL_STATUS_PHYS_BUF_LIST_TOO_LONG,
	NSER_COMPL_STATUS_INVALID_VIRT_ADDRESS,
	NSER_COMPL_STATUS_INVALID_REGION,
	NSER_COMPL_STATUS_INVALID_WINDOW,
	NSER_COMPL_STATUS_INVALID_TOTAL_LEN,
	NSER_COMPL_STATUS_UNKNOWN,
};

enum nser_cmpl_notify {
	NSER_CQ_COMPL_EVENT     = 0,
	NSER_CQ_COMPL_SOLICITED = 1,
};

enum nser_qp_caps {
	NSER_WRITE_WITH_IMM = 1,
	NSER_SEND_WITH_IMM  = 2,
	NSER_ROCE	     = 4,
	NSER_PUSH_MODE      = 8,
};

struct nser_qp_uk;
struct nser_cq_uk;
struct nser_qp_uk_init_info;
struct nser_cq_uk_init_info;

struct nser_sge {
	nser_tagged_offset tag_off;
	u32 len;
	nser_stag stag;
};

struct nser_ring {
	u32 head;
	u32 tail;
	u32 size;
};

struct nser_cqe {
	__le64 buf[NSER_CQE_SIZE];
};

struct nser_extended_cqe {
	__le64 buf[NSER_EXTENDED_CQE_SIZE];
};

struct nser_post_send {
	nser_sgl sg_list;
	u32 num_sges;
	u32 qkey;
	u32 dest_qp;
	u32 ah_id;
};

struct nser_post_inline_send {
	void *data;
	u32 len;
	u32 qkey;
	u32 dest_qp;
	u32 ah_id;
};

struct nser_post_rq_info {
	u64 wr_id;
	nser_sgl sg_list;
	u32 num_sges;
};

struct nser_rdma_write {
	nser_sgl lo_sg_list;
	u32 num_lo_sges;
	struct nser_sge rem_addr;
};

struct nser_inline_rdma_write {
	void *data;
	u32 len;
	struct nser_sge rem_addr;
};

struct nser_rdma_read {
	nser_sgl lo_sg_list;
	u32 num_lo_sges;
	struct nser_sge rem_addr;
};

struct nser_bind_window {
	nser_stag mr_stag;
	u64 bind_len;
	void *va;
	enum nser_addressing_type addressing_type;
	bool ena_reads:1;
	bool ena_writes:1;
	nser_stag mw_stag;
	bool mem_window_type_1:1;
};

struct nser_inv_local_stag {
	nser_stag target_stag;
};

struct nser_atomic_fetch_add {
	u64 tagged_offset;
	u64 remote_tagged_offset;
	u64 fetch_add_data_bytes;
	u32 stag;
	u32 remote_stag;
};

struct nser_atomic_compare_swap {
	u64 tagged_offset;
	u64 remote_tagged_offset;
	u64 swap_data_bytes;
	u64 compare_data_bytes;
	u32 stag;
	u32 remote_stag;
};

struct nser_atomic_write {
	u64 tagged_offset;
	u64 remote_tagged_offset;
	u64 write_data_bytes;
	u64 inline_data;
	u32 remote_stag;
	u32 stag;
	bool is_inline_data:1;
};

struct nser_post_sq_info {
	u64 wr_id;
	u8 op_type;
	u8 l4len;
	bool signaled:1;
	bool read_fence:1;
	bool local_fence:1;
	bool inline_data:1;
	bool imm_data_valid:1;
	bool report_rtt:1;
	bool udp_hdr:1;
	bool defer_flag:1;
	u32 imm_data;
	u32 stag_to_inv;
	union {
		struct nser_post_send send;
		struct nser_rdma_write rdma_write;
		struct nser_rdma_read rdma_read;
		struct nser_bind_window bind_window;
		struct nser_inv_local_stag inv_local_stag;
		struct nser_atomic_fetch_add atomic_fetch_add;
		struct nser_atomic_compare_swap atomic_compare_swap;
		struct nser_atomic_write atomic_write;
		struct nser_inline_rdma_write inline_rdma_write;
		struct nser_post_inline_send inline_send;
	} op;
};

struct nser_cq_poll_info {
	u64 wr_id;
	nser_qp_handle qp_handle;
	u32 bytes_xfered;
	u32 qp_id;
	u32 ud_src_qpn;
	u32 imm_data;
	nser_stag inv_stag; /* or L_R_Key */
	enum nser_cmpl_status comp_status;
	u16 major_err;
	u16 minor_err;
	u16 ud_vlan;
	u8 ud_smac[6];
	u8 op_type;
	u8 q_type;
	bool stag_invalid_set:1; /* or L_R_Key set */
	bool error:1;
	bool solicited_event:1;
	bool ipv4:1;
	bool ud_vlan_valid:1;
	bool ud_smac_valid:1;
	bool imm_valid:1;
	union {
		u32 roce_psn;
		u32 rtt;
		u32 raw;
	} stat;
};

int nser_uk_atomic_write(struct nser_qp_uk *qp,
			  struct nser_post_sq_info *info, bool post_sq);

int nser_uk_atomic_compare_swap(struct nser_qp_uk *qp,
				 struct nser_post_sq_info *info, bool post_sq);
int nser_uk_atomic_fetch_add(struct nser_qp_uk *qp,
			      struct nser_post_sq_info *info, bool post_sq);
int nser_uk_inline_rdma_write(struct nser_qp_uk *qp,
			       struct nser_post_sq_info *info, bool post_sq);
int nser_uk_inline_send(struct nser_qp_uk *qp,
			 struct nser_post_sq_info *info, bool post_sq);
int nser_uk_mw_bind(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
		     bool post_sq);
int nser_uk_post_nop(struct nser_qp_uk *qp, u64 wr_id, bool signaled,
		      bool post_sq);
int nser_uk_post_receive(struct nser_qp_uk *qp,
			  struct nser_post_rq_info *info);
void nser_uk_qp_post_wr(struct nser_qp_uk *qp);
int nser_uk_rdma_read(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
		       bool inv_stag, bool post_sq);
int nser_uk_rdma_write(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
			bool post_sq);
int nser_uk_send(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
		  bool post_sq);
int nser_uk_stag_local_invalidate(struct nser_qp_uk *qp,
				   struct nser_post_sq_info *info,
				   bool post_sq);

struct nser_wqe_uk_ops {
	void (*iw_copy_inline_data)(u8 *dest, struct nser_sge *sge_list, u32 num_sges, u8 polarity);
	u16 (*iw_inline_data_size_to_quanta)(u32 data_size);
	void (*iw_set_fragment)(__le64 *wqe, u32 offset, struct nser_sge *sge,
				u8 valid);
	void (*iw_set_mw_bind_wqe)(__le64 *wqe,
				   struct nser_bind_window *op_info);
};

int nser_uk_cq_poll_cmpl(struct nser_cq_uk *cq,
			  struct nser_cq_poll_info *info);
void nser_uk_cq_request_notification(struct nser_cq_uk *cq,
				      enum nser_cmpl_notify cq_notify);
void nser_uk_cq_resize(struct nser_cq_uk *cq, void *cq_base, int size);
void nser_uk_cq_set_resized_cnt(struct nser_cq_uk *qp, u16 cnt);
int nser_uk_cq_init(struct nser_cq_uk *cq,
		     struct nser_cq_uk_init_info *info);
int nser_uk_qp_init(struct nser_qp_uk *qp,
		     struct nser_qp_uk_init_info *info);
struct nser_sq_uk_wr_trk_info {
	u64 wrid;
	u32 wr_len;
	u16 quanta;
	u8 reserved[2];
};

struct nser_qp_quanta {
	__le64 elem[NSER_WQE_SIZE];
};

struct nser_qp_uk {
	struct nser_qp_quanta *sq_base;
	struct nser_qp_quanta *rq_base;
	struct nser_uk_attrs *uk_attrs;
	u32 __iomem *wqe_alloc_db;
	struct nser_sq_uk_wr_trk_info *sq_wrtrk_array;
	u64 *rq_wrid_array;
	__le64 *shadow_area;
	struct nser_ring sq_ring;
	struct nser_ring rq_ring;
	struct nser_ring initial_ring;
	u32 qp_id;
	u32 qp_caps;
	u32 sq_size;
	u32 rq_size;
	u32 max_sq_frag_cnt;
	u32 max_rq_frag_cnt;
	u32 max_inline_data;
	struct nser_wqe_uk_ops wqe_ops;
	u16 conn_wqes;
	u8 qp_type;
	u8 swqe_polarity;
	u8 swqe_polarity_deferred;
	u8 rwqe_polarity;
	u8 rq_wqe_size;
	u8 rq_wqe_size_multiplier;
	u16 rqe_stride;
	bool deferred_flag:1;
	bool first_sq_wq:1;
	bool sq_flush_complete:1; /* Indicates flush was seen and SQ was empty after the flush */
	bool rq_flush_complete:1; /* Indicates flush was seen and RQ was empty after the flush */
	bool destroy_pending:1; /* Indicates the QP is being destroyed */
	void *back_qp;
	spinlock_t *lock;
	u8 dbg_rq_flushed;
	u16 ord_cnt;
	u8 sq_flush_seen;
	u8 rq_flush_seen;
	u8 rd_fence_rate;
	u16 qs_handle;
};

struct nser_cq_uk {
	struct nser_cqe *cq_base;
	u32 __iomem *cqe_alloc_db;
	u32 __iomem *cq_ack_db;
	__le64 *shadow_area;
	u32 cq_id;
	u32 cq_size;
	struct nser_ring cq_ring;
	u8 polarity;
	bool armed:1;
	bool avoid_mem_cflct:1;
};

struct nser_qp_uk_init_info {
	struct nser_qp_quanta *sq;
	struct nser_qp_quanta *rq;
	struct nser_uk_attrs *uk_attrs;
	u32 __iomem *wqe_alloc_db;
	__le64 *shadow_area;
	struct nser_sq_uk_wr_trk_info *sq_wrtrk_array;
	u64 *rq_wrid_array;
	u32 qp_id;
	u32 qp_caps;
	u32 sq_size;
	u32 rq_size;
	u32 max_sq_frag_cnt;
	u32 max_rq_frag_cnt;
	u32 max_inline_data;
	u8 first_sq_wq;
	u8 type;
	u8 rd_fence_rate;
	int abi_ver;
};

struct nser_cq_uk_init_info {
	u32 __iomem *cqe_alloc_db;
	u32 __iomem *cq_ack_db;
	struct nser_cqe *cq_base;
	__le64 *shadow_area;
	u32 cq_size;
	u32 cq_id;
	bool avoid_mem_cflct;
};

void nser_print_cqes(struct nser_cq_uk *cq);
void nser_print_sq_wqes(struct nser_qp_uk *qp);
__le64 *nser_qp_get_next_send_wqe(struct nser_qp_uk *qp, u32 *wqe_idx,
				   u16 *quanta, u32 total_size,
				   struct nser_post_sq_info *info);
__le64 *nser_qp_get_next_recv_wqe(struct nser_qp_uk *qp, u32 *wqe_idx);
void nser_uk_clean_cq(void *q, struct nser_cq_uk *cq);

int nser_fragcnt_to_quanta_sq(u32 frag_cnt, u16 *quanta);
int nser_fragcnt_to_wqesize_rq(u32 frag_cnt, u16 *wqe_size);
void nser_get_wqe_shift(struct nser_uk_attrs *uk_attrs, u32 sge,
			 u32 inline_data, u8 *shift);
int nser_get_sqdepth(struct nser_uk_attrs *uk_attrs, u32 sq_size, u8 shift, u32 *sqdepth);
int nser_get_rqdepth(struct nser_uk_attrs *uk_attrs, u32 rq_size, u8 shift, u32 *rqdepth);

void nser_clr_wqes(struct nser_qp_uk *qp, u32 qp_wqe_idx);
#endif /* NSER_USER_H */
