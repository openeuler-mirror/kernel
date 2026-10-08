/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_IB_USER_V2_H
#define NBL_IB_USER_V2_H

#include <linux/sizes.h>

#define NBL_MAX_MR_SIZE 0x100000000000ULL
#define PBLE_CNT_V2_ALIGN_SIZE 8

#define NBL_RSN_DBG_LEN 32
#define NBL_RSN_TBUF_LEN 24

#define nbl_handle void *
#define nbl_qp_handle nbl_handle

/*CQE minor error*/
enum nbl_flush_opcode {
	FLUSH_INVALID = 0,
	FLUSH_GENERAL_ERR,
	FLUSH_PROT_ERR,
	FLUSH_REM_ACCESS_ERR,
	FLUSH_LOC_QP_OP_ERR,
	FLUSH_REM_OP_ERR,
	FLUSH_LOC_LEN_ERR,
	FLUSH_FATAL_ERR,
};

enum nbl_cmpl_status {
	NBL_COMPL_STATUS_SUCCESS = 0,
	NBL_COMPL_STATUS_FLUSHED,
	NBL_COMPL_STATUS_RESIZE,
	NBL_COMPL_STATUS_UNKNOWN,
};

struct nbl_ring {
	u32 head;
	u32 tail;
	u32 size;
};

enum nbl_cmpl_notify {
	NBL_CQ_COMPL_EVENT = 0,
	NBL_CQ_COMPL_SOLICITED = 1,
};

enum nbl_device_caps_const {
	NBL_CQE_SIZE = 8,
	NBL_CEQE_SIZE = 2,
	NBL_AEQE_SIZE = 2,

	NBL_MIN_AEQ_ENTRIES = 1024,
	NBL_MAX_AEQ_ENTRIES = 131072, /*128k*/
	NBL_MIN_CEQ_ENTRIES = 1024,
	NBL_MAX_CEQ_ENTRIES = 131072, /*128k*/
	NBL_MIN_CQ_SIZE = 256, /* 16k */
	NBL_MAX_CQ_SIZE = 32768, /*32k*/
	NBL_MAX_OUTBOUND_MSG_SIZE = 2147483647,
	NBL_MAX_INBOUND_MSG_SIZE = 2147483647,
	NBL_MIN_OST_RD_ATOMIC = 8,
	NBL_MAX_OST_RD_ATOMIC_V2 = 64,
	NBL_MAX_CEQ_COUNT_VF = 2,
	NBL_MAX_CEQ_COUNT = 16,
	NBL_MAX_CEQ_COUNT_RNIC = 64,
	NBL_MIN_CEQ_COUNT = 2,
	NBL_MAX_PDS = SZ_256K,
	NBL_MAX_AHS = SZ_128K,
};

/* NBL_ADDR_TYPE_ZERO_BASED is only used for FMR */
enum nbl_address_type {
	NBL_ADDR_TYPE_ZERO_BASED = 0,
	NBL_ADDR_TYPE_VA_BASED = 1,
};

enum dbg_rsc_type {
	NBL_DBG_RSC_QP,
	NBL_DBG_RSC_EQ,
	NBL_DBG_RSC_CQ,
};

struct nbl_field_desc {
	int idx;
	struct nbl_rsc_debug *rdbg;
};

struct nbl_rsc_debug {
	struct nbl_device *dev;
	void *object;
	enum dbg_rsc_type type;
	struct dentry *root;
	struct nbl_field_desc fields[];
};

struct nbl_buf_list {
	void *buf;
	dma_addr_t map;
};

struct nbl_frag_buf {
	struct nbl_buf_list *frags;
	int npages;
	int size;
	u8 page_shift;
};

struct nbl_cqe {
	__be64 buf[NBL_CQE_SIZE];
};

struct nbl_mem_detail {
	struct nbl_frag_buf frag_buf;
	struct ib_umem *umem;
	bool nbl_peer;
};

struct nbl_buf_desc {
	bool pa_continuous;
	u32 cq_pg_num; /* page num of memory */
	struct nbl_mem_detail buf;
	struct nbl_dma_mem kmem;
};

/*
 * AEQ Entry struct
 */
struct nbl_sc_aeqe {
	__be64 buf[NBL_AEQE_SIZE];
};

struct nbl_cq_poll_info {
	__be64 *cqe;
	bool move_cq_head;
	struct nbl_ring *pring;
	u32 wqe_idx;

	u64 wr_id;
	nbl_qp_handle qp_handle;
	u32 bytes_xfered;
	u32 qpn;
	u32 ud_src_qpn;
	u32 srqn;
	u8 srq_subid;
	u32 imm_data;
	u32 invalidated_mkey;
	enum nbl_cmpl_status comp_status;
	u16 major_err;
	u16 ud_vlan;
	u8 ud_smac[6];
	u8 op_type;
	enum ib_wr_opcode ib_op;
	bool mkey_valid : 1; /* or L_R_Key set */
	bool error : 1;
	bool solicited_event : 1;
	bool ipv4 : 1;
	bool ud_vlan_valid : 1;
	bool ud_smac_valid : 1;
	bool imm_valid : 1;
	u32 wqe_idx_wrid_use; /* dbg wqe idx wrid actual used */
	u8 q_type; /* NBL_CQE_QTYPE_SQ or RQ */
};

struct nbl_cq_uk {
	struct nbl_cqe *cq_base; /* va, from bdes.kmem.va */
	u64 cq_base_pa; /* pa cqp use, from bdes.kmem.pa */
	/* shadow_area: pointer to shadow area(8B)
	 * none DDR mode: point to CQC begin + 56
	 *      DDR mode: point to hmc cq shadow
	 */
	__be64 *shadow_area;
	u32 shdw_page_offset; /* shadow area offset from page start */
	void *cqc_base_va; /* page addr of cqc, va*/
	u64 cqc_base_pa; /* page addr of cqc, dma_addr */
	u32 cq_id;
	u32 cq_size;
	struct nbl_ring cq_ring;
	struct nbl_buf_desc bdes;
	u8 polarity;
	u32 shadow_rd_thd;
	struct nbl_sc_cq *bak_sc_cq;
};

#endif /* NBL_IB_USER_V2_H */
