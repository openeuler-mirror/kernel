/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_CMD_H
#define ROCE_VERBS_CMD_H

#include "rdma_context_format.h"
#include "roce_verbs_pub.h"


/* ************************************************* */
struct tag_roce_verbs_cmd_com {
	union {
		u32 value;

		struct {
			u32 version : 8;
			u32 rsvd : 8;
			u32 cmd_bitmask : 16; // CMD_TYPE_BITMASK_E
		} bs;
	} dw0;

	u32 index; // qpn/cqn/srqn/mpt_index/gid idx
};

struct tag_roce_cmd_gid {
	struct tag_roce_verbs_cmd_com com;

	u32 port;
	u32 rsvd;
	struct roce_gid_context gid_entry;
};

struct tag_roce_clear_gid {
	struct tag_roce_verbs_cmd_com com;

	u32 port;
	u32 gid_num;
};

struct tag_roce_qurey_gid {
	struct tag_roce_verbs_cmd_com com;

	u32 port;
	u32 rsvd;
};

struct tag_roce_flush_mpt {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_cmd_flush_mpt {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_cmd_mpt_query {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_sw2hw_mpt {
	struct tag_roce_verbs_cmd_com com;
	/* When creating a MR/MW, you need to enter the content of the MPT Context. */
	struct roce_mpt_context mpt_entry;
};

struct tag_roce_cmd_modify_mpt {
	struct tag_roce_verbs_cmd_com com;

	u32 new_key;

	/* DW2~3 */
	union {
		u64 length; /* Length of mr or mw */

		struct {
			u32 length_hi; /* Length of mr or mw */
			u32 length_lo; /* Length of mr or mw */
		} dw2;
	};

	/* DW4~5 */
	union {
		u64 iova; /* Start address of mr or mw */

		struct {
			u32 iova_hi; /* Upper 32 bits of the start address of mr or mw */
			u32 iova_lo; /* Lower 32 bits of the start address of mr or mw */
		} dw4;
	};
};

struct tag_roce_cmd_mpt_hw2sw {
	struct tag_roce_verbs_cmd_com com;

	u32 dmtt_flags;
	u32 dmtt_num;
	u32 dmtt_cache_line_start;
	u32 dmtt_cache_line_end;
	u32 dmtt_cache_line_size;
};

struct tag_roce_cmd_query_mtt {
	struct tag_roce_verbs_cmd_com com;

	u32 mtt_addr_start_hi32;
	u32 mtt_addr_start_lo32;
	u32 mtt_num;
	u32 rsvd;
};

struct tag_roce_cmd_creat_cq {
	struct tag_roce_verbs_cmd_com com;
	struct roce_cq_context cqc;
};

struct tag_roce_cmd_resize_cq {
	struct tag_roce_verbs_cmd_com com;

	u32 rsvd;
	u32 page_size;	 /* Size of the resize buf page. */
	u32 log_cq_size;   /* Cq depth after resize */
	u32 mtt_layer_num; /* Number of mtt levels after resize */
	/* DW4~5 */
	union {
		u64 mtt_base_addr; /* Start address of mr or mw */
		u32 cqc_l0mtt_gpa[2];
	};
	u32 mtt_page_size; /* Size of the mtt page after resize. */
	struct tag_roce_cq_mtt_info mtt_info;
};

struct tag_roce_cmd_modify_cq {
	struct tag_roce_verbs_cmd_com com;
	u32 max_cnt;
	u32 timeout;
};

struct tag_roce_cmd_cq_hw2sw {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_cmd_cq_cache_invalidate {
	struct tag_roce_verbs_cmd_com com;
	struct tag_roce_cq_mtt_info mtt_info;
};

struct tag_roce_cmd_roce_cq_query {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_cmd_creat_srq {
	struct tag_roce_verbs_cmd_com com;
	struct roce_srq_context srqc;
};

struct tag_roce_cmd_srq_arm {
	struct tag_roce_verbs_cmd_com com;
	union {
		u32 limitwater;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 lwm : 16;
			u32 warth : 4;
			u32 th_up_en : 1;
			u32 cont_en : 1;
			u32 rsvd : 10;
#else
			u32 rsvd : 10;
			u32 cont_en : 1;
			u32 th_up_en : 1;
			u32 warth : 4;
			u32 lwm : 16;
#endif
		} bs;
	};
};

struct tag_roce_cmd_srq_hw2sw {
	struct tag_roce_verbs_cmd_com com;
	struct tag_roce_cq_mtt_info mtt_info;
	u32 srq_buf_len;
	u32 wqe_cache_line_start;
	u32 wqe_cache_line_end;
	u32 wqe_cache_line_size;
};

struct tag_roce_cmd_srq_query {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_cmd_modify_qpc {
	struct tag_roce_verbs_cmd_com com;

	u32 opt;
	u32 rsvd[3];
	struct roce_qp_context qpc;
};

struct tag_roce_cmd_qp_modify2rst {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_cmd_qp_modify_rts2sqd {
	struct tag_roce_verbs_cmd_com com;

	u32 sqd_event_en;
	u32 rsvd;
};

struct tag_roce_cmd_qp_query {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_cmd_modify_ctx {
	struct tag_roce_verbs_cmd_com com;
	u32 ctx_type;
	u32 offset;
	u32 value;
	u32 mask;
};

struct tag_roce_cmd_cap_pkt {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_modify_hash_value {
	struct tag_roce_verbs_cmd_com com;
	u32 hash_value;
};

struct tag_roce_modify_udp_src_port {
	struct tag_roce_verbs_cmd_com com;
	u32 udp_src_port;
};

struct roce_get_qp_udp_src_port {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_get_qp_rx_port {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_get_qp_func_table {
	struct tag_roce_verbs_cmd_com com;
};

#endif /* ROCE_VERBS_CMD_H */
