/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_ATTR_H
#define ROCE_VERBS_ATTR_H

#include "roce_verbs_mr_attr.h"
#include "roce_verbs_gid_attr.h"
#include "roce_verbs_cq_attr.h"
#include "roce_verbs_srq_attr.h"
#include "roce_verbs_attr_qpc_chip.h"

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 0x4321
#endif

#define ROCE_VERBS_SQ_WQEBB_SIZE (2)
#define ROCE_VERBS_SQ_PI_VLD (1)

#pragma pack(push, 4)
/* qpc_attr_com info ,12*4B */
struct tag_roce_verbs_qpc_attr_com {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 service_type : 3;
			u32 fre : 1;
			u32 rwe : 1;
			u32 rre : 1;
			u32 rae : 1;
			u32 rkey_en : 1;
			u32 dest_qp : 24;
#else
			/*
			 * Destination QP number, which is extended to 24 bits in
			 * consideration of interconnection with commercial devices.
			 */
			u32 dest_qp : 24;
			u32 rkey_en : 1;
			u32 rae : 1;
			u32 rre : 1;
			u32 rwe : 1;
			/* Indicates whether the local FRPMR is enabled. */
			u32 fre : 1;
			/* Transmission Type
			 * 000:RC
			 * 001:UC
			 * 010:RD
			 * 011 UD
			 * 101:XRC
			 * Other:Reserved
			 */
			u32 service_type : 3;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sra_max : 3;
			u32 rra_max : 3;
			u32 rnr_retry_limit : 3;
			u32 to_retry_limit : 3;
			u32 local_qp : 20;
#else
			u32 local_qp : 20;	   /* Local QP number */
			/*
			 * Number of ACK retransmissions. The value 7 indicates unlimited
			 * times, and the value 0 indicates no retransmission.
			 */
			u32 to_retry_limit : 3;
			/*
			 * The maximum number of RNR retransmissions is 7. The value 7
			 * indicates that the maximum number of retransmissions is 7, and
			 * the value 0 indicates that the retransmission is not performed.
			 */
			u32 rnr_retry_limit : 3;
			/* The maximum value of responser resource is 128. */
			u32 rra_max : 3;
			/* The maximum value of initiator depth is 128. */
			u32 sra_max : 3;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ack_to : 5;
			u32 min_rnr_nak : 5;
			u32 cont_size : 2;
			u32 cont_en : 1;
			u32 srq_en : 1;
			u32 xrc_srq_en : 1;
			u32 vroce_en : 1;
			u32 host_oqid : 16;
#else
			u32 host_oqid : 16;
			u32 vroce_en : 1;
			u32 xrc_srq_en : 1;
			u32 srq_en : 1;
			u32 cont_en : 1;
			u32 cont_size : 2;
			/*
			 * NAK code of RNR. This parameter is mandatory when INIT2RNR and
			 * RTR2RTS\SQE2RTS\SQD2SQD\SQD2RTS is optional.
			 */
			u32 min_rnr_nak : 5;
			u32 ack_to : 5;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 tss_timer_num : 3;
			u32 xrc_vld : 1;
			u32 srq_container : 1;
			u32 invalid_credit : 1;
			u32 ext_md : 1;
			u32 ext_mtu : 1;
			u32 dsgl_en : 1;
			u32 dif_en : 1;
			u32 pmtu : 3;
			u32 base_mtu_n : 1;
			u32 pd : 18;
#else
			u32 pd : 18;
			u32 base_mtu_n : 1;
			u32 pmtu : 3;
			u32 dif_en : 1;
			u32 dsgl_en : 1;
			u32 ext_mtu : 1;
			u32 ext_md : 1;
			u32 invalid_credit : 1;
			u32 srq_container : 1;
			u32 xrc_vld : 1;
			u32 tss_timer_num : 3;
#endif
		} bs;

		u32 value;
	} dw3;

	/* DW4 */
	u32 q_key;

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ulp_type : 8;
			u32 oor_en : 1;
			u32 capture_en : 1;
			u32 rsvd : 1;
			u32 acx_mark : 1;
			u32 mtu_code : 4;
			u32 port : 2;
			u32 ep : 3;
			u32 cos : 3;
			u32 so_ro : 2;
			u32 dma_attr_idx : 6;
#else
			u32 dma_attr_idx : 6;
			u32 so_ro : 2;
			u32 cos : 3;
			u32 ep : 3;
			u32 port : 2;
			u32 mtu_code : 4;
			u32 acx_mark : 1;
			u32 rsvd : 1;
			u32 capture_en : 1;
			u32 oor_en : 1;
			u32 ulp_type : 8;
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sd_mpt_idx : 12;
			u32 rsvd : 20;
#else
			u32 rsvd : 20;
			u32 sd_mpt_idx : 12;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 10;
			u32 sq_cqn_lb : 1;
			u32 rq_cqn_lb : 1;
			u32 rq_cqn : 20;
#else
			u32 rq_cqn : 20;
			u32 rq_cqn_lb : 1;
			u32 sq_cqn_lb : 1;
			u32 rsvd : 10;
#endif
		} bs;
		u32 value;
	} dw7;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 next_send_psn : 24;
#else
			u32 next_send_psn : 24;
			u32 rsvd : 8;
#endif
		} bs;
		u32 value;
	} dw8;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 next_rcv_psn : 24;
#else
			u32 next_rcv_psn : 24;
			u32 rsvd : 8;
#endif
		} bs;
		u32 value;
	} dw9;

	/* DW10 */
	u32 lsn;

	/* DW11 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 17;
			u32 set_mpt_indx : 1;
			u32 fake : 1;
			u32 vf_id : 13;
#else
			u32 vf_id : 13;
			u32 fake : 1;
			u32 set_mpt_indx : 1;
			u32 rsvd : 17;
#endif
		} bs;
		u32 value;
	} dw11;

	/* DW12 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ccf_app_id : 8;
			u32 rsvd : 24;
#else
			u32 rsvd : 24;
			u32 ccf_app_id : 8;
#endif
		} bs;
		u32 value;
	} dw12;
};

struct tag_roce_verbs_qpc_attr_path {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 bond_tx_hash_value : 16;
			u32 dmac_h16 : 16;
#else
			u32 dmac_h16 : 16;
			u32 bond_tx_hash_value : 16;
#endif
		} bs;
		u32 value;
	} dw0;

	u32 dmac_l32;

	/* DW2~5 */
	u8 dgid[16];

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 4;
			u32 tclass : 8;
			u32 flow_label : 20;
#else
			u32 flow_label : 20; /* GRH flow lable */
			u32 tclass : 8;
			u32 rsvd : 4;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sl : 3;
			u32 loop : 1;
			u32 udp_src_port : 8;
			u32 rsvd : 4;
			u32 base_sgid_n : 1;
			u32 sgid_index : 7;
			u32 hoplmt : 8;
#else
			u32 hoplmt : 8;
			u32 sgid_index : 7;
			u32 base_sgid_n : 1;
			u32 rsvd : 4;
			u32 udp_src_port : 8;
			u32 loop : 1;
			u32 sl : 3;
#endif
		} bs;
		u32 value;
	} dw7;
};

struct roce_verbs_qpc_attr_nof_aa {
	u32 gid_index;
	u32 qid;
	u32 local_comm_id;
	u32 remote_comm_id;
};

struct roce_verbs_qpc_attr_vbs {
	u32 sqpc_ci_record_addr_h;
	u32 sqpc_ci_record_addr_l;
};

struct roce_verbs_qpc_attr_ext {
	struct roce_verbs_qpc_attr_nof_aa nof_aa_info;
	struct roce_verbs_qpc_attr_vbs vbs_info;
};

/* QPC Struct */
struct tag_roce_verbs_qp_attr {
	/* com seg, DW0 ~ DW11 */
	struct tag_roce_verbs_qpc_attr_com com_info;

	/* path seg, DW0 ~ DW7 */
	struct tag_roce_verbs_qpc_attr_path path_info;

	/* chip seg, DW0 ~ DW19 */
	struct tag_roce_verbs_qpc_attr_chip chip_seg;

	/* ext seg */
	struct roce_verbs_qpc_attr_ext ext_seg;
};


struct tag_roce_verbs_qp_hw2sw_info {
	/* DW0~1 */
	u32 sq_buf_len; /* Buffer length of the SQ queue */
	u32 rq_buf_len; /* Buffer length of the RQ queue */

	/* DW2~6 */
	struct tag_roce_verbs_mtt_cacheout_info cmtt_cache;

	/* DW7~8 */
	union {
		u64 wb_gpa; /* Address written back by the ucode after processing */

		struct {
			u32 syn_gpa_hi32; /* Upper 32 bits of the start address of mr or mw */
			u32 syn_gpa_lo32; /* Lower 32 bits of the start address of mr or mw */
		} gpa_dw;
	};
	union {
		struct {
			u32 rsvd : 16;
			u32 host_oqid : 16;
		} bs;

		u32 value;
	} dw9;
	struct tag_roce_verbs_wqe_cacheout_info wqe_cache;
};

struct tag_roce_verbs_modify_ctx_info {
	u32 ctx_type;
	u32 offset;
	u32 value;
	u32 mask;
};

#pragma pack(pop)

#endif /* ROCE_VERBS_ATTR_H */
