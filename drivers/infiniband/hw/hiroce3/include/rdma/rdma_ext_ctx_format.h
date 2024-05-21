/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef RDMA_EXT_CTX_FORMAT_H
#define RDMA_EXT_CTX_FORMAT_H

#include "roce_compile_macro.h"

#include "roce_ccf_format.h"

#ifdef ROCE_VBS_EN
#include "roce_vbs_format.h"
#endif

#include "roce_dif_format.h"
/* Align each field with 4bytes. */
#pragma pack(push, 4)

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN	0x1234
#endif

/***********************************/
struct ucode_dcc_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 back_token : 9;
			u32 token : 13;
			u32 alpha : 10;
#else
			u32 alpha : 10;
			u32 token : 13;
			u32 back_token : 9;
#endif
		} dcqcn;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 less_mtu_cnt : 2;
			u32 alpha : 2;
			u32 beta : 2;
			u32 set_flag : 1;
			u32 rsvd : 1;
			u32 sw_wnd_fraction : 12;
			u32 sw_wnd : 12;
#else
			u32 sw_wnd : 12;
			u32 sw_wnd_fraction : 12;
			u32 rsvd : 1;
			u32 set_flag : 1;
			u32 beta : 2;
			u32 alpha : 2;
			u32 less_mtu_cnt : 2;
#endif
		} ldcpw;

		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ccf_en : 1;
			u32 cnp_receive : 1;
			u32 cur_rate : 15;
			u32 target_rate : 15;
#else
			u32 target_rate : 15;
			u32 cur_rate : 15;
			u32 cnp_receive : 1;
			u32 ccf_en : 1;
#endif
		} dcqcn;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ccf_en : 1;
			u32 dip_valid : 1;
			u32 dip_index : 16;
			u32 rsvd : 14;
#else
			u32 rsvd : 14;
			u32 dip_index : 16;
			u32 dip_valid : 1;
			u32 ccf_en : 1;
#endif
		} ipqcn;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ccf_en : 1;
			u32 mtu_thr_cnt : 2;
			u32 rsvd : 3;
			u32 sw_wnd_just_halve : 1;
			u32 rr_wnd_just_halve : 1;
			u32 rr_wnd_fraction : 12;
			u32 rr_wnd : 12;
#else
			u32 rr_wnd : 12;
			u32 rr_wnd_fraction : 12;
			u32 rr_wnd_just_halve : 1;
			u32 sw_wnd_just_halve : 1;
			u32 rsvd : 3;
			u32 mtu_thr_cnt : 2;
			u32 ccf_en : 1;
#endif
		} ldcpw;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ccf_en : 1;
			u32 rsvd : 31;
#else
			u32 rsvd : 31;
			u32 ccf_en : 1;
#endif
		} cc_common;

		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rate_timestamp : 13;
			u32 alpha_timestamp : 13;
			u32 cal_token_l : 6;
#else
			u32 cal_token_l : 6;
			u32 alpha_timestamp : 13;
			u32 rate_timestamp : 13;
#endif
		} dcqcn;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sw_left_ce_num : 12;
			u32 last_ack_event_timestamp : 20;
#else
			u32 last_ack_event_timestamp : 20;
			u32 sw_left_ce_num : 12;
#endif
		} ldcpw;

		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rcnp_timestamp : 13;
			u32 token_timestamp : 13;
			u32 f_cnt : 4;
			u32 cal_token_h : 2;
#else
			u32 cal_token_h : 2;
			u32 f_cnt : 4;
			u32 token_timestamp : 13;
			u32 rcnp_timestamp : 13;
#endif
		} dcqcn;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 wnd_ctrl_rtt : 16;
			u32 rr_left_ce_num : 12;
			u32 gamma : 2;
			u32 eta : 2;
#else
			u32 eta : 2;
			u32 gamma : 2;
			u32 rr_left_ce_num : 12;
			u32 wnd_ctrl_rtt : 16;
#endif
		} ldcpw;

		u32 value;
	} dw3;
};

/*************************************/
union ucode_ext_sq_ctx {
	struct ucode_ccf_sq_ctx ccf_sq;

	u32 rsvd;
};

union ucode_ext_sqa_ctx {
	struct ucode_ccf_sqa_ctx ccf_sqa;

	u32 rsvd[2];
};

union ucode_ext_rq_ctx {
	struct ucode_ccf_rq_ctx ccf_rq;
	u8 vbs_rq[4];
	u32 rsvd;
};

union ucode_ext_rqa_ctx {
	struct ucode_ccf_rqa_ctx ccf_rqa;

	u32 rsvd;
};

struct ucode_ext_ctx {
	/* DW0 */
	union ucode_ext_sq_ctx sq;

	/* DW1~2 */
	union ucode_ext_sqa_ctx sqa;

	/* DW3 */
	union ucode_ext_rq_ctx rq;

	/* DW4 */
	union ucode_ext_rqa_ctx rqa;

	/* DW5~8 */
	struct ucode_dcc_ctx dcc;
};

struct tag_nofaa_io_qpn_entry {
	u32 rsvd : 8;
	u32 io_qpn_2 : 12;
	u32 io_qpn_1 : 12;
};

struct ucode_nofaa_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 admin_qp : 1;
			u32 rts_bmp : 4;
			u32 nof_bmp : 4;
			u32 disconn : 1;
			u32 rsvd : 6;
			u32 cm_bmp : 16;
#else
			u32 cm_bmp : 16;
			u32 rsvd : 6;
			u32 disconn : 1;
			u32 nof_bmp : 4;
			u32 rts_bmp : 4;
			u32 admin_qp : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 nof_vport : 2;
			u32 gid_index_3 : 6;
			u32 rsvd2 : 2;
			u32 gid_index_2 : 6;
			u32 rsvd1 : 2;
			u32 gid_index_1 : 6;
			u32 rsvd0 : 2;
			u32 gid_index_0 : 6;
#else
			u32 gid_index_0 : 6;
			u32 rsvd0 : 2;
			u32 gid_index_1 : 6;
			u32 rsvd1 : 2;
			u32 gid_index_2 : 6;
			u32 rsvd2 : 2;
			u32 gid_index_3 : 6;
			u32 nof_vport : 2;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 io_qpn_2 : 12;
			u32 io_qpn_1 : 12;
#else
			u32 io_qpn_1 : 12;
			u32 io_qpn_2 : 12;
			u32 rsvd : 8;
#endif
		} admin_q;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 admin_qpn : 20;
			u32 rsvd : 4;
			u32 qid : 8;
#else
			u32 qid : 8;
			u32 rsvd : 4;
			u32 admin_qpn : 20;
#endif
		} io_q;
		u32 value;
	} dw2;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 io_qpn_4 : 12;
			u32 io_qpn_3 : 12;
#else
			u32 io_qpn_3 : 12;
			u32 io_qpn_4 : 12;
			u32 rsvd : 8;
#endif
		} admin_q;
		struct {
			u32 rsvd;
		} io_q;
		u32 value;
	} dw3;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 io_qpn_6 : 12;
			u32 io_qpn_5 : 12;
#else
			u32 io_qpn_5 : 12;
			u32 io_qpn_6 : 12;
			u32 rsvd : 8;
#endif
		} admin_q;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd;
#else
			u32 rsvd;
#endif
		} io_q;
		u32 value;
	} dw4;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 io_qpn_8 : 12;
			u32 io_qpn_7 : 12;
#else
			u32 io_qpn_7 : 12;
			u32 io_qpn_8 : 12;
			u32 rsvd : 8;
#endif
		} admin_q;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd;
#else
			u32 rsvd;
#endif
		} io_q;
		u32 value;
	} dw5;

	u32 rsvd[2];
};

#pragma pack(pop)

#endif // RDMA_EXT_CTX_FORMAT_H
