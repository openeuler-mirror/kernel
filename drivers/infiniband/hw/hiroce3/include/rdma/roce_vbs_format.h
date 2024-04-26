/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VBS_FORMAT_H
#define ROCE_VBS_FORMAT_H

#include "roce_wqe_format.h"
#include "roce_xqe_format.h"

#ifdef ROCE_VBS_EN

struct roce_wqe_vbs_rdma_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 data_len; /* Length of the data sent by the SQ WQE */

	/* DW2 */
	u32 dw2;

	/* DW3 */
	union roce3_wqe_tsk_misc_seg dw3;
};
#else

union roce_wqe_vbs_tsk_misc_seg {
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 request_id : 16;
		u32 xts_vld : 1;
		u32 rq_buf_shift : 4;
		u32 sio_grp_num : 3;
		u32 sio_grp4_len : 8;

		u32 sio_grp3_len : 8;
		u32 sio_grp2_len : 8;
		u32 sio_grp1_len : 8;
		u32 sio_grp0_len : 8;
#else
		u32 sio_grp0_len : 8;
		u32 sio_grp1_len : 8;
		u32 sio_grp2_len : 8;
		u32 sio_grp3_len : 8;

		u32 sio_grp4_len : 8;
		u32 sio_grp_num : 3;
		u32 rq_buf_shift : 4;
		u32 xts_vld : 1;
		u32 request_id : 16;
#endif
	} bs;
	u64 value;
};

struct roce_wqe_vbs_aad_seg {
	union {
		struct {
			u32 pdu_difx_en : 1;
			u32 pad_len_vld : 1;
			u32 pdu_pad_len : 2;
			u32 smd_tp : 4;
			u32 rsvd0 : 1;
			u32 msg_hdr_vld : 1;
			u32 msg_hdr_len : 2;
			u32 rd_difx_rslt : 1;
			u32 vbs_difx : 1;
			u32 rsvd1 : 1;
			u32 pdu_difx_cnt : 9;
			u32 rsvd2 : 4;
			u32 sio_num : 4;
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
			u32 fst_pdu : 1;
			u32 fst_sct : 1;
			u32 last_pdu : 1;
			u32 rsp_indiv : 1;
			u32 sct_sz : 1;
			u32 dsgl : 1;
			u32 rsp_vld : 1;
			u32 rsp_len : 5;
			u32 app_esc : 1;
			u32 ref_esc : 1;
			u32 sct_v_tp : 2;
			u32 grd_v_en : 1;
			u32 grd_rid : 2;
			u32 grd_v_agm : 1;
			u32 grd_ri_agm : 1;
			u32 grd_agm_ini : 1;
			u32 crc16_ini : 1;
			u32 ipcs_ini : 1;
			u32 ref_v_en : 1;
			u32 ref_rid : 2;
			u32 ref_v_inc : 1;
			u32 ref_ri_inc : 1;
			u32 app_v_en : 1;
			u32 app_rid : 2;
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
			u32 task_tag : 16;
			u32 rep_app_tag : 16;
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
			u32 cmp_app_tag : 16;
			u32 cmp_app_tag_msk : 16;
		} bs;
		u32 value;
	} dw3;

	u32 cmp_ref_tag;

	u32 rep_ref_tag;

	union {
		struct {
			u32 pdu_sd_ofs : 13;
			u32 rsvd0 : 1;
			u32 pdu_sd_len : 18;
		} bs;
		u32 value;
	} dw6;
};

struct roce_wqe_vbs_subinfo {
	union {
		struct {
			u32 sio0_size : 4;
			u32 sio1_size : 4;
			u32 sio2_size : 4;
			u32 sio3_size : 4;
			u32 sio4_size : 4;
			u32 sio5_size : 4;
			u32 sio6_size : 4;
			u32 sio7_size : 4;
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
			u32 sio0_crc2_ini : 16;
			u32 sio1_crc2_ini : 16;
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
			u32 sio2_crc2_ini : 16;
			u32 sio3_crc2_ini : 16;
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
			u32 sio4_crc2_ini : 16;
			u32 sio5_crc2_ini : 16;
		} bs;
		u32 value;
	} dw3;

	union {
		struct {
			u32 sio6_crc2_ini : 16;
			u32 sio7_crc2_ini : 16;
		} bs;
		u32 value;
	} dw4;
};

struct roce_wqe_vbs_rdma_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 data_len; /* Length of the data sent by the SQ WQE */

	/* DW2 */
	/* This parameter is valid for the immediate data operation or SEND invalidate. */
	u32 wqe_ext_len;

	/* DW3 */
	union roce3_wqe_tsk_misc_seg dw3;

	/* DW4~5 */
	union roce_wqe_vbs_tsk_misc_seg misc;

	u32 rsvd[2];

	struct roce_wqe_vbs_aad_seg vbs_aad;
};

#endif

#endif
