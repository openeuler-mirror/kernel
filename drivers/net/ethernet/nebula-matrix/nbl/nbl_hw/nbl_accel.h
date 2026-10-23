/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 nebula-matrix Limited.
 * Author: Rocky Xie <rocky.xie@nebula-matrix.com>
 */

#ifndef _NBL_ACCEL_H_
#define _NBL_ACCEL_H_
#include "nbl_resource.h"

#define NBL_IPSEC_SOFT_EXPIRE			0x80
#define NBL_IPSEC_HARD_EXPIRE			0x100

#define NBL_DIPSEC_SAD_IP_TOTAL			8
#define NBL_DIPSEC_SAD_IP_LEN			4
#define NBL_UIPSEC_BYTE_LEN			20
#define NBL_UIPSEC_POWER			9
#define NBL_IPSEC_LIFETIME_ROUND		31
#define NBL_ACCEL_TMEP_SPEC			1024
#define NBL_IPSEC_BLOCK_NUM			64

#pragma pack(1)

struct nbl_ipsec_tbl_add {
	u32 opcode : 4;
	u32 pf_id : 2;
	u32 kt_idx : 10;
	u32 oft : 1;
	u32 key_l : 15;
	u32 key_m[4];
	u32 key_h : 19;
	u32 act : 10;
	u32 rsv1 : 3;
	u32 rsv2[2];
};

struct nbl_ipsec_tbl_add_rsp {
	u32 opcode : 4;
	u32 status : 2;
	u32 errcode : 4;
	u32 tbl_type : 1;
	u32 tbl_idx : 9;
	u32 slot : 2;
	u32 hash0_data : 8;
	u32 hash1_datal : 2;
	u32 hash1_datah : 6;
	u32 rsv1 : 26;
	u32 rsv2[6];
};

struct nbl_ipsec_tbl_search {
	u32 opcode : 4;
	u32 pf_id : 2;
	u32 mode : 1;
	u32 del_on_hit : 1;
	u32 key_l : 24;
	u32 key_m[4];
	u32 key_h : 10;
	u32 rsv1 : 22;
	u32 rsv2[2];
};

struct nbl_ipsec_tbl_search_rsp {
	u32 opcode : 4;
	u32 status : 2;
	u32 errcode : 4;
	u32 hit_pos : 1;
	u32 hash0_data : 8;
	u32 hash1_data : 8;
	u32 ad_l : 5;
	u32 ad_h : 5;
	u32 rsv1 : 27;
	u32 rsv2[6];
};

struct nbl_ipsec_kt_alloc {
	u32 opcode : 4;
	u32 pf_id : 2;
	u32 rsv1 : 26;
	u32 rsv2[7];
};

struct nbl_ipsec_kt_alloc_rsp {
	u32 opcode : 4;
	u32 status : 2;
	u32 errcode : 4;
	u32 kt_idx : 10;
	u32 rsv1 : 12;
	u32 rsv2[7];
};

struct nbl_ipsec_kt_free {
	u32 opcode : 4;
	u32 mode : 1;
	u32 pf_id : 2;
	u32 kt_idx : 10;
	u32 rsv1 : 15;
	u32 rsv2[7];
};

struct nbl_ipsec_kt_free_rsp {
	u32 opcode : 4;
	u32 status : 2;
	u32 errcode : 4;
	u32 rsv1 : 22;
	u32 rsv2[7];
};

struct nbl_ipsec_tbl_write {
	u32 opcode : 4;
	u32 tbl_type : 4;
	u32 pf_id : 2;
	u32 tbl_addr : 12;
	u32 tbl_wdat_l : 10;
	u32 tbl_wdat_m[5];
	u32 tbl_wdat_h : 2;
	u32 rsv1 : 30;
	u32 rsv2;
};

struct nbl_ipsec_tbl_write_rsp {
	u32 opcode : 4;
	u32 tbl_type : 4;
	u32 status : 2;
	u32 errcode : 4;
	u32 rsv1 : 18;
	u32 rsv2[7];
};

struct nbl_ipsec_tbl_read {
	u32 opcode : 4;
	u32 tbl_type : 4;
	u32 pf_id : 2;
	u32 tbl_addr : 16;
	u32 rsv1 : 6;
	u32 rsv2[7];
};

struct nbl_ipsec_tbl_read_rsp {
	u32 opcode : 4;
	u32 tbl_type : 4;
	u32 status : 2;
	u32 errcode : 4;
	u32 tbl_rdat_l : 18;
	u32 tbl_rdat_m[4];
	u32 tbl_rdat_h : 27;
	u32 rsv1 : 5;
	u32 rsv2[2];
};

#pragma pack()

#endif
