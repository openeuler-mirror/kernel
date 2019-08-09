/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef HISI_SEC_USR_IF_H
#define HISI_SEC_USR_IF_H

struct hisi_sec_sqe_type1 {
	__u32 rsvd2:6;
	__u32 ci_gen:2;
	__u32 ai_gen:2;
	__u32 rsvd1:7;
	__u32 c_key_type:2;
	__u32 a_key_type:2;
	__u32 rsvd0:10;
	__u32 inveld:1;

	__u32 mac_len:6;
	__u32 a_key_len:5;
	__u32 a_alg:6;
	__u32 rsvd3:15;
	__u32 c_icv_len:6;
	__u32 c_width:3;
	__u32 c_key_len:3;
	__u32 c_mode:4;
	__u32 c_alg:4;
	__u32 rsvd4:12;
	__u32 auth_gran_size:24;
	__u32:8;
	__u32 cipher_gran_size:24;
	__u32:8;
	__u32 auth_src_offset:16;
	__u32 cipher_src_offset:16;
	__u32 gran_num:16;
	__u32 rsvd5:16;
	__u32 src_skip_data_len:24;
	__u32 rsvd6:8;
	__u32 dst_skip_data_len:24;
	__u32 rsvd7:8;
	__u32 tag:16;
	__u32 rsvd8:16;
	__u32 gen_page_pad_ctrl:4;
	__u32 gen_grd_ctrl:4;
	__u32 gen_ver_ctrl:4;
	__u32 gen_app_ctrl:4;
	__u32 gen_ver_val:8;
	__u32 gen_app_val:8;
	__u32 private_info;
	__u32 gen_ref_ctrl:4;
	__u32 page_pad_type:2;
	__u32 rsvd9:2;
	__u32 chk_grd_ctrl:4;
	__u32 chk_ref_ctrl:4;
	__u32 block_size:16;
	__u32 lba_l;
	__u32 lba_h;
	__u32 a_key_addr_l;
	__u32 a_key_addr_h;
	__u32 mac_addr_l;
	__u32 mac_addr_h;
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 c_key_addr_l;
	__u32 c_key_addr_h;
	__u32 data_src_addr_l;
	__u32 data_src_addr_h;
	__u32 data_dst_addr_l;
	__u32 data_dst_addr_h;
	__u32 done:1;
	__u32 icv:3;
	__u32 rsvd11:3;
	__u32 flag:4;
	__u32 dif_check:3;
	__u32 rsvd10:2;
	__u32 error_type:8;
	__u32 warning_type:8;
	__u32 dw29;
	__u32 dw30;
	__u32 dw31;
};

struct hisi_sec_sqe_type2 {
	__u32 nonce_len:4;
	__u32 huk:1;
	__u32 key_s:1;
	__u32 ci_gen:2;
	__u32 ai_gen:2;
	__u32 a_pad:2;
	__u32 c_s:2;
	__u32 rsvd1:2;
	__u32 rhf:1;
	__u32 c_key_type:2;
	__u32 a_key_type:2;
	__u32 write_frame_len:3;
	__u32 cal_iv_addr_en:1;
	__u32 tls_up:1;
	__u32 rsvd0:5;
	__u32 inveld:1;
	__u32 mac_len:5;
	__u32 a_key_len:6;
	__u32 a_alg:6;
	__u32 rsvd3:15;
	__u32 c_icv_len:6;
	__u32 c_width:3;
	__u32 c_key_len:3;
	__u32 c_mode:4;
	__u32 c_alg:4;
	__u32 rsvd4:12;
	__u32 a_len:24;
	__u32 iv_offset_l:8;
	__u32 c_len:24;
	__u32 iv_offset_h:8;
	__u32 auth_src_offset:16;
	__u32 cipher_src_offset:16;
	__u32 cs_ip_header_offset:16;
	__u32 cs_udp_header_offset:16;
	__u32 pass_word_len:16;
	__u32 dk_len:16;
	__u32 salt3:8;
	__u32 salt2:8;
	__u32 salt1:8;
	__u32 salt0:8;
	__u32 tag:16;
	__u32 rsvd5:16;
	__u32 c_pad_type:4;
	__u32 c_pad_len:8;
	__u32 c_pad_data_type:4;
	__u32 c_pad_len_field:2;
	__u32 rsvd6:14;
	__u32 long_a_data_len_l;
	__u32 long_a_data_len_h;
	__u32 a_ivin_addr_l;
	__u32 a_ivin_addr_h;
	__u32 a_key_addr_l;
	__u32 a_key_addr_h;
	__u32 mac_addr_l;
	__u32 mac_addr_h;
	__u32 c_ivin_addr_l;
	__u32 c_ivin_addr_h;
	__u32 c_key_addr_l;
	__u32 c_key_addr_h;
	__u32 data_src_addr_l;
	__u32 data_src_addr_h;
	__u32 data_dst_addr_l;
	__u32 data_dst_addr_h;
	__u32 done:1;
	__u32 icv:3;
	__u32 rsvd11:3;
	__u32 flag:4;
	__u32 rsvd10:5;
	__u32 error_type:8;
	__u32 warning_type:8;
	__u32 mac_i3:8;
	__u32 mac_i2:8;
	__u32 mac_i1:8;
	__u32 mac_i0:8;
	__u32 check_sum_i:16;
	__u32 tls_pad_len_i:8;
	__u32 rsvd12:8;
	__u32 counter;
};

struct hisi_sec_sqe {
	__u32 type:4;
	__u32 cipher:2;
	__u32 auth:2;
	__u32 seq:1;
	__u32 de:2;
	__u32 scene:4;
	__u32 src_addr_type:3;
	__u32 dst_addr_type:3;
	__u32 mac_addr_type:3;
	__u32 rsvd0:8;
	union {
		struct hisi_sec_sqe_type1 type1;
		struct hisi_sec_sqe_type2 type2;
	};
};

enum C_ALG {
	C_ALG_DES  = 0x0,
	C_ALG_3DES = 0x1,
	C_ALG_AES  = 0x2,
	C_ALG_SM4  = 0x3,
};

enum C_MODE {
	C_MODE_ECB    = 0x0,
	C_MODE_CBC    = 0x1,
	C_MODE_CTR    = 0x4,
	C_MODE_CCM    = 0x5,
	C_MODE_GCM    = 0x6,
	C_MODE_XTS    = 0x7,
	C_MODE_CBC_CS = 0x9,
};

enum CKEY_LEN {
	CKEY_LEN_128_BIT = 0x0,
	CKEY_LEN_192_BIT = 0x1,
	CKEY_LEN_256_BIT = 0x2,
	CKEY_LEN_DES     = 0x1,
	CKEY_LEN_3DES_3KEY = 0x1,
	CKEY_LEN_3DES_2KEY = 0x3,
};

enum {
	BD_TYPE1 = 0x1,
	BD_TYPE2 = 0x2,
};

#endif
