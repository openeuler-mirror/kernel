/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hisec_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : COMM Commands and struct define between hinicadmdfx and DRIVER(ipsec)
 */

#ifndef HISEC_PUB_CMD_H
#define HISEC_PUB_CMD_H

#include "base_type.h"

/* hisec_cmd_table maximum size is 2MB, minus the size of ipsec_tbl_args */
#define IPSEC_TBL_BUF_MAX (2048 * 1024 - sizeof(ipsec_tbl_args))

typedef enum hisec_driver_cmd_type {
	HISEC_DRIVER_CMD_SET_IPSEC_SA = 0,
	HISEC_DRIVER_CMD_SET_IPSEC_SP,
	HISEC_DRIVER_CMD_SET_IPSEC_MASK,
	HISEC_DRIVER_CMD_LIST_IPSEC_SA,
	HISEC_DRIVER_CMD_LIST_IPSEC_SP,
	HISEC_DRIVER_CMD_GET_IPSEC_SA_EXCIDS,
	HISEC_DRIVER_CMD_GET_IPSEC_SP_EXCIDS,
	HISEC_DRIVER_CMD_GET_TRNG,
	HISEC_DRIVER_CMD_GET_ANTIREPLAY_INFO,
	HISEC_DRIVER_CMD_GET_IPSEC_INFO,
	HISEC_DRIVER_CMD_GET_VERSION = 16,
} hisec_driver_cmd_type_e;

typedef struct tag_hisec_driver_cmd_hdr {
	union {
		struct {
			u32 rsvd0 : 16;
			u32 channel_id : 8; /* logical concurrency channel */
			u32 cmd_type : 8;   /* cmd type */
		} bs;
		u32 value;
	} dw0;

	u32 cmd_sn;
	u32 rsvd1[2];
} hisec_driver_cmd_hdr_s;

#define IPSEC_ANTIREPLAY_BITMAP_MAX_LEN 512

typedef struct {
	u64 ipsec_in_pkt_num;
	u64 ipsec_out_pkt_num;

	u32 ipsec_drop_pkt_num;
	u32 ipsec_pkt_replay_without_esn_error;
	u32 ipsec_pkt_top_seq_error;
	u32 ipsec_pkt_anti_replay_error;
	u32 ipsec_pkt_invalid_error;
} ipsec_antireplay_counter;

typedef struct {
	u64 rx_seq;
	u64 tx_seq;

	u32 replaywin;
	u16 esn_flag;
	u16 exid;

	u16 funcid;
	u16 valid;
	u16 dir;
	u16 rsvd;

	u64 bitmap[IPSEC_ANTIREPLAY_BITMAP_MAX_LEN];
} ipsec_antireplay_info ;

struct ipsec_soft_antireplay_info {
	ipsec_antireplay_info info;
	ipsec_antireplay_counter counter;
};

#define HISEC_ENABLE_HARDWARE_ANTIREPLAY 1
#define HISEC_HARDWARE_ANTIREPLAY_WINDOW_SIZE 64
/* Software constraint: software anti-replay window minimum size is 256 */
#define HISEC_SOFTWARE_ANTIREPLAY_MIN_WINDOW_SIZE 256

struct hinic5_ipsec_driver_enc_info {
	u8 proto;     /* tcp/udp */
	u8 direction; /* out/in */
	u8 mode;      /*  0 transport/ 1 tunnel */
	u8 flag;      /* 1 - esn */

	u16 replaywindow; /* 32-64 */
	u8 alg_type;      /* 0- aead 1-enc 2-auth 3-enc & auth */
	u8 alg_standard;  /* 0 - aes, 1 - SM4 */

	u8 enc_type;  /* hisec_crypto_alg_type */
	u8 auth_type; /* hisec_crypto_alg_type */

	u16 cipher_key_len; /* in  bit */
	u32 cipher_key[8];  /* 128bit 192bit 256bit  */
	u32 salt;           /* 32bit */

	u16 auth_key_len;   /* in bit  */
	u16 auth_trunc_len; /* in bit */
	u16 icv_mac_len;    /* in bit */
	u8 out_ip_type;
	u8 hard_antireplay_en;
	u32 auth_key[32]; /* 1024bit */

	u32 tunnel_sip[4];
	u32 tunnel_dip[4];

	u8 tfc_padding_en;
	u8 tfc_pad_len;
	u8 tfc_pad_val;
	u8 encrypt_path_sel; /* 0 - fast path, 1 - slow path */

	u64 top_seq;
};

typedef struct tag_hisec_driver_cmd_set_ipsec_sa {
	hisec_driver_cmd_hdr_s cmdhdr;

	u32 saddr[4];
	u32 daddr[4];   /* ipv4 in daddr[0] */
	u32 spi;

	u8 ipsec_proto;
	u8 opid;        /* | 0 - add  | 1 - del  | 2 - update | 3 - flush | */
	u8 iptype;      /* | 0 - ipv4 | 1 - ipv6 | */
	u8 ipsec_tls_flag;

	u16 sport;
	u16 dport;

	u16 vlan_id;
	u16 dmac_h16;

	u32 dmac_l32;

	u32 rsvd1;

	u32 isn;

	struct hinic5_ipsec_driver_enc_info enc_info;
} hisec_driver_cmd_set_ipsec_sa_s;

typedef struct tag_hisec_driver_cmd_set_ipsec_sp {
	hisec_driver_cmd_hdr_s cmdhdr;

	u32 saddr[4];
	u32 daddr[4];   /* dip ipv4 in daddr[0] */
	u32 spi;

	u16 vid;
	u16 dport;

	u8 ulp_proto;   /* | 6  - tcp    | 17 - udp     | */
	u8 ipsec_proto; /* | 50 - esp    | 51 - ah      | */
	u8 opid;        /* | 0  - add    | 1  - del     | 2 - update | */
	u8 iptype;      /* | 0  - ipv4   | 1  - ipv6    | */

	u8 action;      /* | 0  - bypass | 1  - protect | 2 - drop   | */
	u8 rsvd0;
	u16 rsvd1;

	u16 sport;
	u16 rsvd2;

	u32 rsvd3[3];
} hisec_driver_cmd_set_ipsec_sp_s;

typedef struct {
	u32 index;
	u32 cnt;
	u32 total_cnt;
} ipsec_tbl_args;

struct hisec_cmd_table {
	ipsec_tbl_args args;
	u8 tbl_buf[IPSEC_TBL_BUF_MAX];
};

typedef struct tag_hisec_cmd_get_trng_req {
	u32 req_num;
	u8 tbl_buf[IPSEC_TBL_BUF_MAX];
} hisec_cmd_get_trng_req_s;

enum operation_type {
	ADD = 0,
	DELETE,
	UPDATE,
	FLUSH,
	LIST,
	SET,
	DUMP,
	ANTIREPLAY,
	OPER_TYPE_MAX,
};

enum algorithm_type {
	ALGO_AEAD = 0,
	ALGO_ENC,
	ALGO_AUTH,
	ALGO_ENC_AND_AUTH,
};

enum algo_name_type {
	RFC4106_GCM_AES = 0,
	CBC_AES,
	RFC3686_CTR_AES,
	HMAC_SHA1,
	HMAC_SHA256,
	HMAC_SHA384,
	HMAC_SHA512,
	HMAC_SM3,
	SM4_GCM,
	ALG_TYPE_MAX,
};

enum alg_standard_type {
	ALG_STANDARD_AES = 0,
	ALG_STANDARD_SM4,
};

enum encapsulation_mode {
	TRANSPORT = 0,
	TUNNEL,
	NATT_TUNNEL,
	ENCAPSULATION_MODE_MAX = 3,
};

enum traffic_direction {
	OUTBOUND = 0,
	INBOUND,
};

/**
 * @brief IPSec SPD action define
 * @application scope used by tool and crypt driver
 * @note the definition must be consistent with that of <hisec_npu_cmd.h>
 */
typedef enum {
	HISEC_CMD_SPD_ACTION_BYPASS = 0,
	HISEC_CMD_SPD_ACTION_PROTECT = 1,
	HISEC_CMD_SPD_ACTION_DROP = 2,
	HISEC_CMD_SPD_ACTION_MAX,
} hisec_cmd_spd_action_type_e;

/* IPsec mask info  */
typedef struct tag_hisec_ipsec_mask_info_st {
	u32 sa_key_mask;
	u32 sp_key_mask;

	u32 rsvd0[2];
} hisec_ipsec_mask_info_s;

#define IPSEC_SA_MAX_NUM (64 * 1024)
#define IPSEC_SP_MAX_NUM (32 * 1024)

struct hisec_cmd_get_sa_excids_out_buf {
	u32 excids_size;
	u16 excids[IPSEC_SA_MAX_NUM];
};

struct hisec_cmd_get_sp_excids_out_buf {
	u32 excids_size;
	u16 excids[IPSEC_SP_MAX_NUM];
};

typedef struct hisec_cmd_get_ipsec_info_out_buf {
	u32 sa_ctxs;
	u32 sp_ctxs;
	u8 sa_mask;
	u8 sp_mask;
	u8 ipsec_work_mode;
	u8 white_list;
} hisec_cmd_get_ipsec_info_out_buf_s;

#endif /* _HISEC_PUB_CMD_H_ */
