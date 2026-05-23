/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : macsec_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : COMM Commands between hinicadmdfx and DRIVER(macsec)
 */
#ifndef MACSEC_PUB_CMD_H
#define MACSEC_PUB_CMD_H

#include "macsec_mpu_cmd_defs.h"

#define HIMACSEC_MAX_SAK_KEY_LEN 32 // The max sak length is 32B
#define HIMACSEC_MAX_SA_IN_SC 4 // The macsec protocol stipulates
				// that SC can have a maximum of 4 SAs
#define HIMACSEC_SALT_BUF_SIZE 12 // The salt is 12B
#define HIMACSEC_ICV_LEN 16
#define HIMACSEC_TOOL_IN_BUF_MAX 1024
#define HIMACSEC_LIST_OUT_BUF_MAX (8 * 1024)
#define HIMACSEC_MIB_OUT_BUF_MAX (1 * 1024)
#define HIMACSEC_COUNTER_OUT_BUF_MAX 512
#define HIMACSEC_CRYPTO_ALGO_AES 0 // TODO: Algorithm type unification
#define HIMACSEC_CRYPTO_ALGO_SM4 1
#define HIMACSEC_POLICY_ENABLE 1
#define HIMACSEC_POLICY_DISABLE 0
#define HIMACSEC_KEY_LENGTH_128 16
#define HIMACSEC_KEY_LENGTH_256 32
#define HIMACSEC_REG_KEY_LENGTH_128 0
#define HIMACSEC_REG_KEY_LENGTH_256 1
#define HIMACSEC_XPN_MAX_REPLAY_WINDOWS ((1 << 30) - 1) // Maximum replay window
							// when XPN mode is enabled is 2^30 -1
#define HIMACSEC_DEFAULT_XPN_THRESHOLD 0xC000000000000000ULL // Default PN threshold in XPN mode
#define HIMACSEC_DEFAULT_PN_THRESHOLD 0xC0000000ULL // Default PN threshold in non-XPN mode
#define HIMACSEC_SET_SC_ENCODING_SA_BIT_VAL 0x1
#define HIMACSEC_SET_SC_PROTECTION_MODE_BIT_VAL 0x2
#define HIMACSEC_SET_SC_PROTECT_FRAMES_BIT_VAL 0x4
#define HIMACSEC_SET_SC_VALIDATE_FRAMES_BIT_VAL 0x8

// MIB query types
typedef enum {
	HIMACSEC_TOOL_MIB_TYPE_SC = 0,  // SC MIB information
	HIMACSEC_TOOL_MIB_TYPE_PORT,    // PORT MIB information
	HIMACSEC_TOOL_MIB_TYPE_MAX
} himacsec_tool_mib_type_e;

// SC protection mode in encryption direction
typedef enum {
	PROTECTION_MODE_INTERITY_ONLY = 0,      // Integrity check only
	PROTECTION_MODE_CONFIDENTIALITY,        // Integrity check and encryption
	PROTECTION_MODE_OFFSET_CONFIDENTIALITY, // Integrity check and encryption,
						// encrypted data can be offset by 0/30/50B
	PROTECTION_MODE_MAX
} himacsec_protection_mode_e;

// SC validation mode in decryption direction
typedef enum {
	VALIDATE_MODE_DISABLE = 1,  // Do not validate packets
	VALIDATE_MODE_CHECK,        // Validate only, no filtering
	VALIDATE_MODE_STRICT,       // Validate and filter
	VALIDATE_MODE_MAX
} himacsec_validate_mode_e;

// Algorithm definition
typedef enum {
	HIMACSEC_TOOL_CIPHER_GCM_AES_128 = 0,
	HIMACSEC_TOOL_CIPHER_GCM_AES_256,
	HIMACSEC_TOOL_CIPHER_GCM_AES_XPN_128,
	HIMACSEC_TOOL_CIPHER_GCM_AES_XPN_256,
	HIMACSEC_TOOL_CIPHER_GCM_SM4_128,
	HIMACSEC_TOOL_CIPHER_GCM_SM4_XPN_128,
	HIMACSEC_TOOL_CIPHER_MAX
} himacsec_tool_algo_e;

// Supported encryption offset specifications
typedef enum {
	HIMACSEC_CONFIDENTIALITY_OFFSET_0 = 0,
	HIMACSEC_CONFIDENTIALITY_OFFSET_30,
	HIMACSEC_CONFIDENTIALITY_OFFSET_50,
	HIMACSEC_CONFIDENTIALITY_OFFSET_MAX
} himacsec_confidentiality_ofs_e;

// MACsec object operation types
typedef enum {
	HIMACSEC_TOOL_OBJ_ENC_SC = 0,
	HIMACSEC_TOOL_OBJ_DEC_SC,
	HIMACSEC_TOOL_OBJ_ENC_SA,
	HIMACSEC_TOOL_OBJ_DEC_SA,
	HIMACSEC_TOOL_OBJ_MAX
} himacsec_tool_obj_e;

typedef enum macsec_direction {  // TODO: Unify with IPsec
	MACSEC_INBOUND = 0,
	MACSEC_OUTBOUND,
} crypt_direction_e;

typedef enum crypt_key_length {
	CRYPT_KEY_LENGTH_128 = 128,
	CRYPT_KEY_LENGTH_256 = 256
} crypt_key_length_e;

enum sc_status {
	SC_STATUS_NONE,
	SC_STATUS_CREATED,
	SC_STATUS_PN_THRESHOLD,
	SC_STATUS_MAX,
};

enum sa_status {
	SA_STATUS_NONE,
	SA_STATUS_CREATED,
	SA_STATUS_ENCODING,
	SA_STATUS_EXPIRED,
	SA_STATUS_MAX,
};

union obj_status {
	enum sc_status sc;
	enum sa_status sa;
};

struct himacsec_status {
	u64 create_time;
	u64 enable_time;
	union obj_status status;
	crypt_direction_e direct;
};

struct himacsec_sa {
	macsec_sa_info_s info;
	struct himacsec_status status;
};

struct himacsec_sc {
	macsec_sc_info_s info;
	struct himacsec_status status;
	struct himacsec_sa sa[HIMACSEC_MAX_SA_IN_SC];
};

// Command inbuf contains an hdr
typedef struct himacsec_cmd_hdr {
	u32 cmd_type;
	himacsec_tool_obj_e obj_type;
} himacsec_cmd_hdr_s;

// inbuf definition
typedef struct himacsec_cmd_in {
	himacsec_cmd_hdr_s hdr;
	u8 buf[HIMACSEC_TOOL_IN_BUF_MAX];
} himacsec_cmd_in_s;

// del command input parameter definition
struct himacsec_cmd_del_in {
	u64 sci;
	u8 an;
	u8 rsvd[7];
};

struct himacsec_cmd_set_sc_in {
	u64 sci;
	u32 set_flag_bitmap;
	u32 rsvd;
	macsec_sc_info_s sc;
};

// list and dump command outbuf output parameter definition
typedef struct himacsec_cmd_list_out {
	u32 enc_sc_cnt;
	u32 dec_sc_cnt;
	u8 enc_sc_buf[HIMACSEC_LIST_OUT_BUF_MAX]; // reserve the 100% resources for expansion
	u8 dec_sc_buf[HIMACSEC_LIST_OUT_BUF_MAX];
} himacsec_cmd_list_out_s;

// MIB input parameter definition
struct himacsec_cmd_mib_in {
	u64 sci;
	himacsec_tool_mib_type_e mib_type;
	u32 rsvd;
};

// MIB output parameter definition
typedef struct himacsec_cmd_mib_out {
	u32 num;
	u8 mib_buf[HIMACSEC_MIB_OUT_BUF_MAX];
} himacsec_cmd_mib_out_s;

// list buf output parameter definition
struct himacsec_cmd_list_sc_buf {
	struct himacsec_sc sc;
	u8 sa_cnt;
};

// counter output parameter definition
typedef struct himacsec_cmd_counter_out {
	u8 enc_cnt_buf[HIMACSEC_COUNTER_OUT_BUF_MAX];
	u8 dec_cnt_buf[HIMACSEC_COUNTER_OUT_BUF_MAX];
} himacsec_cmd_counter_out_s;

#endif /* MACSEC_PUB_CMD_H */
