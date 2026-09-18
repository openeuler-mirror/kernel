/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : adm_dict.h
 * Version       : Initial Draft
 * Created       : 2023/07/17
 * Last Modified : 2026/09/16
 * Description   : Management command address decoupling dictionary definitions
 */

#ifndef ADM_DICT_H
#define ADM_DICT_H

#include "typedef.h"

enum {
	DICT_ELEMENT_U8 = 1,
	DICT_ELEMENT_U16 = 2,
	DICT_ELEMENT_U32 = 4,
	DICT_ELEMENT_U64 = 8,
};

#define MAX_REG_DICT_NAME_LEN 48
#define MAX_DICT_FILE_NAME_LEN 40
#define MAX_REG_FEATURE_NAME_LEN 8
#define MAX_REG_SUB_FEATURE_NAME_LEN 8
#define MAX_SM_TBL_NAME_LEN 40

#define COUNTER_MPU_DICT_NAME "counter_mpu.bin"
#define COUNTER_IPSUTX_DICT_NAME "counter_ipsutx.bin"
#define COUNTER_IPSURX_DICT_NAME "counter_ipsurx.bin"
#define COUNTER_NPU_DICT_NAME "counter_dict.bin"
#define SML_TBL_DEFINE_DICT_NAME "sml_table_define_dict.bin"
#define SML_TABLE_STRUCT_DICT_NAME "sml_table_struct_dict.bin"

// Common dictionary header
typedef struct {
	char file_name[MAX_DICT_FILE_NAME_LEN]; // dictionary file name
	u8 version;       // dictionary's own version info, different from firmware package version
	u8 rsvd;
	u16 item_size;    // single dictionary element size
	u32 item_num;     // number of dictionary elements
	u32 rsvd1[3];
} dict_info_s;

// Register dictionary description
typedef struct {
	char name[MAX_REG_DICT_NAME_LEN];           // display name of register or memory
	char feature[MAX_REG_FEATURE_NAME_LEN];         // feature it belongs to
	char sub_feature[MAX_REG_SUB_FEATURE_NAME_LEN]; // sub-feature it belongs to
	u8 node_id;                                       // module ID the service belongs to
	u8 type;                                          // u16\u32\u64
	u8 bit_start;                                     // start position of single bit description
	u8 bit_end;                                       // end position of single bit description
	u32 addr;                                         // offset address within the module
	u32 rsvd[4];
} reg_dict_s;

typedef struct {
	dict_info_s head;
	reg_dict_s dict[];
} reg_dict_file_s;

typedef struct {
	char name[MAX_SM_TBL_NAME_LEN];      // table name, 40 bytes
	u8 rsvd1;
	u8 node_id;                        // physical node where the table is located
	u8 inst_id;                        // instance number where the table is located
	u8 entry_size;                     // single table entry size
	u8 rsvd[20];
} sml_table_dict_s;

/* Export symbols to tool DT to check basic format */
#ifdef TOOL_DT_MCRO
extern void *counter_mpu_dict_ptr;
extern void *counter_ipsutx_dict_ptr;
extern void *counter_ipsurx_dict_ptr;
#endif

#endif // ADM_DICT_H
