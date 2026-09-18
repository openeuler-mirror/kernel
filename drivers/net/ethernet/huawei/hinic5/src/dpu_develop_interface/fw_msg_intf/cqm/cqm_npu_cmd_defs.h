/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_npu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2015/11/13
 * Last Modified : 2026/09/16
 * Description   : cqm common command interface define.
 */

#ifndef CQM_NPU_CMD_DEFS_H
#define CQM_NPU_CMD_DEFS_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#else
#include "typedef.h"
#endif

typedef struct tag_cqm_cla_cache_invalid_cmd {
	u32 gpa_h;
	u32 gpa_l;

	u32 cache_size; /* CLA cache size=4096B */

	u32 smf_id;
	u32 func_id;
} cqm_cla_cache_invalid_cmd_s;

typedef struct tag_cqm_cla_update_cmd {
    /* Gpa address to be updated */
	u32 gpa_h; // byte addr
	u32 gpa_l; // byte addr

    /* Updated Value */
	u32 value_h;
	u32 value_l;

	u32 smf_id;
	u32 func_id;
} cqm_cla_update_cmd_s;

typedef struct tag_cqm_cla_reset_cmd {
	u32 func_id;
	u32 rsvd1;

	u32 rsvd[0x20]; /* Reserve 2 dwords for each BAT entries */
} cqm_cla_reset_cmd_s;

typedef struct tag_cqm_bloomfilter_cmd {
	u32 rsv1;

#if (BYTE_ORDER == LITTLE_ENDIAN)
	u32 k_en : 4;
	u32 func_id : 16;
	u32 rsv2 : 12;
#else
	u32 rsv2 : 12;
	u32 func_id : 16;
	u32 k_en : 4;
#endif

	u32 index_h;
	u32 index_l;
} cqm_bloomfilter_cmd_s;

#define CQM_BAT_MAX_SIZE 256
typedef struct tag_cqm_cmdq_bat_update {
	u32 offset;   // byte offset,16Byte aligned
	u32 byte_len; // max size: 256byte
	u8 data[CQM_BAT_MAX_SIZE];
	u32 smf_id;
	u32 func_id;
} cqm_bat_update_cmd_s;


typedef struct tag_cqm_bloomfilter_init_cmd {
	u32 bloom_filter_len; // 16Byte aligned
	u32 bloom_filter_addr;
} cqm_bloomfilter_init_cmd_s;

typedef struct tag_compact_srq_update_cmd {
	u32 srqid;
	u32 data[32];
} compact_srq_update_cmd_s;

#endif /* CQM_CMDQ_H */
