/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : counter_dict.h
 * Version       : Initial Draft
 * Created       : 2023/07/10
 * Last Modified : 2026/09/16
 * Description   : counter dictionary definitions, describing the mapping between counter names and counter ids
 */

#ifndef COUNTER_DICT_H
#define COUNTER_DICT_H

#include "base_type.h"

#define MAX_COUNTER_NAME_LEN 80
#define MAX_COUNTER_DESC_LEN 80
#define MAX_FEATURE_NAME_LEN 8
#define MAX_SUB_FEATURE_NAME_LEN 8

typedef struct {
	const char name[MAX_COUNTER_NAME_LEN];  // counter name
	const char desc[MAX_COUNTER_DESC_LEN];  // counter description
	const char feature[MAX_FEATURE_NAME_LEN]; // feature the counter belongs to
	const char sub_feature[MAX_SUB_FEATURE_NAME_LEN]; // sub-feature the counter belongs to
	u8 level;                               // counter level, including KEY, ERR, WARN, INFO, DBG
	u8 type;                                // counter type, including CTR_32, CTR_64, CTR_PAIR, etc.
	u8 unit;                                // single counter size, e.g. CTR_32 is 32 bits, i.e. 4 bytes
	u8 step;                                // counter index step unit, i.e. how many IDs one counter occupies
	u8 node_id;                             // physical node where the counter is located
	u8 inst_id;                             // instance number where the counter is located
	u32 base_id;                            // relative starting ID of the counter within the instance
	u32 num;                                // number of counters
} ctr_dict_s;

#endif /* COUNTER_DICT_H */
