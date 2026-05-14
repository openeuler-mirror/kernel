/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : sml_table_struct_dict_def.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : SML Table structure metadata registration macro definition
 */
#ifndef SML_TABLE_STRUCT_DICT_DEF_H
#define SML_TABLE_STRUCT_DICT_DEF_H

#ifdef DEFINE_TABLE_STRUCT_ENABLE
#define DEFINE_TABLE_STRUCT_VAR_DIRECT(struct_name, table_name, entry_id, entry_num)                    \
	volatile struct_name sml_table_struct_var_prefix__##struct_name##__##entry_id##__##entry_num;       \
	volatile const char sml_table_struct_table_name_var_prefix__##struct_name[] = #table_name

#define DEFINE_TABLE_STRUCT_VAR(struct_name, table_name, entry_id, entry_num)                           \
	DEFINE_TABLE_STRUCT_VAR_DIRECT(struct_name, table_name, entry_id, entry_num)
#else
#define DEFINE_TABLE_STRUCT_VAR(struct_name, table_name, entry_id, entry_num)
#endif

#endif
