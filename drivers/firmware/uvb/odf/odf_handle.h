/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: libodf handle header
 * Author: zhangrui
 * Create: 2025-04-18
 */
#ifndef ODF_HANDLE_H
#define ODF_HANDLE_H
#include <linux/types.h>
#include "cis_uvb_interface.h"

extern struct ubios_od_root *od_root;

/**
@brief Search and match one value name, return the pointer of value if matched.
@param[in] start        start address of the search.
@param[in] end          end address of the search.
@param[in] name         value name.
@param[out] vs          used to return value structure.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
@note:
	start must pointer to the name of value.
*/
int odf_get_vs_by_name(u8 *start, u8 *end, char *name, struct ubios_od_value_struct *vs);

/**
@brief Get table information like row, colomn, sub types, .etc.
@param[in] vs           value structure
@param[out] table_info   used to return table info.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_vs_to_table(struct ubios_od_value_struct *vs, struct ubios_od_table_info *table_info);

/**
@brief Get a value's offset in row of table, will check type first.
@param[in] table        table info get from function OdfGetTable
@param[in] name         name of data in table wanted to get.
@param[in] type         data type.
@param[out] offset      used to return offset in the row.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_offset_in_table(const struct ubios_od_table_info *table,
							char *name, u8 type, u32 *offset);

/**
@brief Get a value from table according name and row, will check type first.
@param[in] table        table info get from function OdfGetTable
@param[in] row          the row of table wanted to get.
@param[in] name         name of data in table wanted to get.
@param[in] type         data type.
@param[out] value       data pointer to store returned value.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_data_from_table(const struct ubios_od_table_info *table,
			u16 row, char *name, u8 type, void *value);

/**
@brief Get a value from table according name and row, will check type first.
@param[in] table        table info get from function OdfGetTable
@param[in] row          the row of table wanted to get.
@param[in] name         name of data in table wanted to get.
@param[out] value       used to return value.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_u8_from_table(const struct ubios_od_table_info *table,
						u16 row, char *name, u8 *value);
int odf_get_u32_from_table(const struct ubios_od_table_info *table,
						u16 row, char *name, u32 *value);
int odf_get_u64_from_table(const struct ubios_od_table_info *table,
						u16 row, char *name, u64 *value);

/**
@brief Get a list from od root, will return a list info structure.
@param[in] root         root pointer of od
@param[in] path         full path to search, if not include index of table.
@param[out] list        used to return a list info structure.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_list(struct ubios_od_root *root, char *path, struct ubios_od_list_info *list);

int odf_get_struct(struct ubios_od_root *root, char *path, struct ubios_od_value_struct *vs);

int odf_get_u32_from_list(const struct ubios_od_list_info *list, u16 index, u32 *value);

/**
@brief Get a value structure from list by index.
@param[in] list         list get by function OdfGetList
@param[in] index        index in list to get.
@param[out] vs          used to return a value structrue
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
@note:
	Usually  function is useful when the data type in list is struct, could get value structure,
	then use OdfGetVsByName to search inside.
*/
int odf_get_data_from_list(const struct ubios_od_list_info *list,
						u16 index, struct ubios_od_value_struct *vs);

/**
@brief Get next structure of a list.
@param[in] list     list pointer witch this data belong to.
@param[in/out] vs   current structure as input, next structure as output.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
@note:
	The caller ensure the input structure is a member of list, this function can't check this.
*/
int odf_next_in_list(const struct ubios_od_list_info *list, struct ubios_od_value_struct *vs);

/**
@brief Get a value from struct according name, will check type first.
@param[in] vs           standard structure of a struct
@param[in] name         name of data in table wanted to get.
@param[out] value       used to return value.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_u8_from_struct(const struct ubios_od_value_struct *vs, char *name, u8 *value);
int odf_get_u16_from_struct(const struct ubios_od_value_struct *vs, char *name, u16 *value);
int odf_get_u32_from_struct(const struct ubios_od_value_struct *vs, char *name, u32 *value);
int odf_get_bool_from_struct(const struct ubios_od_value_struct *vs, char *name, bool *value);
int odf_get_table_from_struct(const struct ubios_od_value_struct *vs,
			char *name, struct ubios_od_table_info *table);
int odf_get_list_from_struct(const struct ubios_od_value_struct *vs,
			char *name, struct ubios_od_list_info *list);
int odf_get_list_from_table(u8 *table, char *path, struct ubios_od_list_info *list);
int odf_get_vs_from_table(u8 *table, char *path, struct ubios_od_value_struct *vs);
/**
@brief Check od root's name and checksum, return is it valid.
@param[in] root         start of od root
@return
@retval = true, it is valid.
@retval = false, it is invalid.
*/
bool is_od_root_valid(struct ubios_od_root *root);

/**
@brief Check od file's checksum, return is it valid.
@param[in] file         start of od file
@return
@retval = true, it is valid.
@retval = false, it is invalid.
*/
bool is_od_file_valid(u8 *file);

/**
@brief Search all pointer in od root, return the specific od file matched the input name.
@param[in] root         start of od root
@param[in] name         name of od
@return
@retval = NULL, not found.
@retval != NULL, found.
*/
u8 *odf_get_od_file(struct ubios_od_root *root, char *name);

u8 odf_read8(u8 *address);
u16 odf_read16(u8 *address);
u32 odf_read32(u8 *address);
u64 odf_read64(u8 *address);

u32 odf_checksum(u8 *data, u32 size);
bool odf_is_checksum_ok(struct ubios_od_header *header);
void odf_update_checksum(struct ubios_od_header *header);
int odf_separate_name(char **path, char *name, u64 max_len, u16 *index);
void odf_get_vs_by_pointer(u8 *data, struct ubios_od_value_struct *vs);

struct cis_group *create_group_from_vs(struct ubios_od_value_struct *vs);

#endif
