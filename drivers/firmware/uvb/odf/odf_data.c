// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ODF data processing, handles ODF various odf data structures
 * Author: zhangrui
 * Create: 2025-04-18
 */
#define pr_fmt(fmt) "[UVB]: " fmt

#include <linux/string.h>
#include "odf_interface.h"
#include "odf_handle.h"
#include "cis_uvb_interface.h"

/**
@brief Search and match one value name, return the pointer of value structrue if matched.
@param[in] start        start address of the search.
@param[in] end          end address of the search.
@param[in] name         value name.
@param[out] vs          used to return value structure.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_vs_by_name(u8 *start, u8 *end, char *name, struct ubios_od_value_struct *vs)
{
	struct ubios_od_value_struct temp;

	if (!start || !end || !name || !vs)
		return -EINVAL;

	if (start >= end)
		return -ENOENT;

	odf_get_vs_by_pointer(start, &temp);

	if (strcmp(name, temp.name) == 0) {
		*vs = temp;
		return 0;
	}

	return odf_get_vs_by_name(temp.data + temp.data_length, end, name, vs);
}

static void odf_vs_to_list(struct ubios_od_value_struct *vs, struct ubios_od_list_info *list)
{
	list->name = vs->name;
	list->data_type = vs->type & ~UBIOS_OD_TYPE_LIST;
	list->count = odf_read16(vs->data);
	list->start = vs->data + sizeof(u16);
	list->end = vs->data + vs->data_length;
}

/**
Change value structure by index in a list, the name will not be changed,
Both change value pointer and length and type.
note:
	index could be 0, that means get the first one in list.
*/
static int odf_change_vs_in_list(struct ubios_od_value_struct *vs, u16 index)
{
	struct ubios_od_list_info list;

	odf_vs_to_list(vs, &list);

	return odf_get_data_from_list(&list, index, vs);
}

/**
Change the value structure with index, move the pointer to the data indicated by index,
and update length.
Note:
Only list support index in path, other type will return not support if index != 0.
*/
static int odf_change_vs_by_index(struct ubios_od_value_struct *vs, u16 index)
{
	if ((vs->type & UBIOS_OD_TYPE_LIST) == UBIOS_OD_TYPE_LIST)
		return odf_change_vs_in_list(vs, index);

	if (index > 0)
		return -EOPNOTSUPP;
	else
		return 0;
}

/**
Search one od file, input value path, output the value structure, contains value info
*/
static int odf_get_vs_from_file(u8 *file, char *path, struct ubios_od_value_struct *vs)
{
	int status;
	u16 index;
	char name[UBIOS_OD_NAME_LEN_MAX];
	struct ubios_od_header *header = (struct ubios_od_header *)file;
	bool is_got_vs = false;

	if (!is_od_file_valid(file)) {
		pr_err("odf: file[%llx] invalid\n", (u64)file);
		return -EINVAL;
	}

	/* start from the od file data */
	vs->data = (u8 *)(header + 1);
	vs->data_length = header->total_size - header->remaining_size -
		sizeof(struct ubios_od_header);
	while (odf_separate_name(&path, name, UBIOS_OD_NAME_LEN_MAX, &index) == 0) {
		status = odf_get_vs_by_name(vs->data, vs->data + vs->data_length, name, vs);
		if (status) {
			pr_err("odf: can not find name[%s]'s value\n", name);
			return status;
		}
		is_got_vs = true;
		if (index != UBIOS_OD_INVALID_INDEX) {
			status = odf_change_vs_by_index(vs, index);
			if (status) {
				pr_err("odf: get value by index failed, name[%s], type[%#x], index[%#x]\n",
						name, vs->type, index);
				return status;
			}
		}
	}
	if ((is_got_vs) && !path)
		return 0;

	pr_err("odf: failed, left path[%s]\n", path);

	return -EOPNOTSUPP;
}

/**
Search all od file in the root, input value path, output the value structure, contains value info.
If file is not NULL, also return od file, could used to update info of od file, such as checksum.
*/
static int odf_get_vs_from_root(struct ubios_od_root *root, char *path,
			u8 **file, struct ubios_od_value_struct *vs)
{
	int status;
	char name[UBIOS_OD_NAME_LEN_MAX];
	u8 *od_file = NULL;

	status = odf_separate_name(&path, name, UBIOS_OD_NAME_LEN_MAX, NULL);
	if (status) {
		pr_err("odf: get od file name failed, %d\n", status);
		return status;
	}

	od_file = odf_get_od_file(root, name);
	if (!od_file) {
		pr_err("odf: can not find od file[%s]\n", name);
		return -ENOENT;
	}

	if (file)
		*file = od_file;

	return odf_get_vs_from_file(od_file, path, vs);
}

static bool is_root_and_path_valid(struct ubios_od_root *root, char *path)
{
	if (!is_od_root_valid(root))
		return false;

	if (!path) {
		pr_err("odf: path is NULL\n");
		return false;
	}

	return true;
}


/**
@brief Get table information like row, colomn, sub types, .etc.
@param[in] vs           value structure
@param[out] table_info   used to return table info.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_vs_to_table(struct ubios_od_value_struct *vs, struct ubios_od_table_info *table_info)
{
	u64 i;
	u8 type;
	u8 *p = vs->data;

	table_info->table_name = vs->name;
	table_info->length_per_row = 0;
	table_info->row = odf_read16(p);
	p += sizeof(u16);
	table_info->col = odf_read8(p);
	p += sizeof(u8);
	table_info->sub_name_start = (char *)p;

	for (i = 0; i < table_info->col; i++) {
		p += strlen((char *)p) + 1;
		type = odf_read8(p);
		p++;
		switch (type) {
		case UBIOS_OD_TYPE_U8:
		case UBIOS_OD_TYPE_S8:
		case UBIOS_OD_TYPE_BOOL:
		case UBIOS_OD_TYPE_CHAR:
			table_info->length_per_row += sizeof(u8);
			break;
		case UBIOS_OD_TYPE_U16:
		case UBIOS_OD_TYPE_S16:
			table_info->length_per_row += sizeof(u16);
			break;
		case UBIOS_OD_TYPE_U32:
		case UBIOS_OD_TYPE_S32:
			table_info->length_per_row += sizeof(u32);
			break;
		case UBIOS_OD_TYPE_U64:
		case UBIOS_OD_TYPE_S64:
			table_info->length_per_row += sizeof(u64);
			break;
		default:
			pr_err("odf: get table[%s] info, invalid type[%d] of column[%llu]\n",
				table_info->table_name, type, i);
			return -EOPNOTSUPP;
		}
	}
	table_info->value_start = p;
	table_info->table_end = table_info->value_start +
		table_info->length_per_row * table_info->row;

	return 0;
}

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
							char *name, u8 type, u32 *offset)
{
	u64 i;
	u8 data_type;
	u32 temp_offset = 0;
	char *sub_name = NULL;

	if (!table || !name || !offset)
		return -EINVAL;

	/* fisrt sub name */
	sub_name = table->sub_name_start;
	for (i = 0; i < table->col; i++) {
		data_type = odf_read8((u8 *)sub_name + strlen(sub_name) + 1);
		if (strcmp(name, sub_name) == 0)
			break;
		sub_name += strlen(sub_name) + 1 + sizeof(data_type);
		switch (data_type) {
		case UBIOS_OD_TYPE_U8:
		case UBIOS_OD_TYPE_S8:
		case UBIOS_OD_TYPE_BOOL:
		case UBIOS_OD_TYPE_CHAR:
			temp_offset += sizeof(u8);
			break;
		case UBIOS_OD_TYPE_U16:
		case UBIOS_OD_TYPE_S16:
			temp_offset += sizeof(u16);
			break;
		case UBIOS_OD_TYPE_U32:
		case UBIOS_OD_TYPE_S32:
			temp_offset += sizeof(u32);
			break;
		case UBIOS_OD_TYPE_U64:
		case UBIOS_OD_TYPE_S64:
			temp_offset += sizeof(u64);
			break;
		default:
			pr_err("odf: get table info, invalid type[%d] of column[%llu]\n",
				data_type, i);
			return -EOPNOTSUPP;
		}
	}
	if (i == table->col)
		return -ENOENT;

	if (type != data_type)
		return -EFAULT;

	*offset = temp_offset;

	return 0;
}

/**
@brief Get a value pointer from table according name and row, will check type first.
@param[in] table        table info get from function OdfGetTable
@param[in] name         name of data in table wanted to get.
@param[in] row          the row of table wanted to get.
@param[in] type         data type.
@param[out] data        used to return data pointer.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_data_from_table(const struct ubios_od_table_info *table,
							u16 row, char *name, u8 type, void *value)
{
	int status;
	u32 offset;
	u8 *p;

	if (!table || !name || !value)
		return -EINVAL;

	if (row >= table->row)
		return -EOVERFLOW;

	status = odf_get_offset_in_table(table, name, type, &offset);
	if (status)
		return status;

	p = table->value_start + table->length_per_row * row + offset;
	switch (type) {
	case UBIOS_OD_TYPE_U8:
	case UBIOS_OD_TYPE_BOOL:
	case UBIOS_OD_TYPE_CHAR:
		*(u8 *)value = odf_read8(p);
		break;
	case UBIOS_OD_TYPE_S8:
		*(s8 *)value = (s8)odf_read8(p);
		break;
	case UBIOS_OD_TYPE_U16:
		*(u16 *)value = odf_read16(p);
		break;
	case UBIOS_OD_TYPE_S16:
		*(s16 *)value = (s16)odf_read16(p);
		break;
	case UBIOS_OD_TYPE_U32:
		*(u32 *)value = odf_read32(p);
		break;
	case UBIOS_OD_TYPE_S32:
		*(s32 *)value = (s32)odf_read32(p);
		break;
	case UBIOS_OD_TYPE_U64:
		*(u64 *)value = odf_read64(p);
		break;
	case UBIOS_OD_TYPE_S64:
		*(s64 *)value = (s64)odf_read64(p);
		break;
	default:
		pr_err("odf: get table data failed, invalid type[%#x]\n", type);
		return -EOPNOTSUPP;
	}

	return status;
}

int odf_get_u8_from_table(const struct ubios_od_table_info *table,
	u16 row, char *name, u8 *value)
{
	return odf_get_data_from_table(table, row, name, UBIOS_OD_TYPE_U8, value);
}

int odf_get_u32_from_table(const struct ubios_od_table_info *table,
	u16 row, char *name, u32 *value)
{
	return odf_get_data_from_table(table, row, name, UBIOS_OD_TYPE_U32, value);
}

int odf_get_u64_from_table(const struct ubios_od_table_info *table,
	u16 row, char *name, u64 *value)
{
	return odf_get_data_from_table(table, row, name, UBIOS_OD_TYPE_U64, value);
}

int odf_get_vs_from_table(u8 *table, char *path, struct ubios_od_value_struct *vs)
{
	if (!table || !vs || !path)
		return -EINVAL;

	return odf_get_vs_from_file(table, path, vs);
}

int odf_get_list_from_table(u8 *table, char *path, struct ubios_od_list_info *list)
{
	int status;
	struct ubios_od_value_struct vs;

	if (!table || !list)
		return -EINVAL;

	status = odf_get_vs_from_table(table, path, &vs);
	if (status)
		return status;

	if ((vs.type & UBIOS_OD_TYPE_LIST) != UBIOS_OD_TYPE_LIST) {
		pr_err("odf:the type[%#x] is not a list\n", vs.type);
		return -EFAULT;
	}

	odf_vs_to_list(&vs, list);

	return 0;
}
EXPORT_SYMBOL(odf_get_list_from_table);

/**
@brief Get a ubios od value struct from od root according to the path
@param[in] root         root pointer of od
@param[in] path         full path to search, if not include index of table.
@param[out] vs          used to return a ubios od value struct.
@return returned status fo the call
@retval = 0, get ubios od value struct success, saved in parameter vs.
@retval < 0, get ubios od value struct failed.
*/
int odf_get_struct(struct ubios_od_root *root, char *path, struct ubios_od_value_struct *vs)
{
	int status;

	if (!is_root_and_path_valid(root, path))
		return -EINVAL;

	status = odf_get_vs_from_root(root, path, NULL, vs);

	return status;
}

/**
@brief Get a list from od root, will return a list info structure.
@param[in] root         root pointer of od
@param[in] path         full path to search, if not include index of table.
@param[out] list        used to return a list info structure.
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_get_list(struct ubios_od_root *root, char *path, struct ubios_od_list_info *list)
{
	int status;
	struct ubios_od_value_struct vs;

	if (!is_root_and_path_valid(root, path) || !list)
		return -EINVAL;

	status = odf_get_vs_from_root(root, path, NULL, &vs);
	if (status)
		return status;

	if ((vs.type & UBIOS_OD_TYPE_LIST) != UBIOS_OD_TYPE_LIST) {
		pr_err("the type[%#x] is not a list\n", vs.type);
		return -EFAULT;
	}

	odf_vs_to_list(&vs, list);

	return 0;
}

int odf_get_u32_from_list(const struct ubios_od_list_info *list, u16 index, u32 *value)
{
	if (!value)
		return -EINVAL;

	if (list->data_type != UBIOS_OD_TYPE_U32)
		return -EFAULT;

	*value = odf_read32(list->start + sizeof(u32) * index);

	return 0;
}

/**
@brief Get a value structure from list by index.
@param[in] list         list get by function OdfGetList
@param[in] index        index in list to get.
@param[out] vs          used to return a value structrue
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
@note:
	Usually this function is useful when the data type in list is struct, get value structure,
	then use OdfGetVsByName to search inside.
*/
int odf_get_data_from_list(const struct ubios_od_list_info *list,
	u16 index, struct ubios_od_value_struct *vs)
{
	u64 i;
	u32 len;
	u8 *p;

	if (!list || !vs)
		return -EINVAL;

	if (index >= list->count)
		return -EOVERFLOW;

	vs->name = list->name;
	vs->type = list->data_type;
	p = list->start;
	switch (vs->type) {
	case UBIOS_OD_TYPE_U8:
	case UBIOS_OD_TYPE_S8:
	case UBIOS_OD_TYPE_BOOL:
	case UBIOS_OD_TYPE_CHAR:
		vs->data = list->start + index * sizeof(u8);
		vs->data_length = sizeof(u8);
		break;
	case UBIOS_OD_TYPE_U16:
	case UBIOS_OD_TYPE_S16:
		vs->data = list->start + index * sizeof(u16);
		vs->data_length = sizeof(u16);
		break;
	case UBIOS_OD_TYPE_U32:
	case UBIOS_OD_TYPE_S32:
		vs->data = list->start + index * sizeof(u32);
		vs->data_length = sizeof(u32);
		break;
	case UBIOS_OD_TYPE_U64:
	case UBIOS_OD_TYPE_S64:
		vs->data = list->start + index * sizeof(u64);
		vs->data_length = sizeof(u64);
		break;
	case UBIOS_OD_TYPE_STRING:
		for (i = 0; i < index; i++)
			p += (strlen((char *)p) + 1);
		vs->data = p;
		vs->data_length = (u32)strlen((char *)p) + 1;
		break;
	case UBIOS_OD_TYPE_STRUCT:
		for (i = 0; i < index; i++) {
			len = odf_read32(p);
			p += (sizeof(u32) + len);
		}
		vs->data = p + sizeof(u32);
		vs->data_length = odf_read32(p);
		break;
	default:
		pr_err("odf: invalid type[%#x], not support\n", vs->type);
		return -EOPNOTSUPP;
	}

	return 0;
}
EXPORT_SYMBOL(odf_get_data_from_list);

/**
@brief Get next value of a list.
@note:
	The caller should ensure the input structure is a member of list,
	this function can only check some of this.
*/
int odf_next_in_list(const struct ubios_od_list_info *list, struct ubios_od_value_struct *vs)
{
	u8 *p;

	if (!vs)
		return -EINVAL;

	if (list->data_type != vs->type || strcmp(list->name, vs->name))
		return -EFAULT;

	switch (vs->type) {
	case UBIOS_OD_TYPE_U8:
	case UBIOS_OD_TYPE_S8:
	case UBIOS_OD_TYPE_BOOL:
	case UBIOS_OD_TYPE_CHAR:
	case UBIOS_OD_TYPE_U16:
	case UBIOS_OD_TYPE_S16:
	case UBIOS_OD_TYPE_U32:
	case UBIOS_OD_TYPE_S32:
	case UBIOS_OD_TYPE_U64:
	case UBIOS_OD_TYPE_S64:
		vs->data = vs->data + vs->data_length;
		break;
	case UBIOS_OD_TYPE_STRING:
		vs->data = vs->data + vs->data_length;
		vs->data_length = (u32)strlen((char *)vs->data) + 1;
		break;
	case UBIOS_OD_TYPE_STRUCT:
		p = vs->data + vs->data_length;
		vs->data_length = odf_read32(p);
		vs->data = p + sizeof(u32);
		break;
	default:
		pr_err("odf: invalid type[%#x], not support\n", vs->type);
		return -EOPNOTSUPP;
	}
	if (vs->data >= list->end)
		return -EOVERFLOW;

	return 0;
}
EXPORT_SYMBOL(odf_next_in_list);

/**
Internal function, get data pointer by path and type.
*/
static int odf_get_data_and_check_type(const struct ubios_od_value_struct *vs,
	char *name, u8 type, void **data)
{
	int status;
	struct ubios_od_value_struct temp_vs;

	if (!vs || !name || !data)
		return -EINVAL;

	status = odf_get_vs_by_name(vs->data, vs->data + vs->data_length, name, &temp_vs);
	if (status)
		return status;

	if (temp_vs.type != type)
		return -EFAULT;

	*data = temp_vs.data;

	return 0;
}

int odf_get_u8_from_struct(const struct ubios_od_value_struct *vs, char *name, u8 *value)
{
	int status;
	u8 *data;

	if (!value)
		return -EINVAL;

	status = odf_get_data_and_check_type(vs, name, UBIOS_OD_TYPE_U8, (void **)&data);
	if (status)
		return status;

	*value = odf_read8(data);

	return 0;
}

int odf_get_u16_from_struct(const struct ubios_od_value_struct *vs, char *name, u16 *value)
{
	int status;
	u8 *data;

	if (!value)
		return -EINVAL;

	status = odf_get_data_and_check_type(vs, name, UBIOS_OD_TYPE_U16, (void **)&data);
	if (status)
		return status;

	*value = odf_read16(data);

	return 0;
}

int odf_get_u32_from_struct(const struct ubios_od_value_struct *vs, char *name, u32 *value)
{
	int status;
	u8 *data;

	if (!value)
		return -EINVAL;

	status = odf_get_data_and_check_type(vs, name, UBIOS_OD_TYPE_U32, (void **)&data);
	if (status)
		return status;

	*value = odf_read32(data);

	return 0;
}

int odf_get_bool_from_struct(const struct ubios_od_value_struct *vs, char *name, bool *value)
{
	int status;
	u8 *data;

	if (!value)
		return -EINVAL;

	status = odf_get_data_and_check_type(vs, name, UBIOS_OD_TYPE_BOOL, (void **)&data);
	if (status)
		return status;

	*value = odf_read8(data);

	return 0;
}

/**
Get table in the value structure.
*/
int odf_get_table_from_struct(const struct ubios_od_value_struct *vs,
			char *name, struct ubios_od_table_info *table)
{
	int status;
	struct ubios_od_value_struct temp_vs;

	if (!vs || !name || !table)
		return -EINVAL;

	status = odf_get_vs_by_name(vs->data, vs->data + vs->data_length, name, &temp_vs);
	if (status)
		return status;

	if (temp_vs.type != UBIOS_OD_TYPE_TABLE)
		return -EFAULT;

	return odf_vs_to_table(&temp_vs, table);
}

int odf_get_list_from_struct(const struct ubios_od_value_struct *vs,
			char *name, struct ubios_od_list_info *list)
{
	int status;
	struct ubios_od_value_struct temp_vs;

	if (!vs || !name || !list)
		return -EINVAL;

	status = odf_get_vs_by_name(vs->data, vs->data + vs->data_length, name, &temp_vs);
	if (status)
		return status;

	if ((temp_vs.type & UBIOS_OD_TYPE_LIST) != UBIOS_OD_TYPE_LIST) {
		pr_err("the type[%#x] is not a list\n", temp_vs.type);
		return -EFAULT;
	}

	odf_vs_to_list(&temp_vs, list);

	return 0;
}
