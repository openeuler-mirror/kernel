// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ODF helper func, including data reading, checksum and path parsing
 * Author: zhangrui
 * Create: 2025-04-18
 */
#define pr_fmt(fmt) "[UVB]: " fmt

#include <linux/string.h>
#include <linux/printk.h>
#include <linux/kstrtox.h>
#include "odf_interface.h"
#include "cis_uvb_interface.h"

#define UBIOS_OD_INDEX_STRING_MAX       7
#define DECIMAL                         10

/* To ensure alignment access, read by one byte */
static void odf_read(u8 *address, u8 *value, u64 size)
{
	u64 i;

	for (i = 0; i < size; i++)
		value[i] = address[i];
}

u8 odf_read8(u8 *address)
{
	return *address;
}

u16 odf_read16(u8 *address)
{
	u16 temp;

	odf_read(address, (u8 *)&temp, sizeof(u16));
	return temp;
}

u32 odf_read32(u8 *address)
{
	u32 temp;

	odf_read(address, (u8 *)&temp, sizeof(u32));
	return temp;
}

u64 odf_read64(u8 *address)
{
	u64 temp;

	odf_read(address, (u8 *)&temp, sizeof(u64));
	return temp;
}

u32 odf_checksum(u8 *data, u32 size)
{
	u64 sum = 0;
	u32 temp = size % sizeof(u32);
	u64 i;

	for (i = 0; i < size - temp; i += sizeof(u32))
		sum += odf_read32(data + i);

	switch (temp) {
	case 1:
		sum += odf_read8(data + i);
		break;
	case 2:
		sum += odf_read16(data + i);
		break;
	case 3:
		sum += odf_read32(data + i) & 0x00FFFFFF;
		break;
	default:
		break;
	}

	return (~((u32)sum) + 1);
}

/**
Only calculate the valid data region
*/
bool odf_is_checksum_ok(struct ubios_od_header *header)
{
	u32 checksum;

	checksum = odf_checksum((u8 *)header, header->total_size);
	if (checksum == 0)
		return true;
	else
		return false;
}

void odf_update_checksum(struct ubios_od_header *header)
{
	header->checksum = 0;
	header->checksum = odf_checksum((u8 *)header, header->total_size);
}

/*
@brief  Separate a name from path
		change path to the new pointer after this name, if finished, set to NULL
		Return a index if it contain [] after name, if input index is NULL, ignore it
@param[in] path         a string to be separated
@param[out] name        a name separate from path
@param[in] maxLen       max length of the name
@param[out] index       if do not have index, return 0xFFFF(-1)
@return returned status fo the call
@retval = 0, success.
@retval < 0, failed.
*/
int odf_separate_name(char **path, char *name, u64 max_len, u16 *index)
{
	char *c;
	u64 i;
	u64 j;
	int ret;
	char index_string[UBIOS_OD_INDEX_STRING_MAX] = {'\0'};
	bool is_index = false;

	if (!path || !name)
		return -EINVAL;

	if (!*path)
		return -EOPNOTSUPP;

	c = *path;
	pr_debug("odf separate name: path[%s]\n", *path);

	/* if the first character is a separator, skip it */
	if (*c == UBIOS_OD_PATH_SEPARATOR)
		c++;

	i = 0;
	j = 0;
	while ((i < max_len) && (j < UBIOS_OD_INDEX_STRING_MAX)) {
		if (*c == UBIOS_OD_PATH_SEPARATOR || *c == '\0') {
			name[i++] = '\0';
			if (index) {
				ret = kstrtou16(index_string, DECIMAL, index);
				if (ret)
					*index = UBIOS_OD_INVALID_INDEX;
			}
			pr_debug("odf separate name: got name[%s]\n", name);
			break;
		} else if (*c == '[') {
			is_index = true;
		} else if (*c == ']') {
			index_string[j++] = '\0';
			is_index = false;
		} else {
			if (is_index)
				index_string[j++] = *c;
			else
				name[i++] = *c;
		}
		c++;
	}

	if ((i == max_len && name[i-1] != '\0') ||
		(j == UBIOS_OD_INDEX_STRING_MAX && index_string[j-1] != '\0'))
		return -EOVERFLOW;

	if (*c == '\0')
		*path = NULL;
	else
		*path = c + 1;

	return 0;
}

/**
@brief Get a name/value structrue by the data pointer
@param[in] data         start address of data.
@param[out] vs          used to return value structure.
*/
void odf_get_vs_by_pointer(u8 *data, struct ubios_od_value_struct *vs)
{
	u8 *type_pointer = NULL;
	u8 sizeof_length = 0;

	vs->name = (char *)data;
	type_pointer = (u8 *)vs->name + strlen(vs->name) + 1;
	vs->type = odf_read8(type_pointer);
	switch (vs->type) {
	case UBIOS_OD_TYPE_U8:
	case UBIOS_OD_TYPE_S8:
	case UBIOS_OD_TYPE_BOOL:
	case UBIOS_OD_TYPE_CHAR:
		vs->data_length = sizeof(u8);
		vs->data = type_pointer + sizeof(u8);
		break;
	case UBIOS_OD_TYPE_U16:
	case UBIOS_OD_TYPE_S16:
		vs->data_length = sizeof(u16);
		vs->data = type_pointer + sizeof(u8);
		break;
	case UBIOS_OD_TYPE_U32:
	case UBIOS_OD_TYPE_S32:
		vs->data_length = sizeof(u32);
		vs->data = type_pointer + sizeof(u8);
		break;
	case UBIOS_OD_TYPE_U64:
	case UBIOS_OD_TYPE_S64:
		vs->data_length = sizeof(u64);
		vs->data = type_pointer + sizeof(u8);
		break;
	case UBIOS_OD_TYPE_STRING:
		vs->data = type_pointer + sizeof(u8);
		vs->data_length = (u32)strlen(vs->data) + 1;
		break;
	default:
		sizeof_length = sizeof(u32);
		vs->data_length = odf_read32(type_pointer + sizeof(u8));
		vs->data = type_pointer + sizeof(u8) + sizeof_length;
		break;
	}
}

bool is_od_root_valid(struct ubios_od_root *root)
{
	if (!root) {
		pr_err("odf: root is NULL\n");
		return false;
	}

	if (!odf_is_checksum_ok(&(root->header))) {
		pr_err("odf: root checksum error, name=%s, total_size=%u, version=%u\n",
		       root->header.name, root->header.total_size, root->header.version);
		return false;
	}

	if (strcmp(root->header.name, UBIOS_OD_ROOT_NAME)) {
		pr_err("odf: root name[%s] mismatch, expected[%s]\n",
		       root->header.name, UBIOS_OD_ROOT_NAME);
		return false;
	}

	return true;
}

bool is_od_file_valid(u8 *file)
{
	struct ubios_od_header *header = (struct ubios_od_header *)file;

	if (!header) {
		pr_err("odf: file is NULL\n");
		return false;
	}

	if (!odf_is_checksum_ok(header)) {
		pr_err("odf: file checksum error.\n");
		return false;
	}

	return true;
}

/**
@brief Search all pointer in od root, return the specific od file matched the input name.
@param[in] root         start of od root
@param[in] name         name of od
@return
@retval = NULL, not found.
@retval != NULL, found.
*/
u8 *odf_get_od_file(struct ubios_od_root *root, char *name)
{
	u64 i;

	if (!is_od_root_valid(root))
		return NULL;

	if (!name)
		return NULL;

	for (i = 0; i < root->count; i++) {
		if (!root->odfs[i])
			continue;

		if (strcmp(name, (char *)(u64)root->odfs[i]) == 0)
			return (u8 *)(u64)root->odfs[i];
	}

	return NULL;
}
