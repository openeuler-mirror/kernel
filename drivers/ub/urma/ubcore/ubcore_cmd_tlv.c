// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Description: ubcore cmd tlv parse implement
 * Author: Chen Yutao
 * Create: 2024-08-06
 * Note:
 * History: 2024-08-06: create file
 */

#include <ub/urma/ubcore_types.h>
#include "ubcore_cmd.h"
#include "ubcore_log.h"
#include "ubcore_cmd_tlv.h"

#define UBCORE_CMD_TLV_MAX_LEN \
	(sizeof(struct ubcore_cmd_attr) * UBCORE_CMD_OUT_TYPE_INIT)

typedef void (*ubcore_fill_spec_func)(void *arg, struct ubcore_cmd_spec *s);

struct ubcore_tlv_handler {
	ubcore_fill_spec_func fill_spec_in;
	size_t spec_in_len;
	ubcore_fill_spec_func fill_spec_out;
	size_t spec_out_len;
	ubcore_fill_spec_func fill_spec_in_post;
	size_t spec_in_len_post;
};

static inline void fill_spec(struct ubcore_cmd_spec *spec, uint16_t type,
			     uint16_t field_size, uint16_t el_num,
			     uint16_t el_size, uintptr_t data)
{
	*spec = (struct ubcore_cmd_spec) {
		.type = type,
		.flag = 0,
		.field_size = field_size,
		.attr_data.bs = { .el_num = el_num, .el_size = el_size },
		.data = data,
	};
}

/**
 * Fill spec with a field, which is a value or an array taken as a whole.
 * @param v Full path of field, e.g. `arg->out.attr.dev_cap.feature`
 */
#define SPEC(spec, type, v) \
	fill_spec(spec, type, sizeof(v), 1, 0, (uintptr_t)(&(v)))

/**
 * Fill spec with a field, which belongs to an array of structs.
 * @param v1 Full path of struct array, e.g. `arg->out.attr.port_attr`
 * @param v2 Path relative to struct in array, e.g. `active_speed`
 */
#define SPEC_ARRAY(spec, type, v1, v2)                          \
	fill_spec(spec, type, sizeof((v1)->v2), ARRAY_SIZE(v1), \
		  sizeof((v1)[0]), (uintptr_t)(&((v1)->v2)))

static void ubcore_set_topo_fill_spec_in(void *arg_addr,
					 struct ubcore_cmd_spec *spec)
{
	struct ubcore_cmd_set_topo *arg = arg_addr;
	struct ubcore_cmd_spec *s = spec;

	SPEC(s++, SET_TOPO_IN_TOPO_INFO, arg->in.topo_info);
	SPEC(s++, SET_TOPO_IN_TOPO_NUM, arg->in.topo_num);
}

static void ubcore_get_topo_fill_spec_in(void *arg_addr,
					 struct ubcore_cmd_spec *spec)
{
	struct ubcore_cmd_get_topo *arg = arg_addr;
	struct ubcore_cmd_spec *s = spec;

	SPEC(s++, GET_TOPO_OUT_TOPO_MAP, arg->out.topo_map);
}

static void ubcore_get_route_list_fill_spec_in(void *arg_addr,
	struct ubcore_cmd_spec *spec)
{
	struct ubcore_cmd_get_route_list *arg = arg_addr;
	struct ubcore_cmd_spec *s = spec;

	SPEC(s++, GET_ROUTE_LIST_IN_ROUTE_PAIR, arg->in);
}

static void ubcore_get_route_list_fill_spec_out(void *arg_addr,
	struct ubcore_cmd_spec *spec)
{
	struct ubcore_cmd_get_route_list *arg = arg_addr;
	struct ubcore_cmd_spec *s = spec;

	SPEC(s++, GET_ROUTE_LIST_OUT_ROUTE_LIST, arg->out);
}

static void ubcore_get_path_set_fill_spec_in(void *arg_addr,
	struct ubcore_cmd_spec *spec)
{
	struct ubcore_cmd_get_path_set *arg = arg_addr;
	struct ubcore_cmd_spec *s = spec;

	SPEC(s++, GET_PATH_SET_IN_SRC_BONDING_EID, arg->in.src_bonding_eid);
	SPEC(s++, GET_PATH_SET_IN_DST_BONDING_EID, arg->in.dst_bonding_eid);
	SPEC(s++, GET_PATH_SET_IN_TP_TYPE, arg->in.tp_type);
	SPEC(s++, GET_PATH_SET_IN_MULTI_PATH, arg->in.multi_path);
}

static void ubcore_get_path_set_fill_spec_out(void *arg_addr,
	struct ubcore_cmd_spec *spec)
{
	struct ubcore_cmd_get_path_set *arg = arg_addr;
	struct ubcore_cmd_spec *s = spec;

	SPEC(s++, GET_PATH_SET_OUT_PATH_SET, arg->out);
}

static struct ubcore_tlv_handler
	g_global_tlv_handler[] = {
		[0] = { 0 },
		[UBCORE_CMD_SET_TOPO] = {
			ubcore_set_topo_fill_spec_in,
			SET_TOPO_IN_NUM,
			NULL,
			0,
		},
		[UBCORE_CMD_GET_ROUTE_LIST] = {
			ubcore_get_route_list_fill_spec_in,
			GET_ROUTE_LIST_IN_NUM,
			ubcore_get_route_list_fill_spec_out,
			GET_ROUTE_LIST_OUT_NUM,
		},
		[UBCORE_CMD_GET_TOPO] = {
			ubcore_get_topo_fill_spec_in,
			GET_TOPO_OUT_NUM,
			NULL,
			0,
		},
		[UBCORE_CMD_GET_PATH_SET] = {
			ubcore_get_path_set_fill_spec_in,
			GET_PATH_SET_IN_NUM,
			ubcore_get_path_set_fill_spec_out,
			GET_PATH_SET_OUT_NUM,
		}
	};

static struct ubcore_cmd_attr *
ubcore_create_tlv_attr(struct ubcore_cmd_hdr *hdr, uint32_t *attr_size)
{
	struct ubcore_cmd_attr *attr;
	int ret = 0;

	if (hdr->args_len % sizeof(struct ubcore_cmd_attr) != 0 ||
	    hdr->args_len >= UBCORE_CMD_TLV_MAX_LEN) {
		ubcore_log_err("Invalid args_len: %u.\n", hdr->args_len);
		return NULL;
	}
	attr = kzalloc(hdr->args_len, GFP_KERNEL);
	if (attr == NULL)
		return NULL;

	ret = ubcore_copy_from_user(
		attr, (void __user *)(uintptr_t)hdr->args_addr, hdr->args_len);
	if (ret != 0) {
		kfree(attr);
		return NULL;
	}
	*attr_size = hdr->args_len / sizeof(struct ubcore_cmd_attr);
	return attr;
}

static int ubcore_cmd_tlv_parse_type(struct ubcore_cmd_spec *spec,
				     struct ubcore_cmd_attr *attr)
{
	uintptr_t ptr_src, ptr_dst;
	uint32_t i;
	int ret = 0;
	uint32_t spec_el_num = spec->attr_data.bs.el_num;
	uint32_t attr_el_num = attr->attr_data.bs.el_num;

	/* length of ubcore spec and from uvs should be strictly checked */
	/* as length of uvs ioctl attr should be strictly equal to length of ubcore */
	if (spec->field_size != attr->field_size ||
	    spec_el_num != attr_el_num) {
		ubcore_log_err(
			"Invalid attr, spec/attr, field_size: %u/%u, el_num: %u/%u, type: %u.\n",
			spec->field_size, attr->field_size, spec_el_num,
			attr_el_num, spec->type);
		return -EINVAL;
	}

	for (i = 0; i < spec_el_num; i++) {
		ptr_dst = (spec->data) + i * spec->attr_data.bs.el_size;
		ptr_src = (attr->data) + i * attr->attr_data.bs.el_size;
		ret = ubcore_copy_from_user((void *)ptr_dst,
					    (void __user *)ptr_src,
					    spec->field_size);
		if (ret != 0)
			return ret;
	}

	return ret;
}

static int ubcore_cmd_tlv_parse(struct ubcore_cmd_spec *spec,
				uint32_t spec_size,
				struct ubcore_cmd_attr *attr,
				uint32_t attr_size)
{
	uint32_t spec_idx, attr_idx;
	bool match = false;
	int ret = 0;

	/* spec type of this range is only in type */
	for (spec_idx = 0; spec_idx < spec_size; spec_idx++) {
		match = false;
		for (attr_idx = 0; attr_idx < attr_size; attr_idx++) {
			if (spec[spec_idx].type == attr[attr_idx].type) {
				ret = ubcore_cmd_tlv_parse_type(
					&spec[spec_idx], &attr[attr_idx]);
				if (ret != 0)
					return ret;
				match = true;
				break;
			}
		}
		if (!match) {
			ubcore_log_err(
				"Failed to match mandatory in type: %u.\n",
				spec[spec_idx].type);
			return -1;
		}
	}

	return 0;
}

static int ubcore_cmd_tlv_append_type(struct ubcore_cmd_spec *spec,
				      struct ubcore_cmd_attr *attr)
{
	uintptr_t ptr_src, ptr_dst;
	uint32_t i;
	int ret = 0;
	uint32_t spec_el_num = spec->attr_data.bs.el_num;
	uint32_t attr_el_num = attr->attr_data.bs.el_num;

	/* length of ubcore spec which from uvs should be strictly checked */
	/* as length of uvs ioctl attr should be strictly equal to length of ubcore */
	if (spec->field_size != attr->field_size ||
	    spec_el_num != attr_el_num) {
		ubcore_log_err(
			"Invalid attr, spec/attr, field_size: %u/%u, array_size: %u/%u, type: %u.\n",
			spec->field_size, attr->field_size, spec_el_num,
			attr_el_num, spec->type);
		return -EINVAL;
	}

	for (i = 0; i < spec_el_num; i++) {
		ptr_src = (spec->data) + i * spec->attr_data.bs.el_size;
		ptr_dst = (attr->data) + i * attr->attr_data.bs.el_size;
		ret = ubcore_copy_to_user((void __user *)ptr_dst,
					  (void *)ptr_src, spec->field_size);
		if (ret != 0)
			return ret;
	}

	return ret;
}

static int ubcore_cmd_tlv_append(struct ubcore_cmd_spec *spec,
				 uint32_t spec_size,
				 struct ubcore_cmd_attr *attr,
				 uint32_t attr_size)
{
	uint32_t spec_idx, attr_idx;
	int ret = 0;

	for (spec_idx = 0; spec_idx < spec_size; spec_idx++) {
		for (attr_idx = 0; attr_idx < attr_size; attr_idx++) {
			if (spec[spec_idx].type == attr[attr_idx].type &&
			    spec[spec_idx].field_size != 0) {
				ret = ubcore_cmd_tlv_append_type(
					&spec[spec_idx], &attr[attr_idx]);
				if (ret != 0)
					return ret;
				break;
			}
		}
	}
	return 0;
}

int ubcore_tlv_parse(ubcore_fill_spec_func fill_spec, size_t spec_size,
		     struct ubcore_cmd_hdr *hdr, void *arg)
{
	struct ubcore_cmd_spec *spec = NULL;
	struct ubcore_cmd_attr *attr = NULL;
	uint32_t attr_size;
	int ret = 0;

	/* Command of hdr is valid, no need to check it */
	if (fill_spec == NULL) {
		ubcore_log_err("Invalid command: %u.\n", hdr->command);
		return -EINVAL;
	}

	spec = kcalloc(spec_size, sizeof(struct ubcore_cmd_spec), GFP_KERNEL);
	if (spec == NULL)
		return -ENOMEM;

	fill_spec(arg, spec);

	attr = ubcore_create_tlv_attr(hdr, &attr_size);
	if (attr == NULL) {
		ret = -ENOMEM;
		goto free_spec;
	}

	ret = ubcore_cmd_tlv_parse(spec, spec_size, attr, attr_size);

	kfree(attr);
free_spec:
	kfree(spec);
	return ret;
}

int ubcore_tlv_append(ubcore_fill_spec_func fill_spec, size_t spec_size,
		      struct ubcore_cmd_hdr *hdr, void *arg)
{
	struct ubcore_cmd_spec *spec = NULL;
	struct ubcore_cmd_attr *attr = NULL;
	uint32_t attr_size;
	int ret = 0;

	/* Command of hdr is valid, no need to check it */
	if (fill_spec == NULL) {
		ubcore_log_err("Invalid command: %u.\n", hdr->command);
		return -EINVAL;
	}

	spec = kcalloc(spec_size, sizeof(struct ubcore_cmd_spec), GFP_KERNEL);
	if (spec == NULL)
		return -ENOMEM;

	fill_spec(arg, spec);

	attr = ubcore_create_tlv_attr(hdr, &attr_size);
	if (attr == NULL) {
		ret = -ENOMEM;
		goto free_spec;
	}

	ret = ubcore_cmd_tlv_append(spec, spec_size, attr, attr_size);

	kfree(attr);
free_spec:
	kfree(spec);
	return ret;
}

int ubcore_global_tlv_parse(struct ubcore_cmd_hdr *hdr, void *arg)
{
	return ubcore_tlv_parse(g_global_tlv_handler[hdr->command].fill_spec_in,
				g_global_tlv_handler[hdr->command].spec_in_len,
				hdr, arg);
}

int ubcore_global_tlv_append(struct ubcore_cmd_hdr *hdr, void *arg)
{
	return ubcore_tlv_append(
		g_global_tlv_handler[hdr->command].fill_spec_out,
		g_global_tlv_handler[hdr->command].spec_out_len -
			UBCORE_CMD_OUT_TYPE_INIT,
		hdr, arg);
}
