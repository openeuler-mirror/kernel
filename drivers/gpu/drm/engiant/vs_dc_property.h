/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_PROPERTY_H__
#define __VS_DC_PROPERTY_H__

#include <linux/types.h>
#include <drm/drm_property.h>

#define VS_DC_MAX_PROPERTY_NUM 64
#define VS_DC_MAX_PROPERTY_STATE_MEM_MAX_SIZE (128 * 1536)

/**
 * VS_DC_BLOB_PROPERTY_PROTO - Define a blob type property protocol
 * @protName: Protocol structure name
 * @strName: Property name string
 * @state_type: Type of the state structure
 * @check_func: Function to validate property value changes
 * @update_func: Function to update property state
 * @config_func: Function to configure hardware
 *
 * This macro creates a static property protocol for blob data types.
 * Blob properties are used for variable-length data like EDID, etc.
 */
#define VS_DC_BLOB_PROPERTY_PROTO(protoname, strname, state_type, check_func, update_func,      \
				  config_func)                                                  \
	static const struct vs_dc_property_proto protoname = { .name = strname,                 \
								.type = VS_DC_PROPERTY_BLOB,    \
								.type_size = sizeof(state_type),\
								.init_val = 0,                  \
								.check = check_func,            \
								.update = update_func,          \
								.config_hw = config_func }

/**
 * VS_DC_ARRAY_PROPERTY_PROTO - Define an array type property protocol
 * @protName: Protocol structure name
 * @strName: Property name string
 * @element_type: Type of each array element
 * @max_count: Maximum number of elements in the array
 * @dynamic: Whether the array size can change dynamically
 * @check_func: Function to validate property value changes
 * @update_func: Function to update property state
 * @config_func: Function to configure hardware
 *
 * This macro creates a static property protocol for array data types.
 * Used for properties that contain multiple values of the same type.
 */
#define VS_DC_ARRAY_PROPERTY_PROTO(protoname, strname, element_type, max_count, dynamic, \
				   check_func, update_func, config_func)                 \
	static const struct vs_dc_property_proto protoname = {                           \
		.name = strname,                                                         \
		.type = VS_DC_PROPERTY_ARRAY,                                            \
		.type_size = max_count * sizeof(element_type),                           \
		.init_val = 0,                                                           \
		.sub_proto = { .array = { max_count, dynamic, sizeof(element_type) } },  \
		.check = check_func,                                                     \
		.update = update_func,                                                   \
		.config_hw = config_func                                                 \
	}

/**
 * VS_DC_BOOL_PROPERTY_PROTO - Define a boolean type property protocol
 * @protName: Protocol structure name
 * @strName: Property name string
 * @check_func: Function to validate property value changes
 * @update_func: Function to update property state
 * @config_func: Function to configure hardware
 *
 * This macro creates a static property protocol for boolean data types.
 * Boolean properties represent on/off or enable/disable states.
 */
#define VS_DC_BOOL_PROPERTY_PROTO(protoname, strname, check_func, update_func, config_func) \
	static const struct vs_dc_property_proto protoname = { .name = strname,             \
								   .type = VS_DC_PROPERTY_BOOL, \
								   .type_size = sizeof(bool),   \
								   .init_val = 0,               \
								   .check = check_func,         \
								   .update = update_func,       \
								   .config_hw = config_func }

/**
 * VS_DC_ENUM_PROPERTY_PROTO - Define an enumeration type property protocol
 * @protName: Protocol structure name
 * @strName: Property name string
 * @enum_list: Array of enumeration value-name pairs
 * @init_val: Initial enumeration value
 * @check_func: Function to validate property value changes
 * @update_func: Function to update property state
 * @config_func: Function to configure hardware
 *
 * This macro creates a static property protocol for enumeration types.
 * Enum properties restrict values to a predefined set of options.
 */
#define VS_DC_ENUM_PROPERTY_PROTO(protoname, strname, _enum_list, _init_val, check_func, \
				  update_func, config_func)                              \
	static const struct vs_dc_property_proto protoname = {                           \
		.name = strname,                                                         \
		.type = VS_DC_PROPERTY_ENUM,                                             \
		.type_size = sizeof(int),                                                \
		.init_val = _init_val,                                                   \
		.sub_proto = { .enum_list = { _enum_list, ARRAY_SIZE(_enum_list) } },    \
		.check = check_func,                                                     \
		.update = update_func,                                                   \
		.config_hw = config_func                                                 \
	}

/* due to @supported_bits may depend on hw info, the const attribute of
 * bitmask property is removed
 */
#define VS_DC_BITMASK_PROPERTY_PROTO(protoname, strname, _enum_list, supported_bits, check_func, \
					 update_func, config_func)                               \
	static struct vs_dc_property_proto protoname = {                                         \
		.name = strname,                                                                 \
		.type = VS_DC_PROPERTY_BITMASK,                                                  \
		.type_size = sizeof(unsigned int),                                               \
		.init_val = 0,                                                                   \
		.sub_proto = { .enum_list = { _enum_list, ARRAY_SIZE(_enum_list),                \
						  supported_bits } },                            \
		.check = check_func,                                                             \
		.update = update_func,                                                           \
		.config_hw = config_func                                                         \
	}

#define VS_DC_RANGE_PROPERTY_PROTO(protoname, strname, min_val, max_val, check_func, update_func, \
				   config_func)                                                   \
	static const struct vs_dc_property_proto protoname = {                                    \
		.name = strname,                                                                  \
		.type = VS_DC_PROPERTY_RANGE,                                                     \
		.type_size = sizeof(u64),                                                         \
		.init_val = 0,                                                                    \
		.sub_proto = { .range = { min_val, max_val } },                                   \
		.check = check_func,                                                              \
		.update = update_func,                                                            \
		.config_hw = config_func                                                          \
	}

#define VS_DC_PROPERTY_VAL(data, type) (*((const type *)(data)))

struct dc_hw;
struct vs_dc_property_state;

enum _vs_dc_property_type {
	VS_DC_PROPERTY_BOOL,
	VS_DC_PROPERTY_ENUM,
	VS_DC_PROPERTY_RANGE,
	VS_DC_PROPERTY_BLOB,
	VS_DC_PROPERTY_ARRAY,
	VS_DC_PROPERTY_BITMASK,
};

union vs_dc_property_sub_proto {
	struct {
		const struct drm_prop_enum_list *data;
		u32 size;
		u32 supported_bits;
	} enum_list;
	struct {
		u64 min_val;
		u64 max_val;
	} range;
	struct {
		u32 max_count;
		bool dynamic;
		u32 element_size;
	} array;
};

struct vs_dc_property_proto {
	const char *name;
	enum _vs_dc_property_type type;
	u32 type_size;
	u64 init_val;
	union vs_dc_property_sub_proto sub_proto;
	bool (*check)(const struct dc_hw *hw, u8 hw_id, const void *data, u32 size,
			  const void *obj_state);
	bool (*update)(struct dc_hw *hw, u8 hw_id, struct vs_dc_property_state *state,
			   const void *data, u32 size, const void *obj_state);
	bool (*config_hw)(struct dc_hw *hw, u8 hw_id, bool enable, const void *data);
};

struct vs_dc_property_state_mem {
	u8 pool[VS_DC_MAX_PROPERTY_STATE_MEM_MAX_SIZE];
	size_t used_size;
	size_t total_size;
};

struct vs_dc_property_state {
	const struct vs_dc_property_proto *proto;
	bool enable;
	bool dirty;
	bool valid;
	void *data;
};

struct vs_dc_property_state_group {
	u32 num;
	struct vs_dc_property_state items[VS_DC_MAX_PROPERTY_NUM];
	struct vs_dc_property_state_mem mem;
};

bool vs_egt_dc_property_register_state(struct vs_dc_property_state_group *states,
				   const struct vs_dc_property_proto *proto);
bool vs_egt_dc_blob_property_update(struct dc_hw *hw, u8 hw_id, struct vs_dc_property_state *state,
				const void *new_data, u32 size, const void *obj_state);
bool vs_egt_dc_bool_property_update(struct dc_hw *hw, u8 hw_id, struct vs_dc_property_state *state,
				bool enable, const void *obj_state);
bool vs_egt_dc_enum_property_update(struct dc_hw *hw, u8 hw_id, struct vs_dc_property_state *state,
				int val, const void *obj_state);
bool vs_egt_dc_bitmask_property_update(struct dc_hw *hw, u8 hw_id,
					struct vs_dc_property_state *state,
					u32 val, const void *obj_state);
bool vs_egt_dc_range_property_update(struct dc_hw *hw, u8 hw_id, struct vs_dc_property_state *state,
				 u64 val, const void *obj_state);
bool vs_egt_dc_array_property_update(struct dc_hw *hw, u8 hw_id, struct vs_dc_property_state *state,
				 const void *new_data, u32 size, const void *obj_state);
bool vs_egt_dc_property_config_hw(struct dc_hw *hw, u8 hw_id, struct vs_dc_property_state *state);
const void *vs_egt_dc_property_get_by_name(const struct vs_dc_property_state_group *states,
					   const char *name, bool *out_enabled);
bool vs_egt_dc_initialize_property_states(struct vs_dc_property_state_group *states);
void vs_egt_dc_deinitialize_property_states(struct vs_dc_property_state_group *states);

#endif
