/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_DRM_PROPERTY_H__
#define __VS_DC_DRM_PROPERTY_H__

#include <drm/drm_device.h>
#include <drm/drm_mode_object.h>

#include "vs_dc_property.h"

/* DONOT include vs_dc.h since it contains vs_crtc.h
 * and vs_crtc.h contains this file
 */
struct vs_dc;
struct vs_plane_state;
struct vs_crtc_state;
struct vs_writeback_connector_state;

struct vs_drm_property {
	const struct vs_dc_property_proto *proto;
	struct drm_property *data;
};

struct vs_drm_property_group {
	u32 num;
	struct vs_drm_property items[VS_DC_MAX_PROPERTY_NUM];
};

struct vs_drm_property_state {
	const struct vs_dc_property_proto *proto;
	union value {
		struct drm_property_blob *blob;
		bool boolean;
		u32 u32val;
		u8 u8val;
		u16 u16val;
		u64 u64val;
		int enumval;
	} value;
	bool is_changed;
};

struct drm_property *vs_egt_dc_create_drm_property(struct drm_device *drm_dev,
						   struct drm_mode_object *obj,
						   const struct vs_dc_property_proto *proto);

int vs_egt_dc_create_drm_properties(struct drm_device *dev, struct drm_mode_object *obj,
				const struct vs_dc_property_state_group *dc_states,
				struct vs_drm_property_group *properties);

void vs_egt_dc_duplicate_drm_properties(struct vs_drm_property_state *new_states,
					const struct vs_drm_property_state *old_states,
					const struct vs_drm_property_group *properties);

void vs_egt_dc_destroy_drm_properties(struct vs_drm_property_state *states,
				  const struct vs_drm_property_group *properties);

int vs_egt_dc_set_drm_property(struct drm_device *dev, struct vs_drm_property_state *states,
			   const struct vs_drm_property_group *properties,
			   const struct drm_property *property, u64 val);

int vs_egt_dc_get_drm_property(const struct vs_drm_property_state *states,
			   const struct vs_drm_property_group *properties,
			   const struct drm_property *property, u64 *val);

void vs_egt_dc_update_drm_properties_to_dc(struct vs_dc *dc, u8 hw_id,
					   const struct vs_drm_property_state *drm_states,
					   u32 registered_drm_properties_num,
					   struct vs_dc_property_state_group *dc_states,
					   const void *obj_state);

struct vs_drm_property_state *vs_egt_dc_get_drm_property_state(struct vs_drm_property_state *states,
							   u32 num, const char *name);
bool vs_egt_dc_check_crtc_std_property(struct vs_dc *dc, u8 hw_id, struct drm_crtc *crtc);

bool vs_egt_dc_check_drm_property(struct vs_dc *dc, u8 hw_id,
				  const struct vs_drm_property_state *states, u32 num,
				  const void *obj_state);

const void *vs_egt_dc_drm_plane_property_get(const struct vs_plane_state *plane, const char *name,
					 u32 *out_len);

const void *vs_egt_dc_drm_crtc_property_get(const struct vs_crtc_state *crtc, const char *name,
					u32 *out_len);
#ifdef CONFIG_ENGIANT_VS_WRITEBACK
const void *vs_egt_dc_drm_connector_property_get(const struct vs_writeback_connector_state *wb,
						 const char *name, u32 *out_len);
#endif
#endif
