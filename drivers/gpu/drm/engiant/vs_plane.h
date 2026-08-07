/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_PLANE_H__
#define __VS_PLANE_H__

#include <drm/drm_fourcc.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_framebuffer.h>

#include "vs_egt_drm.h"
#include "vs_fb.h"
#include "vs_type.h"
#include "vs_dc_hw.h"
#include "vs_dc_property.h"
#include "vs_dc_drm_property.h"

#define MAX_NUM_PLANES 3 /* colour format plane */

struct vs_plane;

struct vs_plane_funcs {
	void (*update)(struct device *dev, struct vs_plane *plane);
#ifdef CONFIG_DEBUG_FS
	void (*set_pattern)(struct device *dev, struct vs_plane *plane);
	void (*set_crc)(struct device *dev, struct vs_plane *plane);
	void (*set_qos)(struct device *dev, struct vs_plane *plane, const char __user *ubuf,
			size_t len);
	int (*show_qos)(struct seq_file *s);
#endif /* CONFIG_DEBUG_FS */
	void (*disable)(struct device *dev, struct vs_plane *plane,
			struct drm_plane_state *old_state);
	int (*check)(struct device *dev, struct vs_plane *plane, struct drm_plane_state *state);
	bool (*format_mod_support)(struct vs_plane *plane, u32 format, u64 modifier);
};

struct vs_plane_status {
	u32 tile_mode;
	struct drm_rect src;
	struct drm_rect dest;
};

struct vs_plane_pattern {
	bool enable;
	u8 mode;
	u64 color;
	struct drm_vs_egt_rect rect;
};

struct vs_plane_crc {
	bool enable;
	u8 pos;
	struct drm_vs_egt_color seed;
	struct drm_vs_egt_color result;
	/*8200*/
	u8 init_mode;
	__u32 init_value;
	__u32 xor_value;
	__u32 golden[3];
};

struct vs_plane_sram_pool {
	u32 sp_handle;
	u32 sp_size;
	u8 sp_unit_size;
	u32 scl_sp_handle;
	u32 scl_sp_size;
};

struct vs_plane_state {
	struct drm_plane_state base;
	struct vs_plane_status status; /* for debugfs */
	struct vs_plane_pattern pattern; /* for pattern debugfs */
	struct vs_plane_crc crc; /* for crc debugfs */
#ifdef CONFIG_DEBUG_FS
	struct dc_hw_plane_qos qos;
#endif

	struct drm_property_blob *watermark;
	struct drm_property_blob *y2r_coef;
	struct drm_property_blob *lut_3d;
	struct drm_property_blob *pvric_clear;
	struct drm_property_blob *pvric_const;
	struct drm_framebuffer *fb_ext;

	bool lut_3d_changed;
	bool pvric_color_changed;

	struct vs_drm_property_state drm_states[VS_DC_MAX_PROPERTY_NUM];
};

struct vs_plane {
	struct drm_plane base;
	u8 id;
	dma_addr_t dma_addr[MAX_NUM_PLANES];
	dma_addr_t ts_addr[MAX_NUM_PLANES];
	void *ts_dma_buf[MAX_NUM_PLANES];

#ifdef CONFIG_DEBUG_FS
	/**
	 * @debugfs_entry:
	 *
	 * Debugfs directory for this plane.
	 */
	struct dentry *debugfs_entry;
#endif

	struct drm_property *watermark_prop;
	struct drm_property *y2r_prop;
	struct drm_property *lut_3d_prop;
	struct drm_property *pvric_clear_prop;
	struct drm_property *pvric_const_prop;
	struct drm_property *ext_layer_fb;

	struct vs_drm_property_group properties;

	struct vs_plane_sram_pool sram;

	const struct vs_plane_funcs *funcs;
};

/* Metadata for cross-device fd share with additional (ts) info. */
struct vs_ts_metadata {
	u32 magic;
	u32 dmabuf_size;
	u32 time_stamp;
	u32 compressed;
	u32 image_format;

	struct {
		u32 offset;
		u32 stride;
		u32 width;
		u32 height;
		u32 compression_format;
		u32 tile_mode;
		int ts_fd;
		void *ts_dma_buf;
		u32 ts_offset;
		u32 fc_enabled;
		u32 fc_value_lower;
		u32 fc_value_upper;
		u32 header_size;
	} plane[3];
	u32 reserved[8];
};

void vs_egt_plane_destroy(struct drm_plane *plane);

void vs_egt_plane_get_dec_tile_status(struct drm_device *dev, struct vs_gem_object *vs_gem,
				  u8 plane_id, dma_addr_t *ts_addr, void **ts_dma_buf);

struct vs_plane *vs_egt_plane_create(const struct dc_hw_plane *hw_plane, struct drm_device *drm_dev,
				 const struct vs_dc_info *info, u8 index,
				 unsigned int possible_crtcs,
				 const struct vs_plane_funcs *dc_plane_funcs);

static inline struct vs_plane *to_vs_plane(struct drm_plane *plane)
{
	return container_of(plane, struct vs_plane, base);
}

static inline struct vs_plane_state *to_vs_plane_state(struct drm_plane_state *state)
{
	return container_of(state, struct vs_plane_state, base);
}

#endif /* __VS_PLANE_H__ */
