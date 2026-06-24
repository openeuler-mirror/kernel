/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_WRITEBACK_H_
#define __VS_WRITEBACK_H_

#include <drm/drm_writeback.h>

#include "vs_egt_drm.h"
#include "vs_type.h"
#include "vs_dc_property.h"

#define MAX_WB_NUM_PLANES 3 /* colour format plane */

struct vs_writeback_connector;

struct vs_writeback_funcs {
	void (*config)(struct vs_writeback_connector *wb_connector, struct drm_framebuffer *fb);
	void (*disable)(struct vs_writeback_connector *wb_connector, struct drm_crtc *crtc);
	int (*check)(struct vs_writeback_connector *wb_connector, struct drm_framebuffer *fb,
			 struct drm_display_mode *mode, struct drm_connector_state *state);
#ifdef CONFIG_DEBUG_FS
	void (*set_qos)(struct device *dev, struct vs_writeback_connector *vs_wb,
			const char __user *ubuf, size_t len);
	int (*show_qos)(struct seq_file *s);
#endif
};

struct vs_writeback_connector_state {
	struct drm_connector_state base;

	u32 wb_point;
	struct dc_hw_wb_qos qos;

	struct vs_drm_property_state drm_states[VS_DC_MAX_PROPERTY_NUM];
};

struct vs_writeback_connector {
	struct drm_writeback_connector base;
	u8 id;
	struct device *dev;
	dma_addr_t dma_addr[MAX_WB_NUM_PLANES];
	unsigned int pitch[MAX_WB_NUM_PLANES];

	struct drm_property *point_prop;

	struct vs_drm_property_group properties;

	const struct vs_writeback_funcs *funcs;
	u8 armed;
};

struct vs_writeback_connector *vs_egt_writeback_create(const struct dc_hw_wb *hw_wb,
						   struct drm_device *drm_dev,
						   const struct vs_wb_info *info,
						   unsigned int possible_crtcs);

void vs_egt_writeback_handle_vblank(struct vs_writeback_connector *vs_wb_connector);

struct drm_writeback_connector *egt_find_wb_connector(struct drm_crtc *crtc);

static inline struct vs_writeback_connector *
to_vs_writeback_connector(struct drm_writeback_connector *wb_connector)
{
	return container_of(wb_connector, struct vs_writeback_connector, base);
}

static inline struct vs_writeback_connector_state *
to_vs_writeback_connector_state(struct drm_connector_state *state)
{
	return container_of(state, struct vs_writeback_connector_state, base);
}

#endif
