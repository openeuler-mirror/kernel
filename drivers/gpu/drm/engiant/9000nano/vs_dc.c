// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2026-03-18
 *   - Added PCIe interrupt register offsets, updated dc_isr
 * Modified: 2025-12-31
 *   - Added mbox message to BMC after DC reset for KVM display
 * Modified: 2025-03-11
 *   - Fixed screen shift: fb->width/height now use drm_rect_width/height(src) >> 16
 *   - Replaced strtoul with kstrtoul for safe parsing
 * Modified: 2026-02-02
 *   - Added VBlank and Flip Done handling on frame_done
 * Modified: 2025-11-27
 *   - Added SOC register offsets for DC, DP, DP PHY
 * Modified: 2026-02-04
 *   - Updated DC driver unload flow
 * Modified: 2025-09-10
 *   - Added driver unload on AER error to prevent hang
 */

#include <linux/clk.h>
#include <linux/component.h>
#include <linux/delay.h>
#include <linux/media-bus-format.h>
#include <linux/pci.h>

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_of.h>
#include <drm/drm_vblank.h>

#include "vs_egt_drm.h"
#include "vs_egt_drm_fourcc.h"
#include "vs_crtc.h"
#include "vs_dc.h"
#include "vs_dc_hw.h"
#include "vs_drv.h"
#include "vs_type.h"
#include "vs_gem.h"
#include "vs_dc_dec.h"
#ifdef CONFIG_ENGIANT_VS_DEBUG
#include "vs_debug.h"
#endif

#ifdef CONFIG_DRM_EGT_DP
#include "egt_dp.h"
#endif /* end of CONFIG_DRM_EGT */

#ifdef CONFIG_ENGIANT_VS_PCIE
#define PCI_INTR_REG_OFFSET         0x18c
#define PCI_INTR_MASK_REG_OFFSET    0x188
#define PCI_INTR_DC_MASK            17
#endif

static inline void update_stride(u32 stride, u32 format, struct dc_hw_fb *fb)
{
	fb->stride = stride;

	switch (format) {
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
	case DRM_FORMAT_RGB565_A8:
	case DRM_FORMAT_BGR565_A8:
		fb->stride = stride * 4 / 3;
		break;
	default:
		break;
	}
}

static inline void update_format(u32 format, u64 mod, struct dc_hw_fb *fb)
{
	u8 f = FORMAT_A8R8G8B8;

	switch (format) {
	case DRM_FORMAT_ARGB4444:
	case DRM_FORMAT_RGBA4444:
	case DRM_FORMAT_ABGR4444:
	case DRM_FORMAT_BGRA4444:
		f = FORMAT_A4R4G4B4;
		break;
	case DRM_FORMAT_ARGB1555:
	case DRM_FORMAT_RGBA5551:
	case DRM_FORMAT_ABGR1555:
	case DRM_FORMAT_BGRA5551:
		f = FORMAT_A1R5G5B5;
		break;
	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_BGR565:
		f = FORMAT_R5G6B5;
		break;
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
		f = FORMAT_R8G8B8;
		break;
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_RGBA8888:
	case DRM_FORMAT_ABGR8888:
	case DRM_FORMAT_BGRA8888:
		f = FORMAT_A8R8G8B8;
		break;
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_YVYU:
		f = FORMAT_YUY2;
		break;
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV21:
		f = FORMAT_NV12;
		break;
	case DRM_FORMAT_RGB565_A8:
	case DRM_FORMAT_BGR565_A8:
		if (fourcc_mod_vs_egt_is_custom_format(mod))
			f = FORMAT_A8R5G6B5;
		else
			f = FORMAT_R5G6B5;
		break;
	default:
		break;
	}
	fb->format = f;
}

static inline void update_swizzle(u32 format, struct dc_hw_fb *fb)
{
	fb->swizzle = SWIZZLE_ARGB;
	fb->uv_swizzle = 0;
	switch (format) {
	case DRM_FORMAT_RGBA4444:
	case DRM_FORMAT_RGBA5551:
	case DRM_FORMAT_RGBA8888:
		fb->swizzle = SWIZZLE_RGBA;
		break;
	case DRM_FORMAT_ABGR4444:
	case DRM_FORMAT_ABGR1555:
	case DRM_FORMAT_BGR565:
	case DRM_FORMAT_BGR888:
	case DRM_FORMAT_ABGR8888:
	case DRM_FORMAT_BGR565_A8:
		fb->swizzle = SWIZZLE_ABGR;
		break;
	case DRM_FORMAT_BGRA4444:
	case DRM_FORMAT_BGRA5551:
	case DRM_FORMAT_BGRA8888:
		fb->swizzle = SWIZZLE_BGRA;
		break;
	case DRM_FORMAT_YVYU:
	case DRM_FORMAT_NV21:
		fb->uv_swizzle = 1;
		break;
	default:
		break;
	}
}

static inline void update_tile_mode(u64 modifier, struct dc_hw_fb *fb)
{
	u8 norm_mode, tile = TILE_MODE_LINEAR;
	u32 format = 0;

	norm_mode = modifier & DRM_FORMAT_MOD_VS_EGT_NORM_MODE_MASK;
	format = fb->format;

	switch (norm_mode) {
	case DRM_FORMAT_MOD_VS_EGT_TILE_MODE4X4:
		/* if color format is NV12, need to change tile mode to 8x8_sub4x4*/

		if (format == FORMAT_NV12)
			tile = TILE_MODE_8X8_SUB4X4;
		else
			tile = TILE_MODE_4X4;
		break;
	default:
		break;
	}

	fb->tile_mode = tile;
}

bool vs_egt_dc_is_yuv_format(u32 format)
{
	bool is_yuv = false;

	switch (format) {
	case FORMAT_YUY2:
	case FORMAT_NV12:
		is_yuv = true;
		break;
	default:
		break;
	}

	return is_yuv;
}

static inline u8 to_vs_yuv_gamut(u32 color_space)
{
	u8 gamut;

	switch (color_space) {
	case DRM_COLOR_YCBCR_BT601:
		gamut = CSC_GAMUT_601;
		break;
	case DRM_COLOR_YCBCR_BT709:
		gamut = CSC_GAMUT_709;
		break;
	default:
		gamut = CSC_GAMUT_601;
		break;
	}

	return gamut;
}

static inline u8 to_vs_display_id(struct vs_dc *dc, struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	const struct vs_display_info *display_info;
	const struct vs_dc_info *dc_info = dc->hw.info;
	u8 id = 0;

	display_info = &dc_info->displays[vs_crtc->id];
	id = display_info->id;

	return id;
}

static inline u8 find_cursor_display_id(struct vs_dc *dc, struct drm_plane *plane)
{
	u8 display_num = dc->hw.info->display_num;
	int i;

	for (i = 0; i < display_num; i++) {
		if (plane == dc->crtc[i]->base.cursor)
			return i;
	}

	return 0;
}

static int vs_dc_enable_clock(struct vs_dc *dc)
{
	int ret;

	ret = clk_prepare_enable(dc->core_clk);
	if (ret < 0) {
		pr_err("failed to prepare/enable core_clk\n");
		return ret;
	}

	ret = clk_prepare_enable(dc->pix_clk);
	if (ret < 0) {
		pr_err("failed to prepare/enable pix_clk\n");
		goto err_unprepare_core_clk;
	}

	ret = clk_prepare_enable(dc->axi_clk);
	if (ret < 0) {
		pr_err("failed to prepare/enable axi_clk\n");
		goto err_unprepare_pix_clk;
	}

	return 0;

err_unprepare_pix_clk:
	clk_disable_unprepare(dc->pix_clk);
err_unprepare_core_clk:
	clk_disable_unprepare(dc->core_clk);

	return ret;
}

static int vs_dc_disable_clock(struct vs_dc *dc)
{
	int ret = 0;

	clk_disable_unprepare(dc->core_clk);
	clk_disable_unprepare(dc->pix_clk);
	clk_disable_unprepare(dc->axi_clk);

	return ret;
}

static void dc_deinit(struct device *dev)
{
	struct vs_dc *dc = dev_get_drvdata(dev);

	egt_dc_hw_enable_vblank(&dc->hw, false);

	egt_dc_hw_deinit(&dc->hw);

	vs_dc_disable_clock(dc);
}

static int dc_init(struct device *dev)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	int ret;

	dc->first_frame = true;

	ret = vs_dc_enable_clock(dc);
	if (ret < 0) {
		pr_debug("failed to enable DC clock.\n");
		return ret;
	}

	dc->pix_clk_rate = clk_get_rate(dc->pix_clk);

	ret = egt_dc_hw_init(&dc->hw);
	if (ret) {
		dev_err(dev, "failed to init DC HW\n");
		return ret;
	}

	return ret;
}

static void vs_dc_enable(struct device *dev, struct drm_crtc *crtc)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct egt_displayport *dp = dc->dp;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	const struct vs_display_info display_info = dc->hw.info->displays[vs_crtc->id];
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(crtc->state);
	struct drm_display_mode *mode = &crtc->state->adjusted_mode;
	struct dc_hw_display_mode display = { 0 };
	const struct drm_vs_egt_r2y_config *r2y_config = NULL;

	/* get the output id info from encoder ID, if the ENCODER NONE, the output_id = hw_id */
	if (crtc_state->encoder_type == DRM_MODE_ENCODER_NONE)
		dc->hw.display[vs_crtc->id].output_id = dc->hw.display[vs_crtc->id].info->id;
	else
		dc->hw.display[vs_crtc->id].output_id = crtc_state->output_id;

	/* For convernienting to debug,
	 * get the output bus format from r2y config,
	 * the default output bus format is MEDIA_BUS_FMT_RGB888_1X24
	 */
	if (display_info.color_formats &
		(DRM_COLOR_FORMAT_YCBCR444 | DRM_COLOR_FORMAT_YCBCR422 | DRM_COLOR_FORMAT_YCBCR420))
		r2y_config = vs_egt_dc_drm_crtc_property_get(crtc_state, "R2Y", NULL);
	if (r2y_config)
		crtc_state->output_fmt = r2y_config->output_bus_format;

	display.bus_format = crtc_state->output_fmt;
	display.output_mode = crtc_state->output_mode;
	display.h_active = mode->hdisplay;
	display.h_total = mode->htotal;
	display.h_sync_start = mode->hsync_start;
	display.h_sync_end = mode->hsync_end;
	if (mode->flags & DRM_MODE_FLAG_PHSYNC)
		display.h_sync_polarity = true;
	else
		display.h_sync_polarity = false;

	display.v_active = mode->vdisplay;
	display.v_total = mode->vtotal;
	display.v_sync_start = mode->vsync_start;
	display.v_sync_end = mode->vsync_end;
	if (mode->flags & DRM_MODE_FLAG_PVSYNC)
		display.v_sync_polarity = true;
	else
		display.v_sync_polarity = false;

	if (dc->pix_clk_rate != mode->clock) {
		clk_set_rate(dc->pix_clk, mode->clock * 1000);
		dc->pix_clk_rate = mode->clock;
	}

	if (crtc_state->encoder_type == DRM_MODE_ENCODER_VIRTUAL) {
		if (crtc_state->out_dp)
			display.out = OUT_DP;
		else
			display.out = OUT_DPI;
	} else if (crtc_state->encoder_type == DRM_MODE_ENCODER_DPI) {
		display.out = OUT_DPI;
	} else if (crtc_state->encoder_type == DRM_MODE_ENCODER_NONE) {
		display.out = OUT_SPI;
	} else if (crtc_state->encoder_type == DRM_MODE_ENCODER_DPMST) {
		display.out = OUT_DP;
	} else
		display.out = OUT_DPI;

	display.enable = crtc_state->base.active;

	egt_dc_hw_setup_display_mode(&dc->hw, vs_crtc->id, &display);

	/* Send an mbox to BMC, DC has been reset done */
	if (dp)
		egt_dp_msg_send(dp, EGT_DC_RESET_DONE);

	egt_dc_hw_config_display_status(&dc->hw, vs_crtc->id, true);
	pr_debug("[%s - %d]\n", __func__, __LINE__);
}

static void vs_dc_disable(struct device *dev, struct drm_crtc *crtc)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct dc_hw_display_mode display;

	display.enable = false;

	egt_dc_hw_setup_display_mode(&dc->hw, vs_crtc->id, &display);

	egt_dc_hw_config_display_status(&dc->hw, vs_crtc->id, true);
	pr_debug("[%s - %d]\n", __func__, __LINE__);
}

static bool vs_dc_mode_fixup(struct device *dev,
				__maybe_unused const struct drm_display_mode *mode,
				struct drm_display_mode *adjusted_mode)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	long clk_rate;
	u32 bdf;

	bdf = readl(dc->pci_base + 0x144);
	if ((bdf == 0xffffffff) || (bdf == 0)) {
		DRM_ERROR("PCIe link is down before frame commit!\n");
		return false;
	}

	pr_debug("[%s - %d] adjusted_mode [%d x %d]\n", __func__, __LINE__,
			adjusted_mode->hdisplay, adjusted_mode->vdisplay);

	if (dc->pix_clk) {
		clk_rate = clk_round_rate(dc->pix_clk, adjusted_mode->clock * 1000);
		adjusted_mode->clock = DIV_ROUND_UP(clk_rate, 1000);
	}

	pr_debug("[%s - %d] adjusted_mode->clock = %d\n", __func__, __LINE__, adjusted_mode->clock);
	return true;
}

static void update_display_gamma(struct vs_dc *dc, u8 id, struct drm_crtc *crtc)
{
	struct drm_crtc_state *crtc_state = crtc->state;
	struct drm_property_blob *blob = crtc_state->gamma_lut;
	struct drm_color_lut *lut;
	u16 i, size;

	/* Standard GAMMA_LUT property entry point. */
	if (crtc_state->color_mgmt_changed) {
		if ((blob) && (blob->length)) {
			lut = blob->data;
			size = blob->length / sizeof(*lut);

			if (size != dc->hw.info->max_gamma_size) {
				pr_err("gamma size does not match!\n");
				return;
			}

			for (i = 0; i < size; i++) {
				egt_dc_hw_update_gamma(&dc->hw, id, i, lut[i].red, lut[i].green,
						   lut[i].blue);
			}

			egt_dc_hw_enable_gamma(&dc->hw, id, true);
		} else
			egt_dc_hw_enable_gamma(&dc->hw, id, false);
	}
}

static void vs_dc_conf_display(struct device *dev, struct drm_crtc *crtc)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(crtc->state);
	struct vs_display_info *display_info;
	struct dc_hw_display *display = &dc->hw.display[vs_crtc->id];

	display_info = (struct vs_display_info *)&dc->hw.info->displays[vs_crtc->id];
	if (!display_info) {
		pr_err("%s: Invalid vs_crtc index.\n", __func__);
		return;
	}

	update_display_gamma(dc, vs_crtc->id, crtc);

	/* dc porperty */
	vs_egt_dc_update_drm_properties_to_dc(dc, vs_crtc->id, crtc_state->drm_states,
					  vs_crtc->properties.num, &display->states, crtc_state);

	egt_dc_hw_config_display_status(&dc->hw, vs_crtc->id, true);
}

static int vs_dc_check_display(struct device *dev, struct drm_crtc *crtc,
				   struct drm_crtc_state *crtc_state)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct vs_crtc_state *vs_crtc_state = to_vs_crtc_state(crtc_state);
	struct vs_display_info *display_info;
	int ret = 0;

	display_info = (struct vs_display_info *)&dc->hw.info->displays[vs_crtc->id];
	if (!display_info)
		return -EINVAL;

	if (!vs_egt_dc_check_drm_property(dc, display_info->id, vs_crtc_state->drm_states,
					  vs_crtc->properties.num, vs_crtc_state))
		return -EINVAL;

	return ret;
}

static void vs_dc_enable_vblank(struct vs_crtc *crtc, bool enable)
{
	struct device *dev = crtc->dev;
	struct vs_dc *dc = dev_get_drvdata(dev);

	egt_dc_hw_enable_vblank(&dc->hw, enable);
}

static u32 vs_dc_get_vblank_count(struct vs_crtc *crtc)
{
	struct device *dev = crtc->dev;
	struct vs_dc *dc = dev_get_drvdata(dev);

	return egt_dc_hw_get_vblank_count(&dc->hw, crtc->id);
}

static void update_plane_fb(struct vs_plane *plane, u8 display_id, struct dc_hw_fb *fb)
{
	struct drm_plane_state *state = plane->base.state;
	struct vs_plane_state *plane_state = to_vs_plane_state(state);
	struct drm_framebuffer *drm_fb = state->fb;
	u32 stride = drm_fb->pitches[0];
	struct drm_rect *src = &state->src;

	fb->display_id = display_id;
	fb->address = (u64)plane->dma_addr[0];
	update_stride(stride, drm_fb->format->format, fb);
	fb->u_address = (u64)plane->dma_addr[1];
	fb->v_address = (u64)plane->dma_addr[2];
	fb->u_stride = drm_fb->pitches[1];
	fb->v_stride = drm_fb->pitches[2];
	fb->width = drm_rect_width(src) >> 16;
	fb->height = drm_rect_height(src) >> 16;
	fb->zpos = state->zpos;
	fb->enable = state->visible;
	update_format(drm_fb->format->format, drm_fb->modifier, fb);
	update_swizzle(drm_fb->format->format, fb);
	update_tile_mode(drm_fb->modifier, fb);
	to_vs_rotation(state->rotation, fb);

	plane_state->status.tile_mode = fb->tile_mode;
}

static void update_plane_y2r(struct vs_dc *dc, u8 id, struct vs_plane_state *plane_state)
{
	struct dc_hw_y2r y2r_conf = { 0 };

	y2r_conf.gamut = to_vs_yuv_gamut(plane_state->base.color_encoding);

	egt_dc_hw_update_plane_y2r(&dc->hw, id, &y2r_conf);
}

static void update_plane_position(struct vs_dc *dc, u8 id, struct vs_plane_state *plane_state)
{
	struct dc_hw_position pos = { 0 };
	struct drm_rect *dest = &plane_state->base.dst;

	pos.rect[0].x = dest->x1;
	pos.rect[0].y = dest->y1;
	pos.rect[0].w = drm_rect_width(dest);
	pos.rect[0].h = drm_rect_height(dest);

	egt_dc_hw_update_plane_position(&dc->hw, id, &pos);
}

static void update_plane_blend(struct vs_dc *dc, u8 zpos, struct vs_plane_state *plane_state,
				   struct vs_plane_info *plane_info)
{
	struct dc_hw_std_bld std_bld = { 0 };
	struct vs_drm_property_state *bld_mode = NULL;

	if (!plane_info->blend_config && !plane_info->blend_mode)
		return;

	bld_mode = vs_egt_dc_get_drm_property_state(plane_state->drm_states, VS_DC_MAX_PROPERTY_NUM,
						"BLEND_MODE");
	if (!bld_mode->is_changed && plane_info->blend_mode) {
		std_bld.alpha = plane_state->base.alpha & VS_BLEND_ALPHA_OPAQUE;
		std_bld.blend_mode = plane_state->base.pixel_blend_mode;

		egt_dc_hw_update_plane_std_bld(&dc->hw, zpos, &std_bld);
	}
}
#ifdef CONFIG_ENGIANT_VS_DEC
static void update_fbc_dec(struct vs_dc *dc, struct vs_plane *plane)
{
	struct drm_plane_state *state = plane->base.state;
	struct drm_framebuffer *drm_fb = state->fb;
	struct dc_dec *dec_config = &dc->planes[plane->id].dec;

	u8 dec_type = fourcc_mod_vs_egt_get_type(drm_fb->modifier);

	if (!dc->hw.info->cap_dec)
		return;

	if (dec_type == DRM_FORMAT_MOD_VS_EGT_TYPE_DECNANO ||
			dec_type == DRM_FORMAT_MOD_VS_EGT_TYPE_ETC2)
		dec_config->enable = true;
	else
		dec_config->enable = false;

	egt_dc_dec_config(dec_config, drm_fb);
}

static void dc_fbc_dec_commit(struct vs_dc *dc)
{
	u8 i, layer_num = dc->hw.info->layer_num;

	for (i = 0; i < layer_num; i++) {
		if (!dc->planes[i].dec.dirty)
			continue;

		egt_dc_dec_commit(&dc->planes[i].dec, &dc->hw, i);
	}
}
#endif

static void update_plane(struct vs_dc *dc, struct vs_plane *plane)
{
	struct drm_plane_state *state = plane->base.state;
	struct vs_plane_state *plane_state = to_vs_plane_state(state);
	struct vs_plane_info *plane_info;
	struct dc_hw_fb fb = { 0 };
	struct dc_hw_plane *hw_plane = &dc->hw.plane[plane->id];
	u8 display_id = 0;

	plane_info = (struct vs_plane_info *)&dc->hw.info->planes[plane->id];
	if (!plane_info) {
		pr_err("%s: Invalid vs_plane index.\n", __func__);
		return;
	}

#ifdef CONFIG_ENGIANT_VS_DEC
	update_fbc_dec(dc, plane);
#endif

	display_id = to_vs_display_id(dc, state->crtc);
	update_plane_fb(plane, display_id, &fb);

	if (vs_egt_dc_is_yuv_format(fb.format))
		update_plane_y2r(dc, plane->id, plane_state);

	update_plane_position(dc, plane->id, plane_state);

	update_plane_blend(dc, fb.zpos, plane_state, plane_info);

	egt_dc_hw_update_plane(&dc->hw, plane->id, &fb);

	egt_dc_hw_config_plane_status(&dc->hw, plane->id, true);

	vs_egt_dc_update_drm_properties_to_dc(dc, plane_info->id, plane_state->drm_states,
					  plane->properties.num, &hw_plane->states, plane_state);
}

static void update_cursor_size(struct drm_plane_state *state, struct dc_hw_cursor *cursor)
{
	u8 size_type;

	switch (state->crtc_w) {
	case 64:
		size_type = CURSOR_SIZE_64X64;
		break;
	default:
		size_type = CURSOR_SIZE_64X64;
		break;
	}

	cursor->size = size_type;
}

static void update_cursor_plane(struct vs_dc *dc, struct vs_plane *plane)
{
	struct drm_plane_state *state = plane->base.state;
	struct dc_hw_cursor cursor;

	cursor.address = (u32)plane->dma_addr[0];
	cursor.x = state->crtc_x;
	cursor.y = state->crtc_y;

	cursor.hot_x = state->fb->hot_x;
	cursor.hot_y = state->fb->hot_y;
	cursor.display_id = to_vs_display_id(dc, state->crtc);
	update_cursor_size(state, &cursor);
	cursor.enable = true;

	egt_dc_hw_update_cursor(&dc->hw, cursor.display_id, &cursor);
}

static void vs_dc_update_plane(struct device *dev, struct vs_plane *plane)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	enum drm_plane_type type = plane->base.type;

	switch (type) {
	case DRM_PLANE_TYPE_PRIMARY:
	case DRM_PLANE_TYPE_OVERLAY:
		update_plane(dc, plane);
		break;
	case DRM_PLANE_TYPE_CURSOR:
		update_cursor_plane(dc, plane);
		break;
	default:
		break;
	}
}

static void vs_dc_disable_plane(struct device *dev, struct vs_plane *plane,
				__maybe_unused struct drm_plane_state *old_state)
{
	struct vs_plane_info *plane_info;
	struct vs_dc *dc = dev_get_drvdata(dev);
	enum drm_plane_type type = plane->base.type;
	struct dc_hw_fb fb = { 0 };
	struct dc_hw_cursor cursor = { 0 };

	plane_info = (struct vs_plane_info *)&dc->hw.info->planes[plane->id];
	if (!plane_info) {
		pr_err("%s: Invalid vs_plane index.\n", __func__);
		return;
	}

	switch (type) {
	case DRM_PLANE_TYPE_PRIMARY:
	case DRM_PLANE_TYPE_OVERLAY:
		fb.enable = false;
		egt_dc_hw_update_plane(&dc->hw, plane->id, &fb);
		egt_dc_hw_config_plane_status(&dc->hw, plane->id, true);
		break;
	case DRM_PLANE_TYPE_CURSOR:
		cursor.enable = false;
		cursor.display_id = find_cursor_display_id(dc, &plane->base);
		egt_dc_hw_update_cursor(&dc->hw, cursor.display_id, &cursor);
		break;
	default:
		break;
	}
}

static bool vs_dc_mod_supported(const struct vs_plane_info *plane_info, u64 modifier, u32 format)
{
	const u64 *mods;
	int i, ret = false;

	if (plane_info->modifiers == NULL)
		return false;

	for (mods = plane_info->modifiers; *mods != DRM_FORMAT_MOD_INVALID; mods++) {
		if ((*mods == modifier) ||
			((*mods | DRM_FORMAT_MOD_VS_EGT_CUSTOM_FORMAT_ENABLE) == modifier)) {
			ret = true;
			break;
		}
	}

	if (plane_info->num_support_custom_formats &&
			fourcc_mod_vs_egt_is_custom_format(modifier)) {
		for (i = 0; i < plane_info->num_support_custom_formats; i++) {
			if (format == plane_info->support_custom_formats[i]) {
				ret &= true;
				break;
			}
		}

		if (i == plane_info->num_support_custom_formats)
			ret = false;
	}

	return ret;
}

static int vs_dc_check_plane(struct device *dev, struct vs_plane *plane,
				 struct drm_plane_state *state)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct drm_framebuffer *fb = state->fb;
	const struct vs_plane_info *plane_info;
	struct drm_crtc *crtc = state->crtc;
	struct drm_crtc_state *crtc_state;
	struct vs_plane_state *vs_plane_state = to_vs_plane_state(state);
	int ret = 0;

	plane_info = &dc->hw.info->planes[plane->id];
	if (plane_info == NULL)
		return -EINVAL;

	if (fb->width < plane_info->min_width || fb->width > plane_info->max_width ||
		fb->height < plane_info->min_height || fb->height > plane_info->max_height) {
		dev_err_once(dev, "buffer size [%d x %d] may not support on plane%d.\n",
				fb->width, fb->height, plane->id);
		return -EINVAL;
	}

	crtc_state = drm_atomic_get_existing_crtc_state(state->state, crtc);
	if (IS_ERR(crtc_state))
		return -EINVAL;

	ret = drm_atomic_helper_check_plane_state(state, crtc_state, plane_info->min_scale,
						  plane_info->max_scale, true, true);
	if (ret)
		return ret;

	if (!state->visible)
		return 0;

	if ((plane->base.type != DRM_PLANE_TYPE_CURSOR) &&
		(!vs_dc_mod_supported(plane_info, fb->modifier, fb->format->format))) {
		dev_err(dev, "unsupported modifier on plane%d.\n", plane->id);
		return -EOPNOTSUPP;
	}

	if (!vs_egt_dc_check_drm_property(dc, plane_info->id, vs_plane_state->drm_states,
					  plane->properties.num, vs_plane_state))
		return -EINVAL;

	return 0;
}

static bool vs_dc_plane_format_mode_support(__maybe_unused struct vs_plane *plane,
						__maybe_unused u32 format, u64 modifier)
{
	if (modifier == DRM_FORMAT_MOD_LINEAR)
		return true;

	if ((modifier >> 56) != DRM_FORMAT_MOD_VENDOR_VS_EGT) {
		pr_err("%s: Unknown modifier (not VS_EGT).\n", __func__);
		return false;
	}
	return true;
}

#ifdef CONFIG_DEBUG_FS
static struct drm_vs_egt_color last_crtc_crc[DC_DISPLAY_NUM];

void vs_egt_crtc_set_last_crc(u32 crtc_id, struct drm_vs_egt_color value)
{
	/* Use crtc_id 0 as last_crtc_crc only supports single display */
	if (crtc_id >= DC_DISPLAY_NUM)
		crtc_id = 0;

	last_crtc_crc[crtc_id].a = value.a;
	last_crtc_crc[crtc_id].r = value.r;
	last_crtc_crc[crtc_id].g = value.g;
	last_crtc_crc[crtc_id].b = value.b;
}

static void vs_dc_set_plane_crc(struct device *dev, struct vs_plane *plane)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct vs_plane_state *plane_state = to_vs_plane_state(plane->base.state);
	struct vs_plane_info *plane_info;
	struct dc_hw_crc crc;

	plane_info = (struct vs_plane_info *)&dc->hw.info->planes[plane->id];
	if (!plane_info) {
		pr_err("%s: Invalid vs_plane index.\n", __func__);
		return;
	}

	if (!plane_info->crc) {
		pr_debug("%s: vs_plane[%u] does not support crc.\n", __func__, plane->id);
		return;
	}

	if (plane_state->crc.pos > VS_EGT_PLANE_CRC_HDR) {
		pr_err("%s: Invalid crc pos.\n", __func__);
		return;
	}

	crc.enable = plane_state->crc.enable;
	if (!crc.enable)
		egt_dc_hw_set_plane_crc(&dc->hw, plane->id, &crc);

	crc.pos = plane_state->crc.pos;
	memcpy(&crc.seed, &plane_state->crc.seed, sizeof(plane_state->crc.seed));

	egt_dc_hw_set_plane_crc(&dc->hw, plane->id, &crc);
}

static void vs_dc_get_plane_crc(struct vs_dc *dc, struct vs_plane *plane)
{
	struct vs_plane_state *plane_state = to_vs_plane_state(plane->base.state);
	struct vs_plane_info *plane_info;
	struct dc_hw_crc crc;

	egt_dc_hw_get_plane_crc_config(&dc->hw, plane->id, &crc);
	plane_state->crc.enable = crc.enable;
	if (!crc.enable)
		return;

	plane_info = (struct vs_plane_info *)&dc->hw.info->planes[plane->id];
	if (!plane_info) {
		pr_err("%s: Invalid vs_plane index.\n", __func__);
		return;
	}

	if (!plane_info->crc) {
		pr_debug("%s: vs_plane[%u] does not support crc.\n", __func__, plane->id);
		return;
	}

	plane_state->crc.pos = crc.pos;
	memcpy(&plane_state->crc.seed, &crc.seed, sizeof(crc.seed));

	egt_dc_hw_get_plane_crc(&dc->hw, plane->id, &crc);
	memcpy(&plane_state->crc.result, &crc.result, sizeof(crc.result));
}

static int vs_dc_put_display_crc_result(struct seq_file *s)
{
	struct drm_crtc *crtc = s->private;
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(crtc->state);

	seq_printf(s, "crtc[%u]: %s\n", crtc->base.id, crtc->name);

	seq_printf(s, "\tenable: %d\n", crtc_state->crc.enable);
	seq_printf(s, "\tpos setting instructions:\n"
			"\t\tpos\t\tid\n"
			"\t\tBLD\t\t0\n"
			"\t\tPOST_PROC\t1\n"
			"\t\tOFIFO_IN\t2\n"
			"\t\tOFIFO_OUT\t3\n"
			"\t\tWB\t\t4\n");
	seq_printf(s, "\tpos-id = %d\n", crtc_state->crc.pos);
	if (crtc_state->crc.pos == VS_EGT_DISP_CRC_OFIFO_OUT) {
		seq_printf(s, "\talpha-seed= [0x%x, 0x%x]\n", crtc_state->crc.seed[0].a,
			   crtc_state->crc.seed[1].a);
		seq_printf(s, "\tred-seed= [0x%x, 0x%x]\n", crtc_state->crc.seed[0].r,
			   crtc_state->crc.seed[1].r);
		seq_printf(s, "\tgreen-seed= [0x%x, 0x%x]\n", crtc_state->crc.seed[0].g,
			   crtc_state->crc.seed[1].g);
		seq_printf(s, "\tblue-seed= [0x%x, 0x%x]\n", crtc_state->crc.seed[0].b,
			   crtc_state->crc.seed[1].b);

		seq_printf(s, "\talpha-crc= [0x%x, 0x%x]\n", crtc_state->crc.result[0].a,
			   crtc_state->crc.result[1].a);
		seq_printf(s, "\tred-crc= [0x%x, 0x%x]\n", crtc_state->crc.result[0].r,
			   crtc_state->crc.result[1].r);
		seq_printf(s, "\tgreen-crc= [0x%x, 0x%x]\n", crtc_state->crc.result[0].g,
			   crtc_state->crc.result[1].g);
		seq_printf(s, "\tblue-crc= [0x%x, 0x%x]\n", crtc_state->crc.result[0].b,
			   crtc_state->crc.result[1].b);
	} else {
		seq_printf(s, "\talpha-seed= [0x%x]\n", crtc_state->crc.seed[0].a);
		seq_printf(s, "\tred-seed= [0x%x]\n", crtc_state->crc.seed[0].r);
		seq_printf(s, "\tgreen-seed= [0x%x]\n", crtc_state->crc.seed[0].g);
		seq_printf(s, "\tblue-seed= [0x%x]\n", crtc_state->crc.seed[0].b);

		seq_printf(s, "\talpha-crc= [0x%x]\n", crtc_state->crc.result[0].a);
		seq_printf(s, "\tred-crc= [0x%x]\n", crtc_state->crc.result[0].r);
		seq_printf(s, "\tgreen-crc= [0x%x]\n", crtc_state->crc.result[0].g);
		seq_printf(s, "\tblue-crc= [0x%x]\n", crtc_state->crc.result[0].b);
	}

	/* Use crtc_id 0 as last_crtc_crc only supports single display */
	if (crtc->base.id < DC_DISPLAY_NUM) {
		seq_printf(s, "\tlast-alpha-crc= [0x%x]\n", last_crtc_crc[crtc->base.id].a);
		seq_printf(s, "\tlast-red-crc= [0x%x]\n", last_crtc_crc[crtc->base.id].r);
		seq_printf(s, "\tlast-green-crc= [0x%x]\n", last_crtc_crc[crtc->base.id].g);
		seq_printf(s, "\tlast-blue-crc= [0x%x]\n", last_crtc_crc[crtc->base.id].b);
	} else {
		seq_printf(s, "\tlast-alpha-crc= [0x%x]\n", last_crtc_crc[0].a);
		seq_printf(s, "\tlast-red-crc= [0x%x]\n", last_crtc_crc[0].r);
		seq_printf(s, "\tlast-green-crc= [0x%x]\n", last_crtc_crc[0].g);
		seq_printf(s, "\tlast-blue-crc= [0x%x]\n", last_crtc_crc[0].b);
	}

	return 0;
}

static void vs_extract_crc_substring(char *str, char *result, size_t result_size)
{
	int i;

	for (i = 0; i < strlen(str); i++) {
		if (str[i] == ' ')
			break;
	}

	strscpy(result, str, result_size);
}

static ssize_t vs_dc_set_display_crc_state(struct drm_crtc *crtc, const char __user *ubuf,
					   size_t len)
{
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(crtc->state);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	unsigned long value;
	char buf[256], *cur = buf;
	char cur1[20];

	buf[len] = '\0';

	if (!vs_crtc->funcs->set_crc)
		return -EINVAL;

	if (len > sizeof(buf) - 1)
		return -EINVAL;

	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;

	cur = strstr(buf, "enable:");

	if (cur) {
		cur += 7;
		vs_extract_crc_substring(cur, cur1, sizeof(cur1));
		if (kstrtoul(cur1, 10, &value))
			return -EINVAL;
		crtc_state->crc.enable = value;
	} else {
		return -EINVAL;
	}
	cur = strstr(buf, "pos:");
	if (cur) {
		cur += 4;
		vs_extract_crc_substring(cur, cur1, sizeof(cur1));
		if (kstrtoul(cur1, 10, &value))
			return -EINVAL;

		crtc_state->crc.pos = value;
	}

	if (crtc_state->crc.pos == VS_EGT_DISP_CRC_OFIFO_OUT) {
		cur = strstr(buf, "a-seed0:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].a = value;
		}
		cur = strstr(buf, "a-seed1:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[1].a = value;
		}
		cur = strstr(buf, "r-seed0:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].r = value;
		}
		cur = strstr(buf, "r-seed1:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[1].r = value;
		}
		cur = strstr(buf, "g-seed0:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].g = value;
		}
		cur = strstr(buf, "g-seed1:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[1].g = value;
		}
		cur = strstr(buf, "b-seed0:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].b = value;
		}
		cur = strstr(buf, "b-seed1:");
		if (cur) {
			cur += 8;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[1].b = value;
		}
	} else {
		cur = strstr(buf, "a-seed:");
		if (cur) {
			cur += 7;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].a = value;
		}

		cur = strstr(buf, "r-seed:");
		if (cur) {
			cur += 7;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].r = value;
		}

		cur = strstr(buf, "g-seed:");
		if (cur) {
			cur += 7;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur1, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].g = value;
		}

		cur = strstr(buf, "b-seed:");
		if (cur) {
			cur += 7;
			vs_extract_crc_substring(cur, cur1, sizeof(cur1));
			if (kstrtoul(cur, 16, &value))
				return -EINVAL;

			crtc_state->crc.seed[0].b = value;
		}
	}

	return len;
}

static void vs_dc_set_display_crc(struct device *dev, struct drm_crtc *crtc,
				  const char __user *ubuf, size_t len)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct drm_crtc_state *state = vs_crtc->base.state;
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(state);
	struct vs_display_info *display_info;
	u8 hw_id;
	struct dc_hw_disp_crc crc;

	if (vs_dc_set_display_crc_state(crtc, ubuf, len) != len) {
		pr_err("%s: parse crc parameter error.\n", __func__);
		return;
	}

	display_info = (struct vs_display_info *)&dc->hw.info->displays[vs_crtc->id];
	if (!display_info) {
		pr_err("%s: Invalid vs_crtc index.\n", __func__);
		return;
	}

	if (!display_info->crc) {
		pr_debug("%s: vs_crtc[%u] does not support crc.\n", __func__, vs_crtc->id);
		return;
	}

	if (crtc_state->crc.pos > VS_EGT_DISP_CRC_OFIFO_OUT) {
		pr_err("%s: Invalid crc pos.\n", __func__);
		return;
	}

	hw_id = display_info->id;

	crc.enable = crtc_state->crc.enable;
	crc.pos = crtc_state->crc.pos;
	if (!crc.enable) {
		egt_dc_hw_set_display_crc(&dc->hw, hw_id, &crc);
		return;
	}

	memcpy(&crc.seed, &crtc_state->crc.seed, sizeof(crtc_state->crc.seed));
	egt_dc_hw_set_display_crc(&dc->hw, hw_id, &crc);
}

static void vs_dc_get_display_crc(struct vs_dc *dc, struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct drm_crtc_state *state = vs_crtc->base.state;
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(state);
	struct vs_display_info *display_info;
	u8 hw_id;

	struct dc_hw_disp_crc crc;

	display_info = (struct vs_display_info *)&dc->hw.info->displays[vs_crtc->id];
	if (!display_info) {
		pr_err("%s: Invalid vs_crtc index.\n", __func__);
		return;
	}

	if (!display_info->crc) {
		pr_debug("%s: vs_crtc[%u] does not support crc.\n", __func__, vs_crtc->id);
		return;
	}

	if (crtc_state->crc.pos > VS_EGT_DISP_CRC_OFIFO_OUT) {
		pr_err("%s: Invalid crc pos.\n", __func__);
		return;
	}

	hw_id = display_info->id;
	egt_dc_hw_get_display_crc_config(&dc->hw, hw_id, &crc);

	crtc_state->crc.enable = crc.enable;
	if (!crc.enable)
		return;

	crtc_state->crc.pos = crc.pos;
	memcpy(&crtc_state->crc.seed, &crc.seed, sizeof(crc.seed));

	egt_dc_hw_get_display_crc(&dc->hw, hw_id, &crc);

	memcpy(&crtc_state->crc.result, &crc.result, sizeof(crc.result));

	if (crtc_state->crc.pos == VS_EGT_DISP_CRC_OFIFO_OUT)
		vs_egt_crtc_set_last_crc(crtc->base.id, crtc_state->crc.result[1]);
	else
		vs_egt_crtc_set_last_crc(crtc->base.id, crtc_state->crc.result[0]);
}
#endif /* CONFIG_DEBUG_FS */

#ifdef CONFIG_PM_SLEEP
int vs_egt_dc_suspend(__maybe_unused struct device *dev)
{
	int ret = 0;
	return ret;
}

int vs_egt_dc_resume(__maybe_unused struct device *dev)
{
	int ret = 0;
	return ret;
}
#endif

static irqreturn_t dc_isr(__maybe_unused int irq, void *data)
{
	int temp = 0;
	struct vs_dc *dc = data;
	const struct vs_dc_info *dc_info = dc->hw.info;
	u32 i, pci_intr_status;
	struct dc_hw_interrupt_status status = { 0 };
	struct drm_crtc *crtc;
	struct drm_device *dev;
	struct drm_vblank_crtc *vblank;
	u64 cur_vblank;

#ifdef CONFIG_ENGIANT_VS_PCIE
	pci_intr_status = readl(dc->pci_base + PCI_INTR_REG_OFFSET);

	if (pci_intr_status == 0xffffffff || !(pci_intr_status & 0x20000))
		return IRQ_NONE;

	writel(0x20000, dc->pci_base + PCI_INTR_REG_OFFSET);
#endif

	temp = egt_dc_hw_get_interrupt(&dc->hw, &status);
	if (temp) {
		pr_err("aer happened!\n");
		return IRQ_HANDLED;
	}

	//pr_debug("%s: frm_start=0x%x frm_done=0x%x ", __func__, status.display_frm_start,
	//	 status.display_frm_done);

	for (i = 0; i < dc_info->display_num; i++) {
		u8 display_id = dc_info->displays[i].id;
		u8 display_mask = BIT(display_id);

		if (display_mask & status.display_underflow) {
			pr_warn_ratelimited("%s: display[%d] underflow\n", __func__, display_id);
			continue;
		}

		if (display_mask & status.display_axi_slow) {
			pr_warn_ratelimited("%s: display[%d] axi frequency too slow\n",
					__func__, display_id);
			continue;
		}

		if ((!!(display_mask & status.display_frm_done)) &&
			dc->hw.display[i].config_status) {
			crtc = &dc->crtc[i]->base;
			dev = crtc->dev;
			cur_vblank = vs_dc_get_vblank_count(dc->crtc[i]);
			vblank = &dev->vblank[display_id];

			vblank->last = cur_vblank;
			atomic64_set(&vblank->count, cur_vblank);
			vs_egt_crtc_handle_vblank(&dc->crtc[i]->base);
			vs_egt_crtc_handle_flip_done_while_hw_done(&dc->crtc[i]->base);
			vs_egt_crtc_handle_frame_done(&dc->crtc[i]->base);
		}
	}

#ifdef CONFIG_DEBUG_FS
	for (i = 0; i < dc_info->plane_num; i++) {
		u32 display_id = dc->hw.plane[i].fb.display_id;
		u8 display_mask = BIT(dc_info->displays[display_id].id);
		u8 plane_mask = 0;

		plane_mask = BIT(dc_info->planes[i].id);

		if ((display_mask & status.display_frm_done) ||
			(plane_mask & status.plane_frm_done))
			vs_dc_get_plane_crc(dc, dc->planes[i].base);
	}
	for (i = 0; i < dc_info->display_num; i++) {
		u8 display_mask = BIT(dc_info->displays[i].id);

		if (dc->hw.display[i].crc.enable && (display_mask & status.display_frm_done))
			vs_dc_get_display_crc(dc, &dc->crtc[i]->base);
	}
#endif

	return IRQ_HANDLED;
}

static void vs_dc_hw_reset(struct vs_crtc *crtc)
{
	struct device *dev = crtc->dev;
	struct vs_dc *dc = dev_get_drvdata(dev);

	egt_dc_hw_reset(&dc->hw);
}

static void vs_dc_commit(struct device *dev, struct drm_crtc *crtc)
{
	struct vs_dc *dc = dev_get_drvdata(dev);
	u8 display_id = to_vs_display_id(dc, crtc);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	unsigned long flags;

	spin_lock_irqsave(&vs_crtc->slock, flags);

	egt_dc_hw_enable_shadow_register(&dc->hw, display_id, false);

#ifdef CONFIG_ENGIANT_VS_DEC
	if (dc->hw.info->cap_dec)
		dc_fbc_dec_commit(dc);
#endif

	egt_dc_hw_commit(&dc->hw, display_id);

	egt_dc_hw_enable_shadow_register(&dc->hw, display_id, true);

	egt_dc_hw_start_trigger(&dc->hw, display_id);
	spin_unlock_irqrestore(&vs_crtc->slock, flags);
}

static const struct vs_crtc_funcs dc_crtc_funcs = {
	.enable = vs_dc_enable,
	.disable = vs_dc_disable,
	.mode_fixup = vs_dc_mode_fixup,
#ifdef CONFIG_DEBUG_FS
	.set_crc = vs_dc_set_display_crc,
	.show_crc = vs_dc_put_display_crc_result,
#endif /* CONFIG_DEBUG_FS */
	.config = vs_dc_conf_display,
	.enable_vblank = vs_dc_enable_vblank,
	.get_vblank_count = vs_dc_get_vblank_count,
	.commit = vs_dc_commit,
	.check = vs_dc_check_display,
	.reset = vs_dc_hw_reset,
};

static const struct vs_plane_funcs dc_plane_funcs = {
	.update = vs_dc_update_plane,
#ifdef CONFIG_DEBUG_FS
	.set_crc = vs_dc_set_plane_crc,
#endif /* CONFIG_DEBUG_FS */
	.disable = vs_dc_disable_plane,
	.check = vs_dc_check_plane,
	.format_mod_support = vs_dc_plane_format_mode_support,
};

static int dc_bind(struct device *dev, __maybe_unused struct device *master, void *data)
{
	struct drm_device *drm_dev = data;
	struct vs_drm_private *priv;
	struct vs_dc *dc = dev_get_drvdata(dev);
	struct vs_crtc *crtc;
	struct drm_crtc *drm_crtc;
	const struct vs_dc_info *dc_info;
	struct vs_plane *plane;
	struct drm_plane *drm_plane, *tmp;
	const struct vs_display_info *display_info;
	const struct vs_plane_info *plane_info;
	struct dc_hw_display *display;
	struct dc_hw_plane *hw_plane;
	int i, ret;
	u32 crtc_mask = 0;
	u32 max_width = 0, max_height = 0;
	u32 min_width = 0xffff, min_heigth = 0xffff;
#ifndef CONFIG_ENGIANT_VS_PCIE
	struct device_node *port;
#endif

	if (!drm_dev || !dc) {
		dev_err(dev, "devices are not created.\n");
		return -ENODEV;
	}

	priv = drm_dev->dev_private;

#ifdef CONFIG_ENGIANT_VS_DEBUG
	dc->hw.dc_capture_fp = priv->dc_capture_fp;
#endif

	ret = dc_init(dev);
	if (ret < 0) {
		dev_err(dev, "Failed to initialize DC hardware.\n");
		return ret;
	}

	ret = vs_egt_drm_iommu_attach_device(drm_dev, dev);
	if (ret < 0) {
		dev_err(dev, "Failed to attached iommu device.\n");
		goto err_clean_dc;
	}

	dc_info = dc->hw.info;

	for (i = 0; i < dc_info->display_num; i++) {
		display_info = &dc_info->displays[i];
		display = &dc->hw.display[i];

#ifndef CONFIG_ENGIANT_VS_PCIE
		port = of_graph_get_port_by_id(dev->of_node, display_info->id);
		if (!port) {
			dev_warn(dev, "port node not found for display #%d\n", display_info->id);
			continue;
		}
#endif
		crtc = vs_egt_crtc_create(display, drm_dev, dc_info, i);
		if (!crtc) {
			dev_err(dev, "Failed to create CRTC.\n");
			ret = -ENOMEM;
#ifndef CONFIG_ENGIANT_VS_PCIE
			of_node_put(port);
#endif
			goto err_detach_dev;
		}
#ifndef CONFIG_ENGIANT_VS_PCIE
		crtc->base.port = port;
#endif

		crtc->dev = dev;
		crtc->funcs = &dc_crtc_funcs;
		dc->crtc[i] = crtc;
		crtc_mask |= drm_crtc_mask(&crtc->base);

		display_info = &dc_info->displays[i];
		max_width = max_t(u32, max_width, display_info->max_width);
		max_height = max_t(u32, max_height, display_info->max_height);
	}

	if (!crtc_mask) {
		dev_err(dev, "no ports found\n");
		ret = -ENOENT;
		goto err_cleanup_crtcs;
	}

	for (i = 0; i < dc_info->plane_num; i++) {
		hw_plane = &dc->hw.plane[i];

		plane = vs_egt_plane_create(hw_plane, drm_dev, dc_info, i,
				crtc_mask, &dc_plane_funcs);
		if (!plane) {
			dev_err(dev, "Failed to create plane.\n");
			ret = -ENOMEM;
			goto err_cleanup_planes;
		}

		plane->id = i;
		plane_info = &dc_info->planes[i];
		dc->planes[i].base = plane;
		dc->planes[i].id = plane_info->id;

		if ((plane_info->type == DRM_PLANE_TYPE_PRIMARY) &&
			(dc->crtc[plane_info->crtc_id])) {
			dc->crtc[plane_info->crtc_id]->base.primary = &plane->base;

			min_width = min_t(u32, min_width, plane_info->min_width);
			min_heigth = min_t(u32, min_heigth, plane_info->min_height);
			/*
			 * Note: these values are used for multiple independent things:
			 * hw display mode filtering, plane buffer sizes, writeback buffer size ...
			 * Use the combined maximum values here to cover all use cases, and do more
			 * specific checking in the respective code paths.
			 */
			max_width = max_t(u32, max_width, plane_info->max_width);
			max_height = max_t(u32, max_height, plane_info->max_height);
		}

		if (plane_info->type == DRM_PLANE_TYPE_CURSOR) {
			dc->crtc[plane_info->crtc_id]->base.cursor = &plane->base;

			drm_dev->mode_config.cursor_width = plane_info->max_width;
			drm_dev->mode_config.cursor_height = plane_info->max_height;
		}
	}

	drm_dev->mode_config.min_width = min_width;
	drm_dev->mode_config.min_height = min_heigth;
	drm_dev->mode_config.max_width = max_width;
	drm_dev->mode_config.max_height = max_height;

	priv->dc_dev = dev;

	vs_egt_drm_update_alignment(drm_dev, dc_info->pitch_alignment, dc_info->addr_alignment);
	return 0;

err_cleanup_planes:
	list_for_each_entry_safe(drm_plane, tmp, &drm_dev->mode_config.plane_list, head)
		if (drm_plane->possible_crtcs & crtc_mask)
			vs_egt_plane_destroy(drm_plane);
err_cleanup_crtcs:
	drm_for_each_crtc(drm_crtc, drm_dev)
		vs_egt_crtc_destroy(drm_crtc);
err_detach_dev:
	vs_egt_drm_iommu_detach_device(drm_dev, dev);
err_clean_dc:
	dc_deinit(dev);
	return ret;
}

static void dc_unbind(struct device *dev, __maybe_unused struct device *master, void *data)
{
	struct drm_device *drm_dev = data;

#ifdef CONFIG_ENGIANT_VS_DEBUG
	struct vs_dc *dc = dev_get_drvdata(dev);

	dc->hw.dc_capture_fp = NULL;
#endif

	dc_deinit(dev);

	vs_egt_drm_iommu_detach_device(drm_dev, dev);
}

static const struct component_ops dc_component_ops = {
	.bind = dc_bind,
	.unbind = dc_unbind,
};

static int dc_construct(struct device *dev, int irq, struct vs_dc **vs_dc)
{
	struct vs_dc *dc;
	int ret = 0;

	dc = devm_kzalloc(dev, sizeof(*dc), GFP_KERNEL);
	if (!dc)
		return -ENOMEM;

	ret = request_irq(irq, dc_isr, IRQF_SHARED, dev_name(dev), (void *)dc);
	if (ret < 0) {
		dev_err(dev, "Failed to install irq:%u.\n", irq);
		return ret;
	}

	*vs_dc = dc;

	return ret;
}


#ifdef CONFIG_ENGIANT_VS_PCIE
#define DISPLAY_MSI_IRQ_NUM 5

#define PCI_DC_OFFSET             0x0
#define PCI_DP_OFFSET             0x40000
#define PCI_MBOX_OFFSET           0x242000
#define PCI_DP_PHY_OFFSET         0x245000
#define PCI_DP_PHY0_OFFSET        0x244000 //256+1024+1024+4+4+8
#define PCI_DP_PHY1_OFFSET        0x344000 //256+1024+1024+4+4+8+1024
#define PCI_DP_PLL_OFFSET         0x384000 //256+1024+1024+4+4+8+1024+256
#define PCI_DP_HSIO_OFFSET        0x241000

u32 vs_egt_dc_reg_read(struct drm_device *drm_dev, u32 reg)
{
	u32 value;
	struct vs_dc *dc;
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;
	dc = dev_get_drvdata(dev);
	value = vs_egt_dc_hw_read(&dc->hw, reg);

	return value;
}

int vs_egt_dc_pci_init(struct drm_device *drm_dev)
{
	struct vs_dc *dc = NULL;
	resource_size_t addr, size;
	int i, ret;
	u32 intr_mask_open, intr_mask_close;
	struct vs_drm_private *priv = drm_dev->dev_private;
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;

#if IS_ENABLED(CONFIG_DRM_LEGACY)
	drm_dev->irq = pdev->irq;
#endif
	pr_debug("pdev->irq = %d\n", pdev->irq);

	dc = devm_kzalloc(dev, sizeof(*dc), GFP_KERNEL);
	if (!dc)
		return -ENOMEM;

	addr = pci_resource_start(pdev, 0);
	size = pci_resource_len(pdev, 0);

	priv->pf_bar_base = devm_ioremap(dev, addr, size);

	if (IS_ERR(priv->pf_bar_base))
		return PTR_ERR(priv->pf_bar_base);

	priv->dc_base = priv->pf_bar_base + PCI_DC_OFFSET;
#ifdef CONFIG_DRM_EGT_DP
	priv->dp_base = priv->pf_bar_base + PCI_DP_OFFSET;
	priv->dp_phy_base = priv->pf_bar_base + PCI_DP_PHY_OFFSET;
#endif
	//dp phy pcie addr
	priv->dp_phy0_base = priv->pf_bar_base + PCI_DP_PHY0_OFFSET;
	priv->dp_phy1_base = priv->pf_bar_base + PCI_DP_PHY1_OFFSET;
	//CRG PLL pcie addr
	priv->crg_base = priv->pf_bar_base + PCI_DP_PLL_OFFSET;
	priv->crg_hsio_base = priv->pf_bar_base + PCI_DP_HSIO_OFFSET;
	priv->mbox_base = priv->pf_bar_base + PCI_MBOX_OFFSET;

	pr_debug("addr = %pa, size = %pa, bar base = %p\n", &addr, &size, priv->pf_bar_base);
	pr_debug("pdev->irq = %#x\n", pdev->irq);

	addr = pci_resource_start(pdev, 4);
	size = pci_resource_len(pdev, 4);

	priv->pci_base = devm_ioremap(dev, addr, size);

	if (IS_ERR(priv->pci_base))
		return PTR_ERR(priv->pci_base);

	ret = pci_alloc_irq_vectors_affinity(pdev, DISPLAY_MSI_IRQ_NUM,
			DISPLAY_MSI_IRQ_NUM, PCI_IRQ_MSI, NULL);
	if (ret < 0) {
		pr_err("Fail to alloc MSI interrupt: %d.\n", ret);
		return -EIO;
	}
	pr_debug("Enabled %d MSI interrupting.\n", ret);
	for (i = 0; i < ret; i++) {
		priv->irq_num[i] = pci_irq_vector(pdev, i);
		pr_debug("irq num is %d\n", priv->irq_num[i]);
	}

	pr_debug("priv->irq_num[1] = %#x, priv->dc_base = %p\n", priv->irq_num[1], priv->dc_base);

#ifdef CONFIG_ENGIANT_VS_PCIE
	/*Disable pcie intr of dc before irq request which may case NULL pointer*/
	intr_mask_open = readl(priv->pci_base + PCI_INTR_MASK_REG_OFFSET);
	intr_mask_open &= ~BIT(PCI_INTR_DC_MASK);
	intr_mask_close = intr_mask_open | BIT(PCI_INTR_DC_MASK);

	writel(intr_mask_open, priv->pci_base + PCI_INTR_MASK_REG_OFFSET);

	pr_debug("Mask pcie interrupt of dc\n");
#endif

	ret = request_irq(priv->irq_num[1], dc_isr, IRQF_SHARED, dev_name(dev), (void *)dc);
	if (ret < 0) {
		dev_err(dev, "Failed to install irq:%u.\n", priv->irq_num[1]);
		return ret;
	}

	dc->hw.reg_base = priv->dc_base;
	dc->hw.pcie_reg_base = priv->pci_base;
	dc->hw.pcie_mask_value = intr_mask_close;
	dc->pci_base = priv->pci_base;

	dev_set_drvdata(dev, dc);

	return dc_bind(dev, NULL, drm_dev);
}

void vs_egt_dc_pci_deinit(struct drm_device *drm_dev)
{
	struct vs_drm_private *priv;
	struct vs_dc *dc;
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;

#if IS_ENABLED(CONFIG_DRM_LEGACY)
	drm_dev->irq = pdev->irq;
#endif
	pr_debug("pdev->irq = %d\n", pdev->irq);

	priv = drm_dev->dev_private;
	dc = dev_get_drvdata(dev);

	dc_unbind(dev, NULL, drm_dev);

	free_irq(priv->irq_num[1], (void *)dc);

	pci_free_irq_vectors(pdev);

	devm_iounmap(dev, priv->pf_bar_base);
	devm_iounmap(dev, priv->pci_base);
}
#endif

static void dc_deinit_aer(struct device *dev)
{
	struct vs_dc *dc = dev_get_drvdata(dev);

	egt_dc_hw_deinit(&dc->hw);

	vs_dc_disable_clock(dc);
}

static void dc_unbind_aer(struct device *dev, void *data)
{
	struct drm_device *drm_dev = data;

#ifdef CONFIG_ENGIANT_VS_DEBUG
		struct vs_dc *dc = dev_get_drvdata(dev);

	dc->hw.dc_capture_fp = NULL;
#endif

	dc_deinit_aer(dev);

	vs_egt_drm_iommu_detach_device(drm_dev, dev);
}

void vs_egt_dc_pci_deinit_aer(struct drm_device *drm_dev)
{
	struct vs_drm_private *priv;
	struct vs_dc *dc;
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;

#if IS_ENABLED(CONFIG_DRM_LEGACY)
	drm_dev->irq = pdev->irq;
#endif
	pr_debug("pdev->irq = %d\n", pdev->irq);

	priv = drm_dev->dev_private;
	dc = dev_get_drvdata(dev);

	dc_unbind_aer(dev, drm_dev);

	free_irq(priv->irq_num[1], (void *)dc);

	pci_free_irq_vectors(pdev);

	devm_iounmap(dev, priv->pf_bar_base);
	devm_iounmap(dev, priv->pci_base);
}

static int dc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct vs_dc *dc;
	int irq, ret;

	irq = platform_get_irq(pdev, 0);

	ret = dc_construct(dev, irq, &dc);
	if (ret)
		return ret;

	dc->hw.reg_base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(dc->hw.reg_base)) {
		ret = PTR_ERR(dc->hw.reg_base);
		goto err_deconstruct;
	}

	dc->core_clk = devm_clk_get_optional(dev, "core_clk");
	if (IS_ERR(dc->core_clk)) {
		dev_err(dev, "failed to get core_clk source\n");
		ret = PTR_ERR(dc->core_clk);
		goto err_deconstruct;
	}

	dc->pix_clk = devm_clk_get_optional(dev, "pix_clk");
	if (IS_ERR(dc->pix_clk)) {
		dev_err(dev, "failed to get pix_clk source\n");
		ret = PTR_ERR(dc->pix_clk);
		goto err_deconstruct;
	}

	dc->axi_clk = devm_clk_get_optional(dev, "axi_clk");
	if (IS_ERR(dc->axi_clk)) {
		dev_err(dev, "failed to get axi_clk source\n");
		ret = PTR_ERR(dc->axi_clk);
		goto err_deconstruct;
	}

	dc->irq_num = irq;

	dev_set_drvdata(dev, dc);

	return component_add(dev, &dc_component_ops);

err_deconstruct:
	free_irq(dc->irq_num, (void *)dc);
	return ret;
}

static int dc_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct vs_dc *dc = dev_get_drvdata(dev);

	component_del(dev, &dc_component_ops);

	free_irq(dc->irq_num, (void *)dc);

	dev_set_drvdata(dev, NULL);

	return 0;
}

static int dc_be_probe(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

static int dc_be_remove(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

static int dc_fe0_probe(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

static int dc_fe0_remove(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

static int dc_fe1_probe(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

static int dc_fe1_remove(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

static int dc_wb_probe(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

static int dc_wb_remove(__maybe_unused struct platform_device *pdev)
{
	int ret = 0;
	return ret;
}

struct platform_driver egt_dc_platform_driver = {
	.probe = dc_probe,
	.remove = dc_remove,
	.driver = {
		.name = "vs-dc",
	},
};

struct platform_driver egt_dc_be_platform_driver = {
	.probe = dc_be_probe,
	.remove = dc_be_remove,

	.driver = {
		.name = "vs-dc-be",
	},
};

struct platform_driver egt_dc_fe0_platform_driver = {
	.probe = dc_fe0_probe,
	.remove = dc_fe0_remove,
	.driver = {
		.name = "vs-dc-fe0",
	},
};

struct platform_driver egt_dc_fe1_platform_driver = {
	.probe = dc_fe1_probe,
	.remove = dc_fe1_remove,

	.driver = {
		.name = "vs-dc-fe1",
	},
};

struct platform_driver egt_dc_wb_platform_driver = {
	.probe = dc_wb_probe,
	.remove = dc_wb_remove,

	.driver = {
		.name = "vs-dc-wb",
	},
};

MODULE_DESCRIPTION("VeriSilicon DC Driver");
MODULE_LICENSE("GPL");
