// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */
#include <drm/drm_fourcc.h>
#include <drm/drm_atomic.h>
#include <drm/drm_format_helper.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_gem_vram_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>

#include "lsdc_drv.h"
#include "lsdc_regs.h"

static const u32 lsdc_primary_formats[] = {
	DRM_FORMAT_RGB565,
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_ARGB8888,
};

static const u32 lsdc_cursor_formats[] = {
	DRM_FORMAT_ARGB8888,
};

static const u64 lsdc_fb_format_modifiers[] = {
	DRM_FORMAT_MOD_LINEAR,
	DRM_FORMAT_MOD_INVALID
};

static void lsdc_update_fb_format(struct lsdc_device *ldev,
				  struct drm_crtc *crtc,
				  const struct drm_format_info *fmt_info)
{
	unsigned int index = drm_crtc_index(crtc);
	u32 val = 0;
	u32 fmt;

	switch (fmt_info->format) {
	case DRM_FORMAT_RGB565:
		fmt = LSDC_PF_RGB565;
		break;
	case DRM_FORMAT_XRGB8888:
		fmt = LSDC_PF_XRGB8888;
		break;
	case DRM_FORMAT_ARGB8888:
		fmt = LSDC_PF_XRGB8888;
		break;
	default:
		fmt = LSDC_PF_XRGB8888;
		break;
	}

	if (index == 0) {
		val = readl(ldev->reg_base + LSDC_CRTC0_CFG_REG);
		val = (val & ~CFG_PIX_FMT_MASK) | fmt;
		writel(val, ldev->reg_base + LSDC_CRTC0_CFG_REG);
	} else if (index == 1) {
		val = readl(ldev->reg_base + LSDC_CRTC1_CFG_REG);
		val = (val & ~CFG_PIX_FMT_MASK) | fmt;
		writel(val, ldev->reg_base + LSDC_CRTC1_CFG_REG);
	}
}

static void lsdc_update_fb_start_addr(struct lsdc_device *ldev,
				      unsigned int index,
				      u64 fb_addr)
{
	u32 lo = fb_addr & 0xFFFFFFFF;
	u32 hi = (fb_addr >> 32) & 0xFF;
	u32 cfg;

	if (index == 0) {
		cfg = lsdc_crtc_rreg32(ldev, LSDC_CRTC0_CFG_REG, index);
		if (cfg & BIT(9)) {
			lsdc_wreg32(ldev, LSDC_CRTC0_FB1_LO_ADDR_REG, lo);
			lsdc_wreg32(ldev, LSDC_CRTC0_FB1_HI_ADDR_REG, hi);
		} else {
			lsdc_wreg32(ldev, LSDC_CRTC0_FB0_LO_ADDR_REG, lo);
			lsdc_wreg32(ldev, LSDC_CRTC0_FB0_HI_ADDR_REG, hi);
		}
	} else if (index == 1) {
		cfg = lsdc_crtc_rreg32(ldev, LSDC_CRTC1_CFG_REG, index);
		if (cfg & BIT(9)) {
			lsdc_wreg32(ldev, LSDC_CRTC1_FB1_LO_ADDR_REG, lo);
			lsdc_wreg32(ldev, LSDC_CRTC1_FB1_HI_ADDR_REG, hi);
		} else {
			lsdc_wreg32(ldev, LSDC_CRTC1_FB0_LO_ADDR_REG, lo);
			lsdc_wreg32(ldev, LSDC_CRTC1_FB0_HI_ADDR_REG, hi);
		}
	}
}

static unsigned int lsdc_get_fb_offset(struct drm_framebuffer *fb,
				       struct drm_plane_state *state,
				       unsigned int plane)
{
	unsigned int offset = fb->offsets[plane];

	offset += fb->format->cpp[plane] * (state->src_x >> 16);
	offset += fb->pitches[plane] * (state->src_y >> 16);

	return offset;
}

static s64 lsdc_get_vram_bo_offset(struct drm_framebuffer *fb)
{
	struct drm_gem_vram_object *gbo;
	s64 gpu_addr;

	gbo = drm_gem_vram_of_gem(fb->obj[0]);
	gpu_addr = drm_gem_vram_offset(gbo);

	return gpu_addr;
}

static int lsdc_primary_plane_atomic_check(struct drm_plane *plane,
					   struct drm_plane_state *state)
{
	struct drm_crtc *crtc = state->crtc;
	struct drm_crtc_state *crtc_state;
	struct drm_framebuffer *fb = state->fb;

	/* no need for further checks if the plane is being disabled */
	if (!crtc || !fb)
		return 0;

	crtc_state = drm_atomic_get_crtc_state(state->state, crtc);
	if (WARN_ON(!crtc_state))
		return -EINVAL;

	return drm_atomic_helper_check_plane_state(plane->state,
						   crtc_state,
						   DRM_PLANE_HELPER_NO_SCALING,
						   DRM_PLANE_HELPER_NO_SCALING,
						   false, true);
}

static void lsdc_update_stride(struct lsdc_device *ldev,
			       struct drm_crtc *crtc,
			       unsigned int stride)
{
	unsigned int index = drm_crtc_index(crtc);

	if (index == 0)
		writel(stride, ldev->reg_base + LSDC_CRTC0_STRIDE_REG);
	else if (index == 1)
		writel(stride, ldev->reg_base + LSDC_CRTC1_STRIDE_REG);

	drm_dbg(&ldev->ddev, "update stride to %u\n", stride);
}

static void lsdc_primary_plane_atomic_update(struct drm_plane *plane,
					     struct drm_plane_state *old_state)
{
	struct drm_device *ddev = plane->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	struct drm_plane_state *new_plane_state = plane->state;
	struct drm_crtc *crtc = new_plane_state->crtc;
	struct drm_framebuffer *fb = new_plane_state->fb;
	u32 fb_offset = lsdc_get_fb_offset(fb, new_plane_state, 0);
	dma_addr_t fb_addr;

	if (ldev->use_vram_helper) {
		s64 gpu_addr;

		gpu_addr = lsdc_get_vram_bo_offset(fb);
		if (gpu_addr < 0)
			return;

		fb_addr = ldev->vram_base + gpu_addr + fb_offset;
	} else {
		struct drm_gem_cma_object *obj = drm_fb_cma_get_gem_obj(fb, 0);

		fb_addr = obj->paddr + fb_offset;
	}

	lsdc_update_fb_start_addr(ldev, drm_crtc_index(crtc), fb_addr);

	lsdc_update_stride(ldev, crtc, fb->pitches[0]);

	if (drm_atomic_crtc_needs_modeset(crtc->state))
		lsdc_update_fb_format(ldev, crtc, fb->format);
}

static void lsdc_primary_plane_atomic_disable(struct drm_plane *plane,
					      struct drm_plane_state *old_state)
{
	drm_dbg(plane->dev, "%s disabled\n", plane->name);
}

static int lsdc_plane_prepare_fb(struct drm_plane *plane,
				 struct drm_plane_state *new_state)
{
	struct lsdc_device *ldev = to_lsdc(plane->dev);

	if (ldev->use_vram_helper)
		return drm_gem_vram_plane_helper_prepare_fb(plane, new_state);

	return drm_gem_fb_prepare_fb(plane, new_state);
}

static void lsdc_plane_cleanup_fb(struct drm_plane *plane,
				  struct drm_plane_state *old_state)
{
	struct drm_device *ddev = plane->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);

	if (ldev->use_vram_helper)
		return drm_gem_vram_plane_helper_cleanup_fb(plane, old_state);
}

static const struct drm_plane_helper_funcs lsdc_primary_plane_helpers = {
	.prepare_fb = lsdc_plane_prepare_fb,
	.cleanup_fb = lsdc_plane_cleanup_fb,
	.atomic_check = lsdc_primary_plane_atomic_check,
	.atomic_update = lsdc_primary_plane_atomic_update,
	.atomic_disable = lsdc_primary_plane_atomic_disable,
};

static int lsdc_cursor_atomic_check(struct drm_plane *plane,
				    struct drm_plane_state *state)
{
	struct drm_framebuffer *fb = state->fb;
	struct drm_crtc *crtc = state->crtc;
	struct drm_crtc_state *crtc_state;

	/* no need for further checks if the plane is being disabled */
	if (!crtc || !fb)
		return 0;

	if (!state->visible)
		return 0;

	crtc_state = drm_atomic_get_crtc_state(state->state, crtc);
	if (WARN_ON(!crtc_state))
		return -EINVAL;

	return drm_atomic_helper_check_plane_state(state,
						   crtc_state,
						   DRM_PLANE_HELPER_NO_SCALING,
						   DRM_PLANE_HELPER_NO_SCALING,
						   true,
						   true);
}

static void lsdc_cursor_atomic_update(struct drm_plane *plane,
				      struct drm_plane_state *old_plane_state)
{
	struct lsdc_display_pipe * const dispipe = cursor_to_display_pipe(plane);
	struct drm_device *ddev = plane->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	const struct lsdc_chip_desc * const descp = ldev->desc;
	struct drm_plane_state *new_plane_state = plane->state;
	struct drm_framebuffer *new_fb = new_plane_state->fb;
	struct drm_framebuffer *old_fb = old_plane_state->fb;
	int dst_x = new_plane_state->crtc_x;
	int dst_y = new_plane_state->crtc_y;
	u32 val;

	if (new_fb != old_fb) {
		u64 cursor_addr;

		if (ldev->use_vram_helper) {
			s64 offset;

			offset = lsdc_get_vram_bo_offset(new_fb);
			cursor_addr = ldev->vram_base + offset;

			drm_dbg(ddev, "%s offset: %llx\n", plane->name, offset);
		} else {
			struct drm_gem_cma_object *cursor_obj;

			cursor_obj = drm_fb_cma_get_gem_obj(new_fb, 0);
			if (!cursor_obj)
				return;

			cursor_addr = cursor_obj->paddr;
		}

		if ((descp->chip == LSDC_CHIP_7A2000) && (dispipe->index == 1))
			writel(cursor_addr, ldev->reg_base + LSDC_CURSOR1_ADDR_REG);
		else
			writel(cursor_addr, ldev->reg_base + LSDC_CURSOR0_ADDR_REG);
	}

	/* Update cursor's position */
	if (dst_x < 0)
		dst_x = 0;

	if (dst_y < 0)
		dst_y = 0;

	val = (dst_y << 16) | dst_x;

	if ((descp->chip == LSDC_CHIP_7A2000) && (dispipe->index == 1))
		writel(val, ldev->reg_base + LSDC_CURSOR1_POSITION_REG);
	else
		writel(val, ldev->reg_base + LSDC_CURSOR0_POSITION_REG);

	/* Update cursor's location and format */
	val = CURSOR_FORMAT_ARGB8888;

	if (descp->chip == LSDC_CHIP_7A2000) {
		/* LS7A2000 support 64x64 and 32x32 */
		val |= CURSOR_SIZE_64X64;
		if (dispipe->index == 1) {
			val |= CURSOR_LOCATION_BIT;
			writel(val, ldev->reg_base + LSDC_CURSOR1_CFG_REG);
		} else if (dispipe->index == 0) {
			val &= ~CURSOR_LOCATION_BIT;
			writel(val, ldev->reg_base + LSDC_CURSOR0_CFG_REG);
		}
	} else {
		/*
		 * Update the location of the cursor
		 * if bit 4 of LSDC_CURSOR_CFG_REG is 1, then the cursor will be
		 * locate at CRTC1, if bit 4 of LSDC_CURSOR_CFG_REG is 0, then
		 * the cursor will be locate at CRTC0.
		 */
		if (dispipe->index)
			val |= CURSOR_LOCATION_BIT;

		writel(val, ldev->reg_base + LSDC_CURSOR0_CFG_REG);
	}
}

static void lsdc_cursor_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *old_state)
{
	const struct lsdc_display_pipe * const dispipe = cursor_to_display_pipe(plane);
	struct drm_device *ddev = plane->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	const struct lsdc_chip_desc * const descp = ldev->desc;
	u32 val;

	if ((descp->chip == LSDC_CHIP_7A2000) && (dispipe->index == 1)) {
		val = readl(ldev->reg_base + LSDC_CURSOR1_CFG_REG);
		val &= ~CURSOR_FORMAT_MASK;
		val |= CURSOR_FORMAT_DISABLE;
		writel(val, ldev->reg_base + LSDC_CURSOR1_CFG_REG);
	} else {
		val = readl(ldev->reg_base + LSDC_CURSOR0_CFG_REG);
		val &= ~CURSOR_FORMAT_MASK;
		val |= CURSOR_FORMAT_DISABLE;
		writel(val, ldev->reg_base + LSDC_CURSOR0_CFG_REG);
	}

	drm_dbg(ddev, "%s disabled\n", plane->name);
}

static const struct drm_plane_helper_funcs lsdc_cursor_plane_helpers = {
	.prepare_fb = lsdc_plane_prepare_fb,
	.cleanup_fb = lsdc_plane_cleanup_fb,
	.atomic_check = lsdc_cursor_atomic_check,
	.atomic_update = lsdc_cursor_atomic_update,
	.atomic_disable = lsdc_cursor_atomic_disable,
};

static int lsdc_plane_get_default_zpos(enum drm_plane_type type)
{
	switch (type) {
	case DRM_PLANE_TYPE_PRIMARY:
		return 0;
	case DRM_PLANE_TYPE_OVERLAY:
		return 1;
	case DRM_PLANE_TYPE_CURSOR:
		return 7;
	}

	return 0;
}

static void lsdc_plane_reset(struct drm_plane *plane)
{
	drm_atomic_helper_plane_reset(plane);

	plane->state->zpos = lsdc_plane_get_default_zpos(plane->type);

	drm_dbg(plane->dev, "%s reset\n", plane->name);
}

static const struct drm_plane_funcs lsdc_plane_funcs = {
	.update_plane = drm_atomic_helper_update_plane,
	.disable_plane = drm_atomic_helper_disable_plane,
	.destroy = drm_plane_cleanup,
	.reset = lsdc_plane_reset,
	.atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_plane_destroy_state,
};

int lsdc_plane_init(struct lsdc_device *ldev,
		    struct drm_plane *plane,
		    enum drm_plane_type type,
		    unsigned int index)
{
	struct drm_device *ddev = &ldev->ddev;
	int zpos = lsdc_plane_get_default_zpos(type);
	unsigned int format_count;
	const u32 *formats;
	const char *name;
	int ret;

	switch (type) {
	case DRM_PLANE_TYPE_PRIMARY:
		formats = lsdc_primary_formats;
		format_count = ARRAY_SIZE(lsdc_primary_formats);
		name = "primary-%u";
		break;
	case DRM_PLANE_TYPE_CURSOR:
		formats = lsdc_cursor_formats;
		format_count = ARRAY_SIZE(lsdc_cursor_formats);
		name = "cursor-%u";
		break;
	case DRM_PLANE_TYPE_OVERLAY:
		drm_err(ddev, "overlay plane is not supported\n");
		break;
	}

	ret = drm_universal_plane_init(ddev, plane, 1 << index,
				       &lsdc_plane_funcs,
				       formats, format_count,
				       lsdc_fb_format_modifiers,
				       type, name, index);
	if (ret) {
		drm_err(ddev, "%s failed: %d\n", __func__, ret);
		return ret;
	}

	switch (type) {
	case DRM_PLANE_TYPE_PRIMARY:
		drm_plane_helper_add(plane, &lsdc_primary_plane_helpers);
		drm_plane_create_zpos_property(plane, zpos, 0, 6);
		break;
	case DRM_PLANE_TYPE_CURSOR:
		drm_plane_helper_add(plane, &lsdc_cursor_plane_helpers);
		drm_plane_create_zpos_immutable_property(plane, zpos);
		break;
	case DRM_PLANE_TYPE_OVERLAY:
		drm_err(ddev, "overlay plane is not supported\n");
		break;
	}

	drm_plane_create_alpha_property(plane);

	return 0;
}
