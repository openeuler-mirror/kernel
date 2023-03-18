// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */
#include <drm/drm_vblank.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>

#include "lsdc_drv.h"
#include "lsdc_regs.h"
#include "lsdc_pll.h"

static int lsdc_crtc_enable_vblank(struct drm_crtc *crtc)
{
	struct lsdc_device *ldev = to_lsdc(crtc->dev);
	unsigned int index = drm_crtc_index(crtc);
	struct drm_crtc_state *state = crtc->state;
	u32 val;

	if (state->enable) {
		val = readl(ldev->reg_base + LSDC_INT_REG);

		if (index == 0)
			val |= INT_CRTC0_VS_EN;
		else if (index == 1)
			val |= INT_CRTC1_VS_EN;

		writel(val, ldev->reg_base + LSDC_INT_REG);
	}

	return 0;
}

static void lsdc_crtc_disable_vblank(struct drm_crtc *crtc)
{
	struct lsdc_device *ldev = to_lsdc(crtc->dev);
	unsigned int index = drm_crtc_index(crtc);
	u32 val;

	val = readl(ldev->reg_base + LSDC_INT_REG);

	if (index == 0)
		val &= ~INT_CRTC0_VS_EN;
	else if (index == 1)
		val &= ~INT_CRTC1_VS_EN;

	writel(val, ldev->reg_base + LSDC_INT_REG);
}

static void lsdc_crtc_reset(struct drm_crtc *crtc)
{
	struct drm_device *ddev = crtc->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	unsigned int index = drm_crtc_index(crtc);
	struct lsdc_crtc_state *priv_crtc_state;
	u32 val = CFG_RESET_BIT | CFG_OUTPUT_EN_BIT | LSDC_PF_XRGB8888;

	if (ldev->enable_gamma)
		val |= CFG_GAMMAR_EN_BIT;

	/* align to 64 */
	if (ldev->desc->chip == LSDC_CHIP_7A2000) {
		val &= ~LS7A2000_DMA_STEP_MASK;
		val |= DMA_STEP_256_BYTE;
	}

	if (index == 0)
		writel(val, ldev->reg_base + LSDC_CRTC0_CFG_REG);
	else if (index == 1)
		writel(val, ldev->reg_base + LSDC_CRTC1_CFG_REG);

	if (crtc->state) {
		priv_crtc_state = to_lsdc_crtc_state(crtc->state);
		__drm_atomic_helper_crtc_destroy_state(&priv_crtc_state->base);
		kfree(priv_crtc_state);
	}

	priv_crtc_state = kzalloc(sizeof(*priv_crtc_state), GFP_KERNEL);
	if (!priv_crtc_state)
		return;

	__drm_atomic_helper_crtc_reset(crtc, &priv_crtc_state->base);

	drm_dbg(ddev, "crtc%u reset\n", index);
}

static void lsdc_crtc_atomic_destroy_state(struct drm_crtc *crtc, struct drm_crtc_state *state)
{
	struct lsdc_crtc_state *priv_crtc_state = to_lsdc_crtc_state(state);

	__drm_atomic_helper_crtc_destroy_state(&priv_crtc_state->base);

	kfree(priv_crtc_state);
}

static struct drm_crtc_state *lsdc_crtc_atomic_duplicate_state(struct drm_crtc *crtc)
{
	struct lsdc_crtc_state *new_priv_state;
	struct lsdc_crtc_state *old_priv_state;
	struct drm_device *ddev = crtc->dev;

	if (drm_WARN_ON(ddev, !crtc->state))
		return NULL;

	new_priv_state = kmalloc(sizeof(*new_priv_state), GFP_KERNEL);
	if (!new_priv_state)
		return NULL;

	__drm_atomic_helper_crtc_duplicate_state(crtc, &new_priv_state->base);

	old_priv_state = to_lsdc_crtc_state(crtc->state);

	memcpy(&new_priv_state->pparams, &old_priv_state->pparams, sizeof(new_priv_state->pparams));

	return &new_priv_state->base;
}

static const struct drm_crtc_funcs lsdc_crtc_funcs = {
	.reset = lsdc_crtc_reset,
	.destroy = drm_crtc_cleanup,
	.set_config = drm_atomic_helper_set_config,
	.page_flip = drm_atomic_helper_page_flip,
	.atomic_duplicate_state = lsdc_crtc_atomic_duplicate_state,
	.atomic_destroy_state = lsdc_crtc_atomic_destroy_state,
	.enable_vblank = lsdc_crtc_enable_vblank,
	.disable_vblank = lsdc_crtc_disable_vblank,
};

static enum drm_mode_status
lsdc_crtc_helper_mode_valid(struct drm_crtc *crtc,
			    const struct drm_display_mode *mode)
{
	struct drm_device *ddev = crtc->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	const struct lsdc_chip_desc * const descp = ldev->desc;

	if (mode->hdisplay > descp->max_width)
		return MODE_BAD_HVALUE;
	if (mode->vdisplay > descp->max_height)
		return MODE_BAD_VVALUE;

	if (mode->clock > descp->max_pixel_clk) {
		drm_dbg(ddev, "mode %dx%d, pixel clock=%d is too high\n",
			mode->hdisplay, mode->vdisplay, mode->clock);
		return MODE_CLOCK_HIGH;
	}

	/* The CRTC hardware dma take 256 bytes once a time,
	 * this is a limitation of the CRTC.
	 * TODO: check RGB565 support
	 */
	if (!ldev->relax_alignment) {
		if ((mode->hdisplay * 4) % descp->stride_alignment) {
			drm_dbg(ddev, "mode %dx%d, stride is not %u bytes aligned\n",
				mode->hdisplay, mode->vdisplay, descp->stride_alignment);
			return MODE_BAD;
		}
	}

	return MODE_OK;
}

static int lsdc_pixpll_atomic_check(struct drm_crtc *crtc,
				    struct drm_crtc_state *state)
{
	struct lsdc_display_pipe * const dispipe = crtc_to_display_pipe(crtc);
	struct lsdc_pll * const pixpll = &dispipe->pixpll;
	const struct lsdc_pixpll_funcs * const pfuncs = pixpll->funcs;
	struct lsdc_crtc_state *priv_state = to_lsdc_crtc_state(state);
	bool ret;

	ret = pfuncs->compute(pixpll, state->mode.clock, &priv_state->pparams);
	if (ret)
		return 0;

	drm_warn(crtc->dev, "failed find PLL parameters for %u\n", state->mode.clock);

	return -EINVAL;
}

static int lsdc_crtc_helper_atomic_check(struct drm_crtc *crtc,
					 struct drm_crtc_state *state)
{
	if (!state->enable)
		return 0; /* no mode checks if CRTC is being disabled */

	if (state->mode_changed || state->active_changed || state->connectors_changed)
		return lsdc_pixpll_atomic_check(crtc, state);

	return 0;
}

static void lsdc_update_pixclk(struct drm_crtc *crtc)
{
	struct lsdc_display_pipe * const dispipe = crtc_to_display_pipe(crtc);
	struct lsdc_pll * const pixpll = &dispipe->pixpll;
	const struct lsdc_pixpll_funcs * const clkfun = pixpll->funcs;
	struct lsdc_crtc_state *priv_state = to_lsdc_crtc_state(crtc->state);

	clkfun->update(pixpll, &priv_state->pparams);
}

static void lsdc_crtc_helper_mode_set_nofb(struct drm_crtc *crtc)
{
	struct drm_device *ddev = crtc->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	struct drm_display_mode *mode = &crtc->state->adjusted_mode;
	unsigned int index = drm_crtc_index(crtc);
	u32 h_sync, v_sync, h_val, v_val;

	/* 26:16 total pixels, 10:0 visiable pixels, in horizontal */
	h_val = (mode->crtc_htotal << 16) | mode->crtc_hdisplay;
	/* Hack to support non 256 bytes aligned stride, for example:
	 * 800x480 DPI panel. In this case userspace do the work to
	 * guarantee the horizontal pixel size is aligned by padding it.
	 * In actual, We allocate 832x480x4 bytes in size.
	 */
	if (ldev->relax_alignment)
		h_val = (h_val + 63) & ~63;

	/* 26:16 total pixels, 10:0 visiable pixels, in vertical */
	v_val = (mode->crtc_vtotal << 16) | mode->crtc_vdisplay;
	/* 26:16 hsync end, 10:0 hsync start, bit 30 is hsync enable */
	h_sync = (mode->crtc_hsync_end << 16) | mode->crtc_hsync_start | EN_HSYNC_BIT;
	if (mode->flags & DRM_MODE_FLAG_NHSYNC)
		h_sync |= INV_HSYNC_BIT;

	/* 26:16 vsync end, 10:0 vsync start, bit 30 is vsync enable */
	v_sync = (mode->crtc_vsync_end << 16) | mode->crtc_vsync_start | EN_VSYNC_BIT;
	if (mode->flags & DRM_MODE_FLAG_NVSYNC)
		v_sync |= INV_VSYNC_BIT;

	if (index == 0) {
		writel(0, ldev->reg_base + LSDC_CRTC0_FB_ORIGIN_REG);
		writel(h_val, ldev->reg_base + LSDC_CRTC0_HDISPLAY_REG);
		writel(v_val, ldev->reg_base + LSDC_CRTC0_VDISPLAY_REG);
		writel(h_sync, ldev->reg_base + LSDC_CRTC0_HSYNC_REG);
		writel(v_sync, ldev->reg_base + LSDC_CRTC0_VSYNC_REG);
	} else if (index == 1) {
		writel(0, ldev->reg_base + LSDC_CRTC1_FB_ORIGIN_REG);
		writel(h_val, ldev->reg_base + LSDC_CRTC1_HDISPLAY_REG);
		writel(v_val, ldev->reg_base + LSDC_CRTC1_VDISPLAY_REG);
		writel(h_sync, ldev->reg_base + LSDC_CRTC1_HSYNC_REG);
		writel(v_sync, ldev->reg_base + LSDC_CRTC1_VSYNC_REG);
	}

	drm_dbg(ddev, "%s modeset: %ux%u\n", crtc->name, mode->hdisplay, mode->vdisplay);

	lsdc_update_pixclk(crtc);
}

static void lsdc_enable_display(struct lsdc_device *ldev, unsigned int index)
{
	u32 val;

	if (index == 0) {
		val = readl(ldev->reg_base + LSDC_CRTC0_CFG_REG);
		val |= CFG_OUTPUT_EN_BIT;
		writel(val, ldev->reg_base + LSDC_CRTC0_CFG_REG);
	} else if (index == 1) {
		val = readl(ldev->reg_base + LSDC_CRTC1_CFG_REG);
		val |= CFG_OUTPUT_EN_BIT;
		writel(val, ldev->reg_base + LSDC_CRTC1_CFG_REG);
	}
}

static void lsdc_disable_display(struct lsdc_device *ldev, unsigned int index)
{
	u32 val;

	if (index == 0) {
		val = readl(ldev->reg_base + LSDC_CRTC0_CFG_REG);
		val &= ~CFG_OUTPUT_EN_BIT;
		writel(val, ldev->reg_base + LSDC_CRTC0_CFG_REG);
	} else if (index == 1) {
		val = readl(ldev->reg_base + LSDC_CRTC1_CFG_REG);
		val &= ~CFG_OUTPUT_EN_BIT;
		writel(val, ldev->reg_base + LSDC_CRTC1_CFG_REG);
	}
}

/*
 * @lsdc_crtc_helper_atomic_enable:
 *
 * This callback should be used to enable the CRTC. With the atomic
 * drivers it is called before all encoders connected to this CRTC are
 * enabled through the encoder's own &drm_encoder_helper_funcs.enable
 * hook.  If that sequence is too simple drivers can just add their own
 * hooks and call it from this CRTC callback here by looping over all
 * encoders connected to it using for_each_encoder_on_crtc().
 *
 * This hook is used only by atomic helpers, for symmetry with
 * @atomic_disable. Atomic drivers don't need to implement it if there's
 * no need to enable anything at the CRTC level. To ensure that runtime
 * PM handling (using either DPMS or the new "ACTIVE" property) works
 * @atomic_enable must be the inverse of @atomic_disable for atomic
 * drivers.
 *
 * Drivers can use the @old_crtc_state input parameter if the operations
 * needed to enable the CRTC don't depend solely on the new state but
 * also on the transition between the old state and the new state.
 *
 * This function is optional.
 */
static void lsdc_crtc_helper_atomic_enable(struct drm_crtc *crtc,
					   struct drm_crtc_state *old_crtc_state)
{
	struct drm_device *ddev = crtc->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);

	drm_crtc_vblank_on(crtc);

	lsdc_enable_display(ldev, drm_crtc_index(crtc));

	drm_dbg(ddev, "%s: enabled\n", crtc->name);
}

static void lsdc_crtc_helper_atomic_disable(struct drm_crtc *crtc,
					    struct drm_crtc_state *old_crtc_state)
{
	struct drm_device *ddev = crtc->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);

	drm_crtc_vblank_off(crtc);

	lsdc_disable_display(ldev, drm_crtc_index(crtc));

	drm_dbg(ddev, "%s: disabled\n", crtc->name);
}

static void lsdc_crtc_update_clut(struct drm_crtc *crtc)
{
	struct lsdc_device *ldev = to_lsdc(crtc->dev);
	unsigned int index = drm_crtc_index(crtc);
	struct drm_color_lut *lut;
	unsigned int i;

	if (!ldev->enable_gamma)
		return;

	if (!crtc->state->color_mgmt_changed || !crtc->state->gamma_lut)
		return;

	lut = (struct drm_color_lut *)crtc->state->gamma_lut->data;

	writel(0, ldev->reg_base + LSDC_CRTC0_GAMMA_INDEX_REG);

	for (i = 0; i < 256; i++) {
		u32 val = ((lut->red << 8) & 0xff0000) |
			  (lut->green & 0xff00) |
			  (lut->blue >> 8);

		if (index == 0)
			writel(val, ldev->reg_base + LSDC_CRTC0_GAMMA_DATA_REG);
		else if (index == 1)
			writel(val, ldev->reg_base + LSDC_CRTC1_GAMMA_DATA_REG);

		lut++;
	}
}

static void lsdc_crtc_atomic_flush(struct drm_crtc *crtc,
				   struct drm_crtc_state *old_crtc_state)
{
	struct drm_pending_vblank_event *event = crtc->state->event;

	lsdc_crtc_update_clut(crtc);

	if (event) {
		crtc->state->event = NULL;

		spin_lock_irq(&crtc->dev->event_lock);
		if (drm_crtc_vblank_get(crtc) == 0)
			drm_crtc_arm_vblank_event(crtc, event);
		else
			drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&crtc->dev->event_lock);
	}
}

static const struct drm_crtc_helper_funcs lsdc_crtc_helper_funcs = {
	.mode_valid = lsdc_crtc_helper_mode_valid,
	.mode_set_nofb = lsdc_crtc_helper_mode_set_nofb,
	.atomic_enable = lsdc_crtc_helper_atomic_enable,
	.atomic_disable = lsdc_crtc_helper_atomic_disable,
	.atomic_check = lsdc_crtc_helper_atomic_check,
	.atomic_flush = lsdc_crtc_atomic_flush,
};

int lsdc_crtc_init(struct drm_device *ddev,
		   struct drm_crtc *crtc,
		   unsigned int index,
		   struct drm_plane *primary,
		   struct drm_plane *cursor)
{
	int ret;

	ret = drm_crtc_init_with_planes(ddev, crtc, primary, cursor,
					&lsdc_crtc_funcs, "crtc-%d", index);

	if (ret) {
		drm_err(ddev, "crtc init with planes failed: %d\n", ret);
		return ret;
	}

	drm_crtc_helper_add(crtc, &lsdc_crtc_helper_funcs);

	ret = drm_mode_crtc_set_gamma_size(crtc, 256);
	if (ret)
		drm_warn(ddev, "set the gamma table size failed\n");

	drm_crtc_enable_color_mgmt(crtc, 0, false, 256);

	return 0;
}
