// SPDX-License-Identifier: GPL-2.0-or-later
/* Hisilicon Hibmc SoC drm driver
 *
 * Based on the bochs drm driver.
 *
 * Copyright (c) 2016 Huawei Limited.
 *
 * Author:
 *	Rongrong Zou <zourongrong@huawei.com>
 *	Rongrong Zou <zourongrong@gmail.com>
 *	Jianhua Li <lijianhua@huawei.com>
 */

#include <drm/drm_atomic_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_print.h>

#include "hibmc_drm_drv.h"
#include "hibmc_drm_regs.h"

#define HIBMC_STANDARD_VREFRESH		60

struct hibmc_resolution {
	int width;
	int height;
};

static const struct hibmc_resolution hibmc_mode_tables[] = {
	{800, 600},
	{1024, 768},
	{1152, 864},
	{1280, 768},
	{1280, 720},
	{1280, 960},
	{1280, 1024},
	{1600, 1200},
	{1920, 1080},
	{1920, 1200},
};

static int hibmc_connector_get_modes(struct drm_connector *connector)
{
	int count;
	void *edid;
	struct hibmc_vdac *vdac = to_hibmc_vdac(connector);

	edid = drm_get_edid(connector, &vdac->adapter);
	if (edid) {
		drm_connector_update_edid_property(connector, edid);
		count = drm_add_edid_modes(connector, edid);
		if (count)
			goto out;
	}

	count = drm_add_modes_noedid(connector,
				     connector->dev->mode_config.max_width,
				     connector->dev->mode_config.max_height);
	drm_set_preferred_mode(connector, 1024, 768);

out:
	kfree(edid);
	return count;
}

static int hibmc_valid_mode(int width, int height)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hibmc_mode_tables); i++) {
		if ((hibmc_mode_tables[i].width == width) &&
			(hibmc_mode_tables[i].height == height)) {
			return MODE_OK;
		}
	}

	return MODE_NOMODE;
}

static enum drm_mode_status hibmc_connector_mode_valid(
	struct drm_connector *connector, struct drm_display_mode *mode)
{
	int vrefresh = drm_mode_vrefresh(mode);

	if ((vrefresh < HIBMC_STANDARD_VREFRESH - 1) ||
		(vrefresh > HIBMC_STANDARD_VREFRESH + 1))
		return MODE_NOMODE;

	return hibmc_valid_mode(mode->hdisplay, mode->vdisplay);
}

static void hibmc_vdac_connector_destroy(struct drm_connector *connector)
{
	struct hibmc_vdac *vdac = to_hibmc_vdac(connector);

	i2c_del_adapter(&vdac->adapter);
	drm_connector_cleanup(connector);
}

static int hibmc_vdac_detect(struct drm_connector *connector, struct drm_modeset_acquire_ctx *ctx,
			     bool force)
{
	struct hibmc_drm_private *priv = to_hibmc_drm_private(connector->dev);
	struct hibmc_dp *dp = &priv->dp;

	if (dp->hpd_status)
		return connector_status_disconnected;

	return connector_status_connected;
}

static const struct drm_connector_helper_funcs
	hibmc_connector_helper_funcs = {
	.get_modes = hibmc_connector_get_modes,
	.mode_valid = hibmc_connector_mode_valid,
	.detect_ctx = hibmc_vdac_detect,
};

static void hibmc_vdac_force(struct drm_connector *connector)
{
	struct hibmc_drm_private *priv = to_hibmc_drm_private(connector->dev);
	struct hibmc_dp *dp = &priv->dp;

	if (dp->hpd_status) {
		connector->status = connector_status_disconnected;
		return;
	}

	connector->status = connector_status_connected;
}

static const struct drm_connector_funcs hibmc_connector_funcs = {
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = hibmc_vdac_connector_destroy,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
	.force = hibmc_vdac_force,
};

static void hibmc_encoder_mode_set(struct drm_encoder *encoder,
				   struct drm_display_mode *mode,
				   struct drm_display_mode *adj_mode)
{
	u32 reg;
	struct drm_device *dev = encoder->dev;
	struct hibmc_drm_private *priv = to_hibmc_drm_private(dev);

	reg = readl(priv->mmio + HIBMC_DISPLAY_CONTROL_HISILE);
	reg |= HIBMC_DISPLAY_CONTROL_FPVDDEN(1);
	reg |= HIBMC_DISPLAY_CONTROL_PANELDATE(1);
	reg |= HIBMC_DISPLAY_CONTROL_FPEN(1);
	reg |= HIBMC_DISPLAY_CONTROL_VBIASEN(1);
	writel(reg, priv->mmio + HIBMC_DISPLAY_CONTROL_HISILE);
}

static const struct drm_encoder_helper_funcs hibmc_encoder_helper_funcs = {
	.mode_set = hibmc_encoder_mode_set,
};

static const struct drm_encoder_funcs hibmc_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

int hibmc_vdac_init(struct hibmc_drm_private *priv)
{
	struct drm_device *dev = &priv->dev;
	struct hibmc_vdac *vdac = &priv->vdac;
	struct drm_encoder *encoder = &vdac->encoder;
	struct drm_connector *connector = &vdac->connector;
	int ret;

	ret = hibmc_ddc_create(dev, vdac);
	if (ret) {
		drm_err(dev, "failed to create ddc: %d\n", ret);
		return ret;
	}

	encoder->possible_crtcs = 0x1;
	ret = drm_encoder_init(dev, encoder, &hibmc_encoder_funcs,
			       DRM_MODE_ENCODER_DAC, NULL);
	if (ret) {
		drm_err(dev, "failed to init encoder: %d\n", ret);
		goto err;
	}

	drm_encoder_helper_add(encoder, &hibmc_encoder_helper_funcs);

	ret = drm_connector_init_with_ddc(dev, connector,
					  &hibmc_connector_funcs,
					  DRM_MODE_CONNECTOR_VGA,
					  &vdac->adapter);
	if (ret) {
		drm_err(dev, "failed to init connector: %d\n", ret);
		goto err;
	}
	drm_connector_helper_add(connector, &hibmc_connector_helper_funcs);

	drm_connector_attach_encoder(connector, encoder);

	connector->polled = DRM_CONNECTOR_POLL_CONNECT | DRM_CONNECTOR_POLL_DISCONNECT;

	return 0;

err:
	hibmc_ddc_del(vdac);

	return ret;
}
