// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include <drm/drm_of.h>
#include <drm/drm_edid.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_connector.h>
#include <drm/drm_bridge_connector.h>

#include "lsdc_drv.h"
#include "lsdc_i2c.h"
#include "lsdc_output.h"
#include "lsdc_regs.h"

static int lsdc_get_modes(struct drm_connector *connector)
{
	unsigned int num = 0;
	struct i2c_adapter *ddc = connector->ddc;

	if (ddc) {
		struct edid *edid;

		edid = drm_get_edid(connector, ddc);
		if (edid) {
			drm_connector_update_edid_property(connector, edid);
			num = drm_add_edid_modes(connector, edid);
			kfree(edid);
		}

		return num;
	}

	drm_dbg(connector->dev, "Failed to get mode from ddc\n");

	num = drm_add_modes_noedid(connector, 1920, 1200);

	drm_set_preferred_mode(connector, 1024, 768);

	return num;
}

static enum drm_connector_status
ls7a1000_connector_detect(struct drm_connector *connector, bool force)
{
	struct i2c_adapter *ddc = connector->ddc;

	if (ddc) {
		if (drm_probe_ddc(ddc))
			return connector_status_connected;
		else
			return connector_status_disconnected;
	}

	return connector_status_unknown;
}

static enum drm_connector_status
ls7a2000_connector_detect(struct drm_connector *connector, bool force)
{
	struct lsdc_display_pipe *dispipe = connector_to_display_pipe(connector);
	struct drm_device *ddev = connector->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	u32 val;

	val = lsdc_rreg32(ldev, LSDC_HDMI_HPD_STATUS_REG);

	if (dispipe->index == 0) {
		if (val & HDMI0_HPD_FLAG)
			return connector_status_connected;

		if (connector->ddc) {
			if (drm_probe_ddc(connector->ddc))
				return connector_status_connected;

			return connector_status_disconnected;
		}
	} else if (dispipe->index == 1) {
		if (val & HDMI1_HPD_FLAG)
			return connector_status_connected;

		return connector_status_disconnected;
	}

	return connector_status_unknown;
}

static void lsdc_connector_destroy(struct drm_connector *connector)
{
	drm_connector_cleanup(connector);
}

static const struct drm_connector_helper_funcs lsdc_connector_helpers = {
	.get_modes = lsdc_get_modes,
};

static const struct drm_connector_funcs ls7a1000_connector_funcs = {
	.dpms = drm_helper_connector_dpms,
	.detect = ls7a1000_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = lsdc_connector_destroy,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static const struct drm_connector_funcs ls7a2000_connector_funcs = {
	.dpms = drm_helper_connector_dpms,
	.detect = ls7a2000_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = lsdc_connector_destroy,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static enum drm_mode_status
ls7a2000_hdmi_encoder_mode_valid(struct drm_encoder *crtc,
				  const struct drm_display_mode *mode)
{
	return MODE_OK;
}

static void ls7a2000_hdmi_encoder_disable(struct drm_encoder *encoder)
{
	int index = encoder->index;
	struct lsdc_device *ldev = to_lsdc(encoder->dev);

	if (index == 0) {
		/* Enable hdmi */
		writel(0, ldev->reg_base + HDMI0_CTRL_REG);

	} else if (index == 1) {
		/* Enable hdmi */
		writel(0, ldev->reg_base + HDMI1_CTRL_REG);
	}

	drm_dbg(encoder->dev, "HDMI%d disable\n", index);
}

static void ls7a2000_hdmi_encoder_enable(struct drm_encoder *encoder)
{
	int index = encoder->index;
	struct lsdc_device *ldev = to_lsdc(encoder->dev);

	if (index == 0) {
		/* Enable hdmi */
		writel(0x280 | HDMI_EN | HDMI_PACKET_EN, ldev->reg_base + HDMI0_CTRL_REG);

		/* hdmi zone idle */
		writel(0x00400040, ldev->reg_base + HDMI0_ZONE_REG);
	} else if (index == 1) {
		/* Enable hdmi */
		writel(0x280 | HDMI_EN | HDMI_PACKET_EN, ldev->reg_base + HDMI1_CTRL_REG);

		/* hdmi zone idle */
		writel(0x00400040, ldev->reg_base + HDMI1_ZONE_REG);
	}

	drm_dbg(encoder->dev, "HDMI%d enable\n", index);
}

static void
ls7a2000_hdmi_encoder_mode_set(struct drm_encoder *encoder,
			       struct drm_display_mode *mode,
			       struct drm_display_mode *adjusted_mode)
{
	int index = encoder->index;
	struct drm_device *ddev = encoder->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	int clock = mode->clock;
	int counter = 0;
	u32 val;

	if (index == 0) {
		writel(0x0, ldev->reg_base + HDMI0_PLL_REG);
		writel(0x0, ldev->reg_base + HDMI0_PHY_CTRL_REG);
	} else {
		writel(0x0, ldev->reg_base + HDMI1_PLL_REG);
		writel(0x0, ldev->reg_base + HDMI1_PHY_CTRL_REG);
	}

	if (clock >= 170000)
		val = (0x0 << 13) | (0x28 << 6) | (0x10 << 1) | HDMI_PLL_EN;
	else if (clock >= 85000 && clock < 170000)
		val = (0x1 << 13) | (0x28 << 6) | (0x8 << 1) | HDMI_PLL_EN;
	else if (clock >= 42500 && clock < 85000)
		val = (0x2 << 13) | (0x28 << 6) | (0x4 << 1) | HDMI_PLL_EN;
	else if (clock >= 21250 && clock < 42500)
		val = (0x3 << 13) | (0x28 << 6) | (0x2 << 1) | HDMI_PLL_EN;

	if (index == 0) {
		writel(val, ldev->reg_base + HDMI0_PLL_REG);
	} else {
		writel(val, ldev->reg_base + HDMI1_PLL_REG);
	}

	do {
		/* wait pll lock */
		if (index == 0)
			val = readl(ldev->reg_base + HDMI0_PLL_REG);
		else if (index == 1)
			val = readl(ldev->reg_base + HDMI1_PLL_REG);

		++counter;
	} while (((val & HDMI_PLL_LOCKED) == 0) && (counter < 1000));

	drm_dbg(ddev, "HDMI%d modeset, PLL: %u loop waited\n", index, counter);

	if (index == 0) {
		writel(0x0f03, ldev->reg_base + HDMI0_PHY_CTRL_REG);
	} else if (index == 1) {
		writel(0x0f03, ldev->reg_base + HDMI1_PHY_CTRL_REG);
	}
}

static const struct drm_encoder_helper_funcs ls7a2000_hdmi_encoder_helper_funcs = {
	.mode_valid = ls7a2000_hdmi_encoder_mode_valid,
	.disable = ls7a2000_hdmi_encoder_disable,
	.enable = ls7a2000_hdmi_encoder_enable,
	.mode_set = ls7a2000_hdmi_encoder_mode_set,
};

static void lsdc_encoder_reset(struct drm_encoder *encoder)
{
	struct lsdc_device *ldev = to_lsdc(encoder->dev);

	if (ldev->desc->chip == LSDC_CHIP_7A2000)
		ls7a2000_hdmi_encoder_enable(encoder);
}

static const struct drm_encoder_funcs lsdc_encoder_funcs = {
	.reset = lsdc_encoder_reset,
	.destroy = drm_encoder_cleanup,
};

static int lsdc_attach_bridges(struct lsdc_device *ldev,
			       struct device_node *ports,
			       unsigned int i)
{
	struct lsdc_display_pipe * const dispipe = &ldev->dispipe[i];
	struct drm_device *ddev = &ldev->ddev;
	struct drm_bridge *bridge;
	struct drm_panel *panel;
	struct drm_connector *connector;
	struct drm_encoder *encoder;
	int ret;

	ret = drm_of_find_panel_or_bridge(ports, i, 0, &panel, &bridge);

	if (panel) {
		bridge = devm_drm_panel_bridge_add_typed(ddev->dev, panel, DRM_MODE_CONNECTOR_DPI);
		drm_info(ddev, "output-%u is a DPI panel\n", i);
	}

	if (!bridge)
		return ret;

	encoder = &dispipe->encoder;

	ret = drm_encoder_init(ddev, encoder, &lsdc_encoder_funcs,
			       DRM_MODE_ENCODER_DPI, "encoder-%u", i);

	if (ret) {
		drm_err(ddev, "Failed to init encoder: %d\n", ret);
		return ret;
	}

	encoder->possible_crtcs = BIT(i);

	ret = drm_bridge_attach(encoder, bridge, NULL, DRM_BRIDGE_ATTACH_NO_CONNECTOR);
	if (ret) {
		drm_err(ddev,
			"failed to attach bridge %pOF for output %u (%d)\n",
			bridge->of_node, i, ret);
		return ret;
	}

	connector = drm_bridge_connector_init(ddev, encoder);
	if (IS_ERR(connector)) {
		drm_err(ddev, "Unable to init connector\n");
		return PTR_ERR(connector);
	}

	drm_connector_attach_encoder(connector, encoder);

	drm_info(ddev, "bridge-%u attached to %s\n", i, encoder->name);

	return 0;
}

int lsdc_attach_output(struct lsdc_device *ldev, uint32_t num_crtc)
{
	struct drm_device *ddev = &ldev->ddev;
	struct device_node *ports;
	struct lsdc_display_pipe *disp;
	unsigned int i;
	int ret;

	ldev->num_output = 0;

	ports = of_get_child_by_name(ddev->dev->of_node, "ports");

	for (i = 0; i < num_crtc; i++) {
		struct drm_bridge *b;
		struct drm_panel *p;

		disp = &ldev->dispipe[i];
		disp->available = false;

		ret = drm_of_find_panel_or_bridge(ports, i, 0, &p, &b);
		if (ret) {
			if (ret == -ENODEV) {
				drm_dbg(ddev, "No active panel or bridge for port%u\n", i);
				disp->available = false;
				continue;
			}

			if (ret == -EPROBE_DEFER)
				drm_dbg(ddev, "Bridge for port%d is defer probed\n", i);

			goto RET;
		}

		disp->available = true;
		ldev->num_output++;
	}

	if (ldev->num_output == 0) {
		drm_err(ddev, "No valid output, abort\n");
		ret = -ENODEV;
		goto RET;
	}

	for (i = 0; i < num_crtc; i++) {
		disp = &ldev->dispipe[i];
		if (disp->available) {
			ret = lsdc_attach_bridges(ldev, ports, i);
			if (ret)
				goto RET;
		} else {
			drm_info(ddev, "output-%u is not available\n", i);
		}
	}

	drm_info(ddev, "number of outputs: %u\n", ldev->num_output);
RET:
	of_node_put(ports);
	return ret;
}

/* No DT support, provide a minimal support */
int lsdc_create_output(struct lsdc_device *ldev,
		       unsigned int index,
		       unsigned int num_crtc)
{
	const struct lsdc_chip_desc * const descp = ldev->desc;
	struct lsdc_display_pipe * const dispipe = &ldev->dispipe[index];
	struct drm_encoder *encoder = &dispipe->encoder;
	struct drm_connector *connector = &dispipe->connector;
	struct drm_device *ddev = &ldev->ddev;
	int encoder_type = DRM_MODE_ENCODER_DPI;
	int connector_type = DRM_MODE_CONNECTOR_DPI;
	int ret;

	if (descp->has_builtin_i2c) {
		dispipe->li2c = lsdc_create_i2c_chan(ddev, ldev->reg_base, index);
		if (IS_ERR(dispipe->li2c)) {
			drm_err(ddev, "Failed to create i2c adapter\n");
			return PTR_ERR(dispipe->li2c);
		}
	} else {
		drm_warn(ddev, "output-%u don't has ddc\n", index);
		dispipe->li2c = NULL;
	}

	if (descp->chip == LSDC_CHIP_7A2000) {
		encoder_type = DRM_MODE_ENCODER_TMDS;
		connector_type = DRM_MODE_CONNECTOR_HDMIA;
	}

	ret = drm_encoder_init(ddev, encoder, &lsdc_encoder_funcs,
			       encoder_type, "encoder-%u", index);

	if (ret) {
		drm_err(ddev, "Failed to init encoder: %d\n", ret);
		return ret;
	}

	encoder->possible_crtcs = BIT(index);

	if (descp->chip == LSDC_CHIP_7A2000)
		drm_encoder_helper_add(encoder, &ls7a2000_hdmi_encoder_helper_funcs);

	if (descp->chip == LSDC_CHIP_7A2000) {
		ret = drm_connector_init_with_ddc(ddev,
						  connector,
						  &ls7a2000_connector_funcs,
						  connector_type,
						  &dispipe->li2c->adapter);
		if (ret) {
			drm_err(ddev, "Init connector%d failed\n", index);
			return ret;
		}
	} else {
		ret = drm_connector_init_with_ddc(ddev,
						  connector,
						  &ls7a1000_connector_funcs,
						  connector_type,
						  &dispipe->li2c->adapter);
		if (ret) {
			drm_err(ddev, "Init connector%d failed\n", index);
			return ret;
		}
	}

	drm_connector_helper_add(connector, &lsdc_connector_helpers);

	connector->polled = DRM_CONNECTOR_POLL_CONNECT | DRM_CONNECTOR_POLL_DISCONNECT;

	drm_connector_attach_encoder(connector, encoder);

	dispipe->available = true;

	ldev->num_output++;

	return 0;
}
