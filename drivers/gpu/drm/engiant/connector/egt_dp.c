// SPDX-License-Identifier: GPL-2.0
/*
 * DisplayPort DRM support functions
 *
 * Copyright (c) 2019-2026, New H3C Semiconductor Technologies Co., Ltd.
 */

#include <drm/drm_edid.h>
#include <drm/drm_probe_helper.h>
#include <linux/pci.h>
#include <linux/ktime.h>
#include "vs_dc.h"
#include "vs_gem.h"
#include "egt_dp_phy.h"
#include "egt_dp.h"

void egt_dp_write(u32 value, u32 reg, struct egt_displayport *dp)
{
	writel(value, dp->mem_base.dp_base + reg);
}

u32 egt_dp_read(u32 reg, struct egt_displayport *dp)
{
	u32 value = readl(dp->mem_base.dp_base + reg);

	return value;
}

void egt_dp_set_hpd_irq(struct egt_displayport *dp, bool enable)
{
	int val = 0;

	val = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	if (!enable)
		val &= ~(BIT(31));
	else
		val |= BIT(31);

	egt_dp_write(val, DP_SOURCE_TX_CONTROL, dp);
}

u32 egt_dp_msg_send_enable(struct egt_displayport *dp, u32 *data)
{
	int ret = 0;

#ifdef CONFIG_X86
	int i = 0;
	u8 *val1 = (u8 *)data;
	u8 val = 0;

	for (i = 0; i < 12; i++)
		outb(val1[i], dp->mem_base.mbox_iobase + i);

	val = inb(dp->mem_base.mbox_iobase + EGT_SIOMBOX_CTRL);
	val |= 0x1;
	outb(val, dp->mem_base.mbox_iobase + EGT_SIOMBOX_CTRL);
#else
	pr_err("Unsupported architecture: only x86 is supported\n");
#endif

	return ret;
}

void egt_dp_msg_send(struct egt_displayport *dp, u32 type)
{
	struct drm_connector *connector = &dp->connector;
	struct drm_display_mode *mode = NULL;
	u32 mbox_data[4] = { 0 };

	pr_debug("msg type = %d\n", type);

	mbox_data[0] = type;
	switch (type) {
	case EGT_DC_TIMING_UPDATE:
		if (connector->state && connector->state->crtc) {
			mode = &connector->state->crtc->state->adjusted_mode;
			pr_debug("timing is  %d x %d\n", mode->hdisplay, mode->vdisplay);

			mbox_data[1] = (mode->hdisplay << 16) | mode->vdisplay;
			mbox_data[2] = (((mode->flags & DRM_MODE_FLAG_PHSYNC) ? 1:0) << 16) |
						((mode->flags & DRM_MODE_FLAG_PVSYNC) ? 1:0);
		} else {
			mbox_data[1] = (EGT_DP_MIN_WIDTH << 16) | EGT_DP_MIN_HEIGHT;
			mbox_data[2] = (1 << 16) | 0x1;
		}
		break;
	case EGT_DC_TIMING_STOP:
		fallthrough;
	case EGT_DC_RESET_DONE:
		pr_debug("send stop\n");
		break;
	default:
		pr_err("invalid msg\n");
		break;
	}

	egt_dp_msg_send_enable(dp, mbox_data);
}

void egt_dp_send_stop_vdp(struct drm_device *drm_dev)
{
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;
	struct vs_dc *dc = NULL;
	struct egt_displayport *dp = NULL;
	u32 mbox_data[4] = { 0 };

	if (!drm_dev) {
		pr_err("drm_dev is NULL\n");
		return;
	}

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;
	dc = dev_get_drvdata(dev);
	dp = dc->dp;

	mbox_data[0] = EGT_DC_TIMING_STOP;
	egt_dp_msg_send_enable(dp, mbox_data);
}

void egt_dp_ticks_wait_us(unsigned int delay_us, struct egt_displayport *dp)
{
	unsigned int to = delay_us / 100 * EGT_TX_100US_TICKS;
	unsigned int tstart = 0;
	unsigned int tnow = 0;
	unsigned int max_timeout_us = 100000;
	unsigned int timeout_us = (delay_us > max_timeout_us / 10) ? max_timeout_us : delay_us * 10;
	s64 elapsed_us = 0;
	ktime_t start_time = 0;

	if (delay_us == 0)
		return;

	tstart = egt_dp_read(DP_SOURCE_TIMESTAMP, dp);
	start_time = ktime_get();

	for (tnow = tstart; ((tnow - tstart) & 0xFFFFFF) < to;
		 tnow = egt_dp_read(DP_SOURCE_TIMESTAMP, dp)) {
		elapsed_us = ktime_to_us(ktime_sub(ktime_get(), start_time));
		if (elapsed_us > timeout_us) {
			pr_warn("wait_us: delay=%u us, elapsed=%lld us\n", delay_us,
					(long long)elapsed_us);
			break;
		}
		usleep_range(3, 4);
	}
}

void egt_dp_set_bits_per_pixel(struct egt_displayport *dp, u32 drm_fourcc)
{
	struct egt_displayport_config *config = &dp->tx_cfg;

	if ((drm_fourcc == DRM_FORMAT_XBGR8888) || (drm_fourcc == DRM_FORMAT_XRGB8888) ||
		(drm_fourcc == DRM_FORMAT_BGR888) || (drm_fourcc == DRM_FORMAT_RGB888) ||
		(drm_fourcc == DRM_FORMAT_XBGR2101010)) {
		config->num_colors = 3;
		config->fmt = 0x0;
	} else {
		dev_dbg(dp->dev, "unknown fourcc format :%d\n", drm_fourcc);
	}

	dp->tx_cfg.bpp = dp->tx_cfg.bpc * dp->tx_cfg.num_colors;
}

void egt_dp_source_video_state(struct drm_device *drm_dev, int state)
{
	struct egt_displayport *dp = NULL;
	struct vs_dc *dc = NULL;
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;
	u32 val = 0;

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;
	dc = dev_get_drvdata(dev);
	dp = dc->dp;

	val = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	val &= ~EGT_TX_TP_MASK;
	if (state != DRM_MODE_DPMS_ON)
		egt_dp_write((val | 0x04), DP_SOURCE_TX_CONTROL, dp);
	else
		egt_dp_write((val | 0x0), DP_SOURCE_TX_CONTROL, dp);

}

struct drm_encoder *egt_dp_best_encoder(struct drm_connector *connector)
{
	struct egt_displayport *dp = container_of(connector, struct egt_displayport, connector);

	return &dp->encoder;
}

int egt_dp_get_modes(struct drm_connector *connector)
{
	int edid_cnt = 0;
	int i = 0;
	struct drm_device *dev = connector->dev;
	struct egt_displayport *dp = container_of(connector, struct egt_displayport, connector);
	struct edid *edid = NULL;
	struct drm_display_mode *mode = NULL;
	struct drm_display_mode egt_noedid_modes[] = {
		{ DRM_MODE("1024x768", DRM_MODE_TYPE_DRIVER, 65000, 1024, 1048,
					1184, 1344, 0, 768, 771, 777, 806, 0,
					(0x1 << 0x1) | (0x1 << 3)), },/* 1024x768@60 */
	};

	if (dp->connected) {
		pr_debug("get edid from sink.\n");
		edid = drm_get_edid(connector, &dp->aux.ddc);

		if (edid) {
			drm_connector_update_edid_property(connector, edid);
			edid_cnt = drm_add_edid_modes(connector, edid);
			dp->edid_present = true;
			kfree(edid);
		}
	} else {
		dev->mode_config.max_width = EGT_DP_MAX_WIDTH;
		dev->mode_config.max_height = EGT_DP_MAX_HEIGHT;
		pr_debug("noedid mode\n");

		edid_cnt = drm_add_modes_noedid(connector, 800, 600);
		for (i = 0; i < ARRAY_SIZE(egt_noedid_modes); i++) {
			if (egt_noedid_modes[i].hdisplay > EGT_DP_MAX_WIDTH ||
				egt_noedid_modes[i].vdisplay > EGT_DP_MAX_HEIGHT) {
				continue;
			}

			mode = drm_mode_duplicate(connector->dev, &egt_noedid_modes[i]);
			if (mode) {
				pr_debug("egt_noedid_modes\n");
				drm_mode_probed_add(connector, mode);
				edid_cnt++;
			}
		}
	}

	pr_debug("edid_cnt = %d\n", edid_cnt);

	if (edid_cnt > 0) {
		drm_mode_sort(&connector->probed_modes);
		drm_set_preferred_mode(connector, 1024, 768);

	} else {
		pr_warn("no modes found! check DP connection\n");
	}

	return edid_cnt;
}

int egt_dp_mode_valid(__maybe_unused struct drm_connector *connector,
					  struct drm_display_mode *mode)
{
	int i = 0;
	struct egt_dp_supported_mode supported_modes[] = {
		{640, 480},
		{800, 600},
		{1024, 768},
		{1280, 1024},
		{1280, 720},
		{1280, 800},
		{1440, 900},
		{1600, 900},
		{1680, 1050},
		{1920, 1080},
		{1920, 1200},
	};

	for (i = 0; i < ARRAY_SIZE(supported_modes); i++) {
		if (mode->hdisplay == supported_modes[i].width &&
			mode->vdisplay == supported_modes[i].height) {
			pr_debug("valid mode: [%dx%d], clock: %d\n",
					 mode->hdisplay, mode->vdisplay, mode->clock);
			return MODE_OK;
		}
	}

	return MODE_NOMODE;
}

enum drm_connector_status
egt_dp_connected_detect(__maybe_unused struct drm_connector *connector, __maybe_unused bool force)
{
	return connector_status_connected;
}

void egt_dp_destroy(struct drm_connector *connector)
{
	drm_connector_unregister(connector);
	drm_connector_cleanup(connector);
}

int egt_dp_atomic_set_property(struct drm_connector *connector,
					  __maybe_unused struct drm_connector_state *state,
					  struct drm_property *prop,
					  uint64_t val)
{
	struct egt_displayport *dp = container_of(connector, struct egt_displayport, connector);
	unsigned int target_bpc = val;

	if (prop == dp->prop.sync_property) {
		if (val)
			dp->tx_cfg.misc0 |= 0x1;
		else
			dp->tx_cfg.misc0 &= ~0x1;
	} else if (prop == dp->prop.bpc_property) {
		if (dp->connector.display_info.bpc > 0 && dp->connector.display_info.bpc != val) {
			dev_dbg(dp->dev, "requested bpc %llu overridden by EDID value: %u\n",
					(unsigned long long)val, dp->connector.display_info.bpc);
			target_bpc = dp->connector.display_info.bpc;
		}
		dp->tx_cfg.bpc = target_bpc;
		dp->tx_cfg.bpp = dp->tx_cfg.bpc * dp->tx_cfg.num_colors;
		if (target_bpc) {
			drm_object_property_set_value(&connector->base, prop, target_bpc);
			return 0;
		}
	} else if (prop == dp->prop.rate_property) {
		pr_debug("set rate\n");
	} else if (prop == dp->prop.lanes_property) {
		pr_debug("set lanes\n");
	} else {
		pr_err("undefined property\n");
		return -EINVAL;
	}

	return 0;
}

int egt_dp_atomic_get_property(struct drm_connector *connector,
					__maybe_unused const struct drm_connector_state *state,
					struct drm_property *prop,
					uint64_t *val)
{
	struct egt_displayport *dp = container_of(connector, struct egt_displayport, connector);

	if (prop == dp->prop.sync_property)
		*val = (dp->tx_cfg.misc0 & 0x1);
	else if (prop == dp->prop.bpc_property)
		*val = dp->tx_cfg.bpc;
	else if (prop == dp->prop.rate_property)
		*val = dp->max_link_rate;
	else if (prop == dp->prop.lanes_property)
		*val = dp->max_lanes;
	else {
		pr_err("get unknown property\n");
		return -EINVAL;
	}

	return 0;
}

void egt_dp_dis_encoder(struct drm_encoder *encoder)
{
	struct egt_displayport *dp = container_of(encoder, struct egt_displayport, encoder);

	if (WARN_ON(!dp->enabled))
		return;

	dp->enabled = false;

	egt_dp_write(EGT_TX_PM_DISABLE, DP_SOURCE_PWR_MNG, dp);
}

static void egt_dp_update_msa(struct egt_displayport *dp, struct vs_crtc_state *crtc_state)
{
	u32 bpc = 0;
	u32 val = 0;
	u32 value = 0;
	u32 fmt = 0;
	u32 i = 0;
	struct egt_dp_msa_mode msa_mode[] = {
		{MEDIA_BUS_FMT_RGB666_1X18,		0x0,	0x0},
		{MEDIA_BUS_FMT_RGB888_1X24,		0x1,	0x0},
		{MEDIA_BUS_FMT_RGB101010_1X30,	0x2,	0x0},
		{MEDIA_BUS_FMT_YUV8_1X24,		0x1,	0x1},
		{MEDIA_BUS_FMT_YUV10_1X30,		0x2,	0x1},
		{MEDIA_BUS_FMT_UYVY8_1X16,		0x1,	0x2},
		{MEDIA_BUS_FMT_UYVY10_1X20,		0x2,	0x2},
	};

	for (i = 0; i < ARRAY_SIZE(msa_mode); i++) {
		if (msa_mode[i].out_fmt == crtc_state->output_fmt) {
			bpc = msa_mode[i].bpc;
			fmt = msa_mode[i].fmt;
		}
	}

	val = egt_dp_read(DP_SOURCE_MSA_COLOUR, dp);
	value = bpc | (fmt << 4);
	egt_dp_write(((val & (~0xff))) | value, DP_SOURCE_MSA_COLOUR, dp);
}

void egt_dp_en_encoder(struct drm_encoder *encoder)
{
	struct egt_displayport *dp = container_of(encoder, struct egt_displayport, encoder);
	struct drm_crtc *crtc = encoder->crtc;
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(crtc->state);

	if (!dp->enabled) {
		dp->enabled = true;
		egt_dp_write(0x2, DP_SOURCE_PWR_MNG, dp);
	}

	egt_dp_update_msa(dp, crtc_state);
}

void egt_dp_atomic_mode_set(struct drm_encoder *encoder,
				struct drm_crtc_state *crtc_state,
				__maybe_unused struct drm_connector_state *connector_state)
{
	struct egt_displayport *dp = container_of(encoder, struct egt_displayport, encoder);
	struct drm_display_mode *mode = NULL;
	struct drm_plane *plane = NULL;
	const struct drm_format_info *format = NULL;
	int max_rate = dp->train_cfg.max_rate;
	u32 drm_fourcc = 0;
	u8 max_lanes = dp->train_cfg.max_lanes;
	u8 bpp = dp->tx_cfg.bpp;
	u8 bw_code = EGT_TX_LINK_BW_2_7;

	if (!crtc_state || !crtc_state->crtc) {
		dev_err(dp->dev, "error crtc_state\n");
		return;
	}

	mode = &crtc_state->mode;

	pr_debug("mode - [%d x %d], clock = %d, max_rate = %d\n",
			 mode->hdisplay, mode->vdisplay, mode->clock, max_rate);

	switch (max_rate) {
	case 162000:
		bw_code = EGT_TX_LINK_BW_1_62;
		break;
	case 270000:
		bw_code = EGT_TX_LINK_BW_2_7;
		break;
	case 540000:
		bw_code = EGT_TX_LINK_BW_5_4;
		break;
	default:
		break;
	}

	/* Set pixel pll and phy */
	egt_dp_pixel_pll_calculate(dp, mode->clock);
	egt_dp_set_phy(dp, bw_code);

	/* Get current plane format info */
	drm_for_each_plane_mask(plane, crtc_state->crtc->dev, crtc_state->plane_mask) {
		if (plane->state && plane->state->fb) {
			dev_dbg(dp->dev, "plane[%d] format:%p\n",
					 drm_plane_index(plane), plane->state->fb->format);
			format = plane->state->fb->format;
		}
	}
	if (!format) {
		dev_err(dp->dev, "get format failed\n");
		return;
	}

	drm_fourcc = format->format;

	egt_dp_set_bits_per_pixel(dp, drm_fourcc);

	pr_debug("pixel-clock is %d, link-rate is %d, timing is [%d x %d]\n",
			 mode->clock, max_rate * max_lanes * 8 / bpp,
			 mode->hdisplay, mode->vdisplay);

	egt_dp_msg_send(dp, EGT_DC_TIMING_UPDATE);

}

int egt_dp_atomic_check(struct drm_encoder *encoder, struct drm_crtc_state *crtc_state,
				struct drm_connector_state *conn_state)
{
	struct vs_crtc_state *state = to_vs_crtc_state(crtc_state);
	struct drm_connector *connector = conn_state->connector;
	int ret = 0;

	if (!state)
		return -EIO;

	state->encoder_type = encoder->encoder_type;
	state->output_id = 0;
	state->output_mode = 0;

	if (connector->display_info.num_bus_formats)
		state->output_fmt = connector->display_info.bus_formats[0];
	else
		state->output_fmt = MEDIA_BUS_FMT_RGB888_1X24;

	if (state->output_fmt == MEDIA_BUS_FMT_RGB666_1X18 ||
		state->output_fmt == MEDIA_BUS_FMT_RGB888_1X24 ||
		state->output_fmt == MEDIA_BUS_FMT_RGB666_1X24_CPADHI ||
		state->output_fmt == MEDIA_BUS_FMT_RGB101010_1X30 ||
		state->output_fmt == MEDIA_BUS_FMT_YUV8_1X24 ||
		state->output_fmt == MEDIA_BUS_FMT_YUV10_1X30 ||
		state->output_fmt == MEDIA_BUS_FMT_UYVY8_1X16 ||
		state->output_fmt == MEDIA_BUS_FMT_UYVY10_1X20) {
	} else {
		pr_err("invalid state->output_fmt\n");
		ret = -EINVAL;
	}

	if (state->output_fmt == MEDIA_BUS_FMT_FIXED) {
		pr_debug("default state->output_fmt\n");
		state->output_fmt = MEDIA_BUS_FMT_RGB888_1X24;
	}

	return ret;
}

MODULE_DESCRIPTION("Engiant DP Driver");
MODULE_LICENSE("GPL");
