// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#include <linux/component.h>
#include <linux/media-bus-format.h>
#include <linux/of_platform.h>
#include <linux/delay.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_encoder.h>
#include <drm/drm_of.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_probe_helper.h>

#include "vs_dc.h"
#include "vs_dc_hw.h"
#include "vs_gem.h"
#include "vs_dc_qspi.h"
#include "vs_dc_reg.h"

#ifdef CONFIG_PCI
#include <linux/pci.h>
#endif

static u8 qspi_cmd_wire = DCREG_PANEL0_QSPI_CONFIG1_CMD_STANDARD_SPI;
static u8 qspi_addr_wire = DCREG_PANEL0_QSPI_CONFIG1_ADDR_STANDARD_SPI;
static u8 qspi_para_wire = DCREG_PANEL0_QSPI_CONFIG1_PARA_STANDARD_SPI;

void egt_qspi_set_intf_format(struct dc_hw *hw, struct dc_hw_display_mode *mode)
{
	u8 intf_pixel_format = 0;

	switch (mode->bus_format) {
	case MEDIA_BUS_FMT_RGB888_1X24:
		intf_pixel_format = 0x77;
		break;
	case MEDIA_BUS_FMT_RGB666_1X18:
		intf_pixel_format = 0x76;
		break;
	case MEDIA_BUS_FMT_RGB565_1X16:
		intf_pixel_format = 0x75;
		break;
	default:
		break;
	}

	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG0_Address,
		 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG0, IDLE_SCLK, HIGH) |
			 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG0, SAMPLE_EDGE, EVEN) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG0, TRANS_TYPE, VS_SPI_TYPE) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG0, BAUD_DIV, 0x1));

	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG1_Address,
		 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_EN, true) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_BITS, VS_SPI_CMD_BIT) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_STANDARD, qspi_cmd_wire) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_EN, true) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_STANDARD, qspi_addr_wire) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_BITS, VS_SPI_ADDR_BIT) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_EN, true) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_STANDARD, qspi_para_wire) |
			 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_NUM, BIT8));

	egt_dc_write(hw, DCREG_PANEL0_QSPI_CMD_DATA_Address, 0x02);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x003A00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, intf_pixel_format);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
}

void egt_qspi_start_trigger(struct dc_hw *hw, struct dc_hw_display_mode *mode)
{
	u32 config, config1;

	config = dc_read(hw, DCREG_PANEL0_QSPI_CONFIG0_Address);
	switch (mode->bus_format) {
	case MEDIA_BUS_FMT_RGB888_1X24:
		config = VS_SET_FIELD_PREDEF(config, DCREG_PANEL0_QSPI_CONFIG0, FORMAT, R8G8B8);
		break;
	case MEDIA_BUS_FMT_RGB666_1X18:
		config = VS_SET_FIELD_PREDEF(config, DCREG_PANEL0_QSPI_CONFIG0, FORMAT, R6G6B6);
		break;
	case MEDIA_BUS_FMT_RGB565_1X16:
		config = VS_SET_FIELD_PREDEF(config, DCREG_PANEL0_QSPI_CONFIG0, FORMAT, R5G6B5);
		break;
	};
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG0_Address, config);

	config1 = dc_read(hw, DCREG_PANEL0_QSPI_CONFIG1_Address);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG1_Address,
		 VS_SET_FIELD(config1, DCREG_PANEL0_QSPI_CONFIG1, CMD_EN, true) |
			 VS_SET_FIELD(config1, DCREG_PANEL0_QSPI_CONFIG1, ADDR_EN, true) |
			 VS_SET_FIELD(config1, DCREG_PANEL0_QSPI_CONFIG1, PARA_EN, false) |
			 VS_SET_FIELD_PREDEF(config1, DCREG_PANEL0_QSPI_CONFIG1, PARA_NUM, BIT8));

	egt_dc_write(hw, DCREG_PANEL0_QSPI_CMD_DATA_Address, 0x02);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x002c00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_CONTINUE_DATA_Address, 0x003c00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x0);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_DUMMY_CYCLE_Address, 0x0);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
}

static void qspi_panel_disable(struct dc_hw *hw)
{
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG0_Address,
		 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG0, IDLE_SCLK, HIGH) |
			 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG0, SAMPLE_EDGE, EVEN) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG0, TRANS_TYPE, VS_SPI_TYPE) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG0, BAUD_DIV, 0x1));

	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG1_Address,
		 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_EN, true) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_BITS, VS_SPI_CMD_BIT) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_STANDARD, qspi_cmd_wire) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_EN, true) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_STANDARD, qspi_addr_wire) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_BITS, VS_SPI_ADDR_BIT) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_EN, false) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_STANDARD, qspi_para_wire) |
			 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_NUM, BIT8));

	egt_dc_write(hw, DCREG_PANEL0_QSPI_CMD_DATA_Address, 0x02);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x002800);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
}

static void qspi_panel_enable(struct dc_hw *hw)
{
	u32 temp0 = 0, temp1 = 0, temp2 = 0, temp3 = 0;
	u32 config = 0;
	u32 display_col = 0;
	u32 display_row = 0;

	temp0 = ((VS_SPI_DISPLAY_X + VS_SPI_DISPLAY_W - 1) & 0xFF) << 24;
	temp1 = ((VS_SPI_DISPLAY_X + VS_SPI_DISPLAY_W - 1) & 0x300) << 8;
	temp2 = (VS_SPI_DISPLAY_X & 0xFF) << 8;
	temp3 = (VS_SPI_DISPLAY_X & 0x300) >> 8;
	display_col = temp0 | temp1 | temp2 | temp3;

	temp0 = ((VS_SPI_DISPLAY_Y + VS_SPI_DISPLAY_H - 1) & 0xFF) << 24;
	temp1 = ((VS_SPI_DISPLAY_Y + VS_SPI_DISPLAY_H - 1) & 0x300) << 8;
	temp2 = (VS_SPI_DISPLAY_Y & 0xFF) << 8;
	temp3 = (VS_SPI_DISPLAY_Y & 0x300) >> 8;
	display_row = temp0 | temp1 | temp2 | temp3;

	/* Init */
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG0_Address,
		 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG0, IDLE_SCLK, HIGH) |
			 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG0, SAMPLE_EDGE, EVEN) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG0, TRANS_TYPE, VS_SPI_TYPE) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG0, BAUD_DIV, 0x1));

	/* send cmd to display for resetting SPI */
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG1_Address,
		 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_EN, true) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_BITS, VS_SPI_CMD_BIT) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, CMD_STANDARD, qspi_cmd_wire) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_EN, false) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_STANDARD, qspi_addr_wire) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, ADDR_BITS, VS_SPI_ADDR_BIT) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_EN, false) |
			 VS_SET_FIELD(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_STANDARD, qspi_para_wire) |
			 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0_QSPI_CONFIG1, PARA_NUM, BIT8));

	/* cmd 0xFF is to reset the dual & quadSPI to singel SPI */
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CMD_DATA_Address, 0xFF);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x0);
	/* strat to send */
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);

	config = dc_read(hw, DCREG_PANEL0_QSPI_CONFIG1_Address);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG1_Address,
		 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, CMD_EN, true) |
			 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, ADDR_EN, true) |
			 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, PARA_EN, true) |
			 VS_SET_FIELD_PREDEF(config, DCREG_PANEL0_QSPI_CONFIG1, PARA_NUM, BIT8));

	/* send cmd */
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CMD_DATA_Address, 0x02);

	/* password */
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x00FE00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x20);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x00F400);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x5A);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x00F500);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x59);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x00FE00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x00);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x00C400);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x80);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x00FE00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x20);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x001900);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x10);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x001C00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0xA0);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x00FE00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x00);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x003500);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x00);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x005300);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0x20);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x005100);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0xFF);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x006300);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, 0xFF);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);

	/* para bit32*/
	config = dc_read(hw, DCREG_PANEL0_QSPI_CONFIG1_Address);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG1_Address,
		 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, CMD_EN, true) |
			 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, ADDR_EN, true) |
			 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, PARA_EN, true) |
			 VS_SET_FIELD_PREDEF(config, DCREG_PANEL0_QSPI_CONFIG1, PARA_NUM, BIT32));

	/* show at (VS_SPI_DISPLAY_X,VS_SPI_DISPLAY_Y,VS_SPI_DISPLAY_W,VS_SPI_DISPLAY_H) */
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x002A00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, display_col);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x002B00);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_PARA_DATA_Address, display_row);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);

	/* stop send para */
	config = dc_read(hw, DCREG_PANEL0_QSPI_CONFIG1_Address);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_CONFIG1_Address,
		 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, CMD_EN, true) |
			 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, ADDR_EN, true) |
			 VS_SET_FIELD(config, DCREG_PANEL0_QSPI_CONFIG1, PARA_EN, false) |
			 VS_SET_FIELD_PREDEF(config, DCREG_PANEL0_QSPI_CONFIG1, PARA_NUM, BIT8));

	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x001100);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
	egt_dc_write(hw, DCREG_PANEL0_QSPI_ADDR_START_DATA_Address, 0x002900);
	egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address, 0x2);
	msleep(200);
}

static void qspi_encoder_atomic_disable(struct drm_encoder *encoder, struct drm_atomic_state *state)
{
	struct vs_qspi *qspi = to_qspi_with_encoder(encoder);
	struct vs_dc *dc = dev_get_drvdata(qspi->dev);

	qspi_panel_disable(&dc->hw);
}

static void qspi_encoder_atomic_enable(struct drm_encoder *encoder, struct drm_atomic_state *state)
{
	struct vs_qspi *qspi = to_qspi_with_encoder(encoder);
	struct vs_dc *dc = dev_get_drvdata(qspi->dev);

	qspi_panel_enable(&dc->hw);
}

static int qspi_encoder_atomic_check(struct drm_encoder *encoder, struct drm_crtc_state *crtc_state,
					 struct drm_connector_state *conn_state)
{
	struct vs_crtc_state *vs_crtc_state = to_vs_crtc_state(crtc_state);
	struct drm_connector *connector = conn_state->connector;
	int ret = 0;

	vs_crtc_state->encoder_type = encoder->encoder_type;

	if (connector->display_info.num_bus_formats)
		vs_crtc_state->output_fmt = connector->display_info.bus_formats[0];
	else
		vs_crtc_state->output_fmt = MEDIA_BUS_FMT_RGB888_1X24;

	switch (vs_crtc_state->output_fmt) {
	case MEDIA_BUS_FMT_FIXED:
	case MEDIA_BUS_FMT_RGB565_1X16:
	case MEDIA_BUS_FMT_RGB666_1X18:
	case MEDIA_BUS_FMT_RGB888_1X24:
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	/* If MEDIA_BUS_FMT_FIXED, set it to default value */
	if (vs_crtc_state->output_fmt == MEDIA_BUS_FMT_FIXED)
		vs_crtc_state->output_fmt = MEDIA_BUS_FMT_RGB888_1X24;

	return ret;
}

static int qspi_connector_get_modes(struct drm_connector *connector)
{
	struct drm_device *dev = connector->dev;

	struct drm_display_mode *mode = NULL;
	unsigned int i;
	static const struct display_mode {
		int w, h, refresh;
	} cvt_mode[] = { { 390, 450, 60 } };

	for (i = 0; i < ARRAY_SIZE(cvt_mode); i++) {
		mode = drm_cvt_mode(dev, cvt_mode[i].w, cvt_mode[i].h, cvt_mode[i].refresh, false,
					false, false);

		mode->hdisplay = cvt_mode[i].w;
		mode->vdisplay = cvt_mode[i].h;
		drm_mode_set_name(mode);
		drm_mode_probed_add(connector, mode);
	}

	return 0;
}

static const struct drm_encoder_helper_funcs qspi_encoder_helper_funcs = {
	.atomic_check = qspi_encoder_atomic_check,
	.atomic_enable = qspi_encoder_atomic_enable,
	.atomic_disable = qspi_encoder_atomic_disable,
};

static const struct drm_encoder_funcs qspi_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

static const struct drm_connector_helper_funcs qspi_connector_helper_funcs = {
	.get_modes = qspi_connector_get_modes,
};

static const struct drm_connector_funcs qspi_connector_funcs = {
	.reset = drm_atomic_helper_connector_reset,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = drm_connector_cleanup,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

#ifdef CONFIG_ENGIANT_VS_PCIE
/*pci*/
int vs_egt_qspi_pci_init(struct drm_device *drm_dev)
{
	struct pci_dev *pdev = to_pci_dev(drm_dev->dev);
	struct device *dev = &pdev->dev;
	struct vs_qspi *vs_qspi = NULL;
	struct vs_dc *dc = dev_get_drvdata(dev);
	const struct vs_dc_info *dc_info = dc->hw.info;
	struct drm_connector *connector = NULL;
	int ret;
	u32 i;

	for (i = 0; i < dc->hw.info->display_num; i++) {
		vs_qspi = devm_kzalloc(dev, sizeof(*vs_qspi), GFP_KERNEL);
		if (!vs_qspi)
			return -ENOMEM;

		vs_qspi->bus_format = MEDIA_BUS_FMT_RGB888_1X24;
		vs_qspi->dev = dev;
		dc->qspi[i] = vs_qspi;
	}

	for (i = 0; i < dc_info->display_num; i++) {
		vs_qspi = dc->qspi[i];

		/* Connector */
		connector = &vs_qspi->connector;
		ret = drm_connector_init(drm_dev, connector, &qspi_connector_funcs,
					 DRM_MODE_CONNECTOR_SPI);
		if (ret)
			return ret;

		drm_connector_helper_add(connector, &qspi_connector_helper_funcs);
		connector->interlace_allowed = false;
		connector->doublescan_allowed = false;
		connector->dpms = DRM_MODE_DPMS_OFF;
		connector->polled = DRM_CONNECTOR_POLL_CONNECT | DRM_CONNECTOR_POLL_DISCONNECT;
		ret = drm_connector_register(connector);
		if (ret)
			goto connector_reg_err;

		vs_qspi->encoder.possible_crtcs = drm_crtc_mask(&dc->crtc[i]->base);
		ret = drm_encoder_init(drm_dev, &vs_qspi->encoder, &qspi_encoder_funcs,
					   DRM_MODE_ENCODER_NONE, NULL);
		if (ret)
			return ret;

		drm_encoder_helper_add(&vs_qspi->encoder, &qspi_encoder_helper_funcs);

		drm_display_info_set_bus_formats(&connector->display_info, &vs_qspi->bus_format, 1);

		/* attach */
		ret = drm_connector_attach_encoder(connector, &vs_qspi->encoder);
		if (ret)
			goto attach_err;
	}

	return 0;

attach_err:
	drm_connector_unregister(connector);
	drm_encoder_cleanup(&vs_qspi->encoder);
connector_reg_err:
	drm_connector_cleanup(connector);
	return ret;
}

void vs_egt_qspi_pci_deinit(struct drm_device *drm_dev)
{
	struct pci_dev *pdev = to_pci_dev(drm_dev->dev);
	struct device *dev = &pdev->dev;
	struct vs_dc *dc = dev_get_drvdata(dev);
	const struct vs_dc_info *dc_info = dc->hw.info;
	struct vs_qspi *vs_qspi = NULL;
	u8 i = 0;

	for (i = 0; i < dc_info->display_num; i++) {
		vs_qspi = dc->qspi[i];
		drm_connector_unregister(&vs_qspi->connector);
		drm_connector_cleanup(&vs_qspi->connector);
		drm_encoder_cleanup(&vs_qspi->encoder);
	}
}

#else
/*platform*/
static int vs_qspi_bind(struct device *dev, struct device *master, void *data)
{
	struct drm_device *drm_dev = data;
	struct vs_drm_private *priv = drm_dev->dev_private;
	struct vs_dc *dc = dev_get_drvdata(priv->dc_dev);
	struct drm_connector *connector = NULL;
	int ret;
	u32 i = 0;
	u32 port_count = 0;
	struct device_node *parent_node, *remote_port;
	struct vs_qspi *vs_qspi = NULL;

	parent_node = of_find_node_by_name(dev->of_node, "ports");
	if (!parent_node) {
		pr_err("failed to find ports in qspi.\n");
		return -ENODEV;
	}

	port_count = of_get_child_count(parent_node);

	for (i = 0; i < port_count && i < DC_DISPLAY_NUM; i++) {
		/* get the remote encoder */
		remote_port = of_graph_get_remote_node(dev->of_node, i, 0);
		if (!remote_port) {
			of_node_put(parent_node);
			ret = -EINVAL;
			return ret;
		}

		vs_qspi = devm_kzalloc(dev, sizeof(*vs_qspi), GFP_KERNEL);
		if (!vs_qspi)
			return -ENOMEM;

		vs_qspi->bus_format = MEDIA_BUS_FMT_RBG888_1X24;
		vs_qspi->dev = priv->dc_dev;
		dc->qspi[i] = vs_qspi;

		/* Connector */
		connector = &vs_qspi->connector;
		ret = drm_connector_init(drm_dev, connector, &qspi_connector_funcs,
					 DRM_MODE_CONNECTOR_SPI);
		if (ret)
			return ret;

		drm_connector_helper_add(connector, &qspi_connector_helper_funcs);
		connector->interlace_allowed = false;
		connector->doublescan_allowed = false;
		connector->dpms = DRM_MODE_DPMS_OFF;
		connector->polled = DRM_CONNECTOR_POLL_CONNECT | DRM_CONNECTOR_POLL_DISCONNECT;
		ret = drm_connector_register(connector);
		if (ret)
			goto connector_reg_err;

		vs_qspi->encoder.possible_crtcs = drm_crtc_mask(&dc->crtc[i]->base);
		ret = drm_encoder_init(drm_dev, &vs_qspi->encoder, &qspi_encoder_funcs,
					   DRM_MODE_ENCODER_NONE, NULL);
		if (ret)
			return ret;

		drm_encoder_helper_add(&vs_qspi->encoder, &qspi_encoder_helper_funcs);

		drm_display_info_set_bus_formats(&connector->display_info, &vs_qspi->bus_format, 1);

		/* attach */
		ret = drm_connector_attach_encoder(connector, &vs_qspi->encoder);
		if (ret)
			goto attach_err;
	}

	dev_set_drvdata(dev, dc->qspi);

	return 0;

attach_err:
	drm_connector_unregister(connector);
	drm_encoder_cleanup(&vs_qspi->encoder);
connector_reg_err:
	drm_connector_cleanup(connector);
	return ret;
}

static void vs_qspi_unbind(struct device *dev, struct device *master, void *data)
{
	struct drm_device *drm_dev = data;
	struct vs_drm_private *priv = drm_dev->dev_private;
	struct vs_dc *dc = dev_get_drvdata(priv->dc_dev);
	struct device_node *parent_node = NULL;
	u32 port_count = 0, i = 0;

	parent_node = of_find_node_by_name(dev->of_node, "ports");
	port_count = of_get_child_count(parent_node);

	for (i = 0; i < port_count && i < DC_DISPLAY_NUM; i++) {
		drm_connector_unregister(&dc->qspi[i]->connector);
		drm_connector_cleanup(&dc->qspi[i]->connector);
		drm_encoder_cleanup(&dc->qspi[i]->encoder);
	}
}

const struct component_ops vs_egt_qspi_component_ops = {
	.bind = vs_qspi_bind,
	.unbind = vs_qspi_unbind,
};

static int vs_qspi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	return component_add(dev, &vs_egt_qspi_component_ops);
}

static int vs_qspi_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	component_del(dev, &vs_egt_qspi_component_ops);

	dev_set_drvdata(dev, NULL);

	return 0;
}

struct platform_driver vs_egt_qspi_platform_driver = {
	.probe = vs_qspi_probe,
	.remove = vs_qspi_remove,
	.driver = {
		.name = "vs-qspi",
	},
};

#endif
MODULE_DESCRIPTION("VeriSilicon Qspi Controller Driver");
MODULE_LICENSE("GPL");
