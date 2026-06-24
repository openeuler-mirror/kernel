/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_QSPI_H_
#define __VS_DC_QSPI_H_

#include <linux/debugfs.h>

/* SPI TYPE DEFINE:
 * 0: 3-wire SPI/Dual-SPI disabled.
 * 1: 4-wire SPI/Dual-SPI disabled.
 * 2: 3-wire SPI.1 wire of data.Dual-SPI enabled.
 * 3: 3-wire SPI.2 wires of data.Dual-SPI enabled.1 pixel/transfer.
 * 4: 3-wire SPI.2 wires of data.Dual-SPI enabled.2 pixels/3 transfers.
 * 5: 4-wire SPI.1 wire of data.Dual-SPI enabled.
 * 6: 4-wire SPI.2 wires of data.Dual-SPI enabled.1 pixel/transfer.
 * 7: 4-wire SPI.2 wires of data.Dual-SPI enabled.2 pixels/3 transfers.
 * 8: Quad-SPI.
 * 9: 3-wire SPI.2 wires of data.
 * 10: 4-wire SPI.2 wires of data.
 */
#define VS_SPI_TYPE 8
#define VS_SPI_CMD_TRANS_WIRE 1
#define VS_SPI_CMD_BIT 7
#define VS_SPI_ADDR_TRANS_WIRE 1
#define VS_SPI_ADDR_BIT 23
#define VS_SPI_PARA_TRANS_WRIE 1
#define VS_SPI_PARA_BIT 8
#define VS_SPI_TRIGGER_MODE 2

#define VS_SPI_DISPLAY_X 4
#define VS_SPI_DISPLAY_Y 0
#define VS_SPI_DISPLAY_W 390
#define VS_SPI_DISPLAY_H 450

struct vs_qspi {
	struct drm_encoder encoder;
	struct drm_connector connector;
	struct device *dev;
	u32 bus_format;
};

static inline struct vs_qspi *to_qspi_with_connector(struct drm_connector *connector)
{
	return container_of(connector, struct vs_qspi, connector);
}

static inline struct vs_qspi *to_qspi_with_encoder(struct drm_encoder *encoder)
{
	return container_of(encoder, struct vs_qspi, encoder);
}

int vs_egt_qspi_pci_init(struct drm_device *drm_dev);
void vs_egt_qspi_pci_deinit(struct drm_device *drm_dev);

extern struct platform_driver vs_egt_qspi_platform_driver;

void egt_qspi_set_intf_format(struct dc_hw *hw, struct dc_hw_display_mode *mode);
void egt_qspi_start_trigger(struct dc_hw *hw, struct dc_hw_display_mode *mode);

#endif /* __VS_DC_QSPI_H_ */
