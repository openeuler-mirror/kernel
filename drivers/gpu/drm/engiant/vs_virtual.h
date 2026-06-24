/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_VIRTUAL_H_
#define __VS_VIRTUAL_H_

#include <linux/debugfs.h>

struct vs_virtual_display {
	struct drm_encoder *encoder;
	struct drm_connector connector;
	struct device *dc;
	u32 bus_format;
};

static inline struct vs_virtual_display *
to_virtual_display_with_connector(struct drm_connector *connector)
{
	return container_of(connector, struct vs_virtual_display, connector);
}

/*
 * static inline struct vs_virtual_display *
 * to_virtual_display_with_encoder(struct drm_encoder *encoder)
 * {
 *	return container_of(encoder, struct vs_virtual_display, encoder);
 * }
 */

#ifdef CONFIG_ENGIANT_VS_PCIE
int vs_egt_vd_pci_init(struct drm_device *drm_dev);
void vs_egt_vd_pci_deinit(struct drm_device *drm_dev);
#endif

extern struct platform_driver egt_virtual_display_platform_driver;
#endif /* __VS_VIRTUAL_H_ */
