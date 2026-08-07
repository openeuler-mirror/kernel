/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_H__
#define __VS_DC_H__

#include <linux/mm_types.h>
#include <linux/of.h>
#include <linux/media-bus-format.h>

#include <drm/drm_modes.h>

#include "vs_crtc.h"
#include "vs_dc_hw.h"
#include "vs_plane.h"
#ifdef CONFIG_PCI
#ifdef CONFIG_ENGIANT_VS_VIRTUAL_DISPLAY
#include "vs_virtual.h"
#endif
#endif
#include "vs_simple_enc.h"
#ifdef CONFIG_ENGIANT_VS_DEC
#include "vs_dc_dec.h"
#endif

#ifdef CONFIG_DRM_EGT_DP
#include "egt_dp.h"
#endif /* end of CONFIG_DRM_EGT */

/*to convert standard rotation to vs_rotation*/
static inline void to_vs_rotation(u32 rotation, struct dc_hw_fb *fb)
{
	switch (rotation & (DRM_MODE_ROTATE_MASK | DRM_MODE_REFLECT_MASK)) {
	case DRM_MODE_ROTATE_0:
		fb->rotation = ROT_0;
		fb->flipx = FLIP_X_DISABLE;
		fb->flipy = FLIP_Y_DISABLE;
		break;
	case DRM_MODE_REFLECT_X | DRM_MODE_ROTATE_0:
		fb->rotation = ROT_0;
		fb->flipx = FLIP_X_ENABLE;
		fb->flipy = FLIP_Y_DISABLE;
		break;
	case DRM_MODE_REFLECT_Y | DRM_MODE_ROTATE_0:
		fb->rotation = ROT_0;
		fb->flipx = FLIP_X_DISABLE;
		fb->flipy = FLIP_Y_ENABLE;
		break;
	case DRM_MODE_ROTATE_180:
		fb->rotation = ROT_0;
		fb->flipx = FLIP_X_ENABLE;
		fb->flipy = FLIP_Y_ENABLE;
		break;
	case DRM_MODE_ROTATE_90:
		fb->rotation = ROT_90;
		fb->flipx = FLIP_X_DISABLE;
		fb->flipy = FLIP_Y_DISABLE;
		break;
	case DRM_MODE_REFLECT_X | DRM_MODE_ROTATE_90:
		fb->rotation = ROT_90;
		fb->flipx = FLIP_X_ENABLE;
		fb->flipy = FLIP_Y_DISABLE;
		break;
	case DRM_MODE_REFLECT_Y | DRM_MODE_ROTATE_90:
		fb->rotation = ROT_90;
		fb->flipx = FLIP_X_DISABLE;
		fb->flipy = FLIP_Y_ENABLE;
		break;
	case DRM_MODE_ROTATE_270:
		fb->rotation = ROT_90;
		fb->flipx = FLIP_X_ENABLE;
		fb->flipy = FLIP_Y_ENABLE;
		break;
	default:
		fb->rotation = ROT_0;
		fb->flipx = FLIP_X_DISABLE;
		fb->flipy = FLIP_Y_DISABLE;
		break;
	}
}

struct vs_dc_plane {
	enum dc_hw_plane_id id;
	struct vs_plane *base;
#ifdef CONFIG_ENGIANT_VS_DEC
	struct dc_dec dec;
#endif
};

struct vs_dc {
	struct vs_crtc *crtc[DC_DISPLAY_NUM];
	struct dc_hw hw;

	struct clk *core_clk;
	struct clk *pix_clk;
	struct clk *axi_clk;
	unsigned int pix_clk_rate; /* in KHz */
	unsigned int irq_num;

	bool first_frame;

	struct vs_dc_plane planes[DC_PLANE_NUM];

	struct simple_encoder *encoder[DC_OUTPUT_NUM];

#ifdef CONFIG_ENGIANT_VS_QSPI
	struct vs_qspi *qspi[DC_DISPLAY_NUM];
#endif

#ifdef CONFIG_ENGIANT_VS_VIRTUAL_DISPLAY
	struct vs_virtual_display *vd[DC_OUTPUT_NUM];
#endif

#ifdef CONFIG_DRM_EGT_DP
	struct egt_displayport *dp;
#endif

#ifdef CONFIG_ENGIANT_VS_PCIE
	void __iomem *pci_base;
#endif
};

extern struct platform_driver egt_dc_platform_driver;
extern struct platform_driver egt_dc_be_platform_driver;
extern struct platform_driver egt_dc_fe0_platform_driver;
extern struct platform_driver egt_dc_fe1_platform_driver;
extern struct platform_driver egt_dc_wb_platform_driver;

int vs_egt_dc_pci_init(struct drm_device *drm_dev);
void vs_egt_dc_pci_deinit(struct drm_device *drm_dev);
void vs_egt_dc_pci_deinit_aer(struct drm_device *drm_dev);
u32 vs_egt_dc_reg_read(struct drm_device *drm_dev, u32 reg);
bool vs_egt_dc_is_yuv_format(u32 format);
#ifdef CONFIG_PM_SLEEP
int vs_egt_dc_suspend(struct device *dev);
int vs_egt_dc_resume(struct device *dev);
#endif

#ifdef CONFIG_DEBUG_FS
void vs_egt_crtc_set_last_crc(u32 crtc_id, struct drm_vs_egt_color value);
#endif

#endif /* __VS_DC_H__ */
