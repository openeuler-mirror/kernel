/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 */
#ifndef __VS_DC_INFO_H__
#define __VS_DC_INFO_H__

#include <linux/kernel.h>
#include <linux/types.h>
#include "vs_type.h"

#include <drm/drm_blend.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_connector.h>

#ifndef DRM_PLANE_HELPER_NO_SCALING
#define DRM_PLANE_HELPER_NO_SCALING DRM_PLANE_NO_SCALING
#endif

#ifndef DRM_COLOR_FORMAT_YCRCB444
#define DRM_COLOR_FORMAT_YCRCB444 DRM_COLOR_FORMAT_YCBCR444
#define DRM_COLOR_FORMAT_YCRCB422 DRM_COLOR_FORMAT_YCBCR422
#define DRM_COLOR_FORMAT_YCRCB420 DRM_COLOR_FORMAT_YCBCR420
#endif

/*
 * Different chip have differnert DC_XXX_NUM.
 * Need find way to separte.
 * For now, use the greatest common divisor of all.
 */
#define DC_PLANE_NUM 5
/* new add*/
#define DC_CURSOR_NUM 1
#define DC_DISPLAY_NUM 1
#define DC_OUTPUT_NUM 5
enum dc_chip_rev {
	DC_REV_0, /* need to refine */
	DC_REV_1,
};

enum dc_hw_plane_id {
	HW_PLANE_0,
	HW_PLANE_1,
	HW_PLANE_2,
	HW_PLANE_3,
	CURSOR_PLANE_0,
	HW_PLANE_NUM,
};

#define GAMMA_SIZE 1024

enum dc_hw_display_id {
	HW_DISPLAY_0,
	HW_DISPLAY_NUM,
};

const struct vs_dc_info *vs_egt_dc_get_chip_info(void);
const struct vs_output_info *vs_egt_dc_get_output_info(void);

#endif
