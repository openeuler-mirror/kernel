// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2025-12-08
 *  - Updated max resolution to 1920x1200
 *  - Updated output interface info, added virtual output mode
 */

#include "vs_egt_drm_fourcc.h"
#include "vs_egt_drm.h"
#include "vs_dc_info.h"
#include "vs_simple_enc.h" //new add
static const u32 plane_format0[] = {
	DRM_FORMAT_ARGB8888,  DRM_FORMAT_ABGR8888,  DRM_FORMAT_RGBA8888, DRM_FORMAT_BGRA8888,
	DRM_FORMAT_RGB565_A8, DRM_FORMAT_BGR565_A8, DRM_FORMAT_ARGB4444, DRM_FORMAT_ABGR4444,
	DRM_FORMAT_RGBA4444,  DRM_FORMAT_BGRA4444,  DRM_FORMAT_ARGB1555, DRM_FORMAT_ABGR1555,
	DRM_FORMAT_RGBA5551,  DRM_FORMAT_BGRA5551,  DRM_FORMAT_RGB888,	 DRM_FORMAT_BGR888,
	DRM_FORMAT_RGB565,    DRM_FORMAT_BGR565,    DRM_FORMAT_NV12,	 DRM_FORMAT_NV21,
	DRM_FORMAT_YUYV,      DRM_FORMAT_YVYU,      DRM_FORMAT_XRGB8888,
};

static const u32 plane_format1[] = {
	DRM_FORMAT_ARGB8888,  DRM_FORMAT_ABGR8888,  DRM_FORMAT_RGBA8888, DRM_FORMAT_BGRA8888,
	DRM_FORMAT_RGB565_A8, DRM_FORMAT_BGR565_A8, DRM_FORMAT_ARGB4444, DRM_FORMAT_ABGR4444,
	DRM_FORMAT_RGBA4444,  DRM_FORMAT_BGRA4444,  DRM_FORMAT_ARGB1555, DRM_FORMAT_ABGR1555,
	DRM_FORMAT_RGBA5551,  DRM_FORMAT_BGRA5551,  DRM_FORMAT_RGB888,	 DRM_FORMAT_BGR888,
	DRM_FORMAT_RGB565,    DRM_FORMAT_BGR565,    DRM_FORMAT_XRGB8888,
};

static const u32 cursor_formats[] = { DRM_FORMAT_ARGB8888, DRM_FORMAT_XRGB8888};

static const u32 plane_custom_format[] = {};

static const u64 format_modifier0[] = {
	DRM_FORMAT_MOD_LINEAR, fourcc_mod_vs_egt_norm_code(DRM_FORMAT_MOD_VS_EGT_LINEAR),
	fourcc_mod_vs_egt_norm_code(DRM_FORMAT_MOD_VS_EGT_TILE_MODE4X4),
	fourcc_mod_vs_egt_etc2_code(DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4),
	/***
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_HV_SAMPLE),
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_H_SAMPLE),
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_NON_SAMPLE),
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_LINEAR,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_NON_SAMPLE),
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_LINEAR,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_H_SAMPLE),
	 ***/
	 DRM_FORMAT_MOD_INVALID,
};

static const u64 format_modifier1[] = {
	DRM_FORMAT_MOD_LINEAR, fourcc_mod_vs_egt_norm_code(DRM_FORMAT_MOD_VS_EGT_LINEAR),
	/***
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_HV_SAMPLE),
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_H_SAMPLE),
	 * fourcc_mod_vs_egt_decnano_code(DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4,
	 *			   DRM_FORMAT_MOD_VS_EGT_DECNANO_NON_SAMPLE),
	 ***/
	 DRM_FORMAT_MOD_INVALID,
};

static const u64 cursor_modifier[] = {
	DRM_FORMAT_MOD_LINEAR,
	fourcc_mod_vs_egt_norm_code(DRM_FORMAT_MOD_VS_EGT_LINEAR),
	DRM_FORMAT_MOD_INVALID,
};

static const struct vs_plane_info dc_hw_planes[] = {
	/* DC_REV_1 */
	{
		.name = "layer0",
		.id = HW_PLANE_0,
		.type = DRM_PLANE_TYPE_PRIMARY,
		.num_formats = ARRAY_SIZE(plane_format0),
		.formats = plane_format0,
		.num_modifiers = ARRAY_SIZE(format_modifier0),
		.modifiers = format_modifier0,
		.num_support_custom_formats = ARRAY_SIZE(plane_custom_format),
		.support_custom_formats = plane_custom_format,
		.min_width = 0,
		.min_height = 0,
		.max_width = 1920,
		.max_height = 1200,
		.rotation = DRM_MODE_ROTATE_0 | DRM_MODE_ROTATE_90 | DRM_MODE_REFLECT_X |
				DRM_MODE_REFLECT_Y | DRM_MODE_ROTATE_180 | DRM_MODE_ROTATE_270,
		.blend_mode = BIT(DRM_MODE_BLEND_PIXEL_NONE) | BIT(DRM_MODE_BLEND_PREMULTI) |
				  BIT(DRM_MODE_BLEND_COVERAGE),
		.color_encoding = BIT(DRM_COLOR_YCBCR_BT601) | BIT(DRM_COLOR_YCBCR_BT709) |
				  BIT(DRM_COLOR_YCBCR_BT2020),
		.color_range = BIT(DRM_COLOR_YCBCR_LIMITED_RANGE),
		.degamma_size = 0,
		.min_scale = DRM_PLANE_HELPER_NO_SCALING,
		.max_scale = DRM_PLANE_HELPER_NO_SCALING,
		.zpos = 0,
		.blend_config = true,
		.color_mgmt = true,
		.roi = false,
	},
	{
		.name = "layer1",
		.id = HW_PLANE_1,
		.type = DRM_PLANE_TYPE_OVERLAY,
		.num_formats = ARRAY_SIZE(plane_format1),
		.formats = plane_format1,
		.num_modifiers = ARRAY_SIZE(format_modifier1),
		.modifiers = format_modifier1,
		.num_support_custom_formats = ARRAY_SIZE(plane_custom_format),
		.support_custom_formats = plane_custom_format,
		.min_width = 0,
		.min_height = 0,
		.max_width = 1920,
		.max_height = 1200,
		.rotation = DRM_MODE_ROTATE_0 | DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y |
				DRM_MODE_ROTATE_180,
		.blend_mode = BIT(DRM_MODE_BLEND_PIXEL_NONE) | BIT(DRM_MODE_BLEND_PREMULTI) |
				  BIT(DRM_MODE_BLEND_COVERAGE),
		.color_encoding = BIT(DRM_COLOR_YCBCR_BT601) | BIT(DRM_COLOR_YCBCR_BT709) |
				  BIT(DRM_COLOR_YCBCR_BT2020),
		.color_range = BIT(DRM_COLOR_YCBCR_LIMITED_RANGE),
		.degamma_size = 0,
		.min_scale = DRM_PLANE_HELPER_NO_SCALING,
		.max_scale = DRM_PLANE_HELPER_NO_SCALING,
		.zpos = 1,
		.blend_config = true,
		.color_mgmt = true,
		.roi = false,
	},
	{
		.name = "layer2",
		.id = HW_PLANE_2,
		.type = DRM_PLANE_TYPE_OVERLAY,
		.num_formats = ARRAY_SIZE(plane_format1),
		.formats = plane_format1,
		.num_modifiers = ARRAY_SIZE(format_modifier1),
		.modifiers = format_modifier1,
		.num_support_custom_formats = ARRAY_SIZE(plane_custom_format),
		.support_custom_formats = plane_custom_format,
		.min_width = 0,
		.min_height = 0,
		.max_width = 1920,
		.max_height = 1200,
		.rotation = DRM_MODE_ROTATE_0 | DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y |
				DRM_MODE_ROTATE_180,
		.blend_mode = BIT(DRM_MODE_BLEND_PIXEL_NONE) | BIT(DRM_MODE_BLEND_PREMULTI) |
				  BIT(DRM_MODE_BLEND_COVERAGE),
		.color_encoding = BIT(DRM_COLOR_YCBCR_BT601) | BIT(DRM_COLOR_YCBCR_BT709) |
				  BIT(DRM_COLOR_YCBCR_BT2020),
		.color_range = BIT(DRM_COLOR_YCBCR_LIMITED_RANGE),
		.degamma_size = 0,
		.min_scale = DRM_PLANE_HELPER_NO_SCALING,
		.max_scale = DRM_PLANE_HELPER_NO_SCALING,
		.zpos = 2,
		.blend_config = true,
		.color_mgmt = true,
		.roi = false,
	},
	{
		.name = "layer3",
		.id = HW_PLANE_3,
		.type = DRM_PLANE_TYPE_OVERLAY,
		.num_formats = ARRAY_SIZE(plane_format1),
		.formats = plane_format1,
		.num_modifiers = ARRAY_SIZE(format_modifier1),
		.modifiers = format_modifier1,
		.num_support_custom_formats = ARRAY_SIZE(plane_custom_format),
		.support_custom_formats = plane_custom_format,
		.min_width = 0,
		.min_height = 0,
		.max_width = 1920,
		.max_height = 1200,
		.rotation = DRM_MODE_ROTATE_0 | DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y |
				DRM_MODE_ROTATE_180,
		.blend_mode = BIT(DRM_MODE_BLEND_PIXEL_NONE) | BIT(DRM_MODE_BLEND_PREMULTI) |
				  BIT(DRM_MODE_BLEND_COVERAGE),
		.color_encoding = BIT(DRM_COLOR_YCBCR_BT601) | BIT(DRM_COLOR_YCBCR_BT709) |
				  BIT(DRM_COLOR_YCBCR_BT2020),
		.color_range = BIT(DRM_COLOR_YCBCR_LIMITED_RANGE),
		.degamma_size = 0,
		.min_scale = DRM_PLANE_HELPER_NO_SCALING,
		.max_scale = DRM_PLANE_HELPER_NO_SCALING,
		.zpos = 3,
		.blend_config = true,
		.color_mgmt = true,
		.roi = false,
	},
	{
		.name = "Cursor",
		.id = CURSOR_PLANE_0,
		.type = DRM_PLANE_TYPE_CURSOR,
		.num_formats = ARRAY_SIZE(cursor_formats),
		.formats = cursor_formats,
		.num_modifiers = ARRAY_SIZE(cursor_modifier),
		.modifiers = cursor_modifier,
		.min_width = 64,
		.min_height = 64,
		.max_width = 64,
		.max_height = 64,
		.rotation = DRM_MODE_ROTATE_0,
		.degamma_size = 0,
		.min_scale = DRM_PLANE_HELPER_NO_SCALING,
		.max_scale = DRM_PLANE_HELPER_NO_SCALING,
		.zpos = 255,
		.watermark = false,
		.color_mgmt = true,
		.roi = false,
		.crtc_id = 0x0,
	},
};

static const struct vs_display_info dc_hw_displays[] = {
	/* For DC8200: DC_REV_0, DC_REV_1 and DC_REV_2
	 * can share a set of display configuration
	 */
	{
		.name = "Out_ctrl0",
		.id = HW_DISPLAY_0,
		.color_formats = DRM_COLOR_FORMAT_RGB444 | DRM_COLOR_FORMAT_YCRCB444 |
				 DRM_COLOR_FORMAT_YCRCB422 | DRM_COLOR_FORMAT_YCRCB420,
		.max_width = 1920,
		.max_height = 1200,
		.min_scale = DRM_PLANE_HELPER_NO_SCALING,
		.max_scale = DRM_PLANE_HELPER_NO_SCALING,
		.background = true,
		.gamma = true,
		.panel_dth = true,
		.crc = true,
	},
};

static const struct vs_output_info output_info[] = {
	{
		.name = "DPI0-CMD",
		.mux_id = VS_SIMPLE_ENC_MUX_ID(0, 0), /* 8-15 bit output id, 0-7 bit number id,*/
		.type = DRM_MODE_ENCODER_DPI,
		.output_mode = VS_SIMPLE_ENC_OUTPUT_MODE_STANDARD_DPI |
				   VS_SIMPLE_ENC_OUTPUT_MODE_CMD,
	},
	{
		.name = "DP0-CMD",
		.mux_id = VS_SIMPLE_ENC_MUX_ID(0, 1),
		.type = DRM_MODE_ENCODER_DPMST,
		.output_mode = VS_SIMPLE_ENC_OUTPUT_MODE_CMD,
	},
	{
		.name = "EDPI0-HW-TE",
		.mux_id = VS_SIMPLE_ENC_MUX_ID(0, 2),
		.type = DRM_MODE_ENCODER_DPI,
		.output_mode = VS_SIMPLE_ENC_OUTPUT_MODE_HW_TE_EDPI | VS_SIMPLE_ENC_OUTPUT_MODE_CMD,
	},
	{
		.name = "EDPI0-SW-TE",
		.mux_id = VS_SIMPLE_ENC_MUX_ID(0, 3),
		.type = DRM_MODE_ENCODER_DPI,
		.output_mode = VS_SIMPLE_ENC_OUTPUT_MODE_SW_TE_EDPI | VS_SIMPLE_ENC_OUTPUT_MODE_CMD,
	},
	{
		.name = "DPI0-VIDEO",
		.mux_id = VS_SIMPLE_ENC_MUX_ID(0, 4), /* 8-15 bit output id, 0-7 bit number id,*/
		.type = DRM_MODE_ENCODER_DPI,
		.output_mode = VS_SIMPLE_ENC_OUTPUT_MODE_STANDARD_DPI,
	},
	{
		.name = "DP0-VIDEO",
		.mux_id = VS_SIMPLE_ENC_MUX_ID(0, 5),
		.type = DRM_MODE_ENCODER_DPMST,
	},
};

static const struct vs_dc_info dc_info = {
	/* DC_REV_1 */
	.name = "DC9000Nano",
	.chip_id = 0x9000,
	.revision = 0x00007040,
	.pid = 0x02090001,
	.cid = 0x20000003,
	.plane_num = ARRAY_SIZE(dc_hw_planes),
	.planes = dc_hw_planes,
	.layer_num = 4,
	.display_num = ARRAY_SIZE(dc_hw_displays),
	.displays = dc_hw_displays,
	.output_num = ARRAY_SIZE(output_info),
	.max_bpc = 10,
	.pitch_alignment = 128,
	.addr_alignment = 256,
	.max_blend_layer = 4,
	.max_gamma_size = GAMMA_SIZE,
	.gamma_bits = 10,
	.std_color_lut = true,
	.pipe_sync = false,
	.mmu_prefetch = false,
	.panel_sync = false,
	.cap_dec = (1 << DRM_FORMAT_MOD_VS_EGT_TYPE_DECNANO) |
		(1 << DRM_FORMAT_MOD_VS_EGT_TYPE_ETC2),
};

const struct vs_dc_info *vs_egt_dc_get_chip_info(void)
{
	return &dc_info;
}

const struct vs_output_info *vs_egt_dc_get_output_info(void)
{
	return output_info;
}
