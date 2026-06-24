// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2026-03-19
 *   - Added __maybe_unused to unused variables for checkpatch.pl compliance
 * Modified: 2026-03-30
 *   - Replaced __ERR_CHECK with if/goto err for checkpatch.pl compliance
 */

#include "vs_dc_postprocess.h"
#include "vs_egt_drm.h"
#include "vs_egt_drm_fourcc.h"
#include "vs_dc_property.h"
#include "vs_dc_hw.h"

static bool bg_color_check(const struct dc_hw *hw, u8 hw_id, __maybe_unused const void *data,
				__maybe_unused u32 size,
				__maybe_unused const void *obj_state)
{
	const struct dc_hw_display *hw_display = vs_egt_dc_hw_get_display(hw, hw_id);
	const struct vs_display_info *display_info = hw_display->info;

	if (!display_info->background) {
		pr_err("%s The display is not support set background color.\n", __func__);
		return false;
	}

	return true;
}

static bool bg_color_config_hw(struct dc_hw *hw, __maybe_unused u8 hw_id, bool enable,
				const void *data)
{
	const struct drm_vs_egt_color *bg_color = data;
	u32 color_config;

	if (enable)
		color_config = VS_SET_FIELD(0, DCREG_SH_PANEL0_BACKGROUND, BLUE, bg_color->b) |
				   VS_SET_FIELD(0, DCREG_SH_PANEL0_BACKGROUND, GREEN, bg_color->g) |
				   VS_SET_FIELD(0, DCREG_SH_PANEL0_BACKGROUND, RED, bg_color->r) |
				   VS_SET_FIELD(0, DCREG_SH_PANEL0_BACKGROUND, ALPHA, bg_color->a);
	else
		color_config = DCREG_SH_PANEL0_BACKGROUND_ResetValue;

	egt_dc_write(hw, DCREG_SH_PANEL0_BACKGROUND_Address, color_config);

	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(bg_color_proto, "BG_COLOR", struct drm_vs_egt_color, bg_color_check, NULL,
			  bg_color_config_hw);

static bool panel_dither_config_hw(struct dc_hw *hw, __maybe_unused u8 hw_id, bool enable,
					const void *data)
{
	const struct drm_vs_egt_dither *dither = data;
	u32 config = 0;

	config = dc_read(hw, DCREG_SH_PANEL0_CONFIG_Address);
	config = VS_SET_FIELD(config, DCREG_SH_PANEL0_CONFIG, DITHER, !!enable);
	egt_dc_write(hw, DCREG_SH_PANEL0_CONFIG_Address, config);

	if (enable) {
		egt_dc_write(hw, DCREG_SH_PANEL0_DITHER_TABLE_LOW_Address, dither->table_low[0]);
		egt_dc_write(hw, DCREG_SH_PANEL0_DITHER_TABLE_HIGH_Address, dither->table_high[0]);
	}

	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(panel_dither_proto, "PANEL_DITHER", struct drm_vs_egt_dither, NULL, NULL,
			  panel_dither_config_hw);

static bool display_r2y_config_hw(struct dc_hw *hw, u8 hw_id, bool enable, const void *data)
{
	const struct drm_vs_egt_r2y_config *r2y = data;
	const u32 reg_config = VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, hw_id, CONFIG_Address);
	const u32 reg_coef =
		VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, hw_id, RGB_TO_YUV_PRE_COEF_D0_Address);
	u32 r2y_config;

	r2y_config = dc_read(hw, reg_config);
	if (enable) {
		r2y_config = VS_SET_FIELD_PREDEF(r2y_config, DCREG_SH_PANEL0_CONFIG, R2Y, ENABLED);
		if (r2y->mode == VS_EGT_CSC_CM_USR)
			egt_dc_write_u32_blob(hw, reg_coef, r2y->coef, VS_EGT_MAX_R2Y_COEF_NUM);
	} else {
		r2y_config = VS_SET_FIELD_PREDEF(r2y_config, DCREG_SH_PANEL0_CONFIG, R2Y, DISABLED);
	}
	egt_dc_write(hw, reg_config, r2y_config);
	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(r2y_proto, "R2Y", struct drm_vs_egt_r2y_config, NULL, NULL,
			  display_r2y_config_hw);

bool vs_egt_dc_register_postprocess_states(struct vs_dc_property_state_group *states,
					   const struct vs_display_info *display_info)
{
	if (display_info->background)
		if (!vs_egt_dc_property_register_state(states, &bg_color_proto))
			goto on_error;

	if (display_info->panel_dth)
		if (!vs_egt_dc_property_register_state(states, &panel_dither_proto))
			goto on_error;

	if (display_info->color_formats &
		(DRM_COLOR_FORMAT_YCBCR444 | DRM_COLOR_FORMAT_YCBCR422 | DRM_COLOR_FORMAT_YCBCR420))
		if (!vs_egt_dc_property_register_state(states, &r2y_proto))
			goto on_error;

	return true;
on_error:
	return false;
}
