// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2026-03-30
 *   - Added __maybe_unused to unused variables for checkpatch.pl compliance
 *   - Replaced __ERR_CHECK with if/goto err for checkpatch.pl compliance
 */

#include "vs_dc_preprocess.h"

#include "vs_dc_hw.h"
#include "vs_type.h"
#include "vs_dc_property.h"
#include "vs_dc.h"
#include "vs_dc_reg.h"

static bool colorkey_check(const struct dc_hw *hw, u8 hw_id, __maybe_unused const void *data,
				__maybe_unused u32 size,
				__maybe_unused const void *obj_state)
{
	const struct dc_hw_plane *hw_plane = vs_egt_dc_hw_get_plane(hw, hw_id);
	const struct vs_plane_info *plane_info = hw_plane->info;

	if (!plane_info->color_mgmt) {
		pr_err("%s The plane is not support colorkey.\n", __func__);
		return false;
	}
	return true;
}

static bool colorkey_config_hw(struct dc_hw *hw, u8 hw_id, bool enable, const void *data)
{
	const struct drm_vs_egt_colorkey *colorkey_data = data;
	u32 config = 0;

	config = dc_read(hw, VS_SH_LAYER_FIELD(hw_id, CONFIG_Address));
	egt_dc_write(hw, VS_SH_LAYER_FIELD(hw_id, CONFIG_Address),
		 VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, COLOR_KEY_EN, !!enable));

	if (enable) {
		egt_dc_write(hw, VS_SH_LAYER_FIELD(hw_id, COLOR_KEY_LOW_Address),
			 colorkey_data->colorkey);
		egt_dc_write(hw, VS_SH_LAYER_FIELD(hw_id, COLOR_KEY_HIGH_Address),
			 colorkey_data->colorkey_high);
	}
	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(colorkey_proto, "COLORKEY", struct drm_vs_egt_colorkey,
			colorkey_check, NULL, colorkey_config_hw);

static bool clear_check(const struct dc_hw *hw, u8 hw_id, __maybe_unused const void *data,
			__maybe_unused u32 size,
			__maybe_unused const void *obj_state)
{
	const struct dc_hw_plane *hw_plane = vs_egt_dc_hw_get_plane(hw, hw_id);
	const struct vs_plane_info *plane_info = hw_plane->info;

	if (!plane_info->color_mgmt) {
		pr_err("%s The plane is not support clear.\n", __func__);
		return false;
	}

	return true;
}

static bool clear_config_hw(struct dc_hw *hw, u8 hw_id, bool enable, const void *data)
{
	const struct drm_vs_egt_color *color = data;
	u32 config = 0;
	u32 color_config = 0;

	config = dc_read(hw, VS_SH_LAYER_FIELD(hw_id, CONFIG_Address));
	egt_dc_write(hw, VS_SH_LAYER_FIELD(hw_id, CONFIG_Address),
		 VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, CLEAR_EN, !!enable));

	if (enable) {
		color_config = VS_SET_FIELD(0, DCREG_SH_LAYER0_CLEAR_VALUE, ALPHA, color->a) |
				   VS_SET_FIELD(0, DCREG_SH_LAYER0_CLEAR_VALUE, RED, color->r) |
				   VS_SET_FIELD(0, DCREG_SH_LAYER0_CLEAR_VALUE, GREEN, color->g) |
				   VS_SET_FIELD(0, DCREG_SH_LAYER0_CLEAR_VALUE, BLUE, color->b);

		egt_dc_write(hw, VS_SH_LAYER_FIELD(hw_id, CLEAR_VALUE_Address), color_config);
	}
	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(clear_proto, "CLEAR", struct drm_vs_egt_color, clear_check, NULL,
			  clear_config_hw);

static bool dma_config_check(const struct dc_hw *hw, u8 hw_id, const void *data,
				__maybe_unused u32 size,
				const void *obj_state)
{
	const struct dc_hw_plane *hw_plane = vs_egt_dc_hw_get_plane(hw, hw_id);
	const struct vs_plane_info *plane_info = hw_plane->info;
	const struct vs_plane_state *vs_plane_state = obj_state;
	const u32 one_roi = plane_info->roi;
	const u32 fb_w = vs_plane_state->base.fb->width;
	const u32 fb_h = vs_plane_state->base.fb->height;

	const struct drm_vs_egt_dma *dma = data;

	if ((dma->mode != VS_EGT_DMA_NORMAL) && (!one_roi)) {
		pr_err("%s not support layer ROI.\n", __func__);
		return false;
	}

	switch (dma->mode) {
	case VS_EGT_DMA_ONE_ROI:
		if (((dma->in_rect[0].w + dma->in_rect[0].x) > fb_w) ||
			((dma->in_rect[0].h + dma->in_rect[0].y) > fb_h)) {
			pr_err("%s ROI area is out of layer area range.\n", __func__);
			return false;
		}
		break;
	case VS_EGT_DMA_TWO_ROI:
	case VS_EGT_DMA_SKIP_ROI:
	case VS_EGT_DMA_EXT_LAYER:
	case VS_EGT_DMA_EXT_LAYER_EX:
		pr_err("%s has invalid layer ROI mode.\n", __func__);
		return false;
	default:
		break;
	}
	return true;
}

static bool dma_config_config_hw(__maybe_unused struct dc_hw *hw,
				 __maybe_unused u8 hw_id,
				 __maybe_unused bool enable,
				 __maybe_unused const void *data)
{
	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(dma_config_proto, "DMA_CONFIG", struct drm_vs_egt_dma,
			dma_config_check, NULL, dma_config_config_hw);

bool vs_egt_dc_register_preprocess_states(struct vs_dc_property_state_group *states,
					  const struct vs_plane_info *info)
{
	if (info->roi)
		if (!vs_egt_dc_property_register_state(states, &dma_config_proto))
			goto on_error;
	if (info->color_mgmt) {
		if (!vs_egt_dc_property_register_state(states, &clear_proto))
			goto on_error;
		if (!vs_egt_dc_property_register_state(states, &colorkey_proto))
			goto on_error;
	}
	return true;
on_error:
	return false;
}
