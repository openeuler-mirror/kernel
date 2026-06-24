// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2026-03-19
 *   - Added __maybe_unused to unused variables for checkpatch.pl compliance
 * Modified: 2026-03-30
 *   - Replaced __ERR_CHECK with if/goto err for checkpatch.pl compliance
 */

#include "vs_dc_plane_blender.h"
#include "vs_egt_drm.h"
#include "vs_dc_property.h"
#include "vs_dc_hw.h"

static bool blend_mode_check(__maybe_unused const struct dc_hw *hw, __maybe_unused u8 hw_id,
				const void *data, __maybe_unused u32 size,
				__maybe_unused const void *obj_state)
{
	const struct drm_vs_egt_blend *bld = data;

	if (bld->color_mode > VS_EGT_BLD_XOR) {
		pr_err("%s doesn't support this blend mode.\n", __func__);
		return false;
	}
	return true;
}

static bool blend_mode_config_hw(struct dc_hw *hw, u8 hw_id, bool enable, const void *data)
{
	const struct drm_vs_egt_blend *bld = data;
	u32 config = 0;

	config = dc_read(hw, VS_SET_FE_FIELD(DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG, hw_id, Address));
	config = VS_SET_FIELD(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0, ALPHA_BLEND_ENABLE,
				  enable);

	if (enable) {
		switch (bld->color_mode) {
		case VS_EGT_BLD_CLR:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ZERO);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ZERO);
			break;
		case VS_EGT_BLD_SRC:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ONE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ZERO);
			break;
		case VS_EGT_BLD_DST:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ZERO);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ONE);
			break;
		case VS_EGT_BLD_SRC_OVR:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_ALPHA_FACTOR, DISABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ONE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, INVERSE);
			break;
		case VS_EGT_BLD_DST_OVR:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_ALPHA_FACTOR, ENABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, INVERSE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ONE);
			break;
		case VS_EGT_BLD_SRC_IN:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_ALPHA_FACTOR, DISABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, NORMAL);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ZERO);
			break;
		case VS_EGT_BLD_DST_IN:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_ALPHA_FACTOR, ENABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ZERO);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, NORMAL);
			break;
		case VS_EGT_BLD_SRC_OUT:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_ALPHA_FACTOR, DISABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, INVERSE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ZERO);
			break;
		case VS_EGT_BLD_DST_OUT:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_ALPHA_FACTOR, ENABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ZERO);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, INVERSE);
			break;
		case VS_EGT_BLD_SRC_ATOP:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ZERO);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ONE);
			break;
		case VS_EGT_BLD_DST_ATOP:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, ONE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, ZERO);
			break;
		case VS_EGT_BLD_XOR:
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_ALPHA_FACTOR, DISABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_ALPHA_FACTOR, ENABLE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, INVERSE);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, INVERSE);
			break;
		default:
			break;
		}
	}

	/* src/dst blending mode configuration */
	egt_dc_write(hw,
		VS_SET_FE_FIELD(DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG, hw_id, Address), config);

	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(blend_mode_proto, "BLEND_MODE", struct drm_vs_egt_blend, blend_mode_check,
			  NULL, blend_mode_config_hw);

static bool blend_alpha_config_hw(struct dc_hw *hw, u8 hw_id, bool enable, const void *data)
{
	const struct drm_vs_egt_blend_alpha *alpha = data;
	const u32 reg_config = VS_SET_FE_FIELD(DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG, hw_id, Address);
	const u32 reg_global = VS_SET_FE_FIELD(DCREG_SH_PANEL0_GLOBAL_ALPHA, hw_id, Address);
	u32 config = 0;
	u32 global_config = 0;

	if (enable) {
		config = dc_read(hw, reg_config);
		/* src/dst alpha mode configuration */
		config = VS_SET_FIELD(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0, SRC_ALPHA_MODE,
					  alpha->sam);
		config = VS_SET_FIELD(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0, DST_ALPHA_MODE,
					  alpha->dam);

		/* src/dst global alpha mode configuration */
		config = VS_SET_FIELD(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
					  SRC_GLOBAL_ALPHA_MODE, alpha->sgam);
		config = VS_SET_FIELD(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
					  DST_GLOBAL_ALPHA_MODE, alpha->dgam);

		egt_dc_write(hw, reg_config, config);

		global_config = dc_read(hw, reg_global);

		/* src/dst global alpha value configuration */
		if (alpha->sgam != VS_EGT_GALPHA_NORMAL)
			global_config = VS_SET_FIELD(global_config, DCREG_SH_PANEL0_GLOBAL_ALPHA0,
							 SRC_ALPHA, alpha->sga);
		if (alpha->dgam != VS_EGT_GALPHA_NORMAL)
			global_config = VS_SET_FIELD(global_config, DCREG_SH_PANEL0_GLOBAL_ALPHA0,
							 DST_ALPHA, alpha->dga);
		egt_dc_write(hw, reg_global, global_config);
	}
	return true;
}

VS_DC_BLOB_PROPERTY_PROTO(blend_alpha_proto, "BLEND_ALPHA", struct drm_vs_egt_blend_alpha,
			NULL, NULL, blend_alpha_config_hw);

bool vs_egt_dc_register_plane_blender_states(struct vs_dc_property_state_group *states,
					 const struct vs_plane_info *info)
{
	if (info->blend_config) {
		if (!vs_egt_dc_property_register_state(states, &blend_mode_proto))
			goto on_error;
		if (!vs_egt_dc_property_register_state(states, &blend_alpha_proto))
			goto on_error;
	}
	return true;
on_error:
	return false;
}
