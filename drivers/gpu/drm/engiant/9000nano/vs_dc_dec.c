// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#include <linux/errno.h>
#include <linux/types.h>

#include "vs_egt_drm_fourcc.h"

#include "vs_dc_dec.h"

static inline void update_dec_dec_mode(struct dc_dec *dec_config, u64 modifier)
{
	u64 dec_nano_mode = 0;
	u8 dec_type = fourcc_mod_vs_egt_get_type(modifier);

	dec_config->dec_mod = DEC_MODE_DISABLE;

	if (dec_type == DRM_FORMAT_MOD_VS_EGT_TYPE_ETC2)
		dec_config->dec_mod = DEC_MODE_ETC2;
	else if (dec_type == DRM_FORMAT_MOD_VS_EGT_TYPE_DECNANO) {
		dec_nano_mode = fourcc_mod_vs_egt_get_dec_nano_mode(modifier);
		if (dec_nano_mode == DRM_FORMAT_MOD_VS_EGT_DECNANO_H_SAMPLE)
			dec_config->dec_mod = DEC_MODE_DEC_NANO_HSAMPLE;
		else if (dec_nano_mode == DRM_FORMAT_MOD_VS_EGT_DECNANO_HV_SAMPLE)
			dec_config->dec_mod = DEC_MODE_DEC_NANO_HVSAMPLE;
		else
			dec_config->dec_mod = DEC_MODE_DEC_NANO_NONSAMPLE;
	}
}

static void update_fb_modifier_stride(struct drm_framebuffer *drm_fb)
{
	u32 format = drm_fb->format->format;
	u8 tile_mod = fourcc_mod_vs_egt_get_tile_mode(drm_fb->modifier);
	u8 norm_mode = DRM_FORMAT_MOD_VS_EGT_LINEAR;
	u8 dec_type = fourcc_mod_vs_egt_get_type(drm_fb->modifier);

	if (dec_type == DRM_FORMAT_MOD_VS_EGT_TYPE_DECNANO) {
		switch (tile_mod) {
		case DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4:
			switch (format) {
			case DRM_FORMAT_ARGB8888:
			case DRM_FORMAT_RGB888:
				norm_mode = DRM_FORMAT_MOD_VS_EGT_TILE_MODE4X4;
				break;
			default:
				break;
			}
			break;
		case DRM_FORMAT_MOD_VS_EGT_DEC_LINEAR:
			switch (format) {
			case DRM_FORMAT_ARGB8888:
			case DRM_FORMAT_RGB888:
				norm_mode = DRM_FORMAT_MOD_VS_EGT_LINEAR;
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}

	} else if (dec_type == DRM_FORMAT_MOD_VS_EGT_TYPE_ETC2) {
		if (tile_mod == DRM_FORMAT_MOD_VS_EGT_DEC_TILE_4X4 &&
				format == DRM_FORMAT_ARGB8888) {
			norm_mode = DRM_FORMAT_MOD_VS_EGT_TILE_MODE4X4;
			drm_fb->pitches[0] = drm_fb->pitches[0] / 4;
		}
	}
	drm_fb->modifier = fourcc_mod_vs_egt_norm_code(norm_mode);
}

static void _dec_config(struct dc_dec *dec_config, struct drm_framebuffer *drm_fb)
{
	update_dec_dec_mode(dec_config, drm_fb->modifier);
	dec_config->dirty = true;

	update_fb_modifier_stride(drm_fb);
}

int egt_dc_dec_config(struct dc_dec *dec_config, struct drm_framebuffer *drm_fb)
{
	u8 dec_type = 0;

	if (!dec_config->enable) {
		dec_config->dirty = true;
		return 0;
	}

	if (!drm_fb)
		return -EINVAL;

	dec_type = fourcc_mod_vs_egt_get_type(drm_fb->modifier);

	if (((dec_type != DRM_FORMAT_MOD_VS_EGT_TYPE_DECNANO) &&
		(dec_type != DRM_FORMAT_MOD_VS_EGT_TYPE_ETC2)))
		return -EINVAL;

	_dec_config(dec_config, drm_fb);

	return 0;
}

int egt_dc_dec_commit(struct dc_dec *dec_config, struct dc_hw *hw, u8 id)
{
	if (dec_config->dirty) {
		egt_dc_hw_set_plane_fbc_dec(hw, id, dec_config->enable, dec_config->dec_mod);
		dec_config->dirty = false;
	}
	return 0;
}
