/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef _VS_DC_DEC_H_
#define _VS_DC_DEC_H_

#include <drm/drm_framebuffer.h>
#include <drm/drm_fourcc.h>

#include "vs_egt_drm.h"
#include "vs_dc_hw.h"
#include "vs_egt_drm_fourcc.h"

#define fourcc_mod_vs_egt_get_type(val) (((val) & DRM_FORMAT_MOD_VS_EGT_TYPE_MASK) >> 53)
#define fourcc_mod_vs_egt_get_tile_mode(val) \
	((u8)((val) & DRM_FORMAT_MOD_VS_EGT_DEC_TILE_MODE_MASK))
#define fourcc_mod_vs_egt_get_dec_nano_mode(val) ((val) & ((__u64)0x07 << 10))

enum dc_dec_mode {
	DEC_MODE_DISABLE = 0,
	DEC_MODE_ETC2,
	DEC_MODE_DEC_NANO_NONSAMPLE = 3,
	DEC_MODE_DEC_NANO_HSAMPLE,
	DEC_MODE_DEC_NANO_HVSAMPLE,
};

struct dc_dec {
	u8 dec_mod;
	bool enable;
	bool dirty;
};

int egt_dc_dec_config(struct dc_dec *dec_config, struct drm_framebuffer *drm_fb);
int egt_dc_dec_commit(struct dc_dec *dec_config, struct dc_hw *hw, u8 id);

#endif /* _VS_DC_DEC_H_ */
