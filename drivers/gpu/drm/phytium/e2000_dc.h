/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Phytium E2000 display controller DRM driver
 *
 * Copyright (C) 2021 Phytium Technology Co., Ltd.
 */

#ifndef __E2000_DC_H__
#define __E2000_DC_H__

#define E2000_DC_PIX_CLOCK_MAX				(594000)
#define E2000_DC_HDISPLAY_MAX				3840
#define E2000_DC_VDISPLAY_MAX				2160
#define E2000_DC_ADDRESS_MASK				0x3f

extern void e2000_dc_hw_vram_init(struct phytium_display_private *priv,
				  resource_size_t vram_addr,
				  resource_size_t vram_size);
extern void e2000_dc_hw_config_pix_clock(struct drm_crtc *crtc, int clock);
extern void e2000_dc_hw_disable(struct drm_crtc *crtc);
extern int e2000_dc_hw_fb_format_check(const struct drm_mode_fb_cmd2 *mode_cmd, int count);
extern void e2000_dc_hw_plane_get_primary_format(const uint64_t **format_modifiers,
						 const uint32_t **formats,
						 uint32_t *format_count);
extern void e2000_dc_hw_plane_get_cursor_format(const uint64_t **format_modifiers,
						const uint32_t **formats,
						uint32_t *format_count);
extern void e2000_dc_hw_update_primary_hi_addr(struct drm_plane *plane);
extern void e2000_dc_hw_update_cursor_hi_addr(struct drm_plane *plane, uint64_t iova);
void e2000_dc_hw_reset(struct drm_crtc *crtc);
#endif /* __E2000_DC_H__ */
