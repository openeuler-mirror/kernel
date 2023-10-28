/* SPDX-License-Identifier: GPL-2.0 */
/* Phytium display drm driver
 *
 * Copyright (C) 2021 Phytium Technology Co., Ltd.
 */

#ifndef __X100_DC_H__
#define __X100_DC_H__

#define X100_DC_PIX_CLOCK_MAX				(594000)
#define x100_DC_HDISPLAY_MAX				3840
#define X100_DC_VDISPLAY_MAX				2160
#define X100_DC_ADDRESS_MASK				0x3f

extern void x100_dc_hw_vram_init(struct phytium_display_private *priv,
					   resource_size_t vram_addr,
					   resource_size_t vram_size);
extern void x100_dc_hw_clear_msi_irq(struct phytium_display_private *priv, uint32_t phys_pipe);
extern void x100_dc_hw_config_pix_clock(struct drm_crtc *crtc, int clock);
extern void x100_dc_hw_disable(struct drm_crtc *crtc);
extern int x100_dc_hw_fb_format_check(const struct drm_mode_fb_cmd2 *mode_cmd, int count);
extern void x100_dc_hw_plane_get_primary_format(const uint64_t **format_modifiers,
								const uint32_t **formats,
								uint32_t *format_count);
extern void x100_dc_hw_plane_get_cursor_format(const uint64_t **format_modifiers,
							       const uint32_t **formats,
							       uint32_t *format_count);
void x100_dc_hw_update_dcreq(struct drm_plane *plane);
void x100_dc_hw_update_primary_hi_addr(struct drm_plane *plane);
#endif /* __X100_DC_H__ */
