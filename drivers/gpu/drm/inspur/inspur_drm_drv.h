/* SPDX-License-Identifier: GPL-2.0-only */
/* INSPUR SoC drm driver
 *
 * Based on the smi drm driver.
 *
 * Copyright (c) 2020 SMI Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef INSPUR_DRM_DRV_H
#define INSPUR_DRM_DRV_H

#include <linux/version.h>
#include <drm/drm_atomic.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_vram_helper.h>
#include <linux/pci.h>
#include <drm/drm_vblank.h>
#include <drm/drm_drv.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include <drm/drm_aperture.h>
#endif

#include <linux/delay.h>
#include <drm/drm_gem_framebuffer_helper.h>
struct drm_device;
struct drm_gem_object;

#define inspur_framebuffer drm_framebuffer
#define BPP16_RED    0x0000f800
#define BPP16_GREEN  0x000007e0
#define BPP16_BLUE   0x0000001f
#define BPP16_WHITE  0x0000ffff
#define BPP16_GRAY   0x00008410
#define BPP16_YELLOW 0x0000ffe0
#define BPP16_CYAN   0x000007ff
#define BPP16_PINK   0x0000f81f
#define BPP16_BLACK  0x00000000
struct inspur_fbdev {
	struct drm_fb_helper helper;
	struct inspur_framebuffer *fb;
	int size;
};

struct inspur_cursor {
	struct drm_gem_vram_object *gbo[2];
	unsigned int next_index;
};

struct inspur_drm_private {
	/* hw */
	void __iomem   *mmio;
	void __iomem   *fb_map;
	unsigned long  fb_base;
	unsigned long  fb_size;

	/* drm */
	struct drm_device  *dev;
	bool mode_config_initialized;
	struct drm_atomic_state *suspend_state;

	/* fbdev */
	struct inspur_fbdev *fbdev;

	/* hw cursor */
	struct inspur_cursor cursor;
};

#define to_inspur_framebuffer(x) container_of(x, struct inspur_framebuffer, fb)


void inspur_set_power_mode(struct inspur_drm_private *priv,
			  unsigned int power_mode);
void inspur_set_current_gate(struct inspur_drm_private *priv,
			    unsigned int gate);
int inspur_load(struct drm_device *dev, unsigned long flags);
void inspur_unload(struct drm_device *dev);

int inspur_de_init(struct inspur_drm_private *priv);
int inspur_vdac_init(struct inspur_drm_private *priv);
int inspur_fbdev_init(struct inspur_drm_private *priv);
void inspur_fbdev_fini(struct inspur_drm_private *priv);

int inspur_gem_create(struct drm_device *dev, u32 size, bool iskernel, struct drm_gem_object **obj);
struct inspur_framebuffer *
inspur_framebuffer_init(struct drm_device *dev,
		       const struct drm_mode_fb_cmd2 *mode_cmd,
		       struct drm_gem_object *obj);

int inspur_mm_init(struct inspur_drm_private *inspur);
void inspur_mm_fini(struct inspur_drm_private *inspur);
int inspur_dumb_create(struct drm_file *file, struct drm_device *dev,
		      struct drm_mode_create_dumb *args);

extern const struct drm_mode_config_funcs inspur_mode_funcs;

/* inspur_drm_cursor.c */
int inspur_cursor_init(struct inspur_drm_private *priv);
void inspur_cursor_fini(struct inspur_drm_private *priv);
int inspur_crtc_cursor_set(struct drm_crtc *crtc,
						struct drm_file *file_priv,
						uint32_t handle, uint32_t width,
						uint32_t height);
int inspur_crtc_cursor_move(struct drm_crtc *crtc, int x, int y);
unsigned char getKVMHWCursorSetting(struct inspur_drm_private *priv);
void colorcur2monocur(void *data, void *out);


#endif
