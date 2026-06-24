/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_FB_H__
#define __VS_FB_H__
#include "drm/drm_fb_helper.h"

#define vs_framebuffer drm_framebuffer
#define to_vs_framebuffer(fb) (fb)
#define to_drm_framebuffer(fb) (fb)

struct vs_fbdev {
	struct drm_fb_helper helper;
	struct vs_framebuffer fb;
	struct vs_drm_private *priv;
	u8 preferred_bpp;
};

void vs_egt_fbdev_destroy(struct vs_fbdev *vs_fbdev);
extern int vs_egt_fbdev_init(struct drm_device *drm_dev);
extern void vs_egt_fbdev_fini(struct drm_device *drm_dev);

struct vs_gem_object *vs_egt_fb_get_gem_obj(struct drm_framebuffer *fb, unsigned char plane);

void vs_egt_mode_config_init(struct drm_device *dev);

#endif /* __VS_FB_H__ */
