// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2025-04-02
 *   - Added fbdev code for console initialization
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fb.h>
#include <asm/types.h>
#include <linux/module.h>
#include <linux/pci.h>

#include <drm/drm_atomic.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_damage_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_vblank.h>
#include <drm/drm_framebuffer.h>

#include "vs_fb.h"
#include "vs_gem.h"
#include "vs_drv.h"
#include "vs_crtc.h"
#include "vs_plane.h"
#include "vs_egt_drm_fourcc.h"

#define fourcc_mod_vs_egt_get_type(val) (((val)&DRM_FORMAT_MOD_VS_EGT_TYPE_MASK) >> 53)
#define _VS_WAIT_VBLANK_TIME_OUT 100000
#define FBDEV_NAME "egtdrmfb"

static void vs_drm_gem_fb_destroy(struct drm_framebuffer *fb)
{
	struct vs_framebuffer *vs_fb = to_vs_framebuffer(fb);

	drm_gem_object_put(vs_fb->obj[0]);
	drm_framebuffer_cleanup(fb);
	kfree(vs_fb);
}

static struct drm_framebuffer_funcs vs_fb_funcs = {
	.create_handle = drm_gem_fb_create_handle,
	.destroy = vs_drm_gem_fb_destroy,
	.dirty = drm_atomic_helper_dirtyfb,
};

static struct drm_framebuffer *vs_fb_alloc(struct drm_device *dev,
					   const struct drm_mode_fb_cmd2 *mode_cmd,
					   struct vs_gem_object **obj, unsigned int num_planes)
{
	struct drm_framebuffer *fb;
	struct vs_drm_private *priv = dev->dev_private;
	int ret, i;
	u64 addr;
	u64 rem;

	fb = kzalloc(sizeof(*fb), GFP_KERNEL);
	if (!fb)
		return ERR_PTR(-ENOMEM);

	drm_helper_mode_fill_fb_struct(dev, fb, mode_cmd);

	for (i = 0; i < num_planes; i++) {
		addr = obj[i]->iova + mode_cmd->offsets[i];
		fb->obj[i] = &obj[i]->base;
		fb->pitches[i] = ALIGN(fb->pitches[i], priv->pitch_alignment);

		div64_u64_rem(addr, priv->addr_alignment, &rem);
		if (rem) {
			dev_err(dev->dev, "The framebuffer address should alignment with %d\n",
				priv->addr_alignment);
			return ERR_PTR(-EINVAL);
		}
	}

	ret = drm_framebuffer_init(dev, fb, &vs_fb_funcs);
	if (ret) {
		dev_err(dev->dev, "Failed to initialize framebuffer: %d\n", ret);
		kfree(fb);
		return ERR_PTR(ret);
	}

	return fb;
}

static struct drm_framebuffer *vs_fb_create(struct drm_device *dev, struct drm_file *file_priv,
						const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct drm_framebuffer *fb;
	const struct drm_format_info *info;
	struct vs_gem_object *objs[MAX_NUM_PLANES];
	struct drm_gem_object *obj;
	unsigned int height, size;
	unsigned char i, num_planes;
	int ret = 0;

	info = drm_get_format_info(dev, mode_cmd);
	if (!info)
		return ERR_PTR(-EINVAL);

	num_planes = info->num_planes;
	if (num_planes > MAX_NUM_PLANES)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < num_planes; i++) {
		obj = drm_gem_object_lookup(file_priv, mode_cmd->handles[i]);
		if (!obj) {
			dev_err(dev->dev, "Failed to lookup GEM object.\n");
			ret = -ENXIO;
			goto err;
		}

		if (!((fourcc_mod_vs_egt_get_type(mode_cmd->modifier[i]) ==
			   DRM_FORMAT_MOD_VS_EGT_TYPE_PVRIC) &&
			  (mode_cmd->modifier[i] & DRM_FORMAT_MOD_VS_EGT_DEC_LOSSY))) {
			height = drm_format_info_plane_height(info, mode_cmd->height, i);
			size = height * mode_cmd->pitches[i] + mode_cmd->offsets[i];

			if (obj->size < size) {
				drm_gem_object_put(obj);
				ret = -EINVAL;
				goto err;
			}
		}

		objs[i] = to_vs_gem_object(obj);
	}

	fb = vs_fb_alloc(dev, mode_cmd, objs, i);
	if (IS_ERR(fb)) {
		ret = PTR_ERR(fb);
		goto err;
	}

	return fb;

err:
	for (; i > 0; i--)
		drm_gem_object_put(&objs[i - 1]->base);

	return ERR_PTR(ret);
}

struct vs_gem_object *vs_egt_fb_get_gem_obj(struct drm_framebuffer *fb, unsigned char plane)
{
	if (plane > MAX_NUM_PLANES)
		return NULL;

	return to_vs_gem_object(fb->obj[plane]);
}

static const struct drm_format_info vs_formats_custom[] = {
	{ .format = DRM_FORMAT_NV12,
	  .depth = 0,
	  .num_planes = 2,
	  .char_per_block = { 20, 40, 0 },
	  .block_w = { 4, 4, 0 },
	  .block_h = { 4, 4, 0 },
	  .hsub = 2,
	  .vsub = 2,
	  .is_yuv = true },
	{ .format = DRM_FORMAT_YUV444,
	  .depth = 0,
	  .num_planes = 3,
	  .char_per_block = { 20, 20, 20 },
	  .block_w = { 4, 4, 4 },
	  .block_h = { 4, 4, 4 },
	  .hsub = 1,
	  .vsub = 1,
	  .is_yuv = true },
	{ .format = DRM_FORMAT_RGB565_A8,
	  .depth = 0,
	  .num_planes = 1,
	  .char_per_block = { 3, 0, 0 },
	  .block_w = { 1, 0, 0 },
	  .block_h = { 1, 0, 0 },
	  .hsub = 1,
	  .vsub = 1,
	  .has_alpha = true },
	{ .format = DRM_FORMAT_BGR565_A8,
	  .depth = 0,
	  .num_planes = 1,
	  .char_per_block = { 3, 0, 0 },
	  .block_w = { 1, 0, 0 },
	  .block_h = { 1, 0, 0 },
	  .hsub = 1,
	  .vsub = 1,
	  .has_alpha = true },
	{ .format = DRM_FORMAT_RGB888, /* RGB888-planer */
	  .num_planes = 3,
	  .cpp = { 1, 1, 1 },
	  .hsub = 1,
	  .vsub = 1 },
	{ .format = DRM_FORMAT_BGR888, /* BRGB888-planer */
	  .num_planes = 3,
	  .cpp = { 1, 1, 1 },
	  .hsub = 1,
	  .vsub = 1 },
	{ .format = DRM_FORMAT_YUV420_10BIT,
	  .depth = 0,
	  .num_planes = 2,
	  .char_per_block = { 4, 8, 0 },
	  .block_w = { 3, 3, 0 },
	  .block_h = { 1, 1, 0 },
	  .hsub = 2,
	  .vsub = 2,
	  .is_yuv = true },
	{ .format = DRM_FORMAT_Y0L0, /* LUMA_10 */
	  .depth = 0,
	  .num_planes = 1,
	  .cpp = { 2, 0, 0 },
	  .hsub = 1,
	  .vsub = 1 }
};

static const struct drm_format_info *vs_lookup_format_info(const struct drm_format_info formats[],
							   int num_formats, u32 format)
{
	int i;

	for (i = 0; i < num_formats; i++) {
		if (formats[i].format == format)
			return &formats[i];
	}

	return NULL;
}

static const struct drm_format_info *vs_get_format_info(const struct drm_mode_fb_cmd2 *cmd)
{
	if (fourcc_mod_vs_egt_is_custom_format(cmd->modifier[0]))
		return vs_lookup_format_info(vs_formats_custom, ARRAY_SIZE(vs_formats_custom),
						 cmd->pixel_format);
	else
		return NULL;
}

static void _vs_drm_atomic_helper_commit_hw_done(struct drm_atomic_state *old_state)
{
	struct drm_crtc_state *old_crtc_state, *new_crtc_state;
	struct drm_crtc_commit *commit;
	struct drm_crtc *crtc;
	struct vs_crtc *vs_crtc;
	int i;

	for_each_oldnew_crtc_in_state(old_state, crtc, old_crtc_state, new_crtc_state, i) {
		commit = new_crtc_state->commit;

		if (!commit)
			continue;

		if (crtc->state != new_crtc_state)
			continue;

		if (old_crtc_state->commit)
			drm_crtc_commit_put(old_crtc_state->commit);

		old_crtc_state->commit = drm_crtc_commit_get(commit);

		WARN_ON(new_crtc_state->event);
		complete_all(&commit->hw_done);
		vs_crtc = to_vs_crtc(crtc);
		vs_crtc->commit_hw_done = true;
	}

	if (old_state->fake_commit) {
		complete_all(&old_state->fake_commit->hw_done);
		complete_all(&old_state->fake_commit->flip_done);
	}
}

static void vs_atomic_commit_tail(struct drm_atomic_state *old_state)
{
	struct drm_device *dev = old_state->dev;

	drm_atomic_helper_commit_modeset_disables(dev, old_state);

	drm_atomic_helper_commit_modeset_enables(dev, old_state);

	drm_atomic_helper_commit_planes(dev, old_state, DRM_PLANE_COMMIT_ACTIVE_ONLY);

	_vs_drm_atomic_helper_commit_hw_done(old_state);
}

static const struct drm_mode_config_funcs vs_mode_config_funcs = {
	.fb_create = vs_fb_create,
	.get_format_info = vs_get_format_info,
	.output_poll_changed = drm_fb_helper_output_poll_changed,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};

static struct drm_mode_config_helper_funcs vs_mode_config_helpers = {
	.atomic_commit_tail = vs_atomic_commit_tail,
};

void vs_egt_mode_config_init(struct drm_device *dev)
{
	if (dev->mode_config.max_width == 0 || dev->mode_config.max_height == 0) {
		dev->mode_config.min_width = 0;
		dev->mode_config.min_height = 0;
		dev->mode_config.max_width = 4096;
		dev->mode_config.max_height = 4096;
	}

	dev->mode_config.funcs = &vs_mode_config_funcs;
	dev->mode_config.helper_private = &vs_mode_config_helpers;
}

static inline int vs_framebuffer_init(struct vs_drm_private *dev_priv,
			 const struct drm_mode_fb_cmd2 *mode_cmd,
			 struct vs_framebuffer *vs_fb,
			 struct drm_gem_object *obj)
{
	struct drm_framebuffer *fb;

	if (!vs_fb)
		return -EINVAL;

	fb = to_drm_framebuffer(vs_fb);
	vs_fb->obj[0] = obj;

	drm_helper_mode_fill_fb_struct(dev_priv->drm_dev, fb, mode_cmd);

	return drm_framebuffer_init(dev_priv->drm_dev, fb, &vs_fb_funcs);
}

static int vs_modeset_validate_init(struct vs_drm_private *dev_priv,
				  struct drm_mode_fb_cmd2 *mode_cmd,
				  struct vs_framebuffer *vs_fb,
				  struct drm_gem_object *obj)
{
	return vs_framebuffer_init(dev_priv, mode_cmd, vs_fb, obj);
}

static struct fb_info *
vs_fbdev_helper_alloc(struct drm_fb_helper *helper)
{
	return drm_fb_helper_alloc_info(helper);
}

static const struct fb_ops s_vs_fbdev_ops = {
	.owner          = THIS_MODULE,
	.fb_check_var   = drm_fb_helper_check_var,
	.fb_set_par     = drm_fb_helper_set_par,
	.fb_fillrect    = cfb_fillrect,
	.fb_copyarea    = cfb_copyarea,
	.fb_imageblit   = cfb_imageblit,
	.fb_pan_display = drm_fb_helper_pan_display,
	.fb_blank       = drm_fb_helper_blank,
	.fb_setcmap     = drm_fb_helper_setcmap,
	.fb_debug_enter = drm_fb_helper_debug_enter,
	.fb_debug_leave = drm_fb_helper_debug_leave,
};

static int vs_fbdev_probe(struct drm_fb_helper *helper,
				struct drm_fb_helper_surface_size *sizes)
{
	struct vs_fbdev *vs_fbdev = container_of(helper, struct vs_fbdev, helper);
	struct drm_framebuffer *fb = to_drm_framebuffer(&vs_fbdev->fb);
	struct vs_gem_private *gem_priv = vs_fbdev->priv->gem_priv;
	struct drm_device *dev = helper->dev;
	struct drm_mode_fb_cmd2 mode_cmd;
	struct drm_gem_object *obj;
	struct fb_info *info;
	void __iomem *vaddr;
	size_t obj_size;
	int err;
	struct vs_gem_object *vs_obj;
	bool locked = false;

	if (helper->fb) {
		mutex_lock(&dev->struct_mutex);
		locked = true;
	}

	/* 1. Create a framebuffer */
	info = vs_fbdev_helper_alloc(helper);
	if (!info) {
		err = -ENOMEM;
		pr_err("fb_dev create failed\n");
		goto err_unlock_dev;
	}

	pr_debug("fb_dev create success\n");

	memset(&mode_cmd, 0, sizeof(mode_cmd));
	mode_cmd.pitches[0] =
		sizes->surface_width * DIV_ROUND_UP(sizes->surface_bpp, 8);
	mode_cmd.width = sizes->surface_width;
	mode_cmd.height = sizes->surface_height;
	mode_cmd.pixel_format = drm_mode_legacy_fb_format(sizes->surface_bpp,
			sizes->surface_depth);
	obj_size = PAGE_ALIGN(mode_cmd.height * mode_cmd.pitches[0]);

	pr_debug("alloc fb obj_size=%zu(height=%d, width=%d pitches=%d)\n",
		obj_size, mode_cmd.height, mode_cmd.width, mode_cmd.pitches[0]);

	/* 2. Create a vs_gem priv */
	obj = vs_egt_gem_create_with_handle(dev, obj_size, gem_priv);
	if (IS_ERR(obj)) {
		err = PTR_ERR(obj);
		goto err_unlock_dev;
	}

	vs_obj = to_vs_gem_object(obj);

	pr_debug("vs_gem_obj_create success addr = %pad size = 0x%zx\n",
			&vs_obj->dma_addr, obj->size);

	/* Ioremap buffer to user */
	vaddr = ioremap_wc(vs_obj->dma_addr, obj->size);
	if (!vaddr) {
		err = -ENOMEM;
		goto err_gem_destroy;
	}

	pr_debug("ioremap_wc ok vaddr = %p\n", vaddr);

	/* Zero fb memory, fb_memset accounts for iomem address space */
	fb_memset(vaddr, 0, obj_size);

	err = vs_modeset_validate_init(vs_fbdev->priv, &mode_cmd,
			&vs_fbdev->fb, obj);

	if (err) {
		DRM_ERROR("vs_modeset_validate_init failed\n");
		goto err_gem_unmap;
	}

	helper->fb = fb;
	helper->info = info;

	/* Fill out the Linux framebuffer info */
	strscpy(info->fix.id, FBDEV_NAME, sizeof(info->fix.id));
	drm_fb_helper_fill_info(info, helper, sizes);
	info->par = helper;
	info->flags = 0 | FBINFO_HWACCEL_DISABLED;
	info->fbops = &s_vs_fbdev_ops;
	info->fix.smem_start = vs_obj->dma_addr;
	info->fix.smem_len = obj_size;
	info->screen_base = vaddr;
	info->screen_size = obj_size;

	if (locked)
		mutex_unlock(&dev->struct_mutex);

	pr_debug("fbdev_probe ok\n");

	return 0;

err_gem_unmap:
	iounmap(vaddr);
err_gem_destroy:
	vs_egt_gem_free_object(obj);
err_unlock_dev:
	if (locked)
		mutex_unlock(&dev->struct_mutex);

	pr_err("failed (err=%d)\n", err);
	return err;
}

static const struct drm_fb_helper_funcs s_vs_fbdev_helper_funcs = {
	.fb_probe = vs_fbdev_probe,
};

void vs_egt_fbdev_destroy(struct vs_fbdev *vs_fbdev)
{
	struct vs_framebuffer *vs_fb;
	struct vs_gem_object *vs_obj;
	struct drm_framebuffer *fb;
	struct fb_info *info;

	if (!vs_fbdev)
		return;

	drm_fb_helper_unregister_info(&vs_fbdev->helper);
	vs_fb = &vs_fbdev->fb;

	vs_obj = to_vs_gem_object(vs_fb->obj[0]);
	if (vs_obj) {
		info = vs_fbdev->helper.info;
		iounmap((void __iomem *)info->screen_base);
	}

	pr_debug("drm_gem_object_put_unlocked\n");

	drm_gem_object_put(vs_fb->obj[0]);

	pr_debug("drm_fb_helper_fini\n");
	drm_fb_helper_fini(&vs_fbdev->helper);

	fb = to_drm_framebuffer(vs_fb);
	if (fb && fb->dev) {
		pr_debug("drm_framebuffer_cleanup\n");
		drm_framebuffer_cleanup(fb);
	}

	kfree(vs_fbdev);
}

static struct vs_fbdev *vs_fbdev_create(struct vs_drm_private *dev_priv)
{
	struct vs_fbdev *vs_fbdev;
	int err;

	vs_fbdev = kzalloc(sizeof(*vs_fbdev), GFP_KERNEL);
	if (!vs_fbdev)
		return ERR_PTR(-ENOMEM);

	pr_debug("vs_fbdv alloc ok\n");

	drm_fb_helper_prepare(dev_priv->drm_dev, &vs_fbdev->helper, 32,
			&s_vs_fbdev_helper_funcs);
	pr_debug("drm_fb_helper_prepare OK\n");

	err = drm_fb_helper_init(dev_priv->drm_dev, &vs_fbdev->helper);

	if (err) {
		pr_err("short of memory\n");
		goto err_free_fbdev;
	}
	pr_debug("dm_fb_helper_init\n");

	vs_fbdev->priv = dev_priv;

	err = drm_fb_helper_initial_config(&vs_fbdev->helper);
	if (err) {
		pr_err("drm_fb_helper_initial_config init failed: %d\n", err);
		goto err_fb_helper_fini;
	}
	pr_debug("fb create succeed\n");

	return vs_fbdev;

err_fb_helper_fini:
	drm_fb_helper_fini(&vs_fbdev->helper);

err_free_fbdev:
	kfree(vs_fbdev);
	pr_err("fb create failed\n");
	return ERR_PTR(err);
}

int vs_egt_fbdev_init(struct drm_device *drm_dev)
{
	struct vs_drm_private *dev_priv = drm_dev->dev_private;
	struct vs_fbdev *fbdev;
	int err;

	pr_debug(" Start init fbdev\n");
	fbdev = vs_fbdev_create(dev_priv);
	if (IS_ERR(fbdev)) {
		pr_err("faile to create fb device\n");
		return PTR_ERR(fbdev);
	}

	dev_priv->fbdev = (void *)fbdev;
	pr_debug("drm_fb_helper_restore_fbdev_mode_unlocked\n");
	err = drm_fb_helper_restore_fbdev_mode_unlocked(&fbdev->helper);
	if (err == -EBUSY) {
		pr_debug("fbdev mode restore deferred (device busy)\n");
		return 0;
	} else if (err) {
		pr_err("failed to set mode (err=%d)\n", err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(vs_egt_fbdev_init);

void vs_egt_fbdev_fini(struct drm_device *drm_dev)
{
	struct vs_drm_private *dev_priv = drm_dev->dev_private;

	vs_egt_fbdev_destroy(dev_priv->fbdev);
}
EXPORT_SYMBOL(vs_egt_fbdev_fini);
