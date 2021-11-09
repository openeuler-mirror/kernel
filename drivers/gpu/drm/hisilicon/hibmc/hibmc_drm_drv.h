/* Hisilicon Hibmc SoC drm driver
 *
 * Based on the bochs drm driver.
 *
 * Copyright (c) 2016 Huawei Limited.
 *
 * Author:
 *	Rongrong Zou <zourongrong@huawei.com>
 *	Rongrong Zou <zourongrong@gmail.com>
 *	Jianhua Li <lijianhua@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef HIBMC_DRM_DRV_H
#define HIBMC_DRM_DRV_H

#include <linux/gpio/consumer.h>
#include <linux/i2c-algo-bit.h>
#include <linux/i2c.h>

#include <drm/drm_edid.h>
#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_gem.h>
#include <drm/ttm/ttm_bo_driver.h>


struct hibmc_framebuffer {
	struct drm_framebuffer fb;
	struct drm_gem_object *obj;
};

struct hibmc_fbdev {
	struct drm_fb_helper helper;
	struct hibmc_framebuffer *fb;
	int size;
};

struct hibmc_connector {
	struct drm_connector base;

	struct i2c_adapter adapter;
	struct i2c_algo_bit_data bit_data;
};

struct hibmc_drm_private {
	/* hw */
	void __iomem   *mmio;
	void __iomem   *fb_map;
	unsigned long  fb_base;
	unsigned long  fb_size;
	bool msi_enabled;

	/* drm */
	struct drm_device  *dev;
	struct hibmc_connector connector;
	bool mode_config_initialized;
	struct drm_atomic_state *suspend_state;

	/* ttm */
	struct drm_global_reference mem_global_ref;
	struct ttm_bo_global_ref bo_global_ref;
	struct ttm_bo_device bdev;
	bool initialized;

	/* fbdev */
	struct hibmc_fbdev *fbdev;
	bool mm_inited;
};

static inline struct hibmc_connector *to_hibmc_connector(struct drm_connector *connector)
{
	return container_of(connector, struct hibmc_connector, base);
}

static inline struct hibmc_drm_private *to_hibmc_drm_private(struct drm_device *dev)
{
	return dev->dev_private;
}

#define to_hibmc_framebuffer(x) container_of(x, struct hibmc_framebuffer, fb)

struct hibmc_bo {
	struct ttm_buffer_object bo;
	struct ttm_placement placement;
	struct ttm_bo_kmap_obj kmap;
	struct drm_gem_object gem;
	struct ttm_place placements[3];
	int pin_count;
};

static inline struct hibmc_bo *hibmc_bo(struct ttm_buffer_object *bo)
{
	return container_of(bo, struct hibmc_bo, bo);
}

static inline struct hibmc_bo *gem_to_hibmc_bo(struct drm_gem_object *gem)
{
	return container_of(gem, struct hibmc_bo, gem);
}

void hibmc_set_power_mode(struct hibmc_drm_private *priv,
			  unsigned int power_mode);
void hibmc_set_current_gate(struct hibmc_drm_private *priv,
			    unsigned int gate);
int hibmc_load(struct drm_device *dev, unsigned long flags);
void hibmc_unload(struct drm_device *dev);

int hibmc_de_init(struct hibmc_drm_private *priv);
int hibmc_vdac_init(struct hibmc_drm_private *priv);
int hibmc_fbdev_init(struct hibmc_drm_private *priv);
void hibmc_fbdev_fini(struct hibmc_drm_private *priv);

int hibmc_gem_create(struct drm_device *dev, u32 size, bool iskernel,
		     struct drm_gem_object **obj);
struct hibmc_framebuffer *
hibmc_framebuffer_init(struct drm_device *dev,
		       const struct drm_mode_fb_cmd2 *mode_cmd,
		       struct drm_gem_object *obj);

int hibmc_mm_init(struct hibmc_drm_private *hibmc);
void hibmc_mm_fini(struct hibmc_drm_private *hibmc);
int hibmc_bo_pin(struct hibmc_bo *bo, u32 pl_flag, u64 *gpu_addr);
int hibmc_bo_unpin(struct hibmc_bo *bo);
void hibmc_gem_free_object(struct drm_gem_object *obj);
int hibmc_dumb_create(struct drm_file *file, struct drm_device *dev,
		      struct drm_mode_create_dumb *args);
int hibmc_dumb_mmap_offset(struct drm_file *file, struct drm_device *dev,
			   u32 handle, u64 *offset);
int hibmc_mmap(struct file *filp, struct vm_area_struct *vma);
int hibmc_ddc_create(struct drm_device *drm_dev, struct hibmc_connector *connector);

extern const struct drm_mode_config_funcs hibmc_mode_funcs;

#endif
