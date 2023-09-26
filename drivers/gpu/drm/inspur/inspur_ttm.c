// SPDX-License-Identifier: GPL-2.0-only
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

#include <drm/drm_atomic_helper.h>

#include "inspur_drm_drv.h"


int inspur_dumb_create(struct drm_file *file, struct drm_device *dev,
		      struct drm_mode_create_dumb *args)
{

	return drm_gem_vram_fill_create_dumb(file, dev, 0, 128, args);
}





const struct drm_mode_config_funcs inspur_mode_funcs = {
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
	.fb_create = drm_gem_fb_create,
	.mode_valid = drm_vram_helper_mode_valid,
};
