/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#ifndef __LSDC_DEBUGFS_H__
#define __LSDC_DEBUGFS_H__

void lsdc_debugfs_init(struct drm_minor *minor);
void lsdc_vram_mm_debugfs_init(struct drm_minor *minor);

#endif
