/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#ifndef __LSDC_OUTPUT_H__
#define __LSDC_OUTPUT_H__

#include <drm/drm_device.h>
#include <drm/drm_connector.h>

int lsdc_create_output(struct lsdc_device *ldev, unsigned int i, unsigned int num_crtc);

int lsdc_attach_output(struct lsdc_device *ldev, uint32_t num_crtc);

#endif
