/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_LUT_H__
#define __VS_DC_LUT_H__

#include <linux/types.h>

bool vs_egt_dc_lut_check_xstep(const u32 *data, u32 size, u32 bit_width);

bool vs_egt_dc_lut_check_data(const u32 *data, u32 size, u32 bit_width);

#endif

