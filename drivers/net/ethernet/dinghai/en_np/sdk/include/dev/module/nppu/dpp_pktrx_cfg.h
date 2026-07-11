/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PKTRX_CFG_H_
#define _DPP_PKTRX_CFG_H_

#include "dpp_pktrx_api.h"
#include "dpp_reg.h"

u32 dpp_pktrx_mcode_glb_cfg_get_0(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_0);
u32 dpp_pktrx_mcode_glb_cfg_get_1(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_1);
u32 dpp_pktrx_mcode_glb_cfg_get_2(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_2);
u32 dpp_pktrx_mcode_glb_cfg_get_3(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_3);

#endif
