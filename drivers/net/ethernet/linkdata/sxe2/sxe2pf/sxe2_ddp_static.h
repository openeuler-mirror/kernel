/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ddp_static.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DDP_STATIC_H__
#define __SXE2_DDP_STATIC_H__

#include <linux/types.h>

struct sxe2_adapter;

void *sxe2_ddp_static_assemble(struct sxe2_adapter *adapter, u32 *total);

void sxe2_ddp_static_ver_get(u16 *drv_maj, u16 *drv_mnr,
			     u16 *fw_maj, u16 *fw_mnr);

#endif
