/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __HRD_SFLASH_HAL_H__
#define __HRD_SFLASH_HAL_H__
#include "hrd_sflash_driver.h"

extern void SFC_CheckErr(struct SFC_SFLASH_INFO *sflash);
extern s32 SFC_RegModeRead(struct SFC_SFLASH_INFO *sflash, u32 offset,
	u8 *pucDest, u32 ulReadLen);
extern s32 SFC_RegModeWrite(struct SFC_SFLASH_INFO *sflash, u32 offset,
	const u8 *pucSrc, u32 ulWriteLen);
extern s32 SFC_BlockErase(struct SFC_SFLASH_INFO *sflash, u32 ulAddr,
	u32 ErCmd);
extern int hrd_sflash_init(struct SFC_SFLASH_INFO *pFlinfo);
extern int SFC_WPSet(struct SFC_SFLASH_INFO *sflash, bool val);

#endif
