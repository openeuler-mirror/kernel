/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_drv_type.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_TYPEDEF_H__
#define __SXE2_DRV_TYPEDEF_H__

#include "ps3_types.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#endif

typedef U8 u8;
typedef U16 u16;
typedef U32 u32;
typedef U64 u64;

#ifndef SXE2_SUPPORT_IPXE
typedef S8 s8;
#endif

typedef S16 s16;
typedef S32 s32;
typedef S64 s64;

typedef U16 __le16;
typedef U32 __le32;
typedef U64 __le64;

#ifndef true
#define true (1)
#endif

#ifndef false
#define false (0)
#endif

#ifndef bool
#define bool Ps3Bool_t
#endif

#define ETH_ALEN    6

#endif
