/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2020, Wuxi Stars Micro System Technologies Co., Ltd.
 *
 * @file	sxe2_type.h
 * @date	2022.11.23
 * @brief	驱动类型定义头文件
 * @note	新增文件,与ps3主库隔离数据类型时使用
 */
#ifndef __SXE2_TYPES_H__
#define __SXE2_TYPES_H__

#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#if defined __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#endif ///< __BYTE_ORDER__
#elif defined __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#endif ///< __BYTE_ORDER__
#elif defined __BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD
#elif defined __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#elif defined RTE_TOOLCHAIN_MSVC
#define __LITTLE_ENDIAN_BITFIELD
#else
#error  "Unknown endianness."
#endif

#define __le16  u16
#define __le32  u32
#define __le64  u64

#define __be16  u16
#define __be32  u32
#define __be64  u64

#define STATIC static

#endif
