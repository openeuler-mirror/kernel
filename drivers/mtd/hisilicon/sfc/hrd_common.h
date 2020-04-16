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
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:
 */

#ifndef __HRD_COMMON_H__
#define __HRD_COMMON_H__

#define HRD_OK (int)(0)
#define HRD_ERR (int)(-1)

#define HRD_ERR_BASE (int)(-1024)

#define HRD_COMMON_ERR_BASE (int)(HRD_ERR_BASE)
#define HRD_COMMON_ERR_NULL_POINTER (int)(HRD_COMMON_ERR_BASE - 1)
#define HRD_COMMON_ERR_UNKNOW_DEVICE (int)(HRD_COMMON_ERR_BASE - 2)
#define HRD_COMMON_ERR_UNKNOW_FUNCTION (int)(HRD_COMMON_ERR_BASE - 3)
#define HRD_COMMON_ERR_OPEN_FAIL (int)(HRD_COMMON_ERR_BASE - 4)
#define HRD_COMMON_ERR_READ_FAIL (int)(HRD_COMMON_ERR_BASE - 5)
#define HRD_COMMON_ERR_WRITE_FAIL (int)(HRD_COMMON_ERR_BASE - 6)
#define HRD_COMMON_ERR_MMAP_FAIL (int)(HRD_COMMON_ERR_BASE - 7)
#define HRD_COMMON_ERR_GET_MEN_RES_FAIL (int)(HRD_COMMON_ERR_BASE - 8)
#define HRD_COMMON_ERR_GET_IRQ_RES_FAIL (int)(HRD_COMMON_ERR_BASE - 9)
#define HRD_COMMON_ERR_INPUT_INVALID (int)(HRD_COMMON_ERR_BASE - 10)
#define HRD_COMMON_ERR_UNKNOW_MODE (int)(HRD_COMMON_ERR_BASE - 11)
#define HRD_COMMON_ERR_NOT_ENOUGH_RES (int)(HRD_COMMON_ERR_BASE - 12)
#define HRD_COMMON_ERR_RES_NOT_EXIST (int)(HRD_COMMON_ERR_BASE - 13)

/* 16 bit nibble swap. example 0x1234 -> 0x2143 */
#define HRD_NIBBLE_SWAP_16BIT(X) ((((X) & 0xf) << 4) |   \
				(((X) & 0xF0) >> 4) |  \
				(((X) & 0xF00) << 4) |  \
				(((X) & 0xF000) >> 4))

/* 32 bit nibble swap. example 0x12345678 -> 0x21436587 */
#define HRD_NIBBLE_SWAP_32BIT(X) ((((X) & 0xF) << 4) |  \
					(((X) & 0xF0) >> 4) |  \
					(((X) & 0xF00) << 4) |  \
					(((X) & 0xF000) >> 4) |  \
					(((X) & 0xF0000) << 4) |  \
					(((X) & 0xF00000) >> 4) |  \
					(((X) & 0xF000000) << 4) |  \
					(((X) & 0xF0000000) >> 4))

/* 16 bit byte swap.  example 0x1234->0x3412 */
#define HRD_BYTE_SWAP_16BIT(X) ((((X) & 0xFF) << 8) | (((X) & 0xFF00) >> 8))

/* 32 bit byte swap. example 0x12345678->0x78563412 */
#define HRD_BYTE_SWAP_32BIT(X) ((((X) & 0xFF) << 24) |  \
				(((X) & 0xFF00) << 8) |  \
				(((X) & 0xFF0000) >> 8) |   \
				(((X) & 0xFF000000) >> 24))

/* 64 bit byte swap.  example 0x11223344.55667788 -> 0x88776655.44332211 */
#define HRD_BYTE_SWAP_64BIT(X) ((l64) ((((X) & 0xFFULL) << 56) |  \
					  (((X) & 0xFF00ULL) << 40) |  \
					  (((X) & 0xFF0000ULL) << 24) |  \
					  (((X) & 0xFF000000ULL) << 8) |   \
					  (((X) & 0xFF00000000ULL) >> 8) |   \
					  (((X) & 0xFF0000000000ULL) >> 24) |  \
					  (((X) & 0xFF000000000000ULL) >> 40) |  \
					  (((X) & 0xFF00000000000000ULL) >> 56)))

/* -- Endianess macros. */
#ifdef HRD_ENDNESS_BIGEND
#define HRD_16BIT_LE(X) HRD_BYTE_SWAP_16BIT(X)
#define HRD_32BIT_LE(X) HRD_BYTE_SWAP_32BIT(X)
#define HRD_64BIT_LE(X) HRD_BYTE_SWAP_64BIT(X)
#define HRD_16BIT_BE(X) (X)
#define HRD_32BIT_BE(X) (X)
#define HRD_64BIT_BE(X) (X)
#else
#define HRD_16BIT_LE(X) (X)
#define HRD_32BIT_LE(X) (X)
#define HRD_64BIT_LE(X) (X)
#define HRD_16BIT_BE(X) HRD_BYTE_SWAP_16BIT(X)
#define HRD_32BIT_BE(X) HRD_BYTE_SWAP_32BIT(X)
#define HRD_64BIT_BE(X) HRD_BYTE_SWAP_64BIT(X)
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#define MTD_FLASH_MAP_DEBUG

#ifdef MTD_FLASH_MAP_DEBUG
#define DB(x) x
#else
#define DB(x)
#endif

#endif
