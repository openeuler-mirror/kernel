/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : HwSafePrint.h
 * Version       : Initial Draft
 * Created       : 2018/12/10
 * Last Modified : 2026/09/16
 * Description   : Huawei safe print function define
 */

#ifndef HW_SAFE_PRINT_H
#define HW_SAFE_PRINT_H

UINTN AsciiSPrintS(
	CHAR8      *startOfBuffer,
	UINTN       bufferSize,
	CONST CHAR8 *formatString,
	...);

UINTN UnicodeSPrintS(
	CHAR16      *startOfBuffer,
	UINTN        bufferSize,
	CONST CHAR16 *formatString,
	...);

UINTN AsciiVSPrintS(
	CHAR8         *startOfBuffer,
	UINTN          bufferSize,
	CONST CHAR8   *formatString,
	VA_LIST        marker);

UINTN UnicodeVSPrintS(
	CHAR16         *startOfBuffer,
	UINTN           bufferSize,
	CONST CHAR16   *formatString,
	VA_LIST         marker);

#ifdef EDKII_SUPPORT
UINTN AsciiBSPrintS(
	CHAR8         *startOfBuffer,
	UINTN          bufferSize,
	CONST CHAR8   *formatString,
	BASE_LIST      marker);

UINTN UnicodeBSPrintS(
	CHAR16         *startOfBuffer,
	UINTN           bufferSize,
	CONST CHAR16   *formatString,
	BASE_LIST       marker);
#endif

#endif
