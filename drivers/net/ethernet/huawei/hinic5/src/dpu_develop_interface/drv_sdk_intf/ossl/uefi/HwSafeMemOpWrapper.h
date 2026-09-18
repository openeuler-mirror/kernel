/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : HwSafeMemOpWrapper.h
 * Version       : Initial Draft
 * Created       : 2018/12/10
 * Last Modified : 2026/09/16
 * Description   : Huawei safe memory operation function define
 */

#ifndef HW_SAFE_MEM_OP_WRAPPER_H
#define HW_SAFE_MEM_OP_WRAPPER_H

EFI_STATUS MemCpyS(
	void *dest,
	UINTN destMax,
	const void *src,
	UINTN count);

EFI_STATUS MemSetS(
	void *dest,
	UINTN destMax,
	UINT8 c,
	UINTN count);

EFI_STATUS MemMoveS(
	void *dest,
	UINTN destMax,
	const void *src,
	UINTN count);

#endif
