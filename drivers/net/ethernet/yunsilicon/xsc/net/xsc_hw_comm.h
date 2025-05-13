/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_HW_COMMON_H
#define XSC_HW_COMMON_H

int xsc_hw_kernel_call(struct xsc_core_device *xdev, u16 opcode, void *req, void *rsp);

#endif
