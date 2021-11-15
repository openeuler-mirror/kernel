/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kabi.h - openEuler kABI abstraction header
 *
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef _LINUX_KABI_H
#define _LINUX_KABI_H

/*
 * Macro for Reserving KABI padding for base data structs before KABI freeze.
 */

#define KABI_RESERVE(n)		unsigned long kabi_reserved##n;

#endif /* _LINUX_KABI_H */
