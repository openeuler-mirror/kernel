/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UDMA_JFC_H
#define _UDMA_JFC_H

#include "hns3_udma_device.h"
static inline uint8_t get_jfc_bankid(uint64_t cqn)
{
	/* The lower 2 bits of CQN are used to hash to different banks */
	return (uint8_t)(cqn & GENMASK(1, 0));
}

#endif /* _UDMA_JFC_H */
