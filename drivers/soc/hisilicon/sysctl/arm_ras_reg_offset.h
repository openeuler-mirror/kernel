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

#ifndef __ARM_RAS_REG_OFFSET_H__
#define __ARM_RAS_REG_OFFSET_H__

/* ARM_RAS Base address of Module's Register */
#define ARM_ARM_RAS_BASE (0x0)

/******************************************************************************/
/*					  xxx ARM_RAS Registers' Definitions */
/******************************************************************************/

#define ARM_ARM_RAS_ARER_ERR_FR_L_REG (ARM_ARM_RAS_BASE + 0x0)
#define ARM_ARM_RAS_ARER_ERR_FR_H_REG (ARM_ARM_RAS_BASE + 0x4)
#define ARM_ARM_RAS_ARER_ERR_CTLR_L_REG (ARM_ARM_RAS_BASE + 0x8)
#define ARM_ARM_RAS_ARER_ERR_CTLR_H_REG (ARM_ARM_RAS_BASE + 0xC)
#define ARM_ARM_RAS_ARER_ERR_STATUS_L_REG (ARM_ARM_RAS_BASE + 0x10)
#define ARM_ARM_RAS_ARER_ERR_STATUS_H_REG (ARM_ARM_RAS_BASE + 0x14)
#define ARM_ARM_RAS_ARER_ERR_ADDR_L_REG (ARM_ARM_RAS_BASE + 0x18)
#define ARM_ARM_RAS_ARER_ERR_ADDR_H_REG (ARM_ARM_RAS_BASE + 0x1C)
#define ARM_ARM_RAS_ARER_ERR_MISC0_L_REG (ARM_ARM_RAS_BASE + 0x20)
#define ARM_ARM_RAS_ARER_ERR_MISC0_H_REG (ARM_ARM_RAS_BASE + 0x24)
#define ARM_ARM_RAS_ARER_ERR_MISC1_L_REG (ARM_ARM_RAS_BASE + 0x28)
#define ARM_ARM_RAS_ARER_ERR_MISC1_H_REG (ARM_ARM_RAS_BASE + 0x2C)

#endif
