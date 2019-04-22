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

#ifndef __HI_LBC_H__
#define __HI_LBC_H__

/**
 * lbc_read8 - read a register byte data through lbc
 * @index: cs index
 * @offset: register offset
 * @value: register byte data
 * return 0 - success, negative - fail
 */

int lbc_read8(unsigned int index, unsigned int offset, unsigned char *value);

/**
 * lbc_write8 - write a register byte data through lbc
 * @index: cs index
 * @offset: register offset
 * @data: register byte data
 * return 0 - success, negative - fail
 */
int lbc_write8(unsigned int index, unsigned int offset, unsigned char data);

/**
 * lbc_read8_nolock - read a register byte data through lbc(no lock)
 * @index: cs index
 * @offset: register offset
 * @value: register byte data
 * return 0 - success, negative - fail
 */
int lbc_read8_nolock(unsigned int index, unsigned int offset, unsigned char *value);

/**
 * lbc_write8_nolock - write a register byte data through lbc(no lock)
 * @index: cs index
 * @offset: register offset
 * @value: register byte data
 * return 0 - success, negative - fail
 */
int lbc_write8_nolock(unsigned int index, unsigned int offset, unsigned char data);

#endif
