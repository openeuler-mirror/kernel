/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef __HCLGE_UNIC_ADDR_H
#define __HCLGE_UNIC_ADDR_H

#include "hnae3.h"

int hclge_unic_add_addr(struct hnae3_handle *handle, const unsigned char *addr,
			enum hnae3_unic_addr_type addr_type);
int hclge_unic_rm_addr(struct hnae3_handle *handle, const unsigned char *addr,
		       enum hnae3_unic_addr_type addr_type);

#endif
