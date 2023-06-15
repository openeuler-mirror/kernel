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

#ifndef __HCLGE_COMM_UNIC_ADDR_H
#define __HCLGE_COMM_UNIC_ADDR_H

#include <linux/types.h>

#include "ubl.h"
#include "hclge_comm_cmd.h"

#define HCLGE_COMM_MGUID_PREFIX_LEN		14

#define HCLGE_COMM_FUNC_GUID_ENTRY_VALID_EN	0x01

struct hclge_comm_func_guid_cmd {
	u8 entry_vld	 : 1;
	u8 lookup_enable : 1;
	u8 rsv0		 : 6;
	u8 rsv1;
	__le16 rsv2;
	/* use big endian here */
	u8 guid[UBL_ALEN];
	__le16 hit_info;
	__le16 rsv3;
};

int hclge_comm_unic_set_func_guid(struct hclge_comm_hw *hw, u8 *guid);
int hclge_comm_unic_get_func_guid(struct hclge_comm_hw *hw, u8 *guid);
void hclge_comm_unic_rm_func_guid(struct hclge_comm_hw *hw);

#endif
