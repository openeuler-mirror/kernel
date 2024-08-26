/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2024-2024 Hisilicon Limited.
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

#ifndef __HCLGE_UNIC_DEBUGFS_H
#define __HCLGE_UNIC_DEBUGFS_H

#include "hclge_main.h"

int hclge_dbg_dump_ip_spec(struct hclge_dev *hdev, char *buf, int len);
int hclge_dbg_dump_guid_spec(struct hclge_dev *hdev, char *buf, int len);
int hclge_dbg_dump_ip_list(struct hclge_dev *hdev, char *buf, int len);
int hclge_dbg_dump_guid_list(struct hclge_dev *hdev, char *buf, int len);
int hclge_dbg_dump_fastpath_info(struct hclge_dev *hdev, char *buf, int len);

#endif
