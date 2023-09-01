/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2023 Hisilicon Limited.

#ifndef __HCLGE_UNIC_GUID_H
#define __HCLGE_UNIC_GUID_H

#include <linux/types.h>

#include "hclge_mbx.h"

struct hclge_dev;

int hclge_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid);
int hclge_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid);
void hclge_unic_rm_func_guid(struct hclge_dev *hdev);

#endif
