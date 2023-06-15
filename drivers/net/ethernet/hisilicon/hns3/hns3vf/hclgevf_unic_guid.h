/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2023 Hisilicon Limited.

#ifndef __HCLGEVF_UNIC_GUID_H
#define __HCLGEVF_UNIC_GUID_H

#include <linux/types.h>

#include "ubl.h"

int hclgevf_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid);
int hclgevf_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid);

#endif
