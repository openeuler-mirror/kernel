/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2023 Hisilicon Limited.

#ifndef __HCLGEVF_UNIC_GUID_H
#define __HCLGEVF_UNIC_GUID_H

#include <linux/types.h>

#include "ubl.h"

void hclgevf_unic_sync_mc_guid_list(struct hclgevf_dev *hdev);
void hclgevf_unic_uninit_mc_guid_list(struct hclgevf_dev *hdev);
int hclgevf_unic_update_guid_list(struct hnae3_handle *handle,
				  enum HCLGE_COMM_ADDR_NODE_STATE state,
				  const unsigned char *addr);
void hclgevf_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid);
int hclgevf_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid);

#endif
