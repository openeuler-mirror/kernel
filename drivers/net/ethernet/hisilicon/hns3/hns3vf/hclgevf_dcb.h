/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2024 Hisilicon Limited.

#ifndef __HCLGEVF_DCB_H__
#define __HCLGEVF_DCB_H__

#include "hclgevf_main.h"

#ifdef CONFIG_HNS3_DCB
void hclgevf_dcb_init(struct hclgevf_dev *hdev);
int hclgevf_tx_ring_tc_config(struct hclgevf_dev *hdev);
void hclgevf_update_tc_info(struct hclgevf_dev *hdev);

#else
static inline void hclgevf_dcb_init(struct hclgevf_dev *hdev) {}
static inline int hclgevf_tx_ring_tc_config(struct hclgevf_dev *hdev)
{
	return 0;
}

static inline void hclgevf_update_tc_info(struct hclgevf_dev *hdev) {}
#endif

#endif /* __HCLGEVF_DCB_H__ */
