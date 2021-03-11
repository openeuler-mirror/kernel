/* SPDX-License-Identifier: GPL-2.0+
 * Copyright (c) 2018-2021 Hisilicon Limited.
 */

#ifndef __HCLGE_SYSFS_H
#define __HCLGE_SYSFS_H

void hclge_reset_pf_rate(struct hclge_dev *hdev);
int hclge_resume_pf_rate(struct hclge_dev *hdev);

void hclge_sysfs_init(struct hnae3_handle *handle);
void hclge_sysfs_uninit(struct hnae3_handle *handle);

#endif
