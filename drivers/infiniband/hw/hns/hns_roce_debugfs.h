/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifndef __HNS_ROCE_DEBUGFS_H
#define __HNS_ROCE_DEBUGFS_H

void hns_roce_init_debugfs(void);
void hns_roce_cleanup_debugfs(void);
void hns_roce_register_debugfs(struct hns_roce_dev *hr_dev);
void hns_roce_unregister_debugfs(struct hns_roce_dev *hr_dev);
void hns_roce_register_uctx_debugfs(struct hns_roce_dev *hr_dev,
				    struct hns_roce_ucontext *uctx);
void hns_roce_unregister_uctx_debugfs(struct hns_roce_dev *hr_dev,
				      struct hns_roce_ucontext *uctx);

#endif
