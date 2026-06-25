/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_sriov.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_SRIOV_H
#define HINIC5_SRIOV_H
#include <linux/types.h>
#include <linux/pci.h>

#include "hinic5_bus.h"

#if !(defined(HAVE_SRIOV_CONFIGURE) || defined(HAVE_RHEL6_SRIOV_CONFIGURE) || \
    defined(__WIN__) || defined(__VMWARE__))
ssize_t hinic5_sriov_totalvfs_show(struct device *dev,
				   struct device_attribute *attr, char *buf);
ssize_t hinic5_sriov_numvfs_show(struct device *dev,
				 struct device_attribute *attr, char *buf);
ssize_t hinic5_sriov_numvfs_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count);
#endif /* !(HAVE_SRIOV_CONFIGURE || HAVE_RHEL6_SRIOV_CONFIGURE || __WIN__ || __VMWARE__) */

struct hinic5_sriov_info *hinic5_get_sriov_info_by_pcidev(struct pci_dev *pdev);
int hinic5_pci_sriov_disable(struct pci_dev *dev);
int hinic5_pci_sriov_enable(struct pci_dev *dev, int num_vfs);
void hinic5_pci_sriov_enable_ops(struct hinic5_adev *adev, int num_vfs);
int hinic5_pci_sriov_configure(struct pci_dev *dev, int num_vfs);
#endif
