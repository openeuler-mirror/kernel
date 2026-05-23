/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_pcie.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_PCIE_H
#define HINIC5_PCIE_H
#include <linux/types.h>
#include <linux/pci.h>
#include "hinic5_dev_mgmt.h"

#define PCI_BUS_NUM_SHIFT  8
#define BUS_MAX_DEV_NUM 256

int hinic5_pci_register_driver(void);
void hinic5_pci_unregister_driver(void);
bool hinic5_pci_is_virtfn(struct hinic5_adev *adev);
struct hinic5_adev *hinic5_pdev_get_pf_adev(struct hinic5_adev *adev);
int hinic5_pci_set_func_en(struct hinic5_adev *dst_adev, bool en, u16 vf_func_id);
int hinic5_pci_get_vf_num(struct hinic5_adev *adev);
u16 hinic5_pci_get_device_id(struct hinic5_adev *adev);
struct hinic5_adev *hinic5_pci_get_vf_adev_by_pf(struct hinic5_adev *adev, u16 func_id);
int hinic5_pci_irq_vectors_alloc(struct hinic5_adev *adev, void *entry, u32 irqs_min, u32 irqs_num);
void hinic5_pci_irq_vectors_free(struct hinic5_adev *adev);
int hinic5_pci_irq_vector(struct hinic5_adev *adev, u32 idx);
int hinic5_pci_init_device_info(struct hinic5_adev *adev);
void hinic5_pci_probe_fault_process(struct hinic5_adev *adev);
#endif
