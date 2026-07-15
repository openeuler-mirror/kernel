/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_bus.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_BUS_H
#define HINIC5_BUS_H
#include <linux/types.h>
#include <linux/pci.h>

struct hinic5_adev;

struct hinic5_bus_ops {
	bool (*is_virtfn)(struct hinic5_adev *adev);
	struct hinic5_adev *(*get_pf_adev)(struct hinic5_adev *adev);
	int (*set_func_en)(struct hinic5_adev *dst_adev, bool en, u16 vf_func_id);
	struct hinic5_adev *(*get_vf_adev_by_pf)(struct hinic5_adev *adev, u16 func_id);
	u16 (*get_device_id)(struct hinic5_adev *adev);
	int (*irq_vectors_alloc)(struct hinic5_adev *adev, void *entry, u32 irqs_min, u32 irqs_num);
	void (*irq_vectors_free)(struct hinic5_adev *adev);
	int (*irq_vector)(struct hinic5_adev *adev, u32 idx);
	int (*get_vf_num)(struct hinic5_adev *adev);
	int (*init_device_info)(struct hinic5_adev *adev);
	void (*virt_configure)(struct hinic5_adev *adev, int nums);
	void (*fault_process)(struct hinic5_adev *adev);
};

enum hinic5_sriov_state {
	HINIC5_SRIOV_DISABLE,
	HINIC5_SRIOV_ENABLE,
	HINIC5_FUNC_PERSENT,
};

struct hinic5_sriov_info {
	bool sriov_enabled;
	unsigned int num_vfs;
	ulong state;
	unsigned short first_ue_idx;    /* ubus first vf ue_idx under current pf */
};

bool hinic5_adev_is_virtfn(struct hinic5_adev *adev);
struct hinic5_adev *hinic5_adev_get_pf_adev(struct hinic5_adev *adev);
struct hinic5_adev *hinic5_get_vf_adev_by_pf(struct hinic5_adev *adev, u16 func_id);
int hinic5_set_func_en(struct hinic5_adev *adev, bool en, u16 vf_func_id);
int hinic5_adev_get_vf_num(struct hinic5_adev *adev);
u16 hinic5_adev_get_device_id(struct hinic5_adev *adev);

#ifndef __UEFI__
int hinic5_adev_irq_vectors_alloc(struct hinic5_adev *adev,
				  void *entry, u32 irqs_min, u32 irqs_num);
void hinic5_adev_irq_vectors_free(struct hinic5_adev *adev);
int hinic5_adev_irq_vector(struct hinic5_adev *adev, u32 idx);
#endif

struct hinic5_bus_ops *hinic5_get_dev_ops(struct hinic5_adev *adev);
int hinic5_register_driver(void);
void hinic5_unregister_driver(void);

void *hinic5_get_hwdev_by_pcidev(struct pci_dev *pdev);
#endif
