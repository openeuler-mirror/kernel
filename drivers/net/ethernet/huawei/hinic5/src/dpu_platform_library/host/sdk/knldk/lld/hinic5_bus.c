/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_bus.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include "ossl_knl.h"
#include "hinic5_hwdev.h"
#include "hinic5_pcie.h"
#ifdef __UBUS_DRIVER__
#include "hinic5_ubus.h"
#endif
#include "hinic5_bus.h"

#ifdef __UBUS_DRIVER__
static struct hinic5_bus_ops g_ubus_ops = {
	.is_virtfn = hinic5_ubus_is_virtfn,
	.get_pf_adev = hinic5_ubus_get_pf_adev,
	.set_func_en = hinic5_ubus_set_func_en,
	.get_vf_adev_by_pf = hinic5_ubus_get_vf_adev_by_pf,
	.get_device_id = hinic5_ubus_get_device_id,
	.irq_vectors_alloc = hinic5_ubus_irq_vectors_alloc,
	.irq_vectors_free = hinic5_ubus_irq_vectors_free,
	.get_vf_num = hinic5_ubus_get_vf_num,
	.irq_vector = hinic5_ubus_irq_vector,
	.init_device_info = hinic5_ub_init_device_info,
	.virt_configure = hinic5_ubus_numvds_store_vds_process,
	.fault_process = hinic5_ubus_probe_fault_process,
};
#endif

static struct hinic5_bus_ops g_pcie_ops = {
	.is_virtfn = hinic5_pci_is_virtfn,
	.get_pf_adev = hinic5_pdev_get_pf_adev,
	.set_func_en = hinic5_pci_set_func_en,
	.get_vf_adev_by_pf = hinic5_pci_get_vf_adev_by_pf,
	.get_device_id = hinic5_pci_get_device_id,
	.irq_vectors_alloc = hinic5_pci_irq_vectors_alloc,
	.irq_vectors_free = hinic5_pci_irq_vectors_free,
	.get_vf_num = hinic5_pci_get_vf_num,
	.irq_vector = hinic5_pci_irq_vector,
	.init_device_info = hinic5_pci_init_device_info,
	.virt_configure = hinic5_pci_sriov_enable_ops,
	.fault_process = hinic5_pci_probe_fault_process,
};

struct hinic5_bus_ops *hinic5_get_dev_ops(struct hinic5_adev *adev)
{
	switch (adev->lld_dev.dev_type) {
	case HINIC5_DEVICE_T_PCI:
		return &g_pcie_ops;
#ifdef __UBUS_DRIVER__
	case HINIC5_DEVICE_T_UB:
		return &g_ubus_ops;
#endif
	default:
		break;
	}
	sdk_err(adev->dev, "Failed to get valid struct hinic5_bus_ops object, dev_type=%d\n",
		adev->lld_dev.dev_type);
	return NULL;
}

/*
 * SDK driver needs to support both UB and PCI scenarios, ub and pci drivers need to register
 */
int hinic5_register_driver(void)
{
	int err;

	err = hinic5_pci_register_driver();
	if (err != 0)
		return err;

#ifdef __UBUS_DRIVER__
	err = hinic5_ubus_register_driver();
	if (err != 0) {
		hinic5_pci_unregister_driver();
		return err;
	}
#endif
	return 0;
}

void hinic5_unregister_driver(void)
{
	hinic5_pci_unregister_driver();
#ifdef __UBUS_DRIVER__
	hinic5_ubus_unregister_driver();
#endif
}

/**
 * @brief Determine if the current device is a VF type
 * @param adev Device adapter layer structure pointer
 * @details vf is considered as pf in a virtual machine, that is
			vf in host -- return 1
			vf in vm   -- return 0
 *
 * @return 0 for PF, 1 for VF
 */
bool hinic5_adev_is_virtfn(struct hinic5_adev *adev)
{
	return adev->bus_ops->is_virtfn(adev);
}

struct hinic5_adev *hinic5_adev_get_pf_adev(struct hinic5_adev *adev)
{
	return adev->bus_ops->get_pf_adev(adev);
}

int hinic5_set_func_en(struct hinic5_adev *adev, bool en, u16 vf_func_id)
{
	return adev->bus_ops->set_func_en(adev, en, vf_func_id);
}

struct hinic5_adev *hinic5_get_vf_adev_by_pf(struct hinic5_adev *adev, u16 func_id)
{
	return adev->bus_ops->get_vf_adev_by_pf(adev, func_id);
}

int hinic5_adev_get_vf_num(struct hinic5_adev *adev)
{
	return adev->bus_ops->get_vf_num(adev);
}
EXPORT_SYMBOL(hinic5_adev_get_vf_num);

u16 hinic5_adev_get_device_id(struct hinic5_adev *adev)
{
	if (!adev || !adev->bus_ops->get_device_id) {
		pr_err("get_device_id is null\n");
		return 0;
	}

	return adev->bus_ops->get_device_id(adev);
}

int hinic5_adev_irq_vectors_alloc(struct hinic5_adev *adev, void *entry, u32 irqs_min, u32 irqs_num)
{
	return adev->bus_ops->irq_vectors_alloc(adev, entry, irqs_min, irqs_num);
}

void hinic5_adev_irq_vectors_free(struct hinic5_adev *adev)
{
	return adev->bus_ops->irq_vectors_free(adev);
}

int hinic5_adev_irq_vector(struct hinic5_adev *adev, u32 idx)
{
	return adev->bus_ops->irq_vector(adev, idx);
}
