/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_pcie.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <net/addrconf.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/inetdevice.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/aer.h>
#include <linux/debugfs.h>

#include "ossl_knl.h"
#include "hinic5_mt.h"
#include "hinic5_common.h"
#include "hinic5_crm.h"
#include "hinic5_id_tbl.h"
#include "hinic5_sriov.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_nictool.h"
#include "hinic5_hw.h"
#include "hinic5_hinic5_vram.h"
#include "hinic5_fast_msg_init.h"
#include "hinic5_lld.h"
#include "hinic5_lld_private.h"
#include "hinic5_profile.h"
#include "hinic5_hwdev.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_prof_adap.h"
#include "hinic5_fw_update.h"
#include "mpu_inband_cmd_defs.h"
#include "hinic5_bus.h"
#include "hinic5_sysfs.h"
#include "hinic5_pcie.h"

#define HINIC5_VF_TIMER_DISABLE_MAX_TIMEOUT   50  /* 50 mseconds */
#define HINIC5_VF_TIMER_DISABLE_WAIT_TIME     5   /* 5 mseconds */
#define HINIC5_VF_NOTIFY_FLR_BIT       BIT(17)
#define HINIC5_PF_HOST_MPU_NOTIFY_BIT  BIT(31)
#define HINIC5_VF_FUNC_ATTRIBUTE6_OFFSET 0x2018
#define HINIC5_PF_HOST_MPU_NOTIFY_OFFSET 0x60C0

typedef struct vf_offset_info {
	u8 valid;
	u16 vf_offset_from_pf[CMD_MAX_MAX_PF_NUM];
} VF_OFFSET_INFO_S;

static VF_OFFSET_INFO_S g_vf_offset;
static DEFINE_MUTEX(g_vf_offset_lock);

static struct attribute *hinic5_attributes[] = {
#if !(defined(HAVE_SRIOV_CONFIGURE) || defined(HAVE_RHEL6_SRIOV_CONFIGURE))
	&dev_attr_sriov_numvfs.attr,
	&dev_attr_sriov_totalvfs.attr,
#endif /* !(HAVE_SRIOV_CONFIGURE || HAVE_RHEL6_SRIOV_CONFIGURE) */
	NULL
};

static const struct attribute_group hinic5_attr_group = {
	.attrs		= hinic5_attributes,
};

static int mapping_bar(struct pci_dev *pdev,
		       struct hinic5_adev *adev)
{
	int cfg_bar;

	cfg_bar = HINIC5_IS_VF_DEV(hinic5_adev_get_device_id(adev)) ?
			HINIC5_VF_PCI_CFG_REG_BAR : HINIC5_PF_PCI_CFG_REG_BAR;

	adev->cfg_base_phy = pci_resource_start(pdev, cfg_bar);
	adev->cfg_base_len = pci_resource_len(pdev, cfg_bar);
	adev->cfg_reg_base = pci_ioremap_bar(pdev, cfg_bar);
	if (!adev->cfg_reg_base) {
		sdk_err(&pdev->dev,
			"Failed to map configuration regs\n");
		return -ENOMEM;
	}

	adev->intr_reg_base = pci_ioremap_bar(pdev, HINIC5_PCI_INTR_REG_BAR);
	if (!adev->intr_reg_base) {
		sdk_err(&pdev->dev,
			"Failed to map interrupt regs\n");
		goto map_intr_bar_err;
	}

	if (!HINIC5_IS_VF_DEV(hinic5_adev_get_device_id(adev))) {
		adev->mgmt_base_phy = pci_resource_start(pdev, HINIC5_PCI_MGMT_REG_BAR);
		adev->mgmt_base_len = pci_resource_len(pdev, HINIC5_PCI_MGMT_REG_BAR);
		adev->mgmt_reg_base =
			pci_ioremap_bar(pdev, HINIC5_PCI_MGMT_REG_BAR);
		if (!adev->mgmt_reg_base) {
			sdk_err(&pdev->dev,
				"Failed to map mgmt regs\n");
			goto map_mgmt_bar_err;
		}
	}

	adev->db_base_phy = pci_resource_start(pdev, HINIC5_PCI_DB_BAR);
	adev->db_dwqe_len = pci_resource_len(pdev, HINIC5_PCI_DB_BAR);
	adev->db_base = pci_ioremap_bar(pdev, HINIC5_PCI_DB_BAR);
	if (!adev->db_base) {
		sdk_err(&pdev->dev,
			"Failed to map doorbell regs\n");
		goto map_db_err;
	}

	return 0;

map_db_err:
	if (!HINIC5_IS_VF_DEV(hinic5_adev_get_device_id(adev)))
		iounmap(adev->mgmt_reg_base);

map_mgmt_bar_err:
	iounmap(adev->intr_reg_base);

map_intr_bar_err:
	iounmap(adev->cfg_reg_base);

	return -ENOMEM;
}

static void unmapping_bar(struct hinic5_adev *adev)
{
	iounmap(adev->db_base);

	if (!HINIC5_IS_VF_DEV(hinic5_adev_get_device_id(adev)))
		iounmap(adev->mgmt_reg_base);

	iounmap(adev->intr_reg_base);
	iounmap(adev->cfg_reg_base);
}

static int hinic5_pci_init(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = NULL;
	int err;

	adev = kzalloc(sizeof(*adev), GFP_KERNEL);
	if (!adev)
		return -ENOMEM;
	adev->dev = &pdev->dev;
	adev->bus_dev = pdev;
	mutex_init(&adev->adev_mutex);

	pci_set_drvdata(pdev, adev);

	err = pci_enable_device(pdev);
	if (err != 0) {
		sdk_err(&pdev->dev, "Failed to enable PCI device\n");
		goto pci_enable_err;
	}

	err = pci_request_regions(pdev, HINIC5_DRV_NAME);
	if (err != 0) {
		sdk_err(&pdev->dev, "Failed to request regions\n");
		goto pci_regions_err;
	}

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);

	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64)); /* 64 bit DMA mask */
	if (err != 0) {
		sdk_warn(&pdev->dev, "Couldn't set 64-bit DMA mask\n");
		err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32)); /* 32 bit DMA mask */
		if (err != 0) {
			sdk_err(&pdev->dev, "Failed to set DMA mask\n");
			goto dma_mask_err;
		}
	}

	err = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64)); /* 64 bit DMA mask */
	if (err != 0) {
		sdk_warn(&pdev->dev, "Couldn't set 64-bit coherent DMA mask\n");
		err = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32)); /* 32 bit DMA mask */
		if (err != 0) {
			sdk_err(&pdev->dev, "Failed to set coherent DMA mask\n");
			goto dma_consistnet_mask_err;
		}
	}

	return 0;

dma_consistnet_mask_err:
dma_mask_err:
	pci_clear_master(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_release_regions(pdev);

pci_regions_err:
	pci_disable_device(pdev);

pci_enable_err:
	pci_set_drvdata(pdev, NULL);
	kfree(adev);

	return err;
}

static void hinic5_pci_deinit(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = pci_get_drvdata(pdev);

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(adev);
}

static int hinic5_remove_func(struct hinic5_adev *adev)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	mutex_lock(&adev->adev_mutex);
	if (adev->lld_state != HINIC5_PROBE_OK) {
		sdk_warn(&pdev->dev, "Current function don not need remove\n");
		mutex_unlock(&adev->adev_mutex);
		return 0;
	}
	adev->lld_state = HINIC5_IN_REMOVE;
	mutex_unlock(&adev->adev_mutex);

	hinic5_detect_hw_present(adev->hwdev);

	hisdk5_remove_pre_process(adev->hwdev);

	if (hinic5_func_type(adev->hwdev) != TYPE_VF) {
		sysfs_remove_group(&pdev->dev.kobj, &hinic5_attr_group);
		wait_sriov_cfg_complete(adev);
		hinic5_pci_sriov_disable(pdev);
	}

	hinic5_func_deinit(adev);

	hinic5_lld_lock_chip_node();
	hinic5_free_chip_node(adev);
	hinic5_lld_unlock_chip_node();

	unmapping_bar(adev);

	mutex_lock(&adev->adev_mutex);
	adev->lld_state = HINIC5_NOT_PROBE;
	mutex_unlock(&adev->adev_mutex);

	sdk_info(&pdev->dev, "Pcie device removed function\n");

	return 0;
}

#ifdef CONFIG_PCI_IOV
STATIC int hinic5_get_pf_device_id(struct pci_dev *pdev)
{
	struct pci_dev *pf_dev = pci_physfn(pdev);

	return pf_dev->device;
}
#endif

static int hinic5_get_pf_info(struct hinic5_adev *dev, u16 service,
			      struct hinic5_hw_pf_infos **pf_infos)
{
	int err;

	if (service >= SERVICE_T_MAX) {
		sdk_err(dev->dev, "Current vf do not supports set service_type = %u state in host\n",
			service);
		return -EFAULT;
	}

	pf_infos = kzalloc(sizeof(*pf_infos), GFP_KERNEL);
	if (!pf_infos) {
		sdk_err(dev->dev, "Failed to allocate pf infos\n");
		return -ENOMEM;
	}
	err = hinic5_get_hw_pf_infos(dev->hwdev, *pf_infos, HINIC5_CHANNEL_COMM);
	if (err != 0) {
		kfree(*pf_infos);
		sdk_err(dev->dev, "Get chipf pf info failed, ret %d\n", err);
		return -EFAULT;
	}

	return 0;
}

static int get_vf_service_state_param(struct hinic5_lld_dev *lld_dev, struct hinic5_adev *dev_ptr,
				      u16 service, struct hinic5_hw_pf_infos **pf_infos)
{
	int err;

	if (!lld_dev || !dev_ptr)
		return -EINVAL;

	err = hinic5_get_pf_info(dev_ptr, service, pf_infos);
	if (err != 0)
		return err;

	return 0;
}

static int hinic5_dst_pdev_valid(struct hinic5_adev *dst_dev,  struct pci_dev **des_pdev_ptr,
				 u16 vf_devfn, bool en)
{
	struct pci_dev *pdev = container_of(dst_dev->dev, struct pci_dev, dev);
	u16 bus;

	bus = pdev->bus->number + vf_devfn / BUS_MAX_DEV_NUM;
	*des_pdev_ptr = pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
						    bus, vf_devfn % BUS_MAX_DEV_NUM);
	if (!(*des_pdev_ptr)) {
		pr_err("des_pdev is NULL\n");
		return -EFAULT;
	}

	/* OVS sriov hw scene, when vf bind to vf_io return error. */
	if (!en && (strcmp((*des_pdev_ptr)->driver->name, HINIC5_DRV_NAME) != 0)) {
		pr_err("vf bind driver:%s\n", (*des_pdev_ptr)->driver->name);
		return -EFAULT;
	}

	return 0;
}

static int paramerter_is_unexpected(struct hinic5_adev *dst_dev, u16 *func_id, u16 *vf_start,
				    u16 *vf_end, u16 vf_func_id)
{
	if (hinic5_func_type(dst_dev->hwdev) == TYPE_VF)
		return -EPERM;

	*func_id = hinic5_global_func_id(dst_dev->hwdev);
	*vf_start = hinic5_glb_pf_vf_offset(dst_dev->hwdev) + 1;
	*vf_end = *vf_start + hinic5_func_max_vf(dst_dev->hwdev);
	if (vf_func_id < *vf_start || vf_func_id >= *vf_end)
		return -EPERM;

	return 0;
}

void hinic5_notify_vf_timer_disable(struct pci_dev *pdev)
{
	ulong timeout;
	void __iomem *bar = NULL;
	void __iomem *bar_physfn = NULL;
	struct pci_dev *physfn = NULL;
	u32 val;

	if (!pdev || pdev->vendor != PCI_VENDOR_ID_HUAWEI ||
	    (pdev->device != HINIC5_DEV_ID_VF && pdev->device != HINIC5_DEV_ID_25V1_VF))
		return;

	sdk_warn(&pdev->dev, "Notify vf disable timer bitmap before flr\n");

	/* VF bar space map */
	bar = pci_ioremap_bar(pdev, HINIC5_VF_PCI_CFG_REG_BAR);
	if (!bar) {
		sdk_err(&pdev->dev, "VF bar map failed in vf timer disable\n");
		return;
	}

	/* PF bar space map */
	physfn = pci_physfn(pdev);
	bar_physfn = pci_ioremap_bar(physfn, HINIC5_PCI_MGMT_REG_BAR);
	if (!bar_physfn) {
		sdk_err(&pdev->dev, "PF bar map failed in vf timer disable\n");
		iounmap(bar);
		return;
	}

	/* Set VF FUNC ATTR6 17bit to mark vf before flr */
	val = ioread32be(bar + HINIC5_VF_FUNC_ATTRIBUTE6_OFFSET);
	iowrite32be(val | HINIC5_VF_NOTIFY_FLR_BIT, bar + HINIC5_VF_FUNC_ATTRIBUTE6_OFFSET);

	/* Set PF HOST_MPU_NOTIFY to cause mpu interrupt */
	val = ioread32be(bar_physfn + HINIC5_PF_HOST_MPU_NOTIFY_OFFSET);
	iowrite32be(val | HINIC5_PF_HOST_MPU_NOTIFY_BIT,
		    bar_physfn + HINIC5_PF_HOST_MPU_NOTIFY_OFFSET);

	/* Wait for MPU disable vf timer bitmap */
	timeout = jiffies + msecs_to_jiffies(HINIC5_VF_TIMER_DISABLE_MAX_TIMEOUT);
	do {
		val = ioread32be(bar + HINIC5_VF_FUNC_ATTRIBUTE6_OFFSET);
		if ((val & HINIC5_VF_NOTIFY_FLR_BIT) == 0)
			break;
		msleep(HINIC5_VF_TIMER_DISABLE_WAIT_TIME);
	} while (time_before(jiffies, timeout));

	iounmap(bar_physfn);
	iounmap(bar);
}
EXPORT_SYMBOL(hinic5_notify_vf_timer_disable);

int hinic5_set_vf_service_state(struct hinic5_lld_dev *lld_dev,
				u16 vf_func_id, u16 service, bool en)
{
	struct hinic5_adev *dev = to_hinic5_adev(lld_dev);
	struct hinic5_hw_pf_infos *pf_infos = NULL;
	struct hinic5_adev *dst_dev = NULL;
	struct pci_dev *des_pdev = NULL;
	struct pci_dev *dst_pdev = NULL;
	u16 vf_start, vf_end, vf_devfn, func_id;
	int err;
	bool find_dst_dev = false;

	err = get_vf_service_state_param(lld_dev, dev, service, &pf_infos);
	if (err != 0 || !pf_infos)
		return err;

	hinic5_lld_hold();
	list_for_each_entry(dst_dev, &dev->chip_node->func_list, node) {
		if (paramerter_is_unexpected(dst_dev, &func_id, &vf_start,
					     &vf_end, vf_func_id) != 0)
			continue;

		dst_pdev = container_of(dst_dev->dev, struct pci_dev, dev);
		vf_devfn = pf_infos->infos[func_id].vf_offset + (vf_func_id - vf_start) +
			(u16)dst_pdev->devfn;
		err = hinic5_dst_pdev_valid(dst_dev, &des_pdev, vf_devfn, en);
		if (err != 0) {
			sdk_err(dev->dev, "Can not get vf func_id %u from pf %u\n",
				vf_func_id, func_id);
			hinic5_lld_put();
			goto free_pf_info;
		}

		dst_dev = pci_get_drvdata(des_pdev);
		/* When enable vf scene, if vf bind to vf-io, return ok */
		if ((strcmp(des_pdev->driver->name, HINIC5_DRV_NAME) != 0) ||
		    !dst_dev || (!en && dst_dev->lld_state != HINIC5_PROBE_OK) ||
		    (en && dst_dev->lld_state != HINIC5_NOT_PROBE)) {
			hinic5_lld_put();
			goto free_pf_info;
		}

		if (en)
			pci_dev_put(des_pdev);
		find_dst_dev = true;
		break;
	}
	hinic5_lld_put();

	if (!find_dst_dev) {
		err = -EFAULT;
		sdk_err(dev->dev, "Invalid parameter vf_id %u\n", vf_func_id);
		goto free_pf_info;
	}

	err = hinic5_pci_set_func_en(dst_dev, en, vf_func_id);

free_pf_info:
	if (pf_infos)
		kfree(pf_infos);
	return err;
}
EXPORT_SYMBOL(hinic5_set_vf_service_state);

int hinic5_pci_irq_vectors_alloc(struct hinic5_adev *adev, void *entry, u32 irqs_min, u32 irqs_num)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	return pci_enable_msix_range(pdev, entry, (int)irqs_min, (int)irqs_num);
}

void hinic5_pci_irq_vectors_free(struct hinic5_adev *adev)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	pci_free_irq_vectors(pdev);
}

int hinic5_pci_irq_vector(struct hinic5_adev *adev, u32 idx)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	return pci_irq_vector(pdev, idx);
}

STATIC bool hinic5_get_vf_load_state(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = NULL;
	struct pci_dev *pf_pdev = NULL;

	if (!pdev) {
		pr_err("pdev is null.\n");
		return false;
	}

	/* vf used in vm */
	if (pci_is_root_bus(pdev->bus))
		return false;

	if (pdev->is_virtfn != 0)
		pf_pdev = pdev->physfn;
	else
		pf_pdev = pdev;

	adev = pci_get_drvdata(pf_pdev);
	if (!adev) {
		sdk_err(&pdev->dev, "adev is null.\n");
		return false;
	}

	return !adev->disable_vf_load;
}

struct hinic5_sriov_info *hinic5_get_sriov_info_by_pcidev(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = NULL;

	if (!pdev)
		return NULL;

	adev = pci_get_drvdata(pdev);
	if (!adev)
		return NULL;

	return &adev->sriov_info;
}

void *hinic5_get_hwdev_by_pcidev(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = NULL;

	if (!pdev)
		return NULL;

	adev = pci_get_drvdata(pdev);
	if (!adev)
		return NULL;

	return adev->hwdev;
}

static void hinic5_pci_remove(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = pci_get_drvdata(pdev);

	if (!adev)
		return;

#ifndef __HIFC__
#ifdef CONFIG_PCI_IOV
	if (pdev->is_virtfn != 0 && (hinic5_get_pf_device_id(pdev) == HINIC5_DEV_ID_SDI_6_0_PF) &&
	    hinic5_get_vf_load_state(pdev))
		return;
#endif
#endif

	sdk_info(&pdev->dev, "Pcie device remove begin\n");

	unregister_device_attr_groups(adev);

	hinic5_remove_func(adev);

	hinic5_pci_deinit(pdev);
	hinic5_probe_pre_unprocess(pdev);

	sdk_info(&pdev->dev, "Pcie device removed\n");
}

#if (defined CONFIG_ARM) || (defined CONFIG_ARM64)
/* Mask the PCI_ERR_UNC_COMP_ABORT to prevent PF from handling Completer Aborts
 * from the VF. On ARM platforms, Completer Aborts may occur when a VF try to
 * write a non-accessible address.
 */
static void hinic5_mask_aer_comp_abort(struct pci_dev *pdev)
{
	u32 err_mask;
	int pos;

	struct pci_dev *rp = pcie_find_root_port(pdev);

	if (!rp) {
		sdk_warn(&pdev->dev, "Cannot find root port.\n");
		return;
	}

	pos = pci_find_ext_capability(rp, PCI_EXT_CAP_ID_ERR);
	if (!pos) {
		sdk_err(&pdev->dev, "AER capability is not found in PCIe config space.\n");
		return;
	}

	pci_read_config_dword(rp, pos + PCI_ERR_UNCOR_MASK, &err_mask);
	err_mask |= PCI_ERR_UNC_COMP_ABORT;
	pci_write_config_dword(rp, pos + PCI_ERR_UNCOR_MASK, err_mask);
}
#endif

static int hinic5_probe_func(struct hinic5_adev *adev)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);
	int err;

	err = probe_func_param_init(adev);
	if (err == -EEXIST)
		return 0;
	else if (err != 0)
		return err;

	err = mapping_bar(pdev, adev);
	if (err != 0) {
		sdk_err(&pdev->dev, "Failed to map bar\n");
		goto map_bar_failed;
	}

	/* if chip information of pcie function exist, add the function into chip */
	hinic5_lld_lock_chip_node();
	err = hinic5_alloc_chip_node(adev);
	if (err != 0) {
		hinic5_lld_unlock_chip_node();
		sdk_err(&pdev->dev, "Failed to add new chip node to global list\n");
		goto alloc_chip_node_fail;
	}
	hinic5_lld_unlock_chip_node();

	err = hinic5_func_init(adev);
	if (err != 0)
		goto func_init_err;

#if (defined CONFIG_ARM) || (defined CONFIG_ARM64)
	/* Prevent PF from being in an abnormal state
	 * due to illegal memory access by its VF.
	 */
	if (hinic5_func_type(adev->hwdev) == TYPE_PPF) {
		if (!hinic5_in_spu(adev->hwdev))
			hinic5_mask_aer_comp_abort(pdev);
	}
#endif /* ARM */

	if (hinic5_func_type(adev->hwdev) != TYPE_VF) {
		err = sysfs_create_group(&pdev->dev.kobj, &hinic5_attr_group);
		if (err != 0) {
			sdk_err(&pdev->dev, "Failed to create sysfs group\n");
			goto create_sysfs_err;
		}

		err = hinic5_set_bdf_ctxt(adev->hwdev, pdev->bus->number,
					  PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
		if (err != 0) {
			sdk_err(&pdev->dev, "Failed to set BDF info to MPU\n");
			sysfs_remove_group(&pdev->dev.kobj, &hinic5_attr_group);
			goto set_bdf_err;
		}
	}

	hinic5_probe_success(adev->hwdev);

	mutex_lock(&adev->adev_mutex);
	adev->lld_state = HINIC5_PROBE_OK;
	mutex_unlock(&adev->adev_mutex);

	return 0;

set_bdf_err:
create_sysfs_err:
	hinic5_func_deinit(adev);

func_init_err:
	hinic5_lld_lock_chip_node();
	hinic5_free_chip_node(adev);
	hinic5_lld_unlock_chip_node();

alloc_chip_node_fail:
	unmapping_bar(adev);

map_bar_failed:
	sdk_err(&pdev->dev, "Pcie device probe function failed\n");
	return err;
}

bool hinic5_pci_is_virtfn(struct hinic5_adev *adev)
{
#ifdef CONFIG_PCI_IOV
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	return (bool)(pdev->is_virtfn);
#else
	return false;
#endif
}

int hinic5_pci_get_vf_num(struct hinic5_adev *adev)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	return pci_num_vf(pdev);
}

int hinic5_pci_init_device_info(struct hinic5_adev *adev)
{
	struct hinic5_adev *pf_adev = hinic5_pdev_get_pf_adev(adev);
	struct pci_dev *pdev = to_pci_dev(pf_adev->dev);
	u64 bus_domain_nr = (u64)pci_domain_nr(pdev->bus);

	adev->info.id = (bus_domain_nr << PCI_BUS_NUM_SHIFT) + pdev->bus->number;

	return 0;
}

u16 hinic5_pci_get_device_id(struct hinic5_adev *adev)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	return pdev->device;
}

int hinic5_pci_set_func_en(struct hinic5_adev *dst_adev, bool en, u16 vf_func_id)
{
	struct pci_dev *des_pdev = container_of(dst_adev->dev, struct pci_dev, dev);
	int err;

	mutex_lock(&dst_adev->adev_mutex);
	/* unload invalid vf func id */
	if (!en && vf_func_id != hinic5_global_func_id(dst_adev->hwdev) &&
	    (strcmp(des_pdev->driver->name, HINIC5_DRV_NAME) == 0)) {
		pr_err("dst_adev func id:%u, vf_func_id:%u\n",
		       hinic5_global_func_id(dst_adev->hwdev), vf_func_id);
		mutex_unlock(&dst_adev->adev_mutex);
		return -EFAULT;
	}

	if (!en && dst_adev->lld_state == HINIC5_PROBE_OK) {
		mutex_unlock(&dst_adev->adev_mutex);
		hinic5_remove_func(dst_adev);
	} else if (en && dst_adev->lld_state == HINIC5_NOT_PROBE) {
		mutex_unlock(&dst_adev->adev_mutex);
		err = hinic5_probe_func(dst_adev);
		if (err != 0)
			return -EFAULT;
	} else {
		mutex_unlock(&dst_adev->adev_mutex);
	}

	return 0;
}

struct hinic5_adev *hinic5_pdev_get_pf_adev(struct hinic5_adev *adev)
{
	struct hinic5_adev *pf_adev = NULL;
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	pf_adev = (hinic5_pci_is_virtfn(adev) != 0) ? pci_get_drvdata(pdev->physfn) : adev;
	return pf_adev;
}

static int hinic5_pf_get_vf_offset_info(struct hinic5_adev *des_adev, u16 *vf_offset)
{
	int err, i;
	struct hinic5_hw_pf_infos *pf_infos = NULL;
	u16 pf_func_id;
	struct hinic5_adev *pf_adev = NULL;

	pf_adev = hinic5_pdev_get_pf_adev(des_adev);
	pf_func_id = hinic5_global_func_id(pf_adev->hwdev);
	if (pf_func_id >= CMD_MAX_MAX_PF_NUM || !vf_offset)
		return -EINVAL;

	mutex_lock(&g_vf_offset_lock);
	if (g_vf_offset.valid == 0) {
		pf_infos = kzalloc(sizeof(*pf_infos), GFP_KERNEL);
		if (!pf_infos) {
			err = -ENOMEM;
			goto err_malloc;
		}

		err = hinic5_get_hw_pf_infos(pf_adev->hwdev, pf_infos, HINIC5_CHANNEL_COMM);
		if (err != 0) {
			sdk_warn(pf_adev->dev, "Hinic5_get_hw_pf_infos fail err %d\n", err);
			err = -EFAULT;
			goto err_out;
		}

		g_vf_offset.valid = 1;
		for (i = 0; i < CMD_MAX_MAX_PF_NUM; i++)
			g_vf_offset.vf_offset_from_pf[i] = pf_infos->infos[i].vf_offset;

		kfree(pf_infos);
	}

	*vf_offset = g_vf_offset.vf_offset_from_pf[pf_func_id];

	mutex_unlock(&g_vf_offset_lock);

	return 0;

err_out:
	kfree(pf_infos);
err_malloc:
	mutex_unlock(&g_vf_offset_lock);
	return err;
}

struct hinic5_adev *hinic5_pci_get_vf_adev_by_pf(struct hinic5_adev *adev, u16 func_id)
{
	int err;
	u16 bus_num;
	u16 vf_start, vf_end;
	u16 des_fn, pf_func_id, vf_offset;
	struct hinic5_adev *src_adev = adev;
	struct pci_dev *pdev = container_of(src_adev->dev, struct pci_dev, dev);
	struct pci_dev *dst_vf_pdev = NULL;
	struct hinic5_adev *dst_adev = NULL;

	vf_start = hinic5_glb_pf_vf_offset(src_adev->hwdev);
	vf_end = vf_start + hinic5_func_max_vf(src_adev->hwdev);
	pf_func_id = hinic5_global_func_id(src_adev->hwdev);
	if (func_id <= vf_start || func_id > vf_end || pf_func_id >= CMD_MAX_MAX_PF_NUM)
		return NULL;

	err = hinic5_pf_get_vf_offset_info(src_adev, &vf_offset);
	if (err != 0) {
		sdk_warn(src_adev->dev, "Hinic5_pf_get_vf_offset_info fail\n");
		return NULL;
	}

	des_fn = ((func_id - vf_start) - 1) + pf_func_id + vf_offset;
	bus_num = pdev->bus->number + des_fn / BUS_MAX_DEV_NUM;

	dst_vf_pdev = pci_get_domain_bus_and_slot(0, bus_num, (des_fn % BUS_MAX_DEV_NUM));
	dst_adev = pci_get_drvdata(dst_vf_pdev);
	put_device(dst_adev->dev);
	return dst_adev;
}

STATIC int hinic5_get_vfid_by_vfpci(void *hwdev, struct pci_dev *pdev, u16 *global_func_id)
{
	struct pci_dev *pf_pdev = NULL;
	struct hinic5_adev *adev = NULL;
	u16 pf_bus, vf_bus, vf_offset;
	int err;

	if (!pdev || !global_func_id || pdev->is_virtfn == 0)
		return -EINVAL;

	pf_pdev = pdev->physfn;

	vf_bus = pdev->bus->number;
	pf_bus = pf_pdev->bus->number;

	if (pdev->vendor != HINIC5_VIRTIO_VNEDER_ID) {
		adev = pci_get_drvdata(pf_pdev);
		err = hinic5_pf_get_vf_offset_info(adev, &vf_offset);
		if (err != 0) {
			sdk_err(&pdev->dev, "Func hinic5_pf_get_vf_offset_info fail\n");
			return -EFAULT;
		}
	} else {
		if (g_vf_offset.valid == 0) {
			sdk_err(&pdev->dev, "Pf offset get fail\n");
			return -EFAULT;
		}
	}

	*global_func_id = (u16)((vf_bus - pf_bus) * BUS_MAX_DEV_NUM) + (u16)pdev->devfn +
		(u16)(CMD_MAX_MAX_PF_NUM - g_vf_offset.vf_offset_from_pf[0]);

	return 0;
}

STATIC bool hinic5_get_vf_nic_en_status(struct pci_dev *pdev)
{
	u8 nic_en;
	u16 global_func_id;
	struct pci_dev *pf_pdev = NULL;
	struct hinic5_adev *adev = NULL;

	if (!pdev) {
		pr_err("pdev is null.\n");
		return false;
	}

	if (pdev->is_virtfn != 0)
		pf_pdev = pdev->physfn;
	else
		return false;

	adev = pci_get_drvdata(pf_pdev);
	if (!adev) {
		sdk_err(&pdev->dev, "adev is null.\n");
		return false;
	}

	if (!IS_BMGW_SLAVE_HOST((struct hinic5_hwdev *)adev->hwdev))
		return false;

	if (hinic5_get_vfid_by_vfpci(NULL, pdev, &global_func_id) != 0) {
		sdk_err(&pdev->dev, "Get vf id by vfpci failed\n");
		return false;
	}

	if (hisdk5_get_plug_srv_bitmap(adev->hwdev, COMM_PLUG_SRV_NIC,
	    global_func_id, &nic_en) != 0) {
		sdk_err(&pdev->dev, "Get function nic status failed\n");
		return false;
	}

	sdk_info(&pdev->dev, "Func %hu %s default probe in host\n",
		 global_func_id, (nic_en != 0) ? "enable" : "disable");

	return (nic_en != 0);
}

static int hinic5_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hinic5_adev *adev = NULL;
	u16 probe_fault_level = FAULT_LEVEL_SERIOUS_FLR;
	int err;

	sdk_info(&pdev->dev, "Pcie device probe begin\n");

#ifndef __HIFC__
#ifdef CONFIG_PCI_IOV
	if (pdev->is_virtfn != 0 && (hinic5_get_pf_device_id(pdev) == HINIC5_DEV_ID_SDI_6_0_PF) &&
	    hinic5_get_vf_load_state(pdev)) {
		sdk_info(&pdev->dev, "VFs are not binded to hinic\n");
		return -EINVAL;
	}
#endif
#endif

	err = hinic5_probe_pre_process(pdev);
	if (err == HINIC5_NOT_PROBE)
		return 0;

	if (err != 0)
		goto out;

	err = hinic5_pci_init(pdev);
	if (err != 0)
		goto pci_init_err;

	adev = pci_get_drvdata(pdev);
	adev->disable_vf_load = hinic5_is_disable_vf_load();
	adev->id = *id;
	adev->lld_state = HINIC5_NOT_PROBE;
	adev->probe_fault_level = probe_fault_level;
	adev->lld_dev.dev_type = HINIC5_DEVICE_T_PCI;
	adev->bus_ops = hinic5_get_dev_ops(adev);
	err = adev->bus_ops->init_device_info(adev);
	if (err != 0)
		goto init_device_info_err;
	hinic5_lld_dev_cnt_init(adev);

	if (pdev->is_virtfn != 0 && (!hinic5_get_vf_load_state(pdev)) &&
	    (!hinic5_get_vf_nic_en_status(pdev))) {
		sdk_info(&pdev->dev, "VF device disable load in host\n");
		return 0;
	}

	err = hinic5_probe_func(adev);
	if (err != 0)
		goto hinic5_probe_func_fail;

	err = register_device_attr_groups(adev);
	if (err != 0)
		goto hinic5_register_device_attrs_fail;

	sdk_info(&pdev->dev, "Pcie device probed\n");
	return 0;

hinic5_register_device_attrs_fail:
	hinic5_remove_func(adev);

hinic5_probe_func_fail:
	probe_fault_level = adev->probe_fault_level;

init_device_info_err:
	hinic5_pci_deinit(pdev);

pci_init_err:
	hinic5_probe_pre_unprocess(pdev);

out:
	hinic5_probe_fault_process(pdev, probe_fault_level);
	sdk_err(&pdev->dev, "Pcie device probe failed\n");
	return err;
}

void hinic5_pci_probe_fault_process(struct hinic5_adev *adev)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	hinic5_probe_fault_process(pdev, FAULT_LEVEL_HOST);
}

static const struct pci_device_id hinic5_pci_table[] = {
#ifdef CONFIG_SP_VID_DID
	{PCI_VDEVICE(SPNIC, HINIC5_DEV_ID_STANDARD), 0},
	{PCI_VDEVICE(SPNIC, HINIC5_DEV_ID_SDI_5_1_PF), 0},
	{PCI_VDEVICE(SPNIC, HINIC5_DEV_ID_VF), 0},
#else
	{PCI_VDEVICE(HUAWEI, HINIC5_DEV_ID_72V1_PF), 0},
	{PCI_VDEVICE(HUAWEI, HINIC5_DEV_ID_72V1_VF), 0},
	{PCI_VDEVICE(HUAWEI, HINIC5_DEV_ID_25V1_PF), 0},
	{PCI_VDEVICE(HUAWEI, HINIC5_DEV_ID_25V1_VF), 0},
#endif
	{0,}

};

MODULE_DEVICE_TABLE(pci, hinic5_pci_table);

/**
 * hinic5_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 *
 * Since we only need error detecting not error handling, so we
 * always return PCI_ERS_RESULT_CAN_RECOVER to tell the AER
 * driver that we don't need reset(error handling).
 */
static pci_ers_result_t hinic5_io_error_detected(struct pci_dev *pdev,
						 pci_channel_state_t state)
{
	struct hinic5_adev *adev = NULL;

	sdk_err(&pdev->dev,
		"Uncorrectable error detected, log and cleanup error status: 0x%08x\n",
		state);

	pci_cleanup_aer_uncorrect_error_status(pdev);
	adev = pci_get_drvdata(pdev);
	if (adev)
		hinic5_record_pcie_error(adev->hwdev);

	return PCI_ERS_RESULT_CAN_RECOVER;
}

static void hinic5_pci_shutdown(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = pci_get_drvdata(pdev);

	sdk_info(&pdev->dev, "Shutdown device\n");

	if (adev)
		hinic5_shutdown_hwdev(adev->hwdev);

	pci_disable_device(pdev);

	if (adev)
		hinic5_set_api_stop(adev->hwdev);
}

#ifdef HAVE_PCIE_RESET_DONE
STATIC void hinic5_reset_done(struct pci_dev *pdev)
{
	struct hinic5_adev *adev = pci_get_drvdata(pdev);

	sdk_info(&pdev->dev, "pcie is reset done\n");
	if (adev)
		hinic5_set_api_stop(adev->hwdev);
}
#endif

#ifdef HAVE_RHEL6_SRIOV_CONFIGURE
static struct pci_driver_rh hinic5_driver_rh = {
	.sriov_configure = hinic5_pci_sriov_configure,
};
#endif

/* Cause we only need error detecting not error handling, so only error_detected
 * callback is enough.
 */
static struct pci_error_handlers hinic5_err_handler = {
	.error_detected = hinic5_io_error_detected,
#ifdef HAVE_PCIE_RESET_DONE
	.reset_done     = hinic5_reset_done,
#endif
};

static struct pci_driver hinic5_driver = {
	.name		 = HINIC5_DRV_NAME,
	.id_table	 = hinic5_pci_table,
	.probe		 = hinic5_pci_probe,
	.remove		 = hinic5_pci_remove,
	.shutdown	 = hinic5_pci_shutdown,
#if defined(HAVE_SRIOV_CONFIGURE)
	.sriov_configure = hinic5_pci_sriov_configure,
#elif defined(HAVE_RHEL6_SRIOV_CONFIGURE)
	.rh_reserved = &hinic5_driver_rh,
#endif
	.err_handler	 = &hinic5_err_handler,
#if (KERNEL_VERSION(3, 10, 0) != LINUX_VERSION_CODE)
	.groups          = hisdk5_driver_attr_groups,
#endif
};

int hinic5_pci_register_driver(void)
{
	return pci_register_driver(&hinic5_driver);
}

void hinic5_pci_unregister_driver(void)
{
	pci_unregister_driver(&hinic5_driver);
}
