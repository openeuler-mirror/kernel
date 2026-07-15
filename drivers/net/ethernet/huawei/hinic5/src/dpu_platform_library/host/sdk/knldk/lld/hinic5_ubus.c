/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ubus.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifdef __UBUS_DRIVER__
#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt
#include <net/addrconf.h>
#include <linux/kernel.h>
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
#ifdef UB_SUPPORT_ENTITY
#include <linux/mod_devicetable.h>
#endif

#include "ossl_knl.h"
#include "hinic5_mt.h"
#include "hinic5_common.h"
#include "hinic5_crm.h"
#include "hinic5_ubus_sriov.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_nictool.h"
#include "hinic5_hw.h"
#include "hinic5_hinic5_vram.h"
#include "hinic5_fast_msg_init.h"
#include "hinic5_lld.h"
#include "hinic5_lld_private.h"
#include "hinic5_id_tbl.h"
#include "hinic5_ubus.h"
#include "hinic5_bus.h"

#include "hinic5_hwdev.h"
#include "hinic5_profile.h"
#include "hinic5_prof_adap.h"
#include "hinic5_fw_update.h"
#include "mpu_inband_cmd_defs.h"
#include "hinic5_sysfs.h"

static u8 ubus_dma_bit_mask = HINIC5_UBUS_DMA_BIT_MASK_DEFAULT;
module_param(ubus_dma_bit_mask, byte, 0444);
MODULE_PARM_DESC(ubus_dma_bit_mask, "ubus dma addr bit mask - default is 48");

static enum ubus_device_type ubus_get_device_type(hinic_ub_dev *ubus_dev)
{
	if (HINIC_UB_GET_DEVICE_ID(ubus_dev) == HINIC5_UDEV_DEVICE_ID_1825_PF ||
	    HINIC_UB_GET_DEVICE_ID(ubus_dev) == HINIC5_UDEV_DEVICE_ID_1825_VF ||
	    HINIC_UB_GET_DEVICE_ID(ubus_dev) == HINIC5_UDEV_DEVICE_ID_1825_TEMP) {
		return UBUS_DEVICE_TYPE_1825;
	} else if (HINIC_UB_GET_DEVICE_ID(ubus_dev) == HINIC5_UDEV_DEVICE_ID_1872_PF ||
		HINIC_UB_GET_DEVICE_ID(ubus_dev) == HINIC5_UDEV_DEVICE_ID_1872_VF) {
		return UBUS_DEVICE_TYPE_1872;
	} else {
		return UBUS_DEVICE_TYPE_INVALID;
	}
}

struct fers2_conf {
	u32 cfg_reg_offset;
	u32 cfg_reg_size;
	u32 mgmt_reg_offset;
	u32 mgmt_reg_size;
};

static const struct fers2_conf PF_RS2_CONF = {
	HINIC5_PF_UBUS_CFG_REG_OFFSET,  HINIC5_PF_UBUS_CFG_REG_SIZE,
	HINIC5_PF_UBUS_MGMT_REG_OFFSET, HINIC5_PF_UBUS_MGMT_REG_SIZE
};

static const struct fers2_conf VF_RS2_CONF = {
	HINIC5_VF_UBUS_CFG_REG_OFFSET,  HINIC5_VF_UBUS_CFG_REG_SIZE,
	0, 0
};

static const struct fers2_conf HTN_PF_RS2_CONF = {
	HINIC5_HTN_PF_UBUS_CFG_REG_OFFSET,  HINIC5_HTN_PF_UBUS_CFG_REG_SIZE,
	HINIC5_HTN_PF_UBUS_MGMT_REG_OFFSET, HINIC5_HTN_PF_UBUS_MGMT_REG_SIZE
};

static const struct fers2_conf HTN_VF_RS2_CONF = {
	HINIC5_HTN_VF_UBUS_CFG_REG_OFFSET, HINIC5_HTN_VF_UBUS_CFG_REG_SIZE,
	0, 0
};

static const struct fers2_conf *get_fers2_config(hinic_ub_dev *ubus_dev,
						 struct hinic5_adev *adev)
{
	enum ubus_device_type dev_type = ubus_get_device_type(ubus_dev);
	bool is_vf = hinic5_ubus_is_virtfn(adev);

	if (dev_type == UBUS_DEVICE_TYPE_1825)
		return is_vf ? &VF_RS2_CONF : &PF_RS2_CONF;
	if (dev_type == UBUS_DEVICE_TYPE_1872)
		return is_vf ? &HTN_VF_RS2_CONF : &HTN_PF_RS2_CONF;
	return NULL;
}

static int ubus_mapping_bar(hinic_ub_dev *ubus_dev, struct hinic5_adev *adev)
{
	bool is_pf = !hinic5_ubus_is_virtfn(adev);
	const struct fers2_conf *rs2 = NULL;

	rs2 = get_fers2_config(ubus_dev, adev);
	if (unlikely(!rs2)) {
		sdk_err(&ubus_dev->dev, "Unsupport device\n");
		return -EFAULT;
	}

#ifdef __HINIC5_UBC_DEBUG__
	sdk_info(&ubus_dev->dev, "fers2 cfg  off 0x%x size 0x%x\n",
		 rs2->cfg_reg_offset, rs2->cfg_reg_size);
	sdk_info(&ubus_dev->dev, "fers2 mgmt off 0x%x size 0x%x\n",
		 rs2->mgmt_reg_offset, rs2->mgmt_reg_size);
#endif

	/* resource 2 */
	adev->fers2_base_phy  = ub_resource_start(ubus_dev, HINIC5_UBUS_FERS2);
	adev->fers2_total_len = ub_resource_len(ubus_dev, HINIC5_UBUS_FERS2);
	adev->fers2_reg_base  = ub_iomap(ubus_dev, HINIC5_UBUS_FERS2, 0);
	if (!adev->fers2_reg_base) {
		sdk_err(&ubus_dev->dev, "Failed to map resource 2\n");
		return -ENOMEM;
	}

	/* cfg reg */
	adev->cfg_reg_base = adev->fers2_reg_base + rs2->cfg_reg_offset;
	adev->cfg_base_phy = adev->fers2_base_phy + rs2->cfg_reg_offset;
	adev->cfg_base_len = rs2->cfg_reg_size;

	/* mgmt reg */
	if (is_pf) {
		adev->mgmt_reg_base = adev->fers2_reg_base + rs2->mgmt_reg_offset;
		adev->mgmt_base_phy = adev->fers2_base_phy + rs2->mgmt_reg_offset;
		adev->mgmt_base_len = rs2->mgmt_reg_offset;
	}

	/* interrupt reg */
	adev->intr_reg_base = ub_iomap(ubus_dev, HINIC5_UBUS_INTR_REG_BAR, 0);
	if (!adev->intr_reg_base) {
		sdk_err(&ubus_dev->dev,
			"Failed to map interrupt regs\n");
		goto map_intr_bar_err;
	}

	/* doorbell reg */
	adev->db_base_phy = ub_resource_start(ubus_dev, HINIC5_UBUS_DB_BAR);
	adev->db_dwqe_len = ub_resource_len(ubus_dev, HINIC5_UBUS_DB_BAR);
	adev->db_base = devm_ioremap_wc(&ubus_dev->dev,
					adev->db_base_phy,
					adev->db_dwqe_len);
	if (!adev->db_base) {
		sdk_err(&ubus_dev->dev,
			"Failed to map doorbell regs\n");
		goto map_db_err;
	}

#ifdef __HINIC5_UBC_DEBUG__
	sdk_info(&ubus_dev->dev, "cfg reg 0x%llx, mgmt reg 0x%llx\n",
		 (u64)adev->cfg_reg_base, (u64)adev->mgmt_reg_base);
#endif

	return 0;

map_db_err:
	ub_iounmap(adev->intr_reg_base);

map_intr_bar_err:
	ub_iounmap(adev->fers2_reg_base);

	return -ENOMEM;
}

static void ubus_unmapping_bar(struct hinic5_adev *adev)
{
	devm_iounmap(adev->dev, adev->db_base);

	ub_iounmap(adev->intr_reg_base);

	ub_iounmap(adev->fers2_reg_base);
}

static void hinic5_ubus_deinit(hinic_ub_dev *ubus_dev)
{
	HINIC_UB_UE_ENABLE(ubus_dev, 0);
	HINIC_UB_UNSET_HOST_INFO(ubus_dev);
	dev_set_drvdata(&ubus_dev->dev, NULL);
}

static int hinic5_ubus_init(hinic_ub_dev *ubus_dev)
{
	struct hinic5_adev *adev = NULL;
	int err;

	/* Write config space, config comes from ubus driver after loading */
	(void)HINIC_UB_SET_HOST_INFO(ubus_dev);

	adev = devm_kzalloc(&ubus_dev->dev, sizeof(*adev), GFP_KERNEL);
	if (!adev) {
		return -ENOMEM;
	}
	adev->dev = &ubus_dev->dev;
	mutex_init(&adev->adev_mutex);

	dev_set_drvdata(&ubus_dev->dev, adev);

	/* set bus_access_en */
	HINIC_UB_UE_ENABLE(ubus_dev, 1);

	sdk_info(&ubus_dev->dev, "Ubus DMA Bit Mask is (%u).\n", ubus_dma_bit_mask);
	if (ubus_dma_bit_mask < HINIC5_UBUS_DMA_BIT_MASK_MIN ||
	    ubus_dma_bit_mask > HINIC5_UBUS_DMA_BIT_MASK_MAX) {
		err = -EPERM;
		sdk_err(&ubus_dev->dev, "Ubus DMA Bit Mask Illegal\n");
		goto dma_mask_err;
	}

	err = dma_set_mask_and_coherent(&ubus_dev->dev,
					DMA_BIT_MASK(ubus_dma_bit_mask));
	if (err != 0) {
		sdk_warn(&ubus_dev->dev, "Couldn't set ubus DMA mask\n");
		goto dma_mask_err;
	}

	return 0;

dma_mask_err:
	hinic5_ubus_deinit(ubus_dev);

	return err;
}

static int hinic5_remove_ubus_func(struct hinic5_adev *adev)
{
	mutex_lock(&adev->adev_mutex);
	if (adev->lld_state != HINIC5_PROBE_OK) {
		sdk_warn(adev->dev, "Current function don not need remove\n");
		mutex_unlock(&adev->adev_mutex);
		return 0;
	}
	adev->lld_state = HINIC5_IN_REMOVE;
	mutex_unlock(&adev->adev_mutex);

	hinic5_detect_hw_present(adev->hwdev);

	if (hinic5_func_type(adev->hwdev) != TYPE_VF)
		wait_sriov_cfg_complete(adev);

	hinic5_func_deinit(adev);

	hinic5_lld_lock_chip_node();
	hinic5_free_chip_node(adev);
	hinic5_lld_unlock_chip_node();

	ubus_unmapping_bar(adev);

	mutex_lock(&adev->adev_mutex);
	adev->lld_state = HINIC5_NOT_PROBE;
	mutex_unlock(&adev->adev_mutex);

	sdk_info(adev->dev, "Ubus device removed function\n");

	return 0;
}

static void hinic5_ubus_remove(hinic_ub_dev *ubus_dev)
{
	struct hinic5_adev *adev = dev_get_drvdata(&ubus_dev->dev);

	if (!adev)
		return;

	sdk_info(&ubus_dev->dev, "Ubus device remove begin\n");

	HINIC_UB_DISABLE_FUNC(ubus_dev);
	hinic5_remove_ubus_func(adev);
	hinic5_ubus_deinit(ubus_dev);
	sdk_info(&ubus_dev->dev, "Ubus device removed\n");
}

static int hinic5_probe_ubus_func(hinic_ub_dev *ubus_dev, struct hinic5_adev *adev)
{
	int err;

	err = probe_func_param_init(adev);
	if (err == -EEXIST)
		return 0;
	else if (err != 0)
		return err;

	err = ubus_mapping_bar(ubus_dev, adev);
	if (err != 0) {
		sdk_err(&ubus_dev->dev, "Failed to map bar\n");
		goto map_bar_failed;
	}

	hinic5_lld_lock_chip_node();
	err = hinic5_alloc_chip_node(adev);
	if (err != 0) {
		hinic5_lld_unlock_chip_node();
		sdk_err(&ubus_dev->dev, "Failed to add new chip node to global list\n");
		goto alloc_chip_node_fail;
	}
	hinic5_lld_unlock_chip_node();

	err = hinic5_func_init(adev);
	if (err != 0)
		goto func_init_err;

	hinic5_probe_success(adev->hwdev);

	mutex_lock(&adev->adev_mutex);
	adev->lld_state = HINIC5_PROBE_OK;
	mutex_unlock(&adev->adev_mutex);

	return 0;

func_init_err:
	hinic5_lld_lock_chip_node();
	hinic5_free_chip_node(adev);
	hinic5_lld_unlock_chip_node();

alloc_chip_node_fail:
	ubus_unmapping_bar(adev);

map_bar_failed:
	sdk_err(adev->dev, "Ubus device probe function failed\n");
	return err;
}

static int hinic5_ubus_probe(hinic_ub_dev *ubus_dev, const struct ub_device_id *utbl_entry)
{
	struct hinic5_adev *adev = NULL;
	u16 probe_fault_level = FAULT_LEVEL_SERIOUS_FLR;
	int err;

	sdk_info(&ubus_dev->dev, "Ubus device probe begin\n");
	err = hinic5_probe_pre_process(ubus_dev);
	if (err == HINIC5_NOT_PROBE)
		return 0;
	if (err != 0)
		goto out;
	err = hinic5_ubus_init(ubus_dev);
	if (err != 0)
		goto out;

	adev = dev_get_drvdata(&ubus_dev->dev);
	adev->disable_vf_load = hinic5_is_disable_vf_load();
	adev->lld_state = HINIC5_NOT_PROBE;
	adev->probe_fault_level = probe_fault_level;
	adev->lld_dev.dev_type = HINIC5_DEVICE_T_UB;
	adev->bus_ops = hinic5_get_dev_ops(adev);
	adev->bus_dev = ubus_dev;
	err = adev->bus_ops->init_device_info(adev);
	if (err != 0)
		goto init_device_info_err;

	hinic5_lld_dev_cnt_init(adev);

	err = hinic5_probe_ubus_func(ubus_dev, adev);
	if (err != 0)
		goto hinic5_probe_func_fail;

	sdk_info(&ubus_dev->dev, "Ubus device probed\n");
	return 0;

hinic5_probe_func_fail:
	probe_fault_level = adev->probe_fault_level;

init_device_info_err:
	hinic5_ubus_deinit(ubus_dev);

out:
	hinic5_probe_fault_process(ubus_dev, probe_fault_level);
	sdk_err(&ubus_dev->dev, "Ubus device probe failed\n");
	return err;
}

void hinic5_ubus_probe_fault_process(struct hinic5_adev *adev)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

	hinic5_probe_fault_process(udev, FAULT_LEVEL_HOST);
}

#ifdef UB_SUPPORT_ENTITY
#define UB_DEVICE UB_ENTITY
#endif

#define HUAWEI_UB_DEVICE_ID(device) \
	UB_DEVICE(HINIC5_UDEV_VENDOR_ID_HUAWEI, device)

/* Old Vendor ID, to be deleted */
#define HUAWEI_UB_DEVICE_ID_OLD(device) \
	UB_DEVICE(HINIC5_UDEV_VENDOR_ID_HUAWEI_E0FC, device)

static const struct ub_device_id hinic5_ubus_tbl[] = {
	{
		HUAWEI_UB_DEVICE_ID(HINIC5_UDEV_DEVICE_ID_1825_PF),
		HINIC5_UDEV_CLASS_CODE_1825, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID(HINIC5_UDEV_DEVICE_ID_1825_VF),
		HINIC5_UDEV_CLASS_CODE_1825, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID(HINIC5_UDEV_DEVICE_ID_1825_TEMP),
		HINIC5_UDEV_CLASS_CODE_1825, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID(HINIC5_UDEV_DEVICE_ID_1872_PF),
		HINIC5_UDEV_CLASS_CODE_1872, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID(HINIC5_UDEV_DEVICE_ID_1872_VF),
		HINIC5_UDEV_CLASS_CODE_1872, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	/* Old Vendor ID, to be deleted */
	{
		HUAWEI_UB_DEVICE_ID_OLD(HINIC5_UDEV_DEVICE_ID_1825_PF),
		HINIC5_UDEV_CLASS_CODE_1825, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID_OLD(HINIC5_UDEV_DEVICE_ID_1825_VF),
		HINIC5_UDEV_CLASS_CODE_1825, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID_OLD(HINIC5_UDEV_DEVICE_ID_1825_TEMP),
		HINIC5_UDEV_CLASS_CODE_1825, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID_OLD(HINIC5_UDEV_DEVICE_ID_1872_PF),
		HINIC5_UDEV_CLASS_CODE_1872, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	{
		HUAWEI_UB_DEVICE_ID_OLD(HINIC5_UDEV_DEVICE_ID_1872_VF),
		HINIC5_UDEV_CLASS_CODE_1872, HINIC5_UDEV_CLASS_CODE_MASK,
	},
	/* required last entry */
	{0},
};

u16 hinic5_ubus_get_device_id(struct hinic5_adev *adev)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

	return HINIC_UB_GET_DEVICE_ID(udev);
}

bool hinic5_ubus_is_virtfn(struct hinic5_adev *adev)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);
	u16 dev_id = hinic5_ubus_get_device_id(adev);

	if (dev_id == HINIC5_UDEV_DEVICE_ID_1825_VF)
		return true;
	if (dev_id == HINIC5_UDEV_DEVICE_ID_1872_VF)
		return true;

#ifdef UB_SUPPORT_ENTITY
	return !udev->is_mue;
#else
	return !udev->is_pd;
#endif
}

int hinic5_ub_init_device_info(struct hinic5_adev *adev)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

	adev->info.id = (u64)((udev->guid.bits.seq_num >> HINIC5_CARD_ID_OFFSET) &
			      HINIC5_CARD_ID_MASK);

	if (sizeof(udev->guid) != sizeof(adev->info.guid)) {
		sdk_err(adev->dev, "guid size is not matched.\n");
		return -EINVAL;
	}
	memcpy(&adev->info.guid, &udev->guid, sizeof(udev->guid));

	sdk_info(adev->dev, "card_id: %lld, seq_num: %lld\n",
		 adev->info.id, (u64)(udev->guid.bits.seq_num));
	return 0;
}

struct hinic5_adev *hinic5_ubus_get_pf_adev(struct hinic5_adev *adev)
{
	struct hinic5_adev *pf_adev = NULL;
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

#ifdef UB_SUPPORT_ENTITY
	pf_adev = (hinic5_ubus_is_virtfn(adev) != 0) ? dev_get_drvdata(&udev->pue->dev) : adev;
#else
	pf_adev = (hinic5_ubus_is_virtfn(adev) != 0) ? dev_get_drvdata(&udev->pdev->dev) : adev;
#endif
	return pf_adev;
}

struct hinic5_adev *hinic5_ubus_get_vf_adev_by_pf(struct hinic5_adev *adev, u16 func_id)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);
	hinic_ub_dev *vd_dev = NULL;

#ifdef UB_SUPPORT_ENTITY
	list_for_each_entry(vd_dev, &udev->ue_list, node) {
		if (vd_dev->entity_idx  == func_id) {
#else
	list_for_each_entry(vd_dev, &udev->vdevice_list, node) {
		if (vd_dev->fe_idx == func_id) {
#endif
			return dev_get_drvdata(&vd_dev->dev);
		}
	}
	return NULL;
}

int hinic5_ubus_get_vf_num(struct hinic5_adev *adev)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

#ifdef UB_SUPPORT_ENTITY
	return udev->num_ues;
#else
	return udev->num_vds;
#endif
}

int hinic5_ubus_set_func_en(struct hinic5_adev *dst_dev, bool en, u16 vf_func_id)
{
	hinic_ub_dev *des_udev = container_of(dst_dev->dev, hinic_ub_dev, dev);
	int err;

	mutex_lock(&dst_dev->adev_mutex);
	/* unload invalid vf func id */
	if (!en && vf_func_id != hinic5_global_func_id(dst_dev->hwdev) &&
	    (strcmp(des_udev->driver->name, HINIC5_DRV_NAME) == 0)) {
		pr_err("dst_dev func id:%u, vf_func_id:%u\n",
		hinic5_global_func_id(dst_dev->hwdev), vf_func_id);
		mutex_unlock(&dst_dev->adev_mutex);
		return -EFAULT;
	}

	if (!en && dst_dev->lld_state == HINIC5_PROBE_OK) {
		mutex_unlock(&dst_dev->adev_mutex);
		hinic5_remove_ubus_func(dst_dev);
	} else if (en && dst_dev->lld_state == HINIC5_NOT_PROBE) {
		mutex_unlock(&dst_dev->adev_mutex);
		err = hinic5_probe_ubus_func(des_udev, dst_dev);
		if (err != 0)
			return -EFAULT;
	} else {
		mutex_unlock(&dst_dev->adev_mutex);
	}

	return 0;
}

int hinic5_ubus_irq_vectors_alloc(struct hinic5_adev *adev, void *entry, u32 irqs_min, u32 irqs_num)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

	return ub_alloc_irq_vectors(udev, irqs_min, irqs_num);
}

void hinic5_ubus_irq_vectors_free(struct hinic5_adev *adev)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

	return ub_disable_intr(udev);
}

int hinic5_ubus_irq_vector(struct hinic5_adev *adev, u32 idx)
{
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

	return ub_irq_vector(udev, idx);
}

static ub_ers_result_t hinic5_ubus_error_detected(hinic_ub_dev *ubus_dev,
						  ub_channel_state_t state)
{
	dev_info(&ubus_dev->dev, "UBUS error detected, state = %d.\n", state);

	switch (state) {
	case ub_channel_io_normal:
		return UB_ERS_RESULT_NEED_RESET;
	case ub_channel_io_frozen:
		return UB_ERS_RESULT_DISCONNECT;
	case ub_channel_io_perm_failure:
	default:
		return UB_ERS_RESULT_NONE;
	}
}

static const struct ub_error_handlers hinic5_ubus_err_handler = {
#ifdef UB_SUPPORT_B177
	.ub_error_detected	= hinic5_ubus_error_detected,
#else
	.error_detected	= hinic5_ubus_error_detected,
#endif
};

static int hinic5_ubus_suspend(struct device *dev)
{
	dev_info(dev, "UBUS suspend start\n");

	return 0;
}

static int hinic5_ubus_resume(struct device *dev)
{
	dev_info(dev, "UBUS resume start\n");

	return 0;
}

static SIMPLE_DEV_PM_OPS(hinic5_ubus_pm_ops, hinic5_ubus_suspend, hinic5_ubus_resume);

static struct ub_driver hinic5_ubus_driver = {
	.name		= HINIC5_DRV_NAME,
	.id_table	= hinic5_ubus_tbl,
	.probe		= hinic5_ubus_probe,
	.remove		= hinic5_ubus_remove,
	.virt_configure	= hinic5_ubus_virt_configure,
	.err_handler	= &hinic5_ubus_err_handler,
	.driver		= {
		.pm = &hinic5_ubus_pm_ops,
	},
	.groups         = hisdk5_driver_attr_groups,
};

int hinic5_ubus_register_driver(void)
{
	return ub_register_driver(&hinic5_ubus_driver);
}

void hinic5_ubus_unregister_driver(void)
{
	ub_unregister_driver(&hinic5_ubus_driver);
}

void hinic5_ubus_numvds_store_vds_process(struct hinic5_adev *adev, int nums)
{
	int vd_start_idx, vd_end_idx, i, cnt, ret;
	hinic_ub_dev *vdev;
	hinic_ub_dev *udev = HINIC_TO_UB_DEV(adev->dev);

	/*
	 * The software finds "cnt" disabled vDevices for "vd_start_idx" to
	 * "vd_end_idx" based on the ordered vdevice_list. "vd_start_idx" is
	 * the ue_idx of first vDevices and "vd_end_idx" is calculated based
	 * on the total number(that is, "nums") vDevices to be enabled.
	 */
#ifdef UB_SUPPORT_ENTITY
	vd_start_idx = udev->uem.start_entity_idx;
	vd_end_idx = vd_start_idx + nums - 1;
	i = vd_start_idx;
	cnt = nums - udev->num_ues;
	list_for_each_entry(vdev, &udev->ue_list, node) {
		for (; i < vdev->entity_idx; i++) {
			/*
			 * The "vdevice_list" is sorted by ue_idx in ascending order.
			 * Ensure that others vDevs before this vDev are enabled.
			 */
			ret = hinic5_ubus_virt_configure(udev, i, 1);
			if (ret != 0)
				sdk_warn(adev->dev, "driver virt_configure return %d\n", ret);
			if (--cnt == 0)
				return;
		}
		/* Skip this enabled vDev. */
		i++;
	}
#else
	vd_start_idx = udev->vd.start_fe_idx;
	vd_end_idx = vd_start_idx + nums - 1;
	i = vd_start_idx;
	cnt = nums - udev->num_vds;
	list_for_each_entry(vdev, &udev->vdevice_list, node) {
		for (; i < vdev->fe_idx; i++) {
			/*
			 * The "vdevice_list" is sorted by ue_idx in ascending order.
			 * Ensure that others vDevs before this vDev are enabled.
			 */
			ret = hinic5_ubus_virt_configure(udev, i, 1);
			if (ret != 0)
				sdk_warn(adev->dev, "driver virt_configure return %d\n", ret);
			if (--cnt == 0)
				return;
		}
		/* Skip this enabled vDev. */
		i++;
	}
#endif
	/* Ensure that the remaining vDevs enabled. */
	for (; i <= vd_end_idx; i++) {
		ret = hinic5_ubus_virt_configure(udev, i, 1);
		if (ret != 0)
			sdk_warn(adev->dev, "driver virt_configure return %d\n", ret);
		if (--cnt == 0)
			return;
	}
}
#endif
