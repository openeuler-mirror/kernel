// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/cper.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <acpi/ghes.h>
#include <uapi/linux/uuid.h>
#include "sysctl_local_ras.h"

enum {
	/* ARM */
	RAS_MODULE_CPU_CORE,
	/* OEM1 */
	RAS_MODULE_PLL,
	RAS_MODULE_SLLC,
	RAS_MODULE_SIOE,
	RAS_MODULE_POE,
	RAS_MODULE_DISPATCH,
	RAS_MODULE_TDH,
	RAS_MODULE_GIC,
	RAS_MODULE_RDE,
	RAS_MODULE_SAS,
	RAS_MODULE_SATA,
	RAS_MODULE_USB,
	/* OEM2 */
	RAS_MODULE_SMMU,
	RAS_MODULE_HHA,
	RAS_MODULE_PA,
	RAS_MODULE_HLLC,
	RAS_MODULE_DDRC,
	/* PCIE LOCAL */
	RAS_MODULE_PCIE_AP,
	RAS_MODULE_PCIE_DL,
	RAS_MODULE_PCIE_MAC,
	RAS_MODULE_PCIE_SDI_LOCAL,
	RAS_MODULE_PCIE_TL,
	/* HPRE */
	RAS_MODULE_ZIP,
	RAS_MODULE_SEC,
	RAS_MODULE_HPRE,
	/* NET */
	RAS_MODULE_NET_GE,
	RAS_MODULE_NET_25GE,
	RAS_MODULE_NET_25GE_RDMA,
	RAS_MODULE_NET_50GE_RDMA,
	RAS_MODULE_NET_100G_RDMA,
	RAS_MODULE_NET_SDI,
	RAS_MODULE_NET_100G_VF,
	RAS_MODULE_NET_100G_RDMA_VF,
	RAS_MODULE_MAX,
};

enum {
	SYSCTL_IOCTL_GET_RAS = 0,
};

#define SYSCTL_PROC "hisi_sysctl"

#define SYSCTRL_DFX_DBG_LEVEL 0
#if SYSCTRL_DFX_DBG_LEVEL
#define SYSCTRL_DFX_DBG(fmt...) printk(fmt)
#else
#define SYSCTRL_DFX_DBG(fmt...)
#endif

struct ras_node {
	u32 cnt;
};

struct ras_handle {
	guid_t gid;
	void (*proc)(const void *err);
};

static DEFINE_MUTEX(g_ras_info_lock);
static struct ras_node g_ras_info[RAS_MODULE_MAX] = {0};

static void do_ras_oem_type1(const void *error);
static void do_ras_oem_type2(const void *error);
static void do_ras_arm(const void *error);
static void do_ras_pcie(const void *error);
static void do_ras_pcie_local(const void *error);
static const struct ras_handle g_ras_handle_tab[] = {
	{
	.gid = CPER_SEC_HISI_OEM_1,
	.proc = do_ras_oem_type1,
	},
	{
	.gid = CPER_SEC_HISI_OEM_2,
	.proc = do_ras_oem_type2,
	},
	{
	.gid = CPER_SEC_HISI_PCIE_LOCAL,
	.proc = do_ras_pcie_local,
	},
	{
	.gid = CPER_SEC_PCIE,
	.proc = do_ras_pcie,
	},
	{
	.gid = CPER_SEC_PROC_ARM,
	.proc = do_ras_arm,
	}
};

static void do_ras_oem_type1(const void *error)
{
	u32 ras_moudle_id;
	const struct hisi_oem_type1_err_sec *err = error;

	if (!err->validation_bits.module_id_vald) {
		pr_err("%s : module id is invalid\n", __func__);
		return;
	}

	SYSCTRL_DFX_DBG("%s module_id = %u\n", __func__, err->module_id);
	switch (err->module_id) {
	case (OEM1_MODULE_PLL):
		ras_moudle_id = RAS_MODULE_PLL;
		break;
	case (OEM1_MODULE_SLLC):
		ras_moudle_id = RAS_MODULE_SLLC;
		break;
	case (OEM1_MODULE_SIOE):
		ras_moudle_id = RAS_MODULE_SIOE;
		break;
	case (OEM1_MODULE_POE):
		ras_moudle_id = RAS_MODULE_POE;
		break;
	case (OEM1_MODULE_DISP):
		ras_moudle_id = RAS_MODULE_DISPATCH;
		break;
	case (OEM1_MODULE_TDH):
		ras_moudle_id = RAS_MODULE_TDH;
		break;
	case (OEM1_MODULE_GIC):
		ras_moudle_id = RAS_MODULE_GIC;
		break;
	case (OEM1_MODULE_RDE):
		ras_moudle_id = RAS_MODULE_RDE;
		break;
	case (OEM1_MODULE_SAS):
		ras_moudle_id = RAS_MODULE_SAS;
		break;
	case (OEM1_MODULE_SATA):
		ras_moudle_id = RAS_MODULE_SATA;
		break;
	case (OEM1_MODULE_USB):
		ras_moudle_id = RAS_MODULE_USB;
		break;
	default:
		return;
	}

	mutex_lock(&g_ras_info_lock);
	g_ras_info[ras_moudle_id].cnt++;
	mutex_unlock(&g_ras_info_lock);
}

static void do_ras_oem_type2(const void *error)
{
	u32 ras_moudle_id;
	const struct hisi_oem_type2_err_sec *err = error;

	if (!(err->val_bits & HISI_OEM_VALID_MODULE_ID)) {
		pr_err("%s: module id is invalid\n", __func__);
		return;
	}

	SYSCTRL_DFX_DBG("%s module_id= %u\n", __func__, err->module_id);
	switch (err->module_id) {
	case (OEM2_MODULE_SMMU):
		ras_moudle_id = RAS_MODULE_SMMU;
		break;
	case (OEM2_MODULE_HHA):
		ras_moudle_id = RAS_MODULE_HHA;
		break;
	case (OEM2_MODULE_PA):
		ras_moudle_id = RAS_MODULE_PA;
		break;
	case (OEM2_MODULE_HLLC):
		ras_moudle_id = RAS_MODULE_HLLC;
		break;
	case (OEM2_MODULE_DDRC):
		ras_moudle_id = RAS_MODULE_DDRC;
		break;
	default:
		return;
	}

	mutex_lock(&g_ras_info_lock);
	g_ras_info[ras_moudle_id].cnt++;
	mutex_unlock(&g_ras_info_lock);
}

static bool is_net_subsys_devid(u16 device_id, u32 *module_id)
{
	switch (device_id) {
	case (HISI_PCIE_DEV_ID_GE):
		*module_id = RAS_MODULE_NET_GE;
		break;
	case (HISI_PCIE_DEV_ID_25GE):
		*module_id = RAS_MODULE_NET_25GE;
		break;
	case (HISI_PCIE_DEV_ID_25GE_RDMA):
		*module_id = RAS_MODULE_NET_25GE_RDMA;
		break;
	case (HISI_PCIE_DEV_ID_50GE_RDMA):
		*module_id = RAS_MODULE_NET_50GE_RDMA;
		break;
	case (HISI_PCIE_DEV_ID_100G_RDMA):
		*module_id = RAS_MODULE_NET_100G_RDMA;
		break;
	case (HISI_PCIE_DEV_ID_SDI):
		*module_id = RAS_MODULE_NET_SDI;
		break;
	case (HISI_PCIE_DEV_ID_100G_VF):
		*module_id = RAS_MODULE_NET_100G_VF;
		break;
	case (HISI_PCIE_DEV_ID_100G_RDMA_VF):
		*module_id = RAS_MODULE_NET_100G_RDMA_VF;
		break;
	default:
		return false;
	}

	return true;
}

static void do_ras_pcie(const void *error)
{
	u32 ras_moudle_id;
	const struct cper_sec_pcie *err = error;

	if (!(err->validation_bits & CPER_PCIE_VALID_DEVICE_ID)) {
		pr_err("do ras pcie : device id is invalid\n");
		return;
	}

	if (err->device_id.vendor_id != HISI_PCIE_VENDOR_ID) {
		pr_err("do ras pcie : vendor id is not hisi\n");
		return;
	}

	SYSCTRL_DFX_DBG("do ras pcie = 0x%x\n", err->device_id.device_id);
	if (err->device_id.device_id == HISI_PCIE_DEV_ID_ZIP) {
		ras_moudle_id = RAS_MODULE_ZIP;
	} else if (err->device_id.device_id == HISI_PCIE_DEV_ID_SEC) {
		ras_moudle_id = RAS_MODULE_SEC;
	} else if (err->device_id.device_id == HISI_PCIE_DEV_ID_HPRE) {
		ras_moudle_id = RAS_MODULE_HPRE;
	} else if (is_net_subsys_devid(err->device_id.device_id, &ras_moudle_id)) {
		SYSCTRL_DFX_DBG("RAS: do_net_ras\n");
	} else {
		pr_err("do ras pcie : device id=0x%x not support\n", err->device_id.device_id);
		return;
	}

	mutex_lock(&g_ras_info_lock);
	g_ras_info[ras_moudle_id].cnt++;
	mutex_unlock(&g_ras_info_lock);
}

static void do_ras_arm(const void *error)
{
	mutex_lock(&g_ras_info_lock);
	g_ras_info[RAS_MODULE_CPU_CORE].cnt++;
	mutex_unlock(&g_ras_info_lock);
}

static void do_ras_pcie_local(const void *error)
{
	u32 ras_moudle_id;
	const struct hisi_pcie_local_err_sec *err = error;

	if (!(err->val_bits & HISI_PCIE_LOCAL_VALID_SUB_MODULE_ID)) {
		pr_err("%s: module id is invalid\n", __func__);
		return;
	}

	SYSCTRL_DFX_DBG("%s module_id=%u\n", __func__, err->sub_module_id);
	switch (err->sub_module_id) {
	case (PCIE_LOCAL_MODULE_AP):
		ras_moudle_id = RAS_MODULE_PCIE_AP;
		break;
	case (PCIE_LOCAL_MODULE_TL):
		ras_moudle_id = RAS_MODULE_PCIE_TL;
		break;
	case (PCIE_LOCAL_MODULE_MAC):
		ras_moudle_id = RAS_MODULE_PCIE_MAC;
		break;
	case (PCIE_LOCAL_MODULE_DL):
		ras_moudle_id = RAS_MODULE_PCIE_DL;
		break;
	case (PCIE_LOCAL_MODULE_SDI):
		ras_moudle_id = RAS_MODULE_PCIE_SDI_LOCAL;
		break;
	default:
		return;
	}

	mutex_lock(&g_ras_info_lock);
	g_ras_info[ras_moudle_id].cnt++;
	mutex_unlock(&g_ras_info_lock);
}

void sysctl_dfx_do_ras(struct acpi_hest_generic_data *gdata)
{
	u32 count;
	guid_t *sec_type = NULL;

	SYSCTRL_DFX_DBG("do ras\n");
	if (!gdata) {
		pr_err("[ERROR]: err gdata\n");
		return;
	}

	sec_type = (guid_t *)gdata->section_type;
	for (count = 0; count < ARRAY_SIZE(g_ras_handle_tab); count++) {
		if (guid_equal(sec_type, &g_ras_handle_tab[count].gid)) {
			g_ras_handle_tab[count].proc(acpi_hest_get_payload(gdata));
			break;
		}
	}
}

static long sysctl_proc_ioctl(struct file *file, unsigned int req, unsigned long arg)
{
	if (req == SYSCTL_IOCTL_GET_RAS) {
		mutex_lock(&g_ras_info_lock);
		if (copy_to_user((void *)arg, &g_ras_info[0], sizeof(g_ras_info)))
			pr_err("sysctl proc : copy to user failed\n");
		mutex_unlock(&g_ras_info_lock);
	}

	return 0;
}

static const struct file_operations g_sysctl_proc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = sysctl_proc_ioctl,
};

int sysctl_proc_init(void)
{
	if (!proc_create(SYSCTL_PROC, S_IRUGO, NULL, &g_sysctl_proc_fops)) {
		pr_err("sysctl proc create failed\n");
		return -ENOMEM;
	}

	SYSCTRL_DFX_DBG("sysctl proc init\n");
	return 0;
}

void sysctl_proc_exit(void)
{
	SYSCTRL_DFX_DBG("sysctl proc exit\n");
	remove_proc_entry(SYSCTL_PROC, NULL);
}
