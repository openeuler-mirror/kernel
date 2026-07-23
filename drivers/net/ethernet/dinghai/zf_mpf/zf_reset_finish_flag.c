// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/helper.h>
#include "epc/pcie-zte-zf-epc.h"

#define SET_BIT1_0 0x0
#define SET_BIT1_1 0x1
#define SYSFS_ZF_RESET_FINISH_FLAG_DIR "zf_reset_finish_flag"
#define ZF_RESET_FINISH_FLAG_MODE 0664
#define ZF_RESET_FINISH_FLAG flag
#define NOTIFY_OFFEST (PCIE_DPU_MPF_CSR_ADDR(PCIE_DPU_EP_CSR_SIZE * PCIE_DPU_EP_NUM) + 4)
#define NOTIFY_VALUE(a) (a << 1)
#define NOTIFY_MASK (1 << 1)

static char flag_data[PAGE_SIZE];
static struct kobject *zf_reset_finish_flag_kobj;
unsigned long op_paddr;

static int notify_host_zf_reset_finished(unsigned long flag)
{
	int ret = 0;

	ret = cfg_phy_rmw(op_paddr + NOTIFY_OFFEST, NOTIFY_VALUE(flag), NOTIFY_MASK);

	if (ret)
		DH_LOG_ERR(MODULE_MPF, "%s, cfg_phy_rmw write failed!\n", __func__);

	return ret;
}

static ssize_t read_flag(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s", flag_data);
}

static ssize_t write_flag(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			  size_t count)
{
	int size = 0;
	unsigned long flag = 0;
	char *end = NULL;
	int ret;

	size = snprintf(flag_data, PAGE_SIZE, "%s", buf);
	if ((size < 0) || (size >= PAGE_SIZE)) {
		DH_LOG_ERR(MODULE_MPF, "get size failed\n");
		size = 0;
		return size;
	}

	ret = kstrtoul(flag_data, 16, &flag);
	if (ret) {
		DH_LOG_ERR(MODULE_MPF, "Invalid flag value: %s\n", flag_data);
		return -EINVAL;
	}

	if ((flag == SET_BIT1_0) || (flag == SET_BIT1_1))
		notify_host_zf_reset_finished(flag);

	return size;
}

static struct kobj_attribute flag_attribute =
	__ATTR(ZF_RESET_FINISH_FLAG, ZF_RESET_FINISH_FLAG_MODE, read_flag, write_flag);

int zf_reset_finish_flag_init(struct dh_core_dev *dh_dev, unsigned long ep_mpf_paddr)
{
	int ret = 0;

	op_paddr = ep_mpf_paddr;
	if (!zf_reset_finish_flag_kobj) {
		zf_reset_finish_flag_kobj =
			kobject_create_and_add(SYSFS_ZF_RESET_FINISH_FLAG_DIR, kernel_kobj);
		if (!zf_reset_finish_flag_kobj)
			return -ENOMEM;

		ret = sysfs_create_file(zf_reset_finish_flag_kobj, &flag_attribute.attr);
		if (ret) {
			kobject_put(zf_reset_finish_flag_kobj);
			zf_reset_finish_flag_kobj = NULL;
		}
	} else {
		DH_LOG_ERR(
			MODULE_MPF,
			"zf_reset_finish_flag_kobj is not NULL!, can't create zf_reset_finish_flag!\n");
		ret = -EINVAL;
	}

	return ret;
}

void zf_reset_finish_flag_exit(void)
{
	if (zf_reset_finish_flag_kobj) {
		sysfs_remove_file(zf_reset_finish_flag_kobj, &flag_attribute.attr);
		kobject_put(zf_reset_finish_flag_kobj);
		zf_reset_finish_flag_kobj = NULL;
	}
}
