// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/time.h>
#include "common/xsc_core.h"
#include "common/xsc_hsi.h"
#include "common/driver.h"
#include "common/xsc_cmd.h"
#include "xsc_ib.h"

static ssize_t hca_type_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	struct pci_dev *pdev = dev->pdev;

	return sprintf(buf, "%x\n", pdev->subsystem_device);
}

static DEVICE_ATTR_RO(hca_type);

static ssize_t hw_rev_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	u32 hw_ver = 0;

	hw_ver = ((dev->chip_ver_l & 0xffff) << 16) |
		(dev->hotfix_num & 0xffff);
	return sprintf(buf, "0x%x\n", hw_ver);
}

static DEVICE_ATTR_RO(hw_rev);

static struct device_attribute *xsc_ib_attributes[] = {
	&dev_attr_hca_type,
	&dev_attr_hw_rev,
};

void xsc_ib_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	int err = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(xsc_ib_attributes); i++) {
		err = device_create_file(&ib_dev->dev, xsc_ib_attributes[i]);
		if (err)
			xsc_core_err(xdev, "Create sysfs file for %s failed.\n",
				     xsc_ib_attributes[i]->attr.name);
	}
}

void xsc_ib_sysfs_fini(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(xsc_ib_attributes); i++)
		device_remove_file(&ib_dev->dev, xsc_ib_attributes[i]);
}

