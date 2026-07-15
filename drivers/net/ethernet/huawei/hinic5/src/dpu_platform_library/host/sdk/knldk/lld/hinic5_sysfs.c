/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_sysfs.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/sysfs.h>

#include "ossl_knl.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_sysfs.h"

/*                             driver attributes                              */
static ssize_t metadata_show(struct device_driver *dev, char *buf)
{
	return (ssize_t)sysfs_emit(buf, "commit: %s\ncompile time: %s\n",
				   GIT_COMMIT_ID, "2026-05-20_00:00:00");
}
static DRIVER_ATTR_RO(metadata);

static struct attribute *hisdk5_driver_attrs[] = {
	&driver_attr_metadata.attr,
	NULL,
};

static const struct attribute_group hisdk5_driver_attr_group = {
	.attrs = hisdk5_driver_attrs,
};

const struct attribute_group *hisdk5_driver_attr_groups[] = {
	&hisdk5_driver_attr_group,
	NULL,
};

/*                             device attributes                              */
static ssize_t timeout_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct hinic5_adev *adev = dev_get_drvdata(dev);
	struct hinic5_hwdev *hwdev = adev->hwdev;
	ssize_t len = 0;

	if (!hwdev || !hwdev->timeout_info)
		return len;

	len += sysfs_emit(buf,
			 "hw_type: %s\n"
			 "mbox_timeout: %u ms\nmailbox_poll_timeout: %u ms\n"
			 "cmdq_timeout: %u ms\n",
			  hwdev->timeout_info->hw_type_desc,
			  hwdev->timeout_info->mbox_timeout,
			  hwdev->timeout_info->mbox_poll_timeout,
			  hwdev->timeout_info->cmdq_timeout);
	return len;
}
static DEVICE_ATTR_RO(timeout);

static struct attribute *hisdk5_device_attrs[] = {
	&dev_attr_timeout.attr,
	NULL
};

static const struct attribute_group hisdk5_device_attr_group = {
	.attrs = hisdk5_device_attrs
};

const struct attribute_group *hisdk5_device_attr_groups[] = {
	&hisdk5_device_attr_group,
	NULL,
};

const struct attribute_group *a_hisdk5_device_attr_groups[] = {
	&hisdk5_device_attr_group,
	NULL,
};

int register_device_attr_groups(struct hinic5_adev *adev)
{
	return sysfs_create_groups(&adev->dev->kobj, hisdk5_device_attr_groups);
}

void unregister_device_attr_groups(struct hinic5_adev *adev)
{
	sysfs_remove_groups(&adev->dev->kobj, hisdk5_device_attr_groups);
}
