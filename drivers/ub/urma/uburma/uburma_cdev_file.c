// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: uburma cdev file
 * Author: Qian Guoxin
 * Create: 2022-08-16
 * Note:
 * History: 2022-08-16: Create file
 */

#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/version.h>

#include <urma/ubcore_types.h>
#include <urma/ubcore_uapi.h>

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_cdev_file.h"

#define UBURMA_MAX_DEV_NAME 64
#define UBURMA_MAX_VALUE_LEN 24

/* callback information */
typedef ssize_t (*uburma_show_attr_cb)(const struct ubcore_device *ubc_dev, char *buf);
typedef ssize_t (*uburma_store_attr_cb)(struct ubcore_device *ubc_dev, const char *buf, size_t len);

static ssize_t uburma_show_dev_attr(struct device *dev, struct device_attribute *attr, char *buf,
				    uburma_show_attr_cb show_cb)
{
	struct uburma_device *ubu_dev = dev_get_drvdata(dev);
	struct ubcore_device *ubc_dev;
	ssize_t ret = -ENODEV;
	int srcu_idx;

	if (!ubu_dev || !buf) {
		uburma_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev)
		ret = show_cb(ubc_dev, buf);

	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static ssize_t uburma_store_dev_attr(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t len, uburma_store_attr_cb store_cb)
{
	struct uburma_device *ubu_dev = dev_get_drvdata(dev);
	struct ubcore_device *ubc_dev;
	ssize_t ret = -ENODEV;
	int srcu_idx;

	if (!ubu_dev || !buf) {
		uburma_log_err("Invalid argument with ubcore device nullptr.\n");
		return -EINVAL;
	}
	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev)
		ret = store_cb(ubc_dev, buf, len);

	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

/* interface for exporting device attributes */
static ssize_t ubdev_show_cb(const struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_DEV_NAME, "%s\n", ubc_dev->dev_name);
}

static ssize_t ubdev_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, ubdev_show_cb);
}

static DEVICE_ATTR_RO(ubdev);

static ssize_t eid_show_cb(const struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, (UBCORE_EID_STR_LEN + 1) + 1, EID_FMT "\n",
			EID_ARGS(ubc_dev->attr.eid));
}

static ssize_t eid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, eid_show_cb);
}

static int str_to_eid(const char *buf, size_t len, union ubcore_eid *eid)
{
	char *end;
	int ret;

	if (buf == NULL || eid == NULL) {
		uburma_log_err("Invalid argument\n");
		return -EINVAL;
	}

	ret = in6_pton(buf, (int)len, (u8 *)eid, -1, (const char **)&end);
	if (ret == 0) {
		uburma_log_err("format error: %s.\n", buf);
		return -EINVAL;
	}
	return 0;
}

static ssize_t eid_store_cb(struct ubcore_device *ubc_dev, const char *buf, size_t len)
{
	union ubcore_eid eid;
	ssize_t ret;

	if (str_to_eid(buf, len, &eid) != 0) {
		uburma_log_err("failed to str_to_eid: %s, %lu.\n", buf, len);
		return -EINVAL;
	}

	ret = ubcore_set_eid(ubc_dev, &eid);
	if (ret == 0)
		ret = (int)len; // len is required for success return.
	return ret;
}

static ssize_t eid_store(struct device *dev, struct device_attribute *attr, const char *buf,
			 size_t len)
{
	return uburma_store_dev_attr(dev, attr, buf, len, eid_store_cb);
}

static DEVICE_ATTR_RW(eid); // 0644

static struct attribute *uburma_dev_attrs[] = {
	&dev_attr_ubdev.attr,
	&dev_attr_eid.attr,
	NULL,
};

static const struct attribute_group uburma_dev_attr_group = {
	.attrs = uburma_dev_attrs,
};

int uburma_create_dev_attr_files(struct uburma_device *ubu_dev)
{
	int ret;

	ret = sysfs_create_group(&ubu_dev->dev->kobj, &uburma_dev_attr_group);
	if (ret != 0) {
		uburma_log_err("sysfs create group failed, ret:%d.\n", ret);
		return -1;
	}

	return 0;
}

void uburma_remove_dev_attr_files(struct uburma_device *ubu_dev)
{
	sysfs_remove_group(&ubu_dev->dev->kobj, &uburma_dev_attr_group);
}
