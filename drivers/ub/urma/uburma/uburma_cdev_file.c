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
typedef ssize_t (*uburma_show_port_attr_cb)(const struct ubcore_device *ubc_dev, char *buf,
					    uint8_t port_num);

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

static ssize_t uburma_show_port_attr(struct uburma_port *p, struct uburma_port_attribute *attr,
				     char *buf, uburma_show_port_attr_cb show_cb)
{
	struct uburma_device *ubu_dev = p->ubu_dev;
	struct ubcore_device *ubc_dev;
	ssize_t ret = -ENODEV;
	int srcu_idx;

	if (!ubu_dev || !buf) {
		uburma_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev == NULL) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return -ENODEV;
	}

	ret = show_cb(ubc_dev, buf, p->port_num);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static ssize_t max_mtu_show_cb(const struct ubcore_device *ubc_dev, char *buf, uint8_t port_num)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%d\n",
			(int)ubc_dev->attr.port_attr[port_num].max_mtu);
}

static ssize_t max_mtu_show(struct uburma_port *p, struct uburma_port_attribute *attr, char *buf)
{
	return uburma_show_port_attr(p, attr, buf, max_mtu_show_cb);
}

static PORT_ATTR_RO(max_mtu);

static ssize_t state_show_cb(const struct ubcore_device *ubc_dev, char *buf, uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for state failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n",
			(uint32_t)status.port_status[port_num].state);
}

static ssize_t state_show(struct uburma_port *p, struct uburma_port_attribute *attr, char *buf)
{
	return uburma_show_port_attr(p, attr, buf, state_show_cb);
}

static PORT_ATTR_RO(state);

static ssize_t active_speed_show_cb(const struct ubcore_device *ubc_dev, char *buf,
				    uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for active speed failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n",
			status.port_status[port_num].active_speed);
}

static ssize_t active_speed_show(struct uburma_port *p, struct uburma_port_attribute *attr,
				 char *buf)
{
	return uburma_show_port_attr(p, attr, buf, active_speed_show_cb);
}

static PORT_ATTR_RO(active_speed);

static ssize_t active_width_show_cb(const struct ubcore_device *ubc_dev, char *buf,
				    uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for active width failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n",
			status.port_status[port_num].active_width);
}

static ssize_t active_width_show(struct uburma_port *p, struct uburma_port_attribute *attr,
				 char *buf)
{
	return uburma_show_port_attr(p, attr, buf, active_width_show_cb);
}

static PORT_ATTR_RO(active_width);

static ssize_t active_mtu_show_cb(const struct ubcore_device *ubc_dev, char *buf, uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for active mtu failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n",
			(uint32_t)status.port_status[port_num].active_mtu);
}

static ssize_t active_mtu_show(struct uburma_port *p, struct uburma_port_attribute *attr, char *buf)
{
	return uburma_show_port_attr(p, attr, buf, active_mtu_show_cb);
}

static PORT_ATTR_RO(active_mtu);

static struct attribute *uburma_port_attrs[] = {
	&port_attr_max_mtu.attr,      &port_attr_state.attr,	  &port_attr_active_speed.attr,
	&port_attr_active_width.attr, &port_attr_active_mtu.attr, NULL,
};

static ssize_t uburma_port_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct uburma_port_attribute *port_attr =
		container_of(attr, struct uburma_port_attribute, attr);
	struct uburma_port *p = container_of(kobj, struct uburma_port, kobj);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(p, port_attr, buf);
}

static ssize_t uburma_port_attr_store(struct kobject *kobj, struct attribute *attr, const char *buf,
				      size_t count)
{
	struct uburma_port_attribute *port_attr =
		container_of(attr, struct uburma_port_attribute, attr);
	struct uburma_port *p = container_of(kobj, struct uburma_port, kobj);

	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static const struct sysfs_ops uburma_port_sysfs_ops = { .show = uburma_port_attr_show,
							.store = uburma_port_attr_store };

static void uburma_port_release(struct kobject *kobj)
{
}

static const struct attribute_group uburma_port_groups = {
	.attrs = uburma_port_attrs,
};

static struct kobj_type uburma_port_type = { .release = uburma_port_release,
					     .sysfs_ops = &uburma_port_sysfs_ops,
					     .default_attrs = uburma_port_attrs
};

int uburma_create_port_attr_files(struct uburma_device *ubu_dev, uint8_t port_num)
{
	struct uburma_port *p;

	p = &ubu_dev->port[port_num];
	p->ubu_dev = ubu_dev;
	p->port_num = port_num;

	return kobject_init_and_add(&p->kobj, &uburma_port_type, &ubu_dev->dev->kobj, "port%hhu",
				    port_num);
}

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

void uburma_remove_port_attr_files(struct uburma_device *ubu_dev, uint8_t port_num)
{
	kobject_put(&ubu_dev->port[port_num].kobj);
}

void uburma_remove_dev_attr_files(struct uburma_device *ubu_dev)
{
	sysfs_remove_group(&ubu_dev->dev->kobj, &uburma_dev_attr_group);
}
