// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/acpi.h>
#include <linux/container.h>

#include "hisi_internal.h"

#define ACPI_MEMORY_DEVICE_HID			"PNP0C80"
#define ACPI_GENERIC_CONTAINER_DEVICE_HID	"PNP0A06"

struct cdev_node {
	struct device *dev;
	struct list_head clist;
};

struct cdev_node cdev_list;

static int get_pxm(struct acpi_device *acpi_device, void *arg)
{
	acpi_handle handle = acpi_device->handle;
	nodemask_t *mask = arg;
	unsigned long long sta;
	acpi_status status;
	int nid;

	status = acpi_evaluate_integer(handle, "_STA", NULL, &sta);
	if (ACPI_SUCCESS(status) && (sta & ACPI_STA_DEVICE_ENABLED)) {
		nid = acpi_get_node(handle);
		if (nid >= 0)
			node_set(nid, *mask);
	}

	return 0;
}

static ssize_t pxms_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct acpi_device *adev = ACPI_COMPANION(dev);
	nodemask_t mask;

	nodes_clear(mask);
	acpi_dev_for_each_child(adev, get_pxm, &mask);

	return sysfs_emit(buf, "%*pbl\n",
		  nodemask_pr_args(&mask));
}
static DEVICE_ATTR_RO(pxms);

static int memdev_power_on(struct acpi_device *adev)
{
	acpi_handle handle = adev->handle;
	acpi_status status;

	status = acpi_evaluate_object(handle, "_ON", NULL, NULL);
	if (ACPI_FAILURE(status)) {
		acpi_handle_warn(handle, "Power on failed (0x%x)\n", status);
		return -ENODEV;
	}

	return 0;
}

static int hbmdev_check(struct acpi_device *adev, void *arg)
{
	const char *hid = acpi_device_hid(adev);

	if (!strcmp(hid, ACPI_MEMORY_DEVICE_HID)) {
		if (arg) {
			bool *found = arg;
			*found = true;
			return -1;
		}

		/* There might be devices have not attached */
		if (!adev->handler)
			return 0;

		acpi_scan_lock_acquire();
		adev->handler->hotplug.demand_offline = true;
		acpi_scan_lock_release();
	}

	return 0;
}

static int memdev_power_off(struct acpi_device *adev)
{
	acpi_handle handle = adev->handle;
	acpi_status status;

	acpi_dev_for_each_child(adev, hbmdev_check, NULL);

	status = acpi_evaluate_object(handle, "_OFF", NULL, NULL);
	if (ACPI_FAILURE(status)) {
		return -ENODEV;
	}
	return 0;
}

static ssize_t state_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct acpi_device *adev = ACPI_COMPANION(dev);
	const int type = online_type_from_str(buf);
	int ret = -EINVAL;

	switch (type) {
	case STATE_ONLINE:
		ret = memdev_power_on(adev);
		break;
	case STATE_OFFLINE:
		ret  = memdev_power_off(adev);
		break;
	default:
		break;
	}

	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(state);

static bool has_hbmdev(struct device *dev)
{
	struct acpi_device *adev = ACPI_COMPANION(dev);
	const char *hid = acpi_device_hid(adev);
	bool found = false;

	if (strcmp(hid, ACPI_GENERIC_CONTAINER_DEVICE_HID))
		return found;

	acpi_dev_for_each_child(adev, hbmdev_check, &found);
	return found;
}

static int container_add(struct device *dev, void *data)
{
	struct cdev_node *cnode;

	if (!has_hbmdev(dev))
		return 0;

	cnode = kmalloc(sizeof(struct cdev_node), GFP_KERNEL);
	if (!cnode)
		return -ENOMEM;

	cnode->dev = dev;
	list_add_tail(&cnode->clist, &cdev_list.clist);

	return 0;
}

static void container_remove(void)
{
	struct cdev_node *cnode, *tmp;

	list_for_each_entry_safe(cnode, tmp, &cdev_list.clist, clist) {
		device_remove_file(cnode->dev, &dev_attr_state);
		device_remove_file(cnode->dev, &dev_attr_pxms);
		list_del(&cnode->clist);
		kfree(cnode);
	}
}

static int container_init(void)
{
	struct cdev_node *cnode;

	INIT_LIST_HEAD(&cdev_list.clist);

	if (bus_for_each_dev(&container_subsys, NULL, NULL, container_add)) {
		container_remove();
		return -ENOMEM;
	}

	if (list_empty(&cdev_list.clist))
		return -ENODEV;

	list_for_each_entry(cnode, &cdev_list.clist, clist) {
		device_create_file(cnode->dev, &dev_attr_state);
		device_create_file(cnode->dev, &dev_attr_pxms);
	}

	return 0;
}


static int __init hbmdev_init(void)
{
	return container_init();
}
module_init(hbmdev_init);

static void __exit hbmdev_exit(void)
{
	container_remove();
}
module_exit(hbmdev_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhang Zekun <zhangzekun11@huawei.com>");
