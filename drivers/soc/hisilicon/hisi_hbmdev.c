// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/acpi.h>
#include <linux/container.h>
#include <linux/node.h>
#include <linux/arch_topology.h>
#include <linux/memory_hotplug.h>

#include "hisi_internal.h"

#define ACPI_MEMORY_DEVICE_HID			"PNP0C80"
#define ACPI_GENERIC_CONTAINER_DEVICE_HID	"PNP0A06"

struct cdev_node {
	struct device *dev;
	struct list_head clist;
};

struct memory_dev {
	struct kobject *memdev_kobj;
	struct kobject *topo_kobj;
	struct cdev_node cdev_list;
	nodemask_t cluster_cpumask[MAX_NUMNODES];
};

static struct memory_dev *mdev;

static ssize_t memory_locality_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	int i, count = 0;

	for (i = 0; i < MAX_NUMNODES; i++) {
		if (hotplug_mdev[i] != NULL && !nodes_empty(mdev->cluster_cpumask[i])) {
			count += sysfs_emit_at(buf, count, "%d %*pbl\n", i,
					       nodemask_pr_args(&mdev->cluster_cpumask[i]));
		}
	}

	return count;
}

static struct kobj_attribute memory_locality_attribute =
	__ATTR(memory_locality, 0444, memory_locality_show, NULL);

static void memory_topo_init(void)
{
	int ret, nid, cluster_id, cpu;
	struct acpi_device *adev;
	nodemask_t mask;

	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		if (!hotplug_mdev[nid])
			continue;

		adev = hotplug_mdev[nid];
		ret = fwnode_property_read_u32(acpi_fwnode_handle(adev),
						"cluster-id", &cluster_id);
		if (ret < 0) {
			pr_debug("Failed to read cluster id\n");
			return;
		}

		nodes_clear(mask);
		for_each_possible_cpu(cpu) {
			if (topology_cluster_id(cpu) == cluster_id)
				node_set(cpu, mask);
		}
		mdev->cluster_cpumask[nid] = mask;
	}

	mdev->topo_kobj = kobject_create_and_add("memory_topo", mdev->memdev_kobj);
	if (!mdev->topo_kobj)
		return;

	ret = sysfs_create_file(mdev->topo_kobj, &memory_locality_attribute.attr);
	if (ret)
		kobject_put(mdev->topo_kobj);
}

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

static int eject_device(struct acpi_device *acpi_device, void *not_used)
{
	acpi_object_type unused;
	acpi_status status;

	status = acpi_get_type(acpi_device->handle, &unused);
	if (ACPI_FAILURE(status) || !acpi_device->flags.ejectable)
		return -ENODEV;

	get_device(&acpi_device->dev);
	status = acpi_hotplug_schedule(acpi_device, ACPI_OST_EC_OSPM_EJECT);
	if (ACPI_SUCCESS(status))
		return 0;

	put_device(&acpi_device->dev);
	acpi_evaluate_ost(acpi_device->handle, ACPI_OST_EC_OSPM_EJECT,
			  ACPI_OST_SC_NON_SPECIFIC_FAILURE, NULL);

	return status == AE_NO_MEMORY ? -ENOMEM : -EAGAIN;
}

static int memdev_power_off(struct acpi_device *adev)
{
	return acpi_dev_for_each_child(adev, eject_device, NULL);
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

static int hbmdev_find(struct acpi_device *adev, void *arg)
{
	const char *hid = acpi_device_hid(adev);
	bool *found = arg;

	if (!strcmp(hid, ACPI_MEMORY_DEVICE_HID)) {
		*found = true;
		return -1;
	}

	return 0;
}

static bool has_hbmdev(struct device *dev)
{
	struct acpi_device *adev = ACPI_COMPANION(dev);
	const char *hid = acpi_device_hid(adev);
	bool found = false;

	if (strcmp(hid, ACPI_GENERIC_CONTAINER_DEVICE_HID))
		return found;

	acpi_dev_for_each_child(adev, hbmdev_find, &found);

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
	list_add_tail(&cnode->clist, &mdev->cdev_list.clist);

	return 0;
}

static void container_remove(void)
{
	struct cdev_node *cnode, *tmp;

	list_for_each_entry_safe(cnode, tmp, &mdev->cdev_list.clist, clist) {
		device_remove_file(cnode->dev, &dev_attr_state);
		device_remove_file(cnode->dev, &dev_attr_pxms);
		list_del(&cnode->clist);
		kfree(cnode);
	}
}

static int container_init(void)
{
	struct cdev_node *cnode;

	INIT_LIST_HEAD(&mdev->cdev_list.clist);

	if (bus_for_each_dev(&container_subsys, NULL, NULL, container_add)) {
		container_remove();
		return -ENOMEM;
	}

	if (list_empty(&mdev->cdev_list.clist))
		return -ENODEV;

	list_for_each_entry(cnode, &mdev->cdev_list.clist, clist) {
		device_create_file(cnode->dev, &dev_attr_state);
		device_create_file(cnode->dev, &dev_attr_pxms);
	}

	return 0;
}


static int __init mdev_init(void)
{
	int ret;

	mdev = kzalloc(sizeof(struct memory_dev), GFP_KERNEL);
	if (!mdev)
		return -ENOMEM;

	ret = container_init();
	if (ret) {
		kfree(mdev);
		return ret;
	}

	mdev->memdev_kobj = kobject_create_and_add("hbm_memory", kernel_kobj);
	if (!mdev->memdev_kobj) {
		container_remove();
		kfree(mdev);
		return -ENOMEM;
	}

	memory_topo_init();
	return ret;
}
module_init(mdev_init);

static void __exit mdev_exit(void)
{
	container_remove();
	kobject_put(mdev->memdev_kobj);
	kobject_put(mdev->topo_kobj);
	kfree(mdev);
}
module_exit(mdev_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhang Zekun <zhangzekun11@huawei.com>");
