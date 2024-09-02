// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>
#include <linux/device.h>

#include "hisi_internal.h"

#define MODULE_NAME            "hbm_cache"

static struct kobject *cache_kobj;

static ssize_t state_store(struct device *d, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct acpi_device *adev = ACPI_COMPANION(d);
	const int type = online_type_from_str(buf);
	acpi_handle handle = adev->handle;
	acpi_status status = AE_OK;

	switch (type) {
	case STATE_ONLINE:
		status = acpi_evaluate_object(handle, "_ON", NULL, NULL);
		break;
	case STATE_OFFLINE:
		status = acpi_evaluate_object(handle, "_OFF", NULL, NULL);
		break;
	default:
		break;
	}

	if (ACPI_FAILURE(status))
		return -ENODEV;

	return count;
}
static DEVICE_ATTR_WO(state);

static ssize_t socket_id_show(struct device *d, struct device_attribute *attr,
				char *buf)
{
	int socket_id;

	if (device_property_read_u32(d, "socket_id", &socket_id))
		return -EINVAL;

	return sysfs_emit(buf, "%d\n", socket_id);
}
static DEVICE_ATTR_RO(socket_id);

static struct attribute *attrs[] = {
	&dev_attr_state.attr,
	&dev_attr_socket_id.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static int cache_probe(struct platform_device *pdev)
{
	int ret;

	ret = sysfs_create_group(&pdev->dev.kobj, &attr_group);
	if (ret)
		return ret;

	ret = sysfs_create_link(cache_kobj,
				&pdev->dev.kobj,
				kobject_name(&pdev->dev.kobj));
	if (ret) {
		sysfs_remove_group(&pdev->dev.kobj, &attr_group);
		return ret;
	}

	return 0;
}

static int cache_remove(struct platform_device *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &attr_group);
	sysfs_remove_link(&pdev->dev.kobj,
			  kobject_name(&pdev->dev.kobj));
	return 0;
}

static const struct acpi_device_id cache_acpi_ids[] = {
	{"HISI04A1", 0},
	{"", 0},
};

static struct platform_driver hbm_cache_driver = {
	.probe = cache_probe,
	.remove = cache_remove,
	.driver = {
		.name = MODULE_NAME,
		.acpi_match_table = ACPI_PTR(cache_acpi_ids),
	},
};

static int __init hbm_cache_module_init(void)
{
	int ret;

	cache_kobj = kobject_create_and_add("hbm_cache", kernel_kobj);
	if (!cache_kobj)
		return -ENOMEM;

	ret = platform_driver_register(&hbm_cache_driver);
	if (ret) {
		kobject_put(cache_kobj);
		return ret;
	}
	return 0;
}
module_init(hbm_cache_module_init);

static void __exit hbm_cache_module_exit(void)
{
	kobject_put(cache_kobj);
	platform_driver_unregister(&hbm_cache_driver);
}
module_exit(hbm_cache_module_exit);
MODULE_LICENSE("GPL");
