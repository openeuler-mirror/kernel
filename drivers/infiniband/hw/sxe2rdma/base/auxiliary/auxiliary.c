// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: auxiliary.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/device.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/string.h>
#include "auxiliary_bus.h"

static const struct auxiliary_device_id *auxiliary_match_id(const struct auxiliary_device_id *id,
							    const struct auxiliary_device *auxdev)
{
	for (; id->name[0]; id++) {
		const char *p = strrchr(dev_name(&auxdev->dev), '.');
		size_t match_size;

		if (!p)
			continue;
		match_size = p - dev_name(&auxdev->dev);

		if (strlen(id->name) == match_size &&
		    !strncmp(dev_name(&auxdev->dev), id->name, match_size))
			return id;
	}
	return NULL;
}

static int auxiliary_match(struct device *dev, struct device_driver *drv)
{
	struct auxiliary_device *auxdev = to_auxiliary_dev(dev);
	struct auxiliary_driver *auxdrv = to_auxiliary_drv(drv);

	return !!auxiliary_match_id(auxdrv->id_table, auxdev);
}

static int auxiliary_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	const char *name, *p;

	name = dev_name(dev);
	p = strrchr(name, '.');

	return add_uevent_var(env, "MODALIAS=%s%.*s", AUXILIARY_MODULE_PREFIX,
			      (int)(p - name), name);
}

static const struct dev_pm_ops auxiliary_dev_pm_ops = {
	SET_RUNTIME_PM_OPS(pm_generic_runtime_suspend, pm_generic_runtime_resume, NULL)
	SET_SYSTEM_SLEEP_PM_OPS(pm_generic_suspend, pm_generic_resume)
};

static int auxiliary_bus_probe(struct device *dev)
{
	struct auxiliary_driver *auxdrv = to_auxiliary_drv(dev->driver);
	struct auxiliary_device *auxdev = to_auxiliary_dev(dev);
	int ret;

	ret = dev_pm_domain_attach(dev, true);
	if (ret != -EPROBE_DEFER) {
		if (auxdrv->probe) {
			ret = auxdrv->probe(auxdev,
					    auxiliary_match_id(auxdrv->id_table,
							       auxdev));
			if (ret)
				dev_pm_domain_detach(dev, true);
		} else {
			ret = 0;
		}
	}

	return ret;
}

static int auxiliary_bus_remove(struct device *dev)
{
	struct auxiliary_driver *auxdrv = to_auxiliary_drv(dev->driver);
	struct auxiliary_device *auxdev = to_auxiliary_dev(dev);

	if (auxdrv->remove)
		auxdrv->remove(auxdev);
	dev_pm_domain_detach(dev, true);

	return 0;
}

static void auxiliary_bus_shutdown(struct device *dev)
{
	struct auxiliary_driver *auxdrv = NULL;
	struct auxiliary_device *auxdev;

	if (dev->driver) {
		auxdrv = to_auxiliary_drv(dev->driver);
		auxdev = to_auxiliary_dev(dev);
	}

	if (auxdrv && auxdrv->shutdown)
		auxdrv->shutdown(auxdev);
}

static struct bus_type auxiliary_bus_type = {
	.name = "sxe2_auxiliary",
	.probe = auxiliary_bus_probe,
	.remove = auxiliary_bus_remove,
	.shutdown = auxiliary_bus_shutdown,
	.match = auxiliary_match,
	.uevent = auxiliary_uevent,
	.pm = &auxiliary_dev_pm_ops,
};

int sxe2_auxiliary_device_init(struct auxiliary_device *auxdev)
{
	struct device *dev = &auxdev->dev;

	if (!dev->parent) {
		pr_err("auxiliary_device has a NULL dev->parent\n");
		return -EINVAL;
	}

	if (!auxdev->name) {
		pr_err("auxiliary_device has a NULL name\n");
		return -EINVAL;
	}

	dev->bus = &auxiliary_bus_type;
	device_initialize(&auxdev->dev);
	return 0;
}
EXPORT_SYMBOL_GPL(sxe2_auxiliary_device_init);

int __sxe2_auxiliary_device_add(struct auxiliary_device *auxdev, const char *modname)
{
	struct device *dev = &auxdev->dev;
	int ret;

	if (!modname) {
		dev_err(dev, "auxiliary device modname is NULL\n");
		return -EINVAL;
	}

	ret = dev_set_name(dev, "%s.%s.%d", modname, auxdev->name, auxdev->id);
	if (ret) {
		dev_err(dev, "auxiliary device dev_set_name failed: %d\n", ret);
		return ret;
	}

	ret = device_add(dev);
	if (ret)
		dev_err(dev, "adding auxiliary device failed!: %d\n", ret);

	return ret;
}
EXPORT_SYMBOL_GPL(__sxe2_auxiliary_device_add);

#ifndef NO_NEED_AUXILIARY_FIND_DEVICE_CONST_DATA
struct auxiliary_device *sxe2_auxiliary_find_device(struct device *start,
						    const void *data,
						    int (*match)(struct device *dev,
								 const void *data))
#else
struct auxiliary_device *sxe2_auxiliary_find_device(struct device *start,
						    void *data,
						    int (*match)(struct device *dev,
								 void *data))
#endif
{
	struct device *dev;

	dev = bus_find_device(&auxiliary_bus_type, start, data, match);
	if (!dev)
		return NULL;

	return to_auxiliary_dev(dev);
}
EXPORT_SYMBOL_GPL(sxe2_auxiliary_find_device);

int __sxe2_auxiliary_driver_register(struct auxiliary_driver *auxdrv,
				     struct module *owner, const char *modname)
{
	int ret;

	if (WARN_ON(!auxdrv->probe) || WARN_ON(!auxdrv->id_table))
		return -EINVAL;

	if (auxdrv->name)
		auxdrv->driver.name = kasprintf(GFP_KERNEL, "%s.%s", modname,
						auxdrv->name);
	else
		auxdrv->driver.name = kasprintf(GFP_KERNEL, "%s", modname);
	if (!auxdrv->driver.name)
		return -ENOMEM;

	auxdrv->driver.owner = owner;
	auxdrv->driver.bus = &auxiliary_bus_type;
	auxdrv->driver.mod_name = modname;

	ret = driver_register(&auxdrv->driver);
	if (ret)
		kfree(auxdrv->driver.name);

	return ret;
}
EXPORT_SYMBOL_GPL(__sxe2_auxiliary_driver_register);

void sxe2_auxiliary_driver_unregister(struct auxiliary_driver *auxdrv)
{
	driver_unregister(&auxdrv->driver);
	kfree(auxdrv->driver.name);
}
EXPORT_SYMBOL_GPL(sxe2_auxiliary_driver_unregister);

static int __init auxiliary_bus_init(void)
{
	return bus_register(&auxiliary_bus_type);
}

static void __exit auxiliary_bus_exit(void)
{
	bus_unregister(&auxiliary_bus_type);
}

module_init(auxiliary_bus_init);
module_exit(auxiliary_bus_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Auxiliary Bus Standalone");
MODULE_AUTHOR("linux.tucana@Stars Micro System.com");
