// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2002-2004, 2007 Greg Kroah-Hartman <greg@kroah.com>
 * (C) Copyright 2007 Novell Inc.
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Thanks to Greg Kroah-Hartman and Novell Inc. for their previous work.
 *
 */

#define pr_fmt(fmt)	"ubus driver: " fmt

#include <linux/module.h>
#include <linux/pm_runtime.h>

#include "services.h"
#include "msg.h"
#include "enum.h"
#include "instance.h"
#include "ioctl.h"
#include "sysfs.h"
#include "ubus.h"
#include "task.h"
#include "ubus_config.h"
#include "ubus_controller.h"
#include "ubus_inner.h"
#include "ubus_entity.h"
#include "services/service.h"
#include "ubus_driver.h"

bool entity_flex_en;
module_param(entity_flex_en, bool, 0444);
MODULE_PARM_DESC(entity_flex_en, "Entity Flexible enable: default: 0");

bool msg_retry = 1;
EXPORT_SYMBOL_GPL(msg_retry);
module_param(msg_retry, bool, 0444);
MODULE_PARM_DESC(msg_retry, "support msg retry: 0(disable)");

DECLARE_RWSEM(ub_bus_sem);

#define UBC_GUID_VENDOR_SHIFT 48
#define UBC_GUID_VENDOR_MASK GENMASK(15, 0)

static DEFINE_MUTEX(manage_subsystem_ops_mutex);
static const struct ub_manage_subsystem_ops *manage_subsystem_ops;

const struct ub_manage_subsystem_ops *get_ub_manage_subsystem_ops(void)
{
	return manage_subsystem_ops;
}

struct ub_bus_controller *ub_find_bus_controller(u32 ctl_no)
{
	struct ub_bus_controller *ubc;

	list_for_each_entry(ubc, &ubc_list, node)
		if (ubc->ctl_no == ctl_no)
			return ubc;

	return NULL;
}
EXPORT_SYMBOL_GPL(ub_find_bus_controller);

int ub_get_bus_controller(struct ub_entity *ubc_dev[], unsigned int max_num,
		      unsigned int *real_num)
{
	struct ub_bus_controller *ubc;
	unsigned int ubc_num = 0;
	int ret;

	if (!manage_subsystem_ops) {
		pr_err("manage subsystem ops is null\n");
		return -EINVAL;
	}

	if (!real_num || !ubc_dev) {
		pr_err("%s: input parameters invalid\n", __func__);
		return -EINVAL;
	}

	list_for_each_entry(ubc, &ubc_list, node) {
		if (ubc_num >= max_num) {
			pr_err("ubc list num over max num %u\n", max_num);
			ret = -ENOMEM;
			goto ubc_put;
		}

		if (!ub_entity_get(ubc->uent)) {
			pr_err("The ub_entity of ubc is null\n");
			ret = -EINVAL;
			goto ubc_put;
		}
		ubc_dev[ubc_num] = ubc->uent;
		ubc_num++;
	}
	*real_num = ubc_num;

	return 0;

ubc_put:
	ub_put_bus_controller(ubc_dev, max_num);
	return ret;
}
EXPORT_SYMBOL_GPL(ub_get_bus_controller);

void ub_put_bus_controller(struct ub_entity *ubc_dev[], unsigned int num)
{
	unsigned int i;

	if (ubc_dev) {
		for (i = 0; i < num; i++)
			ub_entity_put(ubc_dev[i]);
		memset(ubc_dev, 0, sizeof(struct ub_entity *) * num);
	}
}
EXPORT_SYMBOL_GPL(ub_put_bus_controller);

struct ub_entity *ub_entity_get(struct ub_entity *dev)
{
	if (dev)
		get_device(&dev->dev);
	return dev;
}
EXPORT_SYMBOL_GPL(ub_entity_get);

void ub_entity_put(struct ub_entity *dev)
{
	if (dev)
		put_device(&dev->dev);
}
EXPORT_SYMBOL_GPL(ub_entity_put);

struct ub_dynid {
	struct list_head node;
	struct ub_device_id id;
};

static const struct ub_device_id ub_entity_id_any = {
	.vendor = (__u32)UB_ANY_ID,
	.device = (__u32)UB_ANY_ID,
	.mod_vendor = (__u32)UB_ANY_ID,
	.module = (__u32)UB_ANY_ID,
};

static inline const struct ub_device_id *
ub_match_one_device(const struct ub_device_id *id, const struct ub_entity *dev)
{
	if ((id->vendor == UB_ANY_ID || id->vendor == uent_vendor(dev)) &&
	    (id->device == UB_ANY_ID || id->device == uent_device(dev)) &&
	    (id->mod_vendor == UB_ANY_ID || id->mod_vendor == dev->mod_vendor) &&
	    (id->module == UB_ANY_ID || id->module == dev->module) &&
	    !((id->class_code ^ uent_class(dev)) & id->class_mask))
		return id;
	return NULL;
}

static const struct ub_device_id *ub_match_id(const struct ub_device_id *ids,
				       struct ub_entity *dev)
{
	if (ids && dev) {
		while (ids->vendor || ids->mod_vendor || ids->class_mask) {
			if (ub_match_one_device(ids, dev))
				return ids;
			ids++;
		}
	}
	return NULL;
}

static struct ub_entity *
ub_get_dev_by_id_inner(struct ub_entity *from, const void *data,
		       int (*match)(struct device *dev, const void *data))
{
	struct device *dev, *dev_start = NULL;
	struct ub_entity *fdev = NULL;

	if (from)
		dev_start = &from->dev;

	dev = bus_find_device(&ub_bus_type, dev_start, (void *)data, match);
	if (dev)
		fdev = to_ub_entity(dev);

	ub_entity_put(from);
	return fdev;
}

static int ub_entity_match_by_guid(struct device *dev, const void *data)
{
	const struct ub_guid *guid = (const struct ub_guid *)data;
	struct ub_entity *uent = to_ub_entity(dev);

	if (guid_equal(&uent->guid.id, &guid->id))
		return 1;
	return 0;
}

struct ub_entity *ub_get_ent_by_guid(const struct ub_guid *guid)
{
	return ub_get_dev_by_id_inner(NULL, guid, ub_entity_match_by_guid);
}
EXPORT_SYMBOL_GPL(ub_get_ent_by_guid);

static int ub_entity_match_by_eid(struct device *dev, const void *data)
{
	struct ub_entity *uent = to_ub_entity(dev);
	const u32 eid = *((const u32 *)data);

	if (uent->eid == eid)
		return 1;

	return 0;
}

struct ub_entity *ub_get_ent_by_eid(unsigned int eid)
{
	return ub_get_dev_by_id_inner(NULL, &eid, ub_entity_match_by_eid);
}
EXPORT_SYMBOL_GPL(ub_get_ent_by_eid);

static int ub_entity_match_by_uent_num(struct device *dev, const void *data)
{
	const u32 uent_num = *((const u32 *)data);
	struct ub_entity *uent = to_ub_entity(dev);

	if (uent->uent_num == uent_num)
		return 1;

	return 0;
}

struct ub_entity *ub_get_ent_by_uent_num(unsigned int uent_num)
{
	return ub_get_dev_by_id_inner(NULL, &uent_num, ub_entity_match_by_uent_num);
}
EXPORT_SYMBOL_GPL(ub_get_ent_by_uent_num);

/* Should call ub_entity_put after unused */
struct ub_entity *ub_find_entity(struct ub_entity *parent, bool mue, int idx)
{
	struct list_head *head;
	struct ub_entity *uent;
	bool find = false;

	if (!parent)
		return NULL;

	head = mue ? &parent->mue_list : &parent->ue_list;

	down_read(&ub_bus_sem);
	list_for_each_entry(uent, head, node)
		if (uent->entity_idx == idx) {
			find = true;
			ub_entity_get(uent);
			break;
		}
	up_read(&ub_bus_sem);

	return find ? uent : NULL;
}
EXPORT_SYMBOL_GPL(ub_find_entity);

static const struct ub_device_id *ub_match_device(struct ub_driver *drv,
						  struct ub_entity *dev)
{
	const struct ub_device_id *found_id = NULL, *ids;
	struct ub_dynid *dynid;

	/* When driver_override is set, only bind to the matching driver */
	if (dev->driver_override && strcmp(dev->driver_override, drv->name))
		return NULL;

	/* Look at the dynamic ids first, before the static ones */
	spin_lock(&drv->dynids.lock);
	list_for_each_entry(dynid, &drv->dynids.list, node) {
		if (ub_match_one_device(&dynid->id, dev)) {
			found_id = &dynid->id;
			break;
		}
	}
	spin_unlock(&drv->dynids.lock);

	if (found_id)
		return found_id;

	for (ids = drv->id_table; (found_id = ub_match_id(ids, dev));
	     ids = found_id + 1) {
		if (found_id->override_only) {
			if (dev->driver_override)
				return found_id;
		} else {
			return found_id;
		}
	}

	/* driver_override will always match, send a dummy id */
	if (dev->driver_override)
		return &ub_entity_id_any;

	return NULL;
}

static int ub_bus_match(struct device *dev, struct device_driver *drv)
{
	struct ub_driver *ub_drv = to_ub_driver(drv);
	struct ub_entity *ub_entity = to_ub_entity(dev);
	const struct ub_device_id *found_id;

	if (!ub_entity->match_driver)
		return 0;

	found_id = ub_match_device(ub_drv, ub_entity);
	if (found_id)
		return 1;

	return 0;
}

static int ub_call_probe(struct ub_driver *drv, struct ub_entity *dev,
			 const struct ub_device_id *id)
{
	int ret;

	dev->driver = drv;
	/*
	 * Probe function should return < 0 for failure, 0 for success
	 * Treat values > 0 as success, but warn.
	 */
	ret = drv->probe(dev, id);
	if (ret < 0) {
		dev->driver = NULL;
		return ret;
	} else if (ret > 0) {
		ub_warn(dev, "Driver probe function unexpectedly, ret=%d\n",
			ret);
	}

	return 0;
}

static int __ub_entity_probe(struct ub_driver *drv, struct ub_entity *dev)
{
	const struct ub_device_id *id;
	int ret = 0;

	if (drv->probe) {
		ret = -ENODEV;

		id = ub_match_device(drv, dev);
		if (id)
			ret = ub_call_probe(drv, dev, id);
	}

	return ret;
}

static int ub_entity_probe(struct device *dev)
{
	struct ub_driver *drv = to_ub_driver(dev->driver);
	struct ub_entity *ub_entity = to_ub_entity(dev);
	struct ub_entity *pue;
	u16 entity_idx;
	int ret;

	ub_entity_get(ub_entity);
	if (!ub_entity->is_mue) {
		pue = ub_entity->pue;
		entity_idx = ub_entity->entity_idx;
		ub_virt_notify(pue, entity_idx, true);
	}

	ret = __ub_entity_probe(drv, ub_entity);
	if (ret) {
		if (ret == -EAGAIN)
			ub_add_retry_task(ub_entity, TASK_TYPE_ATTACH_RETRY);

		ub_entity_put(ub_entity);
	} else {
		ub_entity_assign_priv_flag(ub_entity, UB_ENTITY_PROBED, true);
	}

	return ret;
}

static void ub_entity_remove(struct device *dev)
{
	struct ub_entity *ub_entity = to_ub_entity(dev);
	struct ub_driver *drv = ub_entity->driver;

	if (drv->remove)
		drv->remove(ub_entity);

	ub_entity->driver = NULL;
	ub_entity_assign_priv_flag(ub_entity, UB_ENTITY_PROBED, false);

	ub_entity_put(ub_entity);
}

static void ub_entity_shutdown(struct device *dev)
{
	struct ub_entity *uent = to_ub_entity(dev);
	struct ub_driver *drv = uent->driver;

	ub_dbg(uent, "come shutdown\n");

	pm_runtime_resume(dev);

	if (drv && drv->shutdown)
		drv->shutdown(uent);
}

static int ub_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
	struct ub_entity *uent;

	if (!dev)
		return -ENODEV;

	uent = to_ub_entity(dev);

	if (add_uevent_var(env, "UB_ID=%04X:%04X", uent_vendor(uent),
			   uent_device(uent)))
		return -ENOMEM;

	if (add_uevent_var(env, "UB_MODULE=%04X:%04X", uent->mod_vendor,
			   uent->module))
		return -ENOMEM;

	if (add_uevent_var(env, "UB_TYPE=%01X", uent_type(uent)))
		return -ENOMEM;

	if (add_uevent_var(env, "UB_CLASS=%04X", uent_class(uent)))
		return -ENOMEM;

	if (add_uevent_var(env, "UB_VERSION=%01X", uent_version(uent)))
		return -ENOMEM;

	if (add_uevent_var(env, "UB_SEQ_NUM=%016llX", uent_seq(uent)))
		return -ENOMEM;

	if (add_uevent_var(env, "UB_ENTITY_NAME=%s", ub_name(uent)))
		return -ENOMEM;

	if (add_uevent_var(env, "MODALIAS=ub:v%04Xd%04Xmv%04Xm%04Xc%04X",
			   uent_vendor(uent), uent_device(uent),
			   uent->mod_vendor, uent->module, uent_class(uent)))
		return -ENOMEM;

	return 0;
}

static int ub_add_dynid(struct ub_driver *drv,
			unsigned int vendor, unsigned int device,
			unsigned int mod_vendor, unsigned int module,
			unsigned int class_code, unsigned int class_mask,
			unsigned long driver_data)
{
	struct ub_dynid *dynid;

	dynid = kzalloc(sizeof(*dynid), GFP_KERNEL);
	if (!dynid)
		return -ENOMEM;

	dynid->id.vendor = vendor;
	dynid->id.device = device;
	dynid->id.mod_vendor = mod_vendor;
	dynid->id.module = module;
	dynid->id.class_code = class_code;
	dynid->id.class_mask = class_mask;
	dynid->id.driver_data = driver_data;

	spin_lock(&drv->dynids.lock);
	list_add_tail(&dynid->node, &drv->dynids.list);
	spin_unlock(&drv->dynids.lock);

	return driver_attach(&drv->driver);
}

static int ub_check_id_exist(struct ub_driver *udrv, u32 vendor, u32 device,
			     u32 mod_vendor, u32 module, u32 class_code)
{
	struct ub_entity *uent;
	int ret = 0;

	uent = kzalloc(sizeof(struct ub_entity), GFP_KERNEL);
	if (!uent)
		return -ENOMEM;

	uent_vendor(uent) = vendor;
	uent_device(uent) = device;
	uent_class(uent) = class_code;
	uent->mod_vendor = mod_vendor;
	uent->module = module;

	if (ub_match_device(udrv, uent))
		ret = -EEXIST;

	kfree(uent);

	return ret;
}

static int ub_check_driver_data_valid(const struct ub_device_id *ids,
				      unsigned long driver_data)
{
	/* Only accept driver_data values that match an exiting id_table entry */
	while (ids->vendor || ids->mod_vendor || ids->class_mask) {
		if (driver_data == ids->driver_data)
			return 0;
		ids++;
	}

	return -EINVAL;
}

static ssize_t new_id_store(struct device_driver *driver, const char *buf,
			    size_t count)
{
	u32 vendor, device, class_code = 0, class_mask = 0;
	u32 mod_vendor = UB_ANY_ID, module = UB_ANY_ID;
	struct ub_driver *udrv = to_ub_driver(driver);
	unsigned long driver_data = 0;
	int fileds, ret;

	fileds = sscanf(buf, "%x %x %x %x %x %x %lx", &vendor, &device,
			&mod_vendor, &module,
			&class_code, &class_mask, &driver_data);
	if (fileds < 2) /* 2 parameter for vender & device id */
		return -EINVAL;

	if (fileds != 7) { /* 7 for driver_data input */
		ret = ub_check_id_exist(udrv, vendor, device, mod_vendor,
					module, class_code);
		if (ret)
			return ret;
	}

	if (udrv->id_table) {
		ret = ub_check_driver_data_valid(udrv->id_table, driver_data);
		if (ret)
			return ret;
	}

	ret = ub_add_dynid(udrv, vendor, device, mod_vendor, module,
			   class_code, class_mask, driver_data);
	if (ret)
		return ret;

	return count;
}
static DRIVER_ATTR_WO(new_id);

static ssize_t remove_id_store(struct device_driver *driver, const char *buf,
			       size_t count)
{
	u32 vendor, device, class_code = 0, class_mask = 0;
	u32 mod_vendor = UB_ANY_ID, module = UB_ANY_ID;
	struct ub_driver *udrv = to_ub_driver(driver);
	struct ub_dynid *dynid, *n;
	ssize_t ret = -ENODEV;
	int fields;

	fields = sscanf(buf, "%x %x %x %x %x %x", &vendor, &device, &mod_vendor,
			&module, &class_code, &class_mask);
	if (fields < 2) /* 2 parameter for vender & device id */
		return -EINVAL;

	spin_lock(&udrv->dynids.lock);
	list_for_each_entry_safe(dynid, n, &udrv->dynids.list, node) {
		struct ub_device_id *id = &dynid->id;

		if ((id->vendor == vendor) &&
		    (id->device == device) &&
		    (mod_vendor == UB_ANY_ID || id->mod_vendor == mod_vendor) &&
		    (module == UB_ANY_ID || id->module == module) &&
		    !((id->class_code ^ class_code) & class_mask)) {
			list_del(&dynid->node);
			kfree(dynid);
			ret = (ssize_t)count;
			break;
		}
	}
	spin_unlock(&udrv->dynids.lock);

	return ret;
}
static DRIVER_ATTR_WO(remove_id);

static struct attribute *ub_drv_attrs[] = {
	&driver_attr_new_id.attr,
	&driver_attr_remove_id.attr,
	NULL
};
ATTRIBUTE_GROUPS(ub_drv);

static int ub_bus_num_ue(struct device *dev)
{
	return ub_num_ue(to_ub_entity(dev));
}

static void ub_bus_type_init(void)
{
	ub_bus_type.match = ub_bus_match;
	ub_bus_type.uevent = ub_uevent;
	ub_bus_type.probe = ub_entity_probe;
	ub_bus_type.remove = ub_entity_remove;
	ub_bus_type.shutdown = ub_entity_shutdown;
	ub_bus_type.dev_groups = ub_entity_groups;
	ub_bus_type.bus_groups = ub_bus_groups;
	ub_bus_type.drv_groups = ub_drv_groups;
	ub_bus_type.num_vf = ub_bus_num_ue;
}

static void ub_bus_type_uninit(void)
{
	ub_bus_type.match = NULL;
	ub_bus_type.uevent = NULL;
	ub_bus_type.probe = NULL;
	ub_bus_type.remove = NULL;
	ub_bus_type.shutdown = NULL;
	ub_bus_type.dev_groups = NULL;
	ub_bus_type.bus_groups = NULL;
	ub_bus_type.drv_groups = NULL;
	ub_bus_type.num_vf = NULL;
}

static int ub_service_bus_match(struct device *dev, struct device_driver *drv)
{
	struct ub_service_device *sdev;
	struct ub_service_driver *sdrv;

	if (drv->bus != &ub_service_bus_type || dev->bus != &ub_service_bus_type)
		return 0;

	sdev = to_ub_service_device(dev);
	sdrv = to_ub_service_driver(drv);
	if (sdrv->service != sdev->service)
		return 0;

	return 1;
}

struct bus_type ub_service_bus_type = {
	.name  = "ub_service",
	.match = ub_service_bus_match,
};

static void ubus_driver_resource_drain(void)
{
	ub_dynamic_bus_instance_drain();
	ub_static_cluster_instance_drain();
}

static int ub_host_probe(void)
{
	int ret;

	ub_bus_type_init();
	ret = ub_cfg_ops_init();
	if (ret)
		goto ub_cfg_ops_init_fail;

	ret = ub_bus_controllers_probe();
	if (ret)
		goto ubcs_probe_fail;

	ret = ub_enum_probe();
	if (ret)
		goto ub_enum_probe_fail;

	/*
	 * Now ub_bus_type build-in, bus_attr_groups will not created,
	 * so init it here.
	 */
	ret = ub_bus_attr_dynamic_init();
	if (ret)
		goto ub_bus_attr_dynamic_init_fail;

	ret = bus_register(&ub_service_bus_type);
	if (ret)
		goto bus_register_fail;

	ret = ub_services_init();
	if (ret)
		goto ub_services_init_fail;

	ret = ub_cdev_init();
	if (ret)
		goto cdev_fail;

	if (!manage_subsystem_ops || !manage_subsystem_ops->ras_handler_probe) {
		ret = -EFAULT;
		goto error_register_fail;
	}

	ret = manage_subsystem_ops->ras_handler_probe();
	if (ret)
		goto error_register_fail;

	ret = message_rx_init();
	if (ret)
		goto message_init_fail;

	return 0;

message_init_fail:
	if (manage_subsystem_ops && manage_subsystem_ops->ras_handler_remove)
		manage_subsystem_ops->ras_handler_remove();
error_register_fail:
	ub_cdev_uninit();
cdev_fail:
	ub_services_exit();
ub_services_init_fail:
	bus_unregister(&ub_service_bus_type);
bus_register_fail:
	ub_bus_attr_dynamic_uninit();
ub_bus_attr_dynamic_init_fail:
	ub_enum_remove();
ub_enum_probe_fail:
	ub_bus_controllers_remove();
ubcs_probe_fail:
	unregister_ub_cfg_ops();
ub_cfg_ops_init_fail:
	ub_bus_type_uninit();
	return ret;
}

static void ub_host_remove(void)
{
	message_rx_uninit();
	if (manage_subsystem_ops && manage_subsystem_ops->ras_handler_remove)
		manage_subsystem_ops->ras_handler_remove();
	ub_cdev_uninit();
	ub_services_exit();
	bus_unregister(&ub_service_bus_type);
	ub_bus_attr_dynamic_uninit();
	ubus_driver_resource_drain();
	ub_enum_remove();
	ub_bus_controllers_remove();
	unregister_ub_cfg_ops();
	ub_bus_type_uninit();
}

int register_ub_manage_subsystem_ops(const struct ub_manage_subsystem_ops *ops)
{
	struct ub_bus_controller *ubc;
	int ret;

	if (!ops) {
		pr_err("ub manage subsystem ops is NULL\n");
		return -EINVAL;
	}

	mutex_lock(&manage_subsystem_ops_mutex);
	if (!manage_subsystem_ops) {
		list_for_each_entry(ubc, &ubc_list, node) {
			if (((ubc->attr.ubc_guid_high >> UBC_GUID_VENDOR_SHIFT) &
			    UBC_GUID_VENDOR_MASK) == ops->vendor) {
				manage_subsystem_ops = ops;
				ret = ub_host_probe();
				if (ret)
					manage_subsystem_ops = NULL;
				else
					pr_info("ub manage subsystem ops register successfully\n");

				mutex_unlock(&manage_subsystem_ops_mutex);
				return ret;
			}
		}
		pr_warn("ub manage subsystem ops is not match with any of ub controller\n");
	} else {
		pr_warn("ub manage subsystem ops has been registered\n");
	}
	mutex_unlock(&manage_subsystem_ops_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(register_ub_manage_subsystem_ops);

void unregister_ub_manage_subsystem_ops(const struct ub_manage_subsystem_ops *ops)
{
	if (!ops) {
		pr_err("ub manage subsystem ops is NULL\n");
		return;
	}

	mutex_lock(&manage_subsystem_ops_mutex);
	if (manage_subsystem_ops == ops) {
		ub_host_remove();
		manage_subsystem_ops = NULL;
		pr_info("ub manage subsystem ops unregister successfully\n");
	} else {
		pr_warn("ub manage subsystem ops is not registered by this vendor\n");
	}
	mutex_unlock(&manage_subsystem_ops_mutex);
}
EXPORT_SYMBOL_GPL(unregister_ub_manage_subsystem_ops);

static int __init ubus_driver_init(void)
{
	pr_info("Ubus driver init successfully.\n");
	return 0;
}

static void __exit ubus_driver_exit(void)
{
	pr_info("Ubus driver exit successfully.\n");
}
module_init(ubus_driver_init);
module_exit(ubus_driver_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UB bus driver");
MODULE_IMPORT_NS(UB_UBFI);
MODULE_IMPORT_NS(UB_UBUS);
