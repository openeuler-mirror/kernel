// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., All rights reserved.
 * Description: UMMU CORE API, extend the IOMMU Framework.
 */

#define pr_fmt(fmt) "[UMMU_CORE]: " fmt
#include <linux/module.h>
#include <ub/ubus/ubus.h>

#include "ummu_core_priv.h"

LIST_HEAD(core_device_list);

static struct ummu_tid_manager *
ummu_core_alloc_tid_manager(struct ummu_core_device *core_device,
			    const struct tid_ops *ops, u32 max,
			    u32 min)
{
	struct ummu_tid_manager *manager;

	if (!ops || !ops->alloc_tid_manager || !ops->free_tid_manager) {
		dev_err(core_device->iommu.dev, "invalid ops.\n");
		return NULL;
	}
	manager = ops->alloc_tid_manager(core_device, max, min);
	if (!manager) {
		dev_err(core_device->iommu.dev, "failed to alloc tid manager.\n");
		return NULL;
	}
	manager->ops = ops;
	manager->max_tid = max;
	manager->min_tid = min;
	return manager;
}

static void ummu_core_free_tid_manager(struct ummu_tid_manager *manager)
{
	manager->ops->free_tid_manager(manager);
}

static int set_global_device(struct ummu_core_device *core_device)
{
	if (!core_device->ops || !core_device->ops->add_eid ||
		!core_device->ops->del_eid || !core_device->iommu.ops) {
		pr_err("invalid ops.\n");
		return -EOPNOTSUPP;
	}
	if (global_core_device)
		return -EEXIST;

	ub_bus_type_iommu_ops_set(core_device->iommu.ops);
	ummu_flush_cached_eid(core_device);
	global_core_device = core_device;

	return 0;
}

static void reset_global_device(void)
{
	ub_bus_type_iommu_ops_set(NULL);
	global_core_device = NULL;
}

static void ummu_core_root_release(struct device *dev)
{
	pr_debug("%s root release\n", dev_name(dev));
	kfree(dev);
}

static int ummu_core_device_add_sysfs(struct ummu_core_device *ummu_core)
{
	struct device *root;
	int ret;

	root = kzalloc(sizeof(*root), GFP_KERNEL);
	if (!root)
		return -ENOMEM;

	root->init_name = dev_name(ummu_core->iommu.dev);
	root->parent = &tid_bus;
	root->release = ummu_core_root_release;

	ret = device_register(root);
	if (ret) {
		pr_err("ummu_core_device root register err!\n");
		put_device(root);
		return ret;
	}

	ummu_core->ummu_core_root = root;
	return 0;
}

static void ummu_core_device_remove_sysfs(struct ummu_core_device *ummu_core)
{
	struct device *root;

	root = ummu_core->ummu_core_root;
	ummu_core->ummu_core_root = NULL;
	device_unregister(root);
}

int ummu_core_device_init(struct ummu_core_device *ummu_core,
			  struct ummu_core_init_args *args)
{
	struct ummu_tid_manager *tid_manager;

	if (!args->iommu_ops)
		return -EINVAL;

	if (args->tid_args.tid_ops) {
		tid_manager = ummu_core_alloc_tid_manager(ummu_core,
						args->tid_args.tid_ops,
						args->tid_args.max_tid,
						args->tid_args.min_tid);
		if (!tid_manager)
			return -ENOMEM;

		ummu_core->tid_manager = tid_manager;
	}
	ummu_core->iommu.ops = args->iommu_ops;
	ummu_core->ops = args->core_ops;
	if (args->hwdev)
		ummu_core->iommu.fwnode = dev_fwnode(args->hwdev);

	return 0;
}
EXPORT_SYMBOL_GPL(ummu_core_device_init);

void ummu_core_device_deinit(struct ummu_core_device *ummu_core)
{
	if (ummu_core->tid_manager)
		ummu_core_free_tid_manager(ummu_core->tid_manager);

	ummu_core->tid_manager = NULL;
	ummu_core->ops = NULL;
	ummu_core->iommu.ops = NULL;
	ummu_core->iommu.fwnode = NULL;
}
EXPORT_SYMBOL_GPL(ummu_core_device_deinit);

int ummu_core_device_register(struct ummu_core_device *ummu_core,
			      enum ummu_register_type type)
{
	int ret;

	if (type >= REGISTER_TYPE_MAX)
		return -EINVAL;

	mutex_lock(&global_device_lock);
	switch (type) {
	case REGISTER_TYPE_GLOBAL: /* register as the global iommu device */
		ret = set_global_device(ummu_core);
		if (ret)
			goto out_unlock;
		fallthrough;
	case REGISTER_TYPE_NORMAL: /* register to the iommu framework */
		ret = iommu_device_register(&ummu_core->iommu,
						ummu_core->iommu.ops,
						NULL);
		if (ret)
			goto out_reset_device;

		ret = ummu_core_device_add_sysfs(ummu_core);
		if (ret) {
			dev_err(ummu_core->iommu.dev, "ummu core device add sysfs failed.\n");
			iommu_device_unregister(&ummu_core->iommu);
			goto out_reset_device;
		}

		list_add_tail(&ummu_core->list, &core_device_list);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&global_device_lock);
	return ret;

out_reset_device:
	if (type == REGISTER_TYPE_GLOBAL)
		reset_global_device();
out_unlock:
	mutex_unlock(&global_device_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ummu_core_device_register);

void ummu_core_device_unregister(struct ummu_core_device *ummu_core)
{
	struct ummu_core_device *entry, *next;

	mutex_lock(&global_device_lock);
	if (global_core_device == ummu_core)
		reset_global_device();

	list_for_each_entry_safe(entry, next, &core_device_list, list)
		if (entry == ummu_core) {
			iommu_device_unregister(&entry->iommu);
			list_del(&entry->list);
			break;
		}

	ummu_core_device_remove_sysfs(ummu_core);
	mutex_unlock(&global_device_lock);
}
EXPORT_SYMBOL_GPL(ummu_core_device_unregister);

int ummu_core_get_resource(struct iommu_sva *sva, struct device *dev,
			   struct resource_args *args)
{
	struct ummu_core_device *core_device;
	struct iommu_domain *domain;
	struct device *device;

	device = sva ? sva->dev : dev;
	if (!device)
		return -EINVAL;

	domain = sva ? sva->handle.domain : iommu_get_domain_for_dev(device);
	if (!domain)
		return -ENOENT;

	core_device = iommu_get_iommu_dev(device, struct ummu_core_device, iommu);
	if (!core_device->ops || !core_device->ops->get_resource)
		return -ENODEV;

	return core_device->ops->get_resource(to_ummu_base_domain(domain), args);
}

void ummu_core_put_resource(struct iommu_sva *sva, struct device *dev,
			    struct resource_args *args)
{
	struct ummu_core_device *core_device;
	struct iommu_domain *domain;
	struct device *device;

	device = sva ? sva->dev : dev;
	if (!device)
		return;

	domain = sva ? sva->handle.domain : iommu_get_domain_for_dev(device);
	if (!domain)
		return;

	core_device = iommu_get_iommu_dev(device, struct ummu_core_device, iommu);
	if (!core_device->ops || !core_device->ops->put_resource)
		return;

	core_device->ops->put_resource(to_ummu_base_domain(domain), args);
}

int ummu_core_get_hw_cap(struct device *dev, u32 *hw_cap)
{
	int ret;

	if (!hw_cap)
		return -EINVAL;

	mutex_lock(&global_device_lock);
	if (!global_core_device) {
		ret = -ENODEV;
		goto out_unlock;
	}

	if (!global_core_device->ops || !global_core_device->ops->get_hw_cap) {
		ret = -ENOENT;
		goto out_unlock;
	}
	ret = global_core_device->ops->get_hw_cap(dev, hw_cap);

out_unlock:
	mutex_unlock(&global_device_lock);
	return ret;
}

int ummu_core_dev_config(struct device *dev, int type, int command, void *data)
{
	if (!data)
		return -EINVAL;

	guard(mutex)(&global_device_lock);
	if (!global_core_device)
		return -ENODEV;

	if (!global_core_device->ops || !global_core_device->ops->dev_config)
		return -EOPNOTSUPP;

	return global_core_device->ops->dev_config(dev, type, command, data);
}
EXPORT_SYMBOL_GPL(ummu_core_dev_config);

int ummu_get_sva_mode(struct device *dev)
{
	u32 hw_cap;
	int ret;

	if (!dev)
		return -EINVAL;

	ret = ummu_core_get_hw_cap(dev, &hw_cap);
	if (ret)
		return ret;

	if (hw_cap & HW_CAP_IOPF)
		return UMMU_SVA_SHARE_MODE;

	if (IS_ENABLED(CONFIG_UB_UMMU_SVA_SEPARATED_PAGES))
		return UMMU_SVA_SEPARATE_MODE;

	return UMMU_SVA_SHARE_MODE;
}
EXPORT_SYMBOL_GPL(ummu_get_sva_mode);

u32 ummu_sva_get_features(struct device *dev)
{
	u32 features = 0;
	u32 hw_cap;
	int ret;

	if (!dev)
		return 0;

	ret = ummu_core_get_hw_cap(dev, &hw_cap);
	if (ret)
		return 0;

	if (hw_cap & HW_CAP_IOPF)
		features |= HW_CAP_IOPF;

	return features;
}
EXPORT_SYMBOL_GPL(ummu_sva_get_features);

struct iommu_sva *ummu_sva_bind_device(struct device *dev, struct mm_struct *mm,
				       struct ummu_param *drvdata)
{
	struct iommu_sva *sva =
		iommu_sva_bind_device_isolated(dev, mm, drvdata);

	if (IS_ERR(sva))
		return NULL;
	return sva;
}
EXPORT_SYMBOL_GPL(ummu_sva_bind_device);

bool ummu_is_ksva(struct iommu_domain *domain)
{
	return iommu_is_ksva_domain(domain);
}
EXPORT_SYMBOL_GPL(ummu_is_ksva);

bool ummu_is_sva(struct iommu_domain *domain)
{
	return domain->mm && !iommu_is_ksva_domain(domain);
}
EXPORT_SYMBOL_GPL(ummu_is_sva);

struct iommu_sva *ummu_ksva_bind_device(struct device *dev,
					struct ummu_param *drvdata)
{
	struct iommu_sva *sva = iommu_ksva_bind_device(dev, (void *)drvdata);

	if (IS_ERR(sva))
		return NULL;
	return sva;
}
EXPORT_SYMBOL_GPL(ummu_ksva_bind_device);

void ummu_sva_unbind_device(struct iommu_sva *sva)
{
	iommu_sva_unbind_device_isolated(sva);
}
EXPORT_SYMBOL_GPL(ummu_sva_unbind_device);

void ummu_ksva_unbind_device(struct iommu_sva *sva)
{
	iommu_ksva_unbind_device(sva);
}
EXPORT_SYMBOL_GPL(ummu_ksva_unbind_device);

int ummu_sva_grant_range(struct iommu_sva *sva, void *va, size_t size, int perm,
			 void *cookie)
{
	return iommu_sva_grant(sva, va, size, perm, cookie);
}
EXPORT_SYMBOL_GPL(ummu_sva_grant_range);

int ummu_sva_ungrant_range(struct iommu_sva *sva, void *va, size_t size,
			   void *cookie)
{
	return iommu_sva_ungrant(sva, va, size, cookie);
}
EXPORT_SYMBOL_GPL(ummu_sva_ungrant_range);

int ummu_get_tid(struct device *dev, struct iommu_sva *sva, u32 *tidp)
{
	struct iommu_domain *domain;

	if (sva)
		domain = sva->handle.domain;
	else
		domain = iommu_get_domain_for_dev(dev);

	if (!domain)
		return -ENODEV;

	*tidp = to_ummu_base_domain(domain)->tid;
	return 0;
}
EXPORT_SYMBOL_GPL(ummu_get_tid);

int ummu_core_invalidate_cfg_table(u32 tid)
{
	struct iommu_domain *domain;
	struct device *dev;
	int ret;

	mutex_lock(&global_device_lock);
	if (!global_core_device) {
		ret = -ENODEV;
		goto out_unlock;
	}
	dev = ummu_core_get_device(global_core_device, tid);
	if (!dev) {
		ret = -ENODEV;
		goto out_unlock;
	}
	domain = ummu_core_get_domain_by_tid(dev, tid);
	if (!domain) {
		ret = -EINVAL;
		goto out_put_device;
	}
	if (!global_core_device->ops || !global_core_device->ops->invalidate_cfg) {
		ret = -ENODEV;
		goto out_put_device;
	}
	ret = global_core_device->ops->invalidate_cfg(to_ummu_base_domain(domain));

out_put_device:
	ummu_core_put_device(dev);
out_unlock:
	mutex_unlock(&global_device_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ummu_core_invalidate_cfg_table);

int ummu_core_invalidate_cfg(struct ummu_invalid_cfg_param *param)
{

	if (!param || !param->mm)
		return -EINVAL;

	return ummu_core_invalidate_tid(param->mm, param->tid);
}
EXPORT_SYMBOL_GPL(ummu_core_invalidate_cfg);

void ummu_core_tlb_inv_walk(struct iommu_domain *domain, unsigned long iova,
			    size_t size, size_t granule)
{
	if (global_core_device && global_core_device->ops &&
	    global_core_device->ops->tlb_inv_walk)
		global_core_device->ops->tlb_inv_walk(domain, iova, size, granule);
}
EXPORT_SYMBOL_NS_GPL(ummu_core_tlb_inv_walk, UMMU_CORE_DRIVER);

static int __init ummu_core_init(void)
{
	int ret;

	ret = tid_misc_init();
	if (ret)
		return ret;

	ret = tdev_init();
	if (ret)
		tid_misc_exit();

	return ret;
}

static void __exit ummu_core_exit(void)
{
	tdev_exit();
	tid_misc_exit();
}

module_init(ummu_core_init);
module_exit(ummu_core_exit);

MODULE_IMPORT_NS(UMMU_CORE_INTERNAL);
#if IS_MODULE(CONFIG_UB_UMMU_CORE_DRIVER)
MODULE_IMPORT_NS(IOMMUFD_INTERNAL); /* get iommu_attach_handle_get */
#endif
MODULE_DESCRIPTION("UMMU Framework");
MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_LICENSE("GPL");
