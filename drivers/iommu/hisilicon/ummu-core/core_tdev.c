// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., All rights reserved.
 * Description: Token-ID Device API.
 */

#define pr_fmt(fmt) "[UMMU_CORE][TDEV]: " fmt

#include <linux/dma-map-ops.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <ub/ubus/ubus.h>

#include "ummu_core_priv.h"

static DEFINE_XARRAY(mm_tid_xa);
static DEFINE_MUTEX(mm_tid_xa_lock);

static void ummu_root_release(struct device *dev)
{
	pr_info("ummu_tid_root release.\n");
}

struct device tid_bus = {
	.init_name = "ummu_tid_root",
	.parent = &platform_bus,
	.release = ummu_root_release,
};

static void ummu_release_dev(struct device *dev)
{
	struct tid_dev *tdev;

	tdev = to_tid_dev(dev);
	kfree(tdev->pdev.name);
	kfree(tdev);
}

/* tdev device sysfs */
static int attr_get_tid(struct device *dev, u32 *tid)
{
	struct tid_dev *tdev;

	tdev = to_tid_dev(dev);

	return ummu_get_tid(dev, tdev->sva, tid);
}

static ssize_t tid_val_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	u32 tid;
	int ret;

	ret = attr_get_tid(dev, &tid);
	if (ret)
		return ret;

	return sysfs_emit(buf, "%u\n", tid);
}
static DEVICE_ATTR_RO(tid_val);

static ssize_t tid_mode_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct ummu_core_device *ummu_core;
	u32 tid;
	int ret;

	ummu_core = to_ummu_core(dev->iommu->iommu_dev);
	ret = attr_get_tid(dev, &tid);
	if (ret)
		return ret;

	ret = ummu_core_get_mapt_mode(ummu_core, tid);

	return sysfs_emit(buf, "%d\n", ret);
}
static DEVICE_ATTR_RO(tid_mode);

static struct attribute *ummu_vdev_attrs[] = {
	&dev_attr_tid_val.attr,
	&dev_attr_tid_mode.attr,
	NULL,
};

static struct attribute_group ummu_vdev_group = {
	.name = "ummu-vdev-attr",
	.attrs = ummu_vdev_attrs,
};

static const struct attribute_group *ummu_vdev_groups[] = {
	&ummu_vdev_group,
	NULL,
};

static int alloc_software_node(struct device *dev, u32 *ptid,
				struct tdev_attr *attr,
				const struct software_node *parent)
{
	struct property_entry props[5] = {0};

	props[0] = PROPERTY_ENTRY_U32("assign-pasid", *ptid);
	props[1] = PROPERTY_ENTRY_U32("pasid-num-bits", UB_MAX_TID_BITS);
	props[2] = PROPERTY_ENTRY_U32("mapt-mode", attr->mode);

	if (attr->usva)
		props[3] = PROPERTY_ENTRY_BOOL("usva-used");

	return device_create_managed_software_node(dev, props, parent);
}

/* tdev device creation */
static int init_tdev(struct tid_dev *tdev, struct tdev_attr *attr, u32 *ptid,
		     struct ummu_core_device *ummu_core)
{
	int ret;

	if (!tdev->pdev.dev.parent)
		tdev->pdev.dev.parent = ummu_core->ummu_core_root;

	tdev->pdev.name = kstrdup(attr->name ? : "ummu_vdev", GFP_KERNEL);
	if (!tdev->pdev.name)
		return -EINVAL;

	ret = alloc_software_node(&tdev->pdev.dev, ptid, attr, NULL);
	if (ret) {
		pr_err("tdev create software node ERR!:%d\n", ret);
		kfree(tdev->pdev.name);
		return ret;
	}

	tdev->pdev.id = PLATFORM_DEVID_AUTO;
	tdev->pdev.dev.release = ummu_release_dev;
	tdev->pdev.dev.coherent_dma_mask = DMA_BIT_MASK(48); // 48 DMA addr size
	tdev->pdev.dev.dma_mask = &(tdev->pdev.dev.coherent_dma_mask);
	tdev->pdev.dev.groups = ummu_vdev_groups;
	tdev->pdev.dma_parms.max_segment_size = U32_MAX;
	device_set_pm_not_required(&tdev->pdev.dev);
	set_dev_node(&tdev->pdev.dev, NUMA_NO_NODE);

	return 0;
}

static struct iommu_device *get_iommu_dev(struct tdev_attr *attr)
{
	struct ummu_core_device *entry;

	mutex_lock(&global_device_lock);
	list_for_each_entry(entry, &core_device_list, list) {
		if (!entry->ops || !entry->ops->tdev_support_attr)
			continue;
		if (entry->ops->tdev_support_attr(entry, attr)) {
			mutex_unlock(&global_device_lock);
			return &entry->iommu;
		}
	}
	mutex_unlock(&global_device_lock);

	pr_err("ummu device not found.\n");
	return NULL;
}

static void set_dma_configure(struct device *dev, enum dev_dma_attr attr)
{
	if (attr == DEV_DMA_NOT_SUPPORTED)
		return;

	setup_tdev_dma_ops(dev, attr == DEV_DMA_COHERENT);
}

struct device *ummu_alloc_tdev(struct tdev_attr *attr, u32 *ptid)
{
	struct iommu_device *iommu_dev;
	struct tid_dev *tdev;
	int ret;

	iommu_dev = get_iommu_dev(attr);
	if (!iommu_dev)
		return NULL;

	tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return NULL;

	kref_init(&tdev->ref);

	ret = iommu_fwspec_init(&tdev->pdev.dev, iommu_dev->fwnode, iommu_dev->ops);
	if (ret)
		goto dev_free;

	ret = init_tdev(tdev, attr, ptid, to_ummu_core(iommu_dev));
	if (ret)
		goto fwspec_free;

	ret = platform_device_register(&tdev->pdev);
	if (ret) {
		iommu_fwspec_free(&tdev->pdev.dev);
		platform_device_put(&tdev->pdev);
		return NULL;
	}

	if (!device_iommu_mapped(&tdev->pdev.dev)) {
		platform_device_unregister(&tdev->pdev);
		return NULL;
	}

	set_dma_configure(&tdev->pdev.dev, attr->dma_attr);

	return &tdev->pdev.dev;

fwspec_free:
	iommu_fwspec_free(&tdev->pdev.dev);
dev_free:
	kfree(tdev);
	return NULL;
}

struct device *ummu_core_alloc_tdev(struct tdev_attr *attr, u32 *ptid)
{
	u32 temp_tid = UMMU_INVALID_TID;
	struct device *dev;
	int ret;

	if (!ptid || !attr) {
		pr_err("invalid param\n");
		return NULL;
	}

	if (*ptid != UMMU_INVALID_TID)
		temp_tid = *ptid;

	dev = ummu_alloc_tdev(attr, ptid);
	if (!dev)
		return NULL;

	ret = ummu_get_tid(dev, NULL, ptid);
	if (ret || (temp_tid != UMMU_INVALID_TID && temp_tid != *ptid)) {
		ummu_core_free_tdev(dev);
		return NULL;
	}

	return dev;
}
EXPORT_SYMBOL_GPL(ummu_core_alloc_tdev);

struct device *ummu_alloc_tdev_separated(u32 *ptid)
{
	struct tdev_attr attr;

	if (!ptid)
		return NULL;

	*ptid = UMMU_INVALID_TID;
	tdev_attr_init(&attr);
	attr.usva = true;

	return ummu_core_alloc_tdev(&attr, ptid);
}
EXPORT_SYMBOL_GPL(ummu_alloc_tdev_separated);

#if IS_ENABLED(CONFIG_UB_UMMU_SVA_SEPARATED_PAGES)
struct device *ummu_core_alloc_separate_tdev(struct tdev_opt *opt, u32 *ptid)
{
	struct tdev_attr attr;
	struct tid_dev *tdev;
	struct device *dev;
	int ret;

	if (!ptid || !opt || (opt->share_by_mm && !opt->mm))
		return NULL;

	*ptid = UMMU_INVALID_TID;
	tdev_attr_init(&attr);
	attr.usva = true;

	if (!opt->share_by_mm)
		return ummu_core_alloc_tdev(&attr, ptid);

	mutex_lock(&mm_tid_xa_lock);
	tdev = xa_load(&mm_tid_xa, (unsigned long)(uintptr_t)opt->mm);
	if (tdev) {
		if (ummu_get_tid(&tdev->pdev.dev, NULL, ptid))
			goto err_out;

		kref_get(&tdev->ref);
		mutex_unlock(&mm_tid_xa_lock);
		return &tdev->pdev.dev;
	}

	dev = ummu_core_alloc_tdev(&attr, ptid);
	if (!dev)
		goto err_out;

	tdev = to_tid_dev(dev);
	tdev->mm = opt->mm;
	ret = xa_err(__xa_store(&mm_tid_xa, (unsigned long)(uintptr_t)opt->mm,
		tdev, GFP_KERNEL));
	mutex_unlock(&mm_tid_xa_lock);
	if (ret) {
		ummu_core_free_tdev(dev);
		return NULL;
	}

	return dev;
err_out:
	mutex_unlock(&mm_tid_xa_lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(ummu_core_alloc_separate_tdev);
#endif /* CONFIG_UB_UMMU_SVA_SEPARATED_PAGES */

static void ummu_core_tdev_release(struct kref *ref)
{
	struct tid_dev *tdev = container_of(ref, struct tid_dev, ref);
	struct tid_dev *entry;

	scoped_guard(mutex, &mm_tid_xa_lock) {
		if (tdev->mm) {
			entry = (struct tid_dev *)__xa_erase(&mm_tid_xa,
							     (unsigned long)(uintptr_t)tdev->mm);
			WARN_ON(entry != tdev);
		}
	}

	platform_device_unregister(&tdev->pdev);
}

int ummu_core_free_tdev(struct device *dev)
{
	struct tid_dev *tdev = to_tid_dev(dev);

	kref_put(&tdev->ref, ummu_core_tdev_release);
	return 0;
}
EXPORT_SYMBOL_GPL(ummu_core_free_tdev);

int tdev_init(void)
{
	device_set_pm_not_required(&tid_bus);
	return device_register(&tid_bus);
}

void tdev_exit(void)
{
	WARN_ON(!(xa_empty(&mm_tid_xa)));
	xa_destroy(&mm_tid_xa);
	device_unregister(&tid_bus);
}
