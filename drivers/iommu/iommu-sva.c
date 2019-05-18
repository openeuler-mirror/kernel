// SPDX-License-Identifier: GPL-2.0
/*
 * Manage PASIDs and bind process address spaces to devices.
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/iommu.h>
#include <linux/slab.h>

/**
 * iommu_sva_device_init() - Initialize Shared Virtual Addressing for a device
 * @dev: the device
 * @features: bitmask of features that need to be initialized
 * @max_pasid: max PASID value supported by the device
 *
 * Users of the bind()/unbind() API must call this function to initialize all
 * features required for SVA.
 *
 * The device must support multiple address spaces (e.g. PCI PASID). By default
 * the PASID allocated during bind() is limited by the IOMMU capacity, and by
 * the device PASID width defined in the PCI capability or in the firmware
 * description. Setting @max_pasid to a non-zero value smaller than this limit
 * overrides it.
 *
 * The device should not be performing any DMA while this function is running,
 * otherwise the behavior is undefined.
 *
 * Return 0 if initialization succeeded, or an error.
 */
int iommu_sva_device_init(struct device *dev, unsigned long features,
			  unsigned int max_pasid)
{
	int ret;
	struct iommu_sva_param *param;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (!domain || !domain->ops->sva_device_init)
		return -ENODEV;

	if (features)
		return -EINVAL;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	param->features		= features;
	param->max_pasid	= max_pasid;

	/*
	 * IOMMU driver updates the limits depending on the IOMMU and device
	 * capabilities.
	 */
	ret = domain->ops->sva_device_init(dev, param);
	if (ret)
		goto err_free_param;

	mutex_lock(&dev->iommu_param->lock);
	if (dev->iommu_param->sva_param)
		ret = -EEXIST;
	else
		dev->iommu_param->sva_param = param;
	mutex_unlock(&dev->iommu_param->lock);
	if (ret)
		goto err_device_shutdown;

	return 0;

err_device_shutdown:
	if (domain->ops->sva_device_shutdown)
		domain->ops->sva_device_shutdown(dev, param);

err_free_param:
	kfree(param);

	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_device_init);

/**
 * iommu_sva_device_shutdown() - Shutdown Shared Virtual Addressing for a device
 * @dev: the device
 *
 * Disable SVA. Device driver should ensure that the device isn't performing any
 * DMA while this function is running.
 */
int iommu_sva_device_shutdown(struct device *dev)
{
	struct iommu_sva_param *param;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (!domain)
		return -ENODEV;

	__iommu_sva_unbind_dev_all(dev);

	mutex_lock(&dev->iommu_param->lock);
	param = dev->iommu_param->sva_param;
	dev->iommu_param->sva_param = NULL;
	mutex_unlock(&dev->iommu_param->lock);
	if (!param)
		return -ENODEV;

	if (domain->ops->sva_device_shutdown)
		domain->ops->sva_device_shutdown(dev, param);

	kfree(param);

	return 0;
}
EXPORT_SYMBOL_GPL(iommu_sva_device_shutdown);

int __iommu_sva_bind_device(struct device *dev, struct mm_struct *mm,
			    int *pasid, unsigned long flags, void *drvdata)
{
	return -ENOSYS; /* TODO */
}
EXPORT_SYMBOL_GPL(__iommu_sva_bind_device);

int __iommu_sva_unbind_device(struct device *dev, int pasid)
{
	return -ENOSYS; /* TODO */
}
EXPORT_SYMBOL_GPL(__iommu_sva_unbind_device);

/**
 * __iommu_sva_unbind_dev_all() - Detach all address spaces from this device
 * @dev: the device
 *
 * When detaching @device from a domain, IOMMU drivers should use this helper.
 */
void __iommu_sva_unbind_dev_all(struct device *dev)
{
	/* TODO */
}
EXPORT_SYMBOL_GPL(__iommu_sva_unbind_dev_all);
