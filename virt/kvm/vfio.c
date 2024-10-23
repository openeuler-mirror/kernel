// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO-KVM bridge pseudo device
 *
 * Copyright (C) 2013 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include "vfio.h"

#ifdef CONFIG_SPAPR_TCE_IOMMU
#include <asm/kvm_ppc.h>
#endif

#ifdef CONFIG_HISI_VIRTCCA_CODA
#include <asm/virtcca_cvm_host.h>
#include <asm/virtcca_coda.h>
#endif

struct kvm_vfio_file {
	struct list_head node;
	struct file *file;
#ifdef CONFIG_SPAPR_TCE_IOMMU
	struct iommu_group *iommu_group;
#endif
};

struct kvm_vfio {
	struct list_head file_list;
	struct mutex lock;
	bool noncoherent;
};

static void kvm_vfio_file_set_kvm(struct file *file, struct kvm *kvm)
{
	void (*fn)(struct file *file, struct kvm *kvm);

	fn = symbol_get(vfio_file_set_kvm);
	if (!fn)
		return;

	fn(file, kvm);

	symbol_put(vfio_file_set_kvm);
}

static bool kvm_vfio_file_enforced_coherent(struct file *file)
{
	bool (*fn)(struct file *file);
	bool ret;

	fn = symbol_get(vfio_file_enforced_coherent);
	if (!fn)
		return false;

	ret = fn(file);

	symbol_put(vfio_file_enforced_coherent);

	return ret;
}

static bool kvm_vfio_file_is_valid(struct file *file)
{
	bool (*fn)(struct file *file);
	bool ret;

	fn = symbol_get(vfio_file_is_valid);
	if (!fn)
		return false;

	ret = fn(file);

	symbol_put(vfio_file_is_valid);

	return ret;
}

#ifdef CONFIG_SPAPR_TCE_IOMMU
static struct iommu_group *kvm_vfio_file_iommu_group(struct file *file)
{
	struct iommu_group *(*fn)(struct file *file);
	struct iommu_group *ret;

	fn = symbol_get(vfio_file_iommu_group);
	if (!fn)
		return NULL;

	ret = fn(file);

	symbol_put(vfio_file_iommu_group);

	return ret;
}

static void kvm_spapr_tce_release_vfio_group(struct kvm *kvm,
					     struct kvm_vfio_file *kvf)
{
	if (WARN_ON_ONCE(!kvf->iommu_group))
		return;

	kvm_spapr_tce_release_iommu_group(kvm, kvf->iommu_group);
	iommu_group_put(kvf->iommu_group);
	kvf->iommu_group = NULL;
}
#endif

/*
 * Groups/devices can use the same or different IOMMU domains. If the same
 * then adding a new group/device may change the coherency of groups/devices
 * we've previously been told about. We don't want to care about any of
 * that so we retest each group/device and bail as soon as we find one that's
 * noncoherent.  This means we only ever [un]register_noncoherent_dma once
 * for the whole device.
 */
static void kvm_vfio_update_coherency(struct kvm_device *dev)
{
	struct kvm_vfio *kv = dev->private;
	bool noncoherent = false;
	struct kvm_vfio_file *kvf;

	list_for_each_entry(kvf, &kv->file_list, node) {
		if (!kvm_vfio_file_enforced_coherent(kvf->file)) {
			noncoherent = true;
			break;
		}
	}

	if (noncoherent != kv->noncoherent) {
		kv->noncoherent = noncoherent;

		if (kv->noncoherent)
			kvm_arch_register_noncoherent_dma(dev->kvm);
		else
			kvm_arch_unregister_noncoherent_dma(dev->kvm);
	}
}

static int kvm_vfio_file_add(struct kvm_device *dev, unsigned int fd)
{
	struct kvm_vfio *kv = dev->private;
	struct kvm_vfio_file *kvf;
	struct file *filp;
	int ret = 0;

	filp = fget(fd);
	if (!filp)
		return -EBADF;

	/* Ensure the FD is a vfio FD. */
	if (!kvm_vfio_file_is_valid(filp)) {
		ret = -EINVAL;
		goto out_fput;
	}

	mutex_lock(&kv->lock);

	list_for_each_entry(kvf, &kv->file_list, node) {
		if (kvf->file == filp) {
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	kvf = kzalloc(sizeof(*kvf), GFP_KERNEL_ACCOUNT);
	if (!kvf) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	kvf->file = get_file(filp);
	list_add_tail(&kvf->node, &kv->file_list);

	kvm_arch_start_assignment(dev->kvm);
	kvm_vfio_file_set_kvm(kvf->file, dev->kvm);
	kvm_vfio_update_coherency(dev);
#ifdef CONFIG_HISI_VIRTCCA_CODA
	ret = cvm_vfio_add_kvm_to_smmu_domain(filp, (void *)kv);
#endif

out_unlock:
	mutex_unlock(&kv->lock);
out_fput:
	fput(filp);
	return ret;
}

static int kvm_vfio_file_del(struct kvm_device *dev, unsigned int fd)
{
	struct kvm_vfio *kv = dev->private;
	struct kvm_vfio_file *kvf;
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = -ENOENT;

	mutex_lock(&kv->lock);

	list_for_each_entry(kvf, &kv->file_list, node) {
		if (kvf->file != f.file)
			continue;

		list_del(&kvf->node);
		kvm_arch_end_assignment(dev->kvm);
#ifdef CONFIG_SPAPR_TCE_IOMMU
		kvm_spapr_tce_release_vfio_group(dev->kvm, kvf);
#endif
		kvm_vfio_file_set_kvm(kvf->file, NULL);
		fput(kvf->file);
		kfree(kvf);
		ret = 0;
		break;
	}

	kvm_vfio_update_coherency(dev);

	mutex_unlock(&kv->lock);

	fdput(f);

	return ret;
}

#ifdef CONFIG_SPAPR_TCE_IOMMU
static int kvm_vfio_file_set_spapr_tce(struct kvm_device *dev,
				       void __user *arg)
{
	struct kvm_vfio_spapr_tce param;
	struct kvm_vfio *kv = dev->private;
	struct kvm_vfio_file *kvf;
	struct fd f;
	int ret;

	if (copy_from_user(&param, arg, sizeof(struct kvm_vfio_spapr_tce)))
		return -EFAULT;

	f = fdget(param.groupfd);
	if (!f.file)
		return -EBADF;

	ret = -ENOENT;

	mutex_lock(&kv->lock);

	list_for_each_entry(kvf, &kv->file_list, node) {
		if (kvf->file != f.file)
			continue;

		if (!kvf->iommu_group) {
			kvf->iommu_group = kvm_vfio_file_iommu_group(kvf->file);
			if (WARN_ON_ONCE(!kvf->iommu_group)) {
				ret = -EIO;
				goto err_fdput;
			}
		}

		ret = kvm_spapr_tce_attach_iommu_group(dev->kvm, param.tablefd,
						       kvf->iommu_group);
		break;
	}

err_fdput:
	mutex_unlock(&kv->lock);
	fdput(f);
	return ret;
}
#endif

static int kvm_vfio_set_file(struct kvm_device *dev, long attr,
			     void __user *arg)
{
	int32_t __user *argp = arg;
	int32_t fd;

	switch (attr) {
	case KVM_DEV_VFIO_FILE_ADD:
		if (get_user(fd, argp))
			return -EFAULT;
		return kvm_vfio_file_add(dev, fd);

	case KVM_DEV_VFIO_FILE_DEL:
		if (get_user(fd, argp))
			return -EFAULT;
		return kvm_vfio_file_del(dev, fd);

#ifdef CONFIG_SPAPR_TCE_IOMMU
	case KVM_DEV_VFIO_GROUP_SET_SPAPR_TCE:
		return kvm_vfio_file_set_spapr_tce(dev, arg);
#endif
	}

	return -ENXIO;
}

static int kvm_vfio_set_attr(struct kvm_device *dev,
			     struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_DEV_VFIO_FILE:
		return kvm_vfio_set_file(dev, attr->attr,
					 u64_to_user_ptr(attr->addr));
	}

	return -ENXIO;
}

static int kvm_vfio_has_attr(struct kvm_device *dev,
			     struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_DEV_VFIO_FILE:
		switch (attr->attr) {
		case KVM_DEV_VFIO_FILE_ADD:
		case KVM_DEV_VFIO_FILE_DEL:
#ifdef CONFIG_SPAPR_TCE_IOMMU
		case KVM_DEV_VFIO_GROUP_SET_SPAPR_TCE:
#endif
			return 0;
		}

		break;
	}

	return -ENXIO;
}

static void kvm_vfio_release(struct kvm_device *dev)
{
	struct kvm_vfio *kv = dev->private;
	struct kvm_vfio_file *kvf, *tmp;

	list_for_each_entry_safe(kvf, tmp, &kv->file_list, node) {
#ifdef CONFIG_SPAPR_TCE_IOMMU
		kvm_spapr_tce_release_vfio_group(dev->kvm, kvf);
#endif
		kvm_vfio_file_set_kvm(kvf->file, NULL);
		fput(kvf->file);
		list_del(&kvf->node);
		kfree(kvf);
		kvm_arch_end_assignment(dev->kvm);
	}

	kvm_vfio_update_coherency(dev);

	kfree(kv);
	kfree(dev); /* alloc by kvm_ioctl_create_device, free by .release */
}

static int kvm_vfio_create(struct kvm_device *dev, u32 type);

static struct kvm_device_ops kvm_vfio_ops = {
	.name = "kvm-vfio",
	.create = kvm_vfio_create,
	.release = kvm_vfio_release,
	.set_attr = kvm_vfio_set_attr,
	.has_attr = kvm_vfio_has_attr,
};

static int kvm_vfio_create(struct kvm_device *dev, u32 type)
{
	struct kvm_device *tmp;
	struct kvm_vfio *kv;

	/* Only one VFIO "device" per VM */
	list_for_each_entry(tmp, &dev->kvm->devices, vm_node)
		if (tmp->ops == &kvm_vfio_ops)
			return -EBUSY;

	kv = kzalloc(sizeof(*kv), GFP_KERNEL_ACCOUNT);
	if (!kv)
		return -ENOMEM;

	INIT_LIST_HEAD(&kv->file_list);
	mutex_init(&kv->lock);

	dev->private = kv;

	return 0;
}

int kvm_vfio_ops_init(void)
{
	return kvm_register_device_ops(&kvm_vfio_ops, KVM_DEV_TYPE_VFIO);
}

void kvm_vfio_ops_exit(void)
{
	kvm_unregister_device_ops(KVM_DEV_TYPE_VFIO);
}

#ifdef CONFIG_HISI_VIRTCCA_CODA
/**
 * cvm_vfio_add_kvm_to_smmu_domain - Bind the confidential
 * virtual machine to smmu domain
 * @filp: The handle of file
 * @kvm: The kvm belone to confidential virtual machine
 *
 * Returns:
 * %-ENXIO if set kvm failed or iommu group is null
 * %0 if set kvm success
 */
int cvm_vfio_add_kvm_to_smmu_domain(struct file *filp, void *kv)
{
	struct iommu_group *iommu_group;
	int ret = 0;
	struct kvm_vfio *_kv = (struct kvm_vfio *)kv;

	if (!is_virtcca_cvm_enable())
		return ret;

	/* Upper-level calling interface has added a kv lock, but the
	 * virtcca_cvm_arm_smmu_domain_set_kvm interface also need add this lock.
	 * Therefore, it is necessary to unlock here and completing the
	 * acquisition, then add the kv lock before return.
	 */
	mutex_unlock(&_kv->lock);
	iommu_group = cvm_vfio_file_iommu_group(filp);
	if (!iommu_group) {
		ret = -ENXIO;
		goto out_lock;
	}
	if (virtcca_cvm_arm_smmu_domain_set_kvm((void *)iommu_group) != 1) {
		ret = -ENXIO;
		goto out_lock;
	}

out_lock:
	mutex_lock(&_kv->lock);
	return ret;
}

/**
 * virtcca_arm_smmu_get_kvm - Find the kvm
 * with vfio devices through SMMU domain
 * @domain: Smmu domain
 *
 * Returns:
 * %kvm if find the kvm with vfio devices
 * %NULL if kvm is null
 */
struct kvm *virtcca_arm_smmu_get_kvm(struct arm_smmu_domain *domain)
{
	int ret = -1;
	struct kvm *kvm;
	struct kvm_device *dev;
	struct kvm_vfio *kv;
	struct kvm_vfio_file *kvf;
	struct iommu_group *iommu_group;
	unsigned long flags;
	struct arm_smmu_master *master;

	spin_lock_irqsave(&domain->devices_lock, flags);
	/* Get smmu master from smmu domain */
	list_for_each_entry(master, &domain->devices, domain_head) {
		if (master && master->num_streams >= 0) {
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&domain->devices_lock, flags);
	if (ret)
		return NULL;

	ret = -1;
	iommu_group = master->dev->iommu_group;
	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		mutex_lock(&kvm->lock);
		/* Get kvm vfio device list from kvm */
		list_for_each_entry(dev, &kvm->devices, vm_node) {
			if (dev->ops && strcmp(dev->ops->name, "kvm-vfio") != 0)
				continue;

			/* Find the kvm vfio which device name is kvm-vfio */
			kv = (struct kvm_vfio *)dev->private;
			mutex_lock(&kv->lock);
			list_for_each_entry(kvf, &kv->file_list, node) {
				/* Get iommu_group from vfio file */
				if (cvm_vfio_file_iommu_group(kvf->file) == iommu_group) {
					ret = 0;
					break;
				}
			}
			mutex_unlock(&kv->lock);
			if (!ret)
				break;
		}
		mutex_unlock(&kvm->lock);
		if (!ret)
			break;
	}
	mutex_unlock(&kvm_lock);

	if (ret)
		return NULL;
	return kvm;
}
EXPORT_SYMBOL_GPL(virtcca_arm_smmu_get_kvm);

/**
 * find_arm_smmu_domain - Find smmu domain list from kvm vfio file
 * @kvf: Kvm vfio file
 * @smmu_domain_group_list: List of smmu domain group
 */
int find_arm_smmu_domain(struct device *dev, void *data)
{
	int ret = 0;
	struct iommu_domain *domain = NULL;
	struct arm_smmu_domain *arm_smmu_domain = NULL;
	struct arm_smmu_domain *arm_smmu_domain_node = NULL;
	struct list_head *smmu_domain_group_list = (struct list_head *)data;

	domain = iommu_get_domain_for_dev(dev);
	arm_smmu_domain = to_smmu_domain(domain);
	list_for_each_entry(arm_smmu_domain_node,
		smmu_domain_group_list, node) {
		if (arm_smmu_domain_node == arm_smmu_domain) {
			ret = -1;
			break;
		}
	}
	if (!ret)
		list_add_tail(&arm_smmu_domain->node, smmu_domain_group_list);

	return 1;
}

/**
 * kvm_get_arm_smmu_domain - Find kvm vfio file from kvm
 * @kvm: Kvm handle
 * @smmu_domain_group_list: List of smmu domain group
 */
void kvm_get_arm_smmu_domain(struct kvm *kvm, struct list_head *smmu_domain_group_list)
{
	struct kvm_device *dev;
	struct kvm_vfio *kv;
	struct kvm_vfio_file *kvf;
	struct iommu_group *iommu_group = NULL;

	INIT_LIST_HEAD(smmu_domain_group_list);

	list_for_each_entry(dev, &kvm->devices, vm_node) {
		/* The device name passed through the vfio driver is called kvm-vfio */
		if (dev->ops && strcmp(dev->ops->name, "kvm-vfio") != 0)
			continue;

		kv = (struct kvm_vfio *)dev->private;
		mutex_lock(&kv->lock);
		list_for_each_entry(kvf, &kv->file_list, node) {
			iommu_group = cvm_vfio_file_iommu_group(kvf->file);
			iommu_group_for_each_dev(iommu_group,
				(void *)smmu_domain_group_list, find_arm_smmu_domain);
		}
		mutex_unlock(&kv->lock);
	}
}

/**
 * cvm_smmu_domain_judge - Find the iommu group corresponding to the smmu domain
 * @dev: The handle of device
 * @data: Smmu domain
 *
 * Returns:
 * %-ENXIO if domain is null
 * %SMMU_DOMAIN_IS_SAME if find the iommu group corresponding to the smmu domain
 * %1 if does not find the iommu group
 */
int cvm_smmu_domain_judge(struct device *dev, void *data)
{
	struct iommu_domain *domain = NULL;
	struct arm_smmu_domain *arm_smmu_domain = NULL;
	struct arm_smmu_domain *smmu_domain = (struct arm_smmu_domain *)data;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return -ENXIO;

	arm_smmu_domain = to_smmu_domain(domain);
	if (arm_smmu_domain == smmu_domain)
		return SMMU_DOMAIN_IS_SAME;

	return 1;
}

/* Judge the iommu group correspond to the smmu domain */
int virtcca_cvm_smmu_domain_judge(struct iommu_group *group, struct arm_smmu_domain *smmu_domain)
{
	int ret;

	ret = iommu_group_for_each_dev((struct iommu_group *)group,
		(void *)smmu_domain, cvm_smmu_domain_judge);
	return ret;
}

/**
 * virtcca_iommu_group_map_msi_address - Find iommu group from kvm vfio file, map it
 * @kvm: The handle of kvm
 * @kvf: Kvm vfio file
 * @smmu_domain: Smmu domain
 * @pa: Physical address
 * @map_size: Mapped size
 */
int virtcca_iommu_group_map_msi_address(struct kvm *kvm, struct kvm_vfio_file *kvf,
	struct arm_smmu_domain *smmu_domain, phys_addr_t pa, unsigned long map_size)
{
	unsigned long iova;
	int ret = 0;
	struct iommu_group *iommu_group = NULL;

	iommu_group = cvm_vfio_file_iommu_group(kvf->file);
	if (iommu_group) {
		if (virtcca_cvm_smmu_domain_judge(iommu_group, smmu_domain) ==
			SMMU_DOMAIN_IS_SAME) {
			iova = virtcca_get_iommu_device_msi_addr(iommu_group);
			if (!iova)
				return -ENXIO;

			ret = virtcca_iommu_group_set_dev_msi_addr(iommu_group, &iova);
			if (ret)
				return ret;

			ret = cvm_map_unmap_ipa_range(kvm, iova, pa, map_size, true);
			if (ret)
				return ret;
		}
	}
	return ret;
}

/* Get iommu group from specific smmu domain, map it */
int virtcca_map_msi_address(struct kvm *kvm, struct arm_smmu_domain *smmu_domain,
	phys_addr_t pa, unsigned long map_size)
{
	int ret = 0;
	struct kvm_device *dev;
	struct kvm_vfio *kv;
	struct kvm_vfio_file *kvf;

	mutex_lock(&kvm->lock);
	list_for_each_entry(dev, &kvm->devices, vm_node) {
		/* Get kvm vfio device list */
		if (dev->ops && strcmp(dev->ops->name, "kvm-vfio") == 0) {
			kv = (struct kvm_vfio *)dev->private;
			mutex_lock(&kv->lock);
			list_for_each_entry(kvf, &kv->file_list, node) {
				/* Get iommu_group from vfio file, map it */
				ret = virtcca_iommu_group_map_msi_address(kvm, kvf, smmu_domain,
					pa, map_size);
			}
			mutex_unlock(&kv->lock);
			if (ret)
				break;
		}
	}
	mutex_unlock(&kvm->lock);
	return ret;
}
#endif
