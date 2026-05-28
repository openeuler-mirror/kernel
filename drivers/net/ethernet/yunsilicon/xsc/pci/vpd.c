// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/kernfs.h>
#include "common/xsc_core.h"

#define MAX_VPD_SIZE PAGE_SIZE
#define XSC_VSC_LEN 8
#define XSC_VPD_CAP_SIZEOF (PCI_CAP_VPD_SIZEOF + XSC_VSC_LEN)

struct xsc_vpd {
	struct bin_attribute *original_config_attr;
	struct bin_attribute new_config_attr;
	struct bin_attribute *original_attr;
	struct bin_attribute new_attr;
	char *data;
	u8 cap;
	u8 hdr[XSC_VPD_CAP_SIZEOF];
	size_t size;
	struct mutex lock; /* vpd cache read lock */
};

static ssize_t cached_vpd_read(struct file *filp, struct kobject *kobj,
			       struct bin_attribute *attr,
			       char *buf, loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct pci_dev *pdev = to_pci_dev(dev);
	struct xsc_core_device *xdev = pci_get_drvdata(pdev);
	struct xsc_vpd *vpd = xdev->priv.vpd;
	ssize_t ret = 0;

	if (!vpd || !vpd->data)
		return -ENODATA;

	mutex_lock(&vpd->lock);

	if (off >= vpd->size)
		goto out_unlock;

	if (off + count > vpd->size)
		count = vpd->size - off;

	memcpy(buf, vpd->data + off, count);
	ret = count;

out_unlock:
	mutex_unlock(&vpd->lock);
	return ret;
}

static struct bin_attribute *get_vpd_attribute(struct pci_dev *dev)
{
	struct kernfs_node *kn;
	struct bin_attribute *attr = NULL;

	kn = kernfs_find_and_get(dev->dev.kobj.sd, "vpd");
	if (kn) {
		attr = kn->priv;
		kernfs_put(kn);
		return attr;
	}
	return NULL;
}

static ssize_t read_vpd_data(struct pci_dev *dev, char *buf, size_t size)
{
	return pci_read_vpd(dev, 0, size, buf);
}

static int safe_backup_vpd_data(struct pci_dev *dev, struct xsc_vpd *vpd)
{
	struct bin_attribute *orig_attr = get_vpd_attribute(dev);
	char *data = NULL;
	ssize_t ret;
	size_t buf_size = MAX_VPD_SIZE;
	size_t actual_size = 0;

	if (!orig_attr)
		return -ENOENT;

	data = kzalloc(buf_size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = read_vpd_data(dev, data, buf_size);
	if (ret < 0) {
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
			    "Failed to read VPD data: %zd\n", ret);
		kfree(data);
		return ret;
	}

	actual_size = ret;
	if (actual_size == 0) {
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
			    "Empty VPD data\n");
		kfree(data);
		return -ENODATA;
	}

	vpd->cap = pci_find_capability(dev, PCI_CAP_ID_VPD);
	pci_read_config_dword(dev, vpd->cap, (u32 *)vpd->hdr);
	pci_read_config_dword(dev, vpd->cap + PCI_CAP_VPD_SIZEOF,
			      (u32 *)(vpd->hdr + PCI_CAP_VPD_SIZEOF));
	vpd->data = data;
	vpd->size = actual_size;
	vpd->original_attr = orig_attr;

	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG, &dev->dev,
		    "Successfully backed up %zu bytes of VPD data, cap: %u\n",
		    actual_size, vpd->cap);
	return 0;
}

static int replace_vpd_file(struct pci_dev *dev, struct xsc_vpd *cache)
{
	int ret;

	sysfs_remove_bin_file(&dev->dev.kobj, cache->original_attr);

	sysfs_bin_attr_init(&cache->new_attr);
	cache->new_attr.attr.name = "vpd";
	cache->new_attr.attr.mode = 0444;
	cache->new_attr.read = cached_vpd_read;
	cache->new_attr.size = cache->size;

	ret = sysfs_create_bin_file(&dev->dev.kobj, &cache->new_attr);
	if (ret) {
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
			    "Failed to create cached VPD file: %d\n", ret);
		if (sysfs_create_bin_file(&dev->dev.kobj, cache->original_attr))
			xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
				    "Critical: Failed to restore original VPD file\n");
		return ret;
	}

	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG, &dev->dev,
		    "Successfully replaced VPD with cached version\n");
	return 0;
}

static int restore_original_vpd(struct pci_dev *dev, struct xsc_vpd *cache)
{
	int ret = 0;

	if (cache->original_attr) {
		ret = sysfs_create_bin_file(&dev->dev.kobj, cache->original_attr);
		if (ret) {
			xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
				    "Failed to restore original VPD file: %d\n", ret);
			return ret;
		}
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG, &dev->dev,
			    "Successfully restored original VPD file\n");
	}

	return ret;
}

static struct bin_attribute *get_config_attribute(struct pci_dev *dev)
{
	struct kernfs_node *kn;
	struct bin_attribute *attr = NULL;

	kn = kernfs_find_and_get(dev->dev.kobj.sd, "config");
	if (kn) {
		attr = kn->priv;
		kernfs_put(kn);
		return attr;
	}
	return NULL;
}

static ssize_t xsc_pci_read_config(struct file *filp, struct kobject *kobj,
				   struct bin_attribute *bin_attr, char *buf,
				   loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct pci_dev *pdev = to_pci_dev(dev);
	struct xsc_core_device *xdev = pci_get_drvdata(pdev);
	struct xsc_vpd *vpd = xdev->priv.vpd;
	struct bin_attribute *orig_config_file = vpd->original_config_attr;
	size_t size;
	ssize_t ret;
	ssize_t total_read = 0;

	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG, dev,
		    "XSC PCI config read, off=%lld, count=%zu", off, count);

	if (!buf || off >= pdev->cfg_size)
		return 0;

	if (off + count <= vpd->cap || off >= (vpd->cap + XSC_VPD_CAP_SIZEOF))
		return orig_config_file->read(filp, kobj, bin_attr, buf, off, count);

	count = min(count, (size_t)(pdev->cfg_size - off));
	while (count > 0) {
		if (off < vpd->cap) {
			size = min(count, (size_t)(vpd->cap - off));
			ret = orig_config_file->read(filp, kobj, bin_attr, buf, off, size);
		} else if (off < vpd->cap + XSC_VPD_CAP_SIZEOF) {
			size = min(count, (size_t)(vpd->cap + XSC_VPD_CAP_SIZEOF - off));
			xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG, dev,
				    "read VPD cap, off=%lld, count=%zu", off, size);
			memcpy(buf, vpd->hdr + off - vpd->cap, size);
			ret = size;
		} else {
			size = count;
			ret = orig_config_file->read(filp, kobj, bin_attr, buf, off, size);
		}

		if (ret <= 0) {
			if (total_read > 0)
				return total_read;
			return ret;
		}

		buf += ret;
		off += ret;
		count -= ret;
		total_read += ret;
	}

	return total_read;
}

static int replace_pci_config_file(struct pci_dev *dev, struct xsc_vpd *cache)
{
	int ret;
	struct bin_attribute *orig_attr = get_config_attribute(dev);

	if (!orig_attr)
		return -ENOENT;

	sysfs_bin_attr_init(&cache->new_config_attr);
	cache->new_config_attr.attr.name = "config";
	cache->new_config_attr.attr.mode = orig_attr->attr.mode;
	cache->new_config_attr.read = xsc_pci_read_config;
	cache->new_config_attr.write = orig_attr->write;
	cache->new_config_attr.size = dev->cfg_size;

	sysfs_remove_bin_file(&dev->dev.kobj, orig_attr);

	ret = sysfs_create_bin_file(&dev->dev.kobj, &cache->new_config_attr);
	if (ret) {
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
			    "Failed to create XSC PCI config file: %d\n", ret);
		if (sysfs_create_bin_file(&dev->dev.kobj, orig_attr))
			xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
				    "Critical: Failed to restore XSC PCI config file\n");
		return ret;
	}

	cache->original_config_attr = orig_attr;

	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG, &dev->dev,
		    "Successfully replaced XSC PCI config file\n");
	return 0;
}

static void restore_pci_config_file(struct pci_dev *dev, struct xsc_vpd *cache)
{
	int ret = 0;

	if (!cache->original_config_attr)
		return;

	sysfs_remove_bin_file(&dev->dev.kobj, &cache->new_config_attr);
	if (cache->original_config_attr->size != dev->cfg_size)
		cache->original_config_attr->size = dev->cfg_size;

	ret = sysfs_create_bin_file(&dev->dev.kobj, cache->original_config_attr);
	if (ret) {
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
			    "Failed to restore XSC PCI config file: %d\n", ret);
		return;
	}
	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG, &dev->dev,
		    "Successfully restored XSC PCI config file\n");
}

int xsc_pci_vpd_cache_init(struct xsc_core_device *cdev)
{
	struct pci_dev *dev = cdev->pdev;
	struct xsc_priv *priv = &cdev->priv;
	struct xsc_vpd *vpd;
	int ret;

	vpd = kzalloc(sizeof(*vpd), GFP_KERNEL);
	if (!vpd)
		return -ENOMEM;

	mutex_init(&vpd->lock);

	ret = safe_backup_vpd_data(dev, vpd);
	if (ret) {
		if (ret != -ENOENT)
			xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
				    "Failed to backup VPD: %d\n", ret);
		goto err_out;
	}

	ret = replace_vpd_file(dev, vpd);
	if (ret) {
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
			    "Failed to replace VPD: %d\n", ret);
		kfree(vpd->data);
		goto err_out;
	}

	replace_pci_config_file(dev, vpd);

	priv->vpd = vpd;

	return 0;

err_out:
	mutex_destroy(&vpd->lock);
	kfree(vpd);
	return ret;
}

void xsc_pci_vpd_cache_remove(struct xsc_core_device *cdev)
{
	struct pci_dev *dev = cdev->pdev;
	struct xsc_priv *priv = &cdev->priv;
	struct xsc_vpd *vpd = priv->vpd;
	int ret;

	if (!vpd)
		return;

	restore_pci_config_file(dev, vpd);

	sysfs_remove_bin_file(&dev->dev.kobj, &vpd->new_attr);

	ret = restore_original_vpd(dev, vpd);
	if (ret)
		xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR, &dev->dev,
			    "VPD restoration failed, system may be in inconsistent state\n");

	kfree(vpd->data);
	mutex_destroy(&vpd->lock);
	kfree(vpd);
}
