// SPDX-License-Identifier: GPL-2.0

#include <linux/sysfs.h>
#include <linux/kernel.h>

#include "ys_pdev.h"
#include "ys_ndev.h"
#include "ys_sysfs.h"
#include "ys_auxiliary.h"
#include "ys_debug.h"

enum { SYSFS_COMMON, SYSFS_NDEV };

struct ys_sysfs_group {
	int type;
	int idx;
	struct kobject *kobj;
	struct attribute_group attr_group;
	struct list_head list;
};

static ssize_t ys_sysfs_aux_bind_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	long idx;
	int ret;

	ret = kstrtol(buf, 10, &idx);
	if (ret)
		return -EINVAL;

	ys_aux_add_adev(pdev, (int)idx, AUX_NAME_SF);

	return count;
}

static ssize_t ys_sysfs_aux_unbind_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	long idx;
	int ret;

	ret = kstrtol(buf, 10, &idx);
	if (ret)
		return -EINVAL;

	ys_aux_del_match_adev(pdev, (int)idx, AUX_NAME_SF);

	return count;
}

static struct device_attribute common_nodes[] = {
	__ATTR(aux_bind, 0200, NULL, ys_sysfs_aux_bind_store),
	__ATTR(aux_unbind, 0200, NULL, ys_sysfs_aux_unbind_store),
};

static int create_sysfs_group(struct device_attribute *device_attrs,
			      int attrs_num, struct list_head *list, int type,
			      int idx, struct kobject *kobj)
{
	struct attribute **grp_attrs = NULL;
	struct ys_sysfs_group *grp = NULL;
	int ret;
	int i;

	if (IS_ERR_OR_NULL(device_attrs) || attrs_num <= 0)
		goto done;

	grp_attrs = kzalloc((attrs_num + 1) * sizeof(struct attribute *),
			    GFP_KERNEL);
	if (IS_ERR_OR_NULL(grp_attrs))
		goto err;

	for (i = 0; i < attrs_num; i++)
		grp_attrs[i] = &device_attrs[i].attr;
	grp_attrs[attrs_num] = NULL;

	grp = kzalloc(sizeof(*grp), GFP_KERNEL);
	if (IS_ERR_OR_NULL(grp))
		goto err;

	grp->type = type;
	grp->idx = idx;
	grp->kobj = kobj;
	grp->attr_group.name = "attrs";
	grp->attr_group.attrs = grp_attrs;
	INIT_LIST_HEAD(&grp->list);

	ret = sysfs_create_group(grp->kobj, &grp->attr_group);
	if (ret) {
		ys_err("create sysfs group failed. ret: %d\n", ret);
		goto err;
	}

	list_add(&grp->list, list);
done:
	return 0;
err:
	if (!IS_ERR_OR_NULL(grp_attrs))
		kfree(grp_attrs);
	if (!IS_ERR_OR_NULL(grp))
		kfree(grp);
	return -ENOMEM;
}

static int create_common_sysfs_group(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	int attrs_num;
	int ret;

	attrs_num = sizeof(common_nodes) / sizeof(struct device_attribute);

	ret = create_sysfs_group(common_nodes, attrs_num, list, SYSFS_COMMON, 0,
				 &pdev->dev.kobj);

	return ret;
}

static int create_ndev_sysfs_group(struct net_device *ndev)
{
	struct device_attribute *device_attrs;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct list_head *list;
	int attrs_num;
	int ret;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	list = &pdev_priv->sysfs_list;

	if (IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_detect_sysfs_attrs))
		return 0;

	attrs_num = pdev_priv->ops->hw_adp_detect_sysfs_attrs(&device_attrs);

	ret = create_sysfs_group(device_attrs, attrs_num, list, SYSFS_NDEV,
				 ndev->dev_port, &ndev->dev.kobj);

	return ret;
}

int ys_sysfs_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	struct net_device *ndev;
	int ret;
	int i;

	INIT_LIST_HEAD(list);

	ret = create_common_sysfs_group(pdev);
	if (ret)
		goto err;

	for (i = 0; i < pdev_priv->nic_type->ndev_sum; i++) {
		ndev = ys_aux_match_ndev(pdev, AUX_TYPE_ETH, i);
		if (!IS_ERR_OR_NULL(ndev)) {
			ret = create_ndev_sysfs_group(ndev);
			if (ret)
				goto err;
		}
	}

	return 0;
err:
	ys_sysfs_uninit(pdev);
	return -ENOMEM;
}

void ys_sysfs_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	struct ys_sysfs_group *grp, *n;

	list_for_each_entry_safe(grp, n, list, list) {
		sysfs_remove_group(grp->kobj, &grp->attr_group);
		if (!IS_ERR_OR_NULL(grp->attr_group.attrs))
			kfree(grp->attr_group.attrs);
		if (!IS_ERR_OR_NULL(grp))
			kfree(grp);
	}

	list_empty(list);
}
