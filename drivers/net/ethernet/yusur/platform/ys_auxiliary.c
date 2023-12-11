// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>
#include <net/devlink.h>

#include "ys_auxiliary.h"
#include "ys_ndev.h"
#include "ys_pdev.h"
#include "../net/ys_ethtool_ops.h"
#include "../net/ys_ndev_ops.h"
#include "ys_debug.h"

int ys_aux_sf_probe(struct auxiliary_device *adev,
		    const struct auxiliary_device_id *id)
{
	struct ys_adev *sf_dev = container_of(adev, struct ys_adev, adev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(sf_dev->pdev);

	ys_info("sf probe %d:%p\n", sf_dev->idx, pdev_priv);
	return 0;
}

void ys_aux_sf_remove(struct auxiliary_device *adev)
{
}

int ys_aux_eth_probe(struct auxiliary_device *adev,
		     const struct auxiliary_device_id *id)
{
	struct ys_adev *eth_dev = container_of(adev, struct ys_adev, adev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(eth_dev->pdev);
	struct ys_ndev_priv *ndev_priv = NULL;
	int ret;

	ys_info("eth probe %d:%p\n", eth_dev->idx, pdev_priv);

	eth_dev->ndev = ys_ndev_create(pdev_priv, eth_dev->idx,
				       pdev_priv->netdev_qnum);

	if (IS_ERR_OR_NULL(eth_dev->ndev))
		return -1;

	ndev_priv = netdev_priv(eth_dev->ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_cfg)) {
		ret = ndev_priv->ys_ndev_hw->ys_update_cfg(eth_dev->ndev, 0);
		if (ret)
			return ret;
	}

	return 0;
}

void ys_aux_eth_remove(struct auxiliary_device *adev)
{
	struct ys_adev *eth_dev = container_of(adev, struct ys_adev, adev);
	struct ys_ndev_priv *ndev_priv = NULL;

	if (!IS_ERR_OR_NULL(eth_dev->ndev)) {
		ndev_priv = netdev_priv(eth_dev->ndev);
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_delete_cfg))
			ndev_priv->ys_ndev_hw->ys_delete_cfg(eth_dev->ndev, 0);

		ys_ndev_destroy(eth_dev->ndev);
		free_netdev(eth_dev->ndev);
	}
}

static void ys_aux_release_adev(struct device *dev)
{
	struct ys_adev *ys_adev = container_of(dev, struct ys_adev, adev.dev);

	complete(&ys_adev->comp);
}

static void ys_aux_del_adev(struct auxiliary_device *adev)
{
	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);
}

struct net_device *ys_aux_match_ndev(struct pci_dev *pdev, int ndev_type,
				     int id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *ys_adev;

	list_for_each_entry(ys_adev, adev_list, list)
		if (ys_adev->ndev_type == ndev_type && ys_adev->idx == id)
			return ys_adev->ndev;

	return NULL;
}

void ys_aux_del_match_adev(struct pci_dev *pdev, int idx, const char *name)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *ys_adev, *temp;

	list_for_each_entry_safe(ys_adev, temp, adev_list, list) {
		if (!strcmp(ys_adev->adev.name, name) &&
		    ys_adev->idx == idx) {
			list_del(&ys_adev->list);
			ys_aux_del_adev(&ys_adev->adev);
		}
	}
}

struct ys_adev *ys_aux_add_adev(struct pci_dev *pdev, int idx, const char *name)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *ys_adev, *entry;
	struct auxiliary_device *adev;
	struct list_head *pos;
	u32 bdf;

	int ret;

	bdf = (pdev_priv->pdev->bus->number << 16)
		+ (PCI_SLOT(pdev_priv->pdev->devfn) << 11)
		+ (PCI_FUNC(pdev_priv->pdev->devfn) << 8);

	ys_adev = kzalloc(sizeof(*ys_adev), GFP_KERNEL);
	if (!ys_adev)
		return ERR_PTR(-ENOMEM);

	adev = &ys_adev->adev;
	adev->id = idx + bdf;
	adev->name = name;
	adev->dev.parent = &pdev->dev;
	adev->dev.release = ys_aux_release_adev;
	ys_adev->pdev = pdev;
	ys_adev->idx = idx;

	init_completion(&ys_adev->comp);

	if (strcmp(adev->name, AUX_NAME_ETH) == 0)
		ys_adev->ndev_type = AUX_TYPE_ETH;
	else if (strcmp(adev->name, AUX_NAME_SF) == 0)
		ys_adev->ndev_type = AUX_TYPE_SF;
	else
		ys_dev_dbg("unknown adev name %s\n", adev->name);

	list_for_each(pos, adev_list) {
		entry = list_entry(pos, struct ys_adev, list);
		if (!strcmp(entry->adev.name, name) &&
		    entry->adev.id == idx + bdf) {
			ys_dev_err("adev %s:%d exist\n", name, idx);
			kfree(ys_adev);
			return ERR_PTR(-EEXIST);
		}
	}

	ret = auxiliary_device_init(adev);
	if (ret) {
		kfree(ys_adev);
		return ERR_PTR(ret);
	}

	list_add(&ys_adev->list, adev_list);

	ret = auxiliary_device_add(adev);
	if (ret) {
		auxiliary_device_uninit(adev);
		return ERR_PTR(ret);
	}

	return ys_adev;
}

int ys_aux_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;

	INIT_LIST_HEAD(adev_list);

	return 0;
}

void ys_aux_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *ys_adev, *temp;

	list_for_each_entry_safe(ys_adev, temp, adev_list, list) {
		ys_aux_del_adev(&ys_adev->adev);
		wait_for_completion(&ys_adev->comp);
		list_del(&ys_adev->list);
		kfree(ys_adev);
		ys_adev = NULL;
	}

	list_empty(adev_list);
}

int ys_aux_init(struct auxiliary_driver *adrvs)
{
	int ret;
	int i;

	if (IS_ERR_OR_NULL(adrvs))
		return -EFAULT;

	for (i = 0; !IS_ERR_OR_NULL(adrvs[i].name); i++) {
		ret = auxiliary_driver_register(&adrvs[i]);
		if (ret)
			return ret;
	}

	return 0;
}

void ys_aux_uninit(struct auxiliary_driver *adrvs)
{
	int i;

	if (IS_ERR_OR_NULL(adrvs))
		return;

	for (i = 0; !IS_ERR_OR_NULL(adrvs[i].name); i++)
		auxiliary_driver_unregister(&adrvs[i]);
}
