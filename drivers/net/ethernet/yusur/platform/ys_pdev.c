// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>
#include <net/devlink.h>

#include "ys_auxiliary.h"
#include "ys_intr.h"
#include "ys_ndev.h"
#include "ys_pdev.h"

#include "ys_debug.h"

static int ys_pdev_dmaconfig(struct ys_pdev_priv *pdev_priv)
{
	struct pci_dev *pdev = pdev_priv->pdev;
	int ret;

	ret = dma_set_mask(&pdev->dev, pdev_priv->nic_type->dma_flag);
	if (ret) {
		ys_dev_err("Failed to set PCI DMA mask");
		return ret;
	}

	ret = dma_set_coherent_mask(&pdev->dev,
				    pdev_priv->nic_type->dma_coherent_flag);
	if (ret) {
		ys_dev_err("Failed to set PCI COHERENT DMA mask");
		return ret;
	}

	/* Set max segment size */
	dma_set_max_seg_size(&pdev->dev, DMA_BIT_MASK(32));

	return 0;
}

static int ys_pdev_mmap(struct ys_pdev_priv *pdev_priv)
{
	struct pci_dev *pdev = pdev_priv->pdev;
	unsigned long bar_start;
	unsigned long bar_flags;
	unsigned long bar_end;
	u64 bar_offset = 0;
	int i;

	for (i = 0; i < BAR_MAX; i++) {
		bar_start = pci_resource_start(pdev, i);
		bar_end = pci_resource_end(pdev, i);
		bar_flags = pci_resource_flags(pdev, i);

		pdev_priv->bar_size[i] = pci_resource_len(pdev, i);
		if (!pdev_priv->bar_size[i]) {
			pdev_priv->bar_addr[i] = NULL;
			continue;
		}

		if (test_bit(i, pdev_priv->nic_type->bar_status))
			pdev_priv->bar_addr[i] = ioremap_wc(bar_start, pdev_priv->bar_size[i]);
		else
			pdev_priv->bar_addr[i] = ioremap(bar_start, pdev_priv->bar_size[i]);

		if (!pdev_priv->bar_addr[i]) {
			ys_dev_err("could't map BAR_%d[0x%08lx-0x%08lx] flag[0x%08lx]",
				   i, bar_start, bar_end, bar_flags);
			return -1;
		}

		pdev_priv->bar_pa[i] = bar_start;
		ys_dev_info("BAR_%d [0x%08lx-0x%08lx] flag[0x%08lx] mapped to %p, length %lu mode %d",
			    i, bar_start, bar_end, bar_flags,
			    pdev_priv->bar_addr[i],
			    (unsigned long)pdev_priv->bar_size[i],
			    test_bit(i, pdev_priv->nic_type->bar_status));

		pdev_priv->bar_offset[i] = bar_offset;
		bar_offset += pdev_priv->bar_size[i];
	}

	return 0;
}

static void ys_pdev_unmap(struct ys_pdev_priv *pdev_priv)
{
	int i;

	for (i = 0; i < BAR_MAX; i++) {
		if (pdev_priv->bar_addr[i]) {
			pci_iounmap(pdev_priv->pdev, pdev_priv->bar_addr[i]);
			pdev_priv->bar_addr[i] = NULL;
		}
	}
}

int ys_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ys_pdev_priv *pdev_priv = NULL;
	struct device *dev = &pdev->dev;
	int ret = 0;

	pdev_priv = kzalloc(sizeof(*pdev_priv), GFP_KERNEL);
	if (!pdev_priv) {
		ret = -ENOMEM;
		goto err_priv_alloc;
	}

	pdev_priv->dev = dev;
	pdev_priv->pdev = pdev;
	pdev_priv->nic_type = (const struct ys_pdev_hw *)id->driver_data;
	pdev_priv->netdev_qnum = pdev_priv->nic_type->ndev_qcount;
	pci_set_drvdata(pdev, pdev_priv);

	ys_dev_info("yusur nic driver probe\n");
	ys_dev_info("Vendor: 0x%04x", pdev->vendor);
	ys_dev_info("Device: 0x%04x", pdev->device);
	ys_dev_info("Subsystem vendor: 0x%04x", pdev->subsystem_vendor);
	ys_dev_info("Subsystem device: 0x%04x", pdev->subsystem_device);
	ys_dev_info("Class: 0x%06x", pdev->class);
	ys_dev_info("PCI ID: %04x:%02x:%02x.%d", pci_domain_nr(pdev->bus),
		    pdev->bus->number, PCI_SLOT(pdev->devfn),
		    PCI_FUNC(pdev->devfn));

	/* Enable the device */
	ret = pci_enable_device(pdev);
	if (ret) {
		ys_dev_err("pci_enable_device() failed\n");
		goto err_pci_enable;
	}

	pci_set_master(pdev);

	/* Request MMIO/IOP resources */
	ret = pci_request_regions(pdev, pdev->driver->name);
	if (ret) {
		ys_dev_err("pci_request_regions() failed\n");
		goto err_regions;
	}

	/* Allocate and initialize shared control data */
	ret = ys_pdev_mmap(pdev_priv);
	if (ret) {
		ys_dev_err("ys_pdev_mmap failed\n");
		goto err_mmap;
	}

	/* YUSUR adapter init(need to be realize by hw) */
	ret = pdev_priv->nic_type->hw_pdev_init(pdev_priv);
	if (ret) {
		ys_dev_err("ys_hw_adapter_init failed");
		goto err_hw_adapter_init;
	}

	ret = ys_pdev_dmaconfig(pdev_priv);
	if (ret) {
		ys_dev_err("dma config failed");
		goto err_pci_dma_config;
	}

	/* Register IRQ handler */
	ret = ys_irq_init(pdev);
	if (ret) {
		ys_dev_err("ys_init_irq failed\n");
		goto err_irq;
	}

	ret = ys_aux_dev_init(pdev);
	if (ret) {
		ys_dev_err("ys_init_auxiliary failed\n");
		goto err_initaux;
	}

	/* YUSUR ndev init */
	ret = ys_ndev_init(pdev_priv);
	if (ret) {
		ys_dev_err("ys_init_netdev failed\n");
		goto err_initnetdev;
	}

	ret = ys_sysfs_init(pdev);
	if (ret)
		goto err_register_sysfs;

	ys_dev_info("yusur nic driver probe finish\n");

	return 0;

err_register_sysfs:
	ys_sysfs_uninit(pdev);
err_initnetdev:
	ys_ndev_uninit(pdev_priv);
err_initaux:
	ys_aux_dev_uninit(pdev);
err_irq:
	ys_irq_uninit(pdev);
err_pci_dma_config:
err_hw_adapter_init:
	/* need to be realize by hw */
	pdev_priv->nic_type->hw_pdev_uninit(pdev_priv);
err_mmap:
	ys_pdev_unmap(pdev_priv);
err_regions:
	pci_set_drvdata(pdev, NULL);
	pci_clear_master(pdev);
	pci_disable_device(pdev);
	pci_release_regions(pdev);
err_pci_enable:
	kfree(pdev_priv);
err_priv_alloc:
	return ret;
}

void ys_pdev_remove(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	ys_sysfs_uninit(pdev);
	ys_ndev_uninit(pdev_priv);
	ys_aux_dev_uninit(pdev);
	ys_irq_uninit(pdev);
	pdev_priv->nic_type->hw_pdev_uninit(pdev_priv);
	ys_pdev_unmap(pdev_priv);
	pci_set_drvdata(pdev, NULL);
	pci_clear_master(pdev);
	pci_disable_device(pdev);
	pci_release_regions(pdev);
	kfree(pdev_priv);
	ys_info("ys pci device remove\n");
}

void ys_pdev_shutdown(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	ys_dev_info("ys pci device shutdown");
	ys_pdev_remove(pdev);
}

int ys_pdev_init(struct pci_driver *pdrv)
{
	int ret = 0;

	ys_info("yusur nic platform init\n");
	ret = pci_register_driver(pdrv);
	if (ret) {
		ys_err("PCI driver registration failed\n");
		return -1;
	}

	return 0;
}

void ys_pdev_uninit(struct pci_driver *pdrv)
{
	ys_info("yusur nic platform uninit\n");
	pci_unregister_driver(pdrv);
}
