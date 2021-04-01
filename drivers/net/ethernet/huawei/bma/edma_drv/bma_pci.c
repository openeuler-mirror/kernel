// SPDX-License-Identifier: GPL-2.0
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/pci.h>
#include <linux/version.h>
#include <linux/module.h>

#include "bma_include.h"
#include "bma_devintf.h"
#include "bma_pci.h"

#define PCI_KBOX_MODULE_NAME		"edma_drv"
#define PCI_VENDOR_ID_HUAWEI_FPGA	0x19aa
#define PCI_DEVICE_ID_KBOX_0		0xe004

#define PCI_VENDOR_ID_HUAWEI_PME	0x19e5
#define PCI_DEVICE_ID_KBOX_0_PME	0x1710
#define PCI_PME_USEABLE_SPACE		(4 * 1024 * 1024)
#define PME_DEV_CHECK(device, vendor) ((device) == PCI_DEVICE_ID_KBOX_0_PME && \
				       (vendor) == PCI_VENDOR_ID_HUAWEI_PME)

#define PCI_BAR0_PME_1710		0x85800000
#define PCI_BAR0			0
#define PCI_BAR1			1
#define PCI_USING_DAC_DEFAULT 0

#define GET_HIGH_ADDR(address)	((sizeof(unsigned long) == 8) ? \
				 ((u64)(address) >> 32) : 0)

/* The value of the expression is true
 * only when dma_set_mask and dma_set_coherent_mask failed.
 */
#define SET_DMA_MASK(p_dev) \
	(dma_set_mask((p_dev), DMA_BIT_MASK(64)) && \
	 dma_set_coherent_mask((p_dev), DMA_BIT_MASK(64)))

int pci_using_dac = PCI_USING_DAC_DEFAULT;
int debug = DLOG_ERROR;
MODULE_PARM_DESC(debug, "Debug switch (0=close debug, 1=open debug)");

static struct bma_pci_dev_s *g_bma_pci_dev;

static int bma_pci_suspend(struct pci_dev *pdev, pm_message_t state);
static int bma_pci_resume(struct pci_dev *pdev);
static int bma_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void bma_pci_remove(struct pci_dev *pdev);

static const struct pci_device_id bma_pci_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_HUAWEI_FPGA, PCI_DEVICE_ID_KBOX_0)},
	{PCI_DEVICE(PCI_VENDOR_ID_HUAWEI_PME, PCI_DEVICE_ID_KBOX_0_PME)},
	{}
};
MODULE_DEVICE_TABLE(pci, bma_pci_tbl);

int edma_param_get_statics(char *buf, const struct kernel_param *kp)
{
	if (!buf)
		return 0;

	return edmainfo_show(buf);
}

module_param_call(statistics, NULL, edma_param_get_statics, &debug, 0444);
MODULE_PARM_DESC(statistics, "Statistics info of edma driver,readonly");

int edma_param_set_debug(const char *buf, const struct kernel_param *kp)
{
	unsigned long val = 0;
	int ret = 0;

	if (!buf)
		return -EINVAL;

	ret = kstrtoul(buf, 0, &val);

	if (ret)
		return ret;

	if (val > 1)
		return -EINVAL;

	return param_set_int(buf, kp);
}
EXPORT_SYMBOL_GPL(edma_param_set_debug);

module_param_call(debug, &edma_param_set_debug, &param_get_int, &debug, 0644);

void __iomem *kbox_get_base_addr(void)
{
	if (!g_bma_pci_dev || (!(g_bma_pci_dev->kbox_base_addr))) {
		BMA_LOG(DLOG_ERROR, "kbox_base_addr NULL point\n");
		return NULL;
	}

	return g_bma_pci_dev->kbox_base_addr;
}
EXPORT_SYMBOL_GPL(kbox_get_base_addr);

unsigned long kbox_get_io_len(void)
{
	if (!g_bma_pci_dev) {
		BMA_LOG(DLOG_ERROR, "kbox_io_len is error,can not get it\n");
		return 0;
	}

	return g_bma_pci_dev->kbox_base_len;
}
EXPORT_SYMBOL_GPL(kbox_get_io_len);

unsigned long kbox_get_base_phy_addr(void)
{
	if (!g_bma_pci_dev || !g_bma_pci_dev->kbox_base_phy_addr) {
		BMA_LOG(DLOG_ERROR, "kbox_base_phy_addr NULL point\n");
		return 0;
	}

	return g_bma_pci_dev->kbox_base_phy_addr;
}
EXPORT_SYMBOL_GPL(kbox_get_base_phy_addr);

static struct pci_driver bma_driver = {
	.name = PCI_KBOX_MODULE_NAME,
	.id_table = bma_pci_tbl,
	.probe = bma_pci_probe,
	.remove = bma_pci_remove,
	.suspend = bma_pci_suspend,
	.resume = bma_pci_resume,
};

s32 __atu_config_H(struct pci_dev *pdev, unsigned int region,
		   unsigned int hostaddr_h, unsigned int hostaddr_l,
		   unsigned int bmcaddr_h, unsigned int bmcaddr_l,
		   unsigned int len)
{
	/*  atu index reg,inbound and region*/
	(void)pci_write_config_dword(pdev, ATU_VIEWPORT,
		REGION_DIR_INPUT + (region & REGION_INDEX_MASK));
	(void)pci_write_config_dword(pdev, ATU_BASE_LOW, hostaddr_l);
	(void)pci_write_config_dword(pdev, ATU_BASE_HIGH, hostaddr_h);
	(void)pci_write_config_dword(pdev, ATU_LIMIT, hostaddr_l + len - 1);
	(void)pci_write_config_dword(pdev, ATU_TARGET_LOW, bmcaddr_l);
	(void)pci_write_config_dword(pdev, ATU_TARGET_HIGH, bmcaddr_h);
	/*  atu ctrl1 reg   */
	(void)pci_write_config_dword(pdev, ATU_REGION_CTRL1, ATU_CTRL1_DEFAULT);
	/*  atu ctrl2 reg   */
	(void)pci_write_config_dword(pdev, ATU_REGION_CTRL2, REGION_ENABLE);

	return 0;
}

static void iounmap_bar_mem(struct bma_pci_dev_s *bma_pci_dev)
{
	if (bma_pci_dev->kbox_base_addr) {
		iounmap(bma_pci_dev->kbox_base_addr);
		bma_pci_dev->kbox_base_addr = NULL;
	}

	if (bma_pci_dev->bma_base_addr) {
		iounmap(bma_pci_dev->bma_base_addr);
		bma_pci_dev->bma_base_addr = NULL;
		bma_pci_dev->edma_swap_addr = NULL;
		bma_pci_dev->hostrtc_viraddr = NULL;
	}
}

static int ioremap_pme_bar1_mem(struct pci_dev *pdev,
				struct bma_pci_dev_s *bma_pci_dev)
{
	unsigned long bar1_resource_flag = 0;
	u32 data = 0;

	bma_pci_dev->kbox_base_len = PCI_PME_USEABLE_SPACE;
	BMA_LOG(DLOG_DEBUG, "1710\n");

	bma_pci_dev->bma_base_phy_addr =
	    pci_resource_start(pdev, PCI_BAR1);
	bar1_resource_flag = pci_resource_flags(pdev, PCI_BAR1);

	if (!(bar1_resource_flag & IORESOURCE_MEM)) {
		BMA_LOG(DLOG_ERROR,
			"Cannot find proper PCI device base address, aborting\n");
		return -ENODEV;
	}

	bma_pci_dev->bma_base_len = pci_resource_len(pdev, PCI_BAR1);
	bma_pci_dev->edma_swap_len = EDMA_SWAP_DATA_SIZE;
	bma_pci_dev->veth_swap_len = VETH_SWAP_DATA_SIZE;

	BMA_LOG(DLOG_DEBUG,
		"bar1: bma_base_len = 0x%lx, edma_swap_len = %ld, veth_swap_len = %ld(0x%lx)\n",
		bma_pci_dev->bma_base_len, bma_pci_dev->edma_swap_len,
		bma_pci_dev->veth_swap_len, bma_pci_dev->veth_swap_len);

	bma_pci_dev->hostrtc_phyaddr = bma_pci_dev->bma_base_phy_addr;
	/* edma */
	bma_pci_dev->edma_swap_phy_addr =
		bma_pci_dev->bma_base_phy_addr + EDMA_SWAP_BASE_OFFSET;
	/* veth */
	bma_pci_dev->veth_swap_phy_addr =
		bma_pci_dev->edma_swap_phy_addr + EDMA_SWAP_DATA_SIZE;

	BMA_LOG(DLOG_DEBUG,
		"bar1: hostrtc_phyaddr = 0x%lx, edma_swap_phy_addr = 0x%lx, veth_swap_phy_addr = 0x%lx\n",
		bma_pci_dev->hostrtc_phyaddr,
		bma_pci_dev->edma_swap_phy_addr,
		bma_pci_dev->veth_swap_phy_addr);

	__atu_config_H(pdev, 0,
		       GET_HIGH_ADDR(bma_pci_dev->kbox_base_phy_addr),
			(bma_pci_dev->kbox_base_phy_addr & 0xffffffff),
		0, PCI_BAR0_PME_1710, PCI_PME_USEABLE_SPACE);

	__atu_config_H(pdev, 1,
		       GET_HIGH_ADDR(bma_pci_dev->hostrtc_phyaddr),
			(bma_pci_dev->hostrtc_phyaddr & 0xffffffff),
			0, HOSTRTC_REG_BASE, HOSTRTC_REG_SIZE);

	__atu_config_H(pdev, 2,
		       GET_HIGH_ADDR(bma_pci_dev->edma_swap_phy_addr),
			(bma_pci_dev->edma_swap_phy_addr & 0xffffffff),
			0, EDMA_SWAP_DATA_BASE, EDMA_SWAP_DATA_SIZE);

	__atu_config_H(pdev, 3,
		       GET_HIGH_ADDR(bma_pci_dev->veth_swap_phy_addr),
			(bma_pci_dev->veth_swap_phy_addr & 0xffffffff),
			0, VETH_SWAP_DATA_BASE, VETH_SWAP_DATA_SIZE);

	if (bar1_resource_flag & IORESOURCE_CACHEABLE) {
		bma_pci_dev->bma_base_addr =
		    ioremap(bma_pci_dev->bma_base_phy_addr,
			    bma_pci_dev->bma_base_len);
	} else {
		bma_pci_dev->bma_base_addr =
		    IOREMAP(bma_pci_dev->bma_base_phy_addr,
			    bma_pci_dev->bma_base_len);
	}

	if (!bma_pci_dev->bma_base_addr) {
		BMA_LOG(DLOG_ERROR,
			"Cannot map device registers, aborting\n");

		return -ENODEV;
	}

	bma_pci_dev->hostrtc_viraddr = bma_pci_dev->bma_base_addr;
	bma_pci_dev->edma_swap_addr =
	    (unsigned char *)bma_pci_dev->bma_base_addr +
	    EDMA_SWAP_BASE_OFFSET;
	bma_pci_dev->veth_swap_addr =
	    (unsigned char *)bma_pci_dev->edma_swap_addr +
	    EDMA_SWAP_DATA_SIZE;

	(void)pci_read_config_dword(pdev, 0x78, &data);
	data = data & 0xfffffff0;
	(void)pci_write_config_dword(pdev, 0x78, data);
	(void)pci_read_config_dword(pdev, 0x78, &data);

	return 0;
}

static int ioremap_bar_mem(struct pci_dev *pdev,
			   struct bma_pci_dev_s *bma_pci_dev)
{
	int err = 0;
	unsigned long bar0_resource_flag = 0;

	bar0_resource_flag = pci_resource_flags(pdev, PCI_BAR0);

	if (!(bar0_resource_flag & IORESOURCE_MEM)) {
		BMA_LOG(DLOG_ERROR,
			"Cannot find proper PCI device base address, aborting\n");
		err = -ENODEV;
		return err;
	}

	bma_pci_dev->kbox_base_phy_addr = pci_resource_start(pdev, PCI_BAR0);

	bma_pci_dev->kbox_base_len = pci_resource_len(pdev, PCI_BAR0);

	BMA_LOG(DLOG_DEBUG,
		"bar0: kbox_base_phy_addr = 0x%lx, base_len = %ld(0x%lx)\n",
		bma_pci_dev->kbox_base_phy_addr, bma_pci_dev->kbox_base_len,
		bma_pci_dev->kbox_base_len);

	if (PME_DEV_CHECK(pdev->device, pdev->vendor)) {
		err = ioremap_pme_bar1_mem(pdev, bma_pci_dev);
		if (err != 0)
			return err;
	}

	BMA_LOG(DLOG_DEBUG, "remap BAR0 KBOX\n");

	if (bar0_resource_flag & IORESOURCE_CACHEABLE) {
		bma_pci_dev->kbox_base_addr =
		    ioremap(bma_pci_dev->kbox_base_phy_addr,
			    bma_pci_dev->kbox_base_len);
	} else {
		bma_pci_dev->kbox_base_addr =
		    IOREMAP(bma_pci_dev->kbox_base_phy_addr,
			    bma_pci_dev->kbox_base_len);
	}

	if (!bma_pci_dev->kbox_base_addr) {
		BMA_LOG(DLOG_ERROR, "Cannot map device registers, aborting\n");

		iounmap(bma_pci_dev->bma_base_addr);
		bma_pci_dev->bma_base_addr = NULL;
		bma_pci_dev->edma_swap_addr = NULL;
		bma_pci_dev->hostrtc_viraddr = NULL;
		return -ENOMEM;
	}

	return 0;
}

int pme_pci_enable_msi(struct pci_dev *pdev)
{
	int err = 0;

	pci_set_master(pdev);

#ifdef CONFIG_PCI_MSI
	if (pci_find_capability(pdev, PCI_CAP_ID_MSI) == 0) {
		BMA_LOG(DLOG_ERROR, "not support msi\n");
		pci_disable_device(pdev);
		return err;
	}

	BMA_LOG(DLOG_DEBUG, "support msi\n");

	err = pci_enable_msi(pdev);
	if (err) {
		BMA_LOG(DLOG_ERROR, "pci_enable_msi failed\n");
		pci_disable_device(pdev);
		return err;
	}
#endif

	return err;
}

int pci_device_init(struct pci_dev *pdev, struct bma_pci_dev_s *bma_pci_dev)
{
	int err = 0;

	if (PME_DEV_CHECK(pdev->device, pdev->vendor)) {
		err = bma_devinft_init(bma_pci_dev);
		if (err) {
			BMA_LOG(DLOG_ERROR, "bma_devinft_init failed\n");
			bma_devinft_cleanup(bma_pci_dev);
			iounmap_bar_mem(bma_pci_dev);
			g_bma_pci_dev = NULL;
			pci_release_regions(pdev);
			kfree(bma_pci_dev);
		#ifdef CONFIG_PCI_MSI
			pci_disable_msi(pdev);
		#endif
			pci_disable_device(pdev);

			return err;
		}
	} else {
		BMA_LOG(DLOG_DEBUG, "edma is not supported on this pcie\n");
	}

	pci_set_drvdata(pdev, bma_pci_dev);

	return 0;
}

int pci_device_config(struct pci_dev *pdev)
{
	int err = 0;
	struct bma_pci_dev_s *bma_pci_dev = NULL;

	bma_pci_dev = kmalloc(sizeof(*bma_pci_dev), GFP_KERNEL);
	if (!bma_pci_dev) {
		err = -ENOMEM;
		goto err_out_disable_msi;
	}
	memset(bma_pci_dev, 0, sizeof(*bma_pci_dev));

	bma_pci_dev->pdev = pdev;

	err = pci_request_regions(pdev, PCI_KBOX_MODULE_NAME);
	if (err) {
		BMA_LOG(DLOG_ERROR, "Cannot obtain PCI resources, aborting\n");
		goto err_out_free_dev;
	}

	err = ioremap_bar_mem(pdev, bma_pci_dev);
	if (err) {
		BMA_LOG(DLOG_ERROR, "ioremap_edma_io_mem failed\n");
		goto err_out_release_regions;
	}

	g_bma_pci_dev = bma_pci_dev;

	if (SET_DMA_MASK(&pdev->dev)) {
		BMA_LOG(DLOG_ERROR,
			"No usable DMA ,configuration, aborting,goto failed2!!!\n");
		goto err_out_unmap_bar;
	}

	g_bma_pci_dev = bma_pci_dev;

	return pci_device_init(pdev, bma_pci_dev);

err_out_unmap_bar:
	iounmap_bar_mem(bma_pci_dev);
	g_bma_pci_dev = NULL;
err_out_release_regions:
	pci_release_regions(pdev);
err_out_free_dev:
	kfree(bma_pci_dev);
	bma_pci_dev = NULL;
err_out_disable_msi:
#ifdef CONFIG_PCI_MSI
	pci_disable_msi(pdev);
#endif

	pci_disable_device(pdev);

	return err;
}

static int bma_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int err = 0;

	UNUSED(ent);

	if (g_bma_pci_dev)
		return -EPERM;

	err = pci_enable_device(pdev);
	if (err) {
		BMA_LOG(DLOG_ERROR, "Cannot enable PCI device,aborting\n");
		return err;
	}

	if (PME_DEV_CHECK(pdev->device, pdev->vendor)) {
		err = pme_pci_enable_msi(pdev);
		if (err)
			return err;
	}

	BMA_LOG(DLOG_DEBUG, "pdev->device = 0x%x\n", pdev->device);
	BMA_LOG(DLOG_DEBUG, "pdev->vendor = 0x%x\n", pdev->vendor);

	return pci_device_config(pdev);
}

static void bma_pci_remove(struct pci_dev *pdev)
{
	struct bma_pci_dev_s *bma_pci_dev =
		(struct bma_pci_dev_s *)pci_get_drvdata(pdev);

	g_bma_pci_dev = NULL;
	(void)pci_set_drvdata(pdev, NULL);

	if (bma_pci_dev) {
		bma_devinft_cleanup(bma_pci_dev);

		iounmap_bar_mem(bma_pci_dev);

		kfree(bma_pci_dev);
	}

	pci_release_regions(pdev);

#ifdef CONFIG_PCI_MSI
	pci_disable_msi(pdev);
#endif
	pci_disable_device(pdev);
}

static int bma_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
	UNUSED(pdev);
	UNUSED(state);

	return 0;
}

static int bma_pci_resume(struct pci_dev *pdev)
{
	UNUSED(pdev);

	return 0;
}

int __init bma_pci_init(void)
{
	int ret = 0;

	BMA_LOG(DLOG_DEBUG, "\n");

	ret = pci_register_driver(&bma_driver);
	if (ret)
		BMA_LOG(DLOG_ERROR, "pci_register_driver failed\n");

	return ret;
}

void __exit bma_pci_cleanup(void)
{
	BMA_LOG(DLOG_DEBUG, "\n");

	pci_unregister_driver(&bma_driver);
}

MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_DESCRIPTION("HUAWEI EDMA DRIVER");
MODULE_LICENSE("GPL");
MODULE_VERSION(BMA_VERSION);
#ifndef _lint

module_init(bma_pci_init);
module_exit(bma_pci_cleanup);
#endif
