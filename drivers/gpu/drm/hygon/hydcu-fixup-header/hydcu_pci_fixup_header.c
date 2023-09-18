// SPDX-License-Identifier: GPL-2.0-only
/*
 * HYGON DCU fixup driver
 *
 * Copyright (C) 2024 Hygon Info Technologies Ltd.
 *
 * Author: Baoshun Fang <baoshunfang@hygon.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/delay.h>

#define PCI_VENDOR_ID_HYGON 0x1d94

#define DEVICE_Z100SM		0x51b7
#define DEVICE_C878182		0x52b7
#define DEVICE_C878186		0x53b7
#define DEVICE_Z100		0x54b7
#define DEVICE_Z100L		0x55b7
#define DEVICE_C878181		0x56b7
#define DEVICE_C878185		0x57b7
#define DEVICE_C878188		0x58b7
#define DEVICE_C878174		0x59b7
#define DEVICE_KONGMING		0x61b7
#define DEVICE_KONGMING_E	0x6210

#define DRIVER_VERSION  "0.2"
#define DRIVER_AUTHOR   "huangjun <huangjun@hygon.cn>"
#define DRIVER_DESC     "fix dcu header"

static int hydcu_pci_fixup_header_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	dev_info(&pdev->dev, "add flags NO_BUS_RESET\n");
	pdev->dev_flags |= PCI_DEV_FLAGS_NO_BUS_RESET;
	pdev->pm_cap = 0;
	dev_info(&pdev->dev, "will abort probe\n");

	return -EINVAL;
}

static void hydcu_pci_fixup_header_remove(struct pci_dev *pdev)
{
}

static const struct pci_device_id hydcu_pci_fixup_header_ids[] = {
	{ PCI_VDEVICE(HYGON, DEVICE_Z100SM), },
	{ PCI_VDEVICE(HYGON, DEVICE_C878182), },
	{ PCI_VDEVICE(HYGON, DEVICE_C878186), },
	{ PCI_VDEVICE(HYGON, DEVICE_Z100), },
	{ PCI_VDEVICE(HYGON, DEVICE_Z100L), },
	{ PCI_VDEVICE(HYGON, DEVICE_C878181), },
	{ PCI_VDEVICE(HYGON, DEVICE_C878185), },
	{ PCI_VDEVICE(HYGON, DEVICE_C878188), },
	{ PCI_VDEVICE(HYGON, DEVICE_C878174), },
	{ PCI_VDEVICE(HYGON, DEVICE_KONGMING), },
	{ PCI_VDEVICE(HYGON, DEVICE_KONGMING_E), },
	{},
};

static struct pci_driver hydcu_pci_fixup_header_driver = {
	.name		= "hydcu-fixup-header",
	.id_table	= hydcu_pci_fixup_header_ids,
	.probe		= hydcu_pci_fixup_header_probe,
	.remove		= hydcu_pci_fixup_header_remove,
};

static int __init hydcu_pci_fixup_header_init(void)
{
	/* Register and scan for devices */
	return pci_register_driver(&hydcu_pci_fixup_header_driver);
}

static void __exit hydcu_pci_fixup_header_cleanup(void)
{
	pci_unregister_driver(&hydcu_pci_fixup_header_driver);
}

module_init(hydcu_pci_fixup_header_init);
module_exit(hydcu_pci_fixup_header_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
