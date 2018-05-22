// SPDX-License-Identifier: GPL-2.0+
/*
 * KMS driver for Loongson display controller
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>

#include <drm/drm_modeset_helper.h>

#include "lsdc_drv.h"
#include "lsdc_i2c.h"

static int lsdc_use_vram_helper = -1;
MODULE_PARM_DESC(use_vram_helper, "Using vram helper based driver(0 = disabled)");
module_param_named(use_vram_helper, lsdc_use_vram_helper, int, 0644);

static int lsdc_gamma = -1;
MODULE_PARM_DESC(gamma, "enable gamma (-1 = disabled (default), >0 = enabled)");
module_param_named(gamma, lsdc_gamma, int, 0644);

static int lsdc_relax_alignment = -1;
MODULE_PARM_DESC(relax_alignment,
		 "relax crtc stride alignment (-1 = disabled (default), >0 = enabled)");
module_param_named(relax_alignment, lsdc_relax_alignment, int, 0644);


static struct platform_device *
lsdc_create_platform_device(const char *name,
			    struct device *parent,
			    const struct lsdc_chip_desc *descp,
			    struct resource *res)
{
	struct device *dev;
	struct platform_device *pdev;
	int ret;

	pdev = platform_device_alloc(name, PLATFORM_DEVID_NONE);
	if (!pdev) {
		dev_err(parent, "can not create platform device\n");
		return ERR_PTR(-ENOMEM);
	}

	dev_info(parent, "platform device %s created\n", name);

	dev = &pdev->dev;
	dev->parent = parent;

	if (descp) {
		ret = platform_device_add_data(pdev, descp, sizeof(*descp));
		if (ret) {
			dev_err(parent, "add platform data failed: %d\n", ret);
			goto ERROR_RET;
		}
	}

	if (res) {
		ret = platform_device_add_resources(pdev, res, 1);
		if (ret) {
			dev_err(parent, "add platform resources failed: %d\n", ret);
			goto ERROR_RET;
		}
	}

	ret = platform_device_add(pdev);
	if (ret) {
		dev_err(parent, "add platform device failed: %d\n", ret);
		goto ERROR_RET;
	}

	return pdev;

ERROR_RET:
	platform_device_put(pdev);
	return ERR_PTR(ret);
}

static int lsdc_vram_init(struct lsdc_device *ldev)
{
	const struct lsdc_chip_desc * const descp = ldev->desc;
	struct pci_dev *gpu;
	resource_size_t base, size;

	if (descp->chip == LSDC_CHIP_7A2000) {
		/* BAR 2 of LS7A2000's GPU contain VRAM */
		gpu = pci_get_device(PCI_VENDOR_ID_LOONGSON, 0x7A25, NULL);
	} else if (descp->chip == LSDC_CHIP_7A1000) {
		/* BAR 2 of LS7A1000's GPU(GC1000) contain VRAM */
		gpu = pci_get_device(PCI_VENDOR_ID_LOONGSON, 0x7A15, NULL);
	} else {
		dev_err(ldev->dev, "Unknown chip, the driver need update\n");
		return -ENOENT;
	}

	if (IS_ERR_OR_NULL(gpu)) {
		dev_err(ldev->dev, "Can not get VRAM\n");
		return -ENOENT;
	}

	base = pci_resource_start(gpu, 2);
	size =  pci_resource_len(gpu, 2);

	ldev->vram_base = base;
	ldev->vram_size = size;

	dev_info(ldev->dev, "vram start: 0x%llx, size: %uMB\n",
		 (u64)base, (u32)(size >> 20));

	return 0;
}

static void lsdc_of_probe(struct lsdc_device *ldev, struct device_node *np)
{
	struct device_node *ports;

	if (!np) {
		ldev->has_dt = false;
		ldev->has_ports_node = false;
		dev_info(ldev->dev, "don't has DT support\n");
		return;
	}

	ports = of_get_child_by_name(np, "ports");
	ldev->has_ports_node = ports ? true : false;
	of_node_put(ports);
}

static int lsdc_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	const struct lsdc_chip_desc *descp;
	struct lsdc_device *ldev;
	int ret;

	descp = lsdc_detect_chip(pdev, ent);
	if (!descp) {
		dev_info(dev, "unknown dc ip core, abort\n");
		return -ENOENT;
	}

	ldev = devm_kzalloc(dev, sizeof(*ldev), GFP_KERNEL);
	if (IS_ERR(ldev))
		return PTR_ERR(ldev);

	ldev->desc = descp;
	ldev->dev = dev;

	if (lsdc_use_vram_helper > 0)
		ldev->use_vram_helper = true;
	else if ((lsdc_use_vram_helper < 0) && descp->has_vram)
		ldev->use_vram_helper = true;
	else
		ldev->use_vram_helper = false;

	if (!descp->broken_gamma)
		ldev->enable_gamma = true;
	else
		ldev->enable_gamma = lsdc_gamma > 0 ? true : false;

	ldev->relax_alignment = lsdc_relax_alignment > 0 ? true : false;

	lsdc_of_probe(ldev, dev->of_node);

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	pci_set_master(pdev);

	/* BAR 0 contains registers */
	ldev->reg_base = devm_ioremap_resource(dev, &pdev->resource[0]);
	if (IS_ERR(ldev->reg_base))
		return PTR_ERR(ldev->reg_base);

	/* Create GPIO emulated i2c driver as early as possible */
	if (descp->has_builtin_i2c && ldev->has_ports_node) {
		struct device_node *i2c_node;

		for_each_compatible_node(i2c_node, NULL, "loongson,gpio-i2c") {
			if (!of_device_is_available(i2c_node))
				continue;

			lsdc_of_create_i2c_adapter(dev, ldev->reg_base, i2c_node);
		}
	}

	if (ldev->has_dt) {
		/* Get the optional framebuffer memory resource */
		ret = of_reserved_mem_device_init(dev);
		if (ret && (ret != -ENODEV))
			return ret;
	}

	if (descp->has_vram && ldev->use_vram_helper) {
		ret = lsdc_vram_init(ldev);
		if (ret) {
			dev_err(dev, "VRAM is unavailable\n");
			ldev->use_vram_helper = false;
		}
	}

	ldev->irq = pdev->irq;

	dev_set_drvdata(dev, ldev);

	if (descp->has_vram && ldev->use_vram_helper) {
		struct resource res;

		memset(&res, 0, sizeof(res));
		res.flags = IORESOURCE_MEM;
		res.name = "LS7A_VRAM";
		res.start = ldev->vram_base;
		res.end = ldev->vram_size;
	}

	ldev->dc = lsdc_create_platform_device("lsdc", dev, descp, NULL);
	if (IS_ERR(ldev->dc))
		return PTR_ERR(ldev->dc);

	return platform_driver_register(&lsdc_platform_driver);
}

static void lsdc_pci_remove(struct pci_dev *pdev)
{
	struct lsdc_device *ldev = pci_get_drvdata(pdev);

	platform_device_unregister(ldev->dc);

	pci_set_drvdata(pdev, NULL);

	pci_clear_master(pdev);

	pci_release_regions(pdev);
}

static int lsdc_drm_suspend(struct device *dev)
{
	struct lsdc_device *ldev = dev_get_drvdata(dev);

	return drm_mode_config_helper_suspend(ldev->ddev);
}

static int lsdc_drm_resume(struct device *dev)
{
	struct lsdc_device *ldev = dev_get_drvdata(dev);

	return drm_mode_config_helper_resume(ldev->ddev);
}

static int lsdc_pm_freeze(struct device *dev)
{
	return lsdc_drm_suspend(dev);
}

static int lsdc_pm_thaw(struct device *dev)
{
	return lsdc_drm_resume(dev);
}

static int lsdc_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int error;

	error = lsdc_pm_freeze(dev);
	if (error)
		return error;

	pci_save_state(pdev);
	/* Shut down the device */
	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);

	return 0;
}

static int lsdc_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	if (pcim_enable_device(pdev))
		return -EIO;

	pci_set_power_state(pdev, PCI_D0);

	pci_restore_state(pdev);

	return lsdc_pm_thaw(dev);
}

static const struct dev_pm_ops lsdc_pm_ops = {
	.suspend = lsdc_pm_suspend,
	.resume = lsdc_pm_resume,
	.freeze = lsdc_pm_freeze,
	.thaw = lsdc_pm_thaw,
	.poweroff = lsdc_pm_freeze,
	.restore = lsdc_pm_resume,
};

static const struct pci_device_id lsdc_pciid_list[] = {
	{PCI_VENDOR_ID_LOONGSON, 0x7a06, PCI_ANY_ID, PCI_ANY_ID, 0, 0, (kernel_ulong_t)LSDC_CHIP_7A1000},
	{PCI_VENDOR_ID_LOONGSON, 0x7a36, PCI_ANY_ID, PCI_ANY_ID, 0, 0, (kernel_ulong_t)LSDC_CHIP_7A2000},
	{0, 0, 0, 0, 0, 0, 0}
};

static struct pci_driver lsdc_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = lsdc_pciid_list,
	.probe = lsdc_pci_probe,
	.remove = lsdc_pci_remove,
	.driver.pm = &lsdc_pm_ops,
};

static int __init lsdc_drm_init(void)
{
	struct pci_dev *pdev = NULL;

	while ((pdev = pci_get_class(PCI_CLASS_DISPLAY_VGA << 8, pdev))) {
		/*
		 * Multiple video card workaround
		 *
		 * This integrated video card will always be selected as
		 * default boot device by vgaarb subsystem.
		 */
		if (pdev->vendor != PCI_VENDOR_ID_LOONGSON) {
			pr_info("Discrete graphic card detected, abort\n");
			return 0;
		}
	}

	return pci_register_driver(&lsdc_pci_driver);
}
module_init(lsdc_drm_init);

static void __exit lsdc_drm_exit(void)
{
	pci_unregister_driver(&lsdc_pci_driver);
}
module_exit(lsdc_drm_exit);

MODULE_DEVICE_TABLE(pci, lsdc_pciid_list);
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL v2");
