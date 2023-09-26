// SPDX-License-Identifier: GPL-2.0-only
/* INSPUR SoC drm driver
 *
 * Based on the smi drm driver.
 *
 * Copyright (c) 2020 SMI Limited.
 *
 * Author:
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/console.h>
#include <linux/module.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_probe_helper.h>

#include "inspur_drm_drv.h"
#include "inspur_drm_regs.h"

#define MEM_SIZE_RESERVE4KVM 0x200000


DEFINE_DRM_GEM_FOPS(inspur_fops);
irqreturn_t inspur_drm_interrupt(int irq, void *arg)
{
	struct drm_device *dev = (struct drm_device *)arg;
	struct inspur_drm_private *priv =
		(struct inspur_drm_private *)dev->dev_private;
	u32 status;

	status = readl(priv->mmio + INSPUR_RAW_INTERRUPT);

	if (status & INSPUR_RAW_INTERRUPT_VBLANK(1)) {
		writel(INSPUR_RAW_INTERRUPT_VBLANK(1),
		       priv->mmio + INSPUR_RAW_INTERRUPT);
		drm_handle_vblank(dev, 0);
	}

	return IRQ_HANDLED;
}



static struct drm_driver inspur_driver = {
	.driver_features	= DRIVER_GEM | DRIVER_MODESET |
				  DRIVER_ATOMIC | DRIVER_HAVE_IRQ,

	.fops			= &inspur_fops,
	.name			= "inspur",
	.date			= "20230425",
	.desc			= "inspur drm driver",
	.major			= 2,
	.minor			= 2,
	//.gem_free_object_unlocked = inspur_gem_free_object,
	.dumb_create            = inspur_dumb_create,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	.dumb_map_offset		  = drm_gem_ttm_dumb_map_offset,
#else
	.dumb_map_offset		  = drm_gem_vram_driver_dumb_mmap_offset,
#endif
};

static void inspur_remove_framebuffers(struct pci_dev *pdev)
{
	struct apertures_struct *ap;

	ap = alloc_apertures(1);
	if (!ap)
		return;

	ap->ranges[0].base = pci_resource_start(pdev, 0);
	ap->ranges[0].size = pci_resource_len(pdev, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	drm_aperture_remove_conflicting_pci_framebuffers(pdev, &inspur_driver);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	drm_aperture_remove_conflicting_pci_framebuffers(pdev, "inspurdrmfb");
#else
	drm_fb_helper_remove_conflicting_pci_framebuffers(pdev, "inspurdrmfb");
#endif

	kfree(ap);
}

static int __maybe_unused inspur_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct inspur_drm_private *priv = drm_dev->dev_private;

	drm_kms_helper_poll_disable(drm_dev);
	priv->suspend_state = drm_atomic_helper_suspend(drm_dev);
	if (IS_ERR(priv->suspend_state)) {
		DRM_ERROR("drm_atomic_helper_suspend failed: %ld\n",
			  PTR_ERR(priv->suspend_state));
		drm_kms_helper_poll_enable(drm_dev);
		return PTR_ERR(priv->suspend_state);
	}

	return 0;
}

static int  __maybe_unused inspur_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct inspur_drm_private *priv = drm_dev->dev_private;

	drm_atomic_helper_resume(drm_dev, priv->suspend_state);
	drm_kms_helper_poll_enable(drm_dev);

	return 0;
}

static const struct dev_pm_ops inspur_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(inspur_pm_suspend,
				inspur_pm_resume)
};

static int inspur_kms_init(struct inspur_drm_private *priv)
{
	int ret;

	drm_mode_config_init(priv->dev);
	priv->mode_config_initialized = true;

	priv->dev->mode_config.min_width = 0;
	priv->dev->mode_config.min_height = 0;
	priv->dev->mode_config.max_width = 1920;
	priv->dev->mode_config.max_height = 1200;

	priv->dev->mode_config.fb_base = priv->fb_base;
	priv->dev->mode_config.preferred_depth = 32;
	priv->dev->mode_config.prefer_shadow = 1;

	if (getKVMHWCursorSetting(priv)) {
		priv->dev->mode_config.cursor_width = 64;
		priv->dev->mode_config.cursor_height = 64;
	}

	priv->dev->mode_config.funcs = (void *)&inspur_mode_funcs;

	ret = inspur_de_init(priv);
	if (ret) {
		DRM_ERROR("failed to init de: %d\n", ret);
		return ret;
	}

	ret = inspur_vdac_init(priv);
	if (ret) {
		DRM_ERROR("failed to init vdac: %d\n", ret);
		return ret;
	}

	return 0;
}

static void inspur_kms_fini(struct inspur_drm_private *priv)
{
	if (priv->mode_config_initialized) {
		drm_mode_config_cleanup(priv->dev);
		priv->mode_config_initialized = false;
	}
}

/*
 * It can operate in one of three modes: 0, 1 or Sleep.
 */
void inspur_set_power_mode(struct inspur_drm_private *priv,
			  unsigned int power_mode)
{
	unsigned int control_value = 0;
	void __iomem   *mmio = priv->mmio;
	unsigned int input = 1;

	if (power_mode > INSPUR_PW_MODE_CTL_MODE_SLEEP)
		return;

	if (power_mode == INSPUR_PW_MODE_CTL_MODE_SLEEP)
		input = 0;

	control_value = readl(mmio + INSPUR_POWER_MODE_CTRL);
	control_value &= ~(INSPUR_PW_MODE_CTL_MODE_MASK |
			   INSPUR_PW_MODE_CTL_OSC_INPUT_MASK);
	control_value |= INSPUR_FIELD(INSPUR_PW_MODE_CTL_MODE, power_mode);
	control_value |= INSPUR_FIELD(INSPUR_PW_MODE_CTL_OSC_INPUT, input);
	writel(control_value, mmio + INSPUR_POWER_MODE_CTRL);
}

void inspur_set_current_gate(struct inspur_drm_private *priv, unsigned int gate)
{
	unsigned int gate_reg;
	unsigned int mode;
	void __iomem   *mmio = priv->mmio;

	/* Get current power mode. */
	mode = (readl(mmio + INSPUR_POWER_MODE_CTRL) &
		INSPUR_PW_MODE_CTL_MODE_MASK) >> INSPUR_PW_MODE_CTL_MODE_SHIFT;

	switch (mode) {
	case INSPUR_PW_MODE_CTL_MODE_MODE0:
		gate_reg = INSPUR_MODE0_GATE;
		break;

	case INSPUR_PW_MODE_CTL_MODE_MODE1:
		gate_reg = INSPUR_MODE1_GATE;
		break;

	default:
		gate_reg = INSPUR_MODE0_GATE;
		break;
	}
	writel(gate, mmio + gate_reg);
}

static void inspur_hw_config(struct inspur_drm_private *priv)
{
	unsigned int reg;

	/* On hardware reset, power mode 0 is default. */
	inspur_set_power_mode(priv, INSPUR_PW_MODE_CTL_MODE_MODE0);

	/* Enable display power gate & LOCALMEM power gate*/
	reg = readl(priv->mmio + INSPUR_CURRENT_GATE);
	reg &= ~INSPUR_CURR_GATE_DISPLAY_MASK;
	reg &= ~INSPUR_CURR_GATE_LOCALMEM_MASK;
	reg |= INSPUR_CURR_GATE_DISPLAY(1);
	reg |= INSPUR_CURR_GATE_LOCALMEM(1);

	inspur_set_current_gate(priv, reg);

	/*
	 * Reset the memory controller. If the memory controller
	 * is not reset in chip,the system might hang when sw accesses
	 * the memory.The memory should be resetted after
	 * changing the MXCLK.
	 */
	reg = readl(priv->mmio + INSPUR_MISC_CTRL);
	reg &= ~INSPUR_MSCCTL_LOCALMEM_RESET_MASK;
	reg |= INSPUR_MSCCTL_LOCALMEM_RESET(0);
	writel(reg, priv->mmio + INSPUR_MISC_CTRL);

	reg &= ~INSPUR_MSCCTL_LOCALMEM_RESET_MASK;
	reg |= INSPUR_MSCCTL_LOCALMEM_RESET(1);

	writel(reg, priv->mmio + INSPUR_MISC_CTRL);
}

static int inspur_hw_map(struct inspur_drm_private *priv)
{
	struct drm_device *dev = priv->dev;
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	resource_size_t addr, size, ioaddr, iosize;

	ioaddr = pci_resource_start(pdev, 1);
	iosize = pci_resource_len(pdev, 1);
	priv->mmio = devm_ioremap(dev->dev, ioaddr, iosize);
	if (!priv->mmio) {
		DRM_ERROR("Cannot map mmio region\n");
		return -ENOMEM;
	}

	addr = pci_resource_start(pdev, 0);
	size = pci_resource_len(pdev, 0);
	priv->fb_map = devm_ioremap(dev->dev, addr, size);
	if (!priv->fb_map) {
		DRM_ERROR("Cannot map framebuffer\n");
		return -ENOMEM;
	}
	priv->fb_base = addr;
	priv->fb_size = size - MEM_SIZE_RESERVE4KVM;

	return 0;
}

static void inspur_hw_unmap(struct inspur_drm_private *priv)
{
	struct drm_device *dev = priv->dev;

	if (priv->mmio) {
		devm_iounmap(dev->dev, priv->mmio);
		priv->mmio = NULL;
	}
	if (priv->fb_map) {
		devm_iounmap(dev->dev, priv->fb_map);
		priv->fb_map = NULL;
	}
}

static int inspur_hw_init(struct inspur_drm_private *priv)
{
	int ret;

	ret = inspur_hw_map(priv);
	if (ret)
		return ret;

	inspur_hw_config(priv);

	return 0;
}

void inspur_unload(struct drm_device *dev)
{
	struct inspur_drm_private *priv = dev->dev_private;
	struct pci_dev *pdev = to_pci_dev(dev->dev);

	drm_atomic_helper_shutdown(dev);

	free_irq(pdev->irq, dev);

	inspur_kms_fini(priv);
	inspur_hw_unmap(priv);
	pci_disable_msi(to_pci_dev(dev->dev));
	dev->dev_private = NULL;
}

int inspur_load(struct drm_device *dev, unsigned long flags)
{
	struct inspur_drm_private *priv;
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	int ret;

	priv = devm_kzalloc(dev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		DRM_ERROR("no memory to allocate for inspur_drm_private\n");
		return -ENOMEM;
	}
	dev->dev_private = priv;
	priv->dev = dev;

	ret = inspur_hw_init(priv);
	if (ret)
		goto err;

	ret = drmm_vram_helper_init(dev, pci_resource_start(pdev, 0), priv->fb_size);
	if (ret) {
		drm_err(dev, "Error initializing VRAM MM; %d\n", ret);
		goto err;
	}
	ret = inspur_kms_init(priv);
	if (ret)
		goto err;


	/* reset all the states of crtc/plane/encoder/connector */
	drm_mode_config_reset(dev);

	if (getKVMHWCursorSetting(priv)) {
#if 0
		inspur_bo_create(dev, PAGE_ALIGN(1024), 0, 0, &priv->cursor.cursor_1);
		inspur_bo_create(dev, PAGE_ALIGN(1024), 0, 0, &priv->cursor.cursor_2);
		if (!priv->cursor.cursor_1 || !priv->cursor.cursor_2) {
			priv->cursor.cursor_1 = NULL;
			priv->cursor.cursor_2 = NULL;
			DRM_ERROR("Could not allocate space for cursors. Not doing hardware cursors.\n");
		}
#endif
	}

	return 0;

err:
	inspur_unload(dev);
	DRM_ERROR("failed to initialize drm driver: %d\n", ret);
	return ret;
}

static int inspur_pci_probe(struct pci_dev *pdev,
			   const struct pci_device_id *ent)
{
	int ret = 0;
	struct inspur_drm_private __maybe_unused *priv;
	struct drm_device *dev;

	inspur_remove_framebuffers(pdev);

	dev = drm_dev_alloc(&inspur_driver, &pdev->dev);
	if (IS_ERR(dev)) {
		DRM_ERROR("failed to allocate drm_device\n");
		return PTR_ERR(dev);
	}

	pci_set_drvdata(pdev, dev);
	ret = pci_enable_device(pdev);
	if (ret) {
		drm_err(dev, "failed to enable pci device: %d\n", ret);
		return ret;
	}
	ret = inspur_load(dev, ent->driver_data);
	if (ret)
		goto err_return;

	ret = drm_dev_register(dev, ent->driver_data);
	if (ret)
		goto err_inspur_driver_unload;

	drm_fbdev_generic_setup(dev, dev->mode_config.preferred_depth);

	return 0;
err_inspur_driver_unload:
		inspur_unload(dev);
err_return:
	return ret;
}

static void inspur_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_put_dev(dev);
	pci_disable_device(pdev);
}

static void inspur_pci_shutdown(struct pci_dev *pdev)
{
	inspur_pci_remove(pdev);
}

static struct pci_device_id inspur_pci_table[] = {
	{0x1bd4, 0x0750, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0,}
};

static struct pci_driver inspur_pci_driver = {
	.name =		"inspur-drm",
	.id_table =	inspur_pci_table,
	.probe =	inspur_pci_probe,
	.remove =	inspur_pci_remove,
	.shutdown = inspur_pci_shutdown,
	.driver.pm =    &inspur_pm_ops,
};

static int __init inspur_init(void)
{
	return pci_register_driver(&inspur_pci_driver);
}

static void __exit inspur_exit(void)
{
	return pci_unregister_driver(&inspur_pci_driver);
}

module_init(inspur_init);
module_exit(inspur_exit);

MODULE_DEVICE_TABLE(pci, inspur_pci_table);
MODULE_AUTHOR("");
MODULE_DESCRIPTION("DRM Driver for INSPUR");
MODULE_LICENSE("GPL v2");
