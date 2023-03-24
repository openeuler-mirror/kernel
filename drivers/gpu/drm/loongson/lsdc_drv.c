// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include <linux/pci.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>

#include <drm/drm_vblank.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_vram_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_modeset_helper.h>

#include "lsdc_drv.h"
#include "lsdc_irq.h"
#include "lsdc_output.h"
#include "lsdc_debugfs.h"
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

static const struct lsdc_chip_desc dc_in_ls2k1000 = {
	.chip = LSDC_CHIP_2K1000,
	.num_of_crtc = LSDC_NUM_CRTC,
	/* ls2k1000 user manual say the max pixel clock can be about 200MHz */
	.max_pixel_clk = 200000,
	.max_width = 2560,
	.max_height = 2048,
	.num_of_hw_cursor = 1,
	.hw_cursor_w = 32,
	.hw_cursor_h = 32,
	.stride_alignment = 256,
	.has_builtin_i2c = false,
	.has_vram = false,
	.broken_gamma = true,
};

static const struct lsdc_chip_desc dc_in_ls2k0500 = {
	.chip = LSDC_CHIP_2K0500,
	.num_of_crtc = LSDC_NUM_CRTC,
	.max_pixel_clk = 200000,
	.max_width = 2048,
	.max_height = 2048,
	.num_of_hw_cursor = 1,
	.hw_cursor_w = 32,
	.hw_cursor_h = 32,
	.stride_alignment = 256,
	.has_builtin_i2c = false,
	.has_vram = false,
	.broken_gamma = true,
};

static const struct lsdc_chip_desc dc_in_ls7a1000 = {
	.chip = LSDC_CHIP_7A1000,
	.num_of_crtc = LSDC_NUM_CRTC,
	.max_pixel_clk = 200000,
	.max_width = 2048,
	.max_height = 2048,
	.num_of_hw_cursor = 1,
	.hw_cursor_w = 32,
	.hw_cursor_h = 32,
	.stride_alignment = 256,
	.has_builtin_i2c = true,
	.has_vram = true,
	.broken_gamma = true,
};

static const struct lsdc_chip_desc dc_in_ls7a2000 = {
	.chip = LSDC_CHIP_7A2000,
	.num_of_crtc = LSDC_NUM_CRTC,
	.max_pixel_clk = 200000,
	.max_width = 2048,
	.max_height = 2048,
	.num_of_hw_cursor = 2,
	.hw_cursor_w = 64,
	.hw_cursor_h = 64,
	.stride_alignment = 256,
	.has_builtin_i2c = true,
	.has_vram = true,
	.broken_gamma = true,
};

static enum drm_mode_status
lsdc_device_mode_valid(struct drm_device *ddev, const struct drm_display_mode *mode)
{
	struct lsdc_device *ldev = to_lsdc(ddev);

	if (ldev->use_vram_helper)
		return drm_vram_helper_mode_valid(ddev, mode);

	return MODE_OK;
}

static const struct drm_mode_config_funcs lsdc_mode_config_funcs = {
	.fb_create = drm_gem_fb_create,
	.output_poll_changed = drm_fb_helper_output_poll_changed,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
	.mode_valid = lsdc_device_mode_valid,
};

static int lsdc_gem_cma_dumb_create(struct drm_file *file,
				    struct drm_device *ddev,
				    struct drm_mode_create_dumb *args)
{
	struct lsdc_device *ldev = to_lsdc(ddev);
	const struct lsdc_chip_desc *desc = ldev->desc;
	unsigned int bytes_per_pixel = (args->bpp + 7) / 8;
	unsigned int pitch = bytes_per_pixel * args->width;

	/*
	 * The dc in ls7a1000/ls2k1000/ls2k0500 require the stride be a
	 * multiple of 256 bytes which is for sake of optimize dma data
	 * transfer.
	 */
	args->pitch = roundup(pitch, desc->stride_alignment);

	return drm_gem_cma_dumb_create_internal(file, ddev, args);
}

DEFINE_DRM_GEM_FOPS(lsdc_gem_fops);

static struct drm_driver lsdc_vram_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_ATOMIC,
	.fops = &lsdc_gem_fops,

	.name = "loongson-drm",
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
#ifdef CONFIG_DEBUG_FS
	.debugfs_init = lsdc_vram_mm_debugfs_init,
#endif
	.dumb_create = drm_gem_vram_driver_dumb_create,
	.dumb_map_offset = drm_gem_vram_driver_dumb_mmap_offset,
	.gem_prime_mmap = drm_gem_prime_mmap,
};

static int lsdc_modeset_init(struct lsdc_device *ldev, uint32_t num_crtc)
{
	struct drm_device *ddev = &ldev->ddev;
	unsigned int i;
	int ret;

	if (ldev->has_ports_node) {
		drm_info(ddev, "Has OF graph support\n");
		ret = lsdc_attach_output(ldev, num_crtc);
		if (ret)
			return ret;
	} else {
		drm_info(ddev, "No OF graph support\n");
		for (i = 0; i < num_crtc; i++) {
			ret = lsdc_create_output(ldev, i, num_crtc);
			if (ret)
				return ret;
		}
	}

	for (i = 0; i < num_crtc; i++) {
		struct lsdc_display_pipe * const dispipe = &ldev->dispipe[i];
		struct drm_plane * const primary = &dispipe->primary;
		struct drm_plane * const cursor = &dispipe->cursor;
		struct drm_crtc * const crtc = &dispipe->crtc;
		struct lsdc_pll * const pixpll = &dispipe->pixpll;

		dispipe->index = i;

		ret = lsdc_pixpll_init(pixpll, ddev, i);
		if (ret)
			return ret;

		ret = lsdc_plane_init(ldev, primary, DRM_PLANE_TYPE_PRIMARY, i);
		if (ret)
			return ret;

		ret = lsdc_plane_init(ldev, cursor, DRM_PLANE_TYPE_CURSOR, i);
		if (ret)
			return ret;

		/*
		 * Initial all of the CRTC available, in this way the crtc
		 * index is equal to the hardware crtc index. That is:
		 * display pipe 0 => crtc0 + dvo0 + encoder0
		 * display pipe 1 => crtc1 + dvo1 + encoder1
		 */
		ret = lsdc_crtc_init(ddev, crtc, i, primary, cursor);
		if (ret)
			return ret;

		drm_info(ddev, "display pipe %u initialized\n", i);
	}

	return 0;
}

static int lsdc_mode_config_init(struct lsdc_device *ldev)
{
	const struct lsdc_chip_desc * const descp = ldev->desc;
	struct drm_device *ddev = &ldev->ddev;
	int ret;

	ret = drmm_mode_config_init(ddev);
	if (ret)
		return ret;

	ddev->mode_config.funcs = &lsdc_mode_config_funcs;
	ddev->mode_config.min_width = 1;
	ddev->mode_config.min_height = 1;
	ddev->mode_config.max_width = 4096;
	ddev->mode_config.max_height = 4096;
	ddev->mode_config.preferred_depth = 24;
	ddev->mode_config.prefer_shadow = ldev->use_vram_helper;

	ddev->mode_config.cursor_width = descp->hw_cursor_h;
	ddev->mode_config.cursor_height = descp->hw_cursor_h;

	if (ldev->vram_base)
		ddev->mode_config.fb_base = ldev->vram_base;

	return lsdc_modeset_init(ldev, descp->num_of_crtc);
}

/*
 * lsdc_detect_chip - a function to tell different chips apart.
 */
const struct lsdc_chip_desc *
lsdc_detect_chip(struct pci_dev *pdev, const struct pci_device_id * const ent)
{
	static const struct lsdc_match {
		char name[128];
		const void *data;
	} compat[] = {
		{ .name = "loongson,ls7a1000-dc", .data = &dc_in_ls7a1000 },
		{ .name = "loongson,ls2k1000-dc", .data = &dc_in_ls2k1000 },
		{ .name = "loongson,ls2k0500-dc", .data = &dc_in_ls2k0500 },
		{ .name = "loongson,ls7a2000-dc", .data = &dc_in_ls7a2000 },
		{ .name = "loongson,loongson64c-4core-ls7a", .data = &dc_in_ls7a1000 },
		{ .name = "loongson,loongson64g-4core-ls7a", .data = &dc_in_ls7a1000 },
		{ .name = "loongson,loongson64-2core-2k1000", .data = &dc_in_ls2k1000 },
		{ .name = "loongson,loongson2k1000", .data = &dc_in_ls2k1000 },
		{ /* sentinel */ },
	};

	struct device_node *np;
	unsigned int i;

	if (ent->driver_data == LSDC_CHIP_7A2000)
		return &dc_in_ls7a2000;

	if (ent->driver_data == LSDC_CHIP_7A1000)
		return &dc_in_ls7a1000;

	/* Deduce DC variant information from the DC device node */
	for (i = 0; i < ARRAY_SIZE(compat); ++i) {
		np = of_find_compatible_node(NULL, NULL, compat[i].name);
		if (!np)
			continue;

		of_node_put(np);

		return compat[i].data;
	}

	dev_info(&pdev->dev, "No Compatible Device Node Found\n");

	if (pci_get_device(PCI_VENDOR_ID_LOONGSON, 0x7A15, NULL))
		return &dc_in_ls7a1000;
	else if (pci_get_device(PCI_VENDOR_ID_LOONGSON, 0x7A05, NULL))
		return &dc_in_ls2k1000;

	return NULL;
}

static int lsdc_remove_conflicting_framebuffers(void)
{
	struct apertures_struct *ap;

	ap = alloc_apertures(1);
	if (!ap)
		return -ENOMEM;

	ap->ranges[0].base = 0;
	ap->ranges[0].size = ~0;

	return drm_fb_helper_remove_conflicting_framebuffers(ap, "loongsondrmfb", false);
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
		drm_err(&ldev->ddev, "Unknown chip, the driver need update\n");
		return -ENOENT;
	}

	base = pci_resource_start(gpu, 2);
	size = pci_resource_len(gpu, 2);

	ldev->vram_base = base;
	ldev->vram_size = size;

	drm_info(&ldev->ddev, "vram start: 0x%llx, size: %uMB\n",
		 (u64)base, (u32)(size >> 20));

	return 0;
}

static int lsdc_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct lsdc_device *ldev;
	struct drm_device *ddev;
	const struct lsdc_chip_desc *descp;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	pci_set_master(pdev);

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(40));
	if (ret)
		return ret;

	descp = lsdc_detect_chip(pdev, ent);
	if (!descp) {
		pr_info("unknown dc ip core, abort\n");
		return -ENOENT;
	}

	lsdc_remove_conflicting_framebuffers();

	ldev = devm_drm_dev_alloc(&pdev->dev, &lsdc_vram_driver, struct lsdc_device, ddev);
	if (IS_ERR(ldev))
		return PTR_ERR(ldev);

	ldev->desc = descp;
	ldev->use_vram_helper = lsdc_use_vram_helper && descp->has_vram;

	ddev = &ldev->ddev;
	ddev->pdev = pdev;

	pci_set_drvdata(pdev, ddev);

	if (!descp->broken_gamma)
		ldev->enable_gamma = true;
	else
		ldev->enable_gamma = lsdc_gamma > 0 ? true : false;

	ldev->relax_alignment = lsdc_relax_alignment > 0 ? true : false;

	/* BAR 0 of the DC device contain registers base address */
	ldev->reg_base = pcim_iomap(pdev, 0, 0);
	if (!ldev->reg_base)
		return -ENODEV;

	if (ldev->use_vram_helper) {
		ret = lsdc_vram_init(ldev);
		if (ret) {
			drm_err(ddev, "VRAM is unavailable\n");
			ldev->use_vram_helper = false;
		}
	}

	ldev->irq = pdev->irq;

	if (ldev->use_vram_helper) {
		ret = drmm_vram_helper_init(ddev, ldev->vram_base, ldev->vram_size);
		if (ret) {
			drm_err(ddev, "vram helper init failed: %d\n", ret);
			goto err_kms;
		}
	};

	spin_lock_init(&ldev->reglock);

	ret = lsdc_mode_config_init(ldev);
	if (ret) {
		drm_dbg(ddev, "%s: %d\n", __func__, ret);
		goto err_kms;
	}

	drm_mode_config_reset(ddev);

	ret = devm_request_threaded_irq(&pdev->dev,
					ldev->irq,
					lsdc_irq_handler_cb,
					lsdc_irq_thread_cb,
					IRQF_ONESHOT, NULL,
					ddev);
	if (ret) {
		drm_err(ddev, "Failed to register lsdc interrupt\n");
		goto err_kms;
	}

	ret = drm_vblank_init(ddev, ldev->desc->num_of_crtc);
	if (ret)
		goto err_kms;

	drm_kms_helper_poll_init(ddev);

	ret = drm_dev_register(ddev, 0);
	if (ret)
		goto err_poll_fini;

	drm_fbdev_generic_setup(ddev, 32);

	return 0;

err_poll_fini:
	drm_kms_helper_poll_fini(ddev);
err_kms:
	drm_dev_put(ddev);

	return ret;

}

static void lsdc_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *ddev = pci_get_drvdata(pdev);
	struct lsdc_device *ldev = to_lsdc(ddev);

	drm_dev_unregister(ddev);
	drm_atomic_helper_shutdown(ddev);
}

static int lsdc_drm_freeze(struct drm_device *ddev)
{
	int error;

	error = drm_mode_config_helper_suspend(ddev);
	if (error)
		return error;

	pci_save_state(to_pci_dev(ddev->dev));

	return 0;
}

static int lsdc_drm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);

	return drm_mode_config_helper_resume(ddev);
}

static int lsdc_pm_freeze(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);

	return lsdc_drm_freeze(ddev);
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
