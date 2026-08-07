// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2026-03-30
 *   - Removed LINUX_VERSION_CODE macros for checkpatch.pl compliance
 * Modified: 2026-03-24
 *   - Added MODULE_DEVICE_TABLE(pci, vs_egt_pci_table)
 * Modified: 2026-04-02
 *   - Added vs_fb_kick_off_efifb to release BIOS framebuffer
 *   - Added vs_egt_fbdev_init for console initialization
 * Modified: 2025-02-10
 *   - Added vs_pci_shutdown to reset DC on reboot
 * Modified: 2025-09-10
 *   - Added vs_pci_error_detected to release driver on AER error
 */

#include <linux/component.h>
#include <linux/iommu.h>
#include <linux/of_graph.h>
#include <linux/aperture.h>

#include <drm/drm_aperture.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_of.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_debugfs.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_prime.h>
#include <drm/drm_vblank.h>

#ifdef CONFIG_ENGIANT_VS_PCIE
#include <linux/pci.h>
#endif

#include "vs_crtc.h"
#include "vs_dc.h"
#include "vs_drv.h"
#include "vs_fb.h"
#include "vs_gem.h"
#include "vs_plane.h"
#include "vs_simple_enc.h"
#include "vs_virtual.h"

#ifdef CONFIG_DRM_EGT_DP
#include "egt_dp.h"
#endif /* end of CONFIG_DRM_EGT */

#ifdef CONFIG_ENGIANT_VS_QSPI
#include "vs_dc_qspi.h"
#endif

#define DRV_NAME "egt_drm"
#define DRV_DESC "VeriSilicon DRM driver"
#define DRV_DATE "20191101"
#define DRV_MAJOR 1
#define DRV_MINOR 0

/* pcie driver and platform driver common */

static bool has_iommu = true;
static struct drm_device *dev_drm;
static int aer;

/*for interrupts destinations*/
/*"NS" is non-security, "TZ" is trust zone, "GSA" is G security, "AOC" is ambient on computing*/
static bool intr_dest_ns = true;
module_param_named(NS, intr_dest_ns, bool, 0644);
static bool intr_dest_tz;
module_param_named(TZ, intr_dest_tz, bool, 0644);
static bool intr_dest_gsa;
module_param_named(GSA, intr_dest_gsa, bool, 0644);
static bool intr_dest_aoc;
module_param_named(AOC, intr_dest_aoc, bool, 0644);

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.compat_ioctl = drm_compat_ioctl,
	.poll = drm_poll,
	.read = drm_read,
	.mmap = vs_egt_gem_mmap,
};

#ifdef CONFIG_DEBUG_FS
static int vs_debugfs_planes_show(struct seq_file *s, __maybe_unused void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)s->private;
	struct drm_device *dev = node->minor->dev;
	struct drm_plane *plane;

	list_for_each_entry(plane, &dev->mode_config.plane_list, head) {
		struct drm_plane_state *state = plane->state;
		struct vs_plane_state *plane_state = to_vs_plane_state(state);

		seq_printf(s, "plane[%u]: %s\n", plane->base.id, plane->name);
		seq_printf(s, "\tcrtc = %s\n", state->crtc ? state->crtc->name : "(null)");
		seq_printf(s, "\tcrtc id = %u\n", state->crtc ? state->crtc->base.id : 0);
		seq_printf(s, "\tcrtc-pos = " DRM_RECT_FMT "\n",
			   DRM_RECT_ARG(&plane_state->status.dest));
		seq_printf(s, "\tsrc-pos = " DRM_RECT_FP_FMT "\n",
			   DRM_RECT_FP_ARG(&plane_state->status.src));
		seq_printf(s, "\tformat = %p4cc\n", &state->fb->format->format);
		seq_printf(s, "\trotation = 0x%x\n", state->rotation);
		seq_printf(s, "\ttiling = %u\n", plane_state->status.tile_mode);

		seq_puts(s, "\n");
	}

	return 0;
}

static struct drm_info_list vs_debugfs_list[] = {
	{ "planes", vs_debugfs_planes_show, 0, NULL },
};

static void vs_debugfs_init(struct drm_minor *minor)
{
	drm_debugfs_create_files(vs_debugfs_list, ARRAY_SIZE(vs_debugfs_list), minor->debugfs_root,
				 minor);
}
#endif

static struct drm_driver vs_drm_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_ATOMIC | DRIVER_GEM,
	.lastclose = drm_fb_helper_lastclose,
	.prime_handle_to_fd = drm_gem_prime_handle_to_fd,
	.prime_fd_to_handle = drm_gem_prime_fd_to_handle,

	.gem_prime_import = vs_egt_gem_prime_import,
	.gem_prime_import_sg_table = vs_egt_gem_prime_import_sg_table,
	.dumb_create = vs_egt_gem_dumb_create,
#ifdef CONFIG_DEBUG_FS
	.debugfs_init = vs_debugfs_init,
#endif
	.fops = &fops,
	.name = DRV_NAME,
	.desc = DRV_DESC,
	.date = DRV_DATE,
	.major = DRV_MAJOR,
	.minor = DRV_MINOR,
};

int vs_egt_drm_iommu_attach_device(struct drm_device *drm_dev, struct device *dev)
{
	struct vs_drm_private *priv = drm_dev->dev_private;
	int ret;

	if (!has_iommu)
		return 0;

	if (!priv->domain) {
		priv->domain = iommu_get_domain_for_dev(dev);
		if (IS_ERR(priv->domain))
			return PTR_ERR(priv->domain);
		priv->dma_dev = dev;
	}

	ret = iommu_attach_device(priv->domain, dev);
	if (ret) {
		DRM_DEV_ERROR(dev, "Failed to attach iommu device\n");
		return ret;
	}

	return 0;
}

void vs_egt_drm_iommu_detach_device(struct drm_device *drm_dev, struct device *dev)
{
	struct vs_drm_private *priv = drm_dev->dev_private;

	if (!has_iommu)
		return;

	iommu_detach_device(priv->domain, dev);

	if (priv->dma_dev == dev)
		priv->dma_dev = drm_dev->dev;
}

void vs_egt_drm_update_alignment(struct drm_device *drm_dev, unsigned int pitch_align,
				 unsigned int addr_align)
{
	struct vs_drm_private *priv = drm_dev->dev_private;

	if (pitch_align > priv->pitch_alignment)
		priv->pitch_alignment = pitch_align;

	if (addr_align > priv->addr_alignment)
		priv->addr_alignment = addr_align;
}

#ifdef CONFIG_ENGIANT_VS_PCIE

/* pcie driver */
static struct pci_device_id vs_egt_pci_table[] = {
	{
		PCI_DEVICE(0x1556, 0x0001),
		.class = 0,
		.class_mask = 0,
	},
	{}
};

MODULE_DEVICE_TABLE(pci, vs_egt_pci_table);

static int vs_drm_device_init(struct drm_device *dev)
{
	int ret;

	ret = vs_egt_dc_pci_init(dev);
	if (ret) {
		DRM_ERROR("fail to init vs dc: %d\n", ret);
		goto err_ret;
	}

#ifdef CONFIG_ENGIANT_VS_VIRTUAL_DISPLAY
	/* encoder init. */
	ret = vs_egt_simple_encoder_pci_init(dev);
	if (ret) {
		DRM_ERROR("fail to init encoder: %d\n", ret);
		goto err_ret;
	}

	/* virtual display init. */
	ret = vs_egt_vd_pci_init(dev);
	if (ret) {
		DRM_ERROR("fail to init vs virtual display: %d\n", ret);
		goto err_ret;
	}
#endif

#ifdef CONFIG_DRM_EGT_DP
	/* egt display init. */
	pr_debug("%s egt_dp_device_init %d\n", __func__, __LINE__);
	ret = egt_dp_device_init(dev);
	if (ret) {
		DRM_ERROR("fail to init egt display: %d\n", ret);
		goto err_ret;
	}
#endif

#ifdef CONFIG_ENGIANT_VS_QSPI
	/* vs qspi init. */
	ret = vs_egt_qspi_pci_init(dev);
	if (ret) {
		DRM_ERROR("fail to init vs qspi controller: %d\n", ret);
		goto err_ret;
	}
#endif

err_ret:
	return ret;
}

static void vs_drm_device_deinit(struct drm_device *dev)
{
#ifdef CONFIG_ENGIANT_VS_VIRTUAL_DISPLAY
	vs_egt_simple_encoder_pci_deinit(dev);
	vs_egt_vd_pci_deinit(dev);
#endif

#ifdef CONFIG_DRM_EGT_DP
	/* virtual display deinit. */
	egt_dp_device_deinit(dev);
#endif

#ifdef CONFIG_ENGIANT_VS_QSPI
	vs_egt_qspi_pci_deinit(dev);
#endif

	vs_egt_dc_pci_deinit(dev);
}

static void vs_drm_device_deinit_aer(struct drm_device *dev)
{
#ifdef CONFIG_ENGIANT_VS_VIRTUAL_DISPLAY
	vs_egt_simple_encoder_pci_deinit(dev);
	vs_egt_vd_pci_deinit(dev);
#endif

#ifdef CONFIG_DRM_EGT_DP
	/* virtual display deinit. */
	egt_dp_device_deinit(dev);
#endif

#ifdef CONFIG_ENGIANT_VS_QSPI
	vs_egt_qspi_pci_deinit(dev);
#endif
	vs_egt_dc_pci_deinit_aer(dev);
}

struct vs_gem_private *vs_egt_gem_priv_init(struct drm_device *drm_dev)
{
	struct vs_gem_private *gem_priv = kmalloc(sizeof(*gem_priv), GFP_KERNEL);
	struct pci_dev *pdev = to_pci_dev(drm_dev->dev);

	if (!gem_priv) {
		DRM_ERROR("Failed to allocate gem_private\n");
		return NULL;
	}

	mutex_init(&gem_priv->vram_lock);

	memset(&gem_priv->vram, 0, sizeof(gem_priv->vram));

	/*map pci bar2 resource*/
	gem_priv->pci_addr = pci_resource_start(pdev, 2);
	pr_debug("pci_bar2 phiscal address: %pa, len: %#llx\n",
		   &gem_priv->pci_addr,
		   (unsigned long long)pci_resource_len(pdev, 2));

	/*initialize a drm-mm allocator to manager vram*/
	drm_mm_init(&gem_priv->vram, (u64)pci_resource_start(pdev, 2), EGT_VIDMEM_SIZE_64M);

	return gem_priv;
}

void vs_egt_gem_priv_deinit(struct drm_device *drm_dev)
{
	struct vs_drm_private *priv = NULL;
	struct vs_gem_private *gem_priv = NULL;

	if (!drm_dev) {
		DRM_ERROR("drm_dev is NULL\n");
		return;
	}

	priv = (struct vs_drm_private *)drm_dev->dev_private;
	gem_priv = priv->gem_priv;
	if (!gem_priv) {
		DRM_ERROR("gem_private is NULL\n");
		return;
	}

	gem_priv->pci_addr = 0;

	mutex_lock(&gem_priv->vram_lock);
	drm_mm_takedown(&gem_priv->vram);
	mutex_unlock(&gem_priv->vram_lock);
	mutex_destroy(&gem_priv->vram_lock);

	kfree(gem_priv);
	gem_priv = NULL;
	pr_debug("GEM private deinitialized successfully\n");
}

static int vs_fb_kick_off_efifb(void)
{
	resource_size_t base = 0;
	resource_size_t size = 0x300000;

	drm_aperture_remove_conflicting_framebuffers(base, size, &vs_drm_driver);
	return 0;
}

static int vs_pci_probe(struct pci_dev *pdev, __maybe_unused const struct pci_device_id *pent)
{
	struct drm_device *drm_dev;
	struct vs_drm_private *priv;
	int ret;

	drm_dev = drm_dev_alloc(&vs_drm_driver, &pdev->dev);
	if (IS_ERR(drm_dev)) {
		DRM_ERROR("failed to allocate drm device\n");
		return PTR_ERR(drm_dev);
	}

	ret = pci_enable_device(pdev);
	if (ret) {
		DRM_ERROR("fail to enable PCI device: %d\n", ret);
		goto err_out;
	}

	pci_set_master(pdev);

	dev_drm = drm_dev;

	priv = devm_kzalloc(drm_dev->dev, sizeof(struct vs_drm_private), GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto err_put;
	}

	/*gem private create*/
	priv->gem_priv = vs_egt_gem_priv_init(drm_dev);
	if (!priv->gem_priv) {
		ret = -ENOMEM;
		goto err_put;
	}

	priv->intr_dest = ((intr_dest_ns << 0) | (intr_dest_tz << 1) | (intr_dest_gsa << 2) |
			   (intr_dest_aoc << 3));
	priv->pitch_alignment = 64;
	priv->addr_alignment = 128;
	priv->dma_dev = drm_dev->dev;
	priv->drm_dev = dev_drm;
	drm_dev->dev_private = priv;

	drm_mode_config_init(drm_dev);

	has_iommu = false;

	ret = vs_drm_device_init(drm_dev);
	if (ret) {
		DRM_ERROR("fail to init drm device: %d\n", ret);
		goto err_mode;
	}

	vs_egt_mode_config_init(drm_dev);

	ret = drm_vblank_init(drm_dev, drm_dev->mode_config.num_crtc);
	if (ret) {
		DRM_ERROR("fail to init drm vblank: %d\n", ret);
		goto err_deinit;
	}

	drm_mode_config_reset(drm_dev);

#if IS_ENABLED(CONFIG_DRM_LEGACY)
	drm_dev->irq_enabled = drm_dev->num_crtcs != 0;
#endif

	drm_kms_helper_poll_init(drm_dev);

	ret = drm_dev_register(drm_dev, 0);
	if (ret) {
		DRM_ERROR("fail to register drm device: %d\n", ret);
		goto err_helper;
	}

	//kick off uefi fb
	vs_fb_kick_off_efifb();
	pr_debug("kick off uefi fb\n");

	//register fbdev
	ret = vs_egt_fbdev_init(drm_dev);
	if (ret)
		pr_err("fail to register framebuffer device: %d\n", ret);

	return 0;

err_helper:
	drm_kms_helper_poll_fini(drm_dev);
err_deinit:
	vs_drm_device_deinit(drm_dev);

	if (priv->domain)
		iommu_domain_free(priv->domain);

err_mode:
	drm_mode_config_cleanup(drm_dev);
	vs_egt_gem_priv_deinit(drm_dev);
err_put:
	pci_disable_device(pdev);
err_out:
	drm_dev_put(drm_dev);
	drm_dev->dev_private = NULL;
	pci_set_drvdata(pdev, NULL);

	return ret;
}

static void vs_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *drm_dev = dev_drm;

	drm_atomic_helper_shutdown(drm_dev);
	vs_drm_device_deinit(drm_dev);
	drm_dev_unregister(drm_dev);
	vs_egt_fbdev_fini(drm_dev);
	drm_kms_helper_poll_fini(drm_dev);
	drm_mode_config_cleanup(drm_dev);
	vs_egt_gem_priv_deinit(drm_dev);
	drm_dev->dev_private = NULL;
	drm_dev_put(drm_dev);
	pci_set_drvdata(pdev, NULL);
	pci_disable_device(pdev);
}

static int vs_pm_suspend(__maybe_unused struct device *dev)
{
	struct drm_device *drm_dev = dev_drm;
	int err;

	if (IS_ERR(drm_dev)) {
		err = PTR_ERR(drm_dev);
		pr_err("vs pm suspend NULL pointer\n");
		return err;
	}

	drm_mode_config_helper_suspend(drm_dev);

	return 0;
}

static int vs_pm_resume(__maybe_unused struct device *dev)
{
	struct drm_device *drm_dev = dev_drm;
	int err;

	if (IS_ERR(drm_dev)) {
		err = PTR_ERR(drm_dev);
		pr_err("vs pm suspend NULL pointer\n");
		return err;
	}

	drm_mode_config_helper_resume(drm_dev);

	return 0;
}

static void vs_pci_shutdown(__maybe_unused struct pci_dev *pdev)
{
	struct drm_device *drm_dev = dev_drm;

#ifdef CONFIG_DRM_EGT_DP
	egt_dp_send_stop_vdp(drm_dev);
#endif
	drm_atomic_helper_shutdown(drm_dev);
	vs_egt_fbdev_fini(drm_dev);
	drm_mode_config_reset(drm_dev);
}

static const struct dev_pm_ops vs_pm_ops = {
	.suspend = vs_pm_suspend,
	.resume = vs_pm_resume,
};

static u32 vs_drm_reg_read(struct drm_device *dev, u32 reg)
{
	u32 value;

	value = vs_egt_dc_reg_read(dev, reg);

	return value;
}

static pci_ers_result_t vs_pci_error_detected(struct pci_dev *pdev,
						__maybe_unused pci_channel_state_t state)
{
	u32 intr_status;
	struct drm_device *drm_dev = dev_drm;

	aer += 1;
	if (aer > 1)
		return PCI_ERS_RESULT_DISCONNECT;

	intr_status = vs_drm_reg_read(drm_dev, DCREG_BE_INTR_STATUS_Address);
	if (intr_status != 0xffffffff) {
		pr_err("DC register can also be accessed, please try to uninstall the egt_drm\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	vs_drm_device_deinit_aer(drm_dev);
	drm_dev_unregister(drm_dev);
	drm_kms_helper_poll_fini(drm_dev);
	pci_set_drvdata(pdev, NULL);
	pci_disable_device(pdev);

	return PCI_ERS_RESULT_DISCONNECT;
}

static pci_ers_result_t vs_pci_mmio_enabled(__maybe_unused struct pci_dev *pdev)
{
	pr_err("%s %d\n", __func__, __LINE__);
	return PCI_ERS_RESULT_RECOVERED;
}

static pci_ers_result_t vs_pci_slot_reset(__maybe_unused struct pci_dev *pdev)
{
	pr_err("%s %d\n", __func__, __LINE__);
	return PCI_ERS_RESULT_RECOVERED;
}

static void vs_pci_resume(__maybe_unused struct pci_dev *pdev)
{
	pr_err("%s %d\n", __func__, __LINE__);
}

static const struct pci_error_handlers vs_driver_aer_handlers = {
	.error_detected = vs_pci_error_detected,
	.mmio_enabled   = vs_pci_mmio_enabled,
	.slot_reset     = vs_pci_slot_reset,
	.resume         = vs_pci_resume,
};

static struct pci_driver vs_drm_pci_driver = {
	.name = "egt_drm",
	.id_table = vs_egt_pci_table,
	.probe = vs_pci_probe,
	.remove = vs_pci_remove,
	.shutdown = vs_pci_shutdown,
	.driver.pm = &vs_pm_ops,
	.err_handler = &vs_driver_aer_handlers,
};

static int __init vs_drm_init(void)
{
	int ret = pci_register_driver(&vs_drm_pci_driver);

	return ret;
}

static void __exit vs_drm_exit(void)
{
	pci_unregister_driver(&vs_drm_pci_driver);
}

#else
/* platform driver */
static int vs_drm_bind(struct device *dev)
{
	struct drm_device *drm_dev;
	struct vs_drm_private *priv;
	int ret;

	drm_dev = drm_dev_alloc(&vs_drm_driver, dev);
	if (IS_ERR(drm_dev))
		return PTR_ERR(drm_dev);

	dev_set_drvdata(dev, drm_dev);

	priv = devm_kzalloc(drm_dev->dev, sizeof(struct vs_drm_private), GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto err_put_dev;
	}

	priv->intr_dest = ((intr_dest_ns << 0) | (intr_dest_tz << 1) | (intr_dest_gsa << 2) |
			   (intr_dest_aoc << 3));
	priv->pitch_alignment = 64;
	priv->addr_alignment = 128;
	priv->dma_dev = drm_dev->dev;

	drm_dev->dev_private = priv;

	drm_mode_config_init(drm_dev);

	/* Now try and bind all our sub-components */
	ret = component_bind_all(dev, drm_dev);
	if (ret)
		goto err_mode;

	vs_egt_mode_config_init(drm_dev);

	ret = drm_vblank_init(drm_dev, drm_dev->mode_config.num_crtc);
	if (ret)
		goto err_bind;

	drm_mode_config_reset(drm_dev);

#if IS_ENABLED(CONFIG_DRM_LEGACY)
	drm_dev->irq_enabled = drm_dev->num_crtcs != 0;
#endif

	drm_kms_helper_poll_init(drm_dev);

	ret = drm_dev_register(drm_dev, 0);
	if (ret)
		goto err_helper;

	return 0;

err_helper:
	drm_kms_helper_poll_fini(drm_dev);
err_bind:
	component_unbind_all(drm_dev->dev, drm_dev);
err_mode:
	drm_mode_config_cleanup(drm_dev);
	if (priv->domain)
		iommu_domain_free(priv->domain);
err_put_dev:
	drm_dev->dev_private = NULL;
	dev_set_drvdata(dev, NULL);
	drm_dev_put(drm_dev);
	return ret;
}

static void vs_drm_unbind(struct device *dev)
{
	struct drm_device *drm_dev = dev_get_drvdata(dev);
	struct vs_drm_private *priv = drm_dev->dev_private;

	drm_dev_unregister(drm_dev);

	drm_kms_helper_poll_fini(drm_dev);

	drm_atomic_helper_shutdown(drm_dev);

	component_unbind_all(drm_dev->dev, drm_dev);

	drm_mode_config_cleanup(drm_dev);

	if (priv->domain) {
		iommu_domain_free(priv->domain);
		priv->domain = NULL;
	}

	drm_dev->dev_private = NULL;
	dev_set_drvdata(dev, NULL);
	drm_dev_put(drm_dev);
}

static const struct component_master_ops vs_drm_ops = {
	.bind = vs_drm_bind,
	.unbind = vs_drm_unbind,
};

static struct platform_driver vs_drm_platform_driver;

static struct platform_driver *drm_sub_drivers[] = {
	/* put display control driver at start */
	&egt_dc_platform_driver,
	&egt_dc_be_platform_driver,
	&egt_dc_fe0_platform_driver,
	&egt_dc_fe1_platform_driver,
	&egt_dc_wb_platform_driver,

/* bridge */
#ifdef CONFIG_ENGIANT_VS_DW_MIPI_DSI
	&egt_dw_mipi_dsi_driver,
#endif
	/* encoder */
	&egt_simple_encoder_driver,

#ifdef CONFIG_ENGIANT_VS_VIRTUAL_DISPLAY
	&egt_virtual_display_platform_driver,
#endif

#ifdef CONFIG_ENGIANT_VS_QSPI
	&vs_egt_qspi_platform_driver,
#endif
};

#define NUM_DRM_DRIVERS ARRAY_SIZE(drm_sub_drivers)

static int compare_dev(struct device *dev, void *data)
{
	return dev == (struct device *)data;
}

static struct component_match *vs_drm_match_add(struct device *dev)
{
	struct component_match *match = NULL;
	int i;

	for (i = 0; i < NUM_DRM_DRIVERS; ++i) {
		struct platform_driver *drv = drm_sub_drivers[i];
		struct device *p = NULL, *d;

		while ((d = platform_find_device_by_driver(p, &drv->driver))) {
			put_device(p);

			component_match_add(dev, &match, compare_dev, d);
			p = d;
		}
		put_device(p);
	}

	return match ?: ERR_PTR(-ENODEV);
}

static int vs_drm_platform_of_probe(struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct device_node *port;
	bool found = false;
	int i;

	if (!np)
		return -ENODEV;

	for (i = 0;; i++) {
		struct device_node *iommu;

		port = of_parse_phandle(np, "ports", i);
		if (!port)
			break;

		if (!of_device_is_available(port->parent)) {
			of_node_put(port);
			continue;
		}

		iommu = of_parse_phandle(port->parent, "iommus", 0);

		/*
		 * if there is a crtc not support iommu, force set all
		 * crtc use non-iommu buffer.
		 */
		if (!iommu || !of_device_is_available(iommu->parent))
			has_iommu = false;

		found = true;

		of_node_put(iommu);
		of_node_put(port);
	}

	if (i == 0) {
		DRM_DEV_ERROR(dev, "missing 'ports' property\n");
		return -ENODEV;
	}

	if (!found) {
		DRM_DEV_ERROR(dev, "No available DC found.\n");
		return -ENODEV;
	}

	return 0;
}

static int vs_drm_platform_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct component_match *match;
	int ret;

	if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
		dev_warn(&pdev->dev, "No suitable DMA available\n");
		return -ENOMEM;
	}

	ret = vs_drm_platform_of_probe(dev);
	if (ret)
		return ret;

	match = vs_drm_match_add(dev);
	if (IS_ERR(match))
		return PTR_ERR(match);

	return component_master_add_with_match(dev, &vs_drm_ops, match);
}

static int vs_drm_platform_remove(struct platform_device *pdev)
{
	component_master_del(&pdev->dev, &vs_drm_ops);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int vs_drm_suspend(struct device *dev)
{
	int ret;
	struct drm_device *drm = dev_get_drvdata(dev);
	struct vs_drm_private *priv = drm->dev_private;
	struct device *dc_dev = priv->dc_dev;

	ret = drm_mode_config_helper_suspend(drm);
	if (ret < 0) {
		DRM_ERROR("failed to config helper suspend.\n");
		goto err_ret;
	}

	ret = vs_egt_dc_suspend(dc_dev);
	if (ret < 0) {
		DRM_ERROR("failed to vs dc suspend.\n");
		goto err_ret;
	}

err_ret:
	return ret;
}

static int vs_drm_resume(struct device *dev)
{
	int ret;
	struct drm_device *drm = dev_get_drvdata(dev);
	struct vs_drm_private *priv = drm->dev_private;
	struct device *dc_dev = priv->dc_dev;

	ret = vs_egt_dc_resume(dc_dev);
	if (ret < 0) {
		DRM_ERROR("failed to vs dc resume.\n");
		goto err_ret;
	}

	ret = drm_mode_config_helper_resume(drm);
	if (ret < 0) {
		DRM_ERROR("failed to config helper resume.\n");
		goto err_ret;
	}

err_ret:
	return ret;
}

#endif

static SIMPLE_DEV_PM_OPS(vs_drm_pm_ops, vs_drm_suspend, vs_drm_resume);

static struct platform_driver vs_drm_platform_driver = {
	.probe = vs_drm_platform_probe,
	.remove = vs_drm_platform_remove,

	.driver = {
		.name = DRV_NAME,
		.pm = &vs_drm_pm_ops,
	},
};

static int __init vs_drm_init(void)
{
	int ret;

	ret = platform_register_drivers(drm_sub_drivers, NUM_DRM_DRIVERS);
	if (ret)
		return ret;

	ret = platform_driver_register(&vs_drm_platform_driver);
	if (ret)
		platform_unregister_drivers(drm_sub_drivers, NUM_DRM_DRIVERS);
	return ret;
}

static void __exit vs_drm_exit(void)
{
	platform_driver_unregister(&vs_drm_platform_driver);
	platform_unregister_drivers(drm_sub_drivers, NUM_DRM_DRIVERS);
}
#endif

module_init(vs_drm_init);
module_exit(vs_drm_exit);

MODULE_DESCRIPTION("VeriSilicon DRM Driver");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(DMA_BUF);
