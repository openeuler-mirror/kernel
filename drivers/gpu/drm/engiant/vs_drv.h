/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DRV_H__
#define __VS_DRV_H__

#include <linux/module.h>
#include <linux/platform_device.h>

#include <drm/drm_gem.h>

#include "vs_plane.h"
#ifdef CONFIG_ENGIANT_VS_MMU
#include "vs_dc_mmu.h"
#endif

#define EGT_VIDMEM_SIZE_8M    0x00800000
#define EGT_VIDMEM_SIZE_16M   0x01000000
#define EGT_VIDMEM_SIZE_32M   0x02000000
#define EGT_VIDMEM_SIZE_64M   0x04000000
#define EGT_VIDMEM_SIZE_128M  0x08000000
#define EGT_VIDMEM_SIZE_256M  0x10000000
#define EGT_VIDMEM_DEFAULT_SIZE EGT_VIDMEM_SIZE_8M

/*
 *
 * @dma_dev: device for DMA API.
 *  - use the first attached device if support iommu
 *    else use drm device (only contiguous buffer support)
 * @domain: iommu domain for DRM.
 *  - all DC IOMMU share same domain to reduce mapping
 * @pitch_alignment: buffer pitch alignment required by sub-devices.
 *
 */
struct vs_gem_private {
	struct mutex    vram_lock;
	struct drm_mm   vram;
	phys_addr_t pci_addr;
	void __iomem *vram_dev_paddr;
};

struct vs_drm_private {
	struct device *dma_dev;
	/* when we have more than one display core, this need to be an array */
	struct device *dc_dev;

	struct iommu_domain *domain;
#ifdef CONFIG_ENGIANT_VS_MMU
	dc_mmu * mmu;
#endif

	unsigned int pitch_alignment;
	unsigned int addr_alignment;
	u8 intr_dest;
#ifdef CONFIG_ENGIANT_VS_PCIE
	u32 irq_num[5];
	void __iomem *pf_bar_base;
	void __iomem *dc_base;
	void __iomem *dp_base;
	void __iomem *dp_phy_base;
	void __iomem *mbox_base;
	void __iomem *pci_base;
#endif
	void __iomem *dp_phy0_base;
	void __iomem *dp_phy1_base;
	void __iomem *crg_base;
	void __iomem *crg_hsio_base;
	struct vs_gem_private *gem_priv;
	void *fbdev;
	struct drm_device *drm_dev;
	struct drm_gem_object *fbdev_bo;
	struct drm_fb_helper fbdev_helper;
#ifdef CONFIG_ENGIANT_VS_DEBUG
	struct file *dc_capture_fp;
#endif
};


int vs_egt_drm_iommu_attach_device(struct drm_device *drm_dev, struct device *dev);

void vs_egt_drm_iommu_detach_device(struct drm_device *drm_dev, struct device *dev);

void vs_egt_drm_update_alignment(struct drm_device *drm_dev, unsigned int pitch_align,
				 unsigned int addr_align);

struct vs_gem_private *vs_egt_gem_priv_init(struct drm_device *drm_dev);

void vs_egt_gem_priv_deinit(struct drm_device *drm_dev);

static inline struct device *to_dma_dev(struct drm_device *dev)
{
	struct vs_drm_private *priv = dev->dev_private;

	return priv->dma_dev;
}

static inline bool is_iommu_enabled(struct drm_device *dev)
{
	struct vs_drm_private *priv = dev->dev_private;

	return priv->domain != NULL ? true : false;
}
#endif /* __VS_DRV_H__ */
