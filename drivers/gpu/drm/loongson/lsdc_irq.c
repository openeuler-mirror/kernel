// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include <drm/drm_vblank.h>

#include "lsdc_drv.h"
#include "lsdc_regs.h"
#include "lsdc_irq.h"

/* Function to be called in a threaded interrupt context. */
irqreturn_t lsdc_irq_thread_cb(int irq, void *arg)
{
	struct drm_device *ddev = arg;
	struct lsdc_device *ldev = to_lsdc(ddev);
	struct drm_crtc *crtc;

	/* trigger the vblank event */
	if (ldev->irq_status & INT_CRTC0_VS) {
		crtc = drm_crtc_from_index(ddev, 0);
		drm_crtc_handle_vblank(crtc);
	}

	if (ldev->irq_status & INT_CRTC1_VS) {
		crtc = drm_crtc_from_index(ddev, 1);
		drm_crtc_handle_vblank(crtc);
	}

	writel(INT_CRTC0_VS_EN | INT_CRTC1_VS_EN, ldev->reg_base + LSDC_INT_REG);

	return IRQ_HANDLED;
}

/* Function to be called when the IRQ occurs */
irqreturn_t lsdc_irq_handler_cb(int irq, void *arg)
{
	struct drm_device *ddev = arg;
	struct lsdc_device *ldev = to_lsdc(ddev);

	/* Read & Clear the interrupt status */
	ldev->irq_status = readl(ldev->reg_base + LSDC_INT_REG);
	if ((ldev->irq_status & INT_STATUS_MASK) == 0) {
		drm_warn(ddev, "no interrupt occurs\n");
		return IRQ_NONE;
	}

	/* clear all interrupt */
	writel(ldev->irq_status, ldev->reg_base + LSDC_INT_REG);

	return IRQ_WAKE_THREAD;
}
