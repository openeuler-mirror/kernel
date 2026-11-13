// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/kernel.h>
#if IS_ENABLED(CONFIG_IOVA_NOTIFY)
#include <linux/iova_notify.h>
#endif

#include "ubase_dtumem.h"
#include "ubase_mem.h"

static int ubase_eq_basic_alloc(struct ubase_dev *udev, struct ubase_eq *eq)
{
#if IS_ENABLED(CONFIG_IOVA_NOTIFY)
	eq->addr.addr = dma_alloc_coherent_with_notify(udev->dev, eq->addr.size,
						       &eq->addr.dma_addr,
						       udev->gfp);
#else
	eq->addr.addr = dma_alloc_coherent(udev->dev, eq->addr.size,
					   &eq->addr.dma_addr, udev->gfp);
#endif
	if (!eq->addr.addr)
		return -ENOMEM;

	return 0;
}

static void ubase_eq_basic_free(struct ubase_dev *udev, struct ubase_eq *eq)
{
#if IS_ENABLED(CONFIG_IOVA_NOTIFY)
	dma_free_coherent_with_notify(udev->dev, eq->addr.size, eq->addr.addr,
				      eq->addr.dma_addr);
#else
	dma_free_coherent(udev->dev, eq->addr.size, eq->addr.addr,
			  eq->addr.dma_addr);
#endif
	eq->addr.addr = NULL;
	eq->addr.dma_addr = 0;
}

static int ubase_eq_dtu_alloc(struct ubase_dev *udev, struct ubase_eq *eq)
{
	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits) &&
	    eq->addr.page)
		return 0;

	eq->addr.addr = ubase_dtu_alloc(udev, &eq->addr.page, eq->addr.size,
					&eq->addr.dma_addr);
	if (eq->addr.addr)
		return 0;

	ubase_warn(udev, "eq dtu alloc unavailable, fallback to basic alloc.\n");

	return ubase_eq_basic_alloc(udev, eq);
}

static void ubase_eq_dtu_free(struct ubase_dev *udev, struct ubase_eq *eq)
{
	if (!eq->addr.page && !eq->addr.addr)
		return;

	/*
	 * The page pointer is used in DTU process. When the page pointer is
	 * not NULL, the addr pointer must be not NULL.
	 */
	if (eq->addr.page) {
		if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
			memset(eq->addr.addr, 0, eq->addr.size);
		} else {
			ubase_dtu_free(udev, eq->addr.page, eq->addr.size,
				       eq->addr.dma_addr);
			eq->addr.addr = NULL;
			eq->addr.page = NULL;
			eq->addr.dma_addr = 0;
		}
		return;
	}

	ubase_eq_basic_free(udev, eq);
}

int ubase_mem_ops_init(struct ubase_dev *udev)
{
	if (ubase_dev_dtu_supported(udev)) {
		udev->mem_ops.eq.alloc = ubase_eq_dtu_alloc;
		udev->mem_ops.eq.free = ubase_eq_dtu_free;
	} else {
		udev->mem_ops.eq.alloc = ubase_eq_basic_alloc;
		udev->mem_ops.eq.free = ubase_eq_basic_free;
	}

	return 0;
}
