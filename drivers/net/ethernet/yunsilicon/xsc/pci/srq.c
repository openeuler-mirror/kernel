// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include "common/driver.h"
#include "common/xsc_cmd.h"
#include "fw/xsc_fw.h"

int xsc_core_create_srq(struct xsc_core_device *dev, struct xsc_core_srq *srq)
{
	unsigned long flags;
	struct xsc_srq_res *xres = &dev->board_info->srq_res;
	int ret = 0;

	spin_lock_irqsave(&xres->lock, flags);
	ret = alloc_srq_entry(dev, &srq->srqn);
	srq->cache_wr = xres->srq_cache_wr;
	spin_unlock_irqrestore(&xres->lock, flags);
	return ret;
}
EXPORT_SYMBOL(xsc_core_create_srq);

int xsc_core_destroy_srq(struct xsc_core_device *dev, struct xsc_core_srq *srq)
{
	unsigned long flags;
	struct xsc_srq_res *xres = &dev->board_info->srq_res;
	int ret = 0;

	spin_lock_irqsave(&xres->lock, flags);
	ret = dealloc_srq_entry(dev, &srq->srqn);
	spin_unlock_irqrestore(&xres->lock, flags);
	return ret;
}
EXPORT_SYMBOL(xsc_core_destroy_srq);

