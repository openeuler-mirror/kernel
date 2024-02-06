// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/time.h>
#include "common/xsc_core.h"
#include "common/xsc_hsi.h"
#include "common/driver.h"
#include "common/xsc_cmd.h"

int xsc_ib_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	int err = 0;

	return err;
}

void xsc_ib_sysfs_fini(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
}

