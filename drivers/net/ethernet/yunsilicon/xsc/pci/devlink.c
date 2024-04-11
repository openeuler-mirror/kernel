// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "devlink.h"
#ifdef CONFIG_XSC_ESWITCH
#include "eswitch.h"
#endif

static const struct devlink_ops xsc_devlink_ops = {
#ifdef CONFIG_XSC_ESWITCH
	.eswitch_mode_set = xsc_devlink_eswitch_mode_set,
	.eswitch_mode_get = xsc_devlink_eswitch_mode_get,
#endif
};

struct devlink *xsc_devlink_alloc(struct device *dev)
{
	return devlink_alloc(&xsc_devlink_ops, sizeof(struct xsc_core_device), dev);
}

void xsc_devlink_free(struct devlink *devlink)
{
	devlink_free(devlink);
}

void xsc_devlink_register(struct devlink *devlink)
{
	devlink_register(devlink);
}

void xsc_devlink_unregister(struct devlink *devlink)
{
	devlink_unregister(devlink);
}
