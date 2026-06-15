/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_DEVLINK_H
#define XSC_DEVLINK_H

#include <net/devlink.h>

enum xsc_devlink_param_id {
	XSC_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	XSC_DEVLINK_PARAM_ID_REP_MODE,
	XSC_DEVLINK_PARAM_ID_FLOW_STEERING_MODE,
};

int xsc_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode,
				 struct netlink_ext_ack *extack);

int xsc_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode);

struct devlink *xsc_devlink_alloc(struct device *dev);
void xsc_devlink_free(struct devlink *devlink);
int xsc_devlink_register(struct devlink *devlink, struct device *dev);
void xsc_devlink_unregister(struct devlink *devlink);

#endif /* XSC_DEVLINK_H */
