/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_DEVLINK_H
#define XSC_DEVLINK_H

#include <net/devlink.h>

struct devlink *xsc_devlink_alloc(struct device *dev);
void xsc_devlink_free(struct devlink *devlink);
void xsc_devlink_register(struct devlink *devlink);
void xsc_devlink_unregister(struct devlink *devlink);

#endif /* XSC_DEVLINK_H */
