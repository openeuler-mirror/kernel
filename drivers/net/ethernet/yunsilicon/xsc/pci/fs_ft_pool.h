/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __FS_FT_POOL_H__
#define __FS_FT_POOL_H__

#include "common/xsc_core.h"
#include "common/fs_core.h"

#define POOL_NEXT_SIZE 0

int xsc_ft_pool_init(struct xsc_core_device *dev);
void xsc_ft_pool_destroy(struct xsc_core_device *dev);

int xsc_ft_pool_get_avail_sz(struct xsc_core_device *dev,
			     enum fs_flow_table_type table_type,
			     int desired_size);
void xsc_ft_pool_put_sz(struct xsc_core_device *dev, int sz);

#endif /* __XSC_FS_FT_POOL_H__ */
