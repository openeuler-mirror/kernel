/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore host info map
 */

#ifndef UBCORE_HOST_INFO_H
#define UBCORE_HOST_INFO_H

#include <linux/errno.h>
#include <linux/types.h>
#include <ub/urma/ubcore_types.h>

int ubcore_insert_host_info(const union ubcore_eid *eid,
			    const struct ubcore_host_info *host_info);

int ubcore_delete_host_info(const union ubcore_eid *eid);

int ubcore_lookup_host_info(const union ubcore_eid *eid,
			    struct ubcore_host_info *host_info);

void ubcore_flush_host_info(void);

#endif
