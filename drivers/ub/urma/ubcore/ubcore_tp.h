/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore tp header
 * Author: Yan Fangfang
 * Create: 2022-09-08
 * Note:
 * History: 2022-09-208: Create file
 */

#ifndef UBCORE_TP_H
#define UBCORE_TP_H

#include <urma/ubcore_types.h>
#include "ubcore_netlink.h"
#include "ubcore_tp_table.h"

struct ubcore_tp_meta {
	struct ubcore_hash_table *ht;
	uint32_t hash;
	struct ubcore_tp_key key;
};

struct ubcore_tp_advice {
	struct ubcore_ta ta;
	struct ubcore_tp_meta meta;
};

static inline bool ubcore_have_tp_ops(const struct ubcore_device *dev)
{
	return (dev != NULL && dev->ops->create_tp != NULL && dev->ops->modify_tp != NULL &&
		dev->ops->destroy_tp != NULL);
}

/* alpha */
int ubcore_advise_tp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
		     struct ubcore_tp_advice *advice, struct ubcore_udata *udata);
int ubcore_unadvise_tp(struct ubcore_device *dev, struct ubcore_tp_advice *advice);

struct ubcore_nlmsg *ubcore_handle_create_tp_req(struct ubcore_nlmsg *req);
struct ubcore_nlmsg *ubcore_handle_destroy_tp_req(struct ubcore_nlmsg *req);
struct ubcore_nlmsg *ubcore_handle_restore_tp_req(struct ubcore_nlmsg *req);

/* Called when clear tp table */
int ubcore_destroy_tp(struct ubcore_tp *tp);

/* restore tp from error state */
void ubcore_restore_tp(struct ubcore_device *dev, struct ubcore_tp *tp);
#endif
