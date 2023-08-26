/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#ifndef _UDMA_TP_H
#define _UDMA_TP_H

#include <linux/jhash.h>
#include "hns3_udma_qp.h"

struct udma_tp {
	struct ubcore_tp		ubcore_tp;
	struct udma_qp		qp;
	struct ubcore_jetty_id	tjetty_id;
};
struct ubcore_tp *udma_create_tp(struct ubcore_device *dev,
			    const struct ubcore_tp_cfg *cfg,
			    struct ubcore_udata *udata);
int udma_destroy_tp(struct ubcore_tp *tp);

#endif /* _UDMA_TP_H */
