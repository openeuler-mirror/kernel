/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
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

#ifndef _HNS3_UDMA_TP_H
#define _HNS3_UDMA_TP_H

#include <linux/jhash.h>
#include "hns3_udma_qp.h"

enum {
	HNS3_UDMA_SUB_TRANS_MODE_NORMAL_TP,
	HNS3_UDMA_SUB_TRANS_MODE_USER_TP,
};

struct hns3_udma_tp {
	struct ubcore_tp	ubcore_tp;
	struct hns3_udma_qp	qp;
	struct ubcore_jetty_id	tjetty_id;
	uint8_t			sub_trans_mode;
};

static inline struct hns3_udma_tp *to_hns3_udma_tp(struct ubcore_tp *ubcore_tp)
{
	return container_of(ubcore_tp, struct hns3_udma_tp, ubcore_tp);
}

static inline uint32_t hns3_udma_get_jetty_hash(struct ubcore_jetty_id *jetty_id)
{
	return jhash(jetty_id, sizeof(struct ubcore_jetty_id), 0);
}

struct ubcore_tp *hns3_udma_create_tp(struct ubcore_device *dev,
				      struct ubcore_tp_cfg *cfg,
				      struct ubcore_udata *udata);
int hns3_udma_destroy_tp(struct ubcore_tp *tp);
int hns3_udma_modify_tp(struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
			union ubcore_tp_attr_mask mask);
struct hns3_udma_qp *get_qp(struct hns3_udma_dev *udma_device, uint32_t qpn);
struct hns3_udma_tp *hns3_udma_create_user_tp(struct hns3_udma_dev *udma_dev,
					      struct hns3_udma_jetty *jetty,
					      struct ubcore_jetty_cfg *cfg,
					      struct ubcore_udata *udata);
int hns3_udma_modify_user_tp(struct ubcore_device *dev, uint32_t tpn,
			     struct ubcore_tp_cfg *cfg,
			     struct ubcore_tp_attr *attr,
			     union ubcore_tp_attr_mask mask);

#endif /* _HNS3_UDMA_TP_H */
