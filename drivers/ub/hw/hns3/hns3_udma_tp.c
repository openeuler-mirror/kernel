// SPDX-License-Identifier: GPL-2.0
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

#include <linux/acpi.h>
#include <linux/iommu.h>
#include "hns3_udma_jfr.h"
#include "hns3_udma_tp.h"

static void udma_set_tp(struct ubcore_device *dev, const struct ubcore_tp_cfg *cfg,
			struct udma_tp *tp)
{
	tp->ubcore_tp.tpn = tp->qp.qpn;
	tp->ubcore_tp.ub_dev = dev;
	tp->ubcore_tp.flag.bs.target = cfg->flag.bs.target;
	tp->ubcore_tp.flag.bs.oor_en = cfg->flag.bs.oor_en;
	tp->ubcore_tp.flag.bs.sr_en = cfg->flag.bs.sr_en;
	tp->ubcore_tp.flag.bs.spray_en = cfg->flag.bs.spray_en;
	tp->ubcore_tp.local_net_addr = cfg->local_net_addr;
	tp->ubcore_tp.peer_net_addr = cfg->peer_net_addr;
	tp->ubcore_tp.local_eid = cfg->local_eid;
	tp->ubcore_tp.peer_eid = cfg->peer_eid;
	tp->ubcore_tp.trans_mode = cfg->trans_mode;
	tp->ubcore_tp.rx_psn = cfg->rx_psn;
	tp->ubcore_tp.mtu = cfg->mtu;
	tp->ubcore_tp.data_udp_start = cfg->data_udp_start;
	tp->ubcore_tp.ack_udp_start = cfg->ack_udp_start;
	tp->ubcore_tp.udp_range = cfg->udp_range;
	tp->ubcore_tp.retry_num = cfg->retry_num;
	tp->ubcore_tp.ack_timeout = cfg->ack_timeout;
	tp->ubcore_tp.tc = cfg->tc;
	tp->ubcore_tp.state = UBCORE_TP_STATE_RESET;
}

static int udma_store_tp(struct udma_dev *udma_device, struct udma_tp *tp,
			 struct ubcore_tp **fail_ret_tp)
{
	struct udma_qp_attr *qp_attr;
	struct udma_jfr *jfr;
	int ret = 0;

	qp_attr = &tp->qp.qp_attr;
	jfr = qp_attr->jfr;
	if (jfr) {
		ret = xa_err(xa_store(&jfr->tp_table_xa,
					tp->ubcore_tp.tpn, tp,
					GFP_KERNEL));
		if (ret) {
			dev_err(udma_device->dev,
				"failed store jfr tp, ret = %d\n", ret);
			return ret;
		}
	}

	return ret;
}

struct ubcore_tp *udma_create_tp(struct ubcore_device *dev, const struct ubcore_tp_cfg *cfg,
			    struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct ubcore_tp *fail_ret_tp = NULL;
	struct udma_tp *tp;
	int ret;

	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return ERR_PTR(-ENOMEM);

	ret = udma_fill_qp_attr(udma_dev, &tp->qp.qp_attr, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "failed to fill qp attr.\n");
		goto failed_alloc_tp;
	}

	ret = udma_create_qp_common(udma_dev, &tp->qp, udata);
	if (ret) {
		dev_err(udma_dev->dev,
			"Failed to create qp common with ret is %d.\n", ret);
		goto failed_alloc_tp;
	}

	udma_set_tp(dev, cfg, tp);

	ret = udma_store_tp(udma_dev, tp, &fail_ret_tp);
	if (ret || fail_ret_tp)
		goto failed_create_qp;

	return &tp->ubcore_tp;

failed_create_qp:
	udma_destroy_qp_common(udma_dev, &tp->qp);
failed_alloc_tp:
	kfree(tp);

	return fail_ret_tp;
}
