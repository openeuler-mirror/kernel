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

#include <linux/spinlock.h>
#include "hns3_udma_abi.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_qp.h"
static void init_qpn_bitmap(struct udma_qpn_bitmap *qpn_map, uint32_t qpn_shift)
{
	int i;

	qpn_map->qpn_shift = qpn_shift;
	mutex_init(&qpn_map->bank_mutex);
	/* reserved 0 for UD */
	qpn_map->bank[0].min = 1;
	qpn_map->bank[0].inuse = 1;
	qpn_map->bank[0].next = qpn_map->bank[0].min;
	for (i = 0; i < UDMA_QP_BANK_NUM; i++) {
		ida_init(&qpn_map->bank[i].ida);
		qpn_map->bank[i].max = (1 << qpn_shift) / UDMA_QP_BANK_NUM - 1;
	}
}

void init_jetty_x_qpn_bitmap(struct udma_dev *dev,
			     struct udma_qpn_bitmap *qpn_map,
			     uint32_t jetty_x_shift,
			     uint32_t prefix, uint32_t jid)
{
#define QPN_SHIFT_MIN 3
	int qpn_shift;

	qpn_shift = dev->caps.num_qps_shift - jetty_x_shift -
		    UDMA_JETTY_X_PREFIX_BIT_NUM;
	if (qpn_shift <= QPN_SHIFT_MIN) {
		qpn_map->qpn_shift = 0;
		return;
	}

	qpn_map->qpn_prefix = prefix <<
			      (dev->caps.num_qps_shift -
			      UDMA_JETTY_X_PREFIX_BIT_NUM);
	qpn_map->jid = jid;
	init_qpn_bitmap(qpn_map, qpn_shift);
}

void clean_jetty_x_qpn_bitmap(struct udma_qpn_bitmap *qpn_map)
{
	int i;

	if (!qpn_map->qpn_shift)
		return;
	mutex_lock(&qpn_map->bank_mutex);
	for (i = 0; i < UDMA_QP_BANK_NUM; i++)
		ida_destroy(&qpn_map->bank[i].ida);
	mutex_unlock(&qpn_map->bank_mutex);
}

static inline uint8_t get_qp_bankid(uint64_t qpn)
{
	/* The lower 3 bits of QPN are used to hash to different banks */
	return (uint8_t)(qpn & QP_BANKID_MASK);
}

int udma_init_qp_table(struct udma_dev *dev)
{
	struct udma_qp_table *qp_table = &dev->qp_table;
	uint32_t reserved_from_bot;
	uint32_t i;

	qp_table->idx_table.spare_idx = kcalloc(dev->caps.num_qps,
					sizeof(uint32_t), GFP_KERNEL);
	if (!qp_table->idx_table.spare_idx)
		return -ENOMEM;

	mutex_init(&qp_table->bank_mutex);
	xa_init(&qp_table->xa);

	reserved_from_bot = dev->caps.reserved_qps;

	for (i = 0; i < reserved_from_bot; i++) {
		dev->qp_table.bank[get_qp_bankid(i)].inuse++;
		dev->qp_table.bank[get_qp_bankid(i)].min++;
	}

	for (i = 0; i < UDMA_QP_BANK_NUM; i++) {
		ida_init(&dev->qp_table.bank[i].ida);
		dev->qp_table.bank[i].max = dev->caps.num_qps /
						UDMA_QP_BANK_NUM - 1;
		dev->qp_table.bank[i].next = dev->qp_table.bank[i].min;
	}

	return 0;
}

void udma_cleanup_qp_table(struct udma_dev *dev)
{
	int i;

	for (i = 0; i < UDMA_QP_BANK_NUM; i++)
		ida_destroy(&dev->qp_table.bank[i].ida);
	kfree(dev->qp_table.idx_table.spare_idx);
}

void udma_qp_event(struct udma_dev *udma_dev, uint32_t qpn, int event_type)
{
	struct device *dev = udma_dev->dev;
	struct udma_qp *qp;

	xa_lock(&udma_dev->qp_table.xa);
	qp = (struct udma_qp *)xa_load(&udma_dev->qp_table.xa, qpn);
	if (qp)
		refcount_inc(&qp->refcount);
	xa_unlock(&udma_dev->qp_table.xa);

	if (!qp) {
		dev_warn(dev, "Async event for bogus QP 0x%08x\n", qpn);
		return;
	}

	if (qp->event)
		qp->event(qp, (enum udma_event)event_type);

	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);
}
