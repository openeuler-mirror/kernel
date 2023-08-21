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

#ifndef _UDMA_QP_H
#define _UDMA_QP_H

#include "hns3_udma_device.h"

struct udma_qpn_bitmap {
	uint32_t		qpn_prefix;
	uint32_t		jid;
	uint32_t		qpn_shift;
	struct udma_bank	bank[UDMA_QP_BANK_NUM];
	struct mutex		bank_mutex;
	atomic_t		ref_num;
};

struct udma_qp {
	struct udma_dev		*udma_device;
	struct udma_mtr		mtr;
	void (*event)(struct udma_qp *qp,
		      enum udma_event event_type);
	uint64_t		qpn;

	refcount_t		refcount;
	struct completion	free;
};

void init_jetty_x_qpn_bitmap(struct udma_dev *dev,
			     struct udma_qpn_bitmap *qpn_map,
			     uint32_t jetty_x_shift, uint32_t prefix,
			     uint32_t jid);
void clean_jetty_x_qpn_bitmap(struct udma_qpn_bitmap *qpn_map);
void udma_qp_event(struct udma_dev *udma_dev, uint32_t qpn, int event_type);

#endif /* _UDMA_QP_H */
