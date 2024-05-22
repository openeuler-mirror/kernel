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

#ifndef _UDMA_JETTY_H
#define _UDMA_JETTY_H

#include "hns3_udma_qp.h"

struct rc_node {
	struct udma_tp		*tp;
	uint32_t		tpn;
	uint64_t		buf_addr;
	struct udma_mtr		mtr;
	uint32_t		wqe_cnt;
	uint32_t		wqe_shift;
	uint32_t		sge_offset;
	uint32_t		sge_cnt;
	uint32_t		sge_shift;
	struct udma_db		sdb;
	struct ubcore_jetty_id	tjetty_id;
	struct udma_ucontext	*context;
};

struct udma_jetty {
	struct ubcore_jetty		ubcore_jetty;
	bool			shared_jfr;
	struct udma_jfr		*udma_jfr;
	enum ubcore_transport_mode	tp_mode;
	union {
		struct rc_node	rc_node;
		struct xarray	srm_node_table;
		struct udma_qp	qp;
	};
	struct udma_qpn_bitmap	qpn_map;
	uint32_t		jetty_id;
	struct mutex		tp_mutex;
	bool			dca_en;
	struct udma_jfc		*send_jfc;
};

static inline struct udma_jetty *to_udma_jetty(struct ubcore_jetty *ubcore_jetty)
{
	return container_of(ubcore_jetty, struct udma_jetty, ubcore_jetty);
}

void udma_fill_jetty_qp_attr(struct udma_dev *dev, struct udma_qp_attr *qp_attr,
			     struct udma_jetty *jetty,
			     struct ubcore_ucontext *uctx,
			     struct ubcore_jetty_cfg *cfg);
struct ubcore_jetty *udma_create_jetty(struct ubcore_device *dev,
				       struct ubcore_jetty_cfg *cfg,
				       struct ubcore_udata *udata);
int udma_destroy_jetty(struct ubcore_jetty *jetty);
struct ubcore_tjetty *udma_import_jetty(struct ubcore_device *dev,
					struct ubcore_tjetty_cfg *cfg,
					struct ubcore_udata *udata);
int udma_unimport_jetty(struct ubcore_tjetty *tjetty);

#endif /* _UDMA_JETTY_H */
