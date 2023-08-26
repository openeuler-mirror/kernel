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

struct udma_qp_cap {
	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	max_recv_sge;
	uint32_t	max_inline_data;
	uint8_t		retry_cnt;
	uint8_t		rnr_retry;
	uint8_t		min_rnr_timer;
	uint8_t		ack_timeout;
};

struct udma_qpn_bitmap {
	uint32_t		qpn_prefix;
	uint32_t		jid;
	uint32_t		qpn_shift;
	struct udma_bank	bank[UDMA_QP_BANK_NUM];
	struct mutex		bank_mutex;
	atomic_t		ref_num;
};

struct udma_qp_attr {
	bool			is_jetty;
	bool			is_tgt;
	struct ubcore_ucontext	*uctx;
	struct udma_jfc		*send_jfc;
	struct udma_jfc		*recv_jfc;
	struct udma_jfr		*jfr;
	struct udma_qp_cap	cap;
	enum udma_qp_type	qp_type;
	uint32_t		pdn;
	struct udma_qpn_bitmap	*qpn_map;
	void			*reorder_cq_page;
	int			reorder_cq_size;
	dma_addr_t		reorder_cq_addr;
	union ubcore_eid		remote_eid;
	union ubcore_eid		local_eid;
	uint8_t			priority;
};

struct udma_wq {
	uint32_t		wqe_cnt; /* WQE num */
	uint32_t		max_gs;
	int			offset;
	int			wqe_offset;
	int			wqe_shift; /* WQE size */
	uint32_t		head;
};

struct udma_qp_sge {
	uint32_t		sge_cnt; /* SGE num */
	int			offset;
	int			sge_shift; /* SGE size */
	int			wqe_offset;
};

struct udma_qp {
	struct udma_dev		*udma_device;
	enum udma_qp_type	qp_type;
	struct udma_qp_attr	qp_attr;
	struct udma_wq		rq;
	struct udma_jfc		*send_jfc;
	struct udma_jfc		*recv_jfc;
	uint64_t		en_flags;
	struct udma_mtr		mtr;
	enum udma_qp_state	state;
	void (*event)(struct udma_qp *qp,
		      enum udma_event event_type);
	uint64_t		qpn;

	refcount_t		refcount;
	struct completion	free;
	struct udma_qp_sge	sge;
	uint32_t		max_inline_data;
	struct list_head	node; /* all qps are on a list */
	struct list_head	rq_node; /* all recv qps are on a list */
	struct list_head	sq_node; /* all send qps are on a list */
	uint8_t			retry_cnt;
	uint8_t			rnr_retry;
	uint8_t			ack_timeout;
	uint8_t			min_rnr_timer;
	uint8_t			priority;
};

#define gen_qpn(high, mid, low) ((high) | (mid) | (low))

int udma_fill_qp_attr(struct udma_dev *udma_dev, struct udma_qp_attr *qp_attr,
		      const struct ubcore_tp_cfg *cfg, struct ubcore_udata *udata);
int udma_create_qp_common(struct udma_dev *udma_dev, struct udma_qp *qp,
			  struct ubcore_udata *udata);
void udma_destroy_qp_common(struct udma_dev *udma_dev, struct udma_qp *qp);
void init_jetty_x_qpn_bitmap(struct udma_dev *dev,
			     struct udma_qpn_bitmap *qpn_map,
			     uint32_t jetty_x_shift, uint32_t prefix,
			     uint32_t jid);
void clean_jetty_x_qpn_bitmap(struct udma_qpn_bitmap *qpn_map);
void udma_qp_event(struct udma_dev *udma_dev, uint32_t qpn, int event_type);

#endif /* _UDMA_QP_H */
