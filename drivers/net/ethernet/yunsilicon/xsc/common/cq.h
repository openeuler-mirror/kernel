/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_CORE_CQ_H
#define XSC_CORE_CQ_H

#include <rdma/ib_verbs.h>
#include "common/driver.h"
#include "common/xsc_hsi.h"
#include "common/xsc_core.h"

struct xsc_core_cq {
	u32			cqn;
	int			cqe_sz;
	struct xsc_core_device *dev;
	atomic_t		refcount;
	struct completion	free;
	unsigned int		vector;
	int			irqn;
	u16			dim_us;
	u16			dim_pkts;
	void (*comp)(struct xsc_core_cq *cq);
	void (*event)(struct xsc_core_cq *cq, enum xsc_event);
	u32			cons_index;
	unsigned int		arm_sn;
	struct xsc_rsc_debug	*dbg;
	int			pid;
	u32		reg_next_cid;
	u32		reg_done_pid;
	struct xsc_eq		*eq;
};

enum {
	XSC_CQE_OWNER_MASK	= 1,
};

enum {
	CQE_SIZE_64 = 0,
	CQE_SIZE_128 = 1,
};

enum {
	XSC_CQ_DB_REQ_NOT_SOL		= 1,
	XSC_CQ_DB_REQ_NOT		= 0,
};

int xsc_core_create_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq,
		       struct xsc_create_cq_ex_mbox_in *in, int inlen);
int xsc_create_cq_compat_handler(struct xsc_core_device *dev, struct xsc_create_cq_ex_mbox_in *in,
				 struct xsc_create_cq_mbox_out *out);
int xsc_core_destroy_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq);
int xsc_core_query_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq,
		      struct xsc_query_cq_mbox_out *out);
int xsc_debug_cq_add(struct xsc_core_device *dev, struct xsc_core_cq *cq);
void xsc_debug_cq_remove(struct xsc_core_device *dev, struct xsc_core_cq *cq);

void xsc_init_cq_table(struct xsc_core_device *dev);
void xsc_cleanup_cq_table(struct xsc_core_device *dev);
#endif /* XSC_CORE_CQ_H */
