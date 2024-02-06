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
	u64			arm_db;
	u64			ci_db;
	struct xsc_core_device *dev;
	atomic_t		refcount;
	struct completion	free;
	unsigned int		vector;
	int			irqn;
	void (*comp)(struct xsc_core_cq *cq);
	void (*event)(struct xsc_core_cq *cq, enum xsc_event);
	u32			cons_index;
	unsigned int		arm_sn;
	struct xsc_rsc_debug	*dbg;
	int			pid;
	u32		reg_next_cid;
	u32		reg_done_pid;
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

static inline void xsc_cq_arm(struct xsc_core_cq *cq, u8 solicited)
{
	union xsc_cq_doorbell db;

	db.val = 0;
	db.cq_next_cid = cq->cons_index;
	db.cq_id = cq->cqn;
	db.arm = solicited;

	/* Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();
	writel(db.val, REG_ADDR(cq->dev, cq->arm_db));
}

static inline void xsc_cq_set_ci(struct xsc_core_cq *cq)
{
	struct xsc_core_device *xdev = cq->dev;
	union xsc_cq_doorbell db;

	db.cq_next_cid = cq->cons_index;
	db.cq_id = cq->cqn;
	/* ensure write val visable before doorbell */
	wmb();

	writel(db.val, REG_ADDR(xdev, cq->ci_db));
}

int xsc_core_create_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq,
		       struct xsc_create_cq_mbox_in *in, int inlen);
int xsc_core_destroy_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq);
int xsc_core_query_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq,
		      struct xsc_query_cq_mbox_out *out);
int xsc_debug_cq_add(struct xsc_core_device *dev, struct xsc_core_cq *cq);
void xsc_debug_cq_remove(struct xsc_core_device *dev, struct xsc_core_cq *cq);

void xsc_init_cq_table(struct xsc_core_device *dev);
void xsc_cleanup_cq_table(struct xsc_core_device *dev);
#endif /* XSC_CORE_CQ_H */
