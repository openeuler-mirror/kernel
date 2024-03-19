// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <linux/interrupt.h>
#include <linux/module.h>
#include "common/driver.h"
#include "common/cq.h"
#include "fw/xsc_fw.h"
#include "wq.h"
#include "common/xsc_core.h"

enum {
	XSC_EQE_SIZE		= sizeof(struct xsc_eqe),
	XSC_EQE_OWNER_INIT_VAL	= 0x1,
};

enum {
	XSC_NUM_SPARE_EQE	= 0x80,
	XSC_NUM_ASYNC_EQE	= 0x100,
};

struct map_eq_in {
	u64	mask;
	u32	reserved;
	u32	unmap_eqn;
};

struct cre_des_eq {
	u8	reserved[15];
	u8	eqn;
};

static int xsc_cmd_destroy_eq(struct xsc_core_device *dev, u32 eqn)
{
	struct xsc_destroy_eq_mbox_in in;
	struct xsc_destroy_eq_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_EQ);
	in.eqn = cpu_to_be32(eqn);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (!err)
		goto ex;

	if (out.hdr.status)
		err = xsc_cmd_status_to_err(&out.hdr);

ex:
	return err;
}

static struct xsc_eqe *get_eqe(struct xsc_eq *eq, u32 entry)
{
	return xsc_buf_offset(&eq->buf, entry * XSC_EQE_SIZE);
}

static struct xsc_eqe *next_eqe_sw(struct xsc_eq *eq)
{
	struct xsc_eqe *eqe = get_eqe(eq, eq->cons_index & (eq->nent - 1));

	return ((eqe->owner & 1) ^ !!(eq->cons_index & eq->nent)) ? NULL : eqe;
}

static void eq_update_ci(struct xsc_eq *eq, int arm)
{
	union xsc_eq_doorbell db;

	db.val = 0;
	db.arm = !!arm;
	db.eq_next_cid = eq->cons_index;
	db.eq_id = eq->eqn;
#ifdef XSC_DEBUG
	xsc_core_dbg(eq->dev, "ARM EQ %d ci 0x%x arm %d\n", eq->eqn, eq->cons_index, arm);
#endif
	writel(db.val, REG_ADDR(eq->dev, eq->doorbell));
	/* We still want ordering, just not swabbing, so add a barrier */
	mb();
}

void xsc_cq_completion(struct xsc_core_device *dev, u32 cqn)
{
	struct xsc_core_cq *cq;
	struct xsc_cq_table *table = &dev->dev_res->cq_table;

	rcu_read_lock();
	cq = radix_tree_lookup(&table->tree, cqn);
	if (likely(cq))
		atomic_inc(&cq->refcount);
	rcu_read_unlock();

	if (!cq) {
		xsc_core_err(dev, "Completion event for bogus CQ, cqn=%d\n", cqn);
		return;
	}

	++cq->arm_sn;

	if (!cq->comp)
		xsc_core_err(dev, "cq->comp is NULL\n");
	else
		cq->comp(cq);

	if (atomic_dec_and_test(&cq->refcount))
		complete(&cq->free);
}

void xsc_eq_cq_event(struct xsc_core_device *dev, u32 cqn, int event_type)
{
	struct xsc_core_cq *cq;
	struct xsc_cq_table *table = &dev->dev_res->cq_table;

	spin_lock(&table->lock);
	cq = radix_tree_lookup(&table->tree, cqn);
	if (likely(cq))
		atomic_inc(&cq->refcount);
	spin_unlock(&table->lock);

	if (unlikely(!cq)) {
		xsc_core_err(dev, "Async event for bogus CQ, cqn=%d\n", cqn);
		return;
	}

	cq->event(cq, event_type);

	if (atomic_dec_and_test(&cq->refcount))
		complete(&cq->free);
}

static int xsc_eq_int(struct xsc_core_device *dev, struct xsc_eq *eq)
{
	struct xsc_eqe *eqe;
	int eqes_found = 0;
	int set_ci = 0;
	u32 cqn, qpn, queue_id;

	while ((eqe = next_eqe_sw(eq))) {
		/* Make sure we read EQ entry contents after we've
		 * checked the ownership bit.
		 */
		rmb();
#ifdef XSC_DEBUG
		xsc_core_dbg(eq->dev, "eqn=%d, eqe_type=%d, cqn/qpn=%d\n",
			     eq->eqn, eqe->type, eqe->queue_id);
#endif
		switch (eqe->type) {
		case XSC_EVENT_TYPE_COMP:
		case XSC_EVENT_TYPE_INTERNAL_ERROR:
			/* eqe is changing */
			queue_id = eqe->queue_id;
			cqn = queue_id;
			xsc_cq_completion(dev, cqn);
			break;

		case XSC_EVENT_TYPE_CQ_ERROR:
			queue_id = eqe->queue_id;
			cqn = queue_id;
			xsc_eq_cq_event(dev, cqn, eqe->type);
			break;
		case XSC_EVENT_TYPE_WQ_CATAS_ERROR:
		case XSC_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
		case XSC_EVENT_TYPE_WQ_ACCESS_ERROR:
			queue_id = eqe->queue_id;
			qpn = queue_id;
			xsc_qp_event(dev, qpn, eqe->type);
			break;
		default:
			xsc_core_warn(dev, "Unhandle event %d on EQ %d\n", eqe->type, eq->eqn);
			break;
		}

		++eq->cons_index;
		eqes_found = 1;
		++set_ci;

		/* The HCA will think the queue has overflowed if we
		 * don't tell it we've been processing events.  We
		 * create our EQs with XSC_NUM_SPARE_EQE extra
		 * entries, so we must update our consumer index at
		 * least that often.
		 */
		if (unlikely(set_ci >= XSC_NUM_SPARE_EQE)) {
			xsc_core_dbg(dev, "EQ%d eq_num=%d qpn=%d, db_noarm\n",
				     eq->eqn, set_ci, eqe->queue_id);
			eq_update_ci(eq, 0);
			set_ci = 0;
		}
	}

	eq_update_ci(eq, 1);
#ifdef XSC_DEBUG
	xsc_core_dbg(dev, "EQ%d eq_num=%d qpn=%d, db_arm\n",
		     eq->eqn, set_ci, (eqe ? eqe->queue_id : 0));
#endif

	return eqes_found;
}

static irqreturn_t xsc_msix_handler(int irq, void *eq_ptr)
{
	struct xsc_eq *eq = eq_ptr;
	struct xsc_core_device *dev = eq->dev;
#ifdef XSC_DEBUG
	xsc_core_dbg(dev, "EQ %d hint irq: %d\n", eq->eqn, irq);
#endif
	xsc_eq_int(dev, eq);

	/* MSI-X vectors always belong to us */
	return IRQ_HANDLED;
}

static void init_eq_buf(struct xsc_eq *eq)
{
	struct xsc_eqe *eqe;
	int i;

	for (i = 0; i < eq->nent; i++) {
		eqe = get_eqe(eq, i);
		eqe->owner = XSC_EQE_OWNER_INIT_VAL;
	}
}

int xsc_create_map_eq(struct xsc_core_device *dev, struct xsc_eq *eq, u8 vecidx,
		      int nent, const char *name)
{
	struct xsc_dev_resource *dev_res = dev->dev_res;
	u16 msix_vec_offset = dev->msix_vec_base + vecidx;
	struct xsc_create_eq_mbox_in *in;
	struct xsc_create_eq_mbox_out out;
	int err;
	int inlen;
	int hw_npages;

	eq->nent = roundup_pow_of_two(roundup(nent, XSC_NUM_SPARE_EQE));
	err = xsc_buf_alloc(dev, eq->nent * XSC_EQE_SIZE, PAGE_SIZE, &eq->buf);
	if (err)
		return err;

	init_eq_buf(eq);

	hw_npages = DIV_ROUND_UP(eq->nent * XSC_EQE_SIZE, PAGE_SIZE_4K);
	inlen = sizeof(*in) + sizeof(in->pas[0]) * hw_npages;
	in = xsc_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto err_buf;
	}
	memset(&out, 0, sizeof(out));

	xsc_fill_page_array(&eq->buf, in->pas, hw_npages);

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_EQ);
	in->ctx.log_eq_sz = ilog2(eq->nent);
	in->ctx.vecidx = cpu_to_be16(msix_vec_offset);
	in->ctx.pa_num = cpu_to_be16(hw_npages);
	in->ctx.glb_func_id = cpu_to_be16(dev->glb_func_id);
	in->ctx.is_async_eq = (vecidx == XSC_EQ_VEC_ASYNC ? 1 : 0);

	err = xsc_cmd_exec(dev, in, inlen, &out, sizeof(out));
	if (err)
		goto err_in;

	if (out.hdr.status) {
		err = -ENOSPC;
		goto err_in;
	}

	snprintf(dev_res->irq_info[vecidx].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 name, pci_name(dev->pdev));

	eq->eqn = be32_to_cpu(out.eqn);
	eq->irqn = pci_irq_vector(dev->pdev, vecidx);
	eq->dev = dev;
	eq->doorbell = dev->regs.event_db;
	eq->index = vecidx;
	xsc_core_dbg(dev, "msix%d request vector%d eq%d irq%d\n",
		     vecidx, msix_vec_offset, eq->eqn, eq->irqn);

	err = request_irq(eq->irqn, xsc_msix_handler, 0,
			  dev_res->irq_info[vecidx].name, eq);
	if (err)
		goto err_eq;

	/* EQs are created in ARMED state
	 */
	eq_update_ci(eq, 1);
	xsc_vfree(in);
	return 0;

err_eq:
	xsc_cmd_destroy_eq(dev, eq->eqn);

err_in:
	xsc_vfree(in);

err_buf:
	xsc_buf_free(dev, &eq->buf);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_create_map_eq);

int xsc_destroy_unmap_eq(struct xsc_core_device *dev, struct xsc_eq *eq)
{
	int err;

	free_irq(eq->irqn, eq);
	err = xsc_cmd_destroy_eq(dev, eq->eqn);
	if (err)
		xsc_core_warn(dev, "failed to destroy a previously created eq: eqn %d\n",
			      eq->eqn);
	xsc_buf_free(dev, &eq->buf);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_destroy_unmap_eq);

int xsc_eq_init(struct xsc_core_device *dev)
{
	int err;

	spin_lock_init(&dev->dev_res->eq_table.lock);

	err = xsc_eq_debugfs_init(dev);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_eq_init);

void xsc_eq_cleanup(struct xsc_core_device *dev)
{
	xsc_eq_debugfs_cleanup(dev);
}
EXPORT_SYMBOL_GPL(xsc_eq_cleanup);

int xsc_start_eqs(struct xsc_core_device *dev)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	int err;

	err = xsc_create_map_eq(dev, &table->async_eq, XSC_EQ_VEC_ASYNC,
				XSC_NUM_ASYNC_EQE, "xsc_async_eq");
	if (err)
		xsc_core_warn(dev, "failed to create async EQ %d\n", err);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_start_eqs);

void xsc_stop_eqs(struct xsc_core_device *dev)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;

	xsc_destroy_unmap_eq(dev, &table->async_eq);
}

int xsc_core_eq_query(struct xsc_core_device *dev, struct xsc_eq *eq,
		      struct xsc_query_eq_mbox_out *out, int outlen)
{
	struct xsc_query_eq_mbox_in in;
	int err = 0;

	memset(&in, 0, sizeof(in));
	memset(out, 0, outlen);
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_EQ);
	in.eqn = eq->eqn;

	if (out->hdr.status)
		err = xsc_cmd_status_to_err(&out->hdr);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_eq_query);
