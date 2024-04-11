// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include "common/driver.h"
#include "common/cq.h"
#include <rdma/ib_verbs.h>

void xsc_cq_event(struct xsc_core_device *xdev, u32 cqn, int event_type)
{
	struct xsc_cq_table *table = &xdev->dev_res->cq_table;
	struct xsc_core_cq *cq;

	spin_lock(&table->lock);

	cq = radix_tree_lookup(&table->tree, cqn);
	if (cq)
		atomic_inc(&cq->refcount);

	spin_unlock(&table->lock);

	if (!cq) {
		xsc_core_warn(xdev, "Async event for bogus CQ 0x%x\n", cqn);
		return;
	}

	cq->event(cq, event_type);

	if (atomic_dec_and_test(&cq->refcount))
		complete(&cq->free);
}

int xsc_core_create_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq,
		       struct xsc_create_cq_mbox_in *in, int inlen)
{
	int err;
	struct xsc_cq_table *table = &dev->dev_res->cq_table;
	struct xsc_create_cq_mbox_out out;
	struct xsc_destroy_cq_mbox_in din;
	struct xsc_destroy_cq_mbox_out dout;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_CQ);
	memset(&out, 0, sizeof(out));
	err = xsc_cmd_exec(dev, in, inlen, &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);

	cq->cqn = be32_to_cpu(out.cqn);
	cq->cons_index = 0;
	cq->arm_sn = 0;
	cq->arm_db = dev->regs.complete_db;
	cq->ci_db = dev->regs.complete_reg;
	cq->dev = dev;
	atomic_set(&cq->refcount, 1);
	init_completion(&cq->free);

	spin_lock_irq(&table->lock);
	err = radix_tree_insert(&table->tree, cq->cqn, cq);
	spin_unlock_irq(&table->lock);
	if (err)
		goto err_cmd;

	cq->pid = current->pid;
	err = xsc_debug_cq_add(dev, cq);
	if (err)
		xsc_core_dbg(dev, "failed adding CP 0x%x to debug file system\n", cq->cqn);

	return 0;

err_cmd:
	memset(&din, 0, sizeof(din));
	memset(&dout, 0, sizeof(dout));
	din.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_CQ);
	xsc_cmd_exec(dev, &din, sizeof(din), &dout, sizeof(dout));
	return err;
}
EXPORT_SYMBOL(xsc_core_create_cq);

int xsc_core_destroy_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq)
{
	struct xsc_cq_table *table = &dev->dev_res->cq_table;
	struct xsc_destroy_cq_mbox_in in;
	struct xsc_destroy_cq_mbox_out out;
	struct xsc_core_cq *tmp;
	int err;

	spin_lock_irq(&table->lock);
	tmp = radix_tree_delete(&table->tree, cq->cqn);
	spin_unlock_irq(&table->lock);
	if (!tmp) {
		xsc_core_warn(dev, "cq 0x%x not found in tree\n", cq->cqn);
		return -EINVAL;
	}
	if (tmp != cq) {
		xsc_core_warn(dev, "corruption on srqn 0x%x\n", cq->cqn);
		return -EINVAL;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_CQ);
	in.cqn = cpu_to_be32(cq->cqn);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);

	xsc_debug_cq_remove(dev, cq);
	if (atomic_dec_and_test(&cq->refcount))
		complete(&cq->free);
	wait_for_completion(&cq->free);

	return 0;
}
EXPORT_SYMBOL(xsc_core_destroy_cq);

int xsc_core_query_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq,
		      struct xsc_query_cq_mbox_out *out)
{
	struct xsc_query_cq_mbox_in in;
	int err;

	memset(&in, 0, sizeof(in));
	memset(out, 0, sizeof(*out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_CQ);
	in.cqn = cpu_to_be32(cq->cqn);
	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out));
	if (err)
		return err;

	if (out->hdr.status)
		return xsc_cmd_status_to_err(&out->hdr);

	return err;
}
EXPORT_SYMBOL(xsc_core_query_cq);

void xsc_init_cq_table(struct xsc_core_device *dev)
{
	struct xsc_cq_table *table = &dev->dev_res->cq_table;

	spin_lock_init(&table->lock);
	INIT_RADIX_TREE(&table->tree, GFP_ATOMIC);
	xsc_cq_debugfs_init(dev);
}

void xsc_cleanup_cq_table(struct xsc_core_device *dev)
{
	xsc_cq_debugfs_cleanup(dev);
}
