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

static int xsc_set_cq_context(struct xsc_core_device *dev, struct xsc_cq_context_ex *ctx_ex,
			      u32 *pa_list_base, u32 *cqn)
{
	struct xsc_set_cq_context_mbox_in in;
	struct xsc_set_cq_context_mbox_out out;
	int ret = 0;

	memset(&in, 0, sizeof(in));
	memcpy(&in.ctx_ex, ctx_ex, sizeof(*ctx_ex));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_CQ_CONTEXT);
	memset(&out, 0, sizeof(out));
	ret = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(dev, "failed to set cq context\n");
		return -1;
	}

	*pa_list_base = be32_to_cpu(out.cq_pa_list_base);
	*cqn = be32_to_cpu(out.cqn);
	return ret;
}

static int xsc_set_cq_buf_pa(struct xsc_core_device *dev, struct xsc_create_cq_ex_mbox_in *req,
			     u32 pa_list_base, u32 cqn)
{
	struct xsc_set_cq_buf_pa_mbox_in *in;
	struct xsc_set_cq_buf_pa_mbox_out out;
	u16 pa_num_total = be16_to_cpu(req->ctx_ex.ctx.pa_num);
	u16 pa_num_for_each_max = (dev->caps.max_cmd_in_len - sizeof(*in)) / sizeof(__be64);
	u16 pa_num_left = pa_num_total;
	u16 pa_num = 0;
	u32 copy_len = 0;
	int ret = 0;
	int in_len = 0;

	while (pa_num_left) {
		pa_num = min(pa_num_for_each_max, pa_num_left);
		copy_len = pa_num * sizeof(__be64);
		in_len = sizeof(*in) + copy_len;
		in = kvzalloc(in_len, GFP_KERNEL);
		if (!in)
			return -ENOMEM;
		in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_CQ_BUF_PA);
		in->pa_list_start = cpu_to_be32(pa_list_base);
		in->pa_num = cpu_to_be32(pa_num);
		memcpy(in->pas, &req->pas[pa_num_total - pa_num_left], copy_len);
		pa_num_left -= pa_num;
		pa_list_base += pa_num;
		memset(&out, 0, sizeof(out));

		ret = xsc_cmd_exec(dev, in, in_len, &out, sizeof(out));
		kvfree(in);

		if (ret || out.hdr.status) {
			xsc_core_err(dev, "failed to set cq buf pa, cqn = %d\n", cqn);
			return -EINVAL;
		}
	}

	return 0;
}

int xsc_create_cq_compat_handler(struct xsc_core_device *dev, struct xsc_create_cq_ex_mbox_in *in,
				 struct xsc_create_cq_mbox_out *out)
{
	struct xsc_create_cq_mbox_in *_in;
	int _inlen = sizeof(*_in) +
		be16_to_cpu(in->ctx_ex.ctx.pa_num) * sizeof(__be64);
	int err = 0;

	_in = kvzalloc(_inlen, GFP_KERNEL);
	if (!_in)
		return -ENOMEM;

	_in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_CQ);
	memcpy(&_in->ctx, &in->ctx_ex.ctx, sizeof(_in->ctx));
	memcpy(&_in->pas, &in->pas, _inlen - sizeof(*_in));
	memset(out, 0, sizeof(*out));
	err = xsc_cmd_exec(dev, _in, _inlen, out, sizeof(*out));
	kvfree(_in);

	if (err)
		return err;
	if (out->hdr.status)
		return xsc_cmd_status_to_err(&out->hdr);
	return 0;
}
EXPORT_SYMBOL_GPL(xsc_create_cq_compat_handler);

int xsc_core_create_cq(struct xsc_core_device *dev, struct xsc_core_cq *cq,
		       struct xsc_create_cq_ex_mbox_in *in, int inlen)
{
	int err;
	struct xsc_cq_table *table = &dev->dev_res->cq_table;
	struct xsc_create_cq_mbox_out out;
	struct xsc_destroy_cq_mbox_in din;
	struct xsc_destroy_cq_mbox_out dout;
	u32 pa_list_base = 0;
	u32 cqn = 0;

	if (inlen < dev->caps.max_cmd_in_len) {
		in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_CQ_EX);
		memset(&out, 0, sizeof(out));
		err = xsc_cmd_exec(dev, in, inlen, &out, sizeof(out));
		if (err)
			return err;

		if (out.hdr.status && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)
			return xsc_cmd_status_to_err(&out.hdr);

		if (out.hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED) {
			err = xsc_create_cq_compat_handler(dev, in, &out);
			if (err)
				return err;
		}

		cqn = be32_to_cpu(out.cqn);
	} else {
		err = xsc_set_cq_context(dev, &in->ctx_ex, &pa_list_base, &cqn);
		if (err)
			return err;

		err = xsc_set_cq_buf_pa(dev, in, pa_list_base, cqn);
		if (err)
			goto err_cmd;
	}

	cq->cqn = cqn;
	cq->cons_index = 0;
	cq->arm_sn = 0;
	cq->dev = dev;
	atomic_set(&cq->refcount, 1);
	init_completion(&cq->free);

	xsc_arm_cq(dev, cq->cqn, 0, 0);

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
	din.cqn = cpu_to_be32(cqn);
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
