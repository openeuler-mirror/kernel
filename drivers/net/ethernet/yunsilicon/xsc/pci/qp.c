// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/gfp.h>
#include <linux/time.h>
#include <linux/export.h>
#include "common/qp.h"
#include "common/driver.h"
#include <linux/kthread.h>
#include "common/xsc_core.h"

#define GROUP_DESTROY_FLAG_SHFIT 15
#define GROUP_DESTROY_FLAG_MASK (1 << (GROUP_DESTROY_FLAG_SHFIT))

#define	GROUP_OTHER_HASH_SIZE	16
#define	GROUP_CC_HASH_SIZE	(1024 - GROUP_OTHER_HASH_SIZE)

enum {
	GROUP_MODE_PER_QP = 0,
	GROUP_MODE_PER_DEST_IP,
};

struct xsc_qp_rsc {
	struct list_head	node;
	struct xsc_core_qp	*qp;
	struct xsc_core_device	*xdev;
};

struct {
	struct list_head	head;
	spinlock_t		lock;	/* protect delayed_release_list */
	struct task_struct	*poll_task;
	struct wait_queue_head	wq;
	int			wait_flag;
} delayed_release_list;

enum {
	SLEEP,
	WAKEUP,
	EXIT,
};

static bool xsc_qp_flush_finished(struct xsc_core_device *xdev, u32 qpn)
{
	struct xsc_query_qp_flush_status_mbox_in in;
	struct xsc_query_qp_flush_status_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_QP_FLUSH_STATUS);
	in.qpn = cpu_to_be32(qpn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status != 0) {
		xsc_core_dbg(xdev, "qp[%d] flush incomplete.\n", qpn);
		return false;
	}

	return true;
}

static int xsc_qp_flush_check(void *arg)
{
	struct xsc_qp_rsc *entry;

	while (!kthread_should_stop()) {
		if (need_resched())
			schedule();

		spin_lock(&delayed_release_list.lock);
		entry = list_first_entry_or_null(&delayed_release_list.head,
						 struct xsc_qp_rsc, node);
		if (!entry) {
			spin_unlock(&delayed_release_list.lock);
			wait_event_interruptible(delayed_release_list.wq,
						 delayed_release_list.wait_flag != SLEEP);
			if (delayed_release_list.wait_flag == EXIT)
				break;
			delayed_release_list.wait_flag = SLEEP;
			continue;
		}
		list_del(&entry->node);
		spin_unlock(&delayed_release_list.lock);

		if (!xsc_qp_flush_finished(entry->xdev, entry->qp->qpn)) {
			spin_lock(&delayed_release_list.lock);
			list_add_tail(&entry->node, &delayed_release_list.head);
			spin_unlock(&delayed_release_list.lock);
		} else {
			complete(&entry->qp->delayed_release);
			kfree(entry);
		}
	}

	return 0;
}

void xsc_init_delayed_release(void)
{
	INIT_LIST_HEAD(&delayed_release_list.head);
	spin_lock_init(&delayed_release_list.lock);
	init_waitqueue_head(&delayed_release_list.wq);
	delayed_release_list.wait_flag = SLEEP;
	delayed_release_list.poll_task = kthread_create(xsc_qp_flush_check, NULL, "qp flush check");
	if (delayed_release_list.poll_task)
		wake_up_process(delayed_release_list.poll_task);
}

void xsc_stop_delayed_release(void)
{
	delayed_release_list.wait_flag = EXIT;
	wake_up(&delayed_release_list.wq);
	if (delayed_release_list.poll_task)
		kthread_stop(delayed_release_list.poll_task);
}

void xsc_add_to_delayed_release_list(struct xsc_core_device *xdev, struct xsc_core_qp *qp)
{
	struct xsc_qp_rsc *qp_rsc;

	qp_rsc = kzalloc(sizeof(*qp_rsc), GFP_KERNEL);
	if (!qp_rsc)
		return;
	qp_rsc->qp = qp;
	qp_rsc->xdev = xdev;
	spin_lock(&delayed_release_list.lock);
	list_add_tail(&qp_rsc->node, &delayed_release_list.head);
	spin_unlock(&delayed_release_list.lock);
	delayed_release_list.wait_flag = WAKEUP;
	wake_up(&delayed_release_list.wq);
}

int create_resource_common(struct xsc_core_device *xdev,
			   struct xsc_core_qp *qp)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;
	int err;

	spin_lock_irq(&table->lock);
	err = radix_tree_insert(&table->tree, qp->qpn, qp);
	spin_unlock_irq(&table->lock);
	if (err)
		return err;

	atomic_set(&qp->refcount, 1);
	init_completion(&qp->free);
	qp->pid = current->pid;

	return 0;
}
EXPORT_SYMBOL_GPL(create_resource_common);

void destroy_resource_common(struct xsc_core_device *xdev,
			     struct xsc_core_qp *qp)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;
	unsigned long flags;

	spin_lock_irqsave(&table->lock, flags);
	radix_tree_delete(&table->tree, qp->qpn);
	spin_unlock_irqrestore(&table->lock, flags);

	if (atomic_dec_and_test(&qp->refcount))
		complete(&qp->free);
	wait_for_completion(&qp->free);
}
EXPORT_SYMBOL_GPL(destroy_resource_common);

void xsc_qp_event(struct xsc_core_device *xdev, u32 qpn, int event_type)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;
	struct xsc_core_qp *qp;

	spin_lock(&table->lock);

	qp = radix_tree_lookup(&table->tree, qpn);
	if (qp)
		atomic_inc(&qp->refcount);

	spin_unlock(&table->lock);

	if (!qp) {
		xsc_core_warn(xdev, "Async event for bogus QP 0x%x\n", qpn);
		return;
	}

	qp->event(qp, event_type);

	if (atomic_dec_and_test(&qp->refcount))
		complete(&qp->free);
}

int xsc_core_create_qp(struct xsc_core_device *xdev,
		       struct xsc_core_qp *qp,
		       struct xsc_create_qp_mbox_in *in,
		       int inlen)
{
	struct xsc_create_qp_mbox_out out;
	struct xsc_destroy_qp_mbox_in din;
	struct xsc_destroy_qp_mbox_out dout;
	int err;
	struct timespec64 ts;
	int exec = 1;

	ktime_get_boottime_ts64(&ts);
	memset(&dout, 0, sizeof(dout));
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_QP);

	if (!is_support_rdma(xdev)) {
		if (in->req.qp_type == XSC_QUEUE_TYPE_RDMA_MAD ||
		    in->req.qp_type == XSC_QUEUE_TYPE_RDMA_RC) {
			exec = 0;
			qp->qpn = 0;
		}
	}

	if (exec) {
		err = xsc_cmd_exec(xdev, in, inlen, &out, sizeof(out));
		if (err) {
			xsc_core_warn(xdev, "ret %d", err);
			return err;
		}

		if (out.hdr.status) {
			pr_warn("current num of QPs 0x%x\n", atomic_read(&xdev->num_qps));
			return xsc_cmd_status_to_err(&out.hdr);
		}
		qp->qpn = be32_to_cpu(out.qpn) & 0xffffff;
		xsc_core_dbg(xdev, "qpn = %x\n", qp->qpn);
	}

	qp->trace_info = kzalloc(sizeof(*qp->trace_info), GFP_KERNEL);
	if (!qp->trace_info) {
		err = -ENOMEM;
		goto err_cmd;
	}
	qp->trace_info->pid = current->pid;
	qp->trace_info->timestamp = (u64)(u32)ts.tv_sec * MSEC_PER_SEC +
			ts.tv_nsec / NSEC_PER_MSEC;

	err = create_resource_common(xdev, qp);
	if (err) {
		xsc_core_warn(xdev, "err %d", err);
		goto err_trace;
	}

	err = xsc_debug_qp_add(xdev, qp);
	if (err)
		xsc_core_dbg(xdev, "failed adding QP 0x%x to debug file system\n",
			     qp->qpn);

	atomic_inc(&xdev->num_qps);
	return 0;
err_trace:
	kfree(qp->trace_info);
err_cmd:
	memset(&din, 0, sizeof(din));
	memset(&dout, 0, sizeof(dout));
	din.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	din.qpn = cpu_to_be32(qp->qpn);
	xsc_cmd_exec(xdev, &din, sizeof(din), &out, sizeof(dout));

	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_create_qp);

int xsc_core_destroy_qp(struct xsc_core_device *xdev,
			struct xsc_core_qp *qp)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int err;
	int exec = 1;

	xsc_debug_qp_remove(xdev, qp);
	xsc_remove_qptrace(xdev, qp);
	kfree(qp->trace_info);

	destroy_resource_common(xdev, qp);

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(qp->qpn);

	if (!is_support_rdma(xdev)) {
		if (qp->qp_type == XSC_QUEUE_TYPE_RDMA_MAD ||
		    qp->qp_type == XSC_QUEUE_TYPE_RDMA_RC) {
			exec = 0;
		}
	}

	if (exec) {
		err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
		if (err)
			return err;

		if (out.hdr.status)
			return xsc_cmd_status_to_err(&out.hdr);
	}
	atomic_dec(&xdev->num_qps);
	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_destroy_qp);

int xsc_core_qp_modify(struct xsc_core_device *xdev, enum xsc_qp_state cur_state,
		       enum xsc_qp_state new_state,
		       struct xsc_modify_qp_mbox_in *in, int sqd_event,
		       struct xsc_core_qp *qp)
{
	static const u16 optab[XSC_QP_NUM_STATE][XSC_QP_NUM_STATE] = {
		[XSC_QP_STATE_RST] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_INIT]	= XSC_CMD_OP_RST2INIT_QP,
		},
		[XSC_QP_STATE_INIT]  = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_INIT]	= XSC_CMD_OP_INIT2INIT_QP,
			[XSC_QP_STATE_RTR]	= XSC_CMD_OP_INIT2RTR_QP,
		},
		[XSC_QP_STATE_RTR]   = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_RTR2RTS_QP,
		},
		[XSC_QP_STATE_RTS]   = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_RTS2RTS_QP,
			[XSC_QP_STATE_SQD]	= XSC_CMD_OP_RTS2SQD_QP,
		},
		[XSC_QP_STATE_SQD] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_SQD2RTS_QP,
			[XSC_QP_STATE_SQD]	= XSC_CMD_OP_SQD2SQD_QP,
		},
		[XSC_QP_STATE_SQER] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_SQERR2RTS_QP,
		},
		[XSC_QP_STATE_ERR] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
		}
	};

	struct xsc_modify_qp_mbox_out out;
	int err = 0;
	u16 op;
	u8 pf_id;

	if (cur_state >= XSC_QP_NUM_STATE || new_state >= XSC_QP_NUM_STATE ||
	    !optab[cur_state][new_state])
		return -EINVAL;

	memset(&out, 0, sizeof(out));
	op = optab[cur_state][new_state];
	in->hdr.opcode = cpu_to_be16(op);
	in->qpn = cpu_to_be32(qp->qpn);
	in->no_need_wait = 1;

	if (new_state == XSC_QP_STATE_RTR) {
		if (qp->qp_type_internal == XSC_QUEUE_TYPE_RDMA_RC &&
		    ((in->ctx.ip_type == 0 && in->ctx.dip[0] == in->ctx.sip[0]) ||
		    (in->ctx.ip_type != 0 &&
		    memcmp(in->ctx.dip, in->ctx.sip, sizeof(in->ctx.sip)) == 0))) {
			in->ctx.qp_out_port = xdev->caps.nif_port_num + g_xsc_pcie_no;
		} else if (in->ctx.lag_sel_en == 0) {
			if (funcid_to_pf_index(&xdev->caps, xdev->glb_func_id, &pf_id))
				in->ctx.qp_out_port = pf_id;
			else
				return -EINVAL;
		} else {
			in->ctx.qp_out_port = in->ctx.lag_sel;
		}

		in->ctx.pcie_no = g_xsc_pcie_no;
		in->ctx.func_id = cpu_to_be16(xdev->glb_func_id);
	}

	err = xsc_cmd_exec(xdev, in, sizeof(*in), &out, sizeof(out));
	if (err)
		return err;

	if ((op == XSC_CMD_OP_2RST_QP || op == XSC_CMD_OP_2ERR_QP) && out.hdr.status) {
		xsc_core_dbg(xdev, "qp %d flush incomplete in fw.\n", qp->qpn);
		init_completion(&qp->delayed_release);
		xsc_add_to_delayed_release_list(xdev, qp);
		out.hdr.status = 0;
		while ((err = wait_for_completion_interruptible(&qp->delayed_release))
			== -ERESTARTSYS)
			xsc_core_dbg(xdev, "qp %d wait for completion is interrupted, err = %d\n",
				     qp->qpn, err);
	}

	if (new_state == XSC_QP_STATE_RTR) {
		qp->trace_info->main_ver = YS_QPTRACE_VER_MAJOR;
		qp->trace_info->sub_ver = YS_QPTRACE_VER_MINOR;
		qp->trace_info->qp_type = qp->qp_type;
		qp->trace_info->s_port = in->ctx.src_udp_port;
		qp->trace_info->d_port = cpu_to_be16(4791);
		qp->trace_info->lqpn = qp->qpn;
		qp->trace_info->rqpn = be32_to_cpu(in->ctx.remote_qpn);
		qp->trace_info->affinity_idx = 0;
		qp->trace_info->af_type = (in->ctx.ip_type == 0 ? AF_INET : AF_INET6);

		if (in->ctx.ip_type == 0) {
			qp->trace_info->s_addr.s_addr4 = in->ctx.sip[0];
			qp->trace_info->d_addr.d_addr4 = in->ctx.dip[0];
		} else {
			memcpy(qp->trace_info->s_addr.s_addr6, in->ctx.sip,
			       sizeof(qp->trace_info->s_addr.s_addr6));
			memcpy(qp->trace_info->d_addr.d_addr6, in->ctx.dip,
			       sizeof(qp->trace_info->d_addr.d_addr6));
		}

		err = xsc_create_qptrace(xdev, qp);
		if (err)
			return err;
	}

	return xsc_cmd_status_to_err(&out.hdr);
}
EXPORT_SYMBOL_GPL(xsc_core_qp_modify);

int xsc_core_qp_query(struct xsc_core_device *xdev, struct xsc_core_qp *qp,
		      struct xsc_query_qp_mbox_out *out, int outlen)
{
	struct xsc_query_qp_mbox_in in;
	int err;

	memset(&in, 0, sizeof(in));
	memset(out, 0, outlen);
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_QP);
	in.qpn = cpu_to_be32(qp->qpn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), out, outlen);
	if (err)
		return err;

	if (out->hdr.status)
		return xsc_cmd_status_to_err(&out->hdr);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_qp_query);

void xsc_init_qp_table(struct xsc_core_device *xdev)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;

	spin_lock_init(&table->lock);
	INIT_RADIX_TREE(&table->tree, GFP_ATOMIC);

	xsc_qp_debugfs_init(xdev);
	xsc_qptrace_debugfs_init(xdev);
}

void xsc_cleanup_qp_table(struct xsc_core_device *xdev)
{
	xsc_qp_debugfs_cleanup(xdev);
	xsc_qptrace_debugfs_cleanup(xdev);
}
