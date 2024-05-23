// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/debugfs.h>
#include <linux/time.h>
#include "common/xsc_core.h"
#include "common/xsc_hsi.h"
#include "common/driver.h"
#include "common/qp.h"
#include "common/cq.h"

enum {
	QP_PID,
	QP_STATE,
	QP_XPORT,
	QP_MTU,
	QP_N_RECV,
	QP_RECV_SZ,
	QP_N_SEND,
	QP_LOG_PG_SZ,
	QP_RQPN,
};

static char *qp_fields[] = {
	[QP_PID]        = "pid",
	[QP_STATE]      = "state",
	[QP_XPORT]      = "transport",
	[QP_MTU]        = "mtu",
	[QP_N_RECV]     = "num_recv",
	[QP_RECV_SZ]    = "rcv_wqe_sz",
	[QP_N_SEND]     = "num_send",
	[QP_LOG_PG_SZ]  = "log2_page_sz",
	[QP_RQPN]       = "remote_qpn",
};

enum {
	EQ_NUM_EQES,
	EQ_INTR,
	EQ_LOG_PG_SZ,
};

static char *eq_fields[] = {
	[EQ_NUM_EQES]   = "num_eqes",
	[EQ_INTR]       = "intr",
	[EQ_LOG_PG_SZ]  = "log_page_size",
};

enum {
	CQ_PID,
	CQ_NUM_CQES,
	CQ_LOG_PG_SZ,
};

static char *cq_fields[] = {
	[CQ_PID]        = "pid",
	[CQ_NUM_CQES]   = "num_cqes",
	[CQ_LOG_PG_SZ]  = "log_page_size",
};

struct dentry *xsc_debugfs_root;
EXPORT_SYMBOL(xsc_debugfs_root);

static ssize_t xsc_debugfs_reg_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	char *buf;
	int len;
	char xsc_debugfs_reg_buf[256] = "";

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: %s\n",
			"xsc debugfs",
			xsc_debugfs_reg_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);

	return len;
}

static ssize_t xsc_debugfs_reg_write(struct file *filp,
				     const char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct xsc_core_device *xdev = filp->private_data;
	u64 reg;
	int cnt, len;
	int num;
	int offset;
	char xsc_debugfs_reg_buf[256] = "";

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	if (count >= sizeof(xsc_debugfs_reg_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(xsc_debugfs_reg_buf,
				     sizeof(xsc_debugfs_reg_buf) - 1,
				     ppos, buffer, count);
	if (len < 0)
		return len;

	xsc_debugfs_reg_buf[len] = '\0';

	if (strncmp(xsc_debugfs_reg_buf, "write", 5) == 0) {
		cnt = sscanf(&xsc_debugfs_reg_buf[5], "%llx %n",
			     &reg, &offset);
		if (cnt == 1) {
			int tmp;
			int value;
			int buf[8];
			int *ptr;

			offset += 5;
			num = 0;
			while (1) {
				cnt = sscanf(&xsc_debugfs_reg_buf[offset], "%x %n", &value, &tmp);
				if (cnt < 2)
					break;
				xsc_core_info(xdev, "write: 0x%llx = 0x%x\n",
					      (reg + sizeof(int) * num), value);
				offset += tmp;
				buf[num++] = value;
				if (num == 8)
					break;
			}
			if (num > 1) {
				ptr = &buf[0];
				IA_WRITE(xdev, reg, ptr, num);
			} else if (num == 1) {
				REG_WR32(xdev, reg, buf[0]);
			}
		} else {
			xsc_core_err(xdev, "write <reg> <value>\n");
		}
	} else if (strncmp(xsc_debugfs_reg_buf, "read", 4) == 0) {
		cnt = sscanf(&xsc_debugfs_reg_buf[4], "%llx %d %n", &reg, &num, &offset);
		if (cnt == 2) {
			int *buf;
			int i;
			int *ptr;

			buf = kcalloc(num, sizeof(int), GFP_KERNEL);
			if (!buf)
				return -ENOMEM;
			ptr = buf;
			IA_READ(xdev, reg, ptr, num);
			xsc_core_info(xdev, "read: 0x%llx num:%d\n", reg, num);
			for (i = 0; i < num; i++)
				xsc_core_info(xdev, "read:0x%llx = %#x\n",
					      (reg + sizeof(int) * i), buf[i]);
		} else if (cnt == 1) {
			int value = REG_RD32(xdev, reg);

			xsc_core_info(xdev, "read: 0x%llx = %#x\n", reg, value);
		} else {
			xsc_core_err(xdev, "read <reg>\n");
		}
	} else {
		xsc_core_err(xdev, "Unknown command %s\n", xsc_debugfs_reg_buf);
		xsc_core_err(xdev, "Available commands:\n");
		xsc_core_err(xdev, "read <reg>\n");
		xsc_core_err(xdev, "write <reg> <value>\n");
	}
	return count;
}

static const struct file_operations xsc_debugfs_reg_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read =  xsc_debugfs_reg_read,
	.write = xsc_debugfs_reg_write,
};

int xsc_debugfs_init(struct xsc_core_device *dev)
{
	const char *name = pci_name(dev->pdev);
	struct dentry *pfile;

	if (!xsc_debugfs_root)
		return -ENOMEM;

	dev->dev_res->dbg_root = debugfs_create_dir(name, xsc_debugfs_root);
	if (dev->dev_res->dbg_root) {
		pfile = debugfs_create_file("reg_ops", 0600,
					    dev->dev_res->dbg_root, dev,
					    &xsc_debugfs_reg_fops);
		if (!pfile)
			xsc_core_err(dev, "failed to create debugfs ops for %s\n", name);
	} else {
		xsc_core_err(dev, "failed to create debugfs dir for %s\n", name);
		return -ENOMEM;
	}

	return 0;
}

void xsc_debugfs_fini(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove_recursive(dev->dev_res->dbg_root);
}

void xsc_register_debugfs(void)
{
	xsc_debugfs_root = debugfs_create_dir("xsc_pci", NULL);
}

void xsc_unregister_debugfs(void)
{
	debugfs_remove(xsc_debugfs_root);
}

int xsc_qp_debugfs_init(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return 0;

	atomic_set(&dev->num_qps, 0);

	dev->dev_res->qp_debugfs = debugfs_create_dir("QPs", dev->dev_res->dbg_root);
	if (!dev->dev_res->qp_debugfs)
		return -ENOMEM;

	return 0;
}

void xsc_qp_debugfs_cleanup(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove_recursive(dev->dev_res->qp_debugfs);
}

int xsc_eq_debugfs_init(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return 0;

	dev->dev_res->eq_debugfs = debugfs_create_dir("EQs", dev->dev_res->dbg_root);
	if (!dev->dev_res->eq_debugfs)
		return -ENOMEM;

	return 0;
}

void xsc_eq_debugfs_cleanup(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove_recursive(dev->dev_res->eq_debugfs);
}

static ssize_t average_read(struct file *filp, char __user *buf, size_t count,
			    loff_t *pos)
{
	struct xsc_cmd_stats *stats;
	u64 field = 0;
	int ret;
	int err;
	char tbuf[22];

	if (*pos)
		return 0;

	stats = filp->private_data;
	spin_lock(&stats->lock);
	if (stats->n)
		field = stats->sum / stats->n;
	spin_unlock(&stats->lock);
	ret = snprintf(tbuf, sizeof(tbuf), "%llu\n", field);
	if (ret > 0) {
		err = copy_to_user(buf, tbuf, ret);
		if (err)
			return err;
	}

	*pos += ret;
	return ret;
}

static ssize_t average_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct xsc_cmd_stats *stats;

	stats = filp->private_data;
	spin_lock(&stats->lock);
	stats->sum = 0;
	stats->n = 0;
	spin_unlock(&stats->lock);

	*pos += count;

	return count;
}

static const struct file_operations stats_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= average_read,
	.write	= average_write,
};

int xsc_cmdif_debugfs_init(struct xsc_core_device *xdev)
{
	struct xsc_cmd_stats *stats;
	struct xsc_cmd *cmd;
	struct dentry **cmdif_debugfs;
	const char *namep;
	int err;
	int i;

	if (!xsc_debugfs_root)
		return 0;

	cmd = &xdev->cmd;
	cmdif_debugfs = &xdev->dev_res->cmdif_debugfs;
	*cmdif_debugfs = debugfs_create_dir("commands", xdev->dev_res->dbg_root);
	if (!*cmdif_debugfs)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(cmd->stats); i++) {
		stats = &cmd->stats[i];
		namep = xsc_command_str(i);
		if (strcmp(namep, "unknown command opcode")) {
			stats->root = debugfs_create_dir(namep, *cmdif_debugfs);
			if (!stats->root) {
				xsc_core_warn(xdev, "failed adding command %d\n", i);
				err = -ENOMEM;
				goto out;
			}

			stats->avg = debugfs_create_file("average", 0400,
							 stats->root, stats,
							 &stats_fops);
			if (!stats->avg) {
				xsc_core_warn(xdev, "failed creating debugfs file\n");
				err = -ENOMEM;
				goto out;
			}

			debugfs_create_u64("n", 0400, stats->root, &stats->n);
		}
	}

	return 0;
out:
	debugfs_remove_recursive(xdev->dev_res->cmdif_debugfs);
	return err;
}

void xsc_cmdif_debugfs_cleanup(struct xsc_core_device *xdev)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove_recursive(xdev->dev_res->cmdif_debugfs);
}

int xsc_cq_debugfs_init(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return 0;

	dev->dev_res->cq_debugfs = debugfs_create_dir("CQs", dev->dev_res->dbg_root);
	if (!dev->dev_res->cq_debugfs)
		return -ENOMEM;

	return 0;
}

void xsc_cq_debugfs_cleanup(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove_recursive(dev->dev_res->cq_debugfs);
}

int xsc_qptrace_debugfs_init(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return 0;

	dev->dev_res->qptrace_debugfs =
		debugfs_create_dir("QPTrace", dev->dev_res->dbg_root);
	if (!dev->dev_res->qptrace_debugfs)
		return -ENOMEM;

	return 0;
}

void xsc_qptrace_debugfs_cleanup(struct xsc_core_device *dev)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove_recursive(dev->dev_res->qptrace_debugfs);
}

static u64 qp_read_field(struct xsc_core_device *dev, struct xsc_core_qp *qp,
			 int index)
{
	struct xsc_query_qp_mbox_out *out;
	struct xsc_qp_context *ctx;
	u64 param = 0;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return param;

	err = xsc_core_qp_query(dev, qp, out, sizeof(*out));
	if (err) {
		xsc_core_warn(dev, "failed to query qp\n");
		goto out;
	}

	ctx = &out->ctx;
	switch (index) {
	case QP_PID:
		param = qp->pid;
		break;
	case QP_MTU:
		param = ctx->mtu_mode ? IB_MTU_1024 : IB_MTU_4096;
		break;
	case QP_RQPN:
		param = cpu_to_be32(ctx->remote_qpn) & 0xffffff;
		break;
	}

out:
	kfree(out);
	return param;
}

static u64 eq_read_field(struct xsc_core_device *dev, struct xsc_eq *eq,
			 int index)
{
	struct xsc_query_eq_mbox_out *out;
	struct xsc_eq_context *ctx;
	u64 param = 0;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return param;

	ctx = &out->ctx;

	err = xsc_core_eq_query(dev, eq, out, sizeof(*out));
	if (err) {
		xsc_core_warn(dev, "failed to query eq\n");
		goto out;
	}

	switch (index) {
	case EQ_NUM_EQES:
		break;
	case EQ_INTR:
		break;
	case EQ_LOG_PG_SZ:
		break;
	}

out:
	kfree(out);
	return param;
}

static u64 cq_read_field(struct xsc_core_device *dev, struct xsc_core_cq *cq,
			 int index)
{
	struct xsc_query_cq_mbox_out *out;
	struct xsc_cq_context *ctx;
	u64 param = 0;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return param;

	ctx = &out->ctx;

	err = xsc_core_query_cq(dev, cq, out);
	if (err) {
		xsc_core_warn(dev, "failed to query cq\n");
		goto out;
	}

	switch (index) {
	case CQ_PID:
		break;
	case CQ_NUM_CQES:
		break;
	case CQ_LOG_PG_SZ:
		break;
	}

out:
	kfree(out);
	return param;
}

static ssize_t dbg_read(struct file *filp, char __user *buf, size_t count,
			loff_t *pos)
{
	struct xsc_field_desc *desc;
	struct xsc_rsc_debug *d;
	char tbuf[18];
	u64 field;
	int ret;
	int err;

	if (*pos)
		return 0;

	desc = filp->private_data;
	d = (void *)(desc - desc->i) - sizeof(*d);
	switch (d->type) {
	case XSC_DBG_RSC_QP:
		field = qp_read_field(d->xdev, d->object, desc->i);
		break;

	case XSC_DBG_RSC_EQ:
		field = eq_read_field(d->xdev, d->object, desc->i);
		break;

	case XSC_DBG_RSC_CQ:
		field = cq_read_field(d->xdev, d->object, desc->i);
		break;

	default:
		xsc_core_warn(d->xdev, "invalid resource type %d\n", d->type);
		return -EINVAL;
	}

	ret = snprintf(tbuf, sizeof(tbuf), "0x%llx\n", field);
	if (ret > 0) {
		err = copy_to_user(buf, tbuf, ret);
		if (err)
			return err;
	}

	*pos += ret;
	return ret;
}

static const struct file_operations fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= dbg_read,
};

static int add_res_tree(struct xsc_core_device *dev, enum dbg_rsc_type type,
			struct dentry *root, struct xsc_rsc_debug **dbg,
			int rsn, char **field, int nfile, void *data)
{
	struct xsc_rsc_debug *d;
	char resn[32];
	int err;
	int i;

	d = kzalloc(sizeof(*d) + nfile * sizeof(d->fields[0]), GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	d->xdev = dev;
	d->object = data;
	d->type = type;
	sprintf(resn, "0x%x", rsn);
	d->root = debugfs_create_dir(resn,  root);
	if (!d->root) {
		err = -ENOMEM;
		goto out_free;
	}

	for (i = 0; i < nfile; i++) {
		d->fields[i].i = i;
		d->fields[i].dent = debugfs_create_file(field[i], 0400,
							d->root, &d->fields[i],
							&fops);
		if (!d->fields[i].dent) {
			err = -ENOMEM;
			goto out_rem;
		}
	}
	*dbg = d;

	return 0;
out_rem:
	debugfs_remove_recursive(d->root);

out_free:
	kfree(d);
	return err;
}

static void rem_res_tree(struct xsc_rsc_debug *d)
{
	debugfs_remove_recursive(d->root);
	kfree(d);
}

int xsc_debug_qp_add(struct xsc_core_device *dev, struct xsc_core_qp *qp)
{
	int err;

	if (!xsc_debugfs_root)
		return 0;

	err = add_res_tree(dev, XSC_DBG_RSC_QP, dev->dev_res->qp_debugfs,
			   &qp->dbg, qp->qpn, qp_fields,
			   ARRAY_SIZE(qp_fields), qp);
	if (err)
		qp->dbg = NULL;

	return err;
}

void xsc_debug_qp_remove(struct xsc_core_device *dev, struct xsc_core_qp *qp)
{
	if (!xsc_debugfs_root)
		return;

	if (qp->dbg)
		rem_res_tree(qp->dbg);
}

static int set_udp_sport(u32 qpn, u32 sport, struct xsc_core_device *xdev, struct xsc_qp_trace *t)
{
	int err;
	struct xsc_ap_feat_mbox_in in;
	struct xsc_ap_feat_mbox_out out;
	struct timespec64 ts;
	struct xsc_qpt_update_msg msg;

	ktime_get_boottime_ts64(&ts);

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_AP_FEAT);
	in.xsc_ap_feature_opcode = __cpu_to_be16(XSC_AP_FEAT_SET_UDP_SPORT);
	in.ap.set_udp_sport.qpn = __cpu_to_be32(qpn);
	in.ap.set_udp_sport.udp_sport = __cpu_to_be32(sport);

	err = xsc_cmd_exec(xdev, (void *)&in, sizeof(in), (void *)&out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "Failed to set udp_sport, err(%u), status(%u)\n", err,
			     out.hdr.status);
		return -EINVAL;
	}

	msg.main_ver = YS_QPTRACE_VER_MAJOR;
	msg.sub_ver = YS_QPTRACE_VER_MINOR;
	msg.type = YS_QPTRACE_UPDATE_TYPE_SPORT;
	msg.data.timestamp = (u64)(u32)ts.tv_sec * MSEC_PER_SEC +
		ts.tv_nsec / NSEC_PER_MSEC;
	msg.data.qpn = qpn;
	msg.data.bus = xdev->pdev->bus->number;
	msg.data.dev = PCI_SLOT(xdev->pdev->devfn);
	msg.data.fun = PCI_FUNC(xdev->pdev->devfn);
	msg.data.update.sport.port_old = t->s_port;
	msg.data.update.sport.port_new = __cpu_to_be16(sport);
	t->s_port = msg.data.update.sport.port_new;

	qpts_write_one_msg(&msg);

	xsc_core_info(xdev, "Set qpn(%u) udp_sport(%u)\n", qpn, sport);

	return 0;
}

static ssize_t trace_read(struct file *filp, char __user *buf, size_t count, loff_t *pos)
{
	struct xsc_core_qp *qp = filp->private_data;
	struct xsc_qp_trace *trace_info;
	int err;
	int len;

	if (*pos)
		return 0;

	if (!qp || !qp->trace_info)
		return -EIO;

	trace_info = qp->trace_info;

	len = sizeof(struct xsc_qp_trace);
	err = copy_to_user(buf, trace_info, len);
	if (err)
		return err;

	*pos += len;
	return len;
}

static ssize_t trace_write(struct file *filp, const char __user *buf, size_t count, loff_t *pos)
{
	struct xsc_core_qp *qp = filp->private_data;
	struct xsc_qp_trace *trace_info;
	struct xsc_core_device *xdev;
	int ret = 0, len;
	u32 sport;
	char tmp_buf[256] = "";

	ret = -EIO;
	if (!qp || !qp->dbg || !qp->dbg->xdev || !qp->trace_info) {
		pr_err("%s error null pointer!\n", __func__);
		goto trace_write_out;
	}

	trace_info = qp->trace_info;
	xdev = qp->dbg->xdev;

	ret = 0;
	/* don't allow partial writes */
	if (*pos != 0) {
		xsc_core_err(xdev, "Don't allow partial writes!\n");
		goto trace_write_out;
	}

	ret = -ENOSPC;
	if (count >= sizeof(tmp_buf)) {
		xsc_core_err(xdev, "Count out of size of buffer!\n");
		goto trace_write_out;
	}

	len = simple_write_to_buffer(tmp_buf, sizeof(tmp_buf) - 1,
				     pos, buf, count);
	ret = len;
	if (len < 0) {
		xsc_core_err(xdev, "Write to buffer error(%d)!\n", len);
		goto trace_write_out;
	}

	tmp_buf[len] = '\0';
	if (strncmp(tmp_buf, "sport", 5) == 0) {
		ret = kstrtouint(&tmp_buf[6], 0, &sport);
		if (ret != 0) {
			xsc_core_err(xdev, "error arguments: <sport>\n");
			ret = -EINVAL;
			goto trace_write_out;
		}
		ret = set_udp_sport(trace_info->lqpn, sport, xdev, trace_info);
		if (ret) {
			ret = -EIO;
			goto trace_write_out;
		}
	} else {
		xsc_core_err(xdev, "invalid arguments: %s\n", tmp_buf);
		ret = -EOPNOTSUPP;
		goto trace_write_out;
	}

	return count;

trace_write_out:
	return ret;
}

static const struct file_operations fops_trace = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= trace_read,
	.write	= trace_write,
};

int xsc_create_qptrace(struct xsc_core_device *dev, struct xsc_core_qp *qp)
{
	char name[16];

	if (!xsc_debugfs_root)
		return 0;

	snprintf(name, sizeof(name), "%d", qp->qpn);

	qp->trace = debugfs_create_file(name, 0644, dev->dev_res->qptrace_debugfs,
					(void *)qp, &fops_trace);
	if (!qp->trace)
		return -1;

	return 0;
}

void xsc_remove_qptrace(struct xsc_core_device *dev, struct xsc_core_qp *qp)
{
	if (!xsc_debugfs_root)
		return;

	debugfs_remove(qp->trace);
}

int xsc_debug_eq_add(struct xsc_core_device *dev, struct xsc_eq *eq)
{
	int err;

	if (!xsc_debugfs_root)
		return 0;

	err = add_res_tree(dev, XSC_DBG_RSC_EQ, dev->dev_res->eq_debugfs,
			   &eq->dbg, eq->eqn, eq_fields,
			   ARRAY_SIZE(eq_fields), eq);
	if (err)
		eq->dbg = NULL;

	return err;
}

void xsc_debug_eq_remove(struct xsc_core_device *dev, struct xsc_eq *eq)
{
	if (!xsc_debugfs_root)
		return;

	if (eq->dbg)
		rem_res_tree(eq->dbg);
}

int xsc_debug_cq_add(struct xsc_core_device *dev, struct xsc_core_cq *cq)
{
	int err;

	if (!xsc_debugfs_root)
		return 0;

	err = add_res_tree(dev, XSC_DBG_RSC_CQ, dev->dev_res->cq_debugfs,
			   &cq->dbg, cq->cqn, cq_fields,
			   ARRAY_SIZE(cq_fields), cq);
	if (err)
		cq->dbg = NULL;

	return err;
}

void xsc_debug_cq_remove(struct xsc_core_device *dev, struct xsc_core_cq *cq)
{
	if (!xsc_debugfs_root)
		return;

	if (cq->dbg)
		rem_res_tree(cq->dbg);
}
