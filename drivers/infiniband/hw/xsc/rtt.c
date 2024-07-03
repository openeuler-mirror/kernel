// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/sysfs.h>
#include <linux/types.h>
#include "common/xsc_core.h"
#include "common/xsc_hsi.h"
#include "common/driver.h"
#include "common/xsc_cmd.h"

struct xsc_rtt_interface {
	struct xsc_core_device  *xdev;
	struct kobject		kobj;
};

struct xsc_rtt_attributes {
	struct attribute attr;
	ssize_t (*show)(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			char *buf);
	ssize_t (*store)(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			 const char *buf, size_t count);
};

static ssize_t enable_show(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			   char *buf)
{
	int err;
	struct xsc_inbox_hdr in;
	struct xsc_rtt_en_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.opcode = __cpu_to_be16(XSC_CMD_OP_GET_RTT_EN);
	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_inbox_hdr),
			   (void *)&out, sizeof(struct xsc_rtt_en_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to get rtt en, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return sprintf(buf, "%u\n", out.en);
}

static ssize_t enable_store(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			    const char *buf, size_t count)
{
	int err;
	u16 rtt_enable;
	struct xsc_rtt_en_mbox_in in;
	struct xsc_rtt_en_mbox_out out;

	err = kstrtou16(buf, 0, &rtt_enable);
	if (err != 0)
		return -EINVAL;

	if (rtt_enable > 1) {
		xsc_core_err(g->xdev, "Failed to set rtt en, rtt_enable(%u) out of range[0,1]\n",
			     rtt_enable);
		return -EINVAL;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_SET_RTT_EN);
	in.en = rtt_enable;

	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_rtt_en_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_en_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to set rtt en, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return count;
}

static ssize_t qpn_show(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			char *buf)
{
	int err, i;
	u32 count = 0;
	struct xsc_inbox_hdr in;
	struct xsc_get_rtt_qpn_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.opcode = __cpu_to_be16(XSC_CMD_OP_GET_RTT_QPN);
	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_inbox_hdr),
			   (void *)&out, sizeof(struct xsc_get_rtt_qpn_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to get rtt qpn, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	for (i = 0; i < (XSC_RTT_CFG_QPN_MAX - 1); i++)
		count += sprintf(&buf[count], "%hu,", __be16_to_cpu(out.qpn[i]));

	count += sprintf(&buf[count], "%hu\n", __be16_to_cpu(out.qpn[i]));

	return count;
}

#define RTT_CFG_QPN_FORMAT  "%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu," \
"%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu"

static ssize_t qpn_store(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			 const char *buf, size_t count)
{
	int err, i;
	struct xsc_rtt_qpn_mbox_in in;
	struct xsc_rtt_qpn_mbox_out out;
	u16 *ptr = in.qpn;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	err = sscanf(buf, RTT_CFG_QPN_FORMAT, &ptr[0], &ptr[1], &ptr[2], &ptr[3], &ptr[4],
		     &ptr[5], &ptr[6], &ptr[7], &ptr[8], &ptr[9], &ptr[10], &ptr[11], &ptr[12],
		     &ptr[13], &ptr[14], &ptr[15], &ptr[16], &ptr[17], &ptr[18], &ptr[19],
		     &ptr[20], &ptr[21], &ptr[22], &ptr[23], &ptr[24], &ptr[25], &ptr[26],
		     &ptr[27], &ptr[28], &ptr[29], &ptr[30], &ptr[31]);
	if (err != XSC_RTT_CFG_QPN_MAX)
		return -EINVAL;

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_SET_RTT_QPN);

	for (i = 0 ; i < XSC_RTT_CFG_QPN_MAX; i++)
		in.qpn[i] = __cpu_to_be16(ptr[i]);

	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_rtt_qpn_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_qpn_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to set rtt qpn, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return count;
}

static ssize_t period_show(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			   char *buf)
{
	int err;
	struct xsc_inbox_hdr in;
	struct xsc_rtt_period_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.opcode = __cpu_to_be16(XSC_CMD_OP_GET_RTT_PERIOD);
	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_inbox_hdr),
			   (void *)&out, sizeof(struct xsc_rtt_period_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to get rtt period, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return sprintf(buf, "%u\n", __be32_to_cpu(out.period));
}

#define RTT_CFG_PERIOD_MAX	10000 //ms, 10s
static ssize_t period_store(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			    const char *buf, size_t count)
{
	int err;
	u32 rtt_period;
	struct xsc_rtt_period_mbox_in in;
	struct xsc_rtt_period_mbox_out out;

	err = kstrtouint(buf, 0, &rtt_period);
	if (err != 0)
		return -EINVAL;

	if (rtt_period > RTT_CFG_PERIOD_MAX)
		return -EINVAL;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_SET_RTT_PERIOD);
	in.period =	__cpu_to_be32(rtt_period);

	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_rtt_period_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_period_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to set rtt period, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return count;
}

static ssize_t result_show(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			   char *buf)
{
	int i, err;
	u32 count = 0;
	struct xsc_inbox_hdr in;
	struct xsc_rtt_result_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.opcode = __cpu_to_be16(XSC_CMD_OP_GET_RTT_RESULT);

	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_inbox_hdr),
			   (void *)&out, sizeof(struct xsc_rtt_result_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to get rtt result, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	for (i = 0; i < (XSC_RTT_CFG_QPN_MAX - 1); i++)
		count += sprintf(&buf[count], "%lld,", __be64_to_cpu(out.result[i]));

	count += sprintf(&buf[count], "%lld\n", __be64_to_cpu(out.result[i]));

	return count;
}

static ssize_t result_store(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			    const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

static ssize_t stats_show(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			  char *buf)
{
	int err;
	u32 count = 0;
	struct xsc_inbox_hdr in;
	struct xsc_rtt_stats_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.opcode = __cpu_to_be16(XSC_CMD_OP_GET_RTT_STATS);

	err = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(struct xsc_inbox_hdr),
			   (void *)&out, sizeof(struct xsc_rtt_stats_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(g->xdev, "Failed to get rtt stats, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	count += sprintf(&buf[count], "rtt_succ_snd_req_cnt %llu\n",
		__be64_to_cpu(out.stats.rtt_succ_snd_req_cnt));
	count += sprintf(&buf[count], "rtt_succ_snd_rsp_cnt %llu\n",
		__be64_to_cpu(out.stats.rtt_succ_snd_rsp_cnt));
	count += sprintf(&buf[count], "rtt_fail_snd_req_cnt %llu\n",
		__be64_to_cpu(out.stats.rtt_fail_snd_req_cnt));
	count += sprintf(&buf[count], "rtt_fail_snd_rsp_cnt %llu\n",
		__be64_to_cpu(out.stats.rtt_fail_snd_rsp_cnt));
	count += sprintf(&buf[count], "rtt_rcv_req_cnt      %llu\n",
		__be64_to_cpu(out.stats.rtt_rcv_req_cnt));
	count += sprintf(&buf[count], "rtt_rcv_rsp_cnt      %llu\n",
		__be64_to_cpu(out.stats.rtt_rcv_rsp_cnt));
	count += sprintf(&buf[count], "rtt_rcv_unk_cnt      %llu\n",
		__be64_to_cpu(out.stats.rtt_rcv_unk_cnt));
	count += sprintf(&buf[count], "rtt_grp_invaild_cnt  %llu\n",
		__be64_to_cpu(out.stats.rtt_grp_invaild_cnt));

	return count;
}

static ssize_t stats_store(struct xsc_rtt_interface *g, struct xsc_rtt_attributes *a,
			   const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

#define RTT_ATTR(_name) struct xsc_rtt_attributes xsc_rtt_attr_##_name = \
	__ATTR(rtt_probe_##_name, 0644, _name##_show, _name##_store)

RTT_ATTR(enable);
RTT_ATTR(qpn);
RTT_ATTR(period);
RTT_ATTR(result);
RTT_ATTR(stats);

static ssize_t rtt_attr_show(struct kobject *kobj,
			     struct attribute *attr, char *buf)
{
	struct xsc_rtt_attributes *ga =
		container_of(attr, struct xsc_rtt_attributes, attr);
	struct xsc_rtt_interface *g = container_of(kobj, struct xsc_rtt_interface, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t rtt_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t size)
{
	struct xsc_rtt_attributes *ga =
		container_of(attr, struct xsc_rtt_attributes, attr);
	struct xsc_rtt_interface *g = container_of(kobj, struct xsc_rtt_interface, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

static const struct sysfs_ops rtt_sysfs_ops = {
	.show = rtt_attr_show,
	.store = rtt_attr_store,
};

static struct attribute *rtt_attrs[] = {
	&xsc_rtt_attr_enable.attr,
	&xsc_rtt_attr_qpn.attr,
	&xsc_rtt_attr_period.attr,
	&xsc_rtt_attr_result.attr,
	&xsc_rtt_attr_stats.attr,
	NULL
};
ATTRIBUTE_GROUPS(rtt);

static const struct kobj_type rtt_ktype = {
	.sysfs_ops     = &rtt_sysfs_ops,
	.default_groups = rtt_groups,
};

int xsc_rtt_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	struct xsc_rtt_interface *tmp;
	int err;

	if (!xdev || !xsc_core_is_pf(xdev) || xdev->pf_id != 0)
		return -EACCES;

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	err = kobject_init_and_add(&tmp->kobj, &rtt_ktype,
				   &ib_dev->dev.kobj, "rtt");
	if (err)
		goto rtt_attr_err;

	xdev->rtt_priv = tmp;
	tmp->xdev = xdev;
	return 0;

rtt_attr_err:
	kobject_put(&tmp->kobj);
	kfree(tmp);
	return err;
}

void xsc_rtt_sysfs_fini(struct xsc_core_device *xdev)
{
	int err;
	struct xsc_rtt_en_mbox_in in;
	struct xsc_rtt_en_mbox_out out;
	struct xsc_rtt_period_mbox_in period_in;
	struct xsc_rtt_period_mbox_out period_out;
	struct xsc_rtt_interface *rtt;

	if (!xdev || !xdev->rtt_priv)
		return;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_SET_RTT_EN);
	in.en = 0;

	err = xsc_cmd_exec(xdev, (void *)&in, sizeof(struct xsc_rtt_en_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_en_mbox_out));
	if (err || out.hdr.status)
		xsc_core_err(xdev, "Failed to set rtt disable, err(%u), status(%u)\n",
			     err, out.hdr.status);

	memset(&period_in, 0, sizeof(period_in));
	memset(&period_out, 0, sizeof(period_out));

	period_in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_SET_RTT_PERIOD);
	period_in.period = __cpu_to_be32(RTT_CFG_PERIOD_MAX);

	err = xsc_cmd_exec(xdev, (void *)&period_in, sizeof(struct xsc_rtt_period_mbox_in),
			   (void *)&period_out, sizeof(struct xsc_rtt_period_mbox_out));
	if (err || period_out.hdr.status)
		xsc_core_err(xdev, "Failed to set rtt period default, err(%u), status(%u)\n",
			     err, out.hdr.status);

	rtt = xdev->rtt_priv;
	kobject_put(&rtt->kobj);
	kfree(rtt);
	xdev->rtt_priv = NULL;
}

