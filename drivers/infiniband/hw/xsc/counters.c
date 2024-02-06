// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/fs.h>
#include "common/xsc_core.h"
#include "common/xsc_hsi.h"
#include "common/driver.h"
#include "common/xsc_lag.h"
#include "common/xsc_cmd.h"
#include "counters.h"

#define COUNTERS_FILE_NAME         "counters"
#define COUNTERS_NAMES_FILE_NAME   "counters_names"
#define COUNTERS_VALUE_FILE_NAME   "counters_value"
#define COUNTERS_ATTER_GROUP_NAME  "counters"

static const struct counter_desc hw_stats_desc[] = {
	/*by mac port*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  np_cnp_sent) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rp_cnp_handled) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  np_ecn_marked_roce_packets) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rp_cnp_ignored) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  tx_pause) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_pause) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_fcs_errors) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_discards) },
	/*by function*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  out_of_sequence) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  packet_seq_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  out_of_buffer) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rnr_nak_retry_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  local_ack_timeout_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_read_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_write_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  duplicate_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_payload_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_payload_bytes) },
	/*by global*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_loopback_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_loopback_bytes) },
};

static const struct counter_desc vf_hw_stats_desc[] = {
	/*by function*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  out_of_sequence) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  packet_seq_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  out_of_buffer) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rnr_nak_retry_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  local_ack_timeout_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_read_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rx_write_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  duplicate_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_tx_payload_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats,  rdma_rx_payload_bytes) },
};

static ssize_t counters_names_show(struct kobject *kobjs,
				   struct attribute *attr, char *buf)
{
	int i;
	ssize_t count = 0;
	struct xsc_counters_attribute *xsc_counters_name_attr;
	const struct counter_desc *desc;

	xsc_counters_name_attr = container_of(attr,
					      struct xsc_counters_attribute,
					      attr);

	if (!xsc_counters_name_attr->dev ||
	    !xsc_counters_name_attr->desc ||
	    xsc_counters_name_attr->desc_size == 0)
		return 0;

	for (i = 0; i < xsc_counters_name_attr->desc_size; ++i) {
		desc = xsc_counters_name_attr->desc + i;
		count += sprintf(&buf[count], "%s\n", desc->format);
	}

	return count;
}

static ssize_t counters_show(struct kobject *kobjs,
			     struct attribute *attr, char *buf)
{
	int i;
	ssize_t count = 0;
	struct xsc_counters_attribute *xsc_counters_attr;
	struct xsc_hw_stats_mbox_in *in;
	struct xsc_hw_stats_mbox_out out;
	struct xsc_core_device *dev;
	int ret;
	u64 counter;
	const struct counter_desc *desc;
	int inlen;
	struct xsc_lag *ldev;

	xsc_counters_attr = container_of(attr,
					 struct xsc_counters_attribute,
					 attr);

	if (!xsc_counters_attr->dev ||
	    !xsc_counters_attr->desc ||
		xsc_counters_attr->desc_size == 0)
		return 0;

	dev = xsc_counters_attr->dev;
	ldev = xsc_lag_dev_get(dev);
	if (ldev && __xsc_lag_is_roce(ldev))
		inlen = sizeof(struct xsc_hw_stats_mbox_in) + XSC_MAX_PORTS;
	else
		inlen = sizeof(struct xsc_hw_stats_mbox_in);

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return 0;

	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HW_STATS);

	if (ldev && __xsc_lag_is_roce(ldev)) {
		in->is_lag = 1;
		in->lag_member_num = XSC_MAX_PORTS;
		for (i = 0; i < XSC_MAX_PORTS; i++)
			in->member_port[i] = ldev->pf[i].xdev->mac_port;
	} else {
		in->is_lag = 0;
		in->mac_port = dev->mac_port;
	}
	ret = xsc_cmd_exec(dev, (void *)in, inlen, (void *)&out, sizeof(out));
	if (ret || out.hdr.status) {
		kfree(in);
		return 0;
	}

	for (i = 0 ; i < xsc_counters_attr->desc_size; ++i) {
		desc = xsc_counters_attr->desc + i;
		counter = *(u64 *)((char *)&out.hw_stats + desc->offset);
		counter = be64_to_cpu(counter);
		count += sprintf(&buf[count], "%-26s    %-20llu\n",
				desc->format, counter);
	}

	kfree(in);
	return count;
}

static ssize_t counters_value_read(struct file *file,
				   struct kobject *kob,
				   struct bin_attribute *bin_attr,
				   char *buf, loff_t loff, size_t size)
{
	int i;
	struct xsc_counters_bin_attribute *xsc_counters_bin_attr;
	u64 *tmp_value;
	struct xsc_hw_stats_mbox_in in;
	struct xsc_hw_stats_mbox_out out;
	struct xsc_core_device *dev;
	int ret;
	const struct counter_desc *desc;

	xsc_counters_bin_attr = container_of(&bin_attr->attr,
					     struct xsc_counters_bin_attribute,
					     attr);

	if (!xsc_counters_bin_attr->dev ||
	    !xsc_counters_bin_attr->desc ||
	    xsc_counters_bin_attr->desc_size == 0 ||
	    xsc_counters_bin_attr->size == 0)
		return 0;

	dev = xsc_counters_bin_attr->dev;
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HW_STATS);
	in.mac_port = dev->mac_port;
	ret = xsc_cmd_exec(dev, (void *)&in, sizeof(in), (void *)&out, sizeof(out));
	if (ret || out.hdr.status)
		return 0;

	tmp_value = kmalloc(xsc_counters_bin_attr->size, GFP_KERNEL);
	if (!tmp_value)
		return 0;

	for (i = 0; i < xsc_counters_bin_attr->desc_size; ++i) {
		desc = xsc_counters_bin_attr->desc + i;
		tmp_value[i] = *(u64 *)((char *)&out.hw_stats + desc->offset);
		tmp_value[i] = be64_to_cpu(tmp_value[i]);
	}

	memcpy(buf, tmp_value, xsc_counters_bin_attr->size);
	kfree(tmp_value);

	return xsc_counters_bin_attr->size;
}

int xsc_counters_init(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	struct xsc_counters_attribute *xsc_counters_name, *xsc_counters;
	struct xsc_counters_bin_attribute *xsc_counters_bin;
	struct attribute_group *counters_attr_g;
	struct bin_attribute **counters_bin_attrs;
	struct attribute **counters_attrs;
	int id, is_pf;
	int ret = -ENOMEM;

	xsc_counters_name = kzalloc(sizeof(*xsc_counters_name), GFP_KERNEL);
	if (!xsc_counters_name)
		return -ENOMEM;

	xsc_counters = kzalloc(sizeof(*xsc_counters), GFP_KERNEL);
	if (!xsc_counters)
		goto err_xsc_counters;

	xsc_counters_bin = kzalloc(sizeof(*xsc_counters_bin), GFP_KERNEL);
	if (!xsc_counters_bin)
		goto err_xsc_counters_bin;

	id = dev->mac_port;

	is_pf = xsc_core_is_pf(dev);
	xsc_core_dbg(dev, "get xscale id = %d, is_pf = %d.\n", id, is_pf);

	counters_bin_attrs = kzalloc(sizeof(*counters_bin_attrs) * 2, GFP_KERNEL);
	if (!counters_bin_attrs)
		goto err_counters_bin_attrs;

	counters_attrs = kzalloc(sizeof(*counters_attrs) * 3, GFP_KERNEL);
	if (!counters_attrs)
		goto err_counters_attrs;

	counters_attr_g = kzalloc(sizeof(*counters_attr_g), GFP_KERNEL);
	if (!counters_attr_g)
		goto err_counters_attr_g;

	sysfs_attr_init(&xsc_counters_name->attr);
	xsc_counters_name->attr.name = COUNTERS_NAMES_FILE_NAME;
	xsc_counters_name->attr.mode = 0444;
	xsc_counters_name->show = counters_names_show;

	sysfs_attr_init(&xsc_counters->attr);
	xsc_counters->attr.name = COUNTERS_FILE_NAME;
	xsc_counters->attr.mode = 0444;
	xsc_counters->show = counters_show;
	xsc_counters->id = id;
	xsc_counters->dev = dev;

	sysfs_attr_init(&xsc_counters_bin->attr);
	xsc_counters_bin->attr.name = COUNTERS_VALUE_FILE_NAME;
	xsc_counters_bin->attr.mode = 0444;
	xsc_counters_bin->read = counters_value_read;
	xsc_counters_bin->id = id;
	xsc_counters_bin->dev = dev;

	if (is_pf) {
		xsc_counters_name->desc = &hw_stats_desc[0];
		xsc_counters->desc = &hw_stats_desc[0];
		xsc_counters_bin->desc = &hw_stats_desc[0];
		xsc_counters_name->desc_size = ARRAY_SIZE(hw_stats_desc);
		xsc_counters->desc_size = ARRAY_SIZE(hw_stats_desc);
		xsc_counters_bin->desc_size = ARRAY_SIZE(hw_stats_desc);
		xsc_counters_bin->size = xsc_counters_bin->desc_size * sizeof(u64);
	} else {
		xsc_counters_name->desc = &vf_hw_stats_desc[0];
		xsc_counters->desc = &vf_hw_stats_desc[0];
		xsc_counters_bin->desc = &vf_hw_stats_desc[0];
		xsc_counters_name->desc_size = ARRAY_SIZE(vf_hw_stats_desc);
		xsc_counters->desc_size = ARRAY_SIZE(vf_hw_stats_desc);
		xsc_counters_bin->desc_size = ARRAY_SIZE(vf_hw_stats_desc);
		xsc_counters_bin->size = xsc_counters_bin->desc_size * sizeof(u64);
	}

	counters_bin_attrs[0] = (struct bin_attribute *)xsc_counters_bin;
	counters_attrs[0] = (struct attribute *)xsc_counters_name;
	counters_attrs[1] = (struct attribute *)xsc_counters;

	counters_attr_g->name = COUNTERS_ATTER_GROUP_NAME;
	counters_attr_g->attrs = counters_attrs;
	counters_attr_g->bin_attrs = counters_bin_attrs;

	dev->counters_priv = counters_attr_g;

	ret = sysfs_create_group(&ib_dev->dev.kobj, counters_attr_g);
	if (ret)
		goto err_counters_create_group;

	return 0;

err_counters_create_group:
	kfree(counters_attr_g);
	counters_attr_g = NULL;

err_counters_attr_g:
	kfree(counters_attrs);
	counters_attrs = NULL;

err_counters_attrs:
	kfree(counters_bin_attrs);
	counters_bin_attrs = NULL;

err_counters_bin_attrs:
	kfree(xsc_counters_bin);
	xsc_counters_bin = NULL;

err_xsc_counters_bin:
	kfree(xsc_counters);
	xsc_counters = NULL;

err_xsc_counters:
	kfree(xsc_counters_name);
	xsc_counters_name = NULL;

	return ret;
}

void xsc_counters_fini(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	struct xsc_counters_attribute *xsc_counters_name, *xsc_counters;
	struct xsc_counters_bin_attribute *xsc_counters_bin;
	struct bin_attribute **counters_bin_attrs;
	struct attribute **counters_attrs;
	struct attribute_group *counters_attr_g;

	counters_attr_g = dev->counters_priv;
	counters_attrs = counters_attr_g->attrs;
	counters_bin_attrs = counters_attr_g->bin_attrs;

	xsc_counters_bin = (struct xsc_counters_bin_attribute *)counters_bin_attrs[0];
	xsc_counters_name = (struct xsc_counters_attribute *)counters_attrs[0];
	xsc_counters = (struct xsc_counters_attribute *)counters_attrs[1];

	if (counters_attr_g) {
		sysfs_remove_group(&ib_dev->dev.kobj, counters_attr_g);
		kfree(counters_attr_g);
		counters_attr_g = NULL;
	}

	kfree(counters_attrs);
	counters_attrs = NULL;

	kfree(counters_bin_attrs);
	counters_bin_attrs = NULL;

	kfree(xsc_counters_bin);
	xsc_counters_bin = NULL;

	kfree(xsc_counters_name);
	xsc_counters_name = NULL;

	kfree(xsc_counters);
	xsc_counters = NULL;

	xsc_core_dbg(dev, "ok\n");
}

