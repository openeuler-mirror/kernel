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
#include "common/xsc_lag.h"
#include "common/xsc_cmd.h"
#include "counters.h"

#define COUNTERS_FILE_NAME         "counters"
#define COUNTERS_NAMES_FILE_NAME   "counters_names"
#define COUNTERS_VALUE_FILE_NAME   "counters_value"
#define COUNTERS_ATTER_GROUP_NAME  "counters"
#define GLOBAL_COUNTERS_GROUP_NAME "global_counters"
#define GLOBAL_COUNTERS_FILE_NAME  "counters"

static const struct counter_desc hw_rdma_stats_pf_desc[] = {
	/*by mac port*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_tx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_tx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_rx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_rx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  np_cnp_sent) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rp_cnp_handled) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  np_ecn_marked_roce_packets) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rp_cnp_ignored) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  read_rsp_out_of_seq) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  implied_nak_seq_err) },
	/*by function*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  out_of_sequence) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  packet_seq_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  out_of_buffer) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rnr_nak_retry_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  local_ack_timeout_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rx_read_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rx_write_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  duplicate_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_tx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_tx_payload_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_rx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_rx_payload_bytes) },
	/*global*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_loopback_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_loopback_bytes) },

	/*for diamond*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  out_of_sequence_sr) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  packet_seq_err_sr) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_ndp_rx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_ndp_rx_trimmed_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_pf,  rdma_ndp_trimmed_pkts_sr) },
};

static const struct counter_desc hw_rdma_stats_vf_desc[] = {
	/*by function*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  rdma_tx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  rdma_tx_payload_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  rdma_rx_pkts_func) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  rdma_rx_payload_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  out_of_sequence) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  packet_seq_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  out_of_buffer) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  rnr_nak_retry_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  local_ack_timeout_err) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  rx_read_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  rx_write_requests) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_rdma_vf,  duplicate_requests) },
};

static const struct counter_desc hw_global_rdma_stats_desc[] = {
	{ XSC_DECLARE_STAT(struct xsc_hw_global_stats_rdma,  rdma_loopback_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_global_stats_rdma,  rdma_loopback_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_global_stats_rdma,  rx_icrc_encapsulated) },
	{ XSC_DECLARE_STAT(struct xsc_hw_global_stats_rdma,  req_cqe_error) },
	{ XSC_DECLARE_STAT(struct xsc_hw_global_stats_rdma,  resp_cqe_error) },
	{ XSC_DECLARE_STAT(struct xsc_hw_global_stats_rdma,  cqe_msg_code_error) },
};

static int get_hw_stats_rdma(struct xsc_core_device *dev, struct xsc_hw_stats_rdma *stats_rdma)
{
	int i = 0;
	int ret;
	int inlen;
	struct xsc_lag *lag;
	struct xsc_hw_stats_mbox_in *in;
	struct xsc_hw_stats_rdma_mbox_out out;
	struct xsc_core_device *xdev_tmp;

	memset(stats_rdma, 0, sizeof(*stats_rdma));

	if (!dev)
		return -1;

	inlen = sizeof(struct xsc_hw_stats_mbox_in) + XSC_MAX_PORTS;
	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	xsc_board_lag_lock(dev);
	if (xsc_lag_is_roce(dev)) {
		lag = xsc_get_lag(dev);
		in->lag_member_num = lag->xsc_member_cnt;
		list_for_each_entry(xdev_tmp, &lag->slave_list, slave_node)
			in->member_port[i++] = xdev_tmp->mac_port;
		in->is_lag = 1;
	} else {
		in->is_lag = 0;
		in->mac_port = dev->mac_port;
	}
	xsc_board_lag_unlock(dev);

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HW_STATS_RDMA);
	memset(&out, 0, sizeof(out));
	ret = xsc_cmd_exec(dev, (void *)in, inlen, (void *)&out, sizeof(out));
	if (ret || out.hdr.status) {
		kfree(in);
		return -1;
	}

	memcpy(stats_rdma, &out.hw_stats, sizeof(*stats_rdma));
	kfree(in);
	return 0;
}

static ssize_t counters_names_show(struct kobject *kobjs,
				   struct attribute *attr, char *buf)
{
	int i;
	int desc_size;
	ssize_t count = 0;
	const struct counter_desc *desc;
	struct xsc_counters_attribute *xsc_counters_name_attr;
	u32 mask = 0;

	xsc_counters_name_attr = container_of(attr,
					      struct xsc_counters_attribute,
					      attr);

	if (is_support_hw_pf_stats(xsc_counters_name_attr->dev)) {
		desc = &hw_rdma_stats_pf_desc[0];
		desc_size = ARRAY_SIZE(hw_rdma_stats_pf_desc);
	} else {
		desc = &hw_rdma_stats_vf_desc[0];
		desc_size = ARRAY_SIZE(hw_rdma_stats_vf_desc);
	}

	mask = xsc_get_rdma_stat_mask(xsc_counters_name_attr->dev);
	for (i = 0 ; i < desc_size; i++) {
		if (!((1 << i) & mask))
			continue;
		count += sprintf(&buf[count], "%s\n", desc[i].format);
	}

	return count;
}

static ssize_t counters_show(struct kobject *kobjs,
			     struct attribute *attr, char *buf)
{
	int i;
	int ret;
	u8 *stats;
	u64 value;
	int desc_size;
	ssize_t count = 0;
	const struct counter_desc *desc;
	struct xsc_hw_stats_rdma stats_rdma;
	struct xsc_counters_attribute *xsc_counters_attr;
	u32 mask = 0;

	xsc_counters_attr = container_of(attr,
					 struct xsc_counters_attribute,
					 attr);

	ret = get_hw_stats_rdma(xsc_counters_attr->dev, &stats_rdma);
	if (ret || is_support_hw_pf_stats(xsc_counters_attr->dev) != stats_rdma.is_pf)
		return 0;

	if (is_support_hw_pf_stats(xsc_counters_attr->dev)) {
		desc = &hw_rdma_stats_pf_desc[0];
		desc_size = ARRAY_SIZE(hw_rdma_stats_pf_desc);
		stats = (u8 *)&stats_rdma.stats.pf_stats;
	} else {
		desc = &hw_rdma_stats_vf_desc[0];
		desc_size = ARRAY_SIZE(hw_rdma_stats_vf_desc);
		stats = (u8 *)&stats_rdma.stats.vf_stats;
	}

	mask = xsc_get_rdma_stat_mask(xsc_counters_attr->dev);
	for (i = 0 ; i < desc_size; i++) {
		if (!((1 << i) & mask))
			continue;
		value = *(u64 *)(stats + desc[i].offset);
		value = be64_to_cpu(value);
		count += sprintf(&buf[count], "%-26s    %-20llu\n",
				desc[i].format, value);
	}

	return count;
}

static ssize_t counters_value_read(struct file *file,
				   struct kobject *kob,
				   struct bin_attribute *bin_attr,
				   char *buf, loff_t loff, size_t size)
{
	int i = 0;
	int j = 0;
	int ret;
	u8 *stats;
	int bin_size;
	int desc_size;
	u64 *tmp_value;
	struct xsc_core_device *xdev;
	const struct counter_desc *desc;
	struct xsc_hw_stats_rdma stats_rdma;
	struct xsc_counters_bin_attribute *xsc_counters_bin_attr;
	u32 mask = 0;

	xsc_counters_bin_attr = container_of(&bin_attr->attr,
					     struct xsc_counters_bin_attribute,
					     attr);

	if (xsc_counters_bin_attr->size > size || xsc_counters_bin_attr->size == 0)
		return 0;

	xdev = (struct xsc_core_device *)xsc_counters_bin_attr->private;
	ret = get_hw_stats_rdma(xdev, &stats_rdma);
	if (ret || is_support_hw_pf_stats(xdev) != stats_rdma.is_pf)
		return 0;

	if (is_support_hw_pf_stats(xdev)) {
		desc = &hw_rdma_stats_pf_desc[0];
		desc_size = ARRAY_SIZE(hw_rdma_stats_pf_desc);
		stats = (u8 *)&stats_rdma.stats.pf_stats;
	} else {
		desc = &hw_rdma_stats_vf_desc[0];
		desc_size = ARRAY_SIZE(hw_rdma_stats_vf_desc);
		stats = (u8 *)&stats_rdma.stats.vf_stats;
	}

	bin_size = desc_size * sizeof(u64);
	if (xsc_counters_bin_attr->size < bin_size)
		return 0;

	tmp_value = kzalloc(xsc_counters_bin_attr->size, GFP_KERNEL);
	if (!tmp_value)
		return 0;

	mask = xsc_get_rdma_stat_mask(xdev);
	j = 0;
	for (i = 0; i < desc_size; i++) {
		if (!((1 << i) & mask))
			continue;
		tmp_value[j] = *(u64 *)(stats + desc[i].offset);
		tmp_value[j] = be64_to_cpu(tmp_value[i]);
		j++;
	}

	memcpy(buf, tmp_value, xsc_counters_bin_attr->size);

	kfree(tmp_value);
	return xsc_counters_bin_attr->size;
}

static int counters_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	struct xsc_counters_attribute *xsc_counters_name, *xsc_counters;
	struct xsc_counters_bin_attribute *xsc_counters_bin;
	struct attribute_group *counters_attr_g;
	struct bin_attribute **counters_bin_attrs;
	struct attribute **counters_attrs;
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
	xsc_counters_name->dev = dev;

	sysfs_attr_init(&xsc_counters->attr);
	xsc_counters->attr.name = COUNTERS_FILE_NAME;
	xsc_counters->attr.mode = 0444;
	xsc_counters->show = counters_show;
	xsc_counters->dev = dev;

	sysfs_attr_init(&xsc_counters_bin->attr);
	xsc_counters_bin->attr.name = COUNTERS_VALUE_FILE_NAME;
	xsc_counters_bin->attr.mode = 0444;
	xsc_counters_bin->read = counters_value_read;
	xsc_counters_bin->private = dev;
	xsc_counters_bin->size = sizeof(struct xsc_hw_stats_rdma);

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

static void counters_sysfs_fini(struct ib_device *ib_dev, struct xsc_core_device *dev)
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
}

static ssize_t global_cnt_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct xsc_global_cnt_attributes *a =
		container_of(attr, struct xsc_global_cnt_attributes, attr);
	struct xsc_global_cnt_interface *g =
		container_of(kobj, struct xsc_global_cnt_interface, kobj);

	if (!a->show)
		return -EIO;

	return a->show(g, a, buf);
}

static ssize_t global_cnt_attr_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buf, size_t size)
{
	struct xsc_global_cnt_attributes *a =
		container_of(attr, struct xsc_global_cnt_attributes, attr);
	struct xsc_global_cnt_interface *g =
		container_of(kobj, struct xsc_global_cnt_interface, kobj);

	if (!a->store)
		return -EIO;

	return a->store(g, a, buf, size);
}

static ssize_t global_counters_show(struct xsc_global_cnt_interface *g,
				    struct xsc_global_cnt_attributes *a, char *buf)
{
	int i;
	int ret;
	u8 *stats;
	u64 value;
	int desc_size;
	ssize_t count = 0;
	const struct counter_desc *desc;
	struct xsc_hw_global_stats_mbox_in in;
	struct xsc_hw_global_stats_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HW_GLOBAL_STATS);
	ret = xsc_cmd_exec(g->xdev, (void *)&in, sizeof(in),
			   (void *)&out, sizeof(out));
	if (ret || out.hdr.status)
		return 0;

	desc = &hw_global_rdma_stats_desc[0];
	desc_size = ARRAY_SIZE(hw_global_rdma_stats_desc);
	stats = (u8 *)&out.hw_stats;

	for (i = 0 ; i < desc_size; i++) {
		value = *(u64 *)(stats + desc[i].offset);
		value = be64_to_cpu(value);
		count += sprintf(&buf[count], "%-26s    %-20llu\n",
				desc[i].format, value);
	}

	return count;
}

static ssize_t global_counters_store(struct xsc_global_cnt_interface *g,
				     struct xsc_global_cnt_attributes *a,
				     const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

#define GLOBAL_CNT_ATTR(_name) struct xsc_global_cnt_attributes xsc_global_cnt_attr_##_name = \
	__ATTR(_name, 0444, global_##_name##_show, global_##_name##_store)

GLOBAL_CNT_ATTR(counters);

static const struct sysfs_ops global_cnt_sysfs_ops = {
	.show = global_cnt_attr_show,
	.store = global_cnt_attr_store,
};

static struct attribute *global_cnt_attrs[] = {
	&xsc_global_cnt_attr_counters.attr,
	NULL
};

ATTRIBUTE_GROUPS(global_cnt);

static struct kobj_type global_cnt_ktype = {
	.sysfs_ops     = &global_cnt_sysfs_ops,
	.default_groups = global_cnt_groups,
};

static struct xsc_global_cnt_interface *g_global_cnt_interface;

static int global_cnt_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	struct xsc_global_cnt_interface *tmp;
	int err;

	if (!xdev || !xsc_core_is_pf(xdev) || xdev->pf_id != 0)
		return 0;

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	err = kobject_init_and_add(&tmp->kobj, &global_cnt_ktype,
				   &ib_dev->dev.kobj, GLOBAL_COUNTERS_GROUP_NAME);
	if (err)
		goto error_return;

	g_global_cnt_interface = tmp;
	tmp->xdev = xdev;
	return 0;

error_return:
	kobject_put(&tmp->kobj);
	kfree(tmp);
	return err;
}

static void global_cnt_sysfs_fini(struct xsc_core_device *xdev)
{
	if (!g_global_cnt_interface || !xdev || !xsc_core_is_pf(xdev) || xdev->pf_id != 0)
		return;

	kobject_put(&g_global_cnt_interface->kobj);
	kfree(g_global_cnt_interface);
	g_global_cnt_interface = NULL;
}

int xsc_counters_init(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	int ret;

	ret = counters_sysfs_init(ib_dev, dev);
	if (ret)
		goto error_return;

	ret = global_cnt_sysfs_init(ib_dev, dev);
	if (ret)
		goto error_global_cnt;

	return 0;

error_global_cnt:
	counters_sysfs_fini(ib_dev, dev);
error_return:
	return ret;
}

void xsc_counters_fini(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	counters_sysfs_fini(ib_dev, dev);
	global_cnt_sysfs_fini(dev);
}

