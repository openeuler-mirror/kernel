// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "common/xsc_core.h"
#include "common/xsc_cmd.h"

#include "xsc_eth.h"

static void pcie_lat_hw_work(struct work_struct *work)
{
	int err;
	struct delayed_work *dwork = to_delayed_work(work);
	struct xsc_pcie_lat_work *pcie_lat = container_of(dwork, struct xsc_pcie_lat_work, work);
	struct xsc_core_device *xdev = pcie_lat->xdev;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_HW);

	err = xsc_cmd_exec(xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "Failed to run pcie_lat hw, err(%u), status(%u)\n",
			     err, out.hdr.status);
	}
	schedule_delayed_work_on(smp_processor_id(), dwork,
				 msecs_to_jiffies(pcie_lat->period * 1000));
}

static void pcie_lat_hw_init(struct xsc_core_device *xdev)
{
	int err;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_HW_INIT);

	err = xsc_cmd_exec(xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "Failed to run pcie_lat hw, err(%u), status(%u)\n",
			     err, out.hdr.status);
	}
}

static ssize_t pcie_lat_enable_show(struct device *device,
				    struct device_attribute *attr,
				    char *buf)
{
	struct xsc_adapter *adapter = netdev_priv(to_net_dev(device));
	int err;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_GET_EN);

	err = xsc_cmd_exec(adapter->xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "Failed to get pcie_lat en, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return sprintf(buf, "%hhu\n", out.pcie_lat.pcie_lat_enable);
}

static ssize_t pcie_lat_enable_store(struct device *device,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct xsc_adapter *adapter = netdev_priv(to_net_dev(device));
	struct xsc_pcie_lat_work *pcie_lat = adapter->xdev->pcie_lat;
	int err;
	u16 pcie_lat_enable;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	err = kstrtou16(buf, 0, &pcie_lat_enable);
	if (err != 0)
		return -EINVAL;

	if (pcie_lat_enable != XSC_PCIE_LAT_EN_DISABLE &&
	    pcie_lat_enable != XSC_PCIE_LAT_EN_ENABLE) {
		xsc_core_err(adapter->xdev,
			     "pcie_lat_enable should be set as %d or %d, cannot be %d\n",
			      XSC_PCIE_LAT_EN_DISABLE, XSC_PCIE_LAT_EN_ENABLE,
			      pcie_lat_enable);
		return -EPERM;
	}

	if (pcie_lat_enable == XSC_PCIE_LAT_EN_ENABLE &&
	    pcie_lat->enable == XSC_PCIE_LAT_EN_DISABLE) {
		pcie_lat_hw_init(adapter->xdev);
		pcie_lat->adapter = adapter;
		INIT_DELAYED_WORK(&pcie_lat->work, pcie_lat_hw_work);
		schedule_delayed_work_on(smp_processor_id(), &pcie_lat->work,
					 msecs_to_jiffies(pcie_lat->period * 1000));
	} else if (pcie_lat_enable == XSC_PCIE_LAT_EN_DISABLE &&
		   pcie_lat->enable == XSC_PCIE_LAT_EN_ENABLE) {
		cancel_delayed_work_sync(&pcie_lat->work);
		pcie_lat->period = XSC_PCIE_LAT_PERIOD_MIN;
	}

	pcie_lat->enable = pcie_lat_enable;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_SET_EN);
	in.pcie_lat.pcie_lat_enable = pcie_lat_enable;

	err = xsc_cmd_exec(adapter->xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "Failed to set pcie_lat en, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return count;
}

static DEVICE_ATTR_RW(pcie_lat_enable);

static ssize_t pcie_lat_interval_show(struct device *device,
				      struct device_attribute *attr,
				      char *buf)
{
	struct xsc_adapter *adapter = netdev_priv(to_net_dev(device));
	int err, i;
	u32 count = 0;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_GET_INTERVAL);

	err = xsc_cmd_exec(adapter->xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "Failed to get pcie_lat interval, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	for (i = 0; i < (XSC_PCIE_LAT_CFG_INTERVAL_MAX - 1); i++)
		count += sprintf(&buf[count], "%u,",
				 __be32_to_cpu(out.pcie_lat.pcie_lat_interval[i]));

	count += sprintf(&buf[count], "%u\n", __be32_to_cpu(out.pcie_lat.pcie_lat_interval[i]));

	return count;
}

static DEVICE_ATTR_RO(pcie_lat_interval);

static ssize_t pcie_lat_period_show(struct device *device,
				    struct device_attribute *attr,
				    char *buf)
{
	struct xsc_adapter *adapter = netdev_priv(to_net_dev(device));
	struct xsc_pcie_lat_work *tmp = adapter->xdev->pcie_lat;

	return sprintf(buf, "%u\n", tmp->period);
}

static ssize_t pcie_lat_period_store(struct device *device,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct xsc_adapter *adapter = netdev_priv(to_net_dev(device));
	struct xsc_pcie_lat_work *tmp = adapter->xdev->pcie_lat;
	int err;
	u32 pcie_lat_period;

	err = kstrtouint(buf, 0, &pcie_lat_period);
	if (err != 0)
		return -EINVAL;

	if (pcie_lat_period < XSC_PCIE_LAT_PERIOD_MIN ||
	    pcie_lat_period > XSC_PCIE_LAT_PERIOD_MAX) {
		xsc_core_err(adapter->xdev, "pcie_lat_period should be set between [%d-%d], cannot be %d\n",
			     XSC_PCIE_LAT_PERIOD_MIN, XSC_PCIE_LAT_PERIOD_MAX,
			     pcie_lat_period);
		return -EPERM;
	}

	tmp->period = pcie_lat_period;

	return count;
}

static DEVICE_ATTR_RW(pcie_lat_period);

static ssize_t pcie_lat_histogram_show(struct device *device,
				       struct device_attribute *attr,
				       char *buf)
{
	struct xsc_adapter *adapter = netdev_priv(to_net_dev(device));
	int i, err;
	u32 count = 0;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_GET_HISTOGRAM);

	err = xsc_cmd_exec(adapter->xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev,
			     "Failed to get pcie_lat histogram, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	for (i = 0; i < (XSC_PCIE_LAT_CFG_HISTOGRAM_MAX - 1); i++)
		count += sprintf(&buf[count], "%u,",
				 __be32_to_cpu(out.pcie_lat.pcie_lat_histogram[i]));

	count += sprintf(&buf[count], "%u\n", __be32_to_cpu(out.pcie_lat.pcie_lat_histogram[i]));

	return count;
}

static DEVICE_ATTR_RO(pcie_lat_histogram);

static ssize_t pcie_lat_peak_show(struct device *device,
				  struct device_attribute *attr,
				  char *buf)
{
	struct xsc_adapter *adapter = netdev_priv(to_net_dev(device));
	int err;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_GET_PEAK);

	err = xsc_cmd_exec(adapter->xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(adapter->xdev, "Failed to get pcie_lat peak, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return sprintf(buf, "%u\n", __be32_to_cpu(out.pcie_lat.pcie_lat_peak));
}

static DEVICE_ATTR_RO(pcie_lat_peak);

static struct attribute *pcie_lat_attrs[] = {
	&dev_attr_pcie_lat_enable.attr,
	&dev_attr_pcie_lat_interval.attr,
	&dev_attr_pcie_lat_period.attr,
	&dev_attr_pcie_lat_histogram.attr,
	&dev_attr_pcie_lat_peak.attr,
	NULL,
};

static struct attribute_group pcie_lat_group = {
	.name = "pcie_lat",
	.attrs = pcie_lat_attrs,
};

static int xsc_pcie_lat_sysfs_init(struct net_device *dev, struct xsc_core_device *xdev)
{
	int err = 0;
	struct xsc_pcie_lat_work *tmp;

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	xdev->pcie_lat = tmp;
	tmp->xdev = xdev;

	tmp->enable = XSC_PCIE_LAT_EN_DISABLE;
	tmp->period = XSC_PCIE_LAT_PERIOD_MIN;

	err = sysfs_create_group(&dev->dev.kobj, &pcie_lat_group);
	if (err)
		goto remove_pcie_lat;

	return 0;

remove_pcie_lat:
	sysfs_remove_group(&dev->dev.kobj, &pcie_lat_group);
	kfree(tmp);

	return err;
}

static void xsc_pcie_lat_sysfs_fini(struct net_device *dev, struct xsc_core_device *xdev)
{
	int err;
	struct xsc_pcie_lat_work *tmp;
	struct xsc_pcie_lat_feat_mbox_in in;
	struct xsc_pcie_lat_feat_mbox_out out;

	tmp = xdev->pcie_lat;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_PCIE_LAT_FEAT);
	in.xsc_pcie_lat_feature_opcode = __cpu_to_be16(XSC_PCIE_LAT_FEAT_SET_EN);
	in.pcie_lat.pcie_lat_enable = XSC_PCIE_LAT_EN_DISABLE;

	err = xsc_cmd_exec(xdev, (void *)&in, sizeof(struct xsc_pcie_lat_feat_mbox_in),
			   (void *)&out, sizeof(struct xsc_pcie_lat_feat_mbox_out));
	if (err || out.hdr.status)
		xsc_core_err(xdev, "Failed to set pcie_lat disable, err(%u), status(%u)\n",
			     err, out.hdr.status);

	if (tmp->enable == XSC_PCIE_LAT_EN_ENABLE)
		cancel_delayed_work_sync(&tmp->work);

	sysfs_remove_group(&dev->dev.kobj, &pcie_lat_group);

	if (!xdev->pcie_lat)
		return;

	kfree(tmp);
	xdev->pcie_lat = NULL;
}

int xsc_eth_sysfs_create(struct net_device *dev, struct xsc_core_device *xdev)
{
	int err = 0;

	if (xsc_core_is_pf(xdev) && xdev->pf_id == 0)
		err = xsc_pcie_lat_sysfs_init(dev, xdev);

	return err;
}

void xsc_eth_sysfs_remove(struct net_device *dev, struct xsc_core_device *xdev)
{
	if (xsc_core_is_pf(xdev) && xdev->pf_id == 0)
		xsc_pcie_lat_sysfs_fini(dev, xdev);
}
