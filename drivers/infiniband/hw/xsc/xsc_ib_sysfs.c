// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/time.h>
#include "common/xsc_core.h"
#include "common/xsc_hsi.h"
#include "common/driver.h"
#include "common/xsc_cmd.h"
#include "xsc_ib.h"

static ssize_t hca_type_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	struct pci_dev *pdev = dev->pdev;

	return sprintf(buf, "%x\n", pdev->subsystem_device);
}

static DEVICE_ATTR_RO(hca_type);

static ssize_t hw_rev_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	u32 hw_ver = 0;

	hw_ver = ((dev->chip_ver_l & 0xffff) << 16) |
		(dev->hotfix_num & 0xffff);
	return sprintf(buf, "0x%x\n", hw_ver);
}

static DEVICE_ATTR_RO(hw_rev);

static struct device_attribute *xsc_ib_attributes[] = {
	&dev_attr_hca_type,
	&dev_attr_hw_rev,
};

static ssize_t fastcc_rtt_histogram_en_store(struct device *device,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	int err;
	struct xsc_rtt_histogram_mbox_in in;
	struct xsc_rtt_histogram_mbox_out out;
	u32 rtt_histogram_en;

	err = kstrtou32(buf, 0, &rtt_histogram_en);
	if (err != 0)
		return -EINVAL;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_RTT_HISTOGRAM);
	in.xsc_rtt_histogram_opcode = __cpu_to_be16(XSC_RTT_HISTOGRAM_SET_EN);
	in.rtt_histogram.rtt_histogram_en = __cpu_to_be32(rtt_histogram_en);

	err = xsc_cmd_exec(dev,
			   (void *)&in, sizeof(struct xsc_rtt_histogram_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_histogram_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(dev,
			     "Failed to set rtt_histogram_en, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return count;
}

static ssize_t fastcc_rtt_histogram_en_show(struct device *device,
					    struct device_attribute *attr,
					    char *buf)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	int err;
	struct xsc_rtt_histogram_mbox_in in;
	struct xsc_rtt_histogram_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_RTT_HISTOGRAM);
	in.xsc_rtt_histogram_opcode = __cpu_to_be16(XSC_RTT_HISTOGRAM_GET_EN);

	err = xsc_cmd_exec(dev,
			   (void *)&in, sizeof(struct xsc_rtt_histogram_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_histogram_mbox_in));
	if (err || out.hdr.status) {
		xsc_core_err(dev,
			     "Failed to get rtt_histogram_en, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return sprintf(buf, "%u\n", __be32_to_cpu(out.rtt_histogram.rtt_histogram_en));
}

static DEVICE_ATTR_RW(fastcc_rtt_histogram_en);

static ssize_t fastcc_rtt_histogram_cnt_show(struct device *device,
					     struct device_attribute *attr,
					     char *buf)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	int err, i;
	u32 count = 0;
	struct xsc_rtt_histogram_mbox_in in;
	struct xsc_rtt_histogram_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_RTT_HISTOGRAM);
	in.xsc_rtt_histogram_opcode = __cpu_to_be16(XSC_RTT_HISTOGRAM_GET_CNT);

	err = xsc_cmd_exec(dev,
			   (void *)&in, sizeof(struct xsc_rtt_histogram_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_histogram_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(dev,
			     "Failed to get rtt_histogram_cnt, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	for (i = 0; i < (XSC_RTT_HISTOGRAM_CNT_MAX - 1); i++)
		count += sprintf(&buf[count], "%u,",
				 __be32_to_cpu(out.rtt_histogram.rtt_histogram_cnt[i]));

	count += sprintf(&buf[count], "%u\n",
			 __be32_to_cpu(out.rtt_histogram.rtt_histogram_cnt[i]));

	return count;
}

static DEVICE_ATTR_RO(fastcc_rtt_histogram_cnt);

static ssize_t fastcc_rtt_histogram_interval_show(struct device *device,
						  struct device_attribute *attr,
						  char *buf)
{
	struct ib_device *ib_dev = container_of(device, struct ib_device, dev);
	struct xsc_core_device *dev = to_mdev(ib_dev)->xdev;
	int err, i;
	u32 count = 0;
	struct xsc_rtt_histogram_mbox_in in;
	struct xsc_rtt_histogram_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_RTT_HISTOGRAM);
	in.xsc_rtt_histogram_opcode = __cpu_to_be16(XSC_RTT_HISTOGRAM_GET_INTERVAL);

	err = xsc_cmd_exec(dev,
			   (void *)&in, sizeof(struct xsc_rtt_histogram_mbox_in),
			   (void *)&out, sizeof(struct xsc_rtt_histogram_mbox_out));
	if (err || out.hdr.status) {
		xsc_core_err(dev,
			     "Failed to get rtt_histogram_interval, err(%u), status(%u)\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	for (i = 0; i < (XSC_RTT_HISTOGRAM_INTERVAL_MAX - 1); i++)
		count += sprintf(&buf[count], "%u,",
				 __be32_to_cpu(out.rtt_histogram.rtt_histogram_interval[i]));

	count += sprintf(&buf[count], "%u\n",
			  __be32_to_cpu(out.rtt_histogram.rtt_histogram_interval[i]));

	return count;
}

static DEVICE_ATTR_RO(fastcc_rtt_histogram_interval);

static struct attribute *fastcc_rtt_histogram_attrs[] = {
	&dev_attr_fastcc_rtt_histogram_en.attr,
	&dev_attr_fastcc_rtt_histogram_cnt.attr,
	&dev_attr_fastcc_rtt_histogram_interval.attr,
	NULL,
};

static struct attribute_group fastcc_rtt_histogram_group = {
	.name = "fastcc_rtt_histogram",
	.attrs = fastcc_rtt_histogram_attrs,
};

static int xsc_rtt_histogram_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	int err = 0;

	err = sysfs_create_group(&ib_dev->dev.kobj, &fastcc_rtt_histogram_group);
	if (err)
		goto remove_rtt_histogram;

	return 0;

remove_rtt_histogram:
	sysfs_remove_group(&ib_dev->dev.kobj, &fastcc_rtt_histogram_group);

	return err;
}

static void xsc_rtt_histogram_sysfs_fini(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	sysfs_remove_group(&ib_dev->dev.kobj, &fastcc_rtt_histogram_group);
}

void xsc_ib_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	int err = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(xsc_ib_attributes); i++) {
		err = device_create_file(&ib_dev->dev, xsc_ib_attributes[i]);
		if (err)
			xsc_core_err(xdev, "Create sysfs file for %s failed.\n",
				     xsc_ib_attributes[i]->attr.name);
	}

	if (xsc_core_is_pf(xdev) && xdev->pf_id == 0) {
		err = xsc_rtt_histogram_sysfs_init(ib_dev, xdev);
		if (err)
			xsc_core_err(xdev,
				     "Create sysfs file for fastcc_rtt_histogram failed.\n");
	}
}

void xsc_ib_sysfs_fini(struct ib_device *ib_dev, struct xsc_core_device *xdev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(xsc_ib_attributes); i++)
		device_remove_file(&ib_dev->dev, xsc_ib_attributes[i]);

	if (xsc_core_is_pf(xdev) && xdev->pf_id == 0)
		xsc_rtt_histogram_sysfs_fini(ib_dev, xdev);
}

