// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018-2021 Hisilicon Limited. */

#include <linux/device.h>
#include "hnae3.h"
#include "hclge_main.h"
#include "hclge_tm.h"
#include "hclge_sysfs.h"

void hclge_reset_pf_rate(struct hclge_dev *hdev)
{
	struct hclge_vport *vport = &hdev->vport[0];
	int ret;

	/* zero means max rate, if max_tx_rate is zero, just return */
	if (!vport->vf_info.max_tx_rate)
		return;

	vport->vf_info.max_tx_rate = 0;

	ret = hclge_tm_qs_shaper_cfg(vport, vport->vf_info.max_tx_rate);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"failed to reset pf tx rate to default, ret = %d.\n",
			ret);
}

int hclge_resume_pf_rate(struct hclge_dev *hdev)
{
	struct hclge_vport *vport = &hdev->vport[0];
	int ret;

	/* zero means max rate, after reset, firmware already set it to
	 * max rate, so just continue.
	 */
	if (!vport->vf_info.max_tx_rate)
		return 0;

	ret = hclge_tm_qs_shaper_cfg(vport, vport->vf_info.max_tx_rate);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to resume pf tx rate:%u, ret = %d.\n",
			vport->vf_info.max_tx_rate, ret);
		return ret;
	}

	return 0;
}

static ssize_t hclge_max_tx_rate_show(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      char *buf)
{
	struct hclge_vport *vport =
		container_of(kobj, struct hclge_vport, kobj);

	return sprintf(buf, "%d Mbit/s (0 means no limit)\n",
		       vport->vf_info.max_tx_rate);
}

static ssize_t hclge_max_tx_rate_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf,
				       size_t size)
{
	struct hclge_vport *vport =
		container_of(kobj, struct hclge_vport, kobj);
	struct hclge_dev *hdev = vport->back;
	int max_tx_rate;
	int ret;

	ret = kstrtoint(buf, 0, &max_tx_rate);
	if (ret)
		return -EINVAL;

	if (max_tx_rate < 0 || max_tx_rate > hdev->hw.mac.max_speed) {
		dev_err(&hdev->pdev->dev,
			"invalid max_tx_rate:%d [0, %u]\n",
			max_tx_rate, hdev->hw.mac.max_speed);
		return -EINVAL;
	}

	ret = hclge_tm_qs_shaper_cfg(vport, max_tx_rate);
	if (ret)
		return ret;

	vport->vf_info.max_tx_rate = max_tx_rate;

	return ret ? (ssize_t)ret : size;
}

static struct kobj_attribute hclge_attr_max_tx_rate = {
	.attr = {.name = "max_tx_rate",
		 .mode = 0644 },
	.show = hclge_max_tx_rate_show,
	.store = hclge_max_tx_rate_store,
};

static struct attribute *hclge_sysfs_attrs[] = {
	&hclge_attr_max_tx_rate.attr,
	NULL,
};

static struct kobj_type hclge_sysfs_type = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_attrs = hclge_sysfs_attrs,
};

void hclge_sysfs_init(struct hnae3_handle *handle)
{
	struct net_device *netdev = handle->netdev;
	struct hclge_vport *vport = hclge_get_vport(handle);
	int ret;

	handle->kobj = kobject_create_and_add("kunpeng", &netdev->dev.kobj);
	if (!handle->kobj) {
		netdev_err(netdev, "failed to create kobj!\n");
		return;
	}

	ret = kobject_init_and_add(&vport->kobj, &hclge_sysfs_type,
				   handle->kobj, "pf");
	if (ret) {
		netdev_err(netdev, "failed to init kobj, ret = %d\n", ret);
		kobject_put(handle->kobj);
		handle->kobj = NULL;
	}
}

void hclge_sysfs_uninit(struct hnae3_handle *handle)
{
	struct hclge_vport *vport = hclge_get_vport(handle);

	if (!handle->kobj)
		return;

	kobject_put(&vport->kobj);
	kobject_put(handle->kobj);
	handle->kobj = NULL;
}
