// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.

#include "hnae3.h"
#include "hclge_main.h"

static ssize_t lane_num_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
#define HCLGE_GE_PORT_ONE_LANE	1
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
	struct hnae3_ae_dev *ae_dev = pci_get_drvdata(pdev);
	struct hclge_dev *hdev = ae_dev->priv;

	if (hdev->hw.mac.media_type == HNAE3_MEDIA_TYPE_COPPER)
		return scnprintf(buf, PAGE_SIZE, "%u\n",
				 HCLGE_GE_PORT_ONE_LANE);
	else
		return scnprintf(buf, PAGE_SIZE, "%u\n", hdev->hw.mac.lane_num);
}

static ssize_t lane_num_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
#define HCLGE_CONVERSION_NUM	10  /* Convert string to decimal number */

	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
	struct hnae3_ae_dev *ae_dev = pci_get_drvdata(pdev);
	struct hclge_dev *hdev = ae_dev->priv;
	u8 lane_num, duplex;
	u32 speed;
	int ret;

	ret = kstrtou8(buf, HCLGE_CONVERSION_NUM, &lane_num);
	if (ret) {
		dev_err(dev, "input params of lane number format unmatch.\n");
		return -EINVAL;
	}

	if (!lane_num || lane_num > 8 || !is_power_of_2(lane_num)) {
		dev_err(dev, "lane number only supports setting 1, 2, 4, 8.\n");
		return -EINVAL;
	}

	rtnl_lock();

	if (hdev->hw.mac.support_autoneg && hdev->hw.mac.autoneg) {
		ret = count;
		goto out;
	}

	if (lane_num == hdev->hw.mac.lane_num) {
		dev_info(dev, "setting lane number not changed.\n");
		ret = count;
		goto out;
	}

	speed = hdev->hw.mac.speed;
	duplex = hdev->hw.mac.duplex;

	ret = hclge_cfg_mac_speed_dup_hw(hdev, speed, duplex, lane_num);
	if (!ret)
		ret = count;

out:
	rtnl_unlock();
	return ret;
}

static DEVICE_ATTR_RW(lane_num);

static const struct device_attribute *hclge_hw_attrs_list[] = {
	&dev_attr_lane_num,
};

int hclge_register_sysfs(struct hclge_dev *hdev)
{
	int ret;

	if (!hnae3_ae_dev_lane_num_supported(hdev->ae_dev))
		return 0;

	ret = device_create_file(&hdev->pdev->dev, hclge_hw_attrs_list[0]);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"failed to create node %s, ret = %d.\n",
			hclge_hw_attrs_list[0]->attr.name, ret);

	return ret;
}

void hclge_unregister_sysfs(struct hclge_dev *hdev)
{
	device_remove_file(&hdev->pdev->dev, hclge_hw_attrs_list[0]);
}
