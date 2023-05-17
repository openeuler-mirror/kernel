// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>

#include "hw.h"
#include "common.h"
#include "hwmon.h"

enum NBL_HWMON_TEMP {
	NBL_TEMP,
	NBL_TEMP_MAX,
};

enum NBL_HWMON_VOLTAGE {
	NBL_VOLT_VCCINT,
	NBL_VOLT_VCCAUX,
	NBL_VOLT_VCCBRAM,
	NBL_VOLT_VUSER0,
	NBL_VOLT_VUSER1,
	NBL_VOLT_VUSER2,
	NBL_VOLT_VUSER3,
	NBL_VOLT_MAX,
};

#define NBL_HWMON_TEMP_MUL (5093140064ULL)
#define NBL_HWMON_TEMP_SHIFT (16)
#define NBL_HWMON_TEMP_SUB (2802308787LL)
#define NBL_HWMON_TEMP_FAC (10000)

#define NBL_HWMON_VOLT_MUL (3000)
#define NBL_HWMON_VOLT_SHIFT (16)

static ssize_t nbl_hwmon_temp_input_show(struct device *dev, struct device_attribute *attr,
					 char *buf)
{
	struct nbl_adapter *adapter = dev_get_drvdata(dev);
	struct nbl_hw *hw = &adapter->hw;
	int channel = to_sensor_dev_attr(attr)->index;
	u32 val;
	int temperature;
	int len;

	switch (channel) {
	case NBL_TEMP:
		val = rd32(hw, NBL_PRCFG_TEMPERATURE_REG);
		temperature = (int)((((s64)(((u64)val * NBL_HWMON_TEMP_MUL) >>
			       NBL_HWMON_TEMP_SHIFT)) - NBL_HWMON_TEMP_SUB) /
			       NBL_HWMON_TEMP_FAC);
		break;
	default:
		return -EINVAL;
	}

	len = snprintf(buf, PAGE_SIZE, "%d\n", temperature);
	return len;
}

static ssize_t nbl_hwmon_in_input_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct nbl_adapter *adapter = dev_get_drvdata(dev);
	struct nbl_hw *hw = &adapter->hw;
	int channel = to_sensor_dev_attr(attr)->index;
	u32 val;
	u32 voltage;
	int len;

	switch (channel) {
	case NBL_VOLT_VCCINT:
		val = rd32(hw, NBL_PRCFG_VCCINT_REG);
		break;
	case NBL_VOLT_VCCAUX:
		val = rd32(hw, NBL_PRCFG_VCCAUX_REG);
		break;
	case NBL_VOLT_VCCBRAM:
		val = rd32(hw, NBL_PRCFG_VCCBRAM_REG);
		break;
	case NBL_VOLT_VUSER0:
		val = rd32(hw, NBL_PRCFG_VUSER0_REG);
		break;
	case NBL_VOLT_VUSER1:
		val = rd32(hw, NBL_PRCFG_VUSER1_REG);
		break;
	case NBL_VOLT_VUSER2:
		val = rd32(hw, NBL_PRCFG_VUSER2_REG);
		break;
	case NBL_VOLT_VUSER3:
		val = rd32(hw, NBL_PRCFG_VUSER3_REG);
		break;
	default:
		return -EINVAL;
	}

	voltage = (val * NBL_HWMON_VOLT_MUL) >> NBL_HWMON_VOLT_SHIFT;

	len = snprintf(buf, PAGE_SIZE, "%u\n", voltage);
	return len;
}

static SENSOR_DEVICE_ATTR(temp1_input, 0444, nbl_hwmon_temp_input_show, NULL, NBL_TEMP);

static SENSOR_DEVICE_ATTR(in0_input, 0444, nbl_hwmon_in_input_show, NULL, NBL_VOLT_VCCINT);
static SENSOR_DEVICE_ATTR(in1_input, 0444, nbl_hwmon_in_input_show, NULL, NBL_VOLT_VCCAUX);
static SENSOR_DEVICE_ATTR(in2_input, 0444, nbl_hwmon_in_input_show, NULL, NBL_VOLT_VCCBRAM);
static SENSOR_DEVICE_ATTR(in3_input, 0444, nbl_hwmon_in_input_show, NULL, NBL_VOLT_VUSER0);
static SENSOR_DEVICE_ATTR(in4_input, 0444, nbl_hwmon_in_input_show, NULL, NBL_VOLT_VUSER1);
static SENSOR_DEVICE_ATTR(in5_input, 0444, nbl_hwmon_in_input_show, NULL, NBL_VOLT_VUSER2);
static SENSOR_DEVICE_ATTR(in6_input, 0444, nbl_hwmon_in_input_show, NULL, NBL_VOLT_VUSER3);

static struct attribute *hwmon_attributes[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_in0_input.dev_attr.attr,
	&sensor_dev_attr_in1_input.dev_attr.attr,
	&sensor_dev_attr_in2_input.dev_attr.attr,
	&sensor_dev_attr_in3_input.dev_attr.attr,
	&sensor_dev_attr_in4_input.dev_attr.attr,
	&sensor_dev_attr_in5_input.dev_attr.attr,
	&sensor_dev_attr_in6_input.dev_attr.attr,
	NULL,
};

static umode_t hwmon_attributes_visible(struct kobject __always_unused *kobj,
					struct attribute *attr, int __always_unused index)
{
	return attr->mode;
}

static const struct attribute_group hwmon_attrgroup = {
	.attrs = hwmon_attributes,
	.is_visible = hwmon_attributes_visible,
};

static const struct attribute_group *hwmon_groups[] = {
	&hwmon_attrgroup,
	NULL,
};

int nbl_hwmon_init(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct device *dev = nbl_adapter_to_dev(adapter);

	if (!is_af(hw))
		return 0;

	adapter->hwmon_dev = hwmon_device_register_with_groups(dev, "nbl_x4", adapter,
							       hwmon_groups);

	return PTR_ERR_OR_ZERO(adapter->hwmon_dev);
}

void nbl_hwmon_fini(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;

	if (!is_af(hw))
		return;

	if (adapter->hwmon_dev)
		hwmon_device_unregister(adapter->hwmon_dev);
}
