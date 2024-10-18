// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include "nbl_hwmon.h"

static const char * const nbl_hwmon_sensor_name[] = {
	"Sensor0",
	"Module0",
	"Module1",
	"Module2",
	"Module3",
};

static umode_t nbl_hwmon_is_visible(const void *data, enum hwmon_sensor_types type,
				    u32 attr, int channel)
{
	return NBL_HWMON_VISIBLE;
}

static int nbl_hwmon_read(struct device *dev, enum hwmon_sensor_types type,
			  u32 attr, int channel, long *val)
{
	struct nbl_adapter *adapter = dev_get_drvdata(dev);
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	u32 temp;

	switch (channel) {
	case NBL_HWMON_CHIP_SENSOR:
		switch (attr) {
		case hwmon_temp_input:
			temp = serv_ops->get_chip_temperature(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
			*val = (temp & NBL_HWMON_TEMP_MAP) * NBL_HWMON_TEMP_UNIT;
			return 0;
		case hwmon_temp_max:
			temp = serv_ops->get_chip_temperature_max
				(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
			*val = temp * NBL_HWMON_TEMP_UNIT;
			return 0;
		case hwmon_temp_crit:
			temp = serv_ops->get_chip_temperature_crit
				(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
			*val = temp * NBL_HWMON_TEMP_UNIT;
			return 0;
		case hwmon_temp_highest:
			temp = serv_ops->get_chip_temperature(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
			*val = (temp >> NBL_HWMON_TEMP_OFF) * NBL_HWMON_TEMP_UNIT;
			return 0;
		default:
			return -EOPNOTSUPP;
		}
	case NBL_HWMON_LIGHT_MODULE:
		switch (attr) {
		case hwmon_temp_input:
			temp = serv_ops->get_module_temperature(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
								eth_id, NBL_MODULE_TEMP);
			*val = temp * NBL_HWMON_TEMP_UNIT;
			return 0;
		case hwmon_temp_max:
			temp = serv_ops->get_module_temperature(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
								eth_id, NBL_MODULE_TEMP_MAX);
			*val = temp * NBL_HWMON_TEMP_UNIT;
			return 0;
		case hwmon_temp_crit:
			temp = serv_ops->get_module_temperature(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
								eth_id, NBL_MODULE_TEMP_CRIT);
			*val = temp * NBL_HWMON_TEMP_UNIT;
			return 0;
		default:
			return -EOPNOTSUPP;
		}
	default:
		return -EOPNOTSUPP;
	}
}

static __maybe_unused int nbl_hwmon_read_string(struct device *dev, enum hwmon_sensor_types type,
						u32 attr, int channel, const char **str)
{
	struct nbl_adapter *adapter = dev_get_drvdata(dev);
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	u8 func_id = NBL_COMMON_TO_PCI_FUNC_ID(common);

	switch (channel) {
	case NBL_HWMON_CHIP_SENSOR:
		*str = nbl_hwmon_sensor_name[channel];
		return 0;
	case NBL_HWMON_LIGHT_MODULE:
		*str = nbl_hwmon_sensor_name[channel + func_id];
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct hwmon_channel_info *nbl_hwmon_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   HWMON_T_INPUT | HWMON_T_MAX | HWMON_T_CRIT |
			   HWMON_T_HIGHEST | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_MAX | HWMON_T_CRIT | HWMON_T_LABEL),
	NULL
};

static const struct hwmon_ops nbl_hwmon_ops = {
	.is_visible = nbl_hwmon_is_visible,
	.read = nbl_hwmon_read,
	.read_string = nbl_hwmon_read_string,
};

static const struct hwmon_chip_info nbl_hwmon_chip_info = {
	.ops = &nbl_hwmon_ops,
	.info = nbl_hwmon_info,
};

int nbl_dev_setup_hwmon(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);
	struct device *dev = NBL_DEV_MGT_TO_DEV(dev_mgt);

	common_dev->hwmon_dev = hwmon_device_register_with_info(dev, "nbl", adapter,
								&nbl_hwmon_chip_info, NULL);

	return PTR_ERR_OR_ZERO(common_dev->hwmon_dev);
}

void nbl_dev_remove_hwmon(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_common *common_dev = NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt);

	if (common_dev->hwmon_dev)
		hwmon_device_unregister(common_dev->hwmon_dev);
}
