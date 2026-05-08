// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_devlink.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_devlink.h"

#ifdef ESWITCH_MODE_SET_NEED_TWO_PRAMS
int sxe2_eswitch_mode_set(struct devlink *devlink, u16 mode)
#else
int sxe2_eswitch_mode_set(struct devlink *devlink, u16 mode,
			  struct netlink_ext_ack *extack)
#endif
{
#ifdef HAVE_METADATA_PORT_INFO
	s32 ret = 0;
	struct sxe2_adapter *adapter = devlink_priv(devlink);

	if (!test_bit(SXE2_FLAG_SWITCHDEV_CAPABLE, adapter->flags) &&
	    mode == DEVLINK_ESWITCH_MODE_SWITCHDEV) {
		ret = -EOPNOTSUPP;
		return ret;
	}

	if (sxe2_eswitch_mode_write_try_lock(adapter)) {
		LOG_DEV_INFO("PF %d get eswitchlock fail\n", adapter->pf_idx);
		ret = -EBUSY;
		goto l_end;
	}

	if (adapter->eswitch_ctxt.mode == mode)
		goto l_end;

	if (sxe2_vf_is_exist(adapter)) {
		LOG_DEV_INFO("changing eswitch mode is allowed only if there is no\t"
			     "VFs created.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		LOG_DEV_INFO("PF %d changed eswitch mode to legacy.\n",
			     adapter->pf_idx);
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
		if (sxe2_macvlan_is_enabled(adapter)) {
			LOG_DEV_ERR("PF %d switchdev cannot be configured L2\t"
				    "Forwarding Offload is currently enabled.\n",
				    adapter->pf_idx);
			ret = -EOPNOTSUPP;
			goto l_end;
		}
		LOG_DEV_INFO("PF %d changed eswitch mode to switchdev.\n",
			     adapter->pf_idx);
		break;
	default:
#ifndef ESWITCH_MODE_SET_NEED_TWO_PRAMS
		NL_SET_ERR_MSG_MOD(extack, "Unknown eswitch mode");
#endif
		ret = -EINVAL;
		goto l_end;
	}

	adapter->eswitch_ctxt.mode = mode;

l_end:
	sxe2_eswitch_mode_write_unlock(adapter);
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

int sxe2_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct sxe2_adapter *adapter = devlink_priv(devlink);

	*mode = adapter->eswitch_ctxt.mode;
	return 0;
}

static const struct devlink_ops sxe2_devlink_ops = {
#ifdef SUPPORTED_FLASH_UPDATE_PARAMS
		.supported_flash_update_params =
				DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK,
#endif
		.eswitch_mode_get = sxe2_eswitch_mode_get,
		.eswitch_mode_set = sxe2_eswitch_mode_set,
};

void sxe2_devlink_register(struct sxe2_adapter *adapter)
{
	struct devlink *devlink = priv_to_devlink(adapter);
#ifdef DEVLINK_REGISTER_NEED_2_PARAMS
	(void)devlink_register(devlink, &adapter->pdev->dev);
#else
	(void)devlink_register(devlink);
#endif
}

void sxe2_devlink_unregister(struct sxe2_adapter *adapter)
{
	devlink_unregister(priv_to_devlink(adapter));
}

void sxe2_adapter_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

struct sxe2_adapter *sxe2_adapter_create(struct pci_dev *pdev)
{
	struct sxe2_adapter *adapter;
	struct device *dev = &pdev->dev;
	const char *device_name = dev_name(dev);
	struct devlink *devlink;
	u32 device_len;
	size_t copy_result;

	devlink = devlink_alloc(&sxe2_devlink_ops, sizeof(struct sxe2_adapter), dev);
	if (!devlink)
		return NULL;

	if (devm_add_action_or_reset(dev, sxe2_adapter_free, devlink))
		return NULL;

	adapter = devlink_priv(devlink);
	adapter->pdev = pdev;

	device_len = (u32)(strlen(device_name) + 1);
	copy_result = SXE2_STRCPY(adapter->dev_name, device_name,
				  min_t(u32, device_len, DEV_NAME_LEN));
	if (copy_result >= DEV_NAME_LEN) {
		LOG_INFO_BDF("adapter:%pK, pdev:%pK, device_len:%u\n", adapter, pdev,
			     device_len);
	}
	sxe2_eswitch_mode_rwlock_init(adapter);
	LOG_INFO_BDF("adapter:%pK, pdev:%pK\n", adapter, pdev);

	return adapter;
}
