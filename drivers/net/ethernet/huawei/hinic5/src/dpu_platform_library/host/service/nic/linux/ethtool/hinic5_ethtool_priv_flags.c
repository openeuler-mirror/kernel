/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_priv_flags.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>

#include "drv_nic_api.h"
#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_ethtool.h"
#include "hinic5_ethtool_priv_flags.h"

u32 hinic5_get_priv_flags(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u32 priv_flags = 0;

	if (test_bit(HINIC5_SAME_RXTX, &nic_dev->flags))
		priv_flags |= HINIC5_PRIV_FLAGS_SYMM_RSS;

	if (test_bit(HINIC5_FORCE_LINK_UP, &nic_dev->flags))
		priv_flags |= HINIC5_PRIV_FLAGS_LINK_UP;

	if (test_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags))
		priv_flags |= HINIC5_PRIV_FLAGS_RXQ_RECOVERY;

	return priv_flags;
}

int hinic5_set_rxq_recovery_flag(struct net_device *netdev, u32 priv_flags)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	if ((priv_flags & HINIC5_PRIV_FLAGS_RXQ_RECOVERY) != 0) {
		if (HINIC5_SUPPORT_RXQ_RECOVERY(nic_dev->hwdev) == 0) {
			nicif_info(nic_dev, drv, netdev,
				   "Unsupport open rxq recovery\n");
			return -EOPNOTSUPP;
		}

		if (test_and_set_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags) != 0)
			return 0;
		queue_delayed_work(nic_dev->workq, &nic_dev->rxq_check_work, HZ);
		nicif_info(nic_dev, drv, netdev, "open rxq recovery\n");
	} else {
		if (test_and_clear_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags) == 0)
			return 0;
		cancel_delayed_work_sync(&nic_dev->rxq_check_work);
		nicif_info(nic_dev, drv, netdev, "close rxq recovery\n");
	}

	return 0;
}

static int hinic5_set_symm_rss_flag(struct net_device *netdev, u32 priv_flags)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	if ((priv_flags & HINIC5_PRIV_FLAGS_SYMM_RSS) != 0) {
		if (test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags) != 0) {
			nicif_err(nic_dev, drv, netdev,
				  "Failed to open Symmetric RSS while DCB is enabled\n");
			return -EOPNOTSUPP;
		}

		if (test_bit(HINIC5_RSS_ENABLE, &nic_dev->flags) == 0) {
			nicif_err(nic_dev, drv, netdev,
				  "Failed to open Symmetric RSS while RSS is disabled\n");
			return -EOPNOTSUPP;
		}

		set_bit(HINIC5_SAME_RXTX, &nic_dev->flags);
	} else {
		clear_bit(HINIC5_SAME_RXTX, &nic_dev->flags);
	}

	return 0;
}

static int hinic5_set_force_link_flag(struct net_device *netdev, u32 priv_flags)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u8 link_status = 0;
	int err;

	if ((priv_flags & HINIC5_PRIV_FLAGS_LINK_UP) != 0) {
		if (test_and_set_bit(HINIC5_FORCE_LINK_UP, &nic_dev->flags) != 0)
			return 0;

		if (!HINIC5_CHANNEL_RES_VALID(nic_dev))
			return 0;

		if (netif_carrier_ok(netdev))
			return 0;

		nic_dev->link_status = true;
		netif_carrier_on(netdev);
		nicif_info(nic_dev, link, netdev, "Set link up\n");

		if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
			hinic5_notify_all_vfs_link_changed(nic_dev->hwdev, nic_dev->link_status);
	} else {
		if (test_and_clear_bit(HINIC5_FORCE_LINK_UP, &nic_dev->flags) == 0)
			return 0;

		if (!HINIC5_CHANNEL_RES_VALID(nic_dev))
			return 0;

		err = hinic5_get_link_state(nic_dev->hwdev, &link_status);
		if (err != 0) {
			nicif_err(nic_dev, link, netdev,
				  "Get link state err: %d\n", err);
			return err;
		}

		nic_dev->link_status = link_status;

		if (link_status != 0) {
			if (netif_carrier_ok(netdev))
				return 0;

			netif_carrier_on(netdev);
			nicif_info(nic_dev, link, netdev, "Link state is up\n");
		} else {
			if (!netif_carrier_ok(netdev))
				return 0;

			netif_carrier_off(netdev);
			nicif_info(nic_dev, link, netdev, "Link state is down\n");
		}

		if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
			hinic5_notify_all_vfs_link_changed(nic_dev->hwdev, nic_dev->link_status);
	}

	return 0;
}

int hinic5_set_priv_flags(struct net_device *netdev, u32 priv_flags)
{
	int err;

	err = hinic5_set_symm_rss_flag(netdev, priv_flags);
	if (err != 0)
		return err;

	err = hinic5_set_rxq_recovery_flag(netdev, priv_flags);
	if (err != 0)
		return err;

	return hinic5_set_force_link_flag(netdev, priv_flags);
}
