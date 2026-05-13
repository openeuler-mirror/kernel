/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_LB_H__
#define __UNIC_LB_H__

#include <linux/ethtool.h>
#include <linux/netdevice.h>

int unic_get_selftest_count(struct unic_dev *unic_dev);
void unic_self_test(struct net_device *ndev,
		    struct ethtool_test *eth_test, u64 *data);

#endif /* __UNIC_LB_H__ */
