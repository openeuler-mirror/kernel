/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_lb_test.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_ETHTOOL_LB_TEST_H
#define HINIC5_ETHTOOL_LB_TEST_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#define PORT_DOWN_ERR_IDX    0
#define LP_DEFAULT_TIME      5    /* seconds */
#define TEST_TIME_MULTIPLE   5
#define HINIC5_INTERNAL_LP_MODE 5

enum diag_test_index {
	INTERNAL_LP_TEST = 0,
	EXTERNAL_LP_TEST = 1,
	DIAG_TEST_MAX = 2,
};

struct hinic5_nic_dev;

/* Loopback test functions */
void hinic5_run_lp_init_data(struct ethhdr *eth_hdr, struct sk_buff *skb_tmp,
			     const struct hinic5_nic_dev *nic_dev);
int hinic5_run_lp_test(struct hinic5_nic_dev *nic_dev, u32 test_time);
int do_lp_test(struct hinic5_nic_dev *nic_dev, u32 *flags, u32 test_time,
	       enum diag_test_index *test_index);
void hinic5_lp_test(struct net_device *netdev, struct ethtool_test *eth_test,
		    u64 *data, u32 test_time);
void hinic5_diag_test(struct net_device *netdev, struct ethtool_test *eth_test,
		      u64 *data);

#endif /* HINIC5_ETHTOOL_LB_TEST_H */
