/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HNS3_EXT_H
#define __HNS3_EXT_H
#include <linux/types.h>
#include "../hns3_enet.h"
#include "hns3pf/hclge_ext.h"
#include "hns3pf/hclge_main_it.h"

/**
 * nic_chip_recover_handler - reset net device by port id
 * @netdev:	net device
 * @hnae3_reset_type:	nic device event type
 */
void nic_chip_recover_handler(struct net_device *netdev,
			      enum hnae3_reset_type_custom event_t);
int nic_netdev_match_check(struct net_device *netdev);
int nic_clean_stats64(struct net_device *netdev,
		      struct rtnl_link_stats64 *stats);
int nic_get_sfpinfo(struct net_device *netdev, u8 *buff, u16 size, u16 *outlen);
int nic_set_sfp_state(struct net_device *netdev, bool en);
int nic_get_sfp_id(struct net_device *netdev, u32 *sfp_id);
int nic_get_port_num_per_chip(struct net_device *ndev, u32 *port_num);
int nic_get_chip_num(struct net_device *ndev, u32 *chip_num);
int nic_set_led(struct net_device *ndev, int type, int status);
int nic_disable_net_lane(struct net_device *ndev);
int nic_get_net_lane_status(struct net_device *ndev,  u32 *status);
int nic_set_cpu_affinity(struct net_device *netdev, cpumask_t *affinity_mask);
int nic_get_led_signal(struct net_device *ndev,
		       struct hns3_lamp_signal *signal);
int nic_set_mac_state(struct net_device *ndev,  int enable);
int nic_disable_clock(struct net_device *ndev);

#endif
