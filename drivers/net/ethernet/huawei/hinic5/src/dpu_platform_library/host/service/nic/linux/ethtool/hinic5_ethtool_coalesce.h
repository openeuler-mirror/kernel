/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_coalesce.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_ETHTOOL_COALESCE_H
#define HINIC5_ETHTOOL_COALESCE_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

struct hinic5_nic_dev;
struct hinic5_qp_coalesce_info;

/* Coalesce configuration functions */
int get_coalesce(struct net_device *netdev, struct ethtool_coalesce *coal, u16 queue);
int set_queue_coalesce(struct hinic5_nic_dev *nic_dev, u16 q_id,
		       const struct hinic5_qp_coalesce_info *coal);
int is_coalesce_exceed_limit(struct net_device *netdev,
			     const struct ethtool_coalesce *coal);
void tmp_coal_init(struct ethtool_coalesce *tmp_coal, const struct ethtool_coalesce *coal);
int is_coalesce_legal(struct net_device *netdev, const struct ethtool_coalesce *coal);
int set_hw_coal_param(struct hinic5_nic_dev *nic_dev,
		      struct hinic5_qp_coalesce_info *intr_coal, u16 queue);
void check_coalesce_align(struct net_device *netdev, const struct ethtool_coalesce *coal);
int check_coalesce_change(struct net_device *netdev, u16 queue,
			  const struct ethtool_coalesce *coal);
void init_intr_coal_params(struct hinic5_qp_coalesce_info *intr_coal,
			   struct ethtool_coalesce *coal);
int set_coalesce(struct net_device *netdev, struct ethtool_coalesce *coal, u16 queue);

#endif /* HINIC5_ETHTOOL_COALESCE_H */
