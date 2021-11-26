/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_RSS_H
#define SPNIC_RSS_H

#include "spnic_nic_dev.h"

int spnic_rss_init(struct spnic_nic_dev *nic_dev);

void spnic_rss_deinit(struct spnic_nic_dev *nic_dev);

int spnic_set_hw_rss_parameters(struct net_device *netdev, u8 rss_en, u8 num_tc, u8 *prio_tc);

void spnic_init_rss_parameters(struct net_device *netdev);

void spnic_set_default_rss_indir(struct net_device *netdev);

void spnic_try_to_enable_rss(struct spnic_nic_dev *nic_dev);

void spnic_clear_rss_config(struct spnic_nic_dev *nic_dev);

void spnic_flush_rx_flow_rule(struct spnic_nic_dev *nic_dev);
int spnic_ethtool_get_flow(struct spnic_nic_dev *nic_dev, struct ethtool_rxnfc *info, u32 location);

int spnic_ethtool_get_all_flows(struct spnic_nic_dev *nic_dev,
				struct ethtool_rxnfc *info, u32 *rule_locs);

int spnic_ethtool_flow_remove(struct spnic_nic_dev *nic_dev, u32 location);

int spnic_ethtool_flow_replace(struct spnic_nic_dev *nic_dev, struct ethtool_rx_flow_spec *fs);

/* for ethtool */
int spnic_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd, u32 *rule_locs);

int spnic_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd);

void spnic_get_channels(struct net_device *netdev, struct ethtool_channels *channels);

int spnic_set_channels(struct net_device *netdev, struct ethtool_channels *channels);

u32 spnic_get_rxfh_indir_size(struct net_device *netdev);

u32 spnic_get_rxfh_key_size(struct net_device *netdev);

int spnic_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc);

int spnic_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key, const u8 hfunc);

#endif
