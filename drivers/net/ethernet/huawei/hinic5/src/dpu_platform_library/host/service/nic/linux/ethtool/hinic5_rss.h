/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_rss.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_RSS_H
#define HINIC5_RSS_H

#include "hinic5_nic_dev.h"

#define HINIC_NUM_IQ_PER_FUNC	8

int hinic5_rss_init(struct hinic5_nic_dev *nic_dev, u8 *rq2iq_map,
		    u32 map_size, u8 dcb_en);

void hinic5_rss_deinit(struct hinic5_nic_dev *nic_dev);

int hinic5_set_hw_rss_parameters(struct net_device *netdev, u8 rss_en,
				 u8 cos_num, u8 *cos_map, u8 dcb_en);

void hinic5_init_rss_parameters(struct net_device *netdev);

void hinic5_try_to_enable_rss(struct hinic5_nic_dev *nic_dev);

void hinic5_clear_rss_config(struct hinic5_nic_dev *nic_dev);

void hinic5_flush_rx_flow_rule(struct hinic5_nic_dev *nic_dev);
int hinic5_ethtool_get_flow(const struct hinic5_nic_dev *nic_dev,
			    struct ethtool_rxnfc *info, u32 location);

int hinic5_ethtool_get_all_flows(const struct hinic5_nic_dev *nic_dev,
				 struct ethtool_rxnfc *info, u32 *rule_locs);

int hinic5_ethtool_flow_remove(struct hinic5_nic_dev *nic_dev, u32 location);

int hinic5_ethtool_flow_replace(struct hinic5_nic_dev *nic_dev,
				struct ethtool_rx_flow_spec *fs);

bool hinic5_validate_channel_setting_in_ntuple(const struct hinic5_nic_dev *nic_dev, u32 q_num);

/* for ethtool */
#ifdef HAVE_ETHTOOL_GET_RXNFC_VOID_RULELOCS
int hinic5_get_rxnfc(struct net_device *netdev,
		     struct ethtool_rxnfc *cmd, void *rule_locs);
#else
int hinic5_get_rxnfc(struct net_device *netdev,
		     struct ethtool_rxnfc *cmd, u32 *rule_locs);
#endif

int hinic5_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd);

void hinic5_get_channels(struct net_device *netdev,
			 struct ethtool_channels *channels);

int hinic5_set_channels(struct net_device *netdev,
			struct ethtool_channels *channels);

#ifdef HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE
u32 hinic5_get_rxfh_indir_size(struct net_device *netdev);
#endif /* HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE */

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
u32 hinic5_get_rxfh_key_size(struct net_device *netdev);

#ifdef HAVE_ETHTOOL_RXFH_PARAM
int hinic5_get_rxfh(struct net_device *netdev, struct ethtool_rxfh_param *rxfh_param);
#elif defined HAVE_RXFH_HASHFUNC
int hinic5_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc);
#else /* HAVE_RXFH_HASHFUNC */
int hinic5_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key);
#endif /* HAVE_RXFH_HASHFUNC */

#ifdef HAVE_ETHTOOL_RXFH_PARAM
int hinic5_set_rxfh(struct net_device *netdev, struct ethtool_rxfh_param *rxfh_param,
		    struct netlink_ext_ack *extack);
#elif defined HAVE_RXFH_HASHFUNC
int hinic5_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key,
		    const u8 hfunc);
#else
#ifdef HAVE_RXFH_NONCONST
int hinic5_set_rxfh(struct net_device *netdev, u32 *indir, u8 *key);
#else
int hinic5_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key);
#endif /* HAVE_RXFH_NONCONST */
#endif /* HAVE_RXFH_HASHFUNC */

#else /* !(defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)) */

#ifdef HAVE_ETHTOOL_RXFH_INDIR_STRUCT_RXFH_INDIR
int hinic5_get_rxfh_indir(struct net_device *netdev,
			  struct ethtool_rxfh_indir *indir1);
#else
int hinic5_get_rxfh_indir(struct net_device *netdev, u32 *indir);
#endif

#ifdef HAVE_ETHTOOL_RXFH_INDIR_STRUCT_RXFH_INDIR
int hinic5_set_rxfh_indir(struct net_device *netdev,
			  const struct ethtool_rxfh_indir *indir1);
#else
int hinic5_set_rxfh_indir(struct net_device *netdev, const u32 *indir);
#endif /* HAVE_ETHTOOL_RXFH_INDIR_STRUCT_RXFH_INDIR */

#endif /* (defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)) */

#endif
