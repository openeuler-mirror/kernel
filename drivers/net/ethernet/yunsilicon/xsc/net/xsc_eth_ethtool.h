/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ETH_ETHTOOL_H
#define XSC_ETH_ETHTOOL_H

typedef int (*xsc_pflag_handler)(struct net_device *dev, bool enable);

struct pflag_desc {
	char name[ETH_GSTRING_LEN];
	xsc_pflag_handler handler;
};

void eth_set_ethtool_ops(struct net_device *dev);
void xsc_rep_ethtool_get_stats(struct xsc_adapter *adapter,
			       struct ethtool_stats *stats, u64 *data);
void xsc_rep_fill_stats_strings(struct xsc_adapter *adapter, u8 *data);
unsigned int xsc_rep_stats_total_num(struct xsc_adapter *adapter);
void xsc_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info);
int xsc_get_link_ksettings(struct net_device *netdev,
			   struct ethtool_link_ksettings *cmd);
int xsc_set_link_ksettings(struct net_device *netdev,
			   const struct ethtool_link_ksettings *cmd);
int xsc_set_channels(struct net_device *dev, struct ethtool_channels *ch);
void xsc_get_channels(struct net_device *dev, struct ethtool_channels *ch);
u32 xsc_get_rxfh_key_size(struct net_device *dev);
u32 xsc_get_rxfh_indir_size(struct net_device *netdev);
unsigned int xsc_stats_total_num(struct xsc_adapter *adapter);
u32 xsc_get_priv_flags(struct net_device *dev);
int xsc_set_priv_flags(struct net_device *dev, u32 pflags);

int xsc_get_coalesce(struct net_device *netdev,
		     struct ethtool_coalesce *coal,
		     struct kernel_ethtool_coalesce *kernel_coal,
		     struct netlink_ext_ack *extack);
int xsc_set_coalesce(struct net_device *netdev,
		     struct ethtool_coalesce *coal,
		     struct kernel_ethtool_coalesce *kernel_coal,
		     struct netlink_ext_ack *extack);

void xsc_get_ringparam(struct net_device *dev,
		       struct ethtool_ringparam *param,
		       struct kernel_ethtool_ringparam *kernel_param,
		       struct netlink_ext_ack *extack);

int xsc_set_ringparam(struct net_device *dev,
		      struct ethtool_ringparam *param,
		      struct kernel_ethtool_ringparam *kernel_param,
		      struct netlink_ext_ack *extack);

/* EEPROM Standards for plug in modules */
#ifndef ETH_MODULE_SFF_8436_MAX_LEN
#define ETH_MODULE_SFF_8636_MAX_LEN     640
#define ETH_MODULE_SFF_8436_MAX_LEN     640
#endif

#define LED_ACT_ON_HW 0xff

#endif /* XSC_ETH_ETHTOOL_H */
