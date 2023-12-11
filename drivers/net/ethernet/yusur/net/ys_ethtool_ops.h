/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_ETHTOOL_OPS_H_
#define __YS_ETHTOOL_OPS_H_

#define STATS_SCHEDULE_DELAY 18999998
extern const struct ethtool_ops ys_ethtool_ops;

struct ys_ethtool_hw_ops {
	void (*et_update_stats)(struct net_device *ndev);
	void (*et_get_self_strings)(struct net_device *ndev, u8 *data);
	void (*et_get_stats_strings)(struct net_device *ndev, u8 *data);
	void (*et_get_priv_strings)(struct net_device *ndev, u8 *data);
	int (*et_get_self_count)(struct net_device *ndev);
	int (*et_get_stats_count)(struct net_device *ndev);
	int (*et_get_priv_count)(struct net_device *ndev);
	void (*et_self_offline_test)(struct net_device *ndev,
				     struct ethtool_test *eth_test, u64 *data);
	void (*et_self_online_test)(struct net_device *ndev,
				    struct ethtool_test *eth_test, u64 *data);
	void (*et_check_link)(struct net_device *ndev);
	void (*et_get_supported_advertising)(struct ethtool_link_ksettings
			*ksettings);
	void (*et_get_link_speed)(struct net_device *ndev,
				  struct ethtool_link_ksettings *ksettings);
	void (*et_get_link_duplex)(struct net_device *ndev,
				   struct ethtool_link_ksettings *ksettings);
	void (*et_get_link_autoneg)(struct net_device *ndev,
				    struct ethtool_link_ksettings *ksettings);
	u32 (*et_get_priv_flags)(struct net_device *ndev);
	u32 (*et_set_priv_flags)(struct net_device *ndev, u32 flag);
	int (*et_get_coalesce)(struct net_device *ndev,
			       struct ethtool_coalesce *ec,
			       struct kernel_ethtool_coalesce *kec,
			       struct netlink_ext_ack *ack);
	int (*et_set_coalesce)(struct net_device *ndev,
			       struct ethtool_coalesce *ec,
			       struct kernel_ethtool_coalesce *kec,
			       struct netlink_ext_ack *ack);
	int (*et_get_fec_mode)(struct net_device *ndev,
			       struct ethtool_fecparam *fp);
	int (*et_set_fec_mode)(struct net_device *ndev,
			       struct ethtool_fecparam *fp);
	int (*enable_mac)(struct net_device *ndev);

	int (*ys_set_rxfh)(struct net_device *ndev, const u32 *indir,
			   const u8 *key, const u8 hfunc);

	int (*ys_get_rxfh)(struct net_device *ndev, u32 *indir, u8 *key,
			   u8 *hfunc);
	u32 (*ys_get_rxfh_key_size)(struct net_device *dev);
	u32 (*ys_get_rxfh_indir_size)(struct net_device *dev);
	int (*ys_set_rxnfc)(struct net_device *ndev,
			    struct ethtool_rxnfc *rxnfc);
	int (*ys_get_rxnfc)(struct net_device *ndev,
			    struct ethtool_rxnfc *info);
};

int ys_ethtool_hw_init(struct net_device *ndev);
void ys_ethtool_hw_uninit(struct net_device *ndev);

#endif /* __YS_ETHTOOL_OPS_H_ */
