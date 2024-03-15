// SPDX-License-Identifier: GPL-2.0

#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/pci.h>
#include <linux/ptp_clock_kernel.h>

#include "../platform/ys_ndev.h"
#include "../platform/ys_pdev.h"
#include "ys_debug.h"

#define SFF_8024_ID_BYTE (0)
#define SFP_DIAG_MON_BYTE (92)
#define SFP_DIAG_MON_BIT (6)

static void ys_get_drvinfo(struct net_device *ndev,
			   struct ethtool_drvinfo *drvinfo)
{
	struct ys_ndev_priv *ndev_priv;
	size_t copy_len;

	ndev_priv = netdev_priv(ndev);
	copy_len = min(strlen(pci_name(ndev_priv->pdev)),
		       sizeof(drvinfo->bus_info) - 1);

	strscpy(drvinfo->driver, ndev_priv->pdev->driver->name,
		sizeof(drvinfo->driver));
	memcpy(drvinfo->bus_info, pci_name(ndev_priv->pdev), copy_len);
	drvinfo->bus_info[copy_len] = '\0';
}

static int ys_get_module_eeprom(struct net_device *ndev,
				struct ethtool_eeprom *eeep, u8 *data)
{
	return -EOPNOTSUPP;
}

static int ys_get_module_info(struct net_device *ndev,
			      struct ethtool_modinfo *modinfo)
{
	return -EOPNOTSUPP;
}

static void ys_get_ethtool_stats(struct net_device *ndev,
				 struct ethtool_stats *stats, u64 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int i;

	if (ndev_priv->ys_eth_hw->et_update_stats)
		ndev_priv->ys_eth_hw->et_update_stats(ndev);
	for (i = 0; i < ndev_priv->eth_string.stats_len; i++)
		data[i] = ndev_priv->eth_string.lan_stats[i];
}

static void ys_get_strings(struct net_device *ndev, u32 stringset, u8 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	switch (stringset) {
	case ETH_SS_TEST:
		if (ndev_priv->ys_eth_hw->et_get_self_strings)
			ndev_priv->ys_eth_hw->et_get_self_strings(ndev, data);
		break;
	case ETH_SS_STATS:
		if (ndev_priv->ys_eth_hw->et_get_stats_strings)
			ndev_priv->ys_eth_hw->et_get_stats_strings(ndev, data);
		break;
	case ETH_SS_PRIV_FLAGS:
		if (ndev_priv->ys_eth_hw->et_get_priv_strings)
			ndev_priv->ys_eth_hw->et_get_priv_strings(ndev, data);
		break;
	}
}

static int ys_get_sset_count(struct net_device *ndev, int sset)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	switch (sset) {
	case ETH_SS_TEST:
		if (ndev_priv->ys_eth_hw->et_get_self_count)
			return ndev_priv->ys_eth_hw->et_get_self_count(ndev);
		break;
	case ETH_SS_STATS:
		if (ndev_priv->ys_eth_hw->et_get_stats_count)
			return ndev_priv->ys_eth_hw->et_get_stats_count(ndev);
		break;
	case ETH_SS_PRIV_FLAGS:
		if (ndev_priv->ys_eth_hw->et_get_priv_count)
			return ndev_priv->ys_eth_hw->et_get_priv_count(ndev);
		break;
	default:
		break;
	}
	return 0;
}

static void ys_self_test(struct net_device *ndev, struct ethtool_test *eth_test,
			 u64 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 carrier_ok = 0;

	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		carrier_ok = netif_carrier_ok(ndev);
		if (carrier_ok)
			netif_carrier_off(ndev);
		netif_stop_queue(ndev);
		/* Wait until all tx queues are empty. */
		msleep(200);
		if (ndev_priv->ys_eth_hw->et_self_offline_test)
			ndev_priv->ys_eth_hw->et_self_offline_test(ndev,
				eth_test, data);
		if (carrier_ok)
			netif_carrier_on(ndev);
	} else {
		if (ndev_priv->ys_eth_hw->et_self_online_test)
			ndev_priv->ys_eth_hw->et_self_online_test(ndev,
				eth_test, data);
	}
}

static int ys_get_link_ksettings(struct net_device *ndev,
				 struct ethtool_link_ksettings *ksettings)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	ethtool_link_ksettings_zero_link_mode(ksettings, supported);
	ethtool_link_ksettings_zero_link_mode(ksettings, advertising);
	ethtool_link_ksettings_zero_link_mode(ksettings, lp_advertising);

	if (ndev_priv->ys_eth_hw->et_get_supported_advertising)
		ndev_priv->ys_eth_hw->et_get_supported_advertising(ksettings);
	if (ndev_priv->ys_eth_hw->et_get_link_speed)
		ndev_priv->ys_eth_hw->et_get_link_speed(ndev, ksettings);
	if (ndev_priv->ys_eth_hw->et_get_link_duplex)
		ndev_priv->ys_eth_hw->et_get_link_duplex(ndev, ksettings);
	if (ndev_priv->ys_eth_hw->et_get_link_autoneg)
		ndev_priv->ys_eth_hw->et_get_link_autoneg(ndev, ksettings);

	return 0;
}

static u32 ys_get_priv_flags(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 flag = 0;

	if (ndev_priv->ys_eth_hw->et_get_priv_flags)
		flag = ndev_priv->ys_eth_hw->et_get_priv_flags(ndev);
	return flag;
}

static int ys_set_priv_flags(struct net_device *ndev, u32 flag)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->et_set_priv_flags)
		ndev_priv->ys_eth_hw->et_set_priv_flags(ndev, flag);

	return 0;
}

static int ys_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec,
			   struct kernel_ethtool_coalesce *kec,
			   struct netlink_ext_ack *ack)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	ec->rx_coalesce_usecs = ndev_priv->ec->rx_coalesce_usecs;
	if (ndev_priv->ys_eth_hw->et_get_coalesce)
		ndev_priv->ys_eth_hw->et_get_coalesce(ndev, ec, kec, ack);

	return 0;
}

static int ys_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec,
			   struct kernel_ethtool_coalesce *kec,
			   struct netlink_ext_ack *ack)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	ndev_priv->ec->rx_coalesce_usecs = ec->rx_coalesce_usecs;
	if (ndev_priv->ys_eth_hw->et_set_coalesce)
		ndev_priv->ys_eth_hw->et_set_coalesce(ndev, ec, kec, ack);
	return 0;
}

static int ys_get_ts_info(struct net_device *ndev, struct ethtool_ts_info *eti)
{
	eti->so_timestamping = SOF_TIMESTAMPING_RX_SOFTWARE |
			       SOF_TIMESTAMPING_TX_SOFTWARE |
			       SOF_TIMESTAMPING_SOFTWARE;
	eti->phc_index = -1;
	eti->tx_types = 0;
	eti->rx_filters = 0;

	return 0;
}

static int ys_get_fecparam(struct net_device *ndev, struct ethtool_fecparam *fp)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->et_get_fec_mode)
		return ndev_priv->ys_eth_hw->et_get_fec_mode(ndev, fp);
	return 0;
}

static int ys_set_fecparam(struct net_device *ndev, struct ethtool_fecparam *fp)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->et_set_fec_mode)
		return ndev_priv->ys_eth_hw->et_set_fec_mode(ndev, fp);
	return 0;
}

int ys_ethtool_hw_init(struct net_device *ndev)
{
	struct ys_ethtool_hw_ops *eth_hw_ops;
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);
	eth_hw_ops = kzalloc(sizeof(*eth_hw_ops), GFP_KERNEL);

	if (!eth_hw_ops)
		return -ENOMEM;

	ndev_priv->ys_eth_hw = eth_hw_ops;

	return 0;
}

void ys_ethtool_hw_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!ndev_priv->ys_eth_hw)
		kfree(ndev_priv->ys_eth_hw);
}

static int ys_get_rxnfc_eth(struct net_device *ndev,
			    struct ethtool_rxnfc *info,
			    u32 *rules __always_unused)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->ys_get_rxnfc)
		return ndev_priv->ys_eth_hw->ys_get_rxnfc(ndev, info);
	return 0;
}

static int ys_set_rxnfc_eth(struct net_device *ndev,
			    struct ethtool_rxnfc *rxnfc)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->ys_set_rxnfc)
		return ndev_priv->ys_eth_hw->ys_set_rxnfc(ndev, rxnfc);
	return 0;
}

static u32 ys_get_rxfh_indir_size_eth(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->ys_get_rxfh_indir_size)
		return ndev_priv->ys_eth_hw->ys_get_rxfh_indir_size(ndev);
	return 0;
}

static u32 ys_get_rxfh_key_size_eth(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->ys_get_rxfh_key_size)
		return ndev_priv->ys_eth_hw->ys_get_rxfh_key_size(ndev);
	return 0;
}

static int ys_get_rxfh_eth(struct net_device *ndev, u32 *indir, u8 *key,
			   u8 *hfunc)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->ys_get_rxfh)
		return ndev_priv->ys_eth_hw->ys_get_rxfh(ndev, indir, key,
							 hfunc);
	return 0;
}

static int ys_set_rxfh_eth(struct net_device *ndev, const u32 *indir,
			   const u8 *key, const u8 hfunc)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->ys_eth_hw->ys_set_rxfh)
		return ndev_priv->ys_eth_hw->ys_set_rxfh(ndev, indir, key,
							 hfunc);
	return 0;
}

const struct ethtool_ops ys_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS,
	.get_drvinfo = ys_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ethtool_stats = ys_get_ethtool_stats,
	.get_strings = ys_get_strings,
	.get_sset_count = ys_get_sset_count,
	.get_module_eeprom = ys_get_module_eeprom,
	.get_module_info = ys_get_module_info,
	.self_test = ys_self_test,
	.get_link_ksettings = ys_get_link_ksettings,
	.get_priv_flags = ys_get_priv_flags,
	.set_priv_flags = ys_set_priv_flags,
	.get_coalesce = ys_get_coalesce,
	.set_coalesce = ys_set_coalesce,
	.get_ts_info = ys_get_ts_info,
	.get_fecparam = ys_get_fecparam,
	.set_fecparam = ys_set_fecparam,
	.get_rxfh_indir_size = ys_get_rxfh_indir_size_eth,
	.get_rxfh_key_size = ys_get_rxfh_key_size_eth,
	.get_rxfh = ys_get_rxfh_eth,
	.set_rxfh = ys_set_rxfh_eth,
	.get_rxnfc = ys_get_rxnfc_eth,
	.set_rxnfc = ys_set_rxnfc_eth,
};
