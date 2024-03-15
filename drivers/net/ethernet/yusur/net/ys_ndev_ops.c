// SPDX-License-Identifier: GPL-2.0

#include <linux/netdevice.h>
#include <net/neighbour.h>
#include <linux/iopoll.h>
#include "ys_ndev_ops.h"

#include "../platform/ys_ndev.h"
#include "../platform/ys_pdev.h"
#include "ys_debug.h"

static void ys_ndo_update_stats(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!(ndev->flags & IFF_UP))
		return;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_update_stat))
		pdev_priv->ops->hw_adp_update_stat(ndev);

	ndev->stats.tx_packets = ndev_priv->netdev_stats.tx_packets;
	ndev->stats.tx_bytes = ndev_priv->netdev_stats.tx_bytes;
	ndev->stats.rx_packets = ndev_priv->netdev_stats.rx_packets;
	ndev->stats.rx_bytes = ndev_priv->netdev_stats.rx_bytes;

	ndev->stats.tx_dropped = ndev_priv->netdev_stats.tx_dropped;
	ndev->stats.tx_errors = ndev_priv->netdev_stats.tx_errors;
	ndev->stats.rx_dropped = ndev_priv->netdev_stats.rx_dropped;
	ndev->stats.rx_errors = ndev_priv->netdev_stats.rx_errors;
}

static int ys_ndo_start(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	int ret;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_start)) {
		ret = pdev_priv->ops->hw_adp_start(ndev);
		if (ret)
			return ret;
	}

	netif_tx_start_all_queues(ndev);
	netif_device_attach(ndev);
	netif_carrier_on(ndev);
	return 0;
}

static int ys_ndo_stop(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	netif_tx_lock_bh(ndev);
	netif_tx_stop_all_queues(ndev);
	netif_tx_unlock_bh(ndev);
	netif_tx_disable(ndev);

	spin_lock_bh(&ndev_priv->stats_lock);
	ys_ndo_update_stats(ndev);
	spin_unlock_bh(&ndev_priv->stats_lock);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_stop))
		pdev_priv->ops->hw_adp_stop(ndev);

	netif_carrier_off(ndev);
	return 0;
}

static int ys_ndo_open(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = 0;

	mutex_lock(&ndev_priv->state_lock);
	ret = ys_ndo_start(ndev);
	if (ret)
		ys_net_err("Failed to start port: %d", ndev->dev_port);

	mutex_unlock(&ndev_priv->state_lock);
	return ret;
}

static int ys_ndo_close(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = 0;

	mutex_lock(&ndev_priv->state_lock);

	ret = ys_ndo_stop(ndev);
	if (ret)
		ys_net_err("Failed to stop port: %d", ndev->dev_port);

	mutex_unlock(&ndev_priv->state_lock);
	return ret;
}

static netdev_tx_t ys_ndo_start_xmit(struct sk_buff *skb,
				     struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_send))
		return pdev_priv->ops->hw_adp_send(skb, ndev);
	else
		return NETDEV_TX_BUSY;
}

static int ys_ndo_set_mac(struct net_device *ndev, void *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct sockaddr *saddr = addr;
	u8 dev_addr[6];
	int ret;

	memcpy(dev_addr, saddr->sa_data, ETH_ALEN);

	if (!is_valid_ether_addr(dev_addr))
		return -EADDRNOTAVAIL;

	eth_hw_addr_set(ndev, dev_addr);
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_cfg)) {
		ret = ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, 0);
		if (ret)
			return ret;
	}
	ys_net_info("Set MAC address to %02x:%02x:%02x:%02x:%02x:%02x",
		    dev_addr[0], dev_addr[1], dev_addr[2], dev_addr[3],
		    dev_addr[4], dev_addr[5]);

	return 0;
}

static int ys_ndo_hwtstamp_set(struct net_device *ndev, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static int ys_ndo_hwtstamp_get(struct net_device *ndev, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static int ys_ndo_ioctl(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCSHWTSTAMP:
		return ys_ndo_hwtstamp_set(ndev, ifr);
	case SIOCGHWTSTAMP:
		return ys_ndo_hwtstamp_get(ndev, ifr);

	default:
		return -EOPNOTSUPP;
	}
}

static int ys_ndo_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	bool is_running = false;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (new_mtu < ndev->min_mtu || new_mtu > ndev->max_mtu) {
		ys_net_err("Bad MTU: %d", new_mtu);
		return -EPERM;
	}

	ys_net_info("New MTU: %d", new_mtu);

	ndev->mtu = new_mtu;
	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_running))
		is_running = pdev_priv->ops->hw_adp_running(ndev);

	if (is_running || netif_running(ndev)) {
		mutex_lock(&ndev_priv->state_lock);
		netif_tx_disable(ndev);
		ys_ndo_stop(ndev);
		if (ndev_priv->ys_ndev_hw->ys_ndev_change_mtu)
			ndev_priv->ys_ndev_hw->ys_ndev_change_mtu(ndev,
								  new_mtu);
		ys_ndo_start(ndev);
		netif_wake_queue(ndev);
		mutex_unlock(&ndev_priv->state_lock);
	}
	return 0;
}

static void ys_ndo_get_stats64(struct net_device *ndev,
			       struct rtnl_link_stats64 *stats)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	spin_lock_bh(&ndev_priv->stats_lock);
	ys_ndo_update_stats(ndev);
	netdev_stats_to_stats64(stats, &ndev->stats);
	spin_unlock_bh(&ndev_priv->stats_lock);
}

static void ys_change_rx_flags(struct net_device *ndev, int flags)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = 0;

	if (!(ndev->flags & IFF_UP))
		return;

	if (flags & IFF_PROMISC) {
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_rx_flags))
			ret = ndev_priv->ys_ndev_hw->ys_set_rx_flags(ndev);
		if (ret)
			ys_net_info("update switch table failed");
	}
}

static int ys_set_features(struct net_device *ndev, netdev_features_t features)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_features_set))
		return -EOPNOTSUPP;

	ndev_priv->ys_ndev_hw->ys_features_set(ndev, features);
	ndev->features = features;

	return 0;
}

static int ys_mc_addr_sync(struct net_device *ndev, const u8 *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	/* ipv6 multicast does not need to update the mac address */
	if (addr[0] == 0x33 && addr[1] == 0x33)
		return 0;
	if (ndev_priv->ys_ndev_hw->ys_set_mc_mac)
		return ndev_priv->ys_ndev_hw->ys_set_mc_mac(ndev, addr, 1);
	return 0;
}

static int ys_mc_addr_unsync(struct net_device *ndev, const u8 *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	/* ipv6 multicast does not need to update the mac address */
	if (addr[0] == 0x33 && addr[1] == 0x33)
		return 0;

	if (ndev_priv->ys_ndev_hw->ys_set_mc_mac)
		return ndev_priv->ys_ndev_hw->ys_set_mc_mac(ndev, addr, 0);
	return 0;
}

static void ys_set_rx_mode(struct net_device *ndev)
{
	__dev_mc_sync(ndev, ys_mc_addr_sync, ys_mc_addr_unsync);
}

int ys_ndev_hw_init(struct net_device *ndev)
{
	struct ys_ndev_hw_ops *ndev_hw_ops;
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);
	ndev_hw_ops = kzalloc(sizeof(*ndev_hw_ops), GFP_KERNEL);

	if (!ndev_hw_ops)
		return -ENOMEM;

	ndev_priv->ys_ndev_hw = ndev_hw_ops;

	return 0;
}

int ys_ndev_hw_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!ndev_priv->ys_ndev_hw)
		kfree(ndev_priv->ys_ndev_hw);
	return 0;
}

const struct net_device_ops ys_ndev_ops = {
	.ndo_open = ys_ndo_open,
	.ndo_stop = ys_ndo_close,
	.ndo_start_xmit = ys_ndo_start_xmit,
	.ndo_set_mac_address = ys_ndo_set_mac,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_do_ioctl = ys_ndo_ioctl,
	.ndo_change_mtu = ys_ndo_change_mtu,
	.ndo_get_stats64 = ys_ndo_get_stats64,
	.ndo_change_rx_flags = ys_change_rx_flags,
	.ndo_set_rx_mode = ys_set_rx_mode,
	.ndo_set_features = ys_set_features,
};
