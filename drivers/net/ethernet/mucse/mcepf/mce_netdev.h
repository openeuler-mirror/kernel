/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef __MCE_NETDEV_H_
#define __MCE_NETDEV_H_

#define mce_netdev_to_pf(netdev) \
	(((struct mce_netdev_priv *)netdev_priv(netdev))->vsi->back)
#define mce_pf_to_vf(pf) (&(pf)->vf)
#define mce_device_to_netdev(n) container_of(n, struct net_device, dev)

bool netif_is_mce(struct net_device *dev);
int mce_cfg_netdev(struct mce_vsi *vsi);
int mce_register_netdev(struct mce_pf *pf);
int mce_open(struct net_device *netdev);
void mce_check_tx_hang(struct mce_pf *pf);
void mce_update_vsi_ring_stats(struct mce_vsi *vsi);
void mce_udp_tunnel_prepare(struct mce_pf *pf);
void mce_set_rx_mode(struct net_device *netdev);
void mce_notify_fw_ifup_down(struct mce_pf *pf, bool up);
#endif /* __MCE_NETDEV_H_ */
