/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef __MCEVF_NETDEV_H_
#define __MCEVF_NETDEV_H_

/**
 * mcevf_netdev_to_pf - Retrieve the PF struct associated with a netdev
 * @netdev: pointer to the netdev struct
 */
static inline struct mcevf_pf *
mcevf_netdev_to_pf(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);

	return np->vsi->back;
}

int mcevf_cfg_netdev(struct mcevf_vsi *vsi);
int mcevf_register_netdev(struct mcevf_pf *pf);
int mcevf_open(struct net_device *netdev);
int mcevf_open_internal(struct net_device *netdev);
void mcevf_fetch_u64_stats_per_ring(struct mcevf_ring_stats *ring_stat,
				    u64 *pkts, u64 *bytes);
void mcevf_update_vsi_ring_stats(struct mcevf_vsi *vsi);

#endif /* __MCEVF_NETDEV_H_ */
