// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf_lib.h"
#include "mcevf_netdev.h"
#include "mcevf_txrx.h"
#include "mcevf_irq.h"
#include <net/dsfield.h>

/**
 * mcevf_open_internal - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * Internal mcevf_open implementation. Should not be used directly except for mcevf_open and reset
 * handling routine
 *
 * Returns 0 on success, negative value on failure
 */
int mcevf_open_internal(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	int err = 0;

	if (test_bit(MCEVF_NEEDS_RESTART, pf->state)) {
		netdev_err(netdev,
			   "driver needs to be unloaded and reloaded\n");
		return -EIO;
	}

	netif_carrier_off(netdev);

	err = mcevf_vsi_open(vsi);
	if (err)
		netdev_err(netdev, "Failed to open VSI 0x%04X\n",
			   vsi->idx);
	/* Update existing tunnel information. */
	udp_tunnel_get_rx_info(netdev);
	if (netif_msg_ifup(pf))
		netdev_info(netdev, "open");

	set_bit(MCEVF_FLAG_PF_UPDATE_LINK, pf->flags);
	set_bit(MCEVF_FLAG_VF_NDO_OPENED, pf->flags);
	mcevf_service_task_schedule(pf);
	return err;
}

/**
 * mcevf_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP). At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
int mcevf_open(struct net_device *netdev)
{
	return mcevf_open_internal(netdev);
}

/**
 * mcevf_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state. The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
static int mcevf_stop(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;

	clear_bit(MCEVF_FLAG_VF_NDO_OPENED, vsi->back->flags);
	mcevf_vsi_close(vsi);
	if (netif_msg_ifdown(vsi->back))
		netdev_info(netdev, "close");

	return 0;
}

#define MCEVF_TXD_CTX_MIN_MSS 64
#define MCEVF_MAX_TUNNEL_HDR_LEN 80
#define MCEVF_MAX_MAC_HDR_LEN 127
#define MCEVF_MAX_NETWORK_HDR_LEN 511
/**
 * mcevf_features_check - Validate encapsulated packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t
mcevf_features_check(struct sk_buff *skb,
		     struct net_device __always_unused *netdev,
		     netdev_features_t features)
{
	bool gso = skb_is_gso(skb);
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 64 bytes. If it is then we need to drop support for GSO.
	 */
	if (gso && (skb_shinfo(skb)->gso_size < MCEVF_TXD_CTX_MIN_MSS))
		features &= ~NETIF_F_GSO_MASK;

	len = skb_network_offset(skb);
	if (len > MCEVF_MAX_MAC_HDR_LEN /* || len & 0x1 */)
		goto out_rm_features;

	len = skb_network_header_len(skb);
	if (len > MCEVF_MAX_NETWORK_HDR_LEN /* || len & 0x1 */)
		goto out_rm_features;

	if (skb->encapsulation) {
		/* this must work for VXLAN frames AND IPIP/SIT frames, and in
		 * the case of IPIP frames, the transport header pointer is
		 * after the inner header! So check to make sure that this
		 * is a GRE or UDP_TUNNEL frame before doing that math.
		 */
		if (gso && (skb_shinfo(skb)->gso_type &
			    (SKB_GSO_GRE | SKB_GSO_UDP_TUNNEL))) {
			len = skb_inner_network_header(skb) -
			      skb_transport_header(skb);
			if (len >
			    MCEVF_MAX_TUNNEL_HDR_LEN /* || len & 0x1 */)
				goto out_rm_features;
		}

		len = skb_inner_network_header_len(skb);
		if (len > MCEVF_MAX_NETWORK_HDR_LEN /* || len & 0x1 */)
			goto out_rm_features;
	}

	return features;
out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

/**
 * mcevf_fetch_u64_stats_per_ring - get packets and bytes stats per ring
 * @ring_stat: Tx or Rx stats to read from
 * @pkts: packets stats counter
 * @bytes: bytes stats counter
 *
 * This function fetches stats from the ring considering the atomic operations
 * that needs to be performed to read u64 values in 32 bit machine.
 */
void mcevf_fetch_u64_stats_per_ring(struct mcevf_ring_stats *ring_stat,
				    u64 *pkts, u64 *bytes)
{
	unsigned int start;
	*pkts = 0;
	*bytes = 0;

	if (!ring_stat)
		return;
	do {
		start = u64_stats_fetch_begin(&ring_stat->syncp);
		*pkts = ring_stat->stats.pkts;
		*bytes = ring_stat->stats.bytes;
	} while (u64_stats_fetch_retry(&ring_stat->syncp, start));
}

/**
 * mcevf_update_vsi_tx_ring_stats - Update VSI Tx ring stats counters
 * @vsi: the VSI to be updated
 * @vsi_stats: the stats struct to be updated
 * @rings: rings to work on
 * @count: number of rings
 */
static void
mcevf_update_vsi_tx_ring_stats(struct mcevf_vsi *vsi,
			       struct rtnl_link_stats64 *vsi_stats,
				 struct mcevf_ring **rings, u16 count)
{
	struct mcevf_hw *hw = &vsi->back->hw;
	u16 i;

	if (!rings)
		return;

	for (i = 0; i < count; i++) {
		struct mcevf_ring *ring;
		struct mcevf_ring_stats *ring_stat;
		u64 pkts, bytes;

		ring = READ_ONCE(rings[i]);
		if (!ring)
			continue;
		ring_stat = ring->ring_stats;
		if (!ring_stat)
			continue;
		mcevf_fetch_u64_stats_per_ring(ring_stat, &pkts, &bytes);
		ring_stat->tx_stats.bytes = bytes;
		ring_stat->tx_stats.pkts = pkts;
#if __MCEVF_GET_RING_STATS_BY_HW
		ring_stat->tx_stats.multicast = hw->ops->get_hw_ring_stats(ring,
								    MCEVF_HW_R_STATS_TX_MULTICAST);
		ring_stat->tx_stats.broadcast = hw->ops->get_hw_ring_stats(ring,
								    MCEVF_HW_R_STATS_TX_BROADCAST);
		ring_stat->tx_stats.unicast = pkts -
			ring_stat->tx_stats.multicast -
			ring_stat->tx_stats.broadcast;
#endif
		vsi_stats->tx_packets += pkts;
		vsi_stats->tx_bytes += bytes;

		vsi->tx_restart += ring->ring_stats->tx_stats.restart_q;
		vsi->tx_busy += ring->ring_stats->tx_stats.tx_busy;
		vsi->tx_linearize +=
			ring->ring_stats->tx_stats.tx_linearize;
#if __MCEVF_GET_RING_STATS_BY_HW
		vsi->ofld_stats.tx_unicast +=
			ring->ring_stats->tx_stats.unicast;
		vsi->ofld_stats.tx_multicast +=
			ring->ring_stats->tx_stats.multicast;
		vsi->ofld_stats.tx_broadcast +=
			ring->ring_stats->tx_stats.broadcast;
#endif
		vsi->ofld_stats.tx_inserted_vlan +=
			ring->ring_stats->tx_stats.inserted_vlan;
	}
}

/**
 * mcevf_update_vsi_ring_stats - Update VSI stats counters
 * @vsi: the VSI to be updated
 */
void mcevf_update_vsi_ring_stats(struct mcevf_vsi *vsi)
{
	struct rtnl_link_stats64 *net_stats;
	struct rtnl_link_stats64 *stats_prev;
	struct rtnl_link_stats64 *vsi_stats;
	struct mcevf_hw *hw = &vsi->back->hw;
	int i;

	vsi_stats = kzalloc(sizeof(*vsi_stats), GFP_ATOMIC);
	if (!vsi_stats)
		return;

	spin_lock_bh(&vsi->stats_lock);
	if (!vsi->tx_rings || !vsi->rx_rings) {
		spin_unlock_bh(&vsi->stats_lock);
		kfree(vsi_stats);
		return;
	}

	/* reset non-netdev (extended) stats */
	vsi->tx_restart = 0;
	vsi->tx_busy = 0;
	vsi->tx_linearize = 0;
	vsi->rx_buf_failed = 0;
	vsi->rx_page_failed = 0;

	/* reset vlan csum offload stats */
	vsi->ofld_stats.tx_inserted_vlan = 0;
	vsi->ofld_stats.rx_stripped_vlan = 0;
	vsi->ofld_stats.rx_csum_err = 0;
	vsi->ofld_stats.rx_csum_unnecessary = 0;
	vsi->ofld_stats.rx_csum_none = 0;
	vsi->ofld_stats.tx_unicast = 0;
	vsi->ofld_stats.tx_multicast = 0;
	vsi->ofld_stats.tx_broadcast = 0;
	vsi->ofld_stats.rx_unicast = 0;
	vsi->ofld_stats.rx_multicast = 0;
	vsi->ofld_stats.rx_broadcast = 0;
	vsi->ofld_stats.rx_miss_drop = 0;

	rcu_read_lock();

	/* update Tx rings counters */
	mcevf_update_vsi_tx_ring_stats(vsi, vsi_stats, vsi->tx_rings,
				       vsi->num_txq);

	/* update Rx rings counters */
	mcevf_for_each_rxq(vsi, i) {
		struct mcevf_ring *ring = READ_ONCE(vsi->rx_rings[i]);
		struct mcevf_ring_stats *ring_stats;
		u64 pkts, bytes;

		if (!ring)
			continue;
		ring_stats = ring->ring_stats;
		if (!ring_stats)
			continue;
		mcevf_fetch_u64_stats_per_ring(ring_stats, &pkts, &bytes);
		ring_stats->rx_stats.bytes = bytes;
		ring_stats->rx_stats.pkts = pkts;
#if __MCEVF_GET_RING_STATS_BY_HW
		ring_stats->rx_stats.multicast = hw->ops->get_hw_ring_stats(ring,
								     MCEVF_HW_R_STATS_RX_MULTICAST);
		ring_stats->rx_stats.broadcast = hw->ops->get_hw_ring_stats(ring,
								     MCEVF_HW_R_STATS_RX_BROADCAST);
		ring_stats->rx_stats.miss_drop = hw->ops->get_hw_ring_stats(ring,
								     MCEVF_HW_R_STATS_RX_MISS_DROP);
		ring_stats->rx_stats.unicast = pkts -
			ring_stats->rx_stats.multicast -
			ring_stats->rx_stats.broadcast;
#endif
		vsi_stats->rx_packets += pkts;
		vsi_stats->rx_bytes += bytes;
		vsi->rx_buf_failed +=
			ring_stats->rx_stats.alloc_buf_failed;
		vsi->rx_page_failed +=
			ring_stats->rx_stats.alloc_page_failed;

		vsi->ofld_stats.rx_unicast +=
			ring->ring_stats->rx_stats.unicast;
		vsi->ofld_stats.rx_multicast +=
			ring->ring_stats->rx_stats.multicast;
		vsi->ofld_stats.rx_broadcast +=
			ring->ring_stats->rx_stats.broadcast;
		vsi->ofld_stats.rx_miss_drop +=
			ring->ring_stats->rx_stats.miss_drop;
		vsi->ofld_stats.rx_stripped_vlan +=
			ring_stats->rx_stats.stripped_vlan;
		vsi->ofld_stats.rx_csum_err +=
			ring_stats->rx_stats.csum_err;
		vsi->ofld_stats.rx_csum_unnecessary +=
			ring_stats->rx_stats.csum_unnecessary;
		vsi->ofld_stats.rx_csum_none +=
			ring_stats->rx_stats.csum_none;
	}

	rcu_read_unlock();

	net_stats = &vsi->net_stats;
	stats_prev = &vsi->net_stats_prev;

	/* clear prev counters after reset */
	if (vsi_stats->tx_packets < stats_prev->tx_packets ||
	    vsi_stats->rx_packets < stats_prev->rx_packets) {
		stats_prev->tx_packets = 0;
		stats_prev->tx_bytes = 0;
		stats_prev->rx_packets = 0;
		stats_prev->rx_bytes = 0;
	}

	/* update netdev counters */
	net_stats->tx_packets +=
		vsi_stats->tx_packets - stats_prev->tx_packets;
	net_stats->tx_bytes += vsi_stats->tx_bytes - stats_prev->tx_bytes;
	net_stats->rx_packets +=
		vsi_stats->rx_packets - stats_prev->rx_packets;
	net_stats->rx_bytes += vsi_stats->rx_bytes - stats_prev->rx_bytes;

	stats_prev->tx_packets = vsi_stats->tx_packets;
	stats_prev->tx_bytes = vsi_stats->tx_bytes;
	stats_prev->rx_packets = vsi_stats->rx_packets;
	stats_prev->rx_bytes = vsi_stats->rx_bytes;
	spin_unlock_bh(&vsi->stats_lock);
	kfree(vsi_stats);
}

/**
 * mcevf_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
static void mcevf_get_stats64(struct net_device *netdev,
			      struct rtnl_link_stats64 *stats)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct rtnl_link_stats64 *vsi_stats;
	struct mcevf_vsi *vsi = np->vsi;

	vsi_stats = &vsi->net_stats;

	if (!vsi->num_txq || !vsi->num_rxq)
		return;

	/* netdev packet/byte stats come from ring counter. These are obtained
	 * by summing up ring counters (done by mcevf_update_vsi_ring_stats).
	 * But, only call the update routine and read the registers if VSI is
	 * not down.
	 */
	if (!test_bit(MCEVF_VSI_DOWN, vsi->state))
		mcevf_update_vsi_ring_stats(vsi);

	stats->tx_packets = vsi_stats->tx_packets;
	stats->tx_bytes = vsi_stats->tx_bytes;
	stats->rx_packets = vsi_stats->rx_packets;
	stats->rx_bytes = vsi_stats->rx_bytes;

	/* The rest of the stats can be read from the hardware but instead we
	 * just return values that the watchdog task has already obtained from
	 * the hardware.
	 */
	stats->multicast = vsi_stats->multicast;
	stats->tx_errors = vsi_stats->tx_errors;
	stats->tx_dropped = vsi_stats->tx_dropped;
	stats->rx_errors = vsi_stats->rx_errors;
	stats->rx_dropped = vsi_stats->rx_dropped;
	stats->rx_crc_errors = vsi_stats->rx_crc_errors;
	stats->rx_length_errors = vsi_stats->rx_length_errors;
}

/**
 * mcevf_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int mcevf_set_features(struct net_device *netdev,
			      netdev_features_t features)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;
	netdev_features_t changed = netdev->features ^ features;

	if ((changed & NETIF_F_RXCSUM) && !(netdev->flags & IFF_PROMISC) &&
	    !(netdev->features & NETIF_F_RXALL))
		hw->ops->set_rx_csumofld(hw, features);

	if ((changed & NETIF_F_HW_VLAN_CTAG_RX) ||
	    (changed & NETIF_F_HW_VLAN_STAG_RX))
		hw->ops->set_vlan_strip(hw, features);

	if (changed & NETIF_F_RXHASH)
		hw->ops->set_rss_hash(hw, features);

	netdev->features = features;

	return 0;
}

/**
 * mcevf_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 */
static void mcevf_set_rx_mode(struct net_device *netdev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	netdev_features_t features = netdev->features;
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;
	bool uc_enable = true;
	bool mc_enable = true;

	if (!vsi)
		return;

	/* if not in trust, not support promisc */
	if (!(test_bit(MCEVF_FLAG_TRUST_ON, pf->flags))) {
		if (netdev->flags & (IFF_PROMISC | IFF_ALLMULTI)) {
			dev_err(hw->dev, "not support promisc with trust off\n");
			//netdev->flags &= (~(IFF_PROMISC | IFF_ALLMULTI));
		}
	} else {
		if (netdev->flags & IFF_PROMISC) {
			uc_enable = false;
			mc_enable = false;
		} else {
			uc_enable = true;
			mc_enable = true;
		}
	}

	hw->ops->set_vlan_strip(hw, features);
	hw->ops->set_vlan_filter(hw, features);
	hw->ops->set_uc_filter(hw, uc_enable);
	hw->ops->set_mc_filter(hw, mc_enable);

	/* Set the flags to synchronize filters
	 * ndo_set_rx_mode may be triggered even without a change in netdev
	 * flags
	 */
	set_bit(MCEVF_VSI_UMAC_FLTR_CHANGED, vsi->state);
	set_bit(MCEVF_VSI_MMAC_FLTR_CHANGED, vsi->state);
	set_bit(MCEVF_FLAG_FLTR_SYNC, vsi->back->flags);

	/* schedule our worker thread which will take care of
	 * applying the new filter changes
	 */
	mcevf_service_task_schedule(vsi->back);
}

/**
 * mcevf_vlan_rx_add_vid - Add a VLAN ID filter to HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be added
 *
 * net_device_ops implementation for adding VLAN IDs
 */
static int mcevf_vlan_rx_add_vid(struct net_device *netdev, __be16 proto,
				 u16 vid)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;
	int err = 0;

	if (!vid)
		return 0;

	err = hw->ops->set_vlan_vfta(hw, vid, 0, true);
	if (err)
		netdev_err(netdev, "set vlan %d failed maximum allowed:16\n", vid);
	return err;
}

/**
 * mcevf_vlan_rx_kill_vid - Remove a VLAN ID filter from HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be removed
 *
 * net_device_ops implementation for removing VLAN IDs
 */
static int mcevf_vlan_rx_kill_vid(struct net_device *netdev,
				  __be16 proto, u16 vid)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_hw *hw = &vsi->back->hw;

	if (!vid)
		return 0;

	hw->ops->set_vlan_vfta(hw, vid, 0, false);

	return 0;
}

/**
 * mcevf_set_mac_address - NDO callback to set MAC address
 * @netdev: network interface device structure
 * @pi: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 */
static int mcevf_set_mac_address(struct net_device *netdev, void *pi)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;
	struct sockaddr *addr = pi;
	int err = 0;
	u8 *mac = NULL;

	mac = (u8 *)addr->sa_data;
	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, mac)) {
		netdev_dbg(netdev, "already using mac %pM\n", mac);
		return 0;
	}

	if (test_bit(MCEVF_DOWN, pf->state)) {
		netdev_err(netdev, "can't set mac %pM. device not ready\n",
			   mac);
		return -EBUSY;
	}

	err = hw->ops->set_unicast_addr(hw, mac);
	if (err) {
		netdev_err(netdev,
			   "can't set mac %pM. MAC address conflicts with another VF in the same VLAN or something error at hw (err:%d)\n",
			   mac, err);
		return err;
	}

	netif_addr_lock_bh(netdev);
	/* change the netdev's MAC address */
	eth_hw_addr_set(netdev, mac);
	ether_addr_copy(hw->mac.addr, mac);
	//ether_addr_copy(hw->mac.perm_addr, mac);
	//ether_addr_copy(vsi->port_info->mac.perm_addr, mac);
	netif_addr_unlock_bh(netdev);

	return 0;
}

/**
 * mcevf_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int mcevf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	int err = 0;

	if (new_mtu == (int)netdev->mtu) {
		netdev_warn(netdev, "MTU is already %u\n", netdev->mtu);
		return 0;
	}
	netdev->mtu = (unsigned int)new_mtu;

	/* if VSI is up, bring it down and then back up */
	if (!test_and_set_bit(MCEVF_VSI_DOWN, vsi->state)) {
		err = mcevf_down(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_down err %d\n",
				   err);
			return err;
		}

		err = mcevf_up(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_up err %d\n",
				   err);
			return err;
		}
	}

	netdev_dbg(netdev, "changed MTU to %d\n", new_mtu);
	set_bit(MCEVF_FLAG_MTU_CHANGED, pf->flags);

	return 0;
}

/**
 * mcevf_set_tx_maxrate - NDO callback to set the maximum per-queue bitrate
 * @netdev: network interface device structure
 * @queue_index: Queue ID
 * @maxrate: maximum bandwidth in Mbps
 */
static int mcevf_set_tx_maxrate(struct net_device *netdev, int queue_index,
				u32 maxrate)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;
	struct mcevf_ring *tx_ring = vsi->tx_rings[queue_index];
	int status = 0;

	/* Validate maxrate requested is within permitted range */
	if (maxrate && (maxrate > (MCEVF_SCHED_MAX_BW / 1000))) {
		netdev_err(netdev,
			   "Invalid max rate %d specified for the queue %d\n",
			   maxrate, queue_index);
		return -EINVAL;
	}

	if (netif_msg_drv(pf))
		netdev_info(netdev, "tx queue %u set maxrate %uMb\n",
			    queue_index, maxrate);

	/* Set BW back to default, when user set maxrate to 0 */
	if (!maxrate)
		status = hw->ops->cfg_txring_bw_lmt(tx_ring, 0);
	else
		status = hw->ops->cfg_txring_bw_lmt(tx_ring, maxrate);
	if (status)
		netdev_err(netdev, "Unable to set Tx max rate, error %d\n",
			   status);

	return status;
}

/**
 * mcevf_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: Tx queue
 */
static void mcevf_tx_timeout(struct net_device *netdev,
			     unsigned int __always_unused txqueue)
{
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	int i = 0;

	if (!mcevf_pf_flags_reset_get(pf))
		return;
	mcevf_for_each_q_vector(vsi, i) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[i];
		struct mcevf_ring *tx_ring;

		dev_info(mcevf_pf_to_dev(pf), "qticks:%u qold_ticks:%u\n",
			 q_vector->ticks, q_vector->old_ticks);

		mcevf_rc_for_each_ring(tx_ring, q_vector->tx) {
			dev_info(mcevf_pf_to_dev(pf),
				 "txring:next_to_clean:%d next_to_use:%d\n",
				 tx_ring->next_to_clean,
				 tx_ring->next_to_use);
		}
	}
	mcevf_pf_flags_reset_set(pf);
}

static netdev_features_t mcevf_fix_features(struct net_device *netdev,
					    netdev_features_t features)
{
#ifdef NETIF_F_HW_VLAN_STAG_RX
	if (!(features & NETIF_F_HW_VLAN_CTAG_RX)) {
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		features &= ~NETIF_F_HW_VLAN_STAG_RX;
#endif
	}
#endif

#ifdef NETIF_F_HW_VLAN_STAG_RX
	if (!(features & NETIF_F_HW_VLAN_STAG_RX)) {
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		features &= ~NETIF_F_HW_VLAN_CTAG_RX;
#endif
	}
#endif

#ifdef NETIF_F_HW_VLAN_CTAG_TX
	if (!(features & NETIF_F_HW_VLAN_CTAG_TX)) {
#ifdef NETIF_F_HW_VLAN_STAG_RX
		features &= ~NETIF_F_HW_VLAN_STAG_TX;
#endif
	}
#endif

#ifdef NETIF_F_HW_VLAN_STAG_TX
	if (!(features & NETIF_F_HW_VLAN_STAG_TX)) {
#ifdef NETIF_F_HW_VLAN_CTAG_TX
		features &= ~NETIF_F_HW_VLAN_CTAG_TX;
#endif
	}
#endif
	return features;
}

/**
 * mcevf_get_dscp_up - return the UP/TC value for a SKB
 * @dcb: DCB config that contains DSCP to UP/TC mapping
 * @skb: SKB to query for info to determine UP/TC
 *
 * This function is to only be called when the PF is in L3 DSCP PFC mode
 */
static u8 mcevf_get_dscp_up(struct mcevf_dcb *dcb, struct sk_buff *skb)
{
	u8 dscp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return dcb->dscp_map[dscp];
}

static u16 mcevf_select_queue(struct net_device *netdev, struct sk_buff *skb,
			      struct net_device *sb_dev)
{
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_dcb *dcb = pf->dcb;
	struct mcevf_tc_cfg *tccfg = &dcb->cur_tccfg;
	int tc = 0;
	u16 queue;

	if (test_bit(MCEVF_DSCP_EN, dcb->flags)) {
		skb->priority = mcevf_get_dscp_up(dcb, skb);
	} else {
		if (skb_vlan_tag_present(skb)) {
			skb->priority = (skb_vlan_tag_get(skb) >> 13) & 0x7;
		} else if (__VLAN_ALLOWED(skb->protocol)) {
			struct vlan_hdr *vhdr, _vhdr;

			vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr),
						  &_vhdr);
			if (!vhdr)
				goto skip_prio;

			skb->priority = (ntohs(vhdr->h_vlan_TCI) >> 13) & 0x7;
		}
		// no vlan packet use stack prio
	}
skip_prio:
	/* if prio is not valid for this nic, use a valid one */
	if (test_bit(MCEVF_PFC_EN, dcb->flags) && pf->valid_prio) {
		u8 prio = skb->priority & 0x7;

		if (!(pf->valid_prio & BIT(prio))) {
			int first = ffs(pf->valid_prio);

			if (first)
				prio = first - 1;
		}
		skb->priority = prio;
	}
	/* Use the target kernel's XPS/hash queue selection. */
	queue = netdev_pick_tx(netdev, skb, sb_dev);

	if (test_bit(MCEVF_PFC_EN, dcb->flags)) {
		u8 prio = skb->priority & 0x7;

		if (tccfg->pfc_txq_count[tc][prio]) {
			queue = tccfg->pfc_txq_base[tc][prio] +
				(queue % tccfg->pfc_txq_count[tc][prio]);
		} else {
			netdev_err(netdev, "%d txq_count error %d\n", tc,
				   tccfg->pfc_txq_count[tc][prio]);
			queue = 0;
		}
	}

	return queue;
}

static const struct net_device_ops mcevf_netdev_ops = {
	.ndo_open = mcevf_open,
	.ndo_stop = mcevf_stop,
	.ndo_start_xmit = mcevf_start_xmit,
	.ndo_features_check = mcevf_features_check,
	.ndo_get_stats64 = mcevf_get_stats64,
	.ndo_set_features = mcevf_set_features,
	.ndo_set_rx_mode = mcevf_set_rx_mode,
	.ndo_vlan_rx_add_vid = mcevf_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = mcevf_vlan_rx_kill_vid,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = mcevf_set_mac_address,
	.ndo_change_mtu = mcevf_change_mtu,
	.ndo_set_tx_maxrate = mcevf_set_tx_maxrate,
	.ndo_tx_timeout = mcevf_tx_timeout,
	.ndo_fix_features = mcevf_fix_features,
	.ndo_select_queue = mcevf_select_queue,
};

/**
 * mcevf_set_netdev_features - set features for the given netdev
 * @netdev: netdev instance
 */
static void mcevf_set_netdev_features(struct net_device *netdev)
{
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	netdev_features_t csumo_features = 0;
	netdev_features_t vlano_features = 0;
	netdev_features_t dflt_features = 0;
	netdev_features_t tso_features = 0;
	netdev_features_t fixon_features = 0;

	dflt_features |= NETIF_F_SG;
	dflt_features |= NETIF_F_HIGHDMA;
	dflt_features |= NETIF_F_NTUPLE;
	dflt_features |= NETIF_F_RXHASH;

	fixon_features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	fixon_features |= NETIF_F_HW_VLAN_STAG_FILTER;

#ifdef NETIF_F_HW_CSUM
	csumo_features |= NETIF_F_HW_CSUM;
#else
	csumo_features |= NETIF_F_IP_CSUM;
	csumo_features |= NETIF_F_IPV6_CSUM;
#endif
	csumo_features |= NETIF_F_SCTP_CRC;
	csumo_features |= NETIF_F_RXCSUM;

	vlano_features |= NETIF_F_HW_VLAN_CTAG_TX;
	vlano_features |= NETIF_F_HW_VLAN_CTAG_RX;
	vlano_features |= NETIF_F_HW_VLAN_STAG_TX;
	vlano_features |= NETIF_F_HW_VLAN_STAG_RX;

	tso_features |= NETIF_F_TSO;
	tso_features |= NETIF_F_TSO_ECN;
	tso_features |= NETIF_F_TSO6;
	tso_features |= NETIF_F_GSO_GRE;
	tso_features |= NETIF_F_GSO_UDP_TUNNEL;
#ifdef NETIF_F_GSO_GRE_CSUM
	tso_features |= NETIF_F_GSO_GRE_CSUM;
	tso_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM;
#endif
#ifdef NETIF_F_GSO_PARTIAL
	tso_features |= NETIF_F_GSO_PARTIAL;
#endif
#ifdef NETIF_F_GSO_IPXIP4
	tso_features |= NETIF_F_GSO_IPXIP4;
	tso_features |= NETIF_F_GSO_IPXIP6;
#else
#ifdef NETIF_F_GSO_IPIP
	tso_features |= NETIF_F_GSO_IPIP;
	tso_features |= NETIF_F_GSO_SIT;
#endif
#endif /* NETIF_F_GSO_IPXIP4 */
#ifdef NETIF_F_GSO_UDP_L4
	tso_features |= NETIF_F_GSO_UDP_L4;
#endif /* NETIF_F_GSO_UDP_L4 */

#ifndef NETIF_F_GSO_PARTIAL
	tso_features ^= NETIF_F_GSO_UDP_TUNNEL_CSUM;
#else
	netdev->gso_partial_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM;
	netdev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
#endif
	/* set features that user can change */
	netdev->hw_features |= dflt_features;
	netdev->hw_features |= csumo_features;
	netdev->hw_features |= vlano_features;
	netdev->hw_features |= tso_features;

	/* enable features */
	netdev->features |= netdev->hw_features;
	netdev->features |= fixon_features;

	/* encap and VLAN devices inherit default, csumo and tso features */
	netdev->hw_enc_features |= dflt_features;
	netdev->hw_enc_features |= csumo_features;
	netdev->hw_enc_features |= tso_features;

	netdev->vlan_features |= dflt_features;
	netdev->vlan_features |= csumo_features;
	netdev->vlan_features |= tso_features;

#ifdef NETIF_F_HW_TC
	// netdev->hw_features |= NETIF_F_HW_TC;
#endif /* NETIF_F_HW_TC */

	/* Leave CRC / FCS stripping enabled by default, but allow the value to
	 * be changed at runtime
	 */
	if (test_bit(MCEVF_FLAG_NETDEV_STATE_FCS_ENA, pf->flags))
		netdev->features |= NETIF_F_RXFCS;
}

/**
 * mcevf_cfg_netdev - Allocate, configure and register a netdev
 * @vsi: the VSI associated with the new netdev
 *
 * Returns 0 on success, negative value on failure
 */
int mcevf_cfg_netdev(struct mcevf_vsi *vsi)
{
	int alloc_txq = vsi->alloc_txq;
	int alloc_rxq = vsi->alloc_rxq;
	struct mcevf_netdev_priv *np = NULL;
	struct net_device *netdev = NULL;

	netdev = alloc_etherdev_mqs(sizeof(*np), alloc_txq, alloc_rxq);
	if (!netdev)
		return -ENOMEM;

	set_bit(MCEVF_VSI_NETDEV_ALLOCD, vsi->state);
	vsi->netdev = netdev;
	np = netdev_priv(netdev);
	np->vsi = vsi;

	mcevf_set_netdev_features(netdev);

	netdev->netdev_ops = &mcevf_netdev_ops;
	mcevf_set_ethtool_ops(netdev);

	netdev->priv_flags |= IFF_UNICAST_FLT;

	SET_NETDEV_DEV(netdev, mcevf_pf_to_dev(vsi->back));
	eth_hw_addr_set(netdev, vsi->port_info->mac.perm_addr);
	ether_addr_copy(netdev->perm_addr, vsi->port_info->mac.perm_addr);

	netdev->priv_flags |= IFF_UNICAST_FLT;

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 2 * HZ;

	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = MCEVF_MAX_MTU;

	return 0;
}

static void mcevf_dcb_default(struct mcevf_pf *pf)
{
	struct mcevf_dcb *dcb = pf->dcb;
	int i;

	for (i = 0; i < MCEVF_MAX_DSCP; i++)
		dcb->dscp_map[i] = (i / 8);
}

/**
 * mcevf_register_netdev - register netdev and devlink port
 * @pf: pointer to the PF struct
 */
int mcevf_register_netdev(struct mcevf_pf *pf)
{
	struct mcevf_vsi *vsi;
	int err = 0;

	vsi = mcevf_get_main_vsi(pf);
	if (!vsi || !vsi->netdev)
		return -EIO;

	err = register_netdev(vsi->netdev);
	if (err)
		goto err_register_netdev;

	set_bit(MCEVF_VSI_NETDEV_REGISTERED, vsi->state);
	netif_carrier_off(vsi->netdev);
	netif_tx_stop_all_queues(vsi->netdev);
	mcevf_dcb_default(pf);

	return 0;
err_register_netdev:
	free_netdev(vsi->netdev);
	vsi->netdev = NULL;
	clear_bit(MCEVF_VSI_NETDEV_ALLOCD, vsi->state);
	return err;
}
