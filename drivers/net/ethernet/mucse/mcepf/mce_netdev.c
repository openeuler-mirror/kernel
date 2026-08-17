// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/module.h>
#include "mce_lib.h"
#include "mce_netdev.h"
#include "mce_txrx.h"
#include "mce_irq.h"
#include "mce_dcbnl.h"
#include "mce_fdir.h"
#include "mce_dcb.h"
#include "mce_n20/mce_hw_n20.h"

#include "mce_fwchnl.h"
#include "mce_virtchnl.h"

static int sfp_plugin_notify_en;
module_param(sfp_plugin_notify_en, int, 0644);
MODULE_PARM_DESC(sfp_plugin_notify_en, "enable notify sfp plugin/plugout");

static const struct net_device_ops mce_netdev_ops;

bool netif_is_mce(struct net_device *dev)
{
	return dev && (dev->netdev_ops == &mce_netdev_ops);
}

void mce_notify_fw_ifup_down(struct mce_pf *pf, bool up)
{
	bool sfp_plug_ne;

	sfp_plug_ne = up ? (sfp_plugin_notify_en ? true : false) : false;
	if (up) {
		mce_mbx_ifup_down(&pf->hw, true);
		mce_mbx_link_state_change_notify_en(&pf->hw, true);
		mce_mbx_sfp_plug_notify_en(&pf->hw, sfp_plug_ne);
	} else {
		mce_mbx_link_state_change_notify_en(&pf->hw, false);
		mce_mbx_sfp_plug_notify_en(&pf->hw, false);
		mce_mbx_ifup_down(&pf->hw, false);
	}
}

/**
 * mce_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP). At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns: 0 on success, negative value on failure
 */
int mce_open(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	int err = 0;

	if (test_bit(MCE_NEEDS_RESTART, pf->state)) {
		netdev_err(netdev,
			   "driver needs to be unloaded and reloaded\n");
		return -EIO;
	}

	netif_carrier_off(netdev);
	vsi->link = 0;
	hw->ops->update_pf_stat(hw);

	err = mce_vsi_open(vsi);
	if (err) {
		netdev_err(netdev, "Failed to open VSI 0x%04X\n", vsi->idx);
		return err;
	}
	if (IS_REACHABLE(CONFIG_PTP_1588_CLOCK)) {
		err = mce_ptp_register(pf);
		if (err) {
			mce_vsi_close(vsi);
			return err;
		}
	}
	/* Update existing tunnels information */

	if (!test_bit(MCE_NO_LINK, pf->state))
		mce_notify_fw_ifup_down(pf, true);
	if (netif_msg_ifup(pf))
		netdev_info(netdev, "ifup\n");
	return err;
}

/**
 * mce_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state. The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns: success only - not allowed to fail
 */
static int mce_stop(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	mce_notify_fw_ifup_down(pf, false);
	if (IS_REACHABLE(CONFIG_PTP_1588_CLOCK))
		mce_ptp_unregister(pf);
	mce_vsi_close(vsi);

	set_bit(MCE_FLAG_PF_UPDATE_LINK, pf->flags);
	set_bit(MCE_FLAG_PF_FORCE_VF_LINK_DOWN, pf->flags);
	mce_service_task_schedule(pf);

	if (netif_msg_ifdown(pf))
		netdev_info(netdev, "ifdown");
	return 0;
}

/**
 * mce_fetch_u64_stats_per_ring - get packets and bytes stats per ring
 * @ring_stat: Tx or Rx stats to read from
 * @pkts: packets stats counter
 * @bytes: bytes stats counter
 *
 * This function fetches stats from the ring considering the atomic operations
 * that needs to be performed to read u64 values in 32 bit machine.
 */
static void __maybe_unused
mce_fetch_u64_stats_per_ring(struct mce_ring_stats *ring_stat,
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
 * mce_update_vsi_tx_ring_stats - Update VSI Tx ring stats counters
 * @vsi: the VSI to be updated
 * @vsi_stats: the stats struct to be updated
 * @rings: rings to work on
 * @count: number of rings
 */
static void mce_update_vsi_tx_ring_stats(struct mce_vsi *vsi,
					 struct rtnl_link_stats64 *vsi_stats,
					 struct mce_ring **rings, u16 count)
{
#if __MCE_GET_RING_STATS_BY_HW
	struct mce_hw *hw = &vsi->back->hw;
#else
	struct mce_pf *pf = mce_netdev_to_pf(vsi->netdev);
#endif
	u16 i;

	for (i = 0; i < count; i++) {
		struct mce_ring_stats *ring_stat;
		struct mce_ring *ring;
#if !__MCE_GET_RING_STATS_BY_HW
		u64 pkts, bytes;
#endif

		ring = READ_ONCE(rings[i]);
		ring_stat = ring->ring_stats;
#if __MCE_GET_RING_STATS_BY_HW
		ring_stat->tx_stats.bytes = hw->ops->get_hw_ring_stats(ring,
								MCE_HW_R_STATS_TX_BYTES);
		ring_stat->tx_stats.unicast = hw->ops->get_hw_ring_stats(ring,
								  MCE_HW_R_STATS_TX_UNICAST);
		ring_stat->tx_stats.multicast = hw->ops->get_hw_ring_stats(ring,
								    MCE_HW_R_STATS_TX_MULTICAST);
		ring_stat->tx_stats.broadcast = hw->ops->get_hw_ring_stats(ring,
								    MCE_HW_R_STATS_TX_BROADCAST);
		ring_stat->tx_stats.pkts = ring_stat->tx_stats.unicast +
					   ring_stat->tx_stats.multicast +
					   ring_stat->tx_stats.broadcast;
		vsi_stats->tx_packets += ring_stat->tx_stats.pkts;
		vsi_stats->tx_bytes += ring_stat->tx_stats.bytes;

		vsi->ofld_stats.tx_unicast +=
			ring->ring_stats->tx_stats.unicast;
		vsi->ofld_stats.tx_multicast +=
			ring->ring_stats->tx_stats.multicast;
		vsi->ofld_stats.tx_broadcast +=
			ring->ring_stats->tx_stats.broadcast;
#else
		mce_fetch_u64_stats_per_ring(ring->ring_stats, &pkts, &bytes);
		ring_stat->tx_stats.bytes = bytes;
		ring_stat->tx_stats.pkts = pkts;
		vsi_stats->tx_packets += pkts;
		vsi_stats->tx_bytes += bytes;
#endif
		vsi_stats->tx_dropped +=
			READ_ONCE(ring->ring_stats->tx_stats.tx_drop);
		vsi->tx_restart += ring->ring_stats->tx_stats.restart_q;
		vsi->tx_busy += ring->ring_stats->tx_stats.tx_busy;
		vsi->tx_linearize += ring->ring_stats->tx_stats.tx_linearize;
		vsi->ofld_stats.tx_inserted_vlan +=
			ring->ring_stats->tx_stats.inserted_vlan;
	}
#if !__MCE_GET_RING_STATS_BY_HW
	/* we use mac */
	vsi->ofld_stats.tx_unicast = pf->mac_stats.tx_unicast_pkts;
	vsi->ofld_stats.tx_multicast = pf->mac_stats.tx_multicast_pkts;
	vsi->ofld_stats.tx_broadcast = pf->mac_stats.tx_broadcast_pkts;
#endif
}

/**
 * mce_update_vsi_ring_stats - Update VSI stats counters
 * @vsi: the VSI to be updated
 */
void mce_update_vsi_ring_stats(struct mce_vsi *vsi)
{
	struct rtnl_link_stats64 *net_stats, *stats_prev;
	struct rtnl_link_stats64 *vsi_stats;
#if __MCE_GET_RING_STATS_BY_HW
	struct mce_hw *hw = &vsi->back->hw;
#else
	struct mce_pf *pf = mce_netdev_to_pf(vsi->netdev);
#endif
	int i;

	vsi_stats = kzalloc(sizeof(*vsi_stats), GFP_ATOMIC);
	if (!vsi_stats)
		return;

	/* reset non-netdev (extended) stats */
	vsi->tx_restart = 0;
	vsi->tx_busy = 0;
	vsi->tx_linearize = 0;
	vsi->rx_buf_failed = 0;
	vsi->rx_page_failed = 0;
	vsi->rx_page_alloc_ok = 0;
	vsi->rx_page_reuse_ok = 0;
	vsi->rx_page_reuse_reserved = 0;
	vsi->rx_page_reuse_refcnt = 0;
	vsi->rx_page_reuse_offset = 0;

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

	/* Use spinlock to protect concurrent access to net_stats and stats_prev */
	spin_lock(&vsi->stats_lock);
	rcu_read_lock();

	/* update Tx rings counters */
	mce_update_vsi_tx_ring_stats(vsi, vsi_stats, vsi->tx_rings,
				     vsi->alloc_txq);

	/* update Rx rings counters */
	mce_for_each_rxq_new(vsi, i) {
		struct mce_ring *ring = READ_ONCE(vsi->rx_rings[i]);
		struct mce_ring_stats *ring_stats;
#if !__MCE_GET_RING_STATS_BY_HW
		u64 pkts, bytes;
#endif

		if (!ring->q_vector)
			continue;

		ring_stats = ring->ring_stats;
#if __MCE_GET_RING_STATS_BY_HW
		ring_stats->rx_stats.bytes = hw->ops->get_hw_ring_stats(ring,
								MCE_HW_R_STATS_RX_BYTES);
		ring_stats->rx_stats.unicast = hw->ops->get_hw_ring_stats(ring,
								  MCE_HW_R_STATS_RX_UNICAST);
		ring_stats->rx_stats.multicast = hw->ops->get_hw_ring_stats(ring,
								    MCE_HW_R_STATS_RX_MULTICAST);
		ring_stats->rx_stats.broadcast = hw->ops->get_hw_ring_stats(ring,
								    MCE_HW_R_STATS_RX_BROADCAST);
		ring_stats->rx_stats.miss_drop = hw->ops->get_hw_ring_stats(ring,
								      MCE_HW_R_STATS_RX_MISS_DROP);
		ring_stats->rx_stats.pkts = ring_stats->rx_stats.unicast +
					    ring_stats->rx_stats.multicast +
					    ring_stats->rx_stats.broadcast;
		vsi_stats->rx_packets += ring_stats->rx_stats.pkts;
		vsi_stats->rx_bytes += ring_stats->rx_stats.bytes;
		vsi->ofld_stats.rx_unicast +=
			ring->ring_stats->rx_stats.unicast;
		vsi->ofld_stats.rx_multicast +=
			ring->ring_stats->rx_stats.multicast;
		vsi->ofld_stats.rx_broadcast +=
			ring->ring_stats->rx_stats.broadcast;
#else
		mce_fetch_u64_stats_per_ring(ring_stats, &pkts, &bytes);
		ring_stats->rx_stats.bytes = bytes;
		ring_stats->rx_stats.pkts = pkts;
		vsi_stats->rx_packets += pkts;
		vsi_stats->rx_bytes += bytes;
#endif
		vsi->rx_buf_failed += ring_stats->rx_stats.alloc_buf_failed;
		vsi->rx_page_failed += ring_stats->rx_stats.alloc_page_failed;
		vsi->rx_page_alloc_ok += ring_stats->rx_stats.alloc_page_ok;
		vsi->rx_page_reuse_ok += ring_stats->rx_stats.page_reuse_ok;
		vsi->rx_page_reuse_reserved +=
			ring_stats->rx_stats.page_reuse_reserved;
		vsi->rx_page_reuse_refcnt +=
			ring_stats->rx_stats.page_reuse_refcnt;
		vsi->rx_page_reuse_offset +=
			ring_stats->rx_stats.page_reuse_offset;
		vsi->ofld_stats.rx_stripped_vlan +=
			ring_stats->rx_stats.stripped_vlan;
		vsi->ofld_stats.rx_csum_err += ring_stats->rx_stats.csum_err;
		vsi->ofld_stats.rx_csum_unnecessary +=
			ring_stats->rx_stats.csum_unnecessary;
		vsi->ofld_stats.rx_csum_none += ring_stats->rx_stats.csum_none;

		vsi->ofld_stats.rx_miss_drop +=
			ring->ring_stats->rx_stats.miss_drop;
	}
#if !__MCE_GET_RING_STATS_BY_HW
	/* we use mac */
	vsi->ofld_stats.rx_unicast = pf->mac_stats.rx_unicast_pkts;
	vsi->ofld_stats.rx_multicast = pf->mac_stats.rx_multicast_pkts;
	vsi->ofld_stats.rx_broadcast = pf->mac_stats.rx_broadcast_pkts;
#endif

	net_stats = &vsi->net_stats;
	stats_prev = &vsi->net_stats_prev;
	rcu_read_unlock();
#if __MCE_GET_RING_STATS_BY_HW
	net_stats->tx_packets = vsi_stats->tx_packets;
	net_stats->tx_bytes = vsi_stats->tx_bytes;
	net_stats->rx_packets = vsi_stats->rx_packets;
	net_stats->rx_bytes = vsi_stats->rx_bytes;
#else
	/* Process Tx stats: check for race condition or wrap-around. */
	if (unlikely(vsi_stats->tx_packets < stats_prev->tx_packets)) {
		s64 tx_diff = (s64)(vsi_stats->tx_packets -
				    stats_prev->tx_packets);

		/* A large negative delta indicates counter wrap-around. */
		if (tx_diff < -(s64)0x100000000000LL) {
			net_stats->tx_packets += vsi_stats->tx_packets -
					  stats_prev->tx_packets;
			net_stats->tx_bytes += vsi_stats->tx_bytes -
					stats_prev->tx_bytes;
		} else {
			/* Race detected: skip Tx update. */
			goto skip_tx_update;
		}
	} else {
		/* Normal case. */
		net_stats->tx_packets += vsi_stats->tx_packets -
					  stats_prev->tx_packets;
		net_stats->tx_bytes += vsi_stats->tx_bytes -
					 stats_prev->tx_bytes;
	}
	stats_prev->tx_packets = vsi_stats->tx_packets;
	stats_prev->tx_bytes = vsi_stats->tx_bytes;

skip_tx_update:
	/* Process Rx stats: check for race condition or wrap-around. */
	if (unlikely(vsi_stats->rx_packets < stats_prev->rx_packets)) {
		s64 rx_diff = (s64)(vsi_stats->rx_packets -
				    stats_prev->rx_packets);

		if (rx_diff < -(s64)0x100000000000LL) {
			net_stats->rx_packets += vsi_stats->rx_packets -
					  stats_prev->rx_packets;
			net_stats->rx_bytes += vsi_stats->rx_bytes -
					 stats_prev->rx_bytes;
		} else {
			/* Race detected: skip Rx update. */
			goto skip_rx_update;
		}
	} else {
		/* Normal case. */
		net_stats->rx_packets += vsi_stats->rx_packets -
					  stats_prev->rx_packets;
		net_stats->rx_bytes += vsi_stats->rx_bytes -
					 stats_prev->rx_bytes;
	}
	stats_prev->rx_packets = vsi_stats->rx_packets;
	stats_prev->rx_bytes = vsi_stats->rx_bytes;

skip_rx_update:
	/* Update the Tx dropped counter. */
	net_stats->tx_dropped += vsi_stats->tx_dropped - stats_prev->tx_dropped;
	stats_prev->tx_dropped = vsi_stats->tx_dropped;

#endif
	spin_unlock(&vsi->stats_lock);
	kfree(vsi_stats);
}

/**
 * mce_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
static void mce_get_stats64(struct net_device *netdev,
			    struct rtnl_link_stats64 *stats)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct rtnl_link_stats64 *vsi_stats;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = mce_netdev_to_pf(vsi->netdev);

	vsi_stats = &vsi->net_stats;

	if (!vsi->num_txq || !vsi->num_rxq)
		return;

	/* netdev packet/byte stats come from ring counter. These are obtained
	 * by summing up ring counters (done by mce_update_vsi_ring_stats).
	 * But, only call the update routine and read the registers if VSI is
	 * not down.
	 */
	if (!test_bit(MCE_VSI_DOWN, vsi->state)) {
		/* first get mac stats */
		mce_update_mac_stats(pf);
		mce_update_vsi_ring_stats(vsi);
	}

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
 * mce_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 * Returns: The result of the operation.
 */
static int mce_set_features(struct net_device *netdev,
			    netdev_features_t features)
{
	netdev_features_t changed = netdev->features ^ features;
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;

	if ((changed & NETIF_F_HW_VLAN_CTAG_RX) ||
	    (changed & NETIF_F_HW_VLAN_STAG_RX)) {
		hw->ops->set_vlan_strip(hw, features);
	}

	if (((changed & NETIF_F_HW_VLAN_CTAG_FILTER) ||
	     (changed & NETIF_F_HW_VLAN_STAG_FILTER)) &&
	    !(netdev->flags & IFF_PROMISC) &&
	    !(netdev->features & NETIF_F_RXALL)) {
		hw->ops->set_vlan_filter(hw, features);
	}

	if (changed & NETIF_F_RXHASH)
		hw->ops->set_rss_hash(hw, features);

	if (changed & NETIF_F_RXFCS) {
		if (features & NETIF_F_RXFCS) {
			hw->hw_flags |= MCE_F_RX_FCS_EN;
			hw->ops->set_fcs_mode(hw, true);
		} else {
			hw->hw_flags &= ~MCE_F_RX_FCS_EN;
			hw->ops->set_fcs_mode(hw, false);
		}
		mce_vf_notify_fcs_state(pf, !!(features & NETIF_F_RXFCS));
	}

	/* rx-all */
	/* 1. receive checksum err packet */
	/* 2. receive fcs err packet */
	/* 3. receive jumbo/utra packet */
	if (changed & NETIF_F_RXALL) {
		if (features & NETIF_F_RXALL)
			hw->hw_flags |= MCE_F_RX_ALL_EN;
		else
			hw->hw_flags &= ~MCE_F_RX_ALL_EN;
		/* setup max frame to hw */
		hw->ops->set_max_pktlen(hw, netdev->mtu);
		hw->ops->set_err_mode(hw);
	}

	netdev->features = features;
	return 0;
}

/**
 * mce_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 */
void mce_set_rx_mode(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	if (!vsi)
		return;
	mce_setup_L2_filter(pf);
	/* Set the flags to synchronize filters
	 * ndo_set_rx_mode may be triggered even without a change in netdev
	 * flags
	 */
	set_bit(MCE_VSI_UMAC_FLTR_CHANGED, vsi->state);
	set_bit(MCE_VSI_MMAC_FLTR_CHANGED, vsi->state);
	set_bit(MCE_FLAG_FLTR_SYNC, vsi->back->flags);
	/* schedule our worker thread which will take care of
	 * applying the new filter changes
	 */
	mce_service_task_schedule(vsi->back);
}

static int mce_ioctl(struct net_device *netdev, struct ifreq *req, int cmd)
{
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
#endif

	switch (cmd) {
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	case SIOCGHWTSTAMP:
		return mce_ptp_get_ts_config(pf, req);
	case SIOCSHWTSTAMP:
		return mce_ptp_set_ts_config(pf, req);
#endif
	case SIOCGMIIPHY:
		return 0;
	case SIOCGMIIREG:
		fallthrough;
	case SIOCSMIIREG:
		break;
	}
	return -EINVAL;
}

static struct mce_vlan_list_entry *mce_vlan_find_entry_by_vid(struct mce_hw *hw,
							      u16 vid)
{
	struct mce_vlan_list_entry *vlan_entry = NULL;

	list_for_each_entry(vlan_entry, &hw->vlan_list_head, vlan_node) {
		if (vid == vlan_entry->vid)
			return vlan_entry;
	}
	return NULL;
}

/**
 * mce_vlan_rx_add_vid - Add a VLAN ID filter to HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be added
 *
 * net_device_ops implementation for adding VLAN IDs
 * Returns: The result of the operation.
 */
static int mce_vlan_rx_add_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vlan_list_entry *vlan_entry = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = NULL;
	int timeout = 50;
	int ret = 0;
	int new = 0;

	if (!vid) {
		/* add vlan 0*/
		hw->ops->add_vlan_filter(hw, vid);
		hw->ops->set_vlan_strip(hw, netdev->features);
		return ret;
	}

	while (test_and_set_bit(MCE_CFG_BUSY, vsi->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	/* first try to find exit vlan */
	vlan_entry = mce_vlan_find_entry_by_vid(hw, vid);
	if (!vlan_entry) {
		new = 1;
		/* record vlan */
		vlan_entry = devm_kzalloc(mce_hw_to_dev(hw), sizeof(*vlan_entry),
					  GFP_KERNEL);
		if (!vlan_entry) {
			ret = -ENOMEM;
			goto free_entry;
		}
	}

	vlan_entry->vid = vid;
	if (proto == htons(ETH_P_8021Q))
		vlan_entry->status |= CVLAN_T;
	else
		vlan_entry->status |= SVLAN_T;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		/* it is ok set exit vlan twice */
		/* just set it */
		hw->ops->add_vlan_filter(hw, vid);
		hw->ops->set_vlan_strip(hw, netdev->features);
		ret = 0;
		goto exit;
	}
	/* enable sriov */
	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo) {
		ret = -EFAULT;
		goto free_entry;
	}
	/* pf take as vf 0, when turn on sriov */
	if (mce_vf_setup_flr_vlan(pf, PFINFO_IDX, vid) == -ENOMEM) {
		/* out of memory, not add, just free */
		ret = -EFAULT;
		goto free_entry;
	}
exit:
	/* only add when new alloc */
	if (new)
		list_add_tail(&vlan_entry->vlan_node, &hw->vlan_list_head);
	__set_bit(vid, pf->vlan_bitmap);

free_entry:
	clear_bit(MCE_CFG_BUSY, vsi->state);
	if (ret && new && vlan_entry)
		devm_kfree(mce_hw_to_dev(hw), vlan_entry);
	return ret;
}

/**
 * mce_vlan_rx_kill_vid - Remove a VLAN ID filter from HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be removed
 *
 * net_device_ops implementation for removing VLAN IDs
 * Returns: The result of the operation.
 */
static int mce_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto,
				u16 vid)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vlan_list_entry *vlan_entry = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &vsi->back->hw;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = NULL;
	int timeout = 50;
	int ret = 0;

	if (!vid) {
		/*del vlan 0*/
		hw->ops->add_vlan_filter(hw, vid);
		hw->ops->set_vlan_strip(hw, netdev->features);
		return ret;
	}

	while (test_and_set_bit(MCE_CFG_BUSY, vsi->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	vlan_entry = mce_vlan_find_entry_by_vid(hw, vid);
	if (!vlan_entry) {
		ret = -EIO;
		goto err;
	}

	if (proto == htons(ETH_P_8021Q))
		vlan_entry->status &= ~CVLAN_T;
	else
		vlan_entry->status &= ~SVLAN_T;
	/* if others use it, not really free */
	if (vlan_entry->status) {
		ret = 0;
		goto err;
	}

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		hw->ops->del_vlan_filter(hw, vid);
		ret = 0;
		goto exit;
	}

	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo) {
		ret = -EIO;
		goto err;
	}
	mce_vf_del_flr_vlan(pf, PFINFO_IDX, vid);
exit:
	/* del vlan node */
	list_del(&vlan_entry->vlan_node);
	devm_kfree(hw->dev, vlan_entry);
	__clear_bit(vid, pf->vlan_bitmap);
err:
	clear_bit(MCE_CFG_BUSY, vsi->state);
	return ret;
}

/**
 * mce_set_mac_address - NDO callback to set MAC address
 * @netdev: network interface device structure
 * @pi: pointer to an address structure
 *
 * Returns: 0 on success, negative on failure
 */
static int mce_set_mac_address(struct net_device *netdev, void *pi)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	struct sockaddr *addr = pi;
	u8 *mac = NULL;
	int err = 0;

	mac = (u8 *)addr->sa_data;

	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, mac)) {
		netdev_dbg(netdev, "already using mac %pM\n", mac);
		return 0;
	}

	if (test_bit(MCE_DOWN, pf->state)) {
		netdev_err(netdev, "can't set mac %pM. device not ready\n",
			   mac);
		return -EBUSY;
	}
	ether_addr_copy(vf->t_info.macaddr, mac);

	err = mce_vf_set_veb_misc_rule(hw, PFINFO_IDX,
				       VEB_POLICY_TYPE_UC_ADD_MACADDR);
	if (err) {
		netdev_err(netdev, "can't set mac %pM. something error at hw\n",
			   mac);
		return -EIO;
	}

	netif_addr_lock_bh(netdev);
	/* change the netdev's MAC address */
	eth_hw_addr_set(netdev, mac);
	ether_addr_copy(vsi->port_info->addr, mac);
	netif_addr_unlock_bh(netdev);
	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags) && vf && vf->vfinfo)
		memcpy(vf->vfinfo[PFINFO_IDX].vf_mac_addr, vsi->port_info->addr,
		       ETH_ALEN);

	/* update MAC station address used for PFC/pause frame source MAC */
	if (hw->ops->set_mac_station_addr)
		hw->ops->set_mac_station_addr(hw, vsi->port_info->addr);

	return 0;
}

/**
 * mce_check_mtu_valid - check if specified MTU can be set for a netdev
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns: 0 if MTU is valid, negative otherwise
 */
static int mce_check_mtu_valid(struct net_device *netdev, int new_mtu)
{
	if (new_mtu < ETH_MIN_MTU) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   ETH_MIN_MTU);
		return -EINVAL;
	} else if (new_mtu > MCE_MAX_MTU) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   MCE_MAX_MTU);
		return -EINVAL;
	}

	return 0;
}

/**
 * mce_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns: 0 on success, negative on failure
 */
static int mce_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	int err = 0;

	if (new_mtu == (int)netdev->mtu) {
		netdev_warn(netdev, "MTU is already %u\n", netdev->mtu);
		return 0;
	}

	err = mce_check_mtu_valid(netdev, new_mtu);
	if (err)
		return err;

	/* if mrdma insmod, max 9600 */
	if (pf->m_status == MRDMA_INSMOD && new_mtu > NORMAL_MTU)
		return -EINVAL;

	netdev->mtu = (unsigned int)new_mtu;
	/* record mtu */
	if (!test_bit(MCE_VSI_HOLD_VALID_MTU, vsi->state))
		pf->valid_mtu = new_mtu;

	/* if mtu more than 1500, force close pfc */
	if (new_mtu > NORMAL_MTU && test_bit(MCE_PFC_EN, dcb->flags)) {
		clear_bit(MCE_PFC_EN, dcb->flags);
		mce_dcb_update_hwpfccfg(dcb);
	}

	/* if VSI is up, bring it down and then back up */
	if (!test_and_set_bit(MCE_VSI_DOWN, vsi->state)) {
		err = mce_down(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_down err %d\n", err);
			return err;
		}

		err = mce_up(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_up err %d\n", err);
			return err;
		}
	}

	netdev_dbg(netdev, "changed MTU to %d\n", new_mtu);
	set_bit(MCE_FLAG_MTU_CHANGED, pf->flags);

	return 0;
}

/**
 * mce_find_tnl - return -1 mean not match ; return 0 ~ 7 mean matched
 * @hw: pointer to PF struct
 * @tnl_type: tunnel type
 * @port: tunnel port
 * Returns: The result of the operation.
 */
static int mce_find_tnl(struct mce_hw *hw, enum mce_tunnel_type tnl_type,
			u16 port)
{
	struct mce_tunnel_entry *tnl_entry;
	int ret = -1;
	u16 i = 0;

	if (tnl_type >= TNL_ALL) {
		dev_err(hw->dev, "Unknown  tunnel type\n");
		return ret;
	}

	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		tnl_entry = &hw->tnl[tnl_type].tbl[i];
		if (!tnl_entry->in_use)
			continue;

		if (tnl_entry->port == port) {
			ret = i;
			break;
		}
	}

	return ret;
}

/**
 * mce_check_tx_hang - periodic Tx-hang check per queue vector
 * @pf: private board structure
 *
 * Walks every queue vector of the main VSI, compares event counters,
 * and logs or triggers Tx-hang recovery when a ring is stuck.
 */
void mce_check_tx_hang(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_hw *hw = &vsi->back->hw;
	struct mce_q_vector *q_vector;
	struct mce_ring *ring = NULL;
	unsigned long start_time;
	int idx;

	if (test_bit(MCE_VSI_DOWN, vsi->state))
		return;

	mce_for_each_q_vector(vsi, idx) {
		u16 event_old, event;

		q_vector = vsi->q_vectors[idx];
		start_time = q_vector->check_jiffies;

		/* if in polling, no-need check */
		if (test_bit(MCE_Q_VECTOR_POLLING, q_vector->state)) {
			mce_rc_for_each_ring(ring, q_vector->tx)
				ring->next_to_clean_old = 0xffff;
			continue;
		}
		/* check freq 1 hz, if not time, no-need-check */
		if (!time_after(jiffies, (start_time + pf->serv_tmr_period)))
			continue;

		q_vector->check_jiffies = jiffies;
		event_old = q_vector->total_events_old;
		event = q_vector->total_events;

		/* if event comes, no need check */
		if (event_old != event) {
			q_vector->total_events_old = event;
			mce_rc_for_each_ring(ring, q_vector->tx)
				ring->next_to_clean_old = 0xffff;
			continue;
		}

		mce_rc_for_each_ring(ring, q_vector->tx) {
			u16 ntc_old = ring->next_to_clean_old;
			u16 ntc = ring->next_to_clean;
			u16 ntu = ring->next_to_use;

			if (ntu == ntc) {
				ring->next_to_clean_old = 0xffff;
				continue;
			}

			/* if send hw data, waitting dd */
			/* has chance just ntc twice */
			if (ntc_old == ntc) {
				/* check not kick */
				if (ring_rd32(ring, 0x70) != ntu) {
					dev_err(&pf->pdev->dev, "kick to hw %d\n", ring->q_index);
					dev_err(&pf->pdev->dev,
						"ntu %d ntc %d hw %d\n", ntu, ntc,
						ring_rd32(ring, 0x70));
					raw_wr32(ntu, ring->tail);
				} else {
					dev_err(&pf->pdev->dev,
						"tx-hang detected idx %d\n",
							ring->q_index);
					dev_err(&pf->pdev->dev,
						"ntu %d ntc %d hw tail %d hw head %d %lx %lx\n",
						ntu, ntc, ring_rd32(ring, 0x70),
						ring_rd32(ring, 0x6c), start_time, jiffies);
					/* trig this irq */
					hw->ops->set_txring_trig_intr(ring);
					ring->ring_stats->tx_stats.period_intr_drop++;
				}
			} else {
				ring->next_to_clean_old = ntc;
			}
		}
	}
}

/**
 * mce_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: Tx queue
 */
static void mce_tx_timeout(struct net_device *netdev,
			   unsigned int __always_unused txqueue)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);

/* this should more than pfc dead lock(10s) */
#define TX_TIMEO_LIMIT 20000
	netdev_info(netdev, "juest delay watchdog_timeo now %d\n", netdev->watchdog_timeo);
	if (netdev->watchdog_timeo < TX_TIMEO_LIMIT) {
		netdev->watchdog_timeo *= 2;
		pf->tx_timeout_recovery_level = 1;
	} else {
		pf->tx_timeout_recovery_level = 2;
		netdev->watchdog_timeo = 5 * HZ;
	}
}

/**
 * mce_udp_tunnel_add - Get notifications about UDP tunnel ports that come up
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
static void __maybe_unused mce_udp_tunnel_add(struct net_device *netdev,
					      struct udp_tunnel_info *ti)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	enum mce_tunnel_type tnl_type;
	struct mce_hw *hw = &pf->hw;
	u16 port = ntohs(ti->port);
	int index = -1;

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		tnl_type = TNL_VXLAN;
		break;
	case UDP_TUNNEL_TYPE_GENEVE:
		tnl_type = TNL_GENEVE;
		break;
	default:
		netdev_err(netdev, "Unknown tunnel type\n");
		return;
	}

	mutex_lock(&hw->tnl_lock);
	index = mce_find_tnl(hw, tnl_type, port);
	if (index >= 0) {
		++hw->tnl[tnl_type].tbl[index].ref_cnt;
	} else {
		if (hw->tnl[tnl_type].tnl_cnt >= MCE_TUNNEL_MAX_ENTRIES - 1) {
			netdev_info(netdev,
				    "Max tunneled UDP ports:%d reached(reserved one for default), port %d not added\n",
				MCE_TUNNEL_MAX_ENTRIES, port);
			mutex_unlock(&hw->tnl_lock);
			return;
		}
		hw->ops->add_udp_tnl(hw, tnl_type, port);
	}
	mutex_unlock(&hw->tnl_lock);
}

/**
 * mce_udp_tunnel_del - Get notifications about UDP tunnel ports that go away
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
static void __maybe_unused mce_udp_tunnel_del(struct net_device *netdev,
					      struct udp_tunnel_info *ti)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	enum mce_tunnel_type tnl_type;
	u16 port = ntohs(ti->port);
	int index = -1;

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		tnl_type = TNL_VXLAN;
		break;
	case UDP_TUNNEL_TYPE_GENEVE:
		tnl_type = TNL_GENEVE;
		break;
	default:
		netdev_err(netdev, "Unknown tunnel type\n");
		return;
	}
	mutex_lock(&hw->tnl_lock);
	index = mce_find_tnl(hw, tnl_type, port);
	if (index >= 0) {
		if (hw->tnl[tnl_type].tbl[index].ref_cnt > 0)
			hw->tnl[tnl_type].tbl[index].ref_cnt--;
		if (!hw->tnl[tnl_type].tbl[index].ref_cnt)
			hw->ops->del_udp_tnl(hw, tnl_type, port);
	} else {
		netdev_err(netdev,
			   "Unable to find Tunnel, port %u, tnl_type %u\n",
			   port, tnl_type);
	}
	mutex_unlock(&hw->tnl_lock);
}

/**
 * mce_get_dscp_up - return the UP/TC value for a SKB
 * @dcb: DCB config that contains DSCP to UP/TC mapping
 * @skb: SKB to query for info to determine UP/TC
 *
 * This function is to only be called when the PF is in L3 DSCP PFC mode
 * Returns: The result of the operation.
 */
static u8 mce_get_dscp_up(struct mce_dcb *dcb, struct sk_buff *skb)
{
	u8 dscp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return dcb->dscp_map[dscp];
}

static u16 mce_select_queue(struct net_device *netdev, struct sk_buff *skb,
			    struct net_device *sb_dev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	static int e_id = 0, s_id = 0, step, q_id;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &dcb->cur_etscfg;
	struct mce_tc_cfg *tccfg = &dcb->cur_tccfg;
	u16 queue_offset = 0;
	int tc = 0;
	u16 queue;

	if (pf->d_txqueue.en && pf->d_txqueue.permit) {
		s_id = pf->d_txqueue.s_id;
		e_id = pf->d_txqueue.e_id;
		step = e_id - s_id + 1;
		q_id = netdev_pick_tx(netdev, skb, sb_dev);
		q_id = q_id % step + s_id;
		pf->d_txqueue.r_id = q_id;
		return q_id;
	}
	/* if open vlan-map-queue, use vlan map it */
	if (test_bit(MCE_FLAG_PF_VLAN_Q_MAP, pf->flags)) {
		int vid = -1;

		if (skb_vlan_tag_present(skb)) {
			vid = skb_vlan_tag_get(skb) & 0xfff;
		} else if (__VLAN_ALLOWED(skb->protocol)) {
			struct vlan_hdr *vhdr, _vhdr;

			vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr),
						  &_vhdr);
			if (!vhdr)
				goto skip_prio;

			vid = ntohs(vhdr->h_vlan_TCI) & 0xfff;
		}

		if (vid != -1 && dcb->vlan_to_q[vid] != 0xff)
			return queue = dcb->vlan_to_q[vid] % vsi->num_txq_real;
	}

	if (test_bit(MCE_DSCP_EN, dcb->flags)) {
		skb->priority = mce_get_dscp_up(dcb, skb);
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
		/* no vlan packet use stack prio */
	}
skip_prio:
	/* if prio is not valid for this nic, use a valid one */
	/* only do this if ets or pfc on */
	if (test_bit(MCE_ETS_EN, dcb->flags) ||
	    test_bit(MCE_PFC_EN, dcb->flags)) {
		if (!(vsi->valid_prio & (1 << skb->priority)))
			skb->priority = ffs(vsi->valid_prio) - 1;
	}
	/* should check nic valid prio */
	queue = netdev_pick_tx(netdev, skb, sb_dev);
	if (test_bit(MCE_DCB_IN_PROGRESS, pf->state))
		return 0;

	/* if ets on, we change tc, and queue_offset */
	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		tc = etscfg->prio_table[skb->priority & TC_BITMASK];
		/* if ets on, we should offset queue */
		queue_offset = tc * vsi->num_txq_real;
	}

	/* if pfc on, we use pfx_txq_base and pfc_txq_count */
	if (test_bit(MCE_PFC_EN, dcb->flags)) {
		if (tccfg->pfc_txq_count[tc][skb->priority]) {
			queue = (tccfg->pfc_txq_base[tc][skb->priority] +
				 (queue %
				  tccfg->pfc_txq_count[tc][skb->priority]));
		} else {
			queue = 0;
		}
	}

	/* if dcb on, queue should only in tc range */
	if (test_bit(MCE_DCB_EN, dcb->flags))
		queue = queue % vsi->num_txq_real;

	/* try to offset queue */
	queue = queue_offset + queue;

	return queue;
}

/**
 * mce_bridge_getlink - Get the hardware bridge mode
 * @skb: skb buff
 * @pid: process ID
 * @seq: RTNL message seq
 * @dev: the netdev being configured
 * @filter_mask: filter mask passed in
 * @nlflags: netlink flags passed in
 *
 * Return: the bridge mode (VEB/VEPA)
 */
static int mce_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
			      struct net_device *dev, u32 filter_mask,
			       int nlflags)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	u16 bmode;

	bmode = pf->bridge_mode;
	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, bmode, 0, 0, nlflags,
				       filter_mask, NULL);
}

/**
 * mce_bridge_setlink - Set the hardware bridge mode
 * @dev: the netdev being configured
 * @nlh: RTNL message
 * @flags: bridge setlink flags
 * @extack: netlink extended ack
 *
 * Sets the bridge mode (VEB/VEPA) of the switch to which the netdev (VSI) is
 * hooked up to. Iterates through the PF VSI list and sets the loopback mode (if
 * not already set for all VSIs connected to this switch. And also update the
 * unicast switch filter rules for the corresponding switch of the netdev.
 * Returns: The result of the operation.
 */
static int mce_bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
			      u16 __always_unused flags,
			       struct netlink_ext_ack __always_unused *extack)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_pf *pf = np->vsi->back;
	struct nlattr *attr, *br_spec;
	struct mce_hw *hw = &pf->hw;
	int rem, ret;

	/* find the attribute in the netlink message */
	br_spec = nlmsg_find_attr(nlh, sizeof(struct ifinfomsg), IFLA_AF_SPEC);
	nla_for_each_nested(attr, br_spec, rem) {
		__u16 mode;

		if (nla_type(attr) != IFLA_BRIDGE_MODE)
			continue;
		mode = nla_get_u16(attr);
		if (mode != BRIDGE_MODE_VEPA && mode != BRIDGE_MODE_VEB)
			return -EINVAL;
		if (mode == pf->bridge_mode)
			continue;

		ret = mce_vf_set_evb_vepa_mode(hw, mode == BRIDGE_MODE_VEPA);
		if (!ret) {
			/* switch veb/vepa mode */
			if (mode == BRIDGE_MODE_VEPA)
				set_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags);
			else
				clear_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags);
		}
	}
	return 0;
}

static netdev_features_t mce_fix_features(struct net_device *netdev,
					  netdev_features_t features)
{
	(void)netdev;
	if (!(features & NETIF_F_HW_VLAN_CTAG_RX))
		features &= ~NETIF_F_HW_VLAN_STAG_RX;

	if (!(features & NETIF_F_HW_VLAN_STAG_RX))
		features &= ~NETIF_F_HW_VLAN_CTAG_RX;

	if (!(features & NETIF_F_HW_VLAN_CTAG_TX))
		features &= ~NETIF_F_HW_VLAN_STAG_TX;

	if (!(features & NETIF_F_HW_VLAN_STAG_TX))
		features &= ~NETIF_F_HW_VLAN_CTAG_TX;
	return features;
}

#define MCE_TXD_CTX_MIN_MSS 64
#define MCE_MAX_TUNNEL_HDR_LEN 80
#define MCE_MAX_MAC_HDR_LEN 127
#define MCE_MAX_NETWORK_HDR_LEN 511

/**
 * mce_features_check - validate packet headers against hardware limits
 * @skb: packet to validate
 * @netdev: network device being checked
 * @features: offloads requested for this packet
 *
 * The hardware has finite descriptor-header fields.  Remove checksum and
 * segmentation offloads when an encapsulated packet cannot be represented.
 */
static netdev_features_t
mce_features_check(struct sk_buff *skb,
		   struct net_device __always_unused *netdev,
		   netdev_features_t features)
{
	bool gso = skb_is_gso(skb);
	size_t len;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	if (gso && skb_shinfo(skb)->gso_size < MCE_TXD_CTX_MIN_MSS)
		features &= ~NETIF_F_GSO_MASK;

	len = skb_network_offset(skb);
	if (len > MCE_MAX_MAC_HDR_LEN)
		goto out_rm_features;

	len = skb_network_header_len(skb);
	if (len > MCE_MAX_NETWORK_HDR_LEN)
		goto out_rm_features;

	if (skb->encapsulation) {
		if (gso && (skb_shinfo(skb)->gso_type &
			    (SKB_GSO_GRE | SKB_GSO_UDP_TUNNEL))) {
			len = skb_inner_mac_header(skb) - skb_transport_header(skb);
			if (len > MCE_MAX_TUNNEL_HDR_LEN)
				goto out_rm_features;
		}

		len = skb_inner_network_header_len(skb);
		if (len > MCE_MAX_NETWORK_HDR_LEN)
			goto out_rm_features;
	}

	return features;

out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

static const struct net_device_ops mce_netdev_ops = {
	.ndo_open = mce_open,
	.ndo_stop = mce_stop,
	.ndo_start_xmit = mce_start_xmit,
	.ndo_get_stats64 = mce_get_stats64,
	.ndo_set_features = mce_set_features,
	.ndo_features_check = mce_features_check,
	.ndo_bridge_getlink = mce_bridge_getlink,
	.ndo_bridge_setlink = mce_bridge_setlink,
#ifdef CONFIG_RFS_ACCEL
#endif
	.ndo_set_rx_mode = mce_set_rx_mode,
	.ndo_do_ioctl = mce_ioctl,
	.ndo_vlan_rx_add_vid = mce_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = mce_vlan_rx_kill_vid,
	.ndo_fix_features = mce_fix_features,
	.ndo_change_mtu = mce_change_mtu,
	.ndo_set_mac_address = mce_set_mac_address,
	.ndo_set_vf_spoofchk = mce_set_vf_spoofchk,

	.ndo_set_vf_vlan = mce_set_vf_port_vlan,
	.ndo_tx_timeout = mce_tx_timeout,
	.ndo_select_queue = mce_select_queue,
};

/**
 * mce_set_netdev_features - set features for the given netdev
 * @netdev: netdev instance
 */
static void mce_set_netdev_features(struct net_device *netdev)
{
	netdev_features_t csumo_features = 0;
	netdev_features_t vlano_features = 0;
	netdev_features_t dflt_features = 0;
	netdev_features_t tso_features = 0;
	netdev_features_t fixon_features = 0;

	dflt_features |= NETIF_F_SG;
	dflt_features |= NETIF_F_HIGHDMA;
	dflt_features |= NETIF_F_RXHASH;

	fixon_features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	fixon_features |= NETIF_F_HW_VLAN_STAG_FILTER;
	csumo_features |= NETIF_F_HW_CSUM;
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
	tso_features |= NETIF_F_GSO_GRE_CSUM;
	tso_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM;
	tso_features |= NETIF_F_GSO_PARTIAL;
	tso_features |= NETIF_F_GSO_IPXIP4;
	tso_features |= NETIF_F_GSO_IPXIP6;
	tso_features |= NETIF_F_GSO_UDP_L4;

	netdev->gso_partial_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM;
	netdev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
	netdev->gso_partial_features |= NETIF_F_GSO_UDP_TUNNEL;
	netdev->gso_partial_features |= NETIF_F_GSO_GRE;

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

	netdev->hw_features |= NETIF_F_RXFCS;
	netdev->hw_features |= NETIF_F_RXALL;
}

/**
 * mce_cfg_netdev - Allocate, configure and register a netdev
 * @vsi: the VSI associated with the new netdev
 *
 * Returns: 0 on success, negative value on failure
 */
int mce_cfg_netdev(struct mce_vsi *vsi)
{
	struct mce_netdev_priv *np = NULL;
	struct net_device *netdev = NULL;
	int alloc_txq = vsi->alloc_txq;
	int alloc_rxq = vsi->alloc_rxq;
	struct mce_pf *pf = vsi->back;

	netdev = alloc_etherdev_mqs(sizeof(*np), alloc_txq, alloc_rxq);
	if (!netdev)
		return -ENOMEM;

	netdev->max_mtu = MCE_MAX_MTU;

	set_bit(MCE_VSI_NETDEV_ALLOCD, vsi->state);
	vsi->netdev = netdev;
	np = netdev_priv(netdev);
	np->vsi = vsi;

	mce_set_netdev_features(netdev);
	netdev->netdev_ops = &mce_netdev_ops;
	mce_set_ethtool_ops(netdev);

	mce_set_dcbnl_ops(netdev);

	if (vsi->type == MCE_VSI_PF) {
		SET_NETDEV_DEV(netdev, mce_pf_to_dev(vsi->back));
		if (is_valid_ether_addr(vsi->port_info->perm_addr)) {
			ether_addr_copy(vsi->port_info->addr,
					vsi->port_info->perm_addr);
			eth_hw_addr_set(netdev, vsi->port_info->perm_addr);
			ether_addr_copy(netdev->perm_addr,
					vsi->port_info->perm_addr);
		} else {
			netdev_warn(netdev, "Invalid MAC address in list; "
					    "using random MAC");
			eth_hw_addr_random(netdev);
			ether_addr_copy(vsi->port_info->addr, netdev->dev_addr);
		}
	}

	netdev->priv_flags |= IFF_UNICAST_FLT;

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 5 * HZ;

	/* we start from normal */
	pf->valid_mtu = 1500;
	return 0;
}

/**
 * mce_register_netdev - register netdev and devlink port
 * @pf: pointer to the PF struct
 * Returns: The result of the operation.
 */
int mce_register_netdev(struct mce_pf *pf)
{
	struct mce_vsi *vsi;
	int err = 0;

	vsi = mce_get_main_vsi(pf);
	if (!vsi || !vsi->netdev)
		return -EIO;

	err = register_netdev(vsi->netdev);
	if (err)
		goto err_register_netdev;

	set_bit(MCE_VSI_NETDEV_REGISTERED, vsi->state);

	netif_carrier_off(vsi->netdev);
	netif_tx_stop_all_queues(vsi->netdev);
	mce_vsi_dcb_default(vsi);

	return 0;
err_register_netdev:
	free_netdev(vsi->netdev);
	vsi->netdev = NULL;
	clear_bit(MCE_VSI_NETDEV_ALLOCD, vsi->state);
	return err;
}
