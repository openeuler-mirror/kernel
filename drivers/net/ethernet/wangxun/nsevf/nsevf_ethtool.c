// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* ethtool support for nsevf */
#include "nsevf.h"

#include <linux/uaccess.h>

#include "nsevf_ethtool_stats.h"
#include "nsevf_fdir.h"

#define VF_STAT(_name, _stat) NSEVF_STAT(struct nsevf_adapter, _name, _stat)

#define NSEVF_RX_PKTS "rx_packets"
#define NSEVF_RX_BYTES "rx_bytes"
#define NSEVF_RX_UNICAST "rx_unicast"
#define NSEVF_RX_MULTICAST "rx_multicast"
#define NSEVF_RX_BROADCAST "rx_broadcast"
#define NSEVF_RX_DROPPED_ERR "rx_dropped_err"
#define NSEVF_RX_DROPPED_NO_DESC "rx_dropped_no_desc"
#define NSEVF_RX_DROPPED_DPKT "rx_dropped_dpkt"
#define NSEVF_RX_CSUM_GOOD "rx_csum_good"
#define NSEVF_RX_CSUM_BAD "rx_csum_bad"

#define NSEVF_TX_PKTS "tx_packets"
#define NSEVF_TX_BYTES "tx_bytes"
#define NSEVF_TX_UNICAST "tx_unicast"
#define NSEVF_TX_MULTICAST "tx_multicast"
#define NSEVF_TX_BROADCAST "tx_broadcast"

#define NSEVF_FDIR_MATCH "fdir_match"
#define NSEVF_FDIR_MISS "fdir_miss"

static const struct nsevf_stats nsevf_gstrings_stats[] = {
	VF_STAT(NSEVF_RX_PKTS, sw_stats.rx_pkts),
	VF_STAT(NSEVF_RX_BYTES, sw_stats.rx_bytes),
	VF_STAT(NSEVF_RX_UNICAST, hw_stats.rx_upkt),
	VF_STAT(NSEVF_RX_MULTICAST, hw_stats.rx_mpkt),
	VF_STAT(NSEVF_RX_BROADCAST, hw_stats.rx_bpkt),
	VF_STAT(NSEVF_RX_DROPPED_ERR, hw_stats.rx_drop_err),
	VF_STAT(NSEVF_RX_DROPPED_NO_DESC, hw_stats.rx_drop_no_desc),
	VF_STAT(NSEVF_RX_DROPPED_DPKT, hw_stats.rx_dpkt),

	VF_STAT(NSEVF_RX_CSUM_GOOD, sw_stats.rx_csum_good),
	VF_STAT(NSEVF_RX_CSUM_BAD, sw_stats.rx_csum_bad),

	VF_STAT(NSEVF_TX_PKTS, sw_stats.tx_pkts),
	VF_STAT(NSEVF_TX_BYTES, sw_stats.tx_bytes),
	VF_STAT(NSEVF_TX_UNICAST, hw_stats.tx_uptc),
	VF_STAT(NSEVF_TX_MULTICAST, hw_stats.tx_mptc),
	VF_STAT(NSEVF_TX_BROADCAST, hw_stats.tx_bptc),

	VF_STAT(NSEVF_FDIR_MATCH, sw_stats.fdir_match),
	VF_STAT(NSEVF_FDIR_MISS, sw_stats.fdir_miss),

};

#define NSEVF_STATS_LEN ARRAY_SIZE(nsevf_gstrings_stats)

#define NSEVF_TXQ_STATS_LEN ARRAY_SIZE(nsevf_gstrings_txq_stats)
#define NSEVF_RXQ_STATS_LEN ARRAY_SIZE(nsevf_gstrings_rxq_stats)

#define NSEVF_TXCQ_STATS_LEN ARRAY_SIZE(nsevf_gstrings_txcq_stats)

/* For now we have one and only one private flag and it is only defined
 * when we have support for the SKIP_CPU_SYNC DMA attribute.  Instead
 * of leaving all this code sitting around empty we will strip it unless
 * our one private flag is actually available.
 */
struct nsevf_priv_flags {
	char flag_string[ETH_GSTRING_LEN];
	u32 flag;
	bool read_only;
};

#define NSEVF_PRIV_FLAG(_name, _flag, _read_only) \
	{                                         \
		.flag_string = _name,             \
		.flag = _flag,                    \
		.read_only = _read_only,          \
	}

static const struct nsevf_priv_flags nsevf_gstrings_priv_flags[] = {
	NSEVF_PRIV_FLAG("legacy-rx", NSEVF_FLAG_LEGACY_RX, 0),
};

#define NSEVF_PRIV_FLAGS_STR_LEN ARRAY_SIZE(nsevf_gstrings_priv_flags)

/**
 * nsevf_get_sset_count - Get length of string set
 * @netdev: network interface device structure
 * @sset: id of string set
 *
 * Reports size of various string tables.
 **/
static int nsevf_get_sset_count(struct net_device *netdev, int sset)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	int ret = 0;

	/* Report the maximum number queues, even if not every queue is
	 * currently configured. Since allocation of queues is in pairs,
	 * use netdev->real_num_tx_queues * 2. The real_num_tx_queues is set
	 * at device creation and never changes.
	 */
	if (sset == ETH_SS_STATS) {
		ret = NSEVF_STATS_LEN;

		/* in nsevf_set_interrupt_capability(), we have:
		 *
		 *		pairs = adapter->num_active_queues;
		 *
		 *		netif_set_real_num_rx_queues(adapter->netdev, pairs);
		 *		netif_set_real_num_tx_queues(adapter->netdev, pairs);
		 */

		/* Rx rings stats */
		ret += (NSEVF_RXQ_STATS_LEN * netdev->real_num_rx_queues);

		/* Tx rings stats */
		ret += (NSEVF_TXQ_STATS_LEN * netdev->real_num_tx_queues);

		/* TX-CQ rings stats, if any */
		if (adapter->sw_conf.lan_tx_use_cq)
			ret += (NSEVF_TXCQ_STATS_LEN *
				adapter->vf_res->lan_txcq_num);

		return ret;
	} else if (sset == ETH_SS_PRIV_FLAGS) {
		return NSEVF_PRIV_FLAGS_STR_LEN;
	} else {
		return -EINVAL;
	}
}

/**
 * nsevf_get_ethtool_stats - report device statistics
 * @netdev: network interface device structure
 * @stats: ethtool statistics structure
 * @data: pointer to data buffer
 *
 * All statistics are added to the data buffer as an array of u64.
 **/
static void nsevf_get_ethtool_stats(struct net_device *netdev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	struct nsevf_ring *ring;
	struct nsevf_txcq_ring *cq_ring;
	unsigned int i;

	/* Explicitly request stats refresh */
	nsevf_schedule_aq_request(adapter, NSEVF_FLAG_AQ_REQUEST_STATS);

	nsevf_update_sw_stats(adapter);

	nsevf_add_ethtool_stats(&data, adapter, nsevf_gstrings_stats);

	rcu_read_lock();
	/* As num_active_queues describe both tx and rx queues, we can use
	 * it to iterate over rings' stats.
	 */

	/* Rx rings stats */
	for (i = 0; i < adapter->num_active_queues; i++) {
		ring = &adapter->rx_rings[i];
		nsevf_add_txq_rxq_stats(&data, ring, false);
	}

	/* Tx rings stats */
	for (i = 0; i < adapter->num_active_queues; i++) {
		ring = &adapter->tx_rings[i];
		nsevf_add_txq_rxq_stats(&data, ring, true);
	}

	/* TX-CQ rings stats, if any */
	if (adapter->sw_conf.lan_tx_use_cq) {
		nsevf_for_each_txcq(adapter, i) {
			if (adapter->txcq_rings)
				cq_ring = &adapter->txcq_rings[i];
			else
				cq_ring = NULL;

			nsevf_add_txcq_stats(&data, cq_ring);
		}
	}

	rcu_read_unlock();
}

/**
 * nsevf_get_priv_flag_strings - Get private flag strings
 * @netdev: network interface device structure
 * @data: buffer for string data
 *
 * Builds the private flags string table
 **/
static void nsevf_get_priv_flag_strings(struct net_device *netdev, u8 *data)
{
	unsigned int i;

	for (i = 0; i < NSEVF_PRIV_FLAGS_STR_LEN; i++) {
		snprintf(data, ETH_GSTRING_LEN, "%s",
			 nsevf_gstrings_priv_flags[i].flag_string);
		data += ETH_GSTRING_LEN;
	}
}

/**
 * nsevf_get_stat_strings - Get stat strings
 * @netdev: network interface device structure
 * @data: buffer for string data
 *
 * Builds the statistics string table
 **/
static void nsevf_get_stat_strings(struct net_device *netdev, u8 *data)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	unsigned int i;

	nsevf_add_stat_strings(&data, nsevf_gstrings_stats);

	/* Queues are always allocated in pairs, so we just use
	 * real_num_tx_queues for both Tx and Rx queues.
	 */

	/* Rx rings stats */
	for (i = 0; i < netdev->real_num_rx_queues; i++)
		nsevf_add_stat_strings(&data, nsevf_gstrings_rxq_stats, i);

	/* Tx rings stats */
	for (i = 0; i < netdev->real_num_tx_queues; i++)
		nsevf_add_stat_strings(&data, nsevf_gstrings_txq_stats, i);

	/* TX-CQ rings stats, if any */
	if (adapter->sw_conf.lan_tx_use_cq) {
		for (i = 0; i < adapter->vf_res->lan_txcq_num; i++) {
			nsevf_add_stat_strings(&data, nsevf_gstrings_txcq_stats,
					       i);
		}
	}
}

/**
 * nsevf_get_strings - Get string set
 * @netdev: network interface device structure
 * @sset: id of string set
 * @data: buffer for string data
 *
 * Builds string tables for various string sets
 **/
static void nsevf_get_strings(struct net_device *netdev, u32 sset, u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		nsevf_get_stat_strings(netdev, data);
		break;
	case ETH_SS_PRIV_FLAGS:
		nsevf_get_priv_flag_strings(netdev, data);
		break;
	default:
		break;
	}
}

/**
 * nsevf_get_priv_flags - report device private flags
 * @netdev: network interface device structure
 *
 * The get string set count and the string set should be matched for each
 * flag returned.  Add new strings for each flag to the nsevf_gstrings_priv_flags
 * array.
 *
 * Returns a u32 bitmap of flags.
 **/
static u32 nsevf_get_priv_flags(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	const struct nsevf_priv_flags *priv_flags;
	u32 i, ret_flags = 0;

	for (i = 0; i < NSEVF_PRIV_FLAGS_STR_LEN; i++) {
		priv_flags = &nsevf_gstrings_priv_flags[i];

		if (priv_flags->flag & adapter->flags)
			ret_flags |= BIT(i);
	}

	return ret_flags;
}

/**
 * nsevf_determine_priv_flag_change - detect any change in private flags
 * @priv_flags: Ptr to private flags array
 * @num: count of private flags
 * @bit_offset: "offset" into unified view of bits
 * @flags: bit flags to be set
 * @orig: Ptr to flags
 * @changed_flags: bits changed (based on orig and new value)
 *
 * Detect any changes in priv flags and return those changed bits
 **/
static int
nsevf_determine_priv_flag_change(const struct nsevf_priv_flags *priv_flags,
				 int num, int bit_offset, u32 flags, u32 *orig,
				 u32 *changed_flags)
{
	u32 orig_flags = READ_ONCE(*orig);
	u32 new_flags;
	int i;

	new_flags = orig_flags;

	for (i = 0; i < num; i++) {
		if (flags & BIT(i + bit_offset))
			new_flags |= priv_flags->flag;
		else
			new_flags &= ~(priv_flags->flag);

		if (priv_flags->read_only &&
		    ((orig_flags ^ new_flags) & ~BIT(i)))
			return -EOPNOTSUPP;
		priv_flags++;
	}

	/* Before we finalize any flag changes, any checks which we need to
	 * perform to determine if the new flags will be supported should go
	 * here...
	 */

	/* Compare and exchange the new flags into place. If we failed, that
	 * is if cmpxchg returns anything but the old value, this means
	 * something else must have modified the flags variable since we
	 * copied it. We'll just punt with an error and log something in the
	 * message buffer.
	 */
	if (cmpxchg(orig, orig_flags, new_flags) != orig_flags)
		return -EAGAIN;

	*changed_flags = orig_flags ^ new_flags;
	return 0;
}

/**
 * nsevf_set_priv_flags - set private flags
 * @netdev: network interface device structure
 * @flags: bit flags to be set
 **/
static int nsevf_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	u32 changed_flags;
	int ret;

	ret = nsevf_determine_priv_flag_change(&nsevf_gstrings_priv_flags[0],
					       NSEVF_PRIV_FLAGS_STR_LEN, 0,
					       flags, &adapter->flags,
					       &changed_flags);
	if (ret) {
		if (ret == -EAGAIN)
			dev_warn(&adapter->pdev->dev,
				 "Unable to update adapter->flags as it was modified by another thread...\n");
		return ret;
	}

	/* Process any additional changes needed as a result of flag changes.
	 * The changed_flags value reflects the list of bits that were changed
	 * in the code above.
	 */

	/* issue a reset to force legacy-rx change to take effect */
	if (changed_flags & NSEVF_FLAG_LEGACY_RX) {
		if (netif_running(netdev))
			nsevf_schedule_reset(adapter, NSEVF_FLAG_RESET_NEEDED);
	}

	return 0;
}

/**
 * nsevf_get_msglevel - Get debug message level
 * @netdev: network interface device structure
 *
 * Returns current debug message level.
 **/
static u32 nsevf_get_msglevel(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	return adapter->msg_enable;
}

/**
 * nsevf_set_msglevel - Set debug message level
 * @netdev: network interface device structure
 * @data: message level
 *
 * Set current debug message level. Higher values cause the driver to
 * be noisier.
 **/
static void nsevf_set_msglevel(struct net_device *netdev, u32 data)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	if (NSEVF_DBG_USER & data)
		adapter->hw.debug_mask = data;
	adapter->msg_enable = data;
}

/**
 * nsevf_get_drvinfo - Get driver info
 * @netdev: network interface device structure
 * @drvinfo: ethool driver info structure
 *
 * Returns information about the driver and device for display to the user.
 **/
static void nsevf_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	strscpy(drvinfo->driver, nsevf_driver_name, 32);
	strscpy(drvinfo->version, nsevf_driver_version, 32);
	strscpy(drvinfo->fw_version, "N/A", 4);
	strscpy(drvinfo->bus_info, pci_name(adapter->pdev), 32);
	drvinfo->n_priv_flags = NSEVF_PRIV_FLAGS_STR_LEN;
}

/**
 * nsevf_get_ringparam - Get ring parameters
 * @netdev: network interface device structure
 * @ring: ethtool ringparam structure
 * @ker: unused kernel ethtool ringparam structure
 * @extack: unused netlink extended ACK structure
 *
 * Returns current ring parameters. TX and RX rings are reported separately,
 * but the number of rings is not reported.
 **/
static void
nsevf_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring,
		    struct kernel_ethtool_ringparam __always_unused *ker,
		    struct netlink_ext_ack __always_unused *extack)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	ring->rx_max_pending = NSEVF_MAX_RXD;
	ring->tx_max_pending = NSEVF_MAX_TXD;
	ring->rx_pending = adapter->rx_desc_count;
	ring->tx_pending = adapter->tx_desc_count;
}

/**
 * nsevf_set_ringparam - Set ring parameters
 * @netdev: network interface device structure
 * @ring: ethtool ringparam structure
 * @ker: unused kernel ethtool ringparam structure
 * @extack: unused netlink extended ACK structure
 *
 * Sets ring parameters. TX and RX rings are controlled separately, but the
 * number of rings is not specified, so all rings get the same settings.
 **/
static int
nsevf_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring,
		    struct kernel_ethtool_ringparam __always_unused *ker,
		    struct netlink_ext_ack __always_unused *extack)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	u32 new_rx_count, new_tx_count;

	if (ring->rx_mini_pending || ring->rx_jumbo_pending)
		return -EINVAL;

	/* TODO: __NSEVF_RESETTING flags not cleanup after setting ringparam */
	if (adapter->state == __NSEVF_RESETTING ||
	    (adapter->state == __NSEVF_RUNNING &&
	     (adapter->flags & NSEVF_FLAG_QUEUES_DISABLED)))
		return -EAGAIN;

	if (ring->tx_pending > NSEVF_MAX_TXD ||
	    ring->tx_pending < NSEVF_MIN_TXD ||
	    ring->rx_pending > NSEVF_MAX_RXD ||
	    ring->rx_pending < NSEVF_MIN_RXD) {
		netdev_err(netdev,
			   "Descriptors requested (Tx: %d / Rx: %d) out of range [%d-%d] (increment %d)\n",
			ring->tx_pending, ring->rx_pending, NSEVF_MIN_TXD,
			NSEVF_MAX_RXD, NSEVF_REQ_DESCRIPTOR_MULTIPLE);
		return -EINVAL;
	}

	new_tx_count = ALIGN(ring->tx_pending, NSEVF_REQ_DESCRIPTOR_MULTIPLE);
	if (new_tx_count != ring->tx_pending)
		netdev_info(netdev,
			    "Requested Tx descriptor count rounded up to %d\n",
			    new_tx_count);

	new_rx_count = ALIGN(ring->rx_pending, NSEVF_REQ_DESCRIPTOR_MULTIPLE);
	if (new_rx_count != ring->rx_pending)
		netdev_info(netdev,
			    "Requested Rx descriptor count rounded up to %d\n",
			    new_rx_count);

	/* if nothing to do return success */
	if (new_tx_count == adapter->tx_desc_count &&
	    new_rx_count == adapter->rx_desc_count) {
		netdev_dbg(netdev,
			   "Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	if (new_tx_count != adapter->tx_desc_count) {
		netdev_info(netdev,
			    "Changing Tx descriptor count from %d to %d\n",
			    adapter->tx_desc_count, new_tx_count);
		adapter->tx_desc_count = new_tx_count;
	}

	if (new_rx_count != adapter->rx_desc_count) {
		netdev_info(netdev,
			    "Changing Rx descriptor count from %d to %d\n",
			    adapter->rx_desc_count, new_rx_count);
		adapter->rx_desc_count = new_rx_count;
	}

	if (netif_running(netdev))
		nsevf_schedule_reset(adapter, NSEVF_FLAG_RESET_NEEDED);

	return 0;
}

/**
 * __nsevf_get_coalesce - get per-queue coalesce settings
 * @netdev: the netdev to check
 * @ec: ethtool coalesce data structure
 * @queue: which queue to pick
 *
 * Gets the per-queue settings for coalescence. Specifically Rx and Tx usecs
 * are per queue. If queue is <0 then we default to queue 0 as the
 * representative value.
 **/
static int __nsevf_get_coalesce(struct net_device *netdev,
				struct ethtool_coalesce *ec, int queue)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	struct nsevf_ring *rx_ring;
	struct nsevf_q_vector *q_vector;

	/* Rx and Tx usecs per queue value. If user doesn't specify the
	 * queue, return queue 0's value to represent.
	 */
	if (queue < 0)
		queue = 0;
	else if (queue >= adapter->num_active_queues)
		return -EINVAL;

	rx_ring = &adapter->rx_rings[queue];

	q_vector = rx_ring->q_vector;

	ec->use_adaptive_rx_coalesce = ITR_IS_DYNAMIC(q_vector);
	ec->rx_coalesce_usecs = q_vector->itr_setting;
	ec->rx_coalesce_usecs_high = q_vector->intrl;

	return 0;
}

/**
 * nsevf_get_coalesce - Get interrupt coalescing settings
 * @netdev: network interface device structure
 * @ec: ethtool coalesce structure
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Returns current coalescing settings. This is referred to elsewhere in the
 * driver as Interrupt Throttle Rate, as this is how the hardware describes
 * this functionality. Note that if per-queue settings have been modified this
 * only represents the settings of queue 0.
 **/
static int
nsevf_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		   struct kernel_ethtool_coalesce __maybe_unused *kec,
		   struct netlink_ext_ack __maybe_unused *extack)
{
	return __nsevf_get_coalesce(netdev, ec, -1);
}

/**
 * nsevf_get_per_queue_coalesce - get coalesce values for specific queue
 * @netdev: netdev to read
 * @ec: coalesce settings from ethtool
 * @queue: the queue to read
 *
 * Read specific queue's coalesce settings.
 **/
static int nsevf_get_per_queue_coalesce(struct net_device *netdev, u32 queue,
					struct ethtool_coalesce *ec)
{
	return __nsevf_get_coalesce(netdev, ec, queue);
}

/**
 * nsevf_set_itr_per_queue - set ITR values for specific queue
 * @adapter: the VF adapter struct to set values for
 * @ec: coalesce settings from ethtool
 * @queue: the queue to modify
 *
 * Change the ITR settings for a specific queue.
 **/
static int nsevf_set_itr_per_queue(struct nsevf_adapter *adapter,
				   struct ethtool_coalesce *ec, int queue)
{
	const char *c_type_str = "rx";
	u32 use_adaptive_coalesce, coalesce_usecs;
	struct nsevf_ring *rx_ring = &adapter->rx_rings[queue];
	struct nsevf_q_vector *q_vector;
	u16 itr_setting;

	q_vector = rx_ring->q_vector;

	if (ec->rx_coalesce_usecs_high > NSE_INTRL_INTERVAL_MAX_USEC ||
	    (ec->rx_coalesce_usecs_high &&
	     ec->rx_coalesce_usecs_high < adapter->hw.intrl_gran)) {
		netdev_info(adapter->netdev,
			    "Invalid value, %s-usecs-high valid values are 0 (disabled), %d-%d\n",
			c_type_str, adapter->hw.intrl_gran,
			NSE_INTRL_INTERVAL_MAX_USEC);
		return -EINVAL;
	}
	if (ec->rx_coalesce_usecs_high != q_vector->intrl &&
	    ec->use_adaptive_rx_coalesce) {
		netdev_info(adapter->netdev,
			    "Invalid value, %s-usecs-high cannot be changed if adaptive-rx is enabled\n",
			c_type_str);
		return -EINVAL;
	}

	use_adaptive_coalesce = ec->use_adaptive_rx_coalesce;
	coalesce_usecs = ec->rx_coalesce_usecs;

	itr_setting = q_vector->itr_setting;
	if (coalesce_usecs != itr_setting && use_adaptive_coalesce) {
		netdev_info(adapter->netdev,
			    "%s interrupt throttling cannot be changed if adaptive-%s is enabled\n",
			c_type_str, c_type_str);
		return -EINVAL;
	}

	if (coalesce_usecs > NSE_ITR_INTERVAL_MAX_USEC) {
		netdev_info(adapter->netdev,
			    "Invalid value, %s-usecs range is 0-%d\n",
			    c_type_str, NSE_ITR_INTERVAL_MAX_USEC);
		return -EINVAL;
	}

	if (use_adaptive_coalesce) {
		q_vector->itr_mode = ITR_DYNAMIC;

	} else {
		q_vector->itr_mode = ITR_STATIC;
		/* store user facing value how it was set */
		q_vector->itr_setting = coalesce_usecs;

		if (ec->rx_coalesce_usecs_high != q_vector->intrl)
			q_vector->intrl = ec->rx_coalesce_usecs_high;
	}

	/* The interrupt handler itself will take care of programming
	 * the Tx and Rx ITR values based on the values we have entered
	 * into the q_vector, no need to write the values now.
	 */
	q_vector->dyn_itr_refresh = true;
	q_vector->dyn_itr_val = (q_vector->itr_setting >> 1);

	nsevf_set_q_vector_intrl(q_vector);

	return 0;
}

/**
 * nsevf_is_coalesce_param_invalid - check unsupported coalesce parameters
 * @ec: ethtool structure to fill with driver's coalesce settings
 */
static bool nsevf_is_coalesce_param_invalid(struct ethtool_coalesce *ec)
{
	if (ec->stats_block_coalesce_usecs || ec->rate_sample_interval ||
	    ec->pkt_rate_low || ec->pkt_rate_high ||
	    ec->rx_max_coalesced_frames || ec->rx_coalesce_usecs_irq ||
	    ec->rx_max_coalesced_frames_irq || ec->tx_max_coalesced_frames ||
	    ec->tx_coalesce_usecs_irq || ec->tx_max_coalesced_frames_irq ||
	    ec->rx_coalesce_usecs_low || ec->rx_max_coalesced_frames_low ||
	    ec->tx_coalesce_usecs_low || ec->tx_max_coalesced_frames_low ||
	    ec->rx_max_coalesced_frames_high ||
	    ec->tx_max_coalesced_frames_high || ec->tx_coalesce_usecs ||
	    ec->use_adaptive_tx_coalesce || ec->tx_coalesce_usecs_high)
		return true;

	return false;
}

/**
 * __nsevf_set_coalesce - set coalesce settings for particular queue
 * @netdev: the netdev to change
 * @ec: ethtool coalesce settings
 * @queue: the queue to change
 *
 * Sets the coalesce settings for a particular queue.
 **/
static int __nsevf_set_coalesce(struct net_device *netdev,
				struct ethtool_coalesce *ec, int queue)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	int i;

	if (nsevf_is_coalesce_param_invalid(ec))
		return -EOPNOTSUPP;

	if (nsevf_lan_min_itr_no_intrl) {
		dev_err(nsevf_adapter_to_dev(adapter),
			"[%s] don't allow change ITR or INTRL because nse_lan_min_itr_no_intrl = 1\n",
			__func__);
		return -EOPNOTSUPP;
	}

	/* Rx and Tx usecs has per queue value. If user doesn't specify the
	 * queue, apply to all queues.
	 */
	if (queue < 0) {
		for (i = 0; i < adapter->num_active_queues; i++)
			if (nsevf_set_itr_per_queue(adapter, ec, i))
				return -EINVAL;
	} else if (queue < adapter->num_active_queues) {
		if (nsevf_set_itr_per_queue(adapter, ec, queue))
			return -EINVAL;
	} else {
		netif_info(adapter, drv, netdev,
			   "Invalid queue value, queue range is 0 - %d\n",
			   adapter->num_active_queues - 1);
		return -EINVAL;
	}

	return 0;
}

/**
 * nsevf_set_coalesce - Set interrupt coalescing settings
 * @netdev: network interface device structure
 * @ec: ethtool coalesce structure
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Change current coalescing settings for every queue.
 **/
static int
nsevf_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		   struct kernel_ethtool_coalesce __maybe_unused *kec,
		   struct netlink_ext_ack __maybe_unused *extack)
{
	return __nsevf_set_coalesce(netdev, ec, -1);
}

/**
 * nsevf_set_per_queue_coalesce - set specific queue's coalesce settings
 * @netdev: the netdev to change
 * @ec: ethtool's coalesce settings
 * @queue: the queue to modify
 *
 * Modifies a specific queue's coalesce settings.
 */
static int nsevf_set_per_queue_coalesce(struct net_device *netdev, u32 queue,
					struct ethtool_coalesce *ec)
{
	return __nsevf_set_coalesce(netdev, ec, queue);
}

/**
 * nsevf_get_channels: get the number of channels supported by the device
 * @netdev: network interface device structure
 * @ch: channel information structure
 *
 * For the purposes of our device, we only use combined channels, i.e. a tx/rx
 * queue pair. Report one extra channel to match our "other" MSI-X vector.
 **/
static void nsevf_get_channels(struct net_device *netdev,
			       struct ethtool_channels *ch)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	/* Report maximum channels */
	ch->max_combined = adapter->vsi_res->num_queue_pairs;

	ch->max_other = NONQ_VECS;
	ch->other_count = NONQ_VECS;

	ch->combined_count = adapter->num_active_queues;
}

/**
 * nsevf_set_channels: set the new channel count
 * @netdev: network interface device structure
 * @ch: channel information structure
 *
 * Negotiate a new number of channels with the PF then do a reset.  During
 * reset we'll realloc queues and fix the RSS table.  Returns 0 on success,
 * negative on failure.
 **/
static int nsevf_set_channels(struct net_device *netdev,
			      struct ethtool_channels *ch)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	u32 num_req = ch->combined_count;
	unsigned int reset_wait_timeout;
	unsigned int i;

	/* All of these should have already been checked by ethtool before this
	 * even gets to us, but just to be sure.
	 */
	if (num_req == 0 || num_req > adapter->vsi_res->num_queue_pairs)
		return -EINVAL;

	if (num_req == adapter->num_active_queues)
		return 0;

	if (ch->rx_count || ch->tx_count || ch->other_count != NONQ_VECS)
		return -EINVAL;

	reset_wait_timeout =
		(NSEVF_RESET_WAIT_COMPLETE_TIMEOUT_BASE * nse_timeout_scale);

	adapter->num_req_queues = num_req;
	adapter->flags |= NSEVF_FLAG_REINIT_ITR_NEEDED;
	nsevf_schedule_reset(adapter, NSEVF_FLAG_RESET_NEEDED);

	/* wait for the reset is done */
	for (i = 0; i < reset_wait_timeout; i++) {
		msleep(NSEVF_RESET_WAIT_TICK);
		if (adapter->flags & NSEVF_FLAG_RESET_PENDING)
			continue;
		break;
	}
	if (i == reset_wait_timeout) {
		adapter->flags &= ~NSEVF_FLAG_REINIT_ITR_NEEDED;
		adapter->num_req_queues = 0;
		return -EOPNOTSUPP;
	}

	return 0;
}

static int nsevf_get_link_ksettings(struct net_device *netdev,
				    struct ethtool_link_ksettings *cmd)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	ethtool_link_ksettings_zero_link_mode(cmd, supported);
	ethtool_link_ksettings_zero_link_mode(cmd, advertising);

	cmd->base.autoneg = AUTONEG_DISABLE;
	cmd->base.port = PORT_NONE;
	cmd->base.duplex = DUPLEX_FULL;

	if (ADV_LINK_SUPPORT(adapter)) {
		if (adapter->link_speed_mbps &&
		    adapter->link_speed_mbps < U32_MAX)
			cmd->base.speed = adapter->link_speed_mbps;
		else
			cmd->base.speed = SPEED_UNKNOWN;

		return 0;
	}

	switch (adapter->link_speed) {
	case VIRTCHNL_LINK_SPEED_800GB:
		cmd->base.speed = SPEED_800000;
		break;
	case VIRTCHNL_LINK_SPEED_400GB:
		cmd->base.speed = SPEED_400000;
		break;
	case VIRTCHNL_LINK_SPEED_200GB:
		cmd->base.speed = SPEED_200000;
		break;
	case VIRTCHNL_LINK_SPEED_100GB:
		cmd->base.speed = SPEED_100000;
		break;
	case VIRTCHNL_LINK_SPEED_50GB:
		cmd->base.speed = SPEED_50000;
		break;
	case VIRTCHNL_LINK_SPEED_40GB:
		cmd->base.speed = SPEED_40000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		cmd->base.speed = SPEED_25000;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		cmd->base.speed = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		cmd->base.speed = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_5GB:
		cmd->base.speed = SPEED_5000;
		break;
	case VIRTCHNL_LINK_SPEED_2_5GB:
		cmd->base.speed = SPEED_2500;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		cmd->base.speed = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_100MB:
		cmd->base.speed = SPEED_100;
		break;
	case VIRTCHNL_LINK_SPEED_10MB:
		cmd->base.speed = SPEED_10;
		break;
	default:
		cmd->base.speed = SPEED_UNKNOWN;
		break;
	}

	return 0;
}

static int nsevf_get_rss_hash_opt(struct nsevf_adapter *adapter,
				  struct ethtool_rxnfc *cmd)
{
	u32 rss_ctl = adapter->rss_ctl_alg;

	cmd->data = 0;

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_TCP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case UDP_V4_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_UDP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		break;

	case TCP_V6_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_TCP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case UDP_V6_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		if (rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_UDP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;

		break;

	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:

		cmd->data |= RXH_IP_SRC | RXH_IP_DST;

		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * nsevf_get_rxnfc - command to get RX flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 * @rule_locs: pointer to store rule locations
 *
 * Returns Success if the command is supported.
 **/
static int nsevf_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd,
			   u32 *rule_locs)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = adapter->num_active_queues;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		if (adapter->flags & NSEVF_FLAG_FDIR_CAPABLE) {
			cmd->rule_cnt = adapter->fdir_cb.filter_count;

			/* report max rule count */
			cmd->data =
				(adapter->fdir_cb.fdir_mode ==
				 NSEVF_FDIR_CTL_FILTER_MODE_PERFECT) ?
					(adapter->fdir_cb.fdir_max_num_pfilter -
					 2) :
					(adapter->fdir_cb.fdir_max_num_sfilter -
					 2);

			ret = 0;
		}
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = nsevf_get_ethtool_ntuple(adapter, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		ret = nsevf_get_ethtool_ntuple_ids(adapter, cmd, rule_locs);
		break;

	case ETHTOOL_GRXFH:
		ret = nsevf_get_rss_hash_opt(adapter, cmd);
		break;
	default:
		break;
	}

	return ret;
}

static int nsevf_set_rss_hash_opt(struct nsevf_adapter *adapter,
				  struct ethtool_rxnfc *nfc)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	u32 old_alg, new_alg;
	int ret;

	old_alg = adapter->rss_ctl_alg;
	new_alg = old_alg;

	if (nfc->data &
	    ~(RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3))
		return -EINVAL;

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
	case TCP_V6_FLOW:
	case UDP_V4_FLOW:
	case UDP_V6_FLOW:

		if (!(nfc->data & RXH_IP_SRC) || !(nfc->data & RXH_IP_DST))
			return -EINVAL;

		switch (nfc->data & (RXH_L4_B_0_1 | RXH_L4_B_2_3)) {
		case 0:
			if (nfc->flow_type == TCP_V4_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV4_TCP;
			else if (nfc->flow_type == TCP_V6_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV6_TCP;
			else if (nfc->flow_type == UDP_V4_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV4_UDP;
			else if (nfc->flow_type == UDP_V6_FLOW)
				new_alg &= ~NSE_VSI_RSS_CTL_ALG_IPV6_UDP;

			break;

		case (RXH_L4_B_0_1 | RXH_L4_B_2_3):
			if (nfc->flow_type == TCP_V4_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV4_TCP;
			else if (nfc->flow_type == TCP_V6_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV6_TCP;
			else if (nfc->flow_type == UDP_V4_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV4_UDP;
			else if (nfc->flow_type == UDP_V6_FLOW)
				new_alg |= NSE_VSI_RSS_CTL_ALG_IPV6_UDP;

			break;

		default:
			return -EINVAL;
		}

		break;

	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case SCTP_V4_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case SCTP_V6_FLOW:
		if (!(nfc->data & RXH_IP_SRC) || !(nfc->data & RXH_IP_DST) ||
		    (nfc->data & RXH_L4_B_0_1) || (nfc->data & RXH_L4_B_2_3))
			return -EINVAL;

		break;

	default:
		return -EINVAL;
	}

	/* if we changed something we need to update flags */
	if (new_alg != old_alg) {
		adapter->rss_ctl_alg = new_alg;

		ret = nsevf_config_rss(adapter, NSEVF_CONFIG_RSS_FLAG_ALG);
		if (ret) {
			dev_err(dev, "cfg_rss_ctl failed, error = %d\n", ret);

			adapter->rss_ctl_alg =
				old_alg; /* restore old value, if any failure */

			return ret;
		}
	}

	return 0;
}

static int nsevf_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		return nsevf_add_ethtool_ntuple(adapter, cmd);
	case ETHTOOL_SRXCLSRLDEL:
		return nsevf_del_ethtool_ntuple(adapter, cmd);
	case ETHTOOL_SRXFH:
		return nsevf_set_rss_hash_opt(adapter, cmd);
	default:
		break;
	}
	return ret;
}

/**
 * nsevf_get_rxfh_key_size - get the RSS hash key size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 **/
static u32 nsevf_get_rxfh_key_size(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	return adapter->rss_key_size; //NSE_RSS_KEY_SIZE told by PF driver
}

/**
 * nsevf_get_rxfh_indir_size - get the rx flow hash indirection table size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 **/
static u32 nsevf_get_rxfh_indir_size(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	return adapter->rss_lut_size;
}

/**
 * nsevf_get_rxfh - get the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 * @hfunc: hash function in use
 *
 * Reads the indirection table directly from the hardware. Always returns 0.
 **/
static int nsevf_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			  u8 *hfunc)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	u16 i;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	if (key)
		memcpy(key, adapter->rss_key, adapter->rss_key_size);

	if (indir)
		/* Each 32 bits pointed by 'indir' is stored with a lut entry */
		for (i = 0; i < adapter->rss_lut_size; i++)
			indir[i] = (u32)adapter->rss_lut[i];

	return 0;
}

/**
 * nsevf_set_rxfh - set the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 * @hfunc: hash function to use
 *
 * Returns -EINVAL if the table specifies an invalid queue id, otherwise
 * returns 0 after programming the table.
 **/
static int nsevf_set_rxfh(struct net_device *netdev, const u32 *indir,
			  const u8 *key, const u8 hfunc)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	unsigned int flags = 0;
	u16 i;

	/* Only support toeplitz hash function */
	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (indir) {
		/* Verify user input. */
		for (i = 0; i < adapter->rss_lut_size; i++) {
			if (indir[i] >= adapter->num_active_queues)
				return -EINVAL;
		}
	}

	if (!key && !indir)
		return 0;

	if (key) {
		flags |= NSEVF_CONFIG_RSS_FLAG_KEY;

		memcpy(adapter->rss_key, key, adapter->rss_key_size);
	}

	if (indir) {
		flags |= NSEVF_CONFIG_RSS_FLAG_LUT;

		/* Each 32 bits pointed by 'indir' is stored with a lut entry */
		for (i = 0; i < adapter->rss_lut_size; i++)
			adapter->rss_lut[i] = (u16)(indir[i]);
	}

	return nsevf_config_rss(adapter, flags);
}

static const struct ethtool_ops nsevf_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS |
				     ETHTOOL_COALESCE_USE_ADAPTIVE_RX |
				     ETHTOOL_COALESCE_RX_USECS_HIGH,
	.get_drvinfo = nsevf_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ringparam = nsevf_get_ringparam,
	.set_ringparam = nsevf_set_ringparam,
	.get_strings = nsevf_get_strings,
	.get_ethtool_stats = nsevf_get_ethtool_stats,
	.get_sset_count = nsevf_get_sset_count,
	.get_priv_flags = nsevf_get_priv_flags,
	.set_priv_flags = nsevf_set_priv_flags,
	.get_msglevel = nsevf_get_msglevel,
	.set_msglevel = nsevf_set_msglevel,
	.get_coalesce = nsevf_get_coalesce,
	.set_coalesce = nsevf_set_coalesce,
	.get_per_queue_coalesce = nsevf_get_per_queue_coalesce,
	.set_per_queue_coalesce = nsevf_set_per_queue_coalesce,
	.get_rxnfc = nsevf_get_rxnfc,
	.set_rxnfc = nsevf_set_rxnfc,
	.get_rxfh_key_size = nsevf_get_rxfh_key_size,
	.get_rxfh_indir_size = nsevf_get_rxfh_indir_size,
	.get_rxfh = nsevf_get_rxfh,
	.set_rxfh = nsevf_set_rxfh,
	.get_channels = nsevf_get_channels,
	.set_channels = nsevf_set_channels,
	.get_link_ksettings = nsevf_get_link_ksettings,
};

/**
 * nsevf_set_ethtool_ops - Initialize ethtool ops struct
 * @netdev: network interface device structure
 *
 * Sets ethtool ops struct in our netdev so that ethtool can call
 * our functions.
 **/
void nsevf_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &nsevf_ethtool_ops;
}
